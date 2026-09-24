"""Two-ledger authority tests with explicit portable native/readiness fixtures.

SQL admission, immutable links, daily actor/Job intent publication, and isolated
Job-scope registration use their real APIs. Process identity, mutex ownership,
readiness and registration evidence are synthetic and do not prove a Windows
capability, an actual Job, a CPU Set, or emergency restoration.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import os
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_host_authority as module
from sentinel.adaptive import experiment_host_transport as transport
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_local_backing as local
from sentinel.adaptive import experiment_partition_admission as partition
from sentinel.adaptive import host_authority
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.legacy_writer import initialize_registry_locked, register_infrastructure_locked
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.store import LifecycleEvidence
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_experiment_partition_admission as fixtures
from tests import test_adaptive_experiment_host_transport as transport_fixtures
from tests.test_adaptive_coordinator import NOW
from tests.test_adaptive_ipc import Clock, wire_frame


class ExperimentHostAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentPartitionAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.adapter = self.fixture.adapter
        self.context, self.snapshot = self.fixture.context, self.fixture.snapshot
        self.store, self.host = self.fixture.base_store, self.fixture.host
        self.execution_id = self.snapshot.execution_id
        self.scoped_readiness = []
        self.guardian_identity = self.guardian_member = self.guardian_process = None

        def scoped_readiness(path, *, expected_generation):
            self.assertEqual(path, self.host.store.db_path.resolve())
            self.assertEqual(expected_generation, self.fixture.generation)
            self.assertTrue(self.host.fixture.fixture.policy.active)
            self.assertEqual(self.fixture.daily_transactions, [])
            self.scoped_readiness.append(path)
            return self.fixture.deadline

        proof = SimpleNamespace(
            readiness_scopes=partition.daily_generation.readiness_scopes,
            revalidate_transaction=partition.daily_generation.revalidate_transaction,
            read_generation=partition.daily_generation.read_generation,
            revalidate_scoped_readiness=scoped_readiness)
        capability = host_authority.HostCapability("win32", 10, 0, 26340, 8, 1, "255", os.getpid())
        overrides = (
            patch.object(module, "daily_generation", proof),
            patch.object(module.time, "time", return_value=NOW),
            patch.object(host_authority, "read_host_capability", return_value=capability),
            patch.object(module, "read_host_capability", return_value=capability),
        )
        for override in overrides:
            override.start()
            self.addCleanup(override.stop)

    def admit(self):
        result = self.adapter.admit_managed(self.context)
        self.assertTrue(result["allowed"])
        return self.store.query(self.execution_id, existing_path=True)

    def wrapper(self):
        return module.ExperimentBackedHostAuthority.for_wrapper(self.adapter)

    @contextmanager
    def isolated_policy(self):
        self.assertTrue(self.host.fixture.fixture.policy.active)
        self.assertEqual(self.fixture.daily_transactions, [])
        policy = self.store._policy
        guard = policy.prepare(self.snapshot.logon_id)
        with policy.hold(guard):
            self.assertTrue(self.fixture.policy.active)
            yield guard

    def guardian_actor(self):
        if self.guardian_member is None:
            self.guardian_identity = ProcessIdentity(os.getpid(),
                self.snapshot.wrapper_identity.created_filetime_100ns + 5000, self.snapshot.logon_id)
            self.guardian_member, identity = self.host.actor(role="guardian", identity=self.guardian_identity)
            self.assertEqual(identity, self.guardian_identity)
        return self.guardian_member

    def publish_job(self):
        guardian = self.guardian_actor()
        operation = self.fixture.operation
        nonce = uuid4().hex
        job = ledger.JobBinding(operation.member_id, "managed",
            "Local\\ResourceSentinel.Job." + self.execution_id + "." + nonce, nonce,
            guardian.member_id, operation.wrapper_member_id, self.execution_id,
            operation.binding.reservation_id)
        with self.host.locked() as (conn, guard):
            ledger.publish_job_locked(conn, scope=self.host.scope_owner, binding=job,
                                      policy=self.host.policy, guard=guard)
            conn.commit()
        return job

    def register_isolated_job(self, authority, job):
        """Use the real CAS with explicit fixture evidence; no native Job exists."""
        epoch = "fixture-experiment-guardian"
        def evidence(operation, row, caller):
            self.assertEqual(operation, "register_scope")
            return LifecycleEvidence(operation, row["execution_id"], row["state_revision"], uuid4().hex,
                caller, guardian_epoch=epoch, job_name=job.job_name, job_nonce=job.creation_nonce,
                job_creation_never_attempted=True)
        with patch.object(self.store, "evidence_provider", fixture_evidence_provider(evidence)):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                with self.isolated_policy():
                    if self.guardian_process is not None:
                        initialize_registry_locked(self.store)
                        register_infrastructure_locked(self.store, "guardian", self.guardian_process)
                    self.store.register_job_scope(self.execution_id, caller=self.snapshot.wrapper_identity,
                        expected_revision=0, guardian_epoch=epoch, job_name=job.job_name,
                        job_nonce=job.creation_nonce)
        return self.store.query(self.execution_id, existing_path=True)

    def endpoint(self):
        self.guardian_actor()
        return NativePipeEndpoint(self.snapshot.logon_id, str(uuid4()), self.guardian_identity)

    def guardian(self):
        """Run the real child handshake over completed in-memory pipe I/O."""
        member = self.guardian_actor()
        manifest = replace(self.fixture.child_binding.manifest, role="guardian",
            child_identity=self.guardian_identity, actor_member_id=member.member_id, request_id=str(uuid4()))
        backend = transport_fixtures.Backend(self.guardian_identity)
        self.guardian_process = VerifiedProcess(backend, 41, self.guardian_identity)
        self.addCleanup(self.guardian_process.close)
        registration = transport.ExperimentChildRegistration(manifest, transport_fixtures.KEY)
        client = transport.ExperimentChildClient(registration, self.guardian_process)
        request = transport.BindExperimentChildRequest(manifest)
        parent = manifest.endpoint.server_identity
        challenge = {"version": 1, "kind": "ExperimentChildChallenge", "request_id": manifest.request_id,
            "nonce": transport_fixtures.NONCE, "endpoint_id": manifest.endpoint.instance_id,
            "server": parent.to_dict(), "client": self.guardian_identity.to_dict()}
        result = {"bound_manifest": manifest.to_dict()}
        response = {"version": 1, "kind": "ExperimentChildResult", "request_id": manifest.request_id,
            "nonce": challenge["nonce"], "result": result,
            "mac": transport_fixtures.wire_mac("result", request.to_dict(), challenge, result)}
        pipe = transport_fixtures.Pipe(parent, wire_frame(challenge) + wire_frame(response))
        with patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()), \
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False), \
                patch.object(transport.NativePipeConnection, "connect", return_value=pipe):
            binding = client.bind()
        self.addCleanup(transport._ORIGINAL_CLIENTS.pop, client._request_key, None)
        self.addCleanup(binding.close)
        authority = module.ExperimentBackedHostAuthority.for_guardian(binding,
            isolated_store=self.store, daily_store=self.host.store, guardian=self.guardian_process)
        return authority, binding

    def test_wrapper_factory_can_precede_admission_but_scope_cannot(self):
        authority = self.wrapper()
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                self.fail("missing original admission acquired authority")
        row = self.admit()
        with authority.new_work_scope(self.execution_id, operation="prepare"):
            self.assertIsNone(authority.assert_ready())
            self.assertIsNone(authority.assert_covered(row))
        self.assertGreater(len(self.scoped_readiness), 0)

    def test_prepare_holds_daily_before_isolated_without_rpc_or_overlapping_daily_sql(self):
        row = self.admit()
        authority = self.wrapper()
        before = self.host.fixture.assert_retained(self.host.owner)
        with patch.object(transport.NativePipeConnection, "connect", side_effect=AssertionError("unexpected RPC")):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                self.assertTrue(self.host.fixture.fixture.policy.active)
                self.assertFalse(self.fixture.policy.active)
                self.assertEqual(self.fixture.daily_transactions, [])
                with self.isolated_policy():
                    self.assertIsNone(authority.assert_covered(row))
        self.assertFalse(self.host.fixture.fixture.policy.active)
        self.assertFalse(self.fixture.policy.active)
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)

    def test_prepare_without_job_is_not_exclusion_or_create_authority(self):
        row = self.admit()
        authority = self.wrapper()
        endpoint = self.endpoint()
        with authority.new_work_scope(self.execution_id, operation="prepare"):
            self.assertIsNone(authority.assert_covered(row))
            with self.assertRaises(module.ExperimentHostAuthorityError):
                authority.assert_excluded(row)
            with self.assertRaises(host_authority.HostReadinessError):
                authority.assert_create_ready(self.context, row, endpoint)
        for operation in ("claim", "create"):
            with self.subTest(operation=operation), self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation=operation):
                    self.fail("missing Job intent acquired launch authority")

    def test_inverted_isolated_policy_is_rejected_before_readiness_acquisition(self):
        self.admit()
        authority = self.wrapper()
        policy = self.store._policy
        guard = policy.prepare(self.snapshot.logon_id)
        with policy.hold(guard):
            with patch.object(module.daily_generation, "readiness_scopes",
                              side_effect=AssertionError("readiness RPC under isolated POLICY")):
                with self.assertRaisesRegex(module.ExperimentHostAuthorityError, "outer_daily_scope_required"):
                    with authority.new_work_scope(self.execution_id, operation="prepare"):
                        self.fail("inverted POLICY acquisition was accepted")

    def test_real_job_intent_and_isolated_registration_allow_claim_and_exact_create(self):
        self.admit()
        authority = self.wrapper()
        job = self.publish_job()
        row = self.register_isolated_job(authority, job)
        endpoint = self.endpoint()
        for operation in ("claim", "create"):
            with self.subTest(operation=operation):
                with authority.new_work_scope(self.execution_id, operation=operation):
                    self.assertIsNone(authority.assert_covered(row))
                    with self.assertRaisesRegex(module.ExperimentHostAuthorityError, "guardian_required"):
                        authority.assert_excluded(row)
                    if operation == "create":
                        self.assertIsNone(authority.assert_create_ready(self.context, row, endpoint))
                    else:
                        with self.assertRaises(host_authority.HostReadinessError):
                            authority.assert_create_ready(self.context, row, endpoint)
        with self.assertRaises(host_authority.HostReadinessError):
            authority.assert_create_ready(self.context, row, endpoint)

    def test_guardian_missing_job_refuses_restriction_and_renewal_then_exact_intent_allows_them(self):
        self.admit()
        authority, binding = self.guardian()
        for operation in ("claim", "restrict", "renew"):
            with self.subTest(operation=operation), self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation=operation):
                    self.fail("missing Job intent acquired restriction authority")
        job = self.publish_job()
        row = self.register_isolated_job(authority, job)
        for operation in ("claim", "restrict", "renew"):
            with self.subTest(operation=operation):
                with authority.new_work_scope(self.execution_id, operation=operation):
                    self.assertIsNone(authority.assert_covered(row))
                    with self.isolated_policy():
                        self.assertIsNone(authority.assert_excluded(row))
        self.assertTrue(binding.custody_pending)

    def test_existing_ordinary_authority_still_refuses_all_three_linked_execution_surfaces(self):
        row = self.admit()
        ordinary = host_authority.HostAuthority(self.store, clock=lambda: NOW)
        for check in (ordinary.assert_covered, ordinary.assert_excluded):
            with self.subTest(check=check.__name__), self.assertRaisesRegex(host_authority.HostAuthorityError,
                    "local_backing_experiment_backed_authority_required"):
                check(row)
        with self.assertRaisesRegex(host_authority.HostReadinessError,
                "local_backing_experiment_backed_authority_required"):
            ordinary.assert_launch_ready(self.context, row, self.endpoint())

    def test_foreign_constructors_roles_operations_and_execution_ids_are_rejected(self):
        self.admit()
        with self.assertRaises((module.ExperimentHostAuthorityError, TypeError)):
            module.ExperimentBackedHostAuthority.for_wrapper(SimpleNamespace(**self.adapter.__dict__))
        with self.assertRaises((module.ExperimentHostAuthorityError, TypeError)):
            module.ExperimentBackedHostAuthority.for_guardian(self.fixture.child_binding,
                isolated_store=self.store, daily_store=self.host.store, guardian=self.fixture.child_process)
        authority = self.wrapper()
        for operation in ("restrict", "renew", "restore", "unknown"):
            with self.subTest(operation=operation), self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation=operation):
                    self.fail("wrong role or operation acquired authority")
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with authority.new_work_scope(str(uuid4()), operation="prepare"):
                self.fail("foreign execution acquired authority")

    def test_shallow_copied_authority_is_not_an_original_factory_owner(self):
        self.admit()
        authority = self.wrapper()
        copied = object.__new__(module.ExperimentBackedHostAuthority)
        copied.__dict__.update(authority.__dict__)
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with copied.new_work_scope(self.execution_id, operation="prepare"):
                self.fail("copied authority acquired original ownership")

    def test_wrapper_context_and_original_publication_cannot_be_replaced(self):
        self.admit()
        authority = self.wrapper()
        for name in ("_context", "_local_backing_publication"):
            original = getattr(self.adapter, name)
            setattr(self.adapter, name, object())
            try:
                with self.subTest(name=name), self.assertRaises(module.ExperimentHostAuthorityError):
                    with authority.new_work_scope(self.execution_id, operation="prepare"):
                        self.fail("replacement owner acquired authority")
            finally:
                setattr(self.adapter, name, original)

    def test_digest_valid_but_changed_local_link_cannot_supply_another_daily_member(self):
        self.admit()
        authority = self.wrapper()
        with closing(sqlite3.connect(self.store.db_path, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            row = dict(conn.execute("SELECT * FROM " + local.TABLE).fetchone())
            row["member_id"] = str(uuid4())
            row["link_sha256"] = local._digest(row)
            conn.execute("BEGIN IMMEDIATE")
            # Model on-disk corruption, then restore the exact guard schema.
            guard_name = local.PREFIX + "update"
            conn.execute("DROP TRIGGER " + guard_name)
            conn.execute("UPDATE " + local.TABLE + " SET member_id=?,link_sha256=?",
                         (row["member_id"], row["link_sha256"]))
            conn.execute(local.GUARDS[guard_name])
            conn.commit()
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                self.fail("changed local link acquired authority")

    def test_daily_hold_denies_new_work_and_keeps_original_allocations(self):
        self.admit()
        authority = self.wrapper()
        before = self.host.fixture.assert_retained(self.host.owner)
        self.host.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                self.fail("daily HOLD acquired new authority")
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_expired_daily_allocation_denies_new_work_without_releasing_it(self):
        self.admit()
        authority = self.wrapper()
        before = self.host.fixture.assert_retained(self.host.owner)
        expires_at = self.host.rows("reservations")[0]["expires_at"]
        original = self.host.store._connection
        @contextmanager
        def expired_connection(**kwargs):
            with original(**kwargs) as conn:
                conn.create_function("julianday", 1,
                    lambda value: (expires_at + 1) / 86400 + 2440587.5)
                yield conn
        with patch.object(self.host.store, "_connection", expired_connection), \
                patch.object(module.time, "time", return_value=expires_at + 1):
            with self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation="prepare"):
                    self.fail("expired daily allocation acquired new authority")
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_parent_death_denies_new_work_without_reconstructing_binding(self):
        self.admit()
        authority = self.wrapper()
        original = self.fixture.child_binding
        original._peer._backend.status = IdentityStatus.DEAD
        with self.assertRaises(module.ExperimentHostAuthorityError):
            with authority.new_work_scope(self.execution_id, operation="prepare"):
                self.fail("dead parent acquired new authority")
        self.assertIs(self.adapter.child_binding, original)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_existing_guardian_bind_survives_parent_death_hold_and_expiry_without_new_authority(self):
        self.admit()
        authority, binding = self.guardian()
        job = self.publish_job()
        row = self.register_isolated_job(authority, job)
        before = self.host.fixture.assert_retained(self.host.owner)
        binding._peer._backend.status = IdentityStatus.DEAD
        self.host.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        expires_at = self.host.rows("reservations")[0]["expires_at"]
        original = self.host.store._connection
        @contextmanager
        def expired_connection(**kwargs):
            with original(**kwargs) as conn:
                conn.create_function("julianday", 1,
                    lambda value: (expires_at + 1) / 86400 + 2440587.5)
                yield conn
        with patch.object(self.host.store, "_connection", expired_connection), \
                patch.object(module.time, "time", return_value=expires_at + 1):
            with authority.existing_work_scope(self.execution_id):
                self.assertIsNone(authority.assert_existing_covered(row))
                with self.assertRaises(module.ExperimentHostAuthorityError):
                    authority.assert_covered(row)
            with self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation="claim"):
                    self.fail("existing Bind scope became new launch authority")
        self.assertEqual(self.host.fixture.assert_retained(self.host.owner), before)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_uncertain_daily_release_is_retained_and_never_reacquired(self):
        self.admit()
        authority = self.wrapper()
        provider = self.host.fixture.fixture.policy
        original = provider.hold
        acquisitions = []
        @contextmanager
        def uncertain_release(binding, *, timeout_ms=250):
            acquisitions.append(binding)
            with original(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise OSError("experiment_authority_daily_release_unknown")
        with patch.object(provider, "hold", uncertain_release):
            with self.assertRaises(module.ExperimentHostAuthorityError) as first:
                with authority.new_work_scope(self.execution_id, operation="prepare"):
                    pass
            self.assertIs(first.exception.experiment_host_authority, authority)
            self.assertEqual(str(first.exception.original_error), "experiment_authority_daily_release_unknown")
            self.assertIsNotNone(authority._guard)
            self.assertFalse(authority._guard._native_exit_confirmed)
            self.assertEqual(len(acquisitions), 1)
            with self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation="prepare"):
                    self.fail("uncertain original POLICY release was retried")
            self.assertEqual(len(acquisitions), 1)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_uncaught_body_cleanup_error_poison_is_retained_by_cached_factory(self):
        self.admit()
        authority = self.wrapper()
        self.assertIs(self.wrapper(), authority)
        injected = RuntimeError("fixture_caller_cleanup_unverified")
        injected.add_note("lifecycle_connection_cleanup_failed")
        provider = self.host.fixture.fixture.policy
        with patch.object(module.daily_generation, "readiness_scopes",
                          wraps=module.daily_generation.readiness_scopes) as readiness, \
                patch.object(provider, "hold", wraps=provider.hold) as acquisitions:
            with self.assertRaises(module.ExperimentHostAuthorityError) as first:
                with authority.new_work_scope(self.execution_id, operation="prepare"):
                    raise injected
            self.assertIs(first.exception.original_error, injected)
            self.assertIs(first.exception.experiment_host_authority, authority)
            self.assertIn("lifecycle_connection_cleanup_failed", first.exception.__notes__)
            self.assertIs(authority._body_attempt["error"], injected)
            self.assertFalse(authority._body_attempt["returned"])
            self.assertEqual(readiness.call_count, 1)
            self.assertEqual(acquisitions.call_count, 1)
            self.assertIs(self.wrapper(), authority)
            with self.assertRaises(module.ExperimentHostAuthorityError):
                with authority.new_work_scope(self.execution_id, operation="prepare"):
                    self.fail("uncertain caller cleanup was replaced by a new operation")
            self.assertIs(self.wrapper(), authority)
            self.assertEqual(readiness.call_count, 1)
            self.assertEqual(acquisitions.call_count, 1)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)


if __name__ == "__main__":
    unittest.main()
