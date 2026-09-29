"""Connected C2 aggregate completion with actual production SQL and custody.

Only process/pipe/mutex effects and source readiness are portable fixtures.
Scopes, authorities, publication, cancellation, receipt writers and completion
remain their real implementations. No native Job or production gate is tested.
"""
from contextlib import closing
from dataclasses import replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import admission
from sentinel.adaptive import experiment_backing_transport as backing_transport
from sentinel.adaptive import experiment_host_authority as authority_module
from sentinel.adaptive import experiment_host_backing as backing
from sentinel.adaptive import experiment_host_completion as completion
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_retirement_transport as retirement
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive import experiment_job_publication as jobs
from sentinel.adaptive import experiment_local_backing as local_backing
from sentinel.adaptive import experiment_partition_admission as partition
from sentinel.adaptive import host_authority
from sentinel.adaptive import prelaunch_receipt
from sentinel.adaptive.contracts import IdentityStatus, Priority, ProcessIdentity, Role
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.ipc import _get_ipc_auth_record
from sentinel.adaptive.launch_transport import CancelBeforeStartRequest, PrepareExecutionRequest
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_experiment_host_completion as completion_fixture
from tests import test_adaptive_experiment_host_dispatch as dispatch_fixture
from tests import test_adaptive_experiment_host_roles as roles_fixture
from tests import test_adaptive_experiment_role_release as role_fixture
from tests import test_adaptive_experiment_host_transport as wire
from tests import test_adaptive_guardian_launch as launch_fixture
from tests import test_adaptive_guardian_lifecycle as lifecycle_fixture
from tests.test_adaptive_coordinator import NOW
from tests.test_adaptive_ipc import canonical, wire_frame


class ManagedAggregateCompletionTests(unittest.TestCase):
    prepare_release = completion_fixture.ProductionScopeCompletionTests.prepare_release

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="sentinel-managed-completion-")
        self.addCleanup(directory.cleanup)
        self.journal_dir = Path(directory.name)
        base_role = roles_fixture.guardian()
        self.dispatch_fx = dispatch_fixture.ProductionHostDispatcherTests()
        self.addCleanup(self.dispatch_fx.doCleanups)
        # Child actors share the actual test PID while retaining distinct start
        # times, so the production current-process checks need no replacement.
        with patch.object(role_fixture, "ProcessIdentity", side_effect=lambda pid, start, logon:
                          ProcessIdentity(os.getpid(), start, logon)), \
                patch.object(roles_fixture, "guardian", return_value=replace(base_role,
                    journal_dir=str(self.journal_dir))):
            self.dispatch_fx.setUp()
        self.role_fx = self.dispatch_fx.fixture
        self.fx = self.role_fx.host
        self.owner = self.dispatch_fx.owner
        self.demand = self.owner.demand
        self.coordinator = self.fx.fixture.coordinator
        self.dispatcher = self.owner.open_dispatcher()
        self.guardian, self.wrapper, self.member = self.role_fx.guardian, self.role_fx.wrapper, self.role_fx.workload
        self.guardian_actor, self.guardian_registration, _ = self.role_fx.children[self.guardian.member_id]
        self.wrapper_actor, self.wrapper_registration, _ = self.role_fx.children[self.wrapper.member_id]
        guardian_wire = self.dispatch(child.BindExperimentChildRequest(self.guardian_registration.manifest),
                                      self.guardian_registration, "Child")
        wrapper_wire = self.dispatch(child.BindExperimentChildRequest(self.wrapper_registration.manifest),
                                     self.wrapper_registration, "Child")
        self.guardian_binding = self.bind(self.guardian_registration, self.guardian_actor, guardian_wire)
        self.wrapper_binding = self.bind(self.wrapper_registration, self.wrapper_actor, wrapper_wire)
        self.processes = launch_fixture.ProcessBackend()
        current = self.processes.process(self.wrapper_actor.process.identity)
        with patch.object(admission.VerifiedProcess, "current", return_value=current):
            self.context = admission.ManagedAdmission.current(command="fixture-cancel-before-start",
                cwd=str(self.fx.fixture.scope), repo_identifier="aggregate-custody-fixture",
                requested=self.member.requested, role=Role.BACKGROUND, priority=Priority.P2)
            self.snapshot = self.context.snapshot()
        self.addCleanup(self.context.close)
        self.policy = FixturePolicyProvider(current.identity.logon_id)
        self.isolated_coordinator = Coordinator(self.fx.isolated.parent, db_path=self.fx.isolated,
                                                 policy_provider=self.policy)
        with closing(sqlite3.connect(self.fx.isolated)) as conn:
            conn.execute("UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?,"
                "policy_binding_initialized=1 WHERE singleton=1",
                (self.owner.spec.isolated_policy_instance_id, current.identity.logon_id))
            conn.commit()
        self.reservation_id = uuid4().hex
        self.backing_request = backing_transport.PublishExperimentBackingRequest(
            self.wrapper_registration.manifest, str(uuid4()), self.member.member_id, self.reservation_id,
            backing_transport.AdmissionSnapshotObservation.from_snapshot(self.snapshot))
        self.dispatch(self.backing_request, self.wrapper_registration, "Backing")
        proof = SimpleNamespace(readiness_scopes=partition.daily_generation.readiness_scopes,
            revalidate_transaction=partition.daily_generation.revalidate_transaction,
            read_generation=lambda conn: dict(self.fx.fixture.generation),
            revalidate_scoped_readiness=lambda *args, **kwargs: None)
        capability = host_authority.HostCapability("win32", 10, 0, 26340, 8, 1, "255", os.getpid())
        for override in (patch.object(partition, "daily_generation", proof),
                         patch.object(authority_module, "daily_generation", proof),
                         patch.object(authority_module, "read_host_capability", return_value=capability),
                         patch.object(host_authority, "read_host_capability", return_value=capability),
                         patch.object(authority_module.time, "time", return_value=NOW + 1),
                         patch.object(authority_module.time, "monotonic", return_value=10.0),
                         patch.object(creation._NativeCreation, "close", return_value=1)):
            override.start()
            self.addCleanup(override.stop)
        self.adapter = partition.ExperimentPartitionCoordinator(self.isolated_coordinator,
            self.wrapper_binding, member_id=self.member.member_id, reservation_id=self.reservation_id,
            daily_store=self.owner.daily_store)
        self.assertTrue(self.adapter.admit_managed(self.context)["allowed"])
        self.store = LifecycleStore(self.fx.isolated, existing_path=True, policy_provider=self.policy)
        self.authority = authority_module.ExperimentBackedHostAuthority.for_guardian(self.guardian_binding,
            isolated_store=self.store, daily_store=self.owner.daily_store, guardian=self.guardian_actor.process)
        self.journal = RecoveryJournal(self.journal_dir, publisher=lifecycle_fixture.publish_fixture)
        self.guardian_owner = GuardianLaunchOwner(self.store, self.journal,
            guardian_epoch=self.role_fx.guardian_role.guardian_epoch, authority=self.authority,
            guardian=self.guardian_actor.process,
            job_factory=lambda *args, **kwargs: self.fail("C2 fixture attempted native Job creation"),
            mutex_factory=lifecycle_fixture.Mutex)
        self.peer = self.processes.process(self.snapshot.wrapper_identity)
        self.addCleanup(self.peer.close)
        self.auth = _get_ipc_auth_record(self.store.db_path, self.snapshot.execution_id)
        self.deadline = launch_fixture.Deadline()
        self.request = PrepareExecutionRequest(str(uuid4()), self.snapshot.execution_id,
            self.snapshot.spec_hash, self.role_fx.guardian_role.guardian_epoch, 0)
        self.floor = self.fx.fixture.assert_retained(self.demand)

    def dispatch(self, request, registration, family):
        state = {}
        stem = "Experiment" + family
        domain = "experiment-host-retirement-ipc" if family == "HostRetirement" else "experiment-" + family.lower() + "-ipc"
        def mac(purpose, result=None):
            transcript = dict(domain="ResourceSentinel/" + domain + "/v1/" + purpose,
                request=request.to_dict(), challenge=state["challenge"])
            if purpose != "proof":
                transcript["result"] = result
            return hmac.new(registration.auth_key, canonical(transcript), hashlib.sha256).hexdigest()
        def write(connection, message):
            self.role_fx.assert_settled()
            if message["kind"] == stem + "Challenge":
                state["challenge"] = message
                connection.enqueue(dict(version=1, kind=stem + "Proof", request_id=request.request_id,
                    nonce=message["nonce"], mac=mac("proof")))
            elif message["kind"] == stem + "Result":
                self.assertEqual(message["mac"], mac("result", message["result"]))
                state["result"] = message["result"]
                connection.enqueue(dict(version=1, kind=stem + "Receipt", request_id=request.request_id,
                    nonce=message["nonce"], mac=mac("receipt", message["result"])))
            elif family == "HostRetirement" and message["kind"] == stem + "Settled":
                self.assertEqual(message["mac"], mac("settled", state["result"]))
                connection.enqueue(dict(version=1, kind=stem + "Finished", request_id=request.request_id,
                    nonce=message["nonce"], mac=mac("finished", state["result"])))
        hello = dict(version=1, kind=stem + "Hello", request_id=request.request_id,
                     caller=registration.manifest.child_identity.to_dict())
        connection = wire.Pipe(registration.manifest.child_identity,
            wire_frame(hello) + wire_frame(request.to_dict()), on_write=write)
        self.dispatch_fx.pending.append(connection)
        self.dispatcher.serve_once()
        self.assertTrue(connection.closed)
        return connection

    def bind(self, registration, actor, server):
        client = child.ExperimentChildClient(registration, actor.process)
        frames = [message for message in server.writes if message["kind"] in
                  {"ExperimentChildChallenge", "ExperimentChildResult"}]
        connection = wire.Pipe(self.dispatcher.endpoint.server_identity, b"".join(wire_frame(value) for value in frames))
        with patch.object(child.NativePipeConnection, "connect", return_value=connection):
            result = client.bind()
        self.addCleanup(child._ORIGINAL_CLIENTS.pop, client._request_key, None)
        self.addCleanup(result.close)
        return result

    def job_connection(self, *args, **kwargs):
        publication = self.guardian_owner._pending[self.snapshot.execution_id].experiment_job_publication
        request = publication.request
        parent_wire = self.dispatch(request, self.guardian_registration, "Job")
        # The child's original publisher consumes the actual authenticated
        # parent challenge/result, retaining its own separate transport owner.
        frames = [value for value in parent_wire.writes if value["kind"] in
                  {"ExperimentJobChallenge", "ExperimentJobResult"}]
        return wire.Pipe(self.dispatcher.endpoint.server_identity, b"".join(wire_frame(value) for value in frames))

    def retire_c2(self):
        with patch.object(jobs.NativePipeConnection, "connect", side_effect=self.job_connection):
            self.guardian_owner.prepare_experiment_job_intent(self.request, self.peer,
                auth_record=self.auth, deadline=self.deadline)
        # A deterministic interruption before journal publication/Create leaves
        # the original registered scope; cancellation must retire that scope.
        with self.authority.new_work_scope(self.snapshot.execution_id, operation="prepare"):
            with patch.object(self.guardian_owner, "_initial_record",
                    side_effect=LifecycleError("fixture_before_native_create")):
                with self.assertRaisesRegex(LifecycleError, "fixture_before_native_create"):
                    self.guardian_owner.prepare_execution(self.request, self.peer, self.auth, self.deadline)
        row = self.store.query(self.snapshot.execution_id, existing_path=True)
        request = CancelBeforeStartRequest(str(uuid4()), row["execution_id"], row["spec_hash"],
            row["guardian_epoch"], row["state_revision"], row["job_nonce"])
        self.guardian_owner.begin_drain()
        with self.authority.existing_work_scope(row["execution_id"]):
            result = self.guardian_owner.retire_before_start(request, self.peer, self.auth, self.deadline)
        self.assertEqual(result.state, "CANCELLED_BEFORE_START")
        result, = self.guardian_owner.retire_completed_pending()
        self.assertTrue(result["terminal"], result)
        closed, = self.guardian_owner.closed_experiment_custody()
        self.assertEqual(closed[0], "prelaunch")
        body = prelaunch_receipt.assert_prelaunch_custody_receipt(self.store, self.journal,
            self.store.query(row["execution_id"], existing_path=True))
        self.assertEqual(body["job_disposition"], "never-created")
        claim = {key: body[key] for key in ("execution_id", "evidence_kind", "job_name", "manifest_hash")}
        claim.update(job_nonce=body["job_nonce"], receipt_sha256=hashlib.sha256(canonical(body)).hexdigest())
        self.dispatch(retirement.PublishHostClosedRequest(self.guardian_registration.manifest,
            str(uuid4()), canonical(dict(kind="guardian", jobs=[claim]))), self.guardian_registration,
            "HostRetirement")
        wrapper = dict(kind="wrapper", execution_id=row["execution_id"], native_owners_closed=0,
            publication_request_id=self.backing_request.request_id,
            publication_sha256=self.backing_request.payload_sha256, launcher_phase="CLOSED")
        self.dispatch(retirement.PublishHostClosedRequest(self.wrapper_registration.manifest,
            str(uuid4()), canonical(wrapper)), self.wrapper_registration, "HostRetirement")
        for actor, _, _ in self.role_fx.children.values():
            actor.process._backend.state = IdentityStatus.DEAD
        self.body = body
        return body

    def corrupt(self, statement, parameters=()):
        with closing(sqlite3.connect(self.fx.isolated)) as conn:
            conn.execute(statement, parameters)
            conn.commit()

    def local_link(self):
        with closing(sqlite3.connect(self.fx.isolated)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM " + local_backing.TABLE + " WHERE execution_id=?",
                                (self.snapshot.execution_id,)).fetchall()
        self.assertEqual(len(rows), 1)
        row = dict(rows[0])
        self.assertEqual(row["link_sha256"], local_backing._digest(row))
        return row

    def retire_before_prepare(self, *, include_proof=True):
        row = self.store.query(self.snapshot.execution_id, existing_path=True)
        self.assertEqual(row["state"], "RESERVED")
        self.assertIsNone(row["job_name"])
        self.assertEqual(self.owner._job_publications, {})
        cancelled = self.adapter.cancel_managed(self.context,
            reservation_id=self.reservation_id, expected_revision=row["state_revision"], now=NOW + 2)
        self.assertTrue(cancelled["cancelled"])
        self.assertEqual(cancelled["state"], "CANCELLED_BEFORE_START")
        self.guardian_owner.begin_drain()
        self.assertEqual(self.guardian_owner.closed_experiment_custody(), ())
        self.dispatch(retirement.PublishHostClosedRequest(self.guardian_registration.manifest,
            str(uuid4()), canonical(dict(kind="guardian", jobs=[]))), self.guardian_registration,
            "HostRetirement")
        proof = dict(kind="reserved_cancelled", execution_id=self.snapshot.execution_id,
            reservation_id=cancelled["reservation_id"], request_key=self.snapshot.request.request_key,
            spec_hash=self.snapshot.spec_hash, admission_binding_hash=self.snapshot.binding_hash,
            state=cancelled["state"], state_revision=cancelled["state_revision"])
        wrapper = dict(kind="wrapper", execution_id=self.snapshot.execution_id, native_owners_closed=0,
            publication_request_id=self.backing_request.request_id,
            publication_sha256=self.backing_request.payload_sha256, launcher_phase="CLOSED")
        if include_proof:
            wrapper["admission_retirement"] = proof
        self.dispatch(retirement.PublishHostClosedRequest(self.wrapper_registration.manifest,
            str(uuid4()), canonical(wrapper)), self.wrapper_registration, "HostRetirement")
        for actor, _, _ in self.role_fx.children.values():
            actor.process._backend.state = IdentityStatus.DEAD
        return proof

    def assert_retained(self):
        self.assertEqual(self.fx.fixture.assert_retained(self.demand), self.floor)
        self.assertFalse(self.demand._closed)

    def test_actual_c2_custody_and_original_publications_allow_v4_daily_release(self):
        body = self.retire_c2()
        completed = completion.retire(self.owner)
        record = completed.snapshot()
        self.assertEqual(record["schema_version"], completion.HOST_VERSION)
        self.assertEqual(record["isolated_custody"], [dict(member_id=self.member.member_id, receipt=body,
            local_link_sha256=self.local_link()["link_sha256"])])
        self.assertEqual(len(record["backing_rows"]), 1)
        self.assertEqual(len(record["host_rows"][ledger.JOBS_TABLE]), 1)
        self.assertTrue(self.coordinator.release_experiment(self.prepare_release(completed))["released"])
        self.assertTrue(self.demand._closed)

    def test_missing_actual_isolated_receipt_keeps_daily_capacity(self):
        self.retire_c2()
        self.corrupt("DELETE FROM adaptive_prelaunch_custody_receipts")
        with self.assertRaises(LifecycleError):
            completion.retire(self.owner)
        self.assert_retained()

    def test_changed_actual_receipt_body_is_not_replaced_by_authenticated_claim(self):
        self.retire_c2()
        body = dict(self.body, manifest_hash="0" * 64)
        encoded = canonical(body).decode("ascii")
        self.corrupt("UPDATE adaptive_prelaunch_custody_receipts SET receipt_json=?,receipt_hash=?",
            (encoded, hashlib.sha256(encoded.encode("ascii")).hexdigest()))
        with self.assertRaises(LifecycleError):
            completion.retire(self.owner)
        self.assert_retained()

    def test_missing_original_job_publication_cannot_be_reconstructed_from_rows(self):
        self.retire_c2()
        self.owner._job_members.clear()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "original_publication_missing"):
            completion.retire(self.owner)
        self.assert_retained()

    def test_missing_original_backing_publication_cannot_be_reconstructed_from_rows(self):
        self.retire_c2()
        self.owner._backing_members.clear()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "original_publication_missing"):
            completion.retire(self.owner)
        self.assert_retained()

    def test_actual_reserved_cancel_before_prepare_releases_without_job_or_custody_receipt(self):
        proof = self.retire_before_prepare()
        completed = completion.retire(self.owner)
        record = completed.snapshot()
        self.assertEqual(record["schema_version"], completion.HOST_VERSION)
        self.assertEqual(record["host_rows"][ledger.JOBS_TABLE], [])
        self.assertEqual(len(record["backing_rows"]), 1)
        custody, = record["isolated_custody"]
        self.assertEqual(custody["member_id"], self.member.member_id)
        self.assertEqual(custody["admission_retirement"], proof)
        self.assertEqual(len(custody["terminal_row_sha256"]), 64)
        self.assertEqual(len(custody["archive_sha256"]), 64)
        self.assertEqual(custody["local_link_sha256"], self.local_link()["link_sha256"])
        self.assertTrue(self.coordinator.release_experiment(self.prepare_release(completed))["released"])
        self.assertTrue(self.demand._closed)

    def test_reserved_cancel_without_authenticated_admission_proof_keeps_capacity(self):
        self.retire_before_prepare(include_proof=False)
        with self.assertRaisesRegex(completion.ProductionCompletionError, "authenticated_job_retirement_required"):
            completion.retire(self.owner)
        self.assert_retained()

    def test_reserved_cancel_rejects_changed_actual_revision_or_archive(self):
        proof = self.retire_before_prepare()
        cases = (
            ("revision", "UPDATE managed_executions SET state_revision=state_revision+1", (),
             "UPDATE managed_executions SET state_revision=?", (proof["state_revision"],)),
            ("archive", "UPDATE executions SET outcome='fixture_changed_cancellation'", (),
             "UPDATE executions SET outcome='managed_cancelled_before_start'", ()),
        )
        for label, corrupt, arguments, restore, original in cases:
            with self.subTest(changed=label):
                self.corrupt(corrupt, arguments)
                try:
                    with self.assertRaisesRegex(completion.ProductionCompletionError,
                                                "unused_admission_terminal_changed"):
                        completion.retire(self.owner)
                    self.assert_retained()
                finally:
                    self.corrupt(restore, original)

    def test_completed_history_rejects_rehashed_actual_local_link_change(self):
        self.retire_before_prepare()
        completed = completion.retire(self.owner)
        original = self.local_link()
        changed = dict(original, config_digest="0" * 64)
        changed["link_sha256"] = local_backing._digest(changed)
        self.assertNotEqual(changed["link_sha256"], original["link_sha256"])
        # Isolated corruption fixture: restore the exact immutable trigger
        # before verification so missing-schema detection is not the oracle.
        guard = local_backing.PREFIX + "update"
        with closing(sqlite3.connect(self.fx.isolated)) as conn:
            conn.execute("DROP TRIGGER " + guard)
            conn.execute("UPDATE " + local_backing.TABLE + " SET config_digest=?,link_sha256=? WHERE execution_id=?",
                (changed["config_digest"], changed["link_sha256"], self.snapshot.execution_id))
            conn.execute(local_backing.GUARDS[guard])
            conn.commit()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "isolated_partition_changed"):
            completed.revalidate_isolated_history()
        self.assert_retained()


if __name__ == "__main__":
    unittest.main()
