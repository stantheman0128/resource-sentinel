"""Original parent Job publication over real daily and isolated SQLite.

The scope, actor creation custody, authenticated child/backing handshakes and
partition admission are production implementations. Native creation, identity,
POLICY and source readiness are explicit portable fixtures; no Windows Job is
created and these tests are not native launch, recovery or capacity evidence.
"""
from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import admission
from sentinel.adaptive import experiment_backing_transport as backing_transport
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive import experiment_job_publication as jobs
from sentinel.adaptive import experiment_partition_admission as partition
from sentinel.adaptive import identity
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_experiment_backing_publication as backing_fixture
from tests import test_adaptive_experiment_host_creation as creation_fixture
from tests import test_adaptive_experiment_host_scope as scope_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests.test_adaptive_ipc import Clock, Listener, wire_frame


class ExperimentJobParentTests(unittest.TestCase):
    # Reuse only fixture utilities, not another suite's test methods.
    rows = backing_fixture.ExperimentBackingPublicationTests.rows
    revision = backing_fixture.ExperimentBackingPublicationTests.revision
    daily_writer_fault = backing_fixture.ExperimentBackingPublicationTests.daily_writer_fault
    context_snapshot = backing_fixture.ExperimentBackingPublicationTests.context_snapshot
    protocol_pipe = backing_fixture.ExperimentBackingPublicationTests.protocol_pipe

    def setUp(self):
        self.host = scope_fixture.ProductionExperimentScopeTests()
        self.host.MEMBER_ROLES = ("wrapper", "guardian", "workload", "workload")
        self.host.MEMBER_DEMAND = ResourceDemand(.1, 64 << 20, 64 << 20, 0)
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.host.proof.revalidate_scoped_readiness.return_value = None
        self.owner = self.host.prepare()
        self.wrapper, self.guardian, self.member, self.other = self.host.members
        self.owner.reserve_member(self.member)
        self.owner.reserve_member(self.other)
        self.io_events, self.native_creates = [], []
        for override in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()),
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False)):
            override.start()
            self.addCleanup(override.stop)
        self.wrapper_created = self.create_actor(self.wrapper, 113)
        self.guardian_created = self.create_actor(self.guardian, 227)
        self.wrapper_registration = self.owner.child_registration(self.wrapper_created,
            permitted_member_ids=(self.member.member_id,))
        self.guardian_registration = self.owner.child_registration(self.guardian_created,
            permitted_member_ids=tuple(sorted((self.member.member_id, self.other.member_id))))
        self.endpoint = self.wrapper_registration.manifest.endpoint
        self.child_service = child.ExperimentChildService(self.endpoint, self.owner)
        self.select_actor(self.wrapper_registration)
        wrapper_wire = self.accept_actor()
        self.context, self.snapshot = self.context_snapshot()
        self.reservation_id = uuid4().hex
        backing_request = backing_transport.PublishExperimentBackingRequest(self.manifest, str(uuid4()),
            self.member.member_id, self.reservation_id,
            backing_transport.AdmissionSnapshotObservation.from_snapshot(self.snapshot))
        service = backing_transport.ExperimentBackingService(self.endpoint, self.owner)
        service.serve_once(Listener(self.endpoint, self.protocol_pipe(backing_request)))
        self.wrapper_binding = self.bind_wrapper(wrapper_wire)

        self.isolated_policy = FixturePolicyProvider(self.child_identity.logon_id)
        self.isolated_coordinator = Coordinator(self.host.isolated.parent,
            db_path=self.host.isolated, policy_provider=self.isolated_policy)
        # Bind the fixture's isolated POLICY identity to the already declared
        # ledger. This is setup, not an admission/Job publication substitute.
        with closing(sqlite3.connect(self.host.isolated, isolation_level=None)) as conn:
            conn.execute("UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?,"
                "policy_binding_initialized=1 WHERE singleton=1",
                (self.owner.spec.isolated_policy_instance_id, self.child_identity.logon_id))
        proof = SimpleNamespace(
            readiness_scopes=partition.daily_generation.readiness_scopes,
            revalidate_transaction=partition.daily_generation.revalidate_transaction,
            read_generation=lambda conn: dict(self.host.fixture.generation),
            revalidate_scoped_readiness=lambda *args, **kwargs: None)
        override = patch.object(partition, "daily_generation", proof)
        override.start()
        self.addCleanup(override.stop)
        self.adapter = partition.ExperimentPartitionCoordinator(self.isolated_coordinator,
            self.wrapper_binding, member_id=self.member.member_id,
            reservation_id=self.reservation_id, daily_store=self.owner.daily_store)
        self.assertTrue(self.adapter.admit_managed(self.context)["allowed"])
        self.assertEqual(len(self.rows(self.host.isolated, "managed_executions")), 1)

        self.select_actor(self.guardian_registration)
        self.accept_actor()
        nonce = uuid4().hex
        self.request = jobs.PublishExperimentJobRequest(self.manifest, str(uuid4()), self.member.member_id,
            self.wrapper.member_id, self.snapshot.execution_id, self.reservation_id, self.snapshot.spec_hash,
            "fixture-guardian-epoch", "Local\\ResourceSentinel.Job." + self.snapshot.execution_id + "." + nonce,
            nonce, "a" * 64)
        self.service = jobs.ExperimentJobService(self.endpoint, self.owner)
        self.peer = VerifiedProcess(pipe_fixture.Backend(self.child_identity), 61, self.child_identity)
        self.addCleanup(self.peer.close)
        self.floor = self.host.fixture.assert_retained(self.owner.demand)
        self.isolated_before = {name: self.rows(self.host.isolated, name)
            for name in ("reservations", "managed_executions")}
        self.io_events.clear()

    def create_actor(self, member, offset):
        parent = self.owner.process.identity
        # Synthetic identities deliberately share this test process's PID, so
        # client/current-owner gates run unchanged; their start times differ.
        expected = ProcessIdentity(parent.pid, parent.created_filetime_100ns + offset, parent.logon_id)
        backend = creation_fixture.IdentityBackend()
        backend.value = expected

        def create(*arguments):
            attempt = self.owner._attempts[member.member_id]
            self.assertIs(arguments[-1]._obj, attempt._info_original)
            self.assertIs(arguments[1], attempt._buffer_original)
            self.assertIsNone(self.owner._active_sql)
            self.native_creates.append(attempt)
            output = arguments[-1]._obj
            output.hProcess, output.hThread = 800 + offset, 801 + offset
            output.dwProcessId, output.dwThreadId = expected.pid, 902 + offset
            return 1

        def native_init(native):
            native.kernel = SimpleNamespace(CreateProcessW=create)

        command = creation.ChildCommand(str(Path(sys._base_executable).resolve()),
            ("-I", "fixture-inert-child.py"), str(self.host.fixture.scope))
        with patch.object(self.owner, "_inert_command", return_value=command), \
                patch.object(creation._NativeCreation, "__init__", native_init), \
                patch.object(identity, "_backend", return_value=backend):
            result = self.owner.create_actor(member)
        self.addCleanup(result.process.close)
        return result

    def select_actor(self, registration):
        self.registration = registration
        self.manifest = registration.manifest
        self.child_identity = self.manifest.child_identity

    def accept_actor(self):
        request = child.BindExperimentChildRequest(self.manifest)
        connection = self.protocol_pipe(request, family="Child")
        self.child_service.serve_once(Listener(self.endpoint, connection))
        self.assertIs(self.owner._accepted_children[request.request_id], self.registration)
        return connection

    def bind_wrapper(self, server_connection):
        client = child.ExperimentChildClient(self.wrapper_registration, self.wrapper_created.process)
        messages = [message for message in server_connection.writes
            if message["kind"] in ("ExperimentChildChallenge", "ExperimentChildResult")]
        self.assertEqual(len(messages), 2)
        connection = pipe_fixture.Pipe(self.endpoint.server_identity, b"".join(wire_frame(m) for m in messages))
        with patch.object(child.NativePipeConnection, "connect", return_value=connection):
            binding = client.bind()
        self.addCleanup(child._ORIGINAL_CLIENTS.pop, client._request_key, None)
        self.addCleanup(binding.close)
        return binding

    def assert_sql_settled(self):
        backing_fixture.ExperimentBackingPublicationTests.assert_sql_settled(self)
        if hasattr(self, "isolated_policy"):
            self.assertFalse(self.isolated_policy.active)
        if hasattr(self, "adapter"):
            self.assertEqual(self.adapter._daily_reads, [])
            self.assertIsNone(self.adapter._daily_guard)

    def serve(self, request=None, **kwargs):
        connection = self.protocol_pipe(request or self.request, family="Job", **kwargs)
        self.service.serve_once(Listener(self.endpoint, connection))
        self.assertTrue(connection.closed)
        self.assertFalse(self.service.attempts[-1].cleanup_pending)
        self.assert_sql_settled()
        return connection

    def publish_parent(self, request=None, *, peer=None, registration=None):
        return self.owner._publish_transport_job(request or self.request, peer or self.peer,
            registration or self.registration)

    def job_rows(self):
        return self.rows(self.owner.demand.ledger_path, ledger.JOBS_TABLE)

    def entry(self):
        value = self.owner._job_publications[self.request.request_id]
        self.assertIs(value, self.owner._job_members[self.member.member_id])
        self.assertIs(value.registration, self.registration)
        return value

    def assert_capacity_retained(self):
        self.assertEqual(self.host.fixture.assert_retained(self.owner.demand), self.floor)
        for table, before in self.isolated_before.items():
            self.assertEqual(self.rows(self.host.isolated, table), before)
        self.assertFalse(self.owner.demand._closed)

    def test_service_publishes_exact_job_intent_without_locks_at_any_wire_boundary(self):
        connection = self.serve()
        entry = self.entry()
        self.assertEqual(len(self.job_rows()), 1)
        row = self.job_rows()[0]
        for field in ledger.JobBinding.__dataclass_fields__:
            self.assertEqual(row[field], getattr(self.request.job_binding(), field))
        self.assertIs(self.owner.registered_scope._jobs[self.member.member_id][0], entry.binding)
        self.assertIsNot(entry.request, self.request)
        self.assertEqual(entry.request.to_dict(), self.request.to_dict())
        result = next(item["result"] for item in connection.writes if item["kind"] == "ExperimentJobResult")
        self.assertEqual(result["registered_revision"], self.revision())
        self.assertGreater(len(self.io_events), 4)
        self.assertEqual(len(self.native_creates), 2)  # inert actors only, no Job
        self.assert_capacity_retained()

    def test_result_ack_loss_replays_same_parent_entry_binding_and_revision(self):
        error = OSError("fixture_job_result_ack_lost")
        connection = self.protocol_pipe(self.request, family="Job", fail_result=error)
        with self.assertRaises(jobs.ExperimentJobPublicationError) as raised:
            self.service.serve_once(Listener(self.endpoint, connection))
        self.assertIs(raised.exception.original_error, error)
        self.assertTrue(connection.closed)
        self.assertFalse(self.service.attempts[-1].cleanup_pending)
        entry = self.entry()
        request, binding = entry.request, entry.binding
        before, revision = self.job_rows(), self.revision()
        self.serve(jobs.PublishExperimentJobRequest.from_dict(self.request.to_dict()))
        self.assertIs(self.entry(), entry)
        self.assertIs(entry.request, request)
        self.assertIs(entry.binding, binding)
        self.assertEqual(self.job_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assert_capacity_retained()

    def test_real_commit_ack_loss_reuses_original_job_publication(self):
        error = OSError("fixture_job_commit_ack_lost")
        with self.daily_writer_fault(commit_error=error) as connections:
            with self.assertRaises(OSError) as raised:
                self.publish_parent()
        self.assertIs(raised.exception, error)
        self.assertEqual(len(connections), 1)
        attempt = self.owner._sql_attempts[-1]
        self.assertTrue(attempt.commit_entered)
        self.assertFalse(attempt.committed)
        self.assertTrue(attempt.closed)
        entry = self.entry()
        binding, before, revision = entry.binding, self.job_rows(), self.revision()
        self.assertEqual(len(before), 1)
        result = self.publish_parent(jobs.PublishExperimentJobRequest.from_dict(self.request.to_dict()))
        self.assertIs(self.entry(), entry)
        self.assertIs(entry.binding, binding)
        self.assertEqual(result["registered_revision"], before[0]["registered_revision"])
        self.assertEqual(self.job_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assert_capacity_retained()

    def test_changed_name_nonce_request_or_backing_cannot_replace_first_publication(self):
        self.publish_parent()
        entry, before, revision = self.entry(), self.job_rows(), self.revision()
        nonce = uuid4().hex
        alternatives = (
            replace(self.request, creation_nonce=nonce,
                job_name="Local\\ResourceSentinel.Job." + self.snapshot.execution_id + "." + nonce),
            replace(self.request, request_id=str(uuid4())),
            replace(self.request, reservation_id=uuid4().hex),
            replace(self.request, spec_hash="e" * 64),
            replace(self.request, launch_payload_sha256="f" * 64),
            replace(self.request, guardian_epoch="different-guardian-epoch"),
        )
        for changed in alternatives:
            with self.subTest(changed=changed), self.assertRaises(jobs.ExperimentJobPublicationError):
                self.publish_parent(changed)
            self.assertIs(self.entry(), entry)
            self.assertEqual(self.job_rows(), before)
            self.assertEqual(self.revision(), revision)
        self.assertEqual(len(self.owner._job_publications), 1)
        self.assert_capacity_retained()

    def test_inconsistent_name_or_nonce_is_rejected_before_publication(self):
        for values in ({"job_name": "Local\\ResourceSentinel.Job.someone-else"},
                       {"creation_nonce": uuid4().hex}):
            with self.subTest(values=values), self.assertRaises(ledger.HostLedgerError):
                replace(self.request, **values)
        self.assertEqual(self.owner._job_publications, {})
        self.assertEqual(self.job_rows(), [])
        self.assert_capacity_retained()

    def test_unaccepted_guardian_cannot_publish_an_intent(self):
        self.owner._accepted_children.pop(self.manifest.request_id)
        with self.assertRaisesRegex(jobs.ExperimentJobPublicationError, "accepted_guardian_required"):
            self.publish_parent()
        self.assertEqual(self.owner._job_publications, {})
        self.assertEqual(self.job_rows(), [])
        self.assert_capacity_retained()

    def test_wrong_actor_or_peer_cannot_borrow_guardian_registration(self):
        changed_manifest = replace(self.manifest, actor_member_id=self.wrapper.member_id)
        with self.assertRaisesRegex(scopes.ProductionScopeError, "original_child_registration_required"):
            self.publish_parent(replace(self.request, manifest=changed_manifest))
        wrapper_peer = VerifiedProcess(pipe_fixture.Backend(self.wrapper_created.process.identity),
            62, self.wrapper_created.process.identity)
        self.addCleanup(wrapper_peer.close)
        with self.assertRaisesRegex(scopes.ProductionScopeError, "original_child_unavailable"):
            self.publish_parent(peer=wrapper_peer)
        self.assertEqual(self.owner._job_publications, {})
        self.assertEqual(self.job_rows(), [])
        self.assert_capacity_retained()

    def test_invalid_mac_never_enters_parent_sql_publication(self):
        before = self.revision()
        connection = self.protocol_pipe(self.request, family="Job", invalid_proof=True)
        with self.assertRaises(jobs.ExperimentJobPublicationError) as raised:
            self.service.serve_once(Listener(self.endpoint, connection))
        self.assertIn("authentication_failed", str(raised.exception.original_error))
        self.assertEqual(self.owner._job_publications, {})
        self.assertEqual(self.job_rows(), [])
        self.assertEqual(self.revision(), before)
        self.assert_sql_settled()
        self.assert_capacity_retained()

    def test_sql_close_unknown_keeps_capacity_and_forbids_retry_or_second_close(self):
        error = OSError("fixture_job_sql_close_ack_lost")
        with self.daily_writer_fault(close_error=error) as connections:
            with self.assertRaises(OSError) as raised:
                self.publish_parent()
        self.assertIs(raised.exception, error)
        self.assertEqual(len(connections), 1)
        attempt = self.owner._sql_attempts[-1]
        self.assertIs(attempt.connection, connections[0])
        self.assertTrue(attempt.committed)
        self.assertTrue(attempt.close_unknown)
        self.assertFalse(attempt.closed)
        entry, before, revision = self.entry(), self.job_rows(), self.revision()
        self.assertEqual(len(before), 1)
        with patch.object(self.owner, "_sql", side_effect=AssertionError("unsettled SQL cannot reopen")), \
                self.assertRaisesRegex(scopes.ProductionScopeError, "sql_custody_unsettled"):
            self.publish_parent()
        self.assertIs(self.entry(), entry)
        self.assertEqual(connections[0].fixture_close_calls, 1)
        self.assertEqual(self.job_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assert_capacity_retained()

    def test_seal_before_first_job_refuses_without_creating_publication(self):
        self.owner.seal_new_work()
        with self.assertRaisesRegex(jobs.ExperimentJobPublicationError, "new_job_refused"):
            self.publish_parent()
        self.assertEqual(self.owner._job_publications, {})
        self.assertEqual(self.job_rows(), [])
        self.assert_capacity_retained()


if __name__ == "__main__":
    unittest.main()
