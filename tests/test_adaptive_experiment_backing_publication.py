"""Connected parent publication in real SQLite, with portable native fixtures.

The actual scope, retained CreationAttempt, actor/member publication, accepted
child protocol and backing service are composed here. Only process creation,
identity, POLICY and source readiness are explicit fixture providers; this is
not Windows capability, admission capacity or aggregate-provider evidence.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import admission
from sentinel.adaptive import experiment_backing_transport as transport
from sentinel.adaptive import experiment_host_backing as backing
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive import identity
from sentinel.adaptive.contracts import Priority, ProcessIdentity, ResourceDemand, Role
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_experiment_host_creation as creation_fixture
from tests import test_adaptive_experiment_host_scope as scope_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests.test_adaptive_coordinator import CONFIG, NOW, status
from tests.test_adaptive_ipc import Clock, Listener, canonical, wire_frame


class ExperimentBackingPublicationTests(unittest.TestCase):
    def setUp(self):
        self.host = scope_fixture.ProductionExperimentScopeTests()
        self.host.MEMBER_ROLES = ("wrapper", "workload", "workload")
        self.host.MEMBER_DEMAND = ResourceDemand(.1, 64 << 20, 64 << 20, 0)
        self.addCleanup(self.host.doCleanups)
        self.host.setUp()
        self.host.proof.revalidate_scoped_readiness.return_value = None
        self.owner = self.host.prepare()
        self.wrapper, self.member, self.other = self.host.members
        self.owner.reserve_member(self.member)
        self.owner.reserve_member(self.other)
        parent = self.owner.process.identity
        self.child_identity = ProcessIdentity(parent.pid + 37,
            parent.created_filetime_100ns + 113, parent.logon_id)
        self.created_backend = creation_fixture.IdentityBackend()
        self.created_backend.value = self.child_identity
        self.native_creates = []

        def create(*arguments):
            attempt = self.owner._attempts[self.wrapper.member_id]
            self.assertIs(arguments[-1]._obj, attempt._info_original)
            self.assertIs(arguments[1], attempt._buffer_original)
            self.native_creates.append(attempt)
            output = arguments[-1]._obj
            output.hProcess, output.hThread = 800, 801
            output.dwProcessId, output.dwThreadId = self.child_identity.pid, 902
            return 1

        def native_init(backend):
            self.assertIn(self.wrapper.member_id, self.owner._attempts)
            backend.kernel = SimpleNamespace(CreateProcessW=create)

        # Fixed source bootstrap is a named fixture seam. All scope and native
        # acquisition/retention gates, publication and identity checks are real.
        command = creation.ChildCommand(str(Path(sys._base_executable).resolve()),
            ("-I", "fixture-inert-child.py"), str(self.host.fixture.scope))
        with patch.object(self.owner, "_inert_command", return_value=command), \
                patch.object(creation._NativeCreation, "__init__", native_init), \
                patch.object(identity, "_backend", return_value=self.created_backend):
            self.created = self.owner.create_actor(self.wrapper)
        self.addCleanup(self.created.process.close)
        self.registration = self.owner.child_registration(self.created,
            permitted_member_ids=tuple(sorted((self.member.member_id, self.other.member_id))))
        self.manifest = self.registration.manifest
        self.endpoint = self.manifest.endpoint
        self.io_events = []
        self.original_native_queries = []
        for backend in (self.host.backend, self.created_backend):
            for name in ("wait", "identity"):
                method = getattr(backend, name)
                def query(*args, _method=method, _name=name, **kwargs):
                    self.assertIsNone(self.owner._active_sql, "native query inside SQL")
                    self.original_native_queries.append(_name)
                    return _method(*args, **kwargs)
                override = patch.object(backend, name, query)
                override.start()
                self.addCleanup(override.stop)
        for override in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=Clock()),
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False)):
            override.start()
            self.addCleanup(override.stop)
        self.child_service = child.ExperimentChildService(self.endpoint, self.owner)
        bind = child.BindExperimentChildRequest(self.manifest)
        self.bind_pipe = self.protocol_pipe(bind, family="Child")
        self.child_service.serve_once(Listener(self.endpoint, self.bind_pipe))
        self.assertIs(self.owner._accepted_children[bind.request_id], self.registration)
        self.context, snapshot = self.context_snapshot()
        self.snapshot = snapshot
        self.request = transport.PublishExperimentBackingRequest(self.manifest, str(uuid4()),
            self.member.member_id, uuid4().hex,
            transport.AdmissionSnapshotObservation.from_snapshot(snapshot))
        self.service = transport.ExperimentBackingService(self.endpoint, self.owner)
        self.peer_backend = pipe_fixture.Backend(self.child_identity)
        self.peer = VerifiedProcess(self.peer_backend, 61, self.child_identity)
        self.addCleanup(self.peer.close)
        self.isolated_policy = FixturePolicyProvider(parent.logon_id)
        self.isolated_coordinator = Coordinator(self.host.isolated.parent,
            db_path=self.host.isolated, policy_provider=self.isolated_policy)
        self.io_events.clear()

    def context_snapshot(self):
        backend = pipe_fixture.Backend(self.child_identity)
        process = VerifiedProcess(backend, 51, self.child_identity)
        with patch.object(admission.VerifiedProcess, "current", return_value=process), \
                patch.object(admission.os, "getpid", return_value=self.child_identity.pid):
            context = admission.ManagedAdmission.current(command="private-publication-command",
                cwd=str(self.host.fixture.scope), repo_identifier="publication-fixture",
                requested=self.member.requested, role=Role.BACKGROUND, priority=Priority.P2)
            snapshot = context.snapshot()
        self.addCleanup(context.close)
        return context, snapshot

    def assert_sql_settled(self):
        self.assertIsNone(self.owner._active_sql)
        self.assertIsNone(self.owner._guard)
        self.assertFalse(self.owner._guard_unknown)
        self.assertIsNone(self.owner._scope_cleanup_error)
        self.assertFalse(self.host.fixture.fixture.policy.active)
        self.assertTrue(all(attempt.closed and not attempt.close_unknown and not attempt.rollback_unknown
                            for attempt in self.owner._sql_attempts))

    def protocol_pipe(self, request, *, family="Backing", fail_result=None, invalid_proof=False):
        """Completed transfers; challenge/receipt MACs are independently encoded."""
        domain = "experiment-" + family.lower() + "-ipc"
        state = {}
        def mac(purpose, result=None):
            value = dict(domain="ResourceSentinel/" + domain + "/v1/" + purpose,
                         request=request.to_dict(), challenge=state["challenge"])
            if purpose != "proof":
                value["result"] = result
            return hmac.new(self.registration.auth_key, canonical(value), hashlib.sha256).hexdigest()

        def io_boundary(connection, label):
            self.assert_sql_settled()
            self.io_events.append(label)

        def write(connection, message):
            io_boundary(connection, message["kind"])
            if message["kind"] == "Experiment" + family + "Challenge":
                state["challenge"] = message
                connection.enqueue(dict(version=1, kind="Experiment" + family + "Proof",
                    request_id=request.request_id, nonce=message["nonce"],
                    mac="0" * 64 if invalid_proof else mac("proof")))
            elif message["kind"] == "Experiment" + family + "Result":
                self.assertEqual(message["mac"], mac("result", message["result"]))
                if fail_result is not None:
                    raise fail_result
                connection.enqueue(dict(version=1, kind="Experiment" + family + "Receipt",
                    request_id=request.request_id, nonce=message["nonce"],
                    mac=mac("receipt", message["result"])))

        hello = dict(version=1, kind="Experiment" + family + "Hello",
                     request_id=request.request_id, caller=self.child_identity.to_dict())
        return pipe_fixture.Pipe(self.child_identity, wire_frame(hello) + wire_frame(request.to_dict()),
            on_write=write, on_read=lambda conn, size: io_boundary(conn, "read"))

    def serve(self, request=None, **kwargs):
        connection = self.protocol_pipe(request or self.request, **kwargs)
        self.service.serve_once(Listener(self.endpoint, connection))
        self.assertTrue(connection.closed)
        self.assertEqual(connection.backend.closed, [71])
        self.assertFalse(self.service.attempts[-1].cleanup_pending)
        self.assert_sql_settled()
        return connection

    def publish_parent(self, request=None):
        request = self.request if request is None else request
        return self.owner._publish_transport_backing(request, self.peer, self.registration)

    def rows(self, path, table):
        with closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
                return []
            return [dict(row) for row in conn.execute("SELECT * FROM " + table)]

    def backing_rows(self):
        return self.rows(self.owner.demand.ledger_path, backing.TABLE)

    def revision(self):
        return self.rows(self.owner.demand.ledger_path, "adaptive_runtime")[0]["registry_revision"]

    def entry(self):
        value = self.owner._backing_publications[self.request.request_id]
        self.assertIs(self.owner._backing_members[self.member.member_id], value)
        self.assertIs(value.snapshot, value.request.observation.parent_snapshot)
        self.assertIs(value.operation, self.owner.registered_scope._backings[self.member.member_id])
        self.assertIs(value.operation._snapshot, value.snapshot)
        self.assertIs(value.registration, self.registration)
        return value

    @contextmanager
    def daily_writer_fault(self, *, commit_error=None, close_error=None):
        actual_connect = sqlite3.connect
        writer_connections = []
        test = self
        class Connection(sqlite3.Connection):
            def commit(conn):
                super().commit()
                if commit_error is not None:
                    raise commit_error

            def close(conn):
                conn.fixture_close_calls = getattr(conn, "fixture_close_calls", 0) + 1
                super().close()
                if close_error is not None:
                    raise close_error

        def connect(path, *args, **kwargs):
            attempt = test.owner._active_sql
            if (path == test.owner.demand.ledger_path.as_uri() + "?mode=rw" and
                    attempt is not None and attempt.write):
                kwargs["factory"] = Connection
                conn = actual_connect(path, *args, **kwargs)
                writer_connections.append(conn)
                return conn
            return actual_connect(path, *args, **kwargs)

        with patch.object(scopes.sqlite3, "connect", side_effect=connect):
            yield writer_connections

    @contextmanager
    def expired_daily_consumer(self):
        original = self.owner._sql_owned
        expiry = self.host.fixture.rows("reservations")[0]["expires_at"]
        @contextmanager
        def expired(path, **kwargs):
            with original(path, **kwargs) as conn:
                if path == self.owner.demand.ledger_path:
                    conn.create_function("julianday", 1, lambda _: (expiry + 1) / 86400 + 2440587.5)
                yield conn
        with patch.object(self.owner, "_sql_owned", expired):
            yield expiry

    def set_hold(self):
        conn = self.host.fixture.fixture.conn()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
        conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',"
            "hold_reason='reservation_expired',state_revision=state_revision+1 WHERE execution_id=?",
            (self.owner.demand._snapshot.execution_id,))

    def test_actual_service_publishes_one_intent_after_real_creation_and_accepted_child(self):
        floor = self.host.fixture.assert_retained(self.owner.demand)
        isolated = self.host.isolated.read_bytes()
        connection = self.serve()
        entry = self.entry()
        self.assertIsNot(entry.request, self.request)  # first exact decoded parent original
        self.assertEqual(entry.request.to_dict(), self.request.to_dict())
        self.assertIsNot(entry.snapshot, self.snapshot)
        self.assertEqual(len(self.backing_rows()), 1)
        self.assertEqual(len(self.native_creates), 1)
        self.assertIs(self.native_creates[0], self.created)
        self.assertEqual(self.host.fixture.assert_retained(self.owner.demand), floor)
        self.assertEqual(self.host.isolated.read_bytes(), isolated)
        self.assertTrue(self.original_native_queries)
        result = next(item["result"] for item in connection.writes if item["kind"] == "ExperimentBackingResult")
        self.assertEqual(result["registered_revision"], self.revision())
        self.assertEqual(result["binding"], entry.operation.binding.to_dict())
        encoded = json.dumps(self.backing_rows()) + json.dumps(result)
        for secret in (self.snapshot.ipc_auth_key.hex(), self.snapshot.claim_token_hash,
                       "private-publication-command", self.snapshot.task_id, self.snapshot.session_id):
            self.assertNotIn(secret, encoded)
        self.assertEqual(self.created_backend.closes, [])
        self.assertEqual(self.host.backend.closed, [])
        self.assertFalse(self.created.native_settled)
        self.assertFalse(self.owner.demand._closed)

    def test_invalid_mac_cannot_enter_parent_publication_or_sql(self):
        before = self.revision()
        connection = self.protocol_pipe(self.request, invalid_proof=True)
        with self.assertRaises(transport.ExperimentBackingTransportError) as raised:
            self.service.serve_once(Listener(self.endpoint, connection))
        self.assertIn("authentication_failed", str(raised.exception.original_error))
        self.assertEqual(self.owner._backing_publications, {})
        self.assertEqual(self.owner._backing_members, {})
        self.assertEqual(self.revision(), before)
        self.assertEqual(self.backing_rows(), [])
        self.assertTrue(connection.closed)
        self.assertFalse(self.service.attempts[-1].cleanup_pending)

    def test_unaccepted_child_cannot_prepare_an_operation(self):
        self.owner._accepted_children.pop(self.manifest.request_id)
        with self.assertRaisesRegex(scopes.ProductionScopeError, "accepted_wrapper_child_required"):
            self.publish_parent()
        self.assertEqual(self.owner._backing_publications, {})
        self.assertEqual(self.backing_rows(), [])
        self.assert_sql_settled()

    def test_replaced_original_creation_handle_refuses_before_any_backing_sql(self):
        process = self.created.process
        original = process._handle
        process._handle = original + 1
        try:
            with self.assertRaisesRegex(creation.CreationCustodyError, "identity_owner_changed"):
                self.publish_parent()
        finally:
            process._handle = original
        self.assertEqual(self.owner._backing_publications, {})
        self.assertEqual(self.backing_rows(), [])

    def test_prior_ordinary_isolated_admission_cannot_gain_a_daily_backing(self):
        with patch.object(admission.os, "getpid", return_value=self.child_identity.pid):
            outcome = self.isolated_coordinator.admit_managed(self.context, status(), now=NOW, config=CONFIG)
        self.assertTrue(outcome["allowed"])
        self.assertNotEqual(outcome["reservation_id"], self.request.reservation_id)
        before = self.rows(self.host.isolated, "managed_executions")
        daily = self.host.fixture.assert_retained(self.owner.demand)
        with self.assertRaisesRegex(scopes.ProductionScopeError, "isolated_admission_already_present"):
            self.publish_parent()
        self.assertEqual(self.backing_rows(), [])
        self.assertEqual(self.rows(self.host.isolated, "managed_executions"), before)
        self.assertEqual(self.host.fixture.assert_retained(self.owner.demand), daily)
        self.assertIsNotNone(self.entry().operation)
        self.assert_sql_settled()

    def test_prior_ordinary_isolated_queue_cannot_gain_a_daily_backing(self):
        with patch.object(admission.os, "getpid", return_value=self.child_identity.pid):
            outcome = self.isolated_coordinator.admit_managed(self.context, status(commit=94),
                now=NOW, config=CONFIG)
        self.assertFalse(outcome["allowed"])
        before = self.rows(self.host.isolated, "queue")
        self.assertEqual(len(before), 1)
        with self.assertRaisesRegex(scopes.ProductionScopeError, "isolated_admission_already_present"):
            self.publish_parent()
        self.assertEqual(self.rows(self.host.isolated, "queue"), before)
        self.assertEqual(self.backing_rows(), [])
        self.assertEqual(self.rows(self.host.isolated, "reservations"), [])

    def test_changed_payload_member_or_request_cannot_replace_retained_publication(self):
        self.serve()
        entry = self.entry()
        before, revision = self.backing_rows(), self.revision()
        changed_observation = replace(self.request.observation, binding_hash="e" * 64)
        for changed in (replace(self.request, reservation_id=uuid4().hex),
                        replace(self.request, observation=changed_observation),
                        replace(self.request, member_id=self.other.member_id),
                        replace(self.request, request_id=str(uuid4()))):
            with self.subTest(request=changed.request_id, member=changed.member_id), \
                    self.assertRaises(scopes.ProductionScopeError):
                self.publish_parent(changed)
            self.assertIs(self.entry(), entry)
            self.assertEqual(self.backing_rows(), before)
            self.assertEqual(self.revision(), revision)
        self.assertEqual(len(self.owner._backing_publications), 1)
        self.assertEqual(len(self.owner._backing_members), 1)

    def test_committed_exact_replay_survives_hold_expiry_and_seal_without_new_capacity(self):
        self.serve()
        entry = self.entry()
        original = (entry.request, entry.snapshot, entry.operation, entry.operation._row)
        before, revision = self.backing_rows(), self.revision()
        self.set_hold()
        floor = self.host.fixture.assert_retained(self.owner.demand)
        self.owner.seal_new_work()
        with self.expired_daily_consumer() as expiry:
            self.serve(transport.PublishExperimentBackingRequest.from_dict(self.request.to_dict()))
        self.assertEqual(self.backing_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assertEqual(self.host.fixture.assert_retained(self.owner.demand), floor)
        self.assertEqual(floor[0]["expires_at"], expiry)
        for first, current in zip(original, (entry.request, entry.snapshot, entry.operation, entry.operation._row)):
            self.assertIs(first, current)

    def test_new_backing_under_hold_or_expiry_remains_absent_and_original_is_retained(self):
        before = self.revision()
        with self.expired_daily_consumer(), self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
            self.publish_parent()
        entry = self.entry()
        self.set_hold()
        with self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
            self.publish_parent(transport.PublishExperimentBackingRequest.from_dict(self.request.to_dict()))
        self.assertIs(self.entry(), entry)
        self.assertEqual(self.backing_rows(), [])
        self.assertEqual(self.revision(), before)
        self.owner.seal_new_work()
        with self.assertRaisesRegex(backing.BackingError, "no_new_work"):
            self.publish_parent()
        self.assertEqual(self.backing_rows(), [])
        self.assert_sql_settled()

    def test_seal_before_first_publication_refuses_without_creating_owner(self):
        self.owner.seal_new_work()
        with self.assertRaisesRegex(scopes.ProductionScopeError, "new_backing_request_refused"):
            self.publish_parent()
        self.assertEqual(self.owner._backing_publications, {})
        self.assertEqual(self.owner._backing_members, {})
        self.assertEqual(self.backing_rows(), [])

    def test_preparation_failure_keeps_first_request_and_snapshot_before_any_sql(self):
        error = OSError("fixture_backing_prepare_failed")
        def fail_prepare(**kwargs):
            entry = self.owner._backing_publications[self.request.request_id]
            self.assertIs(entry, self.owner._backing_members[self.member.member_id])
            self.assertIs(entry.request, self.request)
            self.assertIs(entry.snapshot, self.request.observation.parent_snapshot)
            self.assertIs(kwargs["snapshot"], entry.snapshot)
            self.assertIsNone(entry.operation)
            self.assert_sql_settled()
            raise error
        with patch.object(backing.ParentAdmissionBacking, "prepare", side_effect=fail_prepare), \
                self.assertRaises(OSError) as raised:
            self.publish_parent()
        self.assertIs(raised.exception, error)
        entry = self.owner._backing_publications[self.request.request_id]
        snapshot = entry.snapshot
        self.assertEqual(self.backing_rows(), [])
        self.publish_parent(transport.PublishExperimentBackingRequest.from_dict(self.request.to_dict()))
        self.assertIs(self.entry(), entry)
        self.assertIs(entry.snapshot, snapshot)
        self.assertIs(entry.request, self.request)

    def test_real_commit_ack_loss_replays_same_original_operation_and_row(self):
        error = OSError("fixture_real_commit_ack_lost")
        with self.daily_writer_fault(commit_error=error) as connections:
            with self.assertRaises(OSError) as raised:
                self.publish_parent()
        self.assertIs(raised.exception, error)
        self.assertEqual(len(connections), 1)
        attempt = self.owner._sql_attempts[-1]
        self.assertIs(attempt.connection, connections[0])
        self.assertIs(attempt.error, error)
        self.assertTrue(attempt.commit_entered)
        self.assertFalse(attempt.committed)
        self.assertTrue(attempt.closed)
        self.assertFalse(attempt.close_unknown)
        self.assertFalse(attempt.rollback_unknown)
        entry = self.entry()
        snapshot, operation, row = entry.snapshot, entry.operation, entry.operation._row
        before, revision = self.backing_rows(), self.revision()
        self.assertEqual(len(before), 1)
        replay = self.publish_parent(transport.PublishExperimentBackingRequest.from_dict(self.request.to_dict()))
        self.assertIs(self.entry(), entry)
        self.assertIs(entry.snapshot, snapshot)
        self.assertIs(entry.operation, operation)
        self.assertIs(entry.operation._row, row)
        self.assertEqual(replay.binding_sha256, before[0]["binding_sha256"])
        self.assertEqual(self.backing_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assert_sql_settled()

    def test_result_write_loss_reuses_first_decoded_request_and_positive_sql_cleanup(self):
        error = OSError("fixture_result_write_lost")
        connection = self.protocol_pipe(self.request, fail_result=error)
        with self.assertRaises(transport.ExperimentBackingTransportError) as raised:
            self.service.serve_once(Listener(self.endpoint, connection))
        self.assertIs(raised.exception.original_error, error)
        self.assertTrue(connection.closed)
        self.assertFalse(self.service.attempts[-1].cleanup_pending)
        self.assert_sql_settled()
        entry = self.entry()
        request, snapshot, operation = entry.request, entry.snapshot, entry.operation
        before, revision = self.backing_rows(), self.revision()
        self.serve()
        self.assertIs(self.entry(), entry)
        self.assertIs(entry.request, request)
        self.assertIs(entry.snapshot, snapshot)
        self.assertIs(entry.operation, operation)
        self.assertEqual(self.backing_rows(), before)
        self.assertEqual(self.revision(), revision)

    def test_unknown_close_retains_original_sql_owner_and_refuses_replay_without_reclose(self):
        error = OSError("fixture_sql_close_ack_lost")
        with self.daily_writer_fault(close_error=error) as connections:
            with self.assertRaises(OSError) as raised:
                self.publish_parent()
        self.assertIs(raised.exception, error)
        attempt = self.owner._sql_attempts[-1]
        self.assertIs(attempt.connection, connections[0])
        self.assertTrue(attempt.commit_entered)
        self.assertTrue(attempt.committed)
        self.assertFalse(attempt.closed)
        self.assertTrue(attempt.close_unknown)
        entry = self.entry()
        before, revision = self.backing_rows(), self.revision()
        self.assertEqual(len(before), 1)
        self.assertEqual(connections[0].fixture_close_calls, 1)
        with patch.object(self.owner, "_sql", side_effect=AssertionError("unsettled SQL cannot reopen")), \
                self.assertRaisesRegex(scopes.ProductionScopeError, "sql_custody_unsettled"):
            self.publish_parent()
        self.assertIs(self.entry(), entry)
        self.assertEqual(self.backing_rows(), before)
        self.assertEqual(self.revision(), revision)
        self.assertFalse(attempt.closed)
        self.assertTrue(attempt.close_unknown)
        self.assertEqual(connections[0].fixture_close_calls, 1)

    def test_commit_and_close_ack_loss_keep_primary_and_cleanup_errors_on_same_owner(self):
        primary, cleanup = OSError("fixture_commit_ack_lost"), OSError("fixture_close_ack_lost")
        with self.daily_writer_fault(commit_error=primary, close_error=cleanup) as connections:
            with self.assertRaises(OSError) as raised:
                self.publish_parent()
        self.assertIs(raised.exception, primary)
        self.assertIs(primary.production_scope_close_error, cleanup)
        self.assertIs(primary.production_scope_owner, self.owner)
        self.assertIs(cleanup.production_scope_owner, self.owner)
        attempt = self.owner._sql_attempts[-1]
        self.assertIs(attempt.connection, connections[0])
        self.assertIs(attempt.error, primary)
        self.assertTrue(attempt.close_unknown)
        self.assertFalse(attempt.closed)
        self.assertEqual(len(self.backing_rows()), 1)
        self.assertIsNotNone(self.entry().operation)


if __name__ == "__main__":
    unittest.main()
