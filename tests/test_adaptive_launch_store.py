"""Authenticated launch-ledger tests with real SQLite and synthetic fences.

These tests do not authenticate a Windows pipe peer or create a native Job.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
import uuid

from sentinel.adaptive import store as store_module
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore, _get_ipc_auth_record
from tests import test_adaptive_managed_admission as admission_fixture


EPOCH = "launch-store-fixture-guardian"


class LaunchEvidence:
    """A retained fixture POLICY and Job lock; no operating-system authority."""

    def __init__(self, case):
        self.case = case
        self.lock = threading.Lock()
        self.active = False
        self.owner = None
        self.events = []
        self.overrides = {}
        self.before_yield = None

    def assert_held(self):
        self.case.assertTrue(self.active)
        self.case.assertTrue(self.lock.locked())
        self.case.assertEqual(self.owner, threading.get_ident())
        self.case.store._policy.assert_held()
        self.case.assertTrue(self.case.policy.active)

    def probe_writer_available(self):
        conn = sqlite3.connect(self.case.coordinator.db_path, timeout=0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        finally:
            conn.close()

    @contextmanager
    def __call__(self, operation, row, caller):
        self.probe_writer_available()
        with self.case.store._publication_scope(caller):
            with self.lock:
                self.active, self.owner = True, threading.get_ident()
                self.events.append(operation + ".enter")
                try:
                    registering = operation == "register_scope"
                    rooted = operation in {"bind_root", "root_exited"}
                    proof = LifecycleEvidence(
                        operation, row["execution_id"], row["state_revision"], "launch-store-proof", caller,
                        guardian_epoch=EPOCH, job_name=self.case.job_name, job_nonce=self.case.job_nonce,
                        job_creation_never_attempted=registering,
                        root=self.case.root if rooted else None,
                        active_process_count=None if registering else (1 if rooted else 0),
                        process_ids=None if registering else ((self.case.root.pid,) if rooted else ()),
                        launch_sealed=rooted, original_cpu_disabled=True,
                        durable_manifest=True, legacy_exclusion=True, root_exited=rooted,
                    )
                    proof = replace(proof, **self.overrides)
                    if self.before_yield is not None:
                        self.before_yield()
                    yield proof
                finally:
                    self.probe_writer_available()
                    self.events.append(operation + ".exit")
                    self.active, self.owner = False, None


class AdaptiveLaunchStoreTests(unittest.TestCase):
    context = admission_fixture.ManagedAdmissionTests.context
    conn = admission_fixture.ManagedAdmissionTests.conn
    admit = admission_fixture.ManagedAdmissionTests.admit

    def setUp(self):
        admission_fixture.ManagedAdmissionTests.setUp(self)
        self.admission = self.context()
        self.snapshot = self.admission.snapshot()
        self.wrapper = self.snapshot.wrapper_identity
        self.root = ProcessIdentity(self.wrapper.pid + 1000,
            self.wrapper.created_filetime_100ns + 1000, self.wrapper.logon_id)
        self.assertTrue(self.admit(self.admission)["allowed"])
        self.execution_id = self.snapshot.execution_id
        self.job_nonce = uuid.uuid4().hex
        self.job_name = f"Local\\ResourceSentinel.Job.{self.execution_id}.{self.job_nonce}"
        self.evidence = LaunchEvidence(self)
        self.store = LifecycleStore(self.coordinator.db_path, evidence_provider=self.evidence,
                                   policy_provider=self.policy, existing_path=True)
        self.auth = _get_ipc_auth_record(self.coordinator.db_path, self.execution_id)
        self.token = None

    def row(self):
        return self.store.query(self.execution_id)

    def custody(self):
        conn = self.conn()
        return {table: tuple(tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in ("adaptive_runtime", "managed_executions", "reservations",
                              "worker_reservations", "adaptive_launch_requests")}

    def register(self, expected_revision=0, **changes):
        args = dict(caller=self.wrapper, expected_revision=expected_revision,
                    guardian_epoch=EPOCH, job_name=self.job_name, job_nonce=self.job_nonce,
                    expected_auth=self.auth)
        args.update(changes)
        return self.store.register_job_scope(self.execution_id, **args)

    def prepare(self, expected_revision=1, **changes):
        args = dict(caller=self.wrapper, expected_revision=expected_revision, expected_auth=self.auth)
        args.update(changes)
        return self.store.mark_prepared(self.execution_id, **args)

    def prepared(self):
        with self.store._publication_scope(self.wrapper):
            self.register()
            return self.prepare()

    def claim_args(self, expected_revision=2):
        if self.token is None:
            self.token = self.admission.launch_claim_token()
        return dict(caller=self.wrapper, expected_revision=expected_revision,
                    guardian_epoch=EPOCH, spec_hash=self.snapshot.spec_hash,
                    claim_token=self.token, expected_auth=self.auth)

    def claimed(self):
        self.prepared()
        with self.store._publication_scope(self.wrapper):
            return self.store.claim_launch_locked(self.execution_id, **self.claim_args())

    def bind(self, expected_revision=3, **changes):
        args = dict(caller=self.wrapper, expected_revision=expected_revision, expected_auth=self.auth)
        args.update(changes)
        return self.store.bind_root(self.execution_id, **args)

    def record(self, operation, request_id=None, payload_hash="a" * 64, **changes):
        args = dict(caller=self.wrapper, expected_auth=self.auth, guardian_epoch=EPOCH)
        args.update(changes)
        return self.store.record_launch_request_locked(self.execution_id, operation,
            request_id or str(uuid.uuid4()), payload_hash, **args)

    def rotate_key(self, key=b"r" * 32):
        self.conn().execute("UPDATE managed_executions SET ipc_auth_key=? WHERE execution_id=?",
                            (key, self.execution_id))

    def damage(self, table, statement, values=()):
        conn = self.conn()
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)).fetchall():
            conn.execute('DROP TRIGGER "' + row[0].replace('"', '""') + '"')
        conn.execute(statement, values)

    @contextmanager
    def audited_writer(self):
        real_connect = sqlite3.connect
        evidence = self.evidence

        class AuditedConnection(sqlite3.Connection):
            def commit(self):
                evidence.assert_held()
                evidence.events.append("commit")
                return super().commit()

            def rollback(self):
                evidence.assert_held()
                evidence.events.append("rollback")
                return super().rollback()

            def close(self):
                evidence.assert_held()
                evidence.events.append("close")
                return super().close()

        def connect(target, *args, **kwargs):
            if evidence.active and isinstance(target, str) and target.endswith("?mode=rw"):
                kwargs["factory"] = AuditedConnection
            return real_connect(target, *args, **kwargs)

        with patch.object(store_module.sqlite3, "connect", side_effect=connect):
            yield

    def test_authenticated_allocation_is_read_only_before_any_job_registration(self):
        before = self.custody()
        real_connect = sqlite3.connect
        opened, statements = [], []
        def connect(target, *args, **kwargs):
            opened.append((target, kwargs.get("uri")))
            conn = real_connect(target, *args, **kwargs)
            conn.set_trace_callback(statements.append)
            return conn
        row = self.row()
        with patch.object(store_module.sqlite3, "connect", side_effect=connect):
            self.assertIsNone(self.store.assert_authenticated_allocation(row, caller=self.wrapper, expected_auth=self.auth))
        self.assertEqual(len(opened), 1)
        self.assertTrue(opened[0][0].endswith("?mode=ro"))
        self.assertIs(opened[0][1], True)
        self.assertFalse(any(sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER")) for sql in statements))
        self.assertEqual(self.evidence.events, [])
        self.assertEqual(before, self.custody())

    def test_authenticated_allocation_rejects_other_caller_stale_key_and_snapshot(self):
        row = self.row()
        for expected, caller, auth in (
            (row, replace(self.wrapper, created_filetime_100ns=self.wrapper.created_filetime_100ns + 1), self.auth),
            (row, self.wrapper, replace(self.auth, ipc_auth_key=b"z" * 32)),
            ({**row, "state_revision": row["state_revision"] + 1}, self.wrapper, self.auth),
            ({**row, "requested_cpu_units": row["requested_cpu_units"] + 1}, self.wrapper, self.auth),
        ):
            with self.subTest(caller=caller, revision=expected["state_revision"]):
                before = self.custody()
                with self.assertRaises(LifecycleError):
                    self.store.assert_authenticated_allocation(expected, caller=caller, expected_auth=auth)
                self.assertEqual(before, self.custody())

    def test_authenticated_allocation_requires_actual_unique_capacity(self):
        row = self.row()
        self.damage("reservations", "DELETE FROM reservations WHERE id=?", (row["reservation_id"],))
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.assert_authenticated_allocation(row, caller=self.wrapper, expected_auth=self.auth)
        self.assertEqual(before, self.custody())

    def test_authenticated_allocation_rejects_a_second_capacity_row_for_execution(self):
        row = self.row()
        duplicate = dict(self.conn().execute("SELECT * FROM reservations WHERE execution_id=?", (self.execution_id,)).fetchone())
        duplicate.update(id=str(uuid.uuid4()), request_key=uuid.uuid4().hex)
        # Model an externally damaged index only in this isolated database.
        self.conn().execute("DROP INDEX idx_reservations_execution")
        self.damage("reservations", "INSERT INTO reservations(" + ",".join(duplicate) + ") VALUES(" +
                    ",".join("?" for _ in duplicate) + ")", tuple(duplicate.values()))
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.assert_authenticated_allocation(row, caller=self.wrapper, expected_auth=self.auth)
        self.assertEqual(before, self.custody())

    def test_register_and_prepare_do_not_export_claim_token(self):
        with patch.object(self.admission, "launch_claim_token", wraps=self.admission.launch_claim_token) as export:
            result = self.prepared()
            export.assert_not_called()
        self.assertEqual(result["state"], "PREPARED")
        self.assertFalse(result["launch_authorized"])
        self.assertEqual((result["job_name"], result["job_nonce"], result["guardian_epoch"]),
                         (self.job_name, self.job_nonce, EPOCH))
        self.assertFalse(self.admission._claim_exported)
        self.assertEqual(self.row()["claim_consumed"], 0)

    def test_register_exact_replay_ack_preserves_record_and_capacity(self):
        with self.store._publication_scope(self.wrapper):
            first = self.register()
            before = self.custody()
            result = self.register()
            self.assertTrue(result["duplicate"])
            self.assertFalse(result["launch_authorized"])
            self.assertEqual(result["state_revision"], first["state_revision"])
            self.assertEqual(before, self.custody())

    def test_prepare_exact_replay_uses_positive_proof_without_second_cas(self):
        self.prepared()
        with self.store._publication_scope(self.wrapper):
            before = self.custody()
            result = self.prepare()
            self.assertTrue(result["duplicate"])
            self.assertFalse(result["launch_authorized"])
            self.assertEqual(before, self.custody())
            self.evidence.overrides = {"active_process_count": 1, "process_ids": (self.root.pid,)}
            with self.assertRaises(LifecycleError):
                self.prepare()
            self.assertEqual(before, self.custody())

    def test_register_replay_rejects_a_different_job_nonce(self):
        with self.store._publication_scope(self.wrapper):
            self.register()
            before = self.custody()
            other = "f" * 32
            with self.assertRaises(LifecycleError):
                self.register(job_nonce=other, job_name=f"Local\\ResourceSentinel.Job.{self.execution_id}.{other}")
            self.assertEqual(before, self.custody())

    def test_auth_rotation_during_each_native_observation_is_rechecked_in_writer_transaction(self):
        with self.store._publication_scope(self.wrapper):
            operations = (self.register, self.prepare,
                lambda: self.store.claim_launch_locked(self.execution_id, **self.claim_args()), self.bind)
            for operation in operations:
                with self.subTest(operation=operation):
                    rotated = []
                    def rotate():
                        self.rotate_key()
                        rotated.append(self.custody())
                    self.evidence.before_yield = rotate
                    with self.assertRaises(LifecycleError):
                        operation()
                    self.assertEqual(len(rotated), 1)
                    self.assertEqual(rotated[0], self.custody())
                    self.rotate_key(self.auth.ipc_auth_key)
                    self.evidence.before_yield = None
                    operation()

    def test_register_duplicate_rejects_rotated_auth_without_repair(self):
        with self.store._publication_scope(self.wrapper):
            self.register()
            self.rotate_key()
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.register()
            self.assertEqual(before, self.custody())

    def test_prepare_duplicate_rejects_rotated_auth_without_repair(self):
        self.prepared()
        with self.store._publication_scope(self.wrapper):
            self.rotate_key()
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.prepare()
            self.assertEqual(before, self.custody())

    def test_claim_duplicates_reject_rotated_auth_on_both_entrypoints(self):
        self.claimed()
        with self.store._publication_scope(self.wrapper):
            self.rotate_key()
            before = self.custody()
            for method in (self.store.claim_launch, self.store.claim_launch_locked):
                with self.subTest(method=method.__name__):
                    with self.assertRaises(LifecycleError):
                        method(self.execution_id, **self.claim_args())
                    self.assertEqual(before, self.custody())

    def test_bind_duplicate_rejects_rotated_auth_without_repair(self):
        self.claimed()
        self.bind()
        with self.store._publication_scope(self.wrapper):
            self.rotate_key()
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.bind()
            self.assertEqual(before, self.custody())

    def test_locked_claim_requires_this_stores_policy_and_raw_claim_token(self):
        self.prepared()
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.claim_launch_locked(self.execution_id, **self.claim_args())
        self.assertEqual(before, self.custody())
        with self.store._publication_scope(self.wrapper):
            before = self.custody()
            for change in ({"claim_token": "x" * 64}, {"guardian_epoch": "other-epoch"},
                           {"caller": replace(self.wrapper, pid=self.wrapper.pid + 1)}):
                with self.subTest(field=next(iter(change))):
                    with self.assertRaises(LifecycleError):
                        self.store.claim_launch_locked(self.execution_id, **(self.claim_args() | change))
                    self.assertEqual(before, self.custody())

    def test_locked_claim_is_one_use_and_duplicate_never_grants_authority(self):
        self.prepared()
        with self.store._publication_scope(self.wrapper):
            first = self.store.claim_launch_locked(self.execution_id, **self.claim_args())
            self.assertTrue(first["launch_authorized"])
            self.assertFalse(first["duplicate"])
            before = self.custody()
            second = self.store.claim_launch_locked(self.execution_id, **self.claim_args())
            self.assertFalse(second["launch_authorized"])
            self.assertTrue(second["duplicate"])
            self.assertEqual(before, self.custody())

    def test_unlocked_consumed_claim_ack_remains_read_only_under_recovery_barrier(self):
        self.claimed()
        self.conn().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        before = self.custody()
        self.evidence.events.clear()
        result = self.store.claim_launch(self.execution_id, **self.claim_args())
        self.assertTrue(result["duplicate"])
        self.assertFalse(result["launch_authorized"])
        self.assertEqual(self.evidence.events, [])
        self.assertEqual(before, self.custody())

    def test_bind_exact_root_replay_preserves_running_draining_and_hold(self):
        self.claimed()
        first = self.bind()
        self.assertEqual(first["state"], "RUNNING")
        with self.store._publication_scope(self.wrapper):
            for state in ("RUNNING", "DRAINING", "UNCERTAIN_HOLD"):
                if state == "DRAINING":
                    current = self.row()
                    self.store.mark_root_exited(self.execution_id, caller=self.wrapper,
                        expected_revision=current["state_revision"], exit_code=0)
                elif state == "UNCERTAIN_HOLD":
                    current = self.row()
                    self.store.hold(self.execution_id, expected_revision=current["state_revision"], reason="heartbeat_lost")
                before = self.custody()
                result = self.bind()
                self.assertTrue(result["duplicate"])
                self.assertFalse(result["launch_authorized"])
                self.assertEqual(result["state"], state)
                self.assertEqual(before, self.custody())

    def test_bind_replay_rejects_different_root_identity_and_missing_allocation(self):
        self.claimed()
        self.bind()
        with self.store._publication_scope(self.wrapper):
            self.evidence.overrides = {"root": replace(self.root, created_filetime_100ns=self.root.created_filetime_100ns + 1)}
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.bind()
            self.assertEqual(before, self.custody())
            self.evidence.overrides = {}
            self.damage("reservations", "DELETE FROM reservations WHERE execution_id=?", (self.execution_id,))
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.bind()
            self.assertEqual(before, self.custody())

    def test_policy_and_job_fences_survive_successful_writer_commit_and_close(self):
        with self.store._publication_scope(self.wrapper):
            operations = (("register_scope", self.register), ("prepare", self.prepare),
                ("claim", lambda: self.store.claim_launch_locked(self.execution_id, **self.claim_args())),
                ("bind_root", self.bind))
            for name, operation in operations:
                with self.subTest(operation=name):
                    self.evidence.events.clear()
                    with self.audited_writer():
                        operation()
                    self.assertEqual(self.evidence.events, [name + ".enter", "commit", "close", name + ".exit"])

    def test_policy_and_job_fences_survive_writer_failure_rollback_and_close(self):
        self.conn().execute("""CREATE TRIGGER fixture_fail_scope BEFORE UPDATE OF job_nonce ON managed_executions
            BEGIN SELECT RAISE(ABORT,'fixture_scope_failure'); END""")
        with self.store._publication_scope(self.wrapper):
            before = self.custody()
            with self.audited_writer():
                with self.assertRaises((LifecycleError, sqlite3.Error)):
                    self.register()
            self.assertEqual(before, self.custody())
            self.assertEqual(self.evidence.events, ["register_scope.enter", "rollback", "close", "register_scope.exit"])

    def test_intent_slots_are_fixed_and_exact_replays_are_read_only(self):
        with self.store._publication_scope(self.wrapper):
            for operation in ("PrepareExecution", "ClaimLaunch", "BindRoot"):
                if operation == "ClaimLaunch":
                    self.register()
                    self.prepare()
                elif operation == "BindRoot":
                    self.store.claim_launch_locked(self.execution_id, **self.claim_args())
                request_id = str(uuid.uuid4())
                before_row = self.row()
                evidence_before = list(self.evidence.events)
                self.assertIs(self.record(operation, request_id), False)
                before = self.custody()
                self.assertIs(self.record(operation, request_id), True)
                self.assertEqual(before, self.custody())
                self.assertEqual(before_row, self.row())
                self.assertEqual(evidence_before, self.evidence.events)
            self.assertEqual(self.conn().execute("SELECT count(*) FROM adaptive_launch_requests WHERE execution_id=?", (self.execution_id,)).fetchone()[0], 3)
            self.assertEqual(self.row()["state"], "LAUNCHING")
            self.assertEqual(self.row()["claim_consumed"], 1)

    def test_intent_rejects_changed_request_payload_epoch_and_global_collision(self):
        request_id = str(uuid.uuid4())
        with self.store._publication_scope(self.wrapper):
            self.record("PrepareExecution", request_id)
            self.register()
            self.prepare()
            before = self.custody()
            attempts = (
                lambda: self.record("PrepareExecution", str(uuid.uuid4())),
                lambda: self.record("PrepareExecution", request_id, "b" * 64),
                lambda: self.record("PrepareExecution", request_id, guardian_epoch="other-epoch"),
                lambda: self.record("ClaimLaunch", request_id),
            )
            for operation in attempts:
                with self.subTest(operation=operation):
                    with self.assertRaises(LifecycleError):
                        operation()
                    self.assertEqual(before, self.custody())

    def test_intent_rejects_global_request_id_reuse_by_another_execution(self):
        other_context = self.context(requested=replace(self.snapshot.requested, io_slots=0))
        self.assertTrue(self.admit(other_context)["allowed"])
        other_snapshot = other_context.snapshot()
        other_auth = _get_ipc_auth_record(self.coordinator.db_path, other_snapshot.execution_id)
        request_id = str(uuid.uuid4())
        with self.store._publication_scope(self.wrapper):
            self.record("PrepareExecution", request_id)
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.store.record_launch_request_locked(other_snapshot.execution_id, "PrepareExecution",
                    request_id, "a" * 64, caller=other_snapshot.wrapper_identity,
                    expected_auth=other_auth, guardian_epoch=EPOCH)
            self.assertEqual(before, self.custody())

    def test_intent_requires_policy_auth_valid_shape_and_actual_capacity(self):
        with self.assertRaises(LifecycleError):
            self.record("PrepareExecution")
        with self.store._publication_scope(self.wrapper):
            before = self.custody()
            for operation, request_id, digest in (("LaunchArbitrary", str(uuid.uuid4()), "a" * 64),
                ("PrepareExecution", "not-a-uuid", "a" * 64),
                ("PrepareExecution", str(uuid.uuid4()), "A" * 64)):
                with self.subTest(operation=operation, request_id=request_id):
                    with self.assertRaises((LifecycleError, ValueError)):
                        self.record(operation, request_id, digest)
                    self.assertEqual(before, self.custody())
            with self.assertRaises(LifecycleError):
                self.record("PrepareExecution", expected_auth=replace(self.auth, ipc_auth_key=b"z" * 32))
            self.assertEqual(before, self.custody())
            self.damage("reservations", "DELETE FROM reservations WHERE execution_id=?", (self.execution_id,))
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.record("PrepareExecution")
            self.assertEqual(before, self.custody())

    def test_intent_table_persists_only_bounded_identity_and_digest_fields(self):
        request_id = str(uuid.uuid4())
        with self.store._publication_scope(self.wrapper):
            self.record("PrepareExecution", request_id)
        record = dict(self.conn().execute("SELECT * FROM adaptive_launch_requests").fetchone())
        self.assertEqual(record["execution_id"], self.execution_id)
        self.assertEqual(record["request_id"], request_id)
        self.assertEqual(record["payload_hash"], "a" * 64)
        self.assertEqual(record["spec_hash"], self.snapshot.spec_hash)
        self.assertEqual(record["guardian_epoch"], EPOCH)
        self.assertFalse(set(record) & {"claim_token", "claim_token_hash", "ipc_auth_key", "command", "command_text", "root_handle"})
        self.assertTrue(all(value is None or type(value) in (str, int) for value in record.values()))
        encoded = json.dumps(record)
        self.assertNotIn(self.admission.launch_claim_token(), encoded)
        self.assertNotIn(self.auth.ipc_auth_key.hex(), encoded)
        self.assertNotIn(admission_fixture.PAYLOAD["command"], encoded)


if __name__ == "__main__":
    unittest.main()
