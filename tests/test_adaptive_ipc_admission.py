"""L1 IPC credential/ledger integration; no pipe, Job, or native ownership proof."""
import base64
from dataclasses import asdict, FrozenInstanceError, replace
import hashlib
import hmac
import json
import os
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.query import query_adaptive
from sentinel.adaptive.store import (
    LifecycleError, LifecycleStore, _get_ipc_auth_record, authenticated_query,
    prelaunch_record_hash,
)
from tests import test_adaptive_managed_admission as fixtures
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import NOW


TRANSCRIPT = b"isolated-ipc-auth-integration-transcript"


class IpcAdmissionTests(unittest.TestCase):
    setUp = fixtures.ManagedAdmissionTests.setUp
    context = fixtures.ManagedAdmissionTests.context
    conn = fixtures.ManagedAdmissionTests.conn
    admit = fixtures.ManagedAdmissionTests.admit
    counts = fixtures.ManagedAdmissionTests.counts

    def admitted(self):
        context = self.context(requested=replace(PAYLOAD["requested"], io_slots=0))
        snapshot = context.snapshot()
        result = self.admit(context)
        self.assertTrue(result["allowed"], result)
        return context, snapshot, result

    def mac(self, context, snapshot, transcript=TRANSCRIPT, **overrides):
        arguments = dict(execution_id=snapshot.execution_id, spec_hash=snapshot.spec_hash,
                         caller=snapshot.wrapper_identity)
        return context._ipc_mac(transcript, **(arguments | overrides))

    def row(self, execution_id):
        return dict(self.conn().execute(
            "SELECT * FROM managed_executions WHERE execution_id=?", (execution_id,)).fetchone())

    def auth(self, snapshot):
        return _get_ipc_auth_record(self.coordinator.db_path, snapshot.execution_id)

    def query(self, snapshot, record=None):
        return authenticated_query(self.coordinator.db_path, snapshot.execution_id,
                                   self.auth(snapshot) if record is None else record)

    def assert_private(self, visible, snapshot, claim_token=None):
        text = visible if isinstance(visible, str) else json.dumps(visible)
        for secret in (repr(snapshot.ipc_auth_key), snapshot.ipc_auth_key.hex(),
                       base64.b64encode(snapshot.ipc_auth_key).decode("ascii")):
            self.assertNotIn(secret, text)
        self.assertNotIn("ipc_auth_key", text)
        if claim_token is not None:
            self.assertNotIn(claim_token, text)

    def test_distinct_query_key_is_atomically_stored_as_exact_blob(self):
        # token_urlsafe also calls token_bytes; the second value is its seed.
        spec_key, ipc_seed, claim_seed = b"s" * 32, b"i" * 32, b"c" * 32
        with patch("sentinel.adaptive.admission.secrets.token_bytes",
                   side_effect=(spec_key, claim_seed, ipc_seed)):
            context = self.context()
        snapshot = context.snapshot()
        self.assertEqual(snapshot.ipc_auth_key, hashlib.sha256(ipc_seed).digest())
        self.assertNotEqual(snapshot.ipc_auth_key, context._key)
        self.assertEqual(context._key, spec_key)
        result = self.admit(context)
        self.assertTrue(result["allowed"])
        row = self.conn().execute(
            "SELECT ipc_auth_key,typeof(ipc_auth_key),length(ipc_auth_key) FROM managed_executions").fetchone()
        self.assertEqual(tuple(row), (snapshot.ipc_auth_key, "blob", 32))
        expected = hmac.new(snapshot.ipc_auth_key, TRANSCRIPT, hashlib.sha256).hexdigest()
        self.assertEqual(self.mac(context, snapshot), expected)
        self.assertNotEqual(expected, hmac.new(spec_key, TRANSCRIPT, hashlib.sha256).hexdigest())

    def test_private_snapshot_and_auth_record_repr_and_generic_json_fail_closed(self):
        context, snapshot, _ = self.admitted()
        record = self.auth(snapshot)
        self.assert_private(repr(context) + repr(snapshot) + repr(record), snapshot)
        self.assertEqual(record.ipc_auth_key, snapshot.ipc_auth_key)
        self.assertEqual(record.wrapper_identity, snapshot.wrapper_identity)
        with self.assertRaises(FrozenInstanceError):
            record.spec_hash = "a" * 64
        for private in (snapshot, record):
            with self.subTest(type=type(private).__name__):
                with self.assertRaisesRegex(TypeError, "bytes is not JSON serializable") as error:
                    json.dumps(asdict(private))
                self.assert_private(str(error.exception), snapshot)

    def test_public_admission_retry_and_queries_exclude_both_credentials(self):
        context, snapshot, admitted = self.admitted()
        token = context._claim_token  # Inspect custody without exporting launch authority.
        public = (admitted, self.admit(context, now=NOW + 1),
                  LifecycleStore(self.coordinator.db_path).query(snapshot.execution_id),
                  query_adaptive(self.coordinator.db_path), self.query(snapshot))
        for result in public:
            with self.subTest(keys=tuple(result)):
                self.assert_private(result, snapshot, token)
                self.assertNotIn("claim_token_hash", json.dumps(result))
        for path in self.directory.glob("*.json"):
            self.assert_private(path.read_text(encoding="utf-8"), snapshot, token)
        self.assertFalse(context._claim_exported)

    def test_lost_admission_ack_replays_same_query_key_without_new_allocation(self):
        context = self.context()
        snapshot = context.snapshot()
        with patch.object(self.coordinator, "_mirror", side_effect=OSError("fixture lost ACK")):
            with self.assertRaisesRegex(OSError, "fixture lost ACK"):
                self.admit(context)
        before = self.row(snapshot.execution_id)
        allocation = dict(self.conn().execute("SELECT * FROM reservations").fetchone())
        with patch("sentinel.adaptive.admission.secrets.token_bytes",
                   side_effect=AssertionError("retry must not mint a key")):
            result = self.admit(context, now=NOW + 1)
        self.assertTrue(result["reused"])
        self.assertEqual(self.row(snapshot.execution_id), before)
        self.assertEqual(before["ipc_auth_key"], snapshot.ipc_auth_key)
        self.assertEqual(dict(self.conn().execute("SELECT * FROM reservations").fetchone()), allocation)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_mac_and_read_query_preserve_unused_claim_cancellation_then_terminal_query(self):
        context, snapshot, admitted = self.admitted()
        original_claim = context._claim_token
        before = self.row(snapshot.execution_id)
        record = self.auth(snapshot)
        with patch.object(context, "launch_claim_token", side_effect=AssertionError("query cannot export claim")):
            first_mac = self.mac(context, snapshot)
            result = self.query(snapshot, record)
        self.assertTrue(result["available"])
        self.assertEqual(self.row(snapshot.execution_id), before)
        self.assertFalse(context._claim_exported)
        self.assertEqual(context._claim_token, original_claim)
        cancelled = context.cancel_reserved(self.coordinator.db_path,
            reservation_id=admitted["reservation_id"], expected_revision=0, now=NOW + 1)
        self.assertTrue(cancelled["cancelled"])
        self.assertTrue(context._cancel_sealed)
        self.assertFalse(context._claim_exported)
        self.assertIsNone(context._claim_token)
        self.assertIsNone(context._key)
        self.assertEqual(self.mac(context, snapshot), first_mac)
        terminal = self.query(snapshot, record)
        self.assertEqual(terminal["executions"][0]["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(terminal["executions"][0]["allocation"]["recorded_binding"], "terminal_allocation_absent")
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assert_private(cancelled, snapshot, original_claim)
        self.assert_private(terminal, snapshot, original_claim)
        context.close()
        self.assertIsNone(context._snapshot)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            self.mac(context, snapshot)

    def test_mac_requires_exact_execution_spec_and_owner_without_exporting_claim(self):
        context = self.context()
        snapshot = context.snapshot()
        for overrides in ({"execution_id": "another-execution"}, {"spec_hash": "b" * 64},
                          {"caller": replace(snapshot.wrapper_identity, pid=snapshot.wrapper_identity.pid + 1)},
                          {"caller": replace(snapshot.wrapper_identity, created_filetime_100ns=snapshot.wrapper_identity.created_filetime_100ns + 1)},
                          {"caller": replace(snapshot.wrapper_identity, logon_id="S-1-5-5-200-300")},
                          {"caller": snapshot.wrapper_identity.to_dict()}):
            with self.subTest(overrides=tuple(overrides)):
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "^ipc_binding_mismatch$") as error:
                    self.mac(context, snapshot, **overrides)
                self.assert_private(str(error.exception), snapshot)
                self.assertFalse(context._claim_exported)
        self.assertEqual(len(self.mac(context, snapshot)), 64)

    def test_mac_revalidates_current_process_alive_and_exact_identity(self):
        context = self.context()
        snapshot = context.snapshot()
        before = self.process.observations
        self.mac(context, snapshot)
        self.assertEqual(self.process.observations, before + 1)
        with patch("sentinel.adaptive.admission.os.getpid", return_value=os.getpid() + 1):
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_is_not_current_process"):
                self.mac(context, snapshot)
        for state in (IdentityStatus.UNKNOWN, IdentityStatus.DEAD):
            self.process.observed = IdentityObservation(
                snapshot.wrapper_identity, state, "query_failed" if state is IdentityStatus.UNKNOWN else None)
            with self.subTest(state=state), self.assertRaisesRegex(
                    ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
                self.mac(context, snapshot)
        self.process.observed = IdentityObservation(
            replace(snapshot.wrapper_identity, created_filetime_100ns=snapshot.wrapper_identity.created_filetime_100ns + 1),
            IdentityStatus.ALIVE)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_mismatch"):
            self.mac(context, snapshot)
        self.assertFalse(context._claim_exported)

    def test_mac_rejects_empty_nonbytes_or_oversize_transcript_without_secret_diagnostics(self):
        context = self.context()
        snapshot = context.snapshot()
        for transcript in (b"", "private-payload-marker", bytearray(b"private-payload-marker"),
                           memoryview(b"private-payload-marker"), b"x" * (256 * 1024 + 1)):
            with self.subTest(type=type(transcript).__name__, length=len(transcript)):
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "^invalid_ipc_transcript$") as error:
                    self.mac(context, snapshot, transcript)
                self.assert_private(str(error.exception), snapshot)
                self.assertNotIn("private-payload-marker", str(error.exception))
        self.assertEqual(len(self.mac(context, snapshot, b"x" * (256 * 1024))), 64)
        self.assertFalse(context._claim_exported)

    def test_authenticated_query_returns_only_its_exact_execution_without_mutation(self):
        _, snapshot, _ = self.admitted()
        _, other, _ = self.admitted()
        before = self.row(snapshot.execution_id)
        result = self.query(snapshot)
        self.assertTrue(result["available"])
        self.assertEqual([row["execution_id"] for row in result["executions"]], [snapshot.execution_id])
        self.assertNotIn(other.execution_id, json.dumps(result))
        self.assertFalse(result["control_writes"])
        self.assertEqual(result["native_readiness"], "unverified")
        self.assertEqual(self.row(snapshot.execution_id), before)

    def test_authenticated_query_uses_one_read_only_transaction_and_no_migration(self):
        _, snapshot, _ = self.admitted()
        record = self.auth(snapshot)
        statements, opened = [], []
        connect = sqlite3.connect

        def traced_connect(*args, **kwargs):
            self.assertTrue(kwargs.get("uri"))
            self.assertIn("mode=ro", args[0])
            conn = connect(*args, **kwargs)
            conn.set_trace_callback(statements.append)
            opened.append(conn)
            return conn

        with patch("sentinel.adaptive.store.sqlite3.connect", side_effect=traced_connect), \
                patch("sentinel.adaptive.store.migrate_schema", side_effect=AssertionError("query must not migrate")), \
                patch("sentinel.adaptive.store.LifecycleStore", side_effect=AssertionError("query must not construct store")):
            self.assertTrue(self.query(snapshot, record)["available"])
        self.assertEqual(len(opened), 1)
        sql = [statement.strip().upper() for statement in statements]
        self.assertEqual(sql.count("BEGIN"), 1)
        self.assertTrue(any("IPC_AUTH_KEY" in statement for statement in sql))
        for statement in sql:
            self.assertFalse(statement.startswith(("INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP")), statement)
        with self.assertRaisesRegex(sqlite3.ProgrammingError, "closed"):
            opened[0].execute("SELECT 1")

    def assert_query_binding_change_rejected(self, changes):
        _, snapshot, _ = self.admitted()
        record = self.auth(snapshot)
        columns = ",".join(key + "=?" for key in changes)
        self.conn().execute(f"UPDATE managed_executions SET {columns} WHERE execution_id=?",
                            (*changes.values(), snapshot.execution_id))
        before = self.row(snapshot.execution_id)
        with self.assertRaisesRegex(LifecycleError, "^ipc_auth_binding_changed$") as error:
            self.query(snapshot, record)
        self.assert_private(str(error.exception), snapshot)
        self.assertEqual(self.row(snapshot.execution_id), before)

    def test_query_revalidates_changed_key_before_returning_state(self):
        self.assert_query_binding_change_rejected({"ipc_auth_key": b"z" * 32})

    def test_query_revalidates_changed_spec_before_returning_state(self):
        self.assert_query_binding_change_rejected({"spec_hash": "a" * 64})

    def test_query_revalidates_changed_wrapper_before_returning_state(self):
        self.assert_query_binding_change_rejected({"wrapper_pid": os.getpid() + 1})

    def test_query_revalidates_changed_allocation_before_returning_state(self):
        self.assert_query_binding_change_rejected({"reservation_id": "different-reservation"})

    def test_query_revalidates_changed_admission_binding_before_returning_state(self):
        self.assert_query_binding_change_rejected({"admission_binding_hash": "c" * 64})

    def test_unknown_execution_has_no_auth_and_does_not_enumerate_other_owners(self):
        _, snapshot, _ = self.admitted()
        with self.assertRaisesRegex(LifecycleError, "^ipc_auth_unavailable$") as error:
            _get_ipc_auth_record(self.coordinator.db_path, str(uuid4()))
        self.assertNotIn(snapshot.execution_id, str(error.exception))
        self.assert_private(str(error.exception), snapshot)

    def test_null_legacy_auth_key_cannot_be_authenticated_or_repaired_by_read(self):
        _, snapshot, _ = self.admitted()
        self.conn().execute("UPDATE managed_executions SET ipc_auth_key=NULL")
        before = self.row(snapshot.execution_id)
        with self.assertRaisesRegex(LifecycleError, "^ipc_auth_unavailable$"):
            self.auth(snapshot)
        self.assertEqual(self.row(snapshot.execution_id), before)

    def test_malformed_auth_keys_cannot_be_authenticated_or_repaired_by_read(self):
        _, snapshot, _ = self.admitted()
        for key in (b"", b"x" * 31, b"x" * 33, "private-key-text", 32):
            with self.subTest(type=type(key).__name__):
                self.conn().execute("UPDATE managed_executions SET ipc_auth_key=?", (key,))
                before = self.row(snapshot.execution_id)
                with self.assertRaisesRegex(LifecycleError, "^ipc_auth_unavailable$") as error:
                    self.auth(snapshot)
                self.assertNotIn("private-key-text", str(error.exception))
                self.assertEqual(self.row(snapshot.execution_id), before)

    def test_pre_ipc_schema_read_does_not_migrate_or_mint_an_existing_row_credential(self):
        _, snapshot, _ = self.admitted()
        conn = self.conn()
        conn.execute("ALTER TABLE managed_executions DROP COLUMN ipc_auth_key")
        before = self.row(snapshot.execution_id)
        with self.assertRaisesRegex(LifecycleError, "^ipc_registry_unavailable$"):
            self.auth(snapshot)
        self.assertNotIn("ipc_auth_key", {row[1] for row in conn.execute("PRAGMA table_info(managed_executions)")})
        self.assertEqual(self.row(snapshot.execution_id), before)
        # Ordinary additive migration may create the column, but cannot mint
        # authority for a previously admitted row that never possessed a key.
        LifecycleStore(self.coordinator.db_path)
        after = self.row(snapshot.execution_id)
        self.assertIsNone(after.pop("ipc_auth_key"))
        self.assertEqual(after, before)
        with self.assertRaisesRegex(LifecycleError, "^ipc_auth_unavailable$"):
            self.auth(snapshot)

    def test_missing_ledger_read_never_creates_database_or_parent(self):
        missing = self.directory / "never-created" / "sentinel.db"
        with self.assertRaisesRegex(LifecycleError, "^ipc_registry_unavailable$"):
            _get_ipc_auth_record(missing, str(uuid4()))
        self.assertFalse(missing.parent.exists())

    def test_invalid_query_identity_or_timeout_rejected_before_database_open(self):
        _, snapshot, _ = self.admitted()
        record = self.auth(snapshot)
        for execution_id, timeout in ((snapshot.execution_id, 0), (snapshot.execution_id, 1001),
                                     (snapshot.execution_id, True), ("not-an-id", 250)):
            with self.subTest(execution_id=execution_id, timeout=timeout), \
                    patch("sentinel.adaptive.store.sqlite3.connect") as connect:
                for operation in (
                        lambda: _get_ipc_auth_record(self.coordinator.db_path, execution_id, timeout_ms=timeout),
                        lambda: authenticated_query(self.coordinator.db_path, execution_id, record, timeout_ms=timeout)):
                    with self.assertRaisesRegex(LifecycleError, "^invalid_ipc_query$"):
                        operation()
                connect.assert_not_called()

    def test_replay_rejects_changed_or_missing_auth_key_without_new_allocation(self):
        context, snapshot, _ = self.admitted()
        allocation = dict(self.conn().execute("SELECT * FROM reservations").fetchone())
        for key in (b"z" * 32, None, b"short"):
            with self.subTest(key_type=type(key).__name__):
                self.conn().execute("UPDATE managed_executions SET ipc_auth_key=?", (key,))
                before = self.row(snapshot.execution_id)
                with self.assertRaisesRegex(LifecycleError, "^managed_admission_binding_mismatch$"):
                    self.admit(context, now=NOW + 1)
                self.assertEqual(self.row(snapshot.execution_id), before)
                self.assertEqual(dict(self.conn().execute("SELECT * FROM reservations").fetchone()), allocation)
                self.assertEqual(self.counts(), (0, 1, 1))

    def test_query_rejects_auth_record_from_another_execution(self):
        _, first, _ = self.admitted()
        _, second, _ = self.admitted()
        with self.assertRaisesRegex(LifecycleError, "^invalid_ipc_query$"):
            self.query(first, self.auth(second))

    def test_query_rejects_untyped_expected_record(self):
        _, snapshot, _ = self.admitted()
        with self.assertRaisesRegex(LifecycleError, "^invalid_ipc_query$"):
            authenticated_query(self.coordinator.db_path, snapshot.execution_id, asdict(self.auth(snapshot)))

    def test_query_rejects_malformed_mutable_numeric_fields_without_disclosure_or_repair(self):
        _, snapshot, _ = self.admitted()
        record = self.auth(snapshot)
        conn = self.conn()
        cases = (
            ("adaptive_runtime", {"registry_revision": "private-corrupt-revision"}),
            ("managed_executions", {"state_revision": b"private-corrupt-state-revision"}),
            ("managed_executions", {"root_pid": b"private-corrupt-pid",
                                     "root_created_filetime_100ns": str(snapshot.wrapper_identity.created_filetime_100ns)}),
        )
        for table, changes in cases:
            with self.subTest(table=table, fields=tuple(changes)):
                before = dict(conn.execute(f"SELECT * FROM {table}").fetchone())
                assignments = ",".join(key + "=?" for key in changes)
                conn.execute(f"UPDATE {table} SET {assignments}", tuple(changes.values()))
                damaged = dict(conn.execute(f"SELECT * FROM {table}").fetchone())
                with self.assertRaisesRegex(LifecycleError, "^ipc_registry_unavailable$") as error:
                    self.query(snapshot, record)
                self.assertNotIn("private-corrupt", str(error.exception))
                self.assert_private(str(error.exception), snapshot)
                self.assertEqual(dict(conn.execute(f"SELECT * FROM {table}").fetchone()), damaged)
                conn.execute(f"UPDATE {table} SET {assignments}", tuple(before[key] for key in changes))

    def test_query_reports_corrupt_allocation_binding_without_returning_private_values_or_repairing(self):
        _, snapshot, admitted = self.admitted()
        record = self.auth(snapshot)
        conn = self.conn()
        # Simulate already damaged storage in this isolated fixture. The
        # normal admission trigger correctly refuses these corrupt updates;
        # dropping it here does not change the production admission boundary.
        conn.execute("DROP TRIGGER managed_direct_update_guard")
        lifecycle_before = self.row(snapshot.execution_id)
        for column, value in (("execution_id", b"private-corrupt-execution"),
                              ("lifecycle_managed", "private-corrupt-managed-flag")):
            with self.subTest(column=column):
                before = dict(conn.execute("SELECT * FROM reservations WHERE id=?",
                                           (admitted["reservation_id"],)).fetchone())
                conn.execute(f"UPDATE reservations SET {column}=? WHERE id=?",
                             (value, admitted["reservation_id"]))
                damaged = dict(conn.execute("SELECT * FROM reservations WHERE id=?",
                                            (admitted["reservation_id"],)).fetchone())
                result = self.query(snapshot, record)
                self.assertTrue(result["available"])
                self.assertEqual(result["executions"][0]["allocation"]["recorded_binding"],
                                 "allocation_binding_inconsistent")
                self.assertNotIn("private-corrupt", json.dumps(result))
                self.assert_private(result, snapshot)
                self.assertEqual(dict(conn.execute("SELECT * FROM reservations WHERE id=?",
                    (admitted["reservation_id"],)).fetchone()), damaged)
                self.assertEqual(self.row(snapshot.execution_id), lifecycle_before)
                conn.execute(f"UPDATE reservations SET {column}=? WHERE id=?",
                             (before[column], admitted["reservation_id"]))

    def test_prelaunch_digest_excludes_query_key_blob_but_includes_admission_binding(self):
        _, snapshot, _ = self.admitted()
        row = self.row(snapshot.execution_id)
        allocation = dict(self.conn().execute("SELECT * FROM reservations").fetchone())
        def digest(record):
            return prelaunch_record_hash(record, claim_token_hash=snapshot.claim_token_hash,
                                         allocation=allocation)
        original = digest(row)
        without_key = dict(row)
        without_key.pop("ipc_auth_key")
        self.assertEqual(original, digest(without_key))
        self.assertEqual(original, digest(row | {"ipc_auth_key": b"changed-query-key"}))
        self.assertNotEqual(original, digest(row | {"admission_binding_hash": "d" * 64}))


if __name__ == "__main__":
    unittest.main()
