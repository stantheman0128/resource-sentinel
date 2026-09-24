"""Data-only successor archives over real SQLite; no restart/native evidence."""
from contextlib import contextmanager
import copy
from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_history as history
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.daily_retirement_fence import OWNER_BINDING_FIELDS
from sentinel.adaptive.policy import PolicyGuard
from tests import test_adaptive_daily_successor_predecessor as predecessor_fixture


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class SuccessorHistoryReaderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.conn.close)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("BEGIN")
        manifest = generation.SourceManifest(tuple(generation.SourceEntry(path, "a" * 64, 0)
            for path in sorted(generation.REQUIRED_PATHS)))
        self.base = dict(singleton=1, schema_version=1, generation=str(uuid4()), state="DRAINING",
            source_digest=manifest.digest, config_digest="b" * 64,
            source_manifest_json=canonical(manifest.to_dict()), source_root=str(self.root),
            ledger_path=str(self.root / "sentinel.db"),
            owner_identity_json=canonical(ProcessIdentity(101, 134342315823996135,
                "S-1-5-5-100-200").to_dict()), ledger_identity_json='["0","123"]',
            readiness_instance_id=str(uuid4()))
        self.policy_id = str(uuid4())

    def schema(self):
        self.conn.execute(history._SCHEMA)
        for statement in history._TRIGGERS.values():
            self.conn.execute(statement)

    def record(self, previous=None):
        old = dict(self.base if previous is None else previous["successor"], state="DRAINING")
        new = dict(old, generation=str(uuid4()), state="ACTIVE", readiness_instance_id=str(uuid4()))
        frozen = dict(singleton=1, schema_version=1, request_id=str(uuid4()),
            **{name: old[name] for name in OWNER_BINDING_FIELDS}, policy_instance_id=self.policy_id,
            policy_logon_id=json.loads(old["owner_identity_json"])["logon_id"],
            freeze_policy_nonce=str(uuid4()), freeze_registry_revision=12,
            phase="SEALED", seal_digest="c" * 64)
        return dict(schema_version=1, transition_id=str(uuid4()), predecessor=old,
            retirement=frozen, successor=new, inventory_digest="d" * 64,
            policy=dict(instance_id=self.policy_id, logon_id=frozen["policy_logon_id"], nonce=str(uuid4())))

    def insert(self, record, ordinal=1, *, raw=None, digest=None):
        raw = canonical(record) if raw is None else raw
        digest = hashlib.sha256(history._DOMAIN + raw.encode("utf-8")).hexdigest() if digest is None else digest
        self.conn.execute(f"INSERT INTO {history.TABLE} VALUES(?,?,?,?,?,?)", (ordinal,
            record["transition_id"], record["predecessor"]["generation"], record["successor"]["generation"], raw, digest))
        return raw, digest

    def read(self, **kwargs):
        return history.read_successor_history(self.conn, **kwargs)

    def reject_large_python_text(self):
        def text(value):
            if len(value) > 65536:
                raise AssertionError("unbounded SQLite text fetched")
            return value.decode("utf-8")
        self.conn.text_factory = text

    def test_absent_archive_is_empty_read_only_data_and_requires_transaction(self):
        before = self.conn.total_changes
        result = self.read(max_rows=0, max_bytes=0)
        self.assertEqual((result.entries, result.rows_used, result.bytes_used), ((), 0, 0))
        self.assertEqual(self.conn.total_changes, before)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)
        self.conn.rollback()
        with self.assertRaisesRegex(history.SuccessorHistoryError, "transaction_required"):
            self.read()

    def test_valid_complete_chain_returns_exact_immutable_cells_and_byte_charge(self):
        self.schema()
        first = self.record()
        second = self.record(first)
        raw1, digest1 = self.insert(first)
        raw2, digest2 = self.insert(second, 2)
        result = self.read()
        self.assertEqual(result.rows_used, 2)
        self.assertEqual(result.bytes_used, len(raw1.encode()) + len(raw2.encode()) + 2 * 180)
        self.assertEqual(result.entries[0].record, raw1.encode())
        self.assertEqual(result.entries[1].sha256, digest2)
        self.assertEqual(result.entries[0]._row, (1, first["transition_id"], first["predecessor"]["generation"],
            first["successor"]["generation"], raw1, digest1))
        with self.assertRaises(FrozenInstanceError):
            result.bytes_used = 0
        with self.assertRaises(TypeError):
            result.entries[0]._row[0] = 7
        self.assertEqual(self.read(max_rows=2, max_bytes=result.bytes_used), result)
        with self.assertRaisesRegex(history.SuccessorHistoryError, "bytes_exceeded"):
            self.read(max_bytes=result.bytes_used - 1)
        with self.assertRaisesRegex(history.SuccessorHistoryError, "rows_exceeded"):
            self.read(max_rows=1)

    def test_update_and_delete_are_refused_by_persistent_immutable_guards(self):
        self.schema()
        self.insert(self.record())
        expected = self.read()
        for statement in (f"UPDATE {history.TABLE} SET sha256='changed'", f"DELETE FROM {history.TABLE}"):
            with self.subTest(statement=statement), self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                self.conn.execute(statement)
        self.assertEqual(self.read(), expected)

    def test_incomplete_schema_is_refused_without_repair(self):
        self.conn.execute(history._SCHEMA)
        before = tuple(tuple(row) for row in self.conn.execute("SELECT name,sql FROM sqlite_master"))
        with self.assertRaisesRegex(history.SuccessorHistoryError, "schema_invalid"):
            self.read()
        self.assertEqual(tuple(tuple(row) for row in self.conn.execute("SELECT name,sql FROM sqlite_master")), before)

    def test_extra_trigger_and_index_are_refused_even_with_unreserved_names(self):
        self.schema()
        for statement, remove in ((f"CREATE TRIGGER extra BEFORE INSERT ON {history.TABLE} BEGIN SELECT 1; END",
                "DROP TRIGGER extra"), (f"CREATE INDEX extra ON {history.TABLE}(sha256)", "DROP INDEX extra")):
            with self.subTest(statement=statement):
                self.conn.execute(statement)
                with self.assertRaisesRegex(history.SuccessorHistoryError, "schema_invalid"):
                    self.read()
                self.conn.execute(remove)
        self.assertEqual(self.read().rows_used, 0)

    def test_reserved_orphan_object_and_noncanonical_table_are_refused(self):
        self.conn.execute(f"CREATE VIEW {history.TABLE}_update AS SELECT 1")
        with self.assertRaisesRegex(history.SuccessorHistoryError, "schema_invalid"):
            self.read()
        self.conn.execute(f"DROP VIEW {history.TABLE}_update")
        self.conn.execute(f"CREATE TABLE {history.TABLE}(ordinal,record_json)")
        with self.assertRaisesRegex(history.SuccessorHistoryError, "schema_invalid"):
            self.read()

    def test_oversized_schema_sql_is_not_fetched_into_python(self):
        self.schema()
        self.conn.execute(f"CREATE TRIGGER extra BEFORE INSERT ON {history.TABLE} BEGIN SELECT 1 /*" +
            "x" * 70000 + "*/; END")
        self.reject_large_python_text()
        with self.assertRaisesRegex(history.SuccessorHistoryError, "schema_invalid"):
            self.read()

    def test_oversized_payload_or_locator_is_refused_before_fetch(self):
        self.schema()
        record = self.record()
        for field, oversized in (("record_json", "x" * (history.MAX_RECORD_BYTES + 1)),
                ("transition_id", "x" * 70000)):
            with self.subTest(field=field):
                values = [1, record["transition_id"], record["predecessor"]["generation"],
                    record["successor"]["generation"], "{}", "0" * 64]
                values[history._FIELDS.index(field)] = oversized
                self.conn.execute("SAVEPOINT malformed")
                self.conn.execute(f"INSERT INTO {history.TABLE} VALUES(?,?,?,?,?,?)", values)
                self.reject_large_python_text()
                with self.assertRaisesRegex(history.SuccessorHistoryError, "row_invalid"):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_4097_rows_are_refused_before_record_decode(self):
        self.schema()
        self.conn.execute(f"""WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<4097)
            INSERT INTO {history.TABLE} SELECT n,
            printf('%08x-0000-4000-8000-000000000000',n),
            printf('%08x-0000-4000-8000-000000000000',n+5000),
            printf('%08x-0000-4000-8000-000000000000',n+10000),'{{}}',? FROM numbers""", ("0" * 64,))
        with self.assertRaisesRegex(history.SuccessorHistoryError, "rows_exceeded"):
            self.read()

    def test_aggregate_16mib_bound_precedes_payload_fetch_and_json_decode(self):
        self.schema()
        payload = "x" * history.MAX_RECORD_BYTES
        previous = None
        for ordinal in range(1, 5):
            previous = self.record(previous)
            self.insert(previous, ordinal, raw=payload)
        self.reject_large_python_text()
        with self.assertRaisesRegex(history.SuccessorHistoryError, "bytes_exceeded"):
            self.read()

    def test_hash_and_indexed_binding_tampering_are_refused(self):
        self.schema()
        for kind in ("hash", "index"):
            with self.subTest(kind=kind):
                self.conn.execute("SAVEPOINT malformed")
                record = self.record()
                if kind == "hash":
                    self.insert(record, digest="0" * 64)
                else:
                    raw = canonical(record)
                    record["transition_id"] = str(uuid4())
                    self.insert(record, raw=raw)
                with self.assertRaisesRegex(history.SuccessorHistoryError, "chain_invalid"):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_duplicate_and_noncanonical_json_are_refused(self):
        self.schema()
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                self.conn.execute("SAVEPOINT malformed")
                record = self.record()
                raw = canonical(record)
                raw = '{"schema_version":1,' + raw[1:] if duplicate else " " + raw
                self.insert(record, raw=raw)
                with self.assertRaises(history.SuccessorHistoryError):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_full_generation_continuity_rejects_same_uuid_with_changed_source_or_owner(self):
        self.schema()
        first = self.record()
        self.insert(first)
        for key, value in (("source_root", str(self.root / "other")), ("config_digest", "e" * 64),
                ("ledger_identity_json", '["0","124"]'),
                ("readiness_instance_id", str(uuid4())),
                ("owner_identity_json", canonical(ProcessIdentity(102, 134342315823996136,
                    "S-1-5-5-100-200").to_dict()))):
            with self.subTest(key=key):
                self.conn.execute("SAVEPOINT malformed")
                second = self.record(first)
                second["predecessor"][key] = second["successor"][key] = value
                if key == "readiness_instance_id":
                    second["successor"][key] = str(uuid4())
                second["retirement"][key] = value
                self.insert(second, 2)
                with self.assertRaisesRegex(history.SuccessorHistoryError, "chain_invalid"):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_cycle_and_reused_readiness_request_or_policy_nonce_are_refused(self):
        self.schema()
        first = self.record()
        self.insert(first)
        for kind in ("cycle", "readiness", "request", "nonce"):
            with self.subTest(kind=kind):
                self.conn.execute("SAVEPOINT malformed")
                second = self.record(first)
                if kind == "cycle":
                    second["successor"]["generation"] = first["predecessor"]["generation"]
                elif kind == "readiness":
                    second["successor"]["readiness_instance_id"] = first["predecessor"]["readiness_instance_id"]
                elif kind == "request":
                    second["retirement"]["request_id"] = first["retirement"]["request_id"]
                else:
                    second["policy"]["nonce"] = first["policy"]["nonce"]
                self.insert(second, 2)
                with self.assertRaisesRegex(history.SuccessorHistoryError, "chain_invalid"):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_inner_generation_json_and_file_ids_must_be_canonical(self):
        self.schema()
        for key, value in (("ledger_identity_json", '["00","123"]'),
                ("ledger_identity_json", '["0","0"]'),
                ("ledger_identity_json", '["0","' + str(1 << 128) + '"]'),
                ("source_manifest_json", " " + self.base["source_manifest_json"]),
                ("owner_identity_json", " " + self.base["owner_identity_json"])):
            with self.subTest(key=key, value=value[:35]):
                self.conn.execute("SAVEPOINT malformed")
                record = self.record()
                record["predecessor"][key] = record["successor"][key] = value
                if key in record["retirement"]:
                    record["retirement"][key] = value
                self.insert(record)
                with self.assertRaisesRegex(history.SuccessorHistoryError, "generation_invalid"):
                    self.read()
                self.conn.execute("ROLLBACK TO malformed")
                self.conn.execute("RELEASE malformed")

    def test_temp_shadow_cannot_replace_main_history(self):
        self.schema()
        record = self.record()
        self.insert(record)
        self.conn.execute(f"CREATE TEMP TABLE {history.TABLE}(secret)")
        self.conn.execute(f"INSERT INTO temp.{history.TABLE} VALUES('not history')")
        self.assertEqual(self.read().entries[0].record, canonical(record).encode())

    def test_invalid_shared_budgets_are_refused(self):
        for values in ({"max_rows": True}, {"max_rows": -1}, {"max_rows": 4097},
                {"max_bytes": True}, {"max_bytes": -1}, {"max_bytes": history.MAX_BYTES + 1}):
            with self.subTest(values=values), self.assertRaisesRegex(history.SuccessorHistoryError, "budget_invalid"):
                self.read(**values)


class OriginalSuccessorHistoryAppendTests(unittest.TestCase):
    def setUp(self):
        self.fixture = predecessor_fixture.DailySuccessorPredecessorTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.retirement = self.fixture.complete()
        self.retirement.assert_successor_predecessor()
        self.transition = str(uuid4())
        self.successor = dict(self.retirement._generation_row, generation=str(uuid4()),
            readiness_instance_id=str(uuid4()))

    @contextmanager
    def transaction(self):
        # Explicit new-POLICY native seam: the same original coordinator has
        # this distinct guard on its thread, backed by the actual SQL nonce.
        # This models the outer successor scope still being implemented; it
        # does not patch archive validation or reconstruct the old retirement.
        conn = sqlite3.connect(self.retirement.owner.ledger_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        guard = PolicyGuard(self.retirement._seal_guard.binding, str(uuid4()))
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=? WHERE singleton=1", (guard.nonce,))
        self.retirement.policy._held.guard = guard
        try:
            yield conn, guard
        finally:
            self.retirement.policy._held.guard = None
            if conn.in_transaction:
                conn.rollback()
            conn.close()

    def append(self, conn, guard, **changes):
        args = dict(retirement=self.retirement, successor_row=self.successor, guard=guard,
                    transition_id=self.transition)
        args.update(changes)
        return history.append_successor_history_locked(conn, **args)

    def test_original_completed_retirement_appends_once_without_commit_or_unfreeze(self):
        with self.transaction() as (conn, guard):
            old_generation = generation.read_generation(conn)
            old_fence = dict(conn.execute("SELECT * FROM adaptive_daily_retirement").fetchone())
            first = self.append(conn, guard)
            replay = self.append(conn, guard)
            self.assertEqual(first, replay)
            self.assertEqual(history.read_successor_history(conn).rows_used, 1)
            self.assertTrue(conn.in_transaction)
            self.assertEqual(generation.read_generation(conn), old_generation)
            self.assertEqual(dict(conn.execute("SELECT * FROM adaptive_daily_retirement").fetchone()), old_fence)
        with sqlite3.connect(self.retirement.owner.ledger_path) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (history.TABLE,)).fetchone())
        self.retirement.assert_successor_predecessor()

    def test_changed_replay_refuses_and_preserves_existing_transaction_record(self):
        with self.transaction() as (conn, guard):
            first = self.append(conn, guard)
            changed = dict(self.successor, generation=str(uuid4()))
            with self.assertRaisesRegex(history.SuccessorHistoryError, "replay_changed"):
                self.append(conn, guard, successor_row=changed)
            self.assertEqual(history.read_successor_history(conn).entries, (first,))
            self.assertTrue(conn.in_transaction)

    def test_old_guard_copy_and_absent_original_transaction_cannot_append(self):
        with self.transaction() as (conn, guard):
            for old in (self.retirement._freeze_guard, self.retirement._seal_guard,
                        copy.copy(self.retirement._seal_guard)):
                with self.subTest(nonce=old.nonce), self.assertRaisesRegex(history.SuccessorHistoryError,
                        "new_policy_guard_required"):
                    self.append(conn, old)
            conn.rollback()
            with self.assertRaisesRegex(history.SuccessorHistoryError, "transaction_required"):
                self.append(conn, guard)

    def test_copied_retirement_and_other_ledger_cannot_append(self):
        with self.transaction() as (conn, guard):
            with self.assertRaisesRegex(RuntimeError, "original_retirement_required"):
                self.append(conn, guard, retirement=copy.copy(self.retirement))
            other = sqlite3.connect(":memory:", isolation_level=None)
            try:
                other.execute("BEGIN")
                with self.assertRaisesRegex(history.SuccessorHistoryError, "original_transaction_required"):
                    self.append(other, guard)
            finally:
                other.close()

    def test_shared_budget_refusal_does_not_create_archive_schema(self):
        with self.transaction() as (conn, guard):
            for budget in ({"max_rows": 0}, {"max_bytes": 1}):
                with self.subTest(budget=budget), self.assertRaisesRegex(history.SuccessorHistoryError, "budget_exceeded"):
                    self.append(conn, guard, **budget)
                self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (history.TABLE,)).fetchone())
            self.assertTrue(conn.in_transaction)


if __name__ == "__main__":
    unittest.main()
