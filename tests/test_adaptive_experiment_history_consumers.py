"""Portable consumer integration over real SQL and synthetic closed history.

History fixtures are assembled before canonical guards are installed; they do
not mint original cleanup authority or establish native acceptance. POLICY is
modeled only in the narrow read-only exclusion/admission consumer tests. Mixed
retirement retains the existing actual POLICY and production custody fixtures.
"""
from dataclasses import FrozenInstanceError, replace
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_retirement_inventory as inventory
from sentinel.adaptive import experiment_demand as demand
from sentinel.adaptive import experiment_exclusion as exclusion
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_daily_retirement_inventory as retirement_tests
from tests import test_adaptive_experiment_history as history_tests


class ExperimentHistoryConsumerTests(unittest.TestCase):
    def setUp(self):
        self.fixture = history_tests.ExperimentHistoryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def blocker(self, conn, *, experiment_id=None):
        owner = self.fixture.owner
        declaration = replace(owner.declaration, experiment_id=experiment_id or str(uuid4()))
        # The method under test is the read-only admission partition. Original
        # ownership, generation and POLICY checks have dedicated custody tests.
        with patch.object(owner, "_locked"), patch.object(owner, "declaration", declaration):
            return owner.admission_blocker_locked(conn, None, None)

    def exclusion_read(self, conn):
        with patch.object(exclusion, "_held", return_value=self.fixture.runtime):
            return exclusion.read_locked(conn, policy=None, guard=None)

    def test_closed_history_reuses_slot_but_never_reuses_experiment_identity(self):
        conn = self.fixture.database()
        before = conn.total_changes
        demand._schema(conn)
        self.assertIsNone(self.blocker(conn))
        self.assertEqual(self.blocker(conn, experiment_id=self.fixture.metadata["experiment_id"]),
                         "experiment_history_identity_reused")
        self.assertEqual(conn.total_changes, before)
        self.assertEqual(conn.execute("SELECT state,revision FROM " + demand.TABLE).fetchone()[:], ("ADMITTED", 0))

    def test_one_active_after_closed_history_retains_slot(self):
        ids = []
        conn = self.fixture.database(mutate=lambda db: ids.append(self.fixture.add_synthetic_active(db)))
        demand._schema(conn)
        self.assertEqual(self.blocker(conn), "experiment_scope_occupied")
        self.assertIsNone(self.blocker(conn, experiment_id=ids[0]))

    def test_closed_hash_without_exact_archive_never_reuses_slot(self):
        conn = self.fixture.database(mutate=lambda db: db.execute("DELETE FROM executions"))
        with self.assertRaises(history.ExperimentHistoryError):
            self.blocker(conn)

    def test_history_row_budget_refuses_before_another_admission(self):
        conn = self.fixture.database()
        with patch.object(history, "MAX_HISTORY", 1):
            self.assertEqual(self.blocker(conn), "experiment_history_exhausted")

    def test_prospective_publication_exhaustion_rolls_back_metadata(self):
        full = history.verify_experiment_history_locked(self.fixture.database(active=True))
        conn = self.fixture.database(active=True, mutate=lambda db: db.execute("DELETE FROM " + demand.TABLE))
        owner = self.fixture.owner
        policy = SimpleNamespace(assert_held=lambda: SimpleNamespace(binding=owner._policy_original))
        verify = history.verify_experiment_history_locked
        conn.execute("SAVEPOINT candidate")
        with patch.object(owner, "_locked"), patch.object(history, "verify_experiment_history_locked",
                side_effect=lambda db: verify(db, max_bytes=full.bytes_used - 1)), \
                self.assertRaisesRegex(history.ExperimentHistoryError, "bytes_exceeded"):
            owner.publish_locked(conn, owner._snapshot, policy,
                                 {"reservation_id": self.fixture.allocation["id"]}, replay=False)
        conn.execute("ROLLBACK TO candidate")
        self.assertEqual(conn.execute("SELECT count(*) FROM " + demand.TABLE).fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_missing_receipt_schema_is_not_repaired_by_existing_demand_schema(self):
        conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(conn.close)
        for name, sql in self.fixture.schemas.items():
            if name != history.TABLE:
                conn.execute(sql)
        for sql in demand._TRIGGER_SQL.values():
            conn.execute(sql)
        conn.execute("BEGIN")
        with self.assertRaisesRegex(demand.ExperimentDemandError, "cleanup_schema_missing"):
            demand._schema(conn, create=True)
        self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (history.TABLE,)).fetchone())

    def test_managed_mutation_supplies_full_original_blob_type_and_exact_rows(self):
        conn = self.fixture.database(active=True)
        calls = []
        conn.create_function("sentinel_experiment_release_mutation", 4,
                             lambda *args: calls.append(args) or 0)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "native_cleanup_unverified"):
            conn.execute("UPDATE managed_executions SET state='CANCELLED_BEFORE_START',claim_consumed=1")
        table, key, old_json, new_json = calls.pop()
        old, new = json.loads(old_json), json.loads(new_json)
        self.assertEqual((table, key), ("managed_executions", self.fixture.managed["execution_id"]))
        self.assertEqual(set(old), set(history.MANAGED_FIELDS) | {"ipc_auth_key_sqlite_type"})
        self.assertEqual(old["ipc_auth_key_sqlite_type"], "blob")
        self.assertTrue(bytes.fromhex(old["ipc_auth_key"]) == self.fixture.managed["ipc_auth_key"])
        self.assertEqual(new["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(conn.execute("SELECT state,claim_consumed FROM managed_executions").fetchone()[:],
                         ("RESERVED", 0))

    def test_reservation_delete_supplies_full_old_row_and_sql_null_new(self):
        conn = self.fixture.database(active=True)
        calls = []
        conn.create_function("sentinel_experiment_release_mutation", 4,
                             lambda *args: calls.append(args) or 0)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM reservations")
        table, key, old_json, new_json = calls.pop()
        self.assertEqual((table, key, new_json), ("reservations", self.fixture.allocation["id"], None))
        self.assertEqual(json.loads(old_json), self.fixture.allocation)
        self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_metadata_and_execution_deletion_stay_immutable_even_if_mutation_function_returns_one(self):
        conn = self.fixture.database(active=True)
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 1)
        for sql in ("DELETE FROM " + demand.TABLE, "UPDATE " + demand.TABLE + " SET revision=0",
                    "DELETE FROM managed_executions", "UPDATE reservations SET heartbeat_at=heartbeat_at+1"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                conn.execute(sql)

    def test_closed_managed_postimage_is_immutable_but_active_heartbeat_is_preserved(self):
        closed = self.fixture.database()
        closed.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        closed.execute("UPDATE managed_executions SET state_revision=state_revision")
        for field in ("heartbeat_at", "state_revision", "cancel_requested_at"):
            with self.subTest(field=field), self.assertRaises(sqlite3.IntegrityError):
                closed.execute("UPDATE managed_executions SET " + field + "=" + field + "+1")
        history.verify_experiment_history_locked(closed)
        active = self.fixture.database(active=True)
        active.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        active.execute("UPDATE managed_executions SET heartbeat_at=heartbeat_at+1")
        self.assertEqual(active.execute("SELECT heartbeat_at FROM managed_executions").fetchone()[0],
                         self.fixture.managed["heartbeat_at"] + 1)

    def test_closed_exclusion_is_omitted_only_after_full_history_validation(self):
        record = self.fixture.native_record("FINISHED")
        conn = self.fixture.database(record)
        before = conn.total_changes
        self.assertEqual(self.exclusion_read(conn), exclusion.ExclusionInventory((), frozenset(), ()))
        self.assertEqual(conn.total_changes, before)
        corrupted = self.fixture.database(record, mutate=lambda db: db.execute("DELETE FROM executions"))
        with self.assertRaisesRegex(exclusion.ExperimentExclusionError, "history_unverified"):
            self.exclusion_read(corrupted)

    def test_exclusion_close_requires_exact_old_new_projection_and_cannot_reopen(self):
        record = self.fixture.native_record("FINISHED")
        conn = self.fixture.database(record, active=True)
        calls = []
        conn.create_function("sentinel_experiment_release_mutation", 4,
                             lambda *args: calls.append(args) or 0)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE " + exclusion.TABLE + " SET phase='CLOSED',cleanup_digest=?", ("a" * 64,))
        table, key, before, after = calls.pop()
        self.assertEqual((table, key), (exclusion.TABLE, record["preimage"]["exclusion"]["scope_execution_id"]))
        self.assertEqual(json.loads(before), record["preimage"]["exclusion"])
        self.assertEqual(set(json.loads(after)), set(exclusion._FIELDS))
        closed = self.fixture.database(record)
        closed.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 1)
        with self.assertRaises(sqlite3.IntegrityError):
            closed.execute("UPDATE " + exclusion.TABLE + " SET phase='REGISTERED',cleanup_digest=NULL")

    def test_original_row_observation_is_immutable_and_credentials_are_not_repr(self):
        observation = history.verify_experiment_history_locked(self.fixture.database())
        row = next(item for item in observation._sql_rows if item.table == "managed_executions")
        cells = dict(zip(row.fields, row.values))
        self.assertTrue(cells["ipc_auth_key"] == self.fixture.managed["ipc_auth_key"])
        self.assertNotIn("ipc_auth_key", repr(row))
        self.assertNotIn("ipc_auth_key", repr(observation))
        with self.assertRaises(FrozenInstanceError):
            row.values = ()

    def production_fixture(self, kind="finished"):
        helper = retirement_tests.DailyRetirementInventoryTests()
        self.addCleanup(helper.doCleanups)
        fixture, case = helper.fixture(kind)
        return helper, fixture, case

    def add_closed_history(self, fixture, *, record=None, corrupt=None):
        source = self.fixture.database(record)
        target = sqlite3.connect(fixture.db, isolation_level=None)
        self.addCleanup(target.close)
        target.row_factory = sqlite3.Row
        target.execute("BEGIN")
        for table in (demand.TABLE, exclusion.TABLE, history.TABLE):
            target.execute(source.execute("SELECT sql FROM sqlite_master WHERE name=?", (table,)).fetchone()[0])
        for table in (demand.TABLE, exclusion.TABLE, history.TABLE, "managed_executions", "executions"):
            for raw in source.execute("SELECT * FROM " + table):
                row = dict(raw)
                if table == "executions":
                    row.pop("id")
                history_tests.insert(target, table, row)
        revision = source.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0]
        target.execute("UPDATE adaptive_runtime SET registry_revision=max(registry_revision,?)", (revision,))
        if corrupt:
            corrupt(target)
        for guards in (demand._TRIGGER_SQL, exclusion._GUARDS, history.TRIGGER_SQL):
            for sql in guards.values():
                target.execute(sql)
        target.commit()
        return target

    def test_mixed_production_and_experiment_retirement_keeps_exact_rows_and_only_production_journal(self):
        for kind in ("finished", "prelaunch", "never-created"):
            with self.subTest(kind=kind):
                helper, fixture, case = self.production_fixture(kind)
                execution_id = case.spec.execution_id if kind == "finished" else case.snapshot.execution_id
                self.add_closed_history(fixture, record=self.fixture.native_record("FINISHED"))
                with fixture.forbid_native_reentry(case), helper.held(fixture):
                    snapshot = helper.verify(fixture)
                    saved = inventory._SNAPSHOTS[snapshot]
                    ledger = json.loads(saved[6])
                    self.assertEqual(len(ledger["tables"]["managed_executions"]), 2)
                    self.assertEqual(ledger["experiment_execution_ids"], [self.fixture.metadata["execution_id"]])
                    self.assertEqual(set(saved[8]), {execution_id})
                    self.assertEqual(ledger["tables"][demand.TABLE], [self.fixture.metadata])
                    self.assertEqual(len(ledger["experiment_archives"]), 1)
                    self.assertEqual(len(inventory.retirement_inventory_digest(fixture.store, snapshot)), 64)

    def test_retirement_does_not_accept_receipt_without_original_archive(self):
        helper, fixture, _ = self.production_fixture()
        self.add_closed_history(fixture, corrupt=lambda db: db.execute(
            "DELETE FROM executions WHERE reservation_id=?", (self.fixture.metadata["reservation_id"],)))
        with helper.held(fixture), self.assertRaisesRegex(LifecycleError, "experiment_history_unverified"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_closed_experiment_history_does_not_exempt_production_manifest(self):
        helper, fixture, case = self.production_fixture("prelaunch")
        self.add_closed_history(fixture)
        (fixture.journal_dir / (case.snapshot.execution_id + ".json")).unlink()
        with helper.held(fixture), self.assertRaisesRegex(LifecycleError, "journal_scope_missing"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_exact_receipt_column_has_two_mib_limit_other_cells_stay_small(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE " + history.TABLE + "(receipt_json TEXT,operation_id TEXT)")
        payload = "x" * (inventory._CELL_BYTES + 1)
        conn.execute("INSERT INTO " + history.TABLE + " VALUES(?,?)", (payload, "op"))
        budget = inventory._Budget()
        rows = inventory._rows(conn, history.TABLE, ("receipt_json", "operation_id"), budget)
        self.assertEqual(rows[0]["receipt_json"], payload)
        conn.execute("UPDATE " + history.TABLE + " SET operation_id=?", (payload,))
        with self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
            inventory._rows(conn, history.TABLE, ("receipt_json", "operation_id"), inventory._Budget())

    def test_final_serialized_inventory_framing_uses_same_aggregate_bound(self):
        ledger, receipts = {"tables": {"a": []}}, {}
        exact = len(inventory._encoded(ledger)) + len(inventory._encoded(receipts))
        with patch.object(inventory, "MAX_BYTES", exact):
            inventory._serialized_bound(ledger, receipts, {})
        with patch.object(inventory, "MAX_BYTES", exact - 1), self.assertRaisesRegex(LifecycleError, "bytes_exceeded"):
            inventory._serialized_bound(ledger, receipts, {})


if __name__ == "__main__":
    unittest.main()
