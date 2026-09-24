"""Next retirement reads actual original successor/epoch SQL history.

The host, startup and epoch use the existing explicit synthetic native fixture.
These tests do not retire a native host, create a guardian or prove restart.
"""
from contextlib import contextmanager
import json
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_retirement_fence as fence
from sentinel.adaptive import daily_retirement_inventory as inventory
from sentinel.adaptive import daily_successor_epoch as epochs
from sentinel.adaptive import daily_successor_history as successions
from sentinel.adaptive import experiment_history
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_startup import supervisor_instance_binding
from tests import test_adaptive_daily_successor_epoch as epoch_fixture


class DailyRetirementSuccessorHistoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = epoch_fixture.SuccessorGuardianEpochTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.assertTrue(self.fixture.owner.tick().complete)
        self.operation, self.store = self.fixture.operation, self.fixture.store
        self.journal = self.operation.retirement.journal
        self.db = self.store.db_path
        self.original = self.fixture.audits().entries[0].to_dict()

    @contextmanager
    def raw(self):
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def frozen(self):
        policy = self.store._policy
        guard = policy.prepare(self.fixture.owner.identity.logon_id)
        with policy.hold(guard):
            with self.raw() as conn:
                conn.execute("BEGIN IMMEDIATE")
                row = generation.read_generation(conn)
                self.freeze = fence.install_freeze_locked(conn,
                    {name: row[name] for name in fence.OWNER_BINDING_FIELDS}, str(uuid4()), guard)
                conn.commit()
            yield guard

    def capture(self):
        return inventory.capture_retirement_inventory(self.store, self.journal)

    def replace_audit(self, changes):
        # Deliberate isolated corruption; restore the canonical trigger before
        # invoking any reader. No production write API is being relaxed.
        value = dict(self.original, **changes)
        with self.raw() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"DROP TRIGGER {epochs.TABLE}_update")
            conn.execute(f"UPDATE {epochs.TABLE} SET " + ",".join(name + "=?" for name in epochs._FIELDS),
                tuple(value[name] for name in epochs._FIELDS))
            conn.execute(epochs._TRIGGERS[epochs.TABLE + "_update"])
            conn.commit()

    def test_actual_published_audit_is_retained_and_revalidated_in_next_frozen_inventory(self):
        with self.frozen():
            snapshot = self.capture()
            ledger = json.loads(inventory._SNAPSHOTS[snapshot][6])
            self.assertEqual(ledger["tables"][epochs.TABLE], [self.original])
            self.assertEqual(len(ledger["tables"][successions.TABLE]), 1)
            self.assertEqual(ledger["tables"][fence.TABLE], [self.freeze])
            with (patch.object(self.journal, "read", side_effect=AssertionError("journal I/O in final TX")),
                  patch.object(inventory.os, "scandir", side_effect=AssertionError("directory I/O in final TX")),
                  self.raw() as conn):
                conn.execute("BEGIN")
                self.assertIsNone(inventory.revalidate_retirement_inventory(conn, self.store, snapshot))
            self.assertEqual(self.fixture.audits().entries[0].to_dict(), self.original)
            self.assertEqual(self.fixture.supervisor.started_guardians, 0)

    def test_missing_epoch_guard_refuses_without_repair(self):
        with self.frozen(), self.raw() as conn:
            conn.execute(f"DROP TRIGGER {epochs.TABLE}_delete")
            before = tuple(tuple(row) for row in conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name"))
            with self.assertRaisesRegex(LifecycleError, "schema_unverified"):
                self.capture()
            self.assertEqual(tuple(tuple(row) for row in conn.execute(
                "SELECT name,sql FROM sqlite_master ORDER BY name")), before)

    def test_canonical_orphan_or_changed_archive_policy_binding_refuses(self):
        binding = PolicyBinding(str(uuid4()), self.original["policy_logon_id"])
        alterations = ({"transition_id": str(uuid4())}, {"succession_sha256": "f" * 64},
            {"successor_generation": str(uuid4())},
            {"policy_instance_id": binding.instance_id,
             "supervisor_instance_id": supervisor_instance_binding(binding).instance_id})
        with self.frozen():
            for changes in alterations:
                with self.subTest(fields=tuple(changes)):
                    self.replace_audit(changes)
                    try:
                        with self.assertRaisesRegex(LifecycleError, "successor_epoch_binding_changed"):
                            self.capture()
                    finally:
                        self.replace_audit({})

    def test_oversized_audit_cell_refuses_before_payload_is_fetched(self):
        with self.frozen() as guard:
            self.replace_audit({"inventory_digest": "x" * 100000})
            with self.raw() as conn:
                def text(value):
                    if len(value) > 65536:
                        raise AssertionError("oversized audit reached Python")
                    return value.decode("utf-8")
                conn.text_factory = text
                conn.execute("BEGIN")
                with self.assertRaisesRegex(LifecycleError, "row_invalid"):
                    inventory._read_ledger(conn, self.store, guard, inventory._Budget())

    def test_shared_row_allowance_counts_actual_experiment_revision_archive_and_epoch(self):
        with self.frozen(), self.raw() as conn:
            conn.execute("BEGIN")
            observed = experiment_history.verify_experiment_history_locked(conn)
            self.assertEqual(observed.rows_used, 1)
            self.assertEqual([(row.table, row.fields) for row in observed._sql_rows],
                [("adaptive_runtime", ("registry_revision",))])
            with patch.object(inventory, "MAX_HISTORY", 3):
                previous, audits = inventory._read_successor_histories(conn, inventory._Budget(),
                    experiment_rows=observed.rows_used)
                self.assertEqual(observed.rows_used + previous.rows_used + audits.rows_used, 3)
            with patch.object(inventory, "MAX_HISTORY", 2), \
                    self.assertRaisesRegex(LifecycleError, "rows_exceeded"):
                inventory._read_successor_histories(conn, inventory._Budget(), experiment_rows=observed.rows_used)
            with self.assertRaisesRegex(LifecycleError, "history_exceeded"):
                inventory._read_successor_histories(conn, inventory._Budget(), experiment_rows=4097)

    def test_shared_byte_allowance_charges_each_original_history_once(self):
        with self.frozen(), self.raw() as conn:
            conn.execute("BEGIN")
            previous = successions.read_successor_history(conn)
            audits = epochs.read_successor_guardian_epochs(conn)
            needed = previous.bytes_used + audits.bytes_used
            budget = inventory._Budget()
            budget.charge(inventory.MAX_BYTES - needed)
            self.assertEqual(inventory._read_successor_histories(conn, budget, experiment_rows=1),
                (previous, audits))
            self.assertEqual(budget.bytes, inventory.MAX_BYTES)
            too_small = inventory._Budget()
            too_small.charge(inventory.MAX_BYTES - needed + 1)
            with self.assertRaisesRegex(LifecycleError, "bytes_exceeded"):
                inventory._read_successor_histories(conn, too_small, experiment_rows=1)

    def test_current_frozen_phase_is_still_required_with_valid_old_histories(self):
        with self.frozen():
            snapshot = self.capture()
            with self.raw() as conn:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
                    conn.execute("UPDATE adaptive_daily_retirement SET phase='SEALED',seal_digest=?", ("a" * 64,))
                    with self.assertRaisesRegex(LifecycleError, "freeze_unverified"):
                        inventory.revalidate_retirement_inventory(conn, self.store, snapshot)
                finally:
                    # Keep the actual canonical triggers. A real rollback
                    # restores this fixture's ACTIVE/FROZEN preimage before
                    # the original normal POLICY scope clears its nonce.
                    conn.rollback()
                self.assertEqual(generation.read_generation(conn)["state"], "ACTIVE")
                self.assertEqual(fence.read_retirement(conn), self.freeze)

    def test_changed_historical_audit_invalidates_original_final_snapshot(self):
        with self.frozen():
            snapshot = self.capture()
            self.replace_audit({"inventory_digest": "e" * 64})
            with self.raw() as conn:
                conn.execute("BEGIN")
                with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                    inventory.revalidate_retirement_inventory(conn, self.store, snapshot)


if __name__ == "__main__":
    unittest.main()
