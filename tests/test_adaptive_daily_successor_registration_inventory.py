"""Actual successor/epoch/registration SQL with explicit synthetic native peers.

These tests exercise bounded current history and original publication ownership;
they do not launch a guardian or establish a Windows native capability gate.
"""
from contextlib import contextmanager
import copy
from dataclasses import FrozenInstanceError
import os
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_epoch as epochs
from sentinel.adaptive import daily_successor_registration_inventory as inventory
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.guardian_registration import GuardianRegistration
from sentinel.adaptive.policy import PolicyGuard
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_daily_successor_startup_inventory as startup_fixture
from tests.test_adaptive_guardian_launch import ProcessBackend


class SuccessorRegistrationInventoryTests(unittest.TestCase):
    def initialize(self, *, terminal=False):
        # This fixture isolates retained unknown readiness scopes before its
        # composed host setup, and restores the original registry last.
        self.fixture = startup_fixture.DailySuccessorStartupInventoryTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.initialize(terminal=terminal)
        self.store, self.db = self.fixture.store, self.fixture.db
        self.epoch = epochs.SuccessorGuardianEpoch(self.fixture.operation, self.fixture.supervisor)
        result = self.epoch.tick()
        self.assertTrue(result.complete, result)
        self.backend = ProcessBackend()
        self.identity = ProcessIdentity(os.getpid(), 134343072009999999, self.epoch.binding.logon_id)
        self.guardian = self.backend.process(self.identity)
        self.addCleanup(self.guardian.close)
        self.registration = GuardianRegistration(self.store, self.fixture.operation.retirement.journal,
            guardian=self.guardian, guardian_epoch=self.epoch.new_epoch)

    @contextmanager
    def raw(self, *, prepare=False):
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            if prepare:
                generation.prepare_connection(conn, role="coordinator", db_path=self.db)
            yield conn
        finally:
            conn.close()

    def under_original_policy(self, callback):
        registration = self.registration
        with registration._sql_scope():
            result = registration._policy_operation._run(self.identity.logon_id,
                lambda: callback(registration.guard), lambda: False)
        self.assertTrue(result.complete, result)
        return result

    def capture(self, guard):
        value = inventory.capture_registration_history(self.registration, guard)
        self.registration._successor_history_snapshot = value
        return value

    def revalidate(self, guard, snapshot):
        with self.store._transaction() as conn:
            self.assertIsNone(inventory.revalidate_registration_history(conn, self.registration, guard, snapshot))

    def publish(self):
        result = self.registration.tick()
        self.assertTrue(result.complete, result)
        self.assertIsNone(self.registration.guard)
        self.assertIs(type(self.registration._successor_history_snapshot), inventory.RegistrationHistorySnapshot)
        return self.registration._successor_history_snapshot

    def postimage(self, snapshot=None):
        snapshot = self.registration._successor_history_snapshot if snapshot is None else snapshot
        with self.registration._sql_scope(), self.store._connection() as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            self.assertIsNone(inventory.revalidate_registration_postimage(conn, self.registration, snapshot))

    def test_actual_child_publishes_after_full_terminal_receipt_and_journal_capture(self):
        self.initialize(terminal=True)
        real = inventory.revalidate_registration_history
        validations = []

        def bounded(conn, registration, guard, snapshot):
            validations.append(conn)
            with patch.object(inventory.prior, "_journal_inventory", side_effect=AssertionError("journal inside TX")), \
                    patch.object(self.guardian, "observe", side_effect=AssertionError("native inside TX")), \
                    patch.object(generation, "_ledger_identity", side_effect=AssertionError("stat inside TX")):
                return real(conn, registration, guard, snapshot)

        with patch.object(inventory, "revalidate_registration_history", side_effect=bounded):
            snapshot = self.publish()
        self.assertTrue(validations)
        captured = inventory._SNAPSHOTS[snapshot]
        self.assertEqual(captured.journals[0][0], self.fixture.case.spec.execution_id)
        self.assertIn(self.fixture.case.spec.execution_id.encode(), captured.receipts)
        self.assertEqual(len(captured.readers), 2)
        for conn in captured.readers:
            with self.assertRaises(sqlite3.ProgrammingError):
                conn.execute("SELECT 1")
        self.assertEqual(snapshot.budget.history_rows, 3)  # experiment runtime + succession + epoch
        self.assertGreater(snapshot.budget.bytes_used, len(captured.ledger))
        with self.assertRaises(FrozenInstanceError):
            snapshot.budget.history_rows = 0
        with patch.object(inventory.prior, "_journal_inventory", side_effect=AssertionError("ACK journal I/O")), \
                patch.object(self.guardian, "observe", side_effect=AssertionError("ACK native query")):
            self.postimage(snapshot)

    def test_full_ordinary_snapshot_is_current_then_exact_until_publication(self):
        self.initialize()
        with self.raw() as conn:
            conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,'before')")

        def check(guard):
            snapshot = self.capture(guard)
            self.revalidate(guard, snapshot)
            with self.raw() as conn:
                conn.execute("UPDATE resource_samples SET disk_json='later'")
            with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                self.revalidate(guard, snapshot)
            with self.raw() as conn:
                conn.execute("UPDATE resource_samples SET disk_json='before'")
            self.revalidate(guard, snapshot)
            return False

        self.under_original_policy(check)

    def test_publication_trigger_history_side_effect_is_rolled_back_before_commit(self):
        self.initialize(terminal=True)
        with self.raw() as conn:
            before = dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())
            history = [dict(row) for row in conn.execute(
                "SELECT * FROM adaptive_launch_requests ORDER BY execution_id,operation")]
            terminal = conn.execute("SELECT execution_id,spec_hash,guardian_epoch FROM managed_executions").fetchall()
            self.assertEqual(len(terminal), 1)
            self.assertEqual(terminal[0]["execution_id"], self.fixture.case.spec.execution_id)
            # This retained schema is already present during both capture reads.
            # Only the original registration INSERT activates its side effect.
            # Use an actual terminal execution: Store enables foreign keys, so
            # an orphan UUID would fail in the trigger before postimage checks.
            conn.execute("""CREATE TRIGGER registration_fixture_history_effect
                AFTER INSERT ON adaptive_infrastructure WHEN NEW.role='guardian'
                BEGIN
                    INSERT OR REPLACE INTO adaptive_launch_requests
                    SELECT execution_id,'PrepareExecution',
                        '59b2773b-cba8-431d-800c-402edc49d00e',
                        'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
                        spec_hash,guardian_epoch FROM managed_executions;
                END""")
        injected = dict(execution_id=terminal[0]["execution_id"], operation="PrepareExecution",
            request_id="59b2773b-cba8-431d-800c-402edc49d00e", payload_hash="c" * 64,
            spec_hash=terminal[0]["spec_hash"], guardian_epoch=terminal[0]["guardian_epoch"])
        expected_history = sorted([row for row in history if
            (row["execution_id"], row["operation"]) != (injected["execution_id"], injected["operation"])] + [injected],
            key=lambda row: (row["execution_id"], row["operation"]))
        self.assertNotEqual(expected_history, history)
        observed = []
        validate = inventory.revalidate_registration_postimage

        def postimage(conn, registration, snapshot):
            observed.append((conn.in_transaction,
                conn.execute("SELECT count(*) FROM adaptive_infrastructure").fetchone()[0],
                [dict(row) for row in conn.execute(
                    "SELECT * FROM adaptive_launch_requests ORDER BY execution_id,operation")]))
            return validate(conn, registration, snapshot)

        with patch.object(inventory, "revalidate_registration_postimage", side_effect=postimage):
            result = self.registration.tick()
        error = self.registration._policy_operation._error
        diagnostic = (result, type(error).__name__, str(error), getattr(error, "__notes__", ()))
        self.assertFalse(result.complete, diagnostic)
        self.assertTrue(result.pending, diagnostic)
        self.assertIn("postimage_changed", str(error), diagnostic)
        self.assertIsNotNone(self.registration._successor_history_snapshot, diagnostic)
        self.assertEqual(observed, [(True, 1, expected_history)], diagnostic)
        self.assertIs(self.registration.guard, self.registration._successor_history_guard)
        with self.raw() as conn:
            after = dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())
            self.assertEqual(self.registration._image(after), self.registration._image(before))
            self.assertEqual(conn.execute("SELECT count(*) FROM adaptive_infrastructure").fetchone()[0], 0)
            self.assertEqual([dict(row) for row in conn.execute(
                "SELECT * FROM adaptive_launch_requests ORDER BY execution_id,operation")], history)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM sqlite_master "
                "WHERE type='trigger' AND name='registration_fixture_history_effect'").fetchone())

    def test_snapshot_and_registration_copies_and_foreign_guards_refuse(self):
        self.initialize()

        def check(guard):
            snapshot = self.capture(guard)
            with self.store._transaction() as conn:
                for other in (copy.copy(snapshot), object.__new__(inventory.RegistrationHistorySnapshot)):
                    with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                        inventory.revalidate_registration_history(conn, self.registration, guard, other)
                with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_registration_history(conn, copy.copy(self.registration), guard, snapshot)
                with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_registration_history(conn, self.registration,
                        PolicyGuard(guard.binding, guard.nonce), snapshot)
            with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                inventory.RegistrationHistorySnapshot()
            self.revalidate(guard, snapshot)
            return False

        self.under_original_policy(check)

    def test_thread_process_self_handle_and_snapshot_handoff_are_exact(self):
        self.initialize()

        def check(guard):
            snapshot = self.capture(guard)
            with self.store._transaction() as conn:
                # Compute before patching the shared os module.
                pid = os.getpid() + 1
                with patch.object(inventory.os, "getpid", return_value=pid), \
                        self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
                with patch.object(inventory.threading, "current_thread", return_value=threading.Thread()), \
                        self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
                for name, value in (("_handle", self.guardian._handle + 100), ("_close_outcome_unknown", True)):
                    with patch.object(self.guardian, name, value), self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                        inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
                with patch.object(self.registration, "_successor_history_snapshot", copy.copy(snapshot)), \
                        self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
            self.revalidate(guard, snapshot)
            return False

        self.under_original_policy(check)

    def test_foreign_original_path_connection_attached_db_and_temp_objects_refuse(self):
        self.initialize()

        def check(guard):
            snapshot = self.capture(guard)
            with self.raw() as conn:
                conn.execute("BEGIN")
                with self.assertRaisesRegex(LifecycleError, "original_sql_transaction_required"):
                    inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
            for sql in ("ATTACH DATABASE ':memory:' AS other", "CREATE TEMP TABLE unrelated(value TEXT)"):
                with self.store._connection() as conn:
                    conn.execute(sql)
                    conn.execute("BEGIN")
                    with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                        inventory.revalidate_registration_history(conn, self.registration, guard, snapshot)
            self.revalidate(guard, snapshot)
            return False

        self.under_original_policy(check)

    def test_unknown_adaptive_schema_and_ordinary_payload_bounds_refuse(self):
        self.initialize()

        def check(guard):
            with self.raw() as conn:
                conn.execute("CREATE TABLE adaptive_unknown(value TEXT)")
            with self.assertRaisesRegex(LifecycleError, "schema_unknown"):
                inventory.capture_registration_history(self.registration, guard)
            with self.raw() as conn:
                conn.execute("DROP TABLE adaptive_unknown")
                conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,?)",
                    ("x" * (inventory.prior._CELL_BYTES + 1),))
            with self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
                inventory.capture_registration_history(self.registration, guard)
            with self.raw() as conn:
                conn.execute("DELETE FROM resource_samples")
                conn.executemany("INSERT INTO resource_samples(sampled_at) VALUES(?)",
                    ((index,) for index in range(inventory.MAX_HISTORY + 1)))
            with self.assertRaisesRegex(LifecycleError, "history_exceeded"):
                inventory.capture_registration_history(self.registration, guard)
            with self.raw() as conn:
                conn.execute("DELETE FROM resource_samples")
            self.revalidate(guard, self.capture(guard))
            return False

        self.under_original_policy(check)

    def test_managed_queue_and_orphan_launch_record_are_not_closed_history(self):
        self.initialize()

        def check(guard):
            with self.raw(prepare=True) as conn:
                conn.execute("UPDATE queue SET managed_execution_id='unverified' WHERE request_key='unrelated'")
            with self.assertRaisesRegex(LifecycleError, "managed_obligation_remaining"):
                inventory.capture_registration_history(self.registration, guard)
            with self.raw(prepare=True) as conn:
                conn.execute("UPDATE queue SET managed_execution_id=NULL WHERE request_key='unrelated'")
                conn.execute("INSERT INTO adaptive_launch_requests VALUES(?,?,?,?,?,?)",
                    (str(uuid4()), "PrepareExecution", str(uuid4()), "a" * 64, "b" * 64, "old-epoch"))
            with self.assertRaisesRegex(LifecycleError, "orphan_scope_record"):
                inventory.capture_registration_history(self.registration, guard)
            with self.raw(prepare=True) as conn:
                conn.execute("DELETE FROM adaptive_launch_requests")
            self.revalidate(guard, self.capture(guard))
            return False

        self.under_original_policy(check)

    def test_actual_journal_rewrite_and_extra_directory_entry_refuse_capture(self):
        self.initialize(terminal=True)

        def check(guard):
            journal = self.registration.journal._directory
            path = journal / (self.fixture.case.spec.execution_id + ".json")
            saved = path.read_bytes()
            try:
                path.write_bytes(b"{}")
                with self.assertRaises(Exception):
                    inventory.capture_registration_history(self.registration, guard)
            finally:
                path.write_bytes(saved)
            extra = journal / (str(uuid4()) + ".json")
            try:
                extra.write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(LifecycleError, "journal_extra_entry"):
                    inventory.capture_registration_history(self.registration, guard)
            finally:
                extra.unlink()
            self.revalidate(guard, self.capture(guard))
            return False

        self.under_original_policy(check)

    def test_postimage_permits_bounded_independent_ordinary_changes(self):
        self.initialize()
        snapshot = self.publish()
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE queue SET heartbeat_at=240 WHERE request_key='unrelated'")
            conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,'ordinary-after-ACK')")
            conn.execute("""INSERT INTO reservations(id,request_key,owner_pid,owner_started,
                repo,command_signature,command_text,resource_class,priority,priority_rank,
                cpu_units,ram_gib,io_slots,created_at,heartbeat_at,expires_at)
                VALUES('ordinary','ordinary',9001,12,'fixture','signature','','HEAVY','P2',2,1,1,0,100,100,700)""")
        self.postimage(snapshot)
        with self.raw() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM reservations WHERE id='ordinary'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT heartbeat_at FROM queue WHERE request_key='unrelated'").fetchone()[0], 240)

    def test_postimage_keeps_exact_adaptive_history_and_owned_revision(self):
        self.initialize()
        snapshot = self.publish()
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        with self.assertRaisesRegex(LifecycleError, "epoch_binding_changed"):
            self.postimage(snapshot)
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision-1")
            conn.execute("INSERT INTO adaptive_launch_requests VALUES(?,?,?,?,?,?)",
                (str(uuid4()), "PrepareExecution", str(uuid4()), "a" * 64, "b" * 64, "old-epoch"))
        with self.assertRaisesRegex(LifecycleError, "orphan_scope_record"):
            self.postimage(snapshot)
        with self.raw(prepare=True) as conn:
            conn.execute("DELETE FROM adaptive_launch_requests")
        self.postimage(snapshot)

    def test_postimage_rejects_changed_guardian_and_copied_snapshot(self):
        self.initialize()
        snapshot = self.publish()
        with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
            self.postimage(copy.copy(snapshot))
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE adaptive_infrastructure SET created_filetime_100ns=? WHERE role='guardian'",
                (str(self.identity.created_filetime_100ns + 1),))
        with self.assertRaisesRegex(LifecycleError, "infrastructure_changed"):
            self.postimage(snapshot)
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE adaptive_infrastructure SET created_filetime_100ns=? WHERE role='guardian'",
                (str(self.identity.created_filetime_100ns),))
        self.postimage(snapshot)

    def test_postimage_clear_requires_exact_original_positive_nonce_evidence(self):
        self.initialize()
        snapshot = self.publish()
        captured = inventory._SNAPSHOTS[snapshot]
        self.assertTrue(captured.guard._nonce_clear_confirmed)
        with patch.object(captured.guard, "_nonce_clear_confirmed", False), \
                patch.object(captured.guard, "_nonce_clear_attempted", False), self.assertRaises(LifecycleError):
            self.postimage(snapshot)
        with patch.object(self.registration, "_successor_history_guard", PolicyGuard(captured.binding, captured.nonce)), \
                self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
            self.postimage(snapshot)
        self.postimage(snapshot)

    def test_original_nonce_clear_commit_ack_loss_reconciles_after_positive_read_close(self):
        self.initialize()
        transaction = self.store._transaction
        error, lost = RuntimeError("registration_nonce_clear_commit_ack_lost"), []

        @contextmanager
        def commit_ack_lost(*args, **kwargs):
            clearing = False
            with transaction(*args, **kwargs) as conn:
                yield conn
                guard = self.registration._successor_history_guard
                clearing = (guard is not None and self.store._policy.current_cleanup_guard() is guard and
                    conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0] is None)
            if clearing and not lost:
                # Real COMMIT and original connection close have succeeded.
                # The enclosing PolicyCoordinator._clear has not returned.
                lost.append(conn)
                raise error

        with patch.object(self.store, "_transaction", side_effect=commit_ack_lost):
            first = self.registration.tick()
        self.assertFalse(first.complete)
        self.assertTrue(first.pending)
        self.assertEqual(len(lost), 1)
        snapshot = self.registration._successor_history_snapshot
        captured = inventory._SNAPSHOTS[snapshot]
        guard = captured.guard
        self.assertIs(self.registration.guard, guard)
        self.assertTrue(guard._native_exit_confirmed)
        self.assertTrue(guard._nonce_clear_attempted)
        self.assertFalse(guard._nonce_clear_confirmed)
        original_confirm = self.registration._confirm_successor_nonce_clear
        confirmations = []

        def confirm(original_snapshot):
            self.assertIs(original_snapshot, snapshot)
            self.assertTrue(all(owner.closed and not owner.close_unknown for owner in self.registration._connections))
            confirmations.append(original_snapshot)
            return original_confirm(original_snapshot)

        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("new nonce")), \
                patch.object(self.store._policy, "hold", side_effect=AssertionError("native reentry")), \
                patch.object(self.store._policy, "_clear", side_effect=AssertionError("second clear")), \
                patch.object(self.registration, "_confirm_successor_nonce_clear", side_effect=confirm):
            second = self.registration.tick()
        self.assertTrue(second.complete, second)
        self.assertEqual(confirmations, [snapshot])
        self.assertIsNone(self.registration.guard)
        self.assertIs(self.registration._successor_history_snapshot, snapshot)
        self.assertFalse(guard._nonce_clear_confirmed)  # Original ACK was never fabricated.

    def test_postimage_rechecks_ordinary_bounds_and_managed_aliases(self):
        self.initialize()
        snapshot = self.publish()
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE queue SET managed_execution_id='unverified' WHERE request_key='unrelated'")
        with self.assertRaisesRegex(LifecycleError, "managed_obligation_remaining"):
            self.postimage(snapshot)
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE queue SET managed_execution_id=NULL WHERE request_key='unrelated'")
            conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,?)",
                ("x" * (inventory.prior._CELL_BYTES + 1),))
        with self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
            self.postimage(snapshot)
        with self.raw() as conn:
            conn.execute("DELETE FROM resource_samples")
        self.postimage(snapshot)

    def _lost_acquisition(self, target):
        self.initialize()
        original, error, opened = sqlite3.connect, RuntimeError("registration_reader_result_lost"), []
        count, snapshots = [0], len(inventory._SNAPSHOTS)

        def connect(*args, **kwargs):
            count[0] += 1
            conn = original(*args, **kwargs)
            if count[0] == target:
                opened.append(conn)
                self.addCleanup(sqlite3.Connection.close, conn)
                raise error
            return conn

        def capture():
            with patch.object(sqlite3, "connect", side_effect=connect):
                inventory.capture_registration_history(self.registration, self.registration.guard)

        with self.registration._sql_scope():
            result = self.registration._policy_operation._run(self.identity.logon_id, capture, lambda: False)
        self.assertFalse(result.complete)
        self.assertTrue(result.pending)
        self.assertEqual(count[0], target)
        self.assertEqual(len(opened), 1)
        self.assertEqual(len(inventory._SNAPSHOTS), snapshots)
        self.assertIs(error._guardian_registration, self.registration)
        owner = self.registration._connections[-1]
        self.assertIsNone(owner.connection)
        self.assertFalse(owner.closed)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("replacement reader")), \
                self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
            self.registration._original()

    def test_first_reader_lost_result_retains_original_acquisition(self):
        self._lost_acquisition(1)

    def test_second_reader_lost_result_retains_original_acquisition(self):
        self._lost_acquisition(2)

    def test_reader_close_ack_loss_retains_owner_and_cannot_mint_snapshot(self):
        self.initialize()
        original, error, owners = sqlite3.connect, RuntimeError("registration_reader_close_unknown"), []

        class CloseLost(sqlite3.Connection):
            def close(conn):
                super().close()
                owners.append(conn)
                raise error

        def connect(*args, **kwargs):
            kwargs["factory"] = CloseLost
            return original(*args, **kwargs)

        def capture():
            with patch.object(sqlite3, "connect", side_effect=connect):
                inventory.capture_registration_history(self.registration, self.registration.guard)

        snapshots = len(inventory._SNAPSHOTS)
        with self.registration._sql_scope():
            result = self.registration._policy_operation._run(self.identity.logon_id, capture, lambda: False)
        self.assertFalse(result.complete)
        self.assertTrue(result.pending)
        self.assertEqual(len(owners), 1)
        self.assertEqual(len(inventory._SNAPSHOTS), snapshots)
        owner = self.registration._connections[-1]
        self.assertIs(owner.connection, owners[0])
        self.assertFalse(owner.closed)
        self.assertTrue(owner.close_unknown)
        self.assertIs(error._guardian_registration, self.registration)


if __name__ == "__main__":
    unittest.main()
