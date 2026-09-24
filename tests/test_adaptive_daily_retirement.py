"""Synthetic original-owner orchestration and real SQLite permission tests.

No native process, daily ledger, installed source or activation is used here.
Full native retirement remains a separate Windows evidence gate.
"""
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import daily_retirement as retirement
from sentinel.adaptive.daily_activation_host import DailyActivationHost, _ConnectionCustody
from sentinel.adaptive.daily_generation import DailyGenerationOwner
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor_host import SupervisorHost


class DailyRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.host = object.__new__(DailyActivationHost)
        self.owner = object.__new__(DailyGenerationOwner)
        self.store = object.__new__(LifecycleStore)
        self.supervisor = object.__new__(SupervisorHost)
        self.policy = Mock(spec=["current_guard", "current_cleanup_guard", "assert_held", "revalidate"])
        self.policy.current_guard.return_value = None
        self.policy.current_cleanup_guard.return_value = None
        self.store._policy = self.policy
        self.host.owner, self.host.store, self.host.supervisor = self.owner, self.store, self.supervisor
        self.host.journal_dir = Path(self.temp.name)
        self.host._generation_settled = True
        self.host._retirement = None
        self.host._connections = []
        self.host._supervisor_closed = True
        self.host._readiness_cleanup_complete = True
        self.host._readiness_joined = True
        self.host._readiness_listener_closed = True
        self.host._readiness_close_unknown = False
        self.owner._closed = False
        self.owner._retirement_operation = None
        self.owner._assert_owner = Mock()
        self.owner.assert_ready = Mock()
        self.owner.assert_readiness_readers_settled = Mock()
        self.owner._matches_generation = Mock(return_value=True)
        self.owner.process = Mock(identity=SimpleNamespace(logon_id="logon"))
        self.owner.cohort = Mock(spec=["assert_retained_retired", "close"])
        self.supervisor.draining = True
        self.supervisor._closed = True
        self.supervisor._operational_error = None
        self.supervisor._drain_children_settled = Mock(return_value=True)
        self.supervisor._custody_snapshot = Mock(return_value={"settled": True,
            "remaining_custody": 0, "mode_off": True, "barrier_cleared": True})
        self.operation = retirement.DailyRetirementOperation(self.host)
        self.host._retirement = self.operation

    def test_constructor_retains_original_operation_before_mutation(self):
        self.assertIs(self.owner._retirement_operation, self.operation)
        self.assertIs(self.operation.host, self.host)
        self.assertFalse(self.operation.freeze_acknowledged)
        self.assertFalse(self.operation.sealed)
        self.assertFalse(self.operation.complete)

    def test_second_operation_cannot_replace_original(self):
        with self.assertRaisesRegex(retirement.DailyRetirementError, "original_owner_required"):
            retirement.DailyRetirementOperation(self.host)

    def test_plain_or_serialized_host_cannot_construct_owner(self):
        for value in ({"generation": "ACTIVE"}, SimpleNamespace(**vars(self.host))):
            with self.subTest(value=type(value)), self.assertRaises(retirement.DailyRetirementError):
                retirement.DailyRetirementOperation(value)

    def test_changed_host_owner_blocks_before_native_cleanup(self):
        self.host.owner = object()
        with self.assertRaisesRegex(retirement.DailyRetirementError, "original_owner_changed"):
            self.operation.close_owner()
        self.owner.process.close.assert_not_called()

    def test_clean_supervisor_without_seal_does_not_close_owner(self):
        with self.assertRaisesRegex(retirement.DailyRetirementError, "keeper_cleanup_unsettled"):
            self.operation.close_owner()
        self.owner.cohort.close.assert_not_called()

    def test_readiness_unknown_close_retains_original_owner(self):
        self.operation._sealed = True
        self.host._readiness_close_unknown = True
        with self.assertRaises(retirement.DailyRetirementError):
            self.operation.close_owner()
        self.owner.process.close.assert_not_called()

    def test_sql_owner_must_be_positively_closed(self):
        self.operation._sealed = True
        self.host._connections.append(SimpleNamespace(closed=False, close_unknown=False))
        with self.assertRaisesRegex(retirement.DailyRetirementError, "sql_custody_unsettled"):
            self.operation.close_owner()
        self.owner.process.close.assert_not_called()

    def test_pending_original_policy_retains_owner(self):
        self.operation._sealed = True
        self.operation._seal._guard = object()
        with self.assertRaisesRegex(retirement.DailyRetirementError, "policy_unsettled"):
            self.operation.close_owner()

    def test_cohort_positive_close_precedes_self_close(self):
        self.operation._sealed = True
        events = []
        self.owner.cohort.close.side_effect = lambda: events.append("cohort")
        self.owner.process.close.side_effect = lambda: events.append("self")
        self.operation.close_owner()
        self.assertEqual(events, ["cohort", "self"])
        self.assertTrue(self.operation.complete)
        self.assertTrue(self.owner._closed)
        self.assertEqual(self.operation.phase, "retired_admission_fenced")
        self.operation.close_owner()
        self.assertEqual(events, ["cohort", "self"])

    def test_unknown_cohort_close_never_retries_or_closes_self(self):
        self.operation._sealed = True
        self.owner.cohort.close.side_effect = OSError("unit unknown close")
        with self.assertRaises(OSError):
            self.operation.close_owner()
        self.owner.process.close.assert_not_called()
        self.assertFalse(self.operation.complete)
        with self.assertRaisesRegex(retirement.DailyRetirementError, "owner_close_unknown"):
            self.operation.close_owner()
        self.owner.cohort.close.assert_called_once()

    def test_unknown_self_close_never_retries(self):
        self.operation._sealed = True
        self.owner.process.close.side_effect = OSError("unit unknown close")
        with self.assertRaises(OSError):
            self.operation.close_owner()
        with self.assertRaises(retirement.DailyRetirementError):
            self.operation.close_owner()
        self.owner.process.close.assert_called_once()
        self.assertFalse(self.operation.complete)

    def test_known_sql_close_is_not_repeated(self):
        raw = Mock(in_transaction=False)
        custody = _ConnectionCustody(raw)
        self.operation._close_write(custody)
        self.operation._close_write(custody)
        raw.close.assert_called_once()

    def test_unknown_sql_close_is_quarantined(self):
        raw = Mock(in_transaction=False)
        raw.close.side_effect = OSError("unit unknown close")
        custody = _ConnectionCustody(raw)
        with self.assertRaises(OSError):
            self.operation._close_write(custody)
        with self.assertRaises(retirement.DailyRetirementError):
            self.operation._close_write(custody)
        raw.close.assert_called_once()

    def test_known_readonly_inventory_blocker_does_not_hold_cleanup_nonce(self):
        guard = SimpleNamespace(clean_rejection=False)
        self.operation._seal._guard = guard
        with patch.object(retirement, "capture_retirement_inventory",
                side_effect=LifecycleError("daily_retirement_allocations_present")), \
                self.assertRaises(LifecycleError):
            self.operation._seal_write()
        self.assertTrue(guard.clean_rejection)
        self.assertFalse(self.operation._seal_attempted)

    def test_unknown_inventory_reader_cleanup_is_not_clean_refusal(self):
        guard = SimpleNamespace(clean_rejection=False)
        self.operation._seal._guard = guard
        error = LifecycleError("daily_retirement_inventory_unavailable")
        error.add_note("coverage_reader_cleanup_failed")
        with patch.object(retirement, "capture_retirement_inventory", side_effect=error), \
                self.assertRaises(LifecycleError):
            self.operation._seal_write()
        self.assertFalse(guard.clean_rejection)

    def test_own_policy_nonce_does_not_make_native_drain_unsettled(self):
        self.policy.current_guard.return_value = object()
        self.supervisor._custody_snapshot.return_value["settled"] = False
        self.operation._supervisor_settled()

    def test_native_child_custody_still_blocks_with_own_nonce(self):
        self.policy.current_guard.return_value = object()
        self.supervisor._custody_snapshot.return_value["remaining_custody"] = 1
        with self.assertRaisesRegex(retirement.DailyRetirementError, "supervisor_unsettled"):
            self.operation._supervisor_settled()

    def nonce_connection(self, *, cleanup=True):
        conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(conn.close)
        conn.executescript("""CREATE TABLE adaptive_runtime(singleton INTEGER PRIMARY KEY,
            policy_instance_id TEXT,
            policy_logon_id TEXT,policy_entry_nonce TEXT,mode TEXT);
            INSERT INTO adaptive_runtime VALUES(1,'policy','logon','nonce','off');
            CREATE TABLE reservations(id TEXT);""")
        op = self.operation
        op._generation_row = {"state": "ACTIVE", "generation": "unit-generation"}
        op._seal_row = {"phase": "SEALED"}
        op._seal_guard = SimpleNamespace(nonce="nonce", binding=SimpleNamespace(
            instance_id="policy", logon_id="logon"))
        op._seal._guard = op._seal_guard
        op._seal_attempted = True
        op._seal_resume_active = True
        self.policy.current_cleanup_guard.return_value = op._seal_guard if cleanup else None
        with patch.object(retirement, "read_retirement", return_value=op._seal_row):
            op.authorize_nonce_cleanup(conn, dict(op._generation_row, state="DRAINING"))
        return conn

    def test_nonce_only_authorizer_permits_exact_cleanup(self):
        conn = self.nonce_connection()
        conn.execute("BEGIN")
        conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
        conn.commit()
        self.assertIsNone(conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_nonce_only_connection_cannot_write_capacity_mode_or_schema(self):
        conn = self.nonce_connection()
        for sql in ("INSERT INTO reservations VALUES('new')",
                    "UPDATE adaptive_runtime SET mode='canary'",
                    "UPDATE adaptive_runtime SET policy_instance_id='other'",
                    "UPDATE adaptive_runtime SET policy_entry_nonce='replacement'",
                    "PRAGMA user_version=99", "PRAGMA writable_schema=ON",
                    "PRAGMA optimize", "PRAGMA wal_checkpoint", "PRAGMA incremental_vacuum",
                    "CREATE TABLE bypass(id TEXT)", "DELETE FROM adaptive_runtime"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                conn.execute(sql)

    def test_nonce_only_connection_has_no_generation_function(self):
        conn = self.nonce_connection()
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("SELECT sentinel_daily_generation()")

    def test_completed_seal_cannot_open_another_cleanup_connection(self):
        conn = self.nonce_connection()
        self.operation._sealed = True
        with self.assertRaisesRegex(retirement.DailyRetirementError, "cleanup_not_owned"):
            self.operation.authorize_nonce_cleanup(conn,
                dict(self.operation._generation_row, state="DRAINING"))

    def test_same_thread_readback_scope_cannot_clear_nonce(self):
        conn = self.nonce_connection(cleanup=False)
        self.assertEqual(conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0], "nonce")
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")

    def test_cleanup_connection_loses_authority_after_exact_scope_exits(self):
        conn = self.nonce_connection()
        self.policy.current_cleanup_guard.return_value = None
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")

    def test_cached_cleanup_statement_cannot_clear_a_second_nonce(self):
        conn = self.nonce_connection()
        sql = "UPDATE adaptive_runtime SET policy_entry_nonce=NULL"
        conn.execute(sql)
        self.policy.current_cleanup_guard.return_value = None
        with self.assertRaises(sqlite3.DatabaseError):
            conn.execute(sql)

    def test_cleanup_scope_on_different_thread_is_rejected(self):
        conn = self.nonce_connection()
        with patch.object(retirement.threading, "get_ident", return_value=self.operation._thread_id + 1), \
                self.assertRaisesRegex(retirement.DailyRetirementError, "cleanup_not_owned"):
            self.operation.authorize_nonce_cleanup(conn,
                dict(self.operation._generation_row, state="DRAINING"))


if __name__ == "__main__":
    unittest.main()
