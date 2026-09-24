"""Full successor observations over real isolated retirement/POLICY/SQLite.

Native collaborators are the explicit predecessor fixture backends. The actual
successor metadata scope acquires the distinct guard; no generation UDF, native
capture, successor publication or activation is fabricated by these tests.
"""
from contextlib import contextmanager
import copy
from dataclasses import FrozenInstanceError, replace
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_successor_inventory as inventory
from sentinel.adaptive import daily_retirement_inventory as prior
from sentinel.adaptive import daily_successor as successor
from sentinel.adaptive.daily_successor import DailySuccessorError, DailySuccessorOperation
from sentinel.adaptive.policy import PolicyGuard
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests import test_adaptive_daily_successor_predecessor as predecessor_fixture
from tests import test_adaptive_guardian_lifecycle as guardian_fixture
from tests import test_adaptive_terminal_receipt as terminal_fixture
from tests.fixtures.adaptive_evidence import fixture_evidence_provider


class DailySuccessorInventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = predecessor_fixture.DailySuccessorPredecessorTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.retirement = self.fixture.operation
        self.db = self.retirement.owner.ledger_path
        self.operation = None

    @contextmanager
    def raw(self, path=None):
        conn = sqlite3.connect(self.db if path is None else path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def complete(self):
        self.fixture.complete()
        self.operation = DailySuccessorOperation(self.retirement)
        return self.operation

    @contextmanager
    def held(self):
        operation = self.operation or self.complete()
        with operation.scope():
            operation._prepare_guard()
            with operation.policy.hold(operation.guard):
                yield operation.guard

    def capture(self, guard):
        return inventory.capture_successor_inventory(self.retirement, guard)

    def revalidate(self, guard, snapshot):
        with self.operation._connection(readonly=True) as conn:
            conn.execute("BEGIN")
            self.assertIsNone(inventory.revalidate_successor_inventory(
                conn, self.retirement, guard, snapshot))
            conn.rollback()

    def seed_sample(self, *, text="fixture"):
        with self.raw() as conn:
            conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,?)", (text,))

    def terminal_history(self):
        """Actual original terminal receipt, added after empty daily install."""
        terminal = terminal_fixture.TerminalReceiptTests()
        self.addCleanup(terminal.doCleanups)
        terminal.directory, terminal.db = self.fixture.fixture.root, self.db
        terminal.policy = self.retirement.store._policy.provider
        terminal.setup_connections, terminal.seed_records = [], {}
        terminal.seed_store = LifecycleStore(self.db, policy_provider=terminal.policy,
            evidence_provider=fixture_evidence_provider(terminal.seed_evidence))
        terminal.store = terminal.seed_store
        terminal.processes = guardian_fixture.ProcessBackend()
        logon = self.retirement.owner.process.identity.logon_id
        guardian = replace(guardian_fixture.GUARDIAN, logon_id=logon)
        terminal.guardian = terminal.processes.process(guardian)
        terminal.journal_dir = self.retirement.host.journal_dir
        terminal.journal = RecoveryJournal(terminal.journal_dir, publisher=guardian_fixture.publish_fixture)
        terminal.mutexes, terminal.cases, terminal.owner = [], [], None
        original_connection = terminal.connection

        def connection():
            conn = original_connection()
            inventory.generation.prepare_connection(conn, role="coordinator", db_path=self.db)
            return conn

        terminal.connection = connection
        lifecycle = guardian_fixture.fixtures
        with (patch.object(guardian_fixture, "GUARDIAN", guardian),
              patch.object(lifecycle, "WRAPPER", replace(lifecycle.WRAPPER, logon_id=logon)),
              patch.object(lifecycle, "ROOT", replace(lifecycle.ROOT, logon_id=logon))):
            case = terminal.retired_case()
        for conn in terminal.setup_connections:
            conn.close()
        return terminal, case

    def test_actual_distinct_policy_capture_and_transaction_preserve_full_rows(self):
        self.seed_sample()
        with self.held() as guard:
            self.assertIsNot(guard, self.retirement._seal_guard)
            snapshot = self.capture(guard)
            captured = inventory._SNAPSHOTS[snapshot]
            full = json.loads(captured.full_ledger)
            with self.raw() as conn:
                names = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertEqual(set(full["tables"]), names)
            self.assertEqual(full["tables"]["resource_samples"][0]["disk_json"], "fixture")
            self.assertIn("queue", full["tables"])
            self.assertIn("workers", full["tables"])
            with (patch.object(prior, "_journal_inventory", side_effect=AssertionError("journal I/O in TX")),
                  patch.object(self.retirement.owner.process, "observe", side_effect=AssertionError("old native query")),
                  patch.object(self.retirement.owner.process, "close", side_effect=AssertionError("old native close"))):
                self.revalidate(guard, snapshot)
            self.assertIsNone(self.operation.owner)
            self.assertGreater(snapshot.budget.bytes_used, 0)
            self.assertEqual(snapshot.budget.remaining_bytes, inventory.MAX_BYTES - snapshot.budget.bytes_used)
            with self.assertRaises(FrozenInstanceError):
                snapshot.budget.bytes_used = 0
        with self.raw() as conn:
            self.assertEqual(conn.execute("SELECT state FROM adaptive_daily_generation").fetchone()[0], "DRAINING")
            self.assertIsNone(conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_history_budget_includes_actual_experiment_revision_observation(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            with self.raw() as conn:
                conn.execute("BEGIN")
                observed = inventory.experiment_history.verify_experiment_history_locked(conn)
            self.assertEqual(observed.rows_used, 1)
            self.assertEqual([(row.table, row.fields) for row in observed._sql_rows],
                [("adaptive_runtime", ("registry_revision",))])
            self.assertEqual(snapshot.budget.history_rows, observed.rows_used)
            self.assertEqual(snapshot.budget.remaining_history_rows, inventory.MAX_HISTORY - observed.rows_used)
            self.revalidate(guard, snapshot)
            with patch.object(prior, "MAX_HISTORY", 0), \
                    self.assertRaisesRegex(LifecycleError, "history_exceeded"):
                self.capture(guard)

    def test_unobserved_ordinary_rows_are_captured_now_then_frozen(self):
        self.complete()
        # The predecessor did not capture resource_samples. Its new observation
        # is deliberately at successor capture, not retroactively at sealing.
        self.seed_sample(text="after-retirement")
        with self.held() as guard:
            snapshot = self.capture(guard)
            self.revalidate(guard, snapshot)
            with self.raw() as conn:
                conn.execute("UPDATE resource_samples SET disk_json='changed-after-capture'")
            with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                self.revalidate(guard, snapshot)

    def test_unrelated_original_queue_is_preserved_without_readmission(self):
        request_key = uuid4().hex
        with self.raw() as conn:
            inventory.generation.prepare_connection(conn, role="coordinator", db_path=self.db)
            conn.execute("""INSERT INTO queue(request_key,owner_pid,owner_started,
                repo,command_signature,command_text,resource_class,priority,priority_rank,
                cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,spec_hash,managed_execution_id)
                VALUES(?,100,1.0,'fixture','fixture','','HEAVY','P2',2,1,1,1,1,1,'',NULL)""", (request_key,))
            original = dict(conn.execute("SELECT * FROM queue WHERE request_key=?", (request_key,)).fetchone())
        with self.held() as guard:
            snapshot = self.capture(guard)
            self.assertEqual(json.loads(inventory._SNAPSHOTS[snapshot].full_ledger)["tables"]["queue"], [original])
            self.revalidate(guard, snapshot)
        with self.raw() as conn:
            self.assertEqual(dict(conn.execute("SELECT * FROM queue WHERE request_key=?", (request_key,)).fetchone()), original)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reservations").fetchone()[0], 0)

    def test_actual_original_nonempty_terminal_receipt_and_journal_are_revalidated(self):
        terminal, case = self.terminal_history()
        with self.held() as guard, terminal.forbid_native_reentry(case):
            snapshot = self.capture(guard)
            self.revalidate(guard, snapshot)
            full = json.loads(inventory._SNAPSHOTS[snapshot].full_ledger)
            self.assertEqual(full["tables"]["managed_executions"][0]["execution_id"], case.spec.execution_id)
            self.assertTrue(full["tables"]["adaptive_terminal_custody_receipts"])

    def test_changed_actual_manifest_refuses_capture_without_replacing_original(self):
        terminal, case = self.terminal_history()
        self.complete()
        path = terminal.journal_dir / (case.spec.execution_id + ".json")
        original = path.read_bytes()
        with self.held() as guard:
            path.write_bytes(b"{}")
            try:
                with self.assertRaises(Exception):
                    self.capture(guard)
            finally:
                path.write_bytes(original)
            self.revalidate(guard, self.capture(guard))

    def test_extra_journal_entry_is_not_hidden_by_empty_predecessor_rows(self):
        self.complete()
        extra = self.retirement.journal._directory / (str(uuid4()) + ".json")
        with self.held() as guard:
            extra.write_text("{}", encoding="utf-8")
            try:
                with self.assertRaisesRegex(LifecycleError, "journal_extra_entry"):
                    self.capture(guard)
            finally:
                extra.unlink()

    def test_changed_original_runtime_is_not_an_allowed_nonce_substitution(self):
        self.complete()
        with self.held() as guard:
            with self.raw() as conn:
                conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
            with self.assertRaisesRegex(LifecycleError, "predecessor_changed"):
                self.capture(guard)

    def test_added_schema_is_not_a_new_ordinary_observation(self):
        self.complete()
        with self.held() as guard:
            with self.raw() as conn:
                conn.execute("CREATE TABLE unknown_successor_table(value TEXT)")
            try:
                with self.assertRaisesRegex(LifecycleError, "schema_changed"):
                    self.capture(guard)
            finally:
                with self.raw() as conn:
                    conn.execute("DROP TABLE unknown_successor_table")

    def test_ordinary_cell_and_row_bounds_apply_before_unbounded_payload_read(self):
        self.complete()
        with self.held() as guard:
            self.seed_sample(text="x" * (prior._CELL_BYTES + 1))
            with self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
                self.capture(guard)
            with self.raw() as conn:
                conn.execute("DELETE FROM resource_samples")
                conn.executemany("INSERT INTO resource_samples(sampled_at) VALUES(?)",
                    ((index,) for index in range(inventory.MAX_HISTORY + 1)))
            with self.assertRaisesRegex(LifecycleError, "history_exceeded"):
                self.capture(guard)

    def test_snapshot_copies_and_caller_minted_tokens_have_no_registration(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            for foreign in (copy.copy(snapshot), object.__new__(inventory.SuccessorInventorySnapshot)):
                with self.subTest(kind=type(foreign)), self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                    self.revalidate(guard, foreign)
            with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                inventory.SuccessorInventorySnapshot()
            self.revalidate(guard, snapshot)

    def test_exact_guard_binding_nonce_thread_and_process_are_retained(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            foreign = PolicyGuard(guard.binding, guard.nonce)
            with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                self.revalidate(foreign, snapshot)
            with self.operation._connection(readonly=True) as conn:
                conn.execute("BEGIN")
                for module, name, value in ((inventory.os, "getpid", self.operation._pid + 1),
                        (inventory.threading, "current_thread", threading.Thread())):
                    with patch.object(module, name, return_value=value), \
                            self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                        inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
                with patch.object(guard, "nonce", str(uuid4())), \
                        self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                    inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
                conn.rollback()
            self.revalidate(guard, snapshot)

    def test_missing_transaction_and_foreign_main_ledger_are_refused(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            with self.operation._connection(readonly=True) as conn:
                with self.assertRaisesRegex(LifecycleError, "transaction_required"):
                    inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
            alternate = self.db.with_name("other.sqlite3")
            with self.raw(alternate) as conn:
                conn.execute("BEGIN")
                with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                    inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)

    def test_original_temporary_nonce_guard_is_exact_and_old_reader_stays_strict(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            with self.operation._connection(readonly=True) as conn:
                conn.execute("BEGIN")
                self.assertEqual({row[1] for row in conn.execute("PRAGMA database_list")}, {"main", "temp"})
                rows = conn.execute("SELECT type,name,tbl_name,sql FROM temp.sqlite_master").fetchall()
                self.assertEqual(len(rows), 1)
                self.assertEqual(tuple(rows[0][:3]) + (" ".join(rows[0][3].split()),), inventory._nonce_guard())
                self.assertIsNone(inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot))
                with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                    prior._connection_path(conn, self.db)
                conn.rollback()

    def test_original_connection_rejects_extra_temp_objects_and_attached_databases(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            original_connect = sqlite3.connect
            cases = (
                ("CREATE TEMP TABLE unrelated(value TEXT)", "temporary_schema_changed"),
                ("CREATE TEMP VIEW adaptive_runtime AS SELECT * FROM main.adaptive_runtime", "temporary_schema_changed"),
                ("ATTACH DATABASE ':memory:' AS foreign_database", "ledger_changed"),
            )
            for statement, reason in cases:
                # Inject unexpected connection-local state before the actual
                # operation installs its guard/authorizer. Neither is disabled.
                def connect(*args, **kwargs):
                    conn = original_connect(*args, **kwargs)
                    conn.execute(statement)
                    return conn

                with self.subTest(statement=statement), patch.object(sqlite3, "connect", side_effect=connect):
                    with self.operation._connection(readonly=True) as conn:
                        conn.execute("BEGIN")
                        with self.assertRaisesRegex(LifecycleError, reason):
                            inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
                        conn.rollback()
            self.revalidate(guard, snapshot)

    def test_missing_or_changed_original_temp_guard_is_not_accepted_by_name(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            original_connect = sqlite3.connect
            for fault in ("missing", "changed"):
                class FaultedTempGuard(sqlite3.Connection):
                    def execute(conn, sql, parameters=()):
                        if sql == successor._NONCE_TRIGGER_SQL:
                            if fault == "missing":
                                return super().execute("SELECT 1")
                            sql = sql.replace("IS NOT 1", "IS NOT 0")
                        return super().execute(sql, parameters)

                def connect(*args, **kwargs):
                    kwargs["factory"] = FaultedTempGuard
                    return original_connect(*args, **kwargs)

                with self.subTest(fault=fault), patch.object(sqlite3, "connect", side_effect=connect):
                    with self.operation._connection(readonly=True) as conn:
                        conn.execute("BEGIN")
                        with self.assertRaisesRegex(LifecycleError, "temporary_schema_changed"):
                            inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
                        conn.rollback()
            self.revalidate(guard, snapshot)

    def test_foreign_same_ledger_connection_cannot_copy_original_temp_guard(self):
        with self.held() as guard:
            snapshot = self.capture(guard)
            for copy_trigger in (False, True):
                with self.subTest(copy_trigger=copy_trigger), self.raw() as conn:
                    if copy_trigger:
                        conn.execute(successor._NONCE_TRIGGER_SQL)
                    conn.execute("BEGIN")
                    with self.assertRaises(DailySuccessorError):
                        inventory.revalidate_successor_inventory(conn, self.retirement, guard, snapshot)
                    conn.rollback()

    def test_original_retirement_and_ambient_distinct_guard_are_required(self):
        with self.assertRaises(Exception):
            inventory.capture_successor_inventory(self.retirement, self.retirement._seal_guard)
        operation = self.complete()
        with self.assertRaises(Exception):
            self.capture(operation.guard)
        with self.held() as guard:
            with self.assertRaises(Exception):
                inventory.capture_successor_inventory(copy.copy(self.retirement), guard)
            with self.assertRaisesRegex(LifecycleError, "distinct_policy_required"):
                self.capture(self.retirement._seal_guard)

    def test_reader_close_error_retains_exact_connection_and_mints_no_snapshot(self):
        self.complete()
        original_connect = sqlite3.connect
        raised = []

        class CloseAckLost(sqlite3.Connection):
            def close(conn):
                super().close()
                error = RuntimeError("fixture_read_close_ack_lost")
                raised.append((conn, error))
                raise error

        def connect(*args, **kwargs):
            kwargs["factory"] = CloseAckLost
            return original_connect(*args, **kwargs)

        before = len(inventory._SNAPSHOTS)
        with self.assertRaisesRegex(RuntimeError, "fixture_read_close_ack_lost") as caught:
            with self.held() as guard:
                with patch.object(sqlite3, "connect", side_effect=connect):
                    self.capture(guard)
        self.assertEqual(len(inventory._SNAPSHOTS), before)
        self.assertEqual(len(raised), 1)
        self.assertIs(caught.exception, raised[0][1])
        retained = [item for item in self.operation._connections if item.connection is raised[0][0]]
        self.assertEqual(len(retained), 1)
        self.assertFalse(retained[0].closed)
        self.assertTrue(retained[0].close_unknown)
        self.assertIs(self.operation._error, caught.exception)
        self.assertIsNotNone(self.operation._quarantine)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown reader replaced")):
            with self.assertRaisesRegex(DailySuccessorError, "custody_unsettled"):
                self.operation.tick()

    def assert_inventory_open_result_lost(self, reader_number):
        self.complete()
        original_connect = sqlite3.connect
        undisclosed, attempted = [], []
        failure = RuntimeError("fixture_inventory_open_result_lost")

        def connect(*args, **kwargs):
            conn = original_connect(*args, **kwargs)
            attempted.append(conn)
            if len(attempted) == reader_number:
                # Only fixture teardown may close this undisclosed result. The
                # operation owns the original pending acquisition, not a handle
                # reconstructed from the test's independent observation.
                undisclosed.append(conn)
                self.addCleanup(sqlite3.Connection.close, conn)
                raise failure
            return conn

        before = len(inventory._SNAPSHOTS)
        with self.assertRaisesRegex(RuntimeError, "fixture_inventory_open_result_lost") as caught:
            with self.held() as guard:
                original_count = len(self.operation._connections)
                with patch.object(sqlite3, "connect", side_effect=connect):
                    self.capture(guard)
        self.assertIs(caught.exception, failure)
        self.assertIs(failure._daily_successor_operation, self.operation)
        self.assertIn("daily_successor_sql_acquisition_unknown", failure.__notes__)
        self.assertIs(self.operation._error, failure)
        self.assertIsNotNone(self.operation._quarantine)
        self.assertEqual(len(inventory._SNAPSHOTS), before)
        self.assertEqual(len(attempted), reader_number)
        acquisitions = self.operation._connections[original_count:]
        self.assertEqual(len(acquisitions), reader_number)
        for index, custody in enumerate(acquisitions[:-1]):
            self.assertIs(custody.connection, attempted[index])
            self.assertTrue(custody.closed)
            self.assertFalse(custody.close_unknown)
        pending = acquisitions[-1]
        self.assertIsNone(pending.connection)
        self.assertFalse(pending.closed)
        self.assertEqual(self.operation._connection_pins[id(pending)], (pending, None))
        self.assertEqual(len(undisclosed), 1)
        self.assertEqual(undisclosed[0].execute("SELECT 1").fetchone()[0], 1)
        self.assertIsNone(self.operation.owner)
        self.assertFalse(self.operation._complete)
        with (patch.object(sqlite3, "connect", side_effect=AssertionError("unknown acquisition replaced")),
              patch.object(inventory.generation.DailyGenerationOwner, "capture",
                  side_effect=AssertionError("unknown acquisition bypassed by native capture"))):
            with self.assertRaisesRegex(DailySuccessorError, "custody_unsettled"):
                self.operation.tick()
        self.assertIs(self.operation._connections[-1], pending)

    def test_first_inventory_reader_open_result_lost_retains_original_pending_acquisition(self):
        self.assert_inventory_open_result_lost(1)

    def test_second_inventory_reader_open_result_lost_retains_first_closed_and_second_pending(self):
        self.assert_inventory_open_result_lost(2)


if __name__ == "__main__":
    unittest.main()
