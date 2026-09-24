"""Original published startup observations; native effects are explicit fixtures.

These tests use real isolated retirement, succession, serving-thread publication,
startup/POLICY ownership, SQLite and immutable audit validation. No native gate,
daily installation or guardian process creation is performed by these fixtures.
"""
from contextlib import contextmanager, nullcontext
import copy
from dataclasses import FrozenInstanceError
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_epoch as epochs
from sentinel.adaptive import daily_successor_startup_inventory as inventory
from sentinel.adaptive.daily_successor import DailySuccessorError
from sentinel.adaptive.policy import PolicyGuard
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_daily_successor_host as host_fixture
from tests import test_adaptive_daily_successor_inventory as transfer_fixture
from tests import test_adaptive_daily_successor_predecessor as predecessor_fixture


class DailySuccessorStartupInventoryTests(unittest.TestCase):
    def initialize(self, *, terminal=False):
        # Unknown custody must stay retained throughout each assertion. Give
        # this synthetic ledger its own registry, restored only after fixture
        # teardown, so it cannot consume a later test's actual pool budget.
        self.readiness_scopes = {}
        readiness_registry = patch.object(generation, "_READINESS_SCOPES", self.readiness_scopes)
        readiness_registry.start()
        self.addCleanup(readiness_registry.stop)
        self.fixture = host_fixture.DailySuccessorHostTests()
        self.addCleanup(self.fixture.doCleanups)
        original_complete = predecessor_fixture.DailySuccessorPredecessorTests.complete
        self.terminal = self.case = None

        def complete(predecessor):
            # Reuse the actual terminal/receipt helper before original retire,
            # not a synthetic terminal row inserted after its seal.
            helper = transfer_fixture.DailySuccessorInventoryTests()
            self.addCleanup(helper.doCleanups)
            helper.fixture, helper.retirement = predecessor, predecessor.operation
            helper.db, helper.operation = predecessor.fixture.db, None
            self.terminal, self.case = helper.terminal_history()
            return original_complete(predecessor)

        with (patch.object(predecessor_fixture.DailySuccessorPredecessorTests, "complete", complete)
              if terminal else nullcontext()):
            self.fixture.setUp()
        self.host = self.fixture.publish_host()
        self.supervisor = self.fixture.acquire_supervisor(self.host)
        self.operation, self.store = self.fixture.operation, self.fixture.store
        self.db = self.operation.ledger_path

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

    @contextmanager
    def held(self):
        with self.operation.startup_sql_scope(self.supervisor):
            guard = self.store._policy.prepare(self.supervisor.startup.binding.logon_id)
            with self.store._policy.hold(guard):
                yield guard

    def capture(self, guard):
        return inventory.capture_startup_inventory(self.operation, self.supervisor, guard)

    def revalidate(self, guard, snapshot):
        with self.store._transaction() as conn:
            self.assertIsNone(inventory.revalidate_startup_inventory(
                conn, self.operation, self.supervisor, guard, snapshot))

    def assert_empty_experiment_history_accounting(self, snapshot, *, epoch_rows):
        with self.store._transaction() as conn:
            experiments = inventory.experiment_history.verify_experiment_history_locked(conn)
            successions = inventory.succession.read_successor_history(conn)
            audits = epochs.read_successor_guardian_epochs(conn)
            revision = conn.execute("SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0]
        self.assertFalse(experiments.completed_execution_ids)
        self.assertFalse(experiments.active_experiment_ids)
        # Even this empty experiment fixture observes and charges the current
        # runtime revision once. It is part of the verifier's actual SQL rows.
        self.assertEqual([(row.table, row.fields, row.values) for row in experiments._sql_rows],
            [("adaptive_runtime", ("registry_revision",), (revision,))])
        self.assertEqual(experiments.rows_used, 1)
        self.assertEqual(successions.rows_used, 1)
        self.assertEqual(audits.rows_used, epoch_rows)
        total = experiments.rows_used + successions.rows_used + audits.rows_used
        self.assertEqual(snapshot.budget.history_rows, total)
        self.assertEqual(snapshot.budget.remaining_history_rows, inventory.MAX_HISTORY - total)

    def test_original_published_startup_retains_complete_snapshot_and_closed_readers(self):
        self.initialize()
        with self.held() as guard:
            snapshot = self.capture(guard)
            captured = inventory._SNAPSHOTS[snapshot]
            self.assertIs(captured.operation, self.operation)
            self.assertIs(captured.supervisor, self.supervisor)
            self.assertIs(captured.guard, guard)
            self.assertIsNot(guard, self.operation.guard)
            self.assertEqual(len(captured.readers), 2)
            for conn in captured.readers:
                with self.assertRaises(sqlite3.ProgrammingError):
                    conn.execute("SELECT 1")
            full = json.loads(captured.full_ledger)
            self.assertEqual(full["tables"]["adaptive_daily_generation"], [self.operation._successor_row])
            self.assertNotIn("adaptive_daily_retirement", full["tables"])
            self.assertEqual(len(full["tables"]["adaptive_generation_successions"]), 1)
            self.assertEqual(full["tables"]["queue"][0]["request_key"], "unrelated")
            self.assertEqual(len(snapshot.digest), 64)
            self.assert_empty_experiment_history_accounting(snapshot, epoch_rows=0)
            self.assertGreater(snapshot.budget.bytes_used, len(captured.full_ledger))
            with self.assertRaises(FrozenInstanceError):
                snapshot.budget.bytes_used = 0
            with patch.object(inventory.prior, "_journal_inventory", side_effect=AssertionError("journal I/O inside TX")):
                self.revalidate(guard, snapshot)

    def test_ordinary_rows_can_change_before_capture_but_not_before_final_transaction(self):
        self.initialize()
        with self.raw(prepare=True) as conn:
            conn.execute("UPDATE queue SET heartbeat_at=210 WHERE request_key='unrelated'")
            conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,'current-observation')")
            conn.execute("""INSERT INTO reservations(id,request_key,owner_pid,owner_started,
                repo,command_signature,command_text,resource_class,priority,priority_rank,
                cpu_units,ram_gib,io_slots,created_at,heartbeat_at,expires_at)
                VALUES('ordinary','ordinary',9001,12,'fixture','signature','','HEAVY','P2',2,1,1,0,100,100,700)""")
        with self.held() as guard:
            snapshot = self.capture(guard)
            full = json.loads(inventory._SNAPSHOTS[snapshot].full_ledger)
            self.assertEqual(full["tables"]["reservations"][0]["id"], "ordinary")
            self.revalidate(guard, snapshot)
            with self.raw() as conn:
                conn.execute("UPDATE resource_samples SET disk_json='changed-after-capture'")
            with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                self.revalidate(guard, snapshot)
            self.revalidate(guard, self.capture(guard))

    def test_actual_nonempty_terminal_receipt_and_journal_remain_exact(self):
        self.initialize(terminal=True)
        with self.held() as guard, self.terminal.forbid_native_reentry(self.case):
            snapshot = self.capture(guard)
            self.revalidate(guard, snapshot)
            captured = inventory._SNAPSHOTS[snapshot]
            self.assertEqual(captured.preimage[2][0][0], self.case.spec.execution_id)
            self.assertIn(self.case.spec.execution_id.encode(), captured.full_ledger)
            path = self.terminal.journal_dir / (self.case.spec.execution_id + ".json")
            original = path.read_bytes()
            try:
                path.write_bytes(b"{}")
                with self.assertRaises(Exception):
                    self.capture(guard)
            finally:
                path.write_bytes(original)
            self.revalidate(guard, snapshot)

    def test_original_snapshot_copy_and_caller_minted_token_are_refused(self):
        self.initialize()
        with self.held() as guard:
            snapshot = self.capture(guard)
            for other in (copy.copy(snapshot), object.__new__(inventory.StartupInventorySnapshot)):
                with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                    self.revalidate(guard, other)
            with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                inventory.StartupInventorySnapshot()
            self.revalidate(guard, snapshot)

    def test_original_operation_supervisor_guard_and_lexical_thread_are_bound(self):
        self.initialize()
        with self.held() as guard:
            snapshot = self.capture(guard)
            for operation, supervisor, other_guard in (
                    (copy.copy(self.operation), self.supervisor, guard),
                    (self.operation, copy.copy(self.supervisor), guard),
                    (self.operation, self.supervisor, PolicyGuard(guard.binding, guard.nonce))):
                with self.store._transaction() as conn:
                    with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                        inventory.revalidate_startup_inventory(conn, operation, supervisor, other_guard, snapshot)
            with self.store._transaction() as conn:
                current = threading.current_thread()
                for name, value in (("getpid", self.operation._pid + 1), ("current_thread", threading.Thread())):
                    module = inventory.os if name == "getpid" else inventory.threading
                    with patch.object(module, name, return_value=value), self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                        inventory.revalidate_startup_inventory(conn, self.operation, self.supervisor, guard, snapshot)
                self.assertIs(threading.current_thread(), current)
            self.revalidate(guard, snapshot)

    def test_snapshot_cannot_cross_distinct_positive_policy_scopes(self):
        self.initialize()
        with self.held() as guard:
            snapshot = self.capture(guard)
        with self.held() as newer:
            self.assertIsNot(newer, guard)
            with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                self.revalidate(newer, snapshot)
            self.revalidate(newer, self.capture(newer))

    def test_unpublished_or_substituted_host_refuses_before_sql_acquisition(self):
        self.initialize()
        with self.held() as guard:
            with patch.object(self.host, "_service", copy.copy(self.host._service)), \
                    patch.object(sqlite3, "connect", side_effect=AssertionError("unpublished SQL")), \
                    self.assertRaises(DailySuccessorError):
                self.capture(guard)

    def test_foreign_same_path_and_attached_connections_cannot_revalidate(self):
        self.initialize()
        with self.held() as guard:
            snapshot = self.capture(guard)
            with self.raw() as conn:
                conn.execute("BEGIN")
                with self.assertRaisesRegex(DailySuccessorError, "original_startup_connection_required"):
                    inventory.revalidate_startup_inventory(conn, self.operation, self.supervisor, guard, snapshot)
            with self.store._connection() as conn:
                conn.execute("ATTACH DATABASE ':memory:' AS other")
                conn.execute("BEGIN")
                with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                    inventory.revalidate_startup_inventory(conn, self.operation, self.supervisor, guard, snapshot)
                conn.rollback()

    def test_new_schema_runtime_change_and_managed_queue_are_independent_refusals(self):
        self.initialize()
        cases = (("CREATE TABLE unobserved_startup(value TEXT)", "DROP TABLE unobserved_startup", "schema_changed"),
            ("UPDATE adaptive_runtime SET registry_revision=registry_revision+1",
             "UPDATE adaptive_runtime SET registry_revision=registry_revision-1", "runtime_changed"),
            ("UPDATE queue SET managed_execution_id='unverified-scope' WHERE request_key='unrelated'",
             "UPDATE queue SET managed_execution_id=NULL WHERE request_key='unrelated'", "managed_obligation_remaining"))
        with self.held() as guard:
            for mutate, restore, reason in cases:
                with self.subTest(reason=reason):
                    with self.raw(prepare=True) as conn:
                        conn.execute(mutate)
                    try:
                        with self.assertRaisesRegex(LifecycleError, reason):
                            self.capture(guard)
                    finally:
                        with self.raw(prepare=True) as conn:
                            conn.execute(restore)
            self.revalidate(guard, self.capture(guard))

    def test_unexpected_infrastructure_and_journal_entry_are_not_subset_proofs(self):
        self.initialize()
        with self.held() as guard:
            with self.raw(prepare=True) as conn:
                conn.execute("INSERT INTO adaptive_infrastructure VALUES('guardian',?,?,?,1)",
                    (9001, "12345", guard.binding.logon_id))
            try:
                with self.assertRaisesRegex(LifecycleError, "retired_history_changed|managed_obligation_remaining"):
                    self.capture(guard)
            finally:
                with self.raw(prepare=True) as conn:
                    conn.execute("DELETE FROM adaptive_infrastructure")
            path = self.operation.retirement.journal._directory / (str(uuid4()) + ".json")
            path.write_text("{}", encoding="utf-8")
            try:
                with self.assertRaisesRegex(LifecycleError, "journal_extra_entry"):
                    self.capture(guard)
            finally:
                path.unlink()

    def test_full_ordinary_cell_and_row_bounds_refuse_without_truncation(self):
        self.initialize()
        with self.held() as guard:
            with self.raw() as conn:
                conn.execute("INSERT INTO resource_samples(sampled_at,disk_json) VALUES(1,?)",
                    ("x" * (inventory.prior._CELL_BYTES + 1),))
            with self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
                self.capture(guard)
            with self.raw() as conn:
                conn.execute("DELETE FROM resource_samples")
                conn.executemany("INSERT INTO resource_samples(sampled_at) VALUES(?)",
                    ((index,) for index in range(inventory.MAX_HISTORY + 1)))
            with self.assertRaisesRegex(LifecycleError, "history_exceeded"):
                self.capture(guard)

    def test_original_completed_epoch_is_the_only_allowed_runtime_and_audit_addition(self):
        self.initialize()
        epoch = epochs.SuccessorGuardianEpoch(self.operation, self.supervisor)
        result = epoch.tick()
        self.assertTrue(result.complete, result)
        self.assertTrue(epoch._complete)
        with self.held() as guard:
            snapshot = self.capture(guard)
            self.revalidate(guard, snapshot)
            full = json.loads(inventory._SNAPSHOTS[snapshot].full_ledger)
            expected = dict(zip(epochs._FIELDS, epoch._candidate))
            self.assertEqual(full["tables"][epochs.TABLE], [expected])
            self.assertEqual(full["tables"]["adaptive_runtime"][0]["guardian_epoch"], epoch.new_epoch)
            self.assert_empty_experiment_history_accounting(snapshot, epoch_rows=1)
            with patch.object(self.operation, "_guardian_epoch_operation", copy.copy(epoch)):
                with self.assertRaises(Exception):
                    self.capture(guard)
            self.revalidate(guard, snapshot)

    def test_reader_acquisition_lost_result_retains_original_and_refuses_reopen(self):
        self.initialize()
        connect = sqlite3.connect
        error = RuntimeError("fixture_startup_reader_result_lost")
        opened = []

        def lost(*args, **kwargs):
            conn = connect(*args, **kwargs)
            opened.append(conn)
            self.addCleanup(sqlite3.Connection.close, conn)
            raise error

        before = len(inventory._SNAPSHOTS)
        with self.assertRaisesRegex(RuntimeError, "fixture_startup_reader_result_lost") as caught:
            with self.held() as guard:
                with patch.object(sqlite3, "connect", side_effect=lost):
                    self.capture(guard)
        self.assertIs(caught.exception, error)
        self.assertIs(error._daily_successor_operation, self.operation)
        retained_scope = error.daily_readiness_scope
        self.assertIs(type(retained_scope), generation._ReadinessScope)
        self.assertIs(retained_scope.error, error)
        self.assertIs(retained_scope.pool, self.readiness_scopes)
        self.assertIs(self.readiness_scopes[id(retained_scope)], retained_scope)
        self.assertFalse(retained_scope.closed)
        self.assertEqual(len(opened), 1)
        pending = self.operation._connections[-1]
        self.assertIsNone(pending.connection)
        self.assertFalse(pending.closed)
        self.assertEqual(len(inventory._SNAPSHOTS), before)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("replacement SQL")):
            with self.assertRaisesRegex(DailySuccessorError, "custody_unsettled"):
                self.operation.assert_supervisor(self.supervisor)

    def test_reader_close_ack_loss_retains_exact_owner_without_snapshot(self):
        self.initialize()
        connect = sqlite3.connect
        error = RuntimeError("fixture_startup_reader_close_unknown")
        closed = []

        class CloseAckLost(sqlite3.Connection):
            def close(conn):
                super().close()
                closed.append(conn)
                raise error

        def lost(*args, **kwargs):
            kwargs["factory"] = CloseAckLost
            return connect(*args, **kwargs)

        before = len(inventory._SNAPSHOTS)
        with self.assertRaisesRegex(RuntimeError, "fixture_startup_reader_close_unknown") as caught:
            with self.held() as guard:
                with patch.object(sqlite3, "connect", side_effect=lost):
                    self.capture(guard)
        self.assertIs(caught.exception, error)
        self.assertEqual(len(closed), 1)
        pending = self.operation._connections[-1]
        self.assertIs(pending.connection, closed[0])
        self.assertFalse(pending.closed)
        self.assertTrue(pending.close_unknown)
        self.assertEqual(len(inventory._SNAPSHOTS), before)
        self.assertIsNotNone(self.operation._quarantine)


if __name__ == "__main__":
    unittest.main()
