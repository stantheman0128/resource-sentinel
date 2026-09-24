"""Original fresh-startup custody over real isolated SQL and retained history.

Native identities, mutexes and pipes are explicit synthetic collaborators from
the published-host fixture. Production startup, successor/readiness validation,
POLICY and SQLite execute unchanged. These tests create no guardian process and
establish no native activation or restart evidence.
"""
from contextlib import contextmanager
import copy
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_scope as successor_scope
from sentinel.adaptive.daily_successor import DailySuccessorError
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_host import SupervisorHost
from sentinel.adaptive.supervisor_startup import SupervisorStartup, supervisor_instance_binding
from tests import test_adaptive_daily_successor_host as host_fixture
from tests import test_adaptive_guardian_launch as process_fixture
from tests import test_adaptive_supervisor_startup as startup_fixture


class DailySuccessorStartupTests(unittest.TestCase):
    def setUp(self):
        self.readiness_scopes = {}
        registry = patch.object(generation, "_READINESS_SCOPES", self.readiness_scopes)
        registry.start()
        self.addCleanup(registry.stop)
        self.fixture = host_fixture.DailySuccessorHostTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host = self.fixture.publish_host()
        self.operation, self.store = self.fixture.operation, self.fixture.store
        self.retirement = self.fixture.retirement
        self.raw_connections = []
        self.addCleanup(self.close_raw_fixture_connections)
        self.held, self.mutexes = {}, []

    def close_raw_fixture_connections(self):
        for connection in self.raw_connections:
            # Physically release this isolated fixture resource only. No
            # original operation/readiness custody flags are cleared or fixed.
            sqlite3.Connection.close(connection)

    def prepare_startup(self):
        supervisor = SupervisorHost(data_dir=self.host.data_dir,
            journal_dir=self.host.journal_dir, child_cwd=self.host.source_root,
            telemetry_factory=lambda: None)
        self.host.supervisor, self.host._supervisor_attempted = supervisor, True
        supervisor._daily_successor_operation = self.operation
        self.operation.bind_supervisor(supervisor)
        supervisor.store, supervisor.journal = self.store, self.retirement.journal
        self.native = process_fixture.ProcessBackend()
        self.current = self.native.process(self.host.owner.process.identity)
        self.addCleanup(self.current.close)

        def mutex_factory(logon, instance):
            mutex = startup_fixture.Mutex(self, logon, instance)
            self.mutexes.append(mutex)
            return mutex

        startup = SupervisorStartup(self.store, self.retirement.journal,
            current=self.current, mutex_factory=mutex_factory)
        supervisor.startup = startup
        startup._daily_successor_operation = self.operation
        startup._daily_successor_supervisor = supervisor
        self.supervisor, self.startup = supervisor, startup
        self.addCleanup(self.close_startup_fixture)
        return startup

    def close_startup_fixture(self):
        try:
            self.startup.close()
        except (DailySuccessorError, LifecycleError, generation.DailyGenerationUnavailable):
            # Deliberately unknown acquisitions must remain held. All retained
            # native handles here belong to an explicit in-memory backend.
            if not (self.operation._quarantine is not None or any(
                    not item.closed or item.close_unknown for item in self.operation._connections)):
                raise
            if self.startup._acquired and self.startup._scope is not None:
                self.startup._scope.__exit__(None, None, None)
            if self.startup._mutex is not None:
                self.startup._mutex.close()
            if self.startup._current is not None:
                self.startup._current.close()

    def runtime(self):
        with self.fixture.fixture.fixture.reader() as conn:
            return dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())

    def history(self):
        return (self.fixture.fixture.ordinary_rows(), self.fixture.fixture.archives(),
                self.fixture.fixture.exemption_rows())

    @contextmanager
    def rw_fault(self, kind):
        """Fault only original Store rw acquisition/close, after real effects."""
        connect = sqlite3.connect
        error = RuntimeError("fixture_startup_" + kind)
        observed = dict(error=error, raised=False, attempts=0, connections=[], pending=[], prepared=[])
        test = self

        class Connection(sqlite3.Connection):
            fixture_prepare = False

            def execute(connection, sql, parameters=()):
                result = super().execute(sql, parameters)
                if " ".join(sql.split()) == (
                        "UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?,"
                        "policy_entry_nonce=?,policy_binding_initialized=1 "
                        "WHERE singleton=1 AND policy_entry_nonce IS NULL"):
                    test.assertEqual(result.rowcount, 1)
                    connection.fixture_prepare = True
                    observed["prepared"].append((connection, tuple(parameters)))
                return result

            def close(connection):
                result = super().close()
                if (not observed["raised"] and
                        (kind == "close_ack" or kind == "prepare_close_ack" and connection.fixture_prepare)):
                    observed["raised"] = True
                    raise error
                return result

        def capture(target, *args, **kwargs):
            if "?mode=rw" not in str(target):
                return connect(target, *args, **kwargs)
            observed["attempts"] += 1
            test.assertIs(successor_scope.current_startup_operation(), test.operation)
            pending = test.operation._connections[-1]
            test.assertIsNone(pending.connection)
            test.assertFalse(pending.closed)
            observed["pending"].append(pending)
            kwargs["factory"] = Connection
            connection = connect(target, *args, **kwargs)
            test.raw_connections.append(connection)
            observed["connections"].append(connection)
            if kind == "open_result_lost" and not observed["raised"]:
                observed["raised"] = True
                raise error
            return connection

        with patch.object(sqlite3, "connect", side_effect=capture):
            yield observed

    def test_new_instance_acquisition_tracks_original_sql_and_preserves_predecessor(self):
        startup = self.prepare_startup()
        first = len(self.operation._connections)
        self.assertIs(startup.acquire(), startup)
        self.assertTrue(startup.acquired)
        self.assertIsNot(startup._current, self.current)
        self.assertEqual(startup._current.identity, self.current.identity)
        self.assertEqual(startup.instance_binding, supervisor_instance_binding(self.operation.guard.binding))
        self.assertIsNot(startup, self.retirement.supervisor.startup)
        self.assertTrue(self.retirement.supervisor.startup._closed)
        self.assertIs(self.operation._startup_pins[1], startup)
        tracked = self.operation._connections[first:]
        self.assertTrue(tracked)
        self.assertTrue(all(item.closed and not item.close_unknown for item in tracked))
        self.operation.assert_supervisor(self.supervisor)
        self.retirement.assert_successor_predecessor()
        self.assertIsNone(successor_scope.current_startup_operation())

    def test_binding_is_retained_before_first_original_process_duplicate(self):
        startup = self.prepare_startup()
        duplicate = self.current.duplicate
        observed = []

        def original_duplicate():
            self.assertIs(self.operation._startup_pins[0], self.supervisor)
            self.assertIs(self.operation._startup_pins[1], startup)
            self.assertIsNone(startup._current)
            observed.append(startup)
            return duplicate()

        with patch.object(self.current, "duplicate", side_effect=original_duplicate):
            startup.acquire()
        self.assertEqual(observed, [startup])
        self.assertTrue(startup.acquired)

    def test_copied_unentered_startup_cannot_acquire_original_binding(self):
        startup = self.prepare_startup()
        copied = copy.copy(startup)
        with patch.object(self.current, "duplicate", side_effect=AssertionError("foreign duplicate")), \
                self.assertRaises((DailySuccessorError, LifecycleError)):
            copied.acquire()
        self.assertFalse(startup._attempted)
        self.assertIsNone(startup._current)
        self.assertIsNone(startup._mutex)
        startup.acquire()
        self.operation.assert_supervisor(self.supervisor)

    def test_replaced_startup_refuses_inspection_without_new_sql_or_mutex(self):
        startup = self.prepare_startup()
        startup.acquire()
        original_mutex = startup._mutex
        with patch.object(self.supervisor, "startup", copy.copy(startup)), \
                patch.object(sqlite3, "connect", side_effect=AssertionError("replacement startup SQL")), \
                self.assertRaises((DailySuccessorError, LifecycleError)):
            startup.assert_fresh()
        self.assertIs(startup._mutex, original_mutex)
        self.assertTrue(startup.acquired)
        self.operation.assert_supervisor(self.supervisor)

    def test_unknown_first_store_open_retains_none_owner_and_refuses_retry_or_close(self):
        startup = self.prepare_startup()
        first = len(self.operation._connections)
        with self.rw_fault("open_result_lost") as observed:
            with self.assertRaisesRegex(RuntimeError, "fixture_startup_open_result_lost") as caught:
                startup.acquire()
        self.assertIs(caught.exception, observed["error"])
        self.assertIs(startup._acquire_error, caught.exception)
        self.assertIs(caught.exception._daily_successor_operation, self.operation)
        self.assertEqual(observed["attempts"], 1)
        self.assertEqual(self.operation._connections[first:], observed["pending"])
        original = observed["pending"][0]
        self.assertIsNone(original.connection)
        self.assertFalse(original.closed)
        self.assertIsNone(startup._mutex)
        retained_process = startup._current
        self.assertIsNotNone(retained_process._handle)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown opener repeated")):
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.retry_acquire()
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.close()
        self.assertFalse(startup._closed)
        self.assertIs(startup._current, retained_process)
        self.assertFalse(original.closed)

    def test_first_store_close_ack_unknown_blocks_clean_startup_close(self):
        startup = self.prepare_startup()
        first = len(self.operation._connections)
        with self.rw_fault("close_ack") as observed:
            with self.assertRaisesRegex(LifecycleError, "connection_cleanup_failed") as caught:
                startup.acquire()
        self.assertTrue(observed["raised"])
        original = self.operation._connections[first]
        self.assertIs(original.connection, observed["connections"][0])
        self.assertFalse(original.closed)
        self.assertIs(caught.exception._sentinel_connection_cleanup, original.connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            original.connection.execute("SELECT 1")  # Physical close is not a received close ACK.
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown cleanup reopened")):
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.close()
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.retry_acquire()
        self.assertFalse(startup._closed)
        self.assertFalse(original.closed)
        self.assertIsNotNone(startup._current)

    def test_unknown_readiness_reader_stays_in_original_registry_before_store_open(self):
        startup = self.prepare_startup()
        original_connect = sqlite3.connect
        error = RuntimeError("fixture_startup_readiness_open_result_lost")
        attempts = []
        first = len(self.operation._connections)

        def lost(target, *args, **kwargs):
            self.assertIn("?mode=ro", str(target))
            connection = original_connect(target, *args, **kwargs)
            self.raw_connections.append(connection)
            attempts.append(connection)
            raise error

        with patch.object(sqlite3, "connect", side_effect=lost), \
                self.assertRaisesRegex(RuntimeError, "readiness_open_result_lost") as caught:
            startup.acquire()
        self.assertIs(caught.exception, error)
        original = error.daily_readiness_scope
        self.assertIs(original.pool, self.readiness_scopes)
        self.assertIs(self.readiness_scopes[id(original)], original)
        self.assertIs(original.error, error)
        self.assertTrue(original.reader.open_attempted)
        self.assertIsNone(original.reader.connection)
        self.assertFalse(original.reader.closed)
        self.assertFalse(original.closed)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(len(self.operation._connections), first)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("readiness owner replaced")):
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.retry_acquire()
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.close()
        self.assertIs(self.readiness_scopes[id(original)], original)
        self.assertFalse(startup._closed)

    def test_first_fresh_inspection_tracks_new_guard_and_preserves_complete_history(self):
        startup = self.prepare_startup()
        startup.acquire()
        before, history = self.runtime(), self.history()
        first = len(self.operation._connections)
        prepare = self.store._policy.prepare
        guards = []

        def original_prepare(logon):
            self.assertIs(successor_scope.current_startup_operation(), self.operation)
            guard = prepare(logon)
            guards.append(guard)
            return guard

        with patch.object(self.store._policy, "prepare", side_effect=original_prepare):
            snapshot = startup.assert_fresh()
        self.assertEqual(snapshot["mode"], "off")
        self.assertEqual(snapshot["guardian_epoch"], before["guardian_epoch"])
        self.assertEqual(len(guards), 1)
        guard = guards[0]
        self.assertIsNot(guard, self.operation.guard)
        self.assertIsNot(guard, self.retirement._freeze_guard)
        self.assertIsNot(guard, self.retirement._seal_guard)
        self.assertTrue(guard._native_exit_confirmed)
        self.assertTrue(guard._nonce_clear_attempted)
        self.assertTrue(guard._nonce_clear_confirmed)
        self.assertTrue(startup.policy_result.complete)
        self.assertFalse(startup.policy_pending)
        self.assertIsNone(self.store._policy.current_guard())
        self.assertIsNone(self.store._policy.current_cleanup_guard())
        self.assertIsNone(successor_scope.current_startup_operation())
        tracked = self.operation._connections[first:]
        self.assertGreater(len(tracked), 2)
        self.assertTrue(all(item.closed and not item.close_unknown for item in tracked))
        self.assertEqual(self.runtime(), before)
        self.assertEqual(self.history(), history)
        self.assertIsNone(self.supervisor.guardian)
        self.assertEqual(self.supervisor.started_guardians, 0)

    def test_fresh_prepare_close_ack_loss_retains_connection_and_original_instance(self):
        startup = self.prepare_startup()
        startup.acquire()
        first = len(self.operation._connections)
        original_mutex, original_lease = startup._mutex, startup._lease
        with self.rw_fault("prepare_close_ack") as observed:
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.assert_fresh()
        self.assertTrue(observed["raised"])
        pending = [item for item in self.operation._connections[first:] if not item.closed]
        self.assertEqual(len(pending), 1)
        self.assertIn(pending[0].connection, observed["connections"])
        self.assertEqual(len(observed["prepared"]), 1)
        self.assertIs(observed["prepared"][0][0], pending[0].connection)
        self.assertEqual(self.runtime()["policy_entry_nonce"], observed["prepared"][0][1][2])
        self.assertTrue(startup.policy_pending)
        self.assertTrue(startup.policy_quarantined)
        self.assertIs(startup._mutex, original_mutex)
        self.assertIs(startup._lease, original_lease)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("fresh inspection replaced SQL")):
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.assert_fresh()
            with self.assertRaises((DailySuccessorError, LifecycleError)):
                startup.close()
        self.assertFalse(startup._closed)
        self.assertFalse(pending[0].closed)


if __name__ == "__main__":
    unittest.main()
