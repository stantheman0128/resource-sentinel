"""Original successor quarantine remains resident; native peers are synthetic.

Real retirement/successor metadata and a real SQL close-ACK loss exercise the
resident loop. No Windows process, Job, listener or supervisor is launched.
"""
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_activation_host as activation
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor as successor
from tests import test_adaptive_daily_successor_host as host_fixture


class _EndResidentTest(BaseException):
    """Test control, raised only after a complete real resident tick."""


class DailySuccessorConsoleTests(unittest.TestCase):
    def setUp(self):
        # Keep synthetic unknown owners retained until this fixture is disposed;
        # restoring the previous registry last prevents cross-test pool leakage.
        registry = patch.object(generation, "_READINESS_SCOPES", {})
        registry.start()
        self.addCleanup(registry.stop)
        self.fixture = host_fixture.DailySuccessorHostTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host, self.operation = self.fixture.predecessor_host, self.fixture.operation
        self.assertIs(self.host.request_successor(), self.operation)
        self.assertTrue(self.host._retirement_complete())
        self.close_error = RuntimeError("fixture_successor_console_sql_close_ack_lost")
        self.close_calls = []
        original, error, calls = sqlite3.connect, self.close_error, self.close_calls

        class CloseAckLost(sqlite3.Connection):
            def close(conn):
                super().close()
                calls.append(conn)
                raise error

        def connect(*args, **kwargs):
            kwargs["factory"] = CloseAckLost
            return original(*args, **kwargs)

        # Capture the genuine new retained owner before losing the actual SQL
        # close result. Its handle and cohort use the fixture's native backend.
        with self.operation.scope():
            self.operation._capture_owner()
            with patch.object(sqlite3, "connect", side_effect=connect), \
                    self.assertRaisesRegex(RuntimeError, "console_sql_close_ack_lost") as caught:
                with self.operation._connection(readonly=True, observation=True) as conn:
                    self.assertEqual(conn.execute("SELECT count(*) FROM adaptive_daily_generation").fetchone()[0], 1)
        self.assertIs(caught.exception, error)
        self.native_owner = self.operation.owner
        self.sql_owner = self.operation._connections[-1]
        self.assertIs(self.sql_owner.connection, conn)
        self.assertFalse(self.sql_owner.closed)
        self.assertTrue(self.sql_owner.close_unknown)
        self.assertIs(self.operation._error, error)
        self.assertEqual(self.operation._quarantine, "sql_cleanup_unknown")
        self.fixture.fixture.capture_mock.assert_called_once()

    def assert_original_custody(self):
        self.assertIs(self.host._successor, self.operation)
        self.assertIs(self.host._retirement._successor_operation, self.operation)
        self.assertIs(self.operation.owner, self.native_owner)
        self.assertIs(self.operation._connections[-1], self.sql_owner)
        self.assertIs(self.operation._error, self.close_error)
        self.assertTrue(self.sql_owner.close_unknown)
        self.assertFalse(self.sql_owner.closed)
        self.assertEqual(self.close_calls, [self.sql_owner.connection])
        self.assertIsNone(self.host._successor_host)
        self.fixture.fixture.capture_mock.assert_called_once()

    def test_quarantined_original_status_and_real_tick_remain_resident_and_paced(self):
        # Strict authority checks still raise; only the exit/diagnostic boundary
        # converts that error into a retained false result.
        with self.assertRaisesRegex(successor.DailySuccessorError, "custody_unsettled"):
            self.host.chain_retirement_complete()
        with patch.object(activation, "emit", return_value=True) as emit, \
                patch.object(activation.time, "sleep") as sleep, \
                patch.object(sqlite3, "connect", side_effect=AssertionError("replacement SQL")), \
                patch.object(successor.DailySuccessorOperation, "__init__", side_effect=AssertionError("replacement successor")), \
                patch.object(activation.DailyActivationHost, "from_successor", side_effect=AssertionError("replacement host")):
            record = self.host.status()
            self.assertFalse(record["clean_exit_allowed"])
            failure = self.host._failure
            self.assertIs(type(failure), successor.DailySuccessorError)
            self.assertIs(failure.operation, self.operation)
            returned = self.host._retained_tick()
            self.assertFalse(returned["clean_exit_allowed"])
            self.assertIs(self.host._failure, failure)
            emit.assert_called_once_with(returned)
            sleep.assert_called_once_with(1.0)
            self.assertFalse(self.host._chain_exit_ready())
        self.assert_original_custody()

    def test_broken_diagnostics_do_not_skip_pacing_or_release_unknown_owner(self):
        reporting = RuntimeError("fixture_console_output_failed")
        with patch.object(activation, "emit", side_effect=reporting) as emit, \
                patch.object(activation.time, "sleep") as sleep, \
                patch.object(sqlite3, "connect", side_effect=AssertionError("replacement SQL")):
            first = self.host._retained_tick()
            failure = self.host._failure
            second = self.host._retained_tick(first)
        self.assertIsNone(first)
        self.assertIsNone(second)
        self.assertEqual(emit.call_count, 2)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1.0,), (1.0,)])
        self.assertIs(self.host._failure, failure)
        self.assertIs(type(failure), successor.DailySuccessorError)
        self.assertIs(failure.operation, self.operation)
        self.assertFalse(self.host.status()["clean_exit_allowed"])
        self.assert_original_custody()

    def test_real_run_forever_survives_quarantine_until_explicit_test_boundary(self):
        real_tick = self.host._retained_tick
        ticks = []
        boundary = _EndResidentTest("two actual resident ticks finished")

        def bounded_tick(previous=None):
            record = real_tick(previous)
            ticks.append(record)
            if len(ticks) == 2:
                # This is outside the production tick's recovery handlers and
                # happens only after its emit/pacing work completed.
                raise boundary
            return record

        with patch.object(self.host, "_retained_tick", side_effect=bounded_tick), \
                patch.object(activation, "emit", return_value=True) as emit, \
                patch.object(activation.time, "sleep") as sleep, \
                patch.object(sqlite3, "connect", side_effect=AssertionError("replacement SQL")), \
                patch.object(successor.DailySuccessorOperation, "__init__", side_effect=AssertionError("replacement successor")), \
                patch.object(activation.DailyActivationHost, "from_successor", side_effect=AssertionError("replacement host")), \
                self.assertRaises(_EndResidentTest) as caught:
            self.host.run_forever()
        self.assertIs(caught.exception, boundary)
        self.assertEqual(len(ticks), 2)
        self.assertTrue(all(record["clean_exit_allowed"] is False for record in ticks))
        self.assertGreaterEqual(emit.call_count, 1)
        self.assertEqual([call.args for call in sleep.call_args_list], [(1.0,), (1.0,)])
        self.assertTrue(self.host._retirement_complete())
        self.assertFalse(self.host._chain_exit_ready())
        self.assert_original_custody()


if __name__ == "__main__":
    unittest.main()
