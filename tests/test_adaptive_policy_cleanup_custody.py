"""POLICY clear-error custody with actual isolated SQL and synthetic leases.

No native mutex, process or Job is opened. The first three cases enter the real
PolicyCoordinator.hold and clear transaction; only SQLite acknowledgement/close
outcomes are injected. Graph cases exercise the bounded data classifier alone.
"""
from contextlib import contextmanager
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive import policy as policy_module
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.windows import NativePolicyMutexError
from tests import test_adaptive_policy_fencing as fencing
from tests import test_adaptive_daily_readiness_lock_boundary as readiness


class PolicyCleanupCustodyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fencing.AdaptivePolicyFencingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.policy, self.guard = self.fixture.policy, self.fixture.guard
        self.provider = self.fixture.provider

    @contextmanager
    def clear_failure(self, *, lost_ack=None, unknown_close=None):
        """Fault only the connection that actually updates the original nonce."""
        connect, clearing, closed, close_attempts = sqlite3.connect, [], [], []

        class ClearConnection(sqlite3.Connection):
            clearing = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if "SET policy_entry_nonce=NULL" in sql:
                    self.clearing = True
                    clearing.append(self)
                return result

            def commit(self):
                super().commit()
                if self.clearing and lost_ack is not None:
                    raise lost_ack

            def close(self):
                if self.clearing:
                    close_attempts.append(self)
                    if unknown_close is not None:
                        raise unknown_close
                super().close()
                closed.append(self)

        try:
            with patch.object(sqlite3, "connect", side_effect=lambda *a, **kw:
                    connect(*a, **kw, factory=ClearConnection)):
                yield clearing, closed, close_attempts
        finally:
            # Test-only positive cleanup of the exact synthetic failed-close
            # connection. Production must retain it and refuse replacement.
            for conn in clearing:
                if conn not in closed:
                    sqlite3.Connection.close(conn)

    def reject_body(self, primary):
        with self.policy.hold(self.guard):
            self.assertIs(self.policy.current_guard(), self.guard)
            # This body has acquired no SQL/native child owner. Its rejection
            # is known before any consumer transaction, as in admission checks.
            self.guard.clean_rejection = True
            raise primary

    def assert_exit_settled(self):
        self.assertFalse(self.provider.active)
        self.assertIsNone(self.policy.current_guard())
        self.assertIsNone(self.policy.current_cleanup_guard())
        self.assertTrue(self.guard._native_exit_confirmed)
        self.assertTrue(self.guard._nonce_clear_attempted)
        self.assertFalse(self.guard._nonce_clear_confirmed)

    def test_body_rejection_retains_plain_clear_commit_ack_loss_without_unknown_marker(self):
        primary = ValueError("synthetic consumer rejection")
        clear_error = sqlite3.OperationalError("synthetic clear commit acknowledgement lost")
        with self.clear_failure(lost_ack=clear_error) as (clearing, closed, attempts):
            with self.assertRaises(ValueError) as caught:
                self.reject_body(primary)
            self.assertIs(caught.exception, primary)
            self.assertIs(primary._policy_entry_cleanup_error, clear_error)
            self.assertEqual(primary.__notes__, ["policy_entry_cleanup_failed"])
            self.assertEqual(len(clearing), 1)
            self.assertEqual(attempts, clearing)
            self.assertIn(clearing[0], closed)
            with self.assertRaises(sqlite3.ProgrammingError):
                clearing[0].execute("SELECT 1")
            # A raised cleanup error naturally points back to the primary;
            # the retained attribute makes a benign cycle, not uncertainty.
            self.assertIs(clear_error.__context__, primary)
            self.assertFalse(policy_module._cleanup_outcome_unverified(primary))
        self.assert_exit_settled()
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assertEqual((self.provider.enters, self.provider.exits), (1, 1))

    def test_body_rejection_keeps_original_unknown_clear_connection_and_extra_marker(self):
        primary = ValueError("synthetic consumer rejection")
        close_error = OSError("synthetic clear connection close unknown")
        with self.clear_failure(unknown_close=close_error) as (clearing, closed, attempts):
            with self.assertRaises(ValueError) as caught:
                self.reject_body(primary)
            self.assertIs(caught.exception, primary)
            cleanup_error = primary._policy_entry_cleanup_error
            self.assertIs(type(cleanup_error), LifecycleError)
            self.assertEqual(primary.__notes__, ["policy_entry_cleanup_failed", "policy_entry_cleanup_unverified"])
            self.assertEqual(len(clearing), 1)
            self.assertIs(cleanup_error._sentinel_connection_cleanup, clearing[0])
            self.assertIs(cleanup_error._sentinel_connection_cleanup_error, close_error)
            self.assertEqual(attempts, clearing)
            self.assertNotIn(clearing[0], closed)
            self.assertTrue(policy_module._cleanup_outcome_unverified(primary))
            # A committed NULL is data only; the original cleanup owner and
            # extra marker still prevent consumers from treating it as settled.
            self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assert_exit_settled()
        self.assertEqual((self.provider.enters, self.provider.exits), (1, 1))

    def test_positive_timeout_preserves_primary_and_original_unknown_clear_graph(self):
        primary = NativePolicyMutexError("policy_mutex_timeout")
        close_error = OSError("synthetic timeout-clear connection close unknown")
        entered = []

        @contextmanager
        def timeout(binding, *, timeout_ms):
            entered.append((binding, timeout_ms))
            raise primary
            yield  # pragma: no cover -- context manager never grants ownership.

        with patch.object(self.provider, "hold", side_effect=timeout), \
                self.clear_failure(unknown_close=close_error) as (clearing, closed, attempts):
            with self.assertRaises(NativePolicyMutexError) as caught:
                with self.policy.hold(self.guard):
                    self.fail("positive timeout granted consumer ownership")
            self.assertIs(caught.exception, primary)
            self.assertEqual(primary.reason, "policy_mutex_timeout")
            self.assertEqual(primary.__notes__, ["policy_entry_cleanup_failed", "policy_entry_cleanup_unverified"])
            cleanup_error = primary._policy_entry_cleanup_error
            self.assertIs(cleanup_error._sentinel_connection_cleanup, clearing[0])
            self.assertIs(cleanup_error._sentinel_connection_cleanup_error, close_error)
            self.assertEqual(attempts, clearing)
            self.assertNotIn(clearing[0], closed)
            self.assertTrue(policy_module._cleanup_outcome_unverified(primary))
        self.assertEqual(entered, [(self.guard.binding, 250)])
        self.assertTrue(self.guard._native_no_entry_confirmed)
        self.assertFalse(self.guard._native_exit_confirmed)
        self.assertTrue(self.guard._nonce_clear_attempted)
        self.assertFalse(self.guard._nonce_clear_confirmed)
        self.assertIsNone(self.policy.current_guard())
        self.assertIsNone(self.policy.current_cleanup_guard())
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])

    def test_cyclic_cleanup_graph_terminates_and_keeps_buried_original_owner(self):
        primary, cleanup_error, nested = (RuntimeError(name) for name in ("primary", "clear", "nested"))
        primary._policy_entry_cleanup_error = cleanup_error
        primary.add_note("policy_entry_cleanup_failed")
        cleanup_error.__context__ = primary
        cleanup_error._daily_readiness_cause = nested
        nested.__cause__ = cleanup_error
        self.assertFalse(policy_module._cleanup_outcome_unverified(primary))
        original_connection = object()
        nested._sentinel_connection_cleanup = original_connection
        self.assertTrue(policy_module._cleanup_outcome_unverified(primary))
        self.assertIs(primary._policy_entry_cleanup_error._daily_readiness_cause._sentinel_connection_cleanup,
                      original_connection)
        self.assertIs(nested.__cause__, cleanup_error)

    def test_cleanup_graph_budget_counts_unique_nodes_and_refuses_uninspected_tail(self):
        errors = [RuntimeError("synthetic node") for _ in range(33)]
        for current, following in zip(errors, errors[1:32]):
            current.__cause__ = following
        errors[31].__context__ = errors[0]
        self.assertFalse(policy_module._cleanup_outcome_unverified(errors[0]))
        errors[31]._policy_entry_cleanup_error = errors[32]
        self.assertTrue(policy_module._cleanup_outcome_unverified(errors[0]))
        self.assertIs(errors[31]._policy_entry_cleanup_error, errors[32])

    def test_local_only_interrupt_exception_never_hides_nested_cleanup_or_owner(self):
        interrupted = KeyboardInterrupt("synthetic final local bookkeeping interruption")
        self.assertTrue(policy_module._cleanup_outcome_unverified(interrupted))
        self.assertFalse(policy_module._cleanup_outcome_unverified(interrupted, local_only=True))
        nested = KeyboardInterrupt("synthetic nested acquisition interruption")
        interrupted.__cause__ = nested
        self.assertTrue(policy_module._cleanup_outcome_unverified(interrupted, local_only=True))
        interrupted.__cause__ = None
        interrupted._identity_handle_cleanup = (object(),)
        self.assertTrue(policy_module._cleanup_outcome_unverified(interrupted, local_only=True))
        del interrupted._identity_handle_cleanup
        interrupted.add_note("policy_entry_cleanup_unverified")
        self.assertTrue(policy_module._cleanup_outcome_unverified(interrupted, local_only=True))


class PolicyReadinessCleanupCustodyTests(unittest.TestCase):
    """Present-generation scopes with actual authority custody and fake pipe I/O."""
    clear_failure = PolicyCleanupCustodyTests.clear_failure
    reject_body = PolicyCleanupCustodyTests.reject_body

    def setUp(self):
        self.fixture = readiness.DailyReadinessLockBoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.policy = self.fixture.store._policy
        self.guard = self.policy.prepare(self.fixture.identity.logon_id)
        self.fixture.events.clear()

    def test_plain_clear_ack_loss_closes_the_original_present_generation_scope(self):
        primary = ValueError("synthetic consumer rejection")
        clear_error = sqlite3.OperationalError("synthetic clear commit acknowledgement lost")
        with self.clear_failure(lost_ack=clear_error) as (clearing, closed, attempts):
            with self.assertRaises(ValueError) as caught:
                with generation.readiness_scope(self.fixture.db) as original:
                    self.assertIsNotNone(original.row)
                    self.assertIs(type(original.authority), transport.DailyReadinessAuthority)
                    self.reject_body(primary)
            self.assertIs(caught.exception, primary)
            self.assertIs(primary._policy_entry_cleanup_error, clear_error)
            self.assertEqual(primary.__notes__, ["policy_entry_cleanup_failed"])
            self.assertEqual(len(clearing), 1)
            self.assertEqual(attempts, clearing)
            self.assertIn(clearing[0], closed)
            self.assertFalse(generation._readiness_cleanup_unknown(primary))
        self.assertTrue(original.closed)
        self.assertIsNone(original.error)
        self.assertTrue(original.authority._closed)
        self.assertIsNone(original.authority._peer._handle)
        self.assertNotIn(id(original), generation._READINESS_SCOPES)
        self.assertEqual(self.fixture.events.count("rpc"), 1)
        with generation.readiness_scope(self.fixture.db) as fresh:
            self.assertIsNot(fresh, original)
            self.assertIsNot(fresh.authority, original.authority)
        self.assertTrue(fresh.closed)
        self.assertEqual(self.fixture.events.count("rpc"), 2)

    def test_unknown_clear_close_retains_original_scope_and_prevents_reacquisition(self):
        primary = ValueError("synthetic consumer rejection")
        close_error = OSError("synthetic clear connection close unknown")
        with self.clear_failure(unknown_close=close_error) as (clearing, closed, attempts):
            with self.assertRaises(ValueError) as caught:
                with generation.readiness_scope(self.fixture.db) as original:
                    self.assertIsNotNone(original.row)
                    self.assertIs(type(original.authority), transport.DailyReadinessAuthority)
                    self.reject_body(primary)
            self.assertIs(caught.exception, primary)
            cleanup_error = primary._policy_entry_cleanup_error
            self.assertIs(cleanup_error._sentinel_connection_cleanup, clearing[0])
            self.assertIs(cleanup_error._sentinel_connection_cleanup_error, close_error)
            self.assertIs(original.error, cleanup_error)
            self.assertIs(primary.daily_readiness_scope, original)
            self.assertIn("policy_entry_cleanup_unverified", primary.__notes__)
            self.assertIn("daily_readiness_scope_cleanup_unknown", primary.__notes__)
            self.assertEqual(attempts, clearing)
            self.assertNotIn(clearing[0], closed)
            self.assertTrue(generation._readiness_cleanup_unknown(primary))
        self.assertIs(generation._READINESS_SCOPES[id(original)], original)
        self.assertFalse(original.closed)
        self.assertFalse(original.authority._closed)
        self.assertIsNotNone(original.authority._peer._handle)
        before = list(self.fixture.events)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown custody reopened SQL")), \
                patch.object(transport.NativePipeConnection, "connect",
                    side_effect=AssertionError("unknown custody reacquired readiness")), \
                self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_pending"):
            with generation.readiness_scope(self.fixture.db):
                self.fail("unknown cleanup was replaced by a new scope")
        self.assertEqual(self.fixture.events, before)
        self.assertIs(original.error._sentinel_connection_cleanup, clearing[0])


if __name__ == "__main__":
    unittest.main()
