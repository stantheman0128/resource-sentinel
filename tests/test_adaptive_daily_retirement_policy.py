"""Synthetic SQL-only proof of the original POLICY nonce-cleanup scope.

These fixtures use an in-memory ledger and never acquire a native mutex. They
exercise the actual coordinator, including the connection-opening boundary
used by the daily-generation retirement gate.
"""
from contextlib import contextmanager
import sqlite3
import threading
import unittest
from uuid import uuid4

from sentinel.adaptive.policy import PolicyBinding, PolicyCoordinator, PolicyError, PolicyGuard


class _SqlFixtureStore:
    """Faultable transaction lifetime; production permission is not simulated."""

    def __init__(self, guard):
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.before_open = self.before_commit = self.after_commit = None
        self.after_cleanup = None
        self.opens = 0
        self.connection.execute("""CREATE TABLE adaptive_runtime(
            singleton INTEGER PRIMARY KEY, schema_version INTEGER, protocol_version INTEGER,
            mode TEXT, registry_revision INTEGER, active_logon_id TEXT,
            admission_barrier TEXT, policy_instance_id TEXT, policy_logon_id TEXT,
            policy_entry_nonce TEXT, policy_binding_initialized INTEGER)""")
        self.connection.execute("""INSERT INTO adaptive_runtime VALUES(
            1,1,1,'off',0,?,'NONE',?,?,?,1)""",
            (guard.binding.logon_id, guard.binding.instance_id, guard.binding.logon_id, guard.nonce))

    @contextmanager
    def _transaction(self):
        self.opens += 1
        if self.before_open is not None:
            self.before_open()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
            if self.before_commit is not None:
                self.before_commit()
            self.connection.commit()
            if self.after_commit is not None:
                self.after_commit()
        except BaseException:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise
        finally:
            if self.after_cleanup is not None:
                self.after_cleanup()


class DailyRetirementPolicyScopeTests(unittest.TestCase):
    def setUp(self):
        self.guard = PolicyGuard(PolicyBinding(str(uuid4()), "S-1-5-5-10-20"), str(uuid4()))
        self.store = _SqlFixtureStore(self.guard)
        self.addCleanup(self.store.connection.close)
        # Supplying a fixture object avoids all native provider interactions.
        self.coordinator = PolicyCoordinator(self.store, provider=object())

    def nonce(self):
        return self.store.connection.execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime WHERE singleton=1").fetchone()[0]

    def test_exact_guard_is_visible_before_open_through_transaction_cleanup(self):
        seen = []
        def observe(label):
            seen.append((label, self.coordinator.current_cleanup_guard(),
                         self.coordinator.current_guard()))
        self.store.before_open = lambda: observe("open")
        self.store.before_commit = lambda: observe("commit")
        self.store.after_cleanup = lambda: observe("cleanup")
        self.assertIsNone(self.coordinator.current_cleanup_guard())
        self.coordinator._clear(self.guard)
        self.assertEqual([item[0] for item in seen], ["open", "commit", "cleanup"])
        for unused_label, cleanup_guard, held_guard in seen:
            self.assertIs(cleanup_guard, self.guard)
            self.assertIsNone(held_guard)
        self.assertIsNone(self.coordinator.current_cleanup_guard())
        self.assertIsNone(self.nonce())

    def test_cleanup_scope_is_not_visible_to_a_different_thread(self):
        observed = []
        def on_open():
            worker = threading.Thread(target=lambda: observed.append(
                self.coordinator.current_cleanup_guard()))
            worker.start()
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
        self.store.before_open = on_open
        self.coordinator._clear(self.guard)
        self.assertEqual(observed, [None])
        self.assertIsNone(self.coordinator.current_cleanup_guard())

    def test_cleanup_scope_is_not_shared_with_another_coordinator(self):
        other = PolicyCoordinator(self.store, provider=object())
        self.store.before_open = lambda: self.assertIsNone(other.current_cleanup_guard())
        self.coordinator._clear(self.guard)
        self.assertIsNone(other.current_cleanup_guard())

    def test_nested_cleanup_refuses_before_open_and_preserves_outer_guard(self):
        different = PolicyGuard(self.guard.binding, str(uuid4()))
        def on_open():
            with self.assertRaises(PolicyError):
                self.coordinator._clear(different)
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
        self.store.before_open = on_open
        self.coordinator._clear(self.guard)
        self.assertEqual(self.store.opens, 1)
        self.assertIsNone(self.coordinator.current_cleanup_guard())
        self.assertIsNone(self.nonce())

    def test_open_failure_clears_marker_without_clearing_nonce(self):
        failure = OSError("synthetic connection opening failed")
        def fail_open():
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
            raise failure
        self.store.before_open = fail_open
        with self.assertRaises(OSError) as caught:
            self.coordinator._clear(self.guard)
        self.assertIs(caught.exception, failure)
        self.assertIsNone(self.coordinator.current_cleanup_guard())
        self.assertEqual(self.nonce(), self.guard.nonce)

    def test_revalidation_rejects_different_nonce_without_overwriting_it(self):
        replacement = str(uuid4())
        self.store.connection.execute(
            "UPDATE adaptive_runtime SET policy_entry_nonce=?", (replacement,))
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            self.coordinator._clear(self.guard)
        self.assertEqual(self.nonce(), replacement)
        self.assertIsNone(self.coordinator.current_cleanup_guard())

    def test_failed_commit_rolls_back_and_removes_scope(self):
        failure = sqlite3.OperationalError("synthetic commit rejection")
        def before_commit():
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
            raise failure
        self.store.before_commit = before_commit
        with self.assertRaises(sqlite3.OperationalError) as caught:
            self.coordinator._clear(self.guard)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.nonce(), self.guard.nonce)
        self.assertIsNone(self.coordinator.current_cleanup_guard())

    def test_lost_commit_ack_removes_scope_and_does_not_recreate_nonce(self):
        failure = OSError("synthetic committed transaction ACK lost")
        def after_commit():
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
            raise failure
        self.store.after_commit = after_commit
        with self.assertRaises(OSError) as caught:
            self.coordinator._clear(self.guard)
        self.assertIs(caught.exception, failure)
        self.assertIsNone(self.nonce())
        self.assertIsNone(self.coordinator.current_cleanup_guard())
        # Calling clear again is not a new capability or idempotent adoption.
        self.store.after_commit = None
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            self.coordinator._clear(self.guard)
        self.assertIsNone(self.nonce())
        self.assertIsNone(self.coordinator.current_cleanup_guard())

    def test_cleanup_exception_retains_error_but_revokes_scope(self):
        failure = OSError("synthetic cleanup unknown")
        def fail_cleanup():
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
            raise failure
        self.store.after_cleanup = fail_cleanup
        with self.assertRaises(OSError) as caught:
            self.coordinator._clear(self.guard)
        self.assertIs(caught.exception, failure)
        self.assertIsNone(self.coordinator.current_cleanup_guard())

    def test_base_exception_also_revokes_original_scope(self):
        failure = SystemExit("synthetic interrupt")
        def fail_open():
            self.assertIs(self.coordinator.current_cleanup_guard(), self.guard)
            raise failure
        self.store.before_open = fail_open
        with self.assertRaises(SystemExit) as caught:
            self.coordinator._clear(self.guard)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.nonce(), self.guard.nonce)
        self.assertIsNone(self.coordinator.current_cleanup_guard())


if __name__ == "__main__":
    unittest.main()
