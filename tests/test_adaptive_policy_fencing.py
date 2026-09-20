"""Post-acquisition policy fencing with real isolated SQLite and fake mutexes.

No test acquires a native mutex or starts a Job/process. The synthetic lease
models only when a consumer may become reachable after the native wait.
"""
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.windows import PolicyMutexLease


LOGON = "S-1-5-5-11-22"


class AcquisitionFixture:
    def __init__(self):
        self.active = False
        self.on_enter = self.on_exit = None
        self.exit_error = None
        self.suppress = False
        self.enters = self.exits = 0

    def current_logon(self):
        return LOGON

    def hold(self, binding, *, timeout_ms=250):
        provider = self

        class Scope:
            def __enter__(self):
                provider.enters += 1
                provider.active = True
                if provider.on_enter is not None:
                    provider.on_enter()
                return PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, False)

            def __exit__(self, kind, error, tb):
                provider.exits += 1
                provider.active = False
                if provider.on_exit is not None:
                    provider.on_exit()
                if provider.exit_error is not None:
                    raise provider.exit_error
                return provider.suppress

        return Scope()


class AdaptivePolicyFencingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "sentinel.db"
        self.provider = AcquisitionFixture()
        self.store = LifecycleStore(self.db, policy_provider=self.provider)
        self.policy = self.store._policy
        self.guard = self.policy.prepare(LOGON)
        self.consumer_calls = 0

    def runtime(self):
        with closing(sqlite3.connect(self.db, timeout=0)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def change(self, assignment, value):
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as conn:
            conn.execute("UPDATE adaptive_runtime SET " + assignment + "=? WHERE singleton=1", (value,))

    def consume(self):
        with self.policy.hold(self.guard):
            self.consumer_calls += 1
            self.assertTrue(self.provider.active)
            self.assertIs(self.policy.assert_held(), self.guard)

    def assert_rejected(self):
        self.assertEqual(self.consumer_calls, 0)
        self.assertEqual((self.provider.enters, self.provider.exits), (1, 1))
        self.assertFalse(self.provider.active)
        self.assertIsNone(self.policy.current_guard())

    def test_valid_guard_is_revalidated_under_lease_before_consumer(self):
        original = self.policy.revalidate
        observations = []

        def observed(conn, guard):
            observations.append((self.provider.active, self.policy.current_guard(), self.consumer_calls,
                                 conn.execute("PRAGMA busy_timeout").fetchone()[0]))
            return original(conn, guard)

        with patch.object(self.policy, "revalidate", side_effect=observed):
            self.consume()
        self.assertEqual(observations[0], (True, None, 0, 250))
        self.assertEqual(self.consumer_calls, 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.policy.current_guard())

    def test_nonce_replaced_during_wait_cannot_reach_consumer_or_clear_new_nonce(self):
        replacement = str(uuid4())
        self.provider.on_enter = lambda: self.change("policy_entry_nonce", replacement)
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            self.consume()
        self.assert_rejected()
        self.assertEqual(self.runtime()["policy_entry_nonce"], replacement)

    def test_nonce_cleared_during_wait_does_not_reconstruct_authority(self):
        self.provider.on_enter = lambda: self.change("policy_entry_nonce", None)
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            self.consume()
        self.assert_rejected()
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_binding_replaced_during_wait_preserves_new_binding_and_old_nonce(self):
        replacement = str(uuid4())
        self.provider.on_enter = lambda: self.change("policy_instance_id", replacement)
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            self.consume()
        self.assert_rejected()
        row = self.runtime()
        self.assertEqual(row["policy_instance_id"], replacement)
        self.assertEqual(row["policy_entry_nonce"], self.guard.nonce)

    def test_unknown_schema_after_wait_never_reaches_consumer(self):
        self.provider.on_enter = lambda: self.change("protocol_version", 999)
        with self.assertRaisesRegex(PolicyError, "policy_runtime_invalid"):
            self.consume()
        self.assert_rejected()
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)

    def test_real_sqlite_busy_after_acquisition_denies_without_clearing_nonce(self):
        lock = sqlite3.connect(self.db, timeout=0, isolation_level=None)
        self.addCleanup(lock.close)
        self.provider.on_enter = lambda: lock.execute("BEGIN EXCLUSIVE")
        self.provider.on_exit = lock.rollback
        # Exercise the production 250ms SQLite lock budget, not a fixture
        # connection override that could hide the former five-second default.
        with self.assertRaises(sqlite3.OperationalError) as caught:
            self.consume()
        self.assertEqual(caught.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
        self.assert_rejected()
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)

    def test_read_connection_cleanup_failure_cannot_expose_guard(self):
        original = self.store._connection

        @contextmanager
        def failed_cleanup():
            with original() as conn:
                yield conn
            # The real fixture connection is closed before simulating its
            # uncertain cleanup ACK, so this test itself leaks no DB owner.
            raise LifecycleError("lifecycle_connection_cleanup_failed")

        with patch.object(self.store, "_connection", failed_cleanup):
            with self.assertRaisesRegex(LifecycleError, "lifecycle_connection_cleanup_failed"):
                self.consume()
        self.assert_rejected()
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)

    def test_stale_guard_keeps_primary_failure_when_provider_cleanup_is_unknown(self):
        replacement = str(uuid4())
        self.provider.on_enter = lambda: self.change("policy_entry_nonce", replacement)
        self.provider.exit_error = OSError("fixture release uncertainty")
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed") as caught:
            self.consume()
        self.assert_rejected()
        self.assertIn("policy_scope_cleanup_failed", caught.exception.__notes__)
        self.assertEqual(self.runtime()["policy_entry_nonce"], replacement)

    def test_suppressed_release_cannot_turn_stale_guard_into_success(self):
        replacement = str(uuid4())
        self.provider.on_enter = lambda: self.change("policy_entry_nonce", replacement)
        self.provider.suppress = True
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed") as caught:
            self.consume()
        self.assert_rejected()
        self.assertIn("policy_scope_cleanup_unverified", caught.exception.__notes__)
        self.assertEqual(self.runtime()["policy_entry_nonce"], replacement)


if __name__ == "__main__":
    unittest.main()
