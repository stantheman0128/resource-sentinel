"""Original global recovery-fence retirement with a synthetic native backend.

GuardianRestorer, NativePolicyMutex and lifecycle delegation are production
objects. The lifecycle state, current process and OS calls are explicit fixtures;
these tests do not create Windows objects, touch a ledger, or establish native
capability or recovery evidence.
"""
from contextlib import nullcontext
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.guardian_lifecycle import GuardianLifecycle
from sentinel.adaptive.guardian_restore import GuardianRestorer
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.windows import NativePolicyMutex, NativePolicyMutexError


LOGON = "S-1-5-5-123-456"


class MutexBackend:
    def __init__(self):
        self.created = []
        self.closes = []
        self.error = None

    def current_owner_sid(self):
        return "S-1-5-21-123-456-789-1001"

    def create(self, name, logon_id, owner_sid):
        self.created.append((name, logon_id, owner_sid))
        return 9901

    def close(self, handle):
        self.closes.append(handle)
        if self.error is not None:
            raise self.error

    def wait(self, *_):
        raise AssertionError("retiring the original fence must not acquire it")

    def release(self, *_):
        raise AssertionError("retiring an unused fence must not release a lease")


class LifecycleFixture:
    def __init__(self):
        self._lock = threading.RLock()
        self.retained_execution_ids = ()
        self._pending_policy = None
        self._scope_entry = None
        self._restorer = GuardianRestorer(self)
        self.store = Mock()
        self._mutex_factory = Mock(side_effect=AssertionError("cleanup reconstructed a POLICY mutex"))
        self._control = Mock(side_effect=AssertionError("cleanup queried a Job"))

    close_retained_fences = GuardianLifecycle.close_retained_fences


class GuardianFenceCleanupTests(unittest.TestCase):
    def case(self):
        owner = LifecycleFixture()
        api = MutexBackend()
        current = SimpleNamespace(
            identity=ProcessIdentity(os.getpid(), 134343072000000099, LOGON),
            observe=lambda: SimpleNamespace(status=IdentityStatus.ALIVE))
        with patch("sentinel.adaptive.windows._backend", return_value=api), \
                patch.object(VerifiedProcess, "current", return_value=nullcontext(current)):
            original = NativePolicyMutex(LOGON, str(uuid4()))
        owner._restorer.policy_mutex = original
        return owner, original, api

    def assert_no_reconstruction_or_query(self, owner, api):
        self.assertEqual(len(api.created), 1)
        owner._mutex_factory.assert_not_called()
        owner._control.assert_not_called()
        self.assertEqual(owner.store.mock_calls, [])

    def test_settled_lifecycle_closes_original_global_mutex_once(self):
        owner, original, api = self.case()
        owner.close_retained_fences()
        owner.close_retained_fences()
        self.assertIs(owner._restorer.policy_mutex, original)
        self.assertTrue(owner._restorer.closed)
        self.assertEqual(api.closes, [9901])
        self.assert_no_reconstruction_or_query(owner, api)

    def test_unpinned_restorer_retires_without_creating_any_mutex(self):
        owner = LifecycleFixture()
        owner.close_retained_fences()
        owner.close_retained_fences()
        self.assertTrue(owner._restorer.closed)
        self.assertIsNone(owner._restorer.policy_mutex)
        owner._mutex_factory.assert_not_called()
        self.assertEqual(owner.store.mock_calls, [])

    def test_retained_execution_policy_scope_or_emergency_entry_prevents_fence_close(self):
        for field in ("execution", "policy", "scope", "emergency"):
            with self.subTest(field=field):
                owner, original, api = self.case()
                if field == "execution":
                    owner.retained_execution_ids = (str(uuid4()),)
                elif field == "policy":
                    owner._pending_policy = object()
                elif field == "scope":
                    owner._scope_entry = object()
                else:
                    owner._restorer._emergency_entry = object()
                with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_still_owned"):
                    owner.close_retained_fences()
                self.assertFalse(owner._restorer.closed)
                self.assertIsNone(owner._restorer.fence_error)
                self.assertIs(owner._restorer.policy_mutex, original)
                self.assertEqual(api.closes, [])
                owner.retained_execution_ids = ()
                owner._pending_policy = owner._scope_entry = owner._restorer._emergency_entry = None
                owner.close_retained_fences()
                self.assertEqual(api.closes, [9901])
                self.assert_no_reconstruction_or_query(owner, api)

    def test_already_uncertain_fence_cannot_be_closed_by_cleanup(self):
        owner, original, api = self.case()
        failure = RuntimeError("fixture prior release unknown")
        owner._restorer.poison(failure)
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_uncertain"):
            owner.close_retained_fences()
        self.assertIs(owner._restorer.fence_error, failure)
        self.assertIs(owner._restorer.policy_mutex, original)
        self.assertEqual(api.closes, [])
        self.assert_no_reconstruction_or_query(owner, api)

    def test_close_failure_or_interrupt_retains_original_mutex_and_never_retries_it(self):
        for failure in (RuntimeError("fixture close outcome unknown"), KeyboardInterrupt(),
                        NativePolicyMutexError("policy_mutex_handle_close_failed", 6)):
            with self.subTest(error=type(failure).__name__):
                owner, original, api = self.case()
                api.error = failure
                with self.assertRaises(type(failure)) as first:
                    owner.close_retained_fences()
                self.assertIs(first.exception, failure)
                self.assertFalse(owner._restorer.closed)
                self.assertIs(owner._restorer.fence_error, failure)
                self.assertIs(owner._restorer.policy_mutex, original)
                # Removing the simulated OS error cannot erase the retained
                # uncertainty or justify another numeric-handle operation.
                api.error = None
                with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_uncertain"):
                    owner.close_retained_fences()
                self.assertEqual(api.closes, [9901])
                self.assert_no_reconstruction_or_query(owner, api)

    def test_closed_restorer_cannot_pin_a_new_mutex_or_authorize_restore(self):
        owner, original, api = self.case()
        owner.close_retained_fences()
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_closed"):
            owner._restorer.pin(object())
        self.assertIs(owner._restorer.policy_mutex, original)
        self.assertEqual(api.closes, [9901])
        self.assert_no_reconstruction_or_query(owner, api)


if __name__ == "__main__":
    unittest.main()
