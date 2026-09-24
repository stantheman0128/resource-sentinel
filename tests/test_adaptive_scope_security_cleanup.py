"""Original scope release after security failure; isolated SQL, fake native APIs."""
from contextlib import contextmanager
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_scope as scope, windows
from sentinel.adaptive.native_job import NativeJobError
from tests import test_adaptive_experiment_release_native as fixtures
from tests.windows.adaptive_scope_launch import ScopeLaunch


class _PreparationMutex(fixtures._JobMutex):
    """The preparation-close path also checks the original handle cell."""
    def __init__(self, *args):
        super().__init__(*args)
        self._handle = object()

    def close(self):
        super().close()
        self._handle = None


class ScopeSecurityCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentNativeReleaseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.stack.enter_context(patch.object(scope, "NativePolicyMutex", _PreparationMutex))

    def failed_scope(self, release):
        demand, command = self.fixture.admitted()
        failed = windows.NativePolicyMutexError("policy_mutex_security_free_failed", 6)
        failed._known_native_close_failed = True
        failed.add_note("policy_mutex_security_free_failed win32=6")
        original = windows._RetainedNative(release, 777)
        failed._policy_mutex_cleanup = (original,)
        self.fixture.native.security.failure = failed
        with self.assertRaises(NativeJobError) as caught:
            scope.ExperimentNativeScope.prepare(demand, command)
        owner = caught.exception.experiment_scope_owner
        self.fixture.scopes.append(owner)
        return demand, owner, failed, original, caught.exception

    def test_positive_original_security_cleanup_allows_actual_scope_and_daily_release(self):
        calls = []
        demand, owner, failure, dependency, translated = self.failed_scope(calls.append)
        self.assertTrue(dependency.closed)
        self.assertTrue(owner._partial_job.closed)
        self.assertEqual(calls, [777])
        self.assertIs(translated.__cause__, failure)
        self.assertIn("policy_mutex_security_free_failed win32=6", failure.__notes__)
        self.assertFalse(hasattr(failure, "_policy_mutex_cleanup"))
        self.assertFalse(hasattr(translated, "_policy_mutex_cleanup"))
        completion = owner.close_native()
        self.assertIs(type(completion), scope.NativeScopeCompletion)
        self.fixture.release_completion(owner, completion)
        self.assertTrue(demand._closed)
        self.assertEqual(self.fixture.rows("reservations"), [])
        self.assertEqual(calls, [777])

    def test_known_failure_retries_original_dependency_then_releases_daily_capacity(self):
        calls = []
        def release(value):
            calls.append(value)
            if len(calls) == 1:
                error = windows.NativePolicyMutexError("policy_mutex_security_free_failed", 6)
                error._known_native_close_failed = True
                raise error
        demand, owner, failure, dependency, translated = self.failed_scope(release)
        self.assertFalse(dependency.closed)
        self.assertFalse(owner._partial_job.closed)
        self.assertEqual(len(self.fixture.rows("reservations")), 1)
        completion = owner.close_native()
        self.assertTrue(dependency.closed)
        self.assertTrue(owner._partial_job.closed)
        self.assertEqual(calls, [777, 777])
        self.fixture.release_completion(owner, completion)
        self.assertTrue(demand._closed)
        self.assertFalse(hasattr(failure, "_policy_mutex_cleanup"))
        self.assertIn("policy_mutex_security_free_failed win32=6", failure.__notes__)

    def test_unaccounted_security_owner_remains_held_after_original_job_closes(self):
        demand, owner, failure, dependency, translated = self.failed_scope(lambda value: None)
        unrelated = windows._RetainedNative(lambda value: None, 888)
        failure._policy_mutex_cleanup = (dependency, unrelated)
        owner._retain(failure)
        before = self.fixture.rows("reservations")
        with self.assertRaisesRegex(RuntimeError, "preparation_cleanup_unverified"):
            owner.close_native()
        self.assertTrue(owner._partial_job.closed)
        self.assertFalse(unrelated.closed)
        self.assertEqual(self.fixture.rows("reservations"), before)
        self.assertFalse(demand._closed)

    def test_readiness_exit_failure_keeps_factory_owner_and_capacity(self):
        demand, command = self.fixture.admitted()
        original_error = windows.NativePolicyMutexError("policy_mutex_security_free_failed", 6)
        original_error._known_native_close_failed = True
        dependency = windows._RetainedNative(lambda value: None, 777)
        original_error._policy_mutex_cleanup = (dependency,)
        self.fixture.native.security.failure = original_error
        exit_error = RuntimeError("synthetic readiness exit failure")
        exit_error._daily_readiness_scopes = (object(),)
        original_scopes = scope.daily_generation.readiness_scopes
        @contextmanager
        def failing_exit(*args, **kwargs):
            with original_scopes(*args, **kwargs):
                yield
            raise exit_error
        before = self.fixture.rows("reservations")
        with patch.object(scope.daily_generation, "readiness_scopes", failing_exit), \
                patch.object(ScopeLaunch, "create_inert") as create_wrapper, \
                self.assertRaises(RuntimeError) as caught:
            scope.ExperimentNativeScope.prepare(demand, command)
        self.assertIs(caught.exception, exit_error)
        owner = exit_error.experiment_scope_owner
        self.fixture.scopes.append(owner)
        self.assertTrue(owner._partial_job.closed)
        self.assertTrue(dependency.closed)
        self.assertIn(exit_error, owner.errors)
        self.assertTrue(any(isinstance(error, NativeJobError) and error.__cause__ is original_error
            for error in owner.errors))
        create_wrapper.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "preparation_cleanup_unverified"):
            owner.close_native()
        self.assertEqual(self.fixture.rows("reservations"), before)
        self.assertFalse(demand._closed)

    def test_unknown_dependency_remains_held_without_repeating_native_free(self):
        calls = []
        original_error = OSError("synthetic unknown free")
        def release(value):
            calls.append(value)
            raise original_error
        demand, owner, failure, dependency, translated = self.failed_scope(release)
        self.assertFalse(dependency.closed)
        self.assertFalse(owner._partial_job.closed)
        before = self.fixture.rows("reservations")
        self.assertEqual(len(before), 1)
        for _ in range(2):
            with self.assertRaises(NativeJobError):
                owner.close_native()
            self.assertEqual(self.fixture.rows("reservations"), before)
            self.assertFalse(owner._partial_job.closed)
        self.assertIs(failure._policy_mutex_cleanup[0], dependency)
        self.assertEqual(calls, [777])
        self.assertFalse(demand._closed)


if __name__ == "__main__":
    unittest.main()
