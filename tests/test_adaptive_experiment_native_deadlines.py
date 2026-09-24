"""Original native timing bounds with explicit, portable Win32 API fixtures.

The deadline factory, Job/CreatedProcess owners and native call boundaries are
production implementations. Only time and Win32 effects are synthetic. No DLL,
Job, process, daily configuration or native acceptance gate is exercised here.
"""
import ctypes as C
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import native_job as job_module
from sentinel.adaptive import native_launcher as launcher
from sentinel.adaptive import pipe_windows
from sentinel.adaptive.contracts import ProcessIdentity
from tests import test_adaptive_native_job as job_tests
from tests import test_adaptive_native_launcher as launch_tests
from tests import test_adaptive_scope_launch as scope_tests
from tests.windows import adaptive_scope_launch as scope


class _TickBackend:
    def __init__(self):
        self.now = 1000
        self.observations = []

    def tick_ms(self):
        self.observations.append(self.now)
        return self.now


def _deadline(clock, duration=100, *, kind=pipe_windows.NativeDeadline):
    # Use the real factory, never a serialized permit or a duck-typed callback.
    with patch.object(pipe_windows, "_backend", return_value=clock):
        return kind.after_ms(duration)


def _invalid_deadlines(clock):
    class DerivedDeadline(pipe_windows.NativeDeadline):
        pass

    return (object(), {"remaining_ms": 100}, SimpleNamespace(require=lambda: 100),
            _deadline(clock, kind=DerivedDeadline))


class NativeJobDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.fixture = job_tests.NativeJobTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.kernel, self.advapi = self.fixture.kernel, self.fixture.advapi
        self.clock = _TickBackend()
        self.deadline = _deadline(self.clock)
        self.end = self.deadline._end

    def create(self, **kwargs):
        return self.fixture.create(**kwargs)

    def calls(self, name):
        return self.fixture.calls(name)

    def _expire_descriptor(self):
        convert = self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW

        def after_descriptor(*args):
            result = convert(*args)
            self.clock.now = self.end
            return result

        return patch.object(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                            side_effect=after_descriptor)

    def test_create_rejects_nonexact_deadlines_before_backend_or_security_effects(self):
        for invalid in _invalid_deadlines(self.clock):
            with self.subTest(kind=type(invalid).__name__), \
                    patch.object(job_module, "_WindowsBackend", side_effect=AssertionError("invalid deadline acquired backend")):
                with self.assertRaisesRegex(ValueError, "native_job_deadline_invalid"):
                    job_module.NativeJob.create(job_tests.NAME, job_tests.NONCE, job_tests.LOGON,
                                                native_deadline=invalid)
        self.assertEqual(self.kernel.calls, [])

    def test_create_uses_same_original_deadline_after_setup_without_renewing(self):
        require, checked = pipe_windows.NativeDeadline.require, []

        def original(value):
            checked.append(value)
            self.assertTrue(self.calls("descriptor"))
            self.assertEqual(self.calls("CreateJobObjectW"), [])
            return require(value)

        with patch.object(pipe_windows.NativeDeadline, "after_ms", side_effect=AssertionError("deadline renewed")), \
                patch.object(pipe_windows.NativeDeadline, "require", autospec=True, side_effect=original):
            job = self.create(native_deadline=self.deadline)
        self.assertTrue(checked)
        self.assertTrue(all(value is self.deadline for value in checked))
        self.assertEqual(self.deadline._end, self.end)
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)
        job.close()

    def test_expiry_during_descriptor_setup_never_enters_create_and_cleans_original_owner(self):
        with self._expire_descriptor(), \
                patch.object(pipe_windows.NativeDeadline, "after_ms", side_effect=AssertionError("expired deadline renewed")):
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                self.create(native_deadline=self.deadline)
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertEqual(self.calls("OpenJobObjectW"), [])
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.assertEqual(self.calls("CloseHandle"), [])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", job_tests.DESCRIPTOR)])
        owner, = caught.exception._native_job_initialization_owners
        self.assertEqual(owner._creation.state, "absent")
        self.assertEqual(owner._job.state, "absent")
        self.assertEqual(owner._descriptor.state, "closed")
        self.assertTrue(owner.closed)
        self.assertEqual(self.deadline._end, self.end)

    def test_expired_create_known_descriptor_free_failure_retains_only_original_setup_cleanup(self):
        self.kernel.free_failure = True
        with self._expire_descriptor():
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                self.create(native_deadline=self.deadline)
        owner, = caught.exception._native_job_initialization_owners
        self.assertIn(owner, caught.exception._native_job_cleanup)
        self.assertFalse(owner.closed)
        self.assertEqual(owner._creation.state, "absent")
        self.assertEqual(owner._descriptor.state, "owned")
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.kernel.free_failure = False
        with patch.object(pipe_windows.NativeDeadline, "require", side_effect=AssertionError("cleanup checked expired deadline")):
            job_module.retry_job_cleanup(caught.exception)
        self.assertTrue(owner.closed)
        self.assertEqual(caught.exception._native_job_cleanup, ())
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", job_tests.DESCRIPTOR)] * 2)
        self.assertEqual(self.calls("CreateJobObjectW"), [])

    def test_expired_create_unknown_descriptor_free_keeps_original_owner_without_retry(self):
        failure = self.kernel.free_exception = RuntimeError("synthetic descriptor free outcome unknown")
        with self._expire_descriptor():
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                self.create(native_deadline=self.deadline)
        owner, = caught.exception._native_job_initialization_owners
        self.assertIs(caught.exception._native_job_cleanup_error, failure)
        self.assertIn(owner, caught.exception._native_job_cleanup)
        self.assertEqual(owner._descriptor.state, "close_unknown")
        self.assertEqual(owner._creation.state, "absent")
        self.kernel.free_exception = None
        with self.assertRaisesRegex(job_module.NativeJobError, "native_job_cleanup_outcome_unknown"):
            job_module.retry_job_cleanup(caught.exception)
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", job_tests.DESCRIPTOR)])
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertFalse(owner.closed)

    def test_setter_rejects_nonexact_deadlines_without_control_effects(self):
        job = self.create(access=job_module.JobAccess.CONTROL)
        self.addCleanup(job.close)
        before = list(self.kernel.calls)
        for invalid in _invalid_deadlines(self.clock):
            with self.subTest(kind=type(invalid).__name__), self.assertRaisesRegex(ValueError, "native_job_deadline_invalid"):
                job.set_cpu_rate_unverified(3500, native_deadline=invalid)
        self.assertEqual(self.kernel.calls, before)
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_setter_expiry_while_waiting_for_actual_lock_prevents_native_set(self):
        job = self.create(access=job_module.JobAccess.CONTROL)
        self.addCleanup(job.close)
        underlying, entered, errors = job._lock, threading.Event(), []

        class ObservedLock:
            def __enter__(self):
                entered.set()
                underlying.acquire()
                return self

            def __exit__(self, *unused):
                underlying.release()

        job._lock = ObservedLock()

        def set_rate():
            try:
                job.set_cpu_rate_unverified(3500, native_deadline=self.deadline)
            except BaseException as error:
                errors.append(error)

        underlying.acquire()
        worker = threading.Thread(target=set_rate)
        worker.start()
        try:
            self.assertTrue(entered.wait(timeout=3), "setter did not reach original lock")
            self.assertTrue(worker.is_alive())
            self.assertEqual(self.calls("SetInformationJobObject"), [])
            self.clock.now = self.end
        finally:
            underlying.release()
            worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], pipe_windows.NativePipeError)
        self.assertEqual(errors[0].reason, "pipe_timeout")
        self.assertEqual(errors[0]._native_job_cleanup, (job,))
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        self.assertEqual(job.handle, job_tests.RETAINED)
        self.assertEqual(self.deadline._end, self.end)

    def test_setter_checks_deadline_after_handle_preparation_not_only_before_lock(self):
        job = self.create(access=job_module.JobAccess.CONTROL)
        self.addCleanup(job.close)
        original = job_module.NativeJob.handle

        def prepared(owner):
            handle = original.fget(owner)
            self.clock.now = self.end
            return handle

        with patch.object(job_module.NativeJob, "handle", new=property(prepared)):
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                job.set_cpu_rate_unverified(3500, native_deadline=self.deadline)
        self.assertEqual(caught.exception._native_job_cleanup, (job,))
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_default_callers_and_disable_restore_remain_available_after_deadline_expiry(self):
        job = self.create(access=job_module.JobAccess.CONTROL, native_deadline=None)
        self.addCleanup(job.close)
        job.set_cpu_rate_unverified(3500, native_deadline=self.deadline)
        self.assertEqual(job.query_cpu(), job_module.CpuState(5, 3500))
        self.clock.now = self.end
        with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout"):
            job.set_cpu_rate_unverified(2500, native_deadline=self.deadline)
        self.assertEqual(len(self.calls("SetInformationJobObject")), 1)
        with patch.object(pipe_windows.NativeDeadline, "require", side_effect=AssertionError("restore required expired readiness")):
            self.assertEqual(job.disable().flags, 0)
            # Omitted/None preserve the pre-existing primitive API contract.
            job.set_cpu_rate_unverified(4500)
            self.assertEqual(job.set_cpu_rate(5000).rate_bp, 5000)
            self.assertEqual(job.disable().flags, 0)
        self.assertEqual(len(self.calls("SetInformationJobObject")), 5)


class WrapperNativeDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.fixture = launch_tests.NativeLauncherTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.sources = scope_tests.ScopeCommandTests()
        self.addCleanup(self.sources.doCleanups)
        self.sources.setUp()
        self.clock = _TickBackend()
        self.deadline = _deadline(self.clock)
        self.end = self.deadline._end
        self.owner = scope.ScopeLaunch(_token=scope._NEW)
        self.owner.scope_id = str(uuid4())
        self.owner.guardian_identity = ProcessIdentity(101, 10001, launch_tests.IDENTITY.logon_id)
        self.owner.command = self.sources.command()
        self.owner.wrapper_command_line = self.owner.command.command_line
        self.owner.fixture_sources = self.owner.command.fixture_sources
        self.owner.deadline = 101.0
        self.monotonic = SimpleNamespace(now=100.0)
        self.fixture.kernel.create_result = 0
        for override in (
                patch.object(launcher, "_WindowsBackend", return_value=self.fixture.backend),
                patch.object(scope.time, "monotonic", side_effect=lambda: self.monotonic.now)):
            override.start()
            self.addCleanup(override.stop)

    def assert_not_entered(self, error):
        self.assertIs(error.scope_launch_owner, self.owner)
        self.assertEqual(self.fixture.calls("CreateProcessW"), [])
        self.assertFalse(self.owner._wrapper_create_entered)
        self.assertTrue(self.owner.process.creation_definitely_absent)
        self.assertEqual(self.owner.process._creation_outcome, "not_attempted")
        self.assertIsNone(self.owner.wrapper_witness)
        self.assertIsNone(self.owner.root_witness)
        self.assertEqual(self.deadline._end, self.end)

    def test_wrapper_rejects_nonexact_deadline_before_setup_or_creation_marker(self):
        for invalid in _invalid_deadlines(self.clock):
            with self.subTest(kind=type(invalid).__name__), \
                    patch.object(launcher, "_WindowsBackend", side_effect=AssertionError("invalid deadline acquired wrapper backend")):
                with self.assertRaisesRegex(ValueError, "scope_wrapper_deadline_invalid"):
                    self.owner.create_inert(native_deadline=invalid)
            self.assertFalse(self.owner._created)
            self.assertFalse(self.owner._wrapper_create_entered)
            self.assertIsNone(self.owner.process)
        self.assertEqual(self.fixture.kernel.calls, [])

    def test_expiry_during_original_fixture_verification_preserves_never_created_owner(self):
        verify, verified = scope.FixtureSource.verify, []

        def verify_then_expire(source):
            verify(source)
            verified.append(source)
            self.clock.now = self.end

        with patch.object(scope.FixtureSource, "verify", autospec=True, side_effect=verify_then_expire), \
                patch.object(pipe_windows.NativeDeadline, "after_ms", side_effect=AssertionError("wrapper deadline renewed")):
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                self.owner.create_inert(native_deadline=self.deadline)
        self.assertEqual(verified, list(self.owner.fixture_sources))
        self.assert_not_entered(caught.exception)
        with patch.object(pipe_windows.NativeDeadline, "require", side_effect=AssertionError("cleanup checked expired deadline")):
            self.owner.close()
        self.assertTrue(self.owner._closed)
        self.assertTrue(self.owner.process._closed)

    def test_expiry_during_command_buffer_setup_is_checked_before_create(self):
        allocate = C.create_unicode_buffer

        def allocate_then_expire(*args, **kwargs):
            result = allocate(*args, **kwargs)
            self.clock.now = self.end
            return result

        with patch.object(C, "create_unicode_buffer", side_effect=allocate_then_expire):
            with self.assertRaisesRegex(pipe_windows.NativePipeError, "pipe_timeout") as caught:
                self.owner.create_inert(native_deadline=self.deadline)
        self.assert_not_entered(caught.exception)
        self.owner.close()
        self.assertTrue(self.owner._closed)

    def test_same_original_deadline_reaches_wrapper_boundary_without_renewal(self):
        require, checked = pipe_windows.NativeDeadline.require, []

        def original(value):
            checked.append(value)
            self.assertFalse(self.owner._wrapper_create_entered)
            self.assertEqual(self.owner.process._creation_outcome, "not_attempted")
            return require(value)

        with patch.object(pipe_windows.NativeDeadline, "after_ms", side_effect=AssertionError("wrapper deadline renewed")), \
                patch.object(pipe_windows.NativeDeadline, "require", autospec=True, side_effect=original):
            with self.assertRaisesRegex(launcher.NativeLaunchError, "scope_wrapper_create_failed"):
                self.owner.create_inert(native_deadline=self.deadline)
        self.assertTrue(checked)
        self.assertTrue(all(value is self.deadline for value in checked))
        self.assertEqual(self.deadline._end, self.end)
        self.assertEqual(len(self.fixture.calls("CreateProcessW")), 1)
        self.assertTrue(self.owner._wrapper_create_entered)
        self.assertEqual(self.owner.process._creation_outcome, "not_created")
        self.owner.close()

    def test_wrapper_default_none_retains_original_create_and_cleanup_behavior(self):
        with self.assertRaisesRegex(launcher.NativeLaunchError, "scope_wrapper_create_failed"):
            self.owner.create_inert()
        self.assertEqual(len(self.fixture.calls("CreateProcessW")), 1)
        self.assertTrue(self.owner._wrapper_create_entered)
        self.assertTrue(self.owner.process.creation_definitely_absent)
        self.owner.close()
        self.assertTrue(self.owner._closed)

    def test_scope_deadline_is_independent_of_still_live_original_native_deadline(self):
        verify = scope.FixtureSource.verify

        def expire_scope_only(source):
            verify(source)
            self.monotonic.now = self.owner.deadline

        with patch.object(scope.FixtureSource, "verify", autospec=True, side_effect=expire_scope_only):
            with self.assertRaisesRegex(scope.ScopeLaunchError, "scope_deadline_expired") as caught:
                self.owner.create_inert(native_deadline=self.deadline)
        self.assertGreater(self.deadline.remaining_ms(), 0)
        self.assert_not_entered(caught.exception)
        self.owner.close()


if __name__ == "__main__":
    unittest.main()
