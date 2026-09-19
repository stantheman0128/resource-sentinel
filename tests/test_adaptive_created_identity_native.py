"""Isolated native identity queries, without Jobs or resource control.

Children are sequential, short commands that return naturally. No workload is
killed. Success establishes retained-handle identity behavior on this host only.
"""
from contextlib import contextmanager
import ctypes
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if os.name == "nt":
    import _winapi

from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess, _backend


# A timeout must not discard a still-live fixture handle or allow another launch.
_UNRESOLVED_FIXTURES = []


@unittest.skipUnless(os.name == "nt" and ctypes.sizeof(ctypes.c_void_p) == 8,
                     "Windows x64 native identity remains unverified")
class NativeCreatedIdentityTests(unittest.TestCase):
    def setUp(self):
        if _UNRESOLVED_FIXTURES:
            self.fail("previous fixture exit unverified; no further launches")
        self.directory = tempfile.TemporaryDirectory(prefix="sentinel-created-identity-")
        self.addCleanup(self.directory.cleanup)
        with VerifiedProcess.current() as current:
            self.logon_id = current.identity.logon_id
        forbidden = patch.object(_backend(), "open_process", side_effect=AssertionError("PID reopen forbidden"))
        forbidden.start()
        self.addCleanup(forbidden.stop)

    @contextmanager
    def child(self, source="pass"):
        if _UNRESOLVED_FIXTURES:
            raise RuntimeError("previous fixture cleanup unverified; no further launches")
        command = subprocess.list2cmdline([sys.executable, "-I", "-c", source])
        process, thread, pid, _ = _winapi.CreateProcess(
            sys.executable, command, None, None, False, 0x08000000,
            None, str(Path(self.directory.name)), subprocess.STARTUPINFO())
        try:
            _winapi.CloseHandle(thread)
            thread = None
            yield process, pid
        finally:
            primary = sys.exc_info()[1]
            errors = []
            retained = {}
            try:
                if _winapi.WaitForSingleObject(process, 3000) != 0:
                    raise RuntimeError("fixture_exit_unverified")
                _winapi.CloseHandle(process)
            except BaseException as error:
                errors.append(error)
                retained["process"] = process
            # A thread-close failure must not prevent process observation, and
            # process cleanup failure must not discard the thread handle.
            if thread is not None:
                try:
                    _winapi.CloseHandle(thread)
                except BaseException as error:
                    errors.append(error)
                    retained["thread"] = thread
            if retained:
                _UNRESOLVED_FIXTURES.append(retained)
            if errors:
                if primary is not None:
                    primary.add_note("fixture_cleanup_unverified_handles_retained")
                else:
                    raise RuntimeError("fixture_cleanup_unverified_handles_retained") from errors[0]

    def wait_natural_exit(self, process):
        self.assertEqual(_winapi.WaitForSingleObject(process, 3000), 0,
                         "fixture did not signal natural exit")
        self.assertEqual(_winapi.GetExitCodeProcess(process), 0)

    def handle_flags(self, handle):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetHandleInformation.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel.GetHandleInformation.restype = ctypes.c_int32
        flags = ctypes.c_uint32()
        if not kernel.GetHandleInformation(handle, ctypes.byref(flags)):
            self.fail("GetHandleInformation failed: " + str(ctypes.get_last_error()))
        return flags.value

    def test_duplicate_after_already_signaled_exit_keeps_full_identity(self):
        for round_number in range(4):
            with self.subTest(round=round_number), self.child() as (original, pid):
                self.wait_natural_exit(original)
                # First full identity acquisition occurs after confirmed exit.
                with VerifiedProcess.duplicate_from_handle(
                        original, expected_pid=pid, expected_logon_id=self.logon_id) as verified:
                    self.assertEqual(verified.identity.pid, pid)
                    self.assertEqual(verified.identity.logon_id, self.logon_id)
                    self.assertGreater(verified.identity.created_filetime_100ns, 0)
                    self.assertIs(verified.observe().status, IdentityStatus.DEAD)
                    self.assertEqual(self.handle_flags(verified._handle) & 1, 0)
                    identity = verified.identity
                # Closing the duplicate must not close its borrowed original.
                self.wait_natural_exit(original)
                with VerifiedProcess.duplicate_from_handle(
                        original, expected_pid=pid, expected_logon_id=self.logon_id) as second:
                    self.assertEqual(second.identity, identity)

    def test_mismatch_preserves_original_and_allows_correct_reverification(self):
        with self.child() as (original, pid):
            self.wait_natural_exit(original)
            components = self.logon_id.split("-")
            components[-1] = str(int(components[-1]) ^ 1)
            wrong_logon = "-".join(components)
            for expected_pid, logon in ((pid ^ 1, self.logon_id), (pid, wrong_logon)):
                with self.subTest(pid_mismatch=expected_pid != pid):
                    with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
                        VerifiedProcess.duplicate_from_handle(
                            original, expected_pid=expected_pid, expected_logon_id=logon)
                    self.wait_natural_exit(original)
            with VerifiedProcess.duplicate_from_handle(
                    original, expected_pid=pid, expected_logon_id=self.logon_id) as verified:
                self.assertEqual(verified.identity.pid, pid)
                self.assertIs(verified.observe().status, IdentityStatus.DEAD)

    def test_retained_duplicate_observes_natural_exit_without_pid_reopen(self):
        with self.child("import time; time.sleep(0.25)") as (original, pid):
            with VerifiedProcess.duplicate_from_handle(
                    original, expected_pid=pid, expected_logon_id=self.logon_id) as verified:
                before = verified.identity
                self.wait_natural_exit(original)
                self.assertIs(verified.observe().status, IdentityStatus.DEAD)
                self.assertEqual(verified.identity, before)
            self.wait_natural_exit(original)


class CreatedIdentityFixtureCleanupTests(unittest.TestCase):
    def fixture(self, native):
        fixture = NativeCreatedIdentityTests()
        fixture.directory = SimpleNamespace(name=tempfile.gettempdir())
        startup = patch.object(subprocess, "STARTUPINFO", return_value=SimpleNamespace(), create=True)
        startup.start()
        self.addCleanup(startup.stop)
        native.CreateProcess.return_value = (100, 200, 300, 400)
        native.WaitForSingleObject.return_value = 0
        return fixture

    def test_timeout_blocks_next_subtest_launch_and_retains_original(self):
        native = Mock()
        fixture = self.fixture(native)
        native.WaitForSingleObject.return_value = 258
        with patch.dict(globals(), _winapi=native, _UNRESOLVED_FIXTURES=[]):
            with self.assertRaisesRegex(RuntimeError, "cleanup_unverified"):
                with fixture.child():
                    pass
            self.assertEqual(_UNRESOLVED_FIXTURES, [{"process": 100}])
            with self.assertRaisesRegex(RuntimeError, "no further launches"):
                with fixture.child():
                    self.fail("must not launch")
            native.CreateProcess.assert_called_once()
            native.CloseHandle.assert_called_once_with(200)

    def test_wait_or_process_close_error_retains_original(self):
        for failing in ("wait", "close"):
            with self.subTest(failing=failing):
                native = Mock()
                fixture = self.fixture(native)
                if failing == "wait":
                    native.WaitForSingleObject.side_effect = OSError("wait failure")
                else:
                    def close(handle):
                        if handle == 100:
                            raise OSError("close failure")
                    native.CloseHandle.side_effect = close
                with patch.dict(globals(), _winapi=native, _UNRESOLVED_FIXTURES=[]):
                    with self.assertRaisesRegex(RuntimeError, "cleanup_unverified"):
                        with fixture.child():
                            pass
                    self.assertEqual(_UNRESOLVED_FIXTURES, [{"process": 100}])

    def test_thread_close_failure_preserves_primary_and_observes_process(self):
        native = Mock()
        fixture = self.fixture(native)
        primary = OSError("thread close failure")
        def close(handle):
            if handle == 200:
                raise primary
        native.CloseHandle.side_effect = close
        with patch.dict(globals(), _winapi=native, _UNRESOLVED_FIXTURES=[]):
            with self.assertRaises(OSError) as caught:
                with fixture.child():
                    self.fail("initial close must fail")
            self.assertIs(caught.exception, primary)
            self.assertEqual(_UNRESOLVED_FIXTURES, [{"thread": 200}])
            native.WaitForSingleObject.assert_called_once_with(100, 3000)
            self.assertIn(((100,), {}), native.CloseHandle.call_args_list)


if __name__ == "__main__":
    unittest.main()
