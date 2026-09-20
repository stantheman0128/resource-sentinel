"""Portable exact-handle exit-code tests; no process launch or OS control.

Microsoft documents limited-query access and the ambiguity of exit value 259:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
These explicit backend fixtures do not prove native lifecycle readiness.
"""
import ctypes as C
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from sentinel.adaptive import identity as identities
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess


IDENTITY = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class SyntheticExitBackend:
    def __init__(self):
        self.value = IDENTITY
        self.state = IdentityStatus.DEAD
        self.code = 0
        self.calls = []
        self.wait_error = self.exit_error = self.close_error = None
        self.on_wait = self.on_exit = None

    def open_process(self, pid):
        self.calls.append(("open", pid))
        return 700

    def identity(self, handle):
        self.calls.append(("identity", handle))
        return self.value

    def wait(self, handle):
        self.calls.append(("wait", handle))
        if self.on_wait:
            self.on_wait()
        if self.wait_error:
            raise self.wait_error
        return self.state

    def exit_code(self, handle):
        self.calls.append(("exit_code", handle))
        if self.on_exit:
            self.on_exit()
        if self.exit_error:
            raise self.exit_error
        return self.code

    def close(self, handle):
        self.calls.append(("close", handle))
        if self.close_error:
            raise self.close_error


class VerifiedProcessExitTests(unittest.TestCase):
    def setUp(self):
        self.backend = SyntheticExitBackend()
        override = patch.object(identities, "_backend", return_value=self.backend)
        override.start()
        self.addCleanup(override.stop)

    def test_dead_process_preserves_unsigned_dword_including_real_exit_259(self):
        for code in (0, 7, 259, 0x80000000, 0xFFFFFFFF):
            with self.subTest(code=code), VerifiedProcess.open(IDENTITY) as process:
                self.backend.calls.clear()
                self.backend.code = code
                self.assertEqual(process.exit_code(), code)
                self.assertEqual(self.backend.calls, [("wait", 700), ("exit_code", 700)])

    def test_alive_unknown_or_untyped_wait_never_queries_exit_code(self):
        with VerifiedProcess.open(IDENTITY) as process:
            for state in (IdentityStatus.ALIVE, IdentityStatus.UNKNOWN, None, "dead", 0):
                with self.subTest(state=state):
                    self.backend.state = state
                    self.backend.code = 259
                    self.backend.calls.clear()
                    with self.assertRaisesRegex(IdentityUnavailable, "^process_exit_unverified$"):
                        process.exit_code()
                    self.assertEqual(self.backend.calls, [("wait", 700)])

    def test_wait_failure_is_sanitized_without_querying_exit_or_claiming_death(self):
        with VerifiedProcess.open(IDENTITY) as process:
            for error in (IdentityUnavailable("private wait detail", 5), OSError("private path")):
                with self.subTest(kind=type(error).__name__):
                    self.backend.wait_error = error
                    self.backend.calls.clear()
                    with self.assertRaisesRegex(IdentityUnavailable, "^process_exit_unverified$") as caught:
                        process.exit_code()
                    self.assertNotIn("private", str(caught.exception))
                    self.assertEqual(self.backend.calls, [("wait", 700)])

    def test_exit_query_failure_is_sanitized_with_only_valid_win32_error(self):
        with VerifiedProcess.open(IDENTITY) as process:
            for error, win32 in ((IdentityUnavailable("private native detail", 5), 5),
                                 (IdentityUnavailable("private native detail", True), None),
                                 (IdentityUnavailable("private native detail", 1 << 32), None),
                                 (OSError("private path"), None)):
                with self.subTest(kind=type(error).__name__, win32=win32):
                    self.backend.exit_error = error
                    with self.assertRaisesRegex(IdentityUnavailable, "^process_exit_code_unavailable$") as caught:
                        process.exit_code()
                    self.assertEqual(caught.exception.win32_error, win32)
                    self.assertNotIn("private", str(caught.exception))

    def test_invalid_backend_values_are_not_truncated_or_treated_as_exit_codes(self):
        with VerifiedProcess.open(IDENTITY) as process:
            for code in (True, None, -1, 1 << 32, "259", C.c_uint32(259)):
                with self.subTest(code=repr(code)):
                    self.backend.code = code
                    with self.assertRaisesRegex(IdentityUnavailable, "^process_exit_code_invalid$"):
                        process.exit_code()

    def test_repeated_queries_never_reopen_pid_or_reidentify_reused_pid(self):
        with VerifiedProcess.open(IDENTITY) as process:
            self.backend.value = replace(IDENTITY,
                created_filetime_100ns=IDENTITY.created_filetime_100ns + 1)
            self.backend.code = 259
            self.assertEqual(process.exit_code(), 259)
            self.assertEqual(process.exit_code(), 259)
            self.assertEqual(process.identity, IDENTITY)
        self.assertEqual([call for call in self.backend.calls if call[0] == "open"], [("open", 101)])
        self.assertEqual([call for call in self.backend.calls if call[0] == "identity"], [("identity", 700)])
        self.assertEqual([call for call in self.backend.calls if call[0] == "exit_code"],
                         [("exit_code", 700), ("exit_code", 700)])

    def test_owner_lock_is_held_across_wait_and_exit_native_calls(self):
        with VerifiedProcess.open(IDENTITY) as process:
            observed = []
            def assert_locked(stage):
                acquired = process._lock.acquire(blocking=False)
                if acquired:
                    process._lock.release()
                self.assertFalse(acquired, stage)
                observed.append(stage)
            self.backend.on_wait = lambda: assert_locked("wait")
            self.backend.on_exit = lambda: assert_locked("exit_code")
            self.assertEqual(process.exit_code(), 0)
            self.assertEqual(observed, ["wait", "exit_code"])

    def test_closed_owner_refuses_without_any_native_observation(self):
        process = VerifiedProcess.open(IDENTITY)
        process.close()
        self.backend.calls.clear()
        with self.assertRaisesRegex(IdentityUnavailable, "^identity_handle_closed$"):
            process.exit_code()
        self.assertEqual(self.backend.calls, [])

    def test_quarantined_close_outcome_refuses_wait_query_or_reclose(self):
        process = VerifiedProcess.open(IDENTITY)
        self.backend.close_error = OSError("synthetic uncertain close")
        with self.assertRaises(OSError):
            process.close()
        self.assertTrue(process._close_outcome_unknown)
        self.backend.calls.clear()
        with self.assertRaisesRegex(IdentityUnavailable, "^process_handle_close_outcome_unknown$") as caught:
            process.exit_code()
        self.assertTrue(caught.exception._native_close_outcome_unknown)
        self.assertIn(process, caught.exception._identity_handle_cleanup)
        self.assertEqual(self.backend.calls, [])

    def test_known_failed_close_retains_valid_handle_for_exit_query(self):
        process = VerifiedProcess.open(IDENTITY)
        self.backend.close_error = IdentityUnavailable("process_handle_close_failed", 5)
        with self.assertRaises(IdentityUnavailable):
            process.close()
        self.backend.close_error = None
        try:
            self.assertFalse(process._close_outcome_unknown)
            self.assertEqual(process.exit_code(), 0)
        finally:
            process.close()


class NativeExitBindingFixtureTests(unittest.TestCase):
    def test_binding_uses_bool_handle_and_pointer_to_dword_without_wider_access(self):
        kernel, security = MagicMock(), MagicMock()
        with patch.object(identities.os, "name", "nt"), \
                patch.object(identities.C, "sizeof", return_value=8), \
                patch.object(identities.C, "WinDLL", create=True, side_effect=[kernel, security]):
            identities._WindowsBackend()
        self.assertIs(kernel.GetExitCodeProcess.restype, identities._BOOL)
        self.assertEqual(kernel.GetExitCodeProcess.argtypes,
                         (identities._HANDLE, C.POINTER(identities._DWORD)))
        self.assertEqual(identities._PROCESS_ACCESS, 0x1000 | 0x100000)

    def test_backend_passes_exact_handle_and_returns_unsigned_out_parameter(self):
        backend = identities._WindowsBackend.__new__(identities._WindowsBackend)
        calls = []
        def get_exit(handle, pointer):
            calls.append(handle)
            C.cast(pointer, C.POINTER(identities._DWORD)).contents.value = 0xFFFFFFFF
            return 1
        backend.kernel = SimpleNamespace(GetExitCodeProcess=get_exit)
        self.assertEqual(backend.exit_code(700), 0xFFFFFFFF)
        self.assertEqual(calls, [700])

    def test_backend_failed_bool_does_not_return_default_out_parameter(self):
        backend = identities._WindowsBackend.__new__(identities._WindowsBackend)
        backend.kernel = SimpleNamespace(GetExitCodeProcess=lambda handle, pointer: 0)
        with patch.object(identities.C, "get_last_error", create=True, return_value=5):
            with self.assertRaisesRegex(IdentityUnavailable, "^process_exit_code_unavailable$") as caught:
                backend.exit_code(700)
        self.assertEqual(caught.exception.win32_error, 5)


if __name__ == "__main__":
    unittest.main()
