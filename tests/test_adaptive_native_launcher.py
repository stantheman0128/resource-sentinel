"""Portable launch/custody contracts using in-process API fakes only.

Normal discovery never loads a Windows DLL or creates a process, Job or file.
The separately selected ``NativeLauncherBindingSmoke.native_bindings`` checks
only DLL binding/ctypes layouts; it does not call a process or Job API.
"""
import ctypes as C
from dataclasses import replace
import os
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import identity as identity_module
from sentinel.adaptive import native_launcher as native
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable


IDENTITY = ProcessIdentity(501, 134342315823996135, "S-1-5-5-100-200")
APPLICATION = os.path.abspath("fixture-only-program.exe")
DIRECTORY = os.path.abspath("fixture-only-directory")
COMMAND = '"fixture-only-program.exe" "a b" && untouched'
JOB_HANDLE = 900
PROCESS_HANDLE, THREAD_HANDLE, IDENTITY_HANDLE = 700, 701, 800
STDIO_SOURCES = (101, 102, 103)
STDIO_COPIES = (201, 202, 203)


class IdentityBackend:
    """Exercise real VerifiedProcess custody without opening any native handle."""

    def __init__(self):
        self.calls = []
        self.value = IDENTITY
        self.failure = None
        self.close_failure = None

    def open_process(self, pid):
        raise AssertionError("a created process must never be reopened by PID")

    def duplicate_process(self, source):
        self.calls.append(("duplicate", source))
        return IDENTITY_HANDLE

    def identity(self, handle):
        self.calls.append(("identity", handle))
        if self.failure is not None:
            raise self.failure
        return self.value

    def close(self, handle):
        self.calls.append(("close", handle))
        if self.close_failure is not None:
            raise self.close_failure


class Kernel:
    """Only the documented calls needed by the launcher exist in this fake."""

    def __init__(self):
        self.calls = []
        self.error = 0
        self.std_handles = dict(zip((0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4), STDIO_SOURCES))
        self.duplicate_count = 0
        self.duplicate_fail_at = None
        self.duplicate_raise_at = None
        self.duplicate_exception = RuntimeError("fixture_duplicate_exception")
        self.size_result, self.size_error, self.attribute_size = 0, 122, 64
        self.initialize_result, self.initialize_exception = 1, None
        self.update_failure = None
        self.update_exception = None
        self.delete_exception = None
        self.create_result, self.create_exception = 1, None
        self.process_info = PROCESS_HANDLE, THREAD_HANDLE, IDENTITY.pid, 502
        self.member, self.membership_result = True, 1
        self.membership_exception = None
        self.close_failures, self.close_exceptions = set(), {}
        self.wait_result, self.exit_value = 258, 17

    def set_last_error(self, value):
        self.calls.append(("set_last_error", value))
        self.error = value

    def GetCurrentProcess(self):
        return -1

    def GetStdHandle(self, selector):
        self.calls.append(("GetStdHandle", selector))
        return self.std_handles[selector]

    def DuplicateHandle(self, source_process, source, target_process, output, access, inherit, options):
        self.duplicate_count += 1
        self.calls.append(("DuplicateHandle", source_process, source, target_process, access, inherit, options))
        # A FALSE/raising call deliberately leaves nonzero undefined output.
        output._obj.value = STDIO_COPIES[self.duplicate_count - 1]
        if self.duplicate_count == self.duplicate_raise_at:
            raise self.duplicate_exception
        if self.duplicate_count == self.duplicate_fail_at:
            self.error = 5
            return 0
        return 1

    def InitializeProcThreadAttributeList(self, buffer, count, flags, size):
        self.calls.append(("InitializeProcThreadAttributeList", buffer is None, count, flags))
        if buffer is None:
            size._obj.value = self.attribute_size
            self.error = self.size_error
            return self.size_result
        if self.initialize_exception is not None:
            raise self.initialize_exception
        if not self.initialize_result:
            self.error = 5
        return self.initialize_result

    def UpdateProcThreadAttribute(self, buffer, flags, attribute, value, size, previous, returned):
        values = tuple(C.cast(value, C.POINTER(C.c_void_p))[i] for i in range(size // C.sizeof(C.c_void_p)))
        self.calls.append(("UpdateProcThreadAttribute", attribute, values, flags, previous, returned))
        if self.update_exception is not None:
            raise self.update_exception
        if attribute == self.update_failure:
            self.error = 5
            return 0
        return 1

    def DeleteProcThreadAttributeList(self, buffer):
        self.calls.append(("DeleteProcThreadAttributeList", C.addressof(buffer)))
        if self.delete_exception is not None:
            raise self.delete_exception

    def CreateProcessW(self, application, command, process_security, thread_security,
                       inherit, flags, environment, cwd, startup, information):
        info, start = information._obj, startup._obj
        self.calls.append(("CreateProcessW", application, command.value, process_security,
                           thread_security, inherit, flags, environment, cwd,
                           start.StartupInfo.cb, start.StartupInfo.dwFlags,
                           (start.StartupInfo.hStdInput, start.StartupInfo.hStdOutput,
                            start.StartupInfo.hStdError), bool(start.lpAttributeList)))
        info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId = self.process_info
        if self.create_exception is not None:
            raise self.create_exception
        if not self.create_result:
            self.error = 5
        return self.create_result

    def IsProcessInJob(self, process, job, result):
        self.calls.append(("IsProcessInJob", process, job))
        if self.membership_exception is not None:
            raise self.membership_exception
        result._obj.value = self.member
        if not self.membership_result:
            self.error = 5
        return self.membership_result

    def GetProcessTimes(self, handle, created, exited, kernel, user):
        self.calls.append(("GetProcessTimes", handle))
        created._obj.dwHighDateTime = IDENTITY.created_filetime_100ns >> 32
        created._obj.dwLowDateTime = IDENTITY.created_filetime_100ns & 0xFFFFFFFF
        return 1

    def WaitForSingleObject(self, handle, milliseconds):
        self.calls.append(("WaitForSingleObject", handle, milliseconds))
        return self.wait_result

    def GetExitCodeProcess(self, handle, result):
        self.calls.append(("GetExitCodeProcess", handle))
        result._obj.value = self.exit_value
        return 1

    def CloseHandle(self, handle):
        self.calls.append(("CloseHandle", handle))
        if handle in self.close_exceptions:
            raise self.close_exceptions[handle]
        if handle in self.close_failures:
            self.error = 6
            return 0
        return 1


class NativeLauncherTests(unittest.TestCase):
    def setUp(self):
        self.kernel, self.identity = Kernel(), IdentityBackend()
        self.backend = native._WindowsBackend(kernel=self.kernel)
        self.job = SimpleNamespace(handle=JOB_HANDLE, logon_sid=IDENTITY.logon_id)
        for override in (
                patch.object(C, "get_last_error", side_effect=lambda: self.kernel.error, create=True),
                patch.object(C, "set_last_error", side_effect=self.kernel.set_last_error, create=True),
                patch.object(C, "WinDLL", side_effect=AssertionError("portable fixture attempted a DLL load"), create=True),
                patch.object(identity_module, "_backend", return_value=self.identity)):
            override.start()
            self.addCleanup(override.stop)

    def launch(self, **overrides):
        arguments = dict(job=self.job, application=APPLICATION, command_line=COMMAND,
                         cwd=DIRECTORY, stdin_handle=STDIO_SOURCES[0],
                         stdout_handle=STDIO_SOURCES[1], stderr_handle=STDIO_SOURCES[2],
                         backend=self.backend)
        arguments.update(overrides)
        return native.launch_in_job(**arguments)

    def calls(self, name):
        return [call for call in self.kernel.calls if call[0] == name]

    def assert_no_create(self):
        self.assertEqual(self.calls("CreateProcessW"), [])
        self.assertEqual(self.identity.calls, [])

    def assert_original_retained(self, error):
        self.assertEqual(error.process.handle, PROCESS_HANDLE)
        self.assertEqual(error.process.pid, IDENTITY.pid)
        self.assertNotIn(("CloseHandle", PROCESS_HANDLE), self.kernel.calls)
        self.assertEqual(len(self.calls("CreateProcessW")), 1)

    def test_single_create_uses_exact_command_job_and_only_duplicated_stdio(self):
        process = self.launch()
        self.assertEqual(self.calls("CreateProcessW"), [
            ("CreateProcessW", APPLICATION, COMMAND, None, None, True, 0x00080000,
             None, DIRECTORY, C.sizeof(native._StartupInfoEx), 0x100, STDIO_COPIES, True)])
        self.assertEqual(self.calls("UpdateProcThreadAttribute"), [
            ("UpdateProcThreadAttribute", 0x0002000D, (JOB_HANDLE,), 0, None, None),
            ("UpdateProcThreadAttribute", 0x00020002, STDIO_COPIES, 0, None, None)])
        self.assertEqual(self.calls("DuplicateHandle"), [
            ("DuplicateHandle", -1, source, -1, 0, True, 2) for source in STDIO_SOURCES])
        self.assertEqual(self.identity.calls, [("duplicate", PROCESS_HANDLE),
                                              ("identity", IDENTITY_HANDLE), ("close", IDENTITY_HANDLE)])
        self.assertEqual(self.calls("IsProcessInJob"), [("IsProcessInJob", PROCESS_HANDLE, JOB_HANDLE)])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", handle)
                                                    for handle in (THREAD_HANDLE, *STDIO_COPIES)])
        self.assertEqual(len(self.calls("DeleteProcThreadAttributeList")), 1)
        self.assertIn(("set_last_error", 0), self.kernel.calls)
        self.assertEqual(process.handle, PROCESS_HANDLE)
        process.close()
        self.assertEqual(self.calls("CloseHandle")[-1], ("CloseHandle", PROCESS_HANDLE))
        self.assertFalse({JOB_HANDLE, *STDIO_SOURCES}.intersection(call[1] for call in self.calls("CloseHandle")))

    def test_default_standard_handles_use_unsigned_selectors_without_borrowed_closes(self):
        process = self.launch(stdin_handle=None, stdout_handle=None, stderr_handle=None)
        self.assertEqual(self.calls("GetStdHandle"), [("GetStdHandle", value)
                                                     for value in (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4)])
        process.close()
        self.assertFalse(set(STDIO_SOURCES).intersection(call[1] for call in self.calls("CloseHandle")))

    def test_bad_application_command_directory_and_encoding_never_create(self):
        cases = (
            {"application": "relative.exe"}, {"application": 3},
            {"application": APPLICATION + "\0private"},
            {"command_line": None}, {"command_line": "private\0text"},
            {"cwd": "relative"}, {"cwd": DIRECTORY + "\0private"},
            {"command_line": "x" * 32767}, {"command_line": "\U0001f642" * 16384},
            {"command_line": "private\ud800"}, {"application": APPLICATION + "\udfff"},
            {"cwd": DIRECTORY + "\ud800"},
        )
        for arguments in cases:
            with self.subTest(fields=tuple(arguments)), self.assertRaises(ValueError) as failed:
                self.launch(**arguments)
            self.assertNotIsInstance(failed.exception, UnicodeEncodeError)
            self.assertNotIn("private", str(failed.exception))
        self.assertEqual(self.kernel.calls, [])
        self.assert_no_create()

    def test_utf16_boundary_includes_terminator_and_counts_non_bmp_characters(self):
        command = "\U0001f642" * 16383  # 32766 code units plus the terminator.
        process = self.launch(command_line=command)
        self.assertEqual(self.calls("CreateProcessW")[0][2], command)
        process.close()

    def test_bad_job_handle_or_noncanonical_logon_never_touches_api(self):
        for handle in (None, 0, -1, True, C.c_void_p(-1), 1 << (C.sizeof(C.c_void_p) * 8 - 1)):
            with self.subTest(handle=repr(handle)), self.assertRaises(ValueError):
                self.launch(job=SimpleNamespace(handle=handle, logon_sid=IDENTITY.logon_id))
        for logon in (None, "S-1-5-18", "fixture", "S-1-5-5-4294967296-1",
                      "S-1-5-5-\u0661-\u0662", IDENTITY.logon_id + "\n"):
            with self.subTest(logon=logon), self.assertRaises(ValueError):
                self.launch(job=SimpleNamespace(handle=JOB_HANDLE, logon_sid=logon))
        self.assertEqual(self.kernel.calls, [])
        self.assert_no_create()

    def test_invalid_stdio_and_job_as_stdio_never_create(self):
        for source in (0, -1, True, C.c_void_p(-1), JOB_HANDLE):
            with self.subTest(source=repr(source)), self.assertRaises(ValueError):
                self.launch(stdin_handle=source)
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.assert_no_create()

    def test_later_invalid_stdio_cleans_only_successful_duplicates(self):
        with self.assertRaises(ValueError):
            self.launch(stderr_handle=0)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", 201), ("CloseHandle", 202)])
        self.assert_no_create()

    def test_failed_duplicate_ignores_undefined_output_and_closes_only_prior_copy(self):
        self.kernel.duplicate_fail_at = 2
        with self.assertRaisesRegex(native.NativeLaunchError, "stdio_duplicate_failed"):
            self.launch()
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", 201)])
        self.assert_no_create()

    def test_raising_duplicate_quarantines_raw_output_and_cleans_prior_copy(self):
        self.kernel.duplicate_raise_at = 2
        with self.assertRaises(RuntimeError) as failed:
            self.launch()
        self.assertIs(failed.exception, self.kernel.duplicate_exception)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", 201)])
        owner = failed.exception.cleanup_owner
        self.assertEqual([value.value for value in owner._duplicate_uncertainty], [202])
        with self.assertRaisesRegex(native.NativeLaunchError, "stdio_duplicate_quarantined"):
            native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", 201)])
        self.assertEqual(len(self.calls("DuplicateHandle")), 2)
        self.assert_no_create()

    def test_attribute_sizing_requires_expected_false_error_and_bounded_size(self):
        for result, error, size in ((1, 122, 64), (0, 0, 64), (0, 5, 64), (0, 122, 0), (0, 122, 65537)):
            with self.subTest(result=result, error=error, size=size):
                self.kernel.duplicate_count = 0
                self.kernel.size_result, self.kernel.size_error, self.kernel.attribute_size = result, error, size
                with self.assertRaisesRegex(native.NativeLaunchError, "attribute_list_size_invalid"):
                    self.launch()
        self.assertEqual(self.calls("DeleteProcThreadAttributeList"), [])
        self.assertEqual(len(self.calls("CloseHandle")), 15)
        self.assert_no_create()

    def test_failed_attribute_initialization_never_deletes_uninitialized_list(self):
        self.kernel.initialize_result = 0
        with self.assertRaisesRegex(native.NativeLaunchError, "attribute_list_initialize_failed"):
            self.launch()
        self.assertEqual(self.calls("DeleteProcThreadAttributeList"), [])
        self.assertEqual(len(self.calls("CloseHandle")), 3)
        self.assert_no_create()

    def test_raising_attribute_initialization_quarantines_allocation_without_retry(self):
        original = self.kernel.initialize_exception = RuntimeError("fixture_initialize_exception")
        with self.assertRaises(RuntimeError) as failed:
            self.launch()
        self.assertIs(failed.exception, original)
        owner = original.cleanup_owner
        self.assertIsNotNone(owner._attributes)
        with self.assertRaisesRegex(native.NativeLaunchError, "attribute_initialization_quarantined"):
            native.retry_launch_cleanup(original)
        self.assertIsNotNone(owner._attributes)
        self.assertEqual(len(self.calls("InitializeProcThreadAttributeList")), 2)
        self.assertEqual(self.calls("DeleteProcThreadAttributeList"), [])
        self.assertEqual(len(self.calls("CloseHandle")), 3)
        self.assert_no_create()

    def test_failed_job_or_handle_attribute_prevents_create_and_cleans_once(self):
        for attribute in (0x0002000D, 0x00020002):
            with self.subTest(attribute=attribute):
                self.kernel.duplicate_count = 0
                self.kernel.update_failure = attribute
                with self.assertRaises(native.NativeLaunchError):
                    self.launch()
        self.assertEqual(len(self.calls("DeleteProcThreadAttributeList")), 2)
        self.assertEqual(len(self.calls("CloseHandle")), 6)
        self.assert_no_create()

    def test_precreate_error_and_failed_cleanup_keep_primary_and_exact_retry_owner(self):
        original = self.kernel.update_exception = RuntimeError("fixture_update_exception")
        self.kernel.close_failures.add(201)
        with self.assertRaises(RuntimeError) as failed:
            self.launch()
        self.assertIs(failed.exception, original)
        self.assertTrue(original._native_cleanup_errors)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", value) for value in STDIO_COPIES])
        self.assertIsNotNone(original.cleanup_owner)
        self.kernel.close_failures.clear()
        native.retry_launch_cleanup(original)
        self.assertEqual(self.calls("CloseHandle")[-1], ("CloseHandle", 201))
        count = len(self.kernel.calls)
        native.retry_launch_cleanup(original)
        self.assertEqual(len(self.kernel.calls), count)
        self.assert_no_create()

    def test_known_create_false_ignores_undefined_process_outputs(self):
        self.kernel.create_result = 0
        # Deliberately nonzero values cannot become handles owned by a FALSE call.
        self.kernel.process_info = JOB_HANDLE, STDIO_SOURCES[0], 42, 43
        with self.assertRaisesRegex(native.NativeLaunchError, "create_process_failed") as failed:
            self.launch()
        self.assertFalse(hasattr(failed.exception, "process"))
        self.assertEqual(len(self.calls("CreateProcessW")), 1)
        self.assertEqual(self.identity.calls, [])
        self.assertEqual(self.calls("IsProcessInJob"), [])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", value) for value in STDIO_COPIES])

    def test_exception_during_create_retains_raw_outputs_but_never_uses_them(self):
        original = self.kernel.create_exception = SystemExit("fixture_create_interruption")
        self.kernel.process_info = JOB_HANDLE, STDIO_SOURCES[0], 42, 43
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        error = failed.exception
        self.assertIs(error.cause, original)
        self.assertIs(error.__cause__, original)
        self.assertIsNone(error.process.handle)
        self.assertEqual(error.process._unverified_process_info.hProcess, JOB_HANDLE)
        self.assertEqual(self.identity.calls, [])
        self.assertEqual(self.calls("IsProcessInJob"), [])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", value) for value in STDIO_COPIES])
        with self.assertRaisesRegex(native.NativeLaunchError, "created_process_handle_unavailable"):
            native.retry_launch_cleanup(error)
        self.assertEqual(len(self.calls("CreateProcessW")), 1)
        self.assertEqual(len(self.calls("CloseHandle")), 3)

    def test_identity_failure_keeps_original_process_without_pid_reopen(self):
        original = self.identity.failure = IdentityUnavailable("fixture_identity_unavailable")
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        self.assertIs(failed.exception.cause, original)
        self.assert_original_retained(failed.exception)
        self.assertEqual(self.calls("IsProcessInJob"), [])
        self.assertIn(("close", IDENTITY_HANDLE), self.identity.calls)
        native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.calls("CloseHandle")[-1], ("CloseHandle", PROCESS_HANDLE))
        self.assertEqual(len(self.calls("CreateProcessW")), 1)

    def test_pid_or_logon_mismatch_never_returns_unverified_process(self):
        for value in (replace(IDENTITY, pid=502), replace(IDENTITY, logon_id="S-1-5-5-100-201")):
            with self.subTest(value=value):
                self.kernel.duplicate_count = 0
                self.identity.value = value
                with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
                    self.launch()
                self.assertIsInstance(failed.exception.cause, IdentityUnavailable)
                self.assertEqual(failed.exception.process.handle, PROCESS_HANDLE)
                native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.calls("IsProcessInJob"), [])

    def test_identity_duplicate_close_failure_retains_duplicate_and_original_until_retry(self):
        # Explicit known native FALSE; an arbitrary Python exception is unknown.
        original = self.identity.close_failure = IdentityUnavailable("process_handle_close_failed", 6)
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        self.assertIs(failed.exception.cause, original)
        self.assert_original_retained(failed.exception)
        self.assertTrue(original._identity_handle_cleanup)
        with self.assertRaises(IdentityUnavailable):
            native.retry_launch_cleanup(failed.exception)
        self.assertNotIn(("CloseHandle", PROCESS_HANDLE), self.kernel.calls)
        self.identity.close_failure = None
        native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.identity.calls.count(("close", IDENTITY_HANDLE)), 3)
        self.assertEqual(self.calls("CloseHandle")[-1], ("CloseHandle", PROCESS_HANDLE))

    def test_membership_mismatch_or_unknown_keeps_same_process_and_cleans_transients(self):
        for result, member in ((1, False), (0, False)):
            with self.subTest(result=result):
                self.kernel.duplicate_count = 0
                self.kernel.membership_result, self.kernel.member = result, member
                with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
                    self.launch()
                self.assertEqual(failed.exception.process.handle, PROCESS_HANDLE)
                self.assertIsInstance(failed.exception.cause, native.NativeLaunchError)
                native.retry_launch_cleanup(failed.exception)
        self.assertEqual(len(self.calls("CreateProcessW")), 2)

    def test_primary_membership_error_survives_independent_thread_and_stdio_failures(self):
        original = self.kernel.membership_exception = RuntimeError("fixture_membership_exception")
        self.kernel.close_failures.update((THREAD_HANDLE, 201, 203))
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        self.assertIs(failed.exception.cause, original)
        self.assert_original_retained(failed.exception)
        self.assertTrue(original._native_cleanup_errors)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", value)
                                                    for value in (THREAD_HANDLE, *STDIO_COPIES)])
        self.assertEqual(len(self.calls("DeleteProcThreadAttributeList")), 1)
        self.kernel.close_failures.clear()
        native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.calls("CloseHandle")[-4:], [("CloseHandle", value)
                                                        for value in (THREAD_HANDLE, 201, 203, PROCESS_HANDLE)])
        self.assertEqual(len(self.calls("CreateProcessW")), 1)

    def test_cleanup_false_after_verified_create_does_not_return_success(self):
        for handle in (THREAD_HANDLE, *STDIO_COPIES):
            with self.subTest(handle=handle):
                self.kernel.duplicate_count = 0
                self.kernel.close_failures.add(handle)
                with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
                    self.launch()
                self.assertEqual(failed.exception.process.handle, PROCESS_HANDLE)
                self.assertEqual(failed.exception.cause.reason, "native_handle_close_failed")
                self.kernel.close_failures.clear()
                before = len(self.calls("CloseHandle"))
                native.retry_launch_cleanup(failed.exception)
                self.assertEqual(self.calls("CloseHandle")[before:],
                                 [("CloseHandle", handle), ("CloseHandle", PROCESS_HANDLE)])

    def test_delete_exception_quarantines_attribute_values_and_never_redeletes(self):
        original = self.kernel.delete_exception = RuntimeError("fixture_delete_exception")
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        self.assertIs(failed.exception.cause, original)
        self.assert_original_retained(failed.exception)
        owner = failed.exception.process
        self.assertIsNotNone(owner._attributes)
        jobs, handles = owner._attribute_values
        self.assertEqual(tuple(jobs), (JOB_HANDLE,))
        self.assertEqual(tuple(handles), STDIO_COPIES)
        self.kernel.delete_exception = None
        with self.assertRaisesRegex(native.NativeLaunchError, "attribute_cleanup_quarantined"):
            native.retry_launch_cleanup(failed.exception)
        self.assertEqual(len(self.calls("DeleteProcThreadAttributeList")), 1)
        self.assertEqual(len(self.calls("CloseHandle")), 4)
        self.assertIsNotNone(owner._attributes)
        self.assert_original_retained(failed.exception)

    def test_ancillary_close_exception_is_quarantined_without_second_close(self):
        original = RuntimeError("fixture_close_exception")
        self.kernel.close_exceptions[THREAD_HANDLE] = original
        with self.assertRaises(native.LaunchOutcomeUnknown) as failed:
            self.launch()
        self.assertIs(failed.exception.cause, original)
        self.assert_original_retained(failed.exception)
        self.kernel.close_exceptions.clear()
        with self.assertRaisesRegex(native.NativeLaunchError, "native_handle_close_quarantined"):
            native.retry_launch_cleanup(failed.exception)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", THREAD_HANDLE)), 1)
        self.assertEqual(len(self.calls("CloseHandle")), 4)
        self.assert_original_retained(failed.exception)

    def test_fast_exit_identity_membership_and_diagnostics_use_original_handle(self):
        self.kernel.wait_result = 0
        process = self.launch()
        self.assertEqual(self.calls("WaitForSingleObject"), [])
        self.assertEqual(process.identity(), {"pid": IDENTITY.pid,
                         "created_filetime_100ns": str(IDENTITY.created_filetime_100ns)})
        self.assertEqual(process.full_identity(expected_logon_id=IDENTITY.logon_id), IDENTITY)
        self.assertTrue(process.is_in_job(self.job))
        self.assertTrue(process.wait(0.0001))
        self.assertIn(("WaitForSingleObject", PROCESS_HANDLE, 1), self.kernel.calls)
        self.assertEqual(process.exit_code(), 17)
        self.assertEqual(self.calls("GetExitCodeProcess"), [("GetExitCodeProcess", PROCESS_HANDLE)])
        process.close()

    def test_live_exit_is_unknown_and_wait_failure_is_never_reported_as_exit(self):
        process = self.launch()
        self.assertFalse(process.wait(0))
        self.assertIsNone(process.exit_code())
        self.assertEqual(self.calls("GetExitCodeProcess"), [])
        self.kernel.wait_result = 0xFFFFFFFF
        with self.assertRaisesRegex(native.NativeLaunchError, "created_process_wait_failed"):
            process.exit_code()
        self.assertEqual(self.calls("GetExitCodeProcess"), [])
        process.close()

    def test_invalid_wait_and_logon_requests_do_not_query_process(self):
        process = self.launch()
        for timeout in (-1, 120.1, True, None, float("nan"), float("inf"), "1"):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                process.wait(timeout)
        calls = list(self.identity.calls)
        with self.assertRaisesRegex(native.NativeLaunchError, "created_process_logon_mismatch"):
            process.full_identity(expected_logon_id="S-1-5-5-100-201")
        self.assertEqual(self.identity.calls, calls)
        self.assertEqual(self.calls("WaitForSingleObject"), [])
        process.close()

    def test_original_close_false_is_retryable_and_successful_close_is_idempotent(self):
        process = self.launch()
        self.kernel.close_failures.add(PROCESS_HANDLE)
        with self.assertRaises(native.NativeLaunchError) as failed:
            process.close()
        self.assertIs(failed.exception.cleanup_owner, process)
        self.assertEqual(process.handle, PROCESS_HANDLE)
        self.kernel.close_failures.clear()
        native.retry_launch_cleanup(failed.exception)
        count = len(self.kernel.calls)
        process.close()
        self.assertEqual(len(self.kernel.calls), count)
        self.assertIsNone(process.handle)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", PROCESS_HANDLE)), 2)
        self.assertEqual(len(self.calls("CreateProcessW")), 1)
        for operation in (process.identity, lambda: process.wait(0), process.exit_code,
                          lambda: process.is_in_job(self.job),
                          lambda: process.full_identity(expected_logon_id=IDENTITY.logon_id)):
            with self.assertRaisesRegex(native.NativeLaunchError, "created_process_handle_unavailable"):
                operation()
        self.assertEqual(len(self.kernel.calls), count)

    def test_original_close_exception_quarantines_all_future_operations(self):
        process = self.launch()
        original = RuntimeError("fixture_original_close_exception")
        self.kernel.close_exceptions[PROCESS_HANDLE] = original
        with self.assertRaises(RuntimeError) as failed:
            process.close()
        self.assertIs(failed.exception, original)
        self.assertIs(original.cleanup_owner, process)
        self.kernel.close_exceptions.clear()
        count, identity_calls = len(self.kernel.calls), list(self.identity.calls)
        for operation in (process.identity, lambda: process.wait(0), process.exit_code,
                          lambda: process.is_in_job(self.job),
                          lambda: process.full_identity(expected_logon_id=IDENTITY.logon_id)):
            with self.assertRaisesRegex(native.NativeLaunchError, "created_process_handle_quarantined"):
                operation()
        with self.assertRaisesRegex(native.NativeLaunchError, "native_handle_close_quarantined"):
            native.retry_launch_cleanup(original)
        self.assertEqual(len(self.kernel.calls), count)
        self.assertEqual(self.identity.calls, identity_calls)
        self.assertEqual(self.calls("CloseHandle").count(("CloseHandle", PROCESS_HANDLE)), 1)

    def test_successful_close_tombstone_prevents_query_or_second_close_before_field_clear(self):
        process = native.CreatedProcess(self.backend, IDENTITY.logon_id)
        process.handle, process.pid = PROCESS_HANDLE, IDENTITY.pid
        # Simulate interruption after the native close completed, before its
        # caller clears the public field. The tombstone must already be durable
        # in this owner; the numeric handle is no longer safe to use.
        process._close_handle(PROCESS_HANDLE)
        self.assertEqual(process.handle, PROCESS_HANDLE)
        count = len(self.kernel.calls)
        for operation in (process.identity, lambda: process.wait(0), process.exit_code,
                          lambda: process.is_in_job(self.job),
                          lambda: process.full_identity(expected_logon_id=IDENTITY.logon_id)):
            with self.assertRaisesRegex(native.NativeLaunchError, "created_process_handle_quarantined"):
                operation()
        process.close()
        process.close()
        self.assertIsNone(process.handle)
        self.assertEqual(len(self.kernel.calls), count)
        self.assertEqual(self.identity.calls, [])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", PROCESS_HANDLE)])
        self.assert_no_create()

    def test_interruption_after_backend_native_success_keeps_preexisting_quarantine(self):
        process = native.CreatedProcess(self.backend, IDENTITY.logon_id)
        process.handle, process.pid = PROCESS_HANDLE, IDENTITY.pid
        original = KeyboardInterrupt("fixture_after_close_before_return")
        real_close = self.backend.close

        def interrupted_close(handle):
            real_close(handle)
            raise original

        with patch.object(self.backend, "close", side_effect=interrupted_close):
            with self.assertRaises(KeyboardInterrupt) as failed:
                process.close()
        self.assertIs(failed.exception, original)
        self.assertIs(original.cleanup_owner, process)
        count = len(self.kernel.calls)
        with self.assertRaisesRegex(native.NativeLaunchError, "created_process_handle_quarantined"):
            process.identity()
        with self.assertRaisesRegex(native.NativeLaunchError, "native_handle_close_quarantined"):
            native.retry_launch_cleanup(original)
        self.assertEqual(len(self.kernel.calls), count)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", PROCESS_HANDLE)])
        self.assert_no_create()

    def test_retry_requires_an_actual_retained_cleanup_owner(self):
        with self.assertRaisesRegex(ValueError, "native_cleanup_owner_missing"):
            native.retry_launch_cleanup(RuntimeError("fixture_unrelated_error"))
        self.assertEqual(self.kernel.calls, [])


@unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8, "requires 64-bit Windows")
class NativeLauncherBindingSmoke(unittest.TestCase):
    def native_bindings(self):
        """Explicit selection only: bind real DLLs, perform no native API call."""
        from tests.windows import adaptive_win32 as adapter

        backend = native._WindowsBackend()
        with patch.object(adapter, "_API", None):
            kernel, _, _ = adapter._api()
        self.assertEqual(C.sizeof(native._StartupInfoEx), 112)
        self.assertEqual(C.sizeof(native._ProcessInfo), 24)
        self.assertEqual(C.sizeof(native._FileTime), 8)
        self.assertIs(adapter._StartupInfoEx, native._StartupInfoEx)
        self.assertIs(adapter._ProcessInfo, native._ProcessInfo)
        for api in (backend.kernel, kernel):
            self.assertIs(api.CreateProcessW.argtypes[-2]._type_, native._StartupInfoEx)
            self.assertIs(api.CreateProcessW.argtypes[-1]._type_, native._ProcessInfo)
            self.assertIs(api.IsProcessInJob.argtypes[-1]._type_, native._BOOL)
            self.assertIs(api.GetExitCodeProcess.argtypes[-1]._type_, native._DWORD)
            for pointer in api.GetProcessTimes.argtypes[1:]:
                self.assertIs(pointer._type_, native._FileTime)


if __name__ == "__main__":
    unittest.main()
