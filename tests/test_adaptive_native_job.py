"""Portable native Job ownership/rights tests; all API objects are explicit fakes.

Discovery loads no DLL and creates no native Job, process or runtime file.
NativeJobBindingSmoke.native_bindings is separately selected and binds DLLs
only. Its separately selected native_empty_job_smoke creates one empty test Job
and queries it; no process is launched/assigned and no CPU limit is written.
"""
import ctypes as C
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from sentinel.adaptive import native_job as native


NONCE = "a" * 32
NAME = "Local\\ResourceSentinel.Job.12345678-1234-4234-8234-123456789abc." + NONCE
TEST_NAME = "Local\\ResourceSentinel.Test.Job." + NONCE
LOGON = "S-1-5-5-100-200"
OWNER = "S-1-5-21-1-2-3-1000"
CREATED, RETAINED, DESCRIPTOR = 700, 701, 900

# Explicit native smoke only: unresolved owners and their original errors stay
# reachable after unittest records a failure. Never sweep another invocation.
_NATIVE_SMOKE_CUSTODY = []
_NATIVE_SMOKE_FAILURES = []


class Security:
    def __init__(self, calls):
        self.calls = calls
        self.owner = OWNER
        self.failure = None
        self.fail_handle = None

    def current_owner_sid(self):
        self.calls.append(("current_owner_sid",))
        return self.owner

    def verify_security(self, handle, logon_id, owner_sid, *, access_mask):
        self.calls.append(("verify_security", handle, logon_id, owner_sid, access_mask))
        if self.failure is not None and (self.fail_handle is None or handle == self.fail_handle):
            raise self.failure


class Advapi:
    def __init__(self, kernel):
        self.kernel = kernel
        self.result, self.exception = 1, None
        self.descriptor = DESCRIPTOR

    def ConvertStringSecurityDescriptorToSecurityDescriptorW(self, sddl, revision, result, size):
        self.kernel.calls.append(("descriptor", sddl, revision, size))
        result._obj.value = self.descriptor
        if self.exception is not None:
            raise self.exception
        if not self.result:
            self.kernel.error = 5
        return self.result


class Kernel:
    def __init__(self):
        self.calls = []
        self.error = 0
        self.create_handle, self.create_error, self.create_exception = CREATED, 0, None
        self.open_handle, self.open_exception = RETAINED, None
        self.duplicate_result, self.duplicate_exception = 1, None
        self.duplicate_handle = RETAINED
        self.handle_flags = {}
        self.handle_information_result = 1
        self.cpu = (0, 10000)
        self.limit_flags, self.ui_restrictions = 0, 0
        self.accounting = (2**53 + 1, 2**53 + 3, 0, 0, 0, 5, 2, 3)
        self.query_failure, self.query_exception = None, None
        self.set_result, self.set_exception = 1, None
        self.apply_set = True
        self.disabled_union = 10000
        self.membership = []
        self.close_failures, self.close_exceptions = set(), {}
        self.free_failure, self.free_exception = False, None

    def set_last_error(self, value):
        self.calls.append(("set_last_error", value))
        self.error = value

    def GetCurrentProcess(self):
        return -1

    def CreateJobObjectW(self, attributes, name):
        value = attributes._obj
        self.calls.append(("CreateJobObjectW", name, value.length, value.descriptor, value.inherit))
        if self.create_exception is not None:
            raise self.create_exception
        self.error = self.create_error
        return self.create_handle

    def OpenJobObjectW(self, access, inherit, name):
        self.calls.append(("OpenJobObjectW", access, inherit, name))
        if self.open_exception is not None:
            raise self.open_exception
        if not self.open_handle:
            self.error = 5
        return self.open_handle

    def DuplicateHandle(self, source_process, source, target_process, output, rights, inherit, options):
        self.calls.append(("DuplicateHandle", source_process, source, target_process, rights, inherit, options))
        # Deliberately populate undefined output on FALSE/exception as well.
        output._obj.value = self.duplicate_handle
        if self.duplicate_exception is not None:
            raise self.duplicate_exception
        if not self.duplicate_result:
            self.error = 5
        return self.duplicate_result

    def GetHandleInformation(self, handle, flags):
        self.calls.append(("GetHandleInformation", handle))
        flags._obj.value = self.handle_flags.get(handle, 0)
        if not self.handle_information_result:
            self.error = 5
        return self.handle_information_result

    def QueryInformationJobObject(self, handle, information_class, output, size, returned):
        self.calls.append(("QueryInformationJobObject", handle, information_class, size))
        if self.query_exception is not None:
            raise self.query_exception
        if self.query_failure == information_class:
            self.error = 5
            return 0
        value = output._obj
        if information_class == 15:
            value.ControlFlags, value.CpuRate = self.cpu
        elif information_class == 9:
            value.BasicLimitInformation.LimitFlags = self.limit_flags
        elif information_class == 4:
            value.value = self.ui_restrictions
        elif information_class == 1:
            fields = ("TotalUserTime", "TotalKernelTime", "ThisPeriodTotalUserTime",
                      "ThisPeriodTotalKernelTime", "TotalPageFaultCount", "TotalProcesses",
                      "ActiveProcesses", "TotalTerminatedProcesses")
            for field, data in zip(fields, self.accounting):
                setattr(value, field, data)
        elif information_class == 3:
            snapshot = self.membership.pop(0) if self.membership else (1, 0, 2, 2, (41, 42))
            ok, self.error, value.assigned, value.listed, pids = snapshot
            for index, pid in enumerate(pids[:len(value.pids)]):
                value.pids[index] = pid
            return ok
        else:
            raise AssertionError("unexpected information class")
        return 1

    def SetInformationJobObject(self, handle, information_class, information, size):
        value = information._obj
        self.calls.append(("SetInformationJobObject", handle, information_class,
                           value.ControlFlags, value.CpuRate, size))
        if self.apply_set:
            self.cpu = (value.ControlFlags, value.CpuRate if value.ControlFlags else self.disabled_union)
        if self.set_exception is not None:
            raise self.set_exception
        if not self.set_result:
            self.error = 5
        return self.set_result

    def CloseHandle(self, handle):
        self.calls.append(("CloseHandle", handle))
        if handle in self.close_exceptions:
            raise self.close_exceptions[handle]
        if handle in self.close_failures:
            self.error = 6
            return 0
        return 1

    def LocalFree(self, pointer):
        value = pointer.value if isinstance(pointer, C.c_void_p) else pointer
        self.calls.append(("LocalFree", value))
        if self.free_exception is not None:
            raise self.free_exception
        if self.free_failure:
            self.error = 6
            return value
        return None


class NativeJobTests(unittest.TestCase):
    def setUp(self):
        self.kernel = Kernel()
        self.advapi, self.security = Advapi(self.kernel), Security(self.kernel.calls)
        self.backend = native._WindowsBackend(kernel=self.kernel, advapi=self.advapi, security=self.security)
        for override in (
                patch.object(C, "get_last_error", side_effect=lambda: self.kernel.error, create=True),
                patch.object(C, "set_last_error", side_effect=self.kernel.set_last_error, create=True),
                patch.object(C, "WinDLL", side_effect=AssertionError("portable fixture attempted DLL load"), create=True)):
            override.start()
            self.addCleanup(override.stop)

    def create(self, **overrides):
        arguments = dict(name=NAME, nonce=NONCE, logon_id=LOGON, backend=self.backend)
        arguments.update(overrides)
        return native.NativeJob.create(**arguments)

    def open(self, **overrides):
        arguments = dict(name=NAME, nonce=NONCE, logon_id=LOGON, backend=self.backend)
        arguments.update(overrides)
        return native.NativeJob.open(**arguments)

    def calls(self, name):
        return [value for value in self.kernel.calls if value[0] == name]

    def assert_retained(self, error, owner):
        self.assertIn(owner, error._native_job_cleanup)

    def test_create_verifies_baseline_then_reduces_rights_without_inheritance(self):
        job = self.create()
        self.assertEqual((job.handle, job.name, job.nonce, job.logon_sid, job.access),
                         (RETAINED, NAME, NONCE, LOGON, native.JobAccess.LAUNCH))
        self.assertEqual(self.calls("descriptor"), [
            ("descriptor", f"O:{OWNER}D:P(A;;0x001f003f;;;{LOGON})", 1, None)])
        self.assertEqual(self.calls("CreateJobObjectW"), [
            ("CreateJobObjectW", NAME, C.sizeof(native._SecurityAttributes), DESCRIPTOR, 0)])
        self.assertEqual(self.calls("verify_security"), [
            ("verify_security", value, LOGON, OWNER, 0x1F003F) for value in (CREATED, RETAINED)])
        self.assertEqual([call[1:3] for call in self.calls("QueryInformationJobObject")],
                         [(CREATED, 9), (CREATED, 4), (CREATED, 15)])
        self.assertEqual(self.calls("DuplicateHandle"), [
            ("DuplicateHandle", -1, CREATED, -1, 0x20005, False, 0)])
        query_position = max(i for i, call in enumerate(self.kernel.calls) if call[0] == "QueryInformationJobObject")
        duplicate_position = next(i for i, call in enumerate(self.kernel.calls) if call[0] == "DuplicateHandle")
        self.assertLess(query_position, duplicate_position)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED)])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        job.close()
        self.assertEqual(self.calls("CloseHandle")[-1], ("CloseHandle", RETAINED))

    def test_open_defaults_to_query_and_never_creates_or_changes_existing_job(self):
        self.kernel.cpu = (5, 3500)
        job = self.open()
        self.assertEqual(self.calls("OpenJobObjectW"), [("OpenJobObjectW", 0x20004, False, NAME)])
        self.assertEqual(job.query_cpu(), native.CpuState(5, 3500))
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.assertEqual(self.calls("descriptor"), [])
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        job.close()
        self.assertEqual(self.kernel.cpu, (5, 3500))

    def test_each_role_requests_only_its_explicit_rights(self):
        roles = ((native.JobAccess.QUERY, 0x20004), (native.JobAccess.LAUNCH, 0x20005),
                 (native.JobAccess.CONTROL, 0x20006), (native.JobAccess.OWNER, 0x20007))
        for role, rights in roles:
            with self.subTest(role=role):
                job = self.create(access=role)
                self.assertEqual(self.calls("DuplicateHandle")[-1][4:], (rights, False, 0))
                job.close()
                job = self.open(access=role)
                self.assertEqual(self.calls("OpenJobObjectW")[-1], ("OpenJobObjectW", rights, False, NAME))
                job.close()

    def test_exact_test_namespace_is_supported_without_relaxing_nonce(self):
        job = self.create(name=TEST_NAME)
        self.assertEqual(job.name, TEST_NAME)
        job.close()

    def test_invalid_names_nonces_logons_and_raw_access_do_not_call_any_api(self):
        cases = (
            {"name": "arbitrary"}, {"name": NAME.replace("Local\\", "Global\\")},
            {"name": NAME + "\\extra"}, {"name": NAME.replace(NONCE, "b" * 32)},
            {"name": NAME.replace("12345678-1234-4234-8234-123456789abc", "00000000-0000-0000-0000-000000000000")},
            {"name": NAME.replace("789abc", "789ABC")}, {"name": None},
            {"nonce": "A" * 32}, {"nonce": "a" * 31}, {"nonce": None},
            {"logon_id": "S-1-5-18"}, {"logon_id": "S-1-5-5-4294967296-1"},
            {"logon_id": "S-1-5-5-\u0661-\u0662"}, {"logon_id": LOGON + "\n"},
            {"access": 0x20007}, {"access": True},
        )
        for arguments in cases:
            for method in (self.create, self.open):
                with self.subTest(fields=tuple(arguments), method=method.__name__), self.assertRaises(ValueError):
                    method(**arguments)
        self.assertEqual(self.kernel.calls, [])

    def test_collision_closes_returned_handle_without_adoption_query_or_write(self):
        self.kernel.create_error = 183
        with self.assertRaisesRegex(native.NativeJobError, "native_job_name_collision") as failed:
            self.create()
        self.assertEqual(failed.exception.win32_error, 183)
        self.assertEqual(self.calls("verify_security"), [])
        self.assertEqual(self.calls("QueryInformationJobObject"), [])
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED)])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])

    def test_create_or_open_null_failure_does_not_close_invalid_handle(self):
        self.kernel.create_handle, self.kernel.create_error = None, 6
        with self.assertRaisesRegex(native.NativeJobError, "native_job_create_failed") as failed:
            self.create()
        self.assertEqual(failed.exception.win32_error, 6)
        self.assertEqual(self.calls("CloseHandle"), [])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])
        self.kernel.open_handle = None
        with self.assertRaisesRegex(native.NativeJobError, "native_job_open_failed"):
            self.open()
        self.assertEqual(self.calls("CloseHandle"), [])

    def test_descriptor_false_ignores_undefined_output_and_never_creates_job(self):
        self.advapi.result = 0
        with self.assertRaisesRegex(native.NativeJobError, "native_job_descriptor_create_failed"):
            self.create()
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertEqual(self.calls("LocalFree"), [])
        self.assertEqual(self.calls("CloseHandle"), [])

    def test_failed_factory_retains_closed_original_without_pending_cleanup_or_query_rights(self):
        self.kernel.create_handle, self.kernel.create_error = None, 6
        self.kernel.open_handle = None
        for operation in (self.create, self.open):
            with self.subTest(operation=operation.__name__):
                with self.assertRaises(native.NativeJobError) as failed:
                    operation()
                owner, = failed.exception._native_job_initialization_owners
                self.assertIs(type(owner), native.NativeJob)
                self.assertEqual((owner.name, owner.nonce, owner.logon_sid), (NAME, NONCE, LOGON))
                self.assertTrue(owner.closed)
                self.assertFalse(getattr(failed.exception, "_native_job_cleanup", ()))
                before = list(self.kernel.calls)
                native.retry_job_cleanup(failed.exception)
                self.assertEqual(self.kernel.calls, before)
                with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
                    _ = owner.handle
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_failed_factory_keeps_original_uncertainty_distinct_from_positive_close(self):
        original = self.kernel.create_exception = KeyboardInterrupt("fixture original acquisition")
        with self.assertRaises(KeyboardInterrupt) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        owner, = original._native_job_initialization_owners
        self.assertIs(original._native_job_cleanup[0], owner)
        self.assertFalse(owner.closed)
        before = list(self.kernel.calls)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(self.kernel.calls, before)

    def test_reused_primary_preserves_each_original_factory_owner(self):
        original = self.security.failure = RuntimeError("fixture same primary")
        for _ in range(2):
            with self.assertRaises(RuntimeError) as failed:
                self.create()
            self.assertIs(failed.exception, original)
        first, second = original._native_job_initialization_owners
        self.assertIsNot(first, second)
        self.assertTrue(first.closed)
        self.assertTrue(second.closed)
        self.assertFalse(getattr(original, "_native_job_cleanup", ()))
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_descriptor_exception_retains_uncertain_buffer_without_free_or_recreate(self):
        original = self.advapi.exception = RuntimeError("fixture_descriptor_exception")
        with self.assertRaises(RuntimeError) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        owner, = original._native_job_cleanup
        self.assertEqual([value.value for value in owner._uncertain_outputs], [DESCRIPTOR])
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(len(self.calls("descriptor")), 1)
        self.assertEqual(self.calls("CreateJobObjectW"), [])
        self.assertEqual(self.calls("LocalFree"), [])

    def test_create_exception_preserves_primary_and_quarantines_allocation(self):
        original = self.kernel.create_exception = KeyboardInterrupt("fixture_create_interruption")
        with self.assertRaises(KeyboardInterrupt) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        owner, = original._native_job_cleanup
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
            _ = owner.handle
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)
        self.assertEqual(self.calls("CloseHandle"), [])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])

    def test_open_exception_never_retries_or_queries_unknown_handle(self):
        original = self.kernel.open_exception = RuntimeError("fixture_open_exception")
        with self.assertRaises(RuntimeError) as failed:
            self.open()
        self.assertIs(failed.exception, original)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(len(self.calls("OpenJobObjectW")), 1)
        self.assertEqual(self.calls("verify_security"), [])
        self.assertEqual(self.calls("CloseHandle"), [])

    def test_nonzero_initial_limits_or_cpu_flags_fail_without_repair_writes(self):
        for cpu, limits, ui in (((5, 5000), 0, 0), ((0, 10000), 0x2000, 0), ((0, 10000), 0, 1)):
            with self.subTest(cpu=cpu, limits=limits, ui=ui):
                self.kernel.cpu, self.kernel.limit_flags, self.kernel.ui_restrictions = cpu, limits, ui
                with self.assertRaisesRegex(native.NativeJobError, "native_job_new_baseline_invalid"):
                    self.create()
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED)] * 3)

    def test_security_or_inheritability_failure_never_returns_authority(self):
        original = self.security.failure = RuntimeError("fixture_acl_mismatch")
        with self.assertRaises(RuntimeError) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        self.assertEqual(self.calls("QueryInformationJobObject"), [])
        self.assertEqual(self.calls("DuplicateHandle"), [])
        self.security.failure = None
        self.kernel.handle_flags[RETAINED] = 1
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_inheritable"):
            self.create()
        self.assertIn(("CloseHandle", RETAINED), self.kernel.calls)
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_failed_handle_information_does_not_treat_unknown_as_noninheritable(self):
        self.kernel.handle_information_result = 0
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_information_failed"):
            self.open()
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_duplicate_false_ignores_undefined_output_but_cleans_original_and_descriptor(self):
        self.kernel.duplicate_result = 0
        with self.assertRaisesRegex(native.NativeJobError, "native_job_duplicate_failed"):
            self.create()
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED)])
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])
        self.assertEqual(len(self.calls("DuplicateHandle")), 1)

    def test_duplicate_exception_retains_raw_output_and_never_adopts_or_closes_it(self):
        original = self.kernel.duplicate_exception = RuntimeError("fixture_duplicate_exception")
        with self.assertRaises(RuntimeError) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        owner, = original._native_job_cleanup
        self.assertEqual([value.value for value in owner._uncertain_outputs], [RETAINED])
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED)])
        self.assertEqual(len(self.calls("DuplicateHandle")), 1)
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)

    def test_independent_initialization_cleanup_preserves_primary_and_exact_retry(self):
        original = self.security.failure = RuntimeError("fixture_security_primary")
        self.security.fail_handle = RETAINED
        self.kernel.close_failures.update((CREATED, RETAINED))
        self.kernel.free_failure = True
        with self.assertRaises(RuntimeError) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        self.assertTrue(original.__notes__)
        self.assertEqual(self.calls("LocalFree"), [("LocalFree", DESCRIPTOR)])
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", CREATED), ("CloseHandle", RETAINED)])
        self.kernel.close_failures.clear()
        self.kernel.free_failure = False
        before = len(self.kernel.calls)
        native.retry_job_cleanup(original)
        self.assertEqual(self.kernel.calls[before:], [("LocalFree", DESCRIPTOR),
                                                     ("CloseHandle", CREATED), ("CloseHandle", RETAINED)])
        self.assertEqual(original._native_job_cleanup, ())
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_temporary_creation_close_failure_cannot_return_reduced_owner_as_success(self):
        self.kernel.close_failures.add(CREATED)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_close_failed") as failed:
            self.create()
        self.assertTrue(failed.exception._native_job_cleanup)
        self.assertIn(("CloseHandle", RETAINED), self.kernel.calls)
        self.kernel.close_failures.clear()
        before = len(self.kernel.calls)
        native.retry_job_cleanup(failed.exception)
        self.assertEqual(self.kernel.calls[before:], [("CloseHandle", CREATED)])
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)

    def test_descriptor_free_exception_is_quarantined_without_second_free(self):
        original = self.kernel.free_exception = RuntimeError("fixture_free_exception")
        with self.assertRaises(RuntimeError) as failed:
            self.create()
        self.assertIs(failed.exception, original)
        self.assertEqual(len(self.calls("LocalFree")), 1)
        self.assertIn(("CloseHandle", RETAINED), self.kernel.calls)
        self.kernel.free_exception = None
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(len(self.calls("LocalFree")), 1)
        self.assertEqual(len(self.calls("CreateJobObjectW")), 1)

    def test_queries_preserve_raw_flags_and_integer_accounting_in_frozen_records(self):
        job = self.open()
        self.kernel.cpu = (0xFFFFFFFF, 0xFFFFFFFE)
        self.kernel.limit_flags, self.kernel.ui_restrictions = 0x80000001, 7
        cpu, limits, accounting = job.query_cpu(), job.query_limits(), job.accounting()
        self.assertEqual(cpu, native.CpuState(0xFFFFFFFF, 0xFFFFFFFE))
        self.assertEqual(limits, native.JobLimits(0x80000001, 7))
        self.assertEqual(accounting, native.JobAccounting(2**53 + 1, 2**53 + 3, 2, 5, 3))
        self.assertEqual(accounting.cpu_100ns, 2**54 + 4)
        self.assertIs(type(accounting.cpu_100ns), int)
        for record, field in ((cpu, "flags"), (limits, "limit_flags"), (accounting, "user_100ns")):
            with self.assertRaises(FrozenInstanceError):
                setattr(record, field, 0)
        self.assertTrue(all(call[1] == RETAINED for call in self.calls("QueryInformationJobObject")))
        job.close()

    def test_negative_accounting_is_unknown_instead_of_wrapped_unsigned_usage(self):
        job = self.open()
        for index in range(4):
            values = [0, 0, 0, 0, 0, 1, 1, 0]
            values[index] = -1
            self.kernel.accounting = tuple(values)
            with self.subTest(index=index), self.assertRaisesRegex(native.NativeJobError, "native_job_accounting_invalid"):
                job.accounting()
        job.close()

    def test_query_failure_is_not_returned_as_zero_usage_or_disabled_control(self):
        job = self.open()
        for information_class, operation in ((15, job.query_cpu), (9, job.query_limits), (1, job.accounting)):
            self.kernel.query_failure = information_class
            with self.subTest(information_class=information_class), self.assertRaisesRegex(native.NativeJobError, "native_job_query_failed"):
                operation()
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        job.close()

    def test_membership_retries_more_data_then_returns_exact_complete_tuple(self):
        job = self.open()
        self.kernel.membership = [(0, 234, 200, 64, tuple(range(1, 65))),
                                  (1, 0, 3, 3, (61, 62, 63))]
        self.assertEqual(job.active_pids(), (61, 62, 63))
        queries = self.calls("QueryInformationJobObject")
        self.assertEqual([call[2] for call in queries], [3, 3])
        self.assertEqual([call[3] for call in queries],
                         [8 + C.sizeof(C.c_size_t) * 64, 8 + C.sizeof(C.c_size_t) * 200])
        job.close()

    def test_membership_empty_is_only_an_observation_and_does_not_close_job(self):
        job = self.open()
        self.kernel.membership = [(1, 0, 0, 0, ())]
        self.assertEqual(job.active_pids(), ())
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(self.calls("CloseHandle"), [])
        job.close()

    def test_incomplete_or_inconsistent_membership_never_becomes_empty(self):
        job = self.open()
        for assigned, listed in ((1, 0), (0, 1), (1, 65)):
            self.kernel.membership = [(1, 0, assigned, listed, (41,))] * 4
            before = len(self.calls("QueryInformationJobObject"))
            with self.subTest(assigned=assigned, listed=listed), self.assertRaisesRegex(native.NativeJobError, "native_job_membership_unstable"):
                job.active_pids()
            self.assertEqual(len(self.calls("QueryInformationJobObject")) - before, 4)
        job.close()

    def test_membership_growth_is_bounded_by_attempts_and_4096_entries(self):
        job = self.open()
        self.kernel.membership = [(0, 234, 65, 0, ())] * 4
        with self.assertRaisesRegex(native.NativeJobError, "native_job_membership_unstable"):
            job.active_pids()
        self.assertEqual(len(self.calls("QueryInformationJobObject")), 4)
        self.kernel.membership = [(0, 234, 4097, 0, ())]
        with self.assertRaisesRegex(native.NativeJobError, "native_job_membership_unstable"):
            job.active_pids()
        self.assertEqual(len(self.calls("QueryInformationJobObject")), 5)
        job.close()

    def test_membership_pid_validation_and_nonresize_failure_do_not_return_partial_data(self):
        job = self.open()
        cases = ((0,), (41, 41))
        if C.sizeof(C.c_size_t) == 8:
            cases += ((0x100000000,),)
        for pids in cases:
            self.kernel.membership = [(1, 0, len(pids), len(pids), pids)]
            with self.subTest(pids=pids), self.assertRaisesRegex(native.NativeJobError, "native_job_membership_invalid"):
                job.active_pids()
        self.kernel.membership = [(0, 5, 0, 0, ())]
        before = len(self.calls("QueryInformationJobObject"))
        with self.assertRaisesRegex(native.NativeJobError, "native_job_membership_failed") as failed:
            job.active_pids()
        self.assertEqual(failed.exception.win32_error, 5)
        self.assertEqual(len(self.calls("QueryInformationJobObject")) - before, 1)
        job.close()

    def test_query_and_launch_rights_never_issue_control_writes(self):
        for access in (native.JobAccess.QUERY, native.JobAccess.LAUNCH):
            job = self.open(access=access)
            for operation in (lambda: job.set_cpu_rate(5000),
                              lambda: job.set_cpu_rate_unverified(5000), job.disable):
                with self.subTest(access=access), self.assertRaisesRegex(native.NativeJobError, "native_job_control_access_required"):
                    operation()
            job.close()
        self.assertEqual(self.calls("SetInformationJobObject"), [])

    def test_invalid_cpu_rates_never_issue_set(self):
        job = self.open(access=native.JobAccess.CONTROL)
        for rate in (True, 0, -1, 10001, 1.0, "5000", None):
            for operation in (job.set_cpu_rate, job.set_cpu_rate_unverified):
                with self.subTest(rate=rate), self.assertRaises(ValueError):
                    operation(rate)
        self.assertEqual(self.calls("SetInformationJobObject"), [])
        job.close()

    def test_control_uses_one_cpu_set_then_readback_and_close_does_not_restore(self):
        for access in (native.JobAccess.CONTROL, native.JobAccess.OWNER):
            job = self.open(access=access)
            before = len(self.kernel.calls)
            self.assertEqual(job.set_cpu_rate(4500), native.CpuState(5, 4500))
            self.assertEqual(self.kernel.calls[before:], [
                ("SetInformationJobObject", RETAINED, 15, 5, 4500, 8),
                ("QueryInformationJobObject", RETAINED, 15, 8)])
            job.close()
            self.assertEqual(self.kernel.cpu, (5, 4500))
        self.assertEqual(len(self.calls("SetInformationJobObject")), 2)

    def test_unverified_set_does_not_query_or_claim_readback(self):
        job = self.open(access=native.JobAccess.CONTROL)
        self.assertIsNone(job.set_cpu_rate_unverified(5000))
        self.assertEqual(self.calls("QueryInformationJobObject"), [])
        self.assertEqual(self.calls("SetInformationJobObject"), [
            ("SetInformationJobObject", RETAINED, 15, 5, 5000, 8)])
        job.close()

    def test_disable_writes_disabled_flags_and_accepts_unused_union_value(self):
        job = self.open(access=native.JobAccess.CONTROL)
        self.kernel.cpu = (5, 4000)
        self.kernel.disabled_union = 123
        self.assertEqual(job.disable(), native.CpuState(0, 123))
        self.assertEqual(self.calls("SetInformationJobObject"), [
            ("SetInformationJobObject", RETAINED, 15, 0, 10000, 8)])
        job.close()

    def test_set_readback_mismatch_retains_live_owner_without_restore_or_retry(self):
        job = self.open(access=native.JobAccess.CONTROL)
        self.kernel.apply_set = False
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cpu_set_readback_mismatch") as failed:
            job.set_cpu_rate(3000)
        self.assert_retained(failed.exception, job)
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(self.calls("CloseHandle"), [])
        self.assertEqual(len(self.calls("SetInformationJobObject")), 1)
        self.assertEqual(job.query_cpu(), native.CpuState(0, 10000))
        native.retry_job_cleanup(failed.exception)
        self.assertEqual(len(self.calls("SetInformationJobObject")), 1)

    def test_disable_readback_mismatch_keeps_control_intent_and_owner(self):
        job = self.open(access=native.JobAccess.CONTROL)
        self.kernel.cpu, self.kernel.apply_set = (5, 3000), False
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cpu_disable_readback_mismatch") as failed:
            job.disable()
        self.assert_retained(failed.exception, job)
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(len(self.calls("SetInformationJobObject")), 1)
        self.assertEqual(self.calls("CloseHandle"), [])
        job.close()

    def test_failed_or_interrupted_set_never_assumes_the_limit_was_not_applied(self):
        job = self.open(access=native.JobAccess.CONTROL)
        self.kernel.set_result = 0
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cpu_set_failed") as failed:
            job.set_cpu_rate(2000)
        self.assert_retained(failed.exception, job)
        self.assertEqual(self.kernel.cpu, (5, 2000))
        self.assertEqual(self.calls("QueryInformationJobObject"), [])
        original = self.kernel.set_exception = KeyboardInterrupt("fixture_set_interruption")
        with self.assertRaises(KeyboardInterrupt) as interrupted:
            job.set_cpu_rate(4000)
        self.assertIs(interrupted.exception, original)
        self.assert_retained(original, job)
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(self.calls("CloseHandle"), [])
        self.assertEqual(len(self.calls("SetInformationJobObject")), 2)
        job.close()

    def test_post_set_query_failure_preserves_error_and_owner(self):
        job = self.open(access=native.JobAccess.CONTROL)
        original = self.kernel.query_exception = RuntimeError("fixture_readback_exception")
        with self.assertRaises(RuntimeError) as failed:
            job.set_cpu_rate(6000)
        self.assertIs(failed.exception, original)
        self.assert_retained(original, job)
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(self.kernel.cpu, (5, 6000))
        self.assertEqual(len(self.calls("SetInformationJobObject")), 1)
        job.close()

    def test_known_close_false_retains_handle_for_cleanup_only_then_is_idempotent(self):
        job = self.open()
        self.kernel.close_failures.add(RETAINED)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_close_failed") as failed:
            job.close()
        self.assert_retained(failed.exception, job)
        before = len(self.kernel.calls)
        for operation in (job.query_cpu, job.query_limits, job.accounting, job.active_pids):
            with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
                operation()
        self.assertEqual(len(self.kernel.calls), before)
        self.kernel.close_failures.clear()
        native.retry_job_cleanup(failed.exception)
        before = len(self.kernel.calls)
        job.close()
        self.assertEqual(len(self.kernel.calls), before)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)] * 2)

    def test_close_exception_quarantines_handle_and_does_not_reclose_or_query(self):
        job = self.open()
        original = self.kernel.close_exceptions[RETAINED] = RuntimeError("fixture_close_exception")
        with self.assertRaises(RuntimeError) as failed:
            job.close()
        self.assertIs(failed.exception, original)
        self.assert_retained(original, job)
        self.kernel.close_exceptions.clear()
        before = len(self.kernel.calls)
        for operation in (job.query_cpu, job.query_limits, job.accounting, job.active_pids):
            with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
                operation()
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(len(self.kernel.calls), before)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])

    def test_interruption_after_native_close_success_never_retries_numeric_handle(self):
        job = self.open()
        original = KeyboardInterrupt("fixture_after_close_before_return")
        real_close = self.backend.close

        def interrupted(handle):
            real_close(handle)
            raise original

        with patch.object(self.backend, "close", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as failed:
                job.close()
        self.assertIs(failed.exception, original)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])

    def test_successful_close_tombstone_rejects_queries_even_before_ready_is_cleared(self):
        job = self.open()
        job._release(job._job)
        before = len(self.kernel.calls)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
            job.query_cpu()
        job.close()
        job.close()
        self.assertEqual(len(self.kernel.calls), before)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])

    def test_adapter_create_keeps_s1_gates_and_explicit_owner_role(self):
        from tests.windows import adaptive_win32 as adapter

        production = self.open(name=TEST_NAME, access=native.JobAccess.OWNER)
        with patch.object(adapter, "_opt_in") as opt_in, \
                patch.object(adapter, "require_supported_host") as host_gate, \
                patch.object(adapter, "_logon_sid", return_value=LOGON), \
                patch.object(native.NativeJob, "create", return_value=production) as create:
            job = adapter.OwnedJob.create(NONCE)
        opt_in.assert_called_once_with()
        host_gate.assert_called_once_with()
        create.assert_called_once_with(TEST_NAME, NONCE, LOGON, access=native.JobAccess.OWNER)
        self.assertEqual(job.handle, RETAINED)
        self.assertEqual(job.security["access_mask"], 0x1F003F)
        job.close()
        self.assertTrue(job.closed)
        self.assertIsNone(job.handle)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
            _ = production.handle

    def test_adapter_create_gate_failure_prevents_native_create(self):
        from tests.windows import adaptive_win32 as adapter

        original = RuntimeError("fixture_host_unsupported")
        with patch.object(adapter, "_opt_in"), \
                patch.object(adapter, "require_supported_host", side_effect=original), \
                patch.object(native.NativeJob, "create") as create:
            with self.assertRaises(RuntimeError) as failed:
                adapter.OwnedJob.create(NONCE)
        self.assertIs(failed.exception, original)
        create.assert_not_called()
        self.assertEqual(self.kernel.calls, [])

    def test_adapter_open_delegates_exact_name_and_converts_records_for_existing_consumers(self):
        from tests.windows import adaptive_win32 as adapter

        production = self.open(name=TEST_NAME, access=native.JobAccess.OWNER)
        self.kernel.accounting = (10_000_001, 20_000_003, 0, 0, 0, 5, 2, 3)
        with patch.object(adapter, "_logon_sid", return_value=LOGON), \
                patch.object(native.NativeJob, "open", return_value=production) as open_job:
            job = adapter.OwnedJob.open(TEST_NAME, NONCE)
        open_job.assert_called_once_with(TEST_NAME, NONCE, LOGON, access=native.JobAccess.OWNER)
        self.assertEqual(job.query_cpu(), {"flags": 0, "rate_bp": 10000})
        self.assertEqual(job.query_limits(), {"limit_flags": 0, "ui_restrictions": 0})
        self.assertEqual(job.accounting(), {"cpu_seconds": 3.0000004, "active_processes": 2, "total_processes": 5})
        self.assertEqual(job.active_pids(), [41, 42])
        with patch.object(adapter, "_opt_in") as opt_in:
            self.assertEqual(job.set_cpu_rate(3000), {"flags": 5, "rate_bp": 3000})
            self.assertIsNone(job.set_cpu_rate_unverified(4000))
            self.assertEqual(job.disable(), {"flags": 0, "rate_bp": 10000})
        self.assertEqual(opt_in.call_count, 3)
        job.close()

    def test_adapter_unknown_close_does_not_report_none_or_closed(self):
        from tests.windows import adaptive_win32 as adapter

        job = adapter.OwnedJob(self.open(name=TEST_NAME))
        self.kernel.close_exceptions[RETAINED] = RuntimeError("fixture_close_exception")
        with self.assertRaises(RuntimeError):
            job.close()
        self.assertFalse(job.closed)
        with self.assertRaisesRegex(native.NativeJobError, "native_job_handle_unavailable"):
            _ = job.handle
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])

    def test_actual_s1_cleanup_persists_failure_when_native_close_outcome_is_unknown(self):
        from tests.windows import adaptive_win32 as adapter
        from tests.windows import test_adaptive_job_capability as s1

        job = adapter.OwnedJob(self.open(name=TEST_NAME))
        self.kernel.accounting = (0, 0, 0, 0, 0, 0, 0, 0)
        self.kernel.membership = [(1, 0, 0, 0, ())] * 2
        original = RuntimeError("fixture_close_outcome_unknown")
        self.kernel.close_exceptions[RETAINED] = original
        owner = SimpleNamespace(job=job, restore=Mock(), finalize=Mock(return_value={"state": "FINISHED"}),
                                close=Mock(side_effect=job.close), _retain=Mock())
        case = s1.WindowsJobCapabilitySpike("test_00_fixture_self_stops_and_job_has_no_other_limits")
        record = {"status": "pass"}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(AssertionError, "owner handle close failed"):
                case._cleanup(owner, job, None, directory, record, s1.time.monotonic() + 120)
            saved = json.loads((directory / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "cleanup_failed")
            self.assertFalse(saved["handles_closed"])
            self.assertTrue(saved["job_empty_verified"])
            self.assertEqual(saved["lifecycle_terminal"], "FINISHED")
            self.assertTrue(any("owner handle close failed" in message for message in saved["cleanup_errors"]))
            self.assertTrue((directory / "stop").exists())
        owner.restore.assert_called_once_with()
        owner.finalize.assert_called_once_with()
        owner.close.assert_called_once_with()
        owner._retain.assert_called_once_with()
        self.assertFalse(job.closed)
        self.kernel.close_exceptions.clear()
        with self.assertRaisesRegex(native.NativeJobError, "native_job_cleanup_outcome_unknown"):
            native.retry_job_cleanup(original)
        self.assertEqual(self.calls("CloseHandle"), [("CloseHandle", RETAINED)])
        self.assertEqual(self.calls("SetInformationJobObject"), [])


@unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8, "requires 64-bit Windows")
class NativeJobBindingSmoke(unittest.TestCase):
    def native_bindings(self):
        """Explicit selection only: DLL loading and ABI checks, no native query."""
        backend = native._WindowsBackend()
        for structure, size in ((native._SecurityAttributes, 24), (native._CpuInfo, 8),
                                (native._BasicAccounting, 48), (native._BasicLimits, 64),
                                (native._IoCounters, 48), (native._ExtendedLimits, 144)):
            self.assertEqual(C.sizeof(structure), size)
        self.assertEqual(native._SecurityAttributes.descriptor.offset, 8)
        self.assertEqual(native._SecurityAttributes.inherit.offset, 16)
        self.assertEqual(native._BasicAccounting.ActiveProcesses.offset, 40)
        self.assertEqual(native._BasicAccounting.TotalTerminatedProcesses.offset, 44)
        self.assertEqual(native._BasicLimits.LimitFlags.offset, 16)
        self.assertEqual(native._BasicLimits.Affinity.offset, 48)
        self.assertEqual(native._ExtendedLimits.IoInfo.offset, 64)
        self.assertEqual(native._ExtendedLimits.PeakJobMemoryUsed.offset, 136)
        self.assertIs(backend.kernel.CreateJobObjectW.argtypes[0]._type_, native._SecurityAttributes)
        self.assertIs(backend.kernel.DuplicateHandle.argtypes[3]._type_, native._HANDLE)
        self.assertIs(backend.kernel.GetHandleInformation.argtypes[-1]._type_, native._DWORD)
        self.assertIs(backend.kernel.QueryInformationJobObject.argtypes[-1]._type_, native._DWORD)
        self.assertIs(backend.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes[2]._type_, C.c_void_p)

    def native_empty_job_smoke(self):
        """Explicit native empty-Job evidence; never a supported-host/P1 pass.

        One random test name, held continuously until both handles are closed.
        Create's exact-handle duplicate requests LAUNCH; the same held name is
        reopened QUERY. No Set, process launch, assignment, parent-Job probe or
        production directory is involved. Permission masks are asserted in the
        portable fixture; this smoke does not probe denial via a native Set.
        """
        from tests.windows import adaptive_win32 as adapter

        nonce = uuid.uuid4().hex
        name = "Local\\ResourceSentinel.Test.Job." + nonce
        logon = adapter._logon_sid()
        owners, primary = [], None
        try:
            created = native.NativeJob.create(name, nonce, logon)
            owners.append(created)
            _NATIVE_SMOKE_CUSTODY.append(created)
            self.assertEqual(created.access, native.JobAccess.LAUNCH)
            self.assertEqual((created.name, created.nonce, created.logon_sid), (name, nonce, logon))
            self.assertEqual(created.query_cpu().flags, 0)
            self.assertEqual(created.query_limits(), native.JobLimits(0, 0))
            self.assertEqual(created.accounting().active_processes, 0)
            self.assertEqual(created.active_pids(), ())
            # The original stays held across Open; a newly created object cannot
            # replace this name while that exact original object is retained.
            opened = native.NativeJob.open(name, nonce, logon)
            owners.append(opened)
            _NATIVE_SMOKE_CUSTODY.append(opened)
            self.assertEqual(opened.access, native.JobAccess.QUERY)
            self.assertEqual(opened.query_cpu().flags, 0)
            self.assertEqual(opened.query_limits(), native.JobLimits(0, 0))
            self.assertEqual(opened.accounting().active_processes, 0)
            self.assertEqual(opened.active_pids(), ())
            for owner in owners:
                self.assertGreater(owner.handle, 0)
                self.assertFalse(owner.closed)
                flags = native._DWORD()
                native._check(owner._backend.kernel.GetHandleInformation(owner.handle, C.byref(flags)),
                              "native_empty_job_handle_information_failed")
                self.assertEqual(flags.value & 1, 0)
        except BaseException as error:
            primary = error
            _NATIVE_SMOKE_FAILURES.append(error)
            for owner in getattr(error, "_native_job_cleanup", ()):
                if owner not in _NATIVE_SMOKE_CUSTODY:
                    _NATIVE_SMOKE_CUSTODY.append(owner)
            raise
        finally:
            cleanup_errors = []
            for owner in reversed(owners):
                try:
                    owner.close()
                    if not owner.closed:
                        raise AssertionError("native empty Job cleanup did not complete")
                    _NATIVE_SMOKE_CUSTODY.remove(owner)
                except BaseException as error:
                    cleanup_errors.append(error)
                    _NATIVE_SMOKE_FAILURES.append(error)
            if cleanup_errors:
                if primary is not None:
                    primary.add_note("native_empty_job_cleanup_unverified")
                else:
                    raise cleanup_errors[0]


if __name__ == "__main__":
    unittest.main()
