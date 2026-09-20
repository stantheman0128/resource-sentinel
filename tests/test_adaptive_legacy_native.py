"""Portable native-adapter contracts, with explicit in-process API fakes only.

No Windows process, Job, runtime DB, mutation or native capability probe runs.
The real VerifiedProcess duplicate/identity/cleanup logic consumes fake handles.
"""
from dataclasses import replace
import ctypes as C
import unittest
from unittest.mock import patch

from sentinel.adaptive import legacy_native as native
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable


IDENTITY = ProcessIdentity(501, 134342315823996135, "S-1-5-5-100-200")
JOB_NAME = "Local\\ResourceSentinel.Job.12345678-1234-4234-8234-123456789abc." + "a" * 32


class IdentityBackend:
    def __init__(self):
        self.value = IDENTITY
        self.state = IdentityStatus.ALIVE
        self.failure = None
        self.calls = []
        self.close_failures = set()

    def open_process(self, pid):
        raise AssertionError("legacy identity must duplicate, never reopen PID")

    def duplicate_process(self, source):
        self.calls.append(("duplicate", source))
        if self.failure == "duplicate":
            raise IdentityUnavailable("fixture_duplicate_failed")
        return 800

    def identity(self, handle):
        self.calls.append(("identity", handle))
        if self.failure == "identity":
            raise IdentityUnavailable("fixture_identity_failed")
        return self.value

    def wait(self, handle):
        self.calls.append(("wait", handle))
        if self.failure == "wait":
            raise IdentityUnavailable("fixture_wait_failed")
        if self.state is IdentityStatus.UNKNOWN:
            # The native wait contract returns only ALIVE/DEAD. Uncertainty
            # raises with a reason; VerifiedProcess builds the UNKNOWN record.
            raise IdentityUnavailable("fixture_wait_unknown")
        return self.state

    def close(self, handle):
        self.calls.append(("close", handle))
        if handle in self.close_failures:
            raise IdentityUnavailable("fixture_identity_close_failed")


class MutationBackend:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.close_failures = set()
        self.member = False
        self.priority_value = 0x20
        self.ignore_priority_set = False
        self.after_membership = None

    def checked(self, operation, *args):
        self.calls.append((operation, *args))
        if self.failure == operation:
            raise native.NativeLegacyError("fixture_" + operation + "_failed", 5)

    def open_process(self, pid, access):
        self.checked("open_process", pid, access)
        return 700

    def open_job(self, name, logon_id):
        self.checked("open_job", name, logon_id)
        return 900

    def verify_job(self, handle, logon_id):
        self.checked("verify_job", handle, logon_id)

    def membership(self, handle, job):
        self.checked("membership", handle, job)
        if self.after_membership is not None:
            self.after_membership()
        return self.member

    def priority(self, handle):
        self.checked("priority", handle)
        return self.priority_value

    def set_priority(self, handle, value):
        self.checked("set_priority", handle, value)
        if not self.ignore_priority_set:
            self.priority_value = value

    def set_io_priority(self, handle, level):
        self.checked("set_io_priority", handle, level)

    def trim(self, handle):
        self.checked("trim", handle)

    def close(self, handle):
        self.calls.append(("close", handle))
        if handle in self.close_failures:
            raise native.NativeLegacyError("fixture_mutation_close_failed", 6)


class NativeLegacyTests(unittest.TestCase):
    def setUp(self):
        self.identity = IdentityBackend()
        self.mutation = MutationBackend()
        for override in (
                patch("sentinel.adaptive.identity._backend", return_value=self.identity),
                patch.object(native, "_backend", return_value=self.mutation)):
            override.start()
            self.addCleanup(override.stop)

    def writes(self):
        return [call for call in self.mutation.calls if call[0] in {"set_priority", "set_io_priority", "trim"}]

    def test_retained_mutation_handle_is_duplicated_once_and_reused_for_all_native_calls(self):
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            self.assertEqual(process.identity, IDENTITY)
            self.assertTrue(process.alive())
            self.assertFalse(process.is_in_job(None))
            self.assertEqual(process.priority(), "Normal")
            process.set_priority("BelowNormal")
            process.set_io_priority(1)
            process.trim()
        self.assertEqual([call for call in self.identity.calls if call[0] == "duplicate"], [("duplicate", 700)])
        self.assertEqual([call for call in self.mutation.calls if call[0] == "open_process"],
                         [("open_process", IDENTITY.pid, 0x00101300)])
        self.assertIn(("membership", 700, None), self.mutation.calls)
        self.assertEqual(self.writes(), [("set_priority", 700, 0x4000), ("set_io_priority", 700, 1), ("trim", 700)])
        self.assertIn(("close", 800), self.identity.calls)
        self.assertIn(("close", 700), self.mutation.calls)

    def test_requested_operations_determine_only_necessary_rights(self):
        for operations, rights in (((), 0x00101000), (("priority",), 0x00101200),
                                  (("io_priority",), 0x00101200), (("trim",), 0x00101100)):
            with self.subTest(operations=operations):
                with native.NativeLegacyProcess.open(IDENTITY, operations=operations):
                    pass
                self.assertIn(("open_process", IDENTITY.pid, rights), self.mutation.calls)

    def test_same_pid_one_filetime_tick_or_logon_mismatch_never_returns_writer(self):
        for observed in (replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1),
                         replace(IDENTITY, pid=502), replace(IDENTITY, logon_id="S-1-5-5-100-201")):
            with self.subTest(observed=observed):
                self.identity.value = observed
                with self.assertRaises((native.NativeLegacyError, IdentityUnavailable)):
                    native.NativeLegacyProcess.open(IDENTITY)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.mutation.calls.count(("close", 700)), 3)
        self.assertEqual(self.identity.calls.count(("close", 800)), 3)

    def test_open_and_identity_failure_do_not_fallback_to_pid_or_unverified_writer(self):
        self.mutation.failure = "open_process"
        with self.assertRaises(native.NativeLegacyError):
            native.NativeLegacyProcess.open(IDENTITY)
        self.assertEqual(self.identity.calls, [])
        self.mutation.failure = None
        self.identity.failure = "identity"
        with self.assertRaises(IdentityUnavailable):
            native.NativeLegacyProcess.open(IDENTITY)
        self.assertIn(("close", 700), self.mutation.calls)
        self.assertIn(("close", 800), self.identity.calls)
        self.assertEqual(self.writes(), [])

    def test_dead_or_unknown_target_is_not_opened_for_mutation(self):
        for state in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            with self.subTest(state=state):
                self.identity.state = state
                reason = "legacy_process_exited" if state is IdentityStatus.DEAD else "legacy_identity_unavailable"
                with self.assertRaisesRegex(native.NativeLegacyError, reason):
                    native.NativeLegacyProcess.open(IDENTITY)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.mutation.calls.count(("close", 700)), 2)
        self.assertEqual(self.identity.calls.count(("close", 800)), 2)

    def test_death_wait_failure_and_closed_handle_never_write_or_report_false_membership(self):
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            self.identity.state = IdentityStatus.DEAD
            self.assertFalse(process.alive())
            self.assertIsNone(process.is_in_job(None))
            self.identity.state = IdentityStatus.ALIVE
            self.identity.failure = "wait"
            self.assertIsNone(process.alive())
            self.assertIsNone(process.is_in_job(None))
            for operation in (lambda: process.set_priority("Normal"), lambda: process.set_io_priority(2), process.trim):
                with self.assertRaises(native.NativeLegacyError):
                    operation()
        self.assertIsNone(process.alive())
        self.assertEqual(self.writes(), [])

    def test_registered_job_is_verified_and_retained_through_membership(self):
        with native.NativeLegacyJob.open(JOB_NAME, IDENTITY.logon_id) as job, \
                native.NativeLegacyProcess.open(IDENTITY) as process:
            self.mutation.member = True
            self.assertTrue(process.is_in_job(job))
            self.assertIn(("verify_job", 900, IDENTITY.logon_id), self.mutation.calls)
            self.assertIn(("membership", 700, 900), self.mutation.calls)
            job.close()
            count = self.mutation.calls.count(("membership", 700, 900))
            self.assertIsNone(process.is_in_job(job))
            self.assertEqual(self.mutation.calls.count(("membership", 700, 900)), count)
        self.assertEqual(self.mutation.calls.count(("close", 900)), 1)

    def test_job_acl_failure_closes_handle_and_does_not_produce_membership_authority(self):
        self.mutation.failure = "verify_job"
        with self.assertRaisesRegex(native.NativeLegacyError, "fixture_verify_job_failed"):
            native.NativeLegacyJob.open(JOB_NAME, IDENTITY.logon_id)
        self.assertIn(("close", 900), self.mutation.calls)
        self.assertFalse(any(call[0] == "membership" for call in self.mutation.calls))

    def test_job_name_logon_and_raw_handle_inputs_are_rejected(self):
        for name in ("arbitrary", JOB_NAME.replace("Local\\", "Global\\"), JOB_NAME + "\\extra"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                native.NativeLegacyJob.open(name, IDENTITY.logon_id)
        for logon in ("S-1-5-18", "fixture-logon", "S-1-5-5-4294967296-1"):
            with self.subTest(logon=logon), self.assertRaises(ValueError):
                native.NativeLegacyJob.open(JOB_NAME, logon)
            with self.subTest(process_logon=logon), self.assertRaises(ValueError):
                native.NativeLegacyProcess.open(replace(IDENTITY, logon_id=logon))
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            with self.assertRaises(TypeError):
                process.is_in_job(900)
        self.assertFalse(any(call[0] == "open_job" for call in self.mutation.calls))

    def test_membership_failure_or_exit_during_query_is_unknown(self):
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            self.mutation.failure = "membership"
            self.assertIsNone(process.is_in_job(None))
            self.mutation.failure = None
            self.mutation.after_membership = lambda: setattr(self.identity, "state", IdentityStatus.DEAD)
            self.assertIsNone(process.is_in_job(None))

    def test_no_default_normal_for_unknown_priority_or_failed_readback(self):
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            self.mutation.priority_value = 0xDEAD
            with self.assertRaisesRegex(native.NativeLegacyError, "legacy_priority_unknown"):
                process.priority()
            self.assertEqual(self.writes(), [])
            self.mutation.priority_value = 0x20
            self.mutation.ignore_priority_set = True
            with self.assertRaisesRegex(native.NativeLegacyError, "legacy_priority_readback_mismatch"):
                process.set_priority("BelowNormal")
            self.assertEqual(self.writes(), [("set_priority", 700, 0x4000)])

    def test_operation_rights_and_parameter_errors_never_write(self):
        with native.NativeLegacyProcess.open(IDENTITY, operations=()) as process:
            for operation in (lambda: process.set_priority("Normal"), lambda: process.set_io_priority(1), process.trim):
                with self.assertRaises(native.NativeLegacyError):
                    operation()
            for operation in (lambda: process.set_priority("default"), lambda: process.set_io_priority(True),
                              lambda: process.set_io_priority(0), lambda: process.set_io_priority(3)):
                with self.assertRaises(ValueError):
                    operation()
        self.assertEqual(self.writes(), [])

    def test_native_write_failure_is_not_retried_or_reported_as_success(self):
        with native.NativeLegacyProcess.open(IDENTITY) as process:
            for name, operation in (("set_priority", lambda: process.set_priority("Normal")),
                                    ("set_io_priority", lambda: process.set_io_priority(1)), ("trim", process.trim)):
                with self.subTest(name=name):
                    self.mutation.failure = name
                    with self.assertRaises(native.NativeLegacyError):
                        operation()
        self.assertEqual(len(self.writes()), 3)

    def test_both_process_handles_are_attempted_and_failed_cleanup_is_retryable(self):
        process = native.NativeLegacyProcess.open(IDENTITY)
        self.identity.close_failures.add(800)
        self.mutation.close_failures.add(700)
        with self.assertRaises(IdentityUnavailable) as failed:
            process.close()
        self.assertIn(("close", 700), self.mutation.calls)
        self.assertIsNone(process.alive())
        with self.assertRaises(native.NativeLegacyError):
            process.trim()
        self.identity.close_failures.clear()
        self.mutation.close_failures.clear()
        native.retry_legacy_cleanup(failed.exception)
        attempts = len(self.mutation.calls)
        process.close()
        self.assertEqual(len(self.mutation.calls), attempts)

    def test_context_cleanup_preserves_original_error_and_retains_failed_owner(self):
        original = RuntimeError("fixture_primary")
        with self.assertRaises(RuntimeError) as failed:
            with native.NativeLegacyProcess.open(IDENTITY):
                self.mutation.close_failures.add(700)
                raise original
        self.assertIs(failed.exception, original)
        self.assertTrue(getattr(original, "_legacy_native_cleanup", ()))
        self.mutation.close_failures.clear()
        native.retry_legacy_cleanup(original)
        self.assertEqual(self.writes(), [])

    def test_duplicate_initialization_cleanup_failure_is_retained_with_source_cleanup(self):
        self.identity.failure = "identity"
        self.identity.close_failures.add(800)
        with self.assertRaises(IdentityUnavailable) as failed:
            native.NativeLegacyProcess.open(IDENTITY)
        self.assertIn(("close", 700), self.mutation.calls)
        self.assertTrue(getattr(failed.exception, "_identity_handle_cleanup", ()))
        self.identity.close_failures.clear()
        native.retry_legacy_cleanup(failed.exception)

    def test_job_initialization_and_context_cleanup_retain_the_original_failure(self):
        self.mutation.failure = "verify_job"
        self.mutation.close_failures.add(900)
        with self.assertRaisesRegex(native.NativeLegacyError, "fixture_verify_job_failed") as failed:
            native.NativeLegacyJob.open(JOB_NAME, IDENTITY.logon_id)
        self.mutation.close_failures.clear()
        native.retry_legacy_cleanup(failed.exception)
        self.mutation.failure = None
        original = RuntimeError("fixture_job_body")
        with self.assertRaises(RuntimeError) as failed:
            with native.NativeLegacyJob.open(JOB_NAME, IDENTITY.logon_id):
                self.mutation.close_failures.add(900)
                raise original
        self.assertIs(failed.exception, original)
        self.mutation.close_failures.clear()
        native.retry_legacy_cleanup(original)


class NativeLegacyAbiTests(unittest.TestCase):
    def test_io_status_uses_signed_32_bit_nt_success_without_last_error_or_retry(self):
        for status in (0, 0x40000000, 0x80000005, 0xC0000022, -1073741790):
            with self.subTest(status=status):
                backend = native._WindowsBackend.__new__(native._WindowsBackend)
                calls = []

                def setter(handle, info_class, information, size):
                    calls.append((handle, info_class, C.cast(information, C.POINTER(C.c_uint32)).contents.value, size))
                    return status

                backend._nt_set = setter
                if C.c_int32(status).value >= 0:
                    backend.set_io_priority(700, 2)
                else:
                    with self.assertRaises(native.NativeLegacyError) as failed:
                        backend.set_io_priority(700, 2)
                    self.assertEqual(failed.exception.ntstatus, status & 0xFFFFFFFF)
                    self.assertIsNone(failed.exception.win32_error)
                self.assertEqual(calls, [(700, 33, 2, 4)])

    def test_job_open_requests_query_and_read_control_only_without_inheritance(self):
        class Kernel:
            def OpenJobObjectW(self, access, inherited, name):
                self.arguments = access, inherited, name
                return 900

        backend = native._WindowsBackend.__new__(native._WindowsBackend)
        backend.kernel = Kernel()
        self.assertEqual(backend.open_job(JOB_NAME, IDENTITY.logon_id), 900)
        self.assertEqual(backend.kernel.arguments, (0x20004, False, JOB_NAME))

    def test_security_readback_requires_exact_existing_descriptor_mask(self):
        class Security:
            def current_owner_sid(self):
                return "S-1-5-21-1-2-3-1000"

            def verify_security(self, *args, **kwargs):
                self.arguments = args, kwargs

        security = Security()
        backend = native._WindowsBackend.__new__(native._WindowsBackend)
        with patch.object(native._security, "_backend", return_value=security):
            backend.verify_job(900, IDENTITY.logon_id)
        self.assertEqual(security.arguments, ((900, IDENTITY.logon_id, "S-1-5-21-1-2-3-1000"),
                                             {"access_mask": 0x1F003F}))


if __name__ == "__main__":
    unittest.main()
