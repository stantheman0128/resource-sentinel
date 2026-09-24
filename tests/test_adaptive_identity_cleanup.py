"""Portable CloseHandle outcome/custody regressions; no native operations.

The actual identity backend close method consumes an explicit fake kernel. The
fixture can model a handle being freed before Python loses the result, so retry
must not touch the reused number. These cases establish no Windows capability.
"""
import unittest
from unittest.mock import patch

from sentinel.adaptive import identity as identities
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import (
    IdentityUnavailable, VerifiedProcess, retry_identity_cleanup,
)


IDENTITY = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class KernelFixture:
    def __init__(self):
        self.calls = []
        self.outcome = 1

    def CloseHandle(self, handle):
        self.calls.append(handle)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class BackendFixture(identities._WindowsBackend):
    """Use only the real close method, never its native-loading constructor."""
    def __init__(self):
        self.kernel = KernelFixture()
        self.queries = []
        self.opened = []
        self.duplicated = []
        self.identity_error = None

    def open_process(self, pid):
        self.opened.append(pid)
        return 700

    def duplicate_process(self, source):
        self.duplicated.append(source)
        return 900

    def duplicate_into(self, source, output, *, source_process=None):
        if source_process is not None:
            raise AssertionError("cleanup fixture only duplicates local handles")
        self.duplicated.append(source)
        output.value = 900

    def identity(self, handle):
        self.queries.append(("identity", handle))
        if self.identity_error is not None:
            raise self.identity_error
        return IDENTITY

    def wait(self, handle):
        self.queries.append(("wait", handle))
        return IdentityStatus.ALIVE

    def membership(self, handle, job):
        self.queries.append(("membership", handle, job))
        return True


class IdentityCleanupTests(unittest.TestCase):
    def setUp(self):
        self.backend = BackendFixture()
        for override in (
            patch.object(identities, "_backend", return_value=self.backend),
            patch.object(identities.C, "get_last_error", return_value=6, create=True),
        ):
            override.start()
            self.addCleanup(override.stop)

    def duplicate(self):
        return VerifiedProcess.duplicate_from_handle(
            800, expected_pid=IDENTITY.pid, expected_logon_id=IDENTITY.logon_id)

    def assert_quarantined(self, process, failure, handle):
        self.assertTrue(failure._native_close_outcome_unknown)
        self.assertIn(process, failure._identity_handle_cleanup)
        self.backend.kernel.outcome = 1  # This number may now be a different object.
        before = tuple(self.backend.queries)
        observation = process.observe()
        self.assertEqual(observation.status, IdentityStatus.UNKNOWN)
        self.assertEqual(observation.reason, "process_handle_close_outcome_unknown")
        self.assertIsNone(process.is_in_job(None))
        self.assertIsNone(process.is_in_job(880))
        with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown") as entered:
            process.__enter__()
        self.assertTrue(entered.exception._native_close_outcome_unknown)
        self.assertIn(process, entered.exception._identity_handle_cleanup)
        for attempt in (process.close, lambda: retry_identity_cleanup(failure)):
            with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown") as raised:
                attempt()
            self.assertTrue(raised.exception._native_close_outcome_unknown)
        self.assertEqual(self.backend.kernel.calls, [handle])
        self.assertEqual(tuple(self.backend.queries), before)
        self.assertIn(process, failure._identity_handle_cleanup)

    def test_success_retires_once_and_never_queries_the_closed_handle(self):
        process = VerifiedProcess.open(IDENTITY)
        process.close()
        process.close()
        before = tuple(self.backend.queries)
        self.assertEqual(process.observe().status, IdentityStatus.UNKNOWN)
        self.assertIsNone(process.is_in_job(880))
        self.assertEqual(tuple(self.backend.queries), before)
        self.assertEqual(self.backend.kernel.calls, [700])

    def test_actual_false_result_retains_live_handle_and_allows_exact_retry(self):
        process = VerifiedProcess.open(IDENTITY)
        self.backend.kernel.outcome = 0
        with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_failed") as raised:
            process.close()
        failure = raised.exception
        self.assertTrue(failure._native_close_failed)
        self.assertFalse(failure._native_close_outcome_unknown)
        self.assertEqual(process.observe().status, IdentityStatus.ALIVE)
        self.assertTrue(process.is_in_job(880))
        self.backend.kernel.outcome = 1
        retry_identity_cleanup(failure)
        retry_identity_cleanup(failure)
        process.close()
        self.assertEqual(self.backend.kernel.calls, [700, 700])
        self.assertEqual(failure._identity_handle_cleanup, ())

    def test_explicit_false_stays_retryable_even_if_last_error_is_zero(self):
        process = self.duplicate()
        self.backend.kernel.outcome = 0
        with patch.object(identities.C, "get_last_error", return_value=0), \
                self.assertRaises(IdentityUnavailable) as raised:
            process.close()
        self.assertEqual(raised.exception.win32_error, 0)
        self.backend.kernel.outcome = 1
        retry_identity_cleanup(raised.exception)
        self.assertEqual(self.backend.kernel.calls, [900, 900])

    def test_native_exception_is_unknown_even_if_its_type_looks_like_known_failure(self):
        for failure in (RuntimeError("fixture completion lost"),
                        KeyboardInterrupt("fixture interruption"),
                        IdentityUnavailable("process_handle_close_failed", 6)):
            with self.subTest(error=type(failure).__name__):
                self.backend.kernel.calls.clear()
                process = self.duplicate()
                self.backend.kernel.outcome = failure
                with self.assertRaises(type(failure)) as raised:
                    process.close()
                self.assertIs(raised.exception, failure)
                self.assert_quarantined(process, failure, 900)
        self.assertNotIn(800, self.backend.kernel.calls)

    def test_failed_duplicate_verification_preserves_primary_and_unknown_custody(self):
        primary = IdentityUnavailable("process_token_unavailable", 5)
        self.backend.identity_error = primary
        self.backend.kernel.outcome = RuntimeError("fixture completion lost")
        with self.assertRaises(IdentityUnavailable) as raised:
            self.duplicate()
        self.assertIs(raised.exception, primary)
        self.assertEqual(primary.reason, "process_token_unavailable")
        self.assertEqual(len(primary._identity_handle_cleanup), 1)
        self.backend.kernel.outcome = 1
        for _ in range(2):
            with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown"):
                retry_identity_cleanup(primary)
        self.assertEqual(self.backend.kernel.calls, [900])
        self.assertEqual(self.backend.duplicated, [800])
        self.assertEqual(self.backend.opened, [])

    def test_failed_open_verification_retains_unknown_cleanup_instead_of_losing_owner(self):
        primary = IdentityUnavailable("process_birth_unavailable", 5)
        self.backend.identity_error = primary
        self.backend.kernel.outcome = KeyboardInterrupt("fixture interruption")
        with self.assertRaises(IdentityUnavailable) as raised:
            VerifiedProcess.open(IDENTITY)
        self.assertIs(raised.exception, primary)
        self.assertEqual(len(primary._identity_handle_cleanup), 1)
        self.backend.kernel.outcome = 1
        with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown"):
            retry_identity_cleanup(primary)
        self.assertEqual(self.backend.kernel.calls, [700])
        self.assertEqual(self.backend.opened, [IDENTITY.pid])

    def test_failed_duplicate_verification_known_false_keeps_original_retry_contract(self):
        primary = RuntimeError("fixture query failure")
        self.backend.identity_error = primary
        self.backend.kernel.outcome = 0
        with self.assertRaises(RuntimeError) as raised:
            self.duplicate()
        self.assertIs(raised.exception, primary)
        with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_failed"):
            retry_identity_cleanup(primary)
        self.backend.kernel.outcome = 1
        retry_identity_cleanup(primary)
        retry_identity_cleanup(primary)
        self.assertEqual(self.backend.kernel.calls, [900, 900, 900])
        self.assertEqual(primary._identity_handle_cleanup, ())

    def test_unknown_explicit_backend_exception_is_quarantined_without_native_metadata(self):
        process = self.duplicate()
        failure = RuntimeError("fixture backend interrupted")
        with patch.object(self.backend, "close", side_effect=failure) as close:
            with self.assertRaises(RuntimeError) as raised:
                process.close()
            self.assertIs(raised.exception, failure)
            before = tuple(self.backend.queries)
            self.assertEqual(process.observe().status, IdentityStatus.UNKNOWN)
            self.assertIsNone(process.is_in_job(880))
            with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown"):
                retry_identity_cleanup(failure)
            close.assert_called_once_with(900)
            self.assertEqual(tuple(self.backend.queries), before)

    def test_interruption_after_success_before_local_retirement_never_recloses(self):
        class InterruptedRetirement(VerifiedProcess):
            def __setattr__(self, name, value):
                if name == "_handle" and value is None and getattr(self, "interrupt", False):
                    self.interrupt = False
                    raise RuntimeError("fixture publication interrupted")
                super().__setattr__(name, value)

        process = InterruptedRetirement.open(IDENTITY)
        process.interrupt = True
        with self.assertRaisesRegex(RuntimeError, "fixture publication interrupted") as raised:
            process.close()
        self.assert_quarantined(process, raised.exception, 700)

    def test_unmarked_close_error_without_known_win32_result_is_not_retryable(self):
        process = VerifiedProcess.open(IDENTITY)
        failure = IdentityUnavailable("process_handle_close_failed")
        with patch.object(self.backend, "close", side_effect=failure) as close:
            with self.assertRaises(IdentityUnavailable):
                process.close()
            with self.assertRaisesRegex(IdentityUnavailable, "process_handle_close_outcome_unknown"):
                process.close()
            self.assertTrue(failure._native_close_outcome_unknown)
            close.assert_called_once_with(700)

    def test_existing_explicit_backend_known_failure_reason_remains_retryable(self):
        process = VerifiedProcess.open(IDENTITY)
        failure = IdentityUnavailable("close_unavailable", 5)
        with patch.object(self.backend, "close", side_effect=failure):
            with self.assertRaises(IdentityUnavailable):
                process.close()
        self.assertEqual(process.observe().status, IdentityStatus.ALIVE)
        retry_identity_cleanup(failure)
        self.assertEqual(self.backend.kernel.calls, [700])


if __name__ == "__main__":
    unittest.main()
