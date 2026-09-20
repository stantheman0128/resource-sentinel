"""Portable borrowed creation-handle ownership and actual caller regressions.

These cases simulate Win32 calls, including the actual launch error path. They
create no processes or Jobs and perform no control writes. Native observation
is covered separately; mocks never establish launch/capability authority.
"""
import ctypes as C
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import identity as identities
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import (
    IdentityUnavailable, VerifiedProcess, retry_identity_cleanup,
)
from tests.windows import adaptive_win32 as native
from tests.windows import test_adaptive_recovery_capability as recovery
from tests.fixtures import adaptive_recovery_actor as actor


IDENTITY = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200")


class Backend:
    def __init__(self):
        self.value = IDENTITY
        self.state = IdentityStatus.ALIVE
        self.duplicates, self.queries, self.closes = [], [], []
        self.duplicate_error = self.identity_error = self.close_error = None

    def duplicate_process(self, source):
        self.duplicates.append(source)
        if self.duplicate_error:
            raise self.duplicate_error
        return 900

    def identity(self, handle):
        self.queries.append(handle)
        if self.identity_error:
            raise self.identity_error
        return self.value

    def wait(self, handle):
        self.queries.append(handle)
        return self.state

    def close(self, handle):
        self.closes.append(handle)
        if self.close_error:
            raise self.close_error

    def open_process(self, *_):
        raise AssertionError("creation handle must never be reopened by PID")


class CreatedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        override = patch.object(identities, "_backend", return_value=self.backend)
        override.start()
        self.addCleanup(override.stop)

    def capture(self, **overrides):
        arguments = dict(source_handle=800, expected_pid=IDENTITY.pid,
                         expected_logon_id=IDENTITY.logon_id)
        return VerifiedProcess.duplicate_from_handle(**(arguments | overrides))

    def test_duplicate_queries_exact_object_and_close_never_closes_source(self):
        with self.capture() as verified:
            self.assertEqual(verified.identity, IDENTITY)
            self.assertEqual(verified.observe().status, IdentityStatus.ALIVE)
            self.backend.state = IdentityStatus.DEAD
            self.assertEqual(verified.observe().status, IdentityStatus.DEAD)
        self.assertEqual(self.backend.duplicates, [800])
        self.assertEqual(self.backend.queries, [900, 900, 900])
        self.assertEqual(self.backend.closes, [900])

    def test_factory_accepts_signaled_object_without_claiming_liveness(self):
        self.backend.state = IdentityStatus.DEAD
        with self.capture() as verified:
            self.assertEqual(verified.identity.created_filetime_100ns,
                             IDENTITY.created_filetime_100ns)
            self.assertEqual(verified.observe().status, IdentityStatus.DEAD)

    def test_pid_and_logon_mismatch_close_only_duplicate(self):
        for value in (replace(IDENTITY, pid=102),
                      replace(IDENTITY, logon_id="S-1-5-5-100-201")):
            with self.subTest(value=value):
                self.backend.value = value
                with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch"):
                    self.capture()
        self.assertEqual(self.backend.closes, [900, 900])

    def test_invalid_borrowed_handle_or_expected_fields_rejected_before_native_call(self):
        cases = [("source_handle", value) for value in (
            None, False, 0, -1, C.c_void_p(-1).value, "800", C.c_void_p(800),
            1 << (C.sizeof(C.c_void_p) * 8))]
        cases += [("expected_pid", value) for value in (None, False, 0, -1, "101", 1 << 32)]
        cases += [("expected_logon_id", value) for value in (
            None, False, "", "S-1-5-21-100", "S-1-5-5-4294967296-1", "S-1-5-5-1-2\n")]
        for field, value in cases:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.capture(**{field: value})
        self.assertEqual(self.backend.duplicates, [])

    def test_duplicate_failure_does_not_close_borrowed_source(self):
        failure = IdentityUnavailable("process_duplicate_unavailable", 5)
        self.backend.duplicate_error = failure
        with self.assertRaises(IdentityUnavailable) as raised:
            self.capture()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.backend.closes, [])

    def test_identity_failure_closes_duplicate_and_preserves_original_error(self):
        failure = IdentityUnavailable("process_token_unavailable", 5)
        self.backend.identity_error = failure
        with self.assertRaises(IdentityUnavailable) as raised:
            self.capture()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.backend.closes, [900])

    def test_failed_duplicate_cleanup_preserves_primary_and_remains_retryable(self):
        primary = RuntimeError("primary-query-failure")
        self.backend.identity_error = primary
        self.backend.close_error = IdentityUnavailable("process_handle_close_failed", 6)
        with self.assertRaises(RuntimeError) as raised:
            self.capture()
        self.assertIs(raised.exception, primary)
        self.assertEqual(str(primary), "primary-query-failure")
        self.assertNotIn("900", repr(primary))
        with self.assertRaises(IdentityUnavailable):
            retry_identity_cleanup(primary)
        self.backend.close_error = None
        retry_identity_cleanup(primary)
        retry_identity_cleanup(primary)
        self.assertEqual(self.backend.closes, [900, 900, 900])
        self.assertEqual(primary._identity_handle_cleanup, ())

    def test_verified_close_failure_keeps_owner_for_explicit_retry(self):
        verified = self.capture()
        failure = IdentityUnavailable("process_handle_close_failed", 6)
        self.backend.close_error = failure
        with self.assertRaises(IdentityUnavailable) as raised:
            verified.close()
        self.assertIs(raised.exception, failure)
        self.assertEqual(verified.observe().status, IdentityStatus.ALIVE)
        self.backend.close_error = None
        retry_identity_cleanup(failure)
        verified.close()
        self.assertEqual(self.backend.closes, [900, 900])
        self.assertEqual(verified.observe().status, IdentityStatus.UNKNOWN)

    def test_native_duplicate_binding_uses_only_limited_noninherited_rights(self):
        calls = []
        def duplicate(source_process, source, target_process, output, access, inherit, options):
            calls.append((source_process, source, target_process, access, inherit, options))
            output._obj.value = 901
            return 1
        backend = object.__new__(identities._WindowsBackend)
        backend.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1,
                                         DuplicateHandle=duplicate)
        self.assertEqual(backend.duplicate_process(800), 901)
        self.assertEqual(calls, [(-1, 800, -1, 0x1000 | 0x100000, False, 0)])

    def test_failed_native_duplicate_ignores_unusable_output_and_preserves_source(self):
        def duplicate(*arguments):
            arguments[3]._obj.value = 901
            return 0
        backend = object.__new__(identities._WindowsBackend)
        backend.kernel = SimpleNamespace(GetCurrentProcess=lambda: -1,
                                         DuplicateHandle=duplicate)
        with patch.object(identities.C, "get_last_error", return_value=5, create=True), \
                self.assertRaisesRegex(IdentityUnavailable, "process_duplicate_unavailable"):
            backend.duplicate_process(800)


class LaunchApi:
    """Portable ABI simulation: no process or Job is created."""
    def __init__(self):
        self.closed, self.created = [], 0
        self.next_stdio = 1000

    def GetCurrentProcess(self):
        return -1

    def GetStdHandle(self, _selector):
        return 600

    def DuplicateHandle(self, _source_process, _source, _target_process, output, *_):
        self.next_stdio += 1
        output._obj.value = self.next_stdio
        return 1

    def InitializeProcThreadAttributeList(self, _buffer, _count, _flags, size):
        size._obj.value = 64
        return 0 if _buffer is None else 1

    def UpdateProcThreadAttribute(self, *_):
        return 1

    def DeleteProcThreadAttributeList(self, *_):
        pass

    def CreateProcessW(self, *arguments):
        self.created += 1
        info = arguments[-1]._obj
        info.hProcess, info.hThread = 800, 801
        info.dwProcessId, info.dwThreadId = IDENTITY.pid, 102
        return 1

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return 1

    def IsProcessInJob(self, _process, _job, output):
        output._obj.value = True
        return 1

    def GetProcessTimes(self, _process, created, *_):
        created._obj.dwHighDateTime = IDENTITY.created_filetime_100ns >> 32
        created._obj.dwLowDateTime = IDENTITY.created_filetime_100ns & 0xFFFFFFFF
        return 1


class LaunchCreatedIdentityTests(unittest.TestCase):
    def setUp(self):
        self.backend, self.api = Backend(), LaunchApi()
        for override in (
            patch.object(identities, "_backend", return_value=self.backend),
            patch.object(native, "_api", return_value=(self.api, None, None)),
            patch.object(native, "_opt_in"),
            patch.object(native, "require_supported_host"),
            patch.object(native.C, "get_last_error", return_value=122, create=True),
            patch.object(native.C, "set_last_error", create=True),
        ):
            override.start()
            self.addCleanup(override.stop)
        self.job = SimpleNamespace(handle=880, logon_sid=IDENTITY.logon_id)

    def launch(self):
        return native.launch_in_job(self.job, os.path.abspath(sys.executable), "fixed-fixture")

    def test_actual_launch_consumer_verifies_full_identity_and_keeps_legacy_shape(self):
        process = self.launch()
        self.assertEqual(self.api.created, 1)
        self.assertEqual(self.backend.duplicates, [800])
        self.assertEqual(self.backend.closes, [900])
        self.assertEqual(process.full_identity(expected_logon_id=IDENTITY.logon_id), IDENTITY)
        self.assertEqual(process.identity(), {"pid": 101,
                         "created_filetime_100ns": str(IDENTITY.created_filetime_100ns)})
        self.assertNotIn(800, self.api.closed)
        process.close()
        self.assertEqual(self.api.closed.count(800), 1)

    def test_actual_launch_pid_or_job_logon_mismatch_retains_original_without_retry(self):
        for observed in (replace(IDENTITY, pid=102),
                         replace(IDENTITY, logon_id="S-1-5-5-100-201")):
            with self.subTest(observed=observed):
                self.backend.value = observed
                before = self.api.created
                with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
                    self.launch()
                failure = raised.exception
                self.assertEqual(failure.process.handle, 800)
                self.assertEqual(failure.process.pid, IDENTITY.pid)
                self.assertEqual(failure.__cause__.reason, "identity_mismatch")
                self.assertEqual(self.api.created, before + 1)
                failure.process.close()

    def test_primary_plus_duplicate_close_failure_retained_by_actual_carrier_cleanup(self):
        primary = IdentityUnavailable("process_token_unavailable", 5)
        self.backend.identity_error = primary
        self.backend.close_error = IdentityUnavailable("process_handle_close_failed", 6)
        with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
            self.launch()
        failure = raised.exception
        self.assertIs(failure.__cause__, primary)
        self.assertEqual(failure.process.handle, 800)
        self.assertEqual(self.api.created, 1)
        self.assertNotIn(800, self.api.closed)
        with self.assertRaises(IdentityUnavailable):
            failure.process.close()
        self.assertEqual(failure.process.handle, 800)
        self.backend.close_error = None
        failure.process.close()
        failure.process.close()
        self.assertEqual(self.backend.closes, [900, 900, 900])
        self.assertEqual(self.api.closed.count(800), 1)

    def test_postverification_close_failure_also_retains_duplicate_on_original_owner(self):
        primary = IdentityUnavailable("process_handle_close_failed", 6)
        self.backend.close_error = primary
        with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
            self.launch()
        failure = raised.exception
        self.assertIs(failure.__cause__, primary)
        self.assertEqual(failure.process.handle, 800)
        self.assertEqual(self.api.created, 1)
        self.backend.close_error = None
        failure.process.close()
        self.assertEqual(self.backend.closes, [900, 900])
        self.assertEqual(self.api.closed.count(800), 1)


class RecoveryCreatedIdentityTests(unittest.TestCase):
    def test_fixture_store_commits_and_closes_its_connection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with actor.fixture_store(directory) as connection:
                connection.execute("UPDATE allocation SET state='finished' WHERE id='own'")
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
            with actor.fixture_store(directory) as reopened:
                self.assertEqual(reopened.execute("SELECT state FROM allocation WHERE id='own'").fetchone()[0], "finished")

    def test_fixture_store_rolls_back_and_closes_after_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                with actor.fixture_store(directory) as connection:
                    connection.execute("UPDATE allocation SET state='finished' WHERE id='own'")
                    raise RuntimeError("fixture failure")
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")
            with actor.fixture_store(directory) as reopened:
                self.assertEqual(reopened.execute("SELECT state FROM allocation WHERE id='own'").fetchone()[0], "held")

    def test_actor_unknown_launch_cooperatively_cleans_once_and_preserves_failure(self):
        for close_fails in (False, True):
            with self.subTest(close_fails=close_fails), tempfile.TemporaryDirectory() as temporary:
                case = Path(temporary)
                process = SimpleNamespace(wait=Mock(return_value=True), close=Mock())
                job = SimpleNamespace(close=Mock())
                failure = native.LaunchOutcomeUnknown(process, RuntimeError("identity_mismatch"))
                if close_fails:
                    process.close.side_effect = RuntimeError("cleanup failure")
                with patch.object(actor, "require_supported_host"), \
                        patch.object(actor.OwnedJob, "open", return_value=job), \
                        patch.object(actor, "launch_in_job", side_effect=failure) as launch, \
                        patch.object(actor, "mark") as mark, \
                        patch.object(actor.os, "_exit") as crash:
                    with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
                        actor.wrapper(case, {"job_name": "fixture", "nonce": "a" * 32})
                self.assertIs(raised.exception, failure)
                self.assertIs(failure.fixture_job, job)
                self.assertTrue((case / "stop").exists())
                launch.assert_called_once()
                process.wait.assert_called_once_with(10)
                process.close.assert_called_once()
                job.close.assert_called_once()
                mark.assert_not_called()
                crash.assert_not_called()
                if close_fails:
                    self.assertIn("fixture_unknown_launch_cleanup_failed:process_close",
                                  failure.__notes__)

    def test_actual_actor_retains_both_handles_when_exit_is_unverified(self):
        for wait_raises in (False, True):
            with self.subTest(wait_raises=wait_raises), tempfile.TemporaryDirectory() as temporary:
                process = SimpleNamespace(wait=Mock(return_value=False), close=Mock())
                if wait_raises:
                    process.wait.side_effect = OSError("wait failure")
                job = SimpleNamespace(close=Mock())
                failure = native.LaunchOutcomeUnknown(process, RuntimeError("identity_mismatch"))
                with patch.object(actor, "require_supported_host"), \
                        patch.object(actor.OwnedJob, "open", return_value=job), \
                        patch.object(actor, "launch_in_job", side_effect=failure) as launch, \
                        patch.object(actor, "mark") as mark, \
                        patch.object(actor.os, "_exit") as crash:
                    with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
                        actor.wrapper(Path(temporary), {"job_name": "fixture", "nonce": "a" * 32})
                self.assertIs(raised.exception, failure)
                self.assertIs(failure.process, process)
                self.assertIs(failure.fixture_job, job)
                self.assertTrue((Path(temporary) / "stop").exists())
                self.assertTrue(failure.__notes__)
                launch.assert_called_once()
                process.close.assert_not_called()
                job.close.assert_not_called()
                mark.assert_not_called()
                crash.assert_not_called()

    def test_actual_s3_case_adopts_unknown_root_into_existing_cleanup(self):
        for close_fails in (False, True):
            with self.subTest(close_fails=close_fails), tempfile.TemporaryDirectory() as temporary:
                harness = recovery.RecoveryCapability("test_s3_native_fault_matrix")
                harness.run, harness.results = Path(temporary), []
                process = SimpleNamespace(close=Mock())
                if close_fails:
                    process.close.side_effect = RuntimeError("cleanup failure")
                failure = native.LaunchOutcomeUnknown(process, RuntimeError("identity_mismatch"))
                job = SimpleNamespace(name="fixture", query_cpu=lambda: {"flags": 0},
                    query_limits=lambda: {"limit_flags": 0, "ui_restrictions": 0},
                    wait_empty=Mock(return_value=False), close=Mock())
                with patch.object(recovery.win.OwnedJob, "create", return_value=job), \
                        patch.object(recovery.win, "interrupt_time_100ns", side_effect=lambda: time.monotonic_ns() // 100), \
                        patch.object(harness, "_workload", side_effect=failure) as launch, \
                        patch.object(harness, "_await") as awaiting, \
                        patch.object(harness, "_popen") as popen:
                    with self.assertRaises(native.LaunchOutcomeUnknown) as raised:
                        harness._case("intent_before", 1)
                self.assertIs(raised.exception, failure)
                launch.assert_called_once()
                process.close.assert_called_once()
                job.close.assert_called_once()
                awaiting.assert_not_called()
                popen.assert_not_called()
                self.assertEqual(len(list(Path(temporary).glob("*/stop"))), 1)
                self.assertEqual(harness.results[0]["result"], "failed")
                self.assertFalse(harness.results[0]["job_empty_verified"])


if __name__ == "__main__":
    unittest.main()
