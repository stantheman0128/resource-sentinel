"""C2 production retirement consumers, isolated SQL and synthetic native owners.

No native control or capability gate is exercised by these tests.
"""
from contextlib import closing
import ctypes as C
from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import (
    CpuControl, CpuControlMode, IdentityStatus, PendingIntent, RecoveryManifest,
)
from sentinel.adaptive.launch_transport import CancelBeforeStartRequest, StartFailedRequest
from sentinel.adaptive import native_job
from sentinel.adaptive.prelaunch_receipt import PrelaunchReceiptOperation
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_reconcile import ReconcileResult
from sentinel.adaptive.windows import NativePolicyMutexError
from tests import test_adaptive_guardian_launch as fixture
from tests import test_adaptive_native_job as native_fixture
from tests.test_adaptive_guardian_launch import GuardianLaunchTests, EPOCH


class EmptyJobKernel(native_fixture.Kernel):
    """Explicit API fake with zero lifetime history; never loads a native DLL."""
    def __init__(self):
        super().__init__()
        self.accounting = (0,) * 8

    def QueryInformationJobObject(self, handle, information_class, output, size, returned):
        if information_class == 3:
            self.membership = [(1, 0, 0, 0, ())]
        return super().QueryInformationJobObject(handle, information_class, output, size, returned)


class GuardianRetirementTests(unittest.TestCase):
    def setUp(self):
        fixture.GuardianLaunchTests.setUp(self)
        # All other fixture rows use this explicit future epoch. Retirement
        # defaults to wall time, so keep the synthetic clock consistent too.
        clock = patch("sentinel.adaptive.store.time.time", return_value=fixture.NOW + 1)
        clock.start()
        self.addCleanup(clock.stop)
    tearDown = GuardianLaunchTests.tearDown
    native_probe = GuardianLaunchTests.native_probe
    make_mutex = GuardianLaunchTests.make_mutex
    make_job = GuardianLaunchTests.make_job
    admitted = GuardianLaunchTests.admitted
    row = GuardianLaunchTests.row
    allocation = GuardianLaunchTests.allocation
    prepare = GuardianLaunchTests.prepare
    claim_request = GuardianLaunchTests.claim_request
    claim = GuardianLaunchTests.claim
    simulate_wrapper_launch = GuardianLaunchTests.simulate_wrapper_launch
    bind = GuardianLaunchTests.bind
    started = GuardianLaunchTests.started

    def request(self, case, *, failure=False):
        row = self.row(case)
        cls = StartFailedRequest if failure else CancelBeforeStartRequest
        return cls(request_id=str(uuid4()), execution_id=row["execution_id"], spec_hash=row["spec_hash"],
                   guardian_epoch=EPOCH, expected_revision=row["state_revision"], job_nonce=row["job_nonce"])

    def retire(self, case, request=None, *, failure=False):
        request = request or self.request(case, failure=failure)
        return self.owner.retire_before_start(request, case.peer, case.auth, case.deadline)

    def archive_count(self, case):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute("SELECT count(*) FROM executions WHERE reservation_id=?",
                                (self.row(case)["reservation_id"],)).fetchone()[0]

    def prepared_native_job(self):
        """Exercise NativeJob's real ownership state machine over fake Win32 APIs."""
        kernel = EmptyJobKernel()
        backend = native_job._WindowsBackend(kernel=kernel, advapi=native_fixture.Advapi(kernel),
            security=native_fixture.Security(kernel.calls))
        for override in (
                patch.object(C, "get_last_error", side_effect=lambda: kernel.error, create=True),
                patch.object(C, "set_last_error", side_effect=kernel.set_last_error, create=True),
                patch.object(C, "WinDLL", side_effect=AssertionError("portable fixture attempted DLL load"), create=True)):
            override.start()
            self.addCleanup(override.stop)
        case = self.admitted()
        def create(name, nonce, logon, *, access):
            return native_job.NativeJob.create(name, nonce, logon, access=access, backend=backend)
        with patch.object(self.owner, "_job_factory", side_effect=create):
            self.prepare(case)
        return case, kernel

    def test_preclaim_cancel_proves_retires_and_exact_replay_after_cleanup(self):
        case = self.admitted()
        self.prepare(case)
        request = self.request(case)
        result = self.retire(case, request)
        self.assertEqual(result.state, "CANCELLED_BEFORE_START")
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)
        self.assertTrue(self.retire(case, request).duplicate)
        self.assertEqual(self.owner.retire_completed_pending()[0]["terminal"], True)
        self.assertEqual(self.owner.retained_execution_ids, ())
        self.assertTrue(case.job.closed)
        self.assertTrue(self.retire(case, request).duplicate)
        self.assertEqual(self.archive_count(case), 1)

    def test_postclaim_cancel_stays_pending_then_separate_start_failed_can_close(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        request = self.request(case)
        result = self.retire(case, request)
        self.assertEqual(result.state, "LAUNCHING")
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 0)
        self.assertTrue(self.retire(case, request).duplicate)
        failure = self.request(case, failure=True)
        self.assertEqual(self.retire(case, failure).state, "START_FAILED")
        self.assertIsNone(self.allocation(case))
        self.assertTrue(self.retire(case, failure).duplicate)
        self.assertEqual(self.archive_count(case), 1)

    def test_rapidly_exited_unbound_root_is_not_never_started(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        case.job.members.clear()
        with self.assertRaisesRegex(LifecycleError, "guardian_never_started_unverified"):
            self.retire(case, failure=True)
        self.assertEqual(self.row(case)["state"], "LAUNCHING")
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 0)

    def test_running_cancel_records_request_without_releasing_or_killing(self):
        case = self.started()
        request = self.request(case)
        result = self.retire(case, request)
        self.assertEqual(result.state, "RUNNING")
        self.assertIsNotNone(self.row(case)["cancel_requested_at"])
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(case.job.members, [case.root.identity.pid])
        self.assertTrue(self.retire(case, request).duplicate)

    def test_cancel_ack_replay_after_natural_finish_is_completion_not_prelaunch(self):
        case = self.started()
        request = self.request(case)
        self.retire(case, request)
        self.processes.objects[case.root.identity].status = IdentityStatus.DEAD
        case.job.members.clear()
        result = self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=fixture.NOW + 2)
        self.assertTrue(result.terminal)
        reply = self.retire(case, request)
        self.assertEqual(reply.state, "FINISHED")
        self.assertTrue(reply.duplicate)
        self.assertEqual(self.archive_count(case), 1)

    def assert_finished_cancel_replay_refuses_manifest(self, change):
        case = self.started()
        request = self.request(case)
        self.retire(case, request)
        self.processes.objects[case.root.identity].status = IdentityStatus.DEAD
        case.job.members.clear()
        self.assertTrue(self.owner.lifecycle.reconcile(
            case.snapshot.execution_id, now=fixture.NOW + 2).terminal)
        record = self.journal.read(case.snapshot.execution_id,
            creation_nonce=case.prepared.job_nonce)
        values = {name: getattr(record, name) for name in record.__dataclass_fields__
                  if name != "manifest_hash"}
        changed = RecoveryManifest.create(**(values | change | {"manifest_seq": record.manifest_seq + 1}))
        # Deliberately inconsistent durable evidence in this isolated fixture.
        # The resulting policy hold is preserved until this fixture is discarded;
        # every inconsistent-manifest scenario has its own test fixture.
        (self.journal_dir / (case.snapshot.execution_id + ".json")).write_text(
            changed.to_json(), encoding="utf-8")
        with self.assertRaises(LifecycleError):
            self.retire(case, request)
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertEqual(self.archive_count(case), 1)
        self.assertIsNone(self.allocation(case))

    def test_finished_cancel_replay_refuses_unsettled_manifest(self):
        self.assert_finished_cancel_replay_refuses_manifest(
            {"last_applied": CpuControl(CpuControlMode.HARD_CAP, 2500)})

    def test_finished_cancel_replay_refuses_pending_manifest_intent(self):
        self.assert_finished_cancel_replay_refuses_manifest({"pending_intent": PendingIntent(
            str(uuid4()), CpuControl(CpuControlMode.DISABLED, None),
            CpuControl(CpuControlMode.HARD_CAP, 2500))})

    def test_cancel_ack_replay_after_root_exit_with_child_retains_allocation(self):
        case = self.started()
        request = self.request(case)
        self.retire(case, request)
        self.processes.objects[case.root.identity].status = IdentityStatus.DEAD
        case.job.members[:] = [case.root.identity.pid + 1]
        self.assertEqual(self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=fixture.NOW + 2).state, "DRAINING")
        self.assertEqual(self.retire(case, request).state, "DRAINING")
        self.assertIsNotNone(self.allocation(case))

    def test_cancel_after_scope_commit_before_manifest_build_uses_original_owner(self):
        case = self.admitted()
        with patch.object(self.owner, "_initial_record", side_effect=LifecycleError("fixture_prepare_cut")):
            with self.assertRaisesRegex(LifecycleError, "fixture_prepare_cut"):
                self.prepare(case)
        entry = self.owner._pending[case.snapshot.execution_id]
        self.assertFalse(entry.create_attempted)
        self.assertIsNone(entry.record)
        self.assertEqual(self.retire(case).state, "CANCELLED_BEFORE_START")
        self.assertEqual(self.jobs, [])
        self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])

    def test_unknown_native_job_creation_is_never_treated_as_never_created(self):
        case = self.admitted()
        with patch.object(self.owner, "_job_factory", side_effect=LifecycleError("fixture_create_unknown")):
            with self.assertRaisesRegex(LifecycleError, "fixture_create_unknown"):
                self.prepare(case)
        entry = self.owner._pending[case.snapshot.execution_id]
        self.assertTrue(entry.create_attempted)
        self.assertIsNone(entry.job)
        with self.assertRaisesRegex(LifecycleError, "guardian_job_creation_already_attempted"):
            self.retire(case)
        self.assertIsNotNone(self.allocation(case))

    def test_retirement_does_not_require_new_admission_readiness(self):
        case = self.admitted()
        self.prepare(case)
        self.authority.ready = False
        self.assertEqual(self.retire(case).state, "CANCELLED_BEFORE_START")

    def test_native_unknown_or_nonzero_lifetime_cannot_release(self):
        cases = [(value, self.admitted()) for value in (None, True, -1, 1, 0.0)]
        for _, case in cases:
            self.prepare(case)
        for value, case in cases:
            with self.subTest(value=value):
                case.job.total_processes = value
                with self.assertRaisesRegex(LifecycleError, "guardian_never_started_unverified"):
                    self.retire(case)
                self.assertIsNotNone(self.allocation(case))

    def test_wrong_nonce_and_revision_do_not_consume_request_or_release(self):
        for changes in ({"job_nonce": "f" * 32}, {"expected_revision": 999}):
            with self.subTest(changes=changes):
                case = self.admitted()
                self.prepare(case)
                request = self.request(case)
                with self.assertRaises(LifecycleError):
                    self.retire(case, replace(request, **changes))
                self.assertIsNotNone(self.allocation(case))
                self.assertEqual(self.retire(case, request).state, "CANCELLED_BEFORE_START")

    def test_terminal_commit_lost_ack_reconciles_original_request_only_once(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        request = self.request(case, failure=True)
        original = self.store.mark_start_failed
        def lose_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise LifecycleError("fixture_lost_terminal_ack")
        with patch.object(self.store, "mark_start_failed", side_effect=lose_ack):
            with self.assertRaisesRegex(LifecycleError, "fixture_lost_terminal_ack"):
                self.retire(case, request)
        self.assertEqual(self.row(case)["state"], "START_FAILED")
        self.assertTrue(self.retire(case, request).duplicate)
        self.assertEqual(self.archive_count(case), 1)

    def test_new_request_id_cannot_replay_terminal_result(self):
        case = self.admitted()
        self.prepare(case)
        request = self.request(case)
        self.retire(case, request)
        with self.assertRaises(LifecycleError):
            self.retire(case, replace(request, request_id=str(uuid4())))
        self.assertEqual(self.archive_count(case), 1)

    def test_cleanup_failure_retains_exact_owners_until_retry(self):
        case = self.admitted()
        self.prepare(case)
        self.retire(case)
        entry = self.owner._pending[case.snapshot.execution_id]
        with patch.object(entry.wrapper, "close", side_effect=RuntimeError("fixture_close_failed")):
            self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertTrue(case.job.closed)
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)
        self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertEqual(self.owner.retained_execution_ids, ())

    def test_receipt_capture_failure_never_starts_native_cleanup(self):
        case = self.admitted()
        self.prepare(case)
        self.retire(case)
        entry = self.owner._pending[case.snapshot.execution_id]
        with patch("sentinel.adaptive.prelaunch_receipt.PrelaunchReceiptOperation",
                   side_effect=LifecycleError("fixture_receipt_capture_failed")), \
                patch.object(entry.job, "close", wraps=entry.job.close) as job_close, \
                patch.object(entry.wrapper, "close", wraps=entry.wrapper.close) as wrapper_close, \
                patch.object(entry.mutex, "close", wraps=entry.mutex.close) as mutex_close:
            result, = self.owner.retire_completed_pending()
        self.assertFalse(result["terminal"])
        self.assertEqual(result["reason"], "guardian_retirement_cleanup_unverified")
        self.assertFalse(entry.retirement_cleanup_started)
        self.assertIsNone(entry.retirement_receipt_operation)
        self.assertEqual(entry.closed_handles, set())
        for close in (job_close, wrapper_close, mutex_close):
            close.assert_not_called()
        self.assertIs(self.owner._pending[case.snapshot.execution_id], entry)
        self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])

    def test_clean_scope_captures_once_and_pending_publication_retains_closed_owners(self):
        case = self.admitted()
        self.prepare(case)
        self.retire(case)
        entry = self.owner._pending[case.snapshot.execution_id]
        captured = []

        def capture(owner, original_entry, row, manifest, binding):
            self.assertIs(owner, self.owner)
            self.assertIs(original_entry, entry)
            self.assertIsNone(owner.lifecycle._scope_entry)
            self.assertIsNone(self.store._policy.current_guard())
            self.assertFalse(entry.mutex.acquired)
            self.assertEqual(entry.closed_handles, set())
            operation = PrelaunchReceiptOperation(owner, entry, row, manifest, binding)
            captured.append(operation)
            return operation

        with patch("sentinel.adaptive.prelaunch_receipt.PrelaunchReceiptOperation", side_effect=capture) as factory, \
                patch.object(entry.job, "close", wraps=entry.job.close) as job_close, \
                patch.object(entry.wrapper, "close", wraps=entry.wrapper.close) as wrapper_close, \
                patch.object(entry.mutex, "close", wraps=entry.mutex.close) as mutex_close:
            with patch.object(PrelaunchReceiptOperation, "tick",
                    return_value=ReconcileResult(False, True, False, "fixture_publication_pending")):
                first, = self.owner.retire_completed_pending()
            self.assertFalse(first["terminal"])
            self.assertEqual(first["reason"], "fixture_publication_pending")
            self.assertEqual(entry.closed_handles, {"job", "wrapper", "mutex"})
            self.assertIs(entry.retirement_receipt_operation, captured[0])
            self.assertIs(self.owner._pending[case.snapshot.execution_id], entry)
            with patch.object(entry.mutex, "acquire", side_effect=AssertionError("closed mutex reacquired")), \
                    patch.object(entry.job, "accounting", side_effect=AssertionError("closed Job queried")):
                final, = self.owner.retire_completed_pending()
            self.assertTrue(final["terminal"], final)
            factory.assert_called_once()
            for close in (job_close, wrapper_close, mutex_close):
                close.assert_called_once()
        self.assertEqual(self.owner.retained_execution_ids, ())
        self.assertEqual(self.archive_count(case), 1)

    def test_native_job_known_close_failure_retries_without_querying_closed_custody(self):
        case, kernel = self.prepared_native_job()
        self.retire(case)
        kernel.close_failures.add(native_fixture.RETAINED)
        self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertFalse(case.job._ready)
        self.assertFalse(case.job.closed)
        query_count = sum(call[0] == "QueryInformationJobObject" for call in kernel.calls)
        # NativeJob deliberately disables future queries even on a known
        # failed close. Only its exact resource owner may retry cleanup now.
        with self.assertRaisesRegex(native_job.NativeJobError, "native_job_handle_unavailable"):
            case.job.accounting()
        kernel.close_failures.clear()
        self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertTrue(case.job.closed)
        self.assertEqual(query_count,
            sum(call[0] == "QueryInformationJobObject" for call in kernel.calls))
        self.assertEqual(kernel.calls.count(("CloseHandle", native_fixture.RETAINED)), 2)
        self.assertFalse(any(call[0] == "SetInformationJobObject" for call in kernel.calls))
        self.assertEqual(self.owner.retained_execution_ids, ())

    def test_native_job_unknown_close_never_reuses_locator_or_queries_it(self):
        case, kernel = self.prepared_native_job()
        self.retire(case)
        kernel.close_exceptions[native_fixture.RETAINED] = RuntimeError("fixture_unknown_close")
        self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertFalse(case.job._ready)
        query_count = sum(call[0] == "QueryInformationJobObject" for call in kernel.calls)
        # Removing the injected fault does not resolve whether the native
        # handle was closed. A later tick cannot reuse its numeric locator.
        kernel.close_exceptions.clear()
        self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertEqual(query_count,
            sum(call[0] == "QueryInformationJobObject" for call in kernel.calls))
        self.assertEqual(kernel.calls.count(("CloseHandle", native_fixture.RETAINED)), 1)
        self.assertFalse(any(call[0] == "SetInformationJobObject" for call in kernel.calls))
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_mutex_known_close_failure_retries_without_reacquiring(self):
        case = self.admitted()
        self.prepare(case)
        self.retire(case)
        mutex = self.owner._pending[case.snapshot.execution_id].mutex
        original_close = mutex.close
        attempts = []
        def close():
            attempts.append("close")
            if len(attempts) == 1:
                raise NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
            original_close()
        with patch.object(mutex, "acquire", wraps=mutex.acquire) as acquire, \
                patch.object(mutex, "close", side_effect=close):
            self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
            self.assertTrue(case.job.closed)
            acquired_before_retry = acquire.call_count
            self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])
            self.assertEqual(acquire.call_count, acquired_before_retry)
        self.assertEqual(attempts, ["close", "close"])
        self.assertTrue(mutex.closed)
        self.assertEqual(self.owner.retained_execution_ids, ())

    def test_mutex_unknown_close_is_quarantined_without_wait_or_reclose(self):
        case = self.admitted()
        self.prepare(case)
        self.retire(case)
        mutex = self.owner._pending[case.snapshot.execution_id].mutex
        def close_then_lose_result():
            mutex.closed = True
            raise RuntimeError("fixture_mutex_close_outcome_unknown")
        with patch.object(mutex, "acquire", wraps=mutex.acquire) as acquire, \
                patch.object(mutex, "close", side_effect=close_then_lose_result) as close:
            self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
            acquired_before_retry = acquire.call_count
            self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
            self.assertFalse(self.owner.retire_completed_pending()[0]["terminal"])
            self.assertEqual(acquire.call_count, acquired_before_retry)
            self.assertEqual(close.call_count, 1)
        self.assertTrue(case.job.closed)
        self.assertTrue(mutex.closed)
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)


del GuardianLaunchTests  # fixture base is not a second copy of its test suite

if __name__ == "__main__":
    unittest.main()
