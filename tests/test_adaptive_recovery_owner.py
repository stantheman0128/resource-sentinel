"""Actual isolated ledger/journal consumer; native owners are explicit fixtures.

These tests do not establish Windows cold-recovery, native ACL or cap efficacy.
No process is launched/killed and no live Job/control/runtime is modified.
"""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
from unittest import TestCase
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, PendingIntent
from sentinel.adaptive.native_job import JobAccess, NativeJobError
from sentinel.adaptive.recovery_journal import RecoveryJournalError
from sentinel.adaptive.recovery_owner import RecoveryOwner
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.windows import NativePolicyMutexError
from tests import test_adaptive_guardian_lifecycle as fixture
from tests.test_adaptive_guardian_launch import ProcessBackend
from tests.test_adaptive_guardian_restore import RestoreJob


CAP, DISABLED = fixture.CAP, fixture.DISABLED


class Mutex(fixture.Mutex):
    def __init__(self, registry, events, *args):
        super().__init__(*args)
        self.registry, self.events = registry, events
        self.before_enter = None

    @contextmanager
    def acquire(self, *, timeout_ms=250):
        if self.registry.get(self.name) is not None:
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.registry[self.name] = self
        self.events.append(("enter", self.name))
        try:
            with super().acquire(timeout_ms=timeout_ms) as lease:
                if self.before_enter:
                    self.before_enter()
                yield lease
        finally:
            if not self.acquired:
                self.registry.pop(self.name, None)
                self.events.append(("leave", self.name))


class RecoveryOwnerTests(TestCase):
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    rewrite_manifest = fixture.GuardianLifecycleTests.rewrite_manifest
    sql = fixture.GuardianLifecycleTests.sql
    allocation = fixture.GuardianLifecycleTests.allocation

    def setUp(self):
        fixture.GuardianLifecycleTests.setUp(self)
        self.native = ProcessBackend()
        self.current = self.native.process(fixture.GUARDIAN)
        self.old_identity = replace(fixture.GUARDIAN, pid=fixture.GUARDIAN.pid + 90000,
                                   created_filetime_100ns=fixture.GUARDIAN.created_filetime_100ns + 700)
        self.old = self.native.process(self.old_identity)
        self.kernel_mutexes, self.events, self.opened = {}, [], []
        self.recovery_mutexes, self.jobs = [], {}
        self.capture_store = None

    def case(self, *, control=CAP, pending=None):
        case = self.seed_started()
        self.rewrite_manifest(case, manifest_seq=2, guardian_identity=self.old_identity,
                              last_applied=control, pending_intent=pending)
        job = RestoreJob(case.record, case.job.handle)
        desired = pending.new if pending is not None else control
        if desired not in (None, DISABLED):
            job.control = {"flags": 5, "rate_bp": desired.cpu_rate_bp}
        case.job = self.jobs[case.record.job_name] = job
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        return case

    def mutex_factory(self, *args):
        mutex = Mutex(self.kernel_mutexes, self.events, *args)
        self.recovery_mutexes.append(mutex)
        return mutex

    def open_job(self, name, nonce, logon, *, access):
        self.assertEqual(access, JobAccess.CONTROL)
        self.assertEqual(logon, self.old_identity.logon_id)
        job = self.jobs[name]
        self.assertEqual(job.nonce, nonce)
        self.assertEqual(len(self.kernel_mutexes), 3)
        self.assertEqual(self.native.state(self.old._handle).status, IdentityStatus.DEAD)
        self.opened.append((name, nonce, logon, access))
        return job

    def capture(self, *, job_opener=None, mutex_factory=None):
        self.capture_store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        self.recovery = RecoveryOwner.capture(self.capture_store, self.journal,
            guardian=self.old, guardian_epoch=fixture.EPOCH, current=self.current,
            mutex_factory=mutex_factory or self.mutex_factory, job_opener=job_opener or self.open_job)
        return self.recovery

    def dead(self):
        self.native.objects[self.old_identity].status = IdentityStatus.DEAD

    def restore(self, case):
        return self.recovery.restore(case.spec.execution_id, creation_nonce=case.record.creation_nonce)

    def record(self, case):
        return self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)

    def snapshot(self):
        with self.connection() as conn:
            return {name: [tuple(row) for row in conn.execute("SELECT * FROM " + name)] for name in
                    ("managed_executions", "reservations", "adaptive_runtime", "adaptive_control_slot", "executions")}

    def test_capture_pins_existing_binding_and_duplicates_exact_live_guardian(self):
        self.case()
        owner = self.capture()
        row = self.connection().execute("SELECT * FROM adaptive_runtime").fetchone()
        self.assertEqual(owner.binding.instance_id, row["policy_instance_id"])
        self.assertEqual(owner.guardian_identity, self.old_identity)
        self.assertEqual(owner.guardian_epoch, fixture.EPOCH)
        self.assertNotEqual(owner._guardian._handle, self.old._handle)
        self.old.close()
        self.assertEqual(owner.observe_guardian().status, IdentityStatus.ALIVE)
        self.assertEqual(self.opened, [])

    def test_capture_requires_alive_witness_and_retains_failed_capture_owners(self):
        self.case()
        self.dead()
        with self.assertRaisesRegex(LifecycleError, "capture_guardian_not_alive") as caught:
            self.capture()
        self.assertIsNotNone(caught.exception._recovery_owner._current)
        self.assertIsNotNone(self.old._handle)
        self.assertEqual(self.opened, [])

    def test_capture_cannot_invent_policy_binding_for_uninitialized_ledger(self):
        self.case()
        self.sql("UPDATE adaptive_runtime SET policy_binding_initialized=0,policy_instance_id=NULL,policy_logon_id=NULL")
        with self.assertRaisesRegex(LifecycleError, "capture_binding_unverified"):
            self.capture()
        row = self.connection().execute("SELECT policy_binding_initialized,policy_instance_id FROM adaptive_runtime").fetchone()
        self.assertEqual(tuple(row), (0, None))
        self.assertEqual(self.opened, [])

    def test_capture_revalidates_binding_after_actual_mutex_acquisition(self):
        self.case()
        original = self.connection().execute("SELECT policy_instance_id FROM adaptive_runtime").fetchone()[0]
        def changed_factory(logon, instance):
            mutex = self.mutex_factory(logon, instance)
            if instance == original:
                mutex.before_enter = lambda: self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
            return mutex
        with self.assertRaisesRegex(LifecycleError, "capture_binding_changed"):
            self.capture(mutex_factory=changed_factory)
        self.assertEqual(self.opened, [])
        self.assertEqual(self.kernel_mutexes, {})

    def test_alive_and_unknown_guardian_do_not_open_or_control_job(self):
        case = self.case()
        self.capture()
        for state in (IdentityStatus.ALIVE, IdentityStatus.UNKNOWN):
            self.native.objects[self.old_identity].status = state
            with self.assertRaisesRegex(LifecycleError, "guardian_death_unverified"):
                self.restore(case)
        self.assertEqual(self.opened, [])
        self.assertEqual(case.job.sets, 0)

    def test_dead_exact_guardian_restores_with_db_unavailable_preserving_all_accounting(self):
        case = self.case()
        owner = self.capture()
        before = self.snapshot()
        self.dead()
        with patch.object(self.capture_store, "_connection", side_effect=AssertionError("restore must not use DB")):
            with patch.object(self.capture_store, "_transaction", side_effect=AssertionError("no accounting mutation")):
                result = self.restore(case)
        self.assertTrue(result.native_disabled and result.journal_settled)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.record(case).last_applied, DISABLED)
        self.assertEqual(self.record(case).guardian_identity, self.old_identity)
        self.assertEqual(self.snapshot(), before)
        self.assertIn(case.spec.execution_id, owner.retained_execution_ids)
        self.assertFalse(case.job.closed)

    def test_original_process_handle_not_reopened_after_pid_reuse(self):
        case = self.case()
        self.capture()
        self.dead()
        replacement = replace(self.old_identity, created_filetime_100ns=self.old_identity.created_filetime_100ns + 1)
        self.native.process(replacement)
        with patch.object(self.native, "open_transfer_source", side_effect=AssertionError("must not reopen PID")):
            self.restore(case)
        self.assertEqual(self.recovery.guardian_identity, self.old_identity)
        self.assertEqual(case.job.sets, 1)

    def test_pending_new_and_old_values_are_restored_without_replaying_intent(self):
        case = self.case(control=None, pending=PendingIntent(str(uuid4()), DISABLED, CAP))
        self.capture()
        self.dead()
        self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertIsNone(self.record(case).pending_intent)
        self.assertEqual(self.record(case).last_applied, DISABLED)
        self.restore(case)
        self.assertEqual(case.job.sets, 1)

    def test_disabled_pending_old_uses_no_set_and_preserves_other_limit_fields(self):
        case = self.case(control=None, pending=PendingIntent(str(uuid4()), DISABLED, CAP))
        case.job.control = {"flags": 0, "rate_bp": 7391}
        self.capture()
        self.dead()
        self.restore(case)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(case.job.control, {"flags": 0, "rate_bp": 7391})

    def test_external_control_is_not_overwritten(self):
        case = self.case()
        case.job.control = {"flags": 5, "rate_bp": 5000}
        self.capture()
        self.dead()
        with self.assertRaisesRegex(LifecycleError, "external_control_conflict") as caught:
            self.restore(case)
        self.assertFalse(caught.exception.recovery_result.native_disabled)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.record(case).last_applied, CAP)

    def test_changed_creator_manifest_is_sticky_and_cannot_fall_back_after_missing_file(self):
        case = self.case()
        self.capture()
        self.dead()
        self.rewrite_manifest(case, manifest_seq=3, guardian_identity=replace(self.old_identity, pid=self.old_identity.pid + 1))
        with self.assertRaisesRegex(LifecycleError, "manifest_binding_changed"):
            self.restore(case)
        with patch.object(self.journal, "read", side_effect=AssertionError("integrity must stay unresolved")):
            with self.assertRaisesRegex(LifecycleError, "manifest_integrity_unresolved"):
                self.restore(case)
        self.assertEqual(self.opened, [])
        self.assertEqual(case.job.sets, 0)

    def test_open_job_acl_failure_retains_owner_and_never_blindly_reopens(self):
        case = self.case()
        failure = NativeJobError("native_job_security_unavailable")
        retained = object()
        failure._native_job_cleanup = retained
        with patch.object(self, "open_job", side_effect=failure) as opener:
            self.capture(job_opener=opener)
            self.dead()
            with self.assertRaises(NativeJobError) as caught:
                self.restore(case)
            self.assertIs(caught.exception._recovery_owner, self.recovery)
            with self.assertRaisesRegex(LifecycleError, "job_open_unverified"):
                self.restore(case)
            self.assertEqual(opener.call_count, 1)
        self.assertIs(self.recovery._entries[case.spec.execution_id].open_error._native_job_cleanup, retained)
        self.assertEqual(case.job.sets, 0)

    def test_set_ack_loss_retains_same_job_and_retry_queries_without_second_set(self):
        case = self.case()
        self.capture()
        self.dead()
        case.job.disable_error = OSError("fixture Set acknowledgement unknown")
        with self.assertRaises(OSError):
            self.restore(case)
        case.job.disable_error = None
        self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(len(self.opened), 1)

    def test_independent_query_failure_after_disable_does_not_settle_journal(self):
        case = self.case()
        self.capture()
        self.dead()
        case.job.on_disable = lambda: setattr(case.job, "query_error", OSError("fixture readback unavailable"))
        with self.assertRaises(OSError) as caught:
            self.restore(case)
        self.assertFalse(caught.exception.recovery_result.native_disabled)
        self.assertEqual(self.record(case).last_applied, CAP)
        self.assertEqual(case.job.sets, 1)

    def test_publish_ack_loss_requires_new_positive_publication_and_no_second_set(self):
        case = self.case()
        self.capture()
        self.dead()
        publish = self.journal.publish
        committed = []
        def lost_ack(record, **kwargs):
            committed.append(publish(record, **kwargs))
            raise RecoveryJournalError("manifest_publication_unverified", publication_may_have_occurred=True)
        with patch.object(self.journal, "publish", side_effect=lost_ack):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.recovery_result.native_disabled)
        self.assertFalse(caught.exception.recovery_result.journal_settled)
        self.restore(case)
        self.assertEqual(self.record(case).manifest_seq, committed[0].manifest_seq + 1)
        self.assertEqual(case.job.sets, 1)

    def test_journal_close_uncertainty_retains_file_custody_without_repeated_io(self):
        case = self.case()
        self.capture()
        self.dead()
        failure = RecoveryJournalError("manifest_read_unavailable")
        failure._journal_cleanup_owner = object()
        with patch.object(self.journal, "read", side_effect=failure) as read:
            with self.assertRaises(RecoveryJournalError):
                self.restore(case)
            with self.assertRaisesRegex(LifecycleError, "journal_cleanup_unverified"):
                self.restore(case)
            self.assertEqual(read.call_count, 1)
        self.assertEqual(case.job.sets, 0)

    def test_native_release_uncertainty_poison_blocks_reacquire_and_close(self):
        case = self.case()
        self.capture()
        self.dead()
        policy = self.recovery._policy_mutex
        policy.release_error = OSError("fixture native release unknown")
        with self.assertRaises(OSError) as caught:
            self.restore(case)
        self.assertTrue(caught.exception.recovery_result.native_disabled)
        self.assertFalse(caught.exception.recovery_result.journal_settled)
        self.assertTrue(policy.acquired)
        with patch.object(policy, "acquire", side_effect=AssertionError("must not reacquire")) as acquire:
            with self.assertRaisesRegex(LifecycleError, "fence_uncertain"):
                self.restore(case)
            acquire.assert_not_called()
        with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
            self.recovery.close_verified(case.spec.execution_id)
        self.assertFalse(case.job.closed)

    def test_recovery_instance_contention_gives_no_second_writer(self):
        case = self.case()
        self.capture()
        self.dead()
        mutex = self.recovery._instance_mutex
        self.kernel_mutexes[mutex.name] = object()
        with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_timeout"):
            self.restore(case)
        self.assertEqual(self.opened, [])
        self.assertEqual(case.job.sets, 0)
        self.kernel_mutexes.clear()
        self.restore(case)
        self.assertEqual(case.job.sets, 1)

    def test_abandoned_fence_permits_only_dead_guardian_restore_and_no_ledger_clear(self):
        case = self.case()
        self.capture()
        before = self.snapshot()
        self.recovery._policy_mutex.abandoned = True
        self.dead()
        self.restore(case)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(case.job.sets, 1)

    def test_verified_close_releases_only_recovery_handles_not_live_allocation(self):
        case = self.case()
        self.capture()
        self.dead()
        before = self.snapshot()
        self.restore(case)
        self.recovery.close_verified(case.spec.execution_id)
        self.assertTrue(case.job.closed)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.recovery.retained_execution_ids, ())
        self.recovery.close()
        self.assertIsNotNone(self.current._handle)
        self.assertIsNotNone(self.old._handle)

    def test_close_refuses_unrestored_inventory(self):
        case = self.case()
        self.capture()
        with self.assertRaises(LifecycleError):
            self.restore(case)
        with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
            self.recovery.close()
        self.assertFalse(case.job.closed)

    def failing_job_factory(self, failures):
        """Fail only per-Job constructors; capture's two fences stay real fixtures."""
        calls = []
        def factory(*args):
            if len(self.recovery_mutexes) < 2:
                return self.mutex_factory(*args)
            calls.append(args)
            if failures:
                raise failures.pop(0)
            return self.mutex_factory(*args)
        return factory, calls

    def test_unverified_job_mutex_constructor_failure_is_sticky_with_original_error(self):
        case = self.case()
        original = RuntimeError("fixture constructor interruption")
        factory, calls = self.failing_job_factory([original])
        self.capture(mutex_factory=factory)
        self.dead()
        with self.assertRaises(RuntimeError) as caught:
            self.restore(case)
        self.assertIs(caught.exception, original)
        self.assertIs(original._recovery_owner, self.recovery)
        for _ in range(3):
            with self.assertRaisesRegex(LifecycleError, "recovery_job_mutex_unverified"):
                self.restore(case)
        # No replacement object is allocated while the first outcome is unknown.
        self.assertEqual(len(calls), 1)
        self.assertIs(self.recovery._entries[case.spec.execution_id].mutex_error, original)
        self.assertEqual((self.opened, case.job.sets), ([], 0))
        self.assertEqual(self.kernel_mutexes, {})
        with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
            self.recovery.close()

    def test_clean_job_mutex_constructor_failure_retains_nothing_and_may_retry(self):
        case = self.case()
        factory, calls = self.failing_job_factory([NativePolicyMutexError("policy_mutex_create_failed", 8)])
        self.capture(mutex_factory=factory)
        self.dead()
        with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_create_failed"):
            self.restore(case)
        self.assertIsNone(self.recovery._entries[case.spec.execution_id].mutex_error)
        self.restore(case)
        self.assertEqual((len(calls), case.job.sets), (2, 1))

    def test_partial_job_mutex_owner_is_closed_before_any_replacement(self):
        case = self.case()
        class Partial:
            def __init__(self):
                self.attempts, self.error = 0, OSError("fixture close FALSE")
            def close(self):
                self.attempts += 1
                if self.error is not None:
                    raise self.error
        partial = Partial()
        original = NativePolicyMutexError("policy_mutex_identity_unavailable", 5)
        original.add_note("policy_mutex_handle_close_failed win32=6")
        original._policy_mutex_cleanup = (partial,)
        factory, calls = self.failing_job_factory([original])
        self.capture(mutex_factory=factory)
        self.dead()
        with self.assertRaises(NativePolicyMutexError) as caught:
            self.restore(case)
        self.assertIs(caught.exception, original)
        with self.assertRaisesRegex(LifecycleError, "recovery_job_mutex_unverified"):
            self.restore(case)
        self.assertEqual((len(calls), partial.attempts, case.job.sets), (1, 1, 0))
        self.assertEqual(original._policy_mutex_cleanup, (partial,))
        partial.error = None
        self.restore(case)
        self.assertEqual((len(calls), partial.attempts, case.job.sets), (2, 2, 1))
        self.assertEqual(original._policy_mutex_cleanup, ())

    def test_close_after_failed_capture_cannot_drop_owner_held_only_by_the_error(self):
        self.case()
        class Partial:
            def __init__(self):
                self.attempts, self.error = 0, OSError("fixture close FALSE")
            def close(self):
                self.attempts += 1
                if self.error is not None:
                    raise self.error
        partial = Partial()
        original = NativePolicyMutexError("policy_mutex_identity_unavailable", 5)
        original._policy_mutex_cleanup = (partial,)
        def factory(*args):
            raise original
        with self.assertRaises(NativePolicyMutexError) as caught:
            self.capture(mutex_factory=factory)
        self.assertIs(caught.exception, original)
        owner = original._recovery_owner
        for _ in range(2):
            with self.assertRaisesRegex(LifecycleError, "custody_unsettled") as refused:
                owner.close()
            self.assertIs(refused.exception._recovery_owner, owner)
        self.assertFalse(owner._closed)
        # The still-needed current/guardian duplicates were not closed early.
        self.assertIsNotNone(owner._current._handle)
        self.assertIsNotNone(owner._guardian._handle)
        partial.error = None
        owner.close()
        self.assertTrue(owner._closed)
        self.assertEqual(partial.attempts, 3)
        self.assertIsNotNone(self.old._handle)

    def test_close_refuses_a_capture_cleanup_note_that_no_owner_accounts_for(self):
        self.case()
        original = NativePolicyMutexError("policy_mutex_create_failed", 8)
        original.add_note("lifecycle_connection_cleanup_failed")
        def factory(*args):
            raise original
        with self.assertRaises(NativePolicyMutexError) as caught:
            self.capture(mutex_factory=factory)
        owner = caught.exception._recovery_owner
        for _ in range(2):
            with self.assertRaisesRegex(LifecycleError, "custody_unsettled") as refused:
                owner.close()
            self.assertIs(refused.exception._recovery_owner, owner)
        self.assertFalse(owner._closed)
        self.assertIsNotNone(owner._current._handle)
        self.assertIsNotNone(owner._guardian._handle)

    def test_close_retry_after_mutex_failure_closes_only_what_is_still_open(self):
        case = self.case()
        self.capture()
        self.dead()
        self.restore(case)
        entry = self.recovery._entries[case.spec.execution_id]
        with patch.object(case.job, "close", wraps=case.job.close) as job_close:
            with patch.object(entry.mutex, "close", side_effect=OSError("fixture close FALSE")):
                with self.assertRaises(OSError):
                    self.recovery.close_verified(case.spec.execution_id)
            self.assertEqual(job_close.call_count, 1)
            self.recovery.close_verified(case.spec.execution_id)
            self.assertEqual(job_close.call_count, 1)
        self.assertEqual(self.recovery.retained_execution_ids, ())
        self.assertTrue(case.job.closed)

    def test_close_after_failed_capture_retries_identity_duplicate_cleanup(self):
        self.case()
        from sentinel.adaptive.identity import IdentityUnavailable
        class Duplicate:
            closed = 0
            def close(self):
                Duplicate.closed += 1
        failure = IdentityUnavailable("duplicate_failed", 6)
        failure._identity_handle_cleanup = (Duplicate(),)
        with patch.object(type(self.old), "duplicate", side_effect=failure):
            with self.assertRaises(IdentityUnavailable):
                self.capture()
        owner = failure._recovery_owner
        owner.close()
        self.assertEqual((Duplicate.closed, failure._identity_handle_cleanup), (1, ()))
