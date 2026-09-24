"""C4 early guardian death: real isolated ledger and synthetic native custody.

The fixture exposes actual VerifiedProcess ownership over synthetic kernel
objects. No native child/Job is created, killed or controlled; these tests are
not Windows capability, crash-recovery timing or promotion evidence.
"""
from dataclasses import replace
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.recovery_owner import RecoveryOwner, RetainedGuardianCreation
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor import GuardianSupervisor
from tests import test_adaptive_guardian_lifecycle as lifecycle
from tests import test_adaptive_recovery_owner as recovery_fixtures
from tests.test_adaptive_guardian_launch import ProcessBackend


class CreationBackend(ProcessBackend):
    """Borrowed CreateProcess fixture handles reference real fixture objects."""

    def duplicate_process(self, handle):
        duplicate = self.new_handle(self.state(handle))
        self.events.append(("duplicate_creation", handle, duplicate))
        return duplicate

    def duplicate_into(self, handle, output, *, source_process=None):
        super().duplicate_into(handle, output, source_process=source_process)
        if source_process is None:
            self.events.append(("duplicate_creation", handle, output.value))

    def open_process(self, pid):
        raise AssertionError("early recovery must never reopen a PID")


class EarlyGuardianDeathTests(unittest.TestCase):
    def setUp(self):
        self.fixture = recovery_fixtures.RecoveryOwnerTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.native = CreationBackend()
        self.fixture.current = self.fixture.native.process(lifecycle.GUARDIAN)
        self.fixture.old = self.fixture.native.process(self.fixture.old_identity)
        self.native = self.fixture.native
        self.case = self.fixture.case()
        self.store = LifecycleStore(self.fixture.db, existing_path=True,
                                    policy_provider=self.fixture.policy)

    def creation(self, *, epoch=lifecycle.EPOCH):
        with patch("sentinel.adaptive.identity._backend", return_value=self.native):
            return RetainedGuardianCreation.from_creation_handle(
                self.fixture.old._handle, expected_pid=self.fixture.old_identity.pid,
                expected_logon_id=self.fixture.old_identity.logon_id, guardian_epoch=epoch)

    def capture(self, created, *, epoch=lifecycle.EPOCH, mutex_factory=None):
        return RecoveryOwner.capture_created(self.store, self.fixture.journal,
            creation=created, guardian_epoch=epoch, current=self.fixture.current,
            mutex_factory=mutex_factory or self.fixture.mutex_factory,
            job_opener=self.fixture.open_job)

    def attach(self, created):
        return GuardianSupervisor.attach_created(self.store, self.fixture.journal,
            creation=created, guardian_epoch=lifecycle.EPOCH, current=self.fixture.current,
            mutex_factory=self.fixture.mutex_factory, job_opener=self.fixture.open_job)

    def test_creation_factory_duplicates_original_handle_and_binds_host_epoch(self):
        raw = self.fixture.old._handle
        created = self.creation()
        self.assertEqual(created.creator_pid, os.getpid())
        self.assertEqual(created.guardian_epoch, lifecycle.EPOCH)
        self.assertEqual(created.process.identity, self.fixture.old_identity)
        self.assertNotEqual(created.process._handle, raw)
        self.assertIn(("duplicate_creation", raw, created.process._handle), self.native.events)
        created.close()
        created.close()
        self.assertFalse(self.native.handles[raw].closed)
        self.assertEqual(self.fixture.old.observe().status, IdentityStatus.ALIVE)

    def test_factory_rejects_untyped_construction_and_invalid_epoch_before_duplication(self):
        with self.assertRaisesRegex(LifecycleError, "guardian_creation_factory_required"):
            RetainedGuardianCreation(object())
        for epoch in (None, "", "x\ny", "x" * 129):
            with self.subTest(epoch=epoch):
                before = list(self.native.events)
                with self.assertRaisesRegex(LifecycleError, "recovery_epoch_invalid") as caught:
                    self.creation(epoch=epoch)
                caught.exception._guardian_creation_owner.close()
                self.assertEqual(before, self.native.events)

    def test_factory_identity_mismatch_closes_only_new_duplicate(self):
        raw = self.fixture.old._handle
        with patch("sentinel.adaptive.identity._backend", return_value=self.native):
            with self.assertRaisesRegex(IdentityUnavailable, "identity_mismatch") as caught:
                RetainedGuardianCreation.from_creation_handle(raw,
                    expected_pid=self.fixture.old_identity.pid + 1,
                    expected_logon_id=self.fixture.old_identity.logon_id,
                    guardian_epoch=lifecycle.EPOCH)
        self.assertFalse(self.native.handles[raw].closed)
        copied = [event[2] for event in self.native.events if event[0] == "duplicate_creation"]
        self.assertEqual(len(copied), 1)
        self.assertTrue(self.native.handles[copied[0]].closed)
        caught.exception._guardian_creation_owner.close()

    def test_capture_created_restores_early_dead_child_without_pid_reopen(self):
        self.fixture.dead()
        created = self.creation()
        before = self.fixture.snapshot()
        owner = self.capture(created)
        self.assertEqual(owner.guardian_identity, self.fixture.old_identity)
        self.assertNotEqual(owner._guardian._handle, created.process._handle)
        self.assertEqual(owner.observe_guardian().status, IdentityStatus.DEAD)
        result = owner.restore(self.case.spec.execution_id,
                               creation_nonce=self.case.record.creation_nonce)
        self.assertTrue(result.native_disabled and result.journal_settled)
        self.assertEqual(self.case.job.sets, 1)
        self.assertEqual(before, self.fixture.snapshot())
        owner.close_verified(self.case.spec.execution_id)
        owner.close()
        self.assertEqual(created.process.observe().status, IdentityStatus.DEAD)
        created.close()

    def test_pid_reuse_never_replaces_original_creation_object(self):
        created = self.creation()
        self.fixture.dead()
        reused = replace(self.fixture.old_identity,
                         created_filetime_100ns=self.fixture.old_identity.created_filetime_100ns + 1)
        new_process = self.native.process(reused)
        owner = self.capture(created)
        self.assertEqual(owner.guardian_identity, self.fixture.old_identity)
        self.assertEqual(owner.observe_guardian().status, IdentityStatus.DEAD)
        self.assertEqual(new_process.observe().status, IdentityStatus.ALIVE)
        owner.close()
        created.close()

    def test_normal_capture_still_requires_alive_guardian(self):
        self.fixture.dead()
        with self.assertRaisesRegex(LifecycleError, "capture_guardian_not_alive") as caught:
            RecoveryOwner.capture(self.store, self.fixture.journal, guardian=self.fixture.old,
                guardian_epoch=lifecycle.EPOCH, current=self.fixture.current,
                mutex_factory=self.fixture.mutex_factory, job_opener=self.fixture.open_job)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.opened, [])

    def test_alive_unknown_and_mismatched_observations_refuse_created_capture(self):
        created = self.creation()
        for status in (IdentityStatus.ALIVE, IdentityStatus.UNKNOWN):
            with self.subTest(status=status):
                self.native.objects[self.fixture.old_identity].status = status
                with self.assertRaisesRegex(LifecycleError, "created_guardian_not_dead") as caught:
                    self.capture(created)
                caught.exception._recovery_owner.close()
        self.fixture.dead()
        wrong = replace(self.fixture.old_identity, pid=self.fixture.old_identity.pid + 1)
        with patch.object(created.process, "observe",
                          return_value=IdentityObservation(wrong, IdentityStatus.DEAD)):
            with self.assertRaisesRegex(LifecycleError, "created_guardian_not_dead") as caught:
                self.capture(created)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.opened, [])
        self.assertEqual(self.case.job.sets, 0)
        created.close()

    def test_capture_rejects_plain_process_boolean_wrong_epoch_and_foreign_owner(self):
        self.fixture.dead()
        created = self.creation()
        for value in (self.fixture.old, True, None, {"dead": True}):
            with self.subTest(value=type(value).__name__):
                with self.assertRaisesRegex(LifecycleError, "creation_witness_unverified") as caught:
                    self.capture(value)
                caught.exception._recovery_owner.close()
        with self.assertRaisesRegex(LifecycleError, "creation_witness_unverified") as caught:
            self.capture(created, epoch="other-epoch")
        caught.exception._recovery_owner.close()
        with patch.object(created, "_creator_pid", os.getpid() + 1):
            with self.assertRaisesRegex(LifecycleError, "creation_witness_unverified") as caught:
                self.capture(created)
            caught.exception._recovery_owner.close()
            with self.assertRaisesRegex(LifecycleError, "creation_owner_changed"):
                created.close()
        self.assertEqual(self.fixture.opened, [])
        created.close()

    def test_closed_creation_witness_cannot_capture(self):
        created = self.creation()
        created.close()
        self.fixture.dead()
        with self.assertRaisesRegex(LifecycleError, "creation_witness_unverified") as caught:
            self.capture(created)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.opened, [])

    def test_death_is_rechecked_inside_fences(self):
        created = self.creation()
        self.fixture.dead()
        original = self.store._policy._runtime(self.fixture.connection())["policy_instance_id"]

        def factory(logon, instance):
            mutex = self.fixture.mutex_factory(logon, instance)
            if instance == original:
                mutex.before_enter = lambda: setattr(self.native.objects[self.fixture.old_identity],
                                                     "status", IdentityStatus.UNKNOWN)
            return mutex

        with self.assertRaisesRegex(LifecycleError, "created_guardian_not_dead") as caught:
            self.capture(created, mutex_factory=factory)
        self.assertIsNotNone(caught.exception._recovery_owner._guardian)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.kernel_mutexes, {})
        self.assertEqual(self.fixture.opened, [])
        created.close()

    def test_binding_change_under_fences_refuses_early_capture(self):
        created = self.creation()
        self.fixture.dead()
        original = self.store._policy._runtime(self.fixture.connection())["policy_instance_id"]

        def factory(logon, instance):
            mutex = self.fixture.mutex_factory(logon, instance)
            if instance == original:
                mutex.before_enter = lambda: self.fixture.sql(
                    "UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
            return mutex

        with self.assertRaisesRegex(LifecycleError, "capture_binding_changed") as caught:
            self.capture(created, mutex_factory=factory)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.opened, [])
        created.close()

    def test_uninitialized_binding_is_not_reconstructed_from_creation(self):
        created = self.creation()
        self.fixture.dead()
        self.fixture.sql("UPDATE adaptive_runtime SET policy_binding_initialized=0,"
                         "policy_instance_id=NULL,policy_logon_id=NULL")
        with self.assertRaisesRegex(LifecycleError, "capture_binding_unverified") as caught:
            self.capture(created)
        caught.exception._recovery_owner.close()
        self.assertEqual(self.fixture.opened, [])
        created.close()

    def test_created_attach_keeps_same_supervisor_after_inventory_failure(self):
        created = self.creation()
        self.fixture.dead()
        failure = OSError("fixture inventory unavailable")
        with patch.object(GuardianSupervisor, "_refresh_inventory", side_effect=failure):
            with self.assertRaises(OSError) as caught:
                self.attach(created)
        self.assertIs(caught.exception, failure)
        supervisor = caught.exception.supervisor_owner
        self.assertEqual(supervisor.recovery.observe_guardian().status, IdentityStatus.DEAD)
        self.assertIsNotNone(supervisor.recovery._guardian._handle)
        supervisor.recovery.close()
        self.assertEqual(created.process.observe().status, IdentityStatus.DEAD)
        created.close()

    def test_created_attach_discovers_exact_scope_without_closing_creation(self):
        created = self.creation()
        self.fixture.dead()
        supervisor = self.attach(created)
        self.assertEqual(supervisor.retained_execution_ids, (self.case.spec.execution_id,))
        self.assertEqual(supervisor.recovery.guardian_identity, self.fixture.old_identity)
        self.assertEqual(created.process.observe().status, IdentityStatus.DEAD)
        self.assertEqual(self.fixture.opened, [])

    def test_creation_close_retries_known_failure_but_quarantines_unknown_outcome(self):
        created = self.creation()
        owned = created.process._handle
        raw = self.fixture.old._handle
        real_close = self.native.close
        with patch.object(self.native, "close",
                          side_effect=IdentityUnavailable("process_handle_close_failed", 6)):
            with self.assertRaises(IdentityUnavailable) as caught:
                created.close()
        self.assertIs(caught.exception._guardian_creation_owner, created)
        self.assertIsNotNone(created.process._handle)
        created.close()
        self.assertTrue(self.native.handles[owned].closed)
        self.assertFalse(self.native.handles[raw].closed)

        ambiguous = self.creation()
        owned = ambiguous.process._handle

        def close_then_raise(handle):
            real_close(handle)
            raise RuntimeError("fixture completion unknown")

        with patch.object(self.native, "close", side_effect=close_then_raise):
            with self.assertRaises(RuntimeError) as caught:
                ambiguous.close()
        self.assertIs(caught.exception._guardian_creation_owner, ambiguous)
        with patch.object(self.native, "close", side_effect=AssertionError("must not retry")):
            with self.assertRaisesRegex(IdentityUnavailable, "close_outcome_unknown"):
                ambiguous.close()
        self.assertTrue(self.native.handles[owned].closed)
        self.assertFalse(self.native.handles[raw].closed)

    def test_failed_factory_retains_partial_duplicate_cleanup_owner(self):
        class Partial:
            def __init__(self):
                self.fail = True
                self.attempts = 0

            def close(self):
                self.attempts += 1
                if self.fail:
                    raise OSError("fixture cleanup unavailable")

        partial = Partial()
        failure = IdentityUnavailable("duplicate_failed", 6)
        failure._identity_handle_cleanup = (partial,)
        with patch.object(VerifiedProcess, "duplicate_from_handle", side_effect=failure):
            with self.assertRaises(IdentityUnavailable) as caught:
                self.creation()
        self.assertIs(caught.exception, failure)
        created = failure._guardian_creation_owner
        with self.assertRaisesRegex(LifecycleError, "creation_custody_unsettled"):
            created.close()
        self.assertEqual(failure._identity_handle_cleanup, (partial,))
        partial.fail = False
        created.close()
        self.assertEqual(partial.attempts, 2)
        self.assertFalse(self.native.handles[self.fixture.old._handle].closed)
