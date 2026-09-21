"""Orphan drain against a real isolated ledger and journal, native fixtures.

Nothing here establishes Windows behaviour. Processes, Jobs, CPU control and
mutexes are explicit synthetic backends; no process is launched or stopped, no
live Job is touched and adaptive mode stays off in every case below.
"""
from contextlib import contextmanager
from dataclasses import replace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.guardian_lifecycle import GuardianLifecycle, job_mutex_instance
from sentinel.adaptive.native_job import JobAccess
from sentinel.adaptive.orphan_lifecycle import OrphanDrainOwner
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.recovery_owner import RecoveryOwner
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease
from tests import test_adaptive_guardian_lifecycle as fixture
from tests import test_adaptive_guardian_restore as restore_fixture
from tests.test_adaptive_guardian_launch import ProcessBackend
from tests.test_adaptive_guardian_restore import RestoreJob
from tests.test_adaptive_recovery_owner import Mutex


CAP, DISABLED = fixture.CAP, fixture.DISABLED
NOW = fixture.fixtures.NOW


class SharedPolicy:
    """The ledger POLICY provider, on the same registry as the owner fences.

    One namespace for both roles. A second acquisition of the held name fails
    here exactly as the native mutex refuses a recursive entry, so these tests
    would notice if the drain tried to hold POLICY twice.
    """

    def __init__(self, registry, events, logon_id):
        self.registry, self.events, self.logon_id = registry, events, logon_id

    def current_logon(self):
        return self.logon_id

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        if self.registry.get(binding.name) is not None:
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.registry[binding.name] = self
        self.events.append(("enter", binding.name))
        try:
            yield PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, False)
        finally:
            del self.registry[binding.name]
            self.events.append(("leave", binding.name))


class OrphanDrainTests(unittest.TestCase):
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    rewrite_manifest = fixture.GuardianLifecycleTests.rewrite_manifest
    sql = fixture.GuardianLifecycleTests.sql
    allocation = fixture.GuardianLifecycleTests.allocation
    row = fixture.GuardianLifecycleTests.row
    seed_slot = restore_fixture.GuardianRestoreTests.seed_slot
    slot = restore_fixture.GuardianRestoreTests.slot
    barrier = restore_fixture.GuardianRestoreTests.barrier

    def setUp(self):
        fixture.GuardianLifecycleTests.setUp(self)
        self.native = ProcessBackend()
        self.current = self.native.process(fixture.GUARDIAN)
        self.old_identity = replace(fixture.GUARDIAN, pid=fixture.GUARDIAN.pid + 90000,
                                    created_filetime_100ns=fixture.GUARDIAN.created_filetime_100ns + 700)
        self.old = self.native.process(self.old_identity)
        self.kernel_mutexes, self.events, self.opened = {}, [], []
        self.jobs = {}

    def case(self, *, control=CAP, slot=True, members=()):
        case = self.seed_started()
        self.rewrite_manifest(case, manifest_seq=2, guardian_identity=self.old_identity,
                              last_applied=control)
        job = RestoreJob(case.record, case.job.handle)
        if control not in (None, DISABLED):
            job.control = {"flags": 5, "rate_bp": control.cpu_rate_bp}
        case.job = self.jobs[case.record.job_name] = job
        if slot:
            self.seed_slot(case)
        else:
            self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        job.members[:] = list(members)
        return case

    def mutex_factory(self, *args):
        return Mutex(self.kernel_mutexes, self.events, *args)

    def open_job(self, name, nonce, logon, *, access):
        self.assertEqual(access, JobAccess.CONTROL)
        job = self.jobs[name]
        self.assertEqual(job.nonce, nonce)
        self.opened.append(name)
        return job

    def capture(self):
        self.capture_store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        self.recovery = RecoveryOwner.capture(self.capture_store, self.journal,
            guardian=self.old, guardian_epoch=fixture.EPOCH, current=self.current,
            mutex_factory=self.mutex_factory, job_opener=self.open_job)
        self.drain_store = LifecycleStore(self.db, existing_path=True,
            policy_provider=SharedPolicy(self.kernel_mutexes, self.events, self.old_identity.logon_id))
        self.orphan = OrphanDrainOwner(self.drain_store, self.recovery)
        return self.orphan

    def prepared(self, **kwargs):
        """Seed one case, witness the guardian die, restore, then start clean."""
        case = self.case(**kwargs)
        self.capture()
        self.native.objects[self.old_identity].status = IdentityStatus.DEAD
        self.recovery.restore(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        self.events.clear()
        return case

    def drain(self, case, *, now=None):
        return self.orphan.drain(case.spec.execution_id,
                                 creation_nonce=case.record.creation_nonce, now=now)

    def fences(self, case):
        job = PolicyBinding(job_mutex_instance(case.spec.execution_id, case.record.creation_nonce),
                            self.old_identity.logon_id)
        return [self.recovery._instance_binding.name, self.recovery.binding.name, job.name]

    def archived(self, case):
        return [row["outcome"] for row in self.connection().execute(
            "SELECT outcome FROM executions WHERE reservation_id=?", (case.spec.reservation.id,))]

    def barrier_clears(self):
        """The lazily created C3 audit rows, or None while the table is absent."""
        conn = self.connection()
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_barrier_clears'").fetchone() is None:
            return None
        return [dict(row) for row in conn.execute("SELECT * FROM adaptive_barrier_clears")]

    def entry_nonce(self):
        return self.connection().execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0]

    def test_empty_job_releases_the_slot_and_finishes_under_the_three_fences(self):
        case = self.prepared()
        result = self.drain(case, now=NOW + 40)
        self.assertEqual((result.state, result.active_processes, result.slot_released, result.finalized),
                         ("FINISHED", 0, True, True))
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archived(case), ["managed_finished"])
        # Clarification C3: the finished Job's own barrier is cleared in the
        # same pass, and the RESTORED slot stays as the durable boundary.
        self.assertEqual((result.barrier_cleared, result.barrier_reason), (True, None))
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("RESTORED", "NONE"))
        self.assertEqual([name for kind, name in self.events if kind == "enter"], self.fences(case))
        # No Set, no reopen and no second cap: the drain only reads the Job.
        self.assertEqual((case.job.sets, self.opened), (1, [case.record.job_name]))
        self.assertFalse(case.job.closed)

    def test_drain_takes_the_policy_fence_and_cannot_enter_while_it_is_owned(self):
        case = self.prepared()
        self.kernel_mutexes[self.recovery.binding.name] = object()
        with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_timeout"):
            self.drain(case)
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual(self.slot()["slot_state"], "HELD")
        del self.kernel_mutexes[self.recovery.binding.name]
        self.assertTrue(self.drain(case, now=NOW + 40).finalized)

    def test_alive_or_unknown_guardian_refuses_every_drain(self):
        case = self.prepared()
        for status in (IdentityStatus.ALIVE, IdentityStatus.UNKNOWN):
            self.native.objects[self.old_identity].status = status
            with self.assertRaisesRegex(LifecycleError, "recovery_guardian_death_unverified"):
                self.drain(case)
        # Death is checked before the first fence, so nothing was acquired.
        self.assertEqual(self.events, [])
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("HELD", "CONTROLLING"))

    def test_a_cap_applied_again_after_the_restore_refuses_the_drain(self):
        case = self.prepared()
        case.job.control = {"flags": 5, "rate_bp": CAP.cpu_rate_bp}
        with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
            self.drain(case)
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("HELD", "CONTROLLING"))
        self.assertEqual(case.job.sets, 1)
        case.job.control = {"flags": 0, "rate_bp": 10000}
        self.assertTrue(self.drain(case, now=NOW + 40).finalized)

    def test_a_live_member_keeps_the_slot_allocation_and_row_untouched(self):
        case = self.prepared(members=(4321,))
        allocation = self.allocation(case)
        result = self.drain(case, now=NOW + 40)
        self.assertEqual((result.state, result.active_processes, result.slot_released, result.finalized),
                         ("RUNNING", 1, False, False))
        self.assertEqual((result.barrier_cleared, result.barrier_reason), (False, None))
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual(self.allocation(case), allocation)
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("HELD", "CONTROLLING"))
        self.assertEqual(self.archived(case), [])
        self.assertIsNone(self.barrier_clears())
        # The same production call finishes the scope once the member is gone.
        case.job.members.clear()
        self.assertTrue(self.drain(case, now=NOW + 50).finalized)
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("RESTORED", "NONE"))

    def test_an_unrestored_or_unknown_scope_is_never_drained(self):
        case = self.case()
        self.capture()
        for _ in range(2):
            with self.assertRaisesRegex(LifecycleError, "orphan_custody_missing"):
                self.drain(case)
        self.native.objects[self.old_identity].status = IdentityStatus.DEAD
        with patch.object(case.job, "disable", side_effect=OSError("fixture Set unknown")):
            with self.assertRaises(OSError):
                self.recovery.restore(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        with self.assertRaisesRegex(LifecycleError, "orphan_restore_unsettled"):
            self.drain(case)
        with self.assertRaisesRegex(LifecycleError, "orphan_custody_missing"):
            self.orphan.drain(case.spec.execution_id, creation_nonce=uuid4().hex)
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("HELD", "CONTROLLING"))

    def forged(self, case, **changes):
        genuine = self.orphan.evidence_scope

        @contextmanager
        def provider(operation, row, caller):
            with genuine(operation, row, caller) as proof:
                yield replace(proof, **changes)

        with patch.object(self.drain_store, "evidence_provider", provider):
            with self.assertRaisesRegex(LifecycleError, "job_scope_evidence_mismatch"):
                self.drain(case)
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual((self.slot()["slot_state"], self.barrier()), ("HELD", "CONTROLLING"))
        self.assertIsNotNone(self.allocation(case))
        # The ledger was asked to change, so the POLICY entry stays uncertain.
        self.assertIsNotNone(self.connection().execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_evidence_carrying_a_foreign_guardian_epoch_is_refused_by_the_store(self):
        self.forged(self.prepared(), guardian_epoch="successor-epoch")

    def test_evidence_carrying_a_foreign_job_nonce_is_refused_by_the_store(self):
        self.forged(self.prepared(), job_nonce=uuid4().hex)

    def test_the_drain_owner_offers_no_begin_tighten_heartbeat_or_launch(self):
        case = self.prepared()
        self.assertEqual({name for name in dir(self.orphan) if not name.startswith("_")},
                         {"drain", "evidence_scope", "recovery", "retained_execution_ids", "store"})
        row = self.row(case)
        for operation in ("register_scope", "prepare", "claim", "bind_root", "heartbeat",
                          "control_begin", "control_tighten", "root_exit"):
            with self.assertRaisesRegex(LifecycleError, "orphan_evidence_operation_unsupported"):
                with self.orphan.evidence_scope(operation, row, case.record.wrapper_identity):
                    pass
        # Even the two supported operations exist only inside a fenced drain.
        for operation in ("control_restore", "finalize"):
            with self.assertRaisesRegex(LifecycleError, "orphan_scope_required"):
                with self.orphan.evidence_scope(operation, row, case.record.wrapper_identity):
                    pass
        self.assertEqual(case.job.sets, 1)

    def test_a_replacement_guardian_identity_is_still_refused(self):
        case = self.prepared(slot=False)
        successor = replace(fixture.GUARDIAN,
                            created_filetime_100ns=fixture.GUARDIAN.created_filetime_100ns + 5000)
        replacement = GuardianLifecycle(
            LifecycleStore(self.db, existing_path=True, policy_provider=self.policy), self.journal,
            guardian=self.native.process(successor), mutex_factory=self.mutex_factory)
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_binding_mismatch"):
            replacement.adopt_started(case.spec.execution_id, job=case.job,
                wrapper=self.native.process(case.record.wrapper_identity),
                root=self.native.process(case.record.root_identity))
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual(self.journal.read(case.spec.execution_id,
            creation_nonce=case.record.creation_nonce).guardian_identity, self.old_identity)
        self.assertEqual(case.job.sets, 1)

    def test_the_drain_finishes_a_scope_that_never_held_a_control_slot(self):
        case = self.prepared(slot=False)
        result = self.drain(case, now=NOW + 40)
        self.assertEqual((result.slot_released, result.finalized), (False, True))
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        # No slot names this execution, so this barrier belongs to someone
        # else. Nothing is asked for and nothing is recorded.
        self.assertEqual((self.slot(), self.barrier()), (None, "RECOVERY_HOLD"))
        self.assertEqual((result.barrier_cleared, result.barrier_reason), (False, None))
        self.assertIsNone(self.barrier_clears())

    # --- clarification C3: the finished Job's own barrier --------------------

    def test_the_clear_records_one_audit_row_carrying_the_row_and_slot_fields(self):
        case = self.prepared()
        slot = self.slot()
        result = self.drain(case, now=NOW + 40)
        self.assertTrue(result.barrier_cleared)
        rows = self.barrier_clears()
        self.assertEqual(len(rows), 1)
        record = rows[0]
        self.assertEqual(record["registry_revision"],
                         self.connection().execute(
                             "SELECT registry_revision FROM adaptive_runtime").fetchone()[0])
        self.assertEqual((record["execution_id"], record["reason"], record["finished_at"]),
                         (case.spec.execution_id, "finished_job", NOW + 40))
        self.assertEqual((record["slot_id"], record["guardian_epoch"]),
                         (slot["slot_id"], case.record.guardian_epoch))
        self.assertEqual(record["slot_revision"], self.slot()["slot_revision"])
        # The clear stamps its own wall clock, never the ledger fixture clock.
        self.assertIsInstance(record["cleared_at"], float)
        # Nothing was actuated: the Job was read, never set or reopened.
        self.assertEqual((case.job.sets, self.opened), (1, [case.record.job_name]))

    def test_a_repeat_drain_after_the_clear_asks_for_nothing_and_adds_no_row(self):
        case = self.prepared()
        self.assertTrue(self.drain(case, now=NOW + 40).barrier_cleared)
        before = self.barrier_clears()
        result = self.drain(case, now=NOW + 50)
        self.assertEqual((result.state, result.finalized), ("FINISHED", True))
        self.assertEqual((result.barrier_cleared, result.barrier_reason), (False, None))
        self.assertEqual(self.barrier_clears(), before)
        self.assertEqual(self.barrier(), "NONE")

    def test_an_unproven_terminal_row_keeps_the_barrier_and_clears_on_a_later_pass(self):
        case = self.prepared()
        refusal = LifecycleError("retained_terminal_unverified")
        with patch.object(self.drain_store, "assert_retained_terminal", side_effect=refusal):
            first = self.drain(case, now=NOW + 40)
            self.assertEqual((first.finalized, first.barrier_cleared, first.barrier_reason),
                             (True, False, "retained_terminal_unverified"))
            self.assertEqual(self.barrier(), "RECOVERY_HOLD")
            self.assertIsNone(self.barrier_clears())
            # The early FINISHED branch refuses before the ledger is asked for
            # anything, so the opportunistic pass leaves no entry nonce behind.
            second = self.drain(case, now=NOW + 50)
            self.assertEqual((second.finalized, second.barrier_cleared, second.barrier_reason),
                             (True, False, "retained_terminal_unverified"))
            self.assertIsNone(self.entry_nonce())
        # The next prepare works and the same production call clears once the
        # proof passes again.
        third = self.drain(case, now=NOW + 60)
        self.assertEqual((third.finalized, third.barrier_cleared, third.barrier_reason),
                         (True, True, None))
        self.assertEqual(self.barrier(), "NONE")
        self.assertEqual(len(self.barrier_clears()), 1)
        self.assertEqual(self.barrier_clears()[0]["finished_at"], NOW + 40)

    def test_a_member_seen_after_the_terminal_row_keeps_the_barrier(self):
        case = self.prepared()
        refusal = LifecycleError("retained_terminal_unverified")
        with patch.object(self.drain_store, "assert_retained_terminal", side_effect=refusal):
            self.assertTrue(self.drain(case, now=NOW + 40).finalized)
        # The ledger proof would pass now, but this pass reads a member in the
        # Job, which contradicts the terminal row. The clear is never asked for.
        case.job.members[:] = [4321]
        result = self.drain(case, now=NOW + 50)
        self.assertEqual((result.state, result.active_processes, result.finalized),
                         ("FINISHED", 1, True))
        self.assertEqual((result.barrier_cleared, result.barrier_reason),
                         (False, "finished_job_not_empty"))
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")
        self.assertIsNone(self.barrier_clears())
        self.assertIsNone(self.entry_nonce())
        case.job.members.clear()
        self.assertTrue(self.drain(case, now=NOW + 60).barrier_cleared)
