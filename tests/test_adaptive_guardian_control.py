"""Guardian control consumer over real isolated SQLite, journal and slot code.

The store, the control slot, the policy coordinator, the recovery journal and
the exemption ledger below are the production modules against real temporary
files. The Job, the processes and the mutexes are explicitly labelled synthetic
backends: they answer queries and count Set calls, and they contain nothing.
Passing here is therefore evidence about this consumer's decisions and durable
records, not about Windows Job containment, host support or any timing.

Every ledger mode write in this module is a fixture write to an isolated test
database. Nothing here promotes a mode, and no production configuration is read
or changed.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import json
import sqlite3
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import (
    ApplyResult, ControlProposal, CpuControl, CpuControlMode, CpuTarget, TICKS_PER_SECOND, Validity,
)
from sentinel.adaptive.control_slot import ControlSlotError, UncappedSample, clear_locked
from sentinel.adaptive.decision import TICKS_PER_MS
from sentinel.adaptive.exemption_sync import bind_policy_locked, commit_grant_locked
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.guardian_control import GrantRelation, GuardianControl
from sentinel.adaptive.recovery_journal import RecoveryJournalError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.exemptions import Exemptions
from tests import test_adaptive_decision as decisions
from tests import test_adaptive_guardian_lifecycle as fixture


DISABLED, CAP = fixture.DISABLED, fixture.CAP
EPOCH = fixture.EPOCH
BASE = 1_000_000_000_000
PROFILE = decisions.profile()


class ControlJob(fixture.Job):
    """Synthetic Job that counts every native Set, cap or disable alike."""

    def __init__(self, record, handle):
        super().__init__(record, handle)
        self.sets = 0
        self.calls = []
        self.set_error = None
        self.set_applies = True

    def set_cpu_rate_unverified(self, rate_bp):
        self._query()
        self.sets += 1
        self.calls.append(("set", rate_bp))
        if self.set_error is not None:
            raise self.set_error
        if self.set_applies:
            self.control = {"flags": 5, "rate_bp": rate_bp}

    def disable(self):
        self._query()
        self.sets += 1
        self.calls.append(("disable", None))
        self.control = {"flags": 0, "rate_bp": 10000}
        return SimpleNamespace(**self.control)

    def query_cpu(self):
        self.calls.append(("query", self.control["flags"]))
        return super().query_cpu()


class Authority:
    """Explicit host collaborator fixture; it proves nothing about this host."""

    def __init__(self):
        self.excluded_error = None
        self.exclusion_calls = 0

    def assert_ready(self):
        return None

    def assert_covered(self, row):
        return None

    def assert_excluded(self, row):
        self.exclusion_calls += 1
        if self.excluded_error is not None:
            raise self.excluded_error
        return None


class Scope:
    """Explicit grant relation fixture; no native identity evidence is claimed."""

    def __init__(self, result=GrantRelation.UNRELATED):
        self.result = result
        self.seen = []

    def relation(self, control, entry, row, lease):
        self.seen.append(dict(lease))
        return self.result


class GuardianControlTests(unittest.TestCase):
    # Reuse setup and helpers; never inherit another module's test methods.
    setUp = fixture.GuardianLifecycleTests.setUp
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    row = fixture.GuardianLifecycleTests.row
    sql = fixture.GuardianLifecycleTests.sql

    # --- fixture plumbing ----------------------------------------------------

    def start(self, *, mode="canary", cases=1):
        self.ticks = BASE + TICKS_PER_SECOND
        self.authority = Authority()
        self.scope = Scope()
        self.store = LifecycleStore(self.db, policy_provider=self.policy, existing_path=True)
        self.launch_owner = GuardianLaunchOwner(self.store, self.journal, guardian_epoch=EPOCH,
            authority=self.authority, guardian=self.guardian, mutex_factory=self.make_mutex)
        self.owner = self.launch_owner.lifecycle
        self.exemptions = Exemptions(self.directory, chain=lambda pid: [(pid, float(pid))])
        made = []
        for _ in range(cases):
            case = self.seed_started()
            case.job = ControlJob(case.record, case.job.handle)
            self.owner.adopt_started(case.spec.execution_id,
                job=case.job, wrapper=case.wrapper, root=case.root)
            made.append(case)
        with self.policy_held():
            bind_policy_locked(self.exemptions, self.store)
        # Fixture write to this isolated test database only. Nothing in the
        # production code path can set a ledger mode, and none is added here.
        self.sql("UPDATE adaptive_runtime SET mode=?", (mode,))
        self.control = GuardianControl(self.launch_owner, profile=PROFILE,
            exemptions=self.exemptions, scope=self.scope, clock=lambda: self.ticks)
        return made[0] if cases == 1 else tuple(made)

    @contextmanager
    def policy_held(self):
        guard = self.store._policy.prepare(fixture.fixtures.WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            yield guard

    def runtime(self):
        with self.connection() as conn:
            return dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def slot(self):
        with self.connection() as conn:
            found = conn.execute("SELECT * FROM adaptive_control_slot").fetchone()
            return None if found is None else dict(found)

    def actions(self):
        with self.connection() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT * FROM adaptive_actions ORDER BY decision_seq")]

    def proposal(self, case, *, seq=1, sample_seq=1, window_end=None, decision=None,
                 rate_bp=2500, **changes):
        runtime = self.runtime()
        window_end = BASE if window_end is None else window_end
        decision = window_end if decision is None else decision
        units = rate_bp * 8 / 10000
        values = dict(request_id=str(uuid4()), execution_id=case.spec.execution_id,
            guardian_epoch=EPOCH, policy_epoch=runtime["policy_instance_id"],
            sampler_epoch="sampler-a", clock_epoch="clock-a", config_revision="c" * 64,
            registry_revision=runtime["registry_revision"], exemption_revision_seen=0,
            decision_seq=seq, sample_seq=sample_seq, sample_window_end_tick_100ns=window_end,
            decision_tick_100ns=decision,
            target=CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, units, rate_bp, 8),
            reason="cpu_pressure")
        return ControlProposal(**(values | changes))

    def grant(self, pid=4321, *, now=None, minutes=60):
        # The snapshot reads active leases against wall clock time, so this
        # isolated fixture grant has to be current, not a fixed past instant.
        now = time.time() if now is None else now
        record = dict(id=uuid4().hex, root_pid=pid, root_started=float(pid), created_at=now,
                      expires_at=now + minutes * 60, reason="explicit isolated test grant",
                      revoked_at=None, owner_metadata="{}")
        with self.policy_held():
            return commit_grant_locked(self.exemptions, record,
                                       lifecycle_store=self.store, now=now)

    def sample(self, case, *, seq, window_start, window_end, observed, cpu_units=6.0):
        return UncappedSample(case.spec.execution_id, "sampler-a", "clock-a", seq,
                              window_start, window_end, observed, cpu_units)

    def uncapped_set(self, case, *, count=5, start=None, gap=TICKS_PER_SECOND, lag=0):
        start = self.boundary(case) if start is None else start
        return tuple(self.sample(case, seq=index + 10, window_start=start + index * gap,
                                 window_end=start + (index + 1) * gap,
                                 observed=start + (index + 1) * gap + lag)
                     for index in range(count))

    def boundary(self, case):
        rows = [row for row in self.actions()
                if row["execution_id"] == case.spec.execution_id and row["action_state"] == "RESTORED"]
        return rows[-1]["applied_tick_100ns"]

    def apply_cap(self, case, **changes):
        ack = self.control.apply(self.proposal(case, **changes), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.APPLIED)
        return ack

    # --- mode gate -----------------------------------------------------------

    def test_off_mode_refuses_every_proposal_with_zero_native_set(self):
        case = self.start(mode="off")
        ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_mode_unavailable")
        self.assertIsNone(ack.action_id)
        self.assertEqual(ack.applied_validity, Validity.UNKNOWN)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assertEqual(self.actions(), [])

    def test_shadow_mode_refuses_every_proposal_with_zero_native_set(self):
        case = self.start(mode="shadow")
        for seq in (1, 2, 3):
            ack = self.control.apply(self.proposal(case, seq=seq), now_tick_100ns=self.ticks)
            self.assertEqual(ack.result, ApplyResult.REJECTED)
            self.assertEqual(ack.reason, "control_mode_unavailable")
        self.assertEqual(case.job.sets, 0)
        self.assertEqual([call for call in case.job.calls if call[0] in {"set", "disable"}], [])
        self.assertIsNone(self.slot())

    # --- happy path ----------------------------------------------------------

    def test_apply_orders_intent_then_set_then_query_then_ack_then_audit(self):
        case = self.start()
        proposal = self.proposal(case)
        ack = self.control.apply(proposal, now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.APPLIED)
        self.assertEqual((ack.applied_flags, ack.applied_rate_bp), (5, 2500))
        self.assertEqual(ack.applied_validity, Validity.VALID)
        self.assertIsNone(ack.win32_error)
        stages = [call[0] for call in self.control.backend_calls
                  if call[1] == case.spec.execution_id]
        # The settle write is the second half of the durable intent: it records
        # what the Query actually returned, and it sits after that Query.
        self.assertEqual(stages, ["intent", "set", "query", "settle", "audit"])
        self.assertLess(stages.index("intent"), stages.index("set"))
        self.assertLess(stages.index("set"), stages.index("query"))
        self.assertLess(stages.index("query"), stages.index("audit"))
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.runtime()["admission_barrier"], "CONTROLLING")
        record = self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        self.assertIsNone(record.pending_intent)
        self.assertEqual(record.last_applied, CAP)
        rows = self.actions()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["action_state"], "APPLIED")
        self.assertEqual(rows[0]["action_id"], ack.action_id)
        self.assertEqual(rows[0]["applied_flags"], 5)

    def test_lease_matches_plan_formula_for_each_minimum_branch(self):
        case = self.start()
        lease_ticks = PROFILE.lease_ms * TICKS_PER_MS
        # Sample one second old: the sample window bounds the lease.
        ack = self.apply_cap(case, window_end=BASE)
        self.assertEqual(ack.lease_deadline_tick_100ns, BASE + lease_ticks)
        self.assertEqual(ack.intervention_deadline_tick_100ns,
                         BASE + PROFILE.intervention_max_ms * TICKS_PER_MS)
        self.assertLess(ack.lease_deadline_tick_100ns, self.ticks + lease_ticks)

    def test_lease_uses_now_when_the_sample_window_just_closed(self):
        case = self.start()
        self.ticks = BASE
        ack = self.apply_cap(case, window_end=BASE, decision=BASE)
        self.assertEqual(ack.lease_deadline_tick_100ns, BASE + PROFILE.lease_ms * TICKS_PER_MS)

    def test_renewal_is_bounded_by_the_original_intervention_deadline(self):
        case = self.start()
        first = self.apply_cap(case)
        intervention = first.intervention_deadline_tick_100ns
        # Renew three seconds before the original deadline: the lease cannot
        # reach beyond it even though six seconds of lease would fit.
        self.ticks = intervention - 3 * TICKS_PER_SECOND
        ack = self.control.apply(self.proposal(case, seq=2, sample_seq=2,
            window_end=self.ticks - TICKS_PER_SECOND, decision=self.ticks), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.RENEWED)
        self.assertEqual(ack.lease_deadline_tick_100ns, intervention)
        self.assertEqual(ack.intervention_deadline_tick_100ns, intervention)
        self.assertEqual(case.job.sets, 1)
        rows = self.actions()
        self.assertEqual([row["action_state"] for row in rows], ["APPLIED", "RENEWED"])

    def test_same_sequence_retry_returns_the_original_ack_without_renewing(self):
        case = self.start()
        proposal = self.proposal(case)
        first = self.control.apply(proposal, now_tick_100ns=self.ticks)
        self.ticks += 2 * TICKS_PER_SECOND
        again = self.control.apply(proposal, now_tick_100ns=self.ticks)
        self.assertIs(again, first)
        self.assertEqual(again.lease_deadline_tick_100ns, first.lease_deadline_tick_100ns)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(len(self.actions()), 1)

    def test_replayed_sequence_under_a_new_request_is_refused(self):
        case = self.start()
        self.apply_cap(case)
        ack = self.control.apply(self.proposal(case, seq=1, sample_seq=2), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "decision_seq_replayed")

    def test_older_sequence_is_refused(self):
        case = self.start()
        self.apply_cap(case, seq=5, sample_seq=5)
        ack = self.control.apply(self.proposal(case, seq=4, sample_seq=6), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "decision_seq_stale")
        self.assertEqual(case.job.sets, 1)

    # --- refusals ------------------------------------------------------------

    def test_stale_guardian_epoch_and_registry_revision_are_refused(self):
        case = self.start()
        stale_epoch = self.control.apply(self.proposal(case, guardian_epoch="other-epoch"),
                                         now_tick_100ns=self.ticks)
        self.assertEqual(stale_epoch.reason, "guardian_epoch_stale")
        revision = self.runtime()["registry_revision"]
        stale_revision = self.control.apply(self.proposal(case, seq=2, registry_revision=revision + 1),
                                            now_tick_100ns=self.ticks)
        self.assertEqual(stale_revision.reason, "registry_revision_stale")
        for ack in (stale_epoch, stale_revision):
            self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_stale_policy_epoch_is_refused(self):
        case = self.start()
        ack = self.control.apply(self.proposal(case, policy_epoch=str(uuid4())),
                                 now_tick_100ns=self.ticks)
        self.assertEqual(ack.reason, "policy_epoch_stale")
        self.assertEqual(case.job.sets, 0)

    def test_expired_sample_window_is_refused(self):
        case = self.start()
        stale = self.ticks - (PROFILE.sample_max_age_ms * TICKS_PER_MS + 1)
        ack = self.control.apply(self.proposal(case, window_end=stale, decision=stale),
                                 now_tick_100ns=self.ticks)
        self.assertEqual(ack.reason, "sample_window_expired")
        self.assertEqual(case.job.sets, 0)

    def test_second_victim_is_refused_while_the_slot_is_held(self):
        first, second = self.start(cases=2)
        self.apply_cap(first)
        ack = self.control.apply(self.proposal(second, seq=1), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_slot_occupied")
        self.assertEqual(second.job.sets, 0)
        self.assertEqual(self.slot()["execution_id"], first.spec.execution_id)

    def test_exempted_scope_is_refused_before_any_set(self):
        case = self.start()
        self.grant()
        self.scope.result = GrantRelation.APPLICABLE
        ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(ack.reason, "execution_exempt")
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())
        self.scope.result = GrantRelation.UNKNOWN
        unknown = self.control.apply(self.proposal(case, seq=2), now_tick_100ns=self.ticks)
        self.assertEqual(unknown.reason, "exemption_scope_unknown")
        self.assertEqual(case.job.sets, 0)

    def test_unreadable_exemption_authority_refuses(self):
        case = self.start()
        self.control.exemptions = None
        ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(ack.reason, "exemption_authority_unavailable")
        self.assertEqual(case.job.sets, 0)

    def test_legacy_writer_exclusion_must_be_proven_by_the_host_authority(self):
        case = self.start()
        self.authority.excluded_error = LifecycleError("legacy_writer_handoff_unverified")
        ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "legacy_writer_handoff_unverified")
        self.assertGreater(self.authority.exclusion_calls, 0)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_role_priority_coverage_and_seal_each_refuse_with_zero_set(self):
        cases = {
            "role": ("UPDATE managed_executions SET role='protected'", "control_execution_ineligible"),
            "neutral": ("UPDATE managed_executions SET role='neutral'", "control_execution_ineligible"),
            "priority": ("UPDATE managed_executions SET priority='P1'", "control_execution_ineligible"),
            "coverage": ("UPDATE managed_executions SET coverage='unmanaged'", "control_execution_ineligible"),
            "sealed": ("UPDATE managed_executions SET launch_sealed=0", "control_launch_unsealed"),
        }
        for name, (statement, reason) in cases.items():
            with self.subTest(name):
                self.setUp()
                case = self.start()
                # Fixture write into this isolated database, to present the
                # consumer with a row it must refuse.
                self.sql(statement)
                ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
                self.assertEqual(ack.result, ApplyResult.REJECTED)
                self.assertEqual(ack.reason, reason)
                self.assertEqual(case.job.sets, 0)
                self.assertIsNone(self.slot())

    # --- faults --------------------------------------------------------------

    def test_intent_write_failure_means_no_set_at_all(self):
        case = self.start()
        failure = RecoveryJournalError("manifest_write_unavailable")
        with patch.object(self.journal, "publish", side_effect=failure):
            with self.assertRaises(RecoveryJournalError):
                self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual([call for call in case.job.calls if call[0] == "set"], [])
        # The publication may still have landed, so the slot is not handed back
        # while the journal is unreadable, and the failed restore attempt has
        # already tightened the barrier. Both directions block admission; no
        # audit row claims anything either.
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual(self.actions(), [])
        # Once the journal answers again the same compare-and-restore path
        # settles the uncertainty and releases the slot.
        result = self.control.request_restore(case.spec.execution_id)
        self.assertTrue(result.native_disabled and result.slot_released)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual([row["action_state"] for row in self.actions()], ["RESTORED"])

    def test_query_mismatch_yields_no_applied_ack_and_attempts_restore(self):
        case = self.start()
        case.job.set_applies = False
        ack = self.control.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertEqual(ack.result, ApplyResult.UNVERIFIED)
        self.assertEqual(ack.reason, "control_readback_mismatch")
        self.assertIsNone(ack.action_id)
        self.assertIsNone(ack.lease_deadline_tick_100ns)
        self.assertEqual(ack.applied_validity, Validity.UNKNOWN)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        rows = self.actions()
        self.assertEqual([row["action_state"] for row in rows], ["RESTORED"])
        record = self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        self.assertIsNone(record.pending_intent)
        self.assertEqual(record.last_applied, DISABLED)

    # --- lease expiry, restore and the barrier -------------------------------

    def test_tick_restores_on_lease_expiry_and_leaves_recovery_hold(self):
        case = self.start()
        ack = self.apply_cap(case)
        self.ticks = ack.lease_deadline_tick_100ns
        outcomes = self.control.tick(self.ticks)
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0][1], "lease_expired")
        self.assertTrue(outcomes[0][2].native_disabled)
        self.assertTrue(outcomes[0][2].slot_released)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual([row["action_state"] for row in self.actions()], ["APPLIED", "RESTORED"])
        # A second sweep neither re-restores nor touches the Job again.
        sets = case.job.sets
        self.assertEqual(self.control.tick(self.ticks + TICKS_PER_SECOND), ())
        self.assertEqual(case.job.sets, sets)

    def test_tick_restores_when_the_ledger_mode_leaves_canary(self):
        case = self.start()
        self.apply_cap(case)
        # Fixture write to this isolated database.
        self.sql("UPDATE adaptive_runtime SET mode='shadow'")
        outcomes = self.control.tick(self.ticks)
        self.assertEqual(outcomes[0][1], "control_mode_unavailable")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_exemption_granted_mid_cap_forces_restore(self):
        case = self.start()
        self.apply_cap(case)
        self.grant()
        self.scope.result = GrantRelation.APPLICABLE
        outcomes = self.control.tick(self.ticks)
        self.assertEqual(outcomes[0][1], "execution_exempt")
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_request_restore_uses_the_same_compare_and_restore_path(self):
        case = self.start()
        self.apply_cap(case)
        result = self.control.request_restore(case.spec.execution_id)
        self.assertTrue(result.native_disabled and result.bookkeeping_settled and result.slot_released)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.control.request_restore(case.spec.execution_id))

    # --- barrier clear -------------------------------------------------------

    def restored_case(self):
        case = self.start()
        ack = self.apply_cap(case)
        self.ticks = ack.lease_deadline_tick_100ns
        self.control.tick(self.ticks)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        return case

    def clear(self, case, samples, *, now=None):
        self.control._samples[case.spec.execution_id] = list(samples)
        return self.control.clear_admission_barrier(case.spec.execution_id,
            now_tick_100ns=self.ticks if now is None else now)

    def test_five_fresh_uncapped_samples_after_the_restore_clear_the_barrier(self):
        case = self.restored_case()
        samples = self.uncapped_set(case)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        revision = self.runtime()["registry_revision"]
        result = self.clear(case, samples)
        self.assertEqual(result["admission_barrier"], "NONE")
        self.assertEqual(result["registry_revision"], revision + 1)
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assertEqual(self.slot()["slot_state"], "RESTORED")

    def test_four_samples_keep_recovery_hold(self):
        case = self.restored_case()
        samples = self.uncapped_set(case, count=4)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        with self.assertRaises(LifecycleError) as caught:
            self.clear(case, samples)
        self.assertEqual(str(caught.exception), "uncapped_samples_insufficient")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_stale_samples_keep_recovery_hold(self):
        case = self.restored_case()
        samples = self.uncapped_set(case, lag=PROFILE.sample_max_age_ms * TICKS_PER_MS + 1)
        self.ticks = samples[-1].observed_tick_100ns
        with self.assertRaises(LifecycleError) as caught:
            self.clear(case, samples)
        self.assertEqual(str(caught.exception), "uncapped_samples_stale")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_a_stalled_sampler_cannot_clear_with_an_old_complete_set(self):
        case = self.restored_case()
        samples = self.uncapped_set(case)
        self.ticks = (samples[-1].window_end_tick_100ns +
                      PROFILE.sample_max_age_ms * TICKS_PER_MS + 1)
        with self.assertRaises(LifecycleError) as caught:
            self.clear(case, samples)
        self.assertEqual(str(caught.exception), "uncapped_samples_stale")

    def test_samples_taken_before_the_restore_keep_recovery_hold(self):
        case = self.restored_case()
        samples = self.uncapped_set(case, start=self.boundary(case) - 10 * TICKS_PER_SECOND)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        with self.assertRaises(LifecycleError) as caught:
            self.clear(case, samples)
        self.assertEqual(str(caught.exception), "uncapped_samples_precede_restore")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_an_unsettled_later_intent_keeps_recovery_hold(self):
        case = self.restored_case()
        samples = self.uncapped_set(case)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        # Fixture write: a later action that never settled into a restore.
        self.sql("""INSERT INTO adaptive_actions(guardian_epoch,execution_id,decision_seq,action_id,
            sample_seq,action_state,desired_mode,desired_rate_bp,applied_flags,applied_rate_bp,
            applied_tick_100ns,lease_deadline_tick_100ns,intervention_deadline_tick_100ns,reason,
            win32_error) VALUES(?,?,?,?,?,'INTENDED','hard_cap',2500,NULL,NULL,NULL,NULL,NULL,
            'cpu_pressure',NULL)""",
            (EPOCH, case.spec.execution_id, 99, str(uuid4()), 99))
        with self.assertRaises(LifecycleError) as caught:
            self.clear(case, samples)
        self.assertEqual(str(caught.exception), "control_restore_boundary_missing")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_a_held_slot_cannot_clear_the_barrier(self):
        case = self.start()
        self.apply_cap(case)
        row = self.row(case)
        runtime = self.runtime()
        with self.policy_held():
            with self.assertRaises(LifecycleError) as caught:
                self.store.clear_recovery_hold_locked(case.spec.execution_id,
                    caller=case.record.wrapper_identity, expected_revision=row["state_revision"],
                    expected_registry_revision=runtime["registry_revision"],
                    slot_id=self.slot()["slot_id"], uncapped_samples=(),
                    now_tick_100ns=self.ticks, required_samples=5, sample_max_age_ms=3000)
        self.assertIn(str(caught.exception),
                      {"control_slot_unrestored", "restore_unverified"})
        self.assertEqual(self.runtime()["admission_barrier"], "CONTROLLING")

    def test_usage_drop_alone_is_not_evidence_that_the_cap_was_removed(self):
        case = self.restored_case()
        # Samples with no CPU use at all still have to be post-restore and
        # fresh; a zero reading buys nothing by itself.
        samples = self.uncapped_set(case, start=self.boundary(case) - 10 * TICKS_PER_SECOND)
        samples = tuple(replace(sample, cpu_units=0.0) for sample in samples)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        with self.assertRaises(LifecycleError):
            self.clear(case, samples)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_barrier_clear_compare_and_swap_loses_cleanly_on_a_changed_runtime(self):
        case = self.restored_case()
        samples = self.uncapped_set(case)
        self.ticks = samples[-1].window_end_tick_100ns + TICKS_PER_SECOND
        with self.policy_held() as guard:
            with self.store._transaction() as conn:
                runtime = self.store._policy.revalidate(conn, guard)
                row = self.store._get(conn, case.spec.execution_id)
                stale = dict(runtime) | {"registry_revision": runtime["registry_revision"] - 1}
                with self.assertRaises(ControlSlotError) as caught:
                    clear_locked(conn, row, stale, guard, samples=samples,
                                 now_tick_100ns=self.ticks, required_samples=5,
                                 sample_max_age_ms=3000)
        self.assertEqual(str(caught.exception), "control_slot_revision_conflict")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_observe_uncapped_refuses_a_sample_taken_while_capped(self):
        case = self.start()
        self.apply_cap(case)
        frame = decisions.frame(11, BASE + 2 * TICKS_PER_SECOND, 8.0,
                                jobs=(decisions.job(case.spec.execution_id),))
        with self.assertRaises(LifecycleError) as caught:
            self.control.observe_uncapped(case.spec.execution_id, frame)
        self.assertEqual(str(caught.exception), "uncapped_sample_capped")
        self.assertEqual(self.control._samples.get(case.spec.execution_id, []), [])

    def test_observe_uncapped_pairs_the_frame_with_its_own_disabled_query(self):
        case = self.restored_case()
        frame = decisions.frame(11, self.boundary(case) + TICKS_PER_SECOND, 8.0,
                                jobs=(decisions.job(case.spec.execution_id),))
        sample = self.control.observe_uncapped(case.spec.execution_id, frame)
        self.assertEqual(sample.sample_seq, 11)
        self.assertEqual(sample.observed_tick_100ns, self.ticks)
        self.assertEqual(sample.sampler_epoch, frame.sampler_epoch)


if __name__ == "__main__":
    unittest.main()
