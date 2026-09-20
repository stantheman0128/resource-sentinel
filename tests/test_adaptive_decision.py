"""Synthetic decision traces only; these establish no Windows behavior.

Every frame, tick and candidate here is fabricated in memory. Nothing measures a
real CPU, a real Job object or a real reaction time, so none of these tests are
evidence for the plan's reaction time, effect or cost thresholds. The bounded
work tests count inspections, not wall clock: a one second or six second timer
would prove nothing about reaction time, so no assertion depends on elapsed time.
"""

from dataclasses import fields, replace
import json
import pathlib
import unittest

from sentinel.adaptive.contracts import (
    ContractViolation, Coverage, CpuControlMode, FastFrame, FrameError, JobFrame, MachineFrame,
    MAX_ENROLLED_JOBS, Priority, RetryClass, Role, TICKS_PER_SECOND, Validity,
    derive_lease_deadline,
)
from sentinel.adaptive.decision import (
    ActiveIntervention, ControllerSnapshot, ControllerState, Decision, DecisionAction, Mode,
    PolicyProfile, TICKS_PER_MS, VictimCandidate, lease_deadline_tick, next_state,
    parse_policy_profile, select_victim, target_rate, uncapped_baseline,
    validate_policy_profile,
)

GIB = 1 << 30
BASE_TICK = 1_000_000_000_000
EXEC_A = "30000000-0000-4000-8000-00000000000a"
EXEC_B = "30000000-0000-4000-8000-00000000000b"
EXEC_C = "30000000-0000-4000-8000-00000000000c"
HIGH_BUSY = 11.5   # 95.8% of twelve logical processors
LOW_BUSY = 8.0     # 66.7%, below the eighty percent recovery threshold
EXAMPLE_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "adaptive.example.json"


def at(second: float) -> int:
    return BASE_TICK + int(second * TICKS_PER_SECOND)


def profile(**changes) -> PolicyProfile:
    base = validate_policy_profile(json.loads(EXAMPLE_PATH.read_text(encoding="utf-8")))
    return replace(base, **changes) if changes else base


EXAMPLE = profile()
ENFORCE = profile(mode=Mode.ENFORCE)
SHADOW = profile(mode=Mode.SHADOW)


def job(execution_id: str = EXEC_A, cpu_units: float = 6.0, **changes) -> JobFrame:
    values = dict(execution_id=execution_id, cpu_units=cpu_units,
                  cpu_uncapped_high_water_units=cpu_units, private_working_set_bytes=4 * GIB,
                  private_commit_bytes=5 * GIB, active_processes=4, membership_complete=True,
                  memory_validity=Validity.VALID, counter_epoch="job-counter-a")
    return JobFrame(**(values | changes))


def frame(seq: int, tick: int, busy: float, jobs=None, **changes) -> FastFrame:
    values = dict(sampler_epoch="sampler-a", clock_epoch="clock-a", sample_seq=seq,
                  window_start_tick_100ns=tick - TICKS_PER_SECOND, window_end_tick_100ns=tick,
                  published_tick_100ns=tick, sampled_at_utc="2026-09-19T03:00:00Z",
                  config_revision="b" * 64, registry_revision=3,
                  machine=MachineFrame(12, 1, busy, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB),
                  jobs=(job(),) if jobs is None else jobs, validity=Validity.VALID, errors=(),
                  collection_cost_ms=14.0, collection_skew_ms=6.0)
    return FastFrame(**(values | changes))


def candidate(execution_id: str = EXEC_A, **changes) -> VictimCandidate:
    values = dict(execution_id=execution_id, principal_id="principal-a", role=Role.BACKGROUND,
                  priority=Priority.P2, coverage=Coverage.JOB_CONTAINED, foreground=False,
                  capability_verified=True, uncapped_samples=(6.0, 6.0, 6.0, 6.0, 6.0))
    return VictimCandidate(**(values | changes))


CANDIDATES = (candidate(),)


def tick(prof: PolicyProfile, snapshot: ControllerSnapshot, second: int, busy: float,
         *, candidates=CANDIDATES, jobs=None, seq=None, now=None) -> Decision:
    moment = at(second)
    current = frame(second + 1 if seq is None else seq, moment, busy, jobs)
    return next_state(profile=prof, snapshot=snapshot, frame=current, candidates=candidates,
                      now_tick_100ns=moment if now is None else now)


def settle(prof: PolicyProfile, seconds=range(0, 5), busy=LOW_BUSY,
           snapshot=None) -> ControllerSnapshot:
    """Run warmup ticks so the controller holds five valid uncapped samples."""
    state = ControllerSnapshot.initial() if snapshot is None else snapshot
    for second in seconds:
        state = tick(prof, state, second, busy).next_snapshot
    return state


class ConfigValidationTests(unittest.TestCase):
    def test_example_profile_is_accepted(self):
        loaded = parse_policy_profile(EXAMPLE_PATH.read_text(encoding="utf-8"))
        self.assertIs(loaded.mode, Mode.OFF)
        self.assertEqual(loaded.max_active_caps, 1)
        self.assertEqual(loaded.eligible_roles, (Role.BACKGROUND,))
        self.assertEqual(loaded.eligible_priorities, (Priority.P2, Priority.P3))
        self.assertEqual(loaded.cap_floor_cpu_units, 1.0)
        self.assertEqual(loaded.lease_ms, 6000)
        self.assertEqual(loaded.intervention_max_ms, 60000)

    def payload(self, **changes) -> dict:
        data = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
        data.update(changes)
        return data

    def test_non_off_mode_is_rejected(self):
        for mode in ("shadow", "enforce", "on", "OFF", 1, None):
            with self.subTest(mode=mode), self.assertRaises(ContractViolation):
                validate_policy_profile(self.payload(mode=mode))

    def test_unknown_and_missing_keys_are_rejected(self):
        with self.assertRaises(ContractViolation):
            validate_policy_profile(self.payload(learning_rate=0.1))
        missing = self.payload()
        missing.pop("lease_ms")
        with self.assertRaises(ContractViolation):
            validate_policy_profile(missing)

    def test_out_of_plan_values_are_rejected(self):
        for changes in (dict(max_active_caps=2), dict(max_enrolled_jobs=11),
                        dict(high_cpu_pct=101), dict(recovery_cpu_pct=90),
                        dict(recovery_cpu_pct=95), dict(retreat_l2_fraction=0.80),
                        dict(retreat_l1_fraction=1.0), dict(retreat_l2_fraction=0.0),
                        dict(lease_ms=3000), dict(lease_ms=2000),
                        dict(normal_change_min_interval_ms=60000),
                        dict(intervention_max_ms=120000), dict(cap_floor_cpu_units=0.0),
                        dict(victim_min_cpu_units=-1.0), dict(schema_version=2),
                        dict(eligible_roles=["background", "protected"]),
                        dict(eligible_roles=["neutral"]), dict(eligible_roles=[]),
                        dict(eligible_priorities=["P0"]), dict(eligible_priorities=["P2", "P2"]),
                        dict(eligible_priorities=["P9"]), dict(baseline_samples=0),
                        dict(cpu_window_min_ms=1500, cpu_window_max_ms=500),
                        dict(sample_max_age_ms=500), dict(sample_ring_frames=3),
                        dict(high_samples=True), dict(log_retention_days=0)):
            with self.subTest(**changes), self.assertRaises(ContractViolation):
                validate_policy_profile(self.payload(**changes))

    def test_profile_is_not_a_json_document_hole(self):
        with self.assertRaises(ContractViolation):
            parse_policy_profile("[]")
        with self.assertRaises(ContractViolation):
            validate_policy_profile("mode=off")


class TargetRateTests(unittest.TestCase):
    def test_plan_worked_example(self):
        level1 = target_rate(baseline_cpu_units=6.0, fraction=0.75, logical_processors=12)
        level2 = target_rate(baseline_cpu_units=6.0, fraction=0.50, logical_processors=12)
        self.assertEqual((level1.target_cpu_units, level1.cpu_rate_bp), (4.5, 3750))
        self.assertEqual((level2.target_cpu_units, level2.cpu_rate_bp), (3.0, 2500))
        self.assertIs(level1.mode, CpuControlMode.HARD_CAP)

    def test_floor_is_never_broken(self):
        target = target_rate(baseline_cpu_units=1.6, fraction=0.50, logical_processors=12)
        self.assertEqual(target.target_cpu_units, 1.0)
        raised = target_rate(baseline_cpu_units=1.6, fraction=0.50, logical_processors=12,
                             floor_cpu_units=1.4)
        self.assertEqual(raised.target_cpu_units, 1.4)

    def test_rounding_is_ceiling_at_boundaries(self):
        exact = target_rate(baseline_cpu_units=8.0, fraction=0.50, logical_processors=8)
        self.assertEqual((exact.target_cpu_units, exact.cpu_rate_bp), (4.0, 5000))
        rounded = target_rate(baseline_cpu_units=2.0, fraction=0.75, logical_processors=12)
        self.assertEqual(rounded.target_cpu_units, 1.5)
        self.assertEqual(rounded.cpu_rate_bp, 1250)
        odd = target_rate(baseline_cpu_units=4.0, fraction=0.75, logical_processors=7)
        self.assertEqual(odd.cpu_rate_bp, 4286)  # ceil(10000 * 3 / 7) == 4286
        wide = target_rate(baseline_cpu_units=2.0, fraction=0.50, logical_processors=4096)
        self.assertEqual(wide.cpu_rate_bp, 3)    # ceil(10000 * 1.0 / 4096) == 3
        self.assertGreaterEqual(wide.cpu_rate_bp, 1)

    def test_target_at_or_above_denominator_yields_no_cap(self):
        self.assertIsNone(target_rate(baseline_cpu_units=4.0, fraction=0.75, logical_processors=1))
        self.assertIsNone(target_rate(baseline_cpu_units=8.0, fraction=0.75, logical_processors=6))
        self.assertIsNotNone(target_rate(baseline_cpu_units=8.0, fraction=0.75,
                                         logical_processors=7))

    def test_inputs_are_bounded(self):
        for changes in (dict(baseline_cpu_units=0.0), dict(fraction=0.0), dict(fraction=1.0),
                        dict(logical_processors=0), dict(floor_cpu_units=0.0),
                        dict(baseline_cpu_units=float("inf"))):
            values = dict(baseline_cpu_units=6.0, fraction=0.75, logical_processors=12,
                          floor_cpu_units=1.0)
            with self.subTest(**changes), self.assertRaises(ContractViolation):
                target_rate(**(values | changes))


class BaselineTests(unittest.TestCase):
    def test_median_of_last_five(self):
        self.assertEqual(uncapped_baseline((9.0, 1.0, 6.0, 6.0, 5.0, 7.0), 5), 6.0)
        self.assertEqual(uncapped_baseline((2.0, 4.0, 6.0, 8.0), 4), 5.0)

    def test_short_history_is_no_baseline(self):
        self.assertIsNone(uncapped_baseline((6.0, 6.0, 6.0, 6.0), 5))
        self.assertIsNone(uncapped_baseline((), 5))


class VictimSelectionTests(unittest.TestCase):
    def select(self, candidates, jobs=None, **changes):
        values = dict(profile=ENFORCE, frame=frame(1, at(0), HIGH_BUSY, jobs),
                      candidates=candidates, now_tick_100ns=at(0))
        return select_victim(**(values | changes))

    def test_eligible_background_job_is_selected(self):
        self.assertEqual(self.select(CANDIDATES).execution_id, EXEC_A)

    def test_ineligible_shapes_are_never_selected(self):
        cases = {
            "protected": candidate(role=Role.PROTECTED),
            "neutral": candidate(role=Role.NEUTRAL),
            "foreground": candidate(foreground=True),
            "priority_p0": candidate(priority=Priority.P0),
            "priority_p1": candidate(priority=Priority.P1),
            "unmanaged": candidate(coverage=Coverage.UNMANAGED),
            "capability_unproven": candidate(capability_verified=False),
            "fault_backoff": candidate(ineligible_until_tick_100ns=at(300)),
            "too_small": candidate(uncapped_samples=(1.0,) * 5),
            "short_history": candidate(uncapped_samples=(6.0,) * 4),
        }
        for name, item in cases.items():
            with self.subTest(name):
                selection = self.select((item,))
                self.assertIsNone(selection.execution_id)
                self.assertEqual(selection.reason, "no_eligible_victim")

    def test_unmeasured_or_incomplete_job_is_not_selected(self):
        self.assertIsNone(self.select((candidate(EXEC_B),)).execution_id)
        partial = (job(cpu_units=None, memory_validity=Validity.UNKNOWN),)
        unusable = frame(1, at(0), HIGH_BUSY, partial,
                         errors=(FrameError("telemetry_stale", "sampler", RetryClass.TRANSIENT),))
        self.assertIsNone(self.select(CANDIDATES, frame=unusable).execution_id)

    def test_small_share_of_machine_busy_is_not_selected(self):
        jobs = (job(cpu_units=0.9),)
        self.assertIsNone(self.select(CANDIDATES, jobs=jobs).execution_id)

    def test_largest_principal_then_largest_job_wins(self):
        candidates = (candidate(EXEC_A, principal_id="solo"),
                      candidate(EXEC_B, principal_id="pair"),
                      candidate(EXEC_C, principal_id="pair"))
        jobs = (job(EXEC_A, 5.0), job(EXEC_B, 3.0), job(EXEC_C, 3.5))
        self.assertEqual(self.select(candidates, jobs).execution_id, EXEC_C)

    def test_tie_breaks_on_earlier_control_then_execution_id(self):
        jobs = (job(EXEC_A, 4.0), job(EXEC_B, 4.0))
        recent = (candidate(EXEC_A, last_controlled_tick_100ns=at(-1)), candidate(EXEC_B))
        self.assertEqual(self.select(recent, jobs).execution_id, EXEC_B)
        equal = (candidate(EXEC_A), candidate(EXEC_B))
        self.assertEqual(self.select(equal, jobs).execution_id, EXEC_A)

    def test_excluded_victim_is_skipped(self):
        jobs = (job(EXEC_A, 6.0), job(EXEC_B, 5.0))
        candidates = (candidate(EXEC_A), candidate(EXEC_B))
        self.assertEqual(self.select(candidates, jobs, excluded_execution_id=EXEC_A).execution_id,
                         EXEC_B)

    def test_unknown_denominator_selects_nobody(self):
        blind = frame(1, at(0), None, jobs=(job(cpu_units=None),),
                      machine=MachineFrame(12, 1, None, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB),
                      validity=Validity.UNKNOWN,
                      errors=(FrameError("denominator_unknown", "sampler", RetryClass.TRANSIENT),))
        selection = self.select(CANDIDATES, frame=blind)
        self.assertIsNone(selection.execution_id)
        self.assertEqual(selection.reason, "denominator_unknown")


class BoundedWorkTests(unittest.TestCase):
    """Work per decision is counted, never timed."""

    def candidates(self, count):
        return tuple(candidate(f"30000000-0000-4000-8000-{index:012d}", principal_id=f"p{index}")
                     for index in range(count))

    def jobs(self, count):
        return tuple(job(f"30000000-0000-4000-8000-{index:012d}", 3.0 + index)
                     for index in range(min(count, MAX_ENROLLED_JOBS)))

    def test_scan_is_linear_in_candidates(self):
        for count in (1, 10):
            with self.subTest(count=count):
                selection = select_victim(profile=ENFORCE,
                                          frame=frame(1, at(0), HIGH_BUSY, self.jobs(count)),
                                          candidates=self.candidates(count),
                                          now_tick_100ns=at(0))
                self.assertGreaterEqual(selection.examined, count)
                self.assertLessEqual(selection.examined, 3 * count)
                self.assertLessEqual(selection.examined, 3 * MAX_ENROLLED_JOBS)

    def test_fifty_candidates_are_refused_without_scanning(self):
        with self.assertRaises(ContractViolation):
            select_victim(profile=ENFORCE, frame=frame(1, at(0), HIGH_BUSY, self.jobs(50)),
                          candidates=self.candidates(50), now_tick_100ns=at(0))
        with self.assertRaises(ContractViolation):
            next_state(profile=ENFORCE, snapshot=ControllerSnapshot.initial(),
                       frame=frame(1, at(0), HIGH_BUSY, self.jobs(50)),
                       candidates=self.candidates(50), now_tick_100ns=at(0))

    def test_one_decision_examines_each_candidate_a_bounded_number_of_times(self):
        state = ControllerSnapshot.initial()
        candidates = self.candidates(10)
        jobs = self.jobs(10)
        actions = []
        for second in range(0, 8):
            decision = next_state(profile=ENFORCE, snapshot=state,
                                  frame=frame(second + 1, at(second), HIGH_BUSY, jobs),
                                  candidates=candidates, now_tick_100ns=at(second))
            self.assertLessEqual(decision.examined_candidates, 3 * len(candidates))
            actions.append(decision.action)
            state = decision.next_snapshot
        self.assertIn(DecisionAction.PROPOSE_L1, actions)


class LeaseTests(unittest.TestCase):
    def test_matches_the_contract_helper(self):
        now, window_end = at(10), at(10)
        deadline = at(40)
        self.assertEqual(
            lease_deadline_tick(ENFORCE, now_tick_100ns=now,
                                sample_window_end_tick_100ns=window_end,
                                intervention_deadline_tick_100ns=deadline),
            derive_lease_deadline(now_tick_100ns=now, sample_window_end_tick_100ns=window_end,
                                  intervention_deadline_tick_100ns=deadline))

    def test_an_aging_sample_does_not_buy_a_full_lease(self):
        now = at(12)
        window_end = at(10)
        lease = lease_deadline_tick(ENFORCE, now_tick_100ns=now,
                                    sample_window_end_tick_100ns=window_end,
                                    intervention_deadline_tick_100ns=at(60))
        self.assertEqual(lease, window_end + 6 * TICKS_PER_SECOND)
        self.assertLess(lease, now + 6 * TICKS_PER_SECOND)

    def test_the_intervention_deadline_wins(self):
        lease = lease_deadline_tick(ENFORCE, now_tick_100ns=at(10),
                                    sample_window_end_tick_100ns=at(10),
                                    intervention_deadline_tick_100ns=at(12))
        self.assertEqual(lease, at(12))

    def test_stale_or_expired_inputs_are_refused(self):
        with self.assertRaises(ContractViolation):
            lease_deadline_tick(ENFORCE, now_tick_100ns=at(20),
                                sample_window_end_tick_100ns=at(10),
                                intervention_deadline_tick_100ns=at(60))
        with self.assertRaises(ContractViolation):
            lease_deadline_tick(ENFORCE, now_tick_100ns=at(10),
                                sample_window_end_tick_100ns=at(10),
                                intervention_deadline_tick_100ns=at(10))


class ModeTests(unittest.TestCase):
    def test_off_never_produces_a_cap_intent(self):
        state = ControllerSnapshot.initial()
        for second in range(0, 12):
            decision = tick(EXAMPLE, state, second, HIGH_BUSY)
            self.assertIs(decision.action, DecisionAction.NO_POLICY_ACTION)
            self.assertIsNone(decision.target)
            self.assertFalse(decision.executable)
            self.assertFalse(decision.would_apply)
            state = decision.next_snapshot
            self.assertIs(state.state, ControllerState.OFF)

    def test_off_still_restores_an_inherited_intervention(self):
        inherited = ControllerSnapshot(
            state=ControllerState.CAPPED_L1,
            active=ActiveIntervention(EXEC_A, 1, 6.0, at(0), at(60), at(0)))
        decision = tick(EXAMPLE, inherited, 5, HIGH_BUSY)
        self.assertIs(decision.action, DecisionAction.REQUEST_RESTORE)
        self.assertTrue(decision.executable)
        self.assertIsNone(decision.target)

    def test_shadow_records_a_would_apply_but_nothing_executable(self):
        state = settle(SHADOW)
        for second in (5, 6):
            state = tick(SHADOW, state, second, HIGH_BUSY).next_snapshot
        decision = tick(SHADOW, state, 7, HIGH_BUSY)
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        self.assertTrue(decision.would_apply)
        self.assertFalse(decision.executable)
        self.assertEqual(decision.target.cpu_rate_bp, 3750)

    def test_enforce_marks_the_same_decision_executable(self):
        state = settle(ENFORCE)
        for second in (5, 6):
            state = tick(ENFORCE, state, second, HIGH_BUSY).next_snapshot
        decision = tick(ENFORCE, state, 7, HIGH_BUSY)
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        self.assertTrue(decision.executable)
        self.assertFalse(decision.would_apply)


class FailClosedTests(unittest.TestCase):
    def capped(self) -> ControllerSnapshot:
        state = settle(ENFORCE)
        for second in (5, 6, 7):
            decision = tick(ENFORCE, state, second, HIGH_BUSY)
            state = decision.next_snapshot
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        return state

    def test_missing_sample_stops_tightening_and_restores(self):
        state = settle(ENFORCE)
        for second in (5, 6):
            state = tick(ENFORCE, state, second, HIGH_BUSY).next_snapshot
        gap = tick(ENFORCE, state, 7, HIGH_BUSY, seq=99)
        self.assertIs(gap.action, DecisionAction.OBSERVE)
        self.assertEqual(gap.reason, "sample_gap")
        self.assertIs(gap.next_snapshot.state, ControllerState.WARMUP)
        capped = tick(ENFORCE, self.capped(), 8, HIGH_BUSY, seq=99)
        self.assertIs(capped.action, DecisionAction.REQUEST_RESTORE)
        self.assertEqual(capped.reason, "sample_gap")

    def test_controller_warms_up_again_after_a_gap_once_frames_are_contiguous(self):
        # Plan 5.4 and 6.2: a gap resets warmup and waits for fresh frames. It
        # must not leave every later frame refused as another gap.
        gap = tick(ENFORCE, settle(ENFORCE), 7, LOW_BUSY, seq=99)
        self.assertEqual((gap.reason, gap.next_snapshot.uncapped_streak), ("sample_gap", 0))
        state, reasons = gap.next_snapshot, []
        for seq, second in enumerate(range(8, 13), start=100):
            decision = tick(ENFORCE, state, second, LOW_BUSY, seq=seq)
            reasons.append(decision.reason)
            state = decision.next_snapshot
        self.assertNotIn("sample_gap", reasons)
        self.assertEqual(state.uncapped_streak, ENFORCE.baseline_samples)
        self.assertIs(state.state, ControllerState.OBSERVING)

    def test_controller_warms_up_again_after_a_rejected_frame_consumed_a_sequence(self):
        state = settle(ENFORCE)
        stale = tick(ENFORCE, state, 5, LOW_BUSY, now=at(5 + 60))
        self.assertEqual(stale.reason, "sample_stale")
        self.assertEqual(stale.next_snapshot.last_sample_seq, state.last_sample_seq)
        state = stale.next_snapshot
        for second in range(66, 72):
            state = tick(ENFORCE, state, second, LOW_BUSY).next_snapshot
        self.assertIs(state.state, ControllerState.OBSERVING)

    def test_controller_warms_up_again_after_a_sampler_or_clock_epoch_change(self):
        for changes in (dict(sampler_epoch="sampler-b"), dict(clock_epoch="clock-b")):
            with self.subTest(changes):
                state = settle(ENFORCE)
                for seq, second in enumerate(range(5, 11), start=1):
                    state = next_state(
                        profile=ENFORCE, snapshot=state, candidates=CANDIDATES,
                        frame=frame(seq, at(second), LOW_BUSY, **changes),
                        now_tick_100ns=at(second)).next_snapshot
                self.assertIs(state.state, ControllerState.OBSERVING)

    def test_a_continuity_break_never_tightens_on_the_frame_that_rebases(self):
        state = settle(ENFORCE)
        for second in (5, 6):
            state = tick(ENFORCE, state, second, HIGH_BUSY).next_snapshot
        rebased = tick(ENFORCE, state, 7, HIGH_BUSY, seq=99)
        self.assertIs(rebased.action, DecisionAction.OBSERVE)
        self.assertEqual((rebased.next_snapshot.high_streak,
                          rebased.next_snapshot.uncapped_streak), (0, 0))
        # The rebasing frame is a baseline only. A replay of it stays refused.
        again = tick(ENFORCE, rebased.next_snapshot, 8, HIGH_BUSY, seq=99)
        self.assertEqual(again.reason, "sample_replay")

    def test_an_unsound_frame_is_never_adopted_as_the_new_baseline(self):
        state = settle(ENFORCE)
        late = tick(ENFORCE, state, 7, LOW_BUSY, seq=99, now=at(7 + 60))
        self.assertEqual(late.reason, "sample_gap")
        self.assertEqual(late.next_snapshot.last_sample_seq, state.last_sample_seq)

    def test_missing_memory_attribution_does_not_refuse_the_cpu_evidence(self):
        # Plan 5.3: without private memory attribution the physical deduction is
        # zero. The frame contract makes the frame say so with an error, and the
        # CPU evidence in that frame is still sound.
        unknown = job(private_working_set_bytes=None, private_commit_bytes=None,
                      memory_validity=Validity.UNKNOWN)
        note = FrameError("memory_attribution_unavailable", "job_memory",
                          RetryClass.AFTER_RECONCILIATION, EXEC_A)
        state = ControllerSnapshot.initial()
        for second in range(5):
            state = next_state(
                profile=ENFORCE, snapshot=state, candidates=CANDIDATES,
                frame=frame(second + 1, at(second), LOW_BUSY, jobs=(unknown,), errors=(note,)),
                now_tick_100ns=at(second)).next_snapshot
        self.assertIs(state.state, ControllerState.OBSERVING)
        other = FrameError("membership_unknown", "job_membership", RetryClass.TRANSIENT, EXEC_A)
        refused = next_state(
            profile=ENFORCE, snapshot=state, candidates=CANDIDATES,
            frame=frame(6, at(5), LOW_BUSY, jobs=(unknown,), errors=(note, other)),
            now_tick_100ns=at(5))
        self.assertEqual(refused.reason, "frame_errors")

    def test_replayed_sample_is_refused(self):
        state = settle(ENFORCE)
        replayed = tick(ENFORCE, state, 5, HIGH_BUSY, seq=2)
        self.assertEqual(replayed.reason, "sample_replay")
        self.assertIs(replayed.action, DecisionAction.OBSERVE)

    def test_stale_sample_stops_tightening_and_restores(self):
        state = settle(ENFORCE)
        for second in (5, 6):
            state = tick(ENFORCE, state, second, HIGH_BUSY).next_snapshot
        stale = next_state(profile=ENFORCE, snapshot=state,
                           frame=frame(8, at(7), HIGH_BUSY), candidates=CANDIDATES,
                           now_tick_100ns=at(12))
        self.assertIs(stale.action, DecisionAction.OBSERVE)
        self.assertEqual(stale.reason, "sample_stale")
        capped = next_state(profile=ENFORCE, snapshot=self.capped(),
                            frame=frame(9, at(8), HIGH_BUSY), candidates=CANDIDATES,
                            now_tick_100ns=at(13))
        self.assertIs(capped.action, DecisionAction.REQUEST_RESTORE)
        self.assertEqual(capped.reason, "sample_stale")

    def test_backwards_clock_is_refused(self):
        state = settle(ENFORCE)
        backwards = next_state(profile=ENFORCE, snapshot=state, frame=frame(6, at(2), HIGH_BUSY),
                               candidates=CANDIDATES, now_tick_100ns=at(2))
        self.assertIs(backwards.action, DecisionAction.OBSERVE)
        self.assertEqual(backwards.reason, "clock_backwards")
        capped = next_state(profile=ENFORCE, snapshot=self.capped(),
                            frame=frame(9, at(3), HIGH_BUSY), candidates=CANDIDATES,
                            now_tick_100ns=at(3))
        self.assertIs(capped.action, DecisionAction.REQUEST_RESTORE)
        self.assertEqual(capped.reason, "clock_backwards")

    def test_epoch_change_and_invalid_frames_are_refused(self):
        state = settle(ENFORCE)
        cases = {
            "sampler_epoch_changed": dict(sampler_epoch="sampler-b"),
            "clock_epoch_changed": dict(clock_epoch="clock-b"),
        }
        for reason, changes in cases.items():
            with self.subTest(reason):
                decision = next_state(profile=ENFORCE, snapshot=state,
                                      frame=frame(6, at(5), HIGH_BUSY, **changes),
                                      candidates=CANDIDATES, now_tick_100ns=at(5))
                self.assertEqual(decision.reason, reason)
                self.assertIs(decision.action, DecisionAction.OBSERVE)
        unknown = frame(6, at(5), None, jobs=(job(cpu_units=None),),
                        machine=MachineFrame(12, 1, None, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB),
                        validity=Validity.UNKNOWN,
                        errors=(FrameError("telemetry_stale", "sampler", RetryClass.TRANSIENT),))
        decision = next_state(profile=ENFORCE, snapshot=state, frame=unknown,
                              candidates=CANDIDATES, now_tick_100ns=at(5))
        self.assertIs(decision.action, DecisionAction.OBSERVE)
        self.assertEqual(decision.reason, "frame_invalid")

    def test_malformed_window_is_refused(self):
        state = settle(ENFORCE)
        narrow = frame(6, at(5), HIGH_BUSY,
                       window_start_tick_100ns=at(5) - 100 * TICKS_PER_MS)
        decision = next_state(profile=ENFORCE, snapshot=state, frame=narrow,
                              candidates=CANDIDATES, now_tick_100ns=at(5))
        self.assertEqual(decision.reason, "sample_window_invalid")

    def test_unverified_restore_never_tightens(self):
        state = ControllerSnapshot(state=ControllerState.RESTORE_UNVERIFIED)
        for second in range(0, 12):
            decision = tick(ENFORCE, state, second, HIGH_BUSY)
            self.assertIs(decision.action, DecisionAction.REQUEST_RESTORE)
            self.assertIsNone(decision.target)
            state = decision.next_snapshot
            self.assertIs(state.state, ControllerState.RESTORE_UNVERIFIED)


class TraceTests(unittest.TestCase):
    def test_escalation_recovery_and_cooldown(self):
        state = ControllerSnapshot.initial()
        actions = {}
        for second in range(0, 90):
            busy = HIGH_BUSY if 5 <= second <= 17 else LOW_BUSY
            decision = tick(ENFORCE, state, second, busy)
            actions[second] = decision
            state = decision.next_snapshot

        self.assertEqual([actions[s].reason for s in range(0, 4)], ["warmup"] * 4)
        self.assertIs(actions[4].next_snapshot.state, ControllerState.OBSERVING)
        self.assertIs(actions[5].next_snapshot.state, ControllerState.PRESSURE_PENDING)
        self.assertIs(actions[6].action, DecisionAction.OBSERVE)

        level1 = actions[7]
        self.assertIs(level1.action, DecisionAction.PROPOSE_L1)
        self.assertEqual(level1.victim_execution_id, EXEC_A)
        self.assertEqual(level1.target.target_cpu_units, 4.5)
        self.assertEqual(level1.target.cpu_rate_bp, 3750)
        self.assertEqual(level1.lease_deadline_tick_100ns, at(7) + 6 * TICKS_PER_SECOND)
        self.assertEqual(level1.next_snapshot.active.deadline_tick_100ns, at(67))

        for second in range(8, 17):
            self.assertIs(actions[second].action, DecisionAction.RENEW, second)
            # A renewal without a deadline would let the guardian's lease lapse.
            self.assertEqual(actions[second].lease_deadline_tick_100ns,
                             at(second) + 6 * TICKS_PER_SECOND, second)
        level2 = actions[17]
        self.assertIs(level2.action, DecisionAction.PROPOSE_L2)
        self.assertEqual(level2.target.target_cpu_units, 3.0)
        self.assertEqual(level2.target.cpu_rate_bp, 2500)
        self.assertIs(level2.next_snapshot.state, ControllerState.CAPPED_L2)

        for second in range(18, 28):
            self.assertIs(actions[second].action, DecisionAction.RENEW, second)
            self.assertIs(actions[second].next_snapshot.state, ControllerState.RECOVERING)
        restored = actions[28]
        self.assertIs(restored.action, DecisionAction.REQUEST_RESTORE)
        self.assertEqual(restored.reason, "pressure_cleared")
        self.assertIsNone(restored.target)
        self.assertIsNone(restored.next_snapshot.active)
        self.assertIs(restored.next_snapshot.state, ControllerState.COOLDOWN)
        self.assertEqual(restored.next_snapshot.cooldown_until_tick_100ns, at(88))

        for second in range(29, 33):
            self.assertEqual(actions[second].reason, "warmup", second)
        for second in range(34, 89):
            self.assertIs(actions[second].action, DecisionAction.OBSERVE, second)

        proposals = [d for d in actions.values() if d.action in
                     (DecisionAction.PROPOSE_L1, DecisionAction.PROPOSE_L2)]
        self.assertEqual(len(proposals), 2)
        self.assertEqual({d.victim_execution_id for d in proposals}, {EXEC_A})

    def test_cooldown_blocks_the_same_victim_while_pressure_returns(self):
        cooled = ControllerSnapshot(state=ControllerState.COOLDOWN,
                                    cooldown_execution_id=EXEC_A,
                                    cooldown_until_tick_100ns=at(50))
        state = settle(ENFORCE, snapshot=cooled)
        for second in (5, 6, 7, 8):
            decision = tick(ENFORCE, state, second, HIGH_BUSY)
            state = decision.next_snapshot
            self.assertIs(decision.action, DecisionAction.OBSERVE, second)
            if second >= 7:  # three consecutive high samples reached
                self.assertEqual(decision.reason, "no_eligible_victim")

    def test_fault_backoff_blocks_the_only_candidate(self):
        blocked = (candidate(ineligible_until_tick_100ns=at(300)),)
        state = ControllerSnapshot.initial()
        for second in range(0, 12):
            decision = tick(ENFORCE, state, second, HIGH_BUSY, candidates=blocked)
            state = decision.next_snapshot
            self.assertIsNot(decision.action, DecisionAction.PROPOSE_L1, second)
        self.assertEqual(decision.reason, "no_eligible_victim")

    def test_high_pressure_shorter_than_three_samples_does_not_trigger(self):
        state = settle(ENFORCE)
        for second, busy in ((5, HIGH_BUSY), (6, HIGH_BUSY), (7, LOW_BUSY), (8, HIGH_BUSY),
                             (9, HIGH_BUSY), (10, LOW_BUSY)):
            decision = tick(ENFORCE, state, second, busy)
            state = decision.next_snapshot
            self.assertIs(decision.action, DecisionAction.OBSERVE, second)
            self.assertIsNone(decision.target)

    def test_intervention_deadline_ends_sustained_pressure(self):
        state = ControllerSnapshot.initial()
        last = None
        for second in range(0, 70):
            decision = tick(ENFORCE, state, second, HIGH_BUSY)
            state = decision.next_snapshot
            if decision.action is DecisionAction.REQUEST_RESTORE:
                last = (second, decision)
                break
        self.assertIsNotNone(last)
        second, decision = last
        # Pressure is high from the first sample, so level 1 lands at second 4
        # and the absolute sixty second deadline falls at second 64.
        self.assertEqual(second, 64)
        self.assertEqual(decision.reason, "intervention_deadline")
        self.assertIsNone(decision.next_snapshot.active)

    def test_losing_eligibility_restores_the_cap(self):
        state = settle(ENFORCE)
        for second in (5, 6, 7):
            decision = tick(ENFORCE, state, second, HIGH_BUSY)
            state = decision.next_snapshot
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        promoted = (candidate(foreground=True),)
        decision = tick(ENFORCE, state, 8, HIGH_BUSY, candidates=promoted)
        self.assertIs(decision.action, DecisionAction.REQUEST_RESTORE)
        self.assertEqual(decision.reason, "no_longer_eligible")

    def test_floor_holds_across_a_small_baseline_trace(self):
        small = (candidate(uncapped_samples=(1.6,) * 5),)
        jobs = (job(cpu_units=1.6),)
        state = ControllerSnapshot.initial()
        seen = []
        for second in range(0, 20):
            decision = tick(ENFORCE, state, second, HIGH_BUSY, candidates=small, jobs=jobs)
            state = decision.next_snapshot
            if decision.target is not None:
                seen.append(decision.target.target_cpu_units)
        self.assertEqual(len(seen), 2)
        self.assertAlmostEqual(seen[0], 1.2)
        self.assertEqual(seen[1], 1.0)
        self.assertTrue(all(value >= ENFORCE.cap_floor_cpu_units for value in seen))


class OutputShapeTests(unittest.TestCase):
    def test_decision_carries_no_capacity_or_admission_signal(self):
        self.assertEqual(
            {field.name for field in fields(Decision)},
            {"action", "reason", "next_snapshot", "victim_execution_id", "target",
             "lease_deadline_tick_100ns", "executable", "would_apply", "examined_candidates"})

    def test_a_cap_never_widens_into_a_second_victim(self):
        candidates = (candidate(EXEC_A), candidate(EXEC_B, principal_id="principal-b"))
        jobs = (job(EXEC_A, 6.0), job(EXEC_B, 5.0))
        state = ControllerSnapshot.initial()
        victims = set()
        for second in range(0, 30):
            decision = tick(ENFORCE, state, second, HIGH_BUSY, candidates=candidates, jobs=jobs)
            state = decision.next_snapshot
            if decision.victim_execution_id is not None:
                victims.add(decision.victim_execution_id)
            self.assertLessEqual(len([x for x in (state.active,) if x is not None]), 1)
        self.assertEqual(victims, {EXEC_A})

    def test_snapshot_and_candidate_inputs_are_validated(self):
        with self.assertRaises(ContractViolation):
            VictimCandidate(EXEC_A, "principal-a", Role.BACKGROUND, Priority.P2,
                            Coverage.JOB_CONTAINED, False, True, [6.0])
        with self.assertRaises(ContractViolation):
            ControllerSnapshot(state="CAPPED_L1")
        with self.assertRaises(ContractViolation):
            ActiveIntervention(EXEC_A, 3, 6.0, at(0), at(60), at(0))
        with self.assertRaises(ContractViolation):
            ActiveIntervention(EXEC_A, 1, 6.0, at(60), at(0), at(60))
        with self.assertRaises(ContractViolation):
            next_state(profile=ENFORCE, snapshot=ControllerSnapshot.initial(),
                       frame=frame(1, at(0), HIGH_BUSY), candidates=[candidate()],
                       now_tick_100ns=at(0))
        with self.assertRaises(ContractViolation):
            next_state(profile=ENFORCE, snapshot=ControllerSnapshot.initial(),
                       frame=frame(1, at(0), HIGH_BUSY),
                       candidates=(candidate(), candidate()), now_tick_100ns=at(0))


if __name__ == "__main__":
    unittest.main()
