"""Authenticated frame/restore boundaries with explicitly synthetic native Jobs.

The shared fixture uses isolated real SQLite, manifests and control slots. Its
capability/floor authorities and native backends are synthetic collaborators;
these tests establish neither Windows capability nor native reaction timing.
"""
from contextlib import contextmanager
from dataclasses import replace
import math
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import (
    ApplyResult, CpuControlMode, CpuTarget, TICKS_PER_SECOND, Validity,
)
from sentinel.adaptive.control_messages import (
    ControlFrameRequest, ControlObservation, ControlRestoreRequest, RestoreOutcome,
)
from sentinel.adaptive.decision import target_rate
from tests import test_adaptive_guardian_control as fixture
from tests import test_adaptive_decision as decisions


class GuardianControlFrameTests(unittest.TestCase):
    # Reuse fixture methods without inheriting any of the fixture's test cases.
    setUp = fixture.GuardianControlTests.setUp
    spec = fixture.GuardianControlTests.spec
    allocate = fixture.GuardianControlTests.allocate
    connection = fixture.GuardianControlTests.connection
    make_mutex = fixture.GuardianControlTests.make_mutex
    seed_evidence = fixture.GuardianControlTests.seed_evidence
    seed_started = fixture.GuardianControlTests.seed_started
    row = fixture.GuardianControlTests.row
    sql = fixture.GuardianControlTests.sql
    start = fixture.GuardianControlTests.start
    policy_held = fixture.GuardianControlTests.policy_held
    runtime = fixture.GuardianControlTests.runtime
    slot = fixture.GuardianControlTests.slot
    actions = fixture.GuardianControlTests.actions
    proposal = fixture.GuardianControlTests.proposal
    sample = fixture.GuardianControlTests.sample
    uncapped_set = fixture.GuardianControlTests.uncapped_set
    boundary = fixture.GuardianControlTests.boundary
    apply_cap = fixture.GuardianControlTests.apply_cap
    recording_journal = fixture.GuardianControlTests.recording_journal

    def send_frame(self, *args, **kwargs):
        return fixture.GuardianControlTests.send_frame(self, *args, **kwargs)

    def apply(self, *args, **kwargs):
        return fixture.GuardianControlTests.apply(self, *args, **kwargs)

    def frame(self, case, *, seq=1, window_end=None):
        proposal = self.proposal(case)
        end = self.ticks if window_end is None else window_end
        job = decisions.job(case.spec.execution_id, cpu_units=8 / 3,
            private_working_set_bytes=case.spec.requested.physical_bytes,
            private_commit_bytes=case.spec.requested.commit_bytes,
            active_processes=1)
        frame = decisions.frame(seq, end, 7.6, jobs=(job,),
            config_revision=proposal.config_revision,
            registry_revision=self.runtime()["registry_revision"])
        return replace(frame, machine=replace(frame.machine, logical_processors=8))

    def submit_frame(self, frame, *, helper=None, request_id=None):
        request = ControlFrameRequest(request_id or str(uuid4()), fixture.EPOCH,
            self.runtime()["policy_instance_id"], frame)
        return self.control.observe_control_frame(request,
            helper_identity=self.helper_identity if helper is None else helper)

    def next_frame(self):
        previous = self.control._latest_frame
        end = previous.window_end_tick_100ns + TICKS_PER_SECOND
        self.ticks = end
        return replace(previous, sample_seq=previous.sample_seq + 1,
            window_start_tick_100ns=previous.window_end_tick_100ns,
            window_end_tick_100ns=end, published_tick_100ns=end,
            registry_revision=self.runtime()["registry_revision"])

    def restore_request(self, case):
        return ControlRestoreRequest(str(uuid4()), fixture.EPOCH,
            self.runtime()["policy_instance_id"], case.spec.execution_id,
            "explicit_test_restore")

    def transition_frame(self, case, *, busy=7.6):
        """Advance exactly one synthetic second; keep real callback continuity."""
        frame = self.next_frame()
        # Deliberately lower measured usage while capped. The retained episode
        # baseline and lifetime demand must not follow that lower measurement.
        jobs = tuple(replace(job, cpu_units=0.5) for job in frame.jobs)
        frame = replace(frame, machine=replace(frame.machine, cpu_busy_units=busy), jobs=jobs)
        ack = self.submit_frame(frame)
        self.assertEqual(len(ack.results), 1)
        self.assertIs(ack.results[0].observation, ControlObservation.CAPPED)
        return frame

    def transition_proposal(self, case, frame, *, target=None, reason="cpu_pressure"):
        episode = self.control._episodes[case.spec.execution_id]
        if target is None:
            fraction = {0: 1.0, 1: self.control.profile.retreat_l1_fraction,
                        2: self.control.profile.retreat_l2_fraction}[episode.level]
            target = self.episode_target(case, fraction)
        proposal = self.proposal(case, seq=episode.decision_seq + 1,
            sample_seq=frame.sample_seq - 4, window_end=frame.window_end_tick_100ns,
            decision=self.ticks, reason=reason)
        return replace(proposal, target=target)

    def apply_transition(self, case, frame, *, target=None, reason="cpu_pressure"):
        proposal = self.transition_proposal(case, frame, target=target, reason=reason)
        return self.control.apply(proposal, helper_identity=self.helper_identity,
            now_tick_100ns=self.ticks)

    def episode_target(self, case, fraction):
        baseline = self.control._episodes[case.spec.execution_id].baseline_cpu_units
        if fraction == 1.0:
            return CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, baseline,
                math.ceil(10000 * baseline / 8), 8)
        return target_rate(
            baseline_cpu_units=baseline,
            fraction=fraction, logical_processors=8,
            floor_cpu_units=self.control.profile.cap_floor_cpu_units)

    def start_timed_episode(self):
        case = self.start()
        self.ticks = fixture.BASE
        applied = self.apply_cap(case)
        self.assertEqual(applied.queried_tick_100ns, fixture.BASE)
        return case, applied

    def enter_level_two(self, case):
        for _ in range(9):
            frame = self.transition_frame(case)
            renewed = self.apply_transition(case, frame)
            self.assertIs(renewed.result, ApplyResult.RENEWED)
        frame = self.transition_frame(case)
        ack = self.apply_transition(case, frame,
            target=self.episode_target(case, self.control.profile.retreat_l2_fraction))
        self.assertIs(ack.result, ApplyResult.APPLIED)
        return ack

    def warmup_uncapped(self, case, *, cpu_units=(8 / 3,) * 5):
        for index, units in enumerate(cpu_units):
            self.ticks = fixture.BASE - (len(cpu_units) - 1 - index) * TICKS_PER_SECOND
            frame = self.send_frame(case, seq=index + 1, window_end=self.ticks, cpu_units=units)
        return frame

    def first_frame_proposal(self, case, frame):
        return self.proposal(case, sample_seq=frame.sample_seq - 4,
            window_end=frame.window_end_tick_100ns, decision=self.ticks)

    def test_proposal_without_authenticated_frame_cannot_apply(self):
        case = self.start()
        ack = self.control.apply(self.proposal(case),
            helper_identity=self.helper_identity, now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_missing_measured_capability_cannot_be_replaced_by_valid_frames(self):
        case = self.start()
        self.control.capability_authority = None
        ack = self.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_capability_evidence_unavailable")
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_missing_floor_publication_prevents_first_cap(self):
        case = self.start()
        self.control.floor_publisher = None
        ack = self.apply(self.proposal(case), now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_floor_publisher_unavailable")
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_another_helper_cannot_propose_from_cached_authenticated_frame(self):
        case = self.start()
        self.submit_frame(self.frame(case))
        other = replace(self.helper_identity, pid=self.helper_identity.pid + 1,
            created_filetime_100ns=self.helper_identity.created_filetime_100ns + 1)
        ack = self.control.apply(self.proposal(case), helper_identity=other,
            now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_helper_binding_invalid")
        self.assertEqual(case.job.sets, 0)

    def test_same_request_and_sequence_with_changed_payload_does_not_replay_ack(self):
        case = self.start()
        proposal = self.proposal(case)
        applied = self.apply(proposal, now_tick_100ns=self.ticks)
        self.assertIs(applied.result, ApplyResult.APPLIED)
        sets = case.job.sets
        changed = replace(proposal, reason="different_payload")
        ack = self.control.apply(changed, helper_identity=self.helper_identity,
            now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(case.job.sets, sets)
        self.assertEqual(self.control._episodes[case.spec.execution_id].lease_deadline_tick_100ns,
            applied.lease_deadline_tick_100ns)

    def test_future_decision_cannot_extend_the_intervention_deadline(self):
        case = self.start()
        proposal = self.proposal(case, decision=self.ticks + TICKS_PER_SECOND)
        ack = self.apply(proposal, now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "decision_tick_invalid")
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_distinct_requests_replaying_one_frame_add_only_one_uncapped_sample(self):
        case = self.start()
        frame = self.frame(case)
        first = self.submit_frame(frame)
        self.assertIs(first.results[0].observation, ControlObservation.UNCAPPED)
        samples = tuple(self.control._samples[case.spec.execution_id])
        self.assertEqual(len(samples), 1)
        second = self.submit_frame(frame)
        self.assertEqual(tuple(self.control._samples[case.spec.execution_id]), samples)
        self.assertEqual(second.sample_seq, first.sample_seq)
        self.assertEqual(case.job.sets, 0)

    def test_capped_frame_is_cacheable_but_cannot_grow_uncapped_baseline(self):
        case = self.start()
        self.apply_cap(case)
        before = tuple(self.control._samples[case.spec.execution_id])
        frame = self.next_frame()
        ack = self.submit_frame(frame)
        self.assertIs(ack.results[0].observation, ControlObservation.CAPPED)
        self.assertEqual(tuple(self.control._samples[case.spec.execution_id]), before)
        self.assertEqual(self.control._latest_frame, frame)
        self.assertEqual(case.job.sets, 1)

    def test_helper_restart_withdraws_owned_cap_and_starts_new_warmup(self):
        case = self.start()
        self.apply_cap(case)
        self.assertAlmostEqual(self.control._episodes[case.spec.execution_id].baseline_cpu_units,
            8 / 3)
        self.assertEqual(self.control._samples[case.spec.execution_id], [])
        replacement = replace(self.helper_identity, pid=self.helper_identity.pid + 1,
            created_filetime_100ns=self.helper_identity.created_filetime_100ns + 1)
        frame = replace(self.next_frame(), sampler_epoch="replacement-sampler", sample_seq=1)
        self.submit_frame(frame, helper=replacement)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertTrue(self.control._episodes[case.spec.execution_id].restored)
        self.assertLessEqual(len(self.control._samples.get(case.spec.execution_id, ())), 1)
        self.assertNotEqual(self.runtime()["admission_barrier"], "NONE")

    def test_frame_authority_changes_cannot_enter_uncapped_sample_buffer(self):
        case = self.start()
        base = self.frame(case)
        frames = (
            replace(base, config_revision="e" * 64),
            replace(base, registry_revision=base.registry_revision + 1),
            replace(base, collection_cost_ms=self.control.profile.sampler_work_budget_ms + 1),
            replace(base, collection_skew_ms=self.control.profile.attribution_max_skew_ms + 1),
        )
        for frame in frames:
            with self.subTest(config=frame.config_revision, revision=frame.registry_revision,
                    cost=frame.collection_cost_ms, skew=frame.collection_skew_ms):
                ack = self.submit_frame(frame)
                self.assertTrue(ack.results)
                self.assertTrue(all(item.observation in (
                    ControlObservation.REJECTED, ControlObservation.UNVERIFIED)
                    for item in ack.results))
                self.assertEqual(self.control._samples.get(case.spec.execution_id, []), [])
                self.assertEqual(case.job.sets, 0)

    def test_frame_denominator_must_match_current_native_host(self):
        case = self.start()
        frame = self.frame(case)
        self.control.native_capability_source = lambda: SimpleNamespace(
            logical_processors=16, processor_groups=1)
        ack = self.submit_frame(frame)
        self.assertEqual(frame.machine.logical_processors, 8)
        self.assertTrue(ack.results)
        self.assertTrue(all(item.observation is ControlObservation.REJECTED
            for item in ack.results))
        self.assertEqual(self.control._samples.get(case.spec.execution_id, []), [])
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_restore_ack_distinguishes_verified_disable_from_remaining_barrier(self):
        case = self.start()
        self.apply_cap(case)
        self.control.capability_authority = None
        self.control.floor_publisher = None
        ack = self.control.restore_control_request(self.restore_request(case),
            helper_identity=self.helper_identity)
        self.assertIs(ack.result, RestoreOutcome.RESTORED)
        self.assertIs(ack.applied_validity, Validity.VALID)
        self.assertIs(ack.native_disabled, True)
        self.assertIs(ack.bookkeeping_settled, True)
        self.assertIs(ack.slot_released, True)
        self.assertIs(ack.barrier_cleared, False)
        self.assertEqual(ack.applied_flags & 1, 0)
        self.assertIsNotNone(ack.queried_tick_100ns)
        self.assertEqual(case.job.control["flags"], 0)

    def test_failed_native_restore_query_cannot_claim_disabled_or_restored(self):
        case = self.start()
        self.apply_cap(case)
        with patch.object(case.job, "query_cpu", side_effect=OSError("synthetic query failure")) as query:
            ack = self.control.restore_control_request(self.restore_request(case),
                helper_identity=self.helper_identity)
        self.assertGreater(query.call_count, 0)
        self.assertIs(ack.result, RestoreOutcome.UNVERIFIED)
        self.assertIs(ack.applied_validity, Validity.UNKNOWN)
        self.assertIsNone(ack.native_disabled)
        self.assertIsNone(ack.applied_flags)
        self.assertIsNone(ack.applied_rate_bp)

    def test_continuous_high_renewals_then_l2_keep_slot_deadline_and_baseline(self):
        case, original = self.start_timed_episode()
        episode = self.control._episodes[case.spec.execution_id]
        slot_id, baseline = episode.slot_id, episode.baseline_cpu_units
        with self.recording_journal(case) as publications:
            for _ in range(9):
                frame = self.transition_frame(case)
                ack = self.apply_transition(case, frame)
                self.assertIs(ack.result, ApplyResult.RENEWED)
                self.assertEqual(case.job.sets, 1)
                self.assertEqual(publications, [])
                self.assertEqual(ack.intervention_deadline_tick_100ns,
                    original.intervention_deadline_tick_100ns)
            frame = self.transition_frame(case)
            applied = self.apply_transition(case, frame,
                target=self.episode_target(case, self.control.profile.retreat_l2_fraction))
        self.assertIs(applied.result, ApplyResult.APPLIED)
        self.assertEqual(publications, ["intent", "settle"])
        self.assertEqual(case.job.sets, 2)
        self.assertEqual(episode.level, 2)
        self.assertEqual((episode.slot_id, self.slot()["slot_id"]), (slot_id, slot_id))
        self.assertEqual(episode.baseline_cpu_units, baseline)
        self.assertEqual(applied.intervention_deadline_tick_100ns,
            original.intervention_deadline_tick_100ns)
        self.assertEqual(self.row(case)["floor_cpu_units"], 3.0)
        self.assertEqual(self.owner._entry(case.spec.execution_id).manifest.original, fixture.DISABLED)
        events = case.job.calls
        intent = max(index for index, item in enumerate(events) if item == ("publish", "intent"))
        changed = next(index for index in range(intent + 1, len(events)) if events[index][0] == "set")
        query = next(index for index in range(changed + 1, len(events)) if events[index][0] == "query")
        settled = next(index for index in range(query + 1, len(events)) if events[index] == ("publish", "settle"))
        self.assertLess(intent, changed)
        self.assertLess(changed, query)
        self.assertLess(query, settled)

    def test_l2_change_requires_both_change_interval_and_ten_seconds_high(self):
        case, _ = self.start_timed_episode()
        l2 = self.episode_target(case, self.control.profile.retreat_l2_fraction)
        with self.recording_journal(case) as publications:
            frame = self.transition_frame(case)
            early = self.apply_transition(case, frame, target=l2)
            self.assertIs(early.result, ApplyResult.REJECTED)
            self.assertEqual(early.reason, "control_change_too_soon")
            for _ in range(3):
                frame = self.transition_frame(case)
                self.assertIs(self.apply_transition(case, frame).result, ApplyResult.RENEWED)
            frame = self.transition_frame(case)
            insufficient_high = self.apply_transition(case, frame, target=l2)
            self.assertIs(insufficient_high.result, ApplyResult.REJECTED)
            self.assertEqual(insufficient_high.reason, "control_target_transition_invalid")
        self.assertEqual(publications, [])
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.control._episodes[case.spec.execution_id].level, 1)

    def test_low_qualification_then_outward_steps_do_not_retighten_on_high_cpu(self):
        case, original = self.start_timed_episode()
        self.enter_level_two(case)
        episode = self.control._episodes[case.spec.execution_id]
        slot_id, baseline = episode.slot_id, episode.baseline_cpu_units
        for _ in range(9):
            frame = self.transition_frame(case, busy=6.0)
            self.assertIs(self.apply_transition(case, frame).result, ApplyResult.RENEWED)
        frame = self.transition_frame(case, busy=6.0)
        recovered_l1 = self.apply_transition(case, frame,
            target=self.episode_target(case, self.control.profile.retreat_l1_fraction),
            reason="recovery_level_1")
        self.assertIs(recovered_l1.result, ApplyResult.APPLIED)
        self.assertEqual(episode.level, 1)
        for _ in range(4):
            frame = self.transition_frame(case)
            self.assertIs(self.apply_transition(case, frame).result, ApplyResult.RENEWED)
        frame = self.transition_frame(case)
        recovered_baseline = self.apply_transition(case, frame,
            target=self.episode_target(case, 1.0), reason="recovery_baseline")
        self.assertIs(recovered_baseline.result, ApplyResult.APPLIED)
        self.assertEqual(episode.level, 0)
        self.assertTrue(episode.recovering)
        for _ in range(9):
            frame = self.transition_frame(case)
            self.assertIs(self.apply_transition(case, frame).result, ApplyResult.RENEWED)
        frame = self.transition_frame(case)
        denied = self.apply_transition(case, frame,
            target=self.episode_target(case, self.control.profile.retreat_l2_fraction))
        self.assertIs(denied.result, ApplyResult.REJECTED)
        self.assertEqual(denied.reason, "control_target_transition_invalid")
        self.assertEqual(case.job.sets, 4)
        self.assertEqual((episode.slot_id, self.slot()["slot_id"]), (slot_id, slot_id))
        self.assertEqual(episode.baseline_cpu_units, baseline)
        self.assertEqual(episode.intervention_deadline_tick_100ns,
            original.intervention_deadline_tick_100ns)
        self.assertEqual(recovered_baseline.intervention_deadline_tick_100ns,
            original.intervention_deadline_tick_100ns)
        self.assertEqual(self.owner._entry(case.spec.execution_id).manifest.original, fixture.DISABLED)

    def test_fresh_frames_cannot_renew_an_expired_lease(self):
        case, original = self.start_timed_episode()
        for _ in range(6):
            frame = self.transition_frame(case)
        self.assertEqual(self.ticks, original.lease_deadline_tick_100ns)
        ack = self.apply_transition(case, frame)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_lease_expired")
        self.assertTrue(self.control._episodes[case.spec.execution_id].restored)
        self.assertIsNone(self.control._episodes[case.spec.execution_id].lease_deadline_tick_100ns)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(case.job.sets, 2)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_adjacent_sequence_cannot_hide_a_three_second_window_gap(self):
        case, _ = self.start_timed_episode()
        previous = self.control._latest_frame
        start = previous.window_end_tick_100ns + 3 * TICKS_PER_SECOND
        self.ticks = start + TICKS_PER_SECOND
        frame = replace(previous, sample_seq=previous.sample_seq + 1,
            window_start_tick_100ns=start, window_end_tick_100ns=self.ticks,
            published_tick_100ns=self.ticks,
            registry_revision=self.runtime()["registry_revision"])
        self.submit_frame(frame)
        episode = self.control._episodes[case.spec.execution_id]
        self.assertTrue(episode.restored)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertIsNone(episode.lease_deadline_tick_100ns)
        self.assertLessEqual(len(self.control._samples.get(case.spec.execution_id, ())), 1)
        self.assertLessEqual(self.control._high_streak, 1)
        ack = self.apply_transition(case, frame)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(case.job.sets, 2)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_restore_scope_exit_failure_cannot_promote_factual_disabled_to_restored(self):
        case, _ = self.start_timed_episode()
        original_scope = self.owner._scope
        depth = 0

        @contextmanager
        def fail_outer_exit(entry):
            nonlocal depth
            depth += 1
            try:
                with original_scope(entry):
                    yield
                if depth == 1:
                    raise RuntimeError("synthetic scope exit failure")
            finally:
                depth -= 1

        with patch.object(self.owner, "_scope", fail_outer_exit):
            ack = self.control.restore_control_request(self.restore_request(case),
                helper_identity=self.helper_identity)
        self.assertIs(ack.result, RestoreOutcome.UNVERIFIED)
        self.assertIs(ack.native_disabled, True)
        self.assertIs(ack.applied_validity, Validity.VALID)
        self.assertEqual(ack.applied_flags & 1, 0)
        self.assertIsNotNone(ack.queried_tick_100ns)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertIsNotNone(self.control._frame_failure)

    def test_unchanged_renewals_preserve_the_native_action_id(self):
        case, original = self.start_timed_episode()
        with self.recording_journal(case) as publications:
            for _ in range(3):
                frame = self.transition_frame(case)
                ack = self.apply_transition(case, frame)
                self.assertIs(ack.result, ApplyResult.RENEWED)
                self.assertEqual(ack.action_id, original.action_id)
        self.assertEqual(publications, [])
        self.assertEqual(case.job.sets, 1)

    def test_native_target_change_gets_new_action_id_then_renewal_preserves_it(self):
        case, original = self.start_timed_episode()
        changed = self.enter_level_two(case)
        self.assertIs(changed.result, ApplyResult.APPLIED)
        self.assertNotEqual(changed.action_id, original.action_id)
        frame = self.transition_frame(case)
        renewed = self.apply_transition(case, frame)
        self.assertIs(renewed.result, ApplyResult.RENEWED)
        self.assertEqual(renewed.action_id, changed.action_id)
        self.assertEqual(case.job.sets, 2)

    def test_floor_collapsed_l2_updates_logical_level_without_new_native_action(self):
        # This explicit synthetic profile makes a 1.1-unit Job eligible. The
        # normal example's 1.5-unit victim minimum cannot exercise floor collapse.
        profile = decisions.profile(victim_min_cpu_units=1.0)
        with patch.object(fixture, "PROFILE", profile):
            case = self.start()
        frame = self.warmup_uncapped(case, cpu_units=(1.1,) * 5)
        initial_target = target_rate(baseline_cpu_units=1.1,
            fraction=profile.retreat_l1_fraction, logical_processors=8,
            floor_cpu_units=profile.cap_floor_cpu_units)
        proposal = replace(self.first_frame_proposal(case, frame), target=initial_target)
        original = self.control.apply(proposal, helper_identity=self.helper_identity,
            now_tick_100ns=self.ticks)
        self.assertIs(original.result, ApplyResult.APPLIED)
        self.assertEqual(original.applied_rate_bp, 1250)
        episode = self.control._episodes[case.spec.execution_id]
        slot_id = episode.slot_id
        with self.recording_journal(case) as publications:
            for _ in range(9):
                frame = self.transition_frame(case)
                renewal = self.apply_transition(case, frame)
                self.assertIs(renewal.result, ApplyResult.RENEWED)
                self.assertEqual(renewal.action_id, original.action_id)
            frame = self.transition_frame(case)
            logical_l2 = self.apply_transition(case, frame,
                target=self.episode_target(case, profile.retreat_l2_fraction),
                reason="retreat_level_2")
        self.assertIs(logical_l2.result, ApplyResult.RENEWED)
        self.assertEqual(logical_l2.action_id, original.action_id)
        self.assertEqual(logical_l2.applied_rate_bp, original.applied_rate_bp)
        self.assertEqual(publications, [])
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(episode.level, 2)
        self.assertEqual(episode.slot_id, slot_id)
        self.assertEqual(episode.baseline_cpu_units, 1.1)
        self.assertEqual(logical_l2.intervention_deadline_tick_100ns,
            original.intervention_deadline_tick_100ns)

    def test_old_median_cannot_select_a_job_whose_current_cpu_has_dropped(self):
        case = self.start()
        frame = self.warmup_uncapped(case, cpu_units=(8 / 3,) * 4 + (0.1,))
        samples = self.control._samples[case.spec.execution_id]
        self.assertEqual(len(samples), 5)
        self.assertEqual(samples[-1].cpu_units, 0.1)
        ack = self.control.apply(self.first_frame_proposal(case, frame),
            helper_identity=self.helper_identity, now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.slot())

    def test_omitted_job_erases_its_prior_uncapped_history(self):
        case = self.start()
        self.warmup_uncapped(case)
        self.assertEqual(len(self.control._samples[case.spec.execution_id]), 5)
        omitted = replace(self.next_frame(), jobs=())
        self.submit_frame(omitted)
        self.assertEqual(self.control._samples.get(case.spec.execution_id, []), [])
        following = self.next_frame()
        job = self.frame(case).jobs[0]
        following = replace(following, jobs=(job,))
        self.submit_frame(following)
        self.assertEqual(len(self.control._samples[case.spec.execution_id]), 1)
        ack = self.control.apply(self.first_frame_proposal(case, following),
            helper_identity=self.helper_identity, now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_warmup_incomplete")
        self.assertEqual(case.job.sets, 0)

    def test_unverified_job_frame_erases_its_prior_uncapped_history(self):
        case = self.start()
        self.warmup_uncapped(case)
        self.assertEqual(len(self.control._samples[case.spec.execution_id]), 5)
        frame = self.next_frame()
        unverified = replace(frame, jobs=(replace(frame.jobs[0], active_processes=2),))
        observed = self.submit_frame(unverified)
        self.assertIs(observed.results[0].observation, ControlObservation.UNVERIFIED)
        self.assertEqual(self.control._samples.get(case.spec.execution_id, []), [])
        following = self.next_frame()
        following = replace(following, jobs=(replace(following.jobs[0], active_processes=1),))
        self.submit_frame(following)
        self.assertEqual(len(self.control._samples[case.spec.execution_id]), 1)
        ack = self.control.apply(self.first_frame_proposal(case, following),
            helper_identity=self.helper_identity, now_tick_100ns=self.ticks)
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_warmup_incomplete")
        self.assertEqual(case.job.sets, 0)

    def test_contradictory_second_cpu_query_cannot_acknowledge_renewal(self):
        case, original = self.start_timed_episode()
        frame = self.transition_frame(case)
        episode = self.control._episodes[case.spec.execution_id]
        foreign = SimpleNamespace(flags=5, rate_bp=original.applied_rate_bp + 100)
        with patch.object(self.owner, "_control", return_value=episode.applied) as first_query, \
                patch.object(case.job, "query_cpu", return_value=foreign) as second_query:
            ack = self.apply_transition(case, frame)
        self.assertGreater(first_query.call_count, 0)
        self.assertGreater(second_query.call_count, 0)
        self.assertIs(ack.result, ApplyResult.UNVERIFIED)
        self.assertEqual(ack.reason, "control_readback_mismatch")
        self.assertIsNone(episode.lease_deadline_tick_100ns)
        # The synthetic first read remains the previously owned cap even
        # during recovery, so compare-and-restore attempts disable. That is a
        # withdrawal, not another restrictive Set or a successful renewal.
        self.assertEqual([call for call in case.job.calls if call[0] in {"set", "disable"}],
            [("set", original.applied_rate_bp), ("disable", None)])
        self.assertFalse(episode.restored)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")


if __name__ == "__main__":
    unittest.main()
