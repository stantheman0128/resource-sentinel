"""Seeded randomized traces through the real decision functions.

Every frame here is fabricated in memory, so these traces prove properties of
the decision layer and nothing about Windows, real CPU behavior, reaction time
or cost. The seeds are fixed and listed below so a failure is reproducible.

Each invariant cites the plan section it comes from
(docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md).

The generator takes the next sample sequence from the controller's own accepted
snapshot rather than from a free running counter. That models a sampler that
rebases its sequence after a rejected frame. A sampler that keeps counting
through rejected frames is covered in tests/test_adaptive_decision.py, where the
controller rebases on the first sound frame after the gap.
"""

import random
import unittest

from sentinel.adaptive.contracts import (
    Coverage, FastFrame, FrameError, JobFrame, MachineFrame, Priority, RetryClass, Role,
    TICKS_PER_SECOND, Validity,
)
from sentinel.adaptive.decision import (
    ControllerSnapshot, DecisionAction, Mode, TICKS_PER_MS, VictimCandidate, next_state,
    validate_policy_profile,
)

import json
import pathlib
from dataclasses import replace

GIB = 1 << 30
BASE_TICK = 1_000_000_000_000
EXEC_A = "50000000-0000-4000-8000-00000000000a"
EXEC_B = "50000000-0000-4000-8000-00000000000b"
HIGH_BUSY = 11.5   # 95.8% of twelve logical processors
LOW_BUSY = 7.0     # 58.3%, below the eighty percent recovery threshold
SEEDS = (20260920, 7, 424242, 99991, 2147483647)
STEPS = 400
CLEAN_PRESSURE = range(20, 60)     # deterministic window that must reach a cap
TAIL = 120                         # trailing clean low pressure steps
TIGHTENING = (DecisionAction.PROPOSE_L1, DecisionAction.PROPOSE_L2)
EXAMPLE_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "adaptive.example.json"

ENFORCE = replace(validate_policy_profile(json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))),
                  mode=Mode.ENFORCE)


def at(second: float) -> int:
    return BASE_TICK + int(second * TICKS_PER_SECOND)


def job(execution_id: str, cpu_units: float) -> JobFrame:
    return JobFrame(execution_id, cpu_units, cpu_units, 4 * GIB, 5 * GIB, 4, True,
                    Validity.VALID, "job-counter-a")


def frame(*, seq: int, window_end: int, busy: float, jobs, sampler_epoch="sampler-a",
          clock_epoch="clock-a", validity=Validity.VALID, errors=(),
          window_ms: int = 1000) -> FastFrame:
    machine = MachineFrame(12, 1, busy, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB)
    return FastFrame(sampler_epoch=sampler_epoch, clock_epoch=clock_epoch, sample_seq=seq,
                     window_start_tick_100ns=window_end - window_ms * TICKS_PER_MS,
                     window_end_tick_100ns=window_end, published_tick_100ns=window_end,
                     sampled_at_utc="2026-09-20T03:00:00Z", config_revision="c" * 64,
                     registry_revision=5, machine=machine, jobs=jobs, validity=validity,
                     errors=errors, collection_cost_ms=12.0, collection_skew_ms=4.0)


def candidate(execution_id: str, principal: str, cpu_units: float, **changes) -> VictimCandidate:
    values = dict(execution_id=execution_id, principal_id=principal, role=Role.BACKGROUND,
                  priority=Priority.P2, coverage=Coverage.JOB_CONTAINED, foreground=False,
                  capability_verified=True, uncapped_samples=(cpu_units,) * 5)
    return VictimCandidate(**(values | changes))


DEGRADING = ("stale", "replay", "gap", "sampler_epoch", "clock_epoch", "backwards",
             "invalid", "window")
# These only degrade a frame once the controller has accepted one, because the
# epoch, sequence and clock checks are skipped while the snapshot holds none.
NEEDS_HISTORY = ("replay", "gap", "sampler_epoch", "clock_epoch", "backwards")
CLOCK_RESET = ("clock_epoch", "backwards")


class Step:
    """One generated tick: what was fed in, and how it was meant to be broken."""

    def __init__(self, second: int, anomaly: str | None, frame: FastFrame,
                 candidates: tuple[VictimCandidate, ...], now: int):
        self.second, self.anomaly, self.frame, self.candidates, self.now = (
            second, anomaly, frame, candidates, now)


def generate(rng: random.Random, snapshot: ControllerSnapshot, second: int,
             free_running: bool = False) -> Step:
    """Build one tick from the controller's own accepted sequence.

    With free_running the sequence is the tick number instead, as from a sampler
    that keeps counting through frames the controller refused. Every refused
    frame then leaves a gap, and the controller has to rebase to recover.
    """
    clean = second in CLEAN_PRESSURE or second >= STEPS - TAIL
    anomaly = None
    if not clean and rng.random() < 0.12:
        anomaly = rng.choice(DEGRADING)
        if anomaly in NEEDS_HISTORY and snapshot.last_sample_seq is None:
            anomaly = "invalid"
    if second >= STEPS - TAIL:
        busy = LOW_BUSY
    elif second in CLEAN_PRESSURE:
        busy = HIGH_BUSY
    else:
        busy = HIGH_BUSY if rng.random() < 0.55 else LOW_BUSY

    accepted = snapshot.last_sample_seq
    seq = 1 if accepted is None else accepted + 1
    if free_running:
        seq = second + 1
    now = at(second)
    window_end = now
    kwargs = {}
    if anomaly == "stale":
        window_end = at(second - 5)
    elif anomaly == "replay":
        seq = max(1, seq - 1)
    elif anomaly == "gap":
        seq = seq + 3
    elif anomaly == "sampler_epoch":
        kwargs["sampler_epoch"] = "sampler-b"
    elif anomaly == "clock_epoch":
        kwargs["clock_epoch"] = "clock-b"
    elif anomaly == "backwards":
        now = snapshot.last_tick_100ns - TICKS_PER_SECOND
        window_end = now
    elif anomaly == "invalid":
        kwargs["validity"] = Validity.UNKNOWN
        kwargs["errors"] = (FrameError("telemetry_stale", "trace", RetryClass.TRANSIENT),)
    elif anomaly == "window":
        kwargs["window_ms"] = rng.choice((200, 2500))

    units_a = round(rng.uniform(5.0, 7.0), 3)
    units_b = round(rng.uniform(3.0, 5.0), 3)
    jobs = (job(EXEC_A, units_a), job(EXEC_B, units_b))
    candidates = [candidate(EXEC_A, "principal-a", 6.0), candidate(EXEC_B, "principal-b", 4.0)]
    if not clean and rng.random() < 0.06:
        index = rng.randrange(2)
        candidates[index] = replace(candidates[index], foreground=True)
    built = frame(seq=seq, window_end=window_end, busy=busy, jobs=jobs, **kwargs)
    return Step(second, anomaly, built, tuple(candidates), now)


class RandomizedTraceTests(unittest.TestCase):
    def run_trace(self, seed: int, free_running: bool = False):
        rng = random.Random(seed)
        snapshot = ControllerSnapshot.initial()
        last_tighten = None
        open_victim = None
        proposals = []
        restores = []
        tail_actions = []
        for second in range(STEPS):
            step = generate(rng, snapshot, second, free_running)
            previous = snapshot
            decision = next_state(profile=ENFORCE, snapshot=previous, frame=step.frame,
                                  candidates=step.candidates, now_tick_100ns=step.now)
            snapshot = decision.next_snapshot
            context = f"seed={seed} second={second} anomaly={step.anomaly} action={decision.action}"

            # Plan section 6.1: at most one active cap over all enrolled Jobs,
            # and section 6.2: a single victim is never swapped without a restore.
            if previous.active is not None and snapshot.active is not None:
                self.assertEqual(previous.active.execution_id, snapshot.active.execution_id, context)
            if decision.action in TIGHTENING or decision.action is DecisionAction.RENEW:
                self.assertIsNotNone(snapshot.active, context)
                self.assertEqual(decision.victim_execution_id, snapshot.active.execution_id, context)
                if open_victim is not None:
                    self.assertEqual(open_victim, decision.victim_execution_id, context)
                open_victim = decision.victim_execution_id
            if decision.action is DecisionAction.REQUEST_RESTORE:
                open_victim = None
                last_tighten = None
                restores.append(second)
                # Plan section 6.2: restore is never gated by mode or cooldown.
                self.assertTrue(decision.executable, context)
                self.assertIsNone(decision.target, context)
                self.assertIsNone(snapshot.active, context)

            # Plan section 6.1 and 13.2: no action past the intervention
            # deadline, and a lease never outlives it.
            if previous.active is not None and step.now >= previous.active.deadline_tick_100ns:
                self.assertIs(decision.action, DecisionAction.REQUEST_RESTORE, context)
            if snapshot.active is not None:
                self.assertLess(step.now, snapshot.active.deadline_tick_100ns, context)
            if decision.lease_deadline_tick_100ns is not None:
                self.assertIsNotNone(snapshot.active, context)
                self.assertLess(step.now, decision.lease_deadline_tick_100ns, context)
                self.assertLessEqual(decision.lease_deadline_tick_100ns,
                                     snapshot.active.deadline_tick_100ns, context)

            # Plan section 5.4 and 13.2: a replayed or older sequence never
            # renews a lease and never tightens.
            if previous.last_sample_seq is not None and step.frame.sample_seq <= previous.last_sample_seq:
                self.assertNotIn(decision.action, TIGHTENING, context)
                self.assertIsNot(decision.action, DecisionAction.RENEW, context)
                self.assertIsNone(decision.lease_deadline_tick_100ns, context)

            # Plan section 6.1: normal tightening steps are at least five
            # seconds apart inside one intervention.
            if decision.action in TIGHTENING:
                proposals.append((second, decision))
                if last_tighten is not None:
                    self.assertGreaterEqual(
                        step.now - last_tighten,
                        ENFORCE.normal_change_min_interval_ms * TICKS_PER_MS, context)
                last_tighten = step.now

            # Plan section 6.4: unknown or stale evidence never tightens.
            if step.anomaly is not None:
                self.assertNotIn(decision.action, TIGHTENING, context)

            # Plan section 5.4: sleep, resume and clock epoch loss clear every
            # streak and leave no intervention behind.
            if step.anomaly in CLOCK_RESET:
                self.assertEqual(snapshot.uncapped_streak, 0, context)
                self.assertEqual(snapshot.high_streak, 0, context)
                self.assertIsNone(snapshot.active, context)

            if second >= STEPS - TAIL:
                tail_actions.append(decision.action)
        return snapshot, proposals, restores, tail_actions

    def test_seeded_traces_hold_every_invariant(self):
        for seed in SEEDS:
            with self.subTest(seed=seed):
                snapshot, proposals, restores, tail = self.run_trace(seed)
                # The deterministic clean pressure window must reach a cap, so
                # the invariants above are exercised and not vacuous.
                self.assertTrue(proposals, "trace never proposed a cap")
                self.assertTrue(any(decision.action is DecisionAction.PROPOSE_L2
                                    for _, decision in proposals), "trace never escalated")
                self.assertTrue(restores, "trace never restored")

                # Plan section 11.2 stability row: no permanent cap after
                # pressure ends.
                self.assertIsNone(snapshot.active, "cap survived the low pressure tail")
                late = tail[-60:]
                self.assertNotIn(DecisionAction.RENEW, late)
                for action in TIGHTENING:
                    self.assertNotIn(action, late)

    def test_free_running_sequences_recover_and_hold_every_invariant(self):
        # Every refused frame leaves a gap here. A controller that never rebased
        # would stay in warmup for the rest of the trace and propose nothing.
        for seed in SEEDS:
            with self.subTest(seed=seed):
                snapshot, proposals, restores, tail = self.run_trace(seed, free_running=True)
                self.assertTrue(proposals, "trace never proposed a cap after a gap")
                self.assertTrue(restores, "trace never restored")
                self.assertIsNone(snapshot.active, "cap survived the low pressure tail")
                for action in (DecisionAction.RENEW, *TIGHTENING):
                    self.assertNotIn(action, tail[-60:])

    def test_generator_produces_the_intended_anomalies(self):
        # A trace that never degrades an input would assert nothing about the
        # fail closed paths, so the generator itself is checked.
        seen = set()
        for seed in SEEDS:
            rng = random.Random(seed)
            snapshot = ControllerSnapshot.initial()
            for second in range(STEPS):
                step = generate(rng, snapshot, second)
                if step.anomaly is not None:
                    seen.add(step.anomaly)
                snapshot = next_state(profile=ENFORCE, snapshot=snapshot, frame=step.frame,
                                      candidates=step.candidates,
                                      now_tick_100ns=step.now).next_snapshot
        self.assertEqual(seen, set(DEGRADING))


if __name__ == "__main__":
    unittest.main()
