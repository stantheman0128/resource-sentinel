"""Shadow helper loop: sample, decide, record. It cannot set a CPU cap.

This is the P4 helper of the adaptive scheduler plan
(docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md, the P4 block and
section 6.5). The plan's exit evidence for this stage is that shadow performs
zero Set and that the loop stays bounded, so this module measures its own cost
instead of regulating anyone's speed.

Zero Set is structural, not a runtime flag:
  - this module imports nothing that can mutate a Job, publish a recovery intent
    or reach a guardian; it imports data contracts, the pure decision layer and
    the sampler only;
  - the constructor takes a profile, a sampler, a clock and a shadow flag, so
    there is no parameter through which an actuator, a Job setter, a journal
    publisher or a guardian could arrive;
  - a decision that would cap is recorded with would_apply set and is never
    turned into a ControlProposal here.

One tick is bounded: one sample, one decision, one ring append. A late tick runs
once. Missed ticks are counted and dropped, never replayed, because catching up
would both burn the budget and feed the controller stale windows.

Nothing in this module emits an admission or capacity number. A rate that fell
because something was capped is recorded as a measurement and nothing else.

Mode: decision.validate_policy_profile accepts only mode off today, so a config
file cannot reach shadow. Until that changes, a caller enables shadow with the
explicit in-process shadow flag below, which is a test and development seam and
is deliberately unreachable from configuration. No thread, no scheduled task and
no CLI entry point exists here; a caller owns the cadence and calls tick().
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace

from .contracts import ContractViolation, Coverage, FastFrame, Priority, Role, TICKS_PER_SECOND
from .decision import (
    ControllerSnapshot, Decision, DecisionAction, Mode, PolicyProfile, VictimCandidate, next_state,
)
from .sampler import FrameSampler

TICKS_PER_MS = TICKS_PER_SECOND // 1000


@dataclass(frozen=True)
class Enrollment:
    """Registry facts about one enrolled Job, as the caller already knows them.

    None of these are verified here. capability_verified and coverage record
    what the enrolling side proved; this module only forwards them.
    """

    execution_id: str
    principal_id: str
    role: Role
    priority: Priority
    coverage: Coverage
    foreground: bool = False
    capability_verified: bool = False

    def __post_init__(self):
        for name in ("execution_id", "principal_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not 1 <= len(value) <= 128:
                raise ContractViolation(f"{name}: bounded identifier required")
        for name, enum_type in (("role", Role), ("priority", Priority), ("coverage", Coverage)):
            if not isinstance(getattr(self, name), enum_type):
                raise ContractViolation(f"{name}: typed enum required")
        for name in ("foreground", "capability_verified"):
            if type(getattr(self, name)) is not bool:
                raise ContractViolation(f"{name}: bool required")


@dataclass(frozen=True)
class DecisionRecord:
    """One recorded decision. It carries no handle and no authorization."""

    tick_100ns: int
    sample_seq: int
    action: DecisionAction
    reason: str
    state: str
    victim_execution_id: str | None
    target_cpu_rate_bp: int | None
    would_apply: bool
    executable: bool


@dataclass(frozen=True)
class HelperMetrics:
    """Cost of the loop itself, measured with the caller's monotonic clock.

    These are synthetic unless the clock and the backend are real. Nothing here
    is evidence for the plan's millisecond thresholds.
    """

    ticks: int
    frames: int
    frame_gaps: int
    late_ticks: int
    missed_ticks: int
    decisions: int
    last_tick_ms: float | None
    max_tick_ms: float | None
    total_tick_ms: float


@dataclass(frozen=True)
class TickResult:
    decision: Decision | None
    reason: str
    duration_ms: float
    missed_ticks: int
    sample_cost_ms: float


class ShadowHelper:
    """Bounded sample, decide and record loop with no actuator of any kind."""

    def __init__(self, *, profile: PolicyProfile, sampler: FrameSampler, clock,
                 shadow: bool = False):
        if not isinstance(profile, PolicyProfile):
            raise ContractViolation("profile: typed profile required")
        if not isinstance(sampler, FrameSampler):
            raise ContractViolation("sampler: typed FrameSampler required")
        if not callable(clock):
            raise ContractViolation("clock: monotonic tick source required")
        if type(shadow) is not bool:
            raise ContractViolation("shadow: bool required")
        if profile.mode is Mode.ENFORCE:
            # The helper has no Set path, so an enforce profile here would be a
            # claim it cannot honor.
            raise ContractViolation("mode: the shadow helper never enforces")
        mode = Mode.SHADOW if shadow or profile.mode is Mode.SHADOW else Mode.OFF
        self._profile = replace(profile, mode=mode)
        self._sampler = sampler
        self._clock = clock
        self._snapshot = ControllerSnapshot.initial()
        self._latest_frame: FastFrame | None = None
        self._ring: deque[DecisionRecord] = deque(maxlen=profile.sample_ring_frames)
        self._enrollments: dict[str, Enrollment] = {}
        self._uncapped: dict[str, deque[float]] = {}
        self._last_tick_100ns: int | None = None
        self._ticks = self._frames = self._gaps = self._late = self._missed = self._decisions = 0
        self._last_ms: float | None = None
        self._max_ms: float | None = None
        self._total_ms = 0.0

    @property
    def mode(self) -> Mode:
        return self._profile.mode

    @property
    def snapshot(self) -> ControllerSnapshot:
        return self._snapshot

    @property
    def latest_frame(self) -> FastFrame | None:
        """The most recent frame only. There is no frame history in memory."""
        return self._latest_frame

    @property
    def decisions(self) -> tuple[DecisionRecord, ...]:
        return tuple(self._ring)

    @property
    def metrics(self) -> HelperMetrics:
        return HelperMetrics(self._ticks, self._frames, self._gaps, self._late, self._missed,
                             self._decisions, self._last_ms, self._max_ms, self._total_ms)

    def enroll(self, enrollment: Enrollment) -> None:
        if not isinstance(enrollment, Enrollment):
            raise ContractViolation("enrollment: typed enrollment required")
        self._sampler.enroll(enrollment.execution_id)
        self._enrollments[enrollment.execution_id] = enrollment
        self._uncapped[enrollment.execution_id] = deque(maxlen=self._profile.baseline_samples)

    def release(self, execution_id: str) -> None:
        self._sampler.release(execution_id)
        self._enrollments.pop(execution_id, None)
        self._uncapped.pop(execution_id, None)

    def tick(self) -> TickResult:
        started = self._clock()
        if type(started) is not int or started < 0:
            raise ContractViolation("clock: unsigned interrupt tick required")
        missed = self._account_cadence(started)
        self._ticks += 1

        result = self._sampler.sample()
        decision = None
        reason = result.reason
        if result.frame is None:
            self._gaps += 1
        else:
            self._frames += 1
            self._latest_frame = result.frame
            decision = self._decide(result.frame)
            reason = decision.reason
        finished = self._clock()
        duration_ms = max(0, finished - started) / TICKS_PER_MS
        self._last_ms = duration_ms
        self._max_ms = duration_ms if self._max_ms is None else max(self._max_ms, duration_ms)
        self._total_ms += duration_ms
        return TickResult(decision, reason, duration_ms, missed, result.collection_cost_ms)

    def _account_cadence(self, started: int) -> int:
        """Count skipped intervals; never run them. Plan section 5.5 bounds the
        loop, so a late tick does one sample and the rest are lost on purpose."""
        missed = 0
        if self._last_tick_100ns is not None:
            interval = self._profile.sample_interval_ms * TICKS_PER_MS
            elapsed = started - self._last_tick_100ns
            missed = max(0, elapsed // interval - 1)
            if missed:
                self._late += 1
                self._missed += missed
        self._last_tick_100ns = started
        return missed

    def _decide(self, frame: FastFrame) -> Decision:
        now = self._clock()
        decision = next_state(profile=self._profile, snapshot=self._snapshot, frame=frame,
                              candidates=self._candidates(), now_tick_100ns=now)
        self._snapshot = decision.next_snapshot
        self._observe_uncapped(frame)
        self._decisions += 1
        self._ring.append(DecisionRecord(
            now, frame.sample_seq, decision.action, decision.reason,
            decision.next_snapshot.state.value, decision.victim_execution_id,
            None if decision.target is None else decision.target.cpu_rate_bp,
            decision.would_apply, decision.executable))
        return decision

    def _candidates(self) -> tuple[VictimCandidate, ...]:
        candidates = []
        for execution_id, enrollment in self._enrollments.items():
            candidates.append(VictimCandidate(
                execution_id, enrollment.principal_id, enrollment.role, enrollment.priority,
                enrollment.coverage, enrollment.foreground, enrollment.capability_verified,
                tuple(self._uncapped[execution_id])))
        return tuple(candidates)

    def _observe_uncapped(self, frame: FastFrame) -> None:
        """Keep a bounded uncapped history. A Job under our own cap contributes
        nothing, so a capped rate can never become its baseline."""
        active = self._snapshot.active
        for job in frame.jobs:
            history = self._uncapped.get(job.execution_id)
            if history is None or job.cpu_units is None or not job.membership_complete:
                continue
            if active is not None and active.execution_id == job.execution_id:
                continue
            history.append(job.cpu_units)


def would_apply_decisions(helper: ShadowHelper) -> tuple[DecisionRecord, ...]:
    """Recorded caps that shadow mode deliberately did not apply."""
    return tuple(record for record in helper.decisions if record.would_apply)
