"""Pure CPU control decisions: state machine, victim choice, target rate, config.

This module is the P4 "policy decision function" layer of the adaptive
scheduler plan (docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md, section
6 and section 13.1). The plan names the file policy.py, but that name is already
taken in this package by the POLICY mutex and ownership coordinator, which is a
different responsibility. The decision functions live here instead, and the name
mapping is: plan policy.next_state -> decision.next_state, plan
policy.select_victim -> decision.select_victim, plan policy.target_rate ->
decision.target_rate, plan config validation -> decision.validate_policy_profile.

Nothing here queries Windows, opens a database, reads a clock, or applies a
control. Every input is supplied by the caller and every output is an intent
that a guardian still has to verify against live authority before acting. A
returned decision is not an authorization: the guardian rereads exemptions,
ownership, identity and API readback on its own.

Fixed safety properties of this layer:
  - the only outputs are maintain, cap at level 1, cap at level 2, and restore;
  - no kill, no suspend, no RAM cap, no GPU control, no worker resize;
  - at most one active cap, over at most ten enrolled Jobs;
  - only explicitly background, P2/P3, Job contained candidates may be victims;
  - a usage drop caused by our own cap is never reported as new capacity, and
    this module emits no admission or capacity signal at all;
  - missing, stale, replayed or backwards samples fail closed: no new tightening
    ever, and an existing intervention is asked to restore.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
import math

from .contracts import (
    ContractViolation, Coverage, CpuControlMode, CpuTarget, FastFrame, MAX_ENROLLED_JOBS,
    Priority, Role, TICKS_PER_SECOND, UINT64_MAX, Validity, strict_json_loads,
)

TICKS_PER_MS = TICKS_PER_SECOND // 1000
MAX_ACTIVE_CAPS = 1
PROFILE_SCHEMA_VERSION = 1


class Mode(str, Enum):
    OFF = "off"
    SHADOW = "shadow"
    ENFORCE = "enforce"


class ControllerState(str, Enum):
    OFF = "OFF"
    WARMUP = "WARMUP"
    OBSERVING = "OBSERVING"
    PRESSURE_PENDING = "PRESSURE_PENDING"
    CAPPED_L1 = "CAPPED_L1"
    CAPPED_L2 = "CAPPED_L2"
    RECOVERING = "RECOVERING"
    COOLDOWN = "COOLDOWN"
    RESTORE_UNVERIFIED = "RESTORE_UNVERIFIED"


class DecisionAction(str, Enum):
    NO_POLICY_ACTION = "NO_POLICY_ACTION"
    OBSERVE = "OBSERVE"
    PROPOSE_L1 = "PROPOSE_L1"
    PROPOSE_L2 = "PROPOSE_L2"
    RENEW = "RENEW"
    REQUEST_RESTORE = "REQUEST_RESTORE"


TIGHTENING_ACTIONS = frozenset({DecisionAction.PROPOSE_L1, DecisionAction.PROPOSE_L2})


def _int(value, name, minimum=0, maximum=UINT64_MAX):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractViolation(f"{name}: integer out of range")
    return value


def _num(value, name, minimum=0.0, maximum=None, allow_minimum=True):
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ContractViolation(f"{name}: finite number required")
    if value < minimum or (not allow_minimum and value == minimum):
        raise ContractViolation(f"{name}: below permitted range")
    if maximum is not None and value > maximum:
        raise ContractViolation(f"{name}: above permitted range")
    return float(value)


def _typed(value, cls, name):
    if not isinstance(value, cls):
        raise ContractViolation(f"{name}: typed value required")
    return value


# --- configuration -----------------------------------------------------------


@dataclass(frozen=True)
class PolicyProfile:
    """Calibration starting points from plan section 6.1, shaped by section 13.1.

    Construction validates internal consistency only. The gate that keeps a
    config file away from enforce lives in validate_policy_profile, so an
    enforce profile can still be built in memory by a trace or a test.
    """

    mode: Mode
    max_enrolled_jobs: int
    max_active_caps: int
    eligible_roles: tuple[Role, ...]
    eligible_priorities: tuple[Priority, ...]
    sample_interval_ms: int
    sample_max_age_ms: int
    cpu_window_min_ms: int
    cpu_window_max_ms: int
    attribution_max_skew_ms: int
    high_cpu_pct: int
    high_samples: int
    baseline_samples: int
    victim_min_cpu_units: float
    victim_min_machine_busy_fraction: float
    retreat_l1_fraction: float
    retreat_l2_fraction: float
    retreat_l2_after_ms: int
    cap_floor_cpu_units: float
    normal_change_min_interval_ms: int
    recovery_cpu_pct: int
    recovery_continuous_ms: int
    lease_ms: int
    intervention_max_ms: int
    victim_cooldown_ms: int
    fault_backoff_ms: int
    prelaunch_lease_ms: int
    lifecycle_heartbeat_ms: int
    admission_release_uncapped_samples: int
    slow_required_counter_max_age_ms: int
    sample_ring_frames: int
    memory_member_scan_max_per_tick: int
    sampler_work_budget_ms: int
    log_max_bytes: int
    log_retention_days: int
    schema_version: int = PROFILE_SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != PROFILE_SCHEMA_VERSION:
            raise ContractViolation("schema_version: unsupported version")
        _typed(self.mode, Mode, "mode")
        _int(self.max_enrolled_jobs, "max_enrolled_jobs", 1, MAX_ENROLLED_JOBS)
        # Plan section 13.1: raising this is a scope change needing a new review.
        if self.max_active_caps != MAX_ACTIVE_CAPS:
            raise ContractViolation("max_active_caps: MVP allows exactly one active cap")
        if tuple(self.eligible_roles) != (Role.BACKGROUND,):
            raise ContractViolation("eligible_roles: only explicit background is eligible")
        if not self.eligible_priorities or set(self.eligible_priorities) - {Priority.P2, Priority.P3}:
            raise ContractViolation("eligible_priorities: only P2 and P3 are eligible")
        if len(set(self.eligible_priorities)) != len(self.eligible_priorities):
            raise ContractViolation("eligible_priorities: duplicate priority")
        for name, low, high in (("sample_interval_ms", 1, 60_000),
                                ("sample_max_age_ms", 1, 60_000),
                                ("cpu_window_min_ms", 1, 60_000),
                                ("cpu_window_max_ms", 1, 60_000),
                                ("attribution_max_skew_ms", 1, 60_000),
                                ("high_samples", 1, 64),
                                ("baseline_samples", 1, 64),
                                ("retreat_l2_after_ms", 1, 60_000),
                                ("normal_change_min_interval_ms", 1, 60_000),
                                ("recovery_continuous_ms", 1, 60_000),
                                ("lease_ms", 1, 60_000),
                                ("intervention_max_ms", 1, 60_000),
                                ("victim_cooldown_ms", 1, 3_600_000),
                                ("fault_backoff_ms", 1, 3_600_000),
                                ("prelaunch_lease_ms", 1, 3_600_000),
                                ("lifecycle_heartbeat_ms", 1, 3_600_000),
                                ("admission_release_uncapped_samples", 1, 64),
                                ("slow_required_counter_max_age_ms", 1, 3_600_000),
                                ("sample_ring_frames", 1, 4096),
                                ("memory_member_scan_max_per_tick", 1, 4096),
                                ("sampler_work_budget_ms", 1, 60_000),
                                ("log_max_bytes", 1, 1 << 40),
                                ("log_retention_days", 1, 365)):
            _int(getattr(self, name), name, low, high)
        _int(self.high_cpu_pct, "high_cpu_pct", 1, 100)
        _int(self.recovery_cpu_pct, "recovery_cpu_pct", 1, 100)
        _num(self.victim_min_cpu_units, "victim_min_cpu_units", 0.0, 4096.0, allow_minimum=False)
        _num(self.victim_min_machine_busy_fraction, "victim_min_machine_busy_fraction",
             0.0, 1.0, allow_minimum=False)
        _num(self.retreat_l1_fraction, "retreat_l1_fraction", 0.0, 1.0, allow_minimum=False)
        _num(self.retreat_l2_fraction, "retreat_l2_fraction", 0.0, 1.0, allow_minimum=False)
        _num(self.cap_floor_cpu_units, "cap_floor_cpu_units", 0.0, 4096.0, allow_minimum=False)
        if not self.recovery_cpu_pct < self.high_cpu_pct:
            raise ContractViolation("recovery_cpu_pct: recovery must be below high pressure")
        if not self.retreat_l2_fraction <= self.retreat_l1_fraction < 1:
            raise ContractViolation("retreat fractions: level 2 must not exceed level 1")
        if not self.lease_ms > self.sample_max_age_ms:
            raise ContractViolation("lease_ms: lease must outlast sample freshness")
        if not self.normal_change_min_interval_ms < self.intervention_max_ms:
            raise ContractViolation("normal_change_min_interval_ms: step must fit the intervention")
        if not self.cpu_window_min_ms < self.cpu_window_max_ms:
            raise ContractViolation("cpu_window_min_ms: window bounds inverted")
        if not self.sample_max_age_ms >= self.sample_interval_ms:
            raise ContractViolation("sample_max_age_ms: freshness below sample interval")
        if self.sample_ring_frames < max(self.baseline_samples, self.high_samples):
            raise ContractViolation("sample_ring_frames: ring smaller than required history")


def validate_policy_profile(payload: dict) -> PolicyProfile:
    """Validate a config object; unknown keys and non-MVP values are rejected.

    Plan section 13.1 requires more than type checks. Modes off and shadow are
    selectable from config because neither one applies a cap. Enforce is not:
    plan section 11.4 promotes through an isolated canary and then explicit
    limited enrollment, which is a guardian acknowledged ledger operation, so a
    config file must never be able to turn control on.
    """
    if type(payload) is not dict:
        raise ContractViolation("profile: object required")
    expected = {field.name for field in fields(PolicyProfile)}
    if set(payload) != expected:
        raise ContractViolation("profile: missing or unknown keys")
    data = dict(payload)
    if data["mode"] not in (Mode.OFF.value, Mode.SHADOW.value):
        raise ContractViolation("mode: only off and shadow are selectable from config")
    data["mode"] = Mode(data["mode"])
    for name, enum_type in (("eligible_roles", Role), ("eligible_priorities", Priority)):
        value = data[name]
        if type(value) is not list or not value or len(value) > 8:
            raise ContractViolation(f"{name}: bounded list required")
        try:
            data[name] = tuple(enum_type(item) for item in value)
        except (ValueError, TypeError):
            raise ContractViolation(f"{name}: unknown enum value") from None
    return PolicyProfile(**data)


def parse_policy_profile(payload: str | bytes) -> PolicyProfile:
    """Decode a config document with the bounded protocol decoder, then validate."""
    return validate_policy_profile(strict_json_loads(payload))


# --- inputs ------------------------------------------------------------------


@dataclass(frozen=True)
class VictimCandidate:
    """One enrolled Job as the caller knows it, before any frame is consulted.

    ineligible_until_tick_100ns carries the caller's fault backoff and any other
    externally decided exclusion. It is an exclusion only: a zero value means
    "no recorded exclusion", never "verified eligible".
    """

    execution_id: str
    principal_id: str
    role: Role
    priority: Priority
    coverage: Coverage
    foreground: bool
    capability_verified: bool
    uncapped_samples: tuple[float, ...]
    ineligible_until_tick_100ns: int = 0
    last_controlled_tick_100ns: int = 0

    def __post_init__(self):
        for name in ("execution_id", "principal_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not 1 <= len(value) <= 128:
                raise ContractViolation(f"{name}: bounded identifier required")
        _typed(self.role, Role, "role")
        _typed(self.priority, Priority, "priority")
        _typed(self.coverage, Coverage, "coverage")
        for name in ("foreground", "capability_verified"):
            if type(getattr(self, name)) is not bool:
                raise ContractViolation(f"{name}: bool required")
        if type(self.uncapped_samples) is not tuple or len(self.uncapped_samples) > 4096:
            raise ContractViolation("uncapped_samples: bounded immutable samples required")
        for sample in self.uncapped_samples:
            _num(sample, "uncapped_samples", 0.0, 4096.0)
        _int(self.ineligible_until_tick_100ns, "ineligible_until_tick_100ns")
        _int(self.last_controlled_tick_100ns, "last_controlled_tick_100ns")


@dataclass(frozen=True)
class ActiveIntervention:
    """Bookkeeping for the single in-flight intervention.

    started_tick_100ns is when this module first proposed a cap, not when the
    guardian confirmed one. Starting the deadline clock at the earlier moment
    only shortens the intervention, which is the conservative direction.
    """

    execution_id: str
    level: int
    baseline_cpu_units: float
    started_tick_100ns: int
    deadline_tick_100ns: int
    level_entered_tick_100ns: int

    def __post_init__(self):
        if not isinstance(self.execution_id, str) or not self.execution_id:
            raise ContractViolation("execution_id: identifier required")
        if self.level not in (1, 2):
            raise ContractViolation("level: only two retreat levels exist")
        _num(self.baseline_cpu_units, "baseline_cpu_units", 0.0, 4096.0, allow_minimum=False)
        for name in ("started_tick_100ns", "deadline_tick_100ns", "level_entered_tick_100ns"):
            _int(getattr(self, name), name)
        if self.deadline_tick_100ns <= self.started_tick_100ns:
            raise ContractViolation("deadline_tick_100ns: bounded intervention required")
        if self.level_entered_tick_100ns < self.started_tick_100ns:
            raise ContractViolation("level_entered_tick_100ns: level predates intervention")


@dataclass(frozen=True)
class ControllerSnapshot:
    """Everything the state machine carries between ticks."""

    state: ControllerState
    sampler_epoch: str | None = None
    clock_epoch: str | None = None
    last_sample_seq: int | None = None
    last_tick_100ns: int | None = None
    uncapped_streak: int = 0
    high_streak: int = 0
    low_since_tick_100ns: int | None = None
    active: ActiveIntervention | None = None
    cooldown_execution_id: str | None = None
    cooldown_until_tick_100ns: int = 0

    def __post_init__(self):
        _typed(self.state, ControllerState, "state")
        for name in ("sampler_epoch", "clock_epoch", "cooldown_execution_id"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128):
                raise ContractViolation(f"{name}: bounded identifier or null required")
        for name in ("last_sample_seq", "last_tick_100ns", "low_since_tick_100ns"):
            if getattr(self, name) is not None:
                _int(getattr(self, name), name)
        _int(self.uncapped_streak, "uncapped_streak", 0, 4096)
        _int(self.high_streak, "high_streak", 0, 4096)
        _int(self.cooldown_until_tick_100ns, "cooldown_until_tick_100ns")
        if self.active is not None:
            _typed(self.active, ActiveIntervention, "active")

    @classmethod
    def initial(cls) -> "ControllerSnapshot":
        return cls(state=ControllerState.OFF)


@dataclass(frozen=True)
class VictimSelection:
    """Chosen Job, or none, plus the work this scan cost.

    examined counts every candidate inspection, so a caller or a test can bound
    the scan without timing it.
    """

    execution_id: str | None
    baseline_cpu_units: float | None
    reason: str
    examined: int


@dataclass(frozen=True)
class Decision:
    """A CPU rate intent. There is deliberately no capacity or admission field.

    executable is true only for a restore, or for a cap while mode is enforce.
    In shadow mode a cap decision carries would_apply and the caller must record
    it without building a ControlProposal from it.
    """

    action: DecisionAction
    reason: str
    next_snapshot: ControllerSnapshot
    victim_execution_id: str | None
    target: CpuTarget | None
    lease_deadline_tick_100ns: int | None
    executable: bool
    would_apply: bool
    examined_candidates: int


# --- pure calculations -------------------------------------------------------


def uncapped_baseline(samples: tuple[float, ...], baseline_samples: int) -> float | None:
    """Median of the most recent uncapped samples; None when history is short.

    Plan section 6.1: the baseline is the median of the victim's last five valid
    uncapped CPU unit samples. Too few samples is not a small baseline, it is no
    baseline, so this returns None and the caller must not cap.
    """
    if type(samples) is not tuple:
        raise ContractViolation("samples: immutable samples required")
    _int(baseline_samples, "baseline_samples", 1, 64)
    if len(samples) < baseline_samples:
        return None
    window = sorted(samples[-baseline_samples:])
    middle = len(window) // 2
    if len(window) % 2:
        return float(window[middle])
    return (window[middle - 1] + window[middle]) / 2


def target_rate(*, baseline_cpu_units: float, fraction: float, logical_processors: int,
                floor_cpu_units: float = 1.0) -> CpuTarget | None:
    """Convert a baseline and retreat fraction into a typed CPU rate target.

    Plan section 6.1: target is max(floor, fraction * baseline) and the floor is
    a ceiling that will not go lower, not a reservation. Plan section 6.1 cap
    conversion: cpu_rate_bp = ceil(10000 * target / N), which CpuTarget itself
    recomputes. A target at or above N cannot be expressed as an effective cap,
    so this returns None and the caller must not propose one.
    """
    _num(baseline_cpu_units, "baseline_cpu_units", 0.0, 4096.0, allow_minimum=False)
    _num(fraction, "fraction", 0.0, 1.0, allow_minimum=False)
    if fraction >= 1:
        raise ContractViolation("fraction: a retreat must be below the baseline")
    _num(floor_cpu_units, "floor_cpu_units", 0.0, 4096.0, allow_minimum=False)
    _int(logical_processors, "logical_processors", 1, 4096)
    target = max(floor_cpu_units, fraction * baseline_cpu_units)
    if target >= logical_processors:
        return None
    rate_bp = math.ceil(10000 * target / logical_processors)
    return CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, target, rate_bp, logical_processors)


def machine_busy_fraction(frame: FastFrame) -> float | None:
    """Whole machine busy as a fraction of logical processors, or None if unknown."""
    _typed(frame, FastFrame, "frame")
    if frame.machine.cpu_busy_units is None:
        return None
    return frame.machine.cpu_busy_units / frame.machine.logical_processors


def lease_deadline_tick(profile: PolicyProfile, *, now_tick_100ns: int,
                        sample_window_end_tick_100ns: int,
                        intervention_deadline_tick_100ns: int) -> int:
    """Plan section 13.2 lease formula, bounded by the original intervention.

    lease_deadline = min(now + lease, sample_window_end + lease, intervention
    deadline). A sample already near its freshness limit therefore cannot buy a
    full fresh lease. This is arithmetic, not a renewal authorization: the
    guardian owns the lease and reverifies everything before honoring it.
    """
    _typed(profile, PolicyProfile, "profile")
    for name, value in (("now_tick_100ns", now_tick_100ns),
                        ("sample_window_end_tick_100ns", sample_window_end_tick_100ns),
                        ("intervention_deadline_tick_100ns", intervention_deadline_tick_100ns)):
        _int(value, name)
    age = now_tick_100ns - sample_window_end_tick_100ns
    if not 0 <= age <= profile.sample_max_age_ms * TICKS_PER_MS:
        raise ContractViolation("lease: fresh same-clock sample required")
    limit = profile.intervention_max_ms * TICKS_PER_MS
    if not now_tick_100ns < intervention_deadline_tick_100ns <= now_tick_100ns + limit:
        raise ContractViolation("lease: active bounded intervention required")
    lease = profile.lease_ms * TICKS_PER_MS
    return min(now_tick_100ns + lease, sample_window_end_tick_100ns + lease,
               intervention_deadline_tick_100ns)


# --- victim selection --------------------------------------------------------


def select_victim(*, profile: PolicyProfile, frame: FastFrame,
                  candidates: tuple[VictimCandidate, ...], now_tick_100ns: int,
                  excluded_execution_id: str | None = None) -> VictimSelection:
    """Pick at most one Job to slow down, or none.

    Plan section 6.3: aggregate known background CPU per principal, then take
    from the largest eligible principal the Job with the largest actual CPU.
    Ties break on the earlier last controlled time, then on execution id.

    A candidate is eligible only with an explicit background role, an eligible
    priority, Job contained coverage, verified capability, no foreground claim,
    no caller recorded exclusion, a matching complete measurement in this frame,
    a baseline of at least victim_min_cpu_units, and at least
    victim_min_machine_busy_fraction of the machine's busy CPU. Anything unknown
    is not eligible.

    The scan is two bounded passes over at most max_enrolled_jobs candidates.
    """
    _typed(profile, PolicyProfile, "profile")
    _typed(frame, FastFrame, "frame")
    _int(now_tick_100ns, "now_tick_100ns")
    _check_candidates(profile, candidates)
    busy = None if frame.machine.cpu_busy_units is None else frame.machine.cpu_busy_units
    if busy is None:
        return VictimSelection(None, None, "denominator_unknown", 0)
    measured = {job.execution_id: job for job in frame.jobs}
    eligible = []
    examined = 0
    for candidate in candidates:
        examined += 1
        job = measured.get(candidate.execution_id)
        if (candidate.role is not Role.BACKGROUND
                or candidate.priority not in profile.eligible_priorities
                or candidate.coverage is not Coverage.JOB_CONTAINED
                or candidate.foreground
                or not candidate.capability_verified
                or candidate.execution_id == excluded_execution_id
                or now_tick_100ns < candidate.ineligible_until_tick_100ns
                or job is None or job.cpu_units is None or not job.membership_complete):
            continue
        baseline = uncapped_baseline(candidate.uncapped_samples, profile.baseline_samples)
        if baseline is None or baseline < profile.victim_min_cpu_units:
            continue
        if job.cpu_units < profile.victim_min_machine_busy_fraction * busy:
            continue
        eligible.append((candidate, job.cpu_units, baseline))
    if not eligible:
        return VictimSelection(None, None, "no_eligible_victim", examined)
    totals: dict[str, float] = {}
    for candidate, cpu_units, _ in eligible:
        examined += 1
        totals[candidate.principal_id] = totals.get(candidate.principal_id, 0.0) + cpu_units
    principal = max(sorted(totals), key=lambda name: totals[name])
    chosen = max(
        (item for item in eligible if item[0].principal_id == principal),
        key=lambda item: (item[1], -item[0].last_controlled_tick_100ns, _reverse_key(item[0].execution_id)),
    )
    return VictimSelection(chosen[0].execution_id, chosen[2], "selected", examined)


def _reverse_key(execution_id: str) -> tuple[int, ...]:
    # max() with a descending tiebreak on a string: compare negated code points.
    return tuple(-ord(char) for char in execution_id)


def _check_candidates(profile: PolicyProfile, candidates) -> None:
    if type(candidates) is not tuple:
        raise ContractViolation("candidates: immutable bounded tuple required")
    if len(candidates) > min(profile.max_enrolled_jobs, MAX_ENROLLED_JOBS):
        raise ContractViolation("candidates: at most max_enrolled_jobs enrolled Jobs")
    for candidate in candidates:
        _typed(candidate, VictimCandidate, "candidates")
    if len({candidate.execution_id for candidate in candidates}) != len(candidates):
        raise ContractViolation("candidates: duplicate execution")


# --- state machine -----------------------------------------------------------


# Plan section 5.3: without private memory attribution the physical deduction is
# zero. The frame contract makes such a frame carry this error. This module reads
# no per-Job memory, so the error says nothing about the CPU evidence.
NON_BLOCKING_FRAME_ERRORS = frozenset({"memory_attribution_unavailable"})


def _evidence_problem(profile: PolicyProfile, snapshot: ControllerSnapshot,
                      frame: FastFrame, now_tick_100ns: int) -> str | None:
    """Fail closed reasons. Any non-None result forbids new tightening."""
    if frame.validity is not Validity.VALID:
        return "frame_invalid"
    if any(error.code not in NON_BLOCKING_FRAME_ERRORS for error in frame.errors):
        return "frame_errors"
    if frame.machine.cpu_busy_units is None:
        return "denominator_unknown"
    if snapshot.sampler_epoch is not None and snapshot.sampler_epoch != frame.sampler_epoch:
        return "sampler_epoch_changed"
    if snapshot.clock_epoch is not None and snapshot.clock_epoch != frame.clock_epoch:
        return "clock_epoch_changed"
    if snapshot.last_sample_seq is not None:
        if frame.sample_seq <= snapshot.last_sample_seq:
            return "sample_replay"
        if frame.sample_seq != snapshot.last_sample_seq + 1:
            return "sample_gap"
    if snapshot.last_tick_100ns is not None and now_tick_100ns < snapshot.last_tick_100ns:
        return "clock_backwards"
    if now_tick_100ns < frame.window_end_tick_100ns:
        return "clock_inconsistent"
    if now_tick_100ns - frame.window_end_tick_100ns > profile.sample_max_age_ms * TICKS_PER_MS:
        return "sample_stale"
    window_ms = (frame.window_end_tick_100ns - frame.window_start_tick_100ns) / TICKS_PER_MS
    if not profile.cpu_window_min_ms <= window_ms <= profile.cpu_window_max_ms:
        return "sample_window_invalid"
    return None


CONTINUITY_BREAKS = frozenset({"sample_gap", "sampler_epoch_changed", "clock_epoch_changed"})


def _rebase_frame(profile: PolicyProfile, snapshot: ControllerSnapshot, frame: FastFrame,
                  now_tick_100ns: int, problem: str) -> FastFrame | None:
    """The frame to restart warmup from after a continuity break, if it is sound.

    Plan sections 5.4 and 6.2 reset warmup on a gap or an epoch change and wait
    for fresh frames. Keeping the old sequence would refuse every later frame as
    another gap. A frame becomes the new baseline only when it fails no check
    besides continuity, and the tick that adopts it never acts on it. A replay
    inside one epoch is not a continuity break and is never adopted.
    """
    if problem not in CONTINUITY_BREAKS:
        return None
    # Ticks of a new clock epoch are not comparable with the old last tick.
    last_tick = None if problem == "clock_epoch_changed" else snapshot.last_tick_100ns
    fresh = ControllerSnapshot(state=ControllerState.WARMUP, last_tick_100ns=last_tick)
    return frame if _evidence_problem(profile, fresh, frame, now_tick_100ns) is None else None


def _observed(snapshot: ControllerSnapshot, frame: FastFrame, now_tick_100ns: int,
              **changes) -> ControllerSnapshot:
    values = dict(sampler_epoch=frame.sampler_epoch, clock_epoch=frame.clock_epoch,
                  last_sample_seq=frame.sample_seq, last_tick_100ns=now_tick_100ns,
                  uncapped_streak=snapshot.uncapped_streak, high_streak=snapshot.high_streak,
                  low_since_tick_100ns=snapshot.low_since_tick_100ns, active=snapshot.active,
                  cooldown_execution_id=snapshot.cooldown_execution_id,
                  cooldown_until_tick_100ns=snapshot.cooldown_until_tick_100ns)
    values.update(changes)
    return ControllerSnapshot(**values)


def _decide(action: DecisionAction, reason: str, snapshot: ControllerSnapshot, *,
            mode: Mode, victim: str | None = None, target: CpuTarget | None = None,
            lease: int | None = None, examined: int = 0) -> Decision:
    # Restores are always executable. Tightening and renewal execute only in
    # enforce mode; shadow records a would-apply and enforces nothing.
    if action is DecisionAction.REQUEST_RESTORE:
        executable, would_apply = True, False
    elif action in TIGHTENING_ACTIONS or action is DecisionAction.RENEW:
        executable = mode is Mode.ENFORCE
        would_apply = mode is Mode.SHADOW
    else:
        executable, would_apply = False, False
    return Decision(action, reason, snapshot, victim, target, lease, executable, would_apply, examined)


def next_state(*, profile: PolicyProfile, snapshot: ControllerSnapshot, frame: FastFrame,
               candidates: tuple[VictimCandidate, ...], now_tick_100ns: int) -> Decision:
    """One controller tick over plan section 6.2 and the section 6.5 pseudocode.

    The returned decision carries the next snapshot, so a caller drives a trace
    by feeding each result back in. Restore reasons name the plan's restore
    states: exempt and degraded evidence map to a degraded restore, the absolute
    deadline and cleared pressure map to recovery, and an unverified restore
    stays unverified rather than claiming OFF.
    """
    _typed(profile, PolicyProfile, "profile")
    _typed(snapshot, ControllerSnapshot, "snapshot")
    _typed(frame, FastFrame, "frame")
    _int(now_tick_100ns, "now_tick_100ns")
    _check_candidates(profile, candidates)

    if profile.mode is Mode.OFF:
        if snapshot.active is not None:
            return _restore(profile, snapshot, now_tick_100ns, "mode_off_restore", frame=frame)
        return _decide(DecisionAction.NO_POLICY_ACTION, "mode_off",
                       ControllerSnapshot(state=ControllerState.OFF), mode=profile.mode)

    if snapshot.state is ControllerState.RESTORE_UNVERIFIED:
        return _decide(DecisionAction.REQUEST_RESTORE, "restore_unverified",
                       _observed(snapshot, frame, now_tick_100ns, state=ControllerState.RESTORE_UNVERIFIED,
                                 uncapped_streak=0, high_streak=0, low_since_tick_100ns=None),
                       mode=profile.mode, victim=snapshot.active.execution_id if snapshot.active else None)

    problem = _evidence_problem(profile, snapshot, frame, now_tick_100ns)
    if problem is not None:
        rebase = _rebase_frame(profile, snapshot, frame, now_tick_100ns, problem)
        if snapshot.active is not None:
            return _restore(profile, snapshot, now_tick_100ns, problem, frame=rebase)
        # Do not adopt epochs or sequence numbers from a frame we rejected. A
        # sound frame after a continuity break is the one exception: it becomes
        # the baseline warmup restarts from, with every streak at zero.
        if rebase is not None:
            return _decide(DecisionAction.OBSERVE, problem,
                           _observed(snapshot, rebase, now_tick_100ns,
                                     state=ControllerState.WARMUP, uncapped_streak=0,
                                     high_streak=0, low_since_tick_100ns=None),
                           mode=profile.mode)
        return _decide(DecisionAction.OBSERVE, problem,
                       ControllerSnapshot(state=ControllerState.WARMUP,
                                          sampler_epoch=snapshot.sampler_epoch,
                                          clock_epoch=snapshot.clock_epoch,
                                          last_sample_seq=snapshot.last_sample_seq,
                                          last_tick_100ns=snapshot.last_tick_100ns,
                                          cooldown_execution_id=snapshot.cooldown_execution_id,
                                          cooldown_until_tick_100ns=snapshot.cooldown_until_tick_100ns),
                       mode=profile.mode)

    busy_pct = 100 * machine_busy_fraction(frame)
    if snapshot.active is not None:
        return _active_tick(profile, snapshot, frame, candidates, now_tick_100ns, busy_pct)
    return _idle_tick(profile, snapshot, frame, candidates, now_tick_100ns, busy_pct)


def _restore(profile: PolicyProfile, snapshot: ControllerSnapshot, now_tick_100ns: int,
             reason: str, frame: FastFrame | None = None) -> Decision:
    """Ask for removal of our own cap and arm the victim cooldown."""
    active = snapshot.active
    cooldown = now_tick_100ns + profile.victim_cooldown_ms * TICKS_PER_MS
    values = dict(state=ControllerState.COOLDOWN, uncapped_streak=0, high_streak=0,
                  low_since_tick_100ns=None, active=None,
                  cooldown_execution_id=active.execution_id if active else None,
                  cooldown_until_tick_100ns=cooldown)
    if frame is not None:
        next_snapshot = _observed(snapshot, frame, now_tick_100ns, **values)
    else:
        next_snapshot = ControllerSnapshot(sampler_epoch=snapshot.sampler_epoch,
                                           clock_epoch=snapshot.clock_epoch,
                                           last_sample_seq=snapshot.last_sample_seq,
                                           last_tick_100ns=snapshot.last_tick_100ns, **values)
    return _decide(DecisionAction.REQUEST_RESTORE, reason, next_snapshot, mode=profile.mode,
                   victim=active.execution_id if active else None)


def _active_tick(profile: PolicyProfile, snapshot: ControllerSnapshot, frame: FastFrame,
                 candidates: tuple[VictimCandidate, ...], now_tick_100ns: int,
                 busy_pct: float) -> Decision:
    active = snapshot.active
    if now_tick_100ns >= active.deadline_tick_100ns:
        return _restore(profile, snapshot, now_tick_100ns, "intervention_deadline", frame=frame)

    # The victim must still be the same Job and still be eligible. A capped Job
    # reports reduced CPU, so its live CPU share is not rechecked here; only the
    # structural eligibility is, which a cap cannot change.
    still = [c for c in candidates if c.execution_id == active.execution_id]
    measured = {job.execution_id: job for job in frame.jobs}
    job = measured.get(active.execution_id)
    if (not still or job is None or not job.membership_complete
            or still[0].role is not Role.BACKGROUND
            or still[0].priority not in profile.eligible_priorities
            or still[0].coverage is not Coverage.JOB_CONTAINED
            or still[0].foreground or not still[0].capability_verified
            or now_tick_100ns < still[0].ineligible_until_tick_100ns):
        return _restore(profile, snapshot, now_tick_100ns, "no_longer_eligible", frame=frame)

    if busy_pct < profile.recovery_cpu_pct:
        low_since = snapshot.low_since_tick_100ns
        low_since = now_tick_100ns if low_since is None else low_since
        if now_tick_100ns - low_since >= profile.recovery_continuous_ms * TICKS_PER_MS:
            return _restore(profile, snapshot, now_tick_100ns, "pressure_cleared", frame=frame)
        return _renew(profile, snapshot, frame, now_tick_100ns, "recovery_pending",
                      low_since_tick_100ns=low_since)

    since_level = now_tick_100ns - active.level_entered_tick_100ns
    if (active.level == 1 and since_level >= profile.retreat_l2_after_ms * TICKS_PER_MS
            and since_level >= profile.normal_change_min_interval_ms * TICKS_PER_MS):
        target = target_rate(baseline_cpu_units=active.baseline_cpu_units,
                             fraction=profile.retreat_l2_fraction,
                             logical_processors=frame.machine.logical_processors,
                             floor_cpu_units=profile.cap_floor_cpu_units)
        if target is not None:
            escalated = ActiveIntervention(active.execution_id, 2, active.baseline_cpu_units,
                                           active.started_tick_100ns, active.deadline_tick_100ns,
                                           now_tick_100ns)
            lease = lease_deadline_tick(profile, now_tick_100ns=now_tick_100ns,
                                        sample_window_end_tick_100ns=frame.window_end_tick_100ns,
                                        intervention_deadline_tick_100ns=active.deadline_tick_100ns)
            return _decide(DecisionAction.PROPOSE_L2, "retreat_level_2",
                           _observed(snapshot, frame, now_tick_100ns, state=ControllerState.CAPPED_L2,
                                     low_since_tick_100ns=None, active=escalated),
                           mode=profile.mode, victim=active.execution_id, target=target, lease=lease)
    return _renew(profile, snapshot, frame, now_tick_100ns, "maintain", low_since_tick_100ns=None)


def _renew(profile: PolicyProfile, snapshot: ControllerSnapshot, frame: FastFrame,
           now_tick_100ns: int, reason: str, *, low_since_tick_100ns: int | None) -> Decision:
    active = snapshot.active
    lease = lease_deadline_tick(profile, now_tick_100ns=now_tick_100ns,
                                sample_window_end_tick_100ns=frame.window_end_tick_100ns,
                                intervention_deadline_tick_100ns=active.deadline_tick_100ns)
    state = ControllerState.CAPPED_L1 if active.level == 1 else ControllerState.CAPPED_L2
    if reason == "recovery_pending":
        state = ControllerState.RECOVERING
    return _decide(DecisionAction.RENEW, reason,
                   _observed(snapshot, frame, now_tick_100ns, state=state,
                             low_since_tick_100ns=low_since_tick_100ns),
                   mode=profile.mode, victim=active.execution_id, lease=lease)


def _idle_tick(profile: PolicyProfile, snapshot: ControllerSnapshot, frame: FastFrame,
               candidates: tuple[VictimCandidate, ...], now_tick_100ns: int,
               busy_pct: float) -> Decision:
    uncapped_streak = min(snapshot.uncapped_streak + 1, profile.baseline_samples)
    high_streak = snapshot.high_streak + 1 if busy_pct >= profile.high_cpu_pct else 0
    high_streak = min(high_streak, profile.high_samples)
    observe = lambda state, reason, examined=0: _decide(  # noqa: E731 - local shorthand
        DecisionAction.OBSERVE, reason,
        _observed(snapshot, frame, now_tick_100ns, state=state, uncapped_streak=uncapped_streak,
                  high_streak=high_streak, low_since_tick_100ns=None),
        mode=profile.mode, examined=examined)

    if uncapped_streak < profile.baseline_samples:
        return observe(ControllerState.WARMUP, "warmup")
    if high_streak < profile.high_samples:
        state = ControllerState.PRESSURE_PENDING if high_streak else ControllerState.OBSERVING
        return observe(state, "pressure_pending" if high_streak else "observing")

    excluded = None
    if now_tick_100ns < snapshot.cooldown_until_tick_100ns:
        excluded = snapshot.cooldown_execution_id
    selection = select_victim(profile=profile, frame=frame, candidates=candidates,
                              now_tick_100ns=now_tick_100ns, excluded_execution_id=excluded)
    if selection.execution_id is None:
        return observe(ControllerState.PRESSURE_PENDING, selection.reason, selection.examined)
    target = target_rate(baseline_cpu_units=selection.baseline_cpu_units,
                         fraction=profile.retreat_l1_fraction,
                         logical_processors=frame.machine.logical_processors,
                         floor_cpu_units=profile.cap_floor_cpu_units)
    if target is None:
        return observe(ControllerState.PRESSURE_PENDING, "target_exceeds_denominator", selection.examined)
    deadline = now_tick_100ns + profile.intervention_max_ms * TICKS_PER_MS
    active = ActiveIntervention(selection.execution_id, 1, selection.baseline_cpu_units,
                                now_tick_100ns, deadline, now_tick_100ns)
    lease = lease_deadline_tick(profile, now_tick_100ns=now_tick_100ns,
                                sample_window_end_tick_100ns=frame.window_end_tick_100ns,
                                intervention_deadline_tick_100ns=deadline)
    return _decide(DecisionAction.PROPOSE_L1, "retreat_level_1",
                   _observed(snapshot, frame, now_tick_100ns, state=ControllerState.CAPPED_L1,
                             uncapped_streak=0, high_streak=high_streak,
                             low_since_tick_100ns=None, active=active),
                   mode=profile.mode, victim=selection.execution_id, target=target, lease=lease,
                   examined=selection.examined)
