"""Paired A/B benchmark harness for the adaptive scheduler (plan P6, section 11.3).

This module owns the schedule, the run record schema, the pure statistics, the
promotion threshold checks and the report renderer for the A0 / A1 / B
comparison required by docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md
sections 11.1 to 11.4. It measures nothing. It launches nothing, touches no
running process, and reads neither the live Sentinel database nor its config.

Native implementation and native acceptance evidence are distinct. This pure
analyzer consumes independently pinned measurements from a concrete runner;
it cannot establish those measurements itself. It refuses to turn fabricated
numbers or incomplete provenance into a pass:

  - every run record carries an evidence source, measured or synthetic;
  - one synthetic record anywhere in a comparison forces the verdict
    NOT_MEASURED, whatever the numbers say;
  - fewer than ten valid pairs, or a missing variant, forces INSUFFICIENT_DATA;
  - a comparison that neither the plan nor the labelled clarification gives a
    number for reports NO_THRESHOLD_DEFINED rather than a pass;
  - a scenario where A1 foreground p95 is already below twenty milliseconds
    reports NO_PROBLEM_TO_CONTROL, which is the plan's "沒有足夠需要控制的問題";
  - no verdict value means "A/B complete". The best available value means the
    thresholds this plan names were met by measured paired data, nothing more.

Every threshold constant below is quoted from plan section 11.3. Plan 11.3
leaves the A0 to A1 and A0 to B comparisons without numbers of their own, so
those two reuse plan numbers under the labelled clarification C1 and C2 recorded
in docs/planning/adaptive-scheduler/AB-THRESHOLD-CLARIFICATION.md. No number in
this module is new. Checks produced under the clarification name it in their
detail text, so a report reader can tell a plan threshold from a clarified one.
Where neither the plan nor the clarification gives a number, this module says so
in the check detail instead of inventing one; those gaps are listed in PLAN_GAPS.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import Enum
import argparse
import hashlib
import json
import math
import random
import sys
from typing import Protocol, Sequence


class BenchmarkDataError(Exception):
    """A run record, schedule request or comparison input is not usable."""


# --- validation helpers ------------------------------------------------------


def _int(value, name, minimum=0, maximum=1 << 62):
    if type(value) is not int or not minimum <= value <= maximum:
        raise BenchmarkDataError(f"{name}: integer out of range")
    return value


def _finite(value, name):
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise BenchmarkDataError(f"{name}: finite number required")
    return float(value)


def _num(value, name, minimum=0.0, maximum=None, allow_minimum=True):
    number = _finite(value, name)
    if number < minimum or (not allow_minimum and number == minimum):
        raise BenchmarkDataError(f"{name}: below permitted range")
    if maximum is not None and number > maximum:
        raise BenchmarkDataError(f"{name}: above permitted range")
    return number


def _typed(value, cls, name):
    if not isinstance(value, cls):
        raise BenchmarkDataError(f"{name}: typed value required")
    return value


def _text(value, name, max_length=200):
    if type(value) is not str or not value.strip() or len(value) > max_length:
        raise BenchmarkDataError(f"{name}: non-empty text required")
    return value


def _sha256(value, name):
    if (type(value) is not str or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise BenchmarkDataError(f"{name}: lowercase SHA256 required")
    return value


# --- closed vocabularies -----------------------------------------------------


class Variant(str, Enum):
    """Plan section 11.3: the three versions under comparison."""

    A0 = "A0"   # P0 confirmed live baseline, original config and collector
    A1 = "A1"   # fixed lifecycle and accounting, helper and guardian present, no CPU cap set
    B = "B"     # identical to A1, single approved victim CPU policy enabled


class Comparison(str, Enum):
    """Plan section 11.3: what each comparison is allowed to show."""

    A0_A1 = "A0_A1"   # cost of the observer, the new launch path and the accounting change
    A1_B = "A1_B"     # the CPU control itself
    A0_B = "A0_B"     # whether the end user actually benefits


COMPARISON_VARIANTS = {
    Comparison.A0_A1: (Variant.A0, Variant.A1),
    Comparison.A1_B: (Variant.A1, Variant.B),
    Comparison.A0_B: (Variant.A0, Variant.B),
}

COMPARISON_SCOPE = {
    Comparison.A0_A1: "observer, new launch and accounting cost only; says nothing about CPU control",
    Comparison.A1_B: "the CPU control itself only; hides any infrastructure regression",
    Comparison.A0_B: "end to end user effect; a veto, not a substitute for A1 to B",
}


class ScenarioClass(str, Enum):
    """Plan section 11.3 工作場景, one class per listed workload shape."""

    CPU_CONTENTION = "CPU_CONTENTION"                 # CPU bound build or test
    IO_BOUND = "IO_BOUND"                             # I/O bound install
    MEMORY_HEAVY = "MEMORY_HEAVY"                     # memory heavy test with a safe ceiling
    NO_PRESSURE = "NO_PRESSURE"                       # normal, no pressure
    UNMANAGED_CPU_PRESSURE = "UNMANAGED_CPU_PRESSURE"  # CPU pressure this tool does not manage
    MIXED_ROLES = "MIXED_ROLES"                       # exempt, background and protected mixed
    MIXED_DURATIONS = "MIXED_DURATIONS"               # root and child of differing lifetimes


# Plan section 11.3 states thresholds for the CPU contention case and for the
# "無壓力／I/O／memory主導" group. It states none for the remaining classes.
CPU_RULE_SCENARIOS = frozenset({ScenarioClass.CPU_CONTENTION})
NEUTRAL_RULE_SCENARIOS = frozenset({
    ScenarioClass.IO_BOUND, ScenarioClass.MEMORY_HEAVY, ScenarioClass.NO_PRESSURE,
})


class EvidenceSource(str, Enum):
    MEASURED = "measured"
    SYNTHETIC = "synthetic"


def parse_evidence_source(value) -> EvidenceSource:
    """Accept exactly the two known labels. Anything else is rejected."""
    if isinstance(value, EvidenceSource):
        return value
    if type(value) is not str:
        raise BenchmarkDataError("evidence_source: unknown value")
    for member in EvidenceSource:
        if value == member.value:
            return member
    raise BenchmarkDataError("evidence_source: unknown value")


class CacheState(str, Enum):
    COLD = "cold"
    WARM = "warm"


class OrderPosition(str, Enum):
    FIRST = "first"
    SECOND = "second"


class Verdict(str, Enum):
    """The closed result set. None of these means "A/B complete"."""

    PROMOTE_ELIGIBLE = "PROMOTE_ELIGIBLE"           # measured paired data met the thresholds named in the plan
    FAIL = "FAIL"                                   # measured paired data missed at least one threshold
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"         # too few valid pairs, or a variant is missing
    NOT_MEASURED = "NOT_MEASURED"                   # at least one record is synthetic
    NO_PROBLEM_TO_CONTROL = "NO_PROBLEM_TO_CONTROL"  # plan: A1 p95 already below the floor worth controlling
    NO_THRESHOLD_DEFINED = "NO_THRESHOLD_DEFINED"   # the plan names no number for this comparison


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    UNVERIFIED = "unverified"


class HeadroomAttribution(str, Enum):
    WITHIN_RESERVE = "within_reserve"
    NEW_ADMISSION = "new_admission_overbooking"
    EXISTING = "existing"
    UNMANAGED = "unmanaged"
    EXEMPT = "exempt"
    MIXED_EXTERNAL = "mixed_external"
    UNKNOWN = "unknown"


# --- thresholds quoted from plan section 11.3 --------------------------------

# "每個主要場景至少10對paired runs"
MIN_PAIRS_PER_SCENARIO = 10

# "B相對A1的foregroundp95 paired改善中位數≥15%，且絕對改善≥5ms"
CPU_FOREGROUND_P95_MIN_RELATIVE_IMPROVEMENT = 0.15
CPU_FOREGROUND_P95_MIN_ABSOLUTE_IMPROVEMENT_MS = 5.0

# "若A1本來p95<20ms，將該場景標為「沒有足夠需要控制的問題」"
CPU_NO_PROBLEM_FOREGROUND_P95_MS = 20.0

# "background整批makespan中位數劣化≤15%，吞吐中位數下降≤10%"
CPU_MAKESPAN_MAX_MEDIAN_DEGRADATION = 0.15
CPU_THROUGHPUT_MAX_MEDIAN_DROP = 0.10

# "makespan與foregroundp95劣化不超過5%"
NEUTRAL_MAX_MEDIAN_DEGRADATION = 0.05

# Plan section 11.3 for the neutral group: "B不應施加不相關cap". The capped
# state names match sentinel.adaptive.decision.ControllerState.
CAPPED_STATE_NAMES = ("CAPPED_L1", "CAPPED_L2")

CLARIFICATION_LABEL_C1 = "clarification C1 (not in plan 11.3)"
CLARIFICATION_LABEL_C2 = "clarification C2 (not in plan 11.3)"

PLAN_GAPS = (
    "Plan 11.3 gives no numeric threshold of its own for A0 to A1. Clarification "
    "C1 holds that comparison to the plan 11.3 neutral rule of 5 percent, because "
    "A1 sets no cap. The monitor CPU rows of plan 11.2 are keyed on enrolled Job "
    "count, which the run record does not carry, so that one check stays "
    "NOT_APPLICABLE.",
    "Plan 11.3 says only 「A0→B若總體成本／互動效果倒退…仍不promotion」 with no "
    "tolerance. Clarification C2 reads that veto with the plan's own scenario "
    "tolerances: foreground p95 may not get worse than the live baseline, and the "
    "batch cost is held to 15 percent makespan and 10 percent throughput in CPU "
    "rule scenarios or to 5 percent in neutral rule scenarios.",
    "Plan 11.3 names no threshold for the unmanaged CPU pressure, mixed role and "
    "mixed duration scenarios; those report NO_THRESHOLD_DEFINED.",
    "Physical and Commit headroom are separate observations. External deficits "
    "are reported with their evidence and are never claimed as prevented by B.",
    "Noise uses a predeclared maximum absolute paired change from at least ten "
    "same-variant repeat pairs. This empirical envelope is not a confidence "
    "interval; noisy or missing calibration cannot establish neutral performance.",
    "Plan 11.3 says 「樣本小就說樣本小」 but names no sample size above which a "
    "statistical guarantee may be claimed, so every result is reported as small.",
)


# --- schedule ----------------------------------------------------------------


@dataclass(frozen=True)
class PairSlot:
    """One paired run: the same scenario run once per variant, in a fixed order."""

    comparison: Comparison
    scenario: str
    scenario_class: ScenarioClass
    pair_index: int
    first_variant: Variant
    second_variant: Variant

    def __post_init__(self):
        _typed(self.comparison, Comparison, "comparison")
        _text(self.scenario, "scenario")
        _typed(self.scenario_class, ScenarioClass, "scenario_class")
        _int(self.pair_index, "pair_index", 0, 1 << 20)
        _typed(self.first_variant, Variant, "first_variant")
        _typed(self.second_variant, Variant, "second_variant")
        pair = COMPARISON_VARIANTS[self.comparison]
        if {self.first_variant, self.second_variant} != set(pair):
            raise BenchmarkDataError("variants: order must cover exactly the compared pair")

    @property
    def order_label(self) -> str:
        return f"{self.first_variant.value}{self.second_variant.value}"

    @property
    def slot_id(self) -> str:
        payload = [self.comparison.value, self.scenario, self.scenario_class.value,
                   self.pair_index]
        return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class Schedule:
    seed: str
    pairs_per_scenario: int
    slots: tuple[PairSlot, ...]

    def __post_init__(self):
        _text(self.seed, "seed")
        _int(self.pairs_per_scenario, "pairs_per_scenario", 1, 1 << 16)
        if type(self.slots) is not tuple or not self.slots:
            raise BenchmarkDataError("slots: schedule is empty")
        for slot in self.slots:
            _typed(slot, PairSlot, "slot")
        if len({slot.slot_id for slot in self.slots}) != len(self.slots):
            raise BenchmarkDataError("slots: duplicate comparison/scenario/pair")


def build_schedule(
    scenarios: Sequence[tuple[str, ScenarioClass]],
    seed: str,
    pairs_per_scenario: int = MIN_PAIRS_PER_SCENARIO,
    comparisons: Sequence[Comparison] = tuple(Comparison),
) -> Schedule:
    """Interleaved AB and BA order, derived from the seed and recorded with it.

    Plan section 11.3 方法: "採AB/BA交錯、預先固定order seed". The order is a
    function of (seed, comparison, scenario) only, so the same seed reproduces
    the same schedule. Each scenario gets a balanced set of orders: equal counts
    when the pair count is even, and a difference of one when it is odd.
    """
    if not scenarios:
        raise BenchmarkDataError("scenarios: at least one scenario required")
    _text(seed, "seed")
    _int(pairs_per_scenario, "pairs_per_scenario", 1, 1 << 16)
    if pairs_per_scenario < MIN_PAIRS_PER_SCENARIO:
        raise BenchmarkDataError(
            f"pairs_per_scenario: plan section 11.3 requires at least {MIN_PAIRS_PER_SCENARIO}")
    if not comparisons:
        raise BenchmarkDataError("comparisons: at least one comparison required")
    if len(set(comparisons)) != len(comparisons):
        raise BenchmarkDataError("comparisons: duplicate comparison")

    seen = set()
    slots = []
    for name, scenario_class in scenarios:
        _text(name, "scenario")
        _typed(scenario_class, ScenarioClass, "scenario_class")
        if name in seen:
            raise BenchmarkDataError("scenario: duplicate scenario name")
        seen.add(name)
        for comparison in comparisons:
            _typed(comparison, Comparison, "comparison")
            baseline, treatment = COMPARISON_VARIANTS[comparison]
            forward = pairs_per_scenario // 2
            orders = [True] * forward + [False] * (pairs_per_scenario - forward)
            random.Random(f"{seed}|{comparison.value}|{name}").shuffle(orders)
            for index, baseline_first in enumerate(orders):
                first, second = (baseline, treatment) if baseline_first else (treatment, baseline)
                slots.append(PairSlot(comparison, name, scenario_class, index, first, second))
    return Schedule(seed, pairs_per_scenario, tuple(slots))


def schedule_order_counts(schedule: Schedule) -> dict[tuple[Comparison, str], dict[str, int]]:
    """Count AB versus BA orders per comparison and scenario, for balance checks."""
    counts: dict[tuple[Comparison, str], dict[str, int]] = {}
    for slot in schedule.slots:
        bucket = counts.setdefault((slot.comparison, slot.scenario), {})
        bucket[slot.order_label] = bucket.get(slot.order_label, 0) + 1
    return counts


# --- run record schema -------------------------------------------------------


@dataclass(frozen=True)
class FixedConditions:
    """Plan section 11.3 方法: the conditions every run in a pair must share."""

    commit: str
    os_build: str
    logical_processors: int
    power_plan: str
    cache_state: CacheState
    thermal_or_power_anomaly: bool
    dataset_sha256: str
    task_count: int
    ui_probe_sha256: str
    collector_scope_sha256: str
    build_variant_sha256: tuple[tuple[Variant, str], ...]

    def __post_init__(self):
        _text(self.commit, "commit")
        _text(self.os_build, "os_build")
        _int(self.logical_processors, "logical_processors", 1, 4096)
        _text(self.power_plan, "power_plan")
        _typed(self.cache_state, CacheState, "cache_state")
        if type(self.thermal_or_power_anomaly) is not bool:
            raise BenchmarkDataError("thermal_or_power_anomaly: boolean required")
        for name in ("dataset_sha256", "ui_probe_sha256", "collector_scope_sha256"):
            _sha256(getattr(self, name), name)
        _int(self.task_count, "task_count", 1, 1 << 20)
        if (type(self.build_variant_sha256) is not tuple
                or len(self.build_variant_sha256) != len(Variant)):
            raise BenchmarkDataError("build_variant_sha256: all three variant pins required")
        variants = []
        for variant, digest in self.build_variant_sha256:
            _typed(variant, Variant, "build variant")
            _sha256(digest, "build variant digest")
            variants.append(variant)
        if set(variants) != set(Variant):
            raise BenchmarkDataError("build_variant_sha256: missing or duplicate variant")

    @property
    def comparable_key(self) -> tuple:
        """Everything that must match across a pair. The anomaly flag excludes a
        run on its own, so it is not part of the match key."""
        return (self.commit, self.os_build, self.logical_processors,
                self.power_plan, self.cache_state, self.dataset_sha256, self.task_count,
                self.ui_probe_sha256, self.collector_scope_sha256,
                tuple(sorted(self.build_variant_sha256)))


@dataclass(frozen=True)
class Preconditions:
    """Plan section 11.3 方法: the between run state each run must start from.

    None means the condition was never checked. False and None both exclude the
    run, so an unverified precondition can never pass as a verified one.
    """

    previous_job_empty: bool | None
    cpu_back_to_baseline: bool | None
    commit_back_to_baseline: bool | None
    cap_audit_disabled: bool | None

    def __post_init__(self):
        for name in ("previous_job_empty", "cpu_back_to_baseline",
                     "commit_back_to_baseline", "cap_audit_disabled"):
            value = getattr(self, name)
            if value is not None and type(value) is not bool:
                raise BenchmarkDataError(f"{name}: boolean or None required")


@dataclass(frozen=True)
class NativeCapInterval:
    """Actual native ENABLE interval, from the write audit plus Query readbacks.

    A baseline rate remains a cap while ENABLE is set, including RECOVERING.
    Even a zero-duration observed enable event counts as a cap, because clock
    resolution must not hide a short write. State labels never establish absence.
    """

    execution_id: str
    start_tick_100ns: int
    end_tick_100ns: int
    flags: int
    rate_bp: int
    state: str

    def __post_init__(self):
        _text(self.execution_id, "execution_id")
        _int(self.start_tick_100ns, "start_tick_100ns")
        _int(self.end_tick_100ns, "end_tick_100ns", self.start_tick_100ns)
        _int(self.flags, "flags", 0, (1 << 32) - 1)
        _int(self.rate_bp, "rate_bp", 0, 10000)
        _text(self.state, "state", 64)
        if not self.flags & 1 or self.rate_bp == 0:
            raise BenchmarkDataError("native cap interval: positive ENABLE rate required")

    @property
    def seconds(self):
        return (self.end_tick_100ns - self.start_tick_100ns) / 10000000.0


@dataclass(frozen=True)
class RunMetrics:
    """Plan section 11.3 報告: the per run figures the report has to carry."""

    foreground_p50_ms: float
    foreground_p95_ms: float
    foreground_p99_ms: float
    makespan_s: float
    completed_units_per_min: float
    queue_wait_p50_s: float
    queue_wait_p95_s: float
    time_in_state_s: tuple[tuple[str, float], ...]
    peak_private_commit_mib: float
    peak_physical_mib: float
    min_physical_headroom_mib: float
    min_commit_headroom_mib: float
    monitor_cpu_units: float
    monitor_commit_mib: float
    api_errors: int
    restore_time_s: float | None
    coverage_fraction: float
    physical_headroom_attribution: HeadroomAttribution
    commit_headroom_attribution: HeadroomAttribution
    physical_headroom_evidence_id: str
    commit_headroom_evidence_id: str
    native_cap_intervals: tuple[NativeCapInterval, ...]
    native_cap_audit_complete: bool
    native_cap_write_audit_sha256: str
    native_cap_readback_sha256: str

    def __post_init__(self):
        for name in ("foreground_p50_ms", "foreground_p95_ms", "foreground_p99_ms",
                     "completed_units_per_min", "queue_wait_p50_s", "queue_wait_p95_s",
                     "peak_private_commit_mib", "peak_physical_mib",
                     "monitor_cpu_units", "monitor_commit_mib"):
            _num(getattr(self, name), name)
        _num(self.makespan_s, "makespan_s", 0.0, allow_minimum=False)
        for kind in ("physical", "commit"):
            value = _finite(getattr(self, f"min_{kind}_headroom_mib"), f"{kind} headroom")
            attribution = getattr(self, f"{kind}_headroom_attribution")
            _typed(attribution, HeadroomAttribution, f"{kind} attribution")
            _text(getattr(self, f"{kind}_headroom_evidence_id"), f"{kind} evidence id")
            if attribution is HeadroomAttribution.WITHIN_RESERVE and value < 4096:
                raise BenchmarkDataError(f"{kind}: within_reserve contradicts measured minimum")
        if type(self.native_cap_audit_complete) is not bool:
            raise BenchmarkDataError("native_cap_audit_complete: boolean required")
        _sha256(self.native_cap_write_audit_sha256, "native_cap_write_audit_sha256")
        _sha256(self.native_cap_readback_sha256, "native_cap_readback_sha256")
        if type(self.native_cap_intervals) is not tuple or len(self.native_cap_intervals) > 10000:
            raise BenchmarkDataError("native_cap_intervals: bounded tuple required")
        for interval in self.native_cap_intervals:
            _typed(interval, NativeCapInterval, "native cap interval")
        _num(self.coverage_fraction, "coverage_fraction", 0.0, 1.0)
        _int(self.api_errors, "api_errors", 0, 1 << 32)
        if self.restore_time_s is not None:
            _num(self.restore_time_s, "restore_time_s")
        if not self.foreground_p50_ms <= self.foreground_p95_ms <= self.foreground_p99_ms:
            raise BenchmarkDataError("foreground percentiles: must be non decreasing")
        if not self.queue_wait_p50_s <= self.queue_wait_p95_s:
            raise BenchmarkDataError("queue wait percentiles: must be non decreasing")
        seen = set()
        for entry in self.time_in_state_s:
            if type(entry) is not tuple or len(entry) != 2:
                raise BenchmarkDataError("time_in_state_s: (state, seconds) pairs required")
            state, seconds = entry
            _text(state, "time_in_state_s state", 64)
            _num(seconds, "time_in_state_s seconds")
            if state in seen:
                raise BenchmarkDataError("time_in_state_s: duplicate state")
            seen.add(state)

    def seconds_in(self, state: str) -> float:
        for name, seconds in self.time_in_state_s:
            if name == state:
                return seconds
        return 0.0


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    scenario: str
    scenario_class: ScenarioClass
    variant: Variant
    pair_index: int
    order_position: OrderPosition
    seed: str
    evidence_source: EvidenceSource
    conditions: FixedConditions
    preconditions: Preconditions
    metrics: RunMetrics
    comparison: Comparison
    slot_id: str
    note: str = ""

    def __post_init__(self):
        _text(self.run_id, "run_id")
        _text(self.scenario, "scenario")
        _typed(self.scenario_class, ScenarioClass, "scenario_class")
        _typed(self.variant, Variant, "variant")
        _int(self.pair_index, "pair_index", 0, 1 << 20)
        _typed(self.order_position, OrderPosition, "order_position")
        _text(self.seed, "seed")
        object.__setattr__(self, "evidence_source", parse_evidence_source(self.evidence_source))
        _typed(self.conditions, FixedConditions, "conditions")
        _typed(self.preconditions, Preconditions, "preconditions")
        _typed(self.metrics, RunMetrics, "metrics")
        _typed(self.comparison, Comparison, "comparison")
        _sha256(self.slot_id, "slot_id")
        if self.variant not in COMPARISON_VARIANTS[self.comparison]:
            raise BenchmarkDataError("variant: not part of this comparison")
        if type(self.note) is not str or len(self.note) > 500:
            raise BenchmarkDataError("note: text up to 500 characters")


MAX_RUN_RECORD_BYTES = 2 * 1024 * 1024


def run_record_to_dict(record: RunRecord) -> dict:
    _typed(record, RunRecord, "record")
    payload = json.dumps(asdict(record), separators=(",", ":"), allow_nan=False)
    if len(payload.encode("utf-8")) > MAX_RUN_RECORD_BYTES:
        raise BenchmarkDataError("run record exceeds 2 MiB")
    return json.loads(payload)


def parse_run_record(value: str | bytes | dict) -> RunRecord:
    """Strict closed schema, bounded JSON and no implicit measured defaults.

    This validates observations, not their authenticity. Native producers must
    retain and verify the raw artifacts named by the audit and readback hashes.
    Parsing cannot turn a fixture or a caller-supplied measured label into L4.
    """
    def unique_object(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise BenchmarkDataError(f"duplicate JSON key: {key}")
            result[key] = item
        return result

    def closed(raw, cls):
        if type(raw) is not dict or set(raw) != {field.name for field in fields(cls)}:
            raise BenchmarkDataError(f"{cls.__name__}: exact schema fields required")
        return dict(raw)

    def bounded_array(raw, name, maximum=10000):
        if type(raw) is not list or len(raw) > maximum:
            raise BenchmarkDataError(f"{name}: bounded JSON array required")
        return raw

    try:
        if isinstance(value, bytes):
            if len(value) > MAX_RUN_RECORD_BYTES:
                raise BenchmarkDataError("run record exceeds 2 MiB")
            value = value.decode("utf-8")
        if type(value) is str:
            if len(value.encode("utf-8")) > MAX_RUN_RECORD_BYTES:
                raise BenchmarkDataError("run record exceeds 2 MiB")
            value = json.loads(value, object_pairs_hook=unique_object)
        elif type(value) is dict:
            if len(json.dumps(value, allow_nan=False).encode("utf-8")) > MAX_RUN_RECORD_BYTES:
                raise BenchmarkDataError("run record exceeds 2 MiB")
        raw = closed(value, RunRecord)
        condition = closed(raw["conditions"], FixedConditions)
        condition["cache_state"] = CacheState(condition["cache_state"])
        pins = bounded_array(condition["build_variant_sha256"], "build variants", 3)
        if any(type(pair) is not list or len(pair) != 2 for pair in pins):
            raise BenchmarkDataError("build variants: pairs required")
        condition["build_variant_sha256"] = tuple((Variant(pair[0]), pair[1]) for pair in pins)
        raw["conditions"] = FixedConditions(**condition)
        raw["preconditions"] = Preconditions(**closed(raw["preconditions"], Preconditions))
        metric = closed(raw["metrics"], RunMetrics)
        states = bounded_array(metric["time_in_state_s"], "time in state", 100)
        if any(type(pair) is not list or len(pair) != 2 for pair in states):
            raise BenchmarkDataError("time in state: pairs required")
        metric["time_in_state_s"] = tuple(tuple(pair) for pair in states)
        metric["native_cap_intervals"] = tuple(
            NativeCapInterval(**closed(interval, NativeCapInterval))
            for interval in bounded_array(metric["native_cap_intervals"], "native cap intervals"))
        for kind in ("physical", "commit"):
            key = f"{kind}_headroom_attribution"
            metric[key] = HeadroomAttribution(metric[key])
        raw["metrics"] = RunMetrics(**metric)
        for key, cls in (("comparison", Comparison), ("variant", Variant),
                         ("scenario_class", ScenarioClass), ("order_position", OrderPosition)):
            raw[key] = cls(raw[key])
        return RunRecord(**raw)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise BenchmarkDataError(f"invalid run record: {type(error).__name__}") from error


def precondition_failures(record: RunRecord) -> tuple[str, ...]:
    """Reasons this run may not be used. Empty means the run is usable."""
    reasons = []
    pre = record.preconditions
    for name, label in (("previous_job_empty", "previous Job not confirmed empty"),
                        ("cpu_back_to_baseline", "CPU not confirmed back to baseline"),
                        ("commit_back_to_baseline", "Commit not confirmed back to baseline"),
                        ("cap_audit_disabled", "cap audit not confirmed disabled")):
        value = getattr(pre, name)
        if value is None:
            reasons.append(f"{label} (never checked)")
        elif value is False:
            reasons.append(label)
    if record.conditions.thermal_or_power_anomaly:
        reasons.append("thermal or power anomaly recorded")
    return tuple(reasons)


@dataclass(frozen=True)
class ExcludedRun:
    run_id: str
    scenario: str
    variant: Variant
    pair_index: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class PairedRun:
    scenario: str
    pair_index: int
    baseline: RunRecord
    treatment: RunRecord

    @property
    def order_label(self) -> str:
        if self.baseline.order_position is OrderPosition.FIRST:
            return f"{self.baseline.variant.value}{self.treatment.variant.value}"
        return f"{self.treatment.variant.value}{self.baseline.variant.value}"


def pair_records(
    records: Sequence[RunRecord],
    comparison: Comparison,
    scenario: str,
    *,
    schedule: Schedule | None = None,
) -> tuple[tuple[PairedRun, ...], tuple[ExcludedRun, ...]]:
    """Match baseline and treatment runs by pair index, excluding unusable runs.

    A run is excluded when a precondition failed or was never checked, when it
    has no partner, or when the pair does not share the fixed conditions.
    """
    baseline_variant, treatment_variant = COMPARISON_VARIANTS[comparison]
    excluded: list[ExcludedRun] = []
    by_slot: dict[tuple[int, Variant], RunRecord] = {}
    scheduled = {}
    if schedule is not None:
        validate_schedule(schedule)
        scheduled = {slot.slot_id: slot for slot in schedule.slots}
    seen_ids = set()
    seen_keys = set()

    for record in records:
        if (record.comparison is not comparison or record.scenario != scenario
                or record.variant not in (baseline_variant, treatment_variant)):
            continue
        key = (record.pair_index, record.variant)
        if record.run_id in seen_ids or key in seen_keys:
            raise BenchmarkDataError("duplicate run identity or comparison/scenario/pair/variant")
        seen_ids.add(record.run_id)
        seen_keys.add(key)
        reasons = list(precondition_failures(record))
        slot = scheduled.get(record.slot_id)
        if schedule is None:
            reasons.append("independent preregistered schedule not supplied")
        elif slot is None:
            reasons.append("slot absent from preregistered schedule")
        elif (record.seed != schedule.seed or slot.comparison is not record.comparison
              or slot.scenario != record.scenario or slot.scenario_class is not record.scenario_class
              or slot.pair_index != record.pair_index):
            reasons.append("record identity or seed differs from preregistered schedule")
        elif ((record.order_position is OrderPosition.FIRST) != (record.variant is slot.first_variant)):
            reasons.append("record order differs from preregistered schedule")
        if reasons:
            excluded.append(ExcludedRun(record.run_id, record.scenario, record.variant,
                                        record.pair_index, tuple(reasons)))
            continue
        by_slot[key] = record

    pairs: list[PairedRun] = []
    for index in sorted({slot[0] for slot in by_slot}):
        baseline = by_slot.get((index, baseline_variant))
        treatment = by_slot.get((index, treatment_variant))
        if baseline is None or treatment is None:
            present = baseline or treatment
            excluded.append(ExcludedRun(present.run_id, present.scenario, present.variant,
                                        index, ("pair incomplete, partner run missing",)))
            continue
        if baseline.conditions.comparable_key != treatment.conditions.comparable_key:
            for record in (baseline, treatment):
                excluded.append(ExcludedRun(record.run_id, record.scenario, record.variant,
                                            index, ("fixed conditions differ across the pair",)))
            continue
        pairs.append(PairedRun(scenario, index, baseline, treatment))
    return tuple(pairs), tuple(excluded)


def validate_schedule(schedule: Schedule) -> None:
    """Verify supplied order against its independently recorded seed and count."""
    _typed(schedule, Schedule, "schedule")
    scenarios = tuple(dict.fromkeys((slot.scenario, slot.scenario_class) for slot in schedule.slots))
    comparisons = tuple(dict.fromkeys(slot.comparison for slot in schedule.slots))
    expected = build_schedule(scenarios, schedule.seed, schedule.pairs_per_scenario, comparisons)
    if schedule.slots != expected.slots:
        raise BenchmarkDataError("schedule: order or slot inventory differs from seed")


@dataclass(frozen=True)
class NoiseEvidence:
    """Predeclared empirical envelope from independent same-variant repeat pairs.

    The estimator is the maximum absolute paired relative change, separately
    for foreground p95 and makespan. It is deliberately not a confidence bound.
    At least ten repeat pairs with the same fixed conditions are required. An
    envelope above the plan's 5% ceiling is too noisy and needs more evidence;
    it can never be enlarged to excuse a regression. Each raw pair must be a
    same-variant repeat, not the treatment/baseline comparison being judged.
    """

    comparison: Comparison
    scenario: str
    seed: str
    variant: Variant
    conditions: FixedConditions
    evidence_source: EvidenceSource
    evidence_id: str
    foreground_p95_pairs_ms: tuple[tuple[float, float], ...]
    makespan_pairs_s: tuple[tuple[float, float], ...]
    repeat_run_ids: tuple[tuple[str, str], ...]
    method: str = "max_absolute_paired_change"

    def __post_init__(self):
        _typed(self.comparison, Comparison, "comparison")
        _typed(self.variant, Variant, "variant")
        if self.variant is not COMPARISON_VARIANTS[self.comparison][0]:
            raise BenchmarkDataError("noise: baseline same-variant calibration required")
        _text(self.scenario, "scenario")
        _text(self.seed, "seed")
        _text(self.evidence_id, "evidence_id")
        _typed(self.conditions, FixedConditions, "conditions")
        object.__setattr__(self, "evidence_source", parse_evidence_source(self.evidence_source))
        if self.method != "max_absolute_paired_change":
            raise BenchmarkDataError("noise: unsupported predeclared estimator")
        count = len(self.foreground_p95_pairs_ms)
        if count != len(self.makespan_pairs_s) or count != len(self.repeat_run_ids) or count > 10000:
            raise BenchmarkDataError("noise: paired observations and identities must match")
        seen = set()
        for raw in (self.foreground_p95_pairs_ms, self.makespan_pairs_s, self.repeat_run_ids):
            if type(raw) is not tuple:
                raise BenchmarkDataError("noise: immutable paired observations required")
            for item in raw:
                if type(item) is not tuple or len(item) != 2:
                    raise BenchmarkDataError("noise: two-element pairs required")
        for left, right in self.foreground_p95_pairs_ms + self.makespan_pairs_s:
            _num(left, "noise baseline", allow_minimum=False)
            _num(right, "noise repeat", allow_minimum=False)
        for identities in self.repeat_run_ids:
            for identity in identities:
                _text(identity, "noise run identity")
                if identity in seen:
                    raise BenchmarkDataError("noise: repeated calibration run identity")
                seen.add(identity)


# --- pure statistics ---------------------------------------------------------


def median(values: Sequence[float]) -> float:
    if not values:
        raise BenchmarkDataError("median: no values")
    ordered = sorted(_finite(value, "median value") for value in values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def percentile(values: Sequence[float], q: float) -> float:
    """Linear interpolation between order statistics, q in percent."""
    if not values:
        raise BenchmarkDataError("percentile: no values")
    _num(q, "q", 0.0, 100.0)
    ordered = sorted(_finite(value, "percentile value") for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * (q / 100.0)
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[int(position)]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def paired_differences(baseline: Sequence[float], treatment: Sequence[float]) -> tuple[float, ...]:
    """Treatment minus baseline, one value per pair, in pair order."""
    if len(baseline) != len(treatment):
        raise BenchmarkDataError("paired_differences: unequal lengths")
    if not baseline:
        raise BenchmarkDataError("paired_differences: no pairs")
    return tuple(_finite(t, "treatment") - _finite(b, "baseline")
                 for b, t in zip(baseline, treatment))


def relative_changes(baseline: Sequence[float], treatment: Sequence[float]) -> tuple[float, ...]:
    """Fractional change per pair. Positive means the treatment value is larger."""
    differences = paired_differences(baseline, treatment)
    changes = []
    for base, difference in zip(baseline, differences):
        if base <= 0:
            raise BenchmarkDataError("relative_changes: baseline must be positive")
        changes.append(difference / base)
    return tuple(changes)


@dataclass(frozen=True)
class Spread:
    count: int
    minimum: float
    p25: float
    median: float
    p75: float
    maximum: float


def spread(values: Sequence[float]) -> Spread:
    if not values:
        raise BenchmarkDataError("spread: no values")
    return Spread(len(values), min(values), percentile(values, 25.0),
                  median(values), percentile(values, 75.0), max(values))


def sample_size_statement(pair_count: int) -> str:
    """Plan section 11.3 報告: say the sample is small, claim no guarantee.

    The plan fixes a minimum of ten pairs and names no size above which a
    statistical guarantee may be claimed, so every result at this scale is
    reported as a small sample.
    """
    _int(pair_count, "pair_count", 0, 1 << 20)
    return (f"{pair_count} valid pairs, small sample; paired medians and spread only, "
            "no statistical guarantee claimed")


# --- threshold checks --------------------------------------------------------


@dataclass(frozen=True)
class ThresholdCheck:
    name: str
    status: CheckStatus
    observed: float | None
    limit: float | None
    detail: str


def _metric_values(pairs: Sequence[PairedRun], attribute: str) -> tuple[list[float], list[float]]:
    baseline = [getattr(pair.baseline.metrics, attribute) for pair in pairs]
    treatment = [getattr(pair.treatment.metrics, attribute) for pair in pairs]
    return baseline, treatment


def check_cpu_contention(pairs: Sequence[PairedRun]) -> tuple[ThresholdCheck, ...]:
    """Plan section 11.3, CPU contention scenario, A1 as baseline and B as treatment."""
    if not pairs:
        raise BenchmarkDataError("check_cpu_contention: no pairs")
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    baseline_median_p95 = median(base_p95)

    if baseline_median_p95 < CPU_NO_PROBLEM_FOREGROUND_P95_MS:
        detail = ("A1 foreground p95 median is already below the floor the plan calls worth "
                  "controlling, so no improvement here may be claimed as a benefit")
        return (ThresholdCheck("A1 foreground p95 worth controlling", CheckStatus.NOT_APPLICABLE,
                               baseline_median_p95, CPU_NO_PROBLEM_FOREGROUND_P95_MS, detail),)

    relative_improvement = median([-change for change in relative_changes(base_p95, treat_p95)])
    absolute_improvement = median([-difference
                                   for difference in paired_differences(base_p95, treat_p95)])
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_degradation = median(relative_changes(base_makespan, treat_makespan))
    base_units, treat_units = _metric_values(pairs, "completed_units_per_min")
    throughput_drop = median([-change for change in relative_changes(base_units, treat_units)])

    return (
        ThresholdCheck(
            "foreground p95 relative improvement median",
            CheckStatus.PASS if relative_improvement >= CPU_FOREGROUND_P95_MIN_RELATIVE_IMPROVEMENT
            else CheckStatus.FAIL,
            relative_improvement, CPU_FOREGROUND_P95_MIN_RELATIVE_IMPROVEMENT,
            "plan 11.3: paired improvement median at least 15 percent"),
        ThresholdCheck(
            "foreground p95 absolute improvement median (ms)",
            CheckStatus.PASS if absolute_improvement >= CPU_FOREGROUND_P95_MIN_ABSOLUTE_IMPROVEMENT_MS
            else CheckStatus.FAIL,
            absolute_improvement, CPU_FOREGROUND_P95_MIN_ABSOLUTE_IMPROVEMENT_MS,
            "plan 11.3: absolute improvement at least 5 ms"),
        ThresholdCheck(
            "background makespan degradation median",
            CheckStatus.PASS if makespan_degradation <= CPU_MAKESPAN_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            makespan_degradation, CPU_MAKESPAN_MAX_MEDIAN_DEGRADATION,
            "plan 11.3: batch makespan degradation median at most 15 percent"),
        ThresholdCheck(
            "throughput drop median",
            CheckStatus.PASS if throughput_drop <= CPU_THROUGHPUT_MAX_MEDIAN_DROP
            else CheckStatus.FAIL,
            throughput_drop, CPU_THROUGHPUT_MAX_MEDIAN_DROP,
            "plan 11.3: completed units per minute drop median at most 10 percent; "
            "queue wait is reported separately and never folded into this"),
    )


def _noise_checks(pairs: Sequence[PairedRun], noise: NoiseEvidence | None,
                  *, label="plan 11.3") -> tuple[ThresholdCheck, ...]:
    reason = None
    reference = pairs[0].baseline
    if noise is None:
        reason = "independent same-variant noise evidence is missing"
    elif noise.evidence_source is not EvidenceSource.MEASURED:
        reason = "synthetic noise is not measured evidence"
    elif len(noise.repeat_run_ids) < MIN_PAIRS_PER_SCENARIO:
        reason = "at least ten independent same-variant repeat pairs required"
    elif (noise.comparison is not reference.comparison or noise.scenario != reference.scenario
          or noise.seed != reference.seed
          or noise.conditions.comparable_key != reference.conditions.comparable_key
          or noise.conditions.thermal_or_power_anomaly):
        reason = "noise identity, seed or fixed conditions differ from the comparison"
    elif ({identity for identities in noise.repeat_run_ids for identity in identities}
          & {record.run_id for pair in pairs for record in (pair.baseline, pair.treatment)}):
        reason = "comparison observations cannot be reused as noise calibration"
    checks = []
    for metric, raw_name in (("makespan_s", "makespan_pairs_s"),
                             ("foreground_p95_ms", "foreground_p95_pairs_ms")):
        baseline, treatment = _metric_values(pairs, metric)
        observed = max(0.0, median(relative_changes(baseline, treatment)))
        envelope = None
        why = reason
        if why is None:
            raw = getattr(noise, raw_name)
            envelope = max(abs((right - left) / left) for left, right in raw)
            if envelope > NEUTRAL_MAX_MEDIAN_DEGRADATION:
                why = "measured noise exceeds the 5 percent ceiling; collect more paired evidence"
        status = (CheckStatus.UNVERIFIED if why is not None else
                  CheckStatus.PASS if observed <= envelope else CheckStatus.FAIL)
        checks.append(ThresholdCheck(
            f"{metric} within measured noise", status, observed, envelope,
            f"{label}: " + (why or "maximum absolute paired repeat change; no statistical guarantee")))
    return tuple(checks)


def _native_absence_check(records: Sequence[RunRecord], name: str) -> ThresholdCheck:
    count = sum(len(record.metrics.native_cap_intervals) for record in records)
    complete = all(record.metrics.native_cap_audit_complete for record in records)
    status = (CheckStatus.FAIL if count else
              CheckStatus.PASS if complete else CheckStatus.UNVERIFIED)
    return ThresholdCheck(name, status, float(count), 0.0,
                          "native ENABLE events/intervals including RECOVERING baseline; "
                          "absence requires complete write audit plus Query readback coverage")


def check_measurement_safety(pairs: Sequence[PairedRun]) -> tuple[ThresholdCheck, ...]:
    """Keep independent reserve/native evidence visible before performance gains."""
    records = [record for pair in pairs for record in (pair.baseline, pair.treatment)]
    checks = []
    complete = all(record.metrics.native_cap_audit_complete for record in records)
    checks.append(ThresholdCheck("native cap evidence complete",
                                 CheckStatus.PASS if complete else CheckStatus.UNVERIFIED,
                                 None, None, "write audit and readback coverage for every run"))
    uncapped = [record for record in records if record.variant in (Variant.A0, Variant.A1)]
    if uncapped:
        checks.append(_native_absence_check(uncapped, "A0/A1 have no Sentinel CPU caps"))
    for resource in ("physical", "commit"):
        minimum = min(getattr(record.metrics, f"min_{resource}_headroom_mib") for record in records)
        unknown = any(getattr(record.metrics, f"{resource}_headroom_attribution")
                      is HeadroomAttribution.UNKNOWN for record in records)
        overbooking = any(getattr(record.metrics, f"min_{resource}_headroom_mib") < 4096
                          and getattr(record.metrics, f"{resource}_headroom_attribution")
                          is HeadroomAttribution.NEW_ADMISSION for record in records)
        external = minimum < 4096 and not unknown and not overbooking
        status = (CheckStatus.FAIL if overbooking else CheckStatus.UNVERIFIED if unknown else
                  CheckStatus.NOT_APPLICABLE if external else CheckStatus.PASS)
        checks.append(ThresholdCheck(
            f"{resource} reserve and attribution", status, minimum, 4096.0,
            "new admission overbooking fails; unknown cause remains unverified; "
            "external deficit is not claimed as prevented by B"))
    return tuple(checks)


def check_neutral_scenario(pairs: Sequence[PairedRun],
                           noise: NoiseEvidence | None = None) -> tuple[ThresholdCheck, ...]:
    """Plan section 11.3, no pressure, I/O dominated and memory dominated scenarios."""
    if not pairs:
        raise BenchmarkDataError("check_neutral_scenario: no pairs")
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_degradation = median(relative_changes(base_makespan, treat_makespan))
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    p95_degradation = median(relative_changes(base_p95, treat_p95))
    return (
        ThresholdCheck(
            "makespan degradation median",
            CheckStatus.PASS if makespan_degradation <= NEUTRAL_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            makespan_degradation, NEUTRAL_MAX_MEDIAN_DEGRADATION,
            "plan 11.3: at most 5 percent, and within measured noise"),
        ThresholdCheck(
            "foreground p95 degradation median",
            CheckStatus.PASS if p95_degradation <= NEUTRAL_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            p95_degradation, NEUTRAL_MAX_MEDIAN_DEGRADATION,
            "plan 11.3: at most 5 percent, and within measured noise"),
        _native_absence_check([pair.treatment for pair in pairs], "no unrelated cap applied"),
    ) + _noise_checks(pairs, noise)


def check_observer_cost(pairs: Sequence[PairedRun],
                        noise: NoiseEvidence | None = None) -> tuple[ThresholdCheck, ...]:
    """A0 to A1 under clarification C1: A1 sets no cap, so the neutral rule applies.

    Plan 11.3 names no A0 to A1 number. C1 reuses the plan's own neutral rule of
    5 percent, because a variant that never caps anything should look like the
    neutral scenarios. The plan 11.2 monitor CPU rows are keyed on enrolled Job
    count, which the run record schema does not carry, so that row is reported
    without a judgement.
    """
    if not pairs:
        raise BenchmarkDataError("check_observer_cost: no pairs")
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    p95_degradation = median(relative_changes(base_p95, treat_p95))
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_degradation = median(relative_changes(base_makespan, treat_makespan))
    detail = (f"{CLARIFICATION_LABEL_C1}: A1 sets no cap, so it is held to the plan 11.3 "
              "neutral rule of at most 5 percent")
    return (
        ThresholdCheck(
            "foreground p95 degradation median",
            CheckStatus.PASS if p95_degradation <= NEUTRAL_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            p95_degradation, NEUTRAL_MAX_MEDIAN_DEGRADATION, detail),
        ThresholdCheck(
            "makespan degradation median",
            CheckStatus.PASS if makespan_degradation <= NEUTRAL_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            makespan_degradation, NEUTRAL_MAX_MEDIAN_DEGRADATION, detail),
        ThresholdCheck(
            "monitor CPU units median (A1)",
            CheckStatus.NOT_APPLICABLE,
            median([pair.treatment.metrics.monitor_cpu_units for pair in pairs]), None,
            f"{CLARIFICATION_LABEL_C1}: the plan 11.2 monitor CPU rows are keyed on "
            "enrolled Job count, which the run record does not carry, so this is "
            "reported for human judgement"),
    ) + _noise_checks(pairs, noise, label=CLARIFICATION_LABEL_C1)


def check_a0_b_regression(pairs: Sequence[PairedRun],
                          scenario_class: ScenarioClass,
                          noise: NoiseEvidence | None = None) -> tuple[ThresholdCheck, ...]:
    """Plan section 11.3 veto: if A0 to B regresses overall, B is not promoted.

    The plan gives no tolerance for 倒退. Clarification C2 reads the veto with the
    plan's own scenario tolerances, because capping a background Job raises its
    makespan by design and a zero tolerance on makespan would veto every B. The
    interaction side keeps a zero tolerance: B may not make foreground p95 worse
    than the live baseline a person already has. Scenario classes the plan lists
    no tolerance for are reported without a judgement.
    """
    if not pairs:
        raise BenchmarkDataError("check_a0_b_regression: no pairs")
    _typed(scenario_class, ScenarioClass, "scenario_class")
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    p95_change = median(relative_changes(base_p95, treat_p95))
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_change = median(relative_changes(base_makespan, treat_makespan))

    if scenario_class not in CPU_RULE_SCENARIOS and scenario_class not in NEUTRAL_RULE_SCENARIOS:
        detail = (f"{CLARIFICATION_LABEL_C2}: plan 11.3 states no tolerance for this "
                  "scenario class, so the veto is reported for human judgement")
        return (
            ThresholdCheck("A0 to B foreground p95 change median",
                           CheckStatus.NOT_APPLICABLE, p95_change, None, detail),
            ThresholdCheck("A0 to B makespan change median",
                           CheckStatus.NOT_APPLICABLE, makespan_change, None, detail),
        )

    p95_detail = (f"{CLARIFICATION_LABEL_C2}: B may not make foreground p95 worse than the "
                  "live A0 baseline, so the tolerance here stays zero")
    checks = [
        ThresholdCheck("A0 to B foreground p95 change median",
                       CheckStatus.PASS if p95_change <= 0.0 else CheckStatus.FAIL,
                       p95_change, 0.0, p95_detail),
    ]
    if scenario_class in CPU_RULE_SCENARIOS:
        base_units, treat_units = _metric_values(pairs, "completed_units_per_min")
        throughput_drop = median([-change for change in relative_changes(base_units, treat_units)])
        checks.append(ThresholdCheck(
            "A0 to B makespan degradation median",
            CheckStatus.PASS if makespan_change <= CPU_MAKESPAN_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            makespan_change, CPU_MAKESPAN_MAX_MEDIAN_DEGRADATION,
            f"{CLARIFICATION_LABEL_C2}: the plan 11.3 CPU scenario batch tolerance of "
            "15 percent, applied to the A0 baseline"))
        checks.append(ThresholdCheck(
            "A0 to B throughput drop median",
            CheckStatus.PASS if throughput_drop <= CPU_THROUGHPUT_MAX_MEDIAN_DROP
            else CheckStatus.FAIL,
            throughput_drop, CPU_THROUGHPUT_MAX_MEDIAN_DROP,
            f"{CLARIFICATION_LABEL_C2}: the plan 11.3 CPU scenario throughput tolerance of "
            "10 percent, applied to the A0 baseline"))
    else:
        checks.append(ThresholdCheck(
            "A0 to B makespan degradation median",
            CheckStatus.PASS if makespan_change <= NEUTRAL_MAX_MEDIAN_DEGRADATION
            else CheckStatus.FAIL,
            makespan_change, NEUTRAL_MAX_MEDIAN_DEGRADATION,
            f"{CLARIFICATION_LABEL_C2}: the plan 11.3 neutral tolerance of 5 percent, "
            "applied to the A0 baseline"))
        checks.extend(_noise_checks(pairs, noise, label=CLARIFICATION_LABEL_C2))
        checks.append(_native_absence_check(
            [pair.treatment for pair in pairs], "no unrelated cap applied"))
    return tuple(checks)


# --- analysis and verdict ----------------------------------------------------


@dataclass(frozen=True)
class ComparisonAnalysis:
    comparison: Comparison
    scenario: str
    scenario_class: ScenarioClass
    evidence_source: EvidenceSource | None
    pairs: tuple[PairedRun, ...]
    excluded: tuple[ExcludedRun, ...]
    checks: tuple[ThresholdCheck, ...]
    verdict: Verdict
    notes: tuple[str, ...]


def analyze_comparison(
    records: Sequence[RunRecord],
    comparison: Comparison,
    scenario: str,
    scenario_class: ScenarioClass,
    min_pairs: int = MIN_PAIRS_PER_SCENARIO,
    *,
    schedule: Schedule | None = None,
    noise: NoiseEvidence | None = None,
) -> ComparisonAnalysis:
    """Pair, validate, check and rule on one comparison in one scenario.

    Verdict precedence: synthetic evidence first, then data sufficiency, then the
    plan's "no problem worth controlling" rule, then missing thresholds, then the
    threshold results. A threshold result can never outrank an evidence problem.

    The A0 to B checks need the scenario class, because clarification C2 reads the
    plan's veto with that scenario's own tolerances.
    """
    _typed(comparison, Comparison, "comparison")
    _text(scenario, "scenario")
    _typed(scenario_class, ScenarioClass, "scenario_class")
    _int(min_pairs, "min_pairs", MIN_PAIRS_PER_SCENARIO, 1 << 16)

    baseline_variant, treatment_variant = COMPARISON_VARIANTS[comparison]
    relevant = [record for record in records
                if record.comparison is comparison and record.scenario == scenario
                and record.variant in (baseline_variant, treatment_variant)]
    if any(record.scenario_class is not scenario_class for record in relevant):
        raise BenchmarkDataError("scenario_class: requested class differs from records")
    pairs, excluded = pair_records(records, comparison, scenario, schedule=schedule)
    if len({pair.baseline.conditions.comparable_key for pair in pairs}) > 1:
        raise BenchmarkDataError("fixed conditions vary between pairs in one comparison")
    notes = [COMPARISON_SCOPE[comparison], sample_size_statement(len(pairs))]

    sources = {record.evidence_source for record in relevant}
    evidence = None
    if sources:
        evidence = (EvidenceSource.SYNTHETIC if EvidenceSource.SYNTHETIC in sources
                    else EvidenceSource.MEASURED)

    checks: tuple[ThresholdCheck, ...] = ()
    if pairs:
        if scenario_class in CPU_RULE_SCENARIOS and comparison is Comparison.A1_B:
            checks = check_cpu_contention(pairs)
        elif scenario_class in NEUTRAL_RULE_SCENARIOS and comparison is Comparison.A1_B:
            checks = check_neutral_scenario(pairs, noise)
        elif comparison is Comparison.A0_A1:
            checks = check_observer_cost(pairs, noise)
        elif comparison is Comparison.A0_B:
            checks = check_a0_b_regression(pairs, scenario_class, noise)

    performance_checks = checks
    if (noise is not None and noise.evidence_source is EvidenceSource.SYNTHETIC
            and any("within measured noise" in check.name for check in performance_checks)):
        evidence = EvidenceSource.SYNTHETIC
    if pairs:
        checks += check_measurement_safety(pairs)

    verdict = _verdict(comparison, scenario_class, pairs, relevant, evidence, checks,
                       min_pairs, notes, performance_checks)
    return ComparisonAnalysis(comparison, scenario, scenario_class, evidence, pairs,
                              excluded, checks, verdict, tuple(notes))


def _verdict(comparison, scenario_class, pairs, relevant, evidence, checks, min_pairs, notes,
             performance_checks):
    if evidence is EvidenceSource.SYNTHETIC:
        notes.append("at least one record is synthetic, so no threshold result counts as evidence")
        return Verdict.NOT_MEASURED
    variants_present = {record.variant for record in relevant}
    if variants_present != set(COMPARISON_VARIANTS[comparison]):
        notes.append("a required variant has no usable record in this scenario")
        return Verdict.INSUFFICIENT_DATA
    if len(pairs) < min_pairs:
        notes.append(f"{len(pairs)} valid pairs, plan section 11.3 requires at least {min_pairs}")
        return Verdict.INSUFFICIENT_DATA
    if any(check.status is CheckStatus.FAIL for check in checks):
        return Verdict.FAIL
    if any(check.status is CheckStatus.UNVERIFIED for check in checks):
        notes.append("noise, native audit or reserve attribution remains unverified")
        return Verdict.INSUFFICIENT_DATA
    if not performance_checks:
        notes.append("plan section 11.3 states no threshold for this comparison and scenario")
        return Verdict.NO_THRESHOLD_DEFINED
    if (comparison is Comparison.A1_B and scenario_class in CPU_RULE_SCENARIOS
            and all(check.status is CheckStatus.NOT_APPLICABLE for check in performance_checks)):
        notes.append("A1 foreground p95 is already low, so this scenario shows no problem "
                     "worth controlling")
        return Verdict.NO_PROBLEM_TO_CONTROL
    if all(check.status is CheckStatus.NOT_APPLICABLE for check in performance_checks):
        notes.append("plan section 11.3 states no threshold for this comparison and scenario")
        return Verdict.NO_THRESHOLD_DEFINED
    return Verdict.PROMOTE_ELIGIBLE


VERDICT_PRECEDENCE = (
    Verdict.NOT_MEASURED,
    Verdict.INSUFFICIENT_DATA,
    Verdict.FAIL,
    Verdict.NO_THRESHOLD_DEFINED,
    Verdict.NO_PROBLEM_TO_CONTROL,
    Verdict.PROMOTE_ELIGIBLE,
)


def overall_verdict(analyses: Sequence[ComparisonAnalysis]) -> Verdict:
    """Require the complete seven-scenario by three-comparison matrix.

    Plan section 11.3: "不能只選A1↔B而隱藏基礎設施造成的退步". A missing comparison
    is therefore insufficient data, not a silent pass.
    """
    if not analyses:
        return Verdict.INSUFFICIENT_DATA
    if any(analysis.verdict is Verdict.NOT_MEASURED for analysis in analyses):
        return Verdict.NOT_MEASURED
    required = {(comparison, name, kind) for name, kind in DEFAULT_SCENARIOS
                for comparison in Comparison}
    actual = [(item.comparison, item.scenario, item.scenario_class) for item in analyses]
    if len(set(actual)) != len(actual) or set(actual) != required:
        return Verdict.INSUFFICIENT_DATA
    records = [record for item in analyses for pair in item.pairs
               for record in (pair.baseline, pair.treatment)]
    if len({record.run_id for record in records}) != len(records):
        return Verdict.INSUFFICIENT_DATA
    if len({record.seed for record in records}) != 1:
        return Verdict.INSUFFICIENT_DATA
    for scenario, _kind in DEFAULT_SCENARIOS:
        if len({record.conditions.comparable_key for record in records
                if record.scenario == scenario}) != 1:
            return Verdict.INSUFFICIENT_DATA
    for verdict in VERDICT_PRECEDENCE:
        if any(analysis.verdict is verdict for analysis in analyses):
            return verdict
    return Verdict.INSUFFICIENT_DATA


# --- report renderer ---------------------------------------------------------


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:+.1f}%"


def _num_text(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _render_pair_rows(analysis: ComparisonAnalysis) -> list[str]:
    baseline_variant, treatment_variant = COMPARISON_VARIANTS[analysis.comparison]
    lines = [
        f"| pair | order | {baseline_variant.value} fg p95 ms | {treatment_variant.value} fg p95 ms "
        f"| diff ms | {baseline_variant.value} makespan s | {treatment_variant.value} makespan s "
        f"| makespan change | units/min change | queue wait p95 s base to treat |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for pair in analysis.pairs:
        base, treat = pair.baseline.metrics, pair.treatment.metrics
        makespan_change = (treat.makespan_s - base.makespan_s) / base.makespan_s
        units_change = ((treat.completed_units_per_min - base.completed_units_per_min)
                        / base.completed_units_per_min
                        if base.completed_units_per_min > 0 else None)
        lines.append(
            f"| {pair.pair_index} | {pair.order_label} | {base.foreground_p95_ms:.2f} "
            f"| {treat.foreground_p95_ms:.2f} "
            f"| {treat.foreground_p95_ms - base.foreground_p95_ms:+.2f} "
            f"| {base.makespan_s:.2f} | {treat.makespan_s:.2f} | {_pct(makespan_change)} "
            f"| {_pct(units_change)} "
            f"| {base.queue_wait_p95_s:.2f} to {treat.queue_wait_p95_s:.2f} |")
    return lines


def render_report(
    analyses: Sequence[ComparisonAnalysis],
    seed: str,
    title: str = "Adaptive scheduler paired A/B report",
) -> str:
    """Plain Markdown, no charts. Evidence source in the header, verdict last."""
    _text(seed, "seed")
    if not analyses:
        raise BenchmarkDataError("render_report: no analyses")
    if any(record.seed != seed for item in analyses for pair in item.pairs
           for record in (pair.baseline, pair.treatment)):
        raise BenchmarkDataError("report seed differs from analyzed records")
    sources = {analysis.evidence_source for analysis in analyses}
    if EvidenceSource.SYNTHETIC in sources:
        header_source = "synthetic, not evidence for any threshold"
    elif sources == {EvidenceSource.MEASURED}:
        header_source = "measured"
    else:
        header_source = "no records"

    lines = [
        f"# {title}",
        "",
        f"- Evidence source: {header_source}",
        f"- Order seed: {seed}",
        f"- Overall verdict: {overall_verdict(analyses).value}",
        f"- Minimum pairs per scenario required by plan section 11.3: {MIN_PAIRS_PER_SCENARIO}",
        "",
    ]
    if EvidenceSource.SYNTHETIC in sources:
        lines += ["Synthetic records are present. No number in this report is evidence that any "
                  "threshold was met, and the A/B comparison is not complete.", ""]

    for analysis in analyses:
        baseline_variant, treatment_variant = COMPARISON_VARIANTS[analysis.comparison]
        lines += [
            f"## {analysis.scenario} ({analysis.scenario_class.value}), "
            f"{baseline_variant.value} to {treatment_variant.value}",
            "",
            f"- Evidence source: "
            f"{analysis.evidence_source.value if analysis.evidence_source else 'no records'}",
            f"- Scope: {COMPARISON_SCOPE[analysis.comparison]}",
            f"- Valid pairs: {len(analysis.pairs)}",
            f"- Excluded runs: {len(analysis.excluded)}",
            "",
        ]
        if analysis.pairs:
            lines += _render_pair_rows(analysis)
            lines.append("")
            base_p95, treat_p95 = _metric_values(analysis.pairs, "foreground_p95_ms")
            differences = paired_differences(base_p95, treat_p95)
            distribution = spread(differences)
            lines += [
                "Paired foreground p95 difference in milliseconds, treatment minus baseline:",
                "",
                f"- count {distribution.count}, minimum {_num_text(distribution.minimum)}, "
                f"p25 {_num_text(distribution.p25)}, median {_num_text(distribution.median)}, "
                f"p75 {_num_text(distribution.p75)}, maximum {_num_text(distribution.maximum)}",
                "",
            ]
            lines += [
                "Per-run resource evidence (MiB); external deficits are not prevention claims:",
                "",
                "| run | p50/p99 ms | queue p50/p95 s | private/physical peak MiB | "
                "physical/Commit minimum MiB | physical/Commit attribution | "
                "monitor CPU/Commit MiB | API errors | restore s | coverage | native cap events |",
                "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
            for pair in analysis.pairs:
                for record in (pair.baseline, pair.treatment):
                    metric = record.metrics
                    lines.append(
                        f"| {record.run_id} | {metric.foreground_p50_ms:.2f}/{metric.foreground_p99_ms:.2f} "
                        f"| {metric.queue_wait_p50_s:.2f}/{metric.queue_wait_p95_s:.2f} "
                        f"| {metric.peak_private_commit_mib:.2f}/{metric.peak_physical_mib:.2f} "
                        f"| {metric.min_physical_headroom_mib:.2f}/{metric.min_commit_headroom_mib:.2f} "
                        f"| {metric.physical_headroom_attribution.value}/{metric.commit_headroom_attribution.value} "
                        f"| {metric.monitor_cpu_units:.4f}/{metric.monitor_commit_mib:.2f} "
                        f"| {metric.api_errors} | {_num_text(metric.restore_time_s)} "
                        f"| {metric.coverage_fraction:.3f} | {len(metric.native_cap_intervals)} |")
            lines.append("")
            for pair in analysis.pairs:
                for record in (pair.baseline, pair.treatment):
                    lines.append(f"- {record.run_id}: states {record.metrics.time_in_state_s}; "
                                 f"headroom evidence {record.metrics.physical_headroom_evidence_id}, "
                                 f"{record.metrics.commit_headroom_evidence_id}; native write/readback "
                                 f"{record.metrics.native_cap_write_audit_sha256}/"
                                 f"{record.metrics.native_cap_readback_sha256}")
            lines.append("")
        if analysis.excluded:
            lines += ["Excluded runs:", ""]
            for item in analysis.excluded:
                lines.append(f"- {item.run_id} ({item.variant.value}, pair {item.pair_index}): "
                             + "; ".join(item.reasons))
            lines.append("")
        if analysis.checks:
            lines += ["| check | status | observed | limit | detail |",
                      "| --- | --- | --- | --- | --- |"]
            for check in analysis.checks:
                lines.append(f"| {check.name} | {check.status.value} "
                             f"| {_num_text(check.observed, 4)} | {_num_text(check.limit, 4)} "
                             f"| {check.detail} |")
            lines.append("")
        for note in analysis.notes:
            lines.append(f"- {note}")
        lines += ["", f"Verdict: {analysis.verdict.value}", ""]

    lines += ["## Plan gaps", ""]
    lines += [f"- {gap}" for gap in PLAN_GAPS]
    lines.append("")
    return "\n".join(lines)


# --- runner interface --------------------------------------------------------


class BenchmarkRunner(Protocol):
    """What a later stage has to implement to produce measured records.

    An implementation launches the workload for one slot and one variant and
    returns a record with complete raw measurement provenance. Nothing in this
    pure module launches workloads or proves a native gate.
    """

    def run(self, slot: PairSlot, variant: Variant) -> RunRecord:
        ...


class DryRunRunner:
    """Prints the schedule. Launches nothing and returns no record."""

    def __init__(self, stream=None):
        self.stream = stream if stream is not None else sys.stdout
        self.requested: list[tuple[PairSlot, Variant]] = []

    def run(self, slot: PairSlot, variant: Variant) -> RunRecord:
        self.requested.append((slot, variant))
        raise BenchmarkDataError(
            "dry run cannot produce a measured record; no workload was launched")

    def print_schedule(self, schedule: Schedule) -> None:
        self.stream.write(render_dry_run(schedule))


def render_dry_run(schedule: Schedule) -> str:
    lines = [f"seed {schedule.seed}, {schedule.pairs_per_scenario} pairs per scenario, "
             f"{len(schedule.slots)} paired slots, nothing is launched"]
    for slot in schedule.slots:
        lines.append(f"{slot.comparison.value} {slot.scenario} "
                     f"[{slot.scenario_class.value}] pair {slot.pair_index} "
                     f"order {slot.order_label}")
    return "\n".join(lines) + "\n"


DEFAULT_SCENARIOS = (
    ("cpu_bound_build", ScenarioClass.CPU_CONTENTION),
    ("io_bound_install", ScenarioClass.IO_BOUND),
    ("memory_heavy_test", ScenarioClass.MEMORY_HEAVY),
    ("no_pressure_idle", ScenarioClass.NO_PRESSURE),
    ("unmanaged_cpu_pressure", ScenarioClass.UNMANAGED_CPU_PRESSURE),
    ("mixed_exempt_background_protected", ScenarioClass.MIXED_ROLES),
    ("mixed_root_and_child_durations", ScenarioClass.MIXED_DURATIONS),
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the paired A/B schedule. Runs nothing.")
    parser.add_argument("--seed", required=True)
    parser.add_argument("--pairs", type=int, default=MIN_PAIRS_PER_SCENARIO)
    arguments = parser.parse_args(argv)
    schedule = build_schedule(DEFAULT_SCENARIOS, arguments.seed, arguments.pairs)
    DryRunRunner().print_schedule(schedule)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
