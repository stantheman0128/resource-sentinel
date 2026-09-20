"""Paired A/B benchmark harness for the adaptive scheduler (plan P6, section 11.3).

This module owns the schedule, the run record schema, the pure statistics, the
promotion threshold checks and the report renderer for the A0 / A1 / B
comparison required by docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md
sections 11.1 to 11.4. It measures nothing. It launches nothing, touches no
running process, and reads neither the live Sentinel database nor its config.

Why it is built before anything can run: variant B needs a CPU actuator that
does not exist yet, so no measured A1 or B data can exist yet either. The plan
is explicit that none of its thresholds have been measured ("這些是本plan提出的
門檻；沒有任何一項已在本輪測得", section 11.2). The harness therefore refuses to
turn fabricated numbers into a pass:

  - every run record carries an evidence source, measured or synthetic;
  - one synthetic record anywhere in a comparison forces the verdict
    NOT_MEASURED, whatever the numbers say;
  - fewer than ten valid pairs, or a missing variant, forces INSUFFICIENT_DATA;
  - a comparison the plan gives no number for reports NO_THRESHOLD_DEFINED
    rather than a pass;
  - a scenario where A1 foreground p95 is already below twenty milliseconds
    reports NO_PROBLEM_TO_CONTROL, which is the plan's "沒有足夠需要控制的問題";
  - no verdict value means "A/B complete". The best available value means the
    thresholds this plan names were met by measured paired data, nothing more.

Every threshold constant below is quoted from plan section 11.3. Where the plan
names no number, this module says so in the check detail instead of inventing
one; those gaps are listed in PLAN_GAPS.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import argparse
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

PLAN_GAPS = (
    "Plan 11.3 gives no numeric threshold for A0 to A1; that comparison reports "
    "NO_THRESHOLD_DEFINED and its measured cost is printed for a human to judge.",
    "Plan 11.3 says only 「A0→B若總體成本／互動效果倒退…仍不promotion」 with no "
    "tolerance, so the A0 to B veto here triggers on any median degradation of "
    "foreground p95 or makespan, which is the strictest reading.",
    "Plan 11.3 names no threshold for the unmanaged CPU pressure, mixed role and "
    "mixed duration scenarios; those report NO_THRESHOLD_DEFINED.",
    "Plan 11.3 lists 「minimum headroom」 without saying whether it is physical or "
    "commit, so the schema carries one field and the report prints it as given.",
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
        pair = COMPARISON_VARIANTS[self.comparison]
        if {self.first_variant, self.second_variant} != set(pair):
            raise BenchmarkDataError("variants: order must cover exactly the compared pair")

    @property
    def order_label(self) -> str:
        return f"{self.first_variant.value}{self.second_variant.value}"


@dataclass(frozen=True)
class Schedule:
    seed: str
    pairs_per_scenario: int
    slots: tuple[PairSlot, ...]

    def __post_init__(self):
        _text(self.seed, "seed")
        _int(self.pairs_per_scenario, "pairs_per_scenario", 1, 1 << 16)
        if not self.slots:
            raise BenchmarkDataError("slots: schedule is empty")


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

    def __post_init__(self):
        _text(self.commit, "commit")
        _text(self.os_build, "os_build")
        _int(self.logical_processors, "logical_processors", 1, 4096)
        _text(self.power_plan, "power_plan")
        _typed(self.cache_state, CacheState, "cache_state")
        if type(self.thermal_or_power_anomaly) is not bool:
            raise BenchmarkDataError("thermal_or_power_anomaly: boolean required")

    @property
    def comparable_key(self) -> tuple:
        """Everything that must match across a pair. The anomaly flag excludes a
        run on its own, so it is not part of the match key."""
        return (self.commit, self.os_build, self.logical_processors,
                self.power_plan, self.cache_state)


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
    min_headroom_mib: float
    monitor_cpu_units: float
    monitor_commit_mib: float
    api_errors: int
    restore_time_s: float | None
    coverage_fraction: float

    def __post_init__(self):
        for name in ("foreground_p50_ms", "foreground_p95_ms", "foreground_p99_ms",
                     "completed_units_per_min", "queue_wait_p50_s", "queue_wait_p95_s",
                     "peak_private_commit_mib", "peak_physical_mib",
                     "monitor_cpu_units", "monitor_commit_mib"):
            _num(getattr(self, name), name)
        _num(self.makespan_s, "makespan_s", 0.0, allow_minimum=False)
        _finite(self.min_headroom_mib, "min_headroom_mib")
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
        if type(self.note) is not str or len(self.note) > 500:
            raise BenchmarkDataError("note: text up to 500 characters")


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
) -> tuple[tuple[PairedRun, ...], tuple[ExcludedRun, ...]]:
    """Match baseline and treatment runs by pair index, excluding unusable runs.

    A run is excluded when a precondition failed or was never checked, when it
    has no partner, or when the pair does not share the fixed conditions.
    """
    baseline_variant, treatment_variant = COMPARISON_VARIANTS[comparison]
    excluded: list[ExcludedRun] = []
    by_slot: dict[tuple[int, Variant], RunRecord] = {}

    for record in records:
        if record.scenario != scenario or record.variant not in (baseline_variant, treatment_variant):
            continue
        reasons = precondition_failures(record)
        if reasons:
            excluded.append(ExcludedRun(record.run_id, record.scenario, record.variant,
                                        record.pair_index, reasons))
            continue
        key = (record.pair_index, record.variant)
        if key in by_slot:
            raise BenchmarkDataError("pair_index: duplicate run for one variant and pair")
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


def check_neutral_scenario(pairs: Sequence[PairedRun]) -> tuple[ThresholdCheck, ...]:
    """Plan section 11.3, no pressure, I/O dominated and memory dominated scenarios."""
    if not pairs:
        raise BenchmarkDataError("check_neutral_scenario: no pairs")
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_degradation = median(relative_changes(base_makespan, treat_makespan))
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    p95_degradation = median(relative_changes(base_p95, treat_p95))
    capped_seconds = sum(pair.treatment.metrics.seconds_in(state)
                         for pair in pairs for state in CAPPED_STATE_NAMES)

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
        ThresholdCheck(
            "no unrelated cap applied",
            CheckStatus.PASS if capped_seconds == 0.0 else CheckStatus.FAIL,
            capped_seconds, 0.0,
            "plan 11.3: B must not apply an unrelated cap in these scenarios"),
    )


def check_observer_cost(pairs: Sequence[PairedRun]) -> tuple[ThresholdCheck, ...]:
    """A0 to A1. Plan section 11.3 names no number here, so nothing is judged."""
    if not pairs:
        raise BenchmarkDataError("check_observer_cost: no pairs")
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    return (
        ThresholdCheck(
            "foreground p95 change median",
            CheckStatus.NOT_APPLICABLE, median(relative_changes(base_p95, treat_p95)), None,
            "plan 11.3 states no A0 to A1 threshold; reported for human judgement"),
        ThresholdCheck(
            "makespan change median",
            CheckStatus.NOT_APPLICABLE, median(relative_changes(base_makespan, treat_makespan)), None,
            "plan 11.3 states no A0 to A1 threshold; reported for human judgement"),
        ThresholdCheck(
            "monitor CPU units median (A1)",
            CheckStatus.NOT_APPLICABLE,
            median([pair.treatment.metrics.monitor_cpu_units for pair in pairs]), None,
            "plan 11.2 holds the monitoring cost thresholds; they are not A/B thresholds"),
    )


def check_a0_b_regression(pairs: Sequence[PairedRun]) -> tuple[ThresholdCheck, ...]:
    """Plan section 11.3 veto: if A0 to B regresses overall, B is not promoted.

    The plan gives no tolerance for 倒退, so any median degradation of foreground
    p95 or of makespan vetoes, which is the strictest reading of that sentence.
    """
    if not pairs:
        raise BenchmarkDataError("check_a0_b_regression: no pairs")
    base_p95, treat_p95 = _metric_values(pairs, "foreground_p95_ms")
    p95_change = median(relative_changes(base_p95, treat_p95))
    base_makespan, treat_makespan = _metric_values(pairs, "makespan_s")
    makespan_change = median(relative_changes(base_makespan, treat_makespan))
    detail = ("plan 11.3 veto, no numeric tolerance stated, so any median degradation "
              "counts as a regression")
    return (
        ThresholdCheck("A0 to B foreground p95 change median",
                       CheckStatus.PASS if p95_change <= 0.0 else CheckStatus.FAIL,
                       p95_change, 0.0, detail),
        ThresholdCheck("A0 to B makespan change median",
                       CheckStatus.PASS if makespan_change <= 0.0 else CheckStatus.FAIL,
                       makespan_change, 0.0, detail),
    )


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
) -> ComparisonAnalysis:
    """Pair, validate, check and rule on one comparison in one scenario.

    Verdict precedence: synthetic evidence first, then data sufficiency, then the
    plan's "no problem worth controlling" rule, then missing thresholds, then the
    threshold results. A threshold result can never outrank an evidence problem.
    """
    _typed(comparison, Comparison, "comparison")
    _text(scenario, "scenario")
    _typed(scenario_class, ScenarioClass, "scenario_class")
    _int(min_pairs, "min_pairs", 1, 1 << 16)

    baseline_variant, treatment_variant = COMPARISON_VARIANTS[comparison]
    relevant = [record for record in records
                if record.scenario == scenario
                and record.variant in (baseline_variant, treatment_variant)]
    pairs, excluded = pair_records(records, comparison, scenario)
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
            checks = check_neutral_scenario(pairs)
        elif comparison is Comparison.A0_A1:
            checks = check_observer_cost(pairs)
        elif comparison is Comparison.A0_B:
            checks = check_a0_b_regression(pairs)

    verdict = _verdict(comparison, scenario_class, pairs, relevant, evidence, checks,
                       min_pairs, notes)
    return ComparisonAnalysis(comparison, scenario, scenario_class, evidence, pairs,
                              excluded, checks, verdict, tuple(notes))


def _verdict(comparison, scenario_class, pairs, relevant, evidence, checks, min_pairs, notes):
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
    if not checks:
        notes.append("plan section 11.3 states no threshold for this comparison and scenario")
        return Verdict.NO_THRESHOLD_DEFINED
    if (comparison is Comparison.A1_B and scenario_class in CPU_RULE_SCENARIOS
            and all(check.status is CheckStatus.NOT_APPLICABLE for check in checks)):
        notes.append("A1 foreground p95 is already low, so this scenario shows no problem "
                     "worth controlling")
        return Verdict.NO_PROBLEM_TO_CONTROL
    if any(check.status is CheckStatus.FAIL for check in checks):
        return Verdict.FAIL
    if all(check.status is CheckStatus.NOT_APPLICABLE for check in checks):
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
    """The worst verdict across the analyses, with all three comparisons required.

    Plan section 11.3: "不能只選A1↔B而隱藏基礎設施造成的退步". A missing comparison
    is therefore insufficient data, not a silent pass.
    """
    if not analyses:
        return Verdict.INSUFFICIENT_DATA
    if {analysis.comparison for analysis in analyses} != set(Comparison):
        if any(analysis.verdict is Verdict.NOT_MEASURED for analysis in analyses):
            return Verdict.NOT_MEASURED
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
    returns a record whose evidence source is measured. Nothing in this module
    implements that, because no CPU actuator exists to make variant B real.
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
