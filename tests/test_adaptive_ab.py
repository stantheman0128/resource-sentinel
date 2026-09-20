"""Portable tests for the paired A/B harness. Every number here is fabricated.

Nothing in this file measures a CPU, a Job object, a foreground probe or a
restore. The records are labelled synthetic on purpose, except where a test
needs to exercise the measured path, and even those records describe a run that
never happened. No assertion depends on elapsed time, because a timer proves
nothing about reaction time or restore time.
"""

import io
import unittest

from tests.benchmarks.adaptive_ab import (
    BenchmarkDataError, CacheState, CheckStatus, Comparison, DEFAULT_SCENARIOS, DryRunRunner,
    EvidenceSource, FixedConditions, MIN_PAIRS_PER_SCENARIO, OrderPosition, PairedRun,
    Preconditions, RunMetrics, RunRecord, ScenarioClass, Variant, Verdict, analyze_comparison,
    build_schedule, check_a0_b_regression, check_cpu_contention, check_neutral_scenario,
    check_observer_cost,
    median, overall_verdict, paired_differences, parse_evidence_source, percentile, pair_records,
    precondition_failures, relative_changes, render_report, schedule_order_counts, spread,
)

SEED = "p6-order-seed-0001"
CPU_SCENARIO = "cpu_bound_build"
NEUTRAL_SCENARIO = "io_bound_install"
GOOD_PRECONDITIONS = Preconditions(True, True, True, True)


def conditions(anomaly=False, commit="0b2f378"):
    return FixedConditions(commit, "10.0.26340.1", 12, "High performance", CacheState.WARM, anomaly)


def metrics(foreground_p95=100.0, makespan=100.0, units=100.0, states=(), queue_wait=1.0):
    return RunMetrics(
        foreground_p50_ms=foreground_p95 / 2.0,
        foreground_p95_ms=foreground_p95,
        foreground_p99_ms=foreground_p95 * 1.5,
        makespan_s=makespan,
        completed_units_per_min=units,
        queue_wait_p50_s=queue_wait / 2.0,
        queue_wait_p95_s=queue_wait,
        time_in_state_s=tuple(states),
        peak_private_commit_mib=120.0,
        peak_physical_mib=150.0,
        min_headroom_mib=4096.0,
        monitor_cpu_units=0.04,
        monitor_commit_mib=140.0,
        api_errors=0,
        restore_time_s=1.2,
        coverage_fraction=1.0,
    )


def record(variant, pair_index, foreground_p95=100.0, makespan=100.0, units=100.0,
           scenario=CPU_SCENARIO, scenario_class=ScenarioClass.CPU_CONTENTION,
           source=EvidenceSource.MEASURED, preconditions=GOOD_PRECONDITIONS,
           conditions_override=None, states=(), order=OrderPosition.FIRST):
    return RunRecord(
        run_id=f"{scenario}-{variant.value}-{pair_index}",
        scenario=scenario,
        scenario_class=scenario_class,
        variant=variant,
        pair_index=pair_index,
        order_position=order,
        seed=SEED,
        evidence_source=source,
        conditions=conditions_override or conditions(),
        preconditions=preconditions,
        metrics=metrics(foreground_p95, makespan, units, states),
        note="fabricated, no run happened",
    )


def dataset(pair_count, baseline_variant, treatment_variant, baseline_p95=100.0,
            treatment_p95=80.0, baseline_makespan=100.0, treatment_makespan=105.0,
            baseline_units=100.0, treatment_units=95.0, source=EvidenceSource.MEASURED,
            scenario=CPU_SCENARIO, scenario_class=ScenarioClass.CPU_CONTENTION):
    """A clean set of pairs that meets every threshold the plan names."""
    records = []
    for index in range(pair_count):
        records.append(record(baseline_variant, index, baseline_p95, baseline_makespan,
                              baseline_units, scenario, scenario_class, source))
        records.append(record(treatment_variant, index, treatment_p95, treatment_makespan,
                              treatment_units, scenario, scenario_class, source,
                              order=OrderPosition.SECOND))
    return records


def pairs_of(baseline_values, treatment_values, scenario_class=ScenarioClass.CPU_CONTENTION,
             scenario=CPU_SCENARIO):
    """Build PairedRun objects straight from (p95, makespan, units) triples."""
    pairs = []
    for index, (base, treat) in enumerate(zip(baseline_values, treatment_values)):
        pairs.append(PairedRun(
            scenario, index,
            record(Variant.A1, index, base[0], base[1], base[2], scenario, scenario_class),
            record(Variant.B, index, treat[0], treat[1], treat[2], scenario, scenario_class,
                   order=OrderPosition.SECOND)))
    return pairs


class ScheduleTests(unittest.TestCase):
    def test_same_seed_reproduces_the_same_schedule(self):
        first = build_schedule(DEFAULT_SCENARIOS, SEED)
        second = build_schedule(DEFAULT_SCENARIOS, SEED)
        self.assertEqual(first.slots, second.slots)
        self.assertEqual(first.seed, SEED)

    def test_a_different_seed_changes_the_order(self):
        first = build_schedule(DEFAULT_SCENARIOS, SEED)
        other = build_schedule(DEFAULT_SCENARIOS, SEED + "-b")
        self.assertNotEqual(first.slots, other.slots)

    def test_orders_are_balanced_per_scenario_and_comparison(self):
        schedule = build_schedule(DEFAULT_SCENARIOS, SEED, 10)
        counts = schedule_order_counts(schedule)
        self.assertEqual(len(counts), len(DEFAULT_SCENARIOS) * len(Comparison))
        for (comparison, _scenario), bucket in counts.items():
            self.assertEqual(sum(bucket.values()), 10)
            self.assertEqual(len(bucket), 2, comparison)
            self.assertEqual(sorted(bucket.values()), [5, 5])

    def test_odd_pair_counts_differ_by_at_most_one(self):
        schedule = build_schedule([(CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)], SEED, 11)
        for bucket in schedule_order_counts(schedule).values():
            values = sorted(bucket.values())
            self.assertEqual(sum(values), 11)
            self.assertLessEqual(values[-1] - values[0], 1)

    def test_schedule_rejects_fewer_pairs_than_the_plan_requires(self):
        with self.assertRaises(BenchmarkDataError):
            build_schedule(DEFAULT_SCENARIOS, SEED, MIN_PAIRS_PER_SCENARIO - 1)

    def test_every_comparison_and_scenario_is_scheduled(self):
        schedule = build_schedule(DEFAULT_SCENARIOS, SEED)
        self.assertEqual(len(schedule.slots),
                         len(DEFAULT_SCENARIOS) * len(Comparison) * MIN_PAIRS_PER_SCENARIO)
        self.assertEqual({slot.comparison for slot in schedule.slots}, set(Comparison))


class SchemaTests(unittest.TestCase):
    def test_unknown_evidence_source_is_rejected(self):
        with self.assertRaises(BenchmarkDataError):
            parse_evidence_source("estimated")
        with self.assertRaises(BenchmarkDataError):
            parse_evidence_source(None)
        self.assertIs(parse_evidence_source("measured"), EvidenceSource.MEASURED)
        self.assertIs(parse_evidence_source("synthetic"), EvidenceSource.SYNTHETIC)

    def test_record_rejects_an_unknown_evidence_source(self):
        with self.assertRaises(BenchmarkDataError):
            record(Variant.B, 0, source="probably measured")

    def test_metrics_reject_decreasing_percentiles(self):
        with self.assertRaises(BenchmarkDataError):
            RunMetrics(10.0, 5.0, 20.0, 1.0, 1.0, 0.0, 0.0, (), 1.0, 1.0, 1.0, 0.0, 0.0, 0,
                       None, 1.0)

    def test_metrics_reject_coverage_above_one(self):
        with self.assertRaises(BenchmarkDataError):
            RunMetrics(1.0, 2.0, 3.0, 1.0, 1.0, 0.0, 0.0, (), 1.0, 1.0, 1.0, 0.0, 0.0, 0,
                       None, 1.5)

    def test_time_in_state_is_readable(self):
        record_with_states = record(Variant.B, 0, states=(("CAPPED_L1", 4.0), ("OBSERVING", 9.0)))
        self.assertEqual(record_with_states.metrics.seconds_in("CAPPED_L1"), 4.0)
        self.assertEqual(record_with_states.metrics.seconds_in("COOLDOWN"), 0.0)


class PreconditionTests(unittest.TestCase):
    def test_failed_precondition_excludes_the_run_and_is_counted(self):
        failed = Preconditions(True, False, True, True)
        records = dataset(10, Variant.A1, Variant.B)
        records[1] = record(Variant.B, 0, 80.0, 105.0, 95.0, preconditions=failed,
                            order=OrderPosition.SECOND)
        pairs, excluded = pair_records(records, Comparison.A1_B, CPU_SCENARIO)
        self.assertEqual(len(pairs), 9)
        self.assertEqual(len(excluded), 2)
        reasons = [reason for item in excluded for reason in item.reasons]
        self.assertIn("CPU not confirmed back to baseline", reasons)
        self.assertIn("pair incomplete, partner run missing", reasons)

    def test_unchecked_precondition_is_treated_as_a_failure(self):
        unchecked = Preconditions(True, True, None, True)
        reasons = precondition_failures(record(Variant.B, 0, preconditions=unchecked))
        self.assertEqual(len(reasons), 1)
        self.assertIn("never checked", reasons[0])

    def test_thermal_anomaly_excludes_the_run(self):
        anomalous = record(Variant.B, 0, conditions_override=conditions(anomaly=True))
        self.assertIn("thermal or power anomaly recorded", precondition_failures(anomalous))

    def test_mismatched_fixed_conditions_exclude_the_pair(self):
        records = dataset(10, Variant.A1, Variant.B)
        records[1] = record(Variant.B, 0, 80.0, 105.0, 95.0,
                            conditions_override=conditions(commit="deadbee"),
                            order=OrderPosition.SECOND)
        pairs, excluded = pair_records(records, Comparison.A1_B, CPU_SCENARIO)
        self.assertEqual(len(pairs), 9)
        self.assertEqual(len(excluded), 2)
        self.assertTrue(all("fixed conditions differ across the pair" in item.reasons
                            for item in excluded))

    def test_duplicate_run_for_one_slot_is_rejected(self):
        records = dataset(10, Variant.A1, Variant.B)
        records.append(record(Variant.B, 0, 80.0, 105.0, 95.0, order=OrderPosition.SECOND))
        with self.assertRaises(BenchmarkDataError):
            pair_records(records, Comparison.A1_B, CPU_SCENARIO)


class StatisticsTests(unittest.TestCase):
    def test_median_of_even_and_odd_counts(self):
        self.assertEqual(median([3.0, 1.0, 2.0]), 2.0)
        self.assertEqual(median([1.0, 2.0, 3.0, 4.0]), 2.5)
        with self.assertRaises(BenchmarkDataError):
            median([])

    def test_percentile_interpolates(self):
        values = [0.0, 10.0, 20.0, 30.0]
        self.assertEqual(percentile(values, 0.0), 0.0)
        self.assertEqual(percentile(values, 100.0), 30.0)
        self.assertEqual(percentile(values, 50.0), 15.0)
        self.assertEqual(percentile([5.0], 95.0), 5.0)

    def test_paired_differences_and_relative_changes(self):
        self.assertEqual(paired_differences([100.0, 50.0], [80.0, 60.0]), (-20.0, 10.0))
        self.assertEqual(relative_changes([100.0, 50.0], [80.0, 60.0]), (-0.2, 0.2))
        with self.assertRaises(BenchmarkDataError):
            paired_differences([1.0], [1.0, 2.0])
        with self.assertRaises(BenchmarkDataError):
            relative_changes([0.0], [1.0])

    def test_spread_reports_the_distribution(self):
        distribution = spread([1.0, 2.0, 3.0, 4.0])
        self.assertEqual(distribution.count, 4)
        self.assertEqual(distribution.minimum, 1.0)
        self.assertEqual(distribution.median, 2.5)
        self.assertEqual(distribution.maximum, 4.0)


class CpuThresholdBoundaryTests(unittest.TestCase):
    def check_names(self, checks):
        return {check.name: check for check in checks}

    def test_relative_improvement_boundary(self):
        at_limit = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(85.0, 100.0, 100.0)] * 3)))
        self.assertIs(at_limit["foreground p95 relative improvement median"].status,
                      CheckStatus.PASS)
        below = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(85.1, 100.0, 100.0)] * 3)))
        self.assertIs(below["foreground p95 relative improvement median"].status,
                      CheckStatus.FAIL)

    def test_absolute_improvement_boundary(self):
        at_limit = self.check_names(check_cpu_contention(
            pairs_of([(25.0, 100.0, 100.0)] * 3, [(20.0, 100.0, 100.0)] * 3)))
        self.assertIs(at_limit["foreground p95 absolute improvement median (ms)"].status,
                      CheckStatus.PASS)
        # Relative improvement is exactly 15 percent, absolute is only 3 ms.
        below = self.check_names(check_cpu_contention(
            pairs_of([(20.0, 100.0, 100.0)] * 3, [(17.0, 100.0, 100.0)] * 3)))
        self.assertIs(below["foreground p95 relative improvement median"].status,
                      CheckStatus.PASS)
        self.assertIs(below["foreground p95 absolute improvement median (ms)"].status,
                      CheckStatus.FAIL)

    def test_makespan_degradation_boundary(self):
        at_limit = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(80.0, 115.0, 100.0)] * 3)))
        self.assertIs(at_limit["background makespan degradation median"].status, CheckStatus.PASS)
        over = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(80.0, 115.1, 100.0)] * 3)))
        self.assertIs(over["background makespan degradation median"].status, CheckStatus.FAIL)

    def test_throughput_drop_boundary(self):
        at_limit = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(80.0, 100.0, 90.0)] * 3)))
        self.assertIs(at_limit["throughput drop median"].status, CheckStatus.PASS)
        over = self.check_names(check_cpu_contention(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(80.0, 100.0, 89.9)] * 3)))
        self.assertIs(over["throughput drop median"].status, CheckStatus.FAIL)

    def test_a1_p95_below_twenty_is_not_a_problem_worth_controlling(self):
        checks = check_cpu_contention(
            pairs_of([(19.9, 100.0, 100.0)] * 3, [(1.0, 100.0, 100.0)] * 3))
        self.assertEqual(len(checks), 1)
        self.assertIs(checks[0].status, CheckStatus.NOT_APPLICABLE)

    def test_a1_p95_at_twenty_is_still_judged(self):
        checks = check_cpu_contention(
            pairs_of([(20.0, 100.0, 100.0)] * 3, [(10.0, 100.0, 100.0)] * 3))
        self.assertEqual(len(checks), 4)


class NeutralThresholdBoundaryTests(unittest.TestCase):
    def names(self, checks):
        return {check.name: check for check in checks}

    def test_makespan_and_p95_degradation_boundary(self):
        at_limit = self.names(check_neutral_scenario(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(105.0, 105.0, 100.0)] * 3,
                     ScenarioClass.IO_BOUND, NEUTRAL_SCENARIO)))
        self.assertIs(at_limit["makespan degradation median"].status, CheckStatus.PASS)
        self.assertIs(at_limit["foreground p95 degradation median"].status, CheckStatus.PASS)
        over = self.names(check_neutral_scenario(
            pairs_of([(100.0, 100.0, 100.0)] * 3, [(105.1, 105.1, 100.0)] * 3,
                     ScenarioClass.IO_BOUND, NEUTRAL_SCENARIO)))
        self.assertIs(over["makespan degradation median"].status, CheckStatus.FAIL)
        self.assertIs(over["foreground p95 degradation median"].status, CheckStatus.FAIL)

    def test_an_unrelated_cap_fails_the_neutral_scenario(self):
        pairs = pairs_of([(100.0, 100.0, 100.0)] * 3, [(100.0, 100.0, 100.0)] * 3,
                         ScenarioClass.IO_BOUND, NEUTRAL_SCENARIO)
        capped = PairedRun(NEUTRAL_SCENARIO, 0, pairs[0].baseline,
                           record(Variant.B, 0, 100.0, 100.0, 100.0, NEUTRAL_SCENARIO,
                                  ScenarioClass.IO_BOUND, states=(("CAPPED_L1", 3.0),),
                                  order=OrderPosition.SECOND))
        checks = {check.name: check for check in check_neutral_scenario([capped] + pairs[1:])}
        self.assertIs(checks["no unrelated cap applied"].status, CheckStatus.FAIL)


class ObserverCostTests(unittest.TestCase):
    """Clarification C1: A0 to A1 held to the plan 11.3 neutral rule of 5 percent."""

    def names(self, baseline, treatment):
        checks = check_observer_cost(pairs_of([baseline] * 3, [treatment] * 3))
        return {check.name: check for check in checks}

    def test_cost_within_five_percent_passes(self):
        at_limit = self.names((100.0, 100.0, 100.0), (105.0, 105.0, 100.0))
        self.assertIs(at_limit["foreground p95 degradation median"].status, CheckStatus.PASS)
        self.assertIs(at_limit["makespan degradation median"].status, CheckStatus.PASS)

    def test_cost_beyond_five_percent_fails(self):
        over = self.names((100.0, 100.0, 100.0), (105.1, 105.1, 100.0))
        self.assertIs(over["foreground p95 degradation median"].status, CheckStatus.FAIL)
        self.assertIs(over["makespan degradation median"].status, CheckStatus.FAIL)

    def test_monitor_cpu_is_not_judged_without_a_job_count(self):
        checks = self.names((100.0, 100.0, 100.0), (100.0, 100.0, 100.0))
        monitor = checks["monitor CPU units median (A1)"]
        self.assertIs(monitor.status, CheckStatus.NOT_APPLICABLE)
        self.assertIn("enrolled Job count", monitor.detail)

    def test_every_check_names_the_clarification(self):
        checks = self.names((100.0, 100.0, 100.0), (100.0, 100.0, 100.0))
        for check in checks.values():
            self.assertIn("clarification C1 (not in plan 11.3)", check.detail)

    def test_measured_cost_within_the_rule_is_promote_eligible(self):
        records = dataset(10, Variant.A0, Variant.A1, treatment_p95=100.0,
                          treatment_makespan=100.0, treatment_units=100.0)
        analysis = analyze_comparison(records, Comparison.A0_A1, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.PROMOTE_ELIGIBLE)

    def test_synthetic_observer_cost_is_not_measured(self):
        records = dataset(10, Variant.A0, Variant.A1, treatment_p95=100.0,
                          treatment_makespan=100.0, treatment_units=100.0,
                          source=EvidenceSource.SYNTHETIC)
        analysis = analyze_comparison(records, Comparison.A0_A1, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.NOT_MEASURED)


class A0ToBVetoTests(unittest.TestCase):
    def names(self, baseline, treatment, scenario_class=ScenarioClass.CPU_CONTENTION,
              scenario=CPU_SCENARIO):
        pairs = pairs_of([baseline] * 3, [treatment] * 3, scenario_class, scenario)
        return {check.name: check for check in check_a0_b_regression(pairs, scenario_class)}

    def test_regression_against_a0_vetoes(self):
        checks = self.names((100.0, 100.0, 100.0), (100.1, 100.0, 100.0))
        self.assertIs(checks["A0 to B foreground p95 change median"].status, CheckStatus.FAIL)

    def test_no_regression_passes(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 99.0, 100.0))
        self.assertTrue(all(check.status is CheckStatus.PASS for check in checks.values()))

    def test_cpu_scenario_allows_the_plan_batch_tolerance(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 110.0, 100.0))
        self.assertTrue(all(check.status is CheckStatus.PASS for check in checks.values()))

    def test_cpu_scenario_rejects_makespan_beyond_fifteen_percent(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 120.0, 100.0))
        self.assertIs(checks["A0 to B makespan degradation median"].status, CheckStatus.FAIL)
        self.assertIs(checks["A0 to B foreground p95 change median"].status, CheckStatus.PASS)

    def test_cpu_scenario_rejects_throughput_drop_beyond_ten_percent(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 110.0, 89.0))
        self.assertIs(checks["A0 to B throughput drop median"].status, CheckStatus.FAIL)

    def test_worse_interaction_fails_even_with_an_acceptable_batch_cost(self):
        checks = self.names((100.0, 100.0, 100.0), (101.0, 110.0, 100.0))
        self.assertIs(checks["A0 to B foreground p95 change median"].status, CheckStatus.FAIL)

    def test_neutral_scenario_rejects_makespan_beyond_five_percent(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 106.0, 100.0),
                            ScenarioClass.IO_BOUND, NEUTRAL_SCENARIO)
        self.assertIs(checks["A0 to B makespan degradation median"].status, CheckStatus.FAIL)
        self.assertNotIn("A0 to B throughput drop median", checks)

    def test_neutral_scenario_within_five_percent_passes(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 105.0, 100.0),
                            ScenarioClass.IO_BOUND, NEUTRAL_SCENARIO)
        self.assertTrue(all(check.status is CheckStatus.PASS for check in checks.values()))

    def test_unlisted_scenario_class_is_not_judged(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 110.0, 100.0),
                            ScenarioClass.MIXED_ROLES, "mixed_roles")
        self.assertTrue(all(check.status is CheckStatus.NOT_APPLICABLE
                            for check in checks.values()))

    def test_every_check_names_the_clarification(self):
        checks = self.names((100.0, 100.0, 100.0), (90.0, 110.0, 100.0))
        for check in checks.values():
            self.assertIn("clarification C2 (not in plan 11.3)", check.detail)

    def test_synthetic_a0_to_b_is_not_measured(self):
        records = dataset(10, Variant.A0, Variant.B, treatment_p95=90.0,
                          treatment_makespan=110.0, treatment_units=100.0,
                          source=EvidenceSource.SYNTHETIC)
        analysis = analyze_comparison(records, Comparison.A0_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.NOT_MEASURED)

    def test_veto_reaches_the_verdict_even_when_a1_to_b_wins(self):
        records = dataset(10, Variant.A0, Variant.B, treatment_p95=110.0,
                          treatment_makespan=100.0, treatment_units=100.0)
        analysis = analyze_comparison(records, Comparison.A0_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.FAIL)


class VerdictTests(unittest.TestCase):
    def test_synthetic_data_that_meets_every_threshold_is_not_measured(self):
        records = dataset(12, Variant.A1, Variant.B, source=EvidenceSource.SYNTHETIC)
        analysis = analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.NOT_MEASURED)
        # The same numbers, labelled measured, would have passed.
        measured = analyze_comparison(dataset(12, Variant.A1, Variant.B), Comparison.A1_B,
                                      CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertIs(measured.verdict, Verdict.PROMOTE_ELIGIBLE)

    def test_one_synthetic_record_among_measured_ones_is_enough(self):
        records = dataset(12, Variant.A1, Variant.B)
        records[0] = record(Variant.A1, 0, source=EvidenceSource.SYNTHETIC)
        analysis = analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.NOT_MEASURED)

    def test_nine_pairs_is_insufficient_data(self):
        analysis = analyze_comparison(dataset(9, Variant.A1, Variant.B), Comparison.A1_B,
                                      CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.INSUFFICIENT_DATA)
        self.assertEqual(len(analysis.pairs), 9)
        self.assertTrue(any("at least 10" in note for note in analysis.notes))

    def test_ten_pairs_is_enough(self):
        analysis = analyze_comparison(dataset(10, Variant.A1, Variant.B), Comparison.A1_B,
                                      CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.PROMOTE_ELIGIBLE)

    def test_missing_variant_is_insufficient_data(self):
        records = [entry for entry in dataset(10, Variant.A1, Variant.B)
                   if entry.variant is Variant.A1]
        analysis = analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.INSUFFICIENT_DATA)

    def test_excluded_runs_can_push_a_comparison_below_the_minimum(self):
        records = dataset(10, Variant.A1, Variant.B)
        records[0] = record(Variant.A1, 0, preconditions=Preconditions(False, True, True, True))
        analysis = analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.INSUFFICIENT_DATA)
        self.assertEqual(len(analysis.excluded), 2)

    def test_low_baseline_latency_reports_no_problem_to_control(self):
        records = dataset(10, Variant.A1, Variant.B, baseline_p95=19.0, treatment_p95=1.0)
        analysis = analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.NO_PROBLEM_TO_CONTROL)

    def test_observer_cost_beyond_the_clarified_rule_fails(self):
        records = dataset(10, Variant.A0, Variant.A1, treatment_p95=106.0,
                          treatment_makespan=100.0, treatment_units=100.0)
        analysis = analyze_comparison(records, Comparison.A0_A1, CPU_SCENARIO,
                                      ScenarioClass.CPU_CONTENTION)
        self.assertIs(analysis.verdict, Verdict.FAIL)

    def test_unlisted_scenario_class_has_no_plan_threshold(self):
        records = dataset(10, Variant.A1, Variant.B, scenario="mixed_roles",
                          scenario_class=ScenarioClass.MIXED_ROLES)
        analysis = analyze_comparison(records, Comparison.A1_B, "mixed_roles",
                                      ScenarioClass.MIXED_ROLES)
        self.assertIs(analysis.verdict, Verdict.NO_THRESHOLD_DEFINED)

    def test_sample_size_is_always_reported_as_small(self):
        analysis = analyze_comparison(dataset(10, Variant.A1, Variant.B), Comparison.A1_B,
                                      CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertTrue(any("small sample" in note for note in analysis.notes))

    def test_overall_verdict_needs_all_three_comparisons(self):
        good = analyze_comparison(dataset(10, Variant.A1, Variant.B), Comparison.A1_B,
                                  CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertIs(overall_verdict([good]), Verdict.INSUFFICIENT_DATA)

    def test_overall_verdict_takes_the_worst(self):
        a1b = analyze_comparison(dataset(10, Variant.A1, Variant.B), Comparison.A1_B,
                                 CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        a0a1 = analyze_comparison(
            dataset(10, Variant.A0, Variant.A1, treatment_p95=100.0, treatment_makespan=100.0,
                    treatment_units=100.0),
            Comparison.A0_A1, CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        # Mixed roles is a scenario class the plan states no tolerance for, so this
        # A0 to B comparison is the one without a threshold.
        a0b = analyze_comparison(
            dataset(10, Variant.A0, Variant.B, treatment_p95=80.0, treatment_makespan=99.0,
                    treatment_units=100.0, scenario="mixed_roles",
                    scenario_class=ScenarioClass.MIXED_ROLES),
            Comparison.A0_B, "mixed_roles", ScenarioClass.MIXED_ROLES)
        self.assertIs(overall_verdict([a1b, a0a1, a0b]), Verdict.NO_THRESHOLD_DEFINED)
        synthetic = analyze_comparison(
            dataset(10, Variant.A1, Variant.B, source=EvidenceSource.SYNTHETIC),
            Comparison.A1_B, CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)
        self.assertIs(overall_verdict([synthetic, a0a1, a0b]), Verdict.NOT_MEASURED)


class ReportTests(unittest.TestCase):
    def analysis(self, source=EvidenceSource.SYNTHETIC):
        records = dataset(10, Variant.A1, Variant.B, source=source)
        records[0] = record(Variant.A1, 0, preconditions=Preconditions(True, True, True, False),
                            source=source)
        return analyze_comparison(records, Comparison.A1_B, CPU_SCENARIO,
                                  ScenarioClass.CPU_CONTENTION)

    def test_report_states_the_evidence_source_and_verdict(self):
        text = render_report([self.analysis()], SEED)
        self.assertIn("Evidence source: synthetic", text)
        self.assertIn(SEED, text)
        self.assertIn("Verdict: NOT_MEASURED", text)
        self.assertIn("the A/B comparison is not complete", text)

    def test_report_lists_pairs_and_exclusions(self):
        analysis = self.analysis()
        text = render_report([analysis], SEED)
        self.assertIn("Excluded runs: 2", text)
        self.assertIn("cap audit not confirmed disabled", text)
        self.assertIn("| pair | order |", text)
        for pair in analysis.pairs:
            self.assertIn(f"| {pair.pair_index} | ", text)

    def test_report_shows_the_paired_spread(self):
        text = render_report([self.analysis()], SEED)
        self.assertIn("Paired foreground p95 difference", text)
        self.assertIn("median", text)

    def test_report_has_no_long_dash_characters(self):
        text = render_report([self.analysis()], SEED)
        for code_point in (0x2014, 0x2013):
            self.assertNotIn(chr(code_point), text)


class DryRunTests(unittest.TestCase):
    def test_dry_run_prints_the_schedule_and_launches_nothing(self):
        stream = io.StringIO()
        runner = DryRunRunner(stream)
        schedule = build_schedule([(CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)], SEED)
        runner.print_schedule(schedule)
        printed = stream.getvalue()
        self.assertIn(SEED, printed)
        self.assertIn("nothing is launched", printed)
        self.assertEqual(printed.count("pair "), len(schedule.slots))
        self.assertEqual(runner.requested, [])

    def test_dry_run_cannot_produce_a_record(self):
        runner = DryRunRunner(io.StringIO())
        slot = build_schedule([(CPU_SCENARIO, ScenarioClass.CPU_CONTENTION)], SEED).slots[0]
        with self.assertRaises(BenchmarkDataError):
            runner.run(slot, Variant.B)
        self.assertEqual(len(runner.requested), 1)


if __name__ == "__main__":
    unittest.main()
