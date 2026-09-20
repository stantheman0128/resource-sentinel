"""Cost probe tests: pure threshold and latency logic, plus one real measurement.

The Windows case starts a plain busy child of its own, measures that child, and
stops it through a stop file. It creates no Job, sets no CPU control, and needs
neither the native spike opt-in nor the host gate. It never opens, enumerates or
signals a process it did not create.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tests.windows.adaptive_cost_probe import (
    OUTCOMES, REACTION_STAGES, THRESHOLDS, CostProbe, CostProbeError, CostSample, ProcessCost,
    ReactionLatency, ReactionLatencyError, evaluate_all, evaluate_threshold, percentile,
    reaction_p95,
)
# One thread of bounded arithmetic. It announces itself, then runs until the stop
# file appears or its own five second deadline passes, whichever comes first.
BUSY_CHILD = """
import os, sys, time
stop = sys.argv[1]
deadline = time.monotonic() + 5.0
print("ready", flush=True)
value = 1
while time.monotonic() < deadline and not os.path.exists(stop):
    for _ in range(20000):
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
"""


def _cost(pid=100, cpu_units=0.25, mib=12.0):
    return ProcessCost(pid, "133700000000000000", cpu_units * 2.0, cpu_units, mib)


class PercentileTests(unittest.TestCase):
    def test_nearest_rank_p95_and_median(self):
        values = [float(index) for index in range(1, 101)]
        self.assertEqual(percentile(values, 0.95), 95.0)
        self.assertEqual(percentile(values, 0.5), 50.0)
        self.assertEqual(percentile([7.0], 0.95), 7.0)
        self.assertEqual(percentile([3.0, 1.0, 2.0], 1.0), 3.0)

    def test_rejects_empty_nonfinite_and_out_of_range_fractions(self):
        for arguments in (([], 0.95), ([1.0], 0.0), ([1.0], 1.5),
                          ([float("nan")], 0.95), ([True], 0.95)):
            with self.subTest(arguments=arguments), self.assertRaises(CostProbeError):
                percentile(*arguments)


class ThresholdTests(unittest.TestCase):
    def test_pass_fail_and_not_measured_are_the_only_outcomes(self):
        self.assertEqual(evaluate_threshold("monitoring_cpu_units_10_jobs", 0.10).outcome, "PASS")
        self.assertEqual(evaluate_threshold("monitoring_cpu_units_10_jobs", 0.11).outcome, "FAIL")
        absent = evaluate_threshold("monitoring_cpu_units_10_jobs", None)
        self.assertEqual(absent.outcome, "NOT_MEASURED")
        self.assertIsNone(absent.measured)
        self.assertEqual(set(OUTCOMES), {"PASS", "FAIL", "NOT_MEASURED"})

    def test_every_eleven_two_threshold_is_reported_even_when_unmeasured(self):
        results = evaluate_all({"fast_tick_p95_seconds_10_jobs": 0.02})
        self.assertEqual(len(results), len(THRESHOLDS))
        outcomes = {result.name: result.outcome for result in results}
        self.assertEqual(outcomes["fast_tick_p95_seconds_10_jobs"], "PASS")
        self.assertEqual(outcomes["monitoring_private_commit_mib"], "NOT_MEASURED")
        self.assertTrue(set(outcomes) == set(THRESHOLDS))

    def test_unknown_threshold_or_invalid_measurement_is_refused(self):
        with self.assertRaises(CostProbeError):
            evaluate_threshold("invented_threshold", 1.0)
        with self.assertRaises(CostProbeError):
            evaluate_threshold("monitoring_cpu_units_1_job", float("inf"))
        with self.assertRaises(CostProbeError):
            evaluate_all({"invented_threshold": 1.0})


class SampleArithmeticTests(unittest.TestCase):
    def test_sums_per_process_cpu_units_and_mib(self):
        sample = CostSample(0.5, (_cost(101, 0.25, 12.0), _cost(102, 0.75, 30.0)))
        self.assertAlmostEqual(sample.total_cpu_units, 1.0)
        self.assertAlmostEqual(sample.total_private_commit_mib, 42.0)
        self.assertAlmostEqual(sample.total_cpu_seconds, 2.0)

    def test_rejects_empty_negative_and_out_of_range_samples(self):
        with self.assertRaises(CostProbeError):
            CostSample(0.5, ())
        with self.assertRaises(CostProbeError):
            CostSample(0.0, (_cost(),))
        with self.assertRaises(CostProbeError):
            ProcessCost(0, "1", 1.0, 1.0, 1.0)
        with self.assertRaises(CostProbeError):
            ProcessCost(5, "1", -1.0, 1.0, 1.0)


class ReactionLatencyTests(unittest.TestCase):
    def _stages(self, **overrides):
        stages = dict(zip(REACTION_STAGES, (10.0, 10.5, 10.75, 11.5)))
        stages.update(overrides)
        return stages

    def test_decomposes_a_measured_reaction(self):
        record = ReactionLatency(self._stages())
        self.assertAlmostEqual(record.total_seconds, 1.5)
        self.assertAlmostEqual(record.stage_durations["decision"], 0.5)
        self.assertAlmostEqual(record.stage_durations["query_confirmed"], 0.75)
        self.assertEqual(tuple(record.stages), REACTION_STAGES)

    def test_missing_extra_or_non_increasing_stages_are_refused(self):
        partial = self._stages()
        partial.pop("apply")
        with self.assertRaises(ReactionLatencyError):
            ReactionLatency(partial)
        with self.assertRaises(ReactionLatencyError):
            ReactionLatency({**self._stages(), "configured_interval_seconds": 1.0})
        with self.assertRaises(ReactionLatencyError):
            ReactionLatency(self._stages(apply=10.4))
        with self.assertRaises(ReactionLatencyError):
            ReactionLatency(self._stages(decision=10.0))
        with self.assertRaises(ReactionLatencyError):
            ReactionLatency(self._stages(apply=float("nan")))

    def test_p95_accepts_only_measured_records(self):
        records = [ReactionLatency(self._stages(query_confirmed=11.0 + index * 0.1))
                   for index in range(10)]
        self.assertAlmostEqual(reaction_p95(records), 1.9, places=6)
        with self.assertRaises(ReactionLatencyError):
            reaction_p95([1.0])


class ProbeArgumentTests(unittest.TestCase):
    def test_refuses_empty_duplicate_and_invalid_pids(self):
        for pids in ((), (1, 1), (0,), (-3,), ("1234",)):
            with self.subTest(pids=pids), self.assertRaises(CostProbeError):
                CostProbe(pids)


@unittest.skipUnless(os.name == "nt", "the cost probe measures Windows processes")
class WindowsCostProbeTests(unittest.TestCase):
    """Measure one child this test started, then stop it cooperatively."""

    def test_measures_own_busy_child_and_stops_it_through_its_stop_file(self):
        process = probe = None
        with tempfile.TemporaryDirectory() as raw:
            stop = Path(raw).resolve() / "stop"
            try:
                process = subprocess.Popen(
                    [sys.executable, "-c", BUSY_CHILD, str(stop)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, close_fds=True)
                self.assertEqual(process.stdout.readline().strip(), b"ready")
                probe = CostProbe([process.pid])
                sample = probe.sample(0.5)

                self.assertGreaterEqual(sample.interval_seconds, 0.5)
                self.assertEqual(len(sample.per_process), 1)
                measured = sample.per_process[0]
                self.assertEqual(measured.pid, process.pid)
                self.assertTrue(str(measured.created_filetime_100ns).isdigit())
                # The bounds only show that real counters were read. An outer Job
                # this host may impose is unknown, so they claim nothing about
                # how much CPU an unconstrained child would get.
                self.assertGreater(measured.cpu_units, 0.1)
                self.assertLess(measured.cpu_units, 2.0)
                self.assertGreater(measured.cpu_seconds, 0.0)
                self.assertGreater(measured.private_commit_mib, 1.0)
                self.assertLess(measured.private_commit_mib, 1024.0)
                self.assertAlmostEqual(sample.total_cpu_units, measured.cpu_units)
                self.assertAlmostEqual(sample.total_private_commit_mib,
                                       measured.private_commit_mib)
            finally:
                errors = []
                # A stop file, never a signal. The child also ends by itself.
                stop.touch(exist_ok=True)
                if probe is not None:
                    probe.close()
                if process is not None:
                    try:
                        if process.wait(10) != 0:
                            errors.append(f"busy child exit code {process.returncode}")
                    except subprocess.TimeoutExpired:
                        errors.append("the busy child did not exit after its stop file")
                    finally:
                        process.stdout.close()
                if errors:
                    self.fail("; ".join(errors))


if __name__ == "__main__":
    unittest.main()
