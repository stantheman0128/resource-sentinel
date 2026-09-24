"""Portable custody/timing tests; these fixtures never attest native P4."""
import io
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.contracts import Validity
from sentinel.adaptive.helper_control_host import OperationalHelperHost
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.telemetry import ResidentTelemetry
from tests.windows import adaptive_overhead_native as native


class OriginalBindingTests(unittest.TestCase):
    def test_different_time_builtins_do_not_alias_the_original_sleep(self):
        host = SimpleNamespace(sleep=time.sleep)
        binding = native._OriginalBinding(host, "sleep", lambda _: None)
        binding.install()
        host.sleep = time.monotonic
        with self.assertRaisesRegex(native.NativeOverheadError, "binding_changed"):
            binding.close()
        self.assertIs(host.sleep, time.monotonic)
        self.assertFalse(binding.closed)

    def test_original_bound_method_restored_without_identity_confusion(self):
        class Host:
            def poll(self):
                return "original"
        host = Host()
        binding = native._OriginalBinding(host, "poll", lambda: "tap")
        original = binding.original
        binding.install()
        self.assertEqual(host.poll(), "tap")
        binding.close()
        self.assertIs(host.poll, original)
        self.assertEqual(host.poll(), "original")

    def test_foreign_replacement_is_retained_and_never_overwritten(self):
        host = SimpleNamespace(sleep=lambda _: None)
        binding = native._OriginalBinding(host, "sleep", lambda _: None)
        binding.install()
        foreign = lambda _: None
        host.sleep = foreign
        with self.assertRaisesRegex(native.NativeOverheadError, "binding_changed"):
            binding.close()
        self.assertIs(host.sleep, foreign)
        self.assertFalse(binding.closed)

    def test_interrupted_assignment_can_restore_original(self):
        host = SimpleNamespace(sleep=lambda _: None)
        binding = native._OriginalBinding(host, "sleep", lambda _: None)
        host.sleep = binding.replacement  # cut after assignment
        binding.close()
        self.assertIs(host.sleep, binding.original)


class Clock:
    def __init__(self):
        self.now = 100_000_000
        self.waits = []

    def __call__(self):
        self.now += 100
        return self.now

    def wait(self, seconds):
        self.waits.append(seconds)
        self.now += round(seconds * 10_000_000)


class ActualLoopFixtureTests(unittest.TestCase):
    def build(self, stream, *, report_every=1):
        """Run the production run_once/_pace/_report, with portable sources."""
        clock = Clock()
        host = object.__new__(OperationalHelperHost)
        host._iterations = host._would_apply = host._dropped = host._skipped_boundaries = 0
        host._started = True
        host._drain_requested = False
        host._deadline_100ns = None
        host._clock, host._sleep = clock, clock.wait
        host.profile = SimpleNamespace(sample_interval_ms=1000)
        host.enroll_every_ticks = 5
        host.report_every_ticks = report_every
        host._last_enrollment_complete = True
        host.refresh_enrollment = Mock()
        host.metrics_record = lambda: {"event": "helper_host_metrics", "iteration": host._iterations}
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        host.telemetry = ResidentTelemetry(data_dir=Path(directory.name), role="helper",
            identity=ProcessIdentity(7001, 134343072000000001, "S-1-5-5-1-2"),
            instance_id="00000000-0000-4000-8000-000000000001")
        host._operator_poll = lambda: setattr(clock, "now", clock.now + 500_000)
        jobs = SimpleNamespace(memory_scanner=object(), memory_budget_source=None,
            unreadable=lambda: (), enrolled=(), last_memory_scan=(), memory_sample_started_tick=0)
        def configure(scanner, budget_source=None):
            jobs.memory_scanner, jobs.memory_budget_source = scanner, budget_source
        jobs.configure_memory = configure
        host.jobs = jobs
        observation = SimpleNamespace(machine=SimpleNamespace(logical_processors=8, processor_groups=1),
            validity=Validity.VALID, errors=())
        host.sampler = SimpleNamespace(_machine_source=lambda: observation)
        shadow = SimpleNamespace(metrics=SimpleNamespace(frames=0), latest_frame=None)
        def tick():
            self.assertIs(host.sampler._machine_source(), observation)
            jobs.memory_sample_started_tick = clock()
            shadow.metrics.frames += 1
            shadow.latest_frame = SimpleNamespace(jobs=(), errors=())
            clock.now += 20_000
            return SimpleNamespace(decision=None, reason="sampled")
        shadow.tick = tick
        host.shadow = shadow
        sampler = object.__new__(native.NativeHelperHostSampler)
        sampler.host = host
        sampler.jobs, sampler._shards, sampler._audits, sampler._bindings = (), [], [], []
        sampler._failure = None
        sampler._closed = False
        sampler._members, sampler._pending_tick = {}, None
        sampler._warmup_pending = True
        sampler._last_tick_warmup = False
        sampler._case_totals = dict.fromkeys(native._CASE_NAMES, 0)
        sampler._clock, sampler._topology = clock, (8, 1)
        sampler._lock = threading.RLock()
        sampler._telemetry_sink = host.telemetry
        sampler._verify_host = Mock()  # Native construction is tested separately.
        sampler._install_taps()
        return sampler, host, clock, observation

    def test_real_operational_loop_includes_poll_and_report_but_defers_sleep(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, clock, observation = self.build(stream)
            original_sleep = sampler._original_sleep
            begin, end, cases = sampler.tick()
            self.assertGreaterEqual(end - begin, 520_000)  # actual poll+sampling work
            self.assertEqual(clock.waits, [])
            self.assertIs(sampler._observation, observation)
            self.assertEqual(sampler._machine_calls, 1)
            self.assertEqual(host._iterations, 1)
            self.assertGreater(sampler._pending_tick[4], 0)
            covered = Mock()
            pacing = sampler.pace(covered)
            self.assertEqual(covered.call_count, 2)
            self.assertEqual(len(clock.waits), 1)
            self.assertGreaterEqual(pacing[7], pacing[5])
            self.assertEqual(pacing[9], 0)
            sampler.close()
            self.assertIs(host._sleep, original_sleep)
            self.assertIsNone(host.jobs.memory_budget_source)

    def test_sixth_iteration_executes_actual_registry_refresh(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, clock, _ = self.build(stream, report_every=2)
            rows = []
            for _ in range(6):
                sampler.tick()
                rows.append(sampler.pace(lambda: None))
            self.assertEqual([row[1] for row in rows], [0, 0, 0, 0, 0, 1])
            self.assertEqual([row[2] for row in rows], [0, 1, 0, 1, 0, 1])
            host.refresh_enrollment.assert_called_once()
            self.assertTrue(all(row[3] == 1 for row in rows))
            sampler.close()

    def test_tick_without_prior_actual_wait_is_refused(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, _, _, _ = self.build(stream)
            sampler.tick()
            with self.assertRaisesRegex(native.NativeOverheadError, "measurement_unresolved"):
                sampler.tick()
            sampler.close()

    def test_overrun_is_recorded_without_extra_sleep_or_catchup(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, _, clock, _ = self.build(stream)
            sampler.tick()
            clock.now = sampler._pending_tick[5] + 90_000
            row = sampler.pace(lambda: None)
            self.assertEqual(clock.waits, [])
            self.assertGreaterEqual(row[9], 90_000)
            sampler.close()

    def test_early_returning_sleep_is_unknown_and_retains_original(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, _, _, _ = self.build(stream)
            sampler.tick()
            sampler._original_sleep = lambda _: None
            with self.assertRaisesRegex(native.NativeOverheadError, "wait_incomplete"):
                sampler.pace(lambda: None)
            self.assertIsNotNone(sampler._failure)
            self.assertIsNotNone(sampler._pending_tick)
            sampler.close()

    def test_report_failure_is_sticky_but_original_bindings_can_be_restored(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, _, _ = self.build(stream)
            original_sleep = sampler._original_sleep
            host.metrics_record = Mock(side_effect=OSError("report unavailable"))
            with self.assertRaisesRegex(OSError, "report unavailable"):
                sampler.tick()
            self.assertIsNotNone(sampler._failure)
            sampler.close()
            self.assertIs(host._sleep, original_sleep)

    def test_foreign_sleep_change_quarantines_without_overwrite(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, _, _ = self.build(stream)
            foreign = lambda _: None
            host._sleep = foreign
            with self.assertRaisesRegex(native.NativeOverheadError, "binding_changed") as caught:
                sampler.close()
            self.assertIs(host._sleep, foreign)
            self.assertIs(caught.exception._native_overhead_owner, sampler)
            self.assertFalse(sampler._closed)

    def test_shards_receive_same_budget_and_late_overlap_rejects_whole_tick(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, _, _ = self.build(stream)
            observed = []
            def extra_tick():
                observed.append(host.jobs.memory_budget_source())
                # Fault fixture writes the same actual budget's overlap set;
                # this does not create native evidence or valid attribution.
                sampler._budget.begin_job("earlier-shard")
                try:
                    sampler._budget.begin_job("earlier-shard")
                except Exception:
                    pass  # actual shared-budget overlap remains recorded
            extra = SimpleNamespace(metrics=SimpleNamespace(frames=0), tick=extra_tick)
            scanner = SimpleNamespace(retained_uncertain=0, close=Mock())
            sampler._shards = [(SimpleNamespace(), extra, scanner)]
            sampler._frame_cases = Mock()
            with self.assertRaisesRegex(native.NativeOverheadError, "membership_overlap"):
                sampler.tick()
            self.assertIs(observed[0], sampler._budget)
            sampler.close()
            scanner.close.assert_called_once()

    def test_extra_scanner_cleanup_failure_retains_owner_and_restores_host_sleep(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch.object(sys, "stderr", stream):
            sampler, host, _, _ = self.build(stream)
            original_sleep = sampler._original_sleep
            scanner = SimpleNamespace(close=Mock(side_effect=OSError("unknown member close")))
            sampler._shards = [(None, None, scanner)]
            with self.assertRaisesRegex(OSError, "unknown member close") as caught:
                sampler.close()
            self.assertIs(caught.exception._native_overhead_owner, sampler)
            self.assertIs(host._sleep, original_sleep)
            self.assertFalse(sampler._closed)


class ProvenanceRefusalTests(unittest.TestCase):
    def test_core_or_flag_cannot_substitute_for_operational_host(self):
        from tests.test_adaptive_decision import SHADOW
        with patch.object(native, "_platform"):
            with self.assertRaisesRegex(native.NativeOverheadError, "actual_operational_host_required"):
                native.NativeHelperHostSampler(SHADOW, (), host=SimpleNamespace(native=True),
                    telemetry_sink=io.StringIO(), log_directory=Path("."), scope_nonce="a" * 32)


class MemoryCaseEvidenceTests(unittest.TestCase):
    def frame(self, *, reason="inaccessible_identity", total=3, active=2,
              memory=Validity.UNKNOWN, private=None):
        source = SimpleNamespace(unreadable=lambda: (), enrolled=("execution",),
            memory_sample_started_tick=110, last_memory_scan=(SimpleNamespace(
                execution_id="execution", reason=reason, total_processes=total,
                active_processes=active),))
        helper = SimpleNamespace(metrics=SimpleNamespace(frames=2), latest_frame=SimpleNamespace(
            errors=(), jobs=(SimpleNamespace(execution_id="execution", cpu_units=.5,
                membership_complete=True, memory_validity=memory,
                private_working_set_bytes=private, private_commit_bytes=private),)))
        return source, helper

    def sampler(self):
        value = object.__new__(native.NativeHelperHostSampler)
        value._members = {}
        value._clock = lambda: 200
        return value

    def test_unknown_native_reason_counts_without_invented_positive_memory(self):
        sampler = self.sampler()
        counts = dict.fromkeys(native._CASE_NAMES, 0)
        sampler._frame_cases(*self.frame(), 1, False, 100, counts)
        self.assertEqual(counts["inaccessible_identity"], 1)
        self.assertEqual(counts["member_scan_timeout"], 0)
        self.assertEqual(counts["subtraction_zero_samples"], 1)
        self.assertEqual(counts["unsafe_subtractions"], 0)

    def test_actual_accounting_turnover_counts_short_lived_members(self):
        sampler = self.sampler()
        counts = dict.fromkeys(native._CASE_NAMES, 0)
        sampler._frame_cases(*self.frame(total=3, active=2), 1, False, 100, counts)
        sampler._frame_cases(*self.frame(total=6, active=2), 1, False, 100, counts)
        self.assertEqual(counts["membership_added"], 3)
        self.assertEqual(counts["membership_removed"], 3)

    def test_missing_accounting_is_not_invented_turnover(self):
        sampler = self.sampler()
        counts = dict.fromkeys(native._CASE_NAMES, 0)
        sampler._frame_cases(*self.frame(total=None, active=None), 1, False, 100, counts)
        self.assertEqual((counts["membership_added"], counts["membership_removed"]), (0, 0))
        self.assertEqual(sampler._members, {})

    def test_memory_returned_after_native_scan_failure_is_unsafe(self):
        sampler = self.sampler()
        counts = dict.fromkeys(native._CASE_NAMES, 0)
        sampler._frame_cases(*self.frame(memory=Validity.VALID, private=1024), 1, False, 100, counts)
        self.assertEqual(counts["unsafe_subtractions"], 1)

    def test_stale_scan_results_cannot_produce_case_evidence(self):
        sampler = self.sampler()
        source, helper = self.frame()
        source.memory_sample_started_tick = 99
        with self.assertRaisesRegex(native.NativeOverheadError, "scan_frame_unverified"):
            sampler._frame_cases(source, helper, 1, False, 100, dict.fromkeys(native._CASE_NAMES, 0))


if __name__ == "__main__":
    unittest.main()
