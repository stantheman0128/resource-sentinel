"""Portable machine-sampler fixtures; default discovery performs no native read.

The separately named NativeMachineSnapshotSmoke methods can only be selected
explicitly after authorization. native_snapshot reads one endpoint;
native_window reads two endpoints with one one-second sleep and no retries.
Neither launches a process, opens a Job or changes machine/runtime state.
"""
from dataclasses import replace
import ctypes as C
import os
import time
import unittest
from unittest.mock import patch

from sentinel.adaptive import machine_sampler as sampler
from sentinel.adaptive.contracts import MachineFrame, Validity


SECOND = 10_000_000
START = 100 * SECOND
TIMES = (200 * SECOND, 400 * SECOND, 100 * SECOND)
PAGES = (16_777_216, 8_388_608, 12_582_912, 25_165_824, 4096)


def endpoint(index=0, *, tick=None, cost=10_000, processors=8, groups=1, cpu=None, memory=PAGES):
    tick = START + index * SECOND if tick is None else tick
    cpu = tuple(base + index * delta * SECOND for base, delta in zip(TIMES, (2, 3, 1))) if cpu is None else cpu
    return sampler._Snapshot(tick, tick + cost, processors, groups, cpu, memory)


class Backend:
    def __init__(self, *snapshots):
        self.snapshots = iter(snapshots)
        self.calls = 0

    def read(self):
        self.calls += 1
        result = next(self.snapshots)
        if isinstance(result, BaseException):
            raise result
        return result


class MachineSamplerTests(unittest.TestCase):
    def test_warmup_has_real_memory_and_unknown_cpu_then_complete_delta(self):
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1)))
        first, second = machine.sample(), machine.sample()
        self.assertIsInstance(first.machine, MachineFrame)
        self.assertIsNone(first.machine.cpu_busy_units)
        self.assertEqual(first.machine.physical_total_bytes, 64 * 1024**3)
        self.assertEqual(first.validity, Validity.UNKNOWN)
        self.assertTrue(first.reset_required)
        self.assertIsNone(first.window_start_tick_100ns)
        self.assertEqual(first.errors[0].stage, "machine_warmup")
        self.assertEqual(second.validity, Validity.VALID)
        self.assertEqual(second.machine.cpu_busy_units, 4.0)
        self.assertEqual(second.window_start_tick_100ns, first.capture_end_tick_100ns)
        self.assertEqual(second.window_end_tick_100ns, second.capture_end_tick_100ns)
        self.assertEqual(second.errors, ())
        self.assertFalse(second.reset_required)
        self.assertEqual(second.collection_cost_ms, 1.0)
        self.assertEqual((first.sample_seq, second.sample_seq), (1, 2))

    def test_kernel_includes_idle_and_cpu_units_scale_to_logical_processors(self):
        for delta, expected in (((4, 4, 0), 0.0), ((0, 3, 1), 8.0), ((2, 3, 1), 4.0)):
            with self.subTest(delta=delta):
                last = tuple(value + increase * SECOND for value, increase in zip(TIMES, delta))
                machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1, cpu=last)))
                machine.sample()
                self.assertEqual(machine.sample().machine.cpu_busy_units, expected)

    def test_cumulative_counters_keep_integer_precision_before_differencing(self):
        values = (1 << 60, 1 << 61, 1 << 60)
        last = tuple(value + increase for value, increase in zip(values, (2, 3, 1)))
        machine = sampler.MachineSampler(backend=Backend(endpoint(cpu=values), endpoint(1, cpu=last)))
        machine.sample()
        self.assertEqual(machine.sample().machine.cpu_busy_units, 4.0)

    def test_page_size_is_measured_and_commit_limit_may_change(self):
        pages = (100, 25, 80, 150, 8192)
        later = (100, 0, 100, 200, 8192)
        machine = sampler.MachineSampler(backend=Backend(endpoint(memory=pages), endpoint(1, memory=later)))
        first, second = machine.sample(), machine.sample()
        self.assertEqual(first.machine.physical_total_bytes, 819200)
        self.assertEqual(first.machine.physical_available_bytes, 204800)
        self.assertEqual(first.machine.commit_used_bytes, 655360)
        self.assertEqual(first.machine.commit_limit_bytes, 1228800)
        self.assertEqual(second.machine.physical_available_bytes, 0)  # Actual valid zero, never a missing-value fallback.
        self.assertEqual(second.machine.commit_limit_bytes, 1638400)
        self.assertEqual(second.validity, Validity.VALID)

    def test_memory_failure_has_nulls_and_breaks_cpu_baseline(self):
        failed = replace(endpoint(1), memory_pages=None,
                         errors=(sampler._error("telemetry_stale", "machine_memory", api_error_code=5),))
        machine = sampler.MachineSampler(backend=Backend(endpoint(), failed, endpoint(2), endpoint(3)))
        machine.sample()
        unknown, warmup, valid = machine.sample(), machine.sample(), machine.sample()
        self.assertIsNone(unknown.machine.cpu_busy_units)
        self.assertIsNone(unknown.machine.physical_available_bytes)
        self.assertIsNone(unknown.machine.commit_limit_bytes)
        self.assertTrue(unknown.reset_required)
        self.assertIn(5, [error.api_error_code for error in unknown.errors])
        self.assertIsNone(warmup.machine.cpu_busy_units)
        self.assertEqual(valid.validity, Validity.VALID)

    def test_inconsistent_memory_is_not_clamped_into_free_capacity(self):
        for pages in ((100, 101, 80, 150, 4096), (100, 25, 151, 150, 4096),
                      (100, 25, 80, 150, 0), (100, 25, 80, 150, 3),
                      (0, 0, 0, 1, 4096), (100, 25, 80, 0, 4096),
                      (1 << 63, 0, 1, 2, 4096), (100, True, 80, 150, 4096)):
            with self.subTest(pages=pages):
                result = sampler.MachineSampler(backend=Backend(endpoint(memory=pages))).sample()
                self.assertNotEqual(result.validity, Validity.VALID)
                self.assertIsNone(result.machine.physical_total_bytes)
                self.assertIsNone(result.machine.commit_used_bytes)
                self.assertIn("measurement_inconsistent", [error.code for error in result.errors])

    def test_unknown_or_unsupported_topology_does_not_invent_a_machine_frame(self):
        for processors, groups in ((None, None), (0, 1), (65, 1), (64, 2), (True, 1), (8, 0)):
            with self.subTest(processors=processors, groups=groups):
                result = sampler.MachineSampler(backend=Backend(endpoint(processors=processors, groups=groups))).sample()
                self.assertIsNone(result.machine)
                self.assertIn("denominator_unknown", [error.code for error in result.errors])
                self.assertFalse(result.is_fresh(result.capture_end_tick_100ns, clock_epoch=result.clock_epoch))

    def test_topology_change_invalidates_pair_and_seeds_new_counter_epoch(self):
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1, processors=6), endpoint(2, processors=6)))
        first, changed, next_sample = machine.sample(), machine.sample(), machine.sample()
        self.assertEqual(changed.validity, Validity.INVALID)
        self.assertEqual(changed.errors[0].stage, "machine_topology_changed")
        self.assertNotEqual(changed.counter_epoch, first.counter_epoch)
        self.assertEqual(changed.clock_epoch, first.clock_epoch)
        self.assertIsNone(changed.machine.cpu_busy_units)
        self.assertEqual(next_sample.machine.cpu_busy_units, 3.0)
        self.assertEqual(next_sample.counter_epoch, changed.counter_epoch)

    def test_window_boundaries_are_inclusive_for_zero_skew_endpoints(self):
        for window in (SECOND // 2, 3 * SECOND // 2):
            with self.subTest(window=window):
                machine = sampler.MachineSampler(backend=Backend(endpoint(cost=0), endpoint(1, tick=START + window, cost=0)))
                machine.sample()
                self.assertEqual(machine.sample().validity, Validity.VALID)

    def test_short_long_and_duplicate_windows_reset_without_reusing_prior_delta(self):
        for window in (0, SECOND // 2 - 1, 3 * SECOND // 2 + 1, 2 * SECOND):
            with self.subTest(window=window):
                current = START + window
                machine = sampler.MachineSampler(backend=Backend(endpoint(cost=0), endpoint(1, tick=current, cost=0),
                                                                 endpoint(2, tick=current + SECOND, cost=0)))
                first, invalid, valid = machine.sample(), machine.sample(), machine.sample()
                self.assertEqual(invalid.validity, Validity.INVALID)
                self.assertEqual(invalid.errors[0].code, "sample_window_invalid")
                self.assertIsNone(invalid.machine.cpu_busy_units)
                self.assertTrue(invalid.reset_required)
                self.assertNotEqual(invalid.counter_epoch, first.counter_epoch)
                self.assertEqual(valid.window_start_tick_100ns, invalid.window_end_tick_100ns)
                self.assertEqual(valid.validity, Validity.VALID)

    def test_complete_capture_brackets_must_fit_the_window_not_only_end_timestamps(self):
        first = endpoint(cost=100_000)
        # End-to-end interval is exactly 0.5 s, but actual CPU read separation
        # could be 0.49 s because the second capture starts earlier than its end.
        second = endpoint(1, tick=START + SECOND // 2, cost=100_000)
        machine = sampler.MachineSampler(backend=Backend(first, second))
        machine.sample()
        result = machine.sample()
        self.assertEqual(result.validity, Validity.INVALID)
        self.assertEqual(result.errors[0].code, "sample_window_invalid")

    def test_long_gap_and_clock_backward_rotate_continuity_and_require_fresh_endpoints(self):
        for tick in (START - SECOND, START + 4 * SECOND):
            with self.subTest(tick=tick):
                machine = sampler.MachineSampler(backend=Backend(endpoint(cost=0), endpoint(1, tick=tick, cost=0),
                                                                 endpoint(2, tick=tick + SECOND, cost=0),
                                                                 endpoint(3, tick=tick + 2 * SECOND, cost=0)))
                first, broken, warmup, valid = (machine.sample() for _ in range(4))
                self.assertNotEqual(broken.clock_epoch, first.clock_epoch)
                self.assertIsNone(broken.window_start_tick_100ns)
                self.assertIn("clock_discontinuity", [error.code for error in broken.errors])
                self.assertIsNone(warmup.machine.cpu_busy_units)
                self.assertEqual(valid.validity, Validity.VALID)

    def test_explicit_resume_invalidation_discards_even_a_short_apparent_pair(self):
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1), endpoint(2)))
        first = machine.sample()
        machine.invalidate_clock()
        next_sample = machine.sample()
        self.assertNotEqual(next_sample.clock_epoch, first.clock_epoch)
        self.assertEqual(next_sample.sampler_epoch, first.sampler_epoch)
        self.assertIsNone(next_sample.machine.cpu_busy_units)
        self.assertEqual(machine.sample().validity, Validity.VALID)

    def test_each_backwards_counter_and_zero_total_delta_is_invalid(self):
        values = [tuple(value - 1 if i == position else value + 10 for i, value in enumerate(TIMES))
                  for position in range(3)] + [TIMES]
        for counters in values:
            with self.subTest(counters=counters):
                machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1, cpu=counters)))
                first, broken = machine.sample(), machine.sample()
                self.assertIsNone(broken.machine.cpu_busy_units)
                self.assertEqual(broken.errors[0].code, "counter_reset")
                self.assertNotEqual(broken.counter_epoch, first.counter_epoch)

    def test_idle_delta_cannot_exceed_kernel_delta_even_if_user_would_hide_it(self):
        later = tuple(value + delta for value, delta in zip(TIMES, (100, 50, 100)))
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1, cpu=later)))
        machine.sample()
        result = machine.sample()
        self.assertIsNone(result.machine.cpu_busy_units)
        self.assertEqual(result.errors[0].code, "measurement_inconsistent")

    def test_missing_or_malformed_counters_do_not_become_idle_machine(self):
        for counters in (None, (1, 0, 1), (-1, 0, 1), (True, 1, 1), (1, float("nan"), 1)):
            with self.subTest(counters=counters):
                raw = replace(endpoint(), cpu_times=counters)
                result = sampler.MachineSampler(backend=Backend(raw)).sample()
                self.assertIsNone(result.machine.cpu_busy_units)
                self.assertNotEqual(result.validity, Validity.VALID)
                self.assertTrue(result.errors)

    def test_capture_over_budget_or_bad_clock_does_not_create_valid_window(self):
        for raw in (endpoint(cost=sampler._CAPTURE_BUDGET + 1),
                    replace(endpoint(), capture_start_tick_100ns=-1),
                    replace(endpoint(), capture_end_tick_100ns=START - 1)):
            with self.subTest(raw=raw):
                result = sampler.MachineSampler(backend=Backend(raw)).sample()
                self.assertNotEqual(result.validity, Validity.VALID)
                self.assertTrue(result.reset_required)
                self.assertTrue(result.errors)
                self.assertTrue(result.machine is None or result.machine.cpu_busy_units is None)

    def test_backend_unavailable_does_not_reuse_last_memory_or_cpu(self):
        failure = sampler.MachineSamplingError(sampler._error("telemetry_stale", "machine_native_api"))
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1), failure, endpoint(3)))
        machine.sample()
        self.assertEqual(machine.sample().validity, Validity.VALID)
        unknown = machine.sample()
        self.assertIsNone(unknown.machine)
        self.assertIsNone(unknown.window_end_tick_100ns)
        self.assertIsNone(unknown.collection_cost_ms)
        self.assertIsNone(machine.sample().machine.cpu_busy_units)

    def test_freshness_uses_measurement_end_and_matching_clock_epoch(self):
        machine = sampler.MachineSampler(backend=Backend(endpoint(), endpoint(1)))
        machine.sample()
        result = machine.sample()
        end = result.window_end_tick_100ns
        oldest = result.capture_start_tick_100ns
        for now, epoch, fresh in ((end, result.clock_epoch, True), (oldest + 3 * SECOND, result.clock_epoch, True),
                                  (oldest + 3 * SECOND + 1, result.clock_epoch, False),
                                  (end + 3 * SECOND, result.clock_epoch, False),
                                  (end - 1, result.clock_epoch, False), (end, "another-clock", False),
                                  (True, result.clock_epoch, False)):
            with self.subTest(now=now, epoch=epoch):
                self.assertEqual(result.is_fresh(now, clock_epoch=epoch), fresh)

    def test_unexpected_backend_error_remains_visible_and_cannot_bridge_a_later_pair(self):
        original = RuntimeError("fixture_backend_interrupted")
        machine = sampler.MachineSampler(backend=Backend(endpoint(), original, endpoint(1)))
        first = machine.sample()
        with self.assertRaises(RuntimeError) as failed:
            machine.sample()
        self.assertIs(failed.exception, original)
        next_sample = machine.sample()
        self.assertIsNone(next_sample.machine.cpu_busy_units)
        self.assertNotEqual(next_sample.clock_epoch, first.clock_epoch)
        self.assertEqual(next_sample.sample_seq, 3)

    def test_constructor_is_lazy_and_new_instances_do_not_reuse_runtime_epochs(self):
        with patch.object(sampler, "_WindowsBackend", side_effect=AssertionError("unexpected native initialization")):
            first, second = sampler.MachineSampler(), sampler.MachineSampler()
        self.assertNotEqual(first.sampler_epoch, second.sampler_epoch)
        self.assertNotEqual(first.clock_epoch, second.clock_epoch)
        self.assertNotEqual(first.counter_epoch, second.counter_epoch)

    def test_concurrent_call_is_bounded_busy_without_consuming_snapshot_or_sequence(self):
        backend = Backend(endpoint())
        machine = sampler.MachineSampler(backend=backend)
        machine._lock.acquire()
        try:
            for operation in (machine.sample, machine.invalidate_clock):
                with self.assertRaises(sampler.MachineSamplingError) as failed:
                    operation()
                self.assertEqual(failed.exception.error.code, "busy")
        finally:
            machine._lock.release()
        self.assertEqual(backend.calls, 0)
        self.assertEqual(machine.sample().sample_seq, 1)


class MachineSamplerAbiTests(unittest.TestCase):
    def test_x64_performance_structure_layout_and_page_counts(self):
        self.assertEqual(C.sizeof(sampler._PerformanceInformation), 104)
        for field, offset in (("cb", 0), ("CommitTotal", 8), ("PageSize", 80),
                              ("HandleCount", 88), ("ProcessCount", 92), ("ThreadCount", 96)):
            self.assertEqual(getattr(sampler._PerformanceInformation, field).offset, offset)

        class Api:
            def GetPerformanceInfo(self, pointer, size):
                value = C.cast(pointer, C.POINTER(sampler._PerformanceInformation)).contents
                self.arguments = value.cb, size
                for field, count in zip(("PhysicalTotal", "PhysicalAvailable", "CommitTotal", "CommitLimit", "PageSize"), PAGES):
                    setattr(value, field, count)
                return 1

        backend = sampler._WindowsBackend.__new__(sampler._WindowsBackend)
        backend.psapi = Api()
        self.assertEqual(backend.memory_pages(), PAGES)
        self.assertEqual(backend.psapi.arguments, (104, 104))

    def test_system_times_preserves_filetime_high_and_low_without_float_conversion(self):
        values = ((1 << 60) + 3, (1 << 61) + 5, (1 << 60) + 7)

        class Api:
            def GetSystemTimes(self, *pointers):
                for pointer, value in zip(pointers, values):
                    target = C.cast(pointer, C.POINTER(sampler._FileTime)).contents
                    target.low, target.high = value & 0xFFFFFFFF, value >> 32
                return 1

        backend = sampler._WindowsBackend.__new__(sampler._WindowsBackend)
        backend.kernel = Api()
        self.assertEqual(backend.cpu_times(), values)

    def test_precise_clock_is_void_and_topology_uses_all_groups(self):
        class Api:
            def QueryInterruptTimePrecise(self, pointer):
                C.cast(pointer, C.POINTER(C.c_uint64)).contents.value = START
                return None

            def GetActiveProcessorGroupCount(self):
                return 1

            def GetActiveProcessorCount(self, group):
                self.group = group
                return 8

        backend = sampler._WindowsBackend.__new__(sampler._WindowsBackend)
        backend.kernel = Api()
        backend.realtime = backend.kernel
        self.assertEqual(backend.tick(), START)
        self.assertEqual(backend.topology(), (8, 1))
        self.assertEqual(backend.kernel.group, 0xFFFF)

    def test_native_binding_uses_realtime_api_set_without_kernel32_forwarder(self):
        class Function:
            def __call__(self, pointer):
                C.cast(pointer, C.POINTER(C.c_uint64)).contents.value = START

        class Library:
            def __init__(self, names):
                for name in names:
                    setattr(self, name, Function())

        libraries = {
            "kernel32": Library(("GetSystemTimes", "GetActiveProcessorGroupCount", "GetActiveProcessorCount")),
            "psapi": Library(("GetPerformanceInfo",)),
            "api-ms-win-core-realtime-l1-1-1.dll": Library(("QueryInterruptTimePrecise",)),
        }
        with patch.object(sampler.os, "name", "nt"), patch.object(C, "WinDLL", create=True,
                side_effect=lambda name, **kwargs: libraries[name]):
            backend = sampler._WindowsBackend()
        self.assertEqual(backend.tick(), START)
        self.assertIsNone(backend.realtime.QueryInterruptTimePrecise.restype)

    def test_group_count_failure_does_not_attach_undocumented_last_error(self):
        class Api:
            def GetActiveProcessorGroupCount(self):
                return 0

        backend = sampler._WindowsBackend.__new__(sampler._WindowsBackend)
        backend.kernel = Api()
        with self.assertRaises(sampler.MachineSamplingError) as failed:
            backend.topology()
        self.assertIsNone(failed.exception.error.api_error_code)

    def test_endpoint_read_detects_topology_change_with_fixed_bounded_queries(self):
        backend = sampler._WindowsBackend.__new__(sampler._WindowsBackend)
        ticks, topologies = iter((START, START + 10_000)), iter(((8, 1), (6, 1)))
        calls = []
        backend.tick = lambda: next(ticks)
        backend.topology = lambda: (calls.append("topology"), next(topologies))[1]
        backend.cpu_times = lambda: (calls.append("cpu"), TIMES)[1]
        backend.memory_pages = lambda: (calls.append("memory"), PAGES)[1]
        result = backend.read()
        self.assertEqual(calls, ["topology", "cpu", "memory", "topology"])
        self.assertIsNone(result.logical_processors)
        self.assertIsNone(result.processor_groups)
        self.assertEqual(result.errors[0].stage, "machine_topology_changed")


class NativeMachineSnapshotSmoke(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8, "Windows x64 read-only smoke only")
    def native_snapshot(self):
        """Explicit-only: python -m unittest tests.test_adaptive_machine_sampler.NativeMachineSnapshotSmoke.native_snapshot -v"""
        result = sampler.MachineSampler().sample()
        self.assertIsInstance(result.machine, MachineFrame, result.errors)
        self.assertEqual(result.machine.processor_groups, 1)
        self.assertLessEqual(result.machine.logical_processors, 64)
        self.assertIsNotNone(result.machine.physical_total_bytes)
        self.assertIsNotNone(result.machine.physical_available_bytes)
        self.assertIsNotNone(result.machine.commit_used_bytes)
        self.assertIsNotNone(result.machine.commit_limit_bytes)
        self.assertIsNone(result.machine.cpu_busy_units)  # One endpoint cannot measure CPU utilization.
        self.assertEqual([error.stage for error in result.errors], ["machine_warmup"])
        self.assertEqual(result.validity, Validity.UNKNOWN)

    @unittest.skipUnless(os.name == "nt" and C.sizeof(C.c_void_p) == 8, "Windows x64 read-only smoke only")
    def native_window(self):
        """Explicit-only: python -m unittest tests.test_adaptive_machine_sampler.NativeMachineSnapshotSmoke.native_window -v"""
        machine = sampler.MachineSampler()
        first = machine.sample()
        self.assertIsInstance(first.machine, MachineFrame, first.errors)
        self.assertEqual(first.validity, Validity.UNKNOWN)
        self.assertEqual([error.stage for error in first.errors], ["machine_warmup"])
        self.assertIsNone(first.machine.cpu_busy_units)

        time.sleep(1.0)  # One bounded request; an overslept/invalid window fails without retry.
        second = machine.sample()
        from tests.windows.adaptive_win32 import interrupt_time_100ns
        now = interrupt_time_100ns()  # Actual recovery consumer's clock in the same native domain.
        self.assertEqual(second.validity, Validity.VALID, second.errors)
        self.assertEqual(second.errors, ())
        self.assertFalse(second.reset_required)
        self.assertTrue(second.is_fresh(now, clock_epoch=machine.clock_epoch))
        self.assertEqual((first.sample_seq, second.sample_seq), (1, 2))
        for field in ("sampler_epoch", "clock_epoch", "counter_epoch"):
            self.assertEqual(getattr(first, field), getattr(second, field), field)
        self.assertEqual(second.window_start_tick_100ns, first.capture_end_tick_100ns)
        self.assertEqual(second.window_end_tick_100ns, second.capture_end_tick_100ns)
        self.assertGreaterEqual(second.capture_start_tick_100ns - first.capture_end_tick_100ns, SECOND // 2)
        self.assertLessEqual(second.capture_end_tick_100ns - first.capture_start_tick_100ns, 3 * SECOND // 2)

        self.assertIsInstance(second.machine, MachineFrame)
        observed = second.machine
        self.assertEqual(observed.processor_groups, 1)
        self.assertGreaterEqual(observed.logical_processors, 1)
        self.assertLessEqual(observed.logical_processors, 64)
        self.assertGreaterEqual(observed.cpu_busy_units, 0.0)
        self.assertLessEqual(observed.cpu_busy_units, observed.logical_processors)
        for field in ("physical_total_bytes", "physical_available_bytes", "commit_used_bytes", "commit_limit_bytes"):
            self.assertIsInstance(getattr(observed, field), int, field)
        self.assertGreater(observed.physical_total_bytes, 0)
        self.assertGreater(observed.commit_limit_bytes, 0)
        self.assertGreaterEqual(observed.physical_available_bytes, 0)
        self.assertLessEqual(observed.physical_available_bytes, observed.physical_total_bytes)
        self.assertGreaterEqual(observed.commit_used_bytes, 0)
        self.assertLessEqual(observed.commit_used_bytes, observed.commit_limit_bytes)


if __name__ == "__main__":
    unittest.main()
