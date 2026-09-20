"""Shadow helper and sampler tests over a synthetic backend only.

Every Job reading, machine endpoint and clock tick below is fabricated in
memory. Nothing here touches a Job object, a Windows API or a real CPU, so none
of it is evidence for the plan's millisecond tick cost, CPU unit overhead or
reaction time thresholds. The cost assertions check that a metric exists and is
finite; a synthetic clock cannot measure the plan's 50 ms or 100 ms p95 gates.

The zero Set property is asserted structurally: the helper's import closure is
compared against a deny list of everything in this package that can mutate a
Job, publish a recovery intent or reach a guardian.
"""

import ast
import inspect
import json
import pathlib
import unittest
from dataclasses import replace

from sentinel.adaptive import helper as helper_module
from sentinel.adaptive.contracts import (
    ContractViolation, Coverage, MachineFrame, Priority, Role, TICKS_PER_SECOND, Validity,
)
from sentinel.adaptive.decision import DecisionAction, Mode, validate_policy_profile
from sentinel.adaptive.helper import Enrollment, ShadowHelper, would_apply_decisions
from sentinel.adaptive.sampler import (
    FrameSampler, JobReading, JobSampler, JobSamplingError, MachineObservation, profile_revision,
)
from sentinel.adaptive.contracts import FrameError, RetryClass

GIB = 1 << 30
BASE_TICK = 1_000_000_000_000
TICKS_PER_MS = TICKS_PER_SECOND // 1000
STEP = 2 * TICKS_PER_MS          # synthetic cost charged to every clock read
HIGH_BUSY = 11.5                 # 95.8% of twelve logical processors
LOW_BUSY = 8.0                   # 66.7%, below the eighty percent recovery mark
ROOT = pathlib.Path(__file__).resolve().parent.parent
EXAMPLE_PATH = ROOT / "config" / "adaptive.example.json"
PACKAGE = ROOT / "sentinel" / "adaptive"


def execution(index: int) -> str:
    return f"40000000-0000-4000-8000-0000000000{index:02x}"


def profile(**changes):
    base = validate_policy_profile(json.loads(EXAMPLE_PATH.read_text(encoding="utf-8")))
    return replace(base, **changes) if changes else base


class ClockStub:
    """Synthetic interrupt-time clock; each read charges a fixed cost."""

    def __init__(self, value: int, step: int = STEP):
        self.value, self.step, self.reads = value, step, 0

    def __call__(self) -> int:
        current = self.value
        self.value += self.step
        self.reads += 1
        return current

    def set(self, value: int) -> None:
        self.value = value


class SyntheticJobBackend:
    """Synthetic per-Job accounting. No handle, no native call, no real Job."""

    def __init__(self, units: dict[str, float], *, memory: bool = True):
        self.units = dict(units)
        self.cpu_100ns = {key: 0 for key in units}
        self.counter_epoch = {key: "counter-1" for key in units}
        self.memory = memory
        self.membership_complete = True
        self.failing: set[str] = set()
        self.reads = 0

    def advance(self, seconds: float) -> None:
        for key, units in self.units.items():
            self.cpu_100ns[key] += int(units * seconds * TICKS_PER_SECOND)

    def reset_counter(self, execution_id: str) -> None:
        self.counter_epoch[execution_id] = "counter-2"
        self.cpu_100ns[execution_id] = 0

    def read(self, execution_id: str) -> JobReading:
        self.reads += 1
        if execution_id in self.failing:
            raise JobSamplingError(FrameError("membership_unknown", "fixture",
                                              RetryClass.TRANSIENT))
        return JobReading(
            cpu_100ns=self.cpu_100ns[execution_id],
            active_processes=4 if self.membership_complete else None,
            membership_complete=self.membership_complete,
            counter_epoch=self.counter_epoch[execution_id],
            private_working_set_bytes=4 * GIB if self.memory else None,
            private_commit_bytes=5 * GIB if self.memory else None)


class SyntheticMachineSource:
    """Synthetic whole machine endpoint with a one second window per call."""

    def __init__(self, clock: ClockStub, busy: float = LOW_BUSY):
        self.clock, self.busy = clock, busy
        self.machine_available = True
        self._previous_end = None

    def __call__(self) -> MachineObservation:
        end = self.clock()
        start = end - TICKS_PER_SECOND if self._previous_end is None else self._previous_end
        self._previous_end = end
        if not self.machine_available:
            return MachineObservation(None, "clock-a", None, None, Validity.UNKNOWN,
                                      (FrameError("telemetry_stale", "fixture",
                                                  RetryClass.TRANSIENT),), True)
        machine = MachineFrame(12, 1, self.busy, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB)
        return MachineObservation(machine, "clock-a", start, end, Validity.VALID)


class Harness:
    def __init__(self, *, jobs: int = 1, units: float = 6.0, busy: float = LOW_BUSY,
                 shadow: bool = True, memory: bool = True, prof=None):
        self.profile = prof or profile()
        self.clock = ClockStub(BASE_TICK)
        self.ids = tuple(execution(index) for index in range(jobs))
        self.backend = SyntheticJobBackend({key: units for key in self.ids}, memory=memory)
        self.machine = SyntheticMachineSource(self.clock, busy)
        self.sampler = FrameSampler(profile=self.profile, backend=self.backend,
                                    machine_source=self.machine, clock=self.clock)
        self.helper = ShadowHelper(profile=self.profile, sampler=self.sampler, clock=self.clock,
                                   shadow=shadow)
        for index, execution_id in enumerate(self.ids):
            self.helper.enroll(Enrollment(execution_id, f"principal-{index}", Role.BACKGROUND,
                                          Priority.P2, Coverage.JOB_CONTAINED, False, True))

    def run(self, ticks: int, *, first: int = 0):
        results = []
        for step in range(first, first + ticks):
            self.clock.set(BASE_TICK + step * TICKS_PER_SECOND)
            self.backend.advance(1.0)
            results.append(self.helper.tick())
        return results


# --- structural zero Set ------------------------------------------------------

DENIED_MODULES = frozenset({
    "ctypes", "subprocess", "threading", "socket", "sqlite3", "multiprocessing", "os",
    "sentinel.adaptive.native_job", "sentinel.adaptive.native_launcher",
    "sentinel.adaptive.legacy_native", "sentinel.adaptive.legacy_writer",
    "sentinel.adaptive.guardian", "sentinel.adaptive.guardian_lifecycle",
    "sentinel.adaptive.guardian_restore", "sentinel.adaptive.recovery_journal",
    "sentinel.adaptive.recovery_owner", "sentinel.adaptive.launcher",
    "sentinel.adaptive.supervisor", "sentinel.adaptive.writers", "sentinel.adaptive.store",
    "sentinel.adaptive.ipc", "sentinel.adaptive.windows", "sentinel.adaptive.machine_sampler",
    "sentinel.adaptive.admission", "sentinel.adaptive.control_slot", "sentinel.adaptive.policy",
})
DENIED_NAMES = frozenset({
    "set_cpu_rate", "set_cpu_rate_unverified", "disable", "SetInformationJobObject",
    "NativeJob", "publish", "apply", "retry_job_cleanup",
})


def imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            prefix = "sentinel.adaptive." if node.level else ""
            found.add(prefix + (node.module or ""))
    return found


class ZeroSetStructureTests(unittest.TestCase):
    def test_helper_imports_exactly_the_pure_layers(self):
        self.assertEqual(imported_modules(PACKAGE / "helper.py"),
                         {"__future__", "collections", "dataclasses",
                          "sentinel.adaptive.contracts", "sentinel.adaptive.decision",
                          "sentinel.adaptive.sampler"})

    def test_import_closure_reaches_nothing_that_can_set_a_cap(self):
        closure = set()
        for name in ("helper.py", "sampler.py", "decision.py", "contracts.py"):
            closure |= imported_modules(PACKAGE / name)
        self.assertEqual(closure & DENIED_MODULES, set())

    def test_module_namespace_exposes_no_actuator(self):
        for name, value in vars(helper_module).items():
            self.assertNotIn(name, DENIED_NAMES)
            module = getattr(value, "__name__", None) if inspect.ismodule(value) else None
            if module is not None:
                self.assertNotIn(module, DENIED_MODULES)

    def test_constructor_admits_no_set_capability(self):
        parameters = inspect.signature(ShadowHelper.__init__).parameters
        self.assertEqual(set(parameters), {"self", "profile", "sampler", "clock", "shadow"})

    def test_shadow_records_would_apply_and_never_marks_a_cap_executable(self):
        harness = Harness(busy=HIGH_BUSY)
        results = harness.run(12)
        proposals = [r.decision for r in results
                     if r.decision is not None and r.decision.target is not None]
        self.assertTrue(proposals, "synthetic pressure produced no cap decision")
        for decision in proposals:
            self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
            self.assertFalse(decision.executable)
            self.assertTrue(decision.would_apply)
        self.assertTrue(would_apply_decisions(harness.helper))
        self.assertIs(harness.helper.mode, Mode.SHADOW)

    def test_enforce_profile_is_refused(self):
        harness = Harness()
        with self.assertRaises(ContractViolation):
            ShadowHelper(profile=profile(mode=Mode.ENFORCE), sampler=harness.sampler,
                         clock=harness.clock, shadow=True)

    def test_off_without_the_seam_takes_no_policy_action(self):
        harness = Harness(busy=HIGH_BUSY, shadow=False)
        self.assertIs(harness.helper.mode, Mode.OFF)
        for result in harness.run(8):
            if result.decision is not None:
                self.assertIs(result.decision.action, DecisionAction.NO_POLICY_ACTION)
                self.assertIsNone(result.decision.target)


# --- bounded loop -------------------------------------------------------------


class BoundedLoopTests(unittest.TestCase):
    def test_decision_ring_is_bounded(self):
        harness = Harness(prof=profile(sample_ring_frames=8))
        harness.run(30)
        self.assertEqual(len(harness.helper.decisions), 8)
        self.assertGreater(harness.helper.metrics.decisions, 8)

    def test_only_the_latest_frame_is_kept(self):
        harness = Harness()
        harness.run(4)
        latest = harness.helper.latest_frame
        self.assertIsNotNone(latest)
        self.assertEqual(latest.sample_seq, harness.sampler.sample_seq)

    def test_a_late_tick_runs_once_and_missed_ticks_are_dropped(self):
        harness = Harness()
        harness.run(3)
        before = harness.backend.reads
        # The last tick started at second two, so this one is six seconds late.
        harness.clock.set(BASE_TICK + 8 * TICKS_PER_SECOND)
        harness.backend.advance(6.0)
        result = harness.helper.tick()
        self.assertEqual(result.missed_ticks, 5)
        self.assertEqual(harness.backend.reads - before, 1)
        self.assertEqual(harness.helper.metrics.late_ticks, 1)
        self.assertEqual(harness.helper.metrics.missed_ticks, 5)
        self.assertEqual(harness.helper.metrics.ticks, 4)

    def test_a_late_tick_never_tightens_on_its_stretched_window(self):
        # Plan section 6.4: a stale or unknown sample must not tighten.
        harness = Harness(busy=HIGH_BUSY)
        harness.run(10)
        harness.clock.set(BASE_TICK + 30 * TICKS_PER_SECOND)
        harness.backend.advance(20.0)
        result = harness.helper.tick()
        self.assertIsNotNone(result.decision)
        self.assertNotIn(result.decision.action,
                         (DecisionAction.PROPOSE_L1, DecisionAction.PROPOSE_L2))

    def test_tick_cost_is_recorded_for_one_and_ten_jobs(self):
        # The plan's 10 Job p95 thresholds need real measurement; these numbers
        # come from a synthetic clock, so only existence and finiteness hold.
        for jobs in (1, 10):
            with self.subTest(jobs=jobs):
                harness = Harness(jobs=jobs)
                results = harness.run(6)
                metrics = harness.helper.metrics
                self.assertEqual(metrics.ticks, 6)
                for result in results:
                    self.assertGreater(result.duration_ms, 0.0)
                    self.assertTrue(result.duration_ms == result.duration_ms)  # finite
                    self.assertLess(result.duration_ms, 1_000.0)
                    self.assertGreaterEqual(result.sample_cost_ms, 0.0)
                self.assertIsNotNone(metrics.last_tick_ms)
                self.assertGreaterEqual(metrics.max_tick_ms, metrics.last_tick_ms)
                self.assertGreater(metrics.total_tick_ms, 0.0)

    def test_a_frame_gap_is_counted_and_decides_nothing(self):
        harness = Harness()
        harness.run(3)
        harness.machine.machine_available = False
        harness.clock.set(BASE_TICK + 3 * TICKS_PER_SECOND)
        harness.backend.advance(1.0)
        result = harness.helper.tick()
        self.assertIsNone(result.decision)
        self.assertEqual(result.reason, "machine_window_unavailable")
        self.assertEqual(harness.helper.metrics.frame_gaps, 1)
        self.assertEqual(harness.helper.metrics.frames, 3)

    def test_decision_records_carry_no_handle_or_authorization(self):
        harness = Harness(busy=HIGH_BUSY)
        harness.run(10)
        record = harness.helper.decisions[-1]
        self.assertEqual(
            set(vars(record)),
            {"tick_100ns", "sample_seq", "action", "reason", "state", "victim_execution_id",
             "target_cpu_rate_bp", "would_apply", "executable"})


# --- sampler ------------------------------------------------------------------


class SamplerTests(unittest.TestCase):
    def build(self, **changes):
        harness = Harness(**changes)
        return harness

    def test_first_reading_produces_no_cpu_value(self):
        harness = self.build()
        result = harness.run(1)[0]
        frame = harness.helper.latest_frame
        self.assertIsNone(frame.jobs[0].cpu_units)
        self.assertIn("sample_window_invalid", [error.code for error in frame.errors])
        self.assertIsNot(frame.validity, Validity.VALID)
        self.assertEqual(result.reason, "frame_invalid")

    def test_second_reading_yields_measured_cpu_units(self):
        harness = self.build(units=6.0)
        harness.run(3)
        frame = harness.helper.latest_frame
        self.assertAlmostEqual(frame.jobs[0].cpu_units, 6.0, places=3)
        self.assertIs(frame.validity, Validity.VALID)
        self.assertEqual(frame.errors, ())

    def test_counter_reset_invalidates_the_delta(self):
        harness = self.build()
        harness.run(3)
        harness.backend.reset_counter(harness.ids[0])
        harness.clock.set(BASE_TICK + 3 * TICKS_PER_SECOND)
        harness.helper.tick()
        frame = harness.helper.latest_frame
        self.assertIsNone(frame.jobs[0].cpu_units)
        self.assertIn("counter_reset", [error.code for error in frame.errors])

    def test_missing_memory_is_unknown_and_never_zero(self):
        harness = self.build(memory=False)
        harness.run(3)
        job = harness.helper.latest_frame.jobs[0]
        self.assertIs(job.memory_validity, Validity.UNKNOWN)
        self.assertIsNone(job.private_working_set_bytes)
        self.assertIsNone(job.private_commit_bytes)
        self.assertIn("memory_attribution_unavailable",
                      [error.code for error in harness.helper.latest_frame.errors])

    def test_incomplete_membership_is_reported(self):
        harness = self.build()
        harness.run(3)
        harness.backend.membership_complete = False
        harness.clock.set(BASE_TICK + 3 * TICKS_PER_SECOND)
        harness.backend.advance(1.0)
        harness.helper.tick()
        job = harness.helper.latest_frame.jobs[0]
        self.assertFalse(job.membership_complete)
        self.assertIsNone(job.active_processes)

    def test_a_failing_read_never_becomes_a_zero(self):
        harness = self.build()
        harness.run(3)
        harness.backend.failing.add(harness.ids[0])
        harness.clock.set(BASE_TICK + 3 * TICKS_PER_SECOND)
        harness.helper.tick()
        job = harness.helper.latest_frame.jobs[0]
        self.assertIsNone(job.cpu_units)
        self.assertFalse(job.membership_complete)

    def test_high_water_never_falls(self):
        harness = self.build(units=6.0)
        harness.run(3)
        harness.backend.units[harness.ids[0]] = 1.0
        harness.run(2, first=3)
        job = harness.helper.latest_frame.jobs[0]
        self.assertAlmostEqual(job.cpu_units, 1.0, places=3)
        self.assertAlmostEqual(job.cpu_uncapped_high_water_units, 6.0, places=3)

    def test_enrollment_is_bounded_and_identified(self):
        harness = self.build(jobs=10)
        with self.assertRaises(ContractViolation):
            harness.sampler.enroll(execution(10))
        with self.assertRaises(ContractViolation):
            harness.sampler.enroll("not-a-uuid")
        with self.assertRaises(ContractViolation):
            harness.sampler.enroll(harness.ids[0])

    def test_capture_budget_is_reported(self):
        prof = profile(sampler_work_budget_ms=1)
        harness = Harness(prof=prof)
        harness.run(3)
        self.assertIn("observer_budget_exceeded",
                      [error.code for error in harness.helper.latest_frame.errors])

    def test_invalidate_clock_drops_every_baseline(self):
        harness = self.build()
        harness.run(3)
        harness.sampler.invalidate_clock()
        harness.clock.set(BASE_TICK + 3 * TICKS_PER_SECOND)
        harness.backend.advance(1.0)
        harness.helper.tick()
        self.assertIsNone(harness.helper.latest_frame.jobs[0].cpu_units)

    def test_profile_revision_is_stable_and_specific(self):
        self.assertEqual(profile_revision(profile()), profile_revision(profile()))
        self.assertNotEqual(profile_revision(profile()), profile_revision(profile(lease_ms=5000)))

    def test_backend_and_clock_are_validated(self):
        with self.assertRaises(ContractViolation):
            JobSampler(backend=object(), profile=profile(), clock=lambda: 0)
        with self.assertRaises(ContractViolation):
            FrameSampler(profile=profile(), backend=SyntheticJobBackend({}),
                         machine_source=None, clock=lambda: 0)


if __name__ == "__main__":
    unittest.main()
