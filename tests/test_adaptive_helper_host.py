"""Shadow helper host: the adapters, enrollment, one iteration and the refusals.

Every Job handle, accounting reading, machine sample, clock tick and sleep below
is an explicit in-process fixture. None of them touches a Job object, a Windows
API or a real CPU, so nothing here is evidence for the plan's tick cost, CPU
overhead or reaction time. A sleep is recorded, never taken, so the pacing
assertions describe the loop's arithmetic and not elapsed time.

The ledger, the policy coordinator and the legacy writer registry are the
production modules against a real isolated SQLite file in a temporary directory.
The retained processes are real VerifiedProcess objects over a synthetic handle
backend, in the same way the guardian lifecycle fixture builds them.

The capability preflight is live. The startup case on this machine expects its
real refusal, and the subprocess smoke expects a refusal from a separate
interpreter. Where a test needs to get past the preflight it patches this
module's own read_host_capability with the synthetic record and says so at the
site.

Zero Set is asserted structurally: the host's imports are compared against the
modules that can mutate a Job or reach a guardian, and its source is compared
against the names that would perform or request a control.
"""
import ast
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import helper_host as module
from sentinel.adaptive import store as store_module
from sentinel.adaptive.contracts import (
    Coverage, FrameError, IdentityStatus, MachineFrame, Priority, ProcessIdentity, RetryClass,
    Role, TICKS_PER_SECOND, Validity,
)
from sentinel.adaptive.decision import Mode
from sentinel.adaptive.helper import ShadowHelper
from sentinel.adaptive.helper_host import (
    EXIT_FAILED, EXIT_OK, EXIT_REFUSED, HelperHost, HelperHostRefused, JobHandleSource,
    MachineObservationSource,
)
from sentinel.adaptive.host_authority import HostCapability, HostCapabilityUnsupported
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.machine_sampler import MachineSample, MachineSamplingError
from sentinel.adaptive.native_job import JobAccounting, JobLimits, NativeJobError
from sentinel.adaptive.sampler import FrameSampler, JobSamplingError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_helper import ClockStub, SyntheticMachineSource, imported_modules, profile
from tests.test_adaptive_host_authority import SYNTHETIC, live_capability_refusal


REPO_ROOT = Path(module.__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "sentinel" / "adaptive"
EXAMPLE_PATH = REPO_ROOT / "config" / "adaptive.example.json"
LOGON = "S-1-5-5-1-2"
HELPER = ProcessIdentity(7001, 134343072000000001, LOGON)
STRANGER = ProcessIdentity(7002, 134343072000000002, LOGON)
BASE_TICK = 1_000_000_000_000
TICKS_PER_MS = TICKS_PER_SECOND // 1000
GIB = 1 << 30
NOW = 2_000_000_000.0


def execution(index: int) -> str:
    return f"40000000-0000-4000-8000-0000000000{index:02x}"


def nonce(index: int) -> str:
    return f"{index:032x}"


def job_name(index: int) -> str:
    return f"Local\\ResourceSentinel.Job.{execution(index)}.{nonce(index)}"


def shadow_profile_file(directory: Path) -> Path:
    """A shadow profile in a temporary file; the shipped example is not touched."""
    payload = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    payload["mode"] = "shadow"
    path = directory / "adaptive.shadow.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class ProcessBackend:
    """A real VerifiedProcess retains these explicit synthetic handle entries."""

    def __init__(self):
        self.entries, self.next_handle = {}, 9000

    def process(self, identity):
        handle = self.next_handle
        self.next_handle += 1
        self.entries[handle] = SimpleNamespace(state=IdentityStatus.ALIVE, closed=False)
        return VerifiedProcess(self, handle, identity)

    def wait(self, handle):
        entry = self.entries[handle]
        if entry.closed:
            raise IdentityUnavailable("fixture_closed_handle")
        return entry.state

    def close(self, handle):
        self.entries[handle].closed = True


class SyntheticJob:
    """An in-process stand-in for one query handle on a Job object.

    It answers accounting and limit queries from fixture values and holds
    nothing. It exposes no Set, terminate or rate operation at all, so a host
    that tried to control a Job would fail here rather than pass.
    """

    def __init__(self, *, user=0, kernel=0, active=2, limit_flags=0):
        self.user, self.kernel, self.active = user, kernel, active
        self.limit_flags = limit_flags
        self.query_error = self.limits_error = self.close_error = None
        self.reads = self.close_calls = 0
        self.closed = False

    def accounting(self):
        if self.query_error is not None:
            raise self.query_error
        self.reads += 1
        return JobAccounting(self.user, self.kernel, self.active, self.active, 0)

    def query_limits(self):
        if self.limits_error is not None:
            raise self.limits_error
        return JobLimits(self.limit_flags, 0)

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True

    def __getattr__(self, name):
        raise AssertionError("helper host reached job." + name)


class SyntheticSampler:
    """Publishes one prepared MachineSample, or raises one prepared failure."""

    def __init__(self, sample=None, error=None):
        self.clock_epoch = "clock-fixture"
        self.sample_value, self.error = sample, error
        self.calls = 0

    def sample(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.sample_value


def machine_sample(**changes):
    machine = MachineFrame(12, 1, 8.0, 64 * GIB, 24 * GIB, 40 * GIB, 96 * GIB)
    values = {"machine": machine, "sampler_epoch": "sampler-fixture",
              "clock_epoch": "clock-fixture", "counter_epoch": "counter-fixture",
              "sample_seq": 4, "capture_start_tick_100ns": BASE_TICK,
              "capture_end_tick_100ns": BASE_TICK + TICKS_PER_MS,
              "window_start_tick_100ns": BASE_TICK - TICKS_PER_SECOND,
              "window_end_tick_100ns": BASE_TICK, "validity": Validity.VALID,
              "errors": (), "reset_required": False, "collection_cost_ms": 0.1}
    values.update(changes)
    return MachineSample(**values)


class LedgerCase(unittest.TestCase):
    """A real isolated ledger plus the fixture policy provider and processes."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        self.policy = FixturePolicyProvider(LOGON)
        self.store = LifecycleStore(self.db, policy_provider=self.policy)
        self.processes = ProcessBackend()
        self.process = self.processes.process(HELPER)

    def connection(self):
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def helper_rows(self):
        return self.connection().execute(
            "SELECT role,pid FROM adaptive_infrastructure ORDER BY role,pid").fetchall()

    def register(self, role, process):
        """Register through the production functions, under the real mutex hold."""
        from sentinel.adaptive.legacy_writer import (
            initialize_registry_locked, register_infrastructure_locked,
        )
        policy = self.store._policy
        guard = policy.prepare(policy.current_logon())
        with policy.hold(guard):
            initialize_registry_locked(self.store)
            register_infrastructure_locked(self.store, role, process)

    def seed(self, index, *, state="RUNNING", coverage="job_contained", logon=LOGON,
             name=None, role="background", priority="P2"):
        """One synthetic managed_executions row. No launch and no real Job."""
        columns = {
            "execution_id": execution(index), "task_id": f"fixture-task-{index}",
            "session_id": "fixture-session", "principal_id": f"fixture-principal-{index}",
            "logon_id": logon, "allocation_kind": "direct",
            "reservation_id": f"fixture-reservation-{index}", "spec_hash": "b" * 64,
            "wrapper_pid": 4000 + index, "wrapper_created_filetime_100ns": "134343072000000003",
            "job_name": job_name(index) if name is None else name, "job_nonce": nonce(index),
            "role": role, "priority": priority, "coverage": coverage, "state": state,
            "claim_token_hash": "a" * 64, "created_at": NOW, "heartbeat_at": NOW,
            "requested_cpu_units": 1.0, "requested_physical_bytes": GIB,
            "requested_commit_bytes": GIB, "requested_io_slots": 0,
            "floor_cpu_units": 1.0, "floor_physical_bytes": GIB,
            "floor_commit_bytes": GIB, "floor_io_slots": 0}
        self.connection().execute(
            "INSERT INTO managed_executions(" + ",".join(columns) + ") VALUES(" +
            ",".join("?" for _ in columns) + ")", tuple(columns.values()))
        return columns["execution_id"]


# --- startup refusals ---------------------------------------------------------


class StartupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.profile_path = shadow_profile_file(self.directory)

    def build(self, **changes):
        options = {"data_dir": self.directory, "profile_path": self.profile_path}
        options.update(changes)
        return HelperHost(**options)

    def test_start_refuses_on_this_host_before_it_opens_anything(self):
        reason = live_capability_refusal()
        host = self.build()
        if reason is None:
            # This machine supports the preflight, so it cannot be the refusal.
            self.assertIsInstance(module.read_host_capability(), HostCapability)
            return
        with self.assertRaises(HelperHostRefused) as caught:
            host.start()
        self.assertEqual(caught.exception.reason, reason)
        self.assertIsNone(host.store)
        self.assertIsNone(host.shadow)
        self.assertFalse(host.registered)
        self.assertFalse((self.directory / "sentinel.db").exists())

    def test_start_refuses_when_the_capability_is_unknown(self):
        unknown = HostCapabilityUnsupported("host_parent_job_membership_unknown", 6)
        with patch.object(module, "read_host_capability", side_effect=unknown):
            with self.assertRaises(HelperHostRefused) as caught:
                self.build().start()
        self.assertEqual(caught.exception.reason, "host_parent_job_membership_unknown")

    def test_an_off_profile_is_refused_before_the_ledger_is_opened(self):
        # The shipped example is mode off, and it is read here, not modified.
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC):
            with self.assertRaises(HelperHostRefused) as caught:
                self.build(profile_path=EXAMPLE_PATH).start()
        self.assertEqual(caught.exception.reason, "helper_host_mode_off")
        self.assertFalse((self.directory / "sentinel.db").exists())

    def test_an_unreadable_profile_is_refused(self):
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC):
            with self.assertRaises(HelperHostRefused) as caught:
                self.build(profile_path=self.directory / "absent.json").start()
        self.assertEqual(caught.exception.reason, "helper_host_profile_unavailable")

    def test_a_missing_ledger_is_refused_after_the_profile(self):
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC):
            with self.assertRaises(HelperHostRefused) as caught:
                self.build(data_dir=self.directory / "absent").start()
        self.assertEqual(caught.exception.reason, "helper_host_ledger_unavailable")

    def test_one_injected_source_without_the_other_is_refused(self):
        host = self.build(clock=ClockStub(BASE_TICK))
        with self.assertRaises(HelperHostRefused) as caught:
            host._sources()
        self.assertEqual(caught.exception.reason, "helper_host_clock_domain_unshared")

    def test_both_injected_sources_are_accepted_unchanged(self):
        clock = ClockStub(BASE_TICK)
        machine = SyntheticMachineSource(clock)
        host = self.build(clock=clock, machine_source=machine)
        host._sources()
        self.assertIs(host._clock, clock)
        self.assertIs(host._machine_source, machine)


# --- registration -------------------------------------------------------------


class RegistrationTests(LedgerCase):
    def build(self):
        host = HelperHost(data_dir=self.directory)
        host.store = self.store
        host.process = self.process
        return host

    def test_registration_writes_exactly_one_helper_row(self):
        host = self.build()
        host._register()
        self.assertTrue(host.registered)
        self.assertEqual([tuple(row) for row in self.helper_rows()], [("helper", 7001)])

    def test_registering_the_same_process_again_adds_no_row(self):
        host = self.build()
        host._register()
        host._register()
        self.assertEqual(len(self.helper_rows()), 1)

    def test_a_foreign_helper_row_refuses_the_start_and_adds_no_row(self):
        self.register("helper", self.processes.process(STRANGER))
        host = self.build()
        with self.assertRaises(HelperHostRefused) as caught:
            host._register()
        self.assertEqual(caught.exception.reason, "helper_host_registry_occupied")
        self.assertFalse(host.registered)
        self.assertEqual([tuple(row) for row in self.helper_rows()], [("helper", 7002)])

    def test_the_occupied_refusal_releases_policy_for_the_next_caller(self):
        # A stale helper row is the expected state on a restart. If the refusal
        # kept the entry nonce, the guardian's next prepare would be
        # policy_scope_busy and nothing would clear it.
        self.register("helper", self.processes.process(STRANGER))
        with self.assertRaises(HelperHostRefused):
            self.build()._register()
        nonce_left = self.connection().execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime WHERE singleton=1").fetchone()[0]
        self.assertIsNone(nonce_left)
        self.register("guardian", self.processes.process(
            ProcessIdentity(7003, 134343072000000004, LOGON)))
        self.assertEqual([tuple(row) for row in self.helper_rows()],
                         [("guardian", 7003), ("helper", 7002)])

    def test_the_candidate_is_verified_before_the_registry_is_touched(self):
        # Order is the whole point: only a scope that has not read or written
        # the ledger can call the identity refusal a clean rejection.
        from sentinel.adaptive import legacy_writer

        calls = []

        def record(name, original):
            def recorded(*args, **kwargs):
                calls.append(name)
                return original(*args, **kwargs)
            return recorded

        with patch.object(legacy_writer, "verify_infrastructure_candidate_locked",
                          record("verify", legacy_writer.verify_infrastructure_candidate_locked)), \
                patch.object(legacy_writer, "initialize_registry_locked",
                             record("initialize", legacy_writer.initialize_registry_locked)):
            host = self.build()
            host._register()
        self.assertEqual(calls, ["verify", "initialize"])
        self.assertEqual([tuple(row) for row in self.helper_rows()], [("helper", 7001)])

    def test_an_unverifiable_candidate_refuses_and_releases_policy(self):
        host = self.build()
        host.process = SimpleNamespace(identity=HELPER)
        with self.assertRaises(HelperHostRefused) as caught:
            host._register()
        self.assertEqual(caught.exception.reason, "helper_host_registry_unavailable")
        self.assertFalse(host.registered)
        self.assertIsNone(self.connection().execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime WHERE singleton=1").fetchone()[0])
        # The scope is free, so the next owner can take it and write.
        self.register("guardian", self.processes.process(STRANGER))
        self.assertEqual([tuple(row) for row in self.helper_rows()], [("guardian", 7002)])

    def test_a_guardian_row_does_not_block_a_helper(self):
        self.register("guardian", self.processes.process(STRANGER))
        host = self.build()
        host._register()
        self.assertEqual([tuple(row) for row in self.helper_rows()],
                         [("guardian", 7002), ("helper", 7001)])


# --- the two adapters ---------------------------------------------------------


class JobHandleSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = JobHandleSource()
        self.job = SyntheticJob(user=3 * TICKS_PER_SECOND, kernel=TICKS_PER_SECOND, active=4)
        self.source.add(execution(1), self.job, membership_provable=True)

    def test_one_read_is_one_accounting_query_and_carries_no_memory(self):
        reading = self.source.read(execution(1))
        self.assertEqual(self.job.reads, 1)
        self.assertEqual(reading.cpu_100ns, 4 * TICKS_PER_SECOND)
        self.assertEqual(reading.active_processes, 4)
        self.assertTrue(reading.membership_complete)
        self.assertIsNone(reading.private_working_set_bytes)
        self.assertIsNone(reading.private_commit_bytes)

    def test_a_job_that_permits_breakaway_reports_incomplete_membership(self):
        self.source.add(execution(2), SyntheticJob(active=9), membership_provable=False)
        reading = self.source.read(execution(2))
        self.assertFalse(reading.membership_complete)
        self.assertIsNone(reading.active_processes)

    def test_a_failed_query_raises_and_never_returns_a_zero(self):
        self.job.query_error = NativeJobError("native_job_query_failed", 5)
        with self.assertRaises(JobSamplingError) as caught:
            self.source.read(execution(1))
        self.assertEqual(caught.exception.error.code, "telemetry_stale")
        self.assertEqual(caught.exception.error.api_error_code, 5)
        self.assertEqual(caught.exception.error.execution_id, execution(1))
        self.assertEqual(self.source.unreadable(), (execution(1),))

    def test_an_unknown_execution_is_a_registry_failure_not_a_reading(self):
        with self.assertRaises(JobSamplingError) as caught:
            self.source.read(execution(9))
        self.assertEqual(caught.exception.error.code, "registry_unavailable")

    def test_a_value_out_of_range_is_refused_rather_than_reported(self):
        self.job.user, self.job.kernel = -1, 0
        with self.assertRaises(JobSamplingError) as caught:
            self.source.read(execution(1))
        self.assertEqual(caught.exception.error.code, "measurement_inconsistent")

    def test_each_handle_gets_its_own_counter_epoch(self):
        self.source.add(execution(2), SyntheticJob(), membership_provable=True)
        first = self.source.read(execution(1)).counter_epoch
        self.assertEqual(first, self.source.read(execution(1)).counter_epoch)
        self.assertNotEqual(first, self.source.read(execution(2)).counter_epoch)

    def test_release_closes_the_handle_once_and_forgets_it(self):
        self.assertIsNone(self.source.release(execution(1)))
        self.assertTrue(self.job.closed)
        self.assertEqual(self.job.close_calls, 1)
        self.assertEqual(self.source.enrolled, ())
        self.assertIsNone(self.source.release(execution(1)))
        self.assertEqual(self.job.close_calls, 1)

    def test_a_handle_whose_close_outcome_is_unknown_is_retained(self):
        self.job.close_error = NativeJobError("native_job_handle_close_failed", 6)
        self.assertEqual(self.source.release(execution(1)), "native_job_handle_close_failed")
        self.assertEqual(self.source.enrolled, ())
        self.assertEqual(self.source.retained_uncertain, 1)

    def test_the_same_execution_cannot_be_enrolled_twice(self):
        with self.assertRaises(ValueError):
            self.source.add(execution(1), SyntheticJob(), membership_provable=True)


class MembershipProofTests(unittest.TestCase):
    def test_a_job_with_no_breakaway_limit_proves_its_membership(self):
        self.assertTrue(HelperHost._membership_provable(SyntheticJob(limit_flags=0)))

    def test_either_breakaway_flag_leaves_membership_unproven(self):
        for flags in (module.JOB_LIMIT_BREAKAWAY_OK, module.JOB_LIMIT_SILENT_BREAKAWAY_OK):
            with self.subTest(flags=flags):
                self.assertFalse(HelperHost._membership_provable(SyntheticJob(limit_flags=flags)))

    def test_limits_that_cannot_be_read_leave_membership_unproven(self):
        job = SyntheticJob()
        job.limits_error = NativeJobError("native_job_query_failed", 5)
        self.assertFalse(HelperHost._membership_provable(job))


class MachineObservationSourceTests(unittest.TestCase):
    def test_the_adapter_copies_the_sample_fields(self):
        sample = machine_sample()
        observation = MachineObservationSource(SyntheticSampler(sample))()
        self.assertIs(observation.machine, sample.machine)
        self.assertEqual(observation.clock_epoch, sample.clock_epoch)
        self.assertEqual(observation.window_start_tick_100ns, sample.window_start_tick_100ns)
        self.assertEqual(observation.window_end_tick_100ns, sample.window_end_tick_100ns)
        self.assertIs(observation.validity, Validity.VALID)
        self.assertEqual(observation.errors, ())
        self.assertFalse(observation.reset_required)

    def test_an_unknown_sample_is_forwarded_without_substitution(self):
        error = FrameError("telemetry_stale", "machine_native_api", RetryClass.NEVER)
        observation = MachineObservationSource(SyntheticSampler(error=MachineSamplingError(error)))()
        self.assertIsNone(observation.machine)
        self.assertIs(observation.validity, Validity.UNKNOWN)
        self.assertEqual(observation.errors, (error,))
        self.assertTrue(observation.reset_required)


# --- enrollment and the loop --------------------------------------------------


class RunningCase(LedgerCase):
    """A started host with injected sources. No native call happens anywhere."""

    def setUp(self):
        super().setUp()
        self.clock = ClockStub(BASE_TICK)
        self.machine = SyntheticMachineSource(self.clock)
        self.sleeps = []
        self.opened = []
        self.jobs = {}
        self.unopenable = set()

    def open_job(self, name, job_nonce, logon_id):
        self.opened.append((name, job_nonce, logon_id))
        if name in self.unopenable:
            raise NativeJobError("native_job_open_failed", 2)
        job = SyntheticJob(user=TICKS_PER_SECOND, active=3)
        self.jobs[name] = job
        return job

    def build(self, **changes):
        """The same wiring start() performs, without the capability preflight,
        the profile file, the ledger constructor and the identity query."""
        host = HelperHost(data_dir=self.directory, clock=self.clock, machine_source=self.machine,
                          open_job=self.open_job, sleep=self.sleeps.append, **changes)
        host.store = self.store
        host.process = self.process
        host.profile = self.profile_value()
        host._sources()
        host.sampler = FrameSampler(profile=host.profile, backend=host.jobs,
                                    machine_source=self.machine, clock=self.clock)
        host.shadow = ShadowHelper(profile=host.profile, sampler=host.sampler, clock=self.clock)
        host._started = True
        return host

    def profile_value(self):
        return replace(profile(), mode=Mode.SHADOW)


class EnrollmentTests(RunningCase):
    def test_only_live_job_contained_rows_of_this_logon_are_enrolled(self):
        self.seed(1)
        self.seed(2)
        self.seed(3, state="FINISHED")
        self.seed(4, coverage="unmanaged")
        self.seed(5, logon="S-1-5-5-9-9")
        host = self.build()
        record = host.refresh_enrollment()
        self.assertEqual(host.jobs.enrolled, (execution(1), execution(2)))
        self.assertEqual(host.sampler.enrolled, (execution(1), execution(2)))
        self.assertEqual((record["opened"], record["left_out"]), (2, 0))
        self.assertEqual([entry[0] for entry in self.opened], [job_name(1), job_name(2)])

    def test_the_cap_bounds_enrollment_and_the_rest_is_counted(self):
        for index in range(1, 6):
            self.seed(index)
        host = self.build()
        host.profile = replace(host.profile, max_enrolled_jobs=2)
        host.sampler = FrameSampler(profile=host.profile, backend=host.jobs,
                                    machine_source=self.machine, clock=self.clock)
        host.shadow = ShadowHelper(profile=host.profile, sampler=host.sampler, clock=self.clock)
        record = host.refresh_enrollment()
        self.assertEqual(host.jobs.enrolled, (execution(1), execution(2)))
        self.assertEqual(record["left_out"], 3)

    def test_a_row_whose_job_name_is_not_canonical_is_rejected_and_counted(self):
        self.seed(1, name="Local\\ResourceSentinel.Job.impostor")
        host = self.build()
        record = host.refresh_enrollment()
        self.assertEqual(host.jobs.enrolled, ())
        self.assertEqual(record["ledger_rows_rejected"], 1)
        self.assertEqual(self.opened, [])

    def test_the_ledger_never_supplies_a_verified_capability(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        enrollment = host.shadow._enrollments[execution(1)]
        self.assertFalse(enrollment.capability_verified)
        self.assertFalse(enrollment.foreground)
        self.assertIs(enrollment.role, Role.BACKGROUND)
        self.assertIs(enrollment.priority, Priority.P2)
        self.assertIs(enrollment.coverage, Coverage.JOB_CONTAINED)

    def test_an_execution_that_left_the_live_set_is_released_and_closed(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        self.connection().execute("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?",
                                  (execution(1),))
        record = host.refresh_enrollment()
        self.assertEqual(record["released"], 1)
        self.assertTrue(self.jobs[job_name(1)].closed)
        self.assertEqual(host.jobs.enrolled, ())
        self.assertEqual(host.sampler.enrolled, ())

    def test_a_job_that_cannot_be_opened_is_counted_and_not_enrolled(self):
        self.seed(1)
        self.unopenable.add(job_name(1))
        host = self.build()
        record = host.refresh_enrollment()
        self.assertEqual((record["open_failed"], record["enrolled"]), (1, 0))

    def test_a_ledger_that_cannot_be_read_releases_nothing(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        with patch.object(store_module, "_ipc_read_transaction",
                          side_effect=LifecycleError("ipc_registry_unavailable")):
            record = host.refresh_enrollment()
        self.assertEqual(record["ledger"], "ipc_registry_unavailable")
        self.assertEqual(host.jobs.enrolled, (execution(1),))
        self.assertFalse(self.jobs[job_name(1)].closed)

    def test_an_unstarted_host_enrolls_nothing(self):
        host = self.build()
        host._started = False
        with self.assertRaises(HelperHostRefused) as caught:
            host.refresh_enrollment()
        self.assertEqual(caught.exception.reason, "helper_host_not_started")


class LoopTests(RunningCase):
    def counted(self, host):
        original, calls = host.shadow.tick, []

        def tick():
            calls.append(1)
            return original()

        host.shadow.tick = tick
        return calls

    def test_one_iteration_ticks_once_and_paces_to_the_next_boundary(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        calls = self.counted(host)
        outcome = host.run_once()
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.sleeps, [1.0])
        self.assertEqual(outcome.slept_seconds, 1.0)
        self.assertFalse(outcome.would_apply)
        self.assertEqual(host.shadow.metrics.ticks, 1)

    def test_a_late_iteration_runs_once_and_never_catches_up(self):
        host = self.build()
        calls = self.counted(host)
        host.run_once()
        self.clock.set(BASE_TICK + 10 * TICKS_PER_SECOND)
        host.run_once()
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.sleeps), 2)
        self.assertGreater(self.sleeps[1], 0.0)
        self.assertLessEqual(self.sleeps[1], 1.0)
        self.assertGreater(host.metrics_record()["skipped_boundaries"], 0)

    def test_the_enrollment_refresh_runs_on_its_own_cadence(self):
        host = self.build(enroll_every_ticks=3)
        refreshed = [host.run_once().refreshed for _ in range(7)]
        self.assertEqual(refreshed, [False, False, False, True, False, False, True])

    def test_a_job_that_cannot_be_read_is_released_by_the_loop(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        self.jobs[job_name(1)].query_error = NativeJobError("native_job_query_failed", 5)
        outcome = host.run_once()
        self.assertEqual(outcome.released, 1)
        self.assertTrue(self.jobs[job_name(1)].closed)
        self.assertEqual(host.jobs.enrolled, ())
        self.assertEqual(host.metrics_record()["dropped_unreadable"], 1)

    def test_the_metrics_record_carries_no_command_text_path_or_identifier(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        host.run_once()
        record = host.metrics_record()
        self.assertEqual(set(record), {
            "event", "mode", "iterations", "ticks", "frames", "frame_gaps", "late_ticks",
            "missed_ticks", "decisions", "last_tick_ms", "max_tick_ms", "total_tick_ms",
            "enrolled", "left_out", "dropped_unreadable", "would_apply", "last_reason",
            "skipped_boundaries", "sample_interval_ms", "handles_retained_uncertain"})
        payload = json.dumps(record, sort_keys=True, default=str)
        for absent in (str(self.directory), "ResourceSentinel.Job", execution(1),
                       "fixture-principal-1", "sentinel.db"):
            self.assertNotIn(absent, payload)

    def test_an_unstarted_host_runs_nothing(self):
        host = self.build()
        host._started = False
        with self.assertRaises(HelperHostRefused) as caught:
            host.run_once()
        self.assertEqual(caught.exception.reason, "helper_host_not_started")
        self.assertEqual(self.sleeps, [])

    def test_close_releases_every_handle_and_keeps_the_registry_row(self):
        self.seed(1)
        self.seed(2)
        host = self.build()
        host.refresh_enrollment()
        record = host.close()
        self.assertTrue(all(job.closed for job in self.jobs.values()))
        self.assertEqual(record["enrolled"], 0)
        self.assertEqual(record["handles_retained_uncertain"], 0)

    def test_close_reports_a_release_whose_outcome_is_unknown(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        self.jobs[job_name(1)].close_error = NativeJobError("native_job_handle_close_failed", 6)
        with self.assertRaises(HelperHostRefused) as caught:
            host.close()
        self.assertEqual(caught.exception.reason, "helper_host_handle_cleanup_unverified")
        self.assertEqual(host.jobs.retained_uncertain, 1)

    def test_the_default_mode_runs_until_it_is_interrupted(self):
        host = self.build()
        calls = []

        def interrupting():
            calls.append(1)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return SimpleNamespace(reason="fixture")

        host.run_once = interrupting
        record = host.serve_until_stopped()
        self.assertEqual(record["reason"], "interrupted")
        self.assertEqual(len(calls), 3)


class EntryPointTests(RunningCase):
    def arguments(self, *extra):
        return ["--data-dir", str(self.directory), *extra]

    def run_main(self, host, *extra):
        with patch.object(module, "HelperHost", return_value=host):
            with patch.object(host, "start", return_value={"event": "fixture_started"}):
                return module.main(self.arguments(*extra))

    def test_an_interrupt_closes_every_handle_and_exits_zero(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()
        host.run_once = self.interrupt
        self.assertEqual(self.run_main(host), EXIT_OK)
        self.assertTrue(self.jobs[job_name(1)].closed)

    def test_an_unexpected_failure_closes_every_handle_and_exits_non_zero(self):
        self.seed(1)
        host = self.build()
        host.refresh_enrollment()

        def failing():
            raise RuntimeError("fixture_tick_failed")

        host.run_once = failing
        self.assertEqual(self.run_main(host, "--iterations", "1"), EXIT_FAILED)
        self.assertTrue(self.jobs[job_name(1)].closed)

    def test_invalid_arguments_are_refused_before_anything_starts(self):
        self.assertEqual(module.main(self.arguments("--enroll-every", "0")), EXIT_REFUSED)
        self.assertEqual(module.main(self.arguments("--iterations", "-1")), EXIT_REFUSED)

    @staticmethod
    def interrupt():
        raise KeyboardInterrupt


# --- structural zero Set ------------------------------------------------------

DENIED_MODULES = frozenset({
    "sentinel.adaptive.control_transport", "sentinel.adaptive.proposal_builder",
    "sentinel.adaptive.guardian", "sentinel.adaptive.guardian_control",
    "sentinel.adaptive.guardian_host", "sentinel.adaptive.guardian_lifecycle",
    "sentinel.adaptive.guardian_restore", "sentinel.adaptive.recovery_owner",
    "sentinel.adaptive.recovery_journal", "sentinel.adaptive.launcher",
    "sentinel.adaptive.native_launcher", "sentinel.adaptive.writers",
})
# The literals the plan stage forbids in this source, checked as text as well.
DENIED_TEXT = frozenset({
    "set_cpu_rate", "set_cpu_rate_unverified", "disable", "NativeJob.create",
    "JobAccess.CONTROL", "JobAccess.OWNER", "JobAccess.LAUNCH",
})
# Names that would perform or request a control if they were used at all. The
# module docstring may say what the host does not build, so these are checked
# against the parsed source and not against its text.
DENIED_NAMES = DENIED_TEXT | {"ControlProposal", "SetInformationJobObject", "apply", "publish"}


def named(path: Path) -> set[str]:
    """Every bare name and every one level attribute chain in a source file."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
            if isinstance(node.value, ast.Name):
                found.add(node.value.id + "." + node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            found.update(alias.asname or alias.name for alias in node.names)
    return found


class ZeroSetStructureTests(unittest.TestCase):
    def test_the_host_imports_exactly_these_modules(self):
        self.assertEqual(imported_modules(PACKAGE / "helper_host.py"), {
            "__future__", "argparse", "dataclasses", "json", "pathlib", "re", "sys", "time",
            "uuid", "sentinel.adaptive.contracts", "sentinel.adaptive.decision",
            "sentinel.adaptive.helper", "sentinel.adaptive.host_authority",
            "sentinel.adaptive.identity", "sentinel.adaptive.legacy_writer",
            "sentinel.adaptive.machine_sampler", "sentinel.adaptive.native_job",
            "sentinel.adaptive.sampler", "sentinel.adaptive.store"})

    def test_it_imports_nothing_that_can_set_a_cap_or_reach_a_guardian(self):
        self.assertEqual(imported_modules(PACKAGE / "helper_host.py") & DENIED_MODULES, set())

    def test_its_source_names_no_job_mutation_and_no_proposal(self):
        self.assertEqual(named(PACKAGE / "helper_host.py") & DENIED_NAMES, set())
        source = (PACKAGE / "helper_host.py").read_text(encoding="utf-8")
        for text in DENIED_TEXT:
            self.assertNotIn(text, source)

    def test_every_job_it_opens_is_opened_with_query_rights_only(self):
        tree = ast.parse((PACKAGE / "helper_host.py").read_text(encoding="utf-8"))
        opens = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "open"]
        self.assertEqual(len(opens), 1)
        access = [keyword.value for keyword in opens[0].keywords if keyword.arg == "access"]
        self.assertEqual(len(access), 1)
        self.assertIsInstance(access[0], ast.Attribute)
        self.assertEqual(access[0].attr, "QUERY")
        self.assertEqual(access[0].value.id, "JobAccess")

    def test_the_shadow_helper_stays_unaware_of_this_host(self):
        self.assertNotIn("sentinel.adaptive.helper_host", imported_modules(PACKAGE / "helper.py"))

    def test_the_module_namespace_exposes_no_actuator(self):
        for name in vars(module):
            self.assertNotIn(name, DENIED_NAMES)

    def test_the_host_never_passes_the_in_process_shadow_flag(self):
        tree = ast.parse((PACKAGE / "helper_host.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self.assertEqual([keyword.arg for keyword in node.keywords
                                  if keyword.arg == "shadow"], [])


class HelperHostSubprocessTests(unittest.TestCase):
    """One real process, expecting a refusal from a separate interpreter."""

    def run_host(self, *arguments):
        return subprocess.run([sys.executable, "-m", "sentinel.adaptive.helper_host", *arguments],
                              cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

    def test_help_is_available(self):
        result = self.run_host("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--data-dir", result.stdout)

    def test_a_start_on_an_isolated_data_directory_refuses(self):
        # The default profile is mode off, so a host that passes the preflight
        # refuses for that reason instead. Neither path reaches a ledger.
        expected = {live_capability_refusal(), "helper_host_mode_off"} - {None}
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_host("--data-dir", directory, "--iterations", "1")
        self.assertEqual(result.returncode, EXIT_REFUSED)
        record = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(record["event"], "helper_host_refused")
        self.assertIn(record["reason"], expected)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
