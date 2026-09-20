"""L1 S1 custody integration with real isolated admission, ledger and journal.

Only native objects and the runtime authority below are synthetic. These tests
do not prove Windows capability, continuous host admission, legacy exclusion,
or production readiness. No executable, Job, OS control or daily data is used.
"""
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from sentinel.adaptive.admission import ManagedAdmission, ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import CpuControlMode, ProcessIdentity
from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_admission_context import FakeCurrentProcess, PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, NOW, status
from tests.windows import adaptive_execution
from tests.windows.adaptive_execution import S1ExecutionOwner, S1Runtime


class SyntheticRuntimeAuthority:
    """Explicit fixture; absence or failure never changes the real host gate."""

    guardian_epoch = "synthetic-s1-guardian"

    def __init__(self, events):
        self.events = events
        self.retained = []
        self.coverage_error = None
        self.exclusion_error = None
        self.ready_error = None

    def assert_ready(self):
        self.events.append("runtime.ready")
        if self.ready_error is not None:
            raise self.ready_error

    def capacity(self):
        return status(now=time.time()), dict(CONFIG)

    def assert_covered(self, admission, row):
        self.events.append("covered")
        if self.coverage_error is not None:
            raise self.coverage_error
        if admission.snapshot().execution_id != row["execution_id"]:
            raise AssertionError("synthetic authority received another execution")

    def assert_excluded(self, row):
        self.events.append("excluded")
        if self.exclusion_error is not None:
            raise self.exclusion_error

    def retain(self, owner):
        self.events.append("retain")
        if owner not in self.retained:
            self.retained.append(owner)

    def authorize_control(self, owner, target):
        # This is explicitly synthetic policy authority. Assert the caller's
        # real in-process fence without claiming any host-wide readiness.
        owner.assert_held()
        if target.mode is not CpuControlMode.HARD_CAP:
            raise AssertionError("synthetic authority expected restrictive target")
        self.events.append("runtime.authorize_control")

    def control_restored(self, owner):
        owner.assert_held()
        manifest = owner.journal.read(owner.execution_id,
                                     creation_nonce=owner.creation_nonce)
        if (owner.query_cpu_control().mode is not CpuControlMode.DISABLED or
                manifest.pending_intent is not None or
                (manifest.last_applied is not None and
                 manifest.last_applied.mode is not CpuControlMode.DISABLED)):
            raise AssertionError("restore reported before settled native state and journal")
        self.events.append("runtime.control_restored")


class SyntheticProcess:
    def __init__(self, native):
        self.native = native
        owner = native.wrapper_identity
        self.identity = ProcessIdentity(owner.pid + 1000,
            owner.created_filetime_100ns + 1000, owner.logon_id)
        self.exited = False
        self.closed = False
        self.close_error = None

    def full_identity(self, *, expected_logon_id):
        if self.identity.logon_id != expected_logon_id:
            raise LifecycleError("synthetic_process_logon_mismatch")
        return self.identity

    def wait(self, timeout):
        return self.exited

    def close(self):
        self.native.events.append("process.close")
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


def _shared_field(name):
    return property(lambda handle: handle._state[name],
                    lambda handle, value: handle._state.__setitem__(name, value))


class SyntheticJob:
    # Native handles alias one kernel object; closing one is handle-local.
    members = _shared_field("members")
    control = _shared_field("control")
    query_error = _shared_field("query_error")
    disable_error = _shared_field("disable_error")
    set_error_after_apply = _shared_field("set_error_after_apply")
    set_observer = _shared_field("set_observer")

    def __init__(self, native, nonce, state=None):
        self.native = native
        self.name = native.JOB_PREFIX + nonce
        self.logon_sid = native.wrapper_identity.logon_id
        self._state = state if state is not None else {
            "members": [], "control": {"flags": 0, "rate_bp": 0},
            "query_error": None, "disable_error": None,
            "set_error_after_apply": None, "set_observer": None,
        }
        self.closed = False
        self.disable_calls = 0

    def assert_open(self):
        if self.closed:
            raise LifecycleError("synthetic_closed_job_handle")

    def accounting(self):
        self.assert_open()
        return {"active_processes": len(self.members)}

    def active_pids(self):
        self.assert_open()
        return list(self.members)

    def query_cpu(self):
        self.assert_open()
        self.native.events.append("job.query_cpu")
        if self.query_error is not None:
            raise self.query_error
        return dict(self.control)

    def set_cpu_rate(self, rate_bp):
        self.assert_open()
        self.native.events.append("job.set_cpu")
        if self.set_observer is not None:
            self.set_observer(rate_bp)
        self.control = {"flags": 5, "rate_bp": rate_bp}
        if self.set_error_after_apply is not None:
            raise self.set_error_after_apply
        return dict(self.control)

    def disable(self):
        self.assert_open()
        self.disable_calls += 1
        self.native.events.append("job.disable")
        if self.disable_error is not None:
            raise self.disable_error
        self.control = {"flags": 0, "rate_bp": 0}
        return dict(self.control)

    def close(self):
        self.native.events.append("job.close")
        self.closed = True


class SyntheticMutex:
    def __init__(self, native, name, nonce):
        self.native = native
        self.name, self.nonce = name, nonce
        self.acquired = False
        self.closed = False
        self.release_error_once = None

    def acquire(self, timeout):
        if self.acquired:
            raise AssertionError("unexpected duplicate synthetic mutex acquire")
        self.native.events.append("mutex.acquire")
        self.acquired = True
        return False

    def release(self):
        if self.release_error_once is not None:
            error = self.release_error_once
            self.release_error_once = None
            self.native.events.append("mutex.release_failed")
            raise error
        self.native.events.append("mutex.release")
        self.acquired = False

    def close(self):
        if self.acquired:
            raise AssertionError("closing held synthetic mutex")
        self.native.events.append("mutex.close")
        self.closed = True


class SyntheticNative:
    JOB_PREFIX = "Local\\ResourceSentinel.Test.Job."
    MUTEX_PREFIX = "Local\\ResourceSentinel.Test.Mutex."

    class LaunchOutcomeUnknown(RuntimeError):
        def __init__(self, process):
            self.process = process
            super().__init__("synthetic_launch_outcome_unknown")

    def __init__(self, identity, events):
        self.wrapper_identity, self.events = identity, events
        self.create_calls = self.launch_calls = 0
        self.open_calls = 0
        self.create_error = None
        self.host_error = None
        self.create_observer = self.launch_observer = None
        self.launch_unknown = False
        self.jobs, self.processes = [], []
        self.created_jobs = {}
        native = self

        class OwnedJob:
            @staticmethod
            def create(*, nonce):
                native.events.append("job.create")
                native.create_calls += 1
                if native.create_observer is not None:
                    native.create_observer()
                if native.create_error is not None:
                    raise native.create_error
                job = SyntheticJob(native, nonce)
                native.jobs.append(job)
                native.created_jobs[job.name] = job
                return job

            @staticmethod
            def open(name, nonce):
                native.events.append("job.open")
                native.open_calls += 1
                if name != native.JOB_PREFIX + nonce or name not in native.created_jobs:
                    raise LifecycleError("synthetic_job_not_found")
                original = native.created_jobs[name]
                handle = SyntheticJob(native, nonce, state=original._state)
                native.jobs.append(handle)
                return handle

        self.OwnedJob = OwnedJob

    def NamedMutex(self, name, nonce):
        return SyntheticMutex(self, name, nonce)

    def require_supported_host(self):
        self.events.append("native.host_preflight")
        if self.host_error is not None:
            raise self.host_error

    def launch_in_job(self, job, application, command_line, **kwargs):
        self.events.append("process.create")
        self.launch_calls += 1
        if self.launch_observer is not None:
            self.launch_observer()
        process = SyntheticProcess(self)
        self.processes.append(process)
        job.members.append(process.identity.pid)
        if self.launch_unknown:
            raise self.LaunchOutcomeUnknown(process)
        return process


class S1ExecutionOwnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        self.current_process = FakeCurrentProcess()
        current = patch("sentinel.adaptive.admission.VerifiedProcess.current",
                        return_value=self.current_process)
        current.start()
        self.addCleanup(current.stop)
        cpu_count = patch("os.cpu_count", return_value=12)
        cpu_count.start()
        self.addCleanup(cpu_count.stop)
        self.admission = ManagedAdmission.current(**PAYLOAD)
        self.addCleanup(self.admission.close)
        admitted = self.coordinator.admit_managed(self.admission, status(), config=CONFIG, now=NOW)
        self.assertTrue(admitted["allowed"], admitted)
        self.execution_id = admitted["execution_id"]
        self.reservation_id = admitted["reservation_id"]
        self.policy = FixturePolicyProvider(self.current_process.identity.logon_id)
        self.store = LifecycleStore(self.coordinator.db_path, policy_provider=self.policy)
        self.events = []
        self.authority = SyntheticRuntimeAuthority(self.events)
        self.native = SyntheticNative(self.current_process.identity, self.events)
        self.journal_directory = self.directory / "journal"
        self.journal_directory.mkdir()
        self.owner = S1ExecutionOwner(admission=self.admission, store=self.store,
            authority=self.authority, directory=self.journal_directory, native=self.native)
        # Fault-injection owners retain only synthetic objects. Remove only our
        # own fixture's module reference after assertions, never native custody.
        self.addCleanup(adaptive_execution._RETAINED_OWNERS.pop, self.execution_id, None)

    def row(self):
        return self.store.query(self.execution_id)

    def manifest(self):
        return self.owner.journal.read(self.execution_id,
                                      creation_nonce=self.owner.creation_nonce)

    def allocation(self):
        with closing(sqlite3.connect(self.coordinator.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute("SELECT * FROM reservations WHERE id=?",
                                     (self.reservation_id,)).fetchone()
            return None if row is None else dict(row)

    def policy_runtime(self):
        with closing(sqlite3.connect(self.coordinator.db_path)) as connection:
            connection.row_factory = sqlite3.Row
            return dict(connection.execute(
                "SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def assert_floor_retained(self):
        allocation = self.allocation()
        self.assertIsNotNone(allocation)
        self.assertEqual(allocation["execution_id"], self.execution_id)
        expected = self.admission.snapshot().requested
        row = self.row()
        for name in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(row["floor_" + name], getattr(expected, name))

    def launch(self):
        return self.owner.launch_once("synthetic.exe", PAYLOAD["command"],
            cwd=PAYLOAD["cwd"], stdin_handle=11, stdout_handle=12, stderr_handle=13)

    def running(self):
        self.owner.prepare()
        return self.launch()

    def make_empty(self):
        self.owner.process.exited = True
        self.owner.job.members.clear()

    def runtime(self):
        # A separate real ledger avoids granting another runtime's reservation
        # any authority over this fixture's already admitted execution.
        directory = self.directory / "runtime-ledger"
        directory.mkdir()
        coordinator = Coordinator(directory, pid_identity=lambda pid: (None, 0.0))
        runtime = S1Runtime(coordinator=coordinator, authority=self.authority,
            native=self.native, store_factory=lambda path: LifecycleStore(path,
                policy_provider=FixturePolicyProvider(self.current_process.identity.logon_id)))
        def release_synthetic_references():
            for admission in runtime.pending_admissions:
                admission.close()
            for owner in runtime.owners:
                owner.admission.close()
                adaptive_execution._RETAINED_OWNERS.pop(owner.execution_id, None)
        self.addCleanup(release_synthetic_references)
        return runtime

    def open_runtime_case(self, runtime):
        nonce = uuid.uuid4().hex
        directory = self.directory / nonce
        directory.mkdir()
        return runtime.open_case(command=PAYLOAD["command"], cwd=PAYLOAD["cwd"],
            directory=directory, requested=PAYLOAD["requested"], creation_nonce=nonce)

    def test_runtime_admits_real_execution_before_owner_and_serializes_cases(self):
        runtime = self.runtime()
        owner = self.open_runtime_case(runtime)
        self.assertEqual(runtime.owners, [owner])
        self.assertEqual(runtime.pending_admissions, [])
        row = owner.store.query(owner.execution_id)
        self.assertEqual(row["state"], "RESERVED")
        self.assertEqual(row["wrapper_pid"], self.current_process.identity.pid)
        self.assertEqual(row["role"], "background")
        self.assertEqual(row["priority"], "P2")
        self.assertEqual(self.native.create_calls, 0)
        with self.assertRaisesRegex(LifecycleError, "previous_case_unsettled"):
            self.open_runtime_case(runtime)
        self.assertEqual(len(runtime.owners), 1)
        owner.finalize()
        owner.close()
        second = self.open_runtime_case(runtime)
        self.assertNotEqual(second.execution_id, owner.execution_id)
        self.assertNotEqual(second.creation_nonce, owner.creation_nonce)
        second.finalize()
        second.close()

    def test_runtime_denial_retains_exact_pending_admission_without_creating_native_job(self):
        runtime = self.runtime()
        with patch.object(self.authority, "capacity",
                          return_value=(status(now=time.time(), commit=95), CONFIG)), \
                patch("tests.windows.adaptive_execution.time.sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.open_runtime_case(runtime)
        self.assertEqual(len(runtime.pending_admissions), 1)
        pending = runtime.pending_admissions[0]
        self.assertTrue(pending._submitted)
        self.assertFalse(pending._claim_exported)
        with closing(sqlite3.connect(runtime.coordinator.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM queue").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM reservations").fetchone()[0], 0)
        with self.assertRaisesRegex(LifecycleError, "previous_case_unsettled"):
            self.open_runtime_case(runtime)
        self.assertIs(runtime.pending_admissions[0], pending)
        self.assertEqual((self.native.create_calls, self.native.launch_calls), (0, 0))

    def test_runtime_retries_same_queued_context_and_admits_when_capacity_recovers(self):
        runtime = self.runtime()
        capacities = [(status(now=time.time(), commit=95), CONFIG),
                      (status(now=time.time()), CONFIG)]
        with patch.object(self.authority, "capacity", side_effect=capacities), \
                patch("tests.windows.adaptive_execution.time.sleep", return_value=None) as sleep, \
                patch.object(runtime.coordinator, "admit_managed",
                             wraps=runtime.coordinator.admit_managed) as submit:
            owner = self.open_runtime_case(runtime)
        sleep.assert_called_once_with(1)
        self.assertEqual(submit.call_count, 2)
        self.assertIs(submit.call_args_list[0].args[0], submit.call_args_list[1].args[0])
        self.assertIs(submit.call_args_list[1].args[0], owner.admission)
        self.assertEqual(runtime.pending_admissions, [])
        with closing(sqlite3.connect(runtime.coordinator.db_path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM queue").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM managed_executions").fetchone()[0], 1)
        owner.finalize()
        owner.close()

    def test_runtime_host_rejection_occurs_before_any_admission_submission(self):
        runtime = self.runtime()
        self.native.host_error = LifecycleError("synthetic_foreign_job")
        with patch.object(runtime.coordinator, "admit_managed",
                          side_effect=AssertionError("admission reached after host rejection")):
            with self.assertRaisesRegex(LifecycleError, "synthetic_foreign_job"):
                self.open_runtime_case(runtime)
        self.assertEqual(runtime.pending_admissions, [])
        self.assertEqual(runtime.owners, [])
        self.assertEqual((self.native.create_calls, self.native.launch_calls), (0, 0))

    def test_db_scope_and_durable_journal_exist_before_first_native_create(self):
        def before_create():
            self.owner.assert_held()
            self.assertTrue(self.policy.active)
            row = self.row()
            self.assertEqual(row["state"], "RESERVED")
            self.assertEqual(row["job_name"], self.owner.job_name)
            self.assertEqual(row["job_nonce"], self.owner.creation_nonce)
            self.assertEqual(row["guardian_epoch"], self.authority.guardian_epoch)
            self.assertFalse(row["claim_consumed"])
            manifest = self.manifest()
            self.assertEqual(manifest.job_name, row["job_name"])
            self.assertEqual(manifest.manifest_seq, 0)
            self.assertIsNone(manifest.root_identity)
            self.assertIsNone(manifest.pending_intent)
            self.assertEqual(manifest.allocated_floor, self.admission.snapshot().requested)
            self.assert_floor_retained()
            self.assertIn("excluded", self.events)
        self.native.create_observer = before_create
        self.owner.prepare()
        self.assertEqual(self.native.create_calls, 1)
        self.assertEqual(self.row()["state"], "PREPARED")
        self.assertFalse(self.policy.active)

    def test_one_use_claim_is_committed_before_exactly_one_process_creation(self):
        self.owner.prepare()
        def before_launch():
            row = self.row()
            self.assertEqual(row["state"], "LAUNCHING")
            self.assertTrue(row["claim_consumed"])
            self.assertTrue(row["launch_in_flight"])
            self.assert_floor_retained()
        self.native.launch_observer = before_launch
        process = self.launch()
        self.assertEqual(self.row()["state"], "RUNNING")
        self.assertEqual(self.row()["root_pid"], process.identity.pid)
        self.assertEqual(self.manifest().root_identity, process.identity)
        with self.assertRaises(LifecycleError):
            self.launch()
        with self.assertRaises(LifecycleError):
            self.owner.prepare()
        self.assertEqual((self.native.create_calls, self.native.launch_calls), (1, 1))

    def test_observer_close_and_reopen_preserve_distinct_owner_custody(self):
        observer = self.owner.prepare()
        owned = self.owner.job
        self.assertIsNot(observer, owned)
        self.assertEqual(observer.name, owned.name)
        self.assertIs(observer._state, owned._state)
        observer.close()
        self.assertFalse(owned.closed)
        self.assertEqual(owned.accounting()["active_processes"], 0)
        second = self.owner.reopen_probe()
        self.assertIsNot(second, owned)
        self.assertIsNot(second, observer)
        self.launch()
        self.owner.set_cpu_rate(2500)
        self.assertEqual(second.query_cpu(), {"flags": 5, "rate_bp": 2500})
        self.owner.restore(through=second)
        self.assertEqual(second.disable_calls, 1)
        self.assertEqual(owned.disable_calls, 0)
        second.close()
        self.assertFalse(owned.closed)
        self.make_empty()
        self.owner.finalize()
        self.owner.close()
        self.assertTrue(owned.closed)

    def test_changed_payload_never_exports_claim_or_launches(self):
        self.owner.prepare()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "launch_payload_mismatch"):
            self.owner.launch_once("synthetic.exe", PAYLOAD["command"] + " changed",
                cwd=PAYLOAD["cwd"], stdin_handle=11, stdout_handle=12, stderr_handle=13)
        self.assertFalse(self.row()["claim_consumed"])
        self.assertFalse(self.admission._claim_exported)
        self.assertEqual(self.native.launch_calls, 0)
        self.assert_floor_retained()

    def test_unknown_launch_retains_exact_returned_handle_and_cannot_retry(self):
        self.owner.prepare()
        self.native.launch_unknown = True
        with self.assertRaises(self.native.LaunchOutcomeUnknown) as caught:
            self.launch()
        self.assertIs(self.owner.process, caught.exception.process)
        self.assertIs(self.owner.process, self.native.processes[0])
        self.assertIn(self.owner, self.authority.retained)
        self.assertFalse(self.owner.process.closed)
        self.assertTrue(self.row()["claim_consumed"])
        with self.assertRaises(LifecycleError):
            self.launch()
        with self.assertRaises(LifecycleError):
            self.owner.close()
        self.assertEqual(self.native.launch_calls, 1)
        self.assert_floor_retained()
        self.assertEqual(self.row()["state"], "START_UNKNOWN")
        self.make_empty()
        self.owner.restore()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.owner.close()
        self.assertEqual(self.native.launch_calls, 1)

    def test_deadline_after_real_committed_claim_finalizes_without_native_launch(self):
        self.owner.prepare()
        real_claim = self.store.claim_launch

        def commit_claim_then_expire(*args, **kwargs):
            claimed = real_claim(*args, **kwargs)
            self.assertTrue(claimed["launch_authorized"])
            self.assertTrue(self.row()["claim_consumed"])
            self.assertTrue(self.row()["launch_in_flight"])
            # Expire only after the real transaction, POLICY release and
            # authority ACK, but before S1ExecutionOwner calls CreateProcess.
            self.owner.observation_deadline = 0
            return claimed

        with patch.object(self.store, "claim_launch", side_effect=commit_claim_then_expire):
            with self.assertRaisesRegex(LifecycleError, "case_observation_deadline_expired"):
                self.launch()
        self.assertEqual(self.row()["state"], "START_UNKNOWN")
        self.assertTrue(self.row()["claim_consumed"])
        self.assertTrue(self.row()["launch_in_flight"])
        self.assertFalse(self.owner._launch_attempted)
        self.assertIsNone(self.owner.process)
        self.assertEqual(self.native.launch_calls, 0)
        self.assertEqual(self.owner.job.active_pids(), [])
        self.assert_floor_retained()
        with self.assertRaises(LifecycleError):
            self.launch()
        self.owner.restore()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.assertIsNone(self.allocation())
        self.owner.close()
        self.assertEqual(self.native.launch_calls, 0)

    def test_committed_claim_policy_release_ack_failure_reuses_exact_guard_to_settle(self):
        self.owner.prepare()
        actual_hold = self.policy.hold
        observed = []

        @contextmanager
        def release_then_lose_ack(binding, *, timeout_ms=250):
            with actual_hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            # The real claim body and the fixture native release completed;
            # only the release acknowledgement fails, before nonce cleanup.
            observed.append(self.row())
            raise OSError("synthetic_policy_release_ack_lost")

        with patch.object(self.policy, "hold", side_effect=release_then_lose_ack):
            with self.assertRaisesRegex(OSError, "synthetic_policy_release_ack_lost"):
                self.launch()
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["state"], "LAUNCHING")
        self.assertTrue(observed[0]["claim_consumed"])
        self.assertTrue(observed[0]["launch_in_flight"])
        self.assertEqual(self.row()["state"], "START_UNKNOWN")
        retained = self.owner._recovery_guard
        self.assertIsNotNone(retained)
        self.assertEqual(self.policy_runtime()["policy_entry_nonce"], retained.nonce)
        self.assertFalse(self.policy.active)
        self.assertEqual(self.native.launch_calls, 0)
        self.assertIsNone(self.owner.process)
        self.assert_floor_retained()
        with self.assertRaises(LifecycleError):
            self.launch()
        with patch.object(self.store._policy, "prepare",
                          side_effect=AssertionError("reminted committed claim policy nonce")):
            self.owner.restore()
        self.assertIsNone(self.policy_runtime()["policy_entry_nonce"])
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.assertIsNone(self.allocation())
        self.owner.close()
        self.assertEqual(self.native.launch_calls, 0)

    def test_clean_claim_revision_conflict_clears_stale_guard_and_cancels_unused_work(self):
        self.owner.prepare()
        actual_evidence = self.store.evidence_provider
        borrowed = []

        @contextmanager
        def evidence_then_committed_revision_change(operation, row, caller):
            with actual_evidence(operation, row, caller) as proof:
                if operation == "claim":
                    borrowed.append(self.store._policy.current_guard())
                    # A real transaction commits a benign heartbeat revision
                    # after evidence collection, before claim's decision CAS.
                    # Do not fake claim rejection or its rollback/cleanup.
                    with self.store._transaction() as connection:
                        self.store._cas(connection, self.execution_id,
                            row["state_revision"], {"heartbeat_at": row["heartbeat_at"] + 1})
                yield proof

        with patch.object(self.store, "evidence_provider",
                          side_effect=evidence_then_committed_revision_change):
            with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
                self.launch()
        self.assertEqual(len(borrowed), 1)
        self.assertTrue(borrowed[0].clean_rejection)
        self.assertIsNone(self.policy_runtime()["policy_entry_nonce"])
        self.assertIsNone(self.owner._recovery_guard)
        self.assertFalse(self.row()["claim_consumed"])
        self.assertFalse(self.row()["launch_in_flight"])
        self.assertIsNone(self.owner.process)
        self.assertEqual(self.native.launch_calls, 0)
        self.assert_floor_retained()
        with self.assertRaises(LifecycleError):
            self.launch()
        self.owner.restore()
        result = self.owner.finalize()
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertTrue(result["cancelled"])
        self.assertIsNone(self.allocation())
        self.owner.close()
        self.assertEqual(self.native.launch_calls, 0)

    def test_changed_pending_policy_nonce_cannot_be_cleared_or_replaced_for_restore(self):
        self.running()
        self.owner.job.set_error_after_apply = OSError("synthetic_set_reply_lost")
        with self.assertRaisesRegex(OSError, "synthetic_set_reply_lost"):
            self.owner.set_cpu_rate(2500)
        retained = self.owner._recovery_guard
        self.assertIsNotNone(retained)
        self.assertEqual(self.policy_runtime()["policy_entry_nonce"], retained.nonce)
        foreign_nonce = str(uuid.uuid4())
        # Explicit isolated DB fault: another ownership entry replaces ours.
        # Neither restored native state nor a fabricated fresh guard is proof
        # that we may erase that entry or act under its custody.
        with self.store._transaction() as connection:
            connection.execute("UPDATE adaptive_runtime SET policy_entry_nonce=? WHERE singleton=1",
                               (foreign_nonce,))
        with patch.object(self.store._policy, "prepare",
                          side_effect=AssertionError("replaced another policy entry")), \
                patch.object(self.owner.job, "disable",
                             side_effect=AssertionError("restored under foreign ownership")):
            with self.assertRaisesRegex(LifecycleError, "case_recovery_policy_changed"):
                self.owner.restore()
        self.assertEqual(self.policy_runtime()["policy_entry_nonce"], foreign_nonce)
        self.assertIs(self.owner._recovery_guard, retained)
        self.assertIsNotNone(self.manifest().pending_intent)
        self.assertEqual(self.owner.job.control, {"flags": 5, "rate_bp": 2500})
        self.assert_floor_retained()
        self.assertFalse(self.owner.job.closed)
        self.assertFalse(self.owner.process.closed)

    def test_root_exit_with_surviving_child_keeps_allocation_and_handles(self):
        process = self.running()
        process.exited = True
        self.owner.job.members[:] = [process.identity.pid + 1]
        row = self.row()
        draining = self.store.mark_root_exited(self.execution_id, caller=self.owner.caller,
            expected_revision=row["state_revision"], exit_code=0)
        self.assertEqual(draining["state"], "DRAINING")
        with self.assertRaisesRegex(LifecycleError, "job_empty_unverified"):
            self.owner.finalize()
        self.assert_floor_retained()
        self.assertFalse(process.closed)
        self.assertFalse(self.owner.job.closed)

    def test_success_requires_restored_current_cpu_and_settled_manifest_then_close(self):
        process = self.running()
        self.owner.set_cpu_rate(2500)
        self.assertEqual(self.manifest().last_applied.mode, CpuControlMode.HARD_CAP)
        self.make_empty()
        self.owner.restore()
        self.assertEqual(self.owner.job.control["flags"], 0)
        manifest = self.manifest()
        self.assertIsNone(manifest.pending_intent)
        self.assertTrue(manifest.last_applied is None or
                        manifest.last_applied.mode is CpuControlMode.DISABLED)
        result = self.owner.finalize()
        self.assertEqual(result["state"], "FINISHED")
        self.assertIsNone(self.allocation())
        self.assertFalse(process.closed)
        self.assertFalse(self.owner.job.closed)
        self.owner.close()
        self.assertTrue(process.closed)
        self.assertTrue(self.owner.job.closed)
        self.assertTrue(self.owner.mutex.closed)
        self.assertEqual(self.current_process.closes, 1)

    def test_empty_job_with_active_cpu_cap_cannot_release_allocation(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        self.make_empty()
        self.assertTrue(self.owner._control_pending)
        with self.assertRaisesRegex(LifecycleError, "case_control_recovery_unverified"):
            self.owner.finalize()
        self.assert_floor_retained()
        self.assertFalse(self.owner.job.closed)

    def test_cpu_disabled_without_settled_durable_record_does_not_release(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        self.make_empty()
        # Synthetic native Query changes without a matching journal update.
        # A disabled flag cannot clear the owner's pending recovery obligation.
        # Verified restore/journal/slot acknowledgement must settle it first.
        self.owner.job.control = {"flags": 0, "rate_bp": 0}
        self.assertTrue(self.owner._control_pending)
        with self.assertRaisesRegex(LifecycleError, "case_control_recovery_unverified"):
            self.owner.finalize()
        self.assert_floor_retained()

    def test_restrictive_intent_is_durable_before_native_set(self):
        self.running()
        def before_set(rate_bp):
            self.owner.assert_held()
            manifest = self.manifest()
            self.assertIsNotNone(manifest.pending_intent)
            self.assertEqual(manifest.pending_intent.old.mode, CpuControlMode.DISABLED)
            self.assertEqual(manifest.pending_intent.new.cpu_rate_bp, rate_bp)
            self.assertIsNone(manifest.last_applied)
        self.owner.job.set_observer = before_set
        self.owner.set_cpu_rate(2500)
        self.assertIsNone(self.manifest().pending_intent)
        self.assertEqual(self.manifest().last_applied.cpu_rate_bp, 2500)

    def test_failed_mutex_release_preserves_primary_and_retries_exact_release_before_recovery(self):
        self.running()
        primary = OSError("synthetic_set_reply_lost")
        self.owner.job.set_error_after_apply = primary
        mutex = self.owner.mutex
        mutex.release_error_once = OSError("synthetic_release_failed")
        with self.assertRaisesRegex(OSError, "synthetic_set_reply_lost") as caught:
            self.owner.set_cpu_rate(2500)
        self.assertIs(caught.exception, primary)
        self.assertIn("case_mutex_release_unverified", primary.__notes__)
        self.assertIs(self.owner.mutex, mutex)
        self.assertTrue(mutex.acquired)
        self.assertIsNotNone(self.owner._release_uncertain_thread)
        boundary = len(self.events)
        self.owner.restore()
        mutex_events = [event for event in self.events[boundary:] if event.startswith("mutex.")]
        self.assertEqual(mutex_events[:2], ["mutex.release", "mutex.acquire"])
        self.assertIsNone(self.owner._release_uncertain_thread)
        self.assertFalse(mutex.acquired)
        self.make_empty()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.owner.close()

    def test_uncertain_set_can_restore_then_finalize_without_losing_its_policy_scope(self):
        self.running()
        self.owner.job.set_error_after_apply = OSError("synthetic_set_reply_lost")
        with self.assertRaisesRegex(OSError, "synthetic_set_reply_lost"):
            self.owner.set_cpu_rate(2500)
        retained_guard = self.owner._recovery_guard
        self.assertIsNotNone(retained_guard)
        self.assertIsNotNone(self.manifest().pending_intent)
        self.assertEqual(self.owner.job.control, {"flags": 5, "rate_bp": 2500})
        self.assert_floor_retained()
        self.assertIn(self.owner, self.authority.retained)
        # The real PolicyCoordinator must reuse and verify the exact retained
        # entry, not generate another nonce to erase a failed Set's custody.
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("reminted policy nonce")):
            self.owner.restore()
        self.assertIsNone(self.owner._recovery_guard)
        self.assertEqual(self.owner.job.control["flags"], 0)
        self.assertIsNone(self.manifest().pending_intent)
        self.make_empty()
        result = self.owner.finalize()
        self.assertEqual(result["state"], "FINISHED")
        self.assertIsNone(self.allocation())
        self.owner.close()

    def test_never_prepared_owner_can_cancel_its_unused_reservation(self):
        result = self.owner.finalize()
        self.assertTrue(result["cancelled"])
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertEqual((self.native.create_calls, self.native.launch_calls), (0, 0))
        self.assertIsNone(self.allocation())
        self.owner.close()

    def test_precreated_empty_unused_job_can_cancel_only_after_verified_settlement(self):
        self.owner.prepare()
        result = self.owner.finalize()
        self.assertTrue(result["cancelled"])
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(self.native.launch_calls, 0)
        self.assertIsNone(self.allocation())
        self.owner.close()
        self.assertTrue(self.owner.job.closed)

    def test_exclusion_failure_prevents_create_and_keeps_original_scope(self):
        self.authority.exclusion_error = LifecycleError("synthetic_exclusion_missing")
        with self.assertRaisesRegex(LifecycleError, "synthetic_exclusion_missing"):
            self.owner.prepare()
        self.assertEqual(self.native.create_calls, 0)
        row = self.row()
        self.assertEqual(row["state"], "RESERVED")
        self.assertEqual(row["job_name"], self.owner.job_name)
        self.assertEqual(self.manifest().creation_nonce, self.owner.creation_nonce)
        self.assert_floor_retained()
        self.assertIn(self.owner, self.authority.retained)
        # The same live owner knows creation was never attempted; this fact is
        # not reconstructed from the file or from a failed native Open call.
        cancelled = self.owner.finalize()
        self.assertTrue(cancelled["cancelled"])
        self.assertIsNone(self.allocation())
        self.assertEqual(self.native.create_calls, 0)
        self.owner.close()

    def test_native_create_uncertainty_cannot_be_treated_as_never_created(self):
        self.native.create_error = OSError("synthetic_create_reply_lost")
        with self.assertRaisesRegex(OSError, "synthetic_create_reply_lost"):
            self.owner.prepare()
        self.assertEqual(self.native.create_calls, 1)
        self.assertIsNone(self.owner.job)
        with self.assertRaises(LifecycleError):
            self.owner.prepare()
        with self.assertRaises((LifecycleError, PolicyError)):
            self.owner.finalize()
        self.assert_floor_retained()
        self.assertIn(self.owner, self.authority.retained)
        self.assertNotEqual(self.row()["state"], "CANCELLED_BEFORE_START")

    def test_initial_journal_write_failure_never_creates_job_or_releases_floor(self):
        with patch.object(self.owner.journal, "create", side_effect=OSError("synthetic_journal_failure")):
            with self.assertRaisesRegex(OSError, "synthetic_journal_failure"):
                self.owner.prepare()
        self.assertEqual(self.native.create_calls, 0)
        self.assert_floor_retained()
        self.assertIn(self.owner, self.authority.retained)
        self.assertIsNone(self.owner.job)

    def test_database_scope_failure_prevents_native_creation(self):
        with patch.object(self.store, "register_job_scope", side_effect=sqlite3.OperationalError("synthetic_db_busy")):
            with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic_db_busy"):
                self.owner.prepare()
        self.assertEqual(self.native.create_calls, 0)
        self.assertIsNone(self.row()["job_name"])
        self.assert_floor_retained()
        self.assertIn(self.owner, self.authority.retained)

    def test_root_journal_failure_after_launch_preserves_native_custody_and_claim(self):
        self.owner.prepare()
        with patch.object(self.owner.journal, "publish", side_effect=OSError("synthetic_root_record_failure")):
            with self.assertRaisesRegex(OSError, "synthetic_root_record_failure"):
                self.launch()
        self.assertEqual(self.native.launch_calls, 1)
        self.assertTrue(self.row()["claim_consumed"])
        self.assertIs(self.owner.process, self.native.processes[0])
        self.assertFalse(self.owner.process.closed)
        self.assertFalse(self.owner.job.closed)
        self.assert_floor_retained()
        with self.assertRaises(LifecycleError):
            self.launch()

    def test_bind_database_failure_preserves_created_root_and_durable_identity(self):
        self.owner.prepare()
        with patch.object(self.store, "bind_root", side_effect=sqlite3.OperationalError("synthetic_bind_failure")):
            with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic_bind_failure"):
                self.launch()
        self.assertEqual(self.manifest().root_identity, self.owner.process.identity)
        self.assertEqual(self.row()["state"], "START_UNKNOWN")
        self.assertTrue(self.row()["launch_in_flight"])
        self.assert_floor_retained()
        self.assertFalse(self.owner.process.closed)
        with self.assertRaises(LifecycleError):
            self.launch()
        self.make_empty()
        self.owner.restore()
        self.assertEqual(self.owner.finalize()["state"], "FINISHED")
        self.owner.close()
        self.assertEqual(self.native.launch_calls, 1)

    def test_finalization_transaction_failure_rolls_back_terminal_state_and_allocation(self):
        self.running()
        self.make_empty()
        with patch.object(self.store, "_archive_allocation", side_effect=sqlite3.OperationalError("synthetic_archive_failure")):
            with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic_archive_failure"):
                self.owner.finalize()
        self.assertEqual(self.row()["state"], "RUNNING")
        self.assert_floor_retained()
        self.assertFalse(self.owner.process.closed)
        self.assertFalse(self.owner.job.closed)
        self.assertIn(self.owner, self.authority.retained)

    def test_close_failure_retains_exact_handle_for_cleanup_retry(self):
        process = self.running()
        self.make_empty()
        self.owner.finalize()
        process.close_error = OSError("synthetic_close_failure")
        with self.assertRaisesRegex(OSError, "synthetic_close_failure"):
            self.owner.close()
        self.assertIs(self.owner.process, process)
        self.assertFalse(self.owner.job.closed)
        self.assertFalse(self.owner.mutex.closed)
        process.close_error = None
        self.owner.close()
        self.assertTrue(process.closed)
        self.assertTrue(self.owner.job.closed)
        self.assertTrue(self.owner.mutex.closed)


if __name__ == "__main__":
    unittest.main()
