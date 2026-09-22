"""Portable managed-wrapper orchestration with explicit in-process collaborators.

No DLL, pipe, Job, process, SQLite database or runtime directory is opened.
These cases establish wrapper ordering/custody, not Windows capability or a
production readiness authority. Native and transport behavior have separate tests.
"""
import ctypes as C
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import launcher as module
from sentinel.adaptive.contracts import Priority, ProcessIdentity, ResourceDemand, Role
from sentinel.adaptive.launch_spec import LaunchSpec
from sentinel.adaptive.launch_transport import LaunchResult
from sentinel.adaptive.native_job import CpuState, JobAccess, JobLimits
from sentinel.adaptive.native_launcher import LaunchOutcomeUnknown
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.windows import NativePolicyMutexError


LOGON = "S-1-5-5-100-200"
EXECUTION = "12345678-1234-4234-8234-123456789abc"
INSTANCE = "12345678-1234-4234-8234-123456789abd"
NONCE = "a" * 32
JOB_NAME = f"Local\\ResourceSentinel.Job.{EXECUTION}.{NONCE}"
GUARDIAN = "fixture-guardian"
SPEC_HASH = "b" * 64
REQUEST_KEY = "fixture-managed-request"
WRAPPER = ProcessIdentity(500, 134343072000000001, LOGON)
ROOT = ProcessIdentity(501, 134343072000000002, LOGON)
SERVER = ProcessIdentity(502, 134343072000000003, LOGON)
ENDPOINT = NativePipeEndpoint(LOGON, INSTANCE, SERVER)
CMD = r"C:\Windows\System32\cmd.exe"
SPEC = LaunchSpec(command='echo "private-command-marker" && echo %FIXTURE_VALUE% & exit /b 125',
                  cwd=r"C:\private-cwd-marker\workspace", repo_identifier="fixture-repo",
                  requested=ResourceDemand(1, 512 << 20, 768 << 20, 1),
                  role=Role.BACKGROUND, priority=Priority.P2, admission_timeout_sec=0)
STDIO = dict(stdin_handle=101, stdout_handle=102, stderr_handle=103)


def result(state, revision, *, authorized=False, duplicate=False):
    return LaunchResult(EXECUTION, SPEC_HASH, GUARDIAN, state, revision,
                        JOB_NAME, NONCE, authorized, duplicate)


class Admission:
    def __init__(self, events):
        self.events = events
        self.value = SimpleNamespace(execution_id=EXECUTION, spec_hash=SPEC_HASH,
            requested=SPEC.requested, role=SPEC.role, priority=SPEC.priority,
            logon_id=LOGON, wrapper_identity=WRAPPER,
            request=SimpleNamespace(request_key=REQUEST_KEY))
        self.payloads = []
        self.close_calls = 0
        self.close_error = None
        self.prepare_attempted = False

    def snapshot(self):
        return self.value

    def snapshot_for_ledger(self, path):
        self.events.append(("snapshot_for_ledger", path))
        return self.value

    def mark_prepare_attempted(self):
        self.prepare_attempted = True
        self.events.append(("prepare.boundary",))

    def verify_launch_payload(self, *, command, cwd):
        self.payloads.append((command, cwd))
        if (command, cwd) != (SPEC.command, SPEC.cwd):
            raise AssertionError("fixture received altered admission payload")

    def close(self):
        self.close_calls += 1
        self.events.append(("admission.close",))
        if self.close_error is not None:
            raise self.close_error


class Coordinator:
    db_path = "fixture-ledger-never-opened"

    def __init__(self, events):
        self.events = events
        self.calls = []
        self.responses = [dict(allowed=True, request_key=REQUEST_KEY,
            execution_id=EXECUTION, state="RESERVED", state_revision=0,
            reservation_id="fixture-reservation", launch_authorized=False)]
        # The wrapper may observe root exit, but must never release this floor.
        self.reservation_retained = True
        self.reconcile_calls = []
        self.cancel_calls = []
        self.reconciliation = self.cancellation = None

    def admit_managed(self, context, status, *, config):
        self.calls.append((context, status, config))
        self.events.append(("admit",))
        value = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(value, BaseException):
            raise value
        return value

    def reconcile_managed(self, context):
        self.reconcile_calls.append(context)
        if self.reconciliation is not None:
            return dict(self.reconciliation)
        return dict(execution_id=EXECUTION, request_key=REQUEST_KEY,
                    state="QUEUED", allowed=False, launch_authorized=False)

    def cancel_managed(self, context, **arguments):
        self.cancel_calls.append((context, dict(arguments)))
        if isinstance(self.cancellation, BaseException):
            raise self.cancellation
        if self.cancellation is not None:
            return dict(self.cancellation)
        result = dict(cancelled=True, execution_id=EXECUTION, request_key=REQUEST_KEY)
        if arguments:
            result.update(state="CANCELLED_BEFORE_START", reservation_id=arguments["reservation_id"],
                          state_revision=arguments["expected_revision"] + 1)
            self.reservation_retained = False
        else:
            result.update(state="QUEUED_CANCELLED")
        return result


class Client:
    def __init__(self, events):
        self.events = events
        self.calls = []
        self.responses = {"prepare": result("PREPARED", 1),
                          "claim": result("LAUNCHING", 2, authorized=True),
                          "bind": result("RUNNING", 3),
                          "cancel": result("LAUNCHING", 3),
                          "start_failed": None}

    def _call(self, name, arguments):
        self.calls.append((name, arguments))
        self.events.append((name,))
        value = self.responses[name]
        if isinstance(value, BaseException):
            raise value
        return value

    def prepare_execution(self, **arguments):
        return self._call("prepare", arguments)

    def claim_launch(self, **arguments):
        return self._call("claim", arguments)

    def bind_root(self, **arguments):
        return self._call("bind", arguments)

    def cancel_before_start(self, **arguments):
        return self._call("cancel", arguments)

    def start_failed(self, **arguments):
        return self._call("start_failed", arguments)


class Readiness:
    def __init__(self, events):
        self.events = events
        self.calls = []
        self.fail_at = None
        self.error = RuntimeError("fixture_readiness_unavailable")
        self.return_value = None

    def assert_launch_ready(self, context, row, endpoint):
        self.calls.append((context, row, endpoint))
        self.events.append(("ready", len(self.calls)))
        if len(self.calls) == self.fail_at:
            raise self.error
        return self.return_value


class Job:
    def __init__(self, events):
        self.events = events
        self.name, self.nonce, self.logon_sid, self.access = JOB_NAME, NONCE, LOGON, JobAccess.LAUNCH
        self.cpu, self.limits = CpuState(0, 10000), JobLimits(0, 0)
        self.close_calls = 0
        self.close_error = None

    def query_cpu(self):
        return self.cpu

    def query_limits(self):
        return self.limits

    def close(self):
        self.close_calls += 1
        self.events.append(("job.close",))
        if self.close_error is not None:
            raise self.close_error


class Process:
    def __init__(self, events):
        self.events = events
        self.handle, self.pid, self.root = 700, ROOT.pid, ROOT
        self.member = True
        self.exited, self.code = False, 125
        self.wait_error = None
        self.close_calls = 0
        self.close_error = None

    def full_identity(self, *, expected_logon_id):
        self.events.append(("identity", expected_logon_id))
        return self.root

    def is_in_job(self, job):
        self.events.append(("membership", job))
        return self.member

    def wait(self, timeout):
        self.events.append(("wait", timeout))
        if self.wait_error is not None:
            raise self.wait_error
        return self.exited

    def exit_code(self):
        self.events.append(("exit_code",))
        return self.code

    def close(self):
        self.close_calls += 1
        self.events.append(("process.close",))
        if self.close_error is not None:
            raise self.close_error
        self.handle = None


class Mutex:
    def __init__(self, events):
        self.events = events
        self.held = False
        self.abandoned = False
        self.acquire_error = self.release_error = self.close_error = None
        self.before_acquire = None
        self.close_calls = 0

    @contextmanager
    def acquire(self, *, timeout_ms):
        self.events.append(("fence.acquire", timeout_ms))
        if self.acquire_error is not None:
            raise self.acquire_error
        if self.before_acquire is not None:
            self.before_acquire()
        self.held = True
        try:
            yield SimpleNamespace(abandoned=self.abandoned)
        finally:
            self.events.append(("fence.release",))
            if self.release_error is not None:
                raise self.release_error
            self.held = False

    def close(self):
        self.close_calls += 1
        if self.held or self.close_error is not None:
            raise self.close_error or RuntimeError("fixture_mutex_still_owned")
        self.events.append(("fence.close",))


class Store:
    def __init__(self, harness):
        self.harness = harness
        self.row = dict(execution_id=EXECUTION, spec_hash=SPEC_HASH, logon_id=LOGON,
            wrapper_pid=WRAPPER.pid, wrapper_created_filetime_100ns=str(WRAPPER.created_filetime_100ns),
            guardian_epoch=GUARDIAN, reservation_id="fixture-reservation",
            allocation_kind="direct", parent_execution_id=None,
            job_name=JOB_NAME, job_nonce=NONCE, state="LAUNCHING", state_revision=2,
            claim_consumed=1, launch_in_flight=1, launch_sealed=0, cancel_requested_at=None,
            root_pid=None, root_created_filetime_100ns=None, root_outcome=None,
            hold_reason=None, finished_at=None)
        self.coverage_error = self.fence_error = None

    def query(self, execution_id, *, existing_path):
        self.harness.events.append(("ledger.query", execution_id, existing_path, self.harness.mutex.held))
        return dict(self.row)

    def assert_admission_covered(self, admission, row):
        self.harness.events.append(("ledger.coverage", self.harness.mutex.held))
        if self.coverage_error is not None:
            raise self.coverage_error

    def assert_launch_fence(self, row, *, version):
        self.harness.events.append(("ledger.fence", version, self.harness.mutex.held))
        if self.fence_error is not None:
            raise self.fence_error


class Harness:
    def __init__(self):
        self.events = []
        self.admission = Admission(self.events)
        self.coordinator = Coordinator(self.events)
        self.client, self.readiness = Client(self.events), Readiness(self.events)
        self.job, self.process = Job(self.events), Process(self.events)
        self.admission_factory = Mock(return_value=self.admission)
        self.client_factory = Mock(return_value=self.client)
        self.job_factory = Mock(side_effect=self.open_job)
        self.native_launch = Mock(side_effect=self.launch)
        self.resolver = Mock(return_value=CMD)
        self.mutex = Mutex(self.events)
        self.mutex_factory = Mock(return_value=self.mutex)
        self.store = Store(self)

    def open_job(self, *args, **kwargs):
        self.events.append(("open_job",))
        return self.job

    def launch(self, *args, **kwargs):
        self.events.append(("create",))
        return self.process

    def build(self, **overrides):
        arguments = dict(coordinator=self.coordinator, endpoint=ENDPOINT, guardian_epoch=GUARDIAN,
            readiness=self.readiness, admission_factory=self.admission_factory,
            client_factory=self.client_factory, job_factory=self.job_factory,
            launch=self.native_launch, cmd_resolver=self.resolver, mutex_factory=self.mutex_factory)
        arguments.update(overrides)
        launcher = module.ManagedLauncher(SPEC, **arguments)
        # Explicit portable ledger double; separate store tests use real SQLite.
        launcher._store = self.store
        return launcher

    def admitted(self, **overrides):
        launcher = self.build(**overrides)
        launcher.admit_once({"fixture_status": True}, config={"fixture_config": True})
        return launcher

    def bound(self):
        launcher = self.admitted()
        launcher.launch_once(**STDIO)
        return launcher


class ManagedLauncherTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(C, "WinDLL", side_effect=AssertionError("portable launcher attempted DLL load"), create=True)
        guard.start()
        self.addCleanup(guard.stop)

    def assert_sealed(self, launcher, harness, *, native_count):
        self.assertEqual(launcher.phase, "UNCERTAIN")
        calls = list(harness.client.calls)
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_attempt_sealed"):
            launcher.launch_once(**STDIO)
        self.assertEqual(harness.client.calls, calls)
        self.assertEqual(harness.native_launch.call_count, native_count)
        self.assertEqual(harness.admission.close_calls, 0)
        self.assertEqual(harness.job.close_calls, 0)
        self.assertEqual(harness.process.close_calls, 0)
        self.assertTrue(harness.coordinator.reservation_retained)

    def test_queued_and_uncertain_admission_retries_keep_context_key_and_original_payload(self):
        h = Harness()
        allowed = dict(h.coordinator.responses[0])
        original = OSError("fixture_admission_ack_lost")
        h.coordinator.responses = [dict(allowed=False, request_key=REQUEST_KEY, reason="queued", position=1), original, allowed]
        launcher = h.build()
        self.assertEqual(launcher.admission_timeout_sec, 0)
        first = launcher.admit_once({"sample": 1}, config={"version": 1})
        self.assertFalse(first["allowed"])
        self.assertEqual(launcher.phase, "QUEUED")
        with self.assertRaises(OSError) as failed:
            launcher.admit_once({"sample": 2}, config={"version": 1})
        self.assertIs(failed.exception, original)
        self.assertIs(original.launcher_owner, launcher)
        self.assertEqual(launcher.phase, "ADMISSION_UNKNOWN")
        self.assertTrue(launcher.admit_once({"sample": 3}, config={"version": 1})["allowed"])
        self.assertTrue(launcher.admit_once({"sample": 4})["allowed"])
        self.assertEqual(len(h.coordinator.calls), 3)
        self.assertTrue(all(call[0] is h.admission for call in h.coordinator.calls))
        h.admission_factory.assert_called_once_with(command=SPEC.command, cwd=SPEC.cwd,
            repo_identifier=SPEC.repo_identifier, requested=SPEC.requested, role=SPEC.role, priority=SPEC.priority)
        h.client_factory.assert_called_once_with(h.admission, ENDPOINT, guardian_epoch=GUARDIAN)
        self.assertEqual(h.admission.close_calls, 0)
        h.native_launch.assert_not_called()

    def test_admission_response_binding_is_validated_before_any_launch(self):
        for changes in ({"allowed": 1}, {"request_key": "other"}, {"execution_id": INSTANCE},
                        {"state": "RUNNING"}, {"state_revision": True}, {"state_revision": -1},
                        {"reservation_id": ""}, {"launch_authorized": True}):
            with self.subTest(changes=changes):
                h = Harness()
                h.coordinator.responses[0].update(changes)
                launcher = h.build()
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_admission_response_invalid"):
                    launcher.admit_once({})
                self.assertEqual(launcher.phase, "ADMISSION_UNKNOWN")
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
                    launcher.close_local()
                self.assertEqual(h.client.calls, [])
                h.native_launch.assert_not_called()

    def test_default_or_boolean_readiness_never_authorizes_launch(self):
        for use_default in (True, False):
            with self.subTest(default=use_default):
                h = Harness()
                h.readiness.return_value = True
                launcher = h.admitted(readiness=None if use_default else h.readiness)
                with self.assertRaises(module.ManagedLaunchError):
                    launcher.launch_once(**STDIO)
                self.assertEqual(launcher.phase, "RESERVED")
                self.assertEqual(h.client.calls, [])
                h.job_factory.assert_not_called()
                h.native_launch.assert_not_called()
                self.assertEqual(h.admission.close_calls, 0)

    def test_invalid_local_inputs_fail_before_rpc_and_do_not_consume_attempt(self):
        h = Harness()
        launcher = h.admitted()
        cases = ({"stdin_handle": True}, {"stdout_handle": 0}, {"stderr_handle": -1},
                 {"timeout_ms": 0}, {"timeout_ms": 1001}, {"timeout_ms": True})
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(module.ManagedLaunchError):
                launcher.launch_once(**(STDIO | changes))
        self.assertEqual(h.client.calls, [])
        launcher.launch_once(**STDIO)
        self.assertEqual(h.native_launch.call_count, 1)

    def test_success_orders_three_guards_exact_claim_and_native_bind_without_raw_rpc_payload(self):
        h = Harness()
        launcher = h.admitted()
        self.assertIs(launcher.launch_once(**STDIO, timeout_ms=800), h.process)
        self.assertEqual(launcher.phase, "BOUND")
        stages = [event for event in h.events if event[0] in {"ready", "prepare", "open_job", "claim", "create", "identity", "membership", "bind"}]
        self.assertEqual([event[0] for event in stages],
                         ["ready", "prepare", "open_job", "ready", "claim", "ready", "create", "identity", "membership", "bind"])
        self.assertEqual([call[1]["state"] for call in h.readiness.calls], ["RESERVED", "PREPARED", "LAUNCHING"])
        self.assertTrue(all(call[0] is h.admission and call[2] is ENDPOINT for call in h.readiness.calls))
        h.job_factory.assert_called_once_with(JOB_NAME, NONCE, LOGON, access=JobAccess.LAUNCH)
        h.native_launch.assert_called_once_with(h.job, CMD, f'"{CMD}" /d /s /c "{SPEC.command}"', cwd=SPEC.cwd, **STDIO)
        prepare, claim, bind = [call[1] for call in h.client.calls]
        self.assertEqual(prepare["expected_revision"], 0)
        self.assertEqual(claim["expected_revision"], 1)
        self.assertEqual(bind["expected_revision"], 2)
        self.assertEqual(claim["job_nonce"], NONCE)
        self.assertEqual(claim["launch_fence_version"], 1)
        self.assertEqual(bind["job_nonce"], NONCE)
        self.assertEqual(bind["root_identity"], ROOT)
        self.assertEqual(bind["root_handle_locator"], 700)
        self.assertEqual({call["timeout_ms"] for call in (prepare, claim, bind)}, {800})
        self.assertEqual(len({call["request_id"] for call in (prepare, claim, bind)}), 3)
        self.assertNotIn(SPEC.command, repr(h.client.calls))
        self.assertNotIn(SPEC.cwd, repr(h.client.calls))
        self.assertTrue(all(payload == (SPEC.command, SPEC.cwd) for payload in h.admission.payloads))
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_attempt_sealed"):
            launcher.launch_once(**STDIO)
        self.assertEqual(h.native_launch.call_count, 1)

    def test_launch_fence_spans_fresh_coverage_and_exactly_one_create_but_no_ipc_or_readiness(self):
        h = Harness()
        launcher = h.admitted()
        def create(*args, **kwargs):
            self.assertTrue(h.mutex.held)
            return h.process
        h.native_launch.side_effect = create
        client_call, ready = h.client._call, h.readiness.assert_launch_ready
        def rpc(name, arguments):
            self.assertFalse(h.mutex.held, "IPC inside Job fence inverts guardian lock ordering")
            return client_call(name, arguments)
        def readiness(*args):
            self.assertFalse(h.mutex.held, "readiness can acquire POLICY and must precede Job")
            return ready(*args)
        h.client._call, h.readiness.assert_launch_ready = rpc, readiness
        launcher.launch_once(**STDIO, timeout_ms=800)
        h.mutex_factory.assert_called_once_with(LOGON, module.job_mutex_instance(EXECUTION, NONCE))
        events = [event for event in h.events if event[0].startswith(("fence.", "ledger."))]
        self.assertEqual(events, [("fence.acquire", 800), ("ledger.query", EXECUTION, True, True),
            ("ledger.coverage", True), ("ledger.fence", 1, True), ("fence.release",)])
        self.assertEqual(h.native_launch.call_count, 1)

    def test_delayed_launch_rechecks_cancel_terminal_revision_identity_and_seal_after_acquiring_fence(self):
        cases = ({"state": "START_FAILED"}, {"state_revision": 3}, {"cancel_requested_at": 123},
                 {"launch_sealed": 1}, {"claim_consumed": 0}, {"launch_in_flight": 0},
                 {"root_pid": ROOT.pid}, {"root_outcome": "exited"}, {"hold_reason": "held"},
                 {"reservation_id": "other"}, {"wrapper_created_filetime_100ns": "1"},
                 {"job_nonce": "b" * 32}, {"guardian_epoch": "other"}, {"spec_hash": "c" * 64})
        for changes in cases:
            with self.subTest(changes=changes):
                h = Harness()
                h.mutex.before_acquire = lambda: h.store.row.update(changes)
                launcher = h.admitted()
                with self.assertRaises(module.ManagedLaunchError):
                    launcher.launch_once(**STDIO)
                self.assertFalse(h.mutex.held)
                self.assert_sealed(launcher, h, native_count=0)
                self.assertFalse(any(event[0] == "ledger.fence" for event in h.events))

    def test_fence_rejects_absent_state_fields_lost_capacity_and_unbound_protocol(self):
        for failure in ("missing_cancel", "capacity", "protocol"):
            with self.subTest(failure=failure):
                h = Harness()
                if failure == "missing_cancel":
                    del h.store.row["cancel_requested_at"]
                elif failure == "capacity":
                    h.store.coverage_error = RuntimeError("fixture_capacity_lost")
                else:
                    h.store.fence_error = RuntimeError("fixture_protocol_unbound")
                launcher = h.admitted()
                with self.assertRaises(RuntimeError):
                    launcher.launch_once(**STDIO)
                self.assertFalse(h.mutex.held)
                self.assert_sealed(launcher, h, native_count=0)

    def test_abandoned_unknown_or_timed_out_mutex_never_creates_and_owner_stays_reachable(self):
        for failure in (True, None, "timeout"):
            with self.subTest(failure=failure):
                h = Harness()
                if failure == "timeout":
                    h.mutex.acquire_error = RuntimeError("fixture_fence_timeout")
                else:
                    h.mutex.abandoned = failure
                launcher = h.admitted()
                with self.assertRaises(RuntimeError) as failed:
                    launcher.launch_once(**STDIO)
                self.assertIs(failed.exception.launcher_owner, launcher)
                self.assertIs(launcher._launch_mutex, h.mutex)
                self.assertEqual(h.mutex.close_calls, 0)
                self.assert_sealed(launcher, h, native_count=0)

    def test_uncertain_fence_release_after_creation_retains_process_and_refuses_failed_start(self):
        h = Harness()
        h.mutex.release_error = RuntimeError("fixture_fence_release_unknown")
        launcher = h.admitted()
        with self.assertRaisesRegex(RuntimeError, "fixture_fence_release_unknown"):
            launcher.launch_once(**STDIO)
        self.assertIs(launcher.process, h.process)
        self.assertTrue(h.mutex.held)
        self.assert_sealed(launcher, h, native_count=1)
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_retirement_native_outcome_retained"):
            launcher.retire_before_start(kind="start_failed")
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim"])

    def test_failed_create_ancillary_cleanup_is_retained_and_retried_only_after_terminal_ack(self):
        h = Harness()
        # Real launch failures retain a CreatedProcess, whose internal resource
        # states already quarantine ambiguous closes and retry known failures.
        ancillary = Mock(spec=module.native_launcher.CreatedProcess)
        ancillary.close.side_effect = RuntimeError("fixture_ancillary_close_failed")
        error = RuntimeError("fixture_known_create_failed")
        error.cleanup_owner = ancillary
        h.native_launch.side_effect = error
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        self.assertEqual(ancillary.close.call_count, 0)
        h.client.responses["start_failed"] = result("START_FAILED", 3)
        launcher.retire_before_start(kind="start_failed")
        with self.assertRaisesRegex(RuntimeError, "fixture_ancillary_close_failed"):
            launcher.close_local()
        self.assertNotEqual(launcher.phase, "CLOSED")
        self.assertEqual(ancillary.close.call_count, 1)
        ancillary.close.side_effect = None
        launcher.close_local()
        self.assertEqual(ancillary.close.call_count, 2)
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual(h.native_launch.call_count, 1)

    def test_preclaim_cancel_terminal_ack_allows_only_local_cleanup(self):
        h = Harness()
        h.readiness.fail_at = 2
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        h.store.row.update(state="PREPARED", state_revision=1, claim_consumed=0, launch_in_flight=0)
        h.client.responses["cancel"] = result("CANCELLED_BEFORE_START", 2)
        response = launcher.retire_before_start()
        self.assertEqual(response.state, "CANCELLED_BEFORE_START")
        self.assertEqual(launcher.phase, "RETIRED")
        self.assertEqual(h.job.close_calls, 0)
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual((h.job.close_calls, h.admission.close_calls), (1, 1))
        self.assertEqual(h.process.close_calls, 0)
        self.assertTrue(h.coordinator.reservation_retained)
        h.native_launch.assert_not_called()

    def test_failed_start_lost_ack_replays_original_revision_and_request_without_fresh_launch(self):
        h = Harness()
        h.readiness.fail_at = 3
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        h.client.responses["start_failed"] = OSError("fixture_terminal_ack_lost")
        with self.assertRaises(OSError):
            launcher.retire_before_start(kind="start_failed")
        original = dict(h.client.calls[-1][1])
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
            launcher.close_local()
        h.store.row.update(state="START_FAILED", state_revision=3, launch_sealed=1)
        h.client.responses["start_failed"] = result("START_FAILED", 3, duplicate=True)
        reply = launcher.retire_before_start(kind="start_failed")
        self.assertEqual(h.client.calls[-1][1], original)
        self.assertEqual(original["expected_revision"], 2)
        self.assertIs(launcher.retire_before_start(kind="start_failed"), reply)
        self.assertEqual(len([call for call in h.client.calls if call[0] == "start_failed"]), 2)
        launcher.close_local()
        h.native_launch.assert_not_called()

    def test_postclaim_cancel_ack_stays_pending_and_cannot_release_local_custody(self):
        h = Harness()
        h.readiness.fail_at = 3
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        response = launcher.retire_before_start(kind="cancel")
        self.assertEqual(response.state, "LAUNCHING")
        self.assertEqual(launcher.phase, "CANCEL_PENDING")
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
            launcher.close_local()
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_attempt_sealed"):
            launcher.launch_once(**STDIO)
        self.assertEqual(h.job.close_calls, 0)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_retirement_rejects_wrong_scope_or_kind_ack_and_never_closes_on_uncertainty(self):
        for reply in (result("START_FAILED", 3), result("LAUNCHING", 3, authorized=True),
                      replace(result("CANCELLED_BEFORE_START", 3), guardian_epoch="other")):
            with self.subTest(reply=reply):
                h = Harness()
                h.readiness.fail_at = 3
                launcher = h.admitted()
                with self.assertRaises(RuntimeError):
                    launcher.launch_once(**STDIO)
                h.client.responses["cancel"] = reply
                with self.assertRaises(module.ManagedLaunchError):
                    launcher.retire_before_start()
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
                    launcher.close_local()
                h.native_launch.assert_not_called()

    def test_retirement_never_treats_unknown_native_result_or_started_root_as_start_failed(self):
        for unknown in (True, False):
            with self.subTest(unknown=unknown):
                h = Harness()
                launcher = h.admitted()
                if unknown:
                    h.native_launch.side_effect = LaunchOutcomeUnknown(h.process, RuntimeError("fixture_unknown"))
                    with self.assertRaises(LaunchOutcomeUnknown):
                        launcher.launch_once(**STDIO)
                else:
                    launcher.launch_once(**STDIO)
                calls = list(h.client.calls)
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_retirement_native_outcome_retained"):
                    launcher.retire_before_start(kind="start_failed")
                self.assertEqual(h.client.calls, calls)
                self.assertEqual(h.process.close_calls, 0)

    def test_each_readiness_failure_stops_the_next_mutation_and_only_initial_failure_can_retry(self):
        for index in (1, 2, 3):
            with self.subTest(index=index):
                h = Harness()
                h.readiness.fail_at = index
                launcher = h.admitted()
                with self.assertRaises(RuntimeError) as failed:
                    launcher.launch_once(**STDIO)
                self.assertIs(failed.exception, h.readiness.error)
                self.assertEqual([call[0] for call in h.client.calls], {1: [], 2: ["prepare"], 3: ["prepare", "claim"]}[index])
                h.native_launch.assert_not_called()
                if index == 1:
                    h.readiness.fail_at = None
                    launcher.launch_once(**STDIO)
                    self.assertEqual(h.native_launch.call_count, 1)
                else:
                    self.assertIs(failed.exception.launcher_owner, launcher)
                    self.assert_sealed(launcher, h, native_count=0)

    def test_prepare_or_claim_ack_loss_seals_attempt_without_create_or_cleanup(self):
        for stage in ("prepare", "claim"):
            with self.subTest(stage=stage):
                h = Harness()
                original = h.client.responses[stage] = OSError("fixture_mutation_ack_lost")
                launcher = h.admitted()
                with self.assertRaises(OSError) as failed:
                    launcher.launch_once(**STDIO)
                self.assertIs(failed.exception, original)
                self.assertIs(original.launcher_owner, launcher)
                self.assert_sealed(launcher, h, native_count=0)

    def test_typed_ack_fields_and_untyped_reply_are_revalidated_at_every_stage(self):
        changes = ({"execution_id": INSTANCE}, {"spec_hash": "c" * 64},
                   {"guardian_epoch": "other-guardian"}, {"state": "RESERVED"},
                   {"state_revision": 0}, {"state_revision": True}, {"job_name": "unowned-job"},
                   {"job_nonce": "b" * 32}, {"launch_authorized": 1}, {"duplicate": 1})
        for stage in ("prepare", "claim", "bind"):
            for fields in (*changes, None):
                with self.subTest(stage=stage, fields=fields):
                    h = Harness()
                    reply = replace(h.client.responses[stage])
                    if fields is None:
                        h.client.responses[stage] = reply.to_dict()
                    else:
                        for key, value in fields.items():
                            object.__setattr__(reply, key, value)
                        h.client.responses[stage] = reply
                    launcher = h.admitted()
                    with self.assertRaises(Exception) as failed:
                        launcher.launch_once(**STDIO)
                    self.assertIs(failed.exception.launcher_owner, launcher)
                    self.assert_sealed(launcher, h, native_count=int(stage == "bind"))

    def test_job_open_failure_or_binding_mismatch_never_claims_or_creates(self):
        cases = ({"name": "other"}, {"nonce": "b" * 32}, {"logon_sid": "S-1-5-5-100-201"},
                 {"access": JobAccess.OWNER}, {"cpu": CpuState(5, 4000)}, {"limits": JobLimits(1, 0)}, None)
        for fields in cases:
            with self.subTest(fields=fields):
                h = Harness()
                if fields is None:
                    h.job_factory.side_effect = OSError("fixture_job_open_failed")
                else:
                    for key, value in fields.items():
                        setattr(h.job, key, value)
                launcher = h.admitted()
                with self.assertRaises(Exception):
                    launcher.launch_once(**STDIO)
                self.assertEqual([call[0] for call in h.client.calls], ["prepare"])
                self.assert_sealed(launcher, h, native_count=0)

    def test_duplicate_or_unauthorized_claim_never_permits_create(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                h = Harness()
                h.client.responses["claim"] = result("LAUNCHING", 2, duplicate=duplicate)
                launcher = h.admitted()
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_claim_not_authorized"):
                    launcher.launch_once(**STDIO)
                self.assert_sealed(launcher, h, native_count=0)

    def test_informational_partial_results_never_authorize_ordinary_launch(self):
        for stage, state, revision in (("prepare", "RESERVED", 1), ("claim", "PREPARED", 1)):
            for duplicate in (False, True):
                with self.subTest(stage=stage, duplicate=duplicate):
                    h = Harness()
                    h.client.responses[stage] = result(state, revision, duplicate=duplicate)
                    launcher = h.admitted()
                    with self.assertRaises(module.ManagedLaunchError):
                        launcher.launch_once(**STDIO)
                    self.assertEqual([call[0] for call in h.client.calls],
                                     ["prepare"] if stage == "prepare" else ["prepare", "claim"])
                    self.assertEqual(h.job_factory.call_count, int(stage == "claim"))
                    self.assert_sealed(launcher, h, native_count=0)

    def test_changed_cmd_resolution_after_claim_seals_without_create(self):
        h = Harness()
        h.resolver.side_effect = [CMD, r"C:\other\cmd.exe"]
        launcher = h.admitted()
        with self.assertRaisesRegex(module.ManagedLaunchError, "system_cmd_changed"):
            launcher.launch_once(**STDIO)
        self.assertEqual(h.resolver.call_args_list[0].args, (None,))
        self.assertEqual(h.resolver.call_args_list[1].args, (CMD,))
        self.assert_sealed(launcher, h, native_count=0)

    def test_native_unknown_retains_exact_original_process_without_bind_or_second_create(self):
        h = Harness()
        original = LaunchOutcomeUnknown(h.process, RuntimeError("fixture_native_unknown"))
        h.native_launch.side_effect = original
        launcher = h.admitted()
        with self.assertRaises(LaunchOutcomeUnknown) as failed:
            launcher.launch_once(**STDIO)
        self.assertIs(failed.exception, original)
        self.assertIs(launcher.process, h.process)
        self.assertIs(original.launcher_owner, launcher)
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim"])
        self.assert_sealed(launcher, h, native_count=1)

    def test_native_exception_is_not_retried_or_given_an_invented_process(self):
        h = Harness()
        original = h.native_launch.side_effect = KeyboardInterrupt("fixture_native_interruption")
        launcher = h.admitted()
        with self.assertRaises(KeyboardInterrupt) as failed:
            launcher.launch_once(**STDIO)
        self.assertIs(failed.exception, original)
        self.assertIsNone(launcher.process)
        self.assert_sealed(launcher, h, native_count=1)

    def test_root_identity_and_membership_must_be_verified_before_bind(self):
        for root, pid, member in ((WRAPPER, WRAPPER.pid, True), (SERVER, SERVER.pid, True),
                                  (replace(ROOT, logon_id="S-1-5-5-100-201"), ROOT.pid, True),
                                  (ROOT, ROOT.pid + 1, True), (ROOT, ROOT.pid, False),
                                  (ROOT, ROOT.pid, None), (ROOT, ROOT.pid, 1)):
            with self.subTest(root=root, pid=pid, member=member):
                h = Harness()
                h.process.root, h.process.pid, h.process.member = root, pid, member
                launcher = h.admitted()
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_root_binding_unverified"):
                    launcher.launch_once(**STDIO)
                self.assertIs(launcher.process, h.process)
                self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim"])
                self.assert_sealed(launcher, h, native_count=1)

    def test_bind_ack_loss_retains_root_and_reports_exit_without_transfer_ack(self):
        h = Harness()
        original = h.client.responses["bind"] = OSError("fixture_bind_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(OSError) as failed:
            launcher.launch_once(**STDIO)
        self.assertIs(failed.exception, original)
        self.assert_sealed(launcher, h, native_count=1)
        h.process.exited = True
        self.assertEqual(launcher.poll_root(), module.RootObservation(EXECUTION, True, 125, False))
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
            launcher.close_local()
        self.assertEqual(h.process.close_calls, 0)
        self.assertEqual(h.job.close_calls, 0)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_reconcile_bind_replays_exact_original_request_without_repeating_launch_authority(self):
        h = Harness()
        h.client.responses["bind"] = OSError("fixture_bind_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        original_bind = dict(h.client.calls[-1][1])
        readiness_count, resolver_count = len(h.readiness.calls), h.resolver.call_count
        acknowledged = h.client.responses["bind"] = result("RUNNING", 3, duplicate=True)
        self.assertIs(launcher.reconcile_bind(), acknowledged)
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim", "bind", "bind"])
        self.assertEqual(h.client.calls[-1][1], original_bind)
        self.assertEqual(original_bind["root_identity"], ROOT)
        self.assertEqual(original_bind["root_handle_locator"], 700)
        self.assertEqual(original_bind["expected_revision"], 2)
        self.assertEqual(len(h.readiness.calls), readiness_count)
        self.assertEqual(h.resolver.call_count, resolver_count)
        self.assertEqual(h.job_factory.call_count, 1)
        self.assertEqual(h.native_launch.call_count, 1)
        self.assertEqual(launcher.phase, "BOUND")
        self.assertIs(launcher.reconcile_bind(), acknowledged)
        self.assertEqual(len(h.client.calls), 4)
        h.process.exited = True
        self.assertEqual(launcher.poll_root(), module.RootObservation(EXECUTION, True, 125, True))
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.admission.close_calls), (1, 1, 1))
        self.assertEqual(len(h.client.calls), 4)
        self.assertEqual(h.native_launch.call_count, 1)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_reconcile_bind_rejects_unknown_create_or_unverified_root_without_rpc_or_relaunch(self):
        for unknown_create in (True, False):
            with self.subTest(unknown_create=unknown_create):
                h = Harness()
                if unknown_create:
                    h.native_launch.side_effect = LaunchOutcomeUnknown(h.process, RuntimeError("fixture_create_unknown"))
                else:
                    h.process.member = False
                launcher = h.admitted()
                with self.assertRaises((LaunchOutcomeUnknown, module.ManagedLaunchError)):
                    launcher.launch_once(**STDIO)
                calls = list(h.client.calls)
                readiness_count, resolver_count = len(h.readiness.calls), h.resolver.call_count
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_bind_reconciliation_unavailable"):
                    launcher.reconcile_bind()
                self.assertEqual(h.client.calls, calls)
                self.assertEqual(len(h.readiness.calls), readiness_count)
                self.assertEqual(h.resolver.call_count, resolver_count)
                self.assert_sealed(launcher, h, native_count=1)

    def test_bound_fast_exit_and_root_125_preserve_descendant_capacity_without_rpc(self):
        h = Harness()
        h.process.exited = True
        h.client.responses["bind"] = result("DRAINING", 3)
        launcher = h.bound()
        calls = list(h.client.calls)
        observation = launcher.poll_root()
        self.assertEqual(observation, module.RootObservation(EXECUTION, True, 125, True))
        self.assertTrue(h.coordinator.reservation_retained)
        launcher.close_local()
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.admission.close_calls), (1, 1, 1))
        self.assertEqual(h.client.calls, calls)
        self.assertEqual(len(h.coordinator.calls), 1)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_root_polling_unknown_or_inconsistent_values_never_synthesize_exit(self):
        h = Harness()
        launcher = h.bound()
        self.assertEqual(launcher.poll_root(), module.RootObservation(EXECUTION, False, None, True))
        original = h.process.wait_error = OSError("fixture_wait_unavailable")
        with self.assertRaises(OSError) as failed:
            launcher.poll_root()
        self.assertIs(failed.exception, original)
        self.assertIs(original.launcher_owner, launcher)
        h.process.wait_error = None
        for exited, code in ((1, 125), (True, None), (True, True), (True, -1), (True, 0x100000000)):
            h.process.exited, h.process.code = exited, code
            with self.subTest(exited=exited, code=code), self.assertRaises(module.ManagedLaunchError):
                launcher.poll_root()
        h.process.exited, h.process.code = True, 125
        self.assertEqual(launcher.poll_root().exit_code, 125)
        h.process.exited = False
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_root_exit_changed"):
            launcher.poll_root()
        self.assertEqual(len(h.client.calls), 3)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_unsubmitted_launcher_closes_only_local_admission_and_cannot_launch(self):
        h = Harness()
        launcher = h.build()
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_not_admitted"):
            launcher.launch_once(**STDIO)
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_root_unavailable"):
            launcher.poll_root()
        launcher.close_local()
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual(h.admission.close_calls, 1)
        self.assertEqual(h.client.calls, [])
        self.assertEqual(h.coordinator.calls, [])
        h.native_launch.assert_not_called()
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_closed_or_closing"):
            launcher.admit_once({})

    def test_denied_queued_reserved_and_running_contexts_cannot_close_or_release_custody(self):
        for stage in ("denied", "queued", "reserved", "running"):
            with self.subTest(stage=stage):
                h = Harness()
                if stage == "queued":
                    h.coordinator.responses = [dict(allowed=False, request_key=REQUEST_KEY, position=1)]
                elif stage == "denied":
                    h.coordinator.responses = [dict(allowed=False, request_key=REQUEST_KEY, reason="managed_policy_mismatch")]
                launcher = h.admitted()
                if stage in {"queued", "denied"}:
                    self.assertEqual(launcher.phase, "QUEUED" if stage == "queued" else "ADMISSION_DENIED")
                if stage == "running":
                    launcher.launch_once(**STDIO)
                with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_custody_unsettled"):
                    launcher.close_local()
                self.assertEqual((h.process.close_calls, h.job.close_calls, h.admission.close_calls), (0, 0, 0))
                self.assertTrue(h.coordinator.reservation_retained)

    def test_independent_cleanup_preserves_primary_and_retries_only_local_owned_objects(self):
        h = Harness()
        launcher = h.bound()
        h.process.exited = True
        original = h.process.close_error = RuntimeError("fixture_process_cleanup_failed")
        h.job.close_error = RuntimeError("fixture_job_cleanup_failed")
        with self.assertRaises(RuntimeError) as failed:
            launcher.close_local()
        self.assertIs(failed.exception, original)
        self.assertIs(original.launcher_owner, launcher)
        self.assertTrue(original.__notes__)
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.admission.close_calls), (1, 1, 1))
        h.process.close_error = h.job.close_error = None
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual(h.admission.close_calls, 1)
        self.assertEqual(len(h.client.calls), 3)
        self.assertEqual(h.native_launch.call_count, 1)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_known_mutex_close_failure_retries_only_that_owner_and_tombstones_successes(self):
        h = Harness()
        launcher = h.bound()
        h.process.exited = True
        h.mutex.close_error = NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        with self.assertRaises(NativePolicyMutexError):
            launcher.close_local()
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.mutex.close_calls,
                          h.admission.close_calls), (1, 1, 1, 1))
        h.mutex.close_error = None
        launcher.close_local()
        self.assertEqual(launcher.phase, "CLOSED")
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.mutex.close_calls,
                          h.admission.close_calls), (1, 1, 2, 1))

    def test_ambiguous_mutex_close_after_native_effect_never_recloses_recycled_locator(self):
        h = Harness()
        launcher = h.bound()
        h.process.exited = True
        locator = {"owner": "launcher", "native_close_calls": 0}
        def ambiguous_close():
            h.mutex.close_calls += 1
            locator["native_close_calls"] += 1
            self.assertEqual(locator["owner"], "launcher")
            locator["owner"] = "unrelated-reused-handle"
            raise KeyboardInterrupt("fixture_close_effect_then_interrupt")
        h.mutex.close = ambiguous_close
        with self.assertRaises(KeyboardInterrupt):
            launcher.close_local()
        for _ in range(2):
            with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_native_cleanup_outcome_unknown"):
                launcher.close_local()
        self.assertEqual(locator, {"owner": "unrelated-reused-handle", "native_close_calls": 1})
        self.assertEqual((h.process.close_calls, h.job.close_calls, h.admission.close_calls), (1, 1, 1))
        self.assertEqual(h.mutex_factory.call_count, 1)
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_closed_or_closing"):
            launcher.launch_once(**STDIO)

    def test_mutex_close_error_with_cleanup_notes_is_not_known_retryable(self):
        h = Harness()
        launcher = h.bound()
        h.process.exited = True
        error = NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        error.add_note("fixture_other_cleanup_outcome_unknown")
        h.mutex.close_error = error
        with self.assertRaises(NativePolicyMutexError):
            launcher.close_local()
        h.mutex.close_error = None
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_native_cleanup_outcome_unknown"):
            launcher.close_local()
        self.assertEqual(h.mutex.close_calls, 1)

    def test_constructor_retained_opaque_owner_is_quarantined_before_any_new_close(self):
        h = Harness()
        extra = Mutex(h.events)
        error = RuntimeError("fixture_constructor_close_already_ambiguous")
        error._policy_mutex_cleanup = (extra,)
        h.mutex_factory.side_effect = error
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        h.client.responses["start_failed"] = result("START_FAILED", 3)
        launcher.retire_before_start(kind="start_failed")
        for _ in range(2):
            with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_native_cleanup_outcome_unknown"):
                launcher.close_local()
        self.assertEqual(extra.close_calls, 0)
        self.assertEqual((h.job.close_calls, h.admission.close_calls), (1, 1))
        self.assertEqual(h.mutex_factory.call_count, 1)

    def test_constructor_known_close_failure_owner_retries_but_each_success_closes_once(self):
        h = Harness()
        extra = Mutex(h.events)
        error = NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        # Duplicate ownership entries must not produce duplicate closes.
        error._policy_mutex_cleanup = (extra, extra)
        h.mutex_factory.side_effect = error
        launcher = h.admitted()
        with self.assertRaises(NativePolicyMutexError):
            launcher.launch_once(**STDIO)
        h.client.responses["start_failed"] = result("START_FAILED", 3)
        launcher.retire_before_start(kind="start_failed")
        launcher.close_local()
        launcher.close_local()
        self.assertEqual(extra.close_calls, 1)
        self.assertEqual(launcher.phase, "CLOSED")

    def test_opaque_failed_create_cleanup_owner_requires_its_own_positive_retryability(self):
        h = Harness()
        extra = Mutex(h.events)
        error = RuntimeError("fixture_native_failure_with_opaque_cleanup")
        error.cleanup_owner = extra
        h.native_launch.side_effect = error
        launcher = h.admitted()
        with self.assertRaises(RuntimeError):
            launcher.launch_once(**STDIO)
        h.client.responses["start_failed"] = result("START_FAILED", 3)
        launcher.retire_before_start(kind="start_failed")
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_native_cleanup_outcome_unknown"):
            launcher.close_local()
        self.assertEqual(extra.close_calls, 0)

    def test_admission_close_partial_failure_is_permanently_quarantined_without_second_call(self):
        h = Harness()
        launcher = h.bound()
        h.process.exited = True
        original = h.admission.close_error = RuntimeError("fixture_admission_close_unknown")
        with self.assertRaises(RuntimeError) as failed:
            launcher.close_local()
        self.assertIs(failed.exception, original)
        self.assertIs(original.launcher_owner, launcher)
        h.admission.close_error = None
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_admission_cleanup_unknown"):
            launcher.close_local()
        self.assertEqual(h.admission.close_calls, 1)
        self.assertNotEqual(launcher.phase, "CLOSED")
        self.assertEqual(len(h.client.calls), 3)
        self.assertTrue(h.coordinator.reservation_retained)

    def test_constructor_binding_or_client_failure_closes_context_and_preserves_primary(self):
        h = Harness()
        h.admission.value.logon_id = "S-1-5-5-100-201"
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_admission_binding_mismatch"):
            h.build()
        self.assertEqual(h.admission.close_calls, 1)
        h.client_factory.assert_not_called()
        h = Harness()
        original = h.client_factory.side_effect = RuntimeError("fixture_client_initialization_failed")
        h.admission.close_error = OSError("fixture_constructor_cleanup_unknown")
        with self.assertRaises(RuntimeError) as failed:
            h.build()
        self.assertIs(failed.exception, original)
        self.assertTrue(original.__notes__)
        self.assertIs(original.launcher_cleanup_error, h.admission.close_error)
        owner = original.launcher_owner
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_admission_cleanup_unknown"):
            owner.close_local()
        self.assertEqual(h.admission.close_calls, 1)
        h.native_launch.assert_not_called()

    def test_cmd_resolution_failure_happens_before_creating_admission_or_client(self):
        h = Harness()
        original = h.resolver.side_effect = module.ManagedLaunchError("system_cmd_unavailable")
        with self.assertRaises(module.ManagedLaunchError) as failed:
            h.build()
        self.assertIs(failed.exception, original)
        h.admission_factory.assert_not_called()
        h.client_factory.assert_not_called()
        h.native_launch.assert_not_called()

    def test_abandon_before_submission_only_closes_local_context(self):
        h = Harness()
        launcher = h.build()
        outcome = launcher.abandon_once()
        self.assertTrue(outcome["settled"])
        self.assertTrue(outcome["closed"])
        self.assertFalse(outcome["guardian_handoff"])
        self.assertEqual(h.admission.close_calls, 1)
        self.assertEqual(h.coordinator.cancel_calls, [])
        self.assertEqual(h.coordinator.reconcile_calls, [])
        self.assertEqual(h.client.calls, [])
        h.native_launch.assert_not_called()

    def test_queued_abandonment_uses_original_context_without_admission_replay(self):
        h = Harness()
        h.coordinator.responses = [dict(allowed=False, request_key=REQUEST_KEY, position=1)]
        launcher = h.build()
        launcher.admit_once({})
        outcome = launcher.abandon_once()
        self.assertTrue(outcome["settled"])
        self.assertEqual(h.coordinator.reconcile_calls, [h.admission])
        self.assertEqual(h.coordinator.cancel_calls, [(h.admission, {})])
        self.assertEqual(len(h.coordinator.calls), 1)
        self.assertEqual(h.client.calls, [])
        h.native_launch.assert_not_called()

    def test_lost_admission_ack_reconciles_exact_allocation_then_cancels_it(self):
        h = Harness()
        observed = dict(h.coordinator.responses[0], allowed=False)
        h.coordinator.responses = [OSError("fixture_commit_ack_lost")]
        h.coordinator.reconciliation = observed
        launcher = h.build()
        with self.assertRaises(OSError):
            launcher.admit_once({})
        outcome = launcher.abandon_once()
        self.assertTrue(outcome["settled"])
        self.assertEqual(h.coordinator.cancel_calls, [(h.admission, dict(
            reservation_id="fixture-reservation", expected_revision=0))])
        self.assertEqual(len(h.coordinator.calls), 1)
        self.assertFalse(h.coordinator.reservation_retained)
        self.assertEqual(h.client.calls, [])

    def test_lost_reserved_cancellation_ack_keeps_original_target_and_context(self):
        h = Harness()
        launcher = h.admitted()
        h.coordinator.cancellation = OSError("fixture_cancel_ack_lost")
        first = launcher.abandon_once()
        self.assertFalse(first["settled"])
        self.assertEqual(h.admission.close_calls, 0)
        with self.assertRaisesRegex(module.ManagedLaunchError, "launcher_attempt_sealed"):
            launcher.launch_once(**STDIO)
        h.coordinator.cancellation = None
        self.assertTrue(launcher.abandon_once()["settled"])
        self.assertEqual(h.coordinator.cancel_calls[0], h.coordinator.cancel_calls[1])
        self.assertEqual(len(h.coordinator.calls), 1)
        h.native_launch.assert_not_called()

    def test_cancellation_boolean_or_wrong_receipt_cannot_close_context(self):
        cases = (dict(cancelled=True), dict(cancelled=True, execution_id=EXECUTION,
            request_key=REQUEST_KEY, state="QUEUED_CANCELLED"),
            dict(cancelled=True, execution_id=EXECUTION, request_key=REQUEST_KEY,
                 state="CANCELLED_BEFORE_START", reservation_id="other", state_revision=1))
        for reply in cases:
            with self.subTest(reply=reply):
                h = Harness()
                launcher = h.admitted()
                h.coordinator.cancellation = reply
                self.assertFalse(launcher.abandon_once()["settled"])
                self.assertEqual(h.admission.close_calls, 0)
                h.native_launch.assert_not_called()

    def test_unknown_prepare_replays_original_request_then_retires_without_claim(self):
        h = Harness()
        h.client.responses["prepare"] = KeyboardInterrupt("fixture_prepare_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(KeyboardInterrupt):
            launcher.launch_once(**STDIO)
        self.assertTrue(launcher._prepare_attempted)
        self.assertTrue(h.admission.prepare_attempted)
        first = h.client.calls[0][1]
        h.client.responses["prepare"] = result("PREPARED", 1, duplicate=True)
        h.client.responses["cancel"] = result("CANCELLED_BEFORE_START", 2)
        h.store.row.update(state="PREPARED", state_revision=1, claim_consumed=0, launch_in_flight=0)
        self.assertTrue(launcher.abandon_once()["settled"])
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "prepare", "cancel"])
        self.assertEqual(h.client.calls[1][1], first)
        self.assertEqual(h.coordinator.cancel_calls, [])
        h.job_factory.assert_not_called()
        h.native_launch.assert_not_called()

    def test_partial_prepare_information_retires_original_named_scope_without_claim(self):
        h = Harness()
        h.client.responses["prepare"] = OSError("fixture_partial_prepare_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        first = dict(h.client.calls[0][1])
        h.client.responses["prepare"] = result("RESERVED", 1, duplicate=True)
        h.client.responses["cancel"] = result("CANCELLED_BEFORE_START", 2)
        h.store.row.update(state="RESERVED", state_revision=1, claim_consumed=0, launch_in_flight=0)

        outcome = launcher.abandon_once()

        self.assertTrue(outcome["settled"])
        self.assertTrue(outcome["closed"])
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "prepare", "cancel"])
        self.assertEqual(h.client.calls[1][1], first)
        self.assertEqual(h.client.calls[2][1]["expected_revision"], 1)
        self.assertEqual(h.client.calls[2][1]["job_nonce"], NONCE)
        self.assertNotEqual(h.client.calls[2][1]["request_id"], first["request_id"])
        self.assertEqual(h.coordinator.cancel_calls, [])
        self.assertEqual(len(h.coordinator.calls), 1)
        self.assertEqual(h.admission.close_calls, 1)
        self.assertFalse(launcher._claim_attempted)
        h.job_factory.assert_not_called()
        h.native_launch.assert_not_called()

    def test_nonduplicate_or_unadvanced_partial_prepare_cannot_settle_abandonment(self):
        for revision, duplicate in ((1, False), (0, True)):
            with self.subTest(revision=revision, duplicate=duplicate):
                h = Harness()
                h.client.responses["prepare"] = OSError("fixture_partial_prepare_ack_lost")
                launcher = h.admitted()
                with self.assertRaises(OSError):
                    launcher.launch_once(**STDIO)
                original = dict(h.client.calls[-1][1])
                h.client.responses["prepare"] = result("RESERVED", revision, duplicate=duplicate)
                h.store.row.update(state="RESERVED", state_revision=revision,
                                   claim_consumed=0, launch_in_flight=0)

                outcome = launcher.abandon_once()

                self.assertFalse(outcome["settled"])
                self.assertFalse(outcome["closed"])
                self.assertEqual([call[0] for call in h.client.calls], ["prepare", "prepare"])
                self.assertEqual(h.client.calls[-1][1], original)
                self.assertEqual(h.coordinator.cancel_calls, [])
                self.assertEqual(h.admission.close_calls, 0)
                self.assertEqual(h.job.close_calls, 0)
                h.native_launch.assert_not_called()

    def test_prepared_job_open_failure_uses_cancel_without_exporting_claim(self):
        h = Harness()
        h.job_factory.side_effect = OSError("fixture_open_failed")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        h.client.responses["cancel"] = result("CANCELLED_BEFORE_START", 2)
        h.store.row.update(state="PREPARED", state_revision=1, claim_consumed=0, launch_in_flight=0)
        self.assertTrue(launcher.abandon_once()["settled"])
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "cancel"])
        self.assertFalse(launcher._claim_attempted)
        h.native_launch.assert_not_called()

    def test_unknown_claim_retires_without_replaying_claim(self):
        h = Harness()
        h.client.responses["claim"] = OSError("fixture_claim_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        first = dict(h.client.calls[1][1])
        h.client.responses["claim"] = AssertionError("abandonment must not replay ClaimLaunch")
        h.client.responses["start_failed"] = result("START_FAILED", 3)
        self.assertTrue(launcher.abandon_once()["settled"])
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim", "start_failed"])
        self.assertEqual(h.client.calls[1][1], first)
        self.assertEqual(h.client.calls[2][1]["expected_revision"], 2)
        self.assertEqual(h.coordinator.cancel_calls, [])
        h.native_launch.assert_not_called()

    def test_first_claim_refused_during_drain_retires_prepared_scope_without_new_claim(self):
        h = Harness()
        h.client.responses["claim"] = OSError("fixture_first_claim_refused_during_drain")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        h.client.responses["claim"] = AssertionError("draining guardian must not receive another ClaimLaunch")
        h.client.responses["start_failed"] = result("START_FAILED", 2)
        h.store.row.update(state="PREPARED", state_revision=1, claim_consumed=0, launch_in_flight=0)

        outcome = launcher.abandon_once()

        self.assertTrue(outcome["settled"])
        self.assertTrue(outcome["closed"])
        self.assertEqual([call[0] for call in h.client.calls], ["prepare", "claim", "start_failed"])
        retirement = h.client.calls[-1][1]
        self.assertEqual(retirement["expected_revision"], 1)
        self.assertEqual(retirement["job_nonce"], NONCE)
        self.assertNotEqual(retirement["request_id"], h.client.calls[1][1]["request_id"])
        self.assertEqual(h.coordinator.cancel_calls, [])
        self.assertEqual(len(h.coordinator.calls), 1)
        self.assertEqual(h.job.close_calls, 1)
        self.assertEqual(h.admission.close_calls, 1)
        h.native_launch.assert_not_called()

    def test_unknown_create_and_unverified_retained_root_never_claim_start_failed(self):
        for failure in (LaunchOutcomeUnknown(None, "fixture_unknown"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                h = Harness()
                h.native_launch.side_effect = failure
                launcher = h.admitted()
                with self.assertRaises(type(failure)):
                    launcher.launch_once(**STDIO)
                original_calls = list(h.client.calls)
                for _ in range(2):
                    self.assertFalse(launcher.abandon_once()["settled"])
                self.assertEqual(h.client.calls, original_calls)
                self.assertEqual(h.coordinator.cancel_calls, [])
                self.assertEqual(h.native_launch.call_count, 1)
                self.assertEqual(h.job.close_calls, 0)
                self.assertEqual(h.admission.close_calls, 0)
                self.assertTrue(h.coordinator.reservation_retained)

    def test_bind_ack_recovery_retains_root_until_exit_and_never_releases_children(self):
        h = Harness()
        h.client.responses["bind"] = OSError("fixture_bind_ack_lost")
        launcher = h.admitted()
        with self.assertRaises(OSError):
            launcher.launch_once(**STDIO)
        first = h.client.calls[-1][1]
        h.client.responses["bind"] = result("RUNNING", 3, duplicate=True)
        pending = launcher.abandon_once()
        self.assertFalse(pending["settled"])
        self.assertEqual(pending["state"], "ROOT_RUNNING")
        self.assertEqual(h.client.calls[-1][1], first)
        self.assertEqual(h.process.close_calls, 0)
        h.process.exited = True
        settled = launcher.abandon_once()
        self.assertTrue(settled["settled"])
        self.assertTrue(h.coordinator.reservation_retained)
        self.assertEqual(h.coordinator.cancel_calls, [])
        self.assertEqual(h.native_launch.call_count, 1)

    def test_transport_cleanup_unknown_quarantines_further_rpc_and_local_close(self):
        from sentinel.adaptive.launch_transport import LaunchTransportError
        h = Harness()
        cleanup = OSError("fixture_transport_close_effect_unknown")
        cleanup.add_note("pipe_connection_cleanup_unverified")
        h.client.responses["prepare"] = LaunchTransportError("launch_rpc_failed",
            launch_outcome_unknown=True, cleanup_error=cleanup)
        launcher = h.admitted()
        with self.assertRaises(LaunchTransportError):
            launcher.launch_once(**STDIO)
        calls = list(h.client.calls)
        h.client.responses["prepare"] = result("PREPARED", 1, duplicate=True)
        h.client.responses["cancel"] = result("CANCELLED_BEFORE_START", 2)
        h.store.row.update(state="PREPARED", state_revision=1, claim_consumed=0, launch_in_flight=0)
        first = launcher.abandon_once()
        self.assertFalse(first["settled"])
        self.assertEqual(first["reason"], "launcher_transport_cleanup_unknown")
        self.assertFalse(launcher.abandon_once()["settled"])
        self.assertEqual(h.client.calls, calls)
        self.assertEqual(h.admission.close_calls, 0)
        self.assertTrue(launcher._operation_errors)

    def test_original_native_positive_no_create_owner_can_retire_but_not_a_boolean(self):
        for native_state in ("not_attempted", "not_created", "unknown", "created"):
            with self.subTest(native_state=native_state):
                h = Harness()
                owner = module.native_launcher.CreatedProcess(SimpleNamespace(), LOGON)
                owner._creation_outcome = native_state
                failure = module.native_launcher.NativeLaunchError("fixture_native_failure")
                failure.native_launch_owner = owner
                h.native_launch.side_effect = failure
                launcher = h.admitted()
                with self.assertRaises(module.native_launcher.NativeLaunchError):
                    launcher.launch_once(**STDIO)
                h.client.responses["start_failed"] = result("START_FAILED", 3)
                outcome = launcher.abandon_once()
                positive = native_state in {"not_attempted", "not_created"}
                self.assertEqual(outcome["settled"], positive)
                self.assertEqual("start_failed" in [call[0] for call in h.client.calls], positive)
                self.assertEqual(h.native_launch.call_count, 1)
                self.assertEqual(h.admission.close_calls, int(positive))
        h = Harness()
        failure = module.native_launcher.NativeLaunchError("create_process_failed")
        failure.native_launch_owner = SimpleNamespace(creation_definitely_absent=True)
        h.native_launch.side_effect = failure
        launcher = h.admitted()
        with self.assertRaises(module.native_launcher.NativeLaunchError):
            launcher.launch_once(**STDIO)
        self.assertFalse(launcher.abandon_once()["settled"])
        self.assertNotIn("start_failed", [call[0] for call in h.client.calls])

    def test_repeated_pending_steps_keep_diagnostic_memory_bounded(self):
        h = Harness()
        h.native_launch.side_effect = KeyboardInterrupt()
        launcher = h.admitted()
        with self.assertRaises(KeyboardInterrupt):
            launcher.launch_once(**STDIO)
        for _ in range(100):
            self.assertFalse(launcher.abandon_once()["settled"])
        self.assertLessEqual(len(launcher._operation_errors), 3)
        self.assertEqual(h.native_launch.call_count, 1)


if __name__ == "__main__":
    unittest.main()
