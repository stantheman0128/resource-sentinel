"""Guardian process host: one bounded iteration, the drain, and shutdown.

The launch owner, the lifecycle dispatcher, the control consumer and the three
pipe services are replaced here by explicit in-process fixtures that record
what the host asks of them. Those modules have their own test files; what is
under test here is the host loop, the drain and the exit conditions.

The capability preflight is live. The startup case on this machine expects its
real refusal, and the subprocess smoke expects the same reason from a separate
interpreter.
"""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import guardian_host as module
from sentinel.adaptive.contracts import ApplyAck, ApplyResult, IdentityStatus, ProcessIdentity, Validity
from sentinel.adaptive.control_messages import (
    ControlFrameAck, ControlFrameResult, ControlObservation, RestoreAck, RestoreOutcome,
)
from sentinel.adaptive.guardian_host import (
    EXIT_OK, EXIT_REFUSED, GuardianHost, GuardianHostRefused,
)
from sentinel.adaptive.host_authority import HostCapabilityUnsupported
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativePipeError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.terminal_custody import TerminalCleanupResult
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_host_authority import SYNTHETIC, live_capability_refusal


EPOCH = "guardian-fixture-epoch"
REPO_ROOT = Path(module.__file__).resolve().parents[2]
LOGON = "S-1-5-5-1-2"
GUARDIAN = ProcessIdentity(6001, 134343072000000005, LOGON)
EXECUTION = "11111111-1111-4111-8111-111111111111"
REQUEST = "22222222-2222-4222-8222-222222222222"


def apply_ack():
    return ApplyAck(request_id=REQUEST, action_id=None, execution_id=EXECUTION,
        guardian_epoch=EPOCH, policy_epoch="fixture-policy", decision_seq=1,
        result=ApplyResult.REJECTED, applied_flags=None, applied_rate_bp=None,
        applied_validity=Validity.UNKNOWN, queried_tick_100ns=None,
        lease_deadline_tick_100ns=None, intervention_deadline_tick_100ns=None,
        reason="fixture_rejected", win32_error=None)


def restore_ack(*, settled=True):
    return RestoreAck(request_id=REQUEST, guardian_epoch=EPOCH,
        policy_epoch="fixture-policy", execution_id=EXECUTION,
        result=RestoreOutcome.RESTORED if settled else RestoreOutcome.UNVERIFIED,
        native_disabled=True, bookkeeping_settled=settled, slot_released=settled,
        barrier_cleared=False, applied_flags=0, applied_rate_bp=None,
        applied_validity=Validity.VALID, queried_tick_100ns=1000,
        reason="fixture_restored" if settled else "fixture_bookkeeping_pending", win32_error=None)


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


class Service:
    """One RPC service that answers exactly once per call and records it."""

    def __init__(self, name, events):
        self.name, self.events = name, events
        self.error = None
        self.result = "fixture-served"
        self.before_serve = None

    def serve_once(self, listener, *, timeout_ms):
        self.events.append((self.name, timeout_ms, listener.name))
        if self.before_serve is not None:
            self.before_serve()
        if self.error is not None:
            raise self.error
        return self.result


class Listener:
    def __init__(self, name, events):
        self.name, self.events = name, events
        self.closed = False
        self.close_error = None

    def close(self):
        self.events.append(("close", self.name))
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class PipeRegistryFixture:
    """Explicit host-owned cleanup status; never touches a global native pipe."""
    def __init__(self):
        self.calls = []
        self.status = SimpleNamespace(resources=0, pending=0, quarantined=0)

    def reap(self, deadline, *, max_ops):
        self.calls.append((deadline, max_ops))
        return self.status


def install_pipe_fixture(case):
    registry = PipeRegistryFixture()
    for patcher in (patch("sentinel.adaptive.pipe_windows._GLOBAL_REGISTRY", registry),
                    patch("sentinel.adaptive.pipe_windows.NativeDeadline.after_ms", return_value=object())):
        patcher.start()
        case.addCleanup(patcher.stop)
    return registry


class Lifecycle:
    def __init__(self, events):
        self.events = events
        self.retained = []
        self.errors = {}
        self.results = {}
        self.cleanup_started = set()
        self.retire_errors = {}
        self.retire_results = {}
        self.fence_close_error = None
        self.fences_closed = False

    @property
    def retained_execution_ids(self):
        return tuple(self.retained)

    def reconcile(self, execution_id, *, now=None):
        self.events.append(("reconcile", execution_id))
        if execution_id in self.errors:
            raise self.errors[execution_id]
        return self.results.get(execution_id, SimpleNamespace(
            execution_id=execution_id, state="RUNNING", active_processes=1, terminal=False))

    def terminal_cleanup_started(self, execution_id):
        return execution_id in self.cleanup_started

    def close_retained_fences(self):
        if self.fences_closed:
            return
        self.events.append(("close_recovery_fence",))
        if self.fence_close_error is not None:
            raise self.fence_close_error
        self.fences_closed = True

    def retire_terminal(self, execution_id, *, now=None):
        self.events.append(("retire_terminal", execution_id))
        if execution_id in self.retire_errors:
            raise self.retire_errors[execution_id]
        result = self.retire_results.get(execution_id, TerminalCleanupResult(
            execution_id, True, False, False, "guardian_terminal_retired", ()))
        if result.complete:
            self.retained.remove(execution_id)
            self.cleanup_started.discard(execution_id)
        return result


class Owner:
    def retire_completed_pending(self):
        return []

    def __init__(self, events):
        self.events = events
        self.lifecycle = Lifecycle(events)
        self.draining = False
        self.new_authorizations = []
        self.recovery_requests = []

    def begin_drain(self):
        self.events.append(("owner_begin_drain",))
        self.draining = True

    def dispatch_fixture(self, operation):
        """Explicit owner boundary for host wiring, not native authority proof."""
        if operation in {"prepare", "claim"}:
            if self.draining:
                raise LifecycleError("guardian_draining")
            self.new_authorizations.append(operation)
        else:
            self.recovery_requests.append(operation)
        return operation

    @property
    def retained_execution_ids(self):
        return self.lifecycle.retained_execution_ids


class Control:
    """Explicit host safety calls; direct apply/Set access remains a violation."""

    def __init__(self, events):
        object.__setattr__(self, "events", events)
        object.__setattr__(self, "restores", [])
        object.__setattr__(self, "now", 1000)
        object.__setattr__(self, "tick_results", [])
        object.__setattr__(self, "tick_error", None)
        object.__setattr__(self, "draining", False)
        object.__setattr__(self, "barrier_errors", {})
        object.__setattr__(self, "barrier_results", {})

    def begin_drain(self):
        self.events.append(("begin_drain",))
        self.draining = True

    def clock(self):
        return self.now

    def tick(self, now):
        self.events.append(("tick", now))
        if self.tick_error is not None:
            raise self.tick_error
        if self.tick_results:
            return self.tick_results.pop(0)
        return list(self.restores)

    def clear_finished_admission_barrier(self, execution_id):
        self.events.append(("clear_finished", execution_id))
        if execution_id in self.barrier_errors:
            raise self.barrier_errors[execution_id]
        return self.barrier_results.get(execution_id, {"admission_barrier": "NONE"})

    def __getattr__(self, name):
        raise AssertionError("guardian host reached control." + name)


class GuardianHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.events = []
        self.pipe_registry = install_pipe_fixture(self)
        self.host = self.build()

    def build(self):
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "recovery",
                            guardian_epoch=EPOCH, rpc_timeout_ms=250,
                            sleep=lambda seconds: self.events.append(("sleep", seconds)))
        host.owner = Owner(self.events)
        host.control = Control(self.events)
        host.launch_service = Service("launch", self.events)
        host.query_service = Service("query", self.events)
        host.control_service = Service("control", self.events)
        # The transport returns its actual typed ack. Host records deliberately
        # omit request bindings, native timestamps and the other protocol fields.
        host.control_service.result = apply_ack()
        host.launch_listener = Listener("launch", self.events)
        host.query_listener = Listener("query", self.events)
        host.control_listener = Listener("control", self.events)
        host._started = True
        return host

    # --- startup ----------------------------------------------------------

    def test_start_refuses_on_this_host_before_opening_anything(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "recovery",
                            guardian_epoch=EPOCH)
        with self.assertRaises(GuardianHostRefused) as caught:
            host.start()
        self.assertEqual(caught.exception.reason, reason)
        self.assertIsNone(host.store)
        self.assertIsNone(host.owner)
        self.assertFalse((self.directory / "sentinel.db").exists())

    def test_start_refuses_when_capability_is_unknown(self):
        unknown = HostCapabilityUnsupported("host_parent_job_membership_unknown", 6)
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory,
                            guardian_epoch=EPOCH)
        with patch.object(module, "read_host_capability", side_effect=unknown):
            with self.assertRaises(GuardianHostRefused) as caught:
                host.start()
        self.assertEqual(caught.exception.reason, "host_parent_job_membership_unknown")

    def test_start_refuses_a_missing_ledger_after_capability(self):
        host = GuardianHost(data_dir=self.directory / "absent", journal_dir=self.directory,
                            guardian_epoch=EPOCH)
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC):
            with self.assertRaises(GuardianHostRefused) as caught:
                host.start()
        self.assertEqual(caught.exception.reason, "guardian_host_ledger_unavailable")

    def test_default_rpc_deadline_is_bounded_to_one_hundred_milliseconds(self):
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory,
                            guardian_epoch=EPOCH)
        options = module.build_parser().parse_args(self.arguments())
        self.assertEqual(host.rpc_timeout_ms, 100)
        self.assertEqual(options.rpc_timeout_ms, 100)
        self.assertEqual(self.host.rpc_timeout_ms, 250)

    def test_start_passes_evidence_authority_and_floor_publisher_to_control(self):
        evidence_directory = self.directory / "isolated-evidence"
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "recovery",
            guardian_epoch=EPOCH, evidence_directory=evidence_directory,
            evidence_sha256="c" * 64, control_purpose="isolated_canary")
        host.launch_endpoint = SimpleNamespace(name="fixture-launch")
        host.query_endpoint = SimpleNamespace(name="fixture-query")
        host.control_endpoint = SimpleNamespace(name="fixture-control")
        profile, evidence_authority, publisher = object(), object(), object()
        owner, control = Owner(self.events), Control(self.events)
        guardian = SimpleNamespace(identity=GUARDIAN)
        store = SimpleNamespace(db_path=self.directory / "sentinel.db")
        observed = []

        def create_control(actual_owner, *, profile, exemptions, capability_authority, floor_publisher):
            observed.append((actual_owner, profile, exemptions, capability_authority, floor_publisher))
            return control

        with patch.object(module, "read_host_capability", return_value=SYNTHETIC), \
                patch.object(host, "_profile", return_value=profile), \
                patch("sentinel.adaptive.store.LifecycleStore", return_value=store), \
                patch("sentinel.adaptive.recovery_journal.RecoveryJournal", return_value=object()), \
                patch.object(VerifiedProcess, "current", return_value=guardian), \
                patch.object(module, "HostAuthority", return_value=object()), \
                patch("sentinel.adaptive.guardian.GuardianLaunchOwner", return_value=owner), \
                patch.object(host, "_register"), patch.object(host, "_endpoints"), \
                patch.object(host, "_control_endpoint"), \
                patch.object(host, "_operator_endpoint"), \
                patch("sentinel.adaptive.capability_evidence.NativeEvidenceAuthority",
                      return_value=evidence_authority) as evidence, \
                patch("sentinel.adaptive.guardian_floor.FloorPublisher", return_value=publisher) as floor, \
                patch("sentinel.adaptive.guardian_control.GuardianControl", side_effect=create_control):
            record = host.start()
        evidence.assert_called_once_with(profile=profile, bundle_directory=evidence_directory,
                                         expected_bundle_sha256="c" * 64, purpose="isolated_canary")
        floor.assert_called_once_with(owner)
        self.assertEqual(observed, [(owner, profile, self.directory / "exemptions.sqlite3",
                                     evidence_authority, publisher)])
        self.assertIs(host.control, control)
        self.assertTrue(host._started)
        self.assertEqual(record["event"], "guardian_host_started")

    # --- one iteration ----------------------------------------------------

    def test_one_iteration_sweeps_before_rpc_then_reconciles_and_sweeps_again(self):
        self.host.owner.lifecycle.retained = ["execution-a", "execution-b"]
        record = self.host.run_once()
        self.assertEqual(self.events, [
            ("tick", 1000),
            ("launch", 250, "launch"), ("control", 250, "control"), ("query", 250, "query"),
            ("reconcile", "execution-a"), ("reconcile", "execution-b"), ("tick", 1000)])
        self.assertTrue(record["launch_rpc"]["served"])
        self.assertTrue(record["query_rpc"]["served"])
        self.assertEqual(record["control_rpc"], {"served": True, "result": {
            "execution_id": EXECUTION, "result": "REJECTED", "reason": "fixture_rejected"}})
        self.assertEqual([entry["execution_id"] for entry in record["reconciled"]],
                         ["execution-a", "execution-b"])

    def test_a_refused_proposal_is_reported_and_the_sweep_still_runs(self):
        self.host.control_service.error = IpcError("control_helper_unregistered")
        record = self.host.run_once()
        self.assertEqual(record["control_rpc"],
                         {"served": False, "reason": "control_helper_unregistered"})
        self.assertIn(("tick", 1000), self.events)

    def test_an_idle_deadline_is_reported_and_not_retried(self):
        self.host.launch_service.error = NativePipeError("pipe_deadline_elapsed")
        record = self.host.run_once()
        self.assertEqual(record["launch_rpc"], {"served": False, "reason": "pipe_deadline_elapsed"})
        self.assertEqual(len([event for event in self.events if event[0] == "launch"]), 1)

    def test_a_reconcile_failure_is_recorded_and_the_sweep_still_runs(self):
        self.host.owner.lifecycle.retained = ["execution-a"]
        self.host.owner.lifecycle.errors["execution-a"] = RuntimeError("fixture_reconcile_unknown")
        record = self.host.run_once()
        self.assertEqual(record["reconcile_errors"],
                         [{"execution_id": "execution-a", "reason": "RuntimeError"}])
        self.assertIn(("tick", 1000), self.events)

    def test_an_unstarted_host_runs_nothing(self):
        self.host._started = False
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.run_once()
        self.assertEqual(caught.exception.reason, "guardian_host_not_started")
        self.assertEqual(self.events, [])

    def test_a_nonterminal_iteration_has_only_two_control_sweeps_and_no_barrier_clear(self):
        # The host may request documented safety work, but Control still raises
        # if this loop attempts to apply a proposal or manipulate native state.
        self.host.owner.lifecycle.retained = [EXECUTION]
        self.host.run_once()
        self.assertEqual([event for event in self.events if event[0] == "tick"],
                         [("tick", 1000), ("tick", 1000)])
        self.assertFalse(any(event[0] == "clear_finished" for event in self.events))

    def test_expiry_sweep_completes_before_first_rpc_wait_and_retains_both_outcomes(self):
        self.host.control.tick_results = [
            [("execution-expired", "lease_expired", None)],
            [("execution-finished", "control_mode_unavailable", None)],
        ]

        def before_wait():
            self.assertEqual(self.events[:2], [("tick", 1000), ("launch", 250, "launch")])
            self.assertEqual(len(self.host.control.tick_results), 1)

        self.host.launch_service.before_serve = before_wait
        record = self.host.run_once()
        self.assertEqual(record["restored"], [
            {"execution_id": "execution-expired", "reason": "lease_expired"},
            {"execution_id": "execution-finished", "reason": "control_mode_unavailable"},
        ])

    def test_failed_initial_safety_sweep_never_enters_a_blocking_rpc(self):
        self.host.control.tick_error = LifecycleError("fixture_restore_unverified")
        with self.assertRaisesRegex(LifecycleError, "fixture_restore_unverified"):
            self.host.run_once()
        self.assertEqual(self.events, [("tick", 1000)])

    def test_finished_retirement_follows_sweep_and_retains_pending_bookkeeping(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = [EXECUTION]
        lifecycle.results[EXECUTION] = SimpleNamespace(
            execution_id=EXECUTION, state="FINISHED", active_processes=0, terminal=True)
        lifecycle.retire_results[EXECUTION] = TerminalCleanupResult(
            EXECUTION, False, True, False, "fixture_bookkeeping_pending", ())
        first = self.host.run_once()
        self.assertEqual(self.events[-3:], [
            ("reconcile", EXECUTION), ("tick", 1000), ("retire_terminal", EXECUTION)])
        self.assertEqual(first["barrier_clears"], [])
        self.assertEqual(first["barrier_clear_errors"], [])
        self.assertEqual(first["terminal_retirements"], [{"execution_id": EXECUTION,
            "complete": False, "pending": True, "reason": "fixture_bookkeeping_pending"}])
        self.assertEqual(self.host.retained_execution_ids(), (EXECUTION,))
        lifecycle.retire_results.clear()
        second = self.host.run_once()
        self.assertEqual(second["barrier_clear_errors"], [])
        self.assertEqual(second["terminal_retirements"], [{"execution_id": EXECUTION,
            "complete": True, "pending": False, "reason": "guardian_terminal_retired"}])
        self.assertEqual(self.host.retained_execution_ids(), ())
        self.assertEqual([event for event in self.events if event[0] == "retire_terminal"],
                         [("retire_terminal", EXECUTION), ("retire_terminal", EXECUTION)])
        self.assertFalse(any(event[0] == "clear_finished" for event in self.events))

    def test_reconcile_failure_does_not_claim_a_finished_barrier_clear(self):
        self.host.owner.lifecycle.retained = [EXECUTION]
        self.host.owner.lifecycle.errors[EXECUTION] = LifecycleError("fixture_reconcile_pending")
        record = self.host.run_once()
        self.assertEqual(record["barrier_clears"], [])
        self.assertEqual(record["barrier_clear_errors"], [])
        self.assertEqual(record["terminal_retirements"], [])
        self.assertFalse(any(event[0] == "clear_finished" for event in self.events))

    def test_control_frame_ack_summary_preserves_each_observation_without_wire_bindings(self):
        second_execution = "33333333-3333-4333-8333-333333333333"
        self.host.control_service.result = ControlFrameAck(
            request_id=REQUEST, guardian_epoch=EPOCH, policy_epoch="fixture-policy",
            sampler_epoch="fixture-sampler", clock_epoch="fixture-clock", sample_seq=7,
            registry_revision=10, config_revision="a" * 64, results=(
                ControlFrameResult(EXECUTION, ControlObservation.UNCAPPED, 1000, True, "fixture_clear"),
                ControlFrameResult(second_execution, ControlObservation.UNVERIFIED, None, False,
                                   "fixture_query_unknown"),
            ))
        result = self.host._control_rpc()
        self.assertEqual(result, {"served": True, "result": {"sample_seq": 7, "results": [
            {"execution_id": EXECUTION, "observation": "UNCAPPED", "barrier_cleared": True,
             "reason": "fixture_clear"},
            {"execution_id": second_execution, "observation": "UNVERIFIED", "barrier_cleared": False,
             "reason": "fixture_query_unknown"},
        ]}})
        self.assertNotIn(REQUEST, json.dumps(result))

    def test_restore_ack_summary_keeps_native_and_bookkeeping_outcomes_separate(self):
        for settled in (False, True):
            with self.subTest(settled=settled):
                ack = restore_ack(settled=settled)
                self.host.control_service.result = ack
                result = self.host._control_rpc()
                self.assertEqual(result, {"served": True, "result": {
                    "execution_id": EXECUTION, "result": ack.result.value, "reason": ack.reason,
                    "native_disabled": True, "bookkeeping_settled": settled,
                    "slot_released": settled, "barrier_cleared": False,
                }})
                self.assertNotIn(REQUEST, json.dumps(result))

    # --- the drain --------------------------------------------------------

    def test_drain_begins_before_sweep_and_still_serves_restore_rpc(self):
        self.host.control_service.result = restore_ack(settled=False)

        def serving_restore():
            self.assertTrue(self.host.control.draining)
            self.assertTrue(self.host.owner.draining)
            self.assertEqual(self.events[:3], [("owner_begin_drain",), ("begin_drain",), ("tick", 1000)])

        self.host.control_service.before_serve = serving_restore
        record = self.host.run_once(serve_launch=False)
        self.assertTrue(record["launch_rpc"]["served"])
        self.assertTrue(record["control_rpc"]["served"])
        self.assertFalse(record["control_rpc"]["result"]["bookkeeping_settled"])
        self.assertTrue(record["query_rpc"]["served"])
        self.assertEqual([event[0] for event in self.events],
                         ["owner_begin_drain", "begin_drain", "tick", "launch", "control", "query", "tick"])

    def test_drain_accepts_an_empty_frame_and_keeps_the_launch_recovery_pipe(self):
        self.host.control_service.result = ControlFrameAck(
            request_id=REQUEST, guardian_epoch=EPOCH, policy_epoch="fixture-policy",
            sampler_epoch="fixture-sampler", clock_epoch="fixture-clock", sample_seq=8,
            registry_revision=10, config_revision="b" * 64, results=())
        record = self.host.run_once(serve_launch=False)
        self.assertTrue(self.host.control.draining)
        self.assertTrue(record["launch_rpc"]["served"])
        self.assertTrue(self.host.owner.draining)
        self.assertEqual(record["control_rpc"], {"served": True,
                                                "result": {"sample_seq": 8, "results": []}})

    def test_a_bounded_drain_reports_retained_work_and_does_not_exit(self):
        self.host.owner.lifecycle.retained = ["execution-a"]
        record = self.host.drain_until_settled(budget=2)
        self.assertEqual(record["settled"], False)
        self.assertEqual(record["exiting"], False)
        self.assertEqual(record["retained"], ["execution-a"])
        self.assertEqual(record["iterations"], 2)
        # The launch owner refuses new authorization, while the same launch
        # pipe remains available for Bind/Cancel and lost-acknowledgement replay.
        self.assertEqual([event[0] for event in self.events
                          if event[0] in {"launch", "control", "query"}],
                         ["launch", "control", "query", "launch", "control", "query"])
        self.assertTrue(self.host.owner.draining)
        self.assertFalse(self.host.launch_listener.closed)

    def test_the_drain_returns_only_once_custody_clears(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = ["execution-a"]
        original = lifecycle.reconcile

        def clearing(execution_id, *, now=None):
            lifecycle.retained = []
            return original(execution_id, now=now)

        lifecycle.reconcile = clearing
        record = self.host.drain_until_settled()
        self.assertEqual((record["settled"], record["iterations"]), (True, 1))

    def test_an_interrupt_during_the_drain_does_not_release_custody(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = ["execution-a"]
        calls = []

        def reconcile(execution_id, *, now=None):
            calls.append(execution_id)
            if len(calls) == 1:
                raise KeyboardInterrupt
            lifecycle.retained = []
            return SimpleNamespace(execution_id=execution_id, state="FINISHED",
                                   active_processes=0, terminal=True)

        lifecycle.reconcile = reconcile
        records = []
        with patch.object(module, "emit", side_effect=records.append):
            record = self.host.drain_until_settled()
        self.assertEqual((record["settled"], record["iterations"]), (True, 2))
        self.assertEqual(records[0], {"event": "guardian_host_interrupt_deferred",
                                      "retained": ["execution-a"]})

    def test_a_settled_host_drains_without_any_iteration(self):
        record = self.host.drain_until_settled()
        self.assertEqual((record["settled"], record["iterations"]), (True, 0))
        self.assertEqual(self.events, [])

    # --- shutdown ---------------------------------------------------------

    def test_close_refuses_while_an_execution_is_retained(self):
        self.host.owner.lifecycle.retained = ["execution-a"]
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_custody_unsettled")
        self.assertFalse(self.host.launch_listener.closed)
        self.assertFalse(self.host.query_listener.closed)

    def test_close_releases_every_endpoint_once_settled(self):
        record = self.host.close()
        self.assertEqual(record["guardian_epoch"], EPOCH)
        self.assertTrue(self.host.launch_listener.closed)
        self.assertTrue(self.host.query_listener.closed)
        self.assertTrue(self.host.control_listener.closed)

    def test_an_endpoint_that_cannot_be_released_is_reported(self):
        self.host.query_listener.close_error = OSError("fixture_close_failed")
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_endpoint_cleanup_unverified")
        self.assertTrue(self.host.launch_listener.closed)

    # --- the entry point --------------------------------------------------

    def arguments(self, *extra):
        return ["--data-dir", str(self.directory), "--journal-dir", str(self.directory),
                "--guardian-epoch", EPOCH, *extra]

    def test_main_drains_before_it_closes(self):
        host = self.host
        host.owner.lifecycle.retained = ["execution-a"]
        original = host.run_once

        def clearing(*, serve_launch=True):
            record = original(serve_launch=serve_launch)
            host.owner.lifecycle.retained = []
            return record

        host.run_once = clearing
        with patch.object(module, "GuardianHost", return_value=host):
            with patch.object(host, "start", return_value={"event": "fixture_started"}):
                code = module.main(self.arguments("--iterations", "1"))
        self.assertEqual(code, EXIT_OK)
        self.assertTrue(host.query_listener.closed)

    def test_main_reports_a_startup_refusal_and_returns_the_refusal_code(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        self.assertEqual(module.main(self.arguments("--iterations", "1")), EXIT_REFUSED)

    def test_the_default_mode_runs_until_it_is_interrupted(self):
        host = self.host
        calls = []

        def interrupting(*, serve_launch=True):
            calls.append(serve_launch)
            if len(calls) == 3:
                raise KeyboardInterrupt
            return {"event": "fixture_iteration"}

        host.run_once = interrupting
        record = host.serve_until_stopped()
        self.assertEqual(record["reason"], "interrupted")
        self.assertEqual(record["iterations"], 2)


class GuardianRegistrationTests(unittest.TestCase):
    """The registration step alone against a real isolated ledger.

    The policy coordinator and the legacy writer are the production modules.
    The policy provider is the in-process fixture and the retained guardian is
    a real VerifiedProcess over a synthetic handle backend, as in the helper
    host registration tests. Nothing native is held here.
    """

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        self.policy = FixturePolicyProvider(LOGON)
        self.store = LifecycleStore(self.db, policy_provider=self.policy)
        self.backend = ProcessBackend()

    def build(self, process=None):
        from sentinel.adaptive.recovery_journal import RecoveryJournal
        host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "recovery",
                            guardian_epoch=EPOCH)
        host.store = self.store
        (self.directory / "recovery").mkdir(exist_ok=True)
        host.journal = RecoveryJournal(self.directory / "recovery")
        host.guardian = self.backend.process(GUARDIAN) if process is None else process
        return host

    def connection(self):
        conn = sqlite3.connect(self.db, isolation_level=None)
        self.addCleanup(conn.close)
        return conn

    def entry_nonce(self):
        return self.connection().execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime WHERE singleton=1").fetchone()[0]

    def rows(self):
        return [tuple(row) for row in self.connection().execute(
            "SELECT role,pid FROM adaptive_infrastructure ORDER BY role,pid")]

    def registry_rows(self):
        return [tuple(row) for row in self.connection().execute(
            "SELECT role,pid,created_filetime_100ns,logon_id,schema_version "
            "FROM adaptive_infrastructure ORDER BY role,pid,created_filetime_100ns,logon_id")]

    def seed_registry(self, *identities, epoch=""):
        from sentinel.adaptive.legacy_writer import initialize_registry_locked

        policy = self.store._policy
        with policy.hold(policy.prepare(LOGON)):
            initialize_registry_locked(self.store)
        # Fixture-only historical rows exercise the real bounded SELECT, including
        # states an older host could have published before singleton enforcement.
        conn = self.connection()
        conn.executemany(
            "INSERT INTO adaptive_infrastructure "
            "(role,pid,created_filetime_100ns,logon_id,schema_version) VALUES('guardian',?,?,?,1)",
            [(identity.pid, str(identity.created_filetime_100ns), identity.logon_id)
             for identity in identities])
        conn.execute("UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=? WHERE singleton=1",
                     (epoch, LOGON if epoch else ""))

    def assert_registration_refused_without_registry_change(self, host, reason):
        before = self.registry_rows()
        with self.assertRaises(GuardianHostRefused) as caught:
            host._register()
        self.assertEqual(caught.exception.reason, reason)
        self.assertFalse(host.registered)
        self.assertEqual(self.registry_rows(), before)
        self.assertIsNone(self.entry_nonce())
        self.assertFalse(self.policy.active)
        # A clean refusal must permit the next POLICY entry, not just make the
        # fixture mutex look free while leaving its durable nonce behind.
        policy = self.store._policy
        with policy.hold(policy.prepare(LOGON)):
            policy.assert_held()
        self.assertIsNone(self.entry_nonce())

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
        self.assertTrue(host.registered)
        self.assertEqual(self.rows(), [("guardian", 6001)])

    def test_empty_registry_registers_exact_identity_and_clears_policy_nonce(self):
        self.seed_registry()
        host = self.build()
        host._register()
        self.assertTrue(host.registered)
        self.assertEqual(self.registry_rows(), [
            ("guardian", GUARDIAN.pid, str(GUARDIAN.created_filetime_100ns), LOGON, 1)])
        self.assertIsNone(self.entry_nonce())

    def test_exact_existing_identity_and_epoch_are_idempotent(self):
        self.seed_registry(GUARDIAN, epoch=EPOCH)
        before = self.registry_rows()
        conn = self.connection()
        revision = conn.execute(
            "SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0]
        for _ in range(2):
            host = self.build()
            host._register()
            self.assertTrue(host.registered)
            self.assertEqual(self.registry_rows(), before)
            self.assertEqual(conn.execute(
                "SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0], revision)
            self.assertIsNone(self.entry_nonce())

    def test_second_guardian_cannot_add_a_registry_row(self):
        first = ProcessIdentity(GUARDIAN.pid + 1, GUARDIAN.created_filetime_100ns + 1, LOGON)
        self.build(self.backend.process(first))._register()
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_registry_occupied")

    def test_same_pid_with_different_creation_identity_is_occupied(self):
        self.seed_registry(ProcessIdentity(GUARDIAN.pid, GUARDIAN.created_filetime_100ns + 1, LOGON))
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_registry_occupied")

    def test_foreign_logon_registry_identity_is_occupied_even_when_pid_and_birth_match(self):
        self.seed_registry(ProcessIdentity(GUARDIAN.pid, GUARDIAN.created_filetime_100ns, "S-1-5-5-3-4"))
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_registry_occupied")

    def test_foreign_logon_candidate_cannot_publish(self):
        self.seed_registry()
        foreign = ProcessIdentity(GUARDIAN.pid, GUARDIAN.created_filetime_100ns, "S-1-5-5-3-4")
        self.assert_registration_refused_without_registry_change(
            self.build(self.backend.process(foreign)), "guardian_host_registry_unavailable")

    def test_two_existing_guardians_refuse_even_when_one_is_exact_self(self):
        self.seed_registry(GUARDIAN, ProcessIdentity(
            GUARDIAN.pid + 1, GUARDIAN.created_filetime_100ns + 1, LOGON))
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_registry_occupied")

    def test_foreign_runtime_epoch_refuses_without_adding_guardian_or_sticking_nonce(self):
        self.seed_registry(epoch="prior-guardian-epoch")
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_epoch_occupied")
        self.assertEqual(self.connection().execute(
            "SELECT guardian_epoch FROM adaptive_runtime WHERE singleton=1").fetchone()[0],
            "prior-guardian-epoch")

    def test_exact_existing_identity_does_not_authorize_a_different_epoch(self):
        self.seed_registry(GUARDIAN, epoch="prior-guardian-epoch")
        self.assert_registration_refused_without_registry_change(
            self.build(), "guardian_host_epoch_occupied")

    def test_an_unverifiable_candidate_refuses_and_releases_policy(self):
        host = self.build(SimpleNamespace(identity=GUARDIAN))
        with self.assertRaises(GuardianHostRefused) as caught:
            host._register()
        self.assertEqual(caught.exception.reason, "guardian_host_registry_unavailable")
        self.assertFalse(host.registered)
        self.assertIsNone(self.entry_nonce())
        # The scope is free, so the next owner can take it and write.
        self.build()._register()
        self.assertEqual(self.rows(), [("guardian", 6001)])


class GuardianHostSubprocessTests(unittest.TestCase):
    """One real process per host module, expecting this machine's refusal."""

    def run_host(self, *arguments):
        return subprocess.run([sys.executable, "-m", "sentinel.adaptive.guardian_host", *arguments],
                              cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

    def test_help_is_available(self):
        result = self.run_host("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--guardian-epoch", result.stdout)

    def test_a_start_on_an_isolated_data_directory_refuses_with_a_typed_reason(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_host("--data-dir", directory, "--journal-dir", directory,
                                   "--guardian-epoch", EPOCH, "--iterations", "1")
        self.assertEqual(result.returncode, EXIT_REFUSED)
        record = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(record["event"], "guardian_host_refused")
        self.assertEqual(record["reason"], reason)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
