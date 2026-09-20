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
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import guardian_host as module
from sentinel.adaptive.guardian_host import (
    EXIT_OK, EXIT_REFUSED, GuardianHost, GuardianHostRefused,
)
from sentinel.adaptive.host_authority import HostCapabilityUnsupported
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativePipeError
from tests.test_adaptive_host_authority import SYNTHETIC, live_capability_refusal


EPOCH = "guardian-fixture-epoch"
REPO_ROOT = Path(module.__file__).resolve().parents[2]


class Service:
    """One RPC service that answers exactly once per call and records it."""

    def __init__(self, name, events):
        self.name, self.events = name, events
        self.error = None
        self.result = "fixture-served"

    def serve_once(self, listener, *, timeout_ms):
        self.events.append((self.name, timeout_ms, listener.name))
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


class Lifecycle:
    def __init__(self, events):
        self.events = events
        self.retained = []
        self.errors = {}

    @property
    def retained_execution_ids(self):
        return tuple(self.retained)

    def reconcile(self, execution_id, *, now=None):
        self.events.append(("reconcile", execution_id))
        if execution_id in self.errors:
            raise self.errors[execution_id]
        return SimpleNamespace(execution_id=execution_id, state="RUNNING",
                               active_processes=1, terminal=False)


class Owner:
    def __init__(self, events):
        self.lifecycle = Lifecycle(events)

    @property
    def retained_execution_ids(self):
        return self.lifecycle.retained_execution_ids


class Control:
    """Records the sweep. Any other attribute access is a design violation."""

    def __init__(self, events):
        object.__setattr__(self, "events", events)
        object.__setattr__(self, "restores", [])
        object.__setattr__(self, "now", 1000)

    def clock(self):
        return self.now

    def tick(self, now):
        self.events.append(("tick", now))
        return list(self.restores)

    def __getattr__(self, name):
        raise AssertionError("guardian host reached control." + name)


class GuardianHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.events = []
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
        # The proposal service returns the ApplyAck it sent. Only these three
        # fields reach a host record.
        host.control_service.result = SimpleNamespace(
            execution_id="execution-a", result=SimpleNamespace(value="REJECTED"),
            reason="fixture_rejected", request_id="private-request-marker")
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

    # --- one iteration ----------------------------------------------------

    def test_one_iteration_serves_each_service_then_reconciles_then_sweeps(self):
        self.host.owner.lifecycle.retained = ["execution-a", "execution-b"]
        record = self.host.run_once()
        self.assertEqual(self.events, [
            ("launch", 250, "launch"), ("control", 250, "control"), ("query", 250, "query"),
            ("reconcile", "execution-a"), ("reconcile", "execution-b"), ("tick", 1000)])
        self.assertTrue(record["launch_rpc"]["served"])
        self.assertTrue(record["query_rpc"]["served"])
        self.assertEqual(record["control_rpc"], {"served": True, "result": {
            "execution_id": "execution-a", "result": "REJECTED", "reason": "fixture_rejected"}})
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

    def test_the_host_never_asks_the_control_consumer_for_anything_but_a_sweep(self):
        # Control raises on every other attribute, so a Set, an apply or a
        # barrier clear from this loop fails the test rather than passing it.
        self.host.run_once()
        self.assertEqual([event for event in self.events if event[0] == "tick"], [("tick", 1000)])

    # --- the drain --------------------------------------------------------

    def test_a_bounded_drain_reports_retained_work_and_does_not_exit(self):
        self.host.owner.lifecycle.retained = ["execution-a"]
        record = self.host.drain_until_settled(budget=2)
        self.assertEqual(record["settled"], False)
        self.assertEqual(record["exiting"], False)
        self.assertEqual(record["retained"], ["execution-a"])
        self.assertEqual(record["iterations"], 2)
        # No launch RPC and no proposal is served while draining; the read
        # only query is.
        self.assertEqual([event[0] for event in self.events
                          if event[0] in {"launch", "control", "query"}], ["query", "query"])
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
