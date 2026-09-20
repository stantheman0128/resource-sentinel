"""Wrapper process host: the run-managed verb end to end over fixtures.

The launcher collaborators come from the managed launcher test harness, which
states that they open no DLL, pipe, Job, process or database. What is under
test here is the host: how it parses a request, what it reports, which exit
code it returns, and what it claims about the workload afterwards.

One case builds the real Coordinator and the real HostAuthority to prove the
host wires the live authority rather than a receipt. The capability preflight
is live everywhere, and the subprocess smoke expects this machine's refusal.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import wrapper_host as module
from sentinel.adaptive.contracts import Priority, ResourceDemand, Role
from sentinel.adaptive.host_authority import HostAuthority
from sentinel.adaptive.native_launcher import LaunchOutcomeUnknown
from sentinel.adaptive.wrapper_host import (
    ATTEMPTED_UNKNOWN, EXIT_POST_LAUNCH, EXIT_REFUSED, EXIT_UNMANAGED, LAUNCHED,
    NOT_ATTEMPTED, WrapperHost, WrapperHostRefused,
)
from tests import test_adaptive_launcher as harness
from tests.test_adaptive_host_authority import SYNTHETIC, live_capability_refusal


REPO_ROOT = Path(module.__file__).resolve().parents[2]
GIB = 1 << 30
STDIO = (101, 102, 103)


class WrapperHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        (self.directory / "status.json").write_text('{"light": "GREEN"}', encoding="utf-8")
        (self.directory / "config.json").write_text('{"admission_policy": "resource-v2"}',
                                                    encoding="utf-8")
        self.harness = harness.Harness()
        self.passed = None
        quiet = patch.object(module, "emit")
        quiet.start()
        self.addCleanup(quiet.stop)
        stdio = patch.object(module, "stdio_handles", return_value=STDIO)
        stdio.start()
        self.addCleanup(stdio.stop)
        capability = patch.object(module, "read_host_capability", return_value=SYNTHETIC)
        capability.start()
        self.addCleanup(capability.stop)
        logon = patch.object(WrapperHost, "_logon", lambda self: harness.LOGON)
        logon.start()
        self.addCleanup(logon.stop)

    def factory(self, spec, *, coordinator, endpoint, guardian_epoch, readiness):
        """Keep what the host built, then hand back the fixture launcher."""
        self.passed = SimpleNamespace(spec=spec, coordinator=coordinator, endpoint=endpoint,
                                      guardian_epoch=guardian_epoch, readiness=readiness)
        return self.harness.build(guardian_epoch=harness.GUARDIAN)

    def build(self, **overrides):
        arguments = dict(data_dir=self.directory, command="echo fixture", cwd=str(self.directory),
                         repo_identifier="fixture-repo", role=Role.BACKGROUND,
                         priority=Priority.P2,
                         requested=ResourceDemand(1.0, GIB, GIB, 0),
                         guardian_epoch=harness.GUARDIAN,
                         guardian_pid=harness.SERVER.pid,
                         guardian_created_filetime_100ns=harness.SERVER.created_filetime_100ns,
                         endpoint_instance_id=harness.INSTANCE,
                         launcher_factory=self.factory, poll_interval_ms=1)
        arguments.update(overrides)
        return WrapperHost(**arguments)

    def arguments(self, *extra):
        return ["run-managed", "--data-dir", str(self.directory), "--command", "echo fixture",
                "--cwd", str(self.directory), "--repo", "fixture-repo",
                "--cpu-units", "1", "--ram-gib", "1",
                "--guardian-epoch", harness.GUARDIAN,
                "--guardian-pid", str(harness.SERVER.pid),
                "--guardian-created-filetime", str(harness.SERVER.created_filetime_100ns),
                "--endpoint-instance-id", harness.INSTANCE, *extra]

    # --- the managed run --------------------------------------------------

    def test_a_managed_run_returns_the_root_exit_code(self):
        self.harness.process.exited = True
        host = self.build()
        self.assertEqual(host.run(), 125)
        self.assertEqual(host.launch_state, LAUNCHED)
        self.assertEqual(self.harness.process.close_calls, 1)
        self.assertEqual(self.harness.job.close_calls, 1)

    def test_the_workload_inherits_the_real_standard_handles(self):
        self.harness.process.exited = True
        self.build().run()
        created = self.harness.native_launch.call_args.kwargs
        self.assertEqual((created["stdin_handle"], created["stdout_handle"],
                          created["stderr_handle"]), STDIO)

    def test_a_denied_admission_refuses_and_starts_nothing(self):
        self.harness.coordinator.responses = [dict(allowed=False, request_key=harness.REQUEST_KEY,
                                                   reason="commit_capacity", position=1)]
        host = self.build()
        with self.assertRaises(WrapperHostRefused) as caught:
            host.run()
        self.assertEqual(caught.exception.reason, "wrapper_host_admission_denied")
        self.assertEqual(caught.exception.detail, "commit_capacity")
        self.assertEqual(host.launch_state, NOT_ATTEMPTED)
        self.harness.native_launch.assert_not_called()

    def test_a_refused_readiness_before_the_create_reports_nothing_started(self):
        self.harness.readiness.fail_at = 1
        host = self.build()
        with self.assertRaises(WrapperHostRefused) as caught:
            host.run()
        self.assertEqual(caught.exception.reason, "wrapper_host_launch_unverified")
        self.assertEqual(host.launch_state, NOT_ATTEMPTED)
        self.harness.native_launch.assert_not_called()

    def test_an_unknown_create_outcome_is_reported_as_attempted(self):
        """A create whose outcome was lost never reports the command as started.

        The bind replay cannot rescue this case: the root was never verified,
        so reconcile_bind itself refuses. The host keeps the retained process
        and says the outcome is unknown rather than guessing either way.
        """
        self.harness.native_launch.side_effect = LaunchOutcomeUnknown(self.harness.process,
                                                                      "fixture_cause")
        host = self.build()
        with self.assertRaises(WrapperHostRefused) as caught:
            host.run()
        self.assertEqual(caught.exception.reason, "wrapper_host_launch_outcome_unknown")
        self.assertEqual(caught.exception.detail, "launcher_bind_reconciliation_unavailable")
        self.assertEqual(host.launch_state, ATTEMPTED_UNKNOWN)
        self.assertEqual(self.harness.process.close_calls, 0)

    def test_a_refusal_after_the_create_reports_the_workload_as_launched(self):
        self.harness.process.wait_error = OSError("fixture_wait_failed")
        host = self.build()
        with self.assertRaises(WrapperHostRefused) as caught:
            host.run()
        self.assertEqual(caught.exception.reason, "wrapper_host_root_unverified")
        self.assertEqual(host.launch_state, LAUNCHED)

    def test_an_expired_wait_refuses_without_closing_custody(self):
        ticks = iter([0, 100, 200, 300])
        clock = SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda seconds: None)
        host = self.build(max_wait_sec=1)
        with patch.object(module, "time", clock):
            with self.assertRaises(WrapperHostRefused) as caught:
                host.run()
        self.assertEqual(caught.exception.reason, "wrapper_host_root_wait_expired")
        self.assertEqual(host.launch_state, LAUNCHED)
        self.assertEqual(self.harness.process.close_calls, 0)

    def test_a_release_after_a_post_launch_refusal_never_forces_a_close(self):
        self.harness.process.wait_error = OSError("fixture_wait_failed")
        host = self.build()
        with self.assertRaises(WrapperHostRefused):
            host.run()
        self.harness.process.wait_error = None
        record = host.release()
        self.assertEqual(record, {"closed": False, "reason": "launcher_custody_unsettled"})
        self.assertEqual(self.harness.process.close_calls, 0)

    # --- what the host wires ----------------------------------------------

    def test_the_launcher_receives_the_live_host_authority_and_the_real_coordinator(self):
        self.harness.process.exited = True
        host = self.build()
        host.run()
        self.assertIsInstance(self.passed.readiness, HostAuthority)
        self.assertIs(self.passed.readiness.store, host.store)
        self.assertEqual(host.store.db_path, (self.directory / "sentinel.db").resolve())
        self.assertEqual(self.passed.coordinator.db_path, self.directory / "sentinel.db")
        self.assertEqual(self.passed.endpoint.server_identity.pid, harness.SERVER.pid)
        self.assertEqual(self.passed.endpoint.instance_id, harness.INSTANCE)
        self.assertEqual(self.passed.guardian_epoch, harness.GUARDIAN)
        self.assertEqual(self.passed.spec.requested, ResourceDemand(1.0, GIB, GIB, 0))

    def test_an_unreadable_status_file_refuses_before_any_admission(self):
        (self.directory / "status.json").unlink()
        with self.assertRaises(WrapperHostRefused) as caught:
            self.build().run()
        self.assertEqual(caught.exception.reason, "wrapper_host_status_unavailable")
        self.assertEqual(self.harness.coordinator.calls, [])

    def test_the_capability_preflight_runs_before_anything_is_opened(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        with patch.object(module, "read_host_capability",
                          side_effect=module.HostCapabilityUnsupported(reason)):
            with self.assertRaises(WrapperHostRefused) as caught:
                self.build().run()
        self.assertEqual(caught.exception.reason, reason)
        self.assertEqual(self.harness.coordinator.calls, [])

    # --- arguments --------------------------------------------------------

    def test_a_fractional_estimate_rounds_up(self):
        options = SimpleNamespace(cpu_units=1.5, ram_gib=1.5, commit_gib=None, io_slots=0)
        demand = module.parse_demand(options)
        self.assertEqual(demand.physical_bytes, GIB + GIB // 2)
        options = SimpleNamespace(cpu_units=1, ram_gib=0.1, commit_gib=None, io_slots=0)
        self.assertEqual(module.parse_demand(options).physical_bytes, 107374183)

    def test_the_timeout_bounds_apply_to_a_direct_construction_too(self):
        with self.assertRaises(WrapperHostRefused) as caught:
            self.build(rpc_timeout_ms=5000)
        self.assertEqual(caught.exception.reason, "wrapper_host_arguments_invalid")
        with self.assertRaises(WrapperHostRefused):
            self.build(poll_interval_ms=0)
        with self.assertRaises(WrapperHostRefused):
            self.build(max_wait_sec=-1)

    def test_an_unknown_role_is_refused(self):
        options = SimpleNamespace(role="supervisor", priority="P2")
        with self.assertRaises(WrapperHostRefused) as caught:
            module.parse_role_priority(options)
        self.assertEqual(caught.exception.reason, "wrapper_host_role_or_priority_invalid")

    # --- the entry point --------------------------------------------------

    def run_main(self, host, *extra):
        with patch.object(module, "WrapperHost", return_value=host):
            return module.main(self.arguments(*extra))

    def test_require_managed_exits_with_the_refusal_code_and_the_typed_reason(self):
        self.harness.coordinator.responses = [dict(allowed=False, request_key=harness.REQUEST_KEY,
                                                   reason="commit_capacity", position=1)]
        host = self.build()
        records = []
        with patch.object(module, "emit", side_effect=records.append):
            code = self.run_main(host, "--require-managed")
        self.assertEqual(code, EXIT_REFUSED)
        refusal = records[-1]
        self.assertEqual(refusal["event"], "wrapper_host_refused")
        self.assertEqual(refusal["reason"], "wrapper_host_admission_denied")
        self.assertIs(refusal["command_started"], False)
        self.harness.native_launch.assert_not_called()

    def test_without_require_managed_the_command_is_still_not_run(self):
        self.harness.coordinator.responses = [dict(allowed=False, request_key=harness.REQUEST_KEY,
                                                   reason="commit_capacity", position=1)]
        host = self.build()
        records = []
        with patch.object(module, "emit", side_effect=records.append):
            code = self.run_main(host)
        self.assertEqual(code, EXIT_UNMANAGED)
        self.assertEqual(records[-1]["event"], "wrapper_host_unmanaged")
        self.assertIs(records[-1]["command_started"], False)
        self.harness.native_launch.assert_not_called()

    def test_a_post_launch_refusal_has_its_own_exit_code_and_event(self):
        self.harness.process.wait_error = OSError("fixture_wait_failed")
        host = self.build()
        records = []
        with patch.object(module, "emit", side_effect=records.append):
            code = self.run_main(host, "--require-managed")
        self.assertEqual(code, EXIT_POST_LAUNCH)
        self.assertEqual(records[-1]["event"], "wrapper_host_post_launch_refused")
        self.assertIs(records[-1]["command_started"], True)
        self.assertEqual(records[-1]["launch_state"], LAUNCHED)

    def test_a_completed_run_returns_the_root_exit_code_from_main(self):
        self.harness.process.exited = True
        host = self.build()
        with patch.object(module, "emit"):
            self.assertEqual(self.run_main(host), 125)


class WrapperHostSubprocessTests(unittest.TestCase):
    def run_host(self, *arguments):
        return subprocess.run([sys.executable, "-m", "sentinel.adaptive.wrapper_host", *arguments],
                              cwd=REPO_ROOT, capture_output=True, text=True, timeout=120)

    def test_help_is_available(self):
        result = self.run_host("run-managed", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--require-managed", result.stdout)

    def test_a_run_on_an_isolated_data_directory_refuses_with_a_typed_reason(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_host("run-managed", "--data-dir", directory,
                                   "--command", "echo fixture", "--cwd", directory,
                                   "--repo", "fixture-repo", "--cpu-units", "1", "--ram-gib", "1",
                                   "--guardian-epoch", "guardian-fixture",
                                   "--guardian-pid", "4242",
                                   "--guardian-created-filetime", "134343072000000003",
                                   "--endpoint-instance-id", harness.INSTANCE,
                                   "--require-managed")
        self.assertEqual(result.returncode, EXIT_REFUSED)
        record = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(record["event"], "wrapper_host_refused")
        self.assertEqual(record["reason"], reason)
        self.assertIs(record["command_started"], False)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
