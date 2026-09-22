"""Portable operational CLI contracts; every process/pipe is a named fixture.

These tests perform no native launch, no control write, and no live data access.
Read-only tests use temporary paths and the real bounded diagnostic reader.
"""
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import operational_cli as cli
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.host_discovery import EndpointLocator, HostDescriptor
from sentinel.adaptive.operator_messages import OperatorOperation, OperatorOutcome, OperatorReply
from sentinel.adaptive.pipe_windows import NativePipeEndpoint


LOGON = "S-1-5-5-123-456"
DATA = "explicit-isolated-target"


def descriptor_fixture():
    parent = ProcessIdentity(801, 134342000123456781, LOGON)
    child = ProcessIdentity(802, 134342000123456782, LOGON)
    instance, policy = str(uuid4()), str(uuid4())

    def endpoints(identity, roles):
        return tuple(EndpointLocator(role, NativePipeEndpoint(LOGON, str(uuid4()), identity))
                     for role in roles)

    guardian = HostDescriptor(str(uuid4()), policy, LOGON, "test-epoch", "guardian", child,
        endpoints(child, ("operator", "launch", "query", "control")), "ready", 1,
        parent_identity=parent, parent_instance_id=instance)
    return HostDescriptor(instance, policy, LOGON, "test-epoch", "supervisor", parent,
        endpoints(parent, ("operator",)), "ready", 1, guardian=guardian)


class CallerFixture:
    def __init__(self):
        self.identity = ProcessIdentity(803, 134342000123456783, LOGON)
        self.enters = 0
        self.closes = 0
        self.close_error = None

    def __enter__(self):
        self.enters += 1
        return self

    def __exit__(self, *exc):
        self.closes += 1
        if self.close_error is not None:
            raise self.close_error


class ClockFixture:
    def __init__(self):
        self.value = 10.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


def reply_fixture(request, outcome="complete", **changes):
    fields = dict(request_id=request.request_id, operation=request.operation,
        instance_id=request.instance_id, policy_instance_id=request.policy_instance_id,
        guardian_epoch=request.guardian_epoch, outcome=OperatorOutcome(outcome), scope="instance",
        reason="fixture_result", inventory_complete=True, native_disabled=True,
        bookkeeping_settled=True, slot_released=True, barrier_cleared=True,
        cleanup_settled=True, registry_revision=7, remaining_executions=0, remaining_custody=0)
    if request.operation is OperatorOperation.DRAIN:
        fields.update(accepted=True, desired_mode="off")
    fields.update(changes)
    return OperatorReply(**fields)


def script_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "sentinelctl.py"
    spec = importlib.util.spec_from_file_location("sentinelctl_operational_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OperationalCliFixture(unittest.TestCase):
    def setUp(self):
        self.caller = CallerFixture()
        self.descriptor = descriptor_fixture()
        self.clock = ClockFixture()
        self.client = Mock()
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request)
        self.current = self.patch("_current_process", return_value=self.caller)
        self.discover = self.patch("_discovery", return_value=self.descriptor)
        self.client_factory = self.patch("_client", return_value=self.client)
        self.ledger = self.patch("_ledger", return_value={"available": True,
            "recorded_mode": "off", "registry_revision": 7, "native_readiness": "unverified"})
        for name, value in (("monotonic", self.clock.monotonic), ("sleep", self.clock.sleep)):
            patcher = patch.object(cli.time, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def patch(self, name, **kwargs):
        patcher = patch.object(cli, name, **kwargs)
        value = patcher.start()
        self.addCleanup(patcher.stop)
        return value

    def invoke(self, *arguments, target=DATA):
        argv = (["--data-dir", target] if target is not None else []) + list(arguments)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, json.loads(out.getvalue()), err.getvalue()


class OperationalCliTests(OperationalCliFixture):
    def test_explicit_target_required_before_any_native_or_ledger_access(self):
        code, result, _ = self.invoke("adaptive-status", target=None)
        self.assertEqual(code, 2)
        self.assertEqual(result["reason"], "operational_explicit_data_dir_required")
        self.ledger.assert_not_called()
        self.current.assert_not_called()
        self.client.request.assert_not_called()

    def test_operational_dispatch_precedes_legacy_service_construction(self):
        module = script_module()
        with patch.object(module, "Coordinator") as coordinator, \
                patch.object(module, "Exemptions") as exemptions, \
                patch("sys.argv", ["sentinelctl", "--data-dir", DATA, "adaptive-status"]), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(module.main(), 0)
        coordinator.assert_not_called()
        exemptions.assert_not_called()
        self.ledger.assert_called_once_with(DATA)

    def test_legacy_snapshot_keeps_its_default_data_directory(self):
        module = script_module()
        with tempfile.TemporaryDirectory() as root, \
                patch.dict(module.os.environ, {"USERPROFILE": root}), \
                patch.object(module, "Coordinator") as coordinator, \
                patch("sys.argv", ["sentinelctl", "snapshot"]), \
                redirect_stdout(io.StringIO()):
            coordinator.return_value.snapshot.return_value = {"queue": []}
            self.assertEqual(module.main(), 0)
            coordinator.assert_called_once_with(str(Path(root) / ".resource-sentinel"))
        self.current.assert_not_called()

    def test_declared_outcomes_have_distinct_exit_codes(self):
        for outcome, expected in (("complete", 0), ("refused", 2), ("pending", 3),
                                  ("unavailable", 4), ("unverified", 5)):
            with self.subTest(outcome=outcome):
                self.client.request.side_effect = lambda request, **kw: reply_fixture(request, outcome)
                code, result, _ = self.invoke("adaptive-status")
                self.assertEqual(code, expected)
                self.assertEqual(result["outcome"], outcome)

    def test_complete_audit_requires_each_separate_evidence_flag(self):
        for field in ("inventory_complete", "native_disabled", "bookkeeping_settled",
                      "slot_released", "cleanup_settled"):
            for value in (None, False):
                with self.subTest(field=field, value=value):
                    self.client.request.side_effect = lambda request, **kw: reply_fixture(
                        request, **{field: value})
                    code, result, _ = self.invoke("adaptive-audit", "--require-no-active-caps")
                    self.assertEqual(code, 5)
                    self.assertEqual(result["reason"], "operational_completion_unverified")

    def test_no_active_caps_does_not_require_jobs_to_be_empty(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request,
            barrier_cleared=False, remaining_executions=2, remaining_custody=2)
        code, result, _ = self.invoke("adaptive-audit", "--require-no-active-caps")
        self.assertEqual(code, 0)
        self.assertFalse(result["result"]["barrier_cleared"])
        self.assertEqual(result["result"]["remaining_executions"], 2)

    def test_status_complete_is_observation_without_native_restoration_claim(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request,
            native_disabled=None, cleanup_settled=None, inventory_complete=None)
        code, result, _ = self.invoke("adaptive-status")
        self.assertEqual(code, 0)
        self.assertIsNone(result["result"]["native_disabled"])

    def test_guardian_scope_cannot_claim_complete_instance_success(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, scope="guardian")
        code, result, _ = self.invoke("adaptive-status")
        self.assertEqual(code, 5)
        self.assertEqual(result["reason"], "operational_instance_scope_unverified")

    def test_drain_complete_with_remaining_custody_is_pending(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request,
            remaining_executions=0, remaining_custody=1)
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain")
        self.assertEqual(code, 3)
        self.assertEqual(result["reason"], "rollback_draining")

    def test_drain_requires_positive_acceptance_off_mode_and_complete_counts(self):
        for changes in ({"accepted": None}, {"desired_mode": None},
                        {"barrier_cleared": False}, {"barrier_cleared": None},
                        {"remaining_executions": None}, {"remaining_custody": None}):
            with self.subTest(changes=changes):
                self.client.request.side_effect = lambda request, **kw: reply_fixture(request, **changes)
                code, _, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain")
                self.assertEqual(code, 5)

    def test_default_pending_performs_exactly_one_bounded_rpc(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, "pending")
        code, _, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain")
        self.assertEqual(code, 3)
        self.client.request.assert_called_once()
        request = self.client.request.call_args.args[0]
        self.assertEqual(request.operation, OperatorOperation.DRAIN)
        self.assertEqual(request.expected_registry_revision, 7)
        self.assertEqual(self.client.request.call_args.kwargs, {"timeout_ms": 1000})
        self.assertEqual(self.caller.closes, 1)

    def test_wait_needs_explicit_finite_bounded_timeout(self):
        for suffix in (("--wait",), ("--wait", "--timeout-sec", "nan"),
                       ("--wait", "--timeout-sec", "inf"),
                       ("--wait", "--timeout-sec", "0"),
                       ("--wait", "--timeout-sec", "-1"),
                       ("--wait", "--timeout-sec", "3601"), ("--timeout-sec", "2")):
            with self.subTest(suffix=suffix):
                code, _, _ = self.invoke("adaptive-status", *suffix)
                self.assertEqual(code, 2)
        self.client.request.assert_not_called()
        self.ledger.assert_not_called()

    def test_wait_observes_same_mutation_without_replay_or_rediscovery(self):
        requests = []

        def respond(request, **kw):
            requests.append(request)
            return reply_fixture(request, "pending" if len(requests) == 1 else "complete",
                                 accepted=True, desired_mode="off")

        self.client.request.side_effect = respond
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain",
                                      "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 0)
        self.assertEqual([item.operation for item in requests],
                         [OperatorOperation.DRAIN, OperatorOperation.DESCRIBE])
        self.assertEqual(requests[1].observe_request_id, requests[0].request_id)
        self.assertNotEqual(requests[0].request_id, requests[1].request_id)
        self.assertEqual(result["operation_request_id"], requests[0].request_id)
        self.assertEqual({item.instance_id for item in requests}, {self.descriptor.instance_id})
        self.assertEqual({item.guardian_epoch for item in requests}, {"test-epoch"})
        self.discover.assert_called_once()
        self.client_factory.assert_called_once_with(self.descriptor, self.caller)
        self.assertEqual((self.caller.enters, self.caller.closes), (1, 1))

    def test_fresh_observer_uses_saved_exact_binding_without_mutation_replay(self):
        original = str(uuid4())
        code, result, _ = self.invoke("adaptive-status", "--observe-request-id", original,
            "--instance-id", self.descriptor.instance_id,
            "--policy-instance-id", self.descriptor.policy_instance_id,
            "--guardian-epoch", self.descriptor.guardian_epoch)
        self.assertEqual(code, 0)
        request = self.client.request.call_args.args[0]
        self.assertEqual(request.operation, OperatorOperation.DESCRIBE)
        self.assertEqual(request.observe_request_id, original)
        self.assertNotEqual(request.request_id, original)
        self.assertFalse(request.mutating)
        self.assertEqual(result["operation_request_id"], original)
        self.assertEqual(result["policy_instance_id"], self.descriptor.policy_instance_id)

    def test_fresh_observer_refuses_incomplete_or_invalid_binding_before_reads(self):
        for suffix in (("--observe-request-id", str(uuid4())),
                       ("--instance-id", str(uuid4())),
                       ("--observe-request-id", "invalid", "--instance-id", str(uuid4()),
                        "--policy-instance-id", str(uuid4()), "--guardian-epoch", "epoch")):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.invoke("adaptive-status", *suffix)[0], 2)
        self.current.assert_not_called()
        self.ledger.assert_not_called()

    def test_fresh_observer_will_not_target_replacement_instance_policy_or_epoch(self):
        for changed in ("instance_id", "policy_instance_id", "guardian_epoch"):
            values = {name: getattr(self.descriptor, name)
                      for name in ("instance_id", "policy_instance_id", "guardian_epoch")}
            values[changed] = "different-epoch" if changed == "guardian_epoch" else str(uuid4())
            with self.subTest(changed=changed):
                code, result, _ = self.invoke("adaptive-status", "--observe-request-id", str(uuid4()),
                    "--instance-id", values["instance_id"], "--policy-instance-id", values["policy_instance_id"],
                    "--guardian-epoch", values["guardian_epoch"])
                self.assertEqual(code, 2)
                self.assertEqual(result["reason"], "operational_observer_target_changed")
        self.client_factory.assert_not_called()
        self.client.request.assert_not_called()

    def test_saved_observer_wait_keeps_original_id_across_describe_requests(self):
        original = str(uuid4())
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, "pending")
        code, result, _ = self.invoke("adaptive-status", "--observe-request-id", original,
            "--instance-id", self.descriptor.instance_id,
            "--policy-instance-id", self.descriptor.policy_instance_id,
            "--guardian-epoch", self.descriptor.guardian_epoch, "--wait", "--timeout-sec", "0.3")
        self.assertEqual(code, 3)
        self.assertEqual(result["operation_request_id"], original)
        calls = self.client.request.call_args_list
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(call.args[0].observe_request_id == original for call in calls))
        self.assertTrue(all(not call.args[0].mutating for call in calls))

    def test_plain_status_wait_refreshes_without_inventing_retained_mutation(self):
        requests = []

        def respond(request, **kw):
            requests.append(request)
            return reply_fixture(request, "pending" if len(requests) == 1 else "complete")

        self.client.request.side_effect = respond
        code, _, _ = self.invoke("adaptive-status", "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 0)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(item.operation is OperatorOperation.DESCRIBE for item in requests))
        self.assertTrue(all(item.observe_request_id is None for item in requests))

    def test_bounded_wait_timeout_keeps_known_pending_owner(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, "pending")
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain",
                                      "--wait", "--timeout-sec", "0.1")
        self.assertEqual(code, 3)
        self.assertEqual(result["reason"], "operational_wait_timeout")
        self.client.request.assert_called_once()
        self.assertLessEqual(self.client.request.call_args.kwargs["timeout_ms"], 100)
        self.assertEqual(self.caller.closes, 1)

    def test_lost_mutation_reply_is_unknown_and_never_retried(self):
        error = RuntimeError("PRIVATE-ERROR-TEXT")
        error.outcome_unknown = True
        self.client.request.side_effect = error
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain",
                                      "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 5)
        self.assertEqual(result["outcome"], "unverified")
        self.assertIn("operation_request_id", result)
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.client.request.assert_called_once()

    def test_unexpected_mutation_error_cannot_claim_clean_unavailable(self):
        self.client.request.side_effect = RuntimeError("PRIVATE")
        code, _, _ = self.invoke("adaptive-recover", "--restore-only", "--verify")
        self.assertEqual(code, 5)
        self.client.request.assert_called_once()

    def test_positive_transport_not_delivered_remains_unavailable(self):
        error = RuntimeError("PRIVATE")
        error.outcome_unknown = False
        self.client.request.side_effect = error
        code, _, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain")
        self.assertEqual(code, 4)

    def test_lost_read_reply_after_write_is_unverified(self):
        error = RuntimeError("PRIVATE")
        error.outcome_unknown = True
        self.client.request.side_effect = error
        code, _, _ = self.invoke("adaptive-status")
        self.assertEqual(code, 5)
        self.client.request.assert_called_once()

    def test_unexpected_read_error_without_delivery_metadata_is_unverified(self):
        self.client.request.side_effect = RuntimeError("PRIVATE unexpected read")
        code, result, _ = self.invoke("adaptive-status")
        self.assertEqual(code, 5)
        self.assertEqual(result["outcome"], "unverified")
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.client.request.assert_called_once()

    def test_observer_interrupt_preserves_operation_identity_and_closes_once(self):
        error = KeyboardInterrupt()
        error.operator_outcome_unknown = True
        self.client.request.side_effect = error
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain",
                                      "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 130)
        self.assertTrue(result["outcome_unknown"])
        self.assertEqual(result["operation_request_id"], self.client.request.call_args.args[0].request_id)
        self.client.request.assert_called_once()
        self.assertEqual(self.caller.closes, 1)

    def test_ambiguous_native_close_cannot_return_success_or_reopen_handle(self):
        error = RuntimeError("PRIVATE-CLOSE")
        error._native_close_outcome_unknown = True
        self.caller.close_error = error
        code, result, _ = self.invoke("adaptive-status")
        self.assertEqual(code, 5)
        self.assertEqual(result["outcome"], "unverified")
        self.current.assert_called_once()
        self.client.request.assert_called_once()
        self.assertEqual(self.caller.closes, 1)

    def test_mismatched_reply_binding_and_untyped_result_are_unverified(self):
        for changes in ({"request_id": str(uuid4())}, {"instance_id": str(uuid4())},
                        {"policy_instance_id": str(uuid4())}, {"guardian_epoch": "different"},
                        {"operation": OperatorOperation.AUDIT}):
            with self.subTest(changes=changes):
                self.client.request.side_effect = lambda request, **kw: reply_fixture(request, **changes)
                self.assertEqual(self.invoke("adaptive-status")[0], 5)
        self.client.request.side_effect = lambda request, **kw: {"outcome": "complete"}
        self.assertEqual(self.invoke("adaptive-status")[0], 5)

    def test_audit_default_does_not_silently_fetch_next_page(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, "pending",
            inventory_complete=False, next_cursor="page.2")
        code, result, _ = self.invoke("adaptive-audit", "--require-no-active-caps")
        self.assertEqual(code, 3)
        self.assertEqual(result["result"]["next_cursor"], "page.2")
        self.client.request.assert_called_once()

    def test_incomplete_audit_without_cursor_is_unverified_without_observer_rpc(self):
        self.client.request.side_effect = lambda request, **kw: reply_fixture(request, "pending",
            inventory_complete=False, next_cursor=None)
        code, result, _ = self.invoke("adaptive-audit", "--require-no-active-caps",
                                      "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 5)
        self.assertEqual(result["reason"], "operational_audit_incomplete")
        self.client.request.assert_called_once()

    def test_audit_wait_uses_distinct_read_id_and_pinned_page_revision(self):
        requests = []

        def respond(request, **kw):
            requests.append(request)
            if len(requests) == 1:
                return reply_fixture(request, "pending", inventory_complete=False, next_cursor="page.2")
            return reply_fixture(request)

        self.client.request.side_effect = respond
        code, _, _ = self.invoke("adaptive-audit", "--require-no-active-caps",
                                 "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 0)
        self.assertEqual(len(requests), 2)
        self.assertTrue(all(request.operation is OperatorOperation.AUDIT for request in requests))
        self.assertNotEqual(requests[0].request_id, requests[1].request_id)
        self.assertEqual(requests[1].cursor, "page.2")
        self.assertEqual(requests[1].expected_registry_revision, 7)

    def test_audit_cannot_finish_after_page_revision_changes(self):
        count = 0

        def respond(request, **kw):
            nonlocal count
            count += 1
            if count == 1:
                return reply_fixture(request, "pending", inventory_complete=False, next_cursor="page.2")
            return reply_fixture(request, registry_revision=8)

        self.client.request.side_effect = respond
        code, result, _ = self.invoke("adaptive-audit", "--require-no-active-caps",
                                      "--wait", "--timeout-sec", "2")
        self.assertEqual(code, 5)
        self.assertEqual(result["reason"], "operational_audit_revision_changed")

    def test_recovery_reaches_retained_owner_when_ledger_is_unavailable(self):
        self.ledger.return_value = {"available": False, "reason": "database_busy"}
        code, result, _ = self.invoke("adaptive-recover", "--restore-only", "--verify")
        self.assertEqual(code, 0)
        self.assertFalse(result["ledger"]["available"])
        self.assertEqual(self.client.request.call_args.args[0].operation, OperatorOperation.RESTORE_ONLY)

    def test_unexpected_diagnostic_failure_does_not_block_retained_recovery(self):
        self.ledger.side_effect = OSError("PRIVATE database path")
        code, result, _ = self.invoke("adaptive-recover", "--restore-only", "--verify")
        self.assertEqual(code, 0)
        self.assertEqual(result["ledger"], {"available": False, "reason": "OSError"})
        self.client.request.assert_called_once()

    def test_unavailable_ledger_prevents_status_and_audit_complete_claim(self):
        self.ledger.return_value = {"available": False, "reason": "database_busy"}
        for args in (("adaptive-status",), ("adaptive-audit", "--require-no-active-caps")):
            with self.subTest(args=args):
                code, result, _ = self.invoke(*args)
                self.assertEqual(code, 4)
                self.assertEqual(result["reason"], "operational_ledger_unavailable")
        self.current.assert_not_called()
        self.client.request.assert_not_called()

    def test_drain_cannot_mutate_without_exact_registry_revision(self):
        self.ledger.return_value = {"available": False, "reason": "database_busy"}
        code, result, _ = self.invoke("adaptive-mode", "--mode", "off", "--drain")
        self.assertEqual(code, 4)
        self.assertEqual(result["reason"], "operational_registry_revision_unavailable")
        self.current.assert_not_called()
        self.client.request.assert_not_called()


class ManagedCliTests(OperationalCliFixture):
    def run_args(self, *extra, command='python -c "print(\'測試 C:\\two words\')"'):
        return ["--data-dir", DATA, "run-managed", "--command", command,
                "--cwd", "working directory", "--repo", "repo-id", "--cpu-units", "1",
                "--ram-gib", "2.5", *extra]

    def manual(self):
        return ["--guardian-epoch", "manual-epoch", "--guardian-pid", "902",
                "--guardian-created-filetime", "134342000123456789",
                "--endpoint-instance-id", str(uuid4())]

    def test_managed_workload_stdio_and_nonzero_child_exit_are_preserved(self):
        from sentinel.adaptive import wrapper_host
        raw = 'python -c "print(\'測試 C:\\two words\')"'
        out, err = io.StringIO(), io.StringIO()

        def workload(argv):
            print("actual workload output")
            print("actual workload error", file=__import__("sys").stderr)
            self.assertEqual(argv[argv.index("--command") + 1], raw)
            return 7

        with patch.object(wrapper_host, "main", side_effect=workload) as wrapper, \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(cli.main(self.run_args(*self.manual(), command=raw)), 7)
        self.assertEqual(out.getvalue(), "actual workload output\n")
        self.assertEqual(err.getvalue(), "actual workload error\n")
        wrapper.assert_called_once()
        self.discover.assert_not_called()
        self.ledger.assert_not_called()

    def test_discovery_supplies_exact_child_endpoint_without_claiming_authority(self):
        from sentinel.adaptive import wrapper_host
        with patch.object(wrapper_host, "main", return_value=0) as wrapper:
            self.assertEqual(cli.main(self.run_args()), 0)
        argv = wrapper.call_args.args[0]
        child = self.descriptor.guardian
        endpoint = next(item.endpoint for item in child.endpoints if item.role == "launch")
        self.assertEqual(argv[argv.index("--guardian-pid") + 1], str(child.host_identity.pid))
        self.assertEqual(argv[argv.index("--guardian-created-filetime") + 1],
                         str(child.host_identity.created_filetime_100ns))
        self.assertEqual(argv[argv.index("--endpoint-instance-id") + 1], endpoint.instance_id)
        self.assertEqual(argv[argv.index("--guardian-epoch") + 1], child.guardian_epoch)
        self.assertEqual(self.caller.closes, 1)
        self.client_factory.assert_not_called()
        self.ledger.assert_not_called()

    def test_partial_manual_endpoint_refuses_before_wrapper_or_discovery(self):
        from sentinel.adaptive import wrapper_host
        out, err = io.StringIO(), io.StringIO()
        with patch.object(wrapper_host, "main") as wrapper, redirect_stdout(out), redirect_stderr(err):
            code = cli.main(self.run_args("--guardian-epoch", "partial", "--require-managed"))
        self.assertEqual(code, wrapper_host.EXIT_REFUSED)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("operational_partial_guardian_endpoint", err.getvalue())
        wrapper.assert_not_called()
        self.discover.assert_not_called()

    def test_not_ready_guardian_refuses_without_invoking_workload(self):
        from sentinel.adaptive import wrapper_host
        child = replace(self.descriptor.guardian, state="draining")
        self.discover.return_value = replace(self.descriptor, state="draining", guardian=child)
        with patch.object(wrapper_host, "main") as wrapper, redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(self.run_args("--require-managed")), wrapper_host.EXIT_REFUSED)
        wrapper.assert_not_called()
        self.assertEqual(self.caller.closes, 1)

    def test_execution_stage_failures_are_never_reclassified_as_never_started(self):
        from sentinel.adaptive import wrapper_host
        for error in (RuntimeError("fixture postlaunch"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), \
                    patch.object(wrapper_host, "main", side_effect=error), \
                    patch.object(wrapper_host, "_refused") as refused:
                with self.assertRaises(type(error)):
                    cli.main(self.run_args(*self.manual()))
                refused.assert_not_called()


class OperationalReadOnlyTests(unittest.TestCase):
    def invoke(self, target, command):
        out = io.StringIO()
        args = ["--data-dir", str(target), command]
        if command == "adaptive-audit":
            args.append("--require-no-active-caps")
        with redirect_stdout(out), patch.object(cli, "_current_process", side_effect=RuntimeError("fixture")):
            result = cli.main(args)
        return result, json.loads(out.getvalue())

    def test_missing_target_status_and_audit_create_no_path_or_database(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "missing"
            for command in ("adaptive-status", "adaptive-audit"):
                with self.subTest(command=command):
                    code, result = self.invoke(target, command)
                    self.assertEqual(code, 4)
                    self.assertEqual(result["ledger"]["reason"], "database_missing")
                    self.assertFalse(target.exists())

    def test_incompatible_database_status_and_audit_never_migrate(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root)
            database = target / "sentinel.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE legacy_only (id INTEGER)")
                connection.commit()
            before = {path.name: path.read_bytes() for path in target.iterdir()}
            for command in ("adaptive-status", "adaptive-audit"):
                with self.subTest(command=command):
                    code, result = self.invoke(target, command)
                    self.assertEqual(code, 4)
                    self.assertEqual(result["ledger"]["reason"], "adaptive_schema_missing")
                    self.assertEqual(before, {path.name: path.read_bytes() for path in target.iterdir()})

    def test_discovery_reader_pins_same_logon_and_rejects_direct_guardian_instance(self):
        from sentinel.adaptive.host_discovery import HostDiscovery
        caller, descriptor = CallerFixture(), descriptor_fixture()
        with patch.object(HostDiscovery, "read_instance", return_value=descriptor), \
                patch.object(HostDiscovery, "__init__", return_value=None) as constructor:
            self.assertEqual(cli._discovery(DATA, caller), descriptor)
            constructor.assert_called_once_with(DATA, logon_id=caller.identity.logon_id)
        with patch.object(HostDiscovery, "read_instance", return_value=descriptor.guardian), \
                patch.object(HostDiscovery, "__init__", return_value=None):
            with self.assertRaises(cli.OperationalRefused):
                cli._discovery(DATA, caller)

    def test_endpoint_lookup_rejects_duplicate_or_different_native_identity(self):
        descriptor = descriptor_fixture()
        endpoint = descriptor.endpoints[0]
        with self.assertRaises(cli.OperationalRefused):
            cli._endpoint(SimpleNamespace(endpoints=(endpoint, endpoint),
                host_identity=descriptor.host_identity), "operator")
        with self.assertRaises(cli.OperationalRefused):
            cli._endpoint(SimpleNamespace(endpoints=(endpoint,),
                host_identity=descriptor.guardian.host_identity), "operator")


if __name__ == "__main__":
    unittest.main()
