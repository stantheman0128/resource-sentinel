"""Guardian operational wiring with explicit in-process owners and transports.

No real listener, process, Job, descriptor publisher or control is created.
Transport authentication and durable proof have separate integration suites;
these tests check that the host preserves those owners and their exit gates.
"""
from contextlib import redirect_stdout
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import guardian_host as module
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.guardian_host import GuardianHost, GuardianHostRefused
from sentinel.adaptive.guardian_lifecycle import GuardianLifecycle
from sentinel.adaptive.host_discovery import DiscoveryError, HostDiscovery
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.operator_messages import OperatorOperation, OperatorOutcome, OperatorReply
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.terminal_custody import TerminalCleanupResult
from tests.test_adaptive_guardian_host import (
    Control, EPOCH, EXECUTION, GUARDIAN, LOGON, Listener, Owner, ProcessBackend, Service, apply_ack,
    install_pipe_fixture,
)


class OperationsFixture:
    """Each accepted operation has its own independent settlement state."""
    def __init__(self, events):
        self.events = events
        self.operations = {}
        self.hold_pending = False
        self.tick_count = 0
        self.on_tick = None
        self.latest = {"outcome": OperatorOutcome.COMPLETE, "barrier_cleared": True,
                       "remaining_custody": 0}

    @property
    def settled(self):
        return not self.hold_pending and all(self.operations.values())

    def tick(self):
        self.events.append(("operations_tick",))
        self.tick_count += 1
        if self.on_tick is not None:
            self.on_tick()
        return self.latest


class GuardianOperationsHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.events = []
        self.pipe_registry = install_pipe_fixture(self)
        self.host = GuardianHost(data_dir=self.directory, journal_dir=self.directory / "journal",
            guardian_epoch=EPOCH, rpc_timeout_ms=100, sleep=lambda seconds: None)
        self.host.owner = Owner(self.events)
        self.host.control = Control(self.events)
        for role in ("launch", "query", "control"):
            setattr(self.host, role + "_service", Service(role, self.events))
            setattr(self.host, role + "_listener", Listener(role, self.events))
        self.host.control_service.result = apply_ack()
        self.host._started = True

    def attach_operator(self, *, before_serve=None):
        self.host.policy_instance_id = str(uuid4())
        service = Service("operator", self.events)
        service.before_serve = before_serve
        service.result = OperatorReply(str(uuid4()), OperatorOperation.DRAIN,
            self.host.instance_id, self.host.policy_instance_id, EPOCH,
            OperatorOutcome.PENDING, "guardian", "operator_drain_pending", accepted=True,
            desired_mode="off", host_state="draining")
        self.host.operator_service = service
        self.host.operator_listener = Listener("operator", self.events)
        return service

    def test_operator_drain_precedes_launch_in_the_same_iteration(self):
        self.attach_operator(before_serve=self.host.begin_drain)
        self.host.launch_service.before_serve = lambda: self.host.owner.dispatch_fixture("prepare")
        record = self.host.run_once()
        self.assertEqual(self.events[:4], [
            ("tick", 1000), ("operator", 100, "operator"), ("owner_begin_drain",), ("begin_drain",)])
        self.assertTrue(record["operator_rpc"]["served"])
        self.assertEqual(record["operator_rpc"]["result"]["outcome"], "pending")
        self.assertEqual(record["launch_rpc"], {"served": False, "reason": "guardian_draining"})
        self.assertEqual(self.host.owner.new_authorizations, [])
        self.assertEqual(sum(event[0] == "launch" for event in self.events), 1)
        self.assertTrue(record["control_rpc"]["served"])
        self.assertTrue(record["query_rpc"]["served"])
        self.assertTrue(self.host._draining)
        self.assertTrue(self.host.control.draining)

    def test_drain_is_irreversible_when_later_iterations_use_default_launch_flag(self):
        self.host.launch_service.before_serve = lambda: self.host.owner.dispatch_fixture("claim")
        first = self.host.run_once(serve_launch=False)
        second = self.host.run_once()
        self.assertEqual(first["launch_rpc"], {"served": False, "reason": "guardian_draining"})
        self.assertEqual(second["launch_rpc"], {"served": False, "reason": "guardian_draining"})
        self.assertEqual(self.host.owner.new_authorizations, [])
        self.assertEqual([event for event in self.events if event[0] == "begin_drain"],
                         [("begin_drain",)])
        self.assertEqual([event[0] for event in self.events if event[0] in {"launch", "control", "query"}],
                         ["launch", "control", "query", "launch", "control", "query"])

    def test_drain_keeps_bind_cancel_and_original_request_replay_reachable(self):
        for index, operation in enumerate(("bind_root", "cancel", "start_failed", "original_prepare_replay")):
            self.host.launch_service.before_serve = lambda: self.host.owner.dispatch_fixture(operation)
            record = self.host.run_once(serve_launch=index != 0)
            self.assertTrue(self.host.owner.draining)
            self.assertTrue(record["launch_rpc"]["served"])
        self.assertEqual(self.host.owner.recovery_requests,
                         ["bind_root", "cancel", "start_failed", "original_prepare_replay"])
        self.assertEqual(self.host.owner.new_authorizations, [])

    def test_operator_drain_stops_the_unbounded_normal_loop(self):
        self.attach_operator(before_serve=self.host.begin_drain)
        with patch.object(module, "emit"):
            result = self.host.serve_until_stopped()
        self.assertEqual(result, {"event": "guardian_host_stopping", "reason": "operator_drain",
                                  "iterations": 1})
        self.assertTrue(self.host.owner.draining)
        self.assertEqual(sum(event[0] == "launch" for event in self.events), 1)

    def test_terminal_cleanup_retries_without_reentering_normal_reconciliation(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = [EXECUTION]
        lifecycle.cleanup_started.add(EXECUTION)
        lifecycle.errors[EXECUTION] = AssertionError("closed Job must never be queried")
        lifecycle.retire_results[EXECUTION] = TerminalCleanupResult(
            EXECUTION, False, True, False, "fixture_known_close_pending", ("root",))
        first = self.host.run_once()
        self.assertEqual(first["reconciled"], [])
        self.assertEqual(first["reconcile_errors"], [])
        self.assertEqual(first["terminal_retirements"], [{"execution_id": EXECUTION,
            "complete": False, "pending": True, "reason": "fixture_known_close_pending"}])
        self.assertEqual(self.host.retained_execution_ids(), (EXECUTION,))
        lifecycle.retire_results.clear()
        second = self.host.run_once()
        self.assertTrue(second["terminal_retirements"][0]["complete"])
        self.assertEqual(self.host.retained_execution_ids(), ())
        self.assertFalse(any(event[0] == "reconcile" for event in self.events))
        self.assertEqual(sum(event[0] == "retire_terminal" for event in self.events), 2)

    def test_latest_completed_operation_cannot_hide_an_earlier_pending_owner(self):
        operations = OperationsFixture(self.events)
        operations.operations = {str(uuid4()): False, str(uuid4()): True}
        self.host.operations = operations
        self.host._operation_result = operations.latest
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_operation_unsettled")
        self.assertFalse(any(event[0] == "close" for event in self.events))
        self.assertIs(self.host.operations, operations)

    def test_operation_hold_without_rows_still_prevents_owner_exit(self):
        operations = OperationsFixture(self.events)
        operations.hold_pending = True
        self.host.operations = operations
        self.assertFalse(operations.operations)
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_operation_unsettled")
        self.assertFalse(any(event[0] == "close" for event in self.events))

    def test_bounded_drain_keeps_working_until_every_accepted_operation_settles(self):
        operations = OperationsFixture(self.events)
        first, second = str(uuid4()), str(uuid4())
        operations.operations = {first: False, second: True}
        self.host.operations = operations

        def settle_later():
            if operations.tick_count == 2:
                operations.operations[first] = True

        operations.on_tick = settle_later
        with patch.object(module, "emit"):
            pending = self.host.drain_until_settled(budget=1)
            self.assertFalse(pending["settled"])
            self.assertFalse(pending["exiting"])
            self.assertEqual(pending["retained"], [])
            self.assertEqual(pending["iterations"], 1)
            self.assertFalse(self.host.launch_listener.closed)
            done = self.host.drain_until_settled(budget=1)
        self.assertTrue(done["settled"])
        self.assertEqual(done["iterations"], 1)
        self.assertEqual(operations.tick_count, 2)
        self.assertTrue(self.host.owner.draining)
        self.assertEqual(sum(event[0] == "launch" for event in self.events), 2)
        self.host.close()
        self.assertTrue(self.host.launch_listener.closed)

    def test_unknown_partial_close_keeps_original_owners_without_double_close(self):
        original = self.host.query_listener
        error = RuntimeError("fixture native close unknown")
        error._native_close_outcome_unknown = True
        original.close_error = error
        with self.assertRaises(GuardianHostRefused):
            self.host.close()
        self.assertIs(self.host.query_listener, original)
        self.assertIs(self.host._cleanup_unknown["query"], error)
        self.assertTrue(self.host.launch_listener.closed)
        calls = [event for event in self.events if event[0] == "close"]
        self.assertEqual(calls.count(("close", "query")), 1)
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_cleanup_quarantined")
        self.assertEqual([event for event in self.events if event[0] == "close"], calls)

    def test_interrupt_during_close_quarantines_original_locator_before_return(self):
        original = self.host.launch_listener
        interrupt = KeyboardInterrupt()
        original.close_error = interrupt
        with self.assertRaises((KeyboardInterrupt, GuardianHostRefused)):
            self.host.close()
        self.assertIs(self.host.launch_listener, original)
        self.assertIs(self.host._cleanup_unknown["launch"], interrupt)
        calls = [event for event in self.events if event[0] == "close"]
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_cleanup_quarantined")
        self.assertEqual([event for event in self.events if event[0] == "close"], calls)

    def test_clean_double_close_never_reuses_tombstoned_listeners(self):
        self.host.close()
        calls = [event for event in self.events if event[0] == "close"]
        self.host.close()
        self.assertEqual([event for event in self.events if event[0] == "close"], calls)
        self.assertEqual(len(calls), 3)

    def test_direct_guardian_never_publishes_a_canonical_instance_descriptor(self):
        with patch("sentinel.adaptive.host_discovery.HostDiscovery") as factory, \
                patch.object(VerifiedProcess, "open") as opened:
            self.host._publish_descriptor("ready")
        factory.assert_not_called()
        opened.assert_not_called()
        self.assertIsNone(self.host.descriptor)

    def test_incomplete_parent_binding_is_refused_before_opening_a_process(self):
        self.host.parent_identity = ProcessIdentity(6002, 134343072000000006, LOGON)
        with patch.object(VerifiedProcess, "open") as opened:
            with self.assertRaises(GuardianHostRefused) as caught:
                self.host._publish_descriptor("ready")
        self.assertEqual(caught.exception.reason, "guardian_host_parent_binding_incomplete")
        opened.assert_not_called()

    def descriptor_fixture(self):
        backend = ProcessBackend()
        self.host.guardian = backend.process(GUARDIAN)
        self.host.parent_identity = ProcessIdentity(6002, 134343072000000006, LOGON)
        self.host.parent_instance_id = str(uuid4())
        self.host.policy_instance_id = str(uuid4())
        parent = backend.process(self.host.parent_identity)
        for role in ("operator", "launch", "query", "control"):
            setattr(self.host, role + "_endpoint", NativePipeEndpoint(LOGON, str(uuid4()), GUARDIAN))
        publisher = Mock(spec=HostDiscovery)
        return parent, publisher

    def test_supervised_descriptor_is_cross_bound_and_only_child_metadata_is_published(self):
        parent, publisher = self.descriptor_fixture()
        with patch.object(VerifiedProcess, "open", return_value=parent) as opened, \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            self.host._publish_descriptor("ready")
            original = self.host.descriptor
            self.host._publish_descriptor("ready")
            self.host._publish_descriptor("draining")
        opened.assert_called_once_with(self.host.parent_identity)
        publisher.publish_instance.assert_not_called()
        self.assertEqual(publisher.publish_guardian.call_count, 2)
        first = publisher.publish_guardian.call_args_list[0]
        self.assertEqual(first.kwargs, {"expected": None, "owner_process": self.host.guardian,
                                       "parent_process": parent})
        candidate = first.args[0]
        self.assertEqual(candidate.host_role, "guardian")
        self.assertEqual(candidate.host_identity, GUARDIAN)
        self.assertEqual(candidate.parent_identity, parent.identity)
        self.assertEqual(candidate.parent_instance_id, self.host.parent_instance_id)
        self.assertEqual(candidate.policy_instance_id, self.host.policy_instance_id)
        self.assertEqual({item.role for item in candidate.endpoints}, {"operator", "launch", "query", "control"})
        second = publisher.publish_guardian.call_args_list[1]
        self.assertIs(second.kwargs["expected"], original)
        self.assertIs(second.kwargs["parent_process"], parent)
        self.assertEqual(second.args[0].revision, original.revision + 1)
        self.assertEqual(second.args[0].state, "draining")

    def test_failed_child_publication_retains_same_parent_and_does_not_claim_ready(self):
        parent, publisher = self.descriptor_fixture()
        publisher.publish_guardian.side_effect = DiscoveryError("discovery_fixture_pending")
        with patch.object(VerifiedProcess, "open", return_value=parent) as opened, \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher) as factory:
            for _ in range(2):
                with self.assertRaises(DiscoveryError):
                    self.host._publish_descriptor("ready")
                self.assertIsNone(self.host.descriptor)
                self.assertIs(self.host.parent, parent)
            opened.assert_called_once()
            factory.assert_called_once()
        publisher.publish_instance.assert_not_called()

    def test_lost_publication_ack_retains_exact_candidate_and_blocks_retry_and_exit(self):
        parent, publisher = self.descriptor_fixture()
        error = DiscoveryError("discovery_fixture_unknown", publication_may_have_occurred=True)
        publisher.publish_guardian.side_effect = error
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            with self.assertRaises(DiscoveryError):
                self.host._publish_descriptor("ready")
        candidate = publisher.publish_guardian.call_args.args[0]
        self.assertIs(self.host._descriptor_attempt, candidate)
        self.assertIs(self.host._discovery_error, error)
        self.assertIs(self.host.parent, parent)
        self.assertIsNone(self.host.descriptor)
        with self.assertRaises(GuardianHostRefused) as retry:
            self.host._publish_descriptor("ready")
        self.assertEqual(retry.exception.reason, "guardian_host_discovery_publication_unknown")
        with self.assertRaises(GuardianHostRefused) as close:
            self.host.close()
        self.assertEqual(close.exception.reason, "guardian_host_discovery_publication_unknown")
        publisher.publish_guardian.assert_called_once()
        publisher.remove_guardian.assert_not_called()
        publisher.close.assert_not_called()
        self.assertTrue(self.host._started)
        self.assertFalse(self.host.owner.lifecycle.fences_closed)
        self.assertFalse(any(event[0] == "close" for event in self.events))

    def test_interrupted_publication_retains_candidate_before_any_ack_exists(self):
        parent, publisher = self.descriptor_fixture()
        interrupt = KeyboardInterrupt()
        publisher.publish_guardian.side_effect = interrupt
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            with self.assertRaises(KeyboardInterrupt):
                self.host._publish_descriptor("ready")
        self.assertIs(self.host._descriptor_attempt, publisher.publish_guardian.call_args.args[0])
        self.assertIs(self.host._discovery_error, interrupt)
        with self.assertRaises(GuardianHostRefused):
            self.host.close()
        publisher.remove_guardian.assert_not_called()
        self.assertFalse(self.host.owner.lifecycle.fences_closed)

    def test_descriptor_removal_names_only_original_child_before_owner_cleanup(self):
        parent, publisher = self.descriptor_fixture()
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            self.host._publish_descriptor("ready")
        original = self.host.descriptor
        self.host.close()
        publisher.remove_guardian.assert_called_once_with(original, owner_process=self.host.guardian)
        publisher.remove_instance.assert_not_called()
        publisher.close.assert_called_once()
        self.assertIsNone(self.host.descriptor)

    def test_descriptor_removal_failure_quarantines_same_owner_and_never_repeats(self):
        parent, publisher = self.descriptor_fixture()
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            self.host._publish_descriptor("ready")
        original = self.host.descriptor
        error = DiscoveryError("discovery_fixture_removal_unknown", publication_may_have_occurred=True)
        publisher.remove_guardian.side_effect = error
        with self.assertRaises(GuardianHostRefused) as first:
            self.host.close()
        self.assertEqual(first.exception.reason, "guardian_host_discovery_cleanup_unverified")
        self.assertIs(self.host._cleanup_unknown["descriptor"], error)
        self.assertIs(self.host.descriptor, original)
        self.assertIs(self.host.parent, parent)
        with self.assertRaises(GuardianHostRefused) as second:
            self.host.close()
        self.assertEqual(second.exception.reason, "guardian_host_cleanup_quarantined")
        publisher.remove_guardian.assert_called_once_with(original, owner_process=self.host.guardian)
        publisher.close.assert_not_called()
        self.assertFalse(self.host.owner.lifecycle.fences_closed)
        self.assertFalse(any(event[0] == "close" for event in self.events))
        self.assertTrue(self.host._started)

    def test_descriptor_removal_interrupt_preserves_same_cleanup_quarantine(self):
        parent, publisher = self.descriptor_fixture()
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            self.host._publish_descriptor("ready")
        original = self.host.descriptor
        interrupt = KeyboardInterrupt()
        publisher.remove_guardian.side_effect = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.host.close()
        self.assertIs(self.host._cleanup_unknown["descriptor"], interrupt)
        self.assertIs(self.host.descriptor, original)
        with self.assertRaises(GuardianHostRefused):
            self.host.close()
        publisher.remove_guardian.assert_called_once()
        self.assertFalse(self.host.owner.lifecycle.fences_closed)

    def test_original_recovery_fence_closes_after_descriptor_and_before_endpoint_owners(self):
        parent, publisher = self.descriptor_fixture()
        with patch.object(VerifiedProcess, "open", return_value=parent), \
                patch("sentinel.adaptive.host_discovery.HostDiscovery", return_value=publisher):
            self.host._publish_descriptor("ready")
        publisher.remove_guardian.side_effect = lambda *args, **kwargs: self.events.append(("remove_descriptor",))
        self.host.close()
        self.assertEqual(self.events[:3], [
            ("remove_descriptor",), ("close_recovery_fence",), ("close", "launch")])
        self.assertTrue(self.host.owner.lifecycle.fences_closed)

    def test_recovery_fence_failure_blocks_endpoint_cleanup_and_quarantines_original(self):
        lifecycle = self.host.owner.lifecycle
        error = RuntimeError("fixture fence close unknown")
        lifecycle.fence_close_error = error
        with self.assertRaises(GuardianHostRefused) as first:
            self.host.close()
        self.assertEqual(first.exception.reason, "guardian_host_recovery_fence_cleanup_unverified")
        self.assertIs(self.host.owner.lifecycle, lifecycle)
        self.assertIs(self.host._cleanup_unknown["recovery_fence"], error)
        self.assertFalse(self.host.launch_listener.closed)
        with self.assertRaises(GuardianHostRefused) as second:
            self.host.close()
        self.assertEqual(second.exception.reason, "guardian_host_cleanup_quarantined")
        self.assertEqual(self.events, [("close_recovery_fence",)])
        self.assertTrue(self.host._started)

    def test_lifecycle_fence_cleanup_delegates_to_the_exact_original_restorer(self):
        # Exercise the production delegation without constructing a new mutex,
        # recovering by locator, or requiring any native capability.
        lifecycle = object.__new__(GuardianLifecycle)
        original = Mock()
        lifecycle._restorer = original
        lifecycle.close_retained_fences()
        original.close.assert_called_once_with()
        self.assertIs(lifecycle._restorer, original)

    def retained_close_error(self, error):
        """A real VerifiedProcess close contract over an explicit fake handle."""
        class Backend(ProcessBackend):
            def __init__(self):
                super().__init__()
                self.close_calls = 0
                self.wait_calls = 0
                self.failure = error

            def close(self, handle):
                self.close_calls += 1
                if self.failure is not None:
                    raise self.failure
                super().close(handle)

            def wait(self, handle):
                self.wait_calls += 1
                return super().wait(handle)

        backend = Backend()
        original = backend.process(ProcessIdentity(6010, 134343072000000010, LOGON))
        with self.assertRaises(type(error)):
            original.close()
        self.assertIs(error._identity_handle_cleanup[0], original)
        return backend, original

    def test_rpc_cleanup_retains_original_nested_error_and_reaps_only_known_owner(self):
        error = IdentityUnavailable("process_handle_close_failed", 6)
        backend, original = self.retained_close_error(error)
        outer = IpcError("fixture_rpc_unavailable")
        outer._operator_cause = error
        self.host.launch_service.error = outer
        record = self.host.run_once()
        self.assertEqual(record["launch_rpc"], {"served": False, "reason": "fixture_rpc_unavailable"})
        self.assertEqual(self.host._rpc_cleanup_errors, [error])
        self.assertIs(error._identity_handle_cleanup[0], original)
        self.host._retain_rpc_cleanup(outer)
        self.assertEqual(self.host._rpc_cleanup_errors, [error])
        backend.failure = None
        self.host.launch_service.error = None
        self.host.run_once()
        self.assertEqual(self.host._rpc_cleanup_errors, [])
        self.assertEqual(error._identity_handle_cleanup, ())
        self.assertEqual(backend.close_calls, 2)
        self.assertEqual(backend.wait_calls, 0)
        self.assertEqual([count for _, count in self.pipe_registry.calls], [4, 4])

    def test_unknown_rpc_native_close_is_retained_without_retry_or_shutdown(self):
        error = RuntimeError("fixture invocation completion unknown")
        backend, original = self.retained_close_error(error)
        self.assertTrue(error._native_close_outcome_unknown)
        outer = IpcError("fixture_rpc_unavailable")
        outer._control_cause = error
        self.host.query_service.error = outer
        self.host.run_once()
        self.host.query_service.error = None
        self.host.run_once()
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_operation_unsettled")
        self.assertEqual(self.host._rpc_cleanup_errors, [error])
        self.assertIs(error._identity_handle_cleanup[0], original)
        self.assertEqual(backend.close_calls, 1)
        self.assertEqual(backend.wait_calls, 0)
        self.assertFalse(self.host.owner.lifecycle.fences_closed)
        self.assertFalse(self.host.launch_listener.closed)

    def test_rpc_interrupt_keeps_its_native_cleanup_owner_before_propagating(self):
        interrupt = KeyboardInterrupt()
        backend, original = self.retained_close_error(interrupt)
        self.host.launch_service.error = interrupt
        with self.assertRaises(KeyboardInterrupt):
            self.host.run_once()
        self.assertEqual(self.host._rpc_cleanup_errors, [interrupt])
        self.assertIs(interrupt._identity_handle_cleanup[0], original)
        with self.assertRaises(GuardianHostRefused):
            self.host.close()
        self.assertEqual(backend.close_calls, 1)
        self.assertFalse(self.host.launch_listener.closed)

    def test_pending_pipe_cleanup_keeps_self_and_parent_alive_until_positive_reap(self):
        parent, guardian = Listener("parent", self.events), Listener("self", self.events)
        self.host.parent, self.host.guardian = parent, guardian
        self.pipe_registry.status.resources = 1
        self.pipe_registry.status.pending = 1
        with self.assertRaises(GuardianHostRefused) as caught:
            self.host.close()
        self.assertEqual(caught.exception.reason, "guardian_host_pipe_custody_unsettled")
        self.assertTrue(self.host.launch_listener.closed)
        self.assertFalse(parent.closed)
        self.assertFalse(guardian.closed)
        self.assertIs(self.host.guardian, guardian)
        self.assertTrue(self.host._started)
        earlier = [event for event in self.events if event[0] == "close"]
        self.pipe_registry.status.resources = 0
        self.pipe_registry.status.pending = 0
        self.host.close()
        self.assertTrue(parent.closed)
        self.assertTrue(guardian.closed)
        self.assertEqual([event for event in self.events if event[0] == "close"],
                         earlier + [("close", "parent"), ("close", "self")])
        self.assertEqual([count for _, count in self.pipe_registry.calls], [4, 128, 4, 128])

    def test_runtime_failure_latches_drain_and_retains_original_native_cleanup_until_next_tick(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = [EXECUTION]
        cleanup = IdentityUnavailable("process_handle_close_failed", 6)
        backend, original = self.retained_close_error(cleanup)
        failure = RuntimeError("fixture source failed before reconciliation")
        failure._operator_cause = cleanup
        self.host.launch_service.error = failure
        result = self.host.serve_until_stopped()
        self.assertEqual(result["reason"], "runtime_failure")
        self.assertEqual(result["iterations"], 0)
        self.assertIs(self.host._runtime_error, failure)
        self.assertIs(self.host.owner.lifecycle, lifecycle)
        self.assertEqual(self.host.retained_execution_ids(), (EXECUTION,))
        self.assertEqual(self.host._rpc_cleanup_errors, [cleanup])
        self.assertIs(cleanup._identity_handle_cleanup[0], original)
        self.assertTrue(self.host.owner.draining)
        self.assertTrue(self.host.control.draining)
        self.assertFalse(self.host.launch_listener.closed)
        self.host.launch_service.error = None
        backend.failure = None
        lifecycle.results[EXECUTION] = SimpleNamespace(
            state="FINISHED", active_processes=0, terminal=True)
        with patch.object(module, "emit"):
            settled = self.host.drain_until_settled(budget=1)
        self.assertTrue(settled["settled"])
        self.assertEqual(settled["iterations"], 1)
        self.assertEqual(self.host._rpc_cleanup_errors, [])
        self.assertEqual(backend.close_calls, 2)
        self.assertFalse(self.host.launch_listener.closed)

    def test_bounded_main_failure_enters_resident_drain_and_survives_another_transient_error(self):
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = [EXECUTION]
        lifecycle.results[EXECUTION] = SimpleNamespace(
            state="FINISHED", active_processes=0, terminal=True)
        source, recovering = RuntimeError("fixture source failure"), RuntimeError("fixture restore retry")
        original_tick = self.host.control.tick
        tick_count = 0
        pauses = []

        def tick(now):
            nonlocal tick_count
            tick_count += 1
            if tick_count == 1:
                raise source
            if tick_count == 2:
                raise recovering
            return original_tick(now)

        def pause(seconds):
            pauses.append((self.host.retained_execution_ids(), self.host.launch_listener.closed))

        self.host.control.tick = tick
        self.host._sleep = pause
        records = []
        with patch.object(module, "GuardianHost", return_value=self.host), \
                patch.object(self.host, "start", return_value={"event": "fixture_started"}), \
                patch.object(self.host, "emit", side_effect=records.append):
            code = module.main(["--data-dir", str(self.directory), "--journal-dir", str(self.directory),
                                "--guardian-epoch", EPOCH, "--iterations", "1"])
        self.assertEqual(code, module.EXIT_OK)
        self.assertIs(self.host._runtime_error, recovering)
        self.assertEqual(pauses[0], ((EXECUTION,), False))
        self.assertTrue(any(record.get("event") == "guardian_host_recovery_pending" for record in records))
        self.assertTrue(any(record.get("reason") == "runtime_failure" for record in records))
        self.assertEqual(tick_count, 4)
        self.assertEqual(self.host.retained_execution_ids(), ())
        self.assertTrue(self.host.launch_listener.closed)
        self.assertLess(self.events.index(("retire_terminal", EXECUTION)),
                        self.events.index(("close", "launch")))

    def test_closed_diagnostic_sink_never_redirects_to_stdout_or_unwinds_retained_drain(self):
        class BrokenSink:
            def write(self, value):
                raise BrokenPipeError("fixture diagnostic pipe closed")

            def flush(self):
                raise BrokenPipeError("fixture diagnostic pipe closed")

        closed = io.StringIO()
        closed.close()
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            module.emit({"event": "fixture_before_drain"}, stream=BrokenSink())
            module.emit({"event": "fixture_before_drain"}, stream=closed)
        lifecycle = self.host.owner.lifecycle
        lifecycle.retained = [EXECUTION]
        attempts = []

        def reconcile(execution_id, *, now=None):
            attempts.append(execution_id)
            self.assertFalse(self.host.launch_listener.closed)
            if len(attempts) == 1:
                raise RuntimeError("fixture one incomplete reconciliation")
            return SimpleNamespace(state="FINISHED", active_processes=0, terminal=True)

        lifecycle.reconcile = reconcile
        with patch.object(module.sys, "stderr", closed), redirect_stdout(stdout):
            result = self.host.drain_until_settled()
        self.assertTrue(result["settled"])
        self.assertEqual(result["iterations"], 2)
        self.assertEqual(attempts, [EXECUTION, EXECUTION])
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(self.host.launch_listener.closed)
        self.assertEqual(self.host.retained_execution_ids(), ())


if __name__ == "__main__":
    unittest.main()
