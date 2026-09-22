"""Portable operator routing tests; no native endpoint or process is created."""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.operator_messages import (OperatorOperation as Op,
    OperatorOutcome as Outcome, OperatorReply, OperatorRequest)
from sentinel.adaptive.operator_transport import OperatorTransportError
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_operations import SupervisorHostOperations


LOGON = "S-1-5-5-1-2"
EPOCH = "guardian-test"


class Process:
    def __init__(self, pid):
        self.identity = ProcessIdentity(pid, pid * 100, LOGON)
        self.status = IdentityStatus.ALIVE

    def observe(self):
        return SimpleNamespace(status=self.status, identity=self.identity)


class Host:
    def __init__(self):
        self.draining = False
        self.guardian = self.child(12)
        self.helper = self.child(13)
        self.snapshot = dict(settled=False, remaining_custody=2, registry_revision=3,
                            mode_off=True, barrier_cleared=True,
                            reason="operator_supervisor_custody_pending")
        self.pending = False

    @staticmethod
    def child(pid):
        return SimpleNamespace(process=Process(pid), instance_id=str(uuid4()),
            operator_instance_id=str(uuid4()), epoch=EPOCH)

    def assert_held(self):
        pass

    def begin_drain(self):
        self.draining = True

    def _custody_snapshot(self):
        return dict(self.snapshot)

    def _operational_recovery_pending(self):
        return self.pending


class SupervisorOperationsTests(unittest.TestCase):
    def setUp(self):
        self.host, self.current = Host(), Process(10)
        self.instance, self.policy = str(uuid4()), str(uuid4())
        self.calls, self.clients, self.failures = [], [], {}

        def factory(endpoint, **options):
            role = options["scope"]
            self.clients.append((endpoint, options))

            def request(message, *, timeout_ms):
                self.calls.append((role, message, timeout_ms, self.host.draining))
                if role in self.failures:
                    raise self.failures[role]
                return OperatorReply(message.request_id, message.operation, message.instance_id,
                    message.policy_instance_id, message.guardian_epoch, Outcome.COMPLETE,
                    role, "operator_audit_complete", accepted=True if message.mutating else None,
                    host_state="draining", inventory_complete=True, native_disabled=True,
                    bookkeeping_settled=True, slot_released=True, barrier_cleared=True,
                    cleanup_settled=True, remaining_executions=0, remaining_custody=0,
                    registry_revision=3)
            return SimpleNamespace(request=request)

        self.operations = SupervisorHostOperations(self.host, instance_id=self.instance,
            policy_instance_id=self.policy, guardian_epoch=EPOCH, current=self.current,
            client_factory=factory)
        self.request = OperatorRequest(str(uuid4()), Op.DRAIN, self.instance,
            self.policy, EPOCH, expected_registry_revision=3)

    def invoke(self, request=None):
        return self.operations(request or self.request, caller_identity=self.current.identity)

    def test_drain_latches_before_both_child_requests_and_retains_exact_bindings(self):
        result = self.invoke()
        self.assertEqual([call[0] for call in self.calls], ["guardian", "helper"])
        self.assertTrue(all(call[3] for call in self.calls))
        self.assertTrue(all(call[2] == 250 for call in self.calls))
        record = self.operations.operations[self.request.request_id]
        self.assertIs(record.children["guardian"][0], self.host.guardian)
        self.assertIs(record.children["helper"][0], self.host.helper)
        self.assertEqual(self.clients[0][0].server_identity, self.host.guardian.process.identity)
        self.assertEqual(result.outcome, Outcome.PENDING)

    def test_uncertain_guardian_delivery_still_starts_helper_observation(self):
        error = OperatorTransportError("pipe_timeout", outcome_unknown=True)
        self.failures["guardian"] = error
        result = self.invoke()
        record = self.operations.operations[self.request.request_id]
        self.assertIs(record.errors["guardian"], error)
        original = record.children["guardian"][1]
        self.assertEqual([call[0] for call in self.calls], ["guardian", "helper"])
        self.operations.tick()
        self.assertIs(record.children["guardian"][1], original)
        self.assertEqual(self.calls[2][1], original)
        self.assertEqual(result.outcome, Outcome.PENDING)
        self.assertIsNone(result.native_disabled)

    def test_child_complete_does_not_claim_parent_death_or_cleanup(self):
        result = self.invoke()
        self.assertTrue(result.accepted)
        self.assertEqual(result.remaining_custody, 2)
        self.assertFalse(result.cleanup_settled)
        self.assertEqual(result.outcome, Outcome.PENDING)

    def test_only_retained_parent_completion_can_finish_instance_drain(self):
        self.invoke()
        self.host.snapshot.update(settled=True, remaining_custody=0,
                                  reason="operator_instance_drained")
        self.host.guardian.process.status = IdentityStatus.DEAD
        self.host.helper = None
        result = self.invoke()
        self.assertEqual(result.outcome, Outcome.COMPLETE)
        self.assertEqual(result.remaining_custody, 0)
        self.assertTrue(result.cleanup_settled)

    def test_replay_payload_change_does_not_dispatch_again(self):
        self.invoke()
        before = len(self.calls)
        with self.assertRaisesRegex(LifecycleError, "operator_request_payload_changed"):
            self.invoke(replace(self.request, expected_registry_revision=4))
        self.assertEqual(len(self.calls), before)

    def test_wrong_target_and_foreign_logon_cannot_latch_drain(self):
        with self.assertRaisesRegex(LifecycleError, "operator_target_changed"):
            self.invoke(replace(self.request, guardian_epoch="different-epoch"))
        with self.assertRaisesRegex(LifecycleError, "operator_logon_mismatch"):
            self.operations(self.request, caller_identity=ProcessIdentity(88, 8800, "S-1-5-5-1-3"))
        self.assertFalse(self.host.draining)
        self.assertEqual(self.calls, [])

    def test_operation_observation_uses_fresh_read_only_child_request(self):
        self.invoke()
        original = self.operations.operations[self.request.request_id].children["guardian"][1]
        observed = self.invoke(replace(self.request, request_id=str(uuid4()), operation=Op.DESCRIBE,
            expected_registry_revision=None, observe_request_id=self.request.request_id))
        message = self.calls[-1][1]
        self.assertEqual(message.operation, Op.DESCRIBE)
        self.assertEqual(message.observe_request_id, original.request_id)
        self.assertNotEqual(message.request_id, original.request_id)
        self.assertEqual(observed.outcome, Outcome.PENDING)

    def test_old_request_never_targets_a_replacement_child(self):
        self.invoke()
        record = self.operations.operations[self.request.request_id]
        original = record.children["guardian"][0]
        self.host.guardian = Host.child(90)
        before = len([call for call in self.calls if call[0] == "guardian"])
        self.operations.tick()
        self.assertIs(record.children["guardian"][0], original)
        self.assertEqual(len([call for call in self.calls if call[0] == "guardian"]), before)

    def test_failed_current_read_does_not_reuse_prior_native_disabled_result(self):
        self.invoke()
        self.failures["guardian"] = OperatorTransportError("pipe_timeout")
        result = self.invoke(replace(self.request, request_id=str(uuid4()), operation=Op.DESCRIBE,
            expected_registry_revision=None, observe_request_id=self.request.request_id))
        self.assertIsNone(result.native_disabled)
        self.assertEqual(result.outcome, Outcome.PENDING)

    def test_child_proof_is_not_relabelled_to_a_changed_registry_revision(self):
        self.host.snapshot["registry_revision"] = 4
        result = self.invoke()
        self.assertEqual(result.registry_revision, 4)
        self.assertIsNone(result.native_disabled)
        self.assertIsNone(result.bookkeeping_settled)
        self.assertEqual(result.outcome, Outcome.PENDING)


if __name__ == "__main__":
    unittest.main()
