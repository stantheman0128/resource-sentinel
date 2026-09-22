"""Pure message validation; these types grant no native authority."""
from dataclasses import replace
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import ContractViolation, Validity
from sentinel.adaptive.control_messages import (ControlFrameAck, ControlFrameRequest, ControlFrameResult,
    ControlObservation, ControlRestoreRequest, RestoreAck, RestoreOutcome)
from tests import test_adaptive_decision as fixture


class ControlMessageTests(unittest.TestCase):
    def setUp(self):
        self.frame = fixture.frame(7, 1_000_000_000_000, 8.0)
        self.request = ControlFrameRequest(str(uuid4()), "guardian-1", "policy-1", self.frame)
        self.observation = ControlFrameResult(self.frame.jobs[0].execution_id,
            ControlObservation.UNCAPPED, self.frame.published_tick_100ns, False, "uncapped_observed")
        self.ack = ControlFrameAck(self.request.request_id, self.request.guardian_epoch,
            self.request.policy_epoch, self.frame.sampler_epoch, self.frame.clock_epoch,
            self.frame.sample_seq, self.frame.registry_revision, self.frame.config_revision, (self.observation,))
        self.restore = ControlRestoreRequest(str(uuid4()), "guardian-1", "policy-1",
            self.frame.jobs[0].execution_id, "mode_off")
        self.restored = RestoreAck(self.restore.request_id, self.restore.guardian_epoch,
            self.restore.policy_epoch, self.restore.execution_id, RestoreOutcome.RESTORED,
            True, True, True, False, 0, 0, Validity.VALID, self.frame.published_tick_100ns,
            "restored", None)

    def test_requests_and_acks_roundtrip_with_decimal_ticks(self):
        for message in (self.request, self.restore, self.observation, self.ack, self.restored):
            with self.subTest(kind=type(message).__name__):
                self.assertEqual(type(message).from_dict(message.to_dict()), message)
        self.assertEqual(self.observation.to_dict()["queried_tick_100ns"], "1000000000000")
        self.assertEqual(self.request.to_dict()["frame"]["published_tick_100ns"], "1000000000000")

    def test_unknown_fields_missing_fields_and_wire_versions_are_rejected(self):
        for message in (self.request, self.restore, self.observation, self.ack, self.restored):
            wire = message.to_dict()
            for invalid in (wire | {"force": True}, {k: v for k, v in wire.items() if k != "reason" and k != "request_id" and k != "execution_id"}):
                with self.subTest(kind=type(message).__name__), self.assertRaises(ContractViolation):
                    type(message).from_dict(invalid)
            if "schema_version" in wire:
                with self.assertRaises(ContractViolation):
                    type(message).from_dict(wire | {"schema_version": 2})

    def test_result_bound_and_unique_execution_ids(self):
        results = tuple(replace(self.observation, execution_id=str(uuid4())) for _ in range(10))
        self.assertEqual(len(replace(self.ack, results=results).results), 10)
        for invalid in (results + (self.observation,), (self.observation, self.observation), list(results)):
            with self.assertRaises(ContractViolation):
                replace(self.ack, results=invalid)

    def test_native_observation_requires_query_time_and_barrier_requires_uncapped(self):
        for observation in (ControlObservation.UNCAPPED, ControlObservation.CAPPED):
            with self.assertRaises(ContractViolation):
                replace(self.observation, observation=observation, queried_tick_100ns=None)
        for observation in (ControlObservation.CAPPED, ControlObservation.REJECTED, ControlObservation.UNVERIFIED):
            with self.assertRaises(ContractViolation):
                replace(self.observation, observation=observation, barrier_cleared=True)

    def test_rejected_and_unknown_observations_can_preserve_nulls(self):
        value = replace(self.observation, observation=ControlObservation.UNVERIFIED, queried_tick_100ns=None)
        self.assertEqual(ControlFrameResult.from_dict(value.to_dict()), value)
        value = replace(self.restored, result=RestoreOutcome.UNVERIFIED, native_disabled=None,
            bookkeeping_settled=None, slot_released=None, barrier_cleared=None,
            applied_flags=None, applied_rate_bp=None, applied_validity=Validity.UNKNOWN,
            queried_tick_100ns=None, reason="restore_unverified")
        self.assertEqual(RestoreAck.from_dict(value.to_dict()), value)

    def test_restored_needs_every_required_obligation_and_disabled_readback(self):
        for change in ({"native_disabled": None}, {"bookkeeping_settled": False}, {"slot_released": None},
                       {"queried_tick_100ns": None}, {"win32_error": 5},
                       {"applied_flags": 5, "applied_rate_bp": 2500, "native_disabled": False}):
            with self.subTest(change=change), self.assertRaises(ContractViolation):
                replace(self.restored, **change)
        # A restored native limit can still owe ordinary barrier observations.
        self.assertFalse(self.restored.barrier_cleared)

    def test_unknown_readback_cannot_claim_native_state_or_values(self):
        for validity in (Validity.UNKNOWN, Validity.INVALID):
            with self.assertRaises(ContractViolation):
                replace(self.restored, result=RestoreOutcome.UNVERIFIED, applied_validity=validity)

    def test_native_boolean_matches_enable_flag(self):
        for flags, disabled in ((5, True), (0, False)):
            with self.assertRaises(ContractViolation):
                replace(self.restored, result=RestoreOutcome.UNVERIFIED,
                    applied_flags=flags, native_disabled=disabled)

    def test_barrier_clear_never_hides_unsettled_restore(self):
        with self.assertRaises(ContractViolation):
            replace(self.restored, result=RestoreOutcome.UNVERIFIED, bookkeeping_settled=False, barrier_cleared=True)

    def test_stable_reasons_typed_enums_and_booleans_are_required(self):
        for bad in ("private command text", "", "a" * 129, "a\n"):
            with self.assertRaises(ContractViolation):
                replace(self.restore, reason=bad)
        for change in ({"observation": "UNCAPPED"}, {"barrier_cleared": 1}, {"queried_tick_100ns": True}):
            with self.assertRaises(ContractViolation):
                replace(self.observation, **change)
        for change in ({"result": "RESTORED"}, {"native_disabled": 1}, {"win32_error": -1}):
            with self.assertRaises(ContractViolation):
                replace(self.restored, **change)

    def test_wire_ticks_must_be_canonical_decimal_strings(self):
        for value in (1000, "01000", "-1", str(1 << 64)):
            with self.assertRaises(ContractViolation):
                ControlFrameResult.from_dict(self.observation.to_dict() | {"queried_tick_100ns": value})

    def test_frame_request_requires_typed_frame_and_all_ack_bindings(self):
        with self.assertRaises(ContractViolation):
            replace(self.request, frame=self.frame.to_dict())
        for change in ({"sample_seq": -1}, {"registry_revision": True}, {"config_revision": "bad"},
                       {"request_id": "not-uuid"}, {"sampler_epoch": "invalid epoch"}):
            with self.assertRaises(ContractViolation):
                replace(self.ack, **change)


if __name__ == "__main__":
    unittest.main()
