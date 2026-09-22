"""Portable operator contracts preserve observations without granting authority."""
from dataclasses import FrozenInstanceError, replace
import unittest
from uuid import UUID

from sentinel.adaptive.contracts import ContractViolation
from sentinel.adaptive.operator_messages import (
    MAX_OPERATOR_ITEMS, OperatorInventoryItem, OperatorOperation,
    OperatorOutcome, OperatorReply, OperatorRequest,
)


REQUEST_ID = "abcde123-4567-489a-bcde-123456789abc"
INSTANCE_ID = "abcde123-4567-489a-bcde-123456789abd"
POLICY_ID = "abcde123-4567-489a-bcde-123456789abe"
EXECUTION_ID = "abcde123-4567-489a-bcde-123456789abf"
OBSERVED_REQUEST_ID = "abcde123-4567-489a-bcde-123456789ac0"
TICK = 134_029_234_567_890_123


class OperatorMessageTests(unittest.TestCase):
    def setUp(self):
        self.request = OperatorRequest(
            REQUEST_ID, OperatorOperation.DESCRIBE, INSTANCE_ID, POLICY_ID,
            "guardian-1",
        )
        self.native = OperatorInventoryItem(
            EXECUTION_ID, "native", "native_disabled", native_disabled=True,
            bookkeeping_settled=False, cleanup_complete=False,
            observed_tick_100ns=TICK, applied_flags=0, applied_rate_bp=0,
        )
        self.retired = OperatorInventoryItem(
            str(UUID(int=2)), "retired", "retirement_verified",
            bookkeeping_settled=True, cleanup_complete=True,
        )
        self.unknown = OperatorInventoryItem(
            str(UUID(int=3)), "unknown", "owner_unavailable",
        )
        self.reply = OperatorReply(
            REQUEST_ID, OperatorOperation.DESCRIBE, INSTANCE_ID, POLICY_ID,
            "guardian-1", OperatorOutcome.UNVERIFIED, "guardian",
            "owner_unavailable",
        )

    def test_roundtrip_preserves_native_retired_and_unknown_provenance(self):
        reply = replace(self.reply, items=(self.native, self.retired, self.unknown))
        for message in (self.request, self.native, self.retired, self.unknown, reply):
            with self.subTest(kind=type(message).__name__, message=message):
                self.assertEqual(type(message).from_json(message.to_json()), message)
        wire = reply.to_dict()
        self.assertEqual(wire["items"][0]["observed_tick_100ns"], str(TICK))
        for item in wire["items"][1:]:
            self.assertIsNone(item["observed_tick_100ns"])
            self.assertIsNone(item["native_disabled"])
        self.assertEqual([item["provenance"] for item in wire["items"]],
                         ["native", "retired", "unknown"])

    def test_each_wire_field_is_required_and_extra_authority_fields_are_rejected(self):
        for message in (self.request, self.native, self.reply):
            wire = message.to_dict()
            for name in wire:
                with self.subTest(kind=type(message).__name__, missing=name):
                    incomplete = dict(wire)
                    del incomplete[name]
                    with self.assertRaises(ContractViolation):
                        type(message).from_dict(incomplete)
            for name, value in (("force", True), ("user_authorized", True),
                                ("command", "build"), ("pid", 123)):
                with self.subTest(kind=type(message).__name__, extra=name):
                    with self.assertRaises(ContractViolation):
                        type(message).from_dict(wire | {name: value})

    def test_wire_messages_require_objects_and_supported_integer_version(self):
        for message in (self.request, self.native, self.reply):
            for value in (None, [], "message", 1):
                with self.subTest(kind=type(message).__name__, value=value):
                    with self.assertRaises(ContractViolation):
                        type(message).from_dict(value)
        for message in (self.request, self.reply):
            for version in (0, 2, True, "1", None):
                with self.subTest(kind=type(message).__name__, version=version):
                    with self.assertRaises(ContractViolation):
                        type(message).from_dict(message.to_dict() | {"schema_version": version})

    def test_binding_ids_require_canonical_nonzero_uuid_strings(self):
        invalid = (None, True, UUID(REQUEST_ID), "", REQUEST_ID.upper(),
                   REQUEST_ID.replace("-", ""), "{" + REQUEST_ID + "}",
                   str(UUID(int=0)))
        for message, fields in ((self.request, ("request_id", "instance_id", "policy_instance_id")),
                                (self.reply, ("request_id", "instance_id", "policy_instance_id")),
                                (self.unknown, ("execution_id",))):
            for name in fields:
                for value in invalid:
                    with self.subTest(kind=type(message).__name__, field=name, value=value):
                        with self.assertRaises(ContractViolation):
                            replace(message, **{name: value})

    def test_guardian_epoch_is_bounded_opaque_binding(self):
        for message in (self.request, self.reply):
            self.assertEqual(replace(message, guardian_epoch="a" * 128).guardian_epoch,
                             "a" * 128)
            for epoch in (None, "", "a" * 129, "guardian 1", "guardian/1", "guardian\n"):
                with self.subTest(kind=type(message).__name__, epoch=epoch):
                    with self.assertRaises(ContractViolation):
                        replace(message, guardian_epoch=epoch)

    def test_closed_operations_roundtrip_and_mark_only_mutations(self):
        for operation in OperatorOperation:
            request = replace(self.request, operation=operation,
                              expected_registry_revision=0 if operation is OperatorOperation.DRAIN else None)
            self.assertEqual(OperatorRequest.from_dict(request.to_dict()), request)
            self.assertEqual(request.mutating,
                             operation in (OperatorOperation.DRAIN, OperatorOperation.RESTORE_ONLY))
        for operation in ("describe", "apply", "launch", True, None):
            with self.subTest(operation=operation), self.assertRaises(ContractViolation):
                replace(self.request, operation=operation)
        for operation in ("apply", "launch", "set", True, None):
            with self.subTest(wire_operation=operation), self.assertRaises(ContractViolation):
                OperatorRequest.from_dict(self.request.to_dict() | {"operation": operation})

    def test_drain_requires_original_expected_registry_revision(self):
        with self.assertRaises(ContractViolation):
            replace(self.request, operation=OperatorOperation.DRAIN)
        for revision in (0, (1 << 63) - 1):
            request = replace(self.request, operation=OperatorOperation.DRAIN,
                              expected_registry_revision=revision)
            self.assertEqual(OperatorRequest.from_json(request.to_json()).expected_registry_revision,
                             revision)
        for revision in (-1, 1 << 63, True, 1.0, "1"):
            with self.subTest(revision=revision), self.assertRaises(ContractViolation):
                replace(self.request, expected_registry_revision=revision)

    def test_observe_request_id_is_an_exact_describe_only_locator(self):
        request = replace(self.request, observe_request_id=OBSERVED_REQUEST_ID)
        self.assertEqual(OperatorRequest.from_dict(request.to_dict()).observe_request_id,
                         OBSERVED_REQUEST_ID)
        self.assertFalse(request.mutating)
        for operation in (OperatorOperation.DRAIN, OperatorOperation.RESTORE_ONLY, OperatorOperation.AUDIT):
            with self.subTest(operation=operation), self.assertRaises(ContractViolation):
                replace(request, operation=operation, expected_registry_revision=7)
        for value in (str(UUID(int=0)), OBSERVED_REQUEST_ID.upper(), "", 1):
            with self.subTest(observe_request_id=value), self.assertRaises(ContractViolation):
                replace(self.request, observe_request_id=value)

    def test_audit_continuation_requires_stable_revision(self):
        audit = replace(self.request, operation=OperatorOperation.AUDIT)
        self.assertIsNone(OperatorRequest.from_dict(audit.to_dict()).cursor)
        with self.assertRaises(ContractViolation):
            replace(audit, cursor="page:2")
        continuation = replace(audit, cursor="page:2", expected_registry_revision=0)
        self.assertEqual(OperatorRequest.from_dict(continuation.to_dict()), continuation)
        for operation in (OperatorOperation.DESCRIBE, OperatorOperation.DRAIN, OperatorOperation.RESTORE_ONLY):
            with self.subTest(operation=operation), self.assertRaises(ContractViolation):
                replace(continuation, operation=operation)

    def test_cursor_bounds_reject_paths_and_arbitrary_payloads(self):
        request = replace(self.request, operation=OperatorOperation.AUDIT,
                          expected_registry_revision=7)
        reply = replace(self.reply, operation=OperatorOperation.AUDIT,
                        registry_revision=7, inventory_complete=False)
        for cursor in ("A_1.-:z", "a" * 192):
            self.assertEqual(replace(request, cursor=cursor).cursor, cursor)
            self.assertEqual(replace(reply, next_cursor=cursor).next_cursor, cursor)
        for cursor in ("", "a" * 193, "page 2", "C:/private", "page\n", 1, True):
            for message, field in ((request, "cursor"), (reply, "next_cursor")):
                with self.subTest(field=field, cursor=cursor), self.assertRaises(ContractViolation):
                    replace(message, **{field: cursor})

    def test_native_proof_requires_timestamp_flags_and_matching_disabled_bit(self):
        for change in ({"observed_tick_100ns": None}, {"applied_flags": None},
                       {"native_disabled": None}, {"native_disabled": False},
                       {"applied_flags": 5}, {"observed_tick_100ns": True}):
            with self.subTest(change=change), self.assertRaises(ContractViolation):
                replace(self.native, **change)
        capped = replace(self.native, native_disabled=False, applied_flags=5, applied_rate_bp=2500)
        self.assertEqual(OperatorInventoryItem.from_dict(capped.to_dict()), capped)
        # Disabled readback does not imply that accounting or cleanup settled.
        self.assertTrue(self.native.native_disabled)
        self.assertFalse(self.native.bookkeeping_settled)
        self.assertFalse(self.native.cleanup_complete)

    def test_non_native_provenance_cannot_impersonate_current_readback(self):
        for message in (self.retired, self.unknown):
            for field, value in (("native_disabled", True), ("native_disabled", False),
                                 ("observed_tick_100ns", 0), ("applied_flags", 0),
                                 ("applied_rate_bp", 0)):
                with self.subTest(provenance=message.provenance, field=field, value=value):
                    with self.assertRaises(ContractViolation):
                        replace(message, **{field: value})
        for provenance in ("ledger", "native_query", "", None, 1, [], {}):
            with self.subTest(provenance=provenance), self.assertRaises(ContractViolation):
                replace(self.unknown, provenance=provenance)

    def test_retirement_requires_both_bookkeeping_and_cleanup_evidence(self):
        for field in ("bookkeeping_settled", "cleanup_complete"):
            for value in (False, None):
                with self.subTest(field=field, value=value), self.assertRaises(ContractViolation):
                    replace(self.retired, **{field: value})
        self.assertIsNone(self.retired.native_disabled)
        self.assertIsNone(self.retired.observed_tick_100ns)

    def test_native_readback_numbers_have_independent_bounds(self):
        for change in ({"observed_tick_100ns": -1}, {"observed_tick_100ns": 1 << 64},
                       {"applied_flags": -1}, {"applied_flags": 1 << 32}, {"applied_flags": True},
                       {"applied_rate_bp": -1}, {"applied_rate_bp": 10001}, {"applied_rate_bp": True}):
            with self.subTest(change=change), self.assertRaises(ContractViolation):
                replace(self.native, **change)
        self.assertEqual(replace(self.native, observed_tick_100ns=(1 << 64) - 1).observed_tick_100ns,
                         (1 << 64) - 1)
        self.assertEqual(replace(self.native, applied_rate_bp=10000).applied_rate_bp, 10000)
        self.assertIsNone(replace(self.native, applied_rate_bp=None).applied_rate_bp)

    def test_native_wire_timestamp_requires_lossless_canonical_decimal(self):
        for tick in (TICK, True, "01", "-1", "1.0", "+1", " 1", str(1 << 64), ""):
            with self.subTest(tick=tick), self.assertRaises(ContractViolation):
                OperatorInventoryItem.from_dict(self.native.to_dict() | {"observed_tick_100ns": tick})

    def test_inventory_is_bounded_typed_unique_and_immutable(self):
        self.assertEqual(MAX_OPERATOR_ITEMS, 32)
        items = tuple(replace(self.unknown, execution_id=str(UUID(int=index + 1))) for index in range(32))
        reply = replace(self.reply, items=items)
        self.assertEqual(OperatorReply.from_dict(reply.to_dict()).items, items)
        for invalid in (items + (self.native,), (self.unknown, self.unknown),
                        list(items), (self.unknown.to_dict(),), (None,)):
            with self.subTest(items_type=type(invalid).__name__, count=len(invalid)):
                with self.assertRaises(ContractViolation):
                    replace(self.reply, items=invalid)
        with self.assertRaises(FrozenInstanceError):
            self.unknown.reason = "rewritten"
        with self.assertRaises(FrozenInstanceError):
            reply.items = ()

    def test_wire_inventory_requires_list_of_exact_rows_with_no_duplicates(self):
        for items in (None, (), {}, [self.unknown], [self.unknown.to_dict()] * 2,
                      [self.unknown.to_dict()] * 33,
                      [self.unknown.to_dict() | {"native_verified": True}]):
            with self.subTest(items_type=type(items).__name__), self.assertRaises(ContractViolation):
                OperatorReply.from_dict(self.reply.to_dict() | {"items": items})

    def test_unknown_reply_preserves_nulls_without_inventing_success(self):
        wire = self.reply.to_dict()
        fields = ("accepted", "desired_mode", "inventory_complete", "native_disabled",
                  "bookkeeping_settled", "slot_released", "barrier_cleared", "cleanup_settled",
                  "remaining_executions", "remaining_custody", "registry_revision")
        for field in fields:
            with self.subTest(field=field):
                self.assertIsNone(wire[field])
                self.assertIsNone(getattr(OperatorReply.from_dict(wire), field))

    def test_disabled_caps_do_not_imply_execution_capacity_or_cleanup_release(self):
        reply = replace(self.reply, outcome=OperatorOutcome.PENDING, accepted=True,
                        desired_mode="off", host_state="rollback_draining",
                        inventory_complete=True, native_disabled=True,
                        bookkeeping_settled=False, slot_released=False, barrier_cleared=False,
                        cleanup_settled=False, remaining_executions=4, remaining_custody=2,
                        registry_revision=9, items=(self.native,))
        restored = OperatorReply.from_json(reply.to_json())
        self.assertTrue(restored.native_disabled)
        self.assertFalse(restored.slot_released)
        self.assertFalse(restored.barrier_cleared)
        self.assertFalse(restored.cleanup_settled)
        self.assertEqual((restored.remaining_executions, restored.remaining_custody), (4, 2))

    def test_reply_boolean_facts_reject_integer_and_text_substitutes(self):
        for message, fields in ((self.reply, ("accepted", "inventory_complete", "native_disabled",
                                            "bookkeeping_settled", "slot_released", "barrier_cleared",
                                            "cleanup_settled")),
                                (self.unknown, ("native_disabled", "bookkeeping_settled", "cleanup_complete"))):
            for field in fields:
                for value in (0, 1, "false", "unknown"):
                    with self.subTest(kind=type(message).__name__, field=field, value=value):
                        with self.assertRaises(ContractViolation):
                            replace(message, **{field: value})

    def test_reply_scope_is_explicit_and_desired_mode_cannot_promote(self):
        for scope in ("instance", "guardian", "helper"):
            reply = replace(self.reply, scope=scope)
            self.assertEqual(OperatorReply.from_dict(reply.to_dict()).scope, scope)
        for scope in ("global", "host", "", None, 1, [], {}):
            with self.subTest(scope=scope), self.assertRaises(ContractViolation):
                replace(self.reply, scope=scope)
        self.assertEqual(replace(self.reply, desired_mode="off").desired_mode, "off")
        for mode in ("shadow", "canary", "limited", "on", "", True):
            with self.subTest(mode=mode), self.assertRaises(ContractViolation):
                replace(self.reply, desired_mode=mode)

    def test_reply_outcome_is_a_closed_typed_enum(self):
        for outcome in OperatorOutcome:
            reply = replace(self.reply, outcome=outcome)
            self.assertEqual(OperatorReply.from_dict(reply.to_dict()).outcome, outcome)
        with self.assertRaises(ContractViolation):
            replace(self.reply, outcome="complete")
        for outcome in ("success", "rollback_complete", "", True, None):
            with self.subTest(outcome=outcome), self.assertRaises(ContractViolation):
                OperatorReply.from_dict(self.reply.to_dict() | {"outcome": outcome})

    def test_pending_and_refused_cannot_contradict_known_acceptance(self):
        for outcome, accepted in ((OperatorOutcome.PENDING, False), (OperatorOutcome.REFUSED, True)):
            with self.subTest(outcome=outcome), self.assertRaises(ContractViolation):
                replace(self.reply, outcome=outcome, accepted=accepted)
        for outcome, accepted in ((OperatorOutcome.PENDING, True), (OperatorOutcome.PENDING, None),
                                  (OperatorOutcome.REFUSED, False), (OperatorOutcome.REFUSED, None)):
            reply = replace(self.reply, outcome=outcome, accepted=accepted)
            self.assertEqual(OperatorReply.from_dict(reply.to_dict()), reply)

    def test_reply_counts_and_revision_are_nonnegative_bounded_integers(self):
        for field in ("remaining_executions", "remaining_custody", "registry_revision"):
            for value in (0, (1 << 63) - 1):
                self.assertEqual(getattr(replace(self.reply, **{field: value}), field), value)
            for value in (-1, 1 << 63, True, 1.5, "1"):
                with self.subTest(field=field, value=value), self.assertRaises(ContractViolation):
                    replace(self.reply, **{field: value})

    def test_reply_cursor_cannot_claim_complete_or_unbound_inventory(self):
        reply = replace(self.reply, operation=OperatorOperation.AUDIT,
                        registry_revision=0, inventory_complete=False, next_cursor="page:2")
        self.assertEqual(OperatorReply.from_dict(reply.to_dict()), reply)
        for change in ({"operation": OperatorOperation.DESCRIBE}, {"registry_revision": None},
                       {"inventory_complete": True}):
            with self.subTest(change=change), self.assertRaises(ContractViolation):
                replace(reply, **change)
        # A page may leave completeness unknown; it cannot assert completion.
        self.assertIsNone(replace(reply, inventory_complete=None).inventory_complete)

    def test_reasons_and_host_state_are_bounded_codes_not_private_error_text(self):
        for message, field in ((self.unknown, "reason"), (self.reply, "reason"), (self.reply, "host_state")):
            self.assertEqual(getattr(replace(message, **{field: "a" * 128}), field), "a" * 128)
            for value in ("", "a" * 129, "private command --token", "C:/private", "Error", "code\n", None):
                with self.subTest(kind=type(message).__name__, field=field, value=value):
                    with self.assertRaises(ContractViolation):
                        replace(message, **{field: value})


if __name__ == "__main__":
    unittest.main()
