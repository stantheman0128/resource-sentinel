"""L1 ledger races; synthetic native evidence does not establish Windows gates."""
from dataclasses import replace
import unittest

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_lifecycle as fixtures


class AllocationTransitionTests(unittest.TestCase):
    setUp = fixtures.AdaptiveLifecycleTests.setUp
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def claim(self, spec, registered):
        return self.store.claim_launch(
            spec.execution_id, caller=fixtures.WRAPPER, expected_revision=1,
            claim_token=registered["claim_token"], spec_hash=spec.spec_hash,
            guardian_epoch="fixture-guardian")

    def test_routed_task_identity_must_match_before_adoption(self):
        spec = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(spec)
        with self.assertRaisesRegex(LifecycleError, "allocation_task_mismatch"):
            self.store.prepare_registration(replace(spec, task_id="another-task"),
                                            caller=fixtures.WRAPPER, now=fixtures.NOW)
        conn = self.connection()
        row = conn.execute("SELECT execution_id,lifecycle_managed FROM worker_reservations").fetchone()
        self.assertEqual(tuple(row), (None, 0))
        self.assertEqual(conn.execute("SELECT count(*) FROM managed_executions").fetchone()[0], 0)

    def test_preparation_requires_the_same_retained_allocation(self):
        spec, _ = self.registered()
        self.connection().execute("UPDATE reservations SET execution_id=NULL WHERE id=?", (spec.reservation.id,))
        with self.assertRaisesRegex(LifecycleError, "allocation_binding_mismatch"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        row = self.store.query(spec.execution_id)
        self.assertEqual((row["state"], row["state_revision"], row["job_name"]), ("RESERVED", 0, None))

    def test_allocation_change_during_claim_verification_cannot_authorize_launch(self):
        corruptions = (
            ("DELETE FROM {table} WHERE id=?", "allocation_missing"),
            ("UPDATE {table} SET lifecycle_managed=0 WHERE id=?", "allocation_binding_mismatch"),
            ("UPDATE {table} SET cpu_units=cpu_units+1 WHERE id=?", "allocation_binding_mismatch"),
            ("UPDATE {table} SET spec_hash='changed' WHERE id=?", "allocation_spec_mismatch"),
        )
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            for sql, reason in corruptions:
                with self.subTest(kind=kind, corruption=reason):
                    self.store.verifier = self.verifier
                    spec, registered = self.registered(self.spec(kind=kind))
                    self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                    table = "reservations" if kind is AllocationKind.DIRECT else "worker_reservations"
                    def corrupt(operation, record, caller):
                        evidence = self.verifier(operation, record, caller)
                        if operation == "claim":
                            self.connection().execute(sql.format(table=table), (spec.reservation.id,))
                        return evidence
                    self.store.verifier = corrupt
                    with self.assertRaisesRegex(LifecycleError, reason):
                        self.claim(spec, registered)
                    row = self.store.query(spec.execution_id)
                    self.assertEqual((row["state"], row["state_revision"], row["claim_consumed"], row["launch_in_flight"]),
                                     ("PREPARED", 1, 0, 0))

    def test_routed_task_or_host_change_after_prepare_denies_claim(self):
        for change, reason in (
            ("UPDATE worker_reservations SET task_id='other'", "allocation_task_mismatch"),
            ("UPDATE workers SET capabilities_json='{\"local\":false}'", "nonlocal_allocation"),
        ):
            with self.subTest(reason=reason):
                spec, registered = self.registered(self.spec(kind=AllocationKind.ROUTED))
                self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
                self.connection().execute(change)
                with self.assertRaisesRegex(LifecycleError, reason):
                    self.claim(spec, registered)
                self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_lowered_floor_cannot_be_used_to_claim(self):
        spec, registered = self.registered()
        self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.connection().execute("UPDATE managed_executions SET floor_commit_bytes=0 WHERE execution_id=?", (spec.execution_id,))
        with self.assertRaisesRegex(LifecycleError, "demand_floor_invalid"):
            self.claim(spec, registered)
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_active_registration_retry_detects_capacity_loss(self):
        spec, _ = self.registered()
        self.connection().execute("DELETE FROM reservations WHERE id=?", (spec.reservation.id,))
        with self.assertRaisesRegex(LifecycleError, "allocation_missing"):
            self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")

    def test_nested_adoption_cannot_hide_missing_parent_capacity(self):
        parent, _ = self.running()
        child = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
        self.connection().execute("DELETE FROM reservations WHERE id=?", (parent.reservation.id,))
        with self.assertRaisesRegex(LifecycleError, "allocation_missing"):
            self.store.prepare_registration(child, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertIsNone(self.connection().execute("SELECT 1 FROM managed_executions WHERE execution_id=?", (child.execution_id,)).fetchone())

    def test_nested_adoption_checks_every_ancestor_logon_and_state(self):
        for field, value in (("logon_id", "other-logon"), ("state", "UNCERTAIN_HOLD")):
            with self.subTest(field=field):
                parent, _ = self.running()
                intermediate = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
                self.store.prepare_registration(intermediate, caller=fixtures.WRAPPER, now=fixtures.NOW)
                conn = self.connection()
                conn.execute("UPDATE managed_executions SET state='RUNNING' WHERE execution_id=?", (intermediate.execution_id,))
                conn.execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?", (value, parent.execution_id))
                child = self.spec(kind=AllocationKind.PARENT, parent=intermediate.execution_id)
                with self.assertRaisesRegex(LifecycleError, "parent_membership_unverified"):
                    self.store.prepare_registration(child, caller=fixtures.WRAPPER, now=fixtures.NOW)
                self.assertIsNone(conn.execute("SELECT 1 FROM managed_executions WHERE execution_id=?", (child.execution_id,)).fetchone())

    def test_finished_registration_retry_does_not_require_released_capacity(self):
        spec, row = self.running()
        self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=row["state_revision"], now=fixtures.NOW + 1)
        result = self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW + 2)
        self.assertFalse(result["registered"])
        self.assertIsNone(result["claim_token"])
        self.assertEqual(result["state"], "FINISHED")


if __name__ == "__main__":
    unittest.main()
