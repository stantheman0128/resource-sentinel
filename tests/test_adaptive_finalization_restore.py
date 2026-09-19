"""L1 release invariants with synthetic evidence and real isolated SQLite.

These tests establish no native restoration or capability result.
"""
from dataclasses import fields, replace
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_lifecycle as fixtures


class FinalizationRestoreTests(unittest.TestCase):
    setUp = fixtures.AdaptiveLifecycleTests.setUp
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def test_unverified_restore_keeps_direct_and_routed_allocations(self):
        for kind, table, archive in (
            (AllocationKind.DIRECT, "reservations", "executions"),
            (AllocationKind.ROUTED, "worker_reservations", "routed_executions"),
        ):
            self.store.evidence_provider = fixture_evidence_provider(self.verifier)
            spec, running = self.running(self.spec(kind=kind))
            conn = self.connection()
            allocation = dict(conn.execute(f"SELECT * FROM {table} WHERE id=?",
                                          (spec.reservation.id,)).fetchone())
            runtime = [tuple(row) for row in conn.execute("SELECT * FROM adaptive_runtime")]
            for disabled, settled in ((False, False), (False, True), (True, False)):
                with self.subTest(kind=kind, disabled=disabled, settled=settled):
                    def unverified(operation, row, caller):
                        return replace(self.verifier(operation, row, caller),
                                       current_cpu_disabled=disabled,
                                       recovery_manifest_settled=settled)

                    self.store.evidence_provider = fixture_evidence_provider(unverified)
                    with patch.object(self.store, "_transaction", side_effect=AssertionError("transaction entered")):
                        with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
                            self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                                        expected_revision=running["state_revision"])
                    self.assertEqual(self.store.query(spec.execution_id), running)
                    self.assertEqual([tuple(row) for row in conn.execute("SELECT * FROM adaptive_runtime")], runtime)
                    self.assertEqual(dict(conn.execute(f"SELECT * FROM {table} WHERE id=?",
                                                       (spec.reservation.id,)).fetchone()), allocation)
                    self.assertEqual(conn.execute(f"SELECT count(*) FROM {archive} WHERE reservation_id=?",
                                                  (spec.reservation.id,)).fetchone()[0], 0)

            # The same execution can settle later; rejection must not consume
            # its revision, release its floor, or require relaunching work.
            self.store.evidence_provider = fixture_evidence_provider(self.verifier)
            finished = self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                                   expected_revision=running["state_revision"])
            self.assertEqual(finished["state"], "FINISHED")
            self.assertIsNone(conn.execute(f"SELECT id FROM {table} WHERE id=?",
                                           (spec.reservation.id,)).fetchone())
            self.assertEqual(conn.execute(f"SELECT count(*) FROM {archive} WHERE reservation_id=?",
                                          (spec.reservation.id,)).fetchone()[0], 1)

    def test_old_initial_disabled_evidence_cannot_release(self):
        spec, running = self.running()

        def old_provider(operation, row, caller):
            proof = self.verifier(operation, row, caller)
            values = {field.name: getattr(proof, field.name) for field in fields(proof)
                      if field.name not in {"current_cpu_disabled", "recovery_manifest_settled"}}
            old_proof = LifecycleEvidence(**values)
            self.assertTrue(old_proof.original_cpu_disabled)
            self.assertTrue(old_proof.durable_manifest)
            self.assertFalse(old_proof.current_cpu_disabled)
            self.assertFalse(old_proof.recovery_manifest_settled)
            return old_proof

        self.store.evidence_provider = fixture_evidence_provider(old_provider)
        with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
            self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                        expected_revision=running["state_revision"])
        self.assertEqual(self.store.query(spec.execution_id), running)

    def test_unsettled_parent_does_not_finish_nested_subspan(self):
        parent, running = self.running()
        child = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
        self.store.prepare_registration(child, caller=fixtures.WRAPPER, now=fixtures.NOW)
        child_before = self.store.query(child.execution_id)

        def unsettled(operation, row, caller):
            return replace(self.verifier(operation, row, caller), recovery_manifest_settled=False)

        self.store.evidence_provider = fixture_evidence_provider(unsettled)
        with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
            self.store.finalize_if_empty(parent.execution_id, caller=fixtures.WRAPPER,
                                        expected_revision=running["state_revision"])
        self.assertEqual(self.store.query(child.execution_id), child_before)
        self.assertEqual(self.store.query(parent.execution_id), running)

    def test_public_restore_assertion_cannot_replace_provider(self):
        spec, running = self.running()
        for name in ("current_cpu_disabled", "recovery_manifest_settled"):
            with self.subTest(field=name):
                with self.assertRaises(TypeError):
                    self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                                expected_revision=running["state_revision"], **{name: True})
        self.assertEqual(self.store.query(spec.execution_id), running)

    def test_revision_change_rejects_otherwise_positive_restore_proof(self):
        spec, running = self.running()
        held = None

        def racing_provider(operation, row, caller):
            nonlocal held
            proof = self.verifier(operation, row, caller)
            held = self.store.hold(spec.execution_id, expected_revision=row["state_revision"],
                                   reason="heartbeat_lost")
            return proof

        self.store.evidence_provider = fixture_evidence_provider(racing_provider)
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                        expected_revision=running["state_revision"])
        self.assertEqual(self.store.query(spec.execution_id), held)
        conn = self.connection()
        self.assertIsNotNone(conn.execute("SELECT id FROM reservations WHERE id=?",
                                         (spec.reservation.id,)).fetchone())
        self.assertEqual(conn.execute("SELECT count(*) FROM executions").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
