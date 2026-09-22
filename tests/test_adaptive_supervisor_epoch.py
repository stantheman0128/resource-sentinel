"""Portable C4 epoch settlement: real isolated SQL, synthetic handle backend."""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
from unittest.mock import patch
import unittest

from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.legacy_writer import initialize_registry_locked
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor_epoch import SettledEpochRollover
from tests import test_adaptive_guardian_lifecycle as fixture
from tests import test_adaptive_supervisor as supervisor_fixture


class Instance:
    def __init__(self, binding):
        self.binding = binding
        self.held = True
        self.settled = True
        self.settle_calls = 0

    def assert_held(self):
        if not self.held:
            raise LifecycleError("fixture_instance_not_held")

    def assert_settled_for_rollover(self):
        self.settle_calls += 1
        self.assert_held()
        if not self.settled:
            raise LifecycleError("fixture_cleanup_pending")


class EpochRolloverTests(unittest.TestCase):
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    sql = fixture.GuardianLifecycleTests.sql
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    start_consumer = fixture.GuardianLifecycleTests.start_consumer
    adopt = fixture.GuardianLifecycleTests.adopt
    root_exits = fixture.GuardianLifecycleTests.root_exits
    rewrite_manifest = fixture.GuardianLifecycleTests.rewrite_manifest
    finish = supervisor_fixture.SupervisorTests.finish

    def setUp(self):
        fixture.GuardianLifecycleTests.setUp(self)
        self.store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        guard = self.store._policy.prepare(fixture.GUARDIAN.logon_id)
        with self.store._policy.hold(guard):
            initialize_registry_locked(self.store)
        self.instance = Instance(guard.binding)
        self.new_epoch = "guardian-new-fixture"

    def operation(self):
        self.processes.entry(self.guardian).state = IdentityStatus.DEAD
        return SettledEpochRollover(self.store, self.journal, old_epoch=fixture.EPOCH,
                                   witness=self.guardian, instance_owner=self.instance)

    def current(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def test_settled_native_finalization_rolls_epoch_without_rewriting_provenance(self):
        case = self.seed_started()
        self.finish(case)
        before = self.store.query(case.spec.execution_id)
        manifest = self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        operation = self.operation()
        result = operation.tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        self.assertFalse(result.pending)
        self.assertEqual(self.current()["guardian_epoch"], self.new_epoch)
        self.assertEqual(self.current()["mode"], "off")
        self.assertEqual(self.store.query(case.spec.execution_id), before)
        self.assertEqual(self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce), manifest)
        self.assertEqual(operation.tick(self.new_epoch), result)
        self.assertEqual(self.connection().execute("SELECT count(*) FROM adaptive_epoch_rollovers").fetchone()[0], 1)

    def test_zero_scope_early_death_accepts_blank_runtime(self):
        operation = self.operation()
        self.assertEqual(self.current()["guardian_epoch"], "")
        result = operation.tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        row = self.connection().execute("SELECT * FROM adaptive_epoch_rollovers").fetchone()
        self.assertEqual(row["old_epoch"], fixture.EPOCH)
        self.assertEqual(row["scope_count"], 0)
        self.assertEqual(row["guardian_pid"], fixture.GUARDIAN.pid)

    def test_original_exact_dead_registry_row_does_not_invent_competing_writer(self):
        identity = fixture.GUARDIAN
        self.connection().execute("INSERT INTO adaptive_infrastructure VALUES('guardian',?,?,?,1)",
            (identity.pid, str(identity.created_filetime_100ns), identity.logon_id))
        result = self.operation().tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        self.assertEqual(self.connection().execute("SELECT count(*) FROM adaptive_infrastructure").fetchone()[0], 1)

    def test_other_guardian_row_refuses_blank_runtime_rollover(self):
        identity = fixture.GUARDIAN
        self.connection().execute("INSERT INTO adaptive_infrastructure VALUES('guardian',?,?,?,1)",
            (identity.pid, str(identity.created_filetime_100ns + 1), identity.logon_id))
        result = self.operation().tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "epoch_rollover_competing_guardian")
        self.assertEqual(self.current()["guardian_epoch"], "")

    def test_live_work_remains_allocated_and_old_epoch_remains(self):
        case = self.seed_started()
        result = self.operation().tick(self.new_epoch)
        self.assertEqual(result.reason, "epoch_rollover_unretired_scope")
        self.assertEqual(self.current()["guardian_epoch"], fixture.EPOCH)
        self.assertEqual(self.store.query(case.spec.execution_id)["state"], "RUNNING")
        self.assertEqual(self.connection().execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_dead_witness_is_required_and_identity_boolean_is_not_authority(self):
        operation = self.operation()
        for state in (IdentityStatus.ALIVE, IdentityStatus.UNKNOWN):
            self.processes.entry(self.guardian).state = state
            result = operation.tick(self.new_epoch)
            self.assertEqual(result.reason, "epoch_rollover_death_unverified")
        with self.assertRaisesRegex(LifecycleError, "epoch_rollover_authority_required"):
            SettledEpochRollover(self.store, self.journal, old_epoch=fixture.EPOCH,
                                witness=True, instance_owner=self.instance)

    def test_instance_loss_and_pending_native_cleanup_refuse_write(self):
        operation = self.operation()
        self.instance.held = False
        self.assertFalse(operation.tick(self.new_epoch).complete)
        self.instance.held = True
        self.instance.settled = False
        self.assertEqual(operation.tick(self.new_epoch).reason, "fixture_cleanup_pending")
        self.assertEqual(self.current()["guardian_epoch"], "")
        self.instance.settled = True
        self.assertTrue(operation.tick(self.new_epoch).complete)

    def test_recovery_barrier_is_not_cleared_by_rollover(self):
        self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        result = self.operation().tick(self.new_epoch)
        self.assertEqual(result.reason, "epoch_rollover_barrier_unsettled")
        self.assertEqual(self.current()["admission_barrier"], "RECOVERY_HOLD")

    def test_terminal_state_without_archive_is_not_settlement(self):
        case = self.seed_started()
        self.finish(case)
        self.connection().execute("DELETE FROM executions WHERE reservation_id=?", (case.spec.reservation.id,))
        result = self.operation().tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(self.current()["guardian_epoch"], fixture.EPOCH)

    def test_pending_manifest_refuses_terminal_state(self):
        case = self.seed_started()
        self.finish(case)
        self.rewrite_manifest(case, last_applied=fixture.CAP)
        result = self.operation().tick(self.new_epoch)
        self.assertEqual(result.reason, "epoch_rollover_manifest_unsettled")

    def test_missing_manifest_keeps_obligation(self):
        case = self.seed_started()
        self.finish(case)
        with patch.object(self.journal, "read", side_effect=OSError("fixture missing journal")):
            result = self.operation().tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(self.current()["guardian_epoch"], fixture.EPOCH)

    def test_bound_is_sixteen_terminal_proofs_per_tick(self):
        for _ in range(17):
            self.finish(self.seed_started())
        operation = self.operation()
        with patch.object(self.store, "assert_retained_terminal", wraps=self.store.assert_retained_terminal) as proof:
            first = operation.tick(self.new_epoch)
            self.assertEqual(first.reason, "epoch_rollover_inventory_incomplete")
            self.assertEqual(proof.call_count, 16)
            second = operation.tick(self.new_epoch)
        self.assertTrue(second.complete, second)
        self.assertEqual(proof.call_count, 17)

    def historical(self, case):
        """Explicit earlier-epoch fixture; immutable production data is not edited."""
        self.connection().execute("UPDATE managed_executions SET guardian_epoch=? WHERE execution_id=?",
                                  ("earlier-guardian", case.spec.execution_id))
        self.rewrite_manifest(case, guardian_epoch="earlier-guardian",
            guardian_identity=replace(fixture.GUARDIAN, created_filetime_100ns=fixture.GUARDIAN.created_filetime_100ns - 1))

    def test_earlier_epoch_history_also_obeys_page_bound_and_formal_proof(self):
        for _ in range(17):
            case = self.seed_started()
            self.finish(case)
            self.historical(case)
        operation = self.operation()
        with patch.object(self.store, "assert_retained_terminal", wraps=self.store.assert_retained_terminal) as proof:
            first = operation.tick(self.new_epoch)
            self.assertEqual(first.reason, "epoch_rollover_inventory_incomplete")
            self.assertEqual(proof.call_count, 16)
            second = operation.tick(self.new_epoch)
        self.assertTrue(second.complete, second)
        self.assertEqual(proof.call_count, 17)

    def test_earlier_epoch_missing_archive_is_not_ignored(self):
        case = self.seed_started()
        self.finish(case)
        self.historical(case)
        self.connection().execute("DELETE FROM executions WHERE reservation_id=?", (case.spec.reservation.id,))
        result = self.operation().tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "retained_terminal_unverified")
        self.assertEqual(self.current()["guardian_epoch"], fixture.EPOCH)

    def test_earlier_epoch_prelaunch_without_receipt_is_not_ignored(self):
        case = self.seed_started()
        self.finish(case)
        self.historical(case)
        self.connection().execute("""UPDATE managed_executions SET state='START_FAILED',root_pid=NULL,
            root_created_filetime_100ns=NULL,root_outcome=NULL WHERE execution_id=?""", (case.spec.execution_id,))
        self.connection().execute("UPDATE executions SET outcome='managed_start_failed' WHERE reservation_id=?",
                                  (case.spec.reservation.id,))
        self.rewrite_manifest(case, root_identity=None)
        result = self.operation().tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "prelaunch_retirement_unverified")
        self.assertEqual(self.current()["guardian_epoch"], fixture.EPOCH)

    def test_registry_change_invalidates_prior_page(self):
        cases = [self.seed_started() for _ in range(1)]
        self.finish(cases[0])
        operation = self.operation()
        with patch("sentinel.adaptive.supervisor_epoch._PAGE", 0):
            self.assertEqual(operation.tick(self.new_epoch).reason, "epoch_rollover_inventory_incomplete")
        self.connection().execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        with patch.object(self.store, "assert_retained_terminal", wraps=self.store.assert_retained_terminal) as proof:
            result = operation.tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        self.assertEqual(proof.call_count, 1)

    def test_prior_epoch_and_new_attempt_epoch_cannot_be_reused(self):
        operation = self.operation()
        self.assertEqual(operation.tick(fixture.EPOCH).reason, "epoch_rollover_epoch_reused")
        self.assertEqual(operation.tick("different-epoch").reason, "epoch_rollover_attempt_changed")

    def test_sql_failure_retains_exact_guard_then_retries(self):
        self.connection().execute("""CREATE TRIGGER reject_epoch BEFORE UPDATE OF guardian_epoch
            ON adaptive_runtime WHEN NEW.guardian_epoch != OLD.guardian_epoch
            BEGIN SELECT RAISE(ABORT, 'fixture'); END""")
        operation = self.operation()
        first = operation.tick(self.new_epoch)
        self.assertFalse(first.complete)
        nonce = self.current()["policy_entry_nonce"]
        self.assertIsNotNone(nonce)
        self.connection().execute("DROP TRIGGER reject_epoch")
        second = operation.tick(self.new_epoch)
        self.assertTrue(second.complete, second)
        self.assertIsNone(self.current()["policy_entry_nonce"])

    def test_commit_lost_ack_reconciles_same_audit(self):
        operation = self.operation()
        actual = self.store._transaction
        injected = False

        @contextmanager
        def lost_ack(**kwargs):
            nonlocal injected
            with actual(**kwargs) as conn:
                yield conn
                committed_epoch = conn.execute("SELECT guardian_epoch FROM adaptive_runtime").fetchone()[0]
            if committed_epoch == self.new_epoch and not injected:
                injected = True
                raise sqlite3.OperationalError("fixture lost ack")

        with patch.object(self.store, "_transaction", lost_ack):
            self.assertFalse(operation.tick(self.new_epoch).complete)
        result = operation.tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        self.assertEqual(self.connection().execute("SELECT count(*) FROM adaptive_epoch_rollovers").fetchone()[0], 1)

    def test_changed_policy_nonce_quarantines_original_attempt(self):
        self.instance.settled = False
        operation = self.operation()
        self.assertFalse(operation.tick(self.new_epoch).complete)
        self.connection().execute("UPDATE adaptive_runtime SET policy_entry_nonce='00000000-0000-0000-0000-000000000001'")
        self.instance.settled = True
        result = operation.tick(self.new_epoch)
        self.assertFalse(result.complete)
        self.assertEqual(self.current()["guardian_epoch"], "")


if __name__ == "__main__":
    unittest.main()
