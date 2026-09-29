"""Real aggregate daily SQLite; original scopes and synthetic native collaborators.

These exercise positive prelaunch cleanup and refusal of missing remote evidence.
They neither launch/control native work nor establish a production-host gate.
"""
from contextlib import closing
import json
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_host_completion as completion
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_scope as scopes
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_history as history
from tests import test_adaptive_experiment_host_scope as fixture


class ProductionScopeCompletionTests(unittest.TestCase):
    def setUp(self):
        self.fx = fixture.ProductionExperimentScopeTests()
        self.addCleanup(self.fx.doCleanups)
        self.fx.setUp()
        self.owner = self.fx.prepare()
        self.demand = self.fx.demand
        self.coordinator = self.fx.fixture.coordinator
        self.before = self.fx.fixture.assert_retained(self.demand)

    def assert_charged(self):
        self.assertEqual(self.fx.fixture.assert_retained(self.demand), self.before)
        self.assertFalse(self.demand._closed)

    def test_sealed_prelaunch_scope_has_distinct_exact_completion_and_atomic_release(self):
        self.owner.reserve_member(self.fx.claim)
        completed = completion.retire(self.owner)
        self.assertIs(type(completed), completion.ProductionScopeCompletion)
        record = completed.snapshot()
        self.assertEqual(record["schema_version"], 3)
        self.assertEqual(record["domain"], completion.DOMAIN)
        self.assertEqual(record["actor_outcomes"], [dict(member_id=self.fx.claim.member_id,
            outcome="never_entered", identity=None)])
        operation = self.demand.prepare_release(completed)
        result = self.coordinator.release_experiment(operation)
        self.assertIs(result["released"], True)
        self.assertEqual(self.fx.fixture.rows("reservations"), [])
        receipts = self.fx.fixture.rows(history.TABLE)
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0]["receipt_json"])
        self.assertEqual(receipt["preimage"]["host_rows"], record["host_rows"])
        self.assertEqual(receipt["postimage"]["host_rows"], record["host_rows"])
        for table in ledger.TABLES:
            self.assertEqual(self.fx.fixture.rows(table), record["host_rows"][table])
        self.assertTrue(self.demand._closed)
        self.assertEqual(self.coordinator.release_experiment(operation), result)

    def test_snapshot_or_copied_completion_cannot_mint_release_authority(self):
        completed = completion.retire(self.owner)
        forged = object.__new__(completion.ProductionScopeCompletion)
        forged.__dict__.update(completed.__dict__)
        for value in (completed.snapshot(), forged):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises((cleanup.ExperimentReleaseError, completion.ProductionCompletionError)):
                    # Use a fresh exact release owner solely to test initialization;
                    # public prepare_release intentionally retains a failed attempt.
                    operation = cleanup.ExperimentReleaseOperation(self.demand, value, _token=cleanup._NEW)
                    self.demand._release_operation = operation
                    operation._initialize()
                self.demand._release_operation = None
        self.assert_charged()

    def test_original_completion_is_replayed_without_new_scope_or_sql(self):
        completed = completion.retire(self.owner)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("reopened SQL")):
            self.assertIs(completion.retire(self.owner), completed)
        self.assert_charged()

    def test_new_creation_and_partitions_are_sealed_before_unknown_custody_refusal(self):
        self.owner._guard_unknown = True
        with self.assertRaisesRegex(completion.ProductionCompletionError, "custody_pending"):
            completion.retire(self.owner)
        self.assertTrue(self.owner._sealed)
        with self.assertRaises(scopes.ProductionScopeError):
            self.owner.reserve_member(self.fx.claim)
        self.assert_charged()

    def test_unknown_sql_close_is_not_completion(self):
        attempt = scopes._SqlAttempt(self.demand.ledger_path, False)
        attempt.closed, attempt.close_unknown = False, True
        self.owner._sql_attempts.append(attempt)
        with self.assertRaisesRegex(completion.ProductionCompletionError, "custody_pending"):
            completion.retire(self.owner)
        self.assert_charged()

    def test_original_prepared_creation_is_settled_as_never_created_without_native_entry(self):
        self.owner.reserve_member(self.fx.claim)
        command = creation.ChildCommand("C:\\Python313\\python.exe", ("-I", "inert.py"), "C:\\fixture")
        attempt = creation.CreationAttempt._prepare(self.owner, self.fx.claim, command)
        with patch.object(creation._NativeCreation, "__init__", side_effect=AssertionError("native entry")):
            completed = completion.retire(self.owner)
        self.assertTrue(attempt.native_settled)
        self.assertTrue(attempt.never_created)
        self.assertEqual(completed.snapshot()["actor_outcomes"][0]["outcome"], "never_created")
        self.assert_charged()

    def test_create_entry_with_unknown_outcome_keeps_original_and_capacity(self):
        self.owner.reserve_member(self.fx.claim)
        command = creation.ChildCommand("C:\\Python313\\python.exe", ("-I", "inert.py"), "C:\\fixture")
        attempt = creation.CreationAttempt._prepare(self.owner, self.fx.claim, command)
        # Explicit synthetic interruption at the actual preowned Create boundary.
        attempt._create_entered = True
        with self.assertRaisesRegex(creation.CreationCustodyError, "actor_exit_unverified"):
            completion.retire(self.owner)
        self.assertIs(self.owner._attempts[self.fx.claim.member_id], attempt)
        self.assertFalse(attempt.native_settled)
        self.assert_charged()

    def test_accepted_child_exit_is_not_host_retirement(self):
        self.owner._accepted_children["synthetic-unverified-acceptance"] = object()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "authenticated_host_retirement_required"):
            completion.retire(self.owner)
        self.assert_charged()

    def test_transport_without_positive_original_close_keeps_capacity(self):
        self.owner._transport_service = object()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "original_transport_retirement_required"):
            completion.retire(self.owner)
        self.assert_charged()

    def test_changed_inventory_after_mint_cannot_release(self):
        completed = completion.retire(self.owner)
        self.owner._pending_members[self.fx.claim.member_id] = self.fx.claim
        with self.assertRaisesRegex(completion.ProductionCompletionError, "original_inventory_changed"):
            completed.assert_original()
        self.assert_charged()

    def test_missing_actor_outcome_or_foreign_row_is_rejected_by_history(self):
        completed = completion.retire(self.owner)
        for mutate in (lambda value: value["actor_outcomes"].clear(),
                       lambda value: value["host_rows"][ledger.SCOPES_TABLE][0].update(scope_id="foreign")):
            data = completed.snapshot()
            mutate(data)
            with self.assertRaises((completion.ProductionCompletionError, history.ExperimentHistoryError)):
                completion.validate_record(data)
        self.assert_charged()

    def test_receipt_preimage_must_cover_every_registered_member(self):
        self.owner.reserve_member(self.fx.claim)
        completed = completion.retire(self.owner)
        operation = self.demand.prepare_release(completed)
        self.coordinator.release_experiment(operation)
        record = json.loads(self.fx.fixture.rows(history.TABLE)[0]["receipt_json"])
        record["preimage"]["host_rows"][ledger.MEMBERS_TABLE].clear()
        record["preimage_sha256"] = history.image_digest("preimage", record["preimage"])
        with self.assertRaises(history.ExperimentHistoryError):
            history.canonical_receipt(record)

    def test_ordinary_cancel_cannot_bypass_host_release_guard(self):
        with closing(sqlite3.connect(self.demand.ledger_path)) as conn:
            conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute("DELETE FROM reservations WHERE execution_id=?", (self.demand._snapshot.execution_id,))
            conn.rollback()
        self.assert_charged()


if __name__ == "__main__":
    unittest.main()
