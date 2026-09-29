"""Real aggregate daily SQLite; original scopes and synthetic native collaborators.

These exercise positive prelaunch cleanup and refusal of missing remote evidence.
They neither launch/control native work nor establish a production-host gate.
"""
from contextlib import closing
import hashlib
import hmac
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
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive import experiment_host_retirement_transport as retirement
from tests import test_adaptive_experiment_host_scope as fixture
from tests import test_adaptive_experiment_host_dispatch as dispatch_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests.test_adaptive_ipc import canonical, wire_frame


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

    def prepare_release(self, completed):
        # The parent fixture models source/readiness without installing daily
        # runtime state. Cleanup consumes a real retained generation row. Match
        # the existing release-custody fixture; do not call the actual daily
        # locations or replace any cleanup/POLICY/SQL implementation.
        with closing(sqlite3.connect(self.demand.ledger_path)) as conn:
            row = self.fx.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for override in (patch.object(generation, "_assert_daily_locations"),
                         patch.object(generation, "verify_import_provenance"),
                         patch.object(generation, "_prove_retained_owner_ready",
                             side_effect=AssertionError("cleanup attempted fresh readiness RPC"))):
            override.start()
            self.addCleanup(override.stop)
        return self.demand.prepare_release(completed)

    def test_sealed_prelaunch_scope_has_distinct_exact_completion_and_atomic_release(self):
        self.owner.reserve_member(self.fx.claim)
        completed = completion.retire(self.owner)
        self.assertIs(type(completed), completion.ProductionScopeCompletion)
        record = completed.snapshot()
        self.assertEqual(record["schema_version"], 3)
        self.assertEqual(record["domain"], completion.DOMAIN)
        self.assertEqual(record["actor_outcomes"], [dict(member_id=self.fx.claim.member_id,
            outcome="never_entered", identity=None)])
        operation = self.prepare_release(completed)
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
        operation = self.prepare_release(completed)
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


class AcceptedHostCompletionTests(unittest.TestCase):
    """Real parent/SQL/mux/auth receipts with explicit synthetic native effects."""
    prepare_release = ProductionScopeCompletionTests.prepare_release

    def setUp(self):
        self.dispatch_fx = dispatch_fixture.ProductionHostDispatcherTests()
        self.dispatch_fx.setUp()
        self.addCleanup(self.dispatch_fx.doCleanups)
        self.fx = self.dispatch_fx.fixture.host
        self.owner = self.dispatch_fx.owner
        self.demand = self.owner.demand
        self.coordinator = self.fx.fixture.coordinator
        self.dispatcher = self.owner.open_dispatcher()
        self.dispatch_fx.queue_child()
        self.dispatcher.serve_once()
        self.role_fx = self.dispatch_fx.fixture
        self.actor, self.registration, _ = self.role_fx.children[self.role_fx.guardian.member_id]
        self.native_closes = []
        def close(native, handle):
            self.assertIsNone(self.owner._active_sql)
            self.assertIsNone(self.owner._guard)
            self.native_closes.append(handle)
            return 1
        override = patch.object(creation._NativeCreation, "close", close)
        override.start()
        self.addCleanup(override.stop)

    def receipt(self):
        request = retirement.PublishHostClosedRequest(self.registration.manifest,
            "389776fa-61af-4cda-ab95-e2b58d7c8f4f", canonical(dict(kind="guardian", jobs=[])))
        state = {}
        def mac(purpose, result=None):
            value = dict(domain="ResourceSentinel/experiment-host-retirement-ipc/v1/" + purpose,
                request=request.to_dict(), challenge=state["challenge"])
            if purpose != "proof":
                value["result"] = result
            return hmac.new(self.registration.auth_key, canonical(value), hashlib.sha256).hexdigest()
        def write(connection, message):
            self.role_fx.assert_settled()
            if message["kind"] == "ExperimentHostRetirementChallenge":
                state["challenge"] = message
                connection.enqueue(dict(version=1, kind="ExperimentHostRetirementProof",
                    request_id=request.request_id, nonce=message["nonce"], mac=mac("proof")))
            elif message["kind"] == "ExperimentHostRetirementResult":
                state["payload"] = message["result"]
                connection.enqueue(dict(version=1, kind="ExperimentHostRetirementReceipt",
                    request_id=request.request_id, nonce=message["nonce"], mac=mac("receipt", message["result"])))
            elif message["kind"] == "ExperimentHostRetirementSettled":
                connection.enqueue(dict(version=1, kind="ExperimentHostRetirementFinished",
                    request_id=request.request_id, nonce=message["nonce"], mac=mac("finished", state["payload"])))
        hello = dict(version=1, kind="ExperimentHostRetirementHello", request_id=request.request_id,
                     caller=request.manifest.child_identity.to_dict())
        pipe = pipe_fixture.Pipe(request.manifest.child_identity,
            wire_frame(hello) + wire_frame(request.to_dict()), on_write=write)
        self.dispatch_fx.pending.append(pipe)
        self.dispatcher.serve_once()
        return retirement.retained_retirements(self.owner)[0]

    def actors_dead(self):
        for attempt, _, _ in self.role_fx.children.values():
            attempt.process._backend.state = IdentityStatus.DEAD

    def test_authenticated_host_actual_actor_close_and_dispatcher_close_publish_v4_then_release(self):
        receipt = self.receipt()
        self.actors_dead()
        completed = completion.retire(self.owner)
        data = completed.snapshot()
        self.assertEqual(data["schema_version"], completion.HOST_VERSION)
        self.assertEqual(data["host_retirements"], [receipt.snapshot()])
        self.assertEqual(data["backing_rows"], [])
        self.assertEqual(data["isolated_custody"], [])
        self.assertTrue(all(attempt.native_settled for attempt, _, _ in self.role_fx.children.values()))
        self.assertEqual(len(self.native_closes), 4)
        self.dispatcher.assert_closed()
        result = self.coordinator.release_experiment(self.prepare_release(completed))
        self.assertTrue(result["released"])
        archived = json.loads(self.fx.fixture.rows(history.TABLE)[0]["receipt_json"])
        self.assertEqual(archived["completion"], data)
        self.assertEqual(archived["preimage"]["backing_rows"], [])
        self.assertEqual(archived["postimage"]["backing_rows"], [])

    def test_actor_exit_without_terminal_receipt_retains_listener_and_capacity(self):
        self.actors_dead()
        with self.assertRaisesRegex(completion.ProductionCompletionError, "authenticated_host_retirement_required"):
            completion.retire(self.owner)
        self.assertFalse(self.dispatcher._closed)
        self.assertFalse(self.native_closes)
        self.assertTrue(self.fx.fixture.assert_retained(self.demand))

    def test_authenticated_terminal_receipt_with_live_actor_keeps_capacity(self):
        self.receipt()
        with self.assertRaisesRegex(creation.CreationCustodyError, "actor_exit_unverified"):
            completion.retire(self.owner)
        self.assertFalse(self.dispatcher._closed)
        self.assertFalse(self.demand._closed)

    def test_dispatcher_unknown_close_cannot_be_replaced_by_actor_and_receipt_evidence(self):
        self.receipt()
        self.actors_dead()
        self.dispatch_fx.close_error = OSError("synthetic_unknown_close")
        with self.assertRaises(OSError):
            completion.retire(self.owner)
        self.assertFalse(self.demand._closed)
        self.assertIsNone(self.owner._completion._record)
        self.dispatch_fx.close_error = None
        with self.assertRaises(Exception):
            completion.retire(self.owner)

    def test_copied_or_changed_terminal_receipt_is_not_original_completion_authority(self):
        original = self.receipt()
        self.actors_dead()
        completed = completion.retire(self.owner)
        service = self.owner._retirement_service
        service._receipts[original.request.manifest.actor_member_id] = original.snapshot()
        with self.assertRaises(Exception):
            completed.assert_original()
        self.assertFalse(self.demand._closed)

    def test_v4_history_rejects_foreign_actor_identity_or_unbound_job_claim(self):
        self.receipt()
        self.actors_dead()
        completed = completion.retire(self.owner)
        data = completed.snapshot()
        data["host_retirements"][0]["child_identity"]["pid"] += 1
        with self.assertRaises(completion.ProductionCompletionError):
            completion.validate_record(data)
        data = completed.snapshot()
        data["host_retirements"][0]["closure"]["jobs"] = [dict(
            execution_id="b6a393de-cf66-4c9d-bc2a-68e28aa9f455",
            evidence_kind="guardian_terminal_custody_closed", job_name="unbound-job",
            job_nonce="1" * 32, manifest_hash="2" * 64, receipt_sha256="3" * 64)]
        with self.assertRaises(completion.ProductionCompletionError):
            completion.validate_record(data)


if __name__ == "__main__":
    unittest.main()
