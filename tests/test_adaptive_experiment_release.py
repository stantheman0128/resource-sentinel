"""Original experiment release in isolated SQLite with synthetic native backends.

The demand, completion, release operation, SQL guards and transactions are real.
The current-process handle and POLICY provider are portable fixtures. These tests
do not run a Windows Job, activate daily control, or establish a native gate.
"""
from contextlib import closing, ExitStack
import json
from pathlib import Path
import re
import sqlite3
import unittest
from unittest.mock import call, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.policy import NativePolicyProvider
from sentinel.adaptive.store import hold_expired_allocations
from sentinel.adaptive import windows
from sentinel.coordinator import Coordinator
from tests import test_adaptive_experiment_release_custody as custody_tests
from tests import test_adaptive_experiment_preparation as preparation_tests
from tests import test_adaptive_managed_admission as managed_tests
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_identity import Backend
from tests.test_adaptive_policy_mutex import FixtureBackend, FixtureProcess


def _rows(path, table):
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]


def _release_rows(path):
    return {table: _rows(path, table) for table in (
        "reservations", "queue", "managed_executions", "executions",
        demand_module.TABLE, history.TABLE)}


class ExperimentReleaseTests(unittest.TestCase):
    def setUp(self):
        # Replace the fixture constructor before capture, keeping the actual
        # original VerifiedProcess object through admission and final close.
        self.backend = Backend()
        self.backend.value = IDENTITY
        self.process = VerifiedProcess(self.backend, 700, IDENTITY)
        self.custody = custody_tests.ExperimentReleaseCustodyTests()
        self.addCleanup(self.custody.doCleanups)
        with patch.object(managed_tests, "FakeCurrentProcess", return_value=self.process):
            self.custody.setUp()
        self.demand, self.operation = self.custody.demand, self.custody.operation
        self.coordinator = self.custody.fixture.coordinator
        self.inner, self.policy = self.operation.inner, self.operation.policy
        self.db, self.snapshot = self.custody.db, self.operation.snapshot
        self.before = _release_rows(self.db)
        self.runtime_before = self.custody.runtime()

    def release(self):
        return self.coordinator.release_experiment(self.operation)

    def assert_charged(self, before=None):
        self.assertEqual(_release_rows(self.db), self.before if before is None else before)
        self.assertFalse(self.operation._completed)
        self.assertIsNotNone(self.process._handle)
        self.assertFalse(self.demand._closed)

    def assert_released(self, result, disposition="BEFORE_NATIVE"):
        self.assertIs(result["released"], True)
        self.assertEqual(result["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(result["execution_id"], self.snapshot.execution_id)
        self.assertEqual(result["receipt_id"], self.operation.receipt_id)
        self.assertEqual(result["disposition"], disposition)
        rows = _release_rows(self.db)
        self.assertEqual(rows["reservations"], [])
        self.assertEqual(rows["queue"], [])
        self.assertEqual(rows[demand_module.TABLE], self.before[demand_module.TABLE])
        self.assertEqual(len(rows[history.TABLE]), 1)
        self.assertEqual(len(rows["executions"]), 1)
        record = json.loads(rows[history.TABLE][0]["receipt_json"])
        self.assertEqual(rows["executions"][0]["outcome"], "managed_cancelled_before_start")
        self.assertEqual(rows["managed_executions"][0]["claim_token_hash"], "")
        self.assertEqual(rows["managed_executions"][0]["claim_consumed"], 1)
        self.assertEqual(rows["managed_executions"][0]["launch_sealed"], 1)
        for key in ("requested_cpu_units", "requested_physical_bytes", "requested_commit_bytes",
                    "requested_io_slots", "floor_cpu_units", "floor_physical_bytes",
                    "floor_commit_bytes", "floor_io_slots"):
            self.assertEqual(rows["managed_executions"][0][key], record["preimage"]["managed"][key])
        self.assertEqual(history.managed_image(rows["managed_executions"][0]), record["postimage"]["managed"])
        self.assertEqual(self.custody.runtime()["registry_revision"], record["preimage"]["registry_revision"] + 1)
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        self.assertEqual(self.operation._connections, {})
        self.assertTrue(self.operation._completed)
        self.assertTrue(self.demand._closed)
        self.assertTrue(self.inner._closed)
        self.assertIsNone(self.process._handle)
        self.assertIsNone(self.inner._claim_token)
        self.assertIsNone(self.inner._key)
        self.assertIsNone(self.inner._snapshot)
        return record

    def test_before_native_release_publishes_one_complete_atomic_tuple(self):
        result = self.release()
        record = self.assert_released(result)
        self.assertEqual(record["operation_id"], self.operation.operation_id)
        self.assertEqual(record["completion_digest"], self.custody.completion.digest)
        self.assertIsNone(record["preimage"]["exclusion"])
        self.assertIsNone(record["postimage"]["exclusion"])
        self.assertEqual(record["preimage"]["registry_revision"], self.runtime_before["registry_revision"])
        self.assertEqual(self.backend.closed, [700])

    def test_expired_unused_claim_releases_directly_from_hold_while_draining(self):
        later = self.before["reservations"][0]["expires_at"] + 1
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            # Even a permitted expiry transition compiles the persistent trigger
            # containing this name. The fixture grants no release authority.
            conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(hold_expired_allocations(conn, "direct", later), 1)
            conn.commit()
        held = _rows(self.db, "managed_executions")[0]
        self.assertEqual((held["state"], held["hold_reason"]), ("UNCERTAIN_HOLD", "reservation_expired"))
        self.custody.fixture.clock.return_value = later
        self.custody.change("adaptive_daily_generation", "state", "DRAINING")
        result = self.release()
        record = self.assert_released(result)
        self.assertEqual(record["preimage"]["managed"]["state"], "UNCERTAIN_HOLD")
        self.assertEqual(record["preimage"]["allocation"], self.before["reservations"][0])
        self.assertEqual(record["postimage"]["managed"]["state_revision"], held["state_revision"] + 1)
        self.assertEqual(_rows(self.db, "adaptive_daily_generation")[0]["state"], "DRAINING")

    def test_wrong_operation_or_coordinator_never_opens_sql(self):
        foreign = Coordinator.__new__(Coordinator)
        foreign.db_path = Path(self.db).with_name("not-the-original-ledger.db")
        with patch.object(sqlite3, "connect", side_effect=AssertionError("wrong owner opened SQL")):
            for value in (object(), {"operation_id": self.operation.operation_id}, self.custody.completion):
                with self.subTest(value_type=type(value).__name__), self.assertRaises(TypeError):
                    self.coordinator.release_experiment(value)
            for coordinator in (object(), foreign):
                with self.subTest(coordinator_type=type(coordinator).__name__), \
                        self.assertRaisesRegex(cleanup.ExperimentReleaseError, "actual_daily_coordinator_required"):
                    self.operation.release(coordinator)
        self.assert_charged()

    def test_wrong_archive_row_is_denied_inside_original_publication_scope(self):
        connect, operation, attempted = sqlite3.connect, self.operation, []

        class WrongArchive(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if sql.startswith("INSERT INTO " + history.TABLE) and not attempted:
                    attempted.append(True)
                    archive = dict(operation._record()["postimage"]["archive"])
                    archive["reservation_id"] = "unrelated-reservation"
                    super().execute("INSERT INTO executions(" + ",".join(archive) + ") VALUES(" +
                        ",".join("?" for _ in archive) + ")", tuple(archive.values()))
                return result

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=WrongArchive)):
            with self.assertRaises(sqlite3.DatabaseError):
                self.release()
        self.assertEqual(attempted, [True])
        self.assert_charged()
        self.assert_released(self.release())

    def _interrupt_after_archive_insert(self):
        connect, interrupted = sqlite3.connect, []

        class InterruptedArchive(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if sql.startswith("INSERT INTO executions(") and not interrupted:
                    interrupted.append(True)
                    raise sqlite3.OperationalError("synthetic publication interrupted after archive")
                return result

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=InterruptedArchive)):
            with self.assertRaisesRegex(sqlite3.OperationalError, "interrupted after archive"):
                self.release()
        self.assertEqual(interrupted, [True])
        self.assert_charged()
        self.assertEqual(self.custody.runtime()["registry_revision"], self.runtime_before["registry_revision"])
        self.assertEqual(self.custody.runtime()["policy_entry_nonce"], self.operation._guard.nonce)
        self.assertIsNone(self.operation._quarantine)

    def test_failure_after_archive_insert_rolls_back_every_release_row(self):
        self._interrupt_after_archive_insert()
        self.assert_released(self.release())

    def test_positive_rollback_can_rebase_after_legitimate_registry_revision_change(self):
        self._interrupt_after_archive_insert()
        old_candidate = self.operation._candidate
        self.assertIsNotNone(old_candidate)
        self.operation._settle_previous()
        self.assertTrue(self.operation._policy_settled)
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        self.assertEqual(self.operation._connections, {})
        self.assert_charged()
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1")
            conn.commit()
        revision = self.custody.runtime()["registry_revision"]
        record = self.assert_released(self.release())
        self.assertEqual(record["preimage"]["registry_revision"], revision)
        self.assertEqual(record["postimage"]["registry_revision"], revision + 1)
        self.assertEqual(self.custody.runtime()["registry_revision"], revision + 1)
        self.assertNotEqual(self.operation._candidate, old_candidate)
        self.assertEqual(record["operation_id"], self.operation.operation_id)
        self.assertEqual(record["receipt_id"], self.operation.receipt_id)

    def test_positive_rollback_can_rebase_after_real_expiry_hold_and_draining(self):
        self._interrupt_after_archive_insert()
        old_candidate = self.operation._candidate
        self.operation._settle_previous()
        self.assertTrue(self.operation._policy_settled)
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        later = self.before["reservations"][0]["expires_at"] + 1
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(hold_expired_allocations(conn, "direct", later), 1)
            conn.commit()
        held = _rows(self.db, "managed_executions")[0]
        self.assertEqual((held["state"], held["hold_reason"]), ("UNCERTAIN_HOLD", "reservation_expired"))
        self.assertEqual(_rows(self.db, "reservations"), self.before["reservations"])
        self.custody.fixture.clock.return_value = later
        self.custody.change("adaptive_daily_generation", "state", "DRAINING")
        revision = self.custody.runtime()["registry_revision"]
        record = self.assert_released(self.release())
        self.assertEqual(record["preimage"]["managed"], history.managed_image(held))
        self.assertEqual(record["preimage"]["allocation"], self.before["reservations"][0])
        self.assertEqual(record["preimage"]["registry_revision"], revision)
        self.assertEqual(record["postimage"]["managed"]["state_revision"], held["state_revision"] + 1)
        self.assertNotEqual(self.operation._candidate, old_candidate)
        self.assertEqual(_rows(self.db, "adaptive_daily_generation")[0]["state"], "DRAINING")

    def test_lost_publication_commit_ack_replays_original_tuple_exactly_once(self):
        connect, lost = sqlite3.connect, []

        class LostCommitAck(sqlite3.Connection):
            publication = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if sql.startswith("INSERT INTO " + history.TABLE):
                    self.publication = True
                return result

            def commit(self):
                super().commit()
                if self.publication and not lost:
                    lost.append(True)
                    raise sqlite3.OperationalError("synthetic publication commit acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostCommitAck)):
            with self.assertRaisesRegex(sqlite3.OperationalError, "commit acknowledgement lost"):
                self.release()
        self.assertEqual(lost, [True])
        committed, revision = _release_rows(self.db), self.custody.runtime()["registry_revision"]
        self.assertEqual(len(committed[history.TABLE]), 1)
        self.assertEqual(len(committed["executions"]), 1)
        self.assertEqual(committed["reservations"], [])
        self.assertFalse(self.operation._completed)
        self.assertIsNotNone(self.process._handle)
        original_guard = self.operation._guard
        self.assertIsNone(self.operation._quarantine)
        result = self.release()
        self.assert_released(result)
        self.assertIs(self.operation._guard, original_guard)
        self.assertEqual(_release_rows(self.db), committed)
        self.assertEqual(self.custody.runtime()["registry_revision"], revision)

    def test_completed_replay_reads_only_and_returns_the_identical_result(self):
        first = self.release()
        committed, revision, connect, statements = _release_rows(self.db), self.custody.runtime()["registry_revision"], sqlite3.connect, []

        class Observed(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                statements.append(sql)
                return super().execute(sql, parameters)

        with ExitStack() as stack:
            for owner, method in ((self.policy, "prepare"), (self.policy, "hold"), (self.coordinator, "_mirror"),
                    (self.inner, "snapshot"), (self.inner, "launch_claim_token"), (self.process, "observe"),
                    (self.process, "close")):
                stack.enter_context(patch.object(owner, method, side_effect=AssertionError("completed replay called " + method)))
            stack.enter_context(patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=Observed)))
            self.assertEqual(self.release(), first)
            self.assertIs(self.demand.prepare_release(self.custody.completion), self.operation)
        self.assertTrue(any(sql.startswith("SELECT") for sql in statements))
        self.assertFalse(any(re.match(r"\s*(INSERT|UPDATE|DELETE|REPLACE)\b", sql, re.IGNORECASE) for sql in statements))
        self.assertEqual(_release_rows(self.db), committed)
        self.assertEqual(self.custody.runtime()["registry_revision"], revision)
        self.assertEqual(self.backend.closed, [700])

    def test_lost_commit_ack_never_rebases_original_receipt_after_later_registry_change(self):
        connect, lost = sqlite3.connect, []

        class LostCommitAck(sqlite3.Connection):
            publication = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if sql.startswith("INSERT INTO " + history.TABLE):
                    self.publication = True
                return result

            def commit(self):
                super().commit()
                if self.publication and not lost:
                    lost.append(True)
                    raise sqlite3.OperationalError("synthetic committed candidate acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostCommitAck)):
            with self.assertRaisesRegex(sqlite3.OperationalError, "candidate acknowledgement lost"):
                self.release()
        self.assertEqual(lost, [True])
        original_candidate, original_sha = self.operation._candidate, self.operation._candidate_sha
        committed = _release_rows(self.db)
        self.assertEqual(len(committed[history.TABLE]), 1)
        self.operation._settle_previous()
        self.assertTrue(self.operation._committed)
        self.assertTrue(self.operation._policy_settled)
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        self.assertEqual(self.operation._candidate, original_candidate)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1")
            conn.commit()
        revision = self.custody.runtime()["registry_revision"]
        with patch.object(self.operation, "_prepare_publication", side_effect=AssertionError("committed candidate was rebased")), \
                patch.object(self.policy, "hold", side_effect=AssertionError("committed candidate reacquired POLICY")):
            result = self.release()
        self.assertTrue(result["released"])
        self.assertTrue(self.operation._completed)
        self.assertEqual(self.operation._candidate, original_candidate)
        self.assertEqual(self.operation._candidate_sha, original_sha)
        self.assertEqual(_release_rows(self.db), committed)
        self.assertEqual(self.custody.runtime()["registry_revision"], revision)
        self.assertEqual(json.loads(original_candidate)["postimage"]["registry_revision"], revision - 1)
        self.assertEqual(self.backend.closed, [700])

    def test_changed_stored_ipc_key_cannot_release_original_admission(self):
        original = self.snapshot.ipc_auth_key
        changed = bytes([original[0] ^ 1]) + original[1:]
        self.assertEqual(len(changed), 32)
        trigger = "experiment_execution_update_guard"
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                canonical = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone()[0]
                self.assertEqual(canonical, demand_module._TRIGGER_SQL[trigger])
                # Deliberately corrupt only this isolated fixture, then restore
                # the exact canonical guard before exercising the public route.
                conn.execute("DROP TRIGGER " + trigger)
                conn.execute("UPDATE managed_executions SET ipc_auth_key=? WHERE execution_id=?",
                             (changed, self.snapshot.execution_id))
                conn.execute(canonical)
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
            self.assertEqual(conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone()[0], canonical)
        corrupted = _release_rows(self.db)
        self.assertEqual(self.snapshot.ipc_auth_key, original)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "unused_claim_changed"):
            self.release()
        self.assertEqual(_release_rows(self.db), corrupted)
        self.assertEqual(corrupted["reservations"], self.before["reservations"])
        self.assertEqual(corrupted[history.TABLE], [])
        self.assertEqual(corrupted["executions"], [])
        self.assertEqual(self.backend.closed, [])
        self.assertIsNotNone(self.process._handle)
        self.assertFalse(self.operation._completed)

    def test_changed_archive_prevents_completed_replay_without_policy_reentry(self):
        self.release()
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE executions SET outcome='managed_finished' WHERE reservation_id=?",
                         (self.before["reservations"][0]["id"],))
            conn.commit()
        with patch.object(self.policy, "hold", side_effect=AssertionError("corrupt replay reacquired POLICY")), \
                patch.object(self.process, "close", side_effect=AssertionError("corrupt replay retried close")):
            with self.assertRaises(history.ExperimentHistoryError):
                self.release()
        self.assertEqual(len(_rows(self.db, "executions")), 1)
        self.assertEqual(len(_rows(self.db, history.TABLE)), 1)
        self.assertEqual(_rows(self.db, "reservations"), [])

    def test_final_self_close_follows_positive_sql_nonce_and_readback_settlement(self):
        close = self.backend.close
        observations = []

        def observe_close(handle):
            observations.append(handle)
            self.assertTrue(self.operation._committed)
            self.assertTrue(self.operation._policy_settled)
            self.assertTrue(self.operation._postread)
            self.assertEqual(self.operation._connections, {})
            self.assertIsNone(self.policy.current_guard())
            self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
            self.assertEqual(len(_rows(self.db, history.TABLE)), 1)
            self.assertEqual(_rows(self.db, "reservations"), [])
            return close(handle)

        with patch.object(self.backend, "close", side_effect=observe_close):
            self.assert_released(self.release())
        self.assertEqual(observations, [700])

    def test_known_final_close_false_retries_only_the_same_original_handle(self):
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable") as caught:
                self.release()
            self.assertEqual(caught.exception._identity_handle_cleanup, (self.process,))
            self.assertIs(self.operation._close_error, caught.exception)
            self.assertIsNone(self.operation._quarantine)
            self.assertFalse(self.operation._completed)
            self.assertFalse(self.process._close_outcome_unknown)
            committed, queries = _release_rows(self.db), list(self.backend.queries)
            self.backend.failure = None
            with patch.object(self.policy, "prepare", side_effect=AssertionError("close retry prepared POLICY")), \
                    patch.object(self.policy, "hold", side_effect=AssertionError("close retry acquired POLICY")), \
                    patch.object(self.inner, "snapshot", side_effect=AssertionError("close retry reacquired native proof")):
                self.assert_released(self.release())
            self.assertEqual(close.call_args_list, [call(700), call(700)])
        self.assertEqual(self.backend.queries, queries)
        self.assertEqual(_release_rows(self.db), committed)

    def test_unknown_final_self_close_retains_owner_and_never_retries(self):
        failure = RuntimeError("synthetic final close outcome unknown")
        with patch.object(self.backend, "close", side_effect=failure) as close:
            with self.assertRaises(RuntimeError) as caught:
                self.release()
            self.assertIs(caught.exception, failure)
            self.assertIs(self.operation._quarantine, failure)
            self.assertEqual(failure._identity_handle_cleanup, (self.process,))
            self.assertTrue(self.process._close_outcome_unknown)
            self.assertFalse(self.operation._completed)
            self.assertFalse(self.demand._closed)
            self.assertIsNotNone(self.process._handle)
            committed = _release_rows(self.db)
            with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown close reopened SQL")):
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    self.release()
            self.assertEqual(close.call_args_list, [call(700)])
        self.assertEqual(len(committed[history.TABLE]), 1)
        self.assertEqual(len(committed["executions"]), 1)
        self.assertEqual(committed["reservations"], [])
        self.assertEqual(_release_rows(self.db), committed)

    def _assert_bookkeeping_interruption_replays_without_native(self, owner, field, value):
        assign, failures = type(owner).__setattr__, []
        failure = RuntimeError("synthetic final local bookkeeping interruption")

        def interrupted(target, key, assigned):
            assign(target, key, assigned)
            if target is owner and key == field and assigned is value and not failures:
                failures.append(True)
                raise failure

        with patch.object(type(owner), "__setattr__", interrupted):
            with self.assertRaises(RuntimeError) as caught:
                self.release()
        self.assertIs(caught.exception, failure)
        self.assertEqual(failures, [True])
        self.assertIs(getattr(owner, field), value)
        self.assertTrue(self.operation._close_positive)
        self.assertFalse(self.operation._completed)
        self.assertIsNone(self.process._handle)
        expected = json.loads(self.operation._result_json)
        committed, connect, statements = _release_rows(self.db), sqlite3.connect, []

        class Observed(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                statements.append(sql)
                return super().execute(sql, parameters)

        with ExitStack() as stack:
            for target, method in ((self.operation, "prepare_policy"), (self.policy, "prepare"),
                    (self.policy, "hold"), (self.coordinator, "_mirror"), (self.inner, "snapshot"),
                    (self.inner, "launch_claim_token"), (self.process, "observe"), (self.process, "close")):
                stack.enter_context(patch.object(target, method,
                    side_effect=AssertionError("local finish retried " + method)))
            stack.enter_context(patch.object(sqlite3, "connect",
                side_effect=lambda *a, **k: connect(*a, **k, factory=Observed)))
            self.assertEqual(self.release(), expected)
        self.assertTrue(any(sql.startswith("SELECT") for sql in statements))
        self.assertFalse(any(re.match(r"\s*(INSERT|UPDATE|DELETE|REPLACE)\b", sql, re.IGNORECASE) for sql in statements))
        self.assert_released(expected)
        self.assertEqual(_release_rows(self.db), committed)
        self.assertEqual(self.backend.closed, [700])

    def test_interruption_after_inner_snapshot_clear_finishes_with_reads_and_local_bookkeeping(self):
        self._assert_bookkeeping_interruption_replays_without_native(self.inner, "_snapshot", None)

    def test_interruption_after_demand_closed_finishes_with_reads_and_local_bookkeeping(self):
        self._assert_bookkeeping_interruption_replays_without_native(self.demand, "_closed", True)

    def _assert_wrong_receipt_field_is_rejected_at_insert(self, field, value):
        prepare, refused = self.operation._prepare_publication, []

        def inject(conn):
            fresh = prepare(conn)
            self.assertTrue(fresh)
            columns = self.operation._receipt_columns()
            expected_id, expected_sha = columns["receipt_id"], columns["receipt_sha256"]
            columns[field] = value
            self.assertEqual((columns["receipt_id"], columns["receipt_sha256"]), (expected_id, expected_sha))
            with self.assertRaisesRegex(sqlite3.DatabaseError, "experiment_release_receipt_not_owned"):
                conn.execute("INSERT INTO " + history.TABLE + "(" + ",".join(columns) + ") VALUES(" +
                    ",".join("?" for _ in columns) + ")", tuple(columns.values()))
            self.assertEqual(conn.execute("SELECT count(*) FROM " + history.TABLE).fetchone()[0], 0)
            refused.append(field)
            return fresh

        with patch.object(self.operation, "_prepare_publication", side_effect=inject):
            self.assert_released(self.release())
        self.assertEqual(refused, [field])

    def test_correct_receipt_id_and_sha_do_not_authorize_changed_receipt_json(self):
        self._assert_wrong_receipt_field_is_rejected_at_insert("receipt_json", "{}")

    def test_correct_receipt_id_and_sha_do_not_authorize_changed_operation_id(self):
        self._assert_wrong_receipt_field_is_rejected_at_insert("operation_id", str(uuid4()))

    def test_lost_nonce_clear_commit_ack_reconciles_without_new_prepare_or_native_hold(self):
        connect, lost = sqlite3.connect, []

        class LostClearAck(sqlite3.Connection):
            clearing = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if " ".join(sql.split()).startswith("UPDATE adaptive_runtime SET policy_entry_nonce=NULL"):
                    self.clearing = True
                return result

            def commit(self):
                super().commit()
                if self.clearing and not lost:
                    lost.append(True)
                    raise sqlite3.OperationalError("synthetic nonce clear commit acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostClearAck)):
            with self.assertRaisesRegex(sqlite3.OperationalError, "nonce clear commit acknowledgement lost"):
                self.release()
        self.assertEqual(lost, [True])
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        self.assertIsNone(self.operation._quarantine)
        original_guard = self.operation._guard
        committed, revision = _release_rows(self.db), self.custody.runtime()["registry_revision"]
        with patch.object(self.operation, "prepare_policy", side_effect=AssertionError("clear replay prepared nonce")), \
                patch.object(self.policy, "prepare", side_effect=AssertionError("clear replay prepared POLICY")), \
                patch.object(self.policy, "hold", side_effect=AssertionError("clear replay held POLICY")), \
                patch.object(self.policy.provider, "hold", side_effect=AssertionError("clear replay acquired native mutex")):
            self.assert_released(self.release())
        self.assertIs(self.operation._guard, original_guard)
        self.assertEqual(_release_rows(self.db), committed)
        self.assertEqual(self.custody.runtime()["registry_revision"], revision)

    def _assert_cached_insert_revalidates_original_write_authority(self, change):
        prepare, refused = self.operation._prepare_publication, []

        def inject(conn):
            fresh = prepare(conn)
            self.assertTrue(fresh)
            columns = self.operation._receipt_columns()
            sql = "INSERT INTO " + history.TABLE + "(" + ",".join(columns) + ") SELECT " + \
                ",".join("?" for _ in columns) + " WHERE ?"
            arguments = tuple(columns.values())
            # Compile this exact SQL, including its triggers, without inserting.
            self.assertEqual(conn.execute(sql, (*arguments, 0)).rowcount, 0)
            if change == "config":
                config = Path(self.db).with_name("config.json")
                original = config.read_bytes()
                config.write_bytes(original + b"\n")
                restore = lambda: config.write_bytes(original)
            else:
                guard, original = self.operation._guard, self.operation._guard.nonce
                guard.nonce = str(uuid4())
                restore = lambda: setattr(guard, "nonce", original)
            try:
                # A cached prepare/authorizer result cannot authorize this write.
                with self.assertRaises(sqlite3.DatabaseError):
                    conn.execute(sql, (*arguments, 1))
                refused.append(change)
            finally:
                restore()
            self.assertEqual(conn.execute("SELECT count(*) FROM " + history.TABLE).fetchone()[0], 0)
            return fresh

        with patch.object(self.operation, "_prepare_publication", side_effect=inject):
            self.assert_released(self.release())
        self.assertEqual(refused, [change])

    def test_cached_publication_insert_revalidates_original_config_digest(self):
        self._assert_cached_insert_revalidates_original_write_authority("config")

    def test_cached_publication_insert_revalidates_original_policy_nonce(self):
        self._assert_cached_insert_revalidates_original_write_authority("policy")

    def test_lost_writer_commit_ack_with_unknown_close_quarantines_original_connection(self):
        connect, lost, close_attempts = sqlite3.connect, [], []

        class UnknownWriterClose(sqlite3.Connection):
            publication = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if sql.startswith("INSERT INTO " + history.TABLE):
                    self.publication = True
                return result

            def commit(self):
                super().commit()
                if self.publication and not lost:
                    lost.append(True)
                    raise sqlite3.OperationalError("synthetic writer commit acknowledgement lost")

            def close(self):
                if self.publication:
                    close_attempts.append(self)
                    raise OSError("synthetic writer connection close outcome unknown")
                return super().close()

        try:
            with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=UnknownWriterClose)):
                with self.assertRaisesRegex(sqlite3.OperationalError, "writer commit acknowledgement lost") as caught:
                    self.release()
            self.assertEqual(lost, [True])
            self.assertEqual(len(close_attempts), 1)
            original = close_attempts[0]
            self.assertIs(caught.exception._sentinel_connection_cleanup, original)
            self.assertIs(self.operation._connections[id(original)][0], original)
            self.assertIsNotNone(self.operation._quarantine)
            self.assertFalse(self.operation._completed)
            self.assertEqual(self.backend.closed, [])
            self.assertIsNotNone(self.process._handle)
            committed = _release_rows(self.db)
            self.assertEqual(len(committed[history.TABLE]), 1)
            self.assertEqual(len(committed["executions"]), 1)
            self.assertEqual(committed["reservations"], [])
            self.assertEqual(self.custody.runtime()["policy_entry_nonce"], self.operation._guard.nonce)
            with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown writer cleanup reopened SQL")), \
                    patch.object(self.policy, "hold", side_effect=AssertionError("unknown writer cleanup reacquired POLICY")):
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    self.release()
            self.assertEqual(close_attempts, [original])
            self.assertEqual(_release_rows(self.db), committed)
        finally:
            for connection in close_attempts:
                # Test-only disposal of this isolated SQLite fixture. The
                # production operation remains quarantined and uncompleted.
                sqlite3.Connection.close(connection)

    def test_unverified_native_leave_after_committed_writer_keeps_nonce_and_self(self):
        for mode in ("raise", "suppress", "cleanup_note"):
            with self.subTest(native_leave=mode):
                case = ExperimentReleaseTests()
                try:
                    case.setUp()
                    connect, lost, leaves = sqlite3.connect, [], []
                    original_hold = case.policy.provider.hold

                    class LostWriterAck(sqlite3.Connection):
                        publication = False

                        def execute(self, sql, parameters=()):
                            result = super().execute(sql, parameters)
                            if sql.startswith("INSERT INTO " + history.TABLE):
                                self.publication = True
                            return result

                        def commit(self):
                            super().commit()
                            if self.publication and not lost:
                                lost.append(True)
                                raise sqlite3.OperationalError("synthetic committed writer reply lost")

                    class UnverifiedLeave:
                        def __init__(self, scope):
                            self.scope = scope

                        def __enter__(self):
                            return self.scope.__enter__()

                        def __exit__(self, kind, primary, tb):
                            # The model provider releases its Python lock; the
                            # injected result deliberately withholds proof that
                            # the corresponding native exit completed safely.
                            self.scope.__exit__(kind, primary, tb)
                            leaves.append(primary)
                            if mode == "raise":
                                raise RuntimeError("synthetic native leave outcome unknown")
                            if mode == "cleanup_note":
                                primary.add_note("synthetic_native_cleanup_unverified")
                            return mode == "suppress"

                    def uncertain_hold(binding, **kwargs):
                        return UnverifiedLeave(original_hold(binding, **kwargs))

                    with patch.object(case.policy.provider, "hold", side_effect=uncertain_hold), \
                            patch.object(case.policy, "_clear", side_effect=AssertionError("unverified native exit cleared nonce")) as clear, \
                            patch.object(case.process, "close", side_effect=AssertionError("unverified native exit closed self")) as close, \
                            patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostWriterAck)):
                        with self.assertRaisesRegex(sqlite3.OperationalError, "committed writer reply lost") as caught:
                            case.release()
                    self.assertEqual(lost, [True])
                    self.assertEqual(leaves, [caught.exception])
                    clear.assert_not_called()
                    close.assert_not_called()
                    self.assertFalse(case.operation._guard._native_exit_confirmed)
                    self.assertIsNotNone(case.operation._quarantine)
                    self.assertFalse(case.operation._completed)
                    self.assertIsNotNone(case.process._handle)
                    self.assertEqual(case.custody.runtime()["policy_entry_nonce"], case.operation._guard.nonce)
                    self.assertEqual(len(_rows(case.db, history.TABLE)), 1)
                    self.assertEqual(len(_rows(case.db, "executions")), 1)
                    self.assertEqual(_rows(case.db, "reservations"), [])
                    with patch.object(sqlite3, "connect", side_effect=AssertionError("unverified native exit reopened SQL")):
                        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                            case.release()
                finally:
                    case.doCleanups()

    def test_exact_native_timeout_clear_ack_loss_settles_only_original_no_entry_guard(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.snapshot.wrapper_identity
        backend.wait_error = windows.NativePolicyMutexError("policy_mutex_timeout")
        native, connect, lost = NativePolicyProvider(), sqlite3.connect, []

        class LostClearAck(sqlite3.Connection):
            clearing = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if " ".join(sql.split()).startswith("UPDATE adaptive_runtime SET policy_entry_nonce=NULL"):
                    self.clearing = True
                return result

            def commit(self):
                super().commit()
                if self.clearing and not lost:
                    lost.append(True)
                    raise sqlite3.OperationalError("synthetic no-entry nonce clear acknowledgement lost")

        with patch.object(windows, "_backend", return_value=backend), \
                patch.object(windows.VerifiedProcess, "current", return_value=process), \
                patch.object(self.policy.provider, "hold", side_effect=native.hold), \
                patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostClearAck)):
            with self.assertRaisesRegex(windows.NativePolicyMutexError, "policy_mutex_timeout") as caught:
                self.release()
        self.assertEqual(lost, [True])
        self.assertEqual(caught.exception.__notes__, ["policy_entry_cleanup_failed"])
        guard, calls_before = self.operation._guard, list(backend.calls)
        self.assertTrue(guard._native_no_entry_confirmed)
        self.assertFalse(guard._native_exit_confirmed)
        self.assertTrue(guard._nonce_clear_attempted)
        self.assertFalse(guard._nonce_clear_confirmed)
        self.assertIsNone(self.operation._quarantine)
        self.assertIsNone(self.custody.runtime()["policy_entry_nonce"])
        with patch.object(self.operation, "prepare_policy", side_effect=AssertionError("no-entry settle published new nonce")), \
                patch.object(self.policy, "hold", side_effect=AssertionError("no-entry settle reacquired POLICY")), \
                patch.object(self.policy, "_clear", side_effect=AssertionError("already-null nonce was cleared again")), \
                patch.object(self.process, "close", side_effect=AssertionError("no-entry settle closed original self")):
            self.operation._settle_previous()
        self.assertIs(self.operation._guard, guard)
        self.assertTrue(guard._nonce_clear_confirmed)
        self.assertTrue(self.operation._policy_settled)
        self.assertEqual(backend.calls, calls_before)
        self.assertFalse(any(event[0] == "release" for event in backend.calls))
        self.assert_charged()
        self.assertEqual(self.backend.closed, [])
        self.assert_released(self.release())

    def test_known_final_close_false_cannot_retry_with_replacement_self_owner(self):
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable"):
                self.release()
            self.backend.failure = None
            replacement_backend = Backend()
            replacement_backend.value = self.process.identity
            replacement = VerifiedProcess(replacement_backend, 701, self.process.identity)
            try:
                self.inner._process = replacement
                with patch.object(sqlite3, "connect", side_effect=AssertionError("replacement self opened cleanup SQL")):
                    with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_operation_changed"):
                        self.release()
                self.assertEqual(close.call_args_list, [call(700)])
                self.assertEqual(replacement_backend.closed, [])
                self.assertFalse(self.operation._completed)
            finally:
                self.inner._process = self.process
                replacement.close()  # Synthetic replacement fixture only.

    def test_known_final_close_false_cannot_retry_after_archive_corruption(self):
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable"):
                self.release()
            self.backend.failure = None
            with closing(sqlite3.connect(self.db)) as conn:
                conn.execute("UPDATE executions SET outcome='managed_finished' WHERE reservation_id=?",
                             (self.before["reservations"][0]["id"],))
                conn.commit()
            with patch.object(self.policy, "hold", side_effect=AssertionError("corrupt final close retry acquired POLICY")):
                with self.assertRaises(history.ExperimentHistoryError):
                    self.release()
            self.assertEqual(close.call_args_list, [call(700)])
        self.assertFalse(self.operation._completed)
        self.assertIsNotNone(self.process._handle)
        self.assertFalse(self.process._close_outcome_unknown)
        self.assertEqual(self.backend.closed, [])

    def test_ordinary_cancellation_and_close_never_replace_experiment_release(self):
        for completed in (False, True):
            if completed:
                self.release()
            for action in (
                    lambda: self.coordinator.cancel_managed(self.inner),
                    lambda: self.inner.cancel_reserved(self.db, reservation_id=self.before["reservations"][0]["id"], expected_revision=0),
                    self.inner.close):
                with self.subTest(completed=completed), \
                        self.assertRaisesRegex(ManagedAdmissionUnavailable, "experiment_native_cleanup_unverified"):
                    action()


class ExperimentPreparationReleaseTests(unittest.TestCase):
    def test_original_early_preparation_completion_releases_without_fabricated_native_capability(self):
        fixture = preparation_tests.PreparationTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        demand, scope = fixture.failed_original_check()
        completion = scope.close_native()
        self.assertEqual(completion.snapshot()["disposition"], "PREPARATION_CLOSED")
        self.assertIsNone(completion.snapshot()["reservation_id"])
        operation = demand.prepare_release(completion)
        self.addCleanup(lambda: cleanup._OPERATIONS.pop(operation.operation_id, None))
        with closing(sqlite3.connect(demand.ledger_path)) as conn:
            row = fixture.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" + ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        with patch.object(generation, "_assert_daily_locations"), \
                patch.object(generation, "verify_import_provenance"), \
                patch.object(generation, "_prove_retained_owner_ready", side_effect=AssertionError("release requested fresh readiness")):
            result = fixture.fixture.coordinator.release_experiment(operation)
            self.assertEqual(result["disposition"], "PREPARATION_CLOSED")
            self.assertTrue(result["released"])
            self.assertEqual(fixture.fixture.coordinator.release_experiment(operation), result)
        self.assertEqual(_rows(demand.ledger_path, "reservations"), [])
        receipts = _rows(demand.ledger_path, history.TABLE)
        self.assertEqual(len(receipts), 1)
        record = json.loads(receipts[0]["receipt_json"])
        self.assertEqual(record["completion_digest"], completion.digest)
        self.assertIsNone(record["completion"]["reservation_id"])
        self.assertIsNone(record["completion"]["daily_binding_sha256"])
        self.assertIsNone(record["postimage"]["exclusion"])


if __name__ == "__main__":
    unittest.main()
