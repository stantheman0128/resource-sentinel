"""Unadmitted experiment cleanup with real isolated SQL and synthetic handles.

Queue admission, original settlement, cancellation guards and final ownership
are exercised through their production APIs. No native work, daily runtime or
production configuration is used; synthetic handle outcomes prove source only.
"""
from contextlib import closing, contextmanager, ExitStack
from copy import copy
import json
import sqlite3
import threading
import unittest
from unittest.mock import call, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_retirement_fence as retirement
from sentinel.adaptive import experiment_abandon as abandon
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import windows
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.policy import NativePolicyProvider
from sentinel.coordinator import Coordinator
from tests import test_adaptive_experiment_admission_settlement as settlement_tests
from tests import test_adaptive_experiment_preparation as preparation_tests
from tests.test_adaptive_identity import Backend
from tests.test_adaptive_policy_mutex import FixtureBackend, FixtureProcess


_rows = settlement_tests._rows
_capacity_rows = settlement_tests._capacity_rows
_REFUSED = (RuntimeError, ManagedAdmissionUnavailable)


def _deleting_queue(sql):
    return " ".join(sql.split()).upper().startswith("DELETE FROM QUEUE ")


class ExperimentUnadmittedCleanupTests(unittest.TestCase):
    def setUp(self):
        # Composition keeps the existing settlement tests from being inherited
        # and repeated. Its setup captures the actual original VerifiedProcess.
        self.fixture = settlement_tests.ExperimentAdmissionSettlementTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.demand, self.coordinator = self.fixture.demand, self.fixture.coordinator
        self.inner, self.snapshot = self.fixture.inner, self.fixture.snapshot
        self.process, self.backend, self.db = self.fixture.process, self.fixture.backend, self.fixture.db
        self.addCleanup(self._remove_operation)

    def _remove_operation(self):
        operation = getattr(self.demand, "_unadmitted_cleanup", None)
        if operation is not None:
            for module in (abandon, cleanup):
                registry = getattr(module, "_OPERATIONS", {})
                if registry.get(operation.operation_id) is operation:
                    del registry[operation.operation_id]

    def _queued(self, *, foreign=False):
        self.fixture.fixture.publish_status(commit=94)
        self.assertFalse(self.coordinator.admit_experiment(self.demand)["allowed"])
        self.policy = self.inner._submission_policy
        self.assertIsNone(self.inner._submission_guard)
        self.original_submission = self.demand._submission_original
        self.assertIs(self.original_submission[0], self.policy)
        self.assertIs(self.original_submission[1], self.policy.store)
        self.guard = self.original_submission[2]
        self.assertEqual(self.original_submission[3:], (self.guard.binding, self.guard.nonce))
        self.assertTrue(self.guard._native_exit_confirmed)
        self.assertTrue(self.guard._nonce_clear_confirmed)
        if foreign:
            other_backend = Backend()
            other_backend.value = self.snapshot.wrapper_identity
            self.other_process = VerifiedProcess(other_backend, 701, other_backend.value)
            with patch.object(VerifiedProcess, "current", return_value=self.other_process):
                self.other = self.fixture.fixture.capture()
                self.assertFalse(self.coordinator.admit_experiment(self.other)["allowed"])
        self.fixture._install_generation()
        self._remember()

    def _remember(self):
        self.before = _capacity_rows(self.db)
        self.runtime_before = self.fixture.runtime()

    @contextmanager
    def _no_new_authority(self):
        with ExitStack() as stack:
            for target, name in ((self.policy, "prepare"), (self.policy, "hold"),
                    (self.policy.provider, "hold"), (self.policy, "_clear"),
                    (self.demand, "_prepare_submission"), (self.coordinator, "_admit"),
                    (self.coordinator, "_mirror")):
                stack.enter_context(patch.object(target, name,
                    side_effect=AssertionError("unadmitted cleanup acquired authority: " + name)))
            yield

    def abandon(self):
        with self._no_new_authority():
            return self.coordinator.abandon_experiment(self.demand)

    def assert_preserved(self, expected=None):
        self.assertEqual(_capacity_rows(self.db), self.before if expected is None else expected)
        self.assertIsNone(self.demand._before_native_completion)
        self.assertIsNone(self.demand._release_operation)
        self.assertFalse(self.demand._closed)
        self.assertIsNotNone(self.process._handle)
        self.assertEqual(self.backend.closed, [])

    def assert_abandoned(self, result, state="QUEUED_CANCELLED"):
        self.assertIs(result["cancelled"], True)
        self.assertEqual(result["state"], state)
        self.assertIs(result["launch_authorized"], False)
        self.assertIsNone(result.get("reservation_id"))
        self.assertEqual(result["execution_id"], self.snapshot.execution_id)
        self.assertEqual(result["request_key"], self.snapshot.request.request_key)
        self.assertNotIn("receipt_id", result)
        self.assertNotIn("allowed", result)
        expected = dict(self.before)
        expected["queue"] = [row for row in self.before["queue"]
                             if row["request_key"] != self.snapshot.request.request_key]
        self.assertEqual(_capacity_rows(self.db), expected)
        self.assertEqual(self.fixture.runtime(), self.runtime_before)
        self.assertTrue(self.demand._closed)
        self.assertTrue(self.inner._closed)
        self.assertIsNone(self.inner._snapshot)
        self.assertIsNone(self.inner._claim_token)
        self.assertIsNone(self.inner._key)
        self.assertIsNone(self.process._handle)
        self.assertEqual(self.backend.closed, [700])
        self.assertIsNone(self.demand._before_native_completion)
        self.assertIsNone(self.demand._release_operation)
        operation = self.demand._unadmitted_cleanup
        self.assertIs(type(operation), abandon.ExperimentUnadmittedCleanup)
        self.assertEqual(operation._connections, {})
        self.assertTrue(operation._completed)

    def _fixture_queue_mutation(self, sql, parameters=(), *, event="delete"):
        # Simulate an independent writer/corrupt persisted observation, with the
        # exact canonical guard restored before production cleanup observes it.
        name = "adaptive_daily_queue_" + event
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            statement = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
            conn.execute("DROP TRIGGER " + name)
            conn.execute(sql, parameters)
            conn.execute(statement)
            conn.commit()
            generation.validate_triggers(conn)

    def _pin_before_read(self):
        with patch.object(abandon.ExperimentUnadmittedCleanup, "_read",
                          side_effect=OSError("synthetic before first cleanup read")):
            with self.assertRaisesRegex(OSError, "before first cleanup read"):
                self.abandon()
        operation = self.demand._unadmitted_cleanup
        self.assertIsNone(operation._quarantine)
        return operation

    def _interrupt_writer(self, *, commit_attempted=False):
        connect, failed = sqlite3.connect, []

        class InterruptedWriter(sqlite3.Connection):
            deletion = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                if _deleting_queue(sql):
                    self.deletion = True
                    if not commit_attempted and not failed:
                        failed.append(self)
                        raise OSError("synthetic deletion interrupted before COMMIT")
                return result

            def commit(self):
                if self.deletion and commit_attempted and not failed:
                    failed.append(self)
                    raise OSError("synthetic attempted COMMIT rejected before effect")
                super().commit()

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=InterruptedWriter)):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self.abandon()
        self.assertEqual(len(failed), 1)
        operation = self.demand._unadmitted_cleanup
        self.assertIsNone(operation._quarantine)
        self.assertEqual(operation._connections, {})
        self.assertIs(operation._commit_attempted, commit_attempted)
        self.assert_preserved()
        return operation

    def _initial_queue_clear_ack_loss(self):
        # Keep this demand unsealed: exercise ordinary readmission's original
        # settlement boundary, rather than the sealing cleanup-only API.
        self.fixture.fixture.publish_status(commit=94)
        connect, lost = sqlite3.connect, []

        class LostClearAck(sqlite3.Connection):
            clearing = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clearing = self.clearing or settlement_tests._clearing(sql)
                return result

            def commit(self):
                super().commit()
                if self.clearing and not lost:
                    lost.append(self)
                    raise OSError("synthetic original queued nonce-clear ACK lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostClearAck)):
            with self.assertRaisesRegex(OSError, "queued nonce-clear ACK lost"):
                self.coordinator.admit_experiment(self.demand)
        self.assertEqual(len(lost), 1)
        self.assertFalse(self.demand._native_preparation_sealed)
        self.policy = self.inner._submission_policy
        guard = self.inner._submission_guard
        self.assertIs(guard, self.demand._submission_original[2])
        self.assertTrue(guard._native_exit_confirmed)
        self.assertTrue(guard._nonce_clear_attempted)
        self.assertFalse(guard._nonce_clear_confirmed)
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assertIs(self.inner._submission_transaction["connection_closed"], True)
        return guard

    def test_exact_queued_request_is_removed_and_only_original_self_is_closed(self):
        self._queued(foreign=True)
        other_rows = [row for row in self.before["queue"] if row["request_key"] != self.snapshot.request.request_key]
        observed, close = [], self.backend.close

        def after_sql(handle):
            operation = self.demand._unadmitted_cleanup
            observed.append(handle)
            self.assertEqual(operation._connections, {})
            self.assertEqual(_rows(self.db, "queue"), other_rows)
            self.assertIsNone(self.policy.current_guard())
            self.assertIsNone(self.policy.current_cleanup_guard())
            self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
            return close(handle)

        with patch.object(self.backend, "close", side_effect=after_sql):
            self.assert_abandoned(self.abandon())
        self.assertEqual(observed, [700])
        self.assertEqual(self.other_process._handle, 701)
        self.assertFalse(self.other._closed)

    def test_draining_generation_cleans_queue_without_readiness_or_new_policy(self):
        self._queued()
        self.fixture.change("adaptive_daily_generation", "state", "DRAINING")
        self.assert_abandoned(self.abandon())
        self.assertEqual(_rows(self.db, "adaptive_daily_generation")[0]["state"], "DRAINING")

    def test_unsettled_guard_refuses_then_public_settlement_and_abandon_succeed(self):
        self.fixture._pending_admission(queued=True)
        self.policy = self.inner._submission_policy
        self._remember()
        guard = self.inner._submission_guard
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unsettled admission opened cleanup SQL")):
            with self.assertRaises(_REFUSED):
                self.abandon()
        self.assertIs(self.inner._submission_guard, guard)
        self.assert_preserved()
        settled = self.fixture.settle()
        self.assertEqual(settled["state"], "QUEUED")
        self.runtime_before = self.fixture.runtime()
        self.assert_abandoned(self.abandon())

    def test_never_committed_positive_first_rollback_can_close_without_queue_delete(self):
        self.fixture._pending_admission(rollback=True)
        self.policy = self.inner._submission_policy
        self.assertEqual(self.fixture.settle()["state"], "SUBMISSION_REJECTED")
        self._remember()
        connect, deletes = sqlite3.connect, []

        class NoQueueDelete(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if _deleting_queue(sql):
                    deletes.append(sql)
                    raise AssertionError("rejected first transaction attempted queue cancellation")
                return super().execute(sql, parameters)

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=NoQueueDelete)):
            self.assert_abandoned(self.abandon(), "SUBMISSION_REJECTED")
        self.assertEqual(deletes, [])

    def test_absent_queue_without_this_operations_commit_attempt_is_not_cancellation(self):
        self._queued()
        self._fixture_queue_mutation("DELETE FROM queue WHERE request_key=?", (self.snapshot.request.request_key,))
        absent = _capacity_rows(self.db)
        with self.assertRaises(_REFUSED):
            self.abandon()
        self.assert_preserved(absent)

    def test_actual_admitted_demand_cannot_use_unadmitted_cleanup(self):
        self.assertTrue(self.coordinator.admit_experiment(self.demand)["allowed"])
        self.policy = self.inner._submission_policy
        self.fixture._install_generation()
        self._remember()
        with self.assertRaises(_REFUSED):
            self.abandon()
        self.assert_preserved()

    def test_before_native_completion_cannot_be_reinterpreted_as_unadmitted(self):
        self.assertTrue(self.coordinator.admit_experiment(self.demand)["allowed"])
        completion = self.demand.seal_without_native()
        self.policy = self.inner._submission_policy
        self.fixture._install_generation()
        self._remember()
        with patch.object(sqlite3, "connect", side_effect=AssertionError("completed demand opened unadmitted SQL")):
            with self.assertRaises(_REFUSED):
                self.abandon()
        self.assertIs(self.demand._before_native_completion, completion)
        self.assertEqual(_capacity_rows(self.db), self.before)
        self.assertEqual(self.backend.closed, [])

    def test_actual_retained_native_preparation_refuses_before_sql(self):
        preparation = preparation_tests.PreparationTests()
        self.addCleanup(preparation.doCleanups)
        preparation.setUp()
        demand, native = preparation.failed_original_check()
        before = preparation.fixture.assert_retained(demand)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("native-prepared demand opened abandon SQL")):
            with self.assertRaises(_REFUSED):
                preparation.fixture.coordinator.abandon_experiment(demand)
        self.assertIs(demand._native_preparation, native)
        self.assertEqual(preparation.fixture.assert_retained(demand), before)
        self.assertFalse(demand._closed)

    def test_foreign_queue_delete_is_denied_inside_original_writer(self):
        self._queued(foreign=True)
        foreign_key = self.other._snapshot.request.request_key
        connect, attempts = sqlite3.connect, []

        class WrongDelete(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if _deleting_queue(sql) and not attempts:
                    attempts.append(True)
                    try:
                        super().execute("DELETE FROM queue WHERE request_key=?", (foreign_key,))
                    except sqlite3.DatabaseError:
                        pass
                    else:
                        raise AssertionError("original queue authority deleted another owner's row")
                return super().execute(sql, parameters)

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=WrongDelete)):
            self.assert_abandoned(self.abandon())
        self.assertEqual(attempts, [True])

    def test_missing_canonical_delete_guard_is_not_repaired_or_bypassed(self):
        self._queued()
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("DROP TRIGGER adaptive_daily_queue_delete")
            conn.commit()
        with self.assertRaises(_REFUSED):
            self.abandon()
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_daily_queue_delete'").fetchone())
        self.assert_preserved()

    def test_changed_generation_owner_and_endpoint_never_adopt_current_generation(self):
        self._queued()
        for column, value in (("generation", str(uuid4())), ("readiness_instance_id", str(uuid4())),
                ("owner_identity_json", json.dumps(dict(self.snapshot.wrapper_identity.to_dict(), pid=99)))):
            with self.subTest(column=column):
                self.fixture.change("adaptive_daily_generation", column, value)
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "generation_changed"):
                    self.abandon()
                self.fixture.change("adaptive_daily_generation", column, self.fixture.fixture.generation[column])
                self.assert_preserved()

    def test_sealed_retirement_cannot_obtain_queue_mutation_authority(self):
        self._queued()
        self.fixture.change("adaptive_daily_generation", "state", "DRAINING")
        # A canonical persisted SEALED observation is a refusal fixture, not a
        # manufactured native retirement capability or proof of native cleanup.
        row = dict(singleton=1, schema_version=1, request_id=str(uuid4()),
            **{key: self.fixture.fixture.generation[key] for key in retirement.OWNER_BINDING_FIELDS},
            policy_instance_id=self.guard.binding.instance_id, policy_logon_id=self.guard.binding.logon_id,
            freeze_policy_nonce=self.guard.nonce, freeze_registry_revision=self.runtime_before["registry_revision"],
            phase="SEALED", seal_digest="c" * 64)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute(retirement._SCHEMA)
            conn.execute("INSERT INTO " + retirement.TABLE + "(" + ",".join(retirement._FIELDS) + ") VALUES(" +
                ",".join("?" for _ in retirement._FIELDS) + ")", tuple(row[key] for key in retirement._FIELDS))
            for statement in retirement._definitions(conn).values():
                conn.execute(statement)
            conn.commit()
            self.assertEqual(retirement.read_retirement(conn)["phase"], "SEALED")
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "generation_sealed"):
            self.abandon()
        self.assert_preserved()

    def test_foreign_main_file_with_identical_rows_is_not_original_ledger(self):
        self._queued()
        connect = sqlite3.connect
        foreign = self.db.with_name("foreign-cleanup.sqlite3")
        with closing(connect(self.db)) as source, closing(connect(foreign)) as target:
            source.backup(target)
        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(str(foreign), **k)):
            with self.assertRaises(_REFUSED):
                self.abandon()
        self.assert_preserved()
        self.assertEqual(_rows(foreign, "queue"), self.before["queue"])

    def test_wrong_coordinator_or_copied_owner_cannot_dispatch_original_operation(self):
        self._queued()
        operation = self._pin_before_read()
        foreign = Coordinator.__new__(Coordinator)
        foreign.db_path = self.db
        with patch.object(sqlite3, "connect", side_effect=AssertionError("substituted owner opened SQL")):
            for value in (object(), {"experiment_id": self.demand.declaration.experiment_id}, copy(self.demand)):
                with self.subTest(kind=type(value).__name__), self.assertRaises(_REFUSED):
                    self.coordinator.abandon_experiment(value)
            with self.assertRaises(_REFUSED):
                foreign.abandon_experiment(self.demand)
            with self.assertRaises(_REFUSED):
                abandon.ExperimentUnadmittedCleanup(self.coordinator, self.demand)
            self.demand._unadmitted_cleanup = copy(operation)
            with self.assertRaises(_REFUSED):
                self.coordinator.abandon_experiment(self.demand)
        self.demand._unadmitted_cleanup = operation
        self.assert_preserved()

    def test_original_guard_tuple_and_transaction_cannot_be_replaced_or_mutated(self):
        self._queued()
        operation = self._pin_before_read()
        submission = self.demand._submission_original
        transaction = self.inner._submission_transaction
        self.demand._submission_original = tuple(list(submission))
        with patch.object(sqlite3, "connect", side_effect=AssertionError("copied submission tuple opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_submission_changed"):
                self.abandon()
        self.demand._submission_original = submission
        self.inner._submission_transaction = dict(transaction)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("copied original transaction opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_transaction_changed"):
                self.abandon()
        self.inner._submission_transaction = transaction
        transaction["connection_closed"] = False
        with patch.object(sqlite3, "connect", side_effect=AssertionError("changed original transaction opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_transaction_changed"):
                self.abandon()
        self.assertIs(operation._submission, submission)
        self.assert_preserved()

    def test_original_cleanup_cannot_migrate_to_another_thread(self):
        self._queued()
        self._pin_before_read()
        errors = []

        def run():
            try:
                self.coordinator.abandon_experiment(self.demand)
            except BaseException as error:
                errors.append(error)

        with patch.object(sqlite3, "connect", side_effect=AssertionError("other thread opened cleanup SQL")):
            thread = threading.Thread(target=run)
            thread.start()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], cleanup.ExperimentReleaseError)
        self.assert_preserved()

    def test_positive_rollback_can_recheck_original_queue_after_legitimate_heartbeat(self):
        self._queued()
        operation = self._interrupt_writer()
        previous = operation._candidate
        self._fixture_queue_mutation("UPDATE queue SET heartbeat_at=heartbeat_at+1 WHERE request_key=?",
                                    (self.snapshot.request.request_key,), event="update")
        self.before = _capacity_rows(self.db)
        self.assert_abandoned(self.abandon())
        self.assertNotEqual(operation._candidate, previous)

    def test_failed_writer_begin_does_not_freeze_reader_preimage_before_heartbeat_retry(self):
        self._queued()
        # A real SQLite RESERVED lock permits the cleanup's first read, while
        # its separate BEGIN IMMEDIATE writer must fail within the bounded wait.
        # No synthetic failure is raised from the production transaction seam.
        with closing(sqlite3.connect(self.db, isolation_level=None)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    self.abandon()
            finally:
                blocker.rollback()
        operation = self.demand._unadmitted_cleanup
        self.assertIsNone(operation._candidate)
        self.assertFalse(operation._commit_attempted)
        self.assertFalse(operation._committed)
        self.assertIsNone(operation._writer)
        self.assertIsNone(operation._quarantine)
        self.assertEqual(operation._connections, {})
        self.assert_preserved()
        self._fixture_queue_mutation("UPDATE queue SET heartbeat_at=heartbeat_at+1 WHERE request_key=?",
                                    (self.snapshot.request.request_key,), event="update")
        self.before = _capacity_rows(self.db)
        self.assert_abandoned(self.abandon())
        self.assertIs(self.demand._unadmitted_cleanup, operation)

    def test_attempted_commit_keeps_exact_preimage_and_refuses_changed_queue(self):
        self._queued()
        operation = self._interrupt_writer(commit_attempted=True)
        previous = operation._candidate
        self._fixture_queue_mutation("UPDATE queue SET heartbeat_at=heartbeat_at+1 WHERE request_key=?",
                                    (self.snapshot.request.request_key,), event="update")
        changed = _capacity_rows(self.db)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_queue_changed"):
            self.abandon()
        self.assertEqual(operation._candidate, previous)
        self.assert_preserved(changed)

    def test_lost_delete_commit_ack_reconciles_original_attempt_without_second_delete(self):
        self._queued()
        connect, lost = sqlite3.connect, []

        class LostDeleteAck(sqlite3.Connection):
            deletion = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.deletion = self.deletion or _deleting_queue(sql)
                return result

            def commit(self):
                super().commit()
                if self.deletion and not lost:
                    lost.append(self)
                    raise OSError("synthetic queue delete acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostDeleteAck)):
            with self.assertRaisesRegex(OSError, "delete acknowledgement lost"):
                self.abandon()
        self.assertEqual(len(lost), 1)
        operation = self.demand._unadmitted_cleanup
        self.assertIsNone(operation._quarantine)
        self.assertEqual(operation._connections, {})
        self.assertEqual(_rows(self.db, "queue"), [])
        self.assertEqual(self.backend.closed, [])

        class ReadAfterLostAck(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if _deleting_queue(sql):
                    raise AssertionError("lost ACK replay attempted another delete")
                return super().execute(sql, parameters)

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=ReadAfterLostAck)):
            self.assert_abandoned(self.abandon())
        self.assertIs(self.demand._unadmitted_cleanup, operation)

    def test_unknown_writer_close_keeps_original_connection_and_forbids_reopen(self):
        self._queued()
        connect, unknown = sqlite3.connect, []

        class UnknownWriterClose(sqlite3.Connection):
            deletion = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.deletion = self.deletion or _deleting_queue(sql)
                return result

            def close(self):
                if self.deletion:
                    unknown.append(self)
                    raise OSError("synthetic delete connection close unknown")
                super().close()

        try:
            with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=UnknownWriterClose)):
                with self.assertRaises(Exception):
                    self.abandon()
            self.assertEqual(len(unknown), 1)
            operation = self.demand._unadmitted_cleanup
            self.assertIsNotNone(operation._quarantine)
            self.assertIs(operation._connections[id(unknown[0])][0], unknown[0])
            with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown writer reopened SQL")):
                with self.assertRaises(_REFUSED):
                    self.abandon()
            self.assertEqual(self.backend.closed, [])
            self.assertFalse(self.demand._closed)
        finally:
            for conn in unknown:
                sqlite3.Connection.close(conn)  # Fixture disposal only; never settle production custody.

    def test_known_final_close_false_retries_only_same_original_handle(self):
        self._queued()
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable") as caught:
                self.abandon()
            operation = self.demand._unadmitted_cleanup
            self.assertEqual(caught.exception._identity_handle_cleanup, (self.process,))
            self.assertIsNone(operation._quarantine)
            self.assertFalse(self.process._close_outcome_unknown)
            self.assertEqual(_rows(self.db, "queue"), [])
            self.backend.failure = None
            with patch.object(self.inner, "snapshot", side_effect=AssertionError("close retry acquired native proof")):
                self.assert_abandoned(self.abandon())
            self.assertEqual(close.call_args_list, [call(700), call(700)])

    def test_known_false_close_cannot_retry_a_substituted_process_witness(self):
        self._queued()
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaisesRegex(IdentityUnavailable, "close_unavailable"):
                self.abandon()
            other_backend = Backend()
            other_backend.value = self.snapshot.wrapper_identity
            replacement = VerifiedProcess(other_backend, 701, other_backend.value)
            self.inner._process = replacement
            with patch.object(sqlite3, "connect", side_effect=AssertionError("substituted self witness opened SQL")):
                with self.assertRaises(_REFUSED):
                    self.abandon()
            self.assertEqual(close.call_args_list, [call(700)])
            self.assertEqual(other_backend.closed, [])
        self.assertFalse(self.demand._closed)

    def test_unknown_final_close_retains_witness_and_never_reopens_or_retries(self):
        self._queued()
        failure = RuntimeError("synthetic original self-close outcome unknown")
        with patch.object(self.backend, "close", side_effect=failure) as close:
            with self.assertRaises(RuntimeError) as caught:
                self.abandon()
            self.assertIs(caught.exception, failure)
            operation = self.demand._unadmitted_cleanup
            self.assertIs(operation._quarantine, failure)
            self.assertEqual(failure._identity_handle_cleanup, (self.process,))
            self.assertTrue(self.process._close_outcome_unknown)
            with patch.object(sqlite3, "connect", side_effect=AssertionError("uncertain self-close reopened SQL")):
                with self.assertRaises(_REFUSED):
                    self.abandon()
            self.assertEqual(close.call_args_list, [call(700)])
        self.assertEqual(_rows(self.db, "queue"), [])
        self.assertFalse(self.demand._closed)
        self.assertIsNotNone(self.process._handle)

    def test_completed_replay_is_read_only_and_never_closes_again(self):
        self._queued()
        first = self.abandon()
        operation = self.demand._unadmitted_cleanup
        connect, opened, closed = sqlite3.connect, [], []

        class ReadOnlyReplay(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE ", "REPLACE ")):
                    raise AssertionError("completed cleanup replay wrote persistent state")
                return super().execute(sql, parameters)

            def close(self):
                super().close()
                closed.append(self)

        def open_read(*args, **kwargs):
            conn = connect(*args, **kwargs, factory=ReadOnlyReplay)
            opened.append(conn)
            return conn

        with patch.object(sqlite3, "connect", side_effect=open_read), \
                patch.object(self.process, "close", side_effect=AssertionError("replay closed original self twice")), \
                patch.object(self.process, "observe", side_effect=AssertionError("replay observed retired self")), \
                patch.object(self.inner, "snapshot", side_effect=AssertionError("replay reacquired snapshot")):
            second = self.abandon()
        self.assertEqual(second, first)
        self.assertTrue(opened)
        self.assertEqual(opened, closed)
        self.assertIs(self.demand._unadmitted_cleanup, operation)
        self.assert_abandoned(second)

    def test_positive_no_entry_closes_as_not_submitted_without_queue_delete(self):
        backend, current = FixtureBackend(), FixtureProcess()
        current.identity = self.snapshot.wrapper_identity
        backend.wait_error = windows.NativePolicyMutexError("policy_mutex_timeout")
        native = NativePolicyProvider()
        with patch.object(windows, "_backend", return_value=backend), \
                patch.object(windows.VerifiedProcess, "current", return_value=current), \
                patch.object(self.fixture.fixture.fixture.policy, "hold", side_effect=native.hold):
            with self.assertRaisesRegex(windows.NativePolicyMutexError, "policy_mutex_timeout") as caught:
                self.coordinator.admit_experiment(self.demand)
        self.fixture._after_failure(caught.exception)
        self.policy = self.inner._submission_policy
        self.assertEqual(self.fixture.settle()["state"], "NEVER_SUBMITTED")
        self.assertFalse(self.inner._submitted)
        self.assertIsNone(self.inner._submission_transaction)
        self._remember()
        self.assert_abandoned(self.abandon(), "NOT_SUBMITTED")

    def test_positive_close_interrupted_local_bookkeeping_never_closes_twice(self):
        self._queued()
        original_setattr, interrupted = type(self.inner).__setattr__, []
        inner = self.inner
        failure = KeyboardInterrupt("synthetic after positive close local interruption")

        def assign(instance, name, value):
            original_setattr(instance, name, value)
            if instance is inner and name == "_snapshot" and value is None and not interrupted:
                interrupted.append(True)
                raise failure

        with patch.object(type(inner), "__setattr__", new=assign):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.abandon()
        self.assertIs(caught.exception, failure)
        operation = self.demand._unadmitted_cleanup
        self.assertTrue(operation._close_positive)
        self.assertFalse(operation._completed)
        self.assertIsNone(operation._quarantine)
        self.assertEqual(self.backend.closed, [700])
        with patch.object(self.process, "close", side_effect=AssertionError("local retry closed self twice")), \
                patch.object(self.inner, "snapshot", side_effect=AssertionError("local retry observed retired self")):
            self.assert_abandoned(self.abandon())

    def test_ordinary_readmission_after_original_clear_ack_loss_pins_next_guard_without_orphan_nonce(self):
        previous = self._initial_queue_clear_ack_loss()
        prepare, calls = self.policy.prepare, []

        def prepare_after_original_clear(*args, **kwargs):
            self.assertTrue(previous._nonce_clear_confirmed)
            self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
            calls.append(True)
            return prepare(*args, **kwargs)

        with patch.object(self.policy, "prepare", side_effect=prepare_after_original_clear):
            result = self.coordinator.admit_experiment(self.demand)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "commit_capacity")
        self.assertEqual(calls, [True])
        current = self.demand._submission_original[2]
        self.assertIsNot(current, previous)
        self.assertTrue(previous._nonce_clear_confirmed)
        self.assertTrue(current._native_exit_confirmed)
        self.assertTrue(current._nonce_clear_confirmed)
        self.assertIsNone(self.inner._submission_guard)
        self.assertIsNone(self.inner._submission_policy_error)
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assertEqual(len(_rows(self.db, "queue")), 1)
        self.fixture._install_generation()
        self._remember()
        self.assert_abandoned(self.abandon())

    def test_ordinary_readmission_null_nonce_without_own_clear_attempt_refuses_before_prepare(self):
        self.fixture.fixture.publish_status(commit=94)
        commit = self.coordinator._commit_admission

        def lost_commit(conn, transaction):
            commit(conn, transaction)
            raise OSError("synthetic queued admission COMMIT ACK lost")

        with patch.object(self.coordinator, "_commit_admission", side_effect=lost_commit):
            with self.assertRaisesRegex(OSError, "admission COMMIT ACK lost"):
                self.coordinator.admit_experiment(self.demand)
        self.policy = self.inner._submission_policy
        original = self.demand._submission_original
        self.assertFalse(original[2]._nonce_clear_attempted)
        self.fixture.change("adaptive_runtime", "policy_entry_nonce", None)
        before = _capacity_rows(self.db)
        with patch.object(self.policy, "prepare", side_effect=AssertionError("missing original clear published new nonce")):
            with self.assertRaises(_REFUSED):
                self.coordinator.admit_experiment(self.demand)
        self.assertIs(self.demand._submission_original, original)
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assertEqual(_capacity_rows(self.db), before)
        self.assertEqual(self.backend.closed, [])

    def test_ordinary_readmission_null_nonce_without_positive_native_cleanup_refuses_before_prepare(self):
        previous = self._initial_queue_clear_ack_loss()
        previous._native_exit_confirmed = False
        before = _capacity_rows(self.db)
        with patch.object(self.policy, "prepare", side_effect=AssertionError("unknown native cleanup published new nonce")):
            with self.assertRaises(_REFUSED):
                self.coordinator.admit_experiment(self.demand)
        self.assertIs(self.demand._submission_original[2], previous)
        self.assertIsNone(self.fixture.runtime()["policy_entry_nonce"])
        self.assertEqual(_capacity_rows(self.db), before)
        self.assertEqual(self.backend.closed, [])


if __name__ == "__main__":
    unittest.main()
