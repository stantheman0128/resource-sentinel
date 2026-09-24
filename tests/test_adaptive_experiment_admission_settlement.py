"""Original admission settlement in isolated SQLite, with synthetic identity.

Admission, guard ownership, generation checks, nonce SQL, completion and release
are production paths. The retained process and optional mutex backend are
portable fixtures; these tests provide no native Windows acceptance evidence.
"""
from contextlib import closing, contextmanager, ExitStack
from copy import copy
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import experiment_exclusion as exclusion
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive import windows
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.policy import NativePolicyProvider
from sentinel.adaptive.store import hold_expired_allocations
from sentinel.coordinator import Coordinator
from tests import test_adaptive_experiment_demand as demand_tests
from tests import test_adaptive_managed_admission as managed_tests
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_identity import Backend
from tests.test_adaptive_policy_mutex import FixtureBackend, FixtureProcess


def _rows(path, table):
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
            return None
        return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]


def _capacity_rows(path):
    # Preserve absent schemas as well as existing rows: settlement is no installer.
    return {table: _rows(path, table) for table in (
        "reservations", "queue", "worker_reservations", "managed_executions",
        "executions", demand_module.TABLE, history.TABLE, exclusion.TABLE)}


def _clearing(sql):
    return " ".join(sql.split()).startswith("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")


class ExperimentAdmissionSettlementTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.backend.value = IDENTITY
        self.process = VerifiedProcess(self.backend, 700, IDENTITY)
        self.fixture = demand_tests.ExperimentDemandTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(managed_tests, "FakeCurrentProcess", return_value=self.process):
            self.fixture.setUp()
        self.coordinator = self.fixture.coordinator
        self.demand = self.fixture.capture()
        self.inner, self.snapshot = self.demand._admission, self.demand._snapshot
        self.db = self.demand.ledger_path
        self.addCleanup(self._remove_operations)

    def _remove_operations(self):
        for attribute in ("_admission_settlement", "_release_operation"):
            owner = getattr(self.demand, attribute, None)
            if owner is not None and cleanup._OPERATIONS.get(owner.operation_id) is owner:
                del cleanup._OPERATIONS[owner.operation_id]

    def _install_generation(self):
        # Same full original generation fixture as the cleanup-custody tests.
        # Location/import attestation alone is synthetic; consumer transaction
        # validation and canonical persistent SQL triggers remain real.
        with closing(sqlite3.connect(self.db)) as conn:
            row = self.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for override in (
                patch.object(generation, "_assert_daily_locations"),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "_prove_retained_owner_ready",
                    side_effect=AssertionError("settlement requested a fresh readiness RPC"))):
            override.start()
            self.addCleanup(override.stop)

    def _after_failure(self, error, *, quarantined=False):
        self.original_error = error
        self.guard = self.inner._submission_guard
        self.transaction = self.inner._submission_transaction
        self.policy = self.inner._submission_policy
        self.assertIs(self.inner._submission_policy_error, error)
        self.assertIsNotNone(self.guard)
        if quarantined:
            with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_binding_changed"):
                self.demand.seal_without_native()
        else:
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_submission_unsettled"):
                self.demand.seal_without_native()
        self.assertTrue(self.demand._native_preparation_sealed)
        self.assertIsNone(self.demand._before_native_completion)
        self._install_generation()
        self.before = _capacity_rows(self.db)
        self.runtime_before = self.runtime()

    def _pending_admission(self, *, queued=False, rollback=False):
        if queued:
            self.fixture.publish_status(commit=94)
        original = self.coordinator._commit_admission

        def interrupt(conn, transaction):
            if not rollback:
                original(conn, transaction)
            raise OSError("synthetic initial admission acknowledgement lost" if not rollback else
                          "synthetic admission rejected before COMMIT")

        with patch.object(self.coordinator, "_commit_admission", side_effect=interrupt):
            with self.assertRaisesRegex(OSError, "synthetic") as caught:
                self.coordinator.admit_experiment(self.demand)
        self._after_failure(caught.exception)
        self.assertIs(self.transaction["connection_closed"], True)
        self.assertIs(self.transaction["commit_attempted"], not rollback)
        self.assertIs(self.guard._native_exit_confirmed, True)
        self.assertIs(self.guard._native_no_entry_confirmed, False)
        return caught.exception

    def runtime(self):
        return _rows(self.db, "adaptive_runtime")[0]

    def change(self, table, column, value):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE " + table + " SET " + column + "=?", (value,))
            conn.commit()

    @contextmanager
    def _no_new_authority(self):
        with ExitStack() as stack:
            for target, method in ((self.policy, "prepare"), (self.policy, "hold"),
                    (self.policy.provider, "hold"), (self.demand, "_prepare_submission"),
                    (self.coordinator, "_admit"), (self.coordinator, "_mirror"),
                    (self.process, "close")):
                stack.enter_context(patch.object(target, method,
                    side_effect=AssertionError("settlement acquired forbidden authority: " + method)))
            yield

    def settle(self):
        with self._no_new_authority():
            return self.coordinator.settle_experiment_admission(self.demand)

    def _pin_before_read(self):
        # Interrupt the public route after it retains the actual original
        # operation, without constructing a guard or a completion in the test.
        with patch.object(cleanup.ExperimentAdmissionSettlement, "_read",
                          side_effect=OSError("synthetic pre-read interruption")):
            with self.assertRaisesRegex(OSError, "pre-read interruption"):
                self.settle()
        operation = self.demand._admission_settlement
        self.assertIs(type(operation), cleanup.ExperimentAdmissionSettlement)
        self.assertIsNone(operation._quarantine)
        return operation

    def assert_preserved(self, expected=None):
        self.assertEqual(_capacity_rows(self.db), self.before if expected is None else expected)
        self.assertIsNone(self.demand._before_native_completion)
        self.assertIsNone(self.demand._release_operation)
        self.assertFalse(self.demand._closed)
        self.assertIsNotNone(self.process._handle)
        self.assertEqual(self.backend.closed, [])

    def assert_settled(self, result, state="RESERVED", expected=None):
        self.assertIs(result["settled"], True)
        self.assertIs(result["launch_authorized"], False)
        self.assertEqual(result["state"], state)
        self.assertEqual(result["execution_id"], self.snapshot.execution_id)
        self.assertEqual(result["request_key"], self.snapshot.request.request_key)
        self.assertNotIn("allowed", result)
        self.assertNotIn("released", result)
        self.assertIsNone(self.inner._submission_guard)
        self.assertIsNone(self.inner._submission_policy_error)
        operation = self.demand._admission_settlement
        self.assertIs(operation._guard, self.guard)
        self.assertIs(operation._transaction, self.transaction)
        self.assertIs(operation._prior_error, self.original_error)
        self.assertIs(operation._process, self.process)
        self.assertEqual(operation._connections, {})
        self.assertTrue(operation._settled)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.runtime(), dict(self.runtime_before, policy_entry_nonce=None))
        self.assert_preserved(expected)

    def test_committed_ack_loss_settles_original_guard_then_real_completion_and_release(self):
        self._pending_admission()
        self.fixture.assert_retained(self.demand)
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)
        result = self.settle()
        self.assert_settled(result)
        completion = self.demand.seal_without_native()
        operation = self.demand.prepare_release(completion)
        released = self.coordinator.release_experiment(operation)
        self.assertIs(released["released"], True)
        self.assertEqual(released["disposition"], "BEFORE_NATIVE")
        self.assertEqual(_rows(self.db, "reservations"), [])
        self.assertEqual(len(_rows(self.db, history.TABLE)), 1)
        self.assertEqual(len(_rows(self.db, "executions")), 1)
        self.assertTrue(self.demand._closed)
        self.assertEqual(self.backend.closed, [700])

    def test_expiry_hold_and_draining_preserve_original_capacity_and_allow_later_release(self):
        self._pending_admission()
        later = self.before["reservations"][0]["expires_at"] + 1
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
            conn.execute("BEGIN IMMEDIATE")
            self.assertEqual(hold_expired_allocations(conn, "direct", later), 1)
            conn.commit()
        self.fixture.clock.return_value = later
        self.change("adaptive_daily_generation", "state", "DRAINING")
        held = _capacity_rows(self.db)
        self.assertEqual(held["reservations"], self.before["reservations"])
        self.assertEqual(held["managed_executions"][0]["state"], "UNCERTAIN_HOLD")
        self.runtime_before = self.runtime()
        self.assert_settled(self.settle(), "UNCERTAIN_HOLD", held)
        completion = self.demand.seal_without_native()
        released = self.coordinator.release_experiment(self.demand.prepare_release(completion))
        self.assertTrue(released["released"])
        record = json.loads(_rows(self.db, history.TABLE)[0]["receipt_json"])
        self.assertEqual(record["preimage"]["managed"], history.managed_image(held["managed_executions"][0]))
        self.assertEqual(record["preimage"]["allocation"], self.before["reservations"][0])
        self.assertEqual(_rows(self.db, "adaptive_daily_generation")[0]["state"], "DRAINING")

    def test_original_nonce_clear_ack_loss_reconciles_without_another_clear(self):
        connect, lost = sqlite3.connect, []

        class LostClearAck(sqlite3.Connection):
            clear = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clear = self.clear or _clearing(sql)
                return result

            def commit(self):
                super().commit()
                if self.clear and not lost:
                    lost.append(self)
                    raise OSError("synthetic original clear acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostClearAck)):
            with self.assertRaisesRegex(OSError, "original clear acknowledgement") as caught:
                self.coordinator.admit_experiment(self.demand)
        self.assertEqual(len(lost), 1)
        self._after_failure(caught.exception)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertTrue(self.guard._nonce_clear_attempted)
        self.assertFalse(self.guard._nonce_clear_confirmed)
        with patch.object(self.policy, "_clear", side_effect=AssertionError("cleared an already cleared nonce")):
            self.assert_settled(self.settle())

    def test_settlement_clear_ack_loss_replays_only_original_clear_attempt(self):
        self._pending_admission()
        connect, lost = sqlite3.connect, []

        class LostClearAck(sqlite3.Connection):
            clear = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clear = self.clear or _clearing(sql)
                return result

            def commit(self):
                super().commit()
                if self.clear and not lost:
                    lost.append(self)
                    raise OSError("synthetic settlement clear acknowledgement lost")

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostClearAck)):
            with self.assertRaisesRegex(OSError, "settlement clear acknowledgement"):
                self.settle()
        operation = self.demand._admission_settlement
        self.assertEqual(len(lost), 1)
        self.assertEqual(operation._connections, {})
        self.assertIsNone(operation._quarantine)
        self.assertIs(self.inner._submission_guard, self.guard)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assert_preserved()
        with patch.object(self.policy, "_clear", side_effect=AssertionError("repeated original clear")):
            self.assert_settled(self.settle())
        self.assertIs(self.demand._admission_settlement, operation)

    def test_unknown_settlement_read_close_quarantines_original_connection_without_reopen(self):
        self._pending_admission()
        connect, opened = sqlite3.connect, []

        class UnknownClose(sqlite3.Connection):
            def close(self):
                raise OSError("synthetic settlement read close unknown")

        def open_unknown(*args, **kwargs):
            conn = connect(*args, **kwargs, factory=UnknownClose)
            opened.append(conn)
            return conn

        try:
            with patch.object(sqlite3, "connect", side_effect=open_unknown):
                with self.assertRaisesRegex(Exception, "lifecycle_connection_cleanup_failed"):
                    self.settle()
            operation = self.demand._admission_settlement
            self.assertEqual(len(opened), 1)
            self.assertIs(operation._connections[id(opened[0])][0], opened[0])
            quarantine = operation._quarantine
            self.assertIsNotNone(quarantine)
            with patch.object(sqlite3, "connect", side_effect=AssertionError("reopened uncertain read")):
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    self.settle()
            self.assertIs(operation._quarantine, quarantine)
            self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)
            self.assert_preserved()
        finally:
            for conn in opened:
                sqlite3.Connection.close(conn)  # Fixture disposal, never production cleanup evidence.

    def test_unknown_settlement_clear_close_refuses_even_when_nonce_is_null(self):
        self._pending_admission()
        connect, uncertain = sqlite3.connect, []

        class UnknownClearClose(sqlite3.Connection):
            clear = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clear = self.clear or _clearing(sql)
                return result

            def close(self):
                if self.clear:
                    uncertain.append(self)
                    raise OSError("synthetic settlement clear close unknown")
                super().close()

        try:
            with patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=UnknownClearClose)):
                with self.assertRaisesRegex(Exception, "lifecycle_connection_cleanup_failed"):
                    self.settle()
            self.assertEqual(len(uncertain), 1)
            operation = self.demand._admission_settlement
            self.assertIsNotNone(operation._quarantine)
            self.assertIs(operation._connections[id(uncertain[0])][0], uncertain[0])
            self.assertIsNone(self.runtime()["policy_entry_nonce"])
            with patch.object(sqlite3, "connect", side_effect=AssertionError("reopened uncertain clear")):
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    self.settle()
            self.assertIs(self.inner._submission_guard, self.guard)
            self.assert_preserved()
        finally:
            for conn in uncertain:
                sqlite3.Connection.close(conn)  # Isolated fixture disposal only.

    def test_original_timeout_clear_unknown_close_keeps_nested_owner_and_forbids_replacement(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.snapshot.wrapper_identity
        backend.wait_error = windows.NativePolicyMutexError("policy_mutex_timeout")
        native, connect, uncertain = NativePolicyProvider(), sqlite3.connect, []

        class UnknownClearClose(sqlite3.Connection):
            clear = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clear = self.clear or _clearing(sql)
                return result

            def close(self):
                if self.clear:
                    uncertain.append(self)
                    raise OSError("synthetic original timeout clear close unknown")
                super().close()

        try:
            with patch.object(windows, "_backend", return_value=backend), \
                    patch.object(windows.VerifiedProcess, "current", return_value=process), \
                    patch.object(self.fixture.fixture.policy, "hold", side_effect=native.hold), \
                    patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=UnknownClearClose)):
                with self.assertRaisesRegex(windows.NativePolicyMutexError, "policy_mutex_timeout") as caught:
                    self.coordinator.admit_experiment(self.demand)
            self.assertEqual(len(uncertain), 1)
            nested = caught.exception._policy_entry_cleanup_error
            self.assertIs(nested._sentinel_connection_cleanup, uncertain[0])
            self.assertIn("policy_entry_cleanup_failed", caught.exception.__notes__)
            self.assertIn("policy_entry_cleanup_unverified", caught.exception.__notes__)
            self.assertIsNotNone(self.demand._quarantine)
            original_quarantine = self.demand._quarantine
            self._after_failure(caught.exception, quarantined=True)
            calls = list(backend.calls)
            with patch.object(sqlite3, "connect", side_effect=AssertionError("discarded original unknown close")):
                with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_binding_changed"):
                    self.settle()
                # The original demand is already quarantined: refuse before
                # even constructing another cleanup operation or opening SQL.
                self.assertIsNone(self.demand._admission_settlement)
                self.assertIs(self.inner._submission_policy_error, caught.exception)
                self.assertIs(self.inner._submission_policy_error._policy_entry_cleanup_error, nested)
                with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_binding_changed"):
                    self.settle()
            self.assertIs(self.demand._quarantine, original_quarantine)
            self.assertEqual(backend.calls, calls)
            self.assert_preserved()
        finally:
            for conn in uncertain:
                sqlite3.Connection.close(conn)  # Do not mark the retained production owner settled.

    def test_replacing_original_guard_after_binding_is_refused_before_sql(self):
        self._pending_admission()
        operation = self._pin_before_read()
        self.inner._submission_guard = copy(self.guard)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("replacement guard opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_submission_changed"):
                self.settle()
        self.assertIs(operation._guard, self.guard)
        self.assert_preserved()

    def test_replacement_or_mutation_of_exact_original_transaction_is_refused(self):
        self._pending_admission()
        self._pin_before_read()
        self.inner._submission_transaction = dict(self.transaction)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("replacement transaction opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_transaction_changed"):
                self.settle()
        self.inner._submission_transaction = self.transaction
        original = self.transaction["commit_attempted"]
        self.transaction["commit_attempted"] = not original
        with patch.object(sqlite3, "connect", side_effect=AssertionError("mutated transaction opened SQL")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_transaction_changed"):
                self.settle()
        self.assert_preserved()

    def test_different_coordinator_or_ledger_cannot_settle_original(self):
        self._pending_admission()
        self._pin_before_read()
        foreign = Coordinator.__new__(Coordinator)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("wrong coordinator opened SQL")):
            for db, reason in ((self.db.with_name("foreign.db"), "actual_daily_coordinator_required"),
                               (self.db, "original_settlement_changed")):
                foreign.db_path = db
                with self.subTest(ledger=str(db)), self.assertRaisesRegex(cleanup.ExperimentReleaseError, reason):
                    foreign.settle_experiment_admission(self.demand)
        self.assert_preserved()

    def test_original_settlement_cannot_move_to_another_thread(self):
        self._pending_admission()
        self._pin_before_read()
        errors = []

        def attempt():
            try:
                self.coordinator.settle_experiment_admission(self.demand)
            except BaseException as error:
                errors.append(error)

        with patch.object(sqlite3, "connect", side_effect=AssertionError("other thread opened SQL")):
            thread = threading.Thread(target=attempt)
            thread.start()
            thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], cleanup.ExperimentReleaseError)
        self.assertIn("original_settlement_changed", str(errors[0]))
        self.assert_preserved()

    def test_changed_generation_identity_refuses_and_never_clears_original_nonce(self):
        self._pending_admission()
        for column, value in (("generation", str(uuid4())), ("readiness_instance_id", str(uuid4())),
                ("owner_identity_json", json.dumps(dict(self.snapshot.wrapper_identity.to_dict(), pid=99)))):
            with self.subTest(column=column):
                self.change("adaptive_daily_generation", column, value)
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "generation_changed"):
                    self.settle()
                self.change("adaptive_daily_generation", column, self.fixture.generation[column])
                self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)
                self.assert_preserved()

    def test_null_nonce_without_original_clear_attempt_does_not_prove_cleanup(self):
        self._pending_admission()
        self.assertFalse(self.guard._nonce_clear_attempted)
        self.change("adaptive_runtime", "policy_entry_nonce", None)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_nonce_unsettled"):
            self.settle()
        self.assertIs(self.inner._submission_guard, self.guard)
        self.assertFalse(self.demand._admission_settlement._settled)
        self.assert_preserved()

    def test_changed_original_ipc_key_refuses_without_releasing_capacity(self):
        self._pending_admission()
        changed = bytes(value ^ 0xff for value in self.snapshot.ipc_auth_key)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            guard_sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='experiment_execution_update_guard'").fetchone()[0]
            conn.execute("DROP TRIGGER experiment_execution_update_guard")
            conn.execute("UPDATE managed_executions SET ipc_auth_key=? WHERE execution_id=?",
                         (changed, self.snapshot.execution_id))
            conn.execute(guard_sql)
            conn.commit()
            self.assertEqual(conn.execute("SELECT sql FROM sqlite_master WHERE name='experiment_execution_update_guard'").fetchone()[0], guard_sql)
        corrupted = _capacity_rows(self.db)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "admission_credential_changed"):
            self.settle()
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)
        self.assertEqual(self.snapshot.ipc_auth_key, self.inner._snapshot.ipc_auth_key)
        self.assert_preserved(corrupted)

    def test_missing_or_changed_original_native_facts_cannot_authorize_nonce_clear(self):
        self._pending_admission()
        self._pin_before_read()
        for facts in ((False, False), (True, True), (1, False), (False, True)):
            with self.subTest(facts=facts):
                self.guard._native_exit_confirmed, self.guard._native_no_entry_confirmed = facts
                with patch.object(sqlite3, "connect", side_effect=AssertionError("invalid native facts opened SQL")):
                    with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_native_cleanup_unverified"):
                        self.settle()
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.guard.nonce)
        self.assert_preserved()

    def test_copies_dictionaries_and_direct_constructor_are_not_original_authority(self):
        self._pending_admission()
        operation = self._pin_before_read()
        with patch.object(sqlite3, "connect", side_effect=AssertionError("non-original owner opened SQL")):
            for value in (object(), {"experiment_id": self.demand.declaration.experiment_id}, copy(self.demand)):
                with self.subTest(kind=type(value).__name__), self.assertRaises(
                        (cleanup.ExperimentReleaseError, demand_module.ExperimentDemandError)):
                    self.coordinator.settle_experiment_admission(value)
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_demand_required"):
                cleanup.ExperimentAdmissionSettlement(self.coordinator, self.demand)
            copied = copy(operation)
            self.demand._admission_settlement = copied
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_settlement_changed"):
                self.coordinator.settle_experiment_admission(self.demand)
        self.demand._admission_settlement = operation
        self.assert_preserved()

    def test_successful_replay_is_read_only_without_new_guard_or_clear(self):
        self._pending_admission()
        first = self.settle()
        operation = self.demand._admission_settlement
        connect, writes, opened, closed = sqlite3.connect, [], [], []

        class ReadOnlyReplay(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE ", "REPLACE ")):
                    writes.append(sql)
                    raise AssertionError("settled replay attempted persistent write")
                return super().execute(sql, parameters)

            def close(self):
                super().close()
                closed.append(self)

        def connect_read(*args, **kwargs):
            conn = connect(*args, **kwargs, factory=ReadOnlyReplay)
            opened.append(conn)
            return conn

        with patch.object(sqlite3, "connect", side_effect=connect_read), \
                patch.object(self.policy, "_clear", side_effect=AssertionError("replay cleared a nonce")):
            second = self.settle()
        self.assertEqual(second, first)
        self.assertEqual(writes, [])
        self.assertTrue(opened)
        self.assertEqual(opened, closed)
        self.assertIs(self.demand._admission_settlement, operation)
        self.assert_settled(second)

    def _interrupt_local_settlement(self, exception_type):
        self._pending_admission()
        original_setattr = type(self.inner).__setattr__
        interrupted, inner = [], self.inner
        interruption = exception_type("synthetic local settlement interruption")

        def interrupt(instance, name, value):
            original_setattr(instance, name, value)
            if instance is inner and name == "_submission_guard" and value is None and not interrupted:
                interrupted.append(True)
                raise interruption

        with patch.object(type(inner), "__setattr__", new=interrupt):
            with self.assertRaises(exception_type) as caught:
                self.settle()
        self.assertIs(caught.exception, interruption)
        self.assertEqual(interrupted, [True])
        operation = self.demand._admission_settlement
        self.assertIs(operation._guard, self.guard)
        self.assertIsNone(inner._submission_guard)
        self.assertIs(inner._submission_policy_error, self.original_error)
        self.assertTrue(operation._cleared)
        self.assertFalse(operation._settled)
        self.assertIsNone(operation._quarantine)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assert_preserved()
        connect, writes = sqlite3.connect, []

        class ReadOnlyAfterInterruption(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.lstrip().upper().startswith(("INSERT ", "UPDATE ", "DELETE ", "REPLACE ")):
                    writes.append(sql)
                    raise AssertionError("local retry attempted a persistent write")
                return super().execute(sql, parameters)

        with patch.object(sqlite3, "connect", side_effect=lambda *a, **k:
                          connect(*a, **k, factory=ReadOnlyAfterInterruption)), \
                patch.object(self.policy, "_clear", side_effect=AssertionError("local retry cleared again")):
            result = self.settle()
        self.assertEqual(writes, [])
        self.assertIs(self.demand._admission_settlement, operation)
        self.assert_settled(result)

    def test_keyboard_interrupt_after_pending_guard_clear_replays_only_read_and_local_finish(self):
        self._interrupt_local_settlement(KeyboardInterrupt)

    def test_system_exit_after_pending_guard_clear_replays_only_read_and_local_finish(self):
        self._interrupt_local_settlement(SystemExit)

    def test_queued_ack_loss_settles_without_adopting_capacity_or_cancelling_queue(self):
        self._pending_admission(queued=True)
        self.assertIsNone(self.demand._policy_original)
        self.assertEqual(len(self.before["queue"]), 1)
        self.assertEqual(self.before["reservations"], [])
        self.assert_settled(self.settle(), "QUEUED")
        self.assertEqual(self.inner._submission_transaction, self.transaction)
        self.assertIsNone(self.demand._policy_original)
        self.assertEqual(_rows(self.db, "queue"), self.before["queue"])

    def test_positive_first_rollback_is_rejected_state_without_readmission(self):
        self._pending_admission(rollback=True)
        self.assertTrue(self.transaction["rolled_back"])
        self.assertTrue(self.transaction["first_submission"])
        self.assertTrue(self.guard._nonce_clear_attempted)
        self.assertEqual(self.before["reservations"], [])
        with patch.object(self.policy, "_clear", side_effect=AssertionError("already positively cleared")):
            self.assert_settled(self.settle(), "SUBMISSION_REJECTED")

    def test_original_clean_timeout_clear_ack_loss_is_never_submitted(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.snapshot.wrapper_identity
        backend.wait_error = windows.NativePolicyMutexError("policy_mutex_timeout")
        native, connect, lost = NativePolicyProvider(), sqlite3.connect, []

        class LostTimeoutClearAck(sqlite3.Connection):
            clear = False

            def execute(self, sql, parameters=()):
                result = super().execute(sql, parameters)
                self.clear = self.clear or _clearing(sql)
                return result

            def commit(self):
                super().commit()
                if self.clear and not lost:
                    lost.append(self)
                    raise OSError("synthetic timeout clear acknowledgement lost")

        with patch.object(windows, "_backend", return_value=backend), \
                patch.object(windows.VerifiedProcess, "current", return_value=process), \
                patch.object(self.fixture.fixture.policy, "hold", side_effect=native.hold), \
                patch.object(sqlite3, "connect", side_effect=lambda *a, **k: connect(*a, **k, factory=LostTimeoutClearAck)):
            with self.assertRaisesRegex(windows.NativePolicyMutexError, "policy_mutex_timeout") as caught:
                self.coordinator.admit_experiment(self.demand)
        self.assertEqual(len(lost), 1)
        self._after_failure(caught.exception)
        self.assertIsNone(self.transaction)
        self.assertFalse(self.inner._submitted)
        self.assertIsNone(self.demand._policy_original)
        self.assertFalse(self.guard._native_exit_confirmed)
        self.assertTrue(self.guard._native_no_entry_confirmed)
        self.assertTrue(self.guard._nonce_clear_attempted)
        calls = list(backend.calls)
        with patch.object(self.policy, "_clear", side_effect=AssertionError("repeated timeout clear")):
            self.assert_settled(self.settle(), "NEVER_SUBMITTED")
        self.assertEqual(backend.calls, calls)


if __name__ == "__main__":
    unittest.main()
