"""Original cleanup operation with real isolated SQL and synthetic identity.

No native gate/control is exercised. Only source/location attestation uses the
existing synthetic demand fixture; generation/SQL/POLICY/custody code is real.
"""
from contextlib import closing
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive.policy import PolicyBusy, PolicyGuard
from sentinel.adaptive.policy import NativePolicyProvider
from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive import windows
from tests.test_adaptive_policy_mutex import FixtureBackend, FixtureProcess
from tests import test_adaptive_experiment_demand as demand_tests


class ExperimentReleaseCustodyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = demand_tests.ExperimentDemandTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.demand = self.fixture.capture()
        self.result = self.fixture.coordinator.admit_experiment(self.demand)
        self.assertTrue(self.result["allowed"])
        self.completion = self.demand.seal_without_native()
        self.operation = self.demand.prepare_release(self.completion)
        self.addCleanup(lambda: cleanup._OPERATIONS.pop(self.operation.operation_id, None))
        self.store, self.policy = self.operation.store, self.operation.policy
        self.db = self.demand.ledger_path
        # Install a complete, syntactically valid original generation in this
        # test ledger. This is not production source/native activation.
        with closing(sqlite3.connect(self.db)) as conn:
            row = self.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for change in (
                patch.object(generation, "_assert_daily_locations"),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "_prove_retained_owner_ready",
                             side_effect=AssertionError("cleanup attempted fresh readiness RPC"))):
            change.start()
            self.addCleanup(change.stop)

    def change(self, table, column, value):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE " + table + " SET " + column + "=?", (value,))
            conn.commit()

    def runtime(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())

    def test_original_operation_is_replayed_and_copies_are_rejected(self):
        self.assertIs(self.demand.prepare_release(self.completion), self.operation)
        copied = object.__new__(type(self.completion))
        object.__setattr__(copied, "owner", self.demand)
        object.__setattr__(copied, "digest", self.completion.digest)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "completion_changed"):
            self.demand.prepare_release(copied)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_operation_required"):
            cleanup.ExperimentReleaseOperation(self.demand, self.completion)
        self.assertTrue(self.demand._native_preparation_sealed)
        self.assertTrue(self.demand._admission._cancel_sealed)

    def test_read_scope_does_not_request_fresh_readiness_or_capacity_function(self):
        for state in ("ACTIVE", "DRAINING"):
            self.change("adaptive_daily_generation", "state", state)
            with self.subTest(state=state), self.operation._scope("READ"):
                with self.store._transaction() as conn:
                    self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
                    with self.assertRaises(sqlite3.OperationalError):
                        conn.execute("SELECT sentinel_daily_generation()")
                    for sql in ("DELETE FROM reservations", "DELETE FROM queue",
                                "UPDATE adaptive_runtime SET mode='canary'",
                                "CREATE TABLE unauthorized(x)"):
                        with self.assertRaises(sqlite3.DatabaseError):
                            conn.execute(sql)
            self.assertEqual(self.operation._connections, {})
        self.assertIsNone(cleanup.current_operation())
        self.fixture.assert_retained(self.demand)

    def test_exact_nonce_uses_original_binding_and_normal_positive_native_exit(self):
        before = self.runtime()
        for state in ("ACTIVE", "DRAINING"):
            self.change("adaptive_daily_generation", "state", state)
            with self.subTest(state=state), self.operation._scope("HOLD"):
                guard = self.policy.prepare(self.demand._snapshot.logon_id)
                self.assertIs(guard, self.operation._guard)
                self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
                with self.policy.hold(guard):
                    with self.store._transaction() as conn:
                        self.policy.revalidate(conn, guard)
                        with self.assertRaises(sqlite3.DatabaseError):
                            conn.execute("DELETE FROM reservations")
            after = self.runtime()
            self.assertIsNone(after["policy_entry_nonce"])
            self.assertEqual(after["policy_instance_id"], before["policy_instance_id"])
            self.assertEqual(after["registry_revision"], before["registry_revision"])
            self.assertEqual(self.operation._connections, {})
        self.fixture.assert_retained(self.demand)

    def test_changed_generation_endpoint_and_owner_refuse_without_new_authority(self):
        for column, value in (("readiness_instance_id", str(uuid4())),
                              ("owner_identity_json", json.dumps(dict(
                                  self.demand._snapshot.wrapper_identity.to_dict(), pid=99)))):
            original = self.fixture.generation[column]
            self.change("adaptive_daily_generation", column, value)
            with self.subTest(column=column):
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "generation_changed"):
                    with self.operation._scope("READ"), self.store._transaction():
                        pass
            self.change("adaptive_daily_generation", column, original)
            self.assertEqual(self.operation._connections, {})

    def test_missing_policy_binding_is_never_reinitialized(self):
        self.change("adaptive_runtime", "policy_binding_initialized", 0)
        self.change("adaptive_runtime", "policy_instance_id", None)
        self.change("adaptive_runtime", "policy_logon_id", None)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "policy_binding_changed"):
            self.operation.prepare_policy(self.policy, self.demand._snapshot.logon_id)
        self.assertEqual(self.runtime()["policy_binding_initialized"], 0)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_foreign_nonce_cannot_be_adopted_or_cleared(self):
        foreign = str(uuid4())
        self.change("adaptive_runtime", "policy_entry_nonce", foreign)
        with self.assertRaises(PolicyBusy):
            self.operation.prepare_policy(self.policy, self.demand._snapshot.logon_id)
        self.assertNotEqual(self.operation._guard.nonce, foreign)
        self.assertEqual(self.runtime()["policy_entry_nonce"], foreign)
        forged = PolicyGuard(self.operation._policy_binding, foreign)
        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "nonce_cleanup_not_owned"):
            with self.operation.nonce_cleanup(self.policy, forged):
                pass
        self.assertEqual(self.runtime()["policy_entry_nonce"], foreign)

    def test_commit_ack_loss_retains_same_original_candidate_and_can_reconcile(self):
        real_connect = sqlite3.connect
        failed = []
        class LostAck(sqlite3.Connection):
            def commit(self):
                super().commit()
                if not failed:
                    failed.append(self)
                    raise sqlite3.OperationalError("synthetic commit reply lost")
        def connect(*args, **kwargs):
            return real_connect(*args, **kwargs, factory=LostAck)
        with patch.object(sqlite3, "connect", side_effect=connect):
            with self.assertRaisesRegex(sqlite3.OperationalError, "synthetic commit reply lost"):
                self.operation.prepare_policy(self.policy, self.demand._snapshot.logon_id)
        original = self.operation._guard
        self.assertEqual(self.runtime()["policy_entry_nonce"], original.nonce)
        self.assertIsNone(self.operation._quarantine)
        self.assertIs(self.operation.prepare_policy(self.policy, self.demand._snapshot.logon_id), original)
        with self.operation._scope("HOLD"), self.policy.hold(original):
            pass
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_unknown_close_retains_original_connection_and_refuses_reopen(self):
        real_connect = sqlite3.connect
        opened = []
        class UnknownClose(sqlite3.Connection):
            def close(self):
                raise OSError("synthetic unknown close")
        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs, factory=UnknownClose)
            opened.append(connection)
            return connection
        try:
            with patch.object(sqlite3, "connect", side_effect=connect):
                with self.assertRaisesRegex(Exception, "lifecycle_connection_cleanup_failed"):
                    with self.operation._scope("READ"), self.store._transaction():
                        pass
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    with self.operation._scope("READ"), self.store._transaction():
                        pass
            self.assertEqual(len(opened), 1)
            self.assertIs(self.operation._connections[id(opened[0])][0], opened[0])
        finally:
            for connection in opened:
                sqlite3.Connection.close(connection)  # Known synthetic fixture cleanup only.

    def test_operation_cannot_move_to_another_thread(self):
        errors = []
        def read():
            try:
                with self.operation._scope("READ"):
                    pass
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=read)
        thread.start()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertRegex(str(errors[0]), "original_operation_changed")
        self.assertIsNone(self.operation._quarantine)

    def test_actual_mutex_unknown_wait_retains_failure_and_never_reacquires(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.demand._snapshot.wrapper_identity
        backend.wait_result = None
        self.operation.prepare_policy(self.policy, process.identity.logon_id)
        native = NativePolicyProvider()
        try:
            with patch.object(windows, "_backend", return_value=backend), \
                    patch.object(windows.VerifiedProcess, "current", return_value=process), \
                    patch.object(self.policy.provider, "hold", side_effect=native.hold):
                with self.assertRaisesRegex(windows.NativePolicyMutexError, "wait_outcome_unknown") as caught:
                    with self.operation.hold_policy():
                        self.fail("unknown native wait yielded ownership")
                self.assertIs(self.operation._quarantine, caught.exception)
                self.assertTrue(any("wait_outcome_unknown" in note for note in caught.exception.__notes__))
                before = list(backend.calls)
                with patch.object(sqlite3, "connect", side_effect=AssertionError("reopened after unknown wait")):
                    with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                        self.operation.prepare_policy(self.policy, process.identity.logon_id)
                    with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                        with self.operation.hold_policy():
                            pass
                self.assertEqual(backend.calls, before)
                self.assertIs(self.operation._error, caught.exception)
        finally:
            # Remove only this purely synthetic mutex's in-process test marker.
            with windows._THREAD_NAMES_LOCK:
                windows._THREAD_NAMES.discard((threading.current_thread(), self.operation._guard.binding.name))

    def test_actual_constructor_unknown_close_keeps_original_native_owner(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.demand._snapshot.wrapper_identity
        process.close_error = IdentityUnavailable("fixture_self_close_unknown")
        backend.close_error = windows.NativePolicyMutexError("policy_mutex_handle_close_failed", 6)
        self.operation.prepare_policy(self.policy, process.identity.logon_id)
        native = NativePolicyProvider()
        with patch.object(windows, "_backend", return_value=backend), \
                patch.object(windows.VerifiedProcess, "current", return_value=process), \
                patch.object(self.policy.provider, "hold", side_effect=native.hold):
            with self.assertRaises(windows.NativePolicyMutexError) as caught:
                with self.operation.hold_policy():
                    self.fail("failed constructor yielded")
            self.assertIs(self.operation._quarantine, caught.exception)
            self.assertEqual(len(caught.exception._policy_mutex_cleanup), 1)
            original_owner = caught.exception._policy_mutex_cleanup[0]
            self.assertIsNotNone(original_owner._handle)
            before = list(backend.calls)
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                self.operation.prepare_policy(self.policy, process.identity.logon_id)
            self.assertEqual(before, backend.calls)
            self.assertIs(self.operation._quarantine._policy_mutex_cleanup[0], original_owner)

    def test_nested_retained_owner_is_not_replaced_by_later_failure(self):
        original_owner = object()
        cause = RuntimeError("synthetic original handle cleanup")
        cause._identity_handle_cleanup = (original_owner,)
        outer = RuntimeError("sanitized outer failure")
        outer.__cause__ = cause
        self.operation._retain(outer)
        self.operation._retain(RuntimeError("later unrelated failure"))
        self.assertIs(self.operation._quarantine, outer)
        self.assertIs(self.operation._error, outer)
        self.assertIs(self.operation._quarantine.__cause__._identity_handle_cleanup[0], original_owner)

    def test_timeout_clear_unknown_close_preserves_first_cleanup_owner(self):
        backend, process = FixtureBackend(), FixtureProcess()
        process.identity = self.demand._snapshot.wrapper_identity
        backend.wait_error = windows.NativePolicyMutexError("policy_mutex_timeout")
        self.operation.prepare_policy(self.policy, process.identity.logon_id)
        native, real_connect, opened = NativePolicyProvider(), sqlite3.connect, []
        class UnknownClose(sqlite3.Connection):
            def close(self):
                raise OSError("synthetic timeout clear close unknown")
        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs, factory=UnknownClose)
            opened.append(connection)
            return connection
        try:
            with patch.object(windows, "_backend", return_value=backend), \
                    patch.object(windows.VerifiedProcess, "current", return_value=process), \
                    patch.object(self.policy.provider, "hold", side_effect=native.hold), \
                    patch.object(sqlite3, "connect", side_effect=connect):
                with self.assertRaisesRegex(windows.NativePolicyMutexError, "policy_mutex_timeout") as caught:
                    with self.operation.hold_policy():
                        self.fail("timed out native wait yielded")
                self.assertEqual(len(opened), 1)
                self.assertIsNot(self.operation._quarantine, caught.exception)
                self.assertIs(self.operation._error, self.operation._quarantine)
                self.assertIs(self.operation._quarantine._sentinel_connection_cleanup, opened[0])
                self.assertIn("policy_entry_cleanup_failed", caught.exception.__notes__)
                with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "cleanup_unverified"):
                    self.operation.prepare_policy(self.policy, process.identity.logon_id)
                self.assertEqual(len(opened), 1)
        finally:
            for connection in opened:
                sqlite3.Connection.close(connection)  # Known synthetic fixture cleanup only.


if __name__ == "__main__":
    unittest.main()
