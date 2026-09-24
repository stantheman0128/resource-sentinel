"""L1 evidence lifetime tests using real isolated SQLite transactions.

These explicit scopes model held authority, not native handles or Windows gates.
"""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
import traceback
import unittest
from unittest.mock import patch

from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_lifecycle as fixtures
from tests.test_adaptive_prelaunch import PrelaunchVerifier


class ObservedProvider:
    """Track fixture acquisition/release and verify SQLite is unlocked there."""
    def __init__(self, test):
        self.test = test
        self.verifier = PrelaunchVerifier()
        self.active = None
        self.events = []
        self.enter_error = None
        self.cleanup_error = None
        self.suppress = False
        self.on_verified = None
        self.modify_evidence = None
        self.exits = []

    def assert_unlocked(self):
        conn = sqlite3.connect(self.test.db, timeout=0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        finally:
            conn.close()

    def __call__(self, operation, row, caller):
        provider = self

        class Scope:
            def __enter__(self):
                provider.assert_unlocked()
                provider.test.assertIsNone(provider.active)
                provider.active = operation
                provider.events.append((operation, "enter"))
                try:
                    if provider.enter_error is not None:
                        raise provider.enter_error
                    proof = provider.verifier(operation, row, caller)
                    if provider.modify_evidence is not None:
                        proof = provider.modify_evidence(proof)
                    if provider.on_verified is not None:
                        provider.on_verified(row)
                    provider.events.append((operation, "verified"))
                    return proof
                except BaseException:
                    # A provider owns cleanup for failed partial acquisition;
                    # __exit__ is not called if __enter__ does not complete.
                    provider.events.append((operation, "enter_unwind"))
                    provider.active = None
                    raise

            def __exit__(self, kind, error, tb):
                provider.test.assertEqual(provider.active, operation)
                provider.assert_unlocked()
                provider.exits.append((kind, error))
                provider.events.append((operation, "exit"))
                provider.active = None
                if provider.cleanup_error is not None:
                    raise provider.cleanup_error
                return provider.suppress

        return Scope()


class EvidenceTransactionConnection(sqlite3.Connection):
    """Recognize only policy-bookkeeping writes outside native evidence.

    SQLite's authorizer reports actual write targets, so mentioning a policy
    column cannot hide an allocation, lifecycle, or recovery-barrier mutation.
    Each store connection owns one transaction; statement caching therefore
    cannot hide a write reused from an earlier transaction on this connection.
    """
    policy_columns = {"policy_instance_id", "policy_logon_id", "policy_entry_nonce", "policy_binding_initialized"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.write_targets = set()
        self.set_authorizer(self.observe_statement)

    def observe_statement(self, action, table, column, database, trigger):
        if action in {sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_DELETE}:
            self.write_targets.add((action, table, column))
        return sqlite3.SQLITE_OK

    def transaction_operation(self):
        test = self.observed_test
        policy_only = bool(self.write_targets) and all(
            action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and
            column in self.policy_columns
            for action, table, column in self.write_targets)
        if test.provider.active is None and policy_only:
            return "policy_metadata"
        test.assertIsNotNone(test.provider.active,
                             "non-policy transaction requires live lifecycle evidence")
        return test.provider.active

    def record(self, operation, event):
        test = self.observed_test
        events = test.policy_events if operation == "policy_metadata" else test.provider.events
        events.append((operation, event))


class AdaptiveEvidenceScopeTests(unittest.TestCase):
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.provider = ObservedProvider(self)
        self.store.evidence_provider = self.provider
        self.policy_events = []
        self.commit_error = None
        self.original_connection = self.store._connection
        test = self

        class ObservedConnection(EvidenceTransactionConnection):
            observed_test = test

            def commit(self):
                operation = self.transaction_operation()
                test.assertTrue(self.in_transaction)
                self.record(operation, "commit_enter")
                if operation != "policy_metadata" and test.commit_error is not None:
                    raise test.commit_error
                super().commit()
                test.assertEqual(test.provider.active,
                                 None if operation == "policy_metadata" else operation)
                test.assertFalse(self.in_transaction)
                self.record(operation, "committed")

            def rollback(self):
                operation = self.transaction_operation()
                self.record(operation, "rollback_enter")
                super().rollback()
                test.assertEqual(test.provider.active,
                                 None if operation == "policy_metadata" else operation)
                test.assertFalse(self.in_transaction)
                self.record(operation, "rolled_back")

        @contextmanager
        def observed_connection():
            conn = sqlite3.connect(self.db, timeout=0, isolation_level=None,
                                   factory=ObservedConnection)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            try:
                yield conn
            finally:
                conn.close()

        self.store._connection = observed_connection

    @contextmanager
    def connection_failures(self, *, rollback_error=None, close_error=None, setup_error=None):
        """Exercise production connection ownership, not a replacement cleanup."""
        test = self
        connect = sqlite3.connect
        previous = self.store._connection
        self.store._connection = self.original_connection

        class FailingConnection(EvidenceTransactionConnection):
            observed_test = test
            cleanup_failure_armed = False

            def execute(self, sql, *args):
                if sql == "PRAGMA foreign_keys=ON" and setup_error is not None:
                    self.cleanup_failure_armed = True
                    raise setup_error
                return super().execute(sql, *args)

            def commit(self):
                operation = self.transaction_operation()
                # Metadata commits precede evidence acquisition; preserve the
                # test's injected failure for the lifecycle transaction itself.
                self.cleanup_failure_armed = operation != "policy_metadata"
                result = super().commit()
                self.record(operation, "committed")
                return result

            def rollback(self):
                operation = self.transaction_operation()
                self.cleanup_failure_armed = operation != "policy_metadata"
                if operation != "policy_metadata" and rollback_error is not None:
                    self.record(operation, "rollback_failed")
                    raise rollback_error
                return super().rollback()

            def close(self):
                armed = self.cleanup_failure_armed
                super().close()
                if armed and close_error is not None:
                    test.provider.events.append((test.provider.active, "close_failed"))
                    raise close_error

        def instrumented_connect(*args, **kwargs):
            # Only LifecycleStore's own connection uses this timeout. The
            # independent writer probe and fixture assertions use other values.
            if kwargs.get("timeout") == 5:
                kwargs["factory"] = FailingConnection
            return connect(*args, **kwargs)

        try:
            with patch("sentinel.adaptive.store.sqlite3.connect", side_effect=instrumented_connect):
                yield
        finally:
            self.store._connection = previous

    def claim(self):
        spec, registered = self.registered()
        prepared = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        args = dict(caller=fixtures.WRAPPER, claim_token=registered["claim_token"],
                    spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian",
                    expected_revision=prepared["state_revision"])
        return spec, args

    def allocation_count(self, spec):
        return self.connection().execute("SELECT count(*) FROM reservations WHERE id=?",
                                         (spec.reservation.id,)).fetchone()[0]

    def test_all_eight_mutations_hold_verified_scope_through_actual_commit(self):
        spec, running = self.running()
        drained = self.store.mark_root_exited(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=running["state_revision"], exit_code=7)
        done = self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
            expected_revision=drained["state_revision"], now=fixtures.NOW + 1)
        self.assertEqual(done["state"], "FINISHED")
        cancelled, _ = self.registered()
        self.store.cancel_before_start(cancelled.execution_id, caller=fixtures.WRAPPER,
                                      expected_revision=0, now=fixtures.NOW + 1)
        failed, _ = self.registered()
        self.store.mark_start_failed(failed.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=0, now=fixtures.NOW + 1)
        operations = {operation for operation, _ in self.provider.events}
        self.assertEqual(operations, {"register", "prepare", "claim", "bind_root",
                                      "root_exited", "finalize", "cancel", "start_failed"})
        for offset in range(0, len(self.provider.events), 5):
            events = self.provider.events[offset:offset + 5]
            self.assertEqual([event for _, event in events],
                             ["enter", "verified", "commit_enter", "committed", "exit"])
            self.assertEqual(len({operation for operation, _ in events}), 1)
        # Three registrations, one preparation and one launch claim each own
        # POLICY. Each has its separate durable entry and clear transaction;
        # none replaces the actual lifecycle commits asserted above.
        self.assertEqual(self.policy_events,
                         [("policy_metadata", "commit_enter"), ("policy_metadata", "committed")] * 10)
        self.assertIsNone(self.provider.active)

    def test_policy_metadata_cannot_disguise_a_mutation_without_evidence(self):
        with self.store._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL WHERE singleton=1")
            conn.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD' WHERE singleton=1")
            with self.assertRaisesRegex(AssertionError, "requires live lifecycle evidence"):
                conn.commit()
            # Deliberately bypass observation only to clean up this rejected
            # instrumentation probe; no production path uses this escape.
            sqlite3.Connection.rollback(conn)
        self.assertEqual(self.provider.events, [])
        self.assertEqual(self.policy_events, [])

    def test_prepublication_rejection_with_suppressing_cleanup_keeps_nonce(self):
        spec, _ = self.registered()
        before = self.store.query(spec.execution_id)
        self.provider.modify_evidence = lambda proof: replace(proof, state_revision=99)
        self.provider.suppress = True
        with self.assertRaisesRegex(LifecycleError, "invalid_lifecycle_evidence") as caught:
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=0)
        self.assertIn("lifecycle_evidence_cleanup_unverified", caught.exception.__notes__)
        self.assertEqual(self.store.query(spec.execution_id), before)
        self.assertIsNotNone(self.connection().execute(
            "SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_body_failure_rolls_back_before_cleanup_and_preserves_exact_exception(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        primary = RuntimeError("body failure")
        with patch.object(self.store, "_cas", side_effect=primary):
            with self.assertRaises(RuntimeError) as error:
                self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "rollback_enter", "rolled_back", "exit"])
        self.assertIs(self.provider.exits[-1][1], primary)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        runtime = self.connection().execute("SELECT guardian_epoch FROM adaptive_runtime").fetchone()[0]
        self.assertEqual(runtime, "")
        self.assertEqual(self.allocation_count(spec), 1)

    def test_commit_failure_rolls_back_while_scope_is_live(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        primary = sqlite3.OperationalError("injected commit failure")
        self.commit_error = primary
        with self.assertRaises(sqlite3.OperationalError) as error:
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertEqual([event for _, event in self.provider.events],
            ["enter", "verified", "commit_enter", "rollback_enter", "rolled_back", "exit"])
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_prelaunch_archive_failure_rolls_back_capacity_release_under_held_fence(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        primary = RuntimeError("archive outcome failed")
        archive = self.store._archive_allocation

        def archive_then_fail(conn, row, now, **kwargs):
            archive(conn, row, now, **kwargs)
            self.assertEqual(self.provider.active, "cancel")
            self.assertEqual(conn.execute("SELECT count(*) FROM reservations WHERE id=?",
                                          (spec.reservation.id,)).fetchone()[0], 0)
            raise primary

        with patch.object(self.store, "_archive_allocation", side_effect=archive_then_fail):
            with self.assertRaises(RuntimeError) as error:
                self.store.cancel_before_start(spec.execution_id, caller=fixtures.WRAPPER,
                                              expected_revision=0, now=fixtures.NOW + 1)
        self.assertIs(error.exception, primary)
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "rollback_enter", "rolled_back", "exit"])
        self.assertEqual(self.allocation_count(spec), 1)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertEqual(self.connection().execute("SELECT count(*) FROM executions WHERE reservation_id=?",
                                                  (spec.reservation.id,)).fetchone()[0], 0)

    def test_provider_verification_failure_unwinds_without_opening_transaction(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        primary = LifecycleError("native_verification_failed")
        self.provider.enter_error = primary
        with self.assertRaises(LifecycleError) as error:
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertEqual(self.provider.events, [("prepare", "enter"), ("prepare", "enter_unwind")])
        self.assertIsNone(self.provider.active)
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_invalid_evidence_cleans_up_without_opening_transaction(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        self.provider.modify_evidence = lambda proof: replace(proof, state_revision=99)
        with self.assertRaisesRegex(LifecycleError, "invalid_lifecycle_evidence"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertEqual(self.provider.events,
                         [("prepare", "enter"), ("prepare", "verified"), ("prepare", "exit")])
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_revision_race_after_native_verification_cannot_commit_stale_evidence(self):
        spec, _ = self.registered()
        self.provider.events.clear()

        def race(row):
            self.connection().execute("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?",
                                      (row["execution_id"],))

        self.provider.on_verified = race
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "rollback_enter", "rolled_back", "exit"])
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertEqual(self.allocation_count(spec), 1)

    def test_bare_fixture_evidence_is_not_silently_promoted_to_retained_authority(self):
        spec, _ = self.registered()
        self.store.evidence_provider = self.verifier
        with self.assertRaisesRegex(LifecycleError, "invalid_lifecycle_evidence_scope"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_cleanup_suppression_cannot_hide_body_failure(self):
        spec, _ = self.registered()
        self.provider.suppress = True
        primary = RuntimeError("body failure")
        with patch.object(self.store, "_cas", side_effect=primary):
            with self.assertRaises(RuntimeError) as error:
                self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_cleanup_error_preserves_primary_failure_with_sanitized_note(self):
        spec, _ = self.registered()
        self.provider.cleanup_error = RuntimeError("PRIVATE cleanup detail")
        primary = RuntimeError("body failure")
        with patch.object(self.store, "_cas", side_effect=primary):
            with self.assertRaises(RuntimeError) as error:
                self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertIn("lifecycle_evidence_cleanup_failed", primary.__notes__)
        self.assertNotIn("PRIVATE", "".join(traceback.format_exception(primary)))
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_postcommit_cleanup_failure_is_sanitized_and_claim_retry_cannot_launch_again(self):
        spec, args = self.claim()
        self.provider.events.clear()
        self.provider.cleanup_error = RuntimeError("PRIVATE cleanup detail")
        with self.assertRaisesRegex(LifecycleError, "^lifecycle_evidence_cleanup_failed$") as error:
            self.store.claim_launch(spec.execution_id, **args)
        self.assertNotIn("PRIVATE", "".join(traceback.format_exception(error.exception)))
        row = self.store.query(spec.execution_id)
        self.assertEqual(row["state"], "LAUNCHING")
        self.assertEqual(row["claim_consumed"], 1)
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "commit_enter", "committed", "exit"])
        self.provider.events.clear()
        replay = self.store.claim_launch(spec.execution_id, **args)
        self.assertFalse(replay["launch_authorized"])
        self.assertTrue(replay["duplicate"])
        self.assertEqual(self.provider.events, [])
        self.assertEqual(self.allocation_count(spec), 1)

    def test_body_error_survives_rollback_connection_and_provider_cleanup_failures(self):
        spec, _ = self.registered()
        self.provider.events.clear()
        self.provider.cleanup_error = RuntimeError("PRIVATE provider cleanup")
        primary = RuntimeError("original body failure")
        with self.connection_failures(rollback_error=RuntimeError("PRIVATE rollback cleanup"),
                                      close_error=RuntimeError("PRIVATE connection cleanup")):
            with patch.object(self.store, "_cas", side_effect=primary):
                with self.assertRaises(RuntimeError) as error:
                    self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertIs(error.exception, primary)
        self.assertEqual(primary.__notes__, ["lifecycle_transaction_rollback_failed",
            "lifecycle_connection_cleanup_failed", "lifecycle_evidence_cleanup_failed"])
        self.assertNotIn("PRIVATE", "".join(traceback.format_exception(primary)))
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "rollback_failed", "close_failed", "exit"])
        self.assertEqual(self.store.query(spec.execution_id)["state_revision"], 0)

    def test_connection_setup_error_also_owns_cleanup_and_preserves_primary(self):
        primary = sqlite3.OperationalError("connection setup failed")
        with self.connection_failures(setup_error=primary,
                                      close_error=RuntimeError("PRIVATE connection cleanup")):
            with self.assertRaises(sqlite3.OperationalError) as error:
                with self.store._connection():
                    self.fail("connection setup must not yield")
        self.assertIs(error.exception, primary)
        self.assertEqual(primary.__notes__, ["lifecycle_connection_cleanup_failed"])
        self.assertNotIn("PRIVATE", "".join(traceback.format_exception(primary)))
        self.assertEqual(self.provider.events, [(None, "close_failed")])

    def test_postcommit_connection_close_error_does_not_return_or_repeat_launch_authority(self):
        spec, args = self.claim()
        self.provider.events.clear()
        original_close_error = RuntimeError("PRIVATE connection cleanup")
        with self.connection_failures(close_error=original_close_error):
            with self.assertRaisesRegex(LifecycleError, "^lifecycle_connection_cleanup_failed$") as error:
                self.store.claim_launch(spec.execution_id, **args)
        self.assertNotIn("PRIVATE", "".join(traceback.format_exception(error.exception)))
        self.assertIs(error.exception._sentinel_connection_cleanup_error, original_close_error)
        self.assertIsInstance(error.exception._sentinel_connection_cleanup, sqlite3.Connection)
        self.assertEqual([event for _, event in self.provider.events],
                         ["enter", "verified", "committed", "close_failed", "exit"])
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 1)
        self.provider.events.clear()
        retry = self.store.claim_launch(spec.execution_id, **args)
        self.assertFalse(retry["launch_authorized"])
        self.assertEqual(self.provider.events, [])


if __name__ == "__main__":
    unittest.main()
