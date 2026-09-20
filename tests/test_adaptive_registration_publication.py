"""Portable publication fencing tests; fixture POLICY proves no native ownership."""
from contextlib import closing, contextmanager
from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests import test_adaptive_lifecycle as fixtures
from tests.fixtures.adaptive_evidence import FixturePolicyProvider, fixture_evidence_provider


class CountingPolicy(FixturePolicyProvider):
    def __init__(self):
        super().__init__(fixtures.WRAPPER.logon_id)
        self.holds = 0

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        self.holds += 1
        with super().hold(binding, timeout_ms=timeout_ms) as lease:
            yield lease


class AdaptiveRegistrationPublicationTests(unittest.TestCase):
    # Reuse setup helpers without importing the lifecycle suite's test methods.
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.policy = CountingPolicy()
        self.evidence_active = None
        self.evidence_events = []
        self.evidence_cleanup_error = None
        self.on_evidence = None
        self.modify_evidence = None
        self.store = LifecycleStore(self.db, evidence_provider=self.evidence,
                                    policy_provider=self.policy)

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def assert_database_unlocked(self):
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()

    @contextmanager
    def evidence(self, operation, row, caller):
        # These two publication operations must acquire POLICY before any proof.
        if operation not in {"register", "prepare"}:
            yield self.verifier(operation, row, caller)
            return
        self.assertTrue(self.policy.active)
        self.assertIsNotNone(self.store._policy.current_guard())
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assert_database_unlocked()
        self.assertIsNone(self.evidence_active)
        self.evidence_active = operation
        self.evidence_events.append((operation, "enter"))
        try:
            if self.on_evidence is not None:
                self.on_evidence(operation)
            proof = self.verifier(operation, row, caller)
            yield self.modify_evidence(proof) if self.modify_evidence is not None else proof
        finally:
            self.assertTrue(self.policy.active)
            self.assertIsNotNone(self.store._policy.current_guard())
            self.assert_database_unlocked()
            self.evidence_events.append((operation, "exit"))
            self.evidence_active = None
            if self.evidence_cleanup_error is not None:
                raise self.evidence_cleanup_error

    def assert_unregistered(self, spec):
        conn = self.connection()
        self.assertIsNone(conn.execute(
            "SELECT 1 FROM managed_executions WHERE execution_id=?",
            (spec.execution_id,)).fetchone())
        if spec.reservation.kind is not AllocationKind.PARENT:
            table = ("reservations" if spec.reservation.kind is AllocationKind.DIRECT
                     else "worker_reservations")
            row = conn.execute(f"SELECT execution_id,lifecycle_managed FROM {table} WHERE id=?",
                               (spec.reservation.id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(tuple(row), (None, 0))

    @contextmanager
    def other_live_policy(self):
        other = LifecycleStore(self.db,
                               evidence_provider=fixture_evidence_provider(self.verifier),
                               policy_provider=FixturePolicyProvider(fixtures.WRAPPER.logon_id))
        guard = other._policy.prepare(fixtures.WRAPPER.logon_id)
        with other._policy.hold(guard):
            yield guard

    def assert_first_registration_blocked(self, spec):
        before = self.policy.holds
        events = list(self.evidence_events)
        with self.other_live_policy() as guard:
            # Advance only the bounded retry clock; do not wait a real second.
            with patch("sentinel.adaptive.store.time.monotonic", side_effect=[0.0, 2.0]):
                with self.assertRaisesRegex(LifecycleError, "policy_scope_busy"):
                    self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
            self.assertEqual(self.policy.holds, before)
            self.assertEqual(self.evidence_events, events)
            self.assert_unregistered(spec)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_other_live_policy_blocks_first_direct_registration(self):
        spec = self.spec()
        self.allocate(spec)
        self.assert_first_registration_blocked(spec)

    def test_other_live_policy_blocks_first_routed_registration(self):
        spec = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(spec)
        self.assert_first_registration_blocked(spec)

    def test_other_live_policy_blocks_first_parent_registration(self):
        parent, _ = self.running()
        child = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
        self.assert_first_registration_blocked(child)

    def test_other_live_policy_blocks_job_publication_before_evidence(self):
        spec, _ = self.registered()
        before = self.store.query(spec.execution_id)
        events = list(self.evidence_events)
        holds = self.policy.holds
        with self.other_live_policy() as guard:
            with patch("sentinel.adaptive.store.time.monotonic", side_effect=[0.0, 2.0]):
                with self.assertRaisesRegex(LifecycleError, "policy_scope_busy"):
                    self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                             expected_revision=0)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
            self.assertEqual(self.store.query(spec.execution_id), before)
            self.assertIsNone(before["job_name"])
            self.assertEqual(self.evidence_events, events)
            self.assertEqual(self.policy.holds, holds)

    def test_wrong_same_logon_registration_caller_rejects_before_policy_entry(self):
        spec = self.spec()
        self.allocate(spec)
        before = self.runtime()
        for caller in (replace(fixtures.WRAPPER, pid=fixtures.WRAPPER.pid + 1),
                       replace(fixtures.WRAPPER,
                               created_filetime_100ns=fixtures.WRAPPER.created_filetime_100ns + 1)):
            with self.subTest(caller=caller):
                with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
                    self.store.prepare_registration(spec, caller=caller, now=fixtures.NOW)
                self.assertEqual(self.runtime(), before)
                self.assertEqual(self.policy.holds, 0)
                self.assertEqual(self.evidence_events, [])
                self.assert_unregistered(spec)

    def test_wrong_same_logon_prepare_caller_rejects_before_policy_entry(self):
        spec, _ = self.registered()
        before = self.runtime()
        row = self.store.query(spec.execution_id)
        holds = self.policy.holds
        events = list(self.evidence_events)
        for caller in (replace(fixtures.WRAPPER, pid=fixtures.WRAPPER.pid + 1),
                       replace(fixtures.WRAPPER,
                               created_filetime_100ns=fixtures.WRAPPER.created_filetime_100ns + 1)):
            with self.subTest(caller=caller):
                with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
                    self.store.mark_prepared(spec.execution_id, caller=caller, expected_revision=0)
                self.assertEqual(self.runtime(), before)
                self.assertEqual(self.store.query(spec.execution_id), row)
                self.assertEqual(self.policy.holds, holds)
                self.assertEqual(self.evidence_events, events)

    def test_invalid_prepare_proof_rolls_back_and_clears_owned_nonce(self):
        spec, _ = self.registered()
        row = self.store.query(spec.execution_id)
        revision = self.runtime()["registry_revision"]
        self.modify_evidence = lambda proof: replace(proof, durable_manifest=False)
        with self.assertRaisesRegex(LifecycleError, "job_preparation_unverified"):
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertEqual(self.store.query(spec.execution_id), row)
        self.assertEqual(self.runtime()["registry_revision"], revision)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        self.assertEqual(self.evidence_events[-2:], [("prepare", "enter"), ("prepare", "exit")])

    def test_same_store_borrows_exact_scope_without_another_hold(self):
        spec = self.spec()
        self.allocate(spec)
        guard = self.store._policy.prepare(fixtures.WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            self.assertEqual(self.policy.holds, 1)
            with patch.object(self.store._policy, "revalidate",
                              wraps=self.store._policy.revalidate) as revalidate:
                self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
                row = self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER,
                                               expected_revision=0)
            self.assertEqual(row["state"], "PREPARED")
            self.assertEqual(self.policy.holds, 1)
            self.assertEqual(revalidate.call_count, 2)
            self.assertTrue(all(call.args[1] is guard for call in revalidate.call_args_list))
            self.assertIs(self.store._policy.current_guard(), guard)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.evidence_events,
                         [("register", "enter"), ("register", "exit"),
                          ("prepare", "enter"), ("prepare", "exit")])

    def test_borrowed_scope_revalidates_nonce_before_publication(self):
        spec = self.spec()
        self.allocate(spec)
        guard = self.store._policy.prepare(fixtures.WRAPPER.logon_id)
        changed_nonce = str(uuid4())

        def change_nonce(operation):
            self.connection().execute("UPDATE adaptive_runtime SET policy_entry_nonce=?",
                                      (changed_nonce,))

        self.on_evidence = change_nonce
        # The outer owner's clear also rejects the changed nonce after the
        # publication itself correctly rejects it inside its real transaction.
        with self.assertRaisesRegex(PolicyError, "policy_entry_changed"):
            with self.store._policy.hold(guard):
                with self.assertRaisesRegex(LifecycleError, "policy_entry_changed"):
                    self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
                self.assertFalse(guard.clean_rejection)
                self.assert_unregistered(spec)
        self.assertEqual(self.runtime()["policy_entry_nonce"], changed_nonce)
        self.assertEqual(self.policy.holds, 1)

    def test_precommit_registration_failure_rolls_back_binding_and_clears_owned_nonce(self):
        spec = self.spec()
        self.allocate(spec)
        revision = self.runtime()["registry_revision"]
        self.connection().execute("""CREATE TRIGGER fail_registration BEFORE INSERT ON managed_executions
            BEGIN SELECT RAISE(ABORT,'fixture registration failure'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture registration failure"):
            self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assert_unregistered(spec)
        self.assertEqual(self.runtime()["registry_revision"], revision)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        self.assertEqual(self.evidence_events, [("register", "enter"), ("register", "exit")])

    @contextmanager
    def publication_connection_failure(self, fault):
        """Inject only at publication commit/close, preserving real SQLite I/O."""
        test = self
        connect = sqlite3.connect

        class FaultConnection(sqlite3.Connection):
            publication_committed = False

            def commit(self):
                publication = test.evidence_active is not None
                if publication:
                    test.assertTrue(test.policy.active)
                    test.assertTrue(self.in_transaction)
                    if fault == "commit_before":
                        raise sqlite3.OperationalError("fixture commit uncertain")
                super().commit()
                if publication:
                    self.publication_committed = True
                    if fault == "commit_after":
                        raise sqlite3.OperationalError("fixture commit acknowledgement lost")

            def close(self):
                super().close()
                if self.publication_committed and fault == "close_after":
                    self.publication_committed = False
                    raise sqlite3.OperationalError("fixture connection cleanup uncertain")

        def fault_connect(*args, **kwargs):
            kwargs["factory"] = FaultConnection
            return connect(*args, **kwargs)

        with patch("sentinel.adaptive.store.sqlite3.connect", side_effect=fault_connect):
            yield

    def test_commit_attempt_failure_preserves_owned_nonce_after_rollback(self):
        spec = self.spec()
        self.allocate(spec)
        with self.publication_connection_failure("commit_before"):
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture commit uncertain"):
                self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assert_unregistered(spec)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_commit_acknowledgement_loss_keeps_committed_registration_and_nonce(self):
        spec = self.spec()
        self.allocate(spec)
        with self.publication_connection_failure("commit_after"):
            with self.assertRaisesRegex(sqlite3.OperationalError, "acknowledgement lost"):
                self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_connection_cleanup_uncertainty_keeps_committed_registration_and_nonce(self):
        spec = self.spec()
        self.allocate(spec)
        with self.publication_connection_failure("close_after"):
            with self.assertRaisesRegex(LifecycleError, "lifecycle_connection_cleanup_failed"):
                self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_evidence_cleanup_uncertainty_after_commit_keeps_owned_nonce(self):
        spec = self.spec()
        self.allocate(spec)
        self.evidence_cleanup_error = RuntimeError("fixture evidence cleanup uncertain")
        with self.assertRaisesRegex(LifecycleError, "lifecycle_evidence_cleanup_failed"):
            self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
        self.assertEqual(self.store.query(spec.execution_id)["state"], "RESERVED")
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_publication_transaction_retains_policy_and_evidence_until_commit(self):
        spec = self.spec()
        self.allocate(spec)
        operations = []
        original = self.store._require_allocation

        def observe_allocation(conn, execution_id):
            self.assertTrue(conn.in_transaction)
            self.assertTrue(self.policy.active)
            self.assertIsNotNone(self.store._policy.current_guard())
            self.assertIn(self.evidence_active, {"register", "prepare"})
            operations.append(self.evidence_active)
            return original(conn, execution_id)

        with patch.object(self.store, "_require_allocation", side_effect=observe_allocation):
            self.store.prepare_registration(spec, caller=fixtures.WRAPPER, now=fixtures.NOW)
            self.store.mark_prepared(spec.execution_id, caller=fixtures.WRAPPER, expected_revision=0)
        self.assertEqual(operations, ["register", "prepare"])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])


if __name__ == "__main__":
    unittest.main()
