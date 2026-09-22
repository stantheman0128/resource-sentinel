"""Shared POLICY publication tests with real isolated SQLite and synthetic leases.

No test here acquires a Windows mutex or creates a process or Job.
"""
from contextlib import closing, contextmanager
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.policy import PolicyBusy, PolicyCoordinator, PolicyError
from sentinel.adaptive.store import LifecycleError, LifecycleStore, commit_managed_admission
from sentinel.adaptive.windows import NativePolicyMutexError
from sentinel.coordinator import Coordinator
from tests import test_adaptive_managed_admission as fixtures
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_admission_context import FakeCurrentProcess
from tests.test_adaptive_coordinator import CONFIG, NOW, status


class ObservedPublicationPolicy(FixturePolicyProvider):
    """Retain a real fixture lock and probe SQLite before wait and after release."""

    def __init__(self, test):
        super().__init__(test.process.identity.logon_id)
        self.test = test
        self.enter_error = None
        self.exit_error = None

    def current_logon(self):
        self.test.assert_unlocked()
        self.test.events.append("policy.identity")
        return super().current_logon()

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        self.test.assert_unlocked()
        runtime = self.test.runtime()
        self.test.assertEqual(runtime["policy_instance_id"], binding.instance_id)
        self.test.assertEqual(runtime["policy_logon_id"], binding.logon_id)
        self.test.assertIsNotNone(runtime["policy_entry_nonce"])
        self.test.events.append("policy.wait")
        if self.enter_error is not None:
            raise self.enter_error
        try:
            with super().hold(binding, timeout_ms=timeout_ms) as lease:
                self.test.events.append("policy.held")
                yield lease
        finally:
            self.test.assertFalse(self.active)
            self.test.assert_unlocked()
            self.test.events.append("policy.released")
            if self.exit_error is not None:
                raise self.exit_error


class ManagedPublicationTests(unittest.TestCase):
    context = fixtures.ManagedAdmissionTests.context
    conn = fixtures.ManagedAdmissionTests.conn
    admit = fixtures.ManagedAdmissionTests.admit
    counts = fixtures.ManagedAdmissionTests.counts

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.process = FakeCurrentProcess()
        self.events = []
        self.policy = ObservedPublicationPolicy(self)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0),
                                       policy_provider=self.policy)
        current = patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=self.process)
        current.start()
        self.addCleanup(current.stop)
        cpu = patch("os.cpu_count", return_value=12)
        cpu.start()
        self.addCleanup(cpu.stop)

    def runtime(self):
        return dict(self.conn().execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())

    def publication(self):
        conn = self.conn()
        return {table: [dict(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY 1")]
                for table in ("queue", "reservations", "managed_executions")}

    def assert_unlocked(self):
        with closing(sqlite3.connect(self.coordinator.db_path, timeout=0, isolation_level=None)) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()

    @contextmanager
    def publication_connection_failure(self, failure):
        """Fault capacity writes only, preserving POLICY metadata transactions."""
        real_connect = sqlite3.connect
        events = []

        class FaultConnection(sqlite3.Connection):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.capacity_writer = False
                self.set_authorizer(self.observe_write)

            def observe_write(self, action, table, column, database, trigger):
                if (action in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}
                        and table in {"queue", "reservations", "managed_executions"}):
                    self.capacity_writer = True
                return sqlite3.SQLITE_OK

            def execute(self, sql, *args):
                normalized = sql.strip().upper()
                if normalized == "ROLLBACK" and self.capacity_writer and failure == "rollback":
                    events.append("rollback")
                    raise sqlite3.OperationalError("fixture_publication_rollback_failed")
                result = super().execute(sql, *args)
                if normalized == "COMMIT" and self.capacity_writer and failure == "commit_ack":
                    events.append("commit_ack")
                    raise sqlite3.OperationalError("fixture_publication_commit_ack_lost")
                return result

            def commit(self):
                result = super().commit()
                if self.capacity_writer and failure == "commit_ack":
                    events.append("commit_ack")
                    raise sqlite3.OperationalError("fixture_publication_commit_ack_lost")
                return result

            def rollback(self):
                if self.capacity_writer and failure == "rollback":
                    events.append("rollback")
                    raise sqlite3.OperationalError("fixture_publication_rollback_failed")
                return super().rollback()

            def close(self):
                result = super().close()
                if self.capacity_writer and failure == "close":
                    events.append("close")
                    raise sqlite3.OperationalError("fixture_publication_close_failed")
                return result

        def connect(*args, **kwargs):
            if kwargs.get("timeout") == 10:
                kwargs["factory"] = FaultConnection
            return real_connect(*args, **kwargs)

        with patch("sentinel.coordinator.sqlite3.connect", side_effect=connect):
            yield events

    def test_identity_cleanup_and_exemption_lookup_precede_policy_and_capacity_writer(self):
        context = self.context()
        observe = self.process.observe
        cleanup = self.coordinator._cleanup_observations

        def observed_identity():
            self.assert_unlocked()
            self.events.append("wrapper.identity")
            return observe()

        def observed_cleanup():
            self.assertFalse(self.policy.active)
            self.assert_unlocked()
            self.events.append("cleanup.observations")
            return cleanup()

        def observed_exemption(*args, **kwargs):
            self.assertFalse(self.policy.active)
            self.assert_unlocked()
            self.events.append("exemption.lookup")
            return None

        def observed_commit(conn, admission, reservation_id, **kwargs):
            self.assertTrue(conn.in_transaction)
            self.assertTrue(self.policy.active)
            policy = kwargs["policy_coordinator"]
            self.assertIsInstance(policy, PolicyCoordinator)
            guard = policy.assert_held()
            self.assertEqual(guard.binding.logon_id, admission.logon_id)
            self.events.append("publication.write")
            return commit_managed_admission(conn, admission, reservation_id, **kwargs)

        with patch.object(self.process, "observe", side_effect=observed_identity), \
                patch.object(self.coordinator, "_cleanup_observations", side_effect=observed_cleanup), \
                patch("sentinel.coordinator.Exemptions.match", side_effect=observed_exemption), \
                patch("sentinel.coordinator.commit_managed_admission", side_effect=observed_commit):
            result = self.admit(context)
        self.assertTrue(result["allowed"])
        self.assertFalse(result["launch_authorized"])
        for event in ("wrapper.identity", "cleanup.observations", "exemption.lookup"):
            self.assertLess(self.events.index(event), self.events.index("policy.wait"))
        self.assertLess(self.events.index("policy.held"), self.events.index("publication.write"))
        self.assertLess(self.events.index("publication.write"), self.events.index("policy.released"))
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_ordinary_capacity_denial_keeps_queue_and_releases_policy_nonce(self):
        context = self.context()
        denied = self.admit(context, status(commit=94))
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reason"], "commit_capacity")
        self.assertEqual(self.counts(), (1, 0, 0))
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)
        admitted = self.admit(context, now=NOW + 1)
        self.assertTrue(admitted["allowed"])
        self.assertEqual(admitted["request_key"], denied["request_key"])
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_exact_retry_preserves_capacity_binding_and_original_credential(self):
        context = self.context()
        token = context.launch_claim_token()
        first = self.admit(context)
        before = self.publication()
        repeated = self.admit(context, now=NOW + 1)
        self.assertTrue(repeated["allowed"])
        self.assertTrue(repeated["reused"])
        self.assertFalse(repeated["launch_authorized"])
        self.assertEqual(repeated["reservation_id"], first["reservation_id"])
        self.assertEqual(self.publication(), before)
        self.assertEqual(context.launch_claim_token(), token)

    def test_direct_commit_helper_requires_retained_policy_scope(self):
        context = self.context()
        admitted = self.admit(context)
        snapshot = context.snapshot()
        conn = self.conn()
        before = self.publication()
        forged = SimpleNamespace(
            assert_held=lambda: SimpleNamespace(binding=SimpleNamespace(logon_id=snapshot.logon_id)),
            revalidate=lambda *args: None)
        for arguments in ({}, {"policy_coordinator": forged}):
            with self.subTest(forged=bool(arguments)):
                conn.execute("BEGIN IMMEDIATE")
                try:
                    with self.assertRaisesRegex(LifecycleError, "policy_scope_not_held"):
                        commit_managed_admission(conn, snapshot, admitted["reservation_id"], now=NOW,
                                                 local_context=CONFIG, **arguments)
                finally:
                    conn.rollback()
                self.assertEqual(self.publication(), before)

    def test_unheld_real_policy_coordinator_cannot_authorize_direct_commit(self):
        context = self.context()
        admitted = self.admit(context)
        snapshot = context.snapshot()
        store = LifecycleStore(self.coordinator.db_path, policy_provider=self.policy)
        conn = self.conn()
        before = self.publication()
        conn.execute("BEGIN IMMEDIATE")
        try:
            with self.assertRaisesRegex(LifecycleError, "policy_scope_not_held"):
                commit_managed_admission(conn, snapshot, admitted["reservation_id"], now=NOW,
                                         local_context=CONFIG, policy_coordinator=store._policy)
        finally:
            conn.rollback()
        self.assertEqual(self.publication(), before)

    def test_direct_commit_revalidates_held_nonce_in_its_own_transaction(self):
        context = self.context()
        admitted = self.admit(context)
        snapshot = context.snapshot()
        store = LifecycleStore(self.coordinator.db_path, policy_provider=self.policy)
        guard = store._policy.prepare(self.process.identity.logon_id)
        with store._policy.hold(guard):
            before = self.publication()
            conn = self.conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=?", (str(uuid4()),))
                with self.assertRaisesRegex(LifecycleError, "policy_entry_changed"):
                    commit_managed_admission(conn, snapshot, admitted["reservation_id"], now=NOW,
                                             local_context=CONFIG, policy_coordinator=store._policy)
            finally:
                conn.rollback()
            self.assertEqual(self.publication(), before)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_live_other_policy_scope_blocks_first_publication_without_consuming_context(self):
        context = self.context()
        token = context.launch_claim_token()
        owner = LifecycleStore(self.coordinator.db_path, policy_provider=self.policy)
        guard = owner._policy.prepare(self.process.identity.logon_id)
        with owner._policy.hold(guard):
            before = self.publication()
            with patch("sentinel.coordinator.time.monotonic", side_effect=(0.0, 1.1)):
                with self.assertRaisesRegex(PolicyBusy, "policy_scope_busy"):
                    self.admit(context)
            self.assertEqual(self.publication(), before)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
            self.assertTrue(self.policy.active)
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_not_submitted"):
                context.snapshot_for_ledger(self.coordinator.db_path)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        admitted = self.admit(context)
        self.assertTrue(admitted["allowed"])
        self.assertFalse(admitted["reused"])
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertEqual(context.launch_claim_token(), token)

    def test_positive_policy_wait_timeout_leaves_no_writer_or_consumed_submission(self):
        context = self.context()
        self.policy.enter_error = NativePolicyMutexError("policy_mutex_timeout")
        with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_timeout"):
            self.admit(context)
        self.assertIn("policy.wait", self.events)
        self.assertNotIn("policy.held", self.events)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.counts(), (0, 0, 0))
        self.policy.enter_error = None
        self.assertTrue(self.admit(context)["allowed"])

    def test_timeout_with_cleanup_uncertainty_retains_nonce_without_publication(self):
        context = self.context()
        failure = NativePolicyMutexError("policy_mutex_timeout")
        failure.add_note("fixture_policy_cleanup_uncertain")
        self.policy.enter_error = failure
        with self.assertRaises(NativePolicyMutexError) as caught:
            self.admit(context)
        self.assertIs(caught.exception, failure)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_publication_statement_failure_rolls_back_and_clears_known_clean_scope(self):
        context = self.context()
        self.conn().execute("""CREATE TRIGGER fixture_reject_publication BEFORE INSERT ON managed_executions
            BEGIN SELECT RAISE(ABORT,'fixture_publication_rejected'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture_publication_rejected"):
            self.admit(context)
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_publication_rollback_failure_retains_uncertain_nonce(self):
        context = self.context()
        self.conn().execute("""CREATE TRIGGER fixture_reject_publication BEFORE INSERT ON managed_executions
            BEGIN SELECT RAISE(ABORT,'fixture_publication_rejected'); END""")
        with self.publication_connection_failure("rollback") as events:
            with self.assertRaises(sqlite3.Error):
                self.admit(context)
        self.assertIn("rollback", events)
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_lost_commit_ack_retains_committed_publication_and_uncertain_nonce(self):
        context = self.context()
        token = context.launch_claim_token()
        with self.publication_connection_failure("commit_ack") as events:
            with self.assertRaises(sqlite3.Error):
                self.admit(context)
        self.assertEqual(events, ["commit_ack"])
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_submission_unsettled"):
            context.launch_claim_token()
        # Read-only publication visibility does not settle the original writer
        # or export a launch claim. Preserve its original guard and private
        # token; owned settlement is covered by the abandonment tests.
        guard = context._submission_guard
        with patch.object(PolicyCoordinator, "prepare", side_effect=AssertionError("new guard")):
            result = self.coordinator.reconcile_managed(context)
        self.assertTrue(result["submission_cleanup_pending"])
        self.assertEqual(result["state"], "RESERVED")
        self.assertIs(context._submission_guard, guard)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertEqual(context._claim_token, token)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_submission_unsettled"):
            context.launch_claim_token()
        self.assertFalse(self.policy.active)

    def test_connection_close_failure_retains_committed_publication_and_uncertain_nonce(self):
        context = self.context()
        with self.publication_connection_failure("close") as events:
            with self.assertRaises((sqlite3.Error, LifecycleError)):
                self.admit(context)
        self.assertEqual(events, ["close"])
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)

    def test_native_release_failure_retains_committed_publication_and_nonce(self):
        context = self.context()
        self.policy.exit_error = NativePolicyMutexError("policy_mutex_release_failed")
        with self.assertRaises((LifecycleError, PolicyError, NativePolicyMutexError)):
            self.admit(context)
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertFalse(self.policy.active)


if __name__ == "__main__":
    unittest.main()
