"""Startup publication against isolated SQL/journals and retained handle fixtures.

The real POLICY coordinator, SupervisorStartup inventory and epoch rollover run
here. Native handles/mutexes use explicit portable backends; these tests neither
launch/control a process nor establish Windows capability or promotion gates.
"""
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.guardian_registration import GuardianRegistration
from sentinel.adaptive.legacy_writer import initialize_registry_locked
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleStore
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_guardian_launch import ProcessBackend
from tests import test_adaptive_supervisor_epoch as epoch_fixture
from tests import test_adaptive_supervisor_startup as startup_fixture


LOGON = "S-1-5-5-31-41"
GUARDIAN = ProcessIdentity(6001, 134343072000000601, LOGON)
EPOCH = "guardian-registration-fixture"


class GuardianRegistrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        self.provider = FixturePolicyProvider(LOGON)
        LifecycleStore(self.db, policy_provider=self.provider)
        self.store = LifecycleStore(self.db, existing_path=True, policy_provider=self.provider)
        (self.directory / "recovery").mkdir()
        self.journal = RecoveryJournal(self.directory / "recovery")
        self.backend = ProcessBackend()
        self.guardian = self.backend.process(GUARDIAN)
        policy = self.store._policy
        with policy.hold(policy.prepare(LOGON)):
            initialize_registry_locked(self.store)

    def connection(self):
        conn = sqlite3.connect(self.db, isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def rows(self):
        return [tuple(row) for row in self.connection().execute(
            "SELECT * FROM adaptive_infrastructure ORDER BY role,pid")]

    def operation(self):
        return GuardianRegistration(self.store, self.journal, guardian=self.guardian, guardian_epoch=EPOCH)

    def assert_clean_refusal(self, reason):
        before, rows = self.runtime(), self.rows()
        operation = self.operation()
        result = operation.tick()
        self.assertTrue(result.refused, result)
        self.assertFalse(result.complete)
        self.assertFalse(result.pending)
        self.assertEqual(result.reason, reason)
        self.assertEqual(self.runtime(), before)
        self.assertEqual(self.rows(), rows)
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.pending)
        self.assertFalse(self.provider.active)

    def test_fresh_publication_binds_identity_epoch_and_logon_together(self):
        before = self.runtime()
        operation = self.operation()
        result = operation.tick()
        self.assertTrue(result.complete, result)
        self.assertFalse(result.pending)
        self.assertEqual(self.rows(), [("guardian", GUARDIAN.pid,
            str(GUARDIAN.created_filetime_100ns), LOGON, 1)])
        after = self.runtime()
        self.assertEqual(after, dict(before, guardian_epoch=EPOCH, active_logon_id=LOGON,
                                    registry_revision=before["registry_revision"] + 1))
        self.assertEqual(after["mode"], "off")
        self.assertEqual(after["admission_barrier"], "NONE")
        self.assertEqual(result.registry_revision, after["registry_revision"])
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.pending)

    def test_same_original_tick_and_exact_new_operation_are_idempotent(self):
        operation = self.operation()
        first = operation.tick()
        self.assertTrue(first.complete, first)
        after, rows = self.runtime(), self.rows()
        self.assertEqual(operation.tick(), first)
        self.assertTrue(self.operation().tick().complete)
        self.assertEqual(self.runtime(), after)
        self.assertEqual(self.rows(), rows)

    def test_fresh_old_request_cannot_be_hidden_by_empty_managed_table(self):
        # Deliberate orphan fixture: old/corrupt request history is not fresh.
        self.connection().execute("INSERT INTO adaptive_launch_requests VALUES(?,?,?,?,?,?)",
            (str(uuid4()), "PrepareExecution", str(uuid4()), "a" * 64, "b" * 64, "old-epoch"))
        self.assert_clean_refusal("guardian_registration_old_scope_or_launch")

    def test_fresh_manifest_and_interrupted_publication_each_refuse(self):
        for name in (str(uuid4()) + ".json", "." + str(uuid4()) + "." + uuid4().hex + ".tmp"):
            with self.subTest(name=name):
                path = self.directory / "recovery" / name
                path.write_text("not fresh", encoding="utf-8")
                self.assert_clean_refusal("guardian_registration_old_manifest")
                path.unlink()

    def test_arbitrary_supervisor_or_helper_row_is_not_startup_authority(self):
        for role in ("supervisor", "helper"):
            with self.subTest(role=role):
                conn = self.connection()
                conn.execute("INSERT INTO adaptive_infrastructure VALUES(?,?,?,?,1)",
                    (role, 7001, str(GUARDIAN.created_filetime_100ns + 1), LOGON))
                self.assert_clean_refusal("guardian_registration_old_infrastructure")
                conn.execute("DELETE FROM adaptive_infrastructure")

    def test_foreign_guardian_epoch_is_not_overwritten(self):
        self.connection().execute("UPDATE adaptive_runtime SET guardian_epoch='foreign'")
        self.assert_clean_refusal("guardian_host_epoch_occupied")

    def test_matching_epoch_with_no_active_logon_is_incomplete_binding(self):
        self.connection().execute("UPDATE adaptive_runtime SET guardian_epoch=?", (EPOCH,))
        self.assert_clean_refusal("guardian_registration_partial_binding")

    def test_matching_epoch_alone_cannot_adopt_historical_runtime(self):
        self.connection().execute("UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?", (EPOCH, LOGON))
        self.assert_clean_refusal("guardian_registration_rollover_unverified")

    def test_barrier_prevents_fresh_epoch_publication(self):
        self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        self.assert_clean_refusal("guardian_registration_barrier_unsettled")

    def test_registry_insert_rolls_back_when_epoch_publication_fails(self):
        conn = self.connection()
        conn.execute("CREATE TRIGGER reject_epoch BEFORE UPDATE OF guardian_epoch ON adaptive_runtime "
                     "BEGIN SELECT RAISE(ABORT,'fixture publication failed'); END")
        operation = self.operation()
        first = operation.tick()
        original = operation.guard
        self.assertTrue(first.pending, first)
        self.assertIsNotNone(original)
        self.assertFalse(first.quarantined)
        self.assertEqual(self.rows(), [])
        self.assertEqual(self.runtime()["guardian_epoch"], "")
        self.assertEqual(self.runtime()["policy_entry_nonce"], original.nonce)
        conn.execute("DROP TRIGGER reject_epoch")
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("substitute guard")):
            result = operation.tick()
        self.assertTrue(result.complete, result)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.runtime()["registry_revision"], 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_lost_commit_ack_reconciles_same_guard_without_second_revision(self):
        operation = self.operation()
        original = self.store._transaction
        failed = False

        @contextmanager
        def uncertain(**kwargs):
            nonlocal failed
            with original(**kwargs) as conn:
                yield conn
            if operation.after is not None and not failed:
                failed = True
                raise sqlite3.OperationalError("fixture lost publication ACK")

        with patch.object(self.store, "_transaction", uncertain):
            first = operation.tick()
        self.assertTrue(first.pending, first)
        guard = operation.guard
        self.assertIsNotNone(guard)
        self.assertEqual(self.runtime()["guardian_epoch"], EPOCH)
        revision = self.runtime()["registry_revision"]
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("substitute guard")):
            result = operation.tick()
        self.assertTrue(result.complete, result)
        self.assertEqual(self.runtime()["registry_revision"], revision)
        self.assertEqual(len(self.rows()), 1)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_lost_nonce_clear_ack_uses_readonly_exact_publication_reconciliation(self):
        operation = self.operation()
        original = self.store._policy._clear

        def clear(guard):
            original(guard)
            raise sqlite3.OperationalError("fixture lost clear ACK")

        with patch.object(self.store._policy, "_clear", clear):
            first = operation.tick()
        self.assertTrue(first.pending, first)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        before = self.runtime()
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("substitute guard")), \
                patch.object(operation, "_publish", side_effect=AssertionError("duplicate publication")):
            result = operation.tick()
        self.assertTrue(result.complete, result)
        self.assertEqual(self.runtime(), before)

    def test_busy_parent_policy_keeps_child_startup_pending_then_retries(self):
        policy = self.store._policy
        parent_guard = policy.prepare(LOGON)
        operation = self.operation()
        first = operation.tick()
        self.assertTrue(first.pending)
        self.assertTrue(operation.pending)
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.quarantined)
        with policy.hold(parent_guard):
            pass
        self.assertTrue(operation.tick().complete)

    def test_interrupt_retains_original_guard_and_never_reacquires_when_quarantined(self):
        operation = self.operation()
        with patch.object(operation, "_fresh_journal", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                operation.tick()
        guard = operation.guard
        self.assertIsNotNone(guard)
        self.assertTrue(operation.pending)
        self.assertTrue(operation.quarantined)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("substitute guard")), \
                patch.object(operation, "_publish", side_effect=AssertionError("retry interrupted boundary")):
            result = operation.tick()
        self.assertTrue(result.pending)
        self.assertTrue(result.quarantined)
        self.assertIs(operation.guard, guard)
        self.assertEqual(self.runtime()["guardian_epoch"], "")


class SupervisedFreshRegistrationTests(unittest.TestCase):
    """Compose the real startup fixture; do not inherit its separate test suite."""
    setUp = startup_fixture.SupervisorStartupTests.setUp
    sql = startup_fixture.SupervisorStartupTests.sql
    runtime = startup_fixture.SupervisorStartupTests.runtime
    mutex_factory = startup_fixture.SupervisorStartupTests.mutex_factory
    owner = startup_fixture.SupervisorStartupTests.owner
    cleanup_owner = staticmethod(startup_fixture.SupervisorStartupTests.cleanup_owner)

    def test_original_supervisor_fresh_check_leaves_registry_ready_for_child(self):
        parent = self.owner().acquire()
        parent.assert_fresh()
        before = self.runtime()
        self.assertEqual(self.sql("SELECT * FROM adaptive_infrastructure"), [])
        # SupervisorHost holds this final POLICY through child creation; after
        # its cleanup, the child publishes its own original identity/epoch.
        policy = self.store._policy
        with policy.hold(policy.prepare(LOGON)):
            parent.assert_fresh_locked()
        child_identity = replace(GUARDIAN, pid=GUARDIAN.pid + 1)
        child = self.native.process(child_identity)
        operation = GuardianRegistration(self.store, self.journal,
            guardian=child, guardian_epoch=EPOCH)
        result = operation.tick()
        self.assertTrue(result.complete, result)
        parent.assert_held()
        self.assertEqual(self.runtime()["policy_instance_id"], parent.binding.instance_id)
        self.assertEqual(self.runtime()["guardian_epoch"], EPOCH)
        self.assertEqual(self.runtime()["active_logon_id"], LOGON)
        self.assertEqual(self.runtime()["registry_revision"], before["registry_revision"] + 1)
        self.assertEqual(self.sql("SELECT role,pid FROM adaptive_infrastructure"), [("guardian", child_identity.pid)])


class SettledReplacementRegistrationTests(unittest.TestCase):
    """Actual terminal lifecycle and C4 receipt; all native objects are fixtures."""
    setUp = epoch_fixture.EpochRolloverTests.setUp
    spec = epoch_fixture.EpochRolloverTests.spec
    allocate = epoch_fixture.EpochRolloverTests.allocate
    connection = epoch_fixture.EpochRolloverTests.connection
    seed_evidence = epoch_fixture.EpochRolloverTests.seed_evidence
    seed_started = epoch_fixture.EpochRolloverTests.seed_started
    sql = epoch_fixture.EpochRolloverTests.sql
    make_mutex = epoch_fixture.EpochRolloverTests.make_mutex
    start_consumer = epoch_fixture.EpochRolloverTests.start_consumer
    adopt = epoch_fixture.EpochRolloverTests.adopt
    root_exits = epoch_fixture.EpochRolloverTests.root_exits
    rewrite_manifest = epoch_fixture.EpochRolloverTests.rewrite_manifest
    finish = epoch_fixture.EpochRolloverTests.finish
    operation = epoch_fixture.EpochRolloverTests.operation
    current = epoch_fixture.EpochRolloverTests.current

    def new_registration(self):
        identity = replace(self.guardian.identity, pid=self.guardian.identity.pid + 700,
                           created_filetime_100ns=self.guardian.identity.created_filetime_100ns + 1)
        return GuardianRegistration(self.store, self.journal,
            guardian=self.processes.process(identity), guardian_epoch=self.new_epoch)

    def test_validated_rollover_allows_new_guardian_and_preserves_terminal_history(self):
        case = self.seed_started()
        self.finish(case)
        before = self.store.query(case.spec.execution_id)
        manifest = self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        rolled = self.operation().tick(self.new_epoch)
        self.assertTrue(rolled.complete, rolled)
        revision = self.current()["registry_revision"]
        registration = self.new_registration()
        result = registration.tick()
        self.assertTrue(result.complete, result)
        self.assertEqual(self.current()["registry_revision"], revision + 1)
        self.assertEqual(self.store.query(case.spec.execution_id), before)
        self.assertEqual(self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce), manifest)
        self.assertEqual(self.current()["mode"], "off")
        self.assertEqual(self.current()["admission_barrier"], "NONE")

    def test_zero_scope_receipt_is_valid_replacement_evidence(self):
        result = self.operation().tick(self.new_epoch)
        self.assertTrue(result.complete, result)
        self.assertTrue(self.new_registration().tick().complete)

    def test_receipt_from_an_older_registry_generation_cannot_authorize_registration(self):
        self.assertTrue(self.operation().tick(self.new_epoch).complete)
        self.connection().execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        before = self.current()
        result = self.new_registration().tick()
        self.assertTrue(result.refused, result)
        self.assertEqual(result.reason, "guardian_registration_rollover_unverified")
        self.assertEqual(self.current(), before)

    def test_terminal_history_cannot_be_relabelled_as_fresh_first_start(self):
        case = self.seed_started()
        self.finish(case)
        self.connection().execute("UPDATE adaptive_runtime SET guardian_epoch='',active_logon_id=''")
        before = self.current()
        result = self.new_registration().tick()
        self.assertTrue(result.refused, result)
        self.assertIn(result.reason, {"guardian_registration_old_manifest", "guardian_registration_old_scope_or_launch"})
        self.assertEqual(self.current(), before)


if __name__ == "__main__":
    unittest.main()
