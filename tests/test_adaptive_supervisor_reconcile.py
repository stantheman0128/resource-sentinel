"""C4 portable consumers with real isolated SQL and synthetic native witnesses."""
from contextlib import closing, contextmanager
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import legacy_writer
from sentinel.adaptive import supervisor_reconcile as module
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.supervisor_reconcile import FinishedBarrierJanitor, PendingInfrastructureRetirement
from tests import test_adaptive_lifecycle as base
from tests import test_adaptive_guardian_lifecycle as lifecycle
from tests.test_adaptive_legacy_writer import SyntheticIdentityBackend


class InfrastructureRetirementTests(unittest.TestCase):
    connection = base.AdaptiveLifecycleTests.connection

    def setUp(self):
        base.AdaptiveLifecycleTests.setUp(self)
        self.backend = SyntheticIdentityBackend()
        self.process = VerifiedProcess(self.backend, 99, base.WRAPPER)
        self.addCleanup(self.process.close)
        with self.held():
            legacy_writer.initialize_registry_locked(self.store)
            legacy_writer.register_infrastructure_locked(self.store, "helper", self.process)
        self.backend.status = IdentityStatus.DEAD
        self.pending = PendingInfrastructureRetirement(self.store, role="helper", witness=self.process)

    @contextmanager
    def held(self):
        guard = self.store._policy.prepare(base.WRAPPER.logon_id)
        with self.store._policy.hold(guard):
            yield guard

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def rows(self):
        return list(self.connection().execute("SELECT * FROM adaptive_infrastructure"))

    def block_delete(self):
        self.connection().execute("""CREATE TRIGGER fixture_delete_failure BEFORE DELETE ON adaptive_infrastructure
            BEGIN SELECT RAISE(ABORT,'fixture_delete_failure'); END""")

    def test_deletion_failure_retries_same_guard_then_releases_nonce(self):
        self.block_delete()
        first = self.pending.tick()
        guard = self.pending.guard
        self.assertTrue(first.pending)
        self.assertFalse(first.quarantined)
        self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
        self.connection().execute("DROP TRIGGER fixture_delete_failure")
        original = self.store._policy.hold
        used = []
        @contextmanager
        def record(value):
            used.append(value)
            with original(value):
                yield value
        with patch.object(self.store._policy, "hold", record):
            second = self.pending.tick()
        self.assertTrue(second.complete)
        self.assertTrue(second.changed)
        self.assertEqual(used, [guard])
        self.assertEqual(self.rows(), [])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.backend.closed, [])

    def test_commit_before_lost_ack_is_reconciled_without_deleting_replacement(self):
        original = module.unregister_dead_infrastructure_locked
        def lost(*args):
            original(*args)
            raise sqlite3.OperationalError("fixture_commit_ack_lost")
        revision = self.runtime()["registry_revision"]
        with patch.object(module, "unregister_dead_infrastructure_locked", lost):
            self.assertTrue(self.pending.tick().pending)
        self.assertEqual(self.rows(), [])
        self.connection().execute("""INSERT INTO adaptive_infrastructure
            VALUES('helper',999,'134342315823996999',?,1)""", (base.WRAPPER.logon_id,))
        result = self.pending.tick()
        self.assertTrue(result.complete)
        self.assertEqual([row["pid"] for row in self.rows()], [999])
        self.assertEqual(self.runtime()["registry_revision"], revision + 1)

    def test_absent_exact_row_completes_without_revision_change(self):
        self.connection().execute("DELETE FROM adaptive_infrastructure")
        revision = self.runtime()["registry_revision"]
        result = self.pending.tick()
        self.assertTrue(result.complete)
        self.assertFalse(result.changed)
        self.assertEqual(self.runtime()["registry_revision"], revision)

    def test_unknown_observation_never_prepares_or_deletes(self):
        self.backend.status = IdentityStatus.UNKNOWN
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("must not prepare")):
            result = self.pending.tick()
        self.assertTrue(result.pending)
        self.assertEqual(len(self.rows()), 1)
        self.assertIsNone(self.pending.guard)

    def test_changed_nonce_quarantines_without_retry_delete(self):
        self.block_delete()
        self.pending.tick()
        changed = str(uuid4())
        self.connection().execute("UPDATE adaptive_runtime SET policy_entry_nonce=?", (changed,))
        with patch.object(module, "unregister_dead_infrastructure_locked", side_effect=AssertionError("must not retry")):
            result = self.pending.tick()
            repeated = self.pending.tick()
        self.assertTrue(result.quarantined)
        self.assertEqual(result, repeated)
        self.assertEqual(self.runtime()["policy_entry_nonce"], changed)

    def test_native_release_unknown_keeps_guard_and_permanent_quarantine(self):
        original = self.policy.hold
        @contextmanager
        def unknown_release(binding, **kwargs):
            with original(binding, **kwargs) as lease:
                yield lease
            raise RuntimeError("fixture_native_release_unknown")
        with patch.object(self.policy, "hold", unknown_release):
            first = self.pending.tick()
        self.assertTrue(first.quarantined)
        self.assertIsNotNone(self.pending.guard)
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("must not reacquire")):
            self.assertTrue(self.pending.tick().quarantined)

    def test_native_exit_interrupt_propagates_and_retains_quarantine(self):
        original = self.policy.hold
        changed = []
        interruption = KeyboardInterrupt()
        cleanup_owner = object()
        interruption._journal_cleanup_owner = cleanup_owner
        @contextmanager
        def interrupted_release(binding, **kwargs):
            with original(binding, **kwargs) as lease:
                yield lease
            # The native ownership state may already have changed when the
            # stop arrives. There is no completed release acknowledgement.
            changed.append("native_exit_entered")
            raise interruption
        with patch.object(self.policy, "hold", interrupted_release):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.pending.tick()
        self.assertIs(caught.exception, interruption)
        self.assertEqual(changed, ["native_exit_entered"])
        self.assertIs(self.pending._error, interruption)
        self.assertIs(self.pending._error._journal_cleanup_owner, cleanup_owner)
        self.assertIsNotNone(self.pending.guard)
        self.assertIn("policy_scope_cleanup_failed", interruption.__notes__)
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("must not reenter")), \
                patch.object(self.store._policy, "prepare", side_effect=AssertionError("must not prepare")):
            self.assertTrue(self.pending.tick().quarantined)

    def test_prepare_interrupt_after_commit_does_not_reconstruct_guard(self):
        original = self.store._policy.prepare
        interruption = SystemExit(2)
        def interrupted_prepare(logon):
            original(logon)
            raise interruption
        with patch.object(self.store._policy, "prepare", interrupted_prepare):
            with self.assertRaises(SystemExit) as caught:
                self.pending.tick()
        self.assertIs(caught.exception, interruption)
        self.assertIs(self.pending._error, interruption)
        self.assertIsNone(self.pending.guard)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("must not prepare")):
            result = self.pending.tick()
        self.assertTrue(result.quarantined)
        self.assertEqual(result.reason, "policy_prepare_ownership_unknown")

    def test_operation_interrupt_is_propagated_with_guard_retained(self):
        interruption = SystemExit(3)
        with patch.object(module, "unregister_dead_infrastructure_locked", side_effect=interruption):
            with self.assertRaises(SystemExit):
                self.pending.tick()
        self.assertIs(self.pending._error, interruption)
        self.assertIsNotNone(self.pending.guard)
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.pending.guard.nonce)
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("must not reenter")):
            self.assertTrue(self.pending.tick().quarantined)

    def test_nonce_clear_failure_reuses_guard_and_lost_clear_ack_reads_outcome(self):
        original = self.store._policy._clear
        with patch.object(self.store._policy, "_clear", side_effect=sqlite3.OperationalError("fixture_clear_failure")):
            first = self.pending.tick()
        self.assertTrue(first.pending)
        self.assertIsNotNone(self.pending.guard)
        self.assertTrue(self.pending.tick().complete)
        # Independent second exact row tests an ACK lost AFTER clearing nonce.
        with self.held():
            self.backend.status = IdentityStatus.ALIVE
            legacy_writer.register_infrastructure_locked(self.store, "helper", self.process)
        self.backend.status = IdentityStatus.DEAD
        second = PendingInfrastructureRetirement(self.store, role="helper", witness=self.process)
        def lost(guard):
            original(guard)
            raise sqlite3.OperationalError("fixture_clear_ack_lost")
        with patch.object(self.store._policy, "_clear", lost):
            self.assertTrue(second.tick().pending)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no fresh guard")):
            self.assertTrue(second.tick().complete)

    def test_old_clean_rejection_flag_is_reset_before_sql_retry(self):
        self.block_delete()
        self.pending.tick()
        self.pending.guard.clean_rejection = True
        self.assertTrue(self.pending.tick().pending)
        self.assertFalse(self.pending.guard.clean_rejection)
        self.assertEqual(self.runtime()["policy_entry_nonce"], self.pending.guard.nonce)

    def test_prepare_lost_ack_quarantines_without_reconstructing_guard(self):
        original = self.store._policy.prepare
        def lost(logon):
            original(logon)
            raise sqlite3.OperationalError("fixture_prepare_ack_lost")
        with patch.object(self.store._policy, "prepare", lost):
            result = self.pending.tick()
        self.assertTrue(result.quarantined)
        self.assertEqual(result.reason, "policy_prepare_ownership_unknown")
        self.assertIsNone(self.pending.guard)
        self.assertIsNotNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(len(self.rows()), 1)


class FinishedBarrierJanitorTests(unittest.TestCase):
    setUp = lifecycle.GuardianLifecycleTests.setUp
    spec = lifecycle.GuardianLifecycleTests.spec
    allocate = lifecycle.GuardianLifecycleTests.allocate
    connection = lifecycle.GuardianLifecycleTests.connection
    make_mutex = lifecycle.GuardianLifecycleTests.make_mutex
    seed_evidence = lifecycle.GuardianLifecycleTests.seed_evidence
    seed_started = lifecycle.GuardianLifecycleTests.seed_started
    start_consumer = lifecycle.GuardianLifecycleTests.start_consumer
    adopt = lifecycle.GuardianLifecycleTests.adopt
    root_exits = lifecycle.GuardianLifecycleTests.root_exits
    sql = lifecycle.GuardianLifecycleTests.sql

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def finished(self):
        case = self.adopt()
        self.root_exits(case)
        result = self.owner.reconcile(case.spec.execution_id, now=base.NOW + 10)
        self.assertEqual(result.state, "FINISHED")
        self.owner.close_terminal(case.spec.execution_id)
        runtime = self.runtime()
        # Explicit fixture for an already withdrawn cap; the production C3
        # reader still verifies every persisted binding, archive and manifest.
        self.sql("""INSERT INTO adaptive_control_slot VALUES(1,1,?,1,'RESTORED',?,?,?,?,?,?,?,?,?,0)""",
            (str(uuid4()), case.spec.execution_id, case.record.job_name, case.record.creation_nonce,
             lifecycle.EPOCH, base.WRAPPER.logon_id, case.spec.wrapper_identity.pid,
             str(case.spec.wrapper_identity.created_filetime_100ns), runtime["policy_instance_id"],
             runtime["policy_logon_id"]))
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD',registry_revision=registry_revision+1")
        return case, FinishedBarrierJanitor(self.store, self.journal)

    def audits(self):
        conn = self.connection()
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_barrier_clears'").fetchone() is None:
            return []
        return list(conn.execute("SELECT * FROM adaptive_barrier_clears"))

    def test_restart_after_finish_clears_without_native_job_and_once_only(self):
        case, janitor = self.finished()
        with patch("sentinel.adaptive.native_job.NativeJob.open", side_effect=AssertionError("no native Job")):
            first = janitor.tick(now=base.NOW + 11)
            second = janitor.tick(now=base.NOW + 12)
        self.assertTrue(first.complete)
        self.assertTrue(first.changed)
        self.assertTrue(second.complete)
        self.assertFalse(second.changed)
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assertEqual(len(self.audits()), 1)
        self.assertTrue(case.job.closed)

    def test_missing_archive_holds_without_creating_policy_nonce(self):
        case, janitor = self.finished()
        self.sql("DELETE FROM executions WHERE reservation_id=?", (case.spec.reservation.id,))
        result = janitor.tick()
        self.assertTrue(result.pending)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.audits(), [])

    def test_held_slot_or_missing_manifest_never_clears(self):
        case, janitor = self.finished()
        self.sql("UPDATE adaptive_control_slot SET slot_state='HELD'")
        self.assertTrue(janitor.tick().pending)
        self.sql("UPDATE adaptive_control_slot SET slot_state='RESTORED'")
        (self.journal_dir / (case.spec.execution_id + ".json")).unlink()
        self.assertTrue(janitor.tick().pending)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(self.runtime()["policy_entry_nonce"])

    def test_commit_lost_ack_reconciles_original_audit_with_same_guard(self):
        case, janitor = self.finished()
        original = self.store.clear_recovery_hold_finished_locked
        def lost(*args, **kwargs):
            original(*args, **kwargs)
            raise sqlite3.OperationalError("fixture_clear_ack_lost")
        with patch.object(self.store, "clear_recovery_hold_finished_locked", lost):
            first = janitor.tick(now=base.NOW + 11)
        guard = janitor.guard
        self.assertTrue(first.pending)
        self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
        with patch.object(self.store, "clear_recovery_hold_finished_locked", side_effect=AssertionError("no second clear")):
            second = janitor.tick(now=base.NOW + 12)
        self.assertTrue(second.complete)
        self.assertTrue(second.changed)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(len(self.audits()), 1)

    def test_clear_nonce_lost_ack_reconciles_audit_without_fresh_policy(self):
        case, janitor = self.finished()
        original = self.store._policy._clear
        def lost(guard):
            original(guard)
            raise sqlite3.OperationalError("fixture_nonce_ack_lost")
        with patch.object(self.store._policy, "_clear", lost):
            self.assertTrue(janitor.tick(now=base.NOW + 11).pending)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no prepare")):
            self.assertTrue(janitor.tick(now=base.NOW + 12).complete)
        self.assertEqual(len(self.audits()), 1)

    def test_missing_audit_after_lost_ack_cannot_be_mistaken_for_success(self):
        case, janitor = self.finished()
        original = self.store.clear_recovery_hold_finished_locked
        def lost(*args, **kwargs):
            original(*args, **kwargs)
            raise sqlite3.OperationalError("fixture_clear_ack_lost")
        with patch.object(self.store, "clear_recovery_hold_finished_locked", lost):
            janitor.tick(now=base.NOW + 11)
        self.sql("DELETE FROM adaptive_barrier_clears")
        result = janitor.tick(now=base.NOW + 12)
        self.assertFalse(result.complete)
        self.assertEqual(result.reason, "finished_barrier_audit_unverified")
        self.assertIsNotNone(janitor.guard)


if __name__ == "__main__":
    unittest.main()
