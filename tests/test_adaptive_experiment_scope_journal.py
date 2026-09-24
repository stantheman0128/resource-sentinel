"""Real isolated SQLite, synthetic POLICY: these tests prove no native gate."""
from contextlib import contextmanager
import copy
from pathlib import Path
import sqlite3
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.experiment_scope_journal import (
    DISABLED, S1_CAP, TABLE, ScopeJournal, ScopeJournalError,
)
from sentinel.adaptive.native_job import CpuState
from sentinel.adaptive.policy import PolicyError
from tests import test_adaptive_lifecycle as lifecycle


GUARDIAN = lifecycle.WRAPPER
WRAPPER = ProcessIdentity(201, GUARDIAN.created_filetime_100ns + 5, GUARDIAN.logon_id)
ROOT = ProcessIdentity(301, GUARDIAN.created_filetime_100ns + 10, GUARDIAN.logon_id)


class ScopeJournalTests(unittest.TestCase):
    def setUp(self):
        self.fixture = lifecycle.AdaptiveLifecycleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.store = self.fixture.store
        self.scope_id = str(uuid4())
        self.journal = ScopeJournal(self.store, self.scope_id)
        ledger = Path(self.store.db_path).stat()
        nonce = uuid4().hex
        self.binding = dict(schema_version=1, experiment_id=str(uuid4()),
            scope_id=self.scope_id, daily_execution_id=str(uuid4()),
            reservation_id=str(uuid4()), isolated_ledger_identity=[ledger.st_dev, ledger.st_ino],
            job_name="Local\\ResourceSentinel.Test.Job." + nonce, creation_nonce=nonce,
            guardian_identity=GUARDIAN.to_dict(), wrapper_identity=WRAPPER.to_dict(),
            command_sha256="a" * 64, source_generation=str(uuid4()),
            source_digest="b" * 64, config_digest="c" * 64,
            deadline_monotonic_ns=120_000_000_000)

    @contextmanager
    def locked(self):
        guard = self.store._policy.prepare(GUARDIAN.logon_id)
        with self.store._policy.hold(guard):
            with self.store._transaction() as conn:
                yield conn

    def initialized(self):
        with self.locked() as conn:
            return self.journal.initialize_locked(conn, self.binding)

    def running(self, conn):
        self.journal.initialize_locked(conn, self.binding)
        self.journal.begin_launch_locked(conn)
        self.journal.acknowledge_launch_locked(conn, ROOT)
        return self.journal.seal_launch_locked(conn, "started")

    def test_initialization_is_pinned_and_never_allocates_capacity(self):
        with self.locked() as conn:
            before = {table: conn.execute("SELECT count(*) FROM " + table).fetchone()[0]
                for table in ("reservations", "worker_reservations", "managed_executions", "adaptive_control_slot")}
            row = self.journal.initialize_locked(conn, self.binding)
            self.assertEqual(row["state"], "PREPARED")
            self.assertEqual(row["revision"], 0)
            self.assertIsNone(row["last_applied_cpu"])
            self.assertEqual(row["original_cpu"], dict(flags=0, rate_bp=0))
            self.assertEqual(row, self.journal.initialize_locked(conn, copy.deepcopy(self.binding)))
            after = {table: conn.execute("SELECT count(*) FROM " + table).fetchone()[0] for table in before}
            self.assertEqual(before, after)
            self.assertEqual(conn.execute("SELECT mode FROM adaptive_runtime").fetchone()[0], "off")

    def test_transaction_and_actual_store_policy_are_required(self):
        with self.store._connection() as conn:
            with self.assertRaisesRegex(ScopeJournalError, "transaction_required"):
                self.journal.initialize_locked(conn, self.binding)
        with self.store._transaction() as conn:
            with self.assertRaisesRegex(PolicyError, "scope_not_held"):
                self.journal.initialize_locked(conn, self.binding)

    def test_another_ledger_cannot_borrow_the_held_policy(self):
        self.initialized()
        with self.locked():
            foreign = sqlite3.connect(":memory:", isolation_level=None)
            self.addCleanup(foreign.close)
            foreign.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(ScopeJournalError, "ledger_changed"):
                self.journal.read_locked(foreign)
            foreign.rollback()

    def test_attached_ledger_is_rejected(self):
        self.initialized()
        with self.locked() as conn:
            conn.execute("ATTACH DATABASE ':memory:' AS extra")
            with self.assertRaisesRegex(ScopeJournalError, "ledger_changed"):
                self.journal.read_locked(conn)

    def test_existing_schema_is_validated_even_when_empty(self):
        with self.locked() as conn:
            conn.execute("CREATE TABLE " + TABLE + " (scope_id TEXT PRIMARY KEY)")
        with self.locked() as conn:
            with self.assertRaisesRegex(ScopeJournalError, "schema_unknown"):
                self.journal.initialize_locked(conn, self.binding)

    def test_orphan_guard_cannot_be_repaired_by_initialization(self):
        with self.locked() as conn:
            conn.execute("CREATE TABLE experiment_scope_journal_unknown (value TEXT)")
            with self.assertRaisesRegex(ScopeJournalError, "schema_unknown"):
                self.journal.initialize_locked(conn, self.binding)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone())

    def test_missing_or_extra_guard_is_unknown(self):
        self.initialized()
        with self.locked() as conn:
            conn.execute("DROP TRIGGER experiment_scope_journal_delete_guard")
            with self.assertRaisesRegex(ScopeJournalError, "schema_unknown"):
                self.journal.read_locked(conn)

    def test_binding_replay_cannot_swap_original_actors_or_deadline(self):
        self.initialized()
        for key, value in (("deadline_monotonic_ns", 121_000_000_000),
                ("command_sha256", "d" * 64), ("reservation_id", "different")):
            with self.subTest(key=key), self.locked() as conn:
                changed = dict(self.binding, **{key: value})
                with self.assertRaisesRegex(ScopeJournalError, "binding_mismatch"):
                    self.journal.initialize_locked(conn, changed)

    def test_binding_rejects_noncanonical_or_conflated_identities(self):
        changes = [dict(schema_version=True), dict(scope_id="not-a-uuid"),
            dict(job_name="Local\\ResourceSentinel.Job." + self.scope_id),
            dict(guardian_identity=WRAPPER.to_dict()),
            dict(wrapper_identity=ProcessIdentity(201, 123, "S-1-5-5-9-9").to_dict()),
            dict(creation_nonce="z" * 32), dict(deadline_monotonic_ns=True),
            dict(isolated_ledger_identity=[True, 2])]
        for changed in changes:
            with self.subTest(changed=changed), self.locked() as conn:
                with self.assertRaises(ScopeJournalError):
                    self.journal.initialize_locked(conn, dict(self.binding, **changed))

    def test_direct_binding_mutation_or_delete_is_fenced(self):
        self.initialized()
        with self.locked() as conn:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE " + TABLE + " SET binding_json='{}',revision=revision+1")
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM " + TABLE)

    def test_launch_intent_precedes_root_and_unknown_never_implies_no_launch(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            with self.assertRaisesRegex(ScopeJournalError, "launch_unavailable"):
                self.journal.acknowledge_launch_locked(conn, ROOT)
            self.assertEqual(self.journal.begin_launch_locked(conn)["state"], "LAUNCH_INTENT")
            self.assertEqual(self.journal.mark_launch_unknown_locked(conn)["state"], "LAUNCH_UNKNOWN")
            with self.assertRaisesRegex(ScopeJournalError, "seal_unavailable"):
                self.journal.seal_launch_locked(conn, "never_launched")
            with self.assertRaisesRegex(ScopeJournalError, "launch_unavailable"):
                self.journal.begin_launch_locked(conn)
            row = self.journal.acknowledge_launch_locked(conn, ROOT)
            self.assertEqual(row["state"], "RUNNING")
            self.assertEqual(row["root"], ROOT.to_dict())

    def test_root_must_be_distinct_and_in_original_logon(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_launch_locked(conn)
            for root in (GUARDIAN, WRAPPER, ProcessIdentity(301, 123, "S-1-5-5-4-5")):
                with self.subTest(root=root), self.assertRaisesRegex(ScopeJournalError, "identity_invalid"):
                    self.journal.acknowledge_launch_locked(conn, root)

    def test_seal_is_irreversible_and_empty_completion_is_test_specific(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_control_locked(conn, S1_CAP)
            self.journal.acknowledge_control_locked(conn, S1_CAP)
            self.journal.begin_restore_locked(conn, S1_CAP)
            restored = self.journal.acknowledge_control_locked(conn, DISABLED)
            self.assertEqual(restored["last_applied_cpu"], dict(flags=0, rate_bp=0))
            self.journal.seal_launch_locked(conn, "never_launched")
            with self.assertRaisesRegex(ScopeJournalError, "launch_unavailable"):
                self.journal.begin_launch_locked(conn)
            with self.assertRaisesRegex(ScopeJournalError, "finish_invalid"):
                self.journal.finish_locked(conn, None, 1)
            row = self.journal.finish_locked(conn, None, 0)
            self.assertEqual(row["state"], "NEVER_LAUNCHED")
            self.assertEqual(row["last_applied_cpu"], dict(flags=0, rate_bp=0))
            self.assertEqual(row, self.journal.seal_launch_locked(conn, "never_launched"))
            self.assertEqual(row, self.journal.finish_locked(conn, None, 0))
            self.assertEqual(conn.execute("SELECT count(*) FROM managed_executions").fetchone()[0], 0)

    def test_control_is_only_disabled_or_s1_hard_cap(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            for target in (CpuState(5, 2000), CpuState(1, 2500), CpuState(9, 2500),
                    CpuState(True, 2500), CpuState(5, True), CpuState(-1, 0)):
                with self.subTest(target=target), self.assertRaises(ScopeJournalError):
                    self.journal.begin_control_locked(conn, target)
            self.assertEqual(self.journal.read_locked(conn)["revision"], 0)

    def test_pending_set_is_not_acknowledged_by_a_different_query(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_control_locked(conn, S1_CAP)
            with self.assertRaisesRegex(ScopeJournalError, "control_ack_mismatch"):
                self.journal.acknowledge_control_locked(conn, DISABLED)
            with self.assertRaisesRegex(ScopeJournalError, "intent_pending"):
                self.journal.begin_control_locked(conn, DISABLED)
            self.assertEqual(self.journal.read_locked(conn)["pending_target_cpu"], dict(flags=5, rate_bp=2500))

    def test_pending_set_can_restore_from_either_actual_possible_native_state(self):
        for observed in (DISABLED, S1_CAP):
            with self.subTest(observed=observed), self.locked() as conn:
                self.journal.initialize_locked(conn, self.binding)
                self.journal.begin_control_locked(conn, S1_CAP)
                restored = self.journal.begin_restore_locked(conn, observed)
                self.assertEqual(restored["pending_target_cpu"], dict(flags=0, rate_bp=0))
                self.journal.acknowledge_control_locked(conn, DISABLED)

    def test_restore_refuses_external_cpu_state_without_overwriting_pending_intent(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            before = self.journal.begin_control_locked(conn, S1_CAP)
            with self.assertRaisesRegex(ScopeJournalError, "cpu_state_external"):
                self.journal.begin_restore_locked(conn, CpuState(5, 5000))
            self.assertEqual(before, self.journal.read_locked(conn))

    def test_unexplained_cap_cannot_be_adopted_for_restore(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            with self.assertRaisesRegex(ScopeJournalError, "restore_conflict"):
                self.journal.begin_restore_locked(conn, S1_CAP)

    def test_disabled_native_union_is_normalized_but_enabled_unknown_is_not(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_restore_locked(conn, CpuState(4, 0xFFFFFFFF))
            row = self.journal.acknowledge_control_locked(conn, CpuState(0, 12345))
            self.assertEqual(row["last_applied_cpu"], dict(flags=0, rate_bp=0))

    def test_lost_intent_commit_ack_is_reconciled_without_replacing_intent(self):
        self.initialized()
        with self.locked() as conn:
            saved = self.journal.begin_control_locked(conn, S1_CAP)
        with self.locked() as conn:
            replay = self.journal.begin_control_locked(conn, S1_CAP)
            self.assertEqual(saved, replay)
            settled = self.journal.acknowledge_control_locked(conn, S1_CAP)
        with self.locked() as conn:
            self.assertEqual(settled, self.journal.acknowledge_control_locked(conn, S1_CAP))

    def test_stale_revision_cannot_advance_launch_or_control(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_control_locked(conn, S1_CAP, expected_revision=0)
            with self.assertRaisesRegex(ScopeJournalError, "revision_conflict"):
                self.journal.acknowledge_control_locked(conn, S1_CAP, expected_revision=0)
            with self.assertRaisesRegex(ScopeJournalError, "revision_conflict"):
                self.journal.begin_restore_locked(conn, S1_CAP, expected_revision=True)

    def test_finish_requires_sealed_launch_exact_root_exit_and_settled_cpu(self):
        with self.locked() as conn:
            self.running(conn)
            self.journal.begin_control_locked(conn, S1_CAP)
            with self.assertRaisesRegex(ScopeJournalError, "finish_unsettled"):
                self.journal.finish_locked(conn, 0, 1)
            self.journal.acknowledge_control_locked(conn, S1_CAP)
            with self.assertRaisesRegex(ScopeJournalError, "finish_unsettled"):
                self.journal.finish_locked(conn, 0, 1)
            self.journal.begin_restore_locked(conn, S1_CAP)
            self.journal.acknowledge_control_locked(conn, DISABLED)
            for exit_code, total in ((None, 1), (0, 0), (True, 1), (0, True), (-1, 1)):
                with self.subTest(exit_code=exit_code, total=total), self.assertRaises(ScopeJournalError):
                    self.journal.finish_locked(conn, exit_code, total)
            row = self.journal.finish_locked(conn, 0, 4)
            self.assertEqual((row["state"], row["total_processes"]), ("FINISHED", 4))
            self.assertEqual(row, self.journal.begin_restore_locked(conn, DISABLED))
            self.assertEqual(row, self.journal.acknowledge_control_locked(conn, DISABLED))
            self.assertEqual(row, self.journal.seal_launch_locked(conn, "started"))
            self.assertEqual(row, self.journal.finish_locked(conn, 0, 4))
            with self.assertRaisesRegex(ScopeJournalError, "finish_invalid"):
                self.journal.finish_locked(conn, 0, 3)
            with self.assertRaisesRegex(ScopeJournalError, "control_unavailable"):
                self.journal.begin_control_locked(conn, S1_CAP)
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE " + TABLE + " SET revision=revision+1")

    def test_pending_restore_survives_scope_reconstruction_without_authority(self):
        self.initialized()
        with self.locked() as conn:
            self.journal.begin_control_locked(conn, S1_CAP)
            self.journal.begin_restore_locked(conn, S1_CAP)
        bookkeeping_only = ScopeJournal(self.store, self.scope_id)
        with self.locked() as conn:
            row = bookkeeping_only.read_locked(conn)
            self.assertEqual(row["pending_target_cpu"], dict(flags=0, rate_bp=0))
            self.assertEqual(row["last_applied_cpu"], dict(flags=5, rate_bp=2500))
            self.assertEqual(row["state"], "PREPARED")
            # Restore intent committed, but native Disable never ran. The
            # previous unacknowledged cap remains recoverable by its owner.
            self.assertEqual(row, bookkeeping_only.begin_restore_locked(conn, S1_CAP))
            self.assertEqual(bookkeeping_only.acknowledge_control_locked(conn, DISABLED)["last_applied_cpu"],
                             dict(flags=0, rate_bp=0))
        self.assertFalse(hasattr(bookkeeping_only, "release_capacity"))

    def test_untouched_empty_terminal_restore_is_idempotent_without_inventing_write(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.seal_launch_locked(conn, "never_launched")
            row = self.journal.finish_locked(conn, None, 0)
            self.assertIsNone(row["last_applied_cpu"])
            self.assertEqual(row, self.journal.begin_restore_locked(conn, DISABLED))
            self.assertEqual(row, self.journal.acknowledge_control_locked(conn, DISABLED))
            self.assertIsNone(self.journal.read_locked(conn)["last_applied_cpu"])

    def uncreated_after_intent(self, *, unknown):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            self.journal.begin_launch_locked(conn)
            if unknown:
                self.journal.mark_launch_unknown_locked(conn)
            sealed = self.journal.seal_uncreated_locked(conn)
            self.assertEqual((sealed["state"], sealed["launch_sealed"]), ("SEALED_UNCREATED", 1))
            self.assertIsNone(sealed["root"])
            self.assertEqual(sealed, self.journal.seal_uncreated_locked(conn))
            self.assertEqual(sealed, self.journal.seal_launch_locked(conn, "never_launched"))
            for operation in (lambda: self.journal.begin_launch_locked(conn),
                    lambda: self.journal.acknowledge_launch_locked(conn, ROOT),
                    lambda: self.journal.begin_control_locked(conn, S1_CAP)):
                with self.assertRaises(ScopeJournalError):
                    operation()
            for exit_code, total in ((0, 0), (None, 1)):
                with self.assertRaisesRegex(ScopeJournalError, "finish_invalid"):
                    self.journal.finish_locked(conn, exit_code, total)
            terminal = self.journal.finish_locked(conn, None, 0)
            self.assertEqual(terminal["state"], "NEVER_LAUNCHED")
            self.assertEqual(terminal, self.journal.seal_uncreated_locked(conn))
            self.assertEqual(conn.execute("SELECT count(*) FROM managed_executions").fetchone()[0], 0)

    def test_positive_no_dispatch_can_seal_committed_launch_intent_without_reset(self):
        self.uncreated_after_intent(unknown=False)

    def test_positive_no_creation_can_seal_unknown_launch_without_relaunch(self):
        self.uncreated_after_intent(unknown=True)

    def test_uncreated_seal_rejects_pending_control_and_requires_restore_before_finish(self):
        with self.locked() as conn:
            self.journal.initialize_locked(conn, self.binding)
            pending = self.journal.begin_control_locked(conn, S1_CAP)
            with self.assertRaisesRegex(ScopeJournalError, "uncreated_seal_unavailable"):
                self.journal.seal_uncreated_locked(conn)
            self.assertEqual(pending, self.journal.read_locked(conn))
            self.journal.acknowledge_control_locked(conn, S1_CAP)
            sealed = self.journal.seal_uncreated_locked(conn)
            self.assertEqual(sealed["state"], "SEALED_UNCREATED")
            with self.assertRaisesRegex(ScopeJournalError, "finish_unsettled"):
                self.journal.finish_locked(conn, None, 0)
            self.journal.begin_restore_locked(conn, S1_CAP)
            self.journal.acknowledge_control_locked(conn, DISABLED)
            self.assertEqual(self.journal.finish_locked(conn, None, 0)["state"], "NEVER_LAUNCHED")

    def test_running_root_and_stale_revision_cannot_use_uncreated_seal(self):
        with self.locked() as conn:
            row = self.running(conn)
            with self.assertRaisesRegex(ScopeJournalError, "uncreated_seal_unavailable"):
                self.journal.seal_uncreated_locked(conn)
            with self.assertRaisesRegex(ScopeJournalError, "revision_conflict"):
                self.journal.seal_uncreated_locked(conn, expected_revision=row["revision"] - 1)
            self.assertEqual(row, self.journal.read_locked(conn))


if __name__ == "__main__":
    unittest.main()
