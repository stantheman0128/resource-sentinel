"""Isolated SQL inventory and resident recovery dispatch; no native controls."""
from contextlib import closing, contextmanager
from dataclasses import replace
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor import GuardianSupervisor
from tests import test_adaptive_guardian_lifecycle as fixture


class Recovery:
    def __init__(self, test):
        self.guardian_identity = fixture.GUARDIAN
        self.guardian_epoch = fixture.EPOCH
        row = test.connection().execute("SELECT * FROM adaptive_runtime").fetchone()
        self.binding = PolicyBinding(row["policy_instance_id"], row["policy_logon_id"])
        self.status = IdentityStatus.ALIVE
        self.journal = test.journal
        self.retained_execution_ids = ()
        self.calls, self.failures = [], {}
        self.closed = False
        self.on_observe = None

    def observe_guardian(self):
        if self.on_observe:
            self.on_observe()
        return IdentityObservation(self.guardian_identity, self.status,
            "fixture_unknown" if self.status is IdentityStatus.UNKNOWN else None)

    def restore(self, execution_id, *, creation_nonce):
        self.calls.append((execution_id, creation_nonce))
        if execution_id in self.failures:
            raise self.failures[execution_id]
        return SimpleNamespace(execution_id=execution_id, native_disabled=True, journal_settled=True)

    def close(self):
        self.closed = True


class SupervisorTests(unittest.TestCase):
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    sql = fixture.GuardianLifecycleTests.sql
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    start_consumer = fixture.GuardianLifecycleTests.start_consumer
    adopt = fixture.GuardianLifecycleTests.adopt
    root_exits = fixture.GuardianLifecycleTests.root_exits

    @contextmanager
    def ledger_locked(self):
        """A real exclusive lock: readers get SQLITE_BUSY after their own timeout.

        The ledger is WAL, where a plain writer never blocks a reader, so the
        blocker takes the database file lock itself. That needs every other
        connection closed, including the fixture's setup readers.
        """
        for connection in self.setup_connections:
            connection.close()
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as blocker:
            blocker.execute("PRAGMA locking_mode=EXCLUSIVE")
            blocker.execute("BEGIN EXCLUSIVE")
            try:
                yield
            finally:
                blocker.execute("ROLLBACK")

    def finish(self, case):
        self.adopt(case)
        self.root_exits(case)
        result = self.owner.reconcile(case.spec.execution_id, now=fixture.fixtures.NOW + 20)
        self.assertEqual(result.state, "FINISHED")
        self.owner.close_terminal(case.spec.execution_id)

    def setUp(self):
        fixture.GuardianLifecycleTests.setUp(self)
        self.case = self.seed_started()
        self.store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        self.recovery = Recovery(self)
        self.supervisor = GuardianSupervisor(self.store, self.recovery)

    def test_alive_refreshes_without_restore_and_dead_dispatches_exact_scope(self):
        first = self.supervisor.tick()
        self.assertTrue(first.inventory_verified)
        self.assertEqual(first.guardian_status, IdentityStatus.ALIVE)
        self.assertEqual(self.recovery.calls, [])
        before = list(self.connection().execute("SELECT * FROM reservations").fetchall())
        self.recovery.status = IdentityStatus.DEAD
        second = self.supervisor.tick()
        self.assertEqual(second.restored_executions, (self.case.spec.execution_id,))
        self.assertEqual(self.recovery.calls, [(self.case.spec.execution_id, self.case.record.creation_nonce)])
        self.assertEqual(list(self.connection().execute("SELECT * FROM reservations").fetchall()), before)
        self.assertEqual(self.connection().execute("SELECT state FROM managed_executions").fetchone()[0], "RUNNING")
        self.assertFalse(self.recovery.closed)

    def test_unknown_guardian_never_attempts_restore(self):
        self.recovery.status = IdentityStatus.UNKNOWN
        result = self.supervisor.tick()
        self.assertEqual(result.unresolved_executions, (self.case.spec.execution_id,))
        self.assertEqual(self.recovery.calls, [])

    def test_new_registered_scope_is_discovered_before_dead_dispatch(self):
        self.supervisor.tick()
        second = self.seed_started()
        self.recovery.status = IdentityStatus.DEAD
        result = self.supervisor.tick()
        self.assertEqual(set(result.restored_executions), {self.case.spec.execution_id, second.spec.execution_id})

    def test_db_unavailable_still_restores_cached_scopes_without_inventory_claim(self):
        self.supervisor.tick()
        self.recovery.status = IdentityStatus.DEAD
        with self.ledger_locked():
            result = self.supervisor.tick()
        self.assertFalse(result.inventory_verified)
        self.assertEqual(result.inventory_error, "supervisor_inventory_unverified")
        self.assertEqual(result.restored_executions, (self.case.spec.execution_id,))
        self.assertEqual(self.supervisor.retained_execution_ids, (self.case.spec.execution_id,))

    def test_first_db_failure_cannot_claim_empty_complete_inventory(self):
        self.recovery.status = IdentityStatus.DEAD
        with self.ledger_locked():
            result = self.supervisor.tick()
        self.assertFalse(result.inventory_verified)
        self.assertEqual(result.restored_executions, ())
        self.assertEqual(self.recovery.calls, [])

    def test_real_busy_is_retried_but_a_readable_schema_contradiction_is_sticky(self):
        self.supervisor.tick()
        with self.ledger_locked():
            self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertTrue(self.supervisor.tick().inventory_verified)
        self.sql("ALTER TABLE adaptive_control_slot RENAME TO adaptive_control_slot_moved")
        self.recovery.status = IdentityStatus.DEAD
        self.assertFalse(self.supervisor.tick().inventory_verified)
        self.sql("ALTER TABLE adaptive_control_slot_moved RENAME TO adaptive_control_slot")
        self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_untyped_operational_error_is_not_accepted_as_unavailability(self):
        self.supervisor.tick()
        self.recovery.status = IdentityStatus.DEAD
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("busy")):
            self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_readable_binding_change_is_sticky_even_if_later_unavailable(self):
        self.supervisor.tick()
        self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
        self.recovery.status = IdentityStatus.DEAD
        self.assertFalse(self.supervisor.tick().inventory_verified)
        with patch.object(self.store, "_connection", side_effect=AssertionError("must not reread")):
            self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_readable_invalid_protocol_is_not_db_unavailability(self):
        self.supervisor.tick()
        self.sql("UPDATE adaptive_runtime SET protocol_version=999")
        self.recovery.status = IdentityStatus.DEAD
        self.assertFalse(self.supervisor.tick().inventory_verified)
        self.sql("UPDATE adaptive_runtime SET protocol_version=1")
        self.assertFalse(self.supervisor.tick().inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_oversized_job_metadata_is_rejected_without_native_restore(self):
        self.supervisor.tick()
        self.sql("UPDATE managed_executions SET job_name=?", ("x" * 8192,))
        self.recovery.status = IdentityStatus.DEAD
        result = self.supervisor.tick()
        self.assertFalse(result.inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_inventory_overflow_does_not_claim_complete_or_drop_cached_scope(self):
        self.supervisor.tick()
        # Exercise the exact overflow failure after a known inventory. The
        # database producer separately enforces its own registration bound.
        self.recovery.status = IdentityStatus.DEAD
        with patch.object(self.supervisor, "_read_inventory", side_effect=
                LifecycleError("supervisor_inventory_bound_exceeded")):
            result = self.supervisor.tick()
        self.assertFalse(result.inventory_verified)
        self.assertEqual(result.known_executions, (self.case.spec.execution_id,))
        self.assertEqual(result.restored_executions, (self.case.spec.execution_id,))

    def test_more_than_ten_sequential_finished_jobs_do_not_consume_the_concurrent_bound(self):
        self.finish(self.case)
        for _ in range(11):
            self.finish(self.seed_started())
        live = self.seed_started()
        result = self.supervisor.tick()
        self.assertTrue(result.inventory_verified)
        self.assertEqual(result.known_executions, (live.spec.execution_id,))
        self.recovery.status = IdentityStatus.DEAD
        self.assertEqual(self.supervisor.tick().restored_executions, (live.spec.execution_id,))

    def test_known_scope_retires_only_after_formal_finalization_evidence(self):
        self.supervisor.tick()
        self.finish(self.case)
        result = self.supervisor.tick()
        self.assertEqual((result.inventory_verified, result.known_executions), (True, ()))
        self.supervisor.close()
        self.assertTrue(self.recovery.closed)

    def test_finished_state_without_archive_or_settled_manifest_stays_an_obligation(self):
        execution = self.case.spec.execution_id
        self.supervisor.tick()
        # SQL state alone, as a bare writer or a corrupt row would leave it.
        self.sql("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?", (execution,))
        result = self.supervisor.tick()
        self.assertEqual((result.inventory_verified, result.known_executions), (True, (execution,)))
        self.recovery.status = IdentityStatus.DEAD
        self.assertEqual(self.supervisor.tick().restored_executions, (execution,))
        with self.assertRaisesRegex(LifecycleError, "supervisor_custody_unsettled"):
            self.supervisor.close()

    def test_real_busy_inside_the_retirement_proof_is_retried_not_sticky(self):
        execution = self.case.spec.execution_id
        self.supervisor.tick()
        self.finish(self.case)
        # finish() starts the guardian consumer, which rebinds self.store.
        store = self.supervisor.store
        query = store.query

        def locked(execution_id):
            # The store reports this lock under its own sanitized reason.
            with self.ledger_locked():
                return query(execution_id)

        with patch.object(store, "query", side_effect=locked):
            busy = self.supervisor.tick()
        self.assertEqual((busy.inventory_verified, busy.known_executions), (False, (execution,)))
        self.assertEqual(str(self.supervisor._inventory_error), "coverage_database_busy")
        result = self.supervisor.tick()
        self.assertEqual((result.inventory_verified, result.known_executions), (True, ()))
        self.supervisor.close()

    def test_held_terminal_scope_retires_once_its_evidence_completes(self):
        execution = self.case.spec.execution_id
        self.supervisor.tick()
        self.finish(self.case)
        with patch.object(self.supervisor.store, "assert_retained_terminal",
                          side_effect=LifecycleError("fixture_refusal")):
            held = self.supervisor.tick()
        self.assertEqual((held.inventory_verified, held.known_executions), (True, (execution,)))
        result = self.supervisor.tick()
        self.assertEqual((result.inventory_verified, result.known_executions), (True, ()))
        self.supervisor.close()

    def test_unproven_history_found_at_attach_is_held_not_skipped(self):
        other = self.seed_started()
        self.sql("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?",
                 (other.spec.execution_id,))
        result = self.supervisor.tick()
        self.assertTrue(result.inventory_verified)
        self.assertEqual(set(result.known_executions), {self.case.spec.execution_id, other.spec.execution_id})

    def test_long_history_is_paged_and_unverified_until_fully_read(self):
        self.finish(self.case)
        for _ in range(17):
            self.finish(self.seed_started())
        first = self.supervisor.tick()
        self.assertEqual((first.inventory_verified, first.known_executions), (False, ()))
        second = self.supervisor.tick()
        self.assertEqual((second.inventory_verified, second.known_executions), (True, ()))

    def test_changed_scope_not_replaced_or_restored(self):
        self.supervisor.tick()
        self.sql("UPDATE managed_executions SET job_nonce=?", (uuid4().hex,))
        self.recovery.status = IdentityStatus.DEAD
        result = self.supervisor.tick()
        self.assertFalse(result.inventory_verified)
        self.assertEqual(result.unresolved_executions, (self.case.spec.execution_id,))
        self.assertEqual(self.recovery.calls, [])

    def test_missing_prior_scope_remains_owned_and_sticky(self):
        self.supervisor.tick()
        self.sql("UPDATE managed_executions SET job_name=NULL")
        self.recovery.status = IdentityStatus.DEAD
        result = self.supervisor.tick()
        self.assertEqual(result.known_executions, (self.case.spec.execution_id,))
        self.assertFalse(result.inventory_verified)
        self.assertEqual(self.recovery.calls, [])

    def test_one_failure_does_not_strand_later_job_and_retry_preserves_owner(self):
        second = self.seed_started()
        self.recovery.status = IdentityStatus.DEAD
        original = RuntimeError("restore uncertainty")
        self.recovery.failures[self.case.spec.execution_id] = original
        result = self.supervisor.tick()
        self.assertEqual(result.unresolved_executions, (self.case.spec.execution_id,))
        self.assertEqual(result.restored_executions, (second.spec.execution_id,))
        self.assertIs(self.supervisor.errors[0][1], original)
        self.recovery.failures.clear()
        result = self.supervisor.tick()
        self.assertEqual(set(result.restored_executions), {self.case.spec.execution_id, second.spec.execution_id})
        self.assertEqual(self.supervisor.errors, ())

    def test_restore_success_never_allows_supervisor_to_discard_live_obligations(self):
        self.recovery.status = IdentityStatus.DEAD
        self.supervisor.tick()
        with self.assertRaisesRegex(LifecycleError, "supervisor_custody_unsettled"):
            self.supervisor.close()
        self.assertFalse(self.recovery.closed)

    def test_wrong_observation_identity_rejected(self):
        observation = IdentityObservation(replace(fixture.GUARDIAN, pid=fixture.GUARDIAN.pid + 1), IdentityStatus.DEAD)
        with patch.object(self.recovery, "observe_guardian", return_value=observation):
            with self.assertRaisesRegex(LifecycleError, "supervisor_guardian_observation_invalid"):
                self.supervisor.tick()
        self.assertEqual(self.recovery.calls, [])

    def test_attach_failure_retains_same_recovery_owner(self):
        with patch("sentinel.adaptive.supervisor.RecoveryOwner.capture", return_value=self.recovery):
            with self.ledger_locked():
                with self.assertRaises(sqlite3.OperationalError) as caught:
                    GuardianSupervisor.attach(self.store, self.journal,
                        guardian=self.guardian, guardian_epoch=fixture.EPOCH)
        self.assertEqual(caught.exception.sqlite_errorcode & 0xFF, sqlite3.SQLITE_BUSY)
        retained = caught.exception.supervisor_owner
        self.assertIs(retained.recovery, self.recovery)
        self.assertFalse(self.recovery.closed)
        self.recovery.status = IdentityStatus.DEAD
        self.assertEqual(retained.tick().restored_executions, (self.case.spec.execution_id,))

    def test_unsettled_or_wrong_restore_ack_not_reported_as_restored(self):
        self.recovery.status = IdentityStatus.DEAD
        with patch.object(self.recovery, "restore", return_value=SimpleNamespace(
                execution_id=self.case.spec.execution_id, native_disabled=True, journal_settled=False)):
            result = self.supervisor.tick()
        self.assertEqual(result.restored_executions, ())
        self.assertEqual(result.unresolved_executions, (self.case.spec.execution_id,))


if __name__ == "__main__":
    unittest.main()
