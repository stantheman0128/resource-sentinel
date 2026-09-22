"""Terminal cleanup over real isolated ledgers and explicit native fixtures.

VerifiedProcess is the production retained owner over a synthetic backend.
Jobs and mutexes are synthetic; these tests make no Windows capability, native
timing, control-effect, or deployed drain claim.
"""
from contextlib import ExitStack
import unittest
from unittest.mock import patch

from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive.native_job import NativeJobError
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.windows import NativePolicyMutexError
from tests import test_adaptive_guardian_lifecycle as fixture
from tests import test_adaptive_guardian_control as control_fixture


class TerminalCustodyTests(unittest.TestCase):
    # Reuse fixture methods, never inherit another module's test cases.
    setUp = fixture.GuardianLifecycleTests.setUp
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    start_consumer = fixture.GuardianLifecycleTests.start_consumer
    adopt = fixture.GuardianLifecycleTests.adopt
    row = fixture.GuardianLifecycleTests.row
    allocation = fixture.GuardianLifecycleTests.allocation
    root_exits = fixture.GuardianLifecycleTests.root_exits
    rewrite_manifest = fixture.GuardianLifecycleTests.rewrite_manifest
    sql = fixture.GuardianLifecycleTests.sql

    def finished_case(self):
        case = self.adopt()
        self.root_exits(case)
        result = self.owner.reconcile(case.spec.execution_id, now=fixture.fixtures.NOW + 10)
        self.assertTrue(result.terminal)
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        case.root_handle, case.wrapper_handle = case.root._handle, case.wrapper._handle
        case.retained = self.owner._entry(case.spec.execution_id)
        return case

    def retire(self, case):
        return self.owner.retire_terminal(case.spec.execution_id, now=fixture.fixtures.NOW + 11)

    def forbid_native_reentry(self, case):
        stack = ExitStack()
        stack.enter_context(patch.object(case.job, "_query",
            side_effect=AssertionError("terminal cleanup queried a possibly closed Job")))
        stack.enter_context(patch.object(case.retained.mutex, "acquire",
            side_effect=AssertionError("terminal cleanup reacquired its Job mutex")))
        stack.enter_context(patch.object(self.owner, "reconcile",
            side_effect=AssertionError("terminal cleanup restarted normal reconciliation")))
        return stack

    def process_closes(self, handle):
        return self.processes.events.count(("close", handle))

    def assert_no_close(self, case):
        self.assertEqual(self.process_closes(case.root_handle), 0)
        self.assertEqual(self.process_closes(case.wrapper_handle), 0)
        self.assertEqual(case.job.close_calls, 0)
        self.assertFalse(case.retained.mutex.closed)

    def assert_unfinished(self, result, case):
        self.assertFalse(result.complete)
        self.assertTrue(result.pending or result.quarantined)
        self.assertTrue(result.reason)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def block_wrapper_close(self, case):
        native = self.processes.entry(case.wrapper)
        native.close_error = IdentityUnavailable("process_handle_close_failed", 5)
        result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertTrue(result.pending)
        self.assertFalse(result.quarantined)
        self.assertTrue(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assertEqual(set(result.closed_owners), {"root"})
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)
        return native

    def test_finished_without_control_episode_leaves_retained_inventory(self):
        case = self.finished_case()
        archive = dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone())
        manifest = (self.journal_dir / (case.spec.execution_id + ".json")).read_bytes()
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        result = self.retire(case)
        self.assertTrue(result.complete)
        self.assertFalse(result.pending)
        self.assertFalse(result.quarantined)
        self.assertEqual(set(result.closed_owners), {"root", "wrapper", "job", "mutex"})
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)
        self.assertEqual(case.job.close_calls, 1)
        self.assertTrue(case.retained.mutex.closed)
        self.assertEqual(dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone()), archive)
        self.assertEqual((self.journal_dir / (case.spec.execution_id + ".json")).read_bytes(), manifest)

    def test_unrelated_no_slot_hold_is_preserved_when_cleanup_completes(self):
        case = self.finished_case()
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        result = self.retire(case)
        self.assertTrue(result.complete)
        runtime = self.connection().execute("SELECT * FROM adaptive_runtime").fetchone()
        self.assertEqual(runtime["admission_barrier"], "RECOVERY_HOLD")
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_known_process_close_failure_retries_original_owner_without_native_reentry(self):
        case = self.finished_case()
        native = self.block_wrapper_close(case)
        root_owner, wrapper_owner = case.root, case.wrapper
        native.close_error = None
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assertTrue(result.complete)
        self.assertIs(case.retained.root, root_owner)
        self.assertIs(case.retained.wrapper, wrapper_owner)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 2)
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(set(result.closed_owners), {"root", "wrapper", "job", "mutex"})

    def test_known_job_close_failure_retries_only_remaining_original_owners(self):
        case = self.finished_case()
        failure = NativeJobError("job_handle_close_failed", 5)
        failure._known_native_close_failed = True
        case.job.close_error = failure
        first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.pending)
        self.assertFalse(first.quarantined)
        self.assertEqual(set(first.closed_owners), {"root", "wrapper"})
        self.assertTrue(self.owner.terminal_cleanup_started(case.spec.execution_id))
        case.job.close_error = None
        with self.forbid_native_reentry(case):
            final = self.retire(case)
        self.assertTrue(final.complete)
        self.assertIs(case.retained.job, case.job)
        self.assertEqual(case.job.close_calls, 2)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)

    def test_known_mutex_close_failure_never_reacquires_or_recloses_tombstoned_owners(self):
        case = self.finished_case()
        mutex = case.retained.mutex
        original_close = mutex.close
        attempts = []
        fail = True

        def close_mutex():
            attempts.append(mutex)
            if fail:
                raise NativePolicyMutexError("policy_mutex_handle_close_failed", 5)
            original_close()

        with patch.object(mutex, "close", close_mutex):
            first = self.retire(case)
            self.assert_unfinished(first, case)
            self.assertFalse(first.quarantined)
            self.assertEqual(set(first.closed_owners), {"root", "wrapper", "job"})
            fail = False
            with self.forbid_native_reentry(case):
                final = self.retire(case)
        self.assertTrue(final.complete)
        self.assertEqual(attempts, [mutex, mutex])
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)

    def test_ambiguous_job_close_quarantines_locator_and_all_later_native_cleanup(self):
        case = self.finished_case()
        case.job.close_error = OSError("synthetic unknown close outcome")
        first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.quarantined)
        self.assertTrue(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assertEqual(set(first.closed_owners), {"root", "wrapper"})
        case.job.close_error = None
        with self.forbid_native_reentry(case):
            second = self.retire(case)
        self.assert_unfinished(second, case)
        self.assertTrue(second.quarantined)
        self.assertEqual(case.job.close_calls, 1)
        self.assertFalse(case.retained.mutex.closed)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)

    def test_ambiguous_process_close_quarantines_the_retained_verified_process(self):
        case = self.finished_case()
        native = self.processes.entry(case.root)
        native.close_error = OSError("synthetic process close uncertainty")
        first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.quarantined)
        self.assertTrue(case.root._close_outcome_unknown)
        native.close_error = None
        with self.forbid_native_reentry(case):
            second = self.retire(case)
        self.assert_unfinished(second, case)
        self.assertTrue(second.quarantined)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 0)
        self.assertEqual(case.job.close_calls, 0)

    def test_interrupt_publishes_quarantine_before_rethrow_and_never_retries_locator(self):
        case = self.finished_case()
        native = self.processes.entry(case.root)
        native.close_error = KeyboardInterrupt("synthetic interruption during close")
        with self.assertRaises(KeyboardInterrupt):
            self.retire(case)
        self.assertTrue(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assertTrue(case.root._close_outcome_unknown)
        native.close_error = None
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertTrue(result.quarantined)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 0)
        self.assertEqual(case.job.close_calls, 0)

    def test_changed_archive_blocks_remaining_close_after_partial_cleanup(self):
        case = self.finished_case()
        native = self.block_wrapper_close(case)
        native.close_error = None
        self.sql("UPDATE executions SET outcome='changed_archive' WHERE reservation_id=?",
            (case.spec.reservation.id,))
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertEqual(set(result.closed_owners), {"root"})
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)
        self.assertEqual(case.job.close_calls, 0)

    def test_even_valid_new_manifest_revision_cannot_replace_frozen_cleanup_binding(self):
        case = self.finished_case()
        native = self.block_wrapper_close(case)
        native.close_error = None
        self.rewrite_manifest(case, manifest_seq=case.record.manifest_seq + 1)
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertEqual(set(result.closed_owners), {"root"})
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)
        self.assertEqual(case.job.close_calls, 0)

    def test_changed_terminal_row_revision_blocks_remaining_close(self):
        case = self.finished_case()
        native = self.block_wrapper_close(case)
        native.close_error = None
        self.sql("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?",
            (case.spec.execution_id,))
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)
        self.assertEqual(case.job.close_calls, 0)

    def test_native_member_contradiction_prevents_cleanup_publication(self):
        case = self.finished_case()
        case.job.members.append(456789)
        result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assert_no_close(case)

    def test_native_cpu_contradiction_prevents_cleanup_publication(self):
        case = self.finished_case()
        case.job.control = {"flags": 5, "rate_bp": 2500}
        result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assert_no_close(case)

    def test_proof_scope_release_failure_cannot_publish_cleanup_or_close_owners(self):
        case = self.finished_case()
        proof_queries = []
        case.job.on_query = lambda: proof_queries.append(True)
        case.retained.mutex.release_error = NativePolicyMutexError("policy_mutex_release_failed", 5)
        result = self.retire(case)
        self.assert_unfinished(result, case)
        self.assertTrue(proof_queries)
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assert_no_close(case)

    def test_off_inventory_refusal_releases_policy_nonce_before_retry(self):
        case = self.finished_case()
        with patch("sentinel.adaptive.operational_policy.assert_terminal_retirement_allowed_locked",
                side_effect=LifecycleError("off_inventory_recovery_pending")):
            first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.pending)
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assert_no_close(case)
        runtime = self.connection().execute("SELECT * FROM adaptive_runtime").fetchone()
        self.assertIsNone(runtime["policy_entry_nonce"])
        second = self.retire(case)
        self.assertTrue(second.complete)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)


class TerminalControlRetirementTests(unittest.TestCase):
    # This class shares only fixture methods, not the other module's tests.
    setUp = control_fixture.GuardianControlTests.setUp
    spec = control_fixture.GuardianControlTests.spec
    allocate = control_fixture.GuardianControlTests.allocate
    connection = control_fixture.GuardianControlTests.connection
    make_mutex = control_fixture.GuardianControlTests.make_mutex
    seed_evidence = control_fixture.GuardianControlTests.seed_evidence
    seed_started = control_fixture.GuardianControlTests.seed_started
    row = control_fixture.GuardianControlTests.row
    sql = control_fixture.GuardianControlTests.sql
    start = control_fixture.GuardianControlTests.start
    policy_held = control_fixture.GuardianControlTests.policy_held
    runtime = control_fixture.GuardianControlTests.runtime
    slot = control_fixture.GuardianControlTests.slot
    actions = control_fixture.GuardianControlTests.actions
    proposal = control_fixture.GuardianControlTests.proposal
    send_frame = control_fixture.GuardianControlTests.send_frame
    apply = control_fixture.GuardianControlTests.apply
    apply_cap = control_fixture.GuardianControlTests.apply_cap
    root_exits = fixture.GuardianLifecycleTests.root_exits

    def restored_actions(self, case):
        return [row for row in self.actions() if row["execution_id"] == case.spec.execution_id
                and row["action_state"] == "RESTORED"]

    def finish(self, case):
        self.root_exits(case)
        result = self.owner.reconcile(case.spec.execution_id, now=fixture.fixtures.NOW + 20)
        self.assertTrue(result.terminal)
        self.assertEqual(self.row(case)["state"], "FINISHED")
        case.retained = self.owner._entry(case.spec.execution_id)
        return case

    def finished_after_cap(self):
        case = self.start()
        self.apply_cap(case)
        self.finish(case)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(self.restored_actions(case), [])
        self.assertFalse(self.control._episodes[case.spec.execution_id].restored)
        return case

    def retire(self, case):
        return self.owner.retire_terminal(case.spec.execution_id, now=fixture.fixtures.NOW + 21)

    def assert_cleanup_not_started(self, case):
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assertIsNotNone(case.root._handle)
        self.assertIsNotNone(case.wrapper._handle)
        self.assertEqual(case.job.close_calls, 0)
        self.assertFalse(case.retained.mutex.closed)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_never_controlled_finished_job_clears_by_exact_proof_then_retires(self):
        case = self.start()
        self.finish(case)
        self.assertNotIn(case.spec.execution_id, self.control._episodes)
        settled = self.control.clear_finished_admission_barrier(case.spec.execution_id,
            now=fixture.fixtures.NOW + 21)
        self.assertEqual(settled["admission_barrier"], "NONE")
        self.assertFalse(settled["applicable_slot"])
        self.assertFalse(self.owner.terminal_cleanup_started(case.spec.execution_id))
        result = self.retire(case)
        self.assertTrue(result.complete)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.restored_actions(case), [])

    def test_lifecycle_restore_is_audited_before_any_close_and_no_later_control_query(self):
        case = self.finished_after_cap()
        closes = []

        def checked_close(kind, original):
            def close(*args, **kwargs):
                rows = self.restored_actions(case)
                self.assertEqual(len(rows), 1)
                self.assertTrue(self.control._episodes[case.spec.execution_id].restored)
                closes.append((kind, rows[0]["action_id"]))
                return original(*args, **kwargs)
            return close

        with patch.object(self.processes, "close", checked_close("process", self.processes.close)), \
                patch.object(case.job, "close", checked_close("job", case.job.close)), \
                patch.object(case.retained.mutex, "close", checked_close("mutex", case.retained.mutex.close)):
            result = self.retire(case)
        self.assertTrue(result.complete)
        self.assertEqual([kind for kind, _ in closes], ["process", "process", "job", "mutex"])
        self.assertEqual(len({action for _, action in closes}), 1)
        self.assertEqual(len(self.restored_actions(case)), 1)
        episode = self.control._episodes[case.spec.execution_id]
        self.assertTrue(episode.restored)
        self.assertIsNone(episode.lease_deadline_tick_100ns)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)
        with patch.object(case.job, "_query", side_effect=AssertionError("retired Job queried")), \
                patch.object(self.owner, "_entry", side_effect=AssertionError("retired entry requested")):
            self.assertEqual(self.control.tick(self.ticks), ())

    def test_restore_audit_write_failure_keeps_all_custody_until_same_batch_settles(self):
        case = self.finished_after_cap()
        original = self.store.record_control_actions_locked
        batches = []

        def fail_before_write(*args, **kwargs):
            batches.append(tuple(kwargs["actions"]))
            if len(batches) == 1:
                raise RuntimeError("synthetic audit write failure")
            return original(*args, **kwargs)

        with patch.object(self.store, "record_control_actions_locked", fail_before_write):
            first = self.retire(case)
            self.assertFalse(first.complete)
            self.assertTrue(first.pending)
            self.assert_cleanup_not_started(case)
            self.assertEqual(self.restored_actions(case), [])
            self.assertFalse(self.control._episodes[case.spec.execution_id].restored)
            second = self.retire(case)
        self.assertTrue(second.complete)
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0], batches[1])
        saved = self.restored_actions(case)
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["action_id"], batches[0][0].action_id)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_restore_audit_lost_ack_reconciles_original_action_without_duplicate(self):
        case = self.finished_after_cap()
        original = self.store.record_control_actions_locked
        batches = []

        def lose_first_ack(*args, **kwargs):
            batches.append(tuple(kwargs["actions"]))
            result = original(*args, **kwargs)
            if len(batches) == 1:
                raise RuntimeError("synthetic audit acknowledgement loss")
            return result

        with patch.object(self.store, "record_control_actions_locked", lose_first_ack):
            first = self.retire(case)
            self.assertFalse(first.complete)
            self.assertTrue(first.pending)
            self.assert_cleanup_not_started(case)
            committed = self.restored_actions(case)
            self.assertEqual(len(committed), 1)
            self.assertEqual(committed[0]["action_id"], batches[0][0].action_id)
            self.assertFalse(self.control._episodes[case.spec.execution_id].restored)
            second = self.retire(case)
        self.assertTrue(second.complete)
        self.assertEqual(self.restored_actions(case), committed)
        self.assertTrue(all(batch == batches[0] for batch in batches))
        self.assertEqual(len({row["action_id"] for row in self.restored_actions(case)}), 1)
        self.assertEqual(self.control._actions.get(case.spec.execution_id, []), [])
        self.assertTrue(self.control._episodes[case.spec.execution_id].restored)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_new_off_generation_during_partial_close_preserves_hold_without_native_reentry(self):
        case = self.finished_after_cap()
        root_handle = case.root._handle
        wrapper_handle = case.wrapper._handle
        wrapper_native = self.processes.entry(case.wrapper)
        wrapper_native.close_error = IdentityUnavailable("process_handle_close_failed", 5)
        first = self.retire(case)
        self.assertFalse(first.complete)
        self.assertTrue(first.pending)
        self.assertFalse(first.quarantined)
        self.assertTrue(self.owner.terminal_cleanup_started(case.spec.execution_id))
        self.assertEqual(set(first.closed_owners), {"root"})
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assertIsNone(case.root._handle)
        self.assertEqual(case.job.close_calls, 0)

        # Explicit isolated fixture mutation represents a later off generation;
        # it cannot revoke the already-published terminal close authority.
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        wrapper_native.close_error = None
        with patch("sentinel.adaptive.operational_policy.assert_terminal_retirement_allowed_locked",
                side_effect=LifecycleError("off_inventory_recovery_pending")) as first_close_gate, \
                patch.object(case.job, "_query", side_effect=AssertionError("partially closed Job queried")), \
                patch.object(case.retained.mutex, "acquire", side_effect=AssertionError("cleanup Job mutex reacquired")):
            second = self.retire(case)
        self.assertTrue(second.complete)
        first_close_gate.assert_not_called()
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual(self.processes.events.count(("close", root_handle)), 1)
        self.assertEqual(self.processes.events.count(("close", wrapper_handle)), 2)
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(set(second.closed_owners), {"root", "wrapper", "job", "mutex"})
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)


if __name__ == "__main__":
    unittest.main()
