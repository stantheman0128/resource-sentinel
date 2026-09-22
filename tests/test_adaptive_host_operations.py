"""Real isolated SQLite/journal, explicitly synthetic retained Windows owners."""
from contextlib import contextmanager
from dataclasses import replace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.control_slot import ControlSlotError, _require_no_off_inventory_hold
from sentinel.adaptive.host_operations import GuardianHostOperations
from sentinel.adaptive.operational_policy import FencedOffOperation, active_off_hold
from sentinel.adaptive.operator_messages import OperatorRequest, OperatorOperation as Op, OperatorOutcome
from sentinel.adaptive.store import LifecycleError
from tests.test_adaptive_guardian_control import GuardianControlTests as Fixture
from tests import test_adaptive_guardian_lifecycle as lifecycle_fixture


class HostOperationsTests(unittest.TestCase):
    setUp = Fixture.setUp
    spec = Fixture.spec
    allocate = Fixture.allocate
    connection = Fixture.connection
    make_mutex = Fixture.make_mutex
    seed_evidence = Fixture.seed_evidence
    seed_started = Fixture.seed_started
    row = Fixture.row
    sql = Fixture.sql
    start = Fixture.start
    policy_held = Fixture.policy_held
    runtime = Fixture.runtime
    slot = Fixture.slot
    actions = Fixture.actions
    proposal = Fixture.proposal
    send_frame = Fixture.send_frame
    apply = Fixture.apply
    apply_cap = Fixture.apply_cap
    sample = Fixture.sample
    uncapped_set = Fixture.uncapped_set
    boundary = Fixture.boundary

    def ops(self):
        self.instance = str(uuid4())
        return GuardianHostOperations(self.launch_owner, self.control,
            instance_id=self.instance, policy_instance_id=self.runtime()["policy_instance_id"])

    def seed_retired(self):
        """Real lifecycle/receipt path, one historical scope at a time."""
        case = self.seed_started()
        self.owner.adopt_started(case.spec.execution_id, job=case.job,
            wrapper=case.wrapper, root=case.root)
        lifecycle_fixture.GuardianLifecycleTests.root_exits(self, case)
        finished = self.owner.reconcile(case.spec.execution_id, now=lifecycle_fixture.fixtures.NOW + 10)
        self.assertTrue(finished.terminal)
        retired = self.owner.retire_terminal(case.spec.execution_id, now=lifecycle_fixture.fixtures.NOW + 11)
        self.assertTrue(retired.complete, retired.reason)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)
        return case

    def request(self, op=Op.DRAIN, **changes):
        values = dict(request_id=str(uuid4()), operation=op, instance_id=self.instance,
            policy_instance_id=self.runtime()["policy_instance_id"],
            guardian_epoch=self.launch_owner.guardian_epoch,
            expected_registry_revision=self.runtime()["registry_revision"])
        return OperatorRequest(**(values | changes))

    def off(self, ops, request, settled=False):
        return FencedOffOperation(self.store, request, logon_id=self.guardian.identity.logon_id,
            assert_owner=ops._assert_owner, begin_drain=ops.begin_drain,
            recovery_settled=lambda: settled, clock=lambda: self.ticks)

    def test_off_atomic_hold_and_exact_replay(self):
        self.start()
        ops = self.ops()
        request = self.request()
        operation = self.off(ops, request)
        first = operation.step()
        self.assertTrue(first.settled)
        self.assertEqual((self.runtime()["mode"], self.runtime()["admission_barrier"]), ("off", "RECOVERY_HOLD"))
        self.assertEqual(self.runtime()["registry_revision"], request.expected_registry_revision + 1)
        self.assertEqual(operation.step(), first)
        self.assertEqual(self.runtime()["registry_revision"], first.registry_revision)
        with self.store._connection() as conn:
            self.assertEqual(active_off_hold(conn)["request_id"], request.request_id)
            with self.assertRaises(ControlSlotError):
                _require_no_off_inventory_hold(conn)

    def test_off_noop_preserves_preexisting_hold_without_revision_inflation(self):
        self.start(mode="off")
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        ops = self.ops()
        request = self.request()
        self.assertTrue(self.off(ops, request, settled=True).step().settled)
        self.assertEqual(self.runtime()["registry_revision"], request.expected_registry_revision)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_wrong_epoch_and_stale_revision_do_not_write(self):
        self.start()
        ops = self.ops()
        before = self.runtime()
        wrong = replace(self.request(), guardian_epoch="another-epoch")
        self.assertFalse(self.off(ops, wrong).step().settled)
        stale = replace(self.request(), expected_registry_revision=before["registry_revision"] + 1)
        self.assertFalse(self.off(ops, stale).step().settled)
        self.assertEqual(self.runtime(), before)

    def test_commit_ack_loss_retries_original_guard_without_increment(self):
        self.start()
        ops = self.ops()
        operation = self.off(ops, self.request())
        original = self.store._transaction
        failed = False

        @contextmanager
        def transaction(**kwargs):
            nonlocal failed
            with original(**kwargs) as conn:
                yield conn
            if operation.after is not None and not failed:
                failed = True
                raise OSError("synthetic lost commit ACK")

        with patch.object(self.store, "_transaction", transaction):
            self.assertFalse(operation.step().settled)
        guard = operation.guard
        revision = self.runtime()["registry_revision"]
        self.assertTrue(operation.step().settled)
        self.assertIs(operation.guard, guard)
        self.assertEqual(self.runtime()["registry_revision"], revision)

    def test_later_revision_prevents_invented_replay_receipt(self):
        self.start()
        ops = self.ops()
        operation = self.off(ops, self.request())
        original = self.store._transaction

        @contextmanager
        def transaction(**kwargs):
            with original(**kwargs) as conn:
                yield conn
            if operation.after is not None:
                raise OSError("synthetic lost ACK")

        with patch.object(self.store, "_transaction", transaction):
            operation.step()
        self.sql("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        self.assertFalse(operation.step().settled)
        self.assertTrue(operation.quarantined)

    def test_status_audit_does_not_prepare_policy_or_restore(self):
        case = self.start()
        ops = self.ops()
        before = self.runtime()
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("readonly")), \
                patch.object(self.launch_owner, "restore_owned_caps", side_effect=AssertionError("readonly")):
            reply = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertEqual(reply.outcome, OperatorOutcome.COMPLETE)
        self.assertTrue(reply.native_disabled)
        self.assertEqual(reply.remaining_executions, 1)
        self.assertEqual(reply.items[0].provenance, "native")
        self.assertEqual(self.runtime(), before)
        self.assertEqual(case.job.sets, 0)

    def test_restore_and_off_keep_live_allocation_and_custody(self):
        case = self.start()
        self.apply_cap(case)
        ops = self.ops()
        request = self.request()
        reply = ops(request, caller_identity=self.guardian.identity)
        self.assertTrue(reply.accepted)
        self.assertTrue(reply.native_disabled)
        self.assertEqual(reply.outcome, OperatorOutcome.PENDING)
        self.assertEqual(reply.remaining_custody, 1)
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual(case.job.control["flags"], 0)
        self.assertIsNotNone(self.slot())
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")

    def test_same_request_changed_payload_refused(self):
        self.start()
        ops = self.ops()
        request = self.request(Op.RESTORE_ONLY)
        ops(request, caller_identity=self.guardian.identity)
        with self.assertRaises(LifecycleError):
            ops(replace(request, expected_registry_revision=request.expected_registry_revision + 1),
                caller_identity=self.guardian.identity)

    def test_describe_operation_does_not_drive_native_restore(self):
        self.start()
        ops = self.ops()
        request = self.request(Op.RESTORE_ONLY)
        ops(request, caller_identity=self.guardian.identity)
        observe = self.request(Op.DESCRIBE, observe_request_id=request.request_id)
        with patch.object(self.launch_owner, "restore_owned_caps", side_effect=AssertionError("readonly")):
            reply = ops(observe, caller_identity=self.guardian.identity)
        self.assertTrue(reply.accepted)

    def test_restore_only_keeps_pristine_job_barrier_clear_and_retries_on_tick(self):
        self.start()
        ops = self.ops()
        request = self.request(Op.RESTORE_ONLY)
        ops(request, caller_identity=self.guardian.identity)
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        with patch.object(ops, "_restore_inventory", wraps=ops._restore_inventory) as restore:
            ops.tick()
        self.assertEqual(restore.call_count, 1)

    def test_unknown_native_query_cannot_claim_complete(self):
        case = self.start()
        ops = self.ops()
        with patch.object(case.job, "query_cpu", side_effect=OSError("private synthetic detail")):
            reply = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertEqual(reply.outcome, OperatorOutcome.UNVERIFIED)
        self.assertFalse(reply.native_disabled)
        self.assertEqual(reply.items[0].provenance, "unknown")
        self.assertNotIn("private synthetic", reply.to_json())

    def test_general_hold_requires_five_real_post_boundary_frames(self):
        case = self.start()
        self.apply_cap(case)
        ops = self.ops()
        request = self.request()
        ops(request, caller_identity=self.guardian.identity)
        # Repeated queries do not manufacture fresh CPU samples.
        for _ in range(6):
            ops.tick()
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        first_seq = self.control._latest_frame.sample_seq
        for index in range(1, 6):
            self.ticks += 10_000_000
            self.send_frame(case, seq=first_seq + index, window_end=self.ticks)
            self.assertIsNone(self.runtime()["policy_entry_nonce"])
            self.assertIsNone(self.owner._pending_policy)
        ops.tick()
        self.assertEqual(self.runtime()["admission_barrier"], "NONE", {
            "operation_error": str(ops.last_error),
            "frame_error": str(self.control._frame_failure),
            "sample_count": len(self.control._samples.get(case.spec.execution_id, ())),
            "hold_quarantined": ops._hold_quarantined,
            "policy_pending": self.runtime()["policy_entry_nonce"] is not None,
        })
        self.assertEqual(self.row(case)["state"], "RUNNING")

    def test_history_is_paged_and_revision_change_invalidates_cursor(self):
        self.start()
        for _ in range(33):
            self.seed_retired()
        ops = self.ops()
        first = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertFalse(first.inventory_complete)
        self.assertEqual(len(first.items), 32)
        self.assertIsNotNone(first.next_cursor)
        second = ops(self.request(Op.AUDIT, cursor=first.next_cursor,
            expected_registry_revision=first.registry_revision), caller_identity=self.guardian.identity)
        self.assertTrue(second.inventory_complete)
        self.assertTrue(second.native_disabled)  # complete exact retired history plus live native proof
        self.assertEqual(second.remaining_executions, 1)
        self.sql("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        with self.assertRaises(LifecycleError):
            ops(self.request(Op.AUDIT, cursor=first.next_cursor,
                expected_registry_revision=first.registry_revision), caller_identity=self.guardian.identity)

    def test_missing_registry_read_does_not_create_file(self):
        self.start()
        ops = self.ops()
        request = self.request(Op.AUDIT)
        missing = self.directory / "does-not-exist.db"
        with patch.object(self.store, "db_path", missing):
            with self.assertRaises(LifecycleError):
                ops(request, caller_identity=self.guardian.identity)
        self.assertFalse(missing.exists())

    def test_uncertain_policy_cleanup_quarantines_original_guard(self):
        self.start()
        ops = self.ops()
        operation = self.off(ops, self.request())
        original = self.store._policy.hold

        @contextmanager
        def uncertain(guard):
            with original(guard):
                yield guard
            error = RuntimeError("synthetic native cleanup uncertainty")
            error.add_note("policy_scope_cleanup_unverified")
            raise error

        with patch.object(self.store._policy, "hold", uncertain):
            self.assertFalse(operation.step().settled)
        guard = operation.guard
        self.assertTrue(operation.quarantined)
        self.assertFalse(operation.step().settled)
        self.assertIs(operation.guard, guard)

    def empty_ops(self):
        self.start(cases=0)
        self.sql("UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?",
            (self.launch_owner.guardian_epoch, self.guardian.identity.logon_id))
        return self.ops()

    def test_settled_checks_every_accepted_operation_and_never_mutates(self):
        ops = self.empty_ops()
        first, second = self.request(Op.RESTORE_ONLY), self.request(Op.RESTORE_ONLY)
        ops(first, caller_identity=self.guardian.identity)
        ops(second, caller_identity=self.guardian.identity)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("readonly")), \
                patch.object(ops, "_advance", side_effect=AssertionError("readonly")):
            self.assertTrue(ops.settled)
            ops._operation_results[first.request_id]["bookkeeping_settled"] = None
            self.assertFalse(ops.settled)  # latest operation alone was complete

    def test_settled_rejects_stale_revision_and_uncertain_retained_guard(self):
        ops = self.empty_ops()
        request = self.request(Op.RESTORE_ONLY)
        ops(request, caller_identity=self.guardian.identity)
        self.assertTrue(ops.settled)
        ops._hold_quarantined = True
        self.assertFalse(ops.settled)
        ops._hold_quarantined = False
        self.sql("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        self.assertFalse(ops.settled)

    def test_successful_restore_with_live_job_is_not_host_settled(self):
        self.start()
        ops = self.ops()
        reply = ops(self.request(Op.RESTORE_ONLY), caller_identity=self.guardian.identity)
        self.assertEqual(reply.outcome, OperatorOutcome.COMPLETE)
        self.assertFalse(ops.settled)

    def test_interrupt_quarantines_off_operation_before_reentry(self):
        self.start()
        ops = self.ops()
        operation = self.off(ops, self.request())
        original = self.store._policy.hold

        @contextmanager
        def interrupted(guard):
            with original(guard):
                yield guard
            raise KeyboardInterrupt()

        with patch.object(self.store._policy, "hold", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                operation.step()
        original_guard = operation.guard
        self.assertTrue(operation.quarantined)
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("no reentry")):
            self.assertFalse(operation.step().settled)
        self.assertIs(operation.guard, original_guard)

    def test_interrupt_quarantines_general_hold_recovery(self):
        self.start()
        ops = self.ops()
        request = self.request()
        self.assertTrue(self.off(ops, request).step().settled)
        with patch.object(ops, "_audit_page", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                ops._recover_hold(request)
        self.assertTrue(ops._hold_quarantined)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no reentry")):
            ops._recover_hold(request)

    def test_partial_terminal_close_never_reenters_native_restore(self):
        self.start()
        ops = self.ops()
        with patch.object(self.owner, "terminal_cleanup_started", return_value=True), \
                patch.object(self.control, "request_restore", side_effect=AssertionError("closed native owner")), \
                patch.object(self.owner, "restore_owned_cap", side_effect=AssertionError("closed native owner")):
            ops._restore_inventory()

    def test_equal_postimage_without_original_receipt_is_not_commit_proof(self):
        self.start(mode="off")
        ops = self.ops()
        operation = self.off(ops, self.request(), settled=True)
        original = self.store._transaction

        @contextmanager
        def rolled_back(**kwargs):
            with original(**kwargs) as conn:
                yield conn
                if operation.after is not None:
                    raise OSError("synthetic rollback before commit")

        with patch.object(self.store, "_transaction", rolled_back):
            self.assertFalse(operation.step().settled)
        self.sql("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
        # The runtime equals the no-op postimage but the original receipt was
        # rolled back. A newer owner cannot stand in for this operation.
        self.assertFalse(operation.step().settled)
        self.assertTrue(operation.quarantined)

    def test_readonly_native_audit_holds_pinned_policy_and_job_mutexes(self):
        case = self.start()
        ops = self.ops()
        entry = self.owner._entry(case.spec.execution_id)

        def observe_fences():
            self.assertTrue(entry.mutex.acquired)
            self.assertTrue(self.owner._restorer.policy_mutex.acquired)

        case.job.on_query = observe_fences
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("readonly")):
            reply = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertEqual(reply.outcome, OperatorOutcome.COMPLETE)
        self.assertFalse(entry.mutex.acquired)

    def test_read_fence_unknown_cleanup_retains_and_quarantines_owner(self):
        case = self.start()
        ops = self.ops()
        entry = self.owner._entry(case.spec.execution_id)
        error = RuntimeError("synthetic unknown ReleaseMutex")
        entry.mutex.release_error = error
        reply = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertEqual(reply.outcome, OperatorOutcome.UNVERIFIED)
        self.assertIs(self.owner._restorer.fence_error, error)
        with patch.object(entry.mutex, "acquire", side_effect=AssertionError("no reentry")):
            again = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
        self.assertEqual(again.outcome, OperatorOutcome.UNVERIFIED)

    def test_more_than_128_audit_sweeps_preserve_bounded_cursor_replay(self):
        self.start()
        for _ in range(32):
            self.seed_retired()
        ops = self.ops()
        original = None
        for _ in range(130):
            first = ops(self.request(Op.AUDIT), caller_identity=self.guardian.identity)
            original = original or first.next_cursor
            self.assertEqual(first.next_cursor, original)
            last = ops(self.request(Op.AUDIT, cursor=first.next_cursor,
                expected_registry_revision=first.registry_revision), caller_identity=self.guardian.identity)
            self.assertTrue(last.inventory_complete)
            self.assertTrue(last.native_disabled)
        self.assertFalse(hasattr(ops, "_audits"))
        self.assertEqual(ops.operations, {})
        changed = original[:-1] + ("A" if original[-1] != "A" else "B")
        with self.assertRaises(LifecycleError):
            ops(self.request(Op.AUDIT, cursor=changed), caller_identity=self.guardian.identity)
