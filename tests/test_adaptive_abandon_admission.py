"""Original-wrapper reconciliation and exact abandonment in isolated SQLite.

These are capacity/lifecycle contract tests. They create no native Job and
provide no evidence for the external-console Windows control gates.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import os
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.policy import PolicyBusy
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests import test_adaptive_managed_admission as fixtures
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import NOW, status


REFUSALS = (ManagedAdmissionUnavailable, LifecycleError)


class ManagedAbandonAdmissionTests(unittest.TestCase):
    setUp = fixtures.ManagedAdmissionTests.setUp
    context = fixtures.ManagedAdmissionTests.context
    conn = fixtures.ManagedAdmissionTests.conn
    admit = fixtures.ManagedAdmissionTests.admit
    counts = fixtures.ManagedAdmissionTests.counts

    def queued(self):
        context = self.context()
        result = self.admit(context, status(commit=94))
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "commit_capacity")
        return context, result

    def reserved(self):
        context = self.context()
        result = self.admit(context)
        self.assertTrue(result["allowed"])
        return context, result

    def cancel_reserved(self, context, result, **overrides):
        arguments = dict(reservation_id=result["reservation_id"],
                         expected_revision=result["state_revision"], now=NOW + 1)
        return self.coordinator.cancel_managed(context, **(arguments | overrides))

    def rows(self, table):
        return [dict(row) for row in self.conn().execute(f"SELECT * FROM {table}")]

    def inject_worker_alias(self, context):
        # This private malformed ledger has no worker process or native Job.
        self.conn().execute("""INSERT INTO worker_reservations(id,task_id,worker_id,failure_domain,
            capacity_scope,capacity_pool,spec_hash,ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,
            expires_at,metadata_json,execution_id,lifecycle_managed,physical_bytes,commit_bytes,
            io_slots,writer_protocol,writer_revision)
            VALUES('corrupt-routed','corrupt-task','absent-worker','local','SHARED_POOL','local',
            'unused',0,0,0,?,?,?,'{}',?,1,0,0,0,1,0)""",
            (NOW, NOW, NOW + 120, context.snapshot().execution_id))

    def inject_queue_alias(self, context):
        snapshot = context.snapshot()
        request = snapshot.request
        self.conn().execute("""INSERT INTO queue(request_key,owner_pid,owner_started,
            tool_use_id,repo,command_signature,command_text,resource_class,priority,
            priority_rank,cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,spec_hash,
            commit_bytes,managed_execution_id,managed_binding_hash)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (request.request_key, request.owner_pid, request.owner_started, request.tool_use_id,
             request.repo, request.command_signature, "", request.resource_class, request.priority,
             int(request.priority[1:]), request.cpu_units, request.ram_gib, request.io_slots,
             NOW, NOW, "managed-v1:" + snapshot.binding_hash, request.commit_bytes,
             snapshot.execution_id, snapshot.binding_hash))

    def assert_sealed(self, context):
        for operation in (
            context.launch_claim_token,
            lambda: context.begin_submission(db_path=self.coordinator.db_path),
            lambda: context.verify_launch_payload(command=PAYLOAD["command"], cwd=PAYLOAD["cwd"]),
            context.mark_prepare_attempted,
        ):
            with self.assertRaises(ManagedAdmissionUnavailable):
                operation()

    def assert_summary(self, result, context, expected_state):
        snapshot = context.snapshot()
        self.assertEqual(result["execution_id"], snapshot.execution_id)
        self.assertEqual(result["request_key"], snapshot.request.request_key)
        self.assertEqual(result["state"], expected_state)
        self.assertIs(result["allowed"], False)
        self.assertIs(result["launch_authorized"], False)
        wire = json.dumps(result)
        for private in ("private-launch-marker", "private-cwd-marker",
                        snapshot.ipc_auth_key.hex(), snapshot.claim_token_hash,
                        snapshot.binding_hash, snapshot.spec_hash):
            self.assertNotIn(private, wire)

    def test_both_entrypoints_require_original_context_not_claimed_identity(self):
        context = self.context()
        for candidate in (context.snapshot(), context.snapshot().wrapper_identity,
                          {"owner_pid": os.getpid()}, None):
            for method in (self.coordinator.reconcile_managed, self.coordinator.cancel_managed):
                with self.subTest(candidate=type(candidate).__name__, method=method.__name__):
                    with self.assertRaises(TypeError):
                        method(candidate)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_never_submitted_reconciliation_does_not_submit_or_export_claim(self):
        context = self.context()
        with patch.object(context, "begin_submission", side_effect=AssertionError("unexpected submission")), \
                patch.object(context, "launch_claim_token", side_effect=AssertionError("claim export")), \
                patch.object(self.coordinator, "admit_managed", side_effect=AssertionError("unexpected admission")):
            result = self.coordinator.reconcile_managed(context)
        self.assert_summary(result, context, "NEVER_SUBMITTED")
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assertFalse(context._submitted)
        self.assertFalse(context._claim_exported)
        self.assertTrue(self.admit(context)["allowed"])

    def test_queue_reconciliation_preserves_all_rows_and_heartbeat(self):
        context, _ = self.queued()
        before = self.rows("queue")
        with patch.object(context, "begin_submission", side_effect=AssertionError("unexpected submission")), \
                patch.object(context, "launch_claim_token", side_effect=AssertionError("claim export")), \
                patch.object(self.coordinator, "_mirror", side_effect=AssertionError("unexpected publication")):
            result = self.coordinator.reconcile_managed(context)
        self.assert_summary(result, context, "QUEUED")
        self.assertEqual(self.rows("queue"), before)
        self.assertFalse(context._claim_exported)

    def test_reserved_reconciliation_is_read_only_and_never_launch_authority(self):
        context, admitted = self.reserved()
        before = {table: self.rows(table) for table in ("queue", "reservations", "managed_executions")}
        result = self.coordinator.reconcile_managed(context)
        self.assert_summary(result, context, "RESERVED")
        self.assertEqual(result["reservation_id"], admitted["reservation_id"])
        self.assertEqual(result["state_revision"], admitted["state_revision"])
        self.assertEqual(before, {table: self.rows(table) for table in before})

    def test_submitted_but_absent_is_not_successful_abandonment(self):
        context, queued = self.queued()
        self.coordinator.cancel_queued(owner_pid=os.getpid(), request_key=queued["request_key"])
        self.assert_summary(self.coordinator.reconcile_managed(context), context,
                            "ABSENT_AFTER_SUBMISSION")
        with self.assertRaises(REFUSALS):
            self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_clean_never_submitted_cancel_seals_every_future_launch_path(self):
        context = self.context()
        result = self.coordinator.cancel_managed(context, now=NOW)
        self.assert_summary(result, context, "NOT_SUBMITTED")
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assert_sealed(context)
        replay = self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assert_summary(replay, context, "NOT_SUBMITTED")

    def test_cancel_queue_removes_only_original_exact_request_and_seals(self):
        first, first_result = self.queued()
        second, second_result = self.queued()
        other = next(row for row in self.rows("queue") if row["request_key"] == second_result["request_key"])
        self.assertNotEqual(first_result["request_key"], second_result["request_key"])
        result = self.coordinator.cancel_managed(first, now=NOW + 1)
        self.assert_summary(result, first, "QUEUED_CANCELLED")
        self.assertEqual(self.rows("queue"), [other])
        self.assertEqual(self.counts(), (1, 0, 0))
        self.assert_sealed(first)
        self.assert_summary(self.coordinator.reconcile_managed(second), second, "QUEUED")

    def test_same_command_new_context_cannot_cancel_another_attempt(self):
        first, _ = self.queued()
        second = self.context()
        before = self.rows("queue")
        result = self.coordinator.cancel_managed(second, now=NOW + 1)
        self.assert_summary(result, second, "NOT_SUBMITTED")
        self.assertEqual(self.rows("queue"), before)
        self.assert_summary(self.coordinator.reconcile_managed(first), first, "QUEUED")

    def test_full_queue_binding_damage_refuses_reconciliation_and_cancellation(self):
        changes = {"owner_pid": os.getpid() + 1, "owner_started": 1.0,
                   "managed_execution_id": "other-execution", "managed_binding_hash": "a" * 64,
                   "spec_hash": "managed-v1:" + "b" * 64, "tool_use_id": "other-tool",
                   "repo": "other-repo", "command_signature": "other-command",
                   "command_text": "private injected command", "priority": "P3",
                   "priority_rank": 3, "cpu_units": 9.5, "ram_gib": 9.5,
                   "io_slots": 8, "commit_bytes": 123, "resource_class": "LIGHT"}
        for field, value in changes.items():
            with self.subTest(field=field):
                context, queued = self.queued()
                self.conn().execute(f"UPDATE queue SET {field}=? WHERE request_key=?",
                                    (value, queued["request_key"]))
                before = self.rows("queue")
                for method in (self.coordinator.reconcile_managed, self.coordinator.cancel_managed):
                    with self.assertRaises(REFUSALS):
                        method(context)
                self.assertEqual(self.rows("queue"), before)

    def test_queue_cancellation_rejects_reserved_target_selectors(self):
        context, _ = self.queued()
        before = self.rows("queue")
        for arguments in ({"reservation_id": "wrong", "expected_revision": 0},
                          {"reservation_id": "wrong"}, {"expected_revision": 0}):
            with self.subTest(arguments=arguments), self.assertRaises(REFUSALS):
                self.coordinator.cancel_managed(context, **arguments)
        self.assertEqual(self.rows("queue"), before)

    def test_reserved_cancel_requires_explicit_allocation_and_revision(self):
        context, admitted = self.reserved()
        for arguments in ({}, {"reservation_id": admitted["reservation_id"]},
                          {"expected_revision": admitted["state_revision"]}):
            with self.subTest(arguments=arguments), self.assertRaises(REFUSALS):
                self.coordinator.cancel_managed(context, **arguments)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_reserved_cancel_archives_once_and_replays_exact_revision(self):
        context, admitted = self.reserved()
        result = self.cancel_reserved(context, admitted)
        self.assert_summary(result, context, "CANCELLED_BEFORE_START")
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assert_sealed(context)
        archived = self.rows("executions")
        self.assertEqual(len(archived), 1)
        self.assertEqual(archived[0]["reservation_id"], admitted["reservation_id"])
        self.assertEqual(archived[0]["outcome"], "managed_cancelled_before_start")
        self.assert_summary(self.cancel_reserved(context, admitted), context, "CANCELLED_BEFORE_START")
        self.assertEqual(self.rows("executions"), archived)

    def test_reserved_cancel_cannot_select_other_reservation(self):
        context, admitted = self.reserved()
        before = self.rows("reservations")
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted, reservation_id="another-reservation")
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted, expected_revision=999)
        self.assertEqual(self.rows("reservations"), before)

    def test_exported_launch_claim_refuses_local_cancel_without_releasing_capacity(self):
        context, admitted = self.reserved()
        context.launch_claim_token()
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_prepare_attempt_is_idempotent_but_ends_local_reserved_cancel_authority(self):
        context, admitted = self.reserved()
        context.mark_prepare_attempted()
        context.mark_prepare_attempted()
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertEqual(self.rows("managed_executions")[0]["state"], "RESERVED")

    def test_prepared_scope_is_never_released_by_local_adapter(self):
        context, admitted = self.reserved()
        self.conn().execute("UPDATE managed_executions SET state='PREPARED',job_name='Local\\held-job',guardian_epoch='held-guardian'")
        before = self.rows("reservations")
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.rows("reservations"), before)

    def test_closed_or_unknown_owner_cannot_reconcile_or_cancel(self):
        context, _ = self.queued()
        actual = self.process.observed
        for observed in (IdentityObservation(actual.identity, IdentityStatus.UNKNOWN, "query_failed"),
                         replace(actual, identity=replace(actual.identity,
                             created_filetime_100ns=actual.identity.created_filetime_100ns + 1))):
            self.process.observed = observed
            for method in (self.coordinator.reconcile_managed, self.coordinator.cancel_managed):
                with self.assertRaises(ManagedAdmissionUnavailable):
                    method(context)
        self.process.observed = actual
        context.close()
        for method in (self.coordinator.reconcile_managed, self.coordinator.cancel_managed):
            with self.assertRaises(ManagedAdmissionUnavailable):
                method(context)
        self.assertEqual(self.counts(), (1, 0, 0))

    def test_queue_with_matching_worker_allocation_is_not_cancelled(self):
        context, _ = self.queued()
        # Deliberately malformed cross-ledger reference in this isolated fixture;
        # no worker is running and no production FK or writer fence is disabled.
        self.conn().execute("""INSERT INTO worker_reservations(id,task_id,worker_id,failure_domain,
            capacity_scope,capacity_pool,spec_hash,ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,
            expires_at,metadata_json,execution_id,lifecycle_managed,physical_bytes,commit_bytes,
            io_slots,writer_protocol,writer_revision)
            VALUES('corrupt-routed','corrupt-task','absent-worker','local','SHARED_POOL','local',
            'unused',0,0,0,?,?,?,'{}',?,1,0,0,0,1,0)""",
            (NOW, NOW, NOW + 120, context.snapshot().execution_id))
        before = self.rows("queue")
        with self.assertRaises(REFUSALS):
            self.coordinator.cancel_managed(context)
        self.assertEqual(self.rows("queue"), before)
        self.assertEqual(len(self.rows("worker_reservations")), 1)

    def test_queue_with_matching_legacy_reservation_is_not_cancelled(self):
        context, queued = self.queued()
        snapshot = context.snapshot()
        legacy = self.coordinator.admit(replace(snapshot.request, tool_use_id="legacy-competing", priority="P1"),
                                        status(), config=fixtures.CONFIG, now=NOW)
        self.assertTrue(legacy["allowed"])
        self.conn().execute("UPDATE reservations SET request_key=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                            (queued["request_key"], legacy["reservation_id"]))
        before = {table: self.rows(table) for table in ("queue", "reservations")}
        with self.assertRaises(REFUSALS):
            self.coordinator.cancel_managed(context)
        self.assertEqual(before, {table: self.rows(table) for table in before})

    def test_queue_delete_rollback_preserves_seal_and_allows_exact_retry(self):
        context, _ = self.queued()
        self.conn().execute("CREATE TRIGGER refuse_abandon BEFORE DELETE ON queue BEGIN SELECT RAISE(ABORT,'cancel rollback'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cancel rollback"):
            self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (1, 0, 0))
        self.conn().execute("DROP TRIGGER refuse_abandon")
        self.assert_summary(self.coordinator.cancel_managed(context, now=NOW + 2), context, "QUEUED_CANCELLED")

    def test_clean_rollback_then_unrelated_disappearance_is_not_lost_ack_success(self):
        context, queued = self.queued()
        self.conn().execute("CREATE TRIGGER refuse_abandon BEFORE DELETE ON queue BEGIN SELECT RAISE(ABORT,'cancel rollback'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.coordinator.cancel_managed(context, now=NOW + 1)
        self.conn().execute("DROP TRIGGER refuse_abandon")
        self.coordinator.cancel_queued(owner_pid=os.getpid(), request_key=queued["request_key"])
        with self.assertRaises(REFUSALS):
            self.coordinator.cancel_managed(context, now=NOW + 2)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_mirror_failure_does_not_undo_successful_queue_cancel_ack(self):
        context, _ = self.queued()
        with patch.object(self.coordinator, "_mirror", side_effect=OSError("publication unavailable")):
            result = self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assert_summary(result, context, "QUEUED_CANCELLED")
        self.assertIs(result["mirror_synced"], False)
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assert_sealed(context)

    def test_mirror_failure_does_not_undo_successful_reserved_cancel_ack(self):
        context, admitted = self.reserved()
        with patch.object(self.coordinator, "_mirror", side_effect=OSError("publication unavailable")):
            result = self.cancel_reserved(context, admitted)
        self.assert_summary(result, context, "CANCELLED_BEFORE_START")
        self.assertIs(result["mirror_synced"], False)
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_reserved_cancel_lost_ack_replays_without_second_archive(self):
        context, admitted = self.reserved()
        original = LifecycleStore.cancel_before_start

        def lose_ack(store, *args, **kwargs):
            original(store, *args, **kwargs)
            raise OSError("cancel reply lost")

        with patch.object(LifecycleStore, "cancel_before_start", lose_ack):
            with self.assertRaisesRegex(OSError, "cancel reply lost"):
                self.cancel_reserved(context, admitted)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (0, 0, 1))
        result = self.cancel_reserved(context, admitted)
        self.assert_summary(result, context, "CANCELLED_BEFORE_START")
        self.assertEqual(len(self.rows("executions")), 1)

    def test_queue_commit_lost_ack_replays_original_target_only_after_revalidation(self):
        context, _ = self.queued()
        original = self.coordinator._commit_admission

        def lose_ack(conn, transaction):
            original(conn, transaction)
            raise OSError("queue commit acknowledgement lost")

        with patch.object(self.coordinator, "_commit_admission", side_effect=lose_ack):
            with self.assertRaisesRegex(OSError, "queue commit acknowledgement lost"):
                self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (0, 0, 0))
        replay = self.coordinator.cancel_managed(context, now=NOW + 2)
        self.assert_summary(replay, context, "QUEUED_CANCELLED")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_lost_admission_commit_ack_retains_policy_guard_then_exact_cancel_settles_it(self):
        for queued in (False, True):
            with self.subTest(queued=queued):
                context = self.context()
                original = self.coordinator._commit_admission

                def lose_ack(conn, transaction):
                    original(conn, transaction)
                    raise OSError("admission commit acknowledgement lost")

                with patch.object(self.coordinator, "_commit_admission", side_effect=lose_ack):
                    with self.assertRaisesRegex(OSError, "admission commit acknowledgement lost"):
                        self.admit(context, status(commit=94) if queued else status())
                guard = context._submission_guard
                self.assertIsNotNone(guard)
                observed = self.coordinator.reconcile_managed(context)
                self.assert_summary(observed, context, "QUEUED" if queued else "RESERVED")
                self.assertIs(observed["submission_cleanup_pending"], True)
                # Readback alone cannot consume the original outstanding guard.
                self.assertIs(context._submission_guard, guard)
                if queued:
                    result = self.coordinator.cancel_managed(context, now=NOW + 1)
                else:
                    result = self.cancel_reserved(context, observed)
                self.assert_summary(result, context, "QUEUED_CANCELLED" if queued else "CANCELLED_BEFORE_START")
                self.assertIsNone(context._submission_guard)
                self.assertIsNone(self.conn().execute(
                    "SELECT policy_entry_nonce FROM adaptive_runtime WHERE singleton=1").fetchone()[0])
                self.assert_sealed(context)

    def test_native_policy_release_uncertainty_refuses_cancellation_and_keeps_capacity(self):
        context = self.context()
        original = self.policy.hold

        @contextmanager
        def release_uncertain(binding, **kwargs):
            with original(binding, **kwargs) as lease:
                yield lease
            raise OSError("synthetic native release outcome unknown")

        with patch.object(self.policy, "hold", side_effect=release_uncertain):
            with self.assertRaisesRegex(OSError, "synthetic native release outcome unknown"):
                self.admit(context)
        observed = self.coordinator.reconcile_managed(context)
        self.assert_summary(observed, context, "RESERVED")
        self.assertIs(observed["submission_cleanup_pending"], True)
        guard = context._submission_guard
        before = self.rows("reservations")
        with patch.object(self.policy, "hold", side_effect=AssertionError("must not reacquire unknown native custody")):
            with self.assertRaises(ManagedAdmissionUnavailable):
                self.cancel_reserved(context, observed)
        self.assertIs(context._submission_guard, guard)
        self.assertEqual(self.rows("reservations"), before)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_known_native_release_with_failed_nonce_clear_can_retry_original_guard(self):
        context = self.context()
        policy = self.coordinator._managed_lifecycle_store()._policy
        with patch.object(policy, "_clear", side_effect=OSError("nonce clear unavailable")):
            with self.assertRaisesRegex(OSError, "nonce clear unavailable"):
                self.admit(context)
        observed = self.coordinator.reconcile_managed(context)
        self.assertIs(observed["submission_cleanup_pending"], True)
        self.assertIsNotNone(context._submission_guard)
        result = self.cancel_reserved(context, observed)
        self.assert_summary(result, context, "CANCELLED_BEFORE_START")
        self.assertIsNone(context._submission_guard)
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_original_initial_admission_rollback_proves_submission_rejected(self):
        context = self.context()
        self.conn().execute("""CREATE TRIGGER reject_initial_binding BEFORE INSERT ON managed_executions
            BEGIN SELECT RAISE(ABORT,'initial binding rejected'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "initial binding rejected"):
            self.admit(context)
        self.assertEqual(self.counts(), (0, 0, 0))
        observed = self.coordinator.reconcile_managed(context)
        self.assert_summary(observed, context, "SUBMISSION_REJECTED")
        result = self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assert_summary(result, context, "SUBMISSION_REJECTED")
        self.assert_sealed(context)
        self.assertIsNone(context._submission_guard)
        self.assert_summary(self.coordinator.cancel_managed(context, now=NOW + 2),
                            context, "SUBMISSION_REJECTED")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_lost_admission_commit_ack_and_missing_queue_never_prove_clean_rejection(self):
        context = self.context()
        original = self.coordinator._commit_admission

        def lose_ack(conn, transaction):
            original(conn, transaction)
            raise OSError("committed queue reply lost")

        with patch.object(self.coordinator, "_commit_admission", side_effect=lose_ack):
            with self.assertRaisesRegex(OSError, "committed queue reply lost"):
                self.admit(context, status(commit=94))
        self.coordinator.cancel_queued(owner_pid=os.getpid(),
            request_key=context.snapshot().request.request_key)
        self.assert_summary(self.coordinator.reconcile_managed(context), context,
                            "ABSENT_AFTER_SUBMISSION")
        with self.assertRaises(REFUSALS):
            self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_policy_busy_with_cleanup_notes_retains_unknown_publication_and_refuses_cancel(self):
        context = self.context()
        policy = self.coordinator._managed_lifecycle_store()._policy
        failure = PolicyBusy("policy_scope_busy")
        failure.add_note("lifecycle_connection_cleanup_failed")
        with patch.object(policy, "prepare", side_effect=failure):
            with self.assertRaises(PolicyBusy) as raised:
                self.admit(context)
        self.assertIs(raised.exception, failure)
        observed = self.coordinator.reconcile_managed(context)
        self.assert_summary(observed, context, "NEVER_SUBMITTED")
        self.assertIs(observed["submission_cleanup_pending"], True)
        self.assertTrue(context._submission_prepare_unknown)
        with self.assertRaises(ManagedAdmissionUnavailable):
            self.coordinator.cancel_managed(context, now=NOW + 1)
        self.assertIs(context._submission_policy_error, failure)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_reserved_cancel_refuses_cross_worker_allocation_before_archiving(self):
        context, admitted = self.reserved()
        self.inject_worker_alias(context)
        before = self.rows("reservations")
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.rows("reservations"), before)
        self.assertEqual(self.rows("executions"), [])
        self.assertEqual(self.rows("managed_executions")[0]["state"], "RESERVED")
        self.assertEqual(len(self.rows("worker_reservations")), 1)

    def test_reserved_cancel_refuses_matching_queue_before_archiving(self):
        context, admitted = self.reserved()
        self.inject_queue_alias(context)
        before = {table: self.rows(table) for table in ("queue", "reservations")}
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(before, {table: self.rows(table) for table in before})
        self.assertEqual(self.rows("executions"), [])
        self.assertEqual(self.rows("managed_executions")[0]["state"], "RESERVED")

    def test_queue_alias_either_request_key_or_execution_id_refuses_initial_and_replay(self):
        context, admitted = self.reserved()
        for terminal in (False, True):
            if terminal:
                self.cancel_reserved(context, admitted)
            for match in ("request_key", "managed_execution_id"):
                with self.subTest(terminal=terminal, match=match):
                    self.inject_queue_alias(context)
                    if match == "request_key":
                        self.conn().execute("UPDATE queue SET managed_execution_id='different-execution'")
                        key = context.snapshot().request.request_key
                    else:
                        self.conn().execute("UPDATE queue SET request_key='different-key'")
                        key = "different-key"
                    before = {table: self.rows(table) for table in
                              ("queue", "reservations", "managed_executions", "executions")}
                    try:
                        with self.assertRaises(REFUSALS):
                            self.cancel_reserved(context, admitted)
                        self.assertEqual(before, {table: self.rows(table) for table in before})
                    finally:
                        self.conn().execute("DELETE FROM queue WHERE request_key=?", (key,))

    def test_missing_or_tampered_launch_authentication_refuses_reserved_cancel(self):
        context, admitted = self.reserved()
        original = self.rows("managed_executions")[0]
        changes = (("admission_binding_hash", None), ("admission_binding_hash", "a" * 64),
                   ("claim_token_hash", ""),
                   ("claim_token_hash", "b" * 64))
        for field, value in changes:
            with self.subTest(field=field, value=value):
                self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?",
                                    (value, admitted["execution_id"]))
                before = {table: self.rows(table) for table in
                          ("reservations", "managed_executions", "executions")}
                try:
                    with self.assertRaises(REFUSALS):
                        self.cancel_reserved(context, admitted)
                    self.assertEqual(before, {table: self.rows(table) for table in before})
                finally:
                    self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?",
                                        (original[field], admitted["execution_id"]))

    def test_queue_alias_after_unused_claim_proof_is_rechecked_in_cancel_transaction(self):
        context, admitted = self.reserved()
        original_transaction = LifecycleStore._transaction
        injected = False

        @contextmanager
        def race_after_proof(store, **kwargs):
            nonlocal injected
            if context._cancel_sealed and not injected:
                injected = True
                self.inject_queue_alias(context)
                # Only the execution ID still matches; a request-key-only
                # precheck would miss this concurrently published obligation.
                self.conn().execute("UPDATE queue SET request_key='late-queue'")
            with original_transaction(store, **kwargs) as conn:
                yield conn

        with patch.object(LifecycleStore, "_transaction", race_after_proof):
            with self.assertRaises(REFUSALS):
                self.cancel_reserved(context, admitted)
        self.assertTrue(injected)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertEqual(self.rows("managed_executions")[0]["state"], "RESERVED")
        self.assertEqual(self.rows("executions"), [])

    def test_terminal_replay_refuses_cross_worker_allocation(self):
        context, admitted = self.reserved()
        self.cancel_reserved(context, admitted)
        archived = self.rows("executions")
        self.inject_worker_alias(context)
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.rows("executions"), archived)
        self.assertEqual(len(self.rows("worker_reservations")), 1)

    def test_terminal_replay_refuses_matching_queue(self):
        context, admitted = self.reserved()
        self.cancel_reserved(context, admitted)
        archived = self.rows("executions")
        self.inject_queue_alias(context)
        queued = self.rows("queue")
        with self.assertRaises(REFUSALS):
            self.cancel_reserved(context, admitted)
        self.assertEqual(self.rows("executions"), archived)
        self.assertEqual(self.rows("queue"), queued)

    def test_terminal_replay_requires_full_original_archive_binding(self):
        context, admitted = self.reserved()
        self.cancel_reserved(context, admitted)
        archived = self.rows("executions")[0]
        changes = {"owner_pid": archived["owner_pid"] + 1, "request_key": "different-request",
                   "repo": "different-repo", "command_signature": "different-command",
                   "cpu_units": archived["cpu_units"] + 1, "ram_gib": archived["ram_gib"] + 1,
                   "io_slots": archived["io_slots"] + 1, "priority": "P3",
                   "resource_class": "LIGHT", "started_at": archived["started_at"] + .5,
                   "ended_at": archived["ended_at"] + .5, "outcome": "managed_finished"}
        for field, value in changes.items():
            with self.subTest(field=field):
                self.conn().execute(f"UPDATE executions SET {field}=? WHERE reservation_id=?",
                                    (value, admitted["reservation_id"]))
                try:
                    with self.assertRaises(REFUSALS):
                        self.cancel_reserved(context, admitted)
                finally:
                    self.conn().execute(f"UPDATE executions SET {field}=? WHERE reservation_id=?",
                                        (archived[field], admitted["reservation_id"]))
        self.assertEqual(self.rows("executions"), [archived])

    def test_unsettled_admission_guard_blocks_claim_and_prepare_until_cancellation(self):
        context = self.context()
        original = self.coordinator._commit_admission

        def lose_ack(conn, transaction):
            original(conn, transaction)
            raise OSError("admission reply lost before handoff")

        with patch.object(self.coordinator, "_commit_admission", side_effect=lose_ack):
            with self.assertRaisesRegex(OSError, "admission reply lost before handoff"):
                self.admit(context)
        observed = self.coordinator.reconcile_managed(context)
        self.assert_summary(observed, context, "RESERVED")
        guard = context._submission_guard
        for operation in (context.launch_claim_token, context.mark_prepare_attempted):
            with self.assertRaises(ManagedAdmissionUnavailable):
                operation()
        self.assertIs(context._submission_guard, guard)
        self.assertFalse(context._claim_exported)
        self.assertFalse(context._prepare_attempted)
        self.assert_summary(self.cancel_reserved(context, observed), context, "CANCELLED_BEFORE_START")
        self.assertIsNone(context._submission_guard)
        self.assert_sealed(context)


if __name__ == "__main__":
    unittest.main()
