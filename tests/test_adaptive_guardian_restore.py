"""Real isolated SQLite/journal restore consumers with explicit native fixtures.

No Job, native cap, crash or production runtime is touched. Native custody and
API responses are synthetic; successful portable tests do not pass P1/P3.
"""
from contextlib import contextmanager
from dataclasses import replace
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, PendingIntent
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.guardian_restore import RestoreBatchError
from sentinel.adaptive.identity import IdentityUnavailable
from sentinel.adaptive.recovery_journal import RecoveryJournalError
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence
from sentinel.adaptive.windows import NativePolicyMutexError
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_guardian_lifecycle as fixture


DISABLED, CAP = fixture.DISABLED, fixture.CAP
NOW = fixture.fixtures.NOW


class RestoreJob(fixture.Job):
    def __init__(self, record, handle):
        super().__init__(record, handle)
        self.sets = 0
        self.disable_error = None
        self.on_disable = None
        self.disable_changes_state = True

    def disable(self):
        self._query()
        self.sets += 1
        if self.on_disable:
            self.on_disable()
        if self.disable_changes_state:
            self.control = {"flags": 0, "rate_bp": 10000}
        if self.disable_error:
            raise self.disable_error
        return SimpleNamespace(**self.control)


class GuardianRestoreTests(unittest.TestCase):
    setUp = fixture.GuardianLifecycleTests.setUp
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    start_consumer = fixture.GuardianLifecycleTests.start_consumer
    row = fixture.GuardianLifecycleTests.row
    allocation = fixture.GuardianLifecycleTests.allocation
    root_exits = fixture.GuardianLifecycleTests.root_exits
    assert_custody = fixture.GuardianLifecycleTests.assert_custody
    rewrite_manifest = fixture.GuardianLifecycleTests.rewrite_manifest
    sql = fixture.GuardianLifecycleTests.sql

    def case(self, *, control=CAP, pending=None, slot=True):
        case = self.seed_started()
        case.job = RestoreJob(case.record, case.job.handle)
        if control is not None or pending is not None:
            self.rewrite_manifest(case, manifest_seq=2, last_applied=control, pending_intent=pending)
        current = pending.new if pending is not None else control
        if current is not None and current != DISABLED:
            case.job.control = {"flags": 5, "rate_bp": current.cpu_rate_bp}
        if slot:
            self.seed_slot(case)
        if self.owner is None:
            self.start_consumer()
        self.owner.adopt_started(case.spec.execution_id,
            job=case.job, wrapper=case.wrapper, root=case.root)
        return case

    def seed_slot(self, case):
        self.sql("UPDATE adaptive_runtime SET mode='canary'")
        record = case.record
        def evidence(operation, row, caller):
            return LifecycleEvidence(operation, row["execution_id"], row["state_revision"],
                "explicit-control-setup", caller, guardian_epoch=record.guardian_epoch,
                job_name=record.job_name, job_nonce=record.creation_nonce, root=record.root_identity,
                durable_manifest=True, legacy_exclusion=True,
                active_process_count=len(case.job.members), process_ids=tuple(case.job.members))
        guard = self.seed_store._policy.prepare(record.wrapper_identity.logon_id)
        case.slot_id = str(uuid4())
        with patch.object(self.seed_store, "evidence_provider", fixture_evidence_provider(evidence)):
            with self.seed_store._policy.hold(guard):
                row = self.seed_store.query(case.spec.execution_id)
                self.seed_store.begin_control_slot_locked(case.spec.execution_id,
                    caller=record.wrapper_identity, expected_revision=row["state_revision"],
                    slot_id=case.slot_id, exemption_revision=0)
        self.sql("UPDATE adaptive_runtime SET mode='off'")

    def slot(self):
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM adaptive_control_slot").fetchone()
            return None if row is None else dict(row)

    def barrier(self):
        return self.connection().execute("SELECT admission_barrier FROM adaptive_runtime").fetchone()[0]

    def restore(self, case):
        return self.owner.restore_owned_cap(case.spec.execution_id)

    def journal_record(self, case):
        return self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)

    def assert_retained(self, case, allocation):
        self.assert_custody(case)
        self.assertEqual(self.allocation(case), allocation)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_explicit_restore_off_mode_set_query_journal_slot_preserves_live_floor(self):
        case = self.case()
        allocation, row = self.allocation(case), self.row(case)
        result = self.restore(case)
        self.assertTrue(result.native_disabled and result.bookkeeping_settled and result.slot_released)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(self.journal_record(case).last_applied, DISABLED)
        self.assertIsNone(self.journal_record(case).pending_intent)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")
        self.assertEqual(self.row(case), row)
        self.assert_retained(case, allocation)

    def test_disabled_baseline_has_no_set_and_no_fabricated_control_slot(self):
        case = self.case(control=None, slot=False)
        before = self.journal_record(case)
        result = self.restore(case)
        self.assertTrue(result.native_disabled and result.bookkeeping_settled)
        self.assertFalse(result.slot_released)
        self.assertIsNone(self.slot())
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.journal_record(case), before)

    def test_pending_new_value_is_restored_not_replayed(self):
        pending = PendingIntent(str(uuid4()), DISABLED, CAP)
        case = self.case(control=None, pending=pending)
        self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.journal_record(case).last_applied, DISABLED)
        self.assertIsNone(self.journal_record(case).pending_intent)

    def test_pending_old_disabled_value_is_settled_without_any_set(self):
        case = self.case(control=None, pending=PendingIntent(str(uuid4()), DISABLED, CAP))
        case.job.control = {"flags": 0, "rate_bp": 7777}
        self.restore(case)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")

    def test_readable_conflicting_cpu_state_never_overwrites_external_value(self):
        case = self.case()
        allocation = self.allocation(case)
        case.job.control = {"flags": 5, "rate_bp": 4000}
        with self.assertRaisesRegex(LifecycleError, "external_control_conflict") as caught:
            self.restore(case)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(case.job.control["rate_bp"], 4000)
        self.assertFalse(hasattr(caught.exception, "guardian_restore_result"))
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")
        self.assert_retained(case, allocation)

    def test_reconcile_consumes_restore_when_root_exits_but_child_lives(self):
        case = self.case()
        allocation = self.allocation(case)
        self.root_exits(case, children=(99119,))
        result = self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
        self.assertEqual(result.state, "DRAINING")
        self.assertFalse(result.restore_required or result.terminal)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        for name in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(self.allocation(case)[name], allocation[name])
        # This legacy fixture has no immutable lease duration. Observation
        # cannot invent one; only admitted allocations with known TTL renew.
        self.assertIsNone(allocation["lease_duration_sec"])
        self.assertEqual(self.allocation(case)["expires_at"], allocation["expires_at"])
        self.assert_custody(case)

    def test_reconcile_restores_then_terminalizes_only_verified_empty_job(self):
        case = self.case()
        self.root_exits(case)
        result = self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
        self.assertTrue(result.terminal)
        self.assertIsNone(self.allocation(case))
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")

    def test_restore_does_not_query_root_or_wrapper_liveness_or_membership(self):
        case = self.case()
        self.processes.entry(case.root).wait_error = IdentityUnavailable("fixture_root_unknown")
        self.processes.entry(case.wrapper).wait_error = IdentityUnavailable("fixture_wrapper_unknown")
        result = self.restore(case)
        self.assertTrue(result.bookkeeping_settled)
        self.assertEqual(case.job.sets, 1)

    def test_early_db_failure_native_restore_uses_pinned_same_mutex_without_sql(self):
        case = self.case()
        allocation = self.allocation(case)
        binding = self.owner._restorer.binding
        pinned = self.owner._restorer.policy_mutex
        self.assertEqual((pinned.instance_id, pinned.logon_id), (binding.instance_id, binding.logon_id))
        def under_emergency_fences():
            self.assertTrue(pinned.acquired)
            self.assertTrue(self.owner._entry(case.spec.execution_id).mutex.acquired)
            self.assertIsNone(self.store._policy.current_guard())
        case.job.on_disable = under_emergency_fences
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("fixture DB missing")):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertFalse(caught.exception.guardian_restore_result.bookkeeping_settled)
        self.assertIn("guardian_native_disabled_bookkeeping_unresolved", caught.exception.__notes__)
        self.assertEqual(self.journal_record(case).last_applied, CAP)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assert_retained(case, allocation)
        case.job.on_disable = None
        self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")

    def test_missing_manifest_uses_only_retained_previously_verified_candidates(self):
        case = self.case()
        path = self.journal_dir / (case.spec.execution_id + ".json")
        previous = path.read_bytes()
        path.unlink()
        with self.assertRaises(RecoveryJournalError) as caught:
            self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertFalse(caught.exception.guardian_restore_result.bookkeeping_settled)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        path.write_bytes(previous)
        self.restore(case)
        self.assertEqual(case.job.sets, 1)

    def test_unavailable_manifest_can_restore_cached_cap_without_claiming_settlement(self):
        case = self.case()
        with patch.object(self.journal, "read", side_effect=RecoveryJournalError("manifest_read_unavailable")):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")

    def test_corrupt_readable_manifest_never_falls_back_to_cache(self):
        case = self.case()
        (self.journal_dir / (case.spec.execution_id + ".json")).write_text("{}", encoding="utf-8")
        with self.assertRaises(RecoveryJournalError) as caught:
            self.restore(case)
        self.assertFalse(hasattr(caught.exception, "guardian_restore_result"))
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(case.job.control["rate_bp"], CAP.cpu_rate_bp)

    def test_retained_journal_cleanup_quarantine_prevents_repeated_reads(self):
        case = self.case()
        error = RecoveryJournalError("manifest_read_unavailable")
        cleanup_owner = object()
        error._journal_cleanup_owner = cleanup_owner
        with patch.object(self.journal, "read", side_effect=error) as read:
            with self.assertRaises(RecoveryJournalError) as first:
                self.restore(case)
            self.assertTrue(first.exception.guardian_restore_result.native_disabled)
            with self.assertRaisesRegex(LifecycleError, "guardian_journal_cleanup_unverified") as second:
                self.restore(case)
            self.assertTrue(second.exception.guardian_restore_result.native_disabled)
            self.assertEqual(read.call_count, 1)
        retained = self.owner._entry(case.spec.execution_id).journal_cleanup_error
        self.assertIs(retained._journal_cleanup_owner, cleanup_owner)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")
        self.assert_custody(case)

    def test_readable_changed_identity_is_not_unavailable_and_gets_no_set(self):
        case = self.case()
        self.rewrite_manifest(case, manifest_seq=3,
            guardian_identity=replace(fixture.GUARDIAN, pid=fixture.GUARDIAN.pid + 1))
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_manifest_changed"):
            self.restore(case)
        self.assertEqual(case.job.sets, 0)

    def test_corruption_with_cleanup_failure_cannot_become_cached_restore_authority(self):
        case = self.case()
        error = RecoveryJournalError("manifest_invalid")
        error._journal_cleanup_owner = object()
        with patch.object(self.journal, "read", side_effect=error) as read:
            with self.assertRaises(RecoveryJournalError):
                self.restore(case)
            with self.assertRaisesRegex(LifecycleError, "guardian_restore_integrity_unresolved"):
                self.restore(case)
            self.assertEqual(read.call_count, 1)
        self.assertFalse(self.owner._entry(case.spec.execution_id).restore_native_disabled)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assert_custody(case)

    def test_prior_success_cannot_be_reused_as_this_failed_attempts_disabled_evidence(self):
        case = self.case()
        self.restore(case)
        case.job.control = {"flags": 5, "rate_bp": 4000}
        (self.journal_dir / (case.spec.execution_id + ".json")).write_text("{}", encoding="utf-8")
        with self.assertRaises(RecoveryJournalError) as caught:
            self.restore(case)
        self.assertFalse(hasattr(caught.exception, "guardian_restore_result"))
        self.assertFalse(self.owner._entry(case.spec.execution_id).restore_native_disabled)
        self.assertEqual(case.job.sets, 1)

    def test_readable_invalid_then_unavailable_never_uses_cached_restore(self):
        case = self.case()
        invalid = RecoveryJournalError("manifest_invalid")
        unavailable = RecoveryJournalError("manifest_read_unavailable")
        with patch.object(self.journal, "read", side_effect=[invalid, unavailable]) as read:
            with self.assertRaises(RecoveryJournalError) as caught:
                self.restore(case)
            self.assertIs(caught.exception, invalid)
            self.assertEqual(read.call_count, 1)
            with self.assertRaisesRegex(LifecycleError, "guardian_restore_integrity_unresolved"):
                self.restore(case)
            self.assertEqual(read.call_count, 1)
        self.assertEqual(case.job.sets, 0)
        self.assertIs(self.owner._entry(case.spec.execution_id).restore_integrity_error, invalid)
        self.assertIsNone(self.owner._restorer.fence_error)
        self.assert_custody(case)

    def test_reconcile_changed_manifest_then_unavailable_never_uses_cache(self):
        case = self.case()
        changed = self.rewrite_manifest(case, manifest_seq=3,
            guardian_identity=replace(fixture.GUARDIAN, pid=fixture.GUARDIAN.pid + 1))
        with patch.object(self.journal, "read", side_effect=[changed,
                RecoveryJournalError("manifest_read_unavailable")]) as read:
            with self.assertRaisesRegex(LifecycleError, "guardian_custody_binding_mismatch"):
                self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
            self.assertEqual(read.call_count, 1)
            with self.assertRaisesRegex(LifecycleError, "guardian_restore_integrity_unresolved"):
                self.restore(case)
            self.assertEqual(read.call_count, 1)
        self.assertEqual(case.job.sets, 0)
        self.assert_custody(case)

    def test_emergency_first_integrity_failure_stays_sticky_across_db_outage_retries(self):
        case = self.case()
        invalid = RecoveryJournalError("manifest_invalid")
        unavailable = RecoveryJournalError("manifest_read_unavailable")
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("fixture DB unavailable")):
            with patch.object(self.journal, "read", side_effect=[invalid, unavailable]) as read:
                with self.assertRaises(sqlite3.OperationalError) as first:
                    self.restore(case)
                self.assertIs(first.exception.guardian_restore_error, invalid)
                self.assertIs(self.owner._entry(case.spec.execution_id).restore_integrity_error, invalid)
                with self.assertRaises(sqlite3.OperationalError) as second:
                    self.restore(case)
                self.assertEqual(read.call_count, 1)
                self.assertFalse(hasattr(second.exception, "guardian_restore_result"))
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.owner._restorer.fence_error)
        self.assert_custody(case)

    def test_generic_normal_policy_exit_failure_poison_prevents_emergency_reacquire(self):
        case = self.case(control=None, slot=False)
        normal_hold = self.policy.hold
        failure = OSError("fixture native policy cleanup unknown")
        @contextmanager
        def failed_exit(binding, *, timeout_ms):
            with normal_hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
            raise failure
        pinned = self.owner._restorer.policy_mutex
        with patch.object(self.policy, "hold", side_effect=failed_exit):
            with patch.object(pinned, "acquire", wraps=pinned.acquire) as acquire:
                with self.assertRaises(OSError) as caught:
                    self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
                self.assertIs(caught.exception, failure)
                self.assertIn("policy_scope_cleanup_failed", failure.__notes__)
                self.assertIs(self.owner._restorer.fence_error, failure)
                with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_uncertain"):
                    self.restore(case)
                acquire.assert_not_called()
        self.assertEqual(case.job.sets, 0)
        self.assert_custody(case)

    def test_terminal_lost_ack_requires_resolved_slot_before_close_without_rearchive(self):
        case = self.case()
        self.root_exits(case)
        finalize = self.store.finalize_if_empty
        def lost_ack(*args, **kwargs):
            finalize(*args, **kwargs)
            raise sqlite3.OperationalError("fixture terminal ACK unknown")
        with patch.object(self.store, "finalize_if_empty", side_effect=lost_ack):
            with self.assertRaises(sqlite3.OperationalError):
                self.owner.reconcile(case.spec.execution_id, now=NOW + 1)
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        with patch.object(self.store, "query_control_slot_locked", side_effect=LifecycleError("control_slot_invalid")):
            with self.assertRaisesRegex(LifecycleError, "control_slot_invalid"):
                self.owner.reconcile(case.spec.execution_id, now=NOW + 2)
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_unsettled"):
            self.owner.close_terminal(case.spec.execution_id)
        with patch.object(self.store, "finalize_if_empty", side_effect=AssertionError("must not archive again")):
            result = self.owner.reconcile(case.spec.execution_id, now=NOW + 3)
        self.assertTrue(result.terminal)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")
        self.owner.close_terminal(case.spec.execution_id)
        self.assertTrue(case.job.closed)

    def test_set_may_apply_then_fail_keeps_intent_and_retry_queries_without_second_set(self):
        case = self.case()
        original = self.journal_record(case)
        case.job.disable_error = OSError("fixture lost Set ACK")
        with self.assertRaises(OSError):
            self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.journal_record(case), original)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        case.job.disable_error = None
        self.restore(case)
        self.assertEqual(case.job.sets, 1)

    def test_set_readback_still_enabled_does_not_publish_or_release(self):
        case = self.case()
        case.job.disable_changes_state = False
        with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
            self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.journal_record(case).last_applied, CAP)
        self.assertEqual(self.slot()["slot_state"], "HELD")

    def test_independent_query_failure_after_set_retains_full_allocation(self):
        case = self.case()
        allocation = self.allocation(case)
        case.job.on_disable = lambda: setattr(case.job, "query_error", OSError("fixture query unavailable"))
        with self.assertRaises(OSError):
            self.restore(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assert_retained(case, allocation)

    def test_journal_publish_ack_loss_requires_new_positive_publication_before_slot_release(self):
        case = self.case()
        publish = self.journal.publish
        committed = []
        def lost_ack(record, **kwargs):
            result = publish(record, **kwargs)
            committed.append(result)
            raise RecoveryJournalError("manifest_publication_unverified", publication_may_have_occurred=True)
        with patch.object(self.journal, "publish", side_effect=lost_ack):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.journal_record(case), committed[0])
        self.restore(case)
        self.assertEqual(self.journal_record(case).manifest_seq, committed[0].manifest_seq + 1)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")

    def test_journal_failure_before_publish_preserves_disabled_native_and_unsettled_slot(self):
        case = self.case()
        before = self.journal_record(case)
        with patch.object(self.journal, "publish", side_effect=RecoveryJournalError("manifest_write_unavailable")):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(self.journal_record(case), before)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.restore(case)
        self.assertEqual(case.job.sets, 1)

    def test_slot_release_ack_loss_replays_exact_slot_with_no_extra_set_or_release_revision(self):
        case = self.case()
        release = self.store.release_control_slot_locked
        def lost_ack(*args, **kwargs):
            release(*args, **kwargs)
            raise sqlite3.OperationalError("fixture slot commit ACK lost")
        with patch.object(self.store, "release_control_slot_locked", side_effect=lost_ack):
            with self.assertRaises(sqlite3.OperationalError):
                self.restore(case)
        slot = self.slot()
        self.assertEqual(slot["slot_state"], "RESTORED")
        self.restore(case)
        self.assertEqual(self.slot(), slot)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.barrier(), "RECOVERY_HOLD")

    def test_missing_slot_never_becomes_success_after_native_and_journal_restore(self):
        case = self.case()
        self.sql("DELETE FROM adaptive_control_slot")
        self.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_slot_unresolved") as caught:
            self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(case.job.sets, 1)
        self.assertIsNone(self.slot())
        self.assert_custody(case)

    def test_slot_query_error_is_not_treated_as_absent_and_never_releases_allocation(self):
        case = self.case()
        allocation = self.allocation(case)
        with patch.object(self.store, "query_control_slot_locked", side_effect=LifecycleError("control_slot_invalid")):
            with self.assertRaisesRegex(LifecycleError, "control_slot_invalid") as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assert_retained(case, allocation)

    def test_no_pinned_binding_cannot_invent_emergency_authority(self):
        case = self.case()
        pinned = self.owner._restorer.policy_mutex
        self.owner._restorer.binding = None  # Explicit corrupt in-memory fixture.
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("fixture unavailable")):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.restore(case)
        self.assertFalse(hasattr(caught.exception, "guardian_restore_result"))
        self.assertIsInstance(caught.exception.guardian_restore_error, LifecycleError)
        self.assertFalse(pinned.acquired)
        self.assertEqual(case.job.sets, 0)

    def test_emergency_release_uncertainty_keeps_mutex_custody_and_poisons_reacquire(self):
        case = self.case()
        pinned = self.owner._restorer.policy_mutex
        pinned.release_error = NativePolicyMutexError("policy_mutex_release_failed", 5)
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("fixture unavailable")):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertTrue(pinned.acquired)
        self.assertIsNotNone(self.owner._restorer.fence_error)
        pinned.release_error = None
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_uncertain"):
            self.restore(case)
        self.assertTrue(pinned.acquired)
        self.assertEqual(case.job.sets, 1)

    def test_abandoned_emergency_mutex_only_restores_and_never_clears_barrier(self):
        case = self.case()
        self.owner._restorer.policy_mutex.abandoned = True
        with patch.object(self.store, "_connection", side_effect=sqlite3.OperationalError("fixture unavailable")):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.restore(case)
        self.assertTrue(caught.exception.guardian_restore_result.native_disabled)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.barrier(), "CONTROLLING")

    def test_restore_batch_continues_to_later_cap_after_first_bookkeeping_failure(self):
        first = self.case(control=None, slot=False)
        second = self.case()
        service = GuardianLaunchOwner.__new__(GuardianLaunchOwner)
        service.lifecycle, service._lock = self.owner, self.owner._lock
        query = self.store.query
        def unavailable_first(execution_id, **kwargs):
            if execution_id == first.spec.execution_id:
                raise sqlite3.OperationalError("fixture first query unavailable")
            return query(execution_id, **kwargs)
        with patch.object(self.store, "query", side_effect=unavailable_first):
            with self.assertRaises(RestoreBatchError) as caught:
                service.restore_owned_caps()
        self.assertEqual(len(caught.exception.restore_errors), 1)
        self.assertEqual(caught.exception.restore_errors[0][0], first.spec.execution_id)
        self.assertEqual(caught.exception.restore_results[0].execution_id, second.spec.execution_id)
        self.assertEqual(second.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "RESTORED")
        self.assert_custody(first)
        self.assert_custody(second)
