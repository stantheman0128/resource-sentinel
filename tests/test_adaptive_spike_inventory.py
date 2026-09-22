"""Shared-ledger inventory over real isolated SQLite/canonical retirement.

Native backends below are explicit existing unit fixtures. The S1-shaped owner
adapter exercises scanner integration only: it is not an authenticated runtime
bridge or evidence that Windows S1 can currently run.
"""
from contextlib import contextmanager
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import CpuControl, CpuControlMode, IdentityStatus
from sentinel.adaptive.recovery_journal import RecoveryJournalError
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_terminal_receipt as receipt_fixture
from tests import test_adaptive_terminal_custody as custody_fixture
from tests.windows.adaptive_execution import S1ExecutionOwner, S1Runtime
from tests.windows.adaptive_spike_inventory import SpikeRecoveryInventory, PAGE_SIZE


class CanonicalOwnerFixture(S1ExecutionOwner):
    """Explicit synthetic S1 subclass borrowing an actual guardian fixture."""
    def __init__(self, fixture, case, runtime):
        self.fixture, self.case, self._runtime = fixture, case, runtime
        self.store, self.journal = fixture.store, fixture.journal
        self.execution_id = case.spec.execution_id
        self.creation_nonce = case.record.creation_nonce
        self.job_name, self.guardian_epoch = case.record.job_name, case.record.guardian_epoch
        self.caller, self._root = case.record.wrapper_identity, case.record.root_identity
        self._entry = fixture.owner._entry(self.execution_id)
        self._closed = self._cleanup_started = self._control_pending = False
        self._recovery_job_released = False
        self._create_attempted = True
        self._terminal = fixture.row(case)["state"] == "FINISHED"
        self._sealed = True
        self.retained = False
        self.job = SimpleNamespace(name=case.job.name, nonce=case.job.nonce,
            logon_sid=case.job.logon_sid,
            accounting=lambda: {"active_processes": case.job.accounting().active_processes},
            active_pids=case.job.active_pids)
        self.process = SimpleNamespace(
            full_identity=lambda **_: case.root.observe().identity,
            wait=lambda _: case.root.observe().status is IdentityStatus.DEAD)

    def _assert_row(self, row):
        self.store._retained_inputs(row, self.journal.read(self.execution_id,
                                                        creation_nonce=self.creation_nonce))

    @contextmanager
    def mutation_scope(self):
        with self.fixture.owner._scope(self._entry):
            yield self

    def query_cpu_control(self):
        state = self.case.job.query_cpu()
        return (CpuControl(CpuControlMode.DISABLED, None) if state.flags == 0 else
                CpuControl(CpuControlMode.HARD_CAP, state.rate_bp))

    def _read_manifest(self):
        return self.journal.read(self.execution_id, creation_nonce=self.creation_nonce)

    def _retain(self):
        self.retained = True


class SpikeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = receipt_fixture.TerminalReceiptTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def original(self, case=None, *, fixture=None, runtime=None):
        fixture = fixture or self.fixture
        case = fixture.finished_case() if case is None else case
        if runtime is None:
            runtime = S1Runtime(coordinator=SimpleNamespace(db_path=fixture.db),
                authority=SimpleNamespace(), native=SimpleNamespace())
        owner = CanonicalOwnerFixture(fixture, case, runtime)
        runtime.owners.append(owner)
        return owner, runtime

    def retired(self):
        case = self.fixture.finished_case()
        self.assertTrue(self.fixture.retire(case).complete)
        self.fixture.read_receipt(case)
        return case

    def complete(self, scanner, owner):
        pages = []
        while True:
            pages.append(scanner.scan_next(owner))
            if pages[-1].complete:
                return pages, scanner.snapshot

    def test_more_than_64_real_retired_rows_are_paged_without_enrollment_charge(self):
        for _ in range(65):
            self.retired()
        owner, runtime = self.original()
        before = self.fixture.durable_snapshot()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        pages, snapshot = self.complete(scanner, owner)
        self.assertEqual([p.scanned_rows for p in pages], [PAGE_SIZE, PAGE_SIZE * 2, 66])
        self.assertEqual(snapshot.retired_foreign_rows, 65)
        self.assertEqual(snapshot.active_jobs, 0)
        self.assertEqual(len(snapshot.owned_rows), 1)
        self.assertEqual(snapshot.owned_rows[0]["execution_id"], owner.execution_id)
        self.assertEqual(self.fixture.durable_snapshot(), before)
        self.assertFalse(owner.case.job.closed)

    def test_foreign_finished_without_positive_receipt_is_refused(self):
        self.fixture.finished_case()
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "terminal_receipt_missing"):
            scanner.scan_next(owner)
        self.assertTrue(owner.retained)
        self.assertFalse(owner.case.job.closed)
        with self.assertRaisesRegex(LifecycleError, "incomplete"):
            _ = scanner.snapshot

    def test_foreign_active_row_is_never_treated_as_history(self):
        self.fixture.adopt()
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "foreign_execution_unverified"):
            scanner.scan_next(owner)

    def test_corrupt_empty_key_cannot_fall_before_initial_keyset_cursor(self):
        foreign = self.fixture.adopt()
        owner, runtime = self.original()
        self.fixture.sql("UPDATE managed_executions SET execution_id='' WHERE execution_id=?",
                         (foreign.spec.execution_id,))
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "execution_identity_invalid"):
            scanner.scan_next(owner)

    def test_corrupted_receipt_or_manifest_does_not_become_empty_history(self):
        case = self.retired()
        owner, runtime = self.original()
        self.fixture.sql("UPDATE adaptive_terminal_custody_receipts SET receipt_hash=? WHERE execution_id=?",
                         ("0" * 64, case.spec.execution_id))
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "terminal_receipt_changed"):
            scanner.scan_next(owner)

    def test_owned_rows_are_immutable_and_snapshot_cannot_be_reconstructed(self):
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        _, snapshot = self.complete(scanner, owner)
        with self.assertRaises(TypeError):
            snapshot.owned_rows[0]["state"] = "RUNNING"
        with owner.mutation_scope(), owner.store._connection() as conn:
            conn.execute("BEGIN")
            with self.assertRaisesRegex(LifecycleError, "complete_original_snapshot_required"):
                scanner.assert_current_locked(owner, conn, replace(snapshot))
            self.assertEqual(scanner.assert_current_locked(owner, conn, snapshot)[0]["registry_revision"],
                             snapshot.registry_revision)

    def test_same_execution_id_does_not_replace_original_owner(self):
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        impostor = CanonicalOwnerFixture(self.fixture, owner.case, runtime)
        with self.assertRaisesRegex(LifecycleError, "original_owner_required"):
            scanner.scan_next(impostor)
        runtime.owners[0] = impostor
        with self.assertRaisesRegex(LifecycleError, "owner_inventory_changed"):
            scanner.scan_next(owner)

    def test_adding_an_owner_invalidates_the_scan(self):
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        runtime.owners.append(owner)
        with self.assertRaisesRegex(LifecycleError, "owner_inventory_changed"):
            scanner.scan_next(owner)

    def test_second_unsettled_original_cannot_be_hidden_in_complete_inventory(self):
        owner, runtime = self.original()
        other, _ = self.original(runtime=runtime)
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "other_owner_unsettled"):
            scanner.scan_next(owner)
        self.assertFalse(other.case.job.closed)

    def test_closed_predecessor_requires_the_actual_same_object_settled_witness(self):
        previous, runtime = self.original()
        previous._closed = True
        owner, _ = self.original(runtime=runtime)
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "terminal_witness_missing"):
            scanner.scan_next(owner)

    def test_closed_predecessor_uses_positive_retained_witness_without_closed_native_reads(self):
        from tests.windows.adaptive_recovery import S1Recovery
        previous, runtime = self.original()
        with previous.mutation_scope():
            witness = S1Recovery._prove_owner(runtime._recovery, previous, self.fixture.row(previous.case))
        runtime._recovery._settled[previous.execution_id] = witness
        self.assertTrue(self.fixture.retire(previous.case).complete)
        previous._closed = previous._recovery_job_released = True
        owner, _ = self.original(runtime=runtime)
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with patch.object(previous, "_assert_row", side_effect=AssertionError("closed admission read")), \
                patch.object(previous.case.job, "_query", side_effect=AssertionError("closed native query")):
            _, snapshot = self.complete(scanner, owner)
        self.assertEqual(len(snapshot.owned_rows), 2)
        self.assertEqual(snapshot.retired_foreign_rows, 0)

    def test_current_owner_native_contradiction_blocks_inventory_completion(self):
        owner, runtime = self.original()
        owner.case.job.members.append(34567)
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        with self.assertRaisesRegex(LifecycleError, "job_not_empty"):
            scanner.scan_next(owner)

    def test_registry_change_between_pages_invalidates_progress(self):
        for _ in range(PAGE_SIZE):
            self.retired()
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        self.assertFalse(scanner.scan_next(owner).complete)
        self.fixture.sql("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
        with self.assertRaisesRegex(LifecycleError, "registry_or_hold_changed"):
            scanner.scan_next(owner)

    def off_hold(self, fixture=None):
        fixture = fixture or self.fixture
        fixture.sql("""CREATE TABLE adaptive_off_holds (
            request_id TEXT PRIMARY KEY, policy_instance_id TEXT NOT NULL,
            guardian_epoch TEXT NOT NULL, created_revision INTEGER NOT NULL,
            boundary_tick INTEGER, prior_barrier TEXT NOT NULL, prior_slot_id TEXT,
            cleared_revision INTEGER)""")
        fixture.sql("""INSERT INTO adaptive_off_holds
            SELECT 'fixture-new-generation',policy_instance_id,guardian_epoch,registry_revision,
                100,admission_barrier,NULL,NULL FROM adaptive_runtime""")

    def test_off_generation_change_is_detected_even_without_revision_change(self):
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        _, snapshot = self.complete(scanner, owner)
        self.off_hold()
        with owner.mutation_scope(), owner.store._connection() as conn:
            conn.execute("BEGIN")
            with self.assertRaisesRegex(LifecycleError, "registry_or_hold_changed"):
                scanner.assert_current_locked(owner, conn, snapshot)

    def test_pending_admission_and_noncanonical_owner_journal_are_refused(self):
        owner, runtime = self.original()
        runtime.pending_admissions.append(object())
        with self.assertRaisesRegex(LifecycleError, "admission_unsettled"):
            SpikeRecoveryInventory(runtime, self.fixture.journal)
        runtime.pending_admissions.clear()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        owner.journal = object()
        # The original owner's identity validation normally reads its journal;
        # bypass only that fixture precheck to test the scanner's explicit gate.
        with patch.object(owner, "_assert_row"):
            with self.assertRaisesRegex(LifecycleError, "canonical_owner_journal_required"):
                scanner.scan_next(owner)

    def test_journal_cleanup_exception_keeps_actual_owner_reachable(self):
        owner, runtime = self.original()
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        failure = RecoveryJournalError("manifest_stream_cleanup_unverified")
        custody = object()
        failure._journal_cleanup_owner = custody
        with patch.object(owner, "_assert_row"), patch.object(owner.journal, "read", side_effect=failure):
            with self.assertRaises(RecoveryJournalError) as caught:
                scanner.scan_next(owner)
        self.assertIs(caught.exception, failure)
        self.assertIs(owner._spike_inventory_failure[1]._journal_cleanup_owner, custody)
        self.assertTrue(owner.retained)

    def test_history_is_not_a_native_close_or_barrier_clear_permission(self):
        owner, runtime = self.original()
        self.fixture.sql("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        scanner = SpikeRecoveryInventory(runtime, self.fixture.journal)
        _, snapshot = self.complete(scanner, owner)
        with self.assertRaisesRegex(LifecycleError, "applicable_finished_slot_required"):
            scanner.clear_finished(owner, snapshot)
        self.assertEqual(self.fixture.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertFalse(owner.case.job.closed)

    def controlled(self):
        fixture = custody_fixture.TerminalControlRetirementTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        case = fixture.finished_after_cap()
        owner, runtime = self.original(case, fixture=fixture)
        scanner = SpikeRecoveryInventory(runtime, fixture.journal)
        return fixture, owner, scanner

    def test_c3_uses_real_finished_archive_and_preserves_native_custody(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        with patch.object(owner.store, "clear_recovery_hold_finished_locked",
                          wraps=owner.store.clear_recovery_hold_finished_locked) as clear:
            result = scanner.clear_finished(owner, snapshot, now=fixture.row(owner.case)["finished_at"] + 1)
        self.assertEqual(clear.call_count, 1)
        self.assertEqual(result["admission_barrier"], "NONE")
        self.assertEqual(fixture.runtime()["admission_barrier"], "NONE")
        self.assertFalse(owner.case.job.closed)
        self.assertFalse(owner._closed)

    def test_general_off_hold_cannot_be_cleared_by_old_finished_slot(self):
        fixture, owner, scanner = self.controlled()
        self.off_hold(fixture)
        _, snapshot = self.complete(scanner, owner)
        with patch.object(owner.store, "clear_recovery_hold_finished_locked",
                          side_effect=AssertionError("general hold must not reach C3")):
            with self.assertRaisesRegex(LifecycleError, "off_inventory_recovery_pending"):
                scanner.clear_finished(owner, snapshot)
        self.assertEqual(fixture.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(fixture.connection().execute(
            "SELECT cleared_revision FROM adaptive_off_holds").fetchone()[0])

    def test_finished_label_does_not_replace_current_native_empty_proof(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        owner.case.job.members.append(918273)
        with self.assertRaisesRegex(LifecycleError, "job_not_empty"):
            scanner.clear_finished(owner, snapshot)
        self.assertEqual(fixture.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertFalse(owner.case.job.closed)

    def test_late_off_generation_refusal_releases_the_read_only_policy_scope(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        self.off_hold(fixture)
        with self.assertRaisesRegex(LifecycleError, "registry_or_hold_changed"):
            scanner.clear_finished(owner, snapshot)
        self.assertIsNone(fixture.runtime()["policy_entry_nonce"])
        self.assertEqual(fixture.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertIsNone(getattr(scanner, "_c3_attempt", None))

    def lost_clear_ack(self, fixture, owner, scanner, snapshot, *, release_scope):
        original_clear = owner.store.clear_recovery_hold_finished_locked
        original_scope = owner.mutation_scope

        def committed_then_lost(*args, **kwargs):
            original_clear(*args, **kwargs)
            raise OSError("fixture committed clear acknowledgement lost")

        @contextmanager
        def cleaned_before_ack_loss():
            error = None
            with original_scope():
                try:
                    yield owner
                except OSError as failed:
                    error = failed
            if error is not None:
                raise error

        with patch.object(owner.store, "clear_recovery_hold_finished_locked", side_effect=committed_then_lost):
            if release_scope:
                with patch.object(owner, "mutation_scope", cleaned_before_ack_loss):
                    with self.assertRaises(OSError):
                        scanner.clear_finished(owner, snapshot, now=fixture.row(owner.case)["finished_at"] + 1)
            else:
                with self.assertRaises(OSError):
                    scanner.clear_finished(owner, snapshot, now=fixture.row(owner.case)["finished_at"] + 1)
        self.assertEqual(fixture.runtime()["admission_barrier"], "NONE")

    def test_lost_clear_ack_with_released_nonce_reconciles_read_only(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        self.lost_clear_ack(fixture, owner, scanner, snapshot, release_scope=True)
        self.assertIsNone(fixture.runtime()["policy_entry_nonce"])
        with patch.object(owner, "mutation_scope", side_effect=AssertionError("must not mint a new guard")), \
                patch.object(owner.store, "clear_recovery_hold_finished_locked",
                             side_effect=AssertionError("must not clear a second time")):
            result = scanner.clear_finished(owner, snapshot)
        self.assertTrue(result["duplicate"])
        self.assertEqual(result["registry_revision"], snapshot.registry_revision + 1)
        self.assertFalse(owner.case.job.closed)

    def test_lost_clear_ack_with_retained_nonce_reuses_exact_guard(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        self.lost_clear_ack(fixture, owner, scanner, snapshot, release_scope=False)
        guard = scanner._c3_attempt["guard"]
        self.assertEqual(fixture.runtime()["policy_entry_nonce"], guard.nonce)
        with patch.object(owner.store, "clear_recovery_hold_finished_locked",
                          side_effect=AssertionError("must not clear a second time")):
            result = scanner.clear_finished(owner, snapshot)
        self.assertTrue(result["duplicate"])
        self.assertIs(scanner._c3_attempt["guard"], guard)
        self.assertIsNone(fixture.runtime()["policy_entry_nonce"])

    def test_lost_clear_ack_does_not_accept_a_different_audit_timestamp(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        self.lost_clear_ack(fixture, owner, scanner, snapshot, release_scope=True)
        fixture.sql("UPDATE adaptive_barrier_clears SET cleared_at=cleared_at+1")
        with patch.object(owner.store, "clear_recovery_hold_finished_locked",
                          side_effect=AssertionError("changed evidence must remain read-only")):
            with self.assertRaisesRegex(LifecycleError, "c3_audit_unverified"):
                scanner.clear_finished(owner, snapshot)

    def test_clear_journal_cleanup_failure_is_retained_and_quarantined(self):
        fixture, owner, scanner = self.controlled()
        _, snapshot = self.complete(scanner, owner)
        failure = RecoveryJournalError("manifest_stream_cleanup_unverified")
        native_file_owner = object()
        failure._journal_cleanup_owner = native_file_owner
        with patch.object(owner.journal, "read", side_effect=failure):
            with self.assertRaises(RecoveryJournalError):
                scanner.clear_finished(owner, snapshot)
        self.assertTrue(owner.retained)
        self.assertIs(owner._spike_c3_quarantine[1][0]._journal_cleanup_owner, native_file_owner)
        with self.assertRaisesRegex(LifecycleError, "c3_cleanup_quarantined"):
            scanner.clear_finished(owner, snapshot)
        self.assertEqual(fixture.runtime()["admission_barrier"], "RECOVERY_HOLD")


if __name__ == "__main__":
    unittest.main()
