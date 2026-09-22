"""Real isolated ledger/journal floor publication with explicit native fixtures.

No host measurements, Job creation, process control or native durability is
claimed. The fault cuts exercise actual publication/accounting and the retained
restore/drain consumers; these portable tests cannot pass a Windows gate.
"""
from contextlib import contextmanager
from dataclasses import fields, replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.accounting import update_demand_floor
from sentinel.adaptive.contracts import (
    FrameError, PendingIntent, RecoveryManifest, ResourceDemand, RetryClass, Validity,
)
from sentinel.adaptive.guardian_floor import FloorPublisher, reconcile_orphan_floor_locked
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_decision as samples
from tests import test_adaptive_guardian_restore as fixtures
from tests import test_adaptive_orphan_lifecycle as orphan_fixtures


KEYS = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")
DISABLED, CAP = fixtures.DISABLED, fixtures.CAP
GIB = 1 << 30


def floor(row):
    return ResourceDemand.from_dict({key: row["floor_" + key] for key in KEYS})


def with_floor(record, demand):
    values = {field.name: getattr(record, field.name) for field in fields(record)
              if field.name != "manifest_hash"}
    values["allocated_floor"] = demand
    return RecoveryManifest.create(**values)


class GuardianFloorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.GuardianRestoreTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def case(self, **kwargs):
        case = self.fixture.case(**({"control": DISABLED, "slot": False} | kwargs))
        self.owner = self.fixture.owner
        self.publisher = FloorPublisher(SimpleNamespace(lifecycle=self.owner))
        self.entry = self.owner._entry(case.spec.execution_id)
        return case

    def frame(self, case, *, errors=(), validity=Validity.VALID, **measurements):
        job = samples.job(case.spec.execution_id, active_processes=len(case.job.members),
            **({"cpu_units": 3, "cpu_uncapped_high_water_units": 11,
                "private_working_set_bytes": 3 * GIB, "private_commit_bytes": 4 * GIB} | measurements))
        return samples.frame(1, samples.at(1), samples.LOW_BUSY,
                             jobs=(job,), errors=errors, validity=validity)

    def prepare(self, case, frame=None, *, uncapped=True):
        with self.owner._scope(self.entry):
            return self.publisher.prepare_locked(self.entry, self.fixture.row(case),
                self.frame(case) if frame is None else frame, uncapped=uncapped)

    def reconcile(self, case):
        with self.owner._scope(self.entry):
            return self.owner._manifest(self.entry, self.fixture.row(case))

    def assert_equal_floor(self, case):
        row, record = self.fixture.row(case), self.fixture.journal_record(case)
        self.assertEqual(floor(row), record.allocated_floor)
        self.owner.store.assert_retained_allocation(row, record)
        return row, record

    def seed_db_ahead(self, case, demand=None):
        demand = demand or {"cpu_units": 3, "physical_bytes": 3 * GIB, "commit_bytes": 4 * GIB}
        with self.owner._scope(self.entry):
            row = self.fixture.row(case)
            with self.owner.store._transaction() as conn:
                update_demand_floor(conn, case.spec.execution_id, demand,
                    expected_revision=row["state_revision"], valid=True, uncapped=True)
        return self.fixture.row(case)

    def test_uncapped_high_water_is_durable_before_return_without_native_set(self):
        case = self.case()
        before, allocation = self.fixture.row(case), self.fixture.allocation(case)
        old_record = self.fixture.journal_record(case)
        updated = self.prepare(case)
        row, record = self.assert_equal_floor(case)
        self.assertEqual(updated, row)
        self.assertEqual(floor(row), ResourceDemand(3, 3 * GIB, 4 * GIB, 1))
        self.assertEqual(row["state_revision"], before["state_revision"] + 1)
        self.assertEqual(record.manifest_seq, old_record.manifest_seq + 1)
        self.assertEqual(self.fixture.allocation(case), allocation)
        self.assertEqual(case.job.sets, 0)
        self.assertIsNone(self.fixture.slot())

    def test_lower_or_repeated_observation_writes_nothing_and_never_lowers(self):
        case = self.case()
        self.prepare(case)
        row, record = self.assert_equal_floor(case)
        lower = self.frame(case, cpu_units=0, cpu_uncapped_high_water_units=0,
                           private_working_set_bytes=0, private_commit_bytes=0)
        with patch.object(self.fixture.journal, "publish", side_effect=AssertionError("unexpected write")):
            self.assertEqual(self.prepare(case, lower), row)
            self.assertEqual(self.prepare(case), row)
        self.assertEqual(self.fixture.journal_record(case), record)
        self.assertEqual(case.job.sets, 0)

    def test_capped_cpu_fields_are_ignored_but_memory_growth_is_retained(self):
        case = self.case(control=CAP, slot=True)
        before = self.fixture.row(case)
        updated = self.prepare(case, self.frame(case, cpu_units=11,
            cpu_uncapped_high_water_units=12), uncapped=False)
        self.assertEqual(updated["floor_cpu_units"], before["floor_cpu_units"])
        self.assertEqual(updated["floor_physical_bytes"], 3 * GIB)
        self.assertEqual(updated["floor_commit_bytes"], 4 * GIB)
        self.assert_equal_floor(case)
        self.assertEqual(case.job.control["rate_bp"], CAP.cpu_rate_bp)
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.fixture.slot()["slot_state"], "HELD")

    def test_claim_of_uncapped_measurement_requires_actual_disabled_readback(self):
        case = self.case(control=CAP, slot=True)
        row, record = self.fixture.row(case), self.fixture.journal_record(case)
        with self.assertRaisesRegex(LifecycleError, "uncapped_unverified"):
            self.prepare(case)
        self.assertEqual(self.fixture.row(case), row)
        self.assertEqual(self.fixture.journal_record(case), record)
        self.assertEqual(case.job.sets, 0)

    def test_unknown_memory_keeps_floor_and_valid_uncapped_cpu_can_raise(self):
        case = self.case()
        error = FrameError("memory_attribution_unavailable", "sampling", RetryClass.TRANSIENT,
                           execution_id=case.spec.execution_id)
        frame = self.frame(case, errors=(error,), memory_validity=Validity.UNKNOWN,
                           private_working_set_bytes=None, private_commit_bytes=None)
        before = self.fixture.row(case)
        row = self.prepare(case, frame)
        self.assertEqual(row["floor_cpu_units"], 3)
        for key in ("physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(row["floor_" + key], before["floor_" + key])
        self.assert_equal_floor(case)

    def test_incomplete_membership_cannot_raise_any_observed_floor(self):
        case = self.case()
        error = FrameError("membership_unknown", "sampling", RetryClass.TRANSIENT,
                           execution_id=case.spec.execution_id)
        frame = self.frame(case, errors=(error,), membership_complete=False,
                           memory_validity=Validity.UNKNOWN)
        before = self.fixture.row(case)
        with patch.object(self.fixture.journal, "publish", side_effect=AssertionError("unexpected write")):
            self.assertEqual(self.prepare(case, frame), before)

    def test_unknown_frame_and_other_execution_are_rejected_without_mutation(self):
        case = self.case()
        before, record = self.fixture.row(case), self.fixture.journal_record(case)
        error = FrameError("telemetry_stale", "sampling", RetryClass.TRANSIENT)
        unknown = self.frame(case, errors=(error,), validity=Validity.UNKNOWN)
        other = replace(self.frame(case), jobs=(samples.job(str(uuid4())),))
        for frame in (unknown, other):
            with self.subTest(frame=frame.validity):
                with self.assertRaisesRegex(LifecycleError, "frame_unverified"):
                    self.prepare(case, frame)
        self.assertEqual(self.fixture.row(case), before)
        self.assertEqual(self.fixture.journal_record(case), record)

    def test_scope_stale_row_and_impossible_cpu_are_rejected(self):
        case = self.case()
        before = self.fixture.row(case)
        with self.assertRaises(Exception):
            self.publisher.prepare_locked(self.entry, before, self.frame(case), uncapped=True)
        self.seed_db_ahead(case)
        with self.owner._scope(self.entry):
            with self.assertRaisesRegex(LifecycleError, "row_changed"):
                self.publisher.prepare_locked(self.entry, before, self.frame(case), uncapped=True)
        with self.assertRaisesRegex(LifecycleError, "cpu_invalid"):
            self.prepare(case, self.frame(case, cpu_units=13))
        self.assertEqual(case.job.sets, 0)

    def test_only_guardian_paired_history_contributes_cpu_and_memory_maxima(self):
        case = self.case()
        row, record = self.fixture.row(case), self.fixture.journal_record(case)
        early = self.frame(case, cpu_units=5, cpu_uncapped_high_water_units=12,
                           private_working_set_bytes=5 * GIB, private_commit_bytes=6 * GIB)
        with patch.object(self.fixture.journal, "publish", side_effect=AssertionError("unexpected observation write")):
            with self.owner._scope(self.entry):
                self.publisher.remember_uncapped_locked(self.entry, early)
                self.publisher.remember_uncapped_locked(self.entry, self.frame(case))
        self.assertEqual(self.fixture.row(case), row)
        self.assertEqual(self.fixture.journal_record(case), record)
        result = self.prepare(case)
        self.assertEqual(floor(result), ResourceDemand(5, 5 * GIB, 6 * GIB, 1))
        self.assert_equal_floor(case)
        self.assertEqual(case.job.sets, 0)

    def test_wire_highwater_never_becomes_uncapped_history(self):
        case = self.case()
        result = self.prepare(case, self.frame(case, cpu_units=2,
                                              cpu_uncapped_high_water_units=999))
        self.assertEqual(result["floor_cpu_units"], 2)
        self.assert_equal_floor(case)

    def test_capped_sample_cannot_enter_guardian_uncapped_history(self):
        case = self.case(control=CAP, slot=True)
        with self.owner._scope(self.entry):
            with self.assertRaisesRegex(LifecycleError, "uncapped_unverified"):
                self.publisher.remember_uncapped_locked(self.entry, self.frame(case, cpu_units=11))
        row = self.prepare(case, uncapped=False)
        self.assertEqual(row["floor_cpu_units"], case.spec.requested.cpu_units)
        self.assert_equal_floor(case)

    def test_unsettled_control_intent_refuses_new_floor_measurements(self):
        case = self.case(control=None, pending=PendingIntent(str(uuid4()), DISABLED, CAP), slot=True)
        before, record = self.fixture.row(case), self.fixture.journal_record(case)
        with self.assertRaisesRegex(LifecycleError, "control_unsettled"):
            self.prepare(case, uncapped=False)
        self.assertEqual(self.fixture.row(case), before)
        self.assertEqual(self.fixture.journal_record(case), record)

    def test_journal_write_failure_keeps_db_floor_hold_and_retained_custody(self):
        case = self.case()
        allocation, record = self.fixture.allocation(case), self.fixture.journal_record(case)
        with patch.object(self.fixture.journal, "publish", side_effect=OSError("fixture write cut")):
            with self.assertRaisesRegex(OSError, "fixture write cut"):
                self.prepare(case)
        row = self.fixture.row(case)
        self.assertEqual(floor(row), ResourceDemand(3, 3 * GIB, 4 * GIB, 1))
        self.assertEqual(self.fixture.journal_record(case), record)
        self.assertEqual(self.fixture.barrier(), "RECOVERY_HOLD")
        self.assertIsNotNone(self.entry._floor_publication.candidate)
        self.assertTrue(self.entry.restore_pending)
        self.assertEqual(self.fixture.allocation(case), allocation)
        self.fixture.assert_custody(case)
        self.assertEqual(case.job.sets, 0)
        with self.assertRaisesRegex(LifecycleError, "retained_manifest_mismatch"):
            self.owner.store.assert_retained_allocation(row, record)
        self.owner.store.assert_retained_floor_growth(row, record)
        self.reconcile(case)
        self.assert_equal_floor(case)
        self.assertEqual(self.fixture.row(case), row)
        self.assertIsNone(self.entry._floor_publication.candidate)

    def test_lost_publication_ack_requires_positive_reaffirmation(self):
        case = self.case()
        publish = self.fixture.journal.publish

        def lost_ack(*args, **kwargs):
            publish(*args, **kwargs)
            raise OSError("fixture publication ACK lost")

        with patch.object(self.fixture.journal, "publish", side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, "ACK lost"):
                self.prepare(case)
        row, landed = self.assert_equal_floor(case)
        self.assertIsNotNone(self.entry._floor_publication.candidate)
        with patch.object(self.fixture.journal, "publish", wraps=publish) as retried:
            repaired = self.reconcile(case)
        self.assertEqual(retried.call_count, 1)
        self.assertEqual(repaired.manifest_seq, landed.manifest_seq + 1)
        self.assertEqual(repaired.allocated_floor, landed.allocated_floor)
        self.assertEqual(self.fixture.row(case), row)
        self.assertIsNone(self.entry._floor_publication.candidate)
        self.assertEqual(case.job.sets, 0)

    def test_committed_db_ack_loss_recovers_without_lowering_or_recounting(self):
        case = self.case()
        transaction = self.owner.store._transaction
        cut = False

        @contextmanager
        def lost_ack():
            nonlocal cut
            grew = False
            with transaction() as conn:
                before = conn.execute("SELECT floor_cpu_units FROM managed_executions WHERE execution_id=?",
                                      (case.spec.execution_id,)).fetchone()[0]
                yield conn
                after = conn.execute("SELECT floor_cpu_units FROM managed_executions WHERE execution_id=?",
                                     (case.spec.execution_id,)).fetchone()[0]
                grew = after > before
            if grew and not cut:
                cut = True
                raise OSError("fixture committed DB ACK lost")

        with patch.object(self.owner.store, "_transaction", lost_ack):
            with self.assertRaisesRegex(OSError, "DB ACK lost"):
                self.prepare(case)
        row = self.fixture.row(case)
        self.assertEqual(floor(row), ResourceDemand(3, 3 * GIB, 4 * GIB, 1))
        self.assertEqual(self.fixture.barrier(), "RECOVERY_HOLD")
        self.reconcile(case)
        self.assert_equal_floor(case)
        self.assertEqual(self.fixture.row(case), row)

    def test_manifest_ahead_and_identity_change_are_never_floor_reconciliation(self):
        case = self.case()
        row, record = self.fixture.row(case), self.fixture.journal_record(case)
        ahead = with_floor(record, ResourceDemand(4, 5 * GIB, 6 * GIB, 1))
        wrong = RecoveryManifest.create(**({field.name: getattr(record, field.name)
            for field in fields(record) if field.name != "manifest_hash"} |
            {"spec_hash": "e" * 64}))
        for invalid in (ahead, wrong):
            with self.assertRaisesRegex(LifecycleError, "retained_manifest_mismatch"):
                self.owner.store.assert_retained_floor_growth(row, invalid)
        self.assertEqual(self.fixture.row(case), row)
        self.assertEqual(self.fixture.journal_record(case), record)

    def test_journal_cleanup_custody_is_sticky_and_prevents_new_open(self):
        case = self.case()
        error = OSError("fixture publication close uncertain")
        error._journal_cleanup_owner = object()
        with patch.object(self.fixture.journal, "publish", side_effect=error):
            with self.assertRaises(OSError):
                self.prepare(case)
        self.assertIs(self.entry.journal_cleanup_error, error)
        with patch.object(self.fixture.journal, "read", side_effect=AssertionError("unexpected open")):
            with self.assertRaisesRegex(LifecycleError, "journal_cleanup_unverified"):
                self.reconcile(case)
        self.fixture.assert_custody(case)
        self.assertEqual(case.job.sets, 0)

    def test_native_restore_remains_possible_when_floor_journal_is_unavailable(self):
        case = self.case(control=CAP, slot=True)
        allocation = self.fixture.allocation(case)
        with patch.object(self.fixture.journal, "publish", side_effect=OSError("fixture storage unavailable")):
            with self.assertRaises(OSError):
                self.prepare(case, uncapped=False)
            with self.assertRaises(OSError):
                self.fixture.restore(case)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.fixture.slot()["slot_state"], "HELD")
        self.assertEqual(self.fixture.barrier(), "RECOVERY_HOLD")
        self.assertEqual(self.fixture.allocation(case), allocation)
        result = self.fixture.restore(case)
        self.assertTrue(result.native_disabled and result.bookkeeping_settled and result.slot_released)
        self.assert_equal_floor(case)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.fixture.allocation(case), allocation)

    def test_publisher_can_be_attached_before_initial_lifecycle_adoption(self):
        self.fixture.start_consumer()
        publisher = FloorPublisher(SimpleNamespace(lifecycle=self.fixture.owner))
        case = self.fixture.case(control=DISABLED, slot=False)
        entry = self.fixture.owner._entry(case.spec.execution_id)
        self.assertTrue(entry.validated)
        self.assertIs(self.fixture.owner._floor_publisher, publisher)
        self.assertEqual(self.fixture.journal_record(case).allocated_floor, case.spec.requested)
        self.assertEqual(case.job.sets, 0)


class OrphanFloorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = orphan_fixtures.OrphanDrainTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def seed_db_ahead(self, case):
        # Explicit durable crash cut: the prior guardian committed the existing
        # accounting operation, then died before its floor journal publication.
        row = self.fixture.row(case)
        with self.fixture.drain_store._transaction() as conn:
            update_demand_floor(conn, case.spec.execution_id,
                {"physical_bytes": 3 * GIB, "commit_bytes": 4 * GIB},
                expected_revision=row["state_revision"], valid=True, uncapped=False)
        return self.fixture.row(case)

    def record(self, case):
        return self.fixture.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)

    def test_dead_guardian_restored_empty_drain_repairs_floor_before_finalizing(self):
        case = self.fixture.prepared(members=())
        grown = self.seed_db_ahead(case)
        before = self.record(case)
        result = self.fixture.drain(case, now=orphan_fixtures.NOW + 1)
        self.assertTrue(result.finalized)
        self.assertEqual(self.fixture.row(case)["state"], "FINISHED")
        self.assertIsNone(self.fixture.allocation(case))
        after = self.record(case)
        self.assertEqual(after.allocated_floor, floor(grown))
        self.assertEqual(after.manifest_seq, before.manifest_seq + 1)
        self.assertEqual(case.job.sets, 1)

    def test_orphan_floor_publication_failure_preserves_allocation_and_retries(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        allocation = self.fixture.allocation(case)
        with patch.object(self.fixture.journal, "publish", side_effect=OSError("fixture orphan publication cut")):
            with self.assertRaisesRegex(OSError, "orphan publication cut"):
                self.fixture.drain(case, now=orphan_fixtures.NOW + 1)
        self.assertEqual(self.fixture.allocation(case), allocation)
        self.assertEqual(self.fixture.row(case)["state"], "RUNNING")
        self.assertEqual(self.fixture.slot()["slot_state"], "HELD")
        self.assertEqual(self.fixture.barrier(), "RECOVERY_HOLD")
        self.assertEqual(case.job.control["flags"], 0)
        retained = self.fixture.orphan._policy_operation.guard
        self.assertIsNotNone(retained)
        self.assertEqual(self.fixture.entry_nonce(), retained.nonce)
        with patch.object(self.fixture.drain_store._policy, "prepare",
                          side_effect=AssertionError("must reuse retained guard")):
            result = self.fixture.drain(case, now=orphan_fixtures.NOW + 2)
        self.assertTrue(result.finalized)
        self.assertIsNone(self.fixture.orphan._policy_operation.guard)
        self.assertIsNone(self.fixture.entry_nonce())
        self.assertEqual(case.job.sets, 1)

    def test_nonempty_orphan_drain_keeps_floor_accounting_and_allocation(self):
        case = self.fixture.prepared(members=(99119,))
        row = self.seed_db_ahead(case)
        allocation, record = self.fixture.allocation(case), self.record(case)
        result = self.fixture.drain(case, now=orphan_fixtures.NOW + 1)
        self.assertFalse(result.finalized)
        self.assertEqual(self.fixture.row(case), row)
        self.assertEqual(self.fixture.allocation(case), allocation)
        self.assertEqual(self.record(case), record)
        self.assertEqual(case.job.sets, 1)

    def test_orphan_lost_ack_is_reaffirmed_before_terminal_release(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        publish = self.fixture.journal.publish

        def lost_ack(*args, **kwargs):
            publish(*args, **kwargs)
            raise OSError("fixture orphan ACK lost")

        with patch.object(self.fixture.journal, "publish", side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, "orphan ACK lost"):
                self.fixture.drain(case, now=orphan_fixtures.NOW + 1)
        landed = self.record(case)
        self.assertIsNotNone(self.fixture.allocation(case))
        with patch.object(self.fixture.journal, "publish", wraps=publish) as retried:
            result = self.fixture.drain(case, now=orphan_fixtures.NOW + 2)
        self.assertTrue(result.finalized)
        self.assertEqual(retried.call_count, 1)
        self.assertEqual(self.record(case).manifest_seq, landed.manifest_seq + 1)
        self.assertEqual(case.job.sets, 1)

    def test_orphan_helper_requires_retained_dead_native_disabled_custody(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        recovery, store = self.fixture.recovery, self.fixture.drain_store
        entry = recovery._entries[case.spec.execution_id]
        with self.assertRaisesRegex(LifecycleError, "recovery_scope_required"):
            reconcile_orphan_floor_locked(store, recovery, entry, self.fixture.row(case), self.record(case))
        with recovery._scope(entry, policy_scope=self.fixture.orphan._policy):
            record = recovery._read(entry)
            case.job.control = {"flags": 5, "rate_bp": CAP.cpu_rate_bp}
            with self.assertRaisesRegex(LifecycleError, "restore_unverified"):
                reconcile_orphan_floor_locked(store, recovery, entry, self.fixture.row(case), record)
        self.assertIsNotNone(self.fixture.allocation(case))
        self.assertEqual(case.job.sets, 1)

    def test_orphan_unknown_journal_cleanup_quarantines_retained_guard(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        failure = OSError("fixture orphan cleanup unknown")
        failure._journal_cleanup_owner = object()
        with patch.object(self.fixture.journal, "publish", side_effect=failure):
            with self.assertRaises(OSError):
                self.fixture.drain(case)
        operation = self.fixture.orphan._policy_operation
        retained = operation.guard
        self.assertIsNotNone(retained)
        self.assertIs(operation._error, failure)
        self.assertIsNotNone(operation._quarantine)
        self.assertEqual(self.fixture.entry_nonce(), retained.nonce)
        with patch.object(self.fixture.drain_store._policy, "prepare",
                          side_effect=AssertionError("must not mint new guard")):
            with self.assertRaisesRegex(LifecycleError, "orphan_policy_cleanup_unverified"):
                self.fixture.drain(case)
        self.assertIs(operation.guard, retained)
        self.assertIsNotNone(self.fixture.allocation(case))
        self.assertEqual(case.job.sets, 1)

    def test_orphan_prepare_ack_loss_cannot_reconstruct_guard_from_nonce(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        prepare = self.fixture.drain_store._policy.prepare

        def lost_ack(*args, **kwargs):
            prepare(*args, **kwargs)
            raise OSError("fixture orphan prepare ACK lost")

        with patch.object(self.fixture.drain_store._policy, "prepare", side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, "prepare ACK lost"):
                self.fixture.drain(case)
        operation = self.fixture.orphan._policy_operation
        self.assertIsNone(operation.guard)
        self.assertIsNotNone(operation._quarantine)
        nonce = self.fixture.entry_nonce()
        self.assertIsNotNone(nonce)
        with self.assertRaisesRegex(LifecycleError, "orphan_policy_cleanup_unverified"):
            self.fixture.drain(case)
        self.assertIsNone(operation.guard)
        self.assertEqual(self.fixture.entry_nonce(), nonce)
        self.assertIsNotNone(self.fixture.allocation(case))

    def test_pending_orphan_guard_is_not_lent_to_different_execution(self):
        case = self.fixture.prepared(members=())
        self.seed_db_ahead(case)
        with patch.object(self.fixture.journal, "publish", side_effect=OSError("fixture floor cut")):
            with self.assertRaises(OSError):
                self.fixture.drain(case)
        retained = self.fixture.orphan._policy_operation.guard
        with self.assertRaisesRegex(LifecycleError, "orphan_policy_operation_pending"):
            with self.fixture.orphan._policy(str(uuid4())):
                self.fail("different execution entered prior POLICY operation")
        self.assertIs(self.fixture.orphan._policy_operation.guard, retained)
        self.assertEqual(self.fixture.entry_nonce(), retained.nonce)


if __name__ == "__main__":
    unittest.main()
