"""Retirement consumer checks over real isolated stores and production methods.

Only the retirement decision is injected: it must be asked inside a real SQL
transaction. Existing lifecycle/guardian fixtures provide explicitly synthetic
native evidence. These tests prove neither Windows settlement nor activation.
"""
from contextlib import contextmanager
import sqlite3
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import AllocationKind, ApplyResult, TICKS_PER_SECOND
from sentinel.adaptive.daily_retirement_fence import DailyRetirementError
from sentinel.adaptive.store import LifecycleError
from sentinel.maintainer import Task
from tests import test_adaptive_guardian_control as controls
from tests import test_adaptive_lifecycle as lifecycles
from tests import test_maintainer as maintainers


FENCE_MODULE = "sentinel.adaptive.daily_retirement_fence."
FROZEN = "daily_retirement_frozen"


class RetirementConsumerTests(unittest.TestCase):
    def fixture(self, case_type):
        # Composition avoids collecting the source class's unrelated tests.
        case = case_type(methodName="runTest")
        # The composed case is never run by unittest; its doCleanups returns
        # False on failure instead of reporting to this test's result object.
        def cleanup():
            self.assertTrue(case.doCleanups(), "composed fixture cleanup failed")
        self.addCleanup(cleanup)
        case.setUp()
        self.addCleanup(case.tearDown)
        return case

    @contextmanager
    def frozen(self, *, tightening=False):
        def deny(conn):
            self.assertIsInstance(conn, sqlite3.Connection)
            self.assertTrue(conn.in_transaction, "consumer checked retirement outside its transaction")
            raise DailyRetirementError(FROZEN)

        name = "assert_tightening_allowed" if tightening else "assert_new_capacity_allowed"
        with patch(FENCE_MODULE + name, side_effect=deny) as check:
            yield check

    @staticmethod
    def rows(case, table):
        conn = sqlite3.connect(case.db)
        conn.row_factory = sqlite3.Row
        try:
            return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]
        finally:
            conn.close()

    def maintainer(self):
        case = self.fixture(maintainers.MaintainerTests)
        case.db = case.maintainer.db_path
        case.maintainer.upsert_worker(maintainers.worker("cloud", 12), now=maintainers.NOW)
        return case

    def test_new_registration_checks_freeze_before_binding_existing_allocation(self):
        case = self.fixture(lifecycles.AdaptiveLifecycleTests)
        spec = case.spec()
        case.allocate(spec)
        before = self.rows(case, "reservations")
        with self.frozen() as check, self.assertRaisesRegex(LifecycleError, FROZEN):
            case.store.prepare_registration(spec, caller=lifecycles.WRAPPER, now=lifecycles.NOW)
        check.assert_called_once()
        self.assertEqual(self.rows(case, "managed_executions"), [])
        self.assertEqual(self.rows(case, "reservations"), before)

    def test_registered_replay_checks_freeze_before_returning_existing_capacity(self):
        case = self.fixture(lifecycles.AdaptiveLifecycleTests)
        spec, _ = case.registered()
        before = self.rows(case, "managed_executions")
        allocation = self.rows(case, "reservations")
        with self.frozen() as check, self.assertRaisesRegex(LifecycleError, FROZEN):
            case.store.prepare_registration(spec, caller=lifecycles.WRAPPER, now=lifecycles.NOW + 1)
        check.assert_called_once()
        self.assertEqual(self.rows(case, "managed_executions"), before)
        self.assertEqual(self.rows(case, "reservations"), allocation)

    def test_fresh_launch_claim_checks_freeze_without_consuming_original_claim(self):
        case = self.fixture(lifecycles.AdaptiveLifecycleTests)
        spec, registered = case.registered()
        prepared = case.store.mark_prepared(spec.execution_id, caller=lifecycles.WRAPPER, expected_revision=0)
        before = self.rows(case, "managed_executions")
        with self.frozen() as check, self.assertRaisesRegex(LifecycleError, FROZEN):
            case.store.claim_launch(spec.execution_id, caller=lifecycles.WRAPPER,
                expected_revision=prepared["state_revision"], claim_token=registered["claim_token"],
                spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        check.assert_called_once()
        self.assertEqual(self.rows(case, "managed_executions"), before)
        self.assertEqual(before[0]["claim_consumed"], 0)
        self.assertEqual(before[0]["launch_in_flight"], 0)
        self.assertTrue(self.rows(case, "reservations"))

    def test_verified_empty_terminal_release_does_not_request_new_capacity(self):
        for kind, allocation, archive in (
                (AllocationKind.DIRECT, "reservations", "executions"),
                (AllocationKind.ROUTED, "worker_reservations", "routed_executions")):
            with self.subTest(kind=kind):
                case = self.fixture(lifecycles.AdaptiveLifecycleTests)
                spec, row = case.running(case.spec(kind=kind))
                with self.frozen() as check:
                    done = case.store.finalize_if_empty(spec.execution_id, caller=lifecycles.WRAPPER,
                        expected_revision=row["state_revision"], now=lifecycles.NOW + 1)
                    replay = case.store.finalize_if_empty(spec.execution_id, caller=lifecycles.WRAPPER,
                        expected_revision=done["state_revision"], now=lifecycles.NOW + 2)
                check.assert_not_called()
                self.assertEqual(done["state"], "FINISHED")
                self.assertEqual(replay["state_revision"], done["state_revision"])
                self.assertEqual(self.rows(case, allocation), [])
                self.assertEqual(len(self.rows(case, archive)), 1)

    def test_maintainer_new_route_checks_freeze_before_reserving_worker_capacity(self):
        case = self.maintainer()
        workers = self.rows(case, "workers")
        with self.frozen() as check, self.assertRaisesRegex(DailyRetirementError, FROZEN):
            case.maintainer.route_and_reserve(Task("new", ram_gib=2), now=maintainers.NOW)
        check.assert_called_once()
        self.assertEqual(self.rows(case, "worker_reservations"), [])
        self.assertEqual(self.rows(case, "workers"), workers)

    def test_maintainer_reserved_replay_checks_freeze_before_reusing_capacity(self):
        case = self.maintainer()
        task = Task("same", ram_gib=2)
        reserved = case.maintainer.route_and_reserve(task, now=maintainers.NOW)
        self.assertTrue(reserved["reserved"])
        before = self.rows(case, "worker_reservations")
        with self.frozen() as check, self.assertRaisesRegex(DailyRetirementError, FROZEN):
            case.maintainer.route_and_reserve(task, now=maintainers.NOW + 1)
        check.assert_called_once()
        self.assertEqual(self.rows(case, "worker_reservations"), before)

    def test_maintainer_heartbeat_and_release_keep_their_existing_authority(self):
        case = self.maintainer()
        reserved = case.maintainer.route_and_reserve(Task("existing", ram_gib=2), now=maintainers.NOW)
        self.assertTrue(reserved["reserved"])
        workers = self.rows(case, "workers")
        with self.frozen() as check:
            self.assertTrue(case.maintainer.heartbeat("existing", now=maintainers.NOW + 1))
            heartbeat = self.rows(case, "worker_reservations")
            self.assertEqual(heartbeat[0]["heartbeat_at"], maintainers.NOW + 1)
            self.assertEqual(case.maintainer.release(task_id="existing", now=maintainers.NOW + 2), 1)
            self.assertEqual(case.maintainer.release(task_id="existing", now=maintainers.NOW + 3), 0)
        check.assert_not_called()
        self.assertEqual(self.rows(case, "worker_reservations"), [])
        self.assertEqual(len(self.rows(case, "routed_executions")), 1)
        self.assertEqual(self.rows(case, "workers"), workers)

    def test_guardian_initial_set_checks_freeze_inside_policy_transaction(self):
        case = self.fixture(controls.GuardianControlTests)
        job = case.start()
        with self.frozen(tightening=True) as check:
            ack = case.apply(case.proposal(job), now_tick_100ns=case.ticks)
        check.assert_called_once()
        self.assertEqual((ack.result, ack.reason), (ApplyResult.REJECTED, FROZEN))
        self.assertEqual(job.job.sets, 0)
        self.assertIsNone(case.slot())
        self.assertEqual(case.actions(), [])
        self.assertEqual(case.runtime()["admission_barrier"], "NONE")

    def test_guardian_renewal_checks_freeze_and_does_not_extend_original_lease(self):
        case = self.fixture(controls.GuardianControlTests)
        job = case.start()
        applied = case.apply_cap(job)
        episode = case.control._episodes[job.spec.execution_id]
        deadline = episode.lease_deadline_tick_100ns
        actions = case.actions()
        slot = case.slot()
        case.ticks = case.control._latest_frame.window_end_tick_100ns + TICKS_PER_SECOND
        proposal = case.proposal(job, seq=2, sample_seq=2,
            window_end=case.ticks, decision=case.ticks)
        with self.frozen(tightening=True) as check:
            ack = case.apply(proposal, now_tick_100ns=case.ticks)
        check.assert_called_once()
        self.assertEqual((ack.result, ack.reason), (ApplyResult.REJECTED, FROZEN))
        self.assertEqual(episode.lease_deadline_tick_100ns, deadline)
        self.assertEqual(deadline, applied.lease_deadline_tick_100ns)
        self.assertEqual(job.job.sets, 1)
        self.assertEqual(case.actions(), actions)
        self.assertEqual(case.slot(), slot)

    def test_guardian_restore_settles_native_fixture_journal_slot_and_audit_during_freeze(self):
        case = self.fixture(controls.GuardianControlTests)
        job = case.start()
        case.apply_cap(job)
        before = len(job.job.calls)
        with self.frozen(tightening=True) as check:
            result = case.control.request_restore(job.spec.execution_id)
            self.assertIsNone(case.control.request_restore(job.spec.execution_id))
        check.assert_not_called()
        self.assertTrue(result.native_disabled and result.bookkeeping_settled and result.slot_released)
        self.assertEqual([call for call in job.job.calls[before:]
                          if call[0] in {"set", "disable"}], [("disable", None)])
        self.assertEqual(job.job.control["flags"], 0)
        self.assertEqual(case.slot()["slot_state"], "RESTORED")
        self.assertEqual(case.runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertEqual([row["action_state"] for row in case.actions()], ["APPLIED", "RESTORED"])
        record = case.journal.read(job.spec.execution_id, creation_nonce=job.record.creation_nonce)
        self.assertIsNone(record.pending_intent)
        self.assertEqual(record.last_applied, controls.DISABLED)


if __name__ == "__main__":
    unittest.main()
