"""Irreversible launch drain over real ledger/journal and explicit L1 natives.

These tests prove operation boundaries, not native Windows drain acceptance.
"""
from contextlib import closing
from dataclasses import replace
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_guardian_launch as launch_fixture
from tests import test_adaptive_guardian_retirement as retirement_fixture


class GuardianLaunchDrainTests(unittest.TestCase):
    setUp = retirement_fixture.GuardianRetirementTests.setUp
    tearDown = launch_fixture.GuardianLaunchTests.tearDown
    native_probe = launch_fixture.GuardianLaunchTests.native_probe
    make_mutex = launch_fixture.GuardianLaunchTests.make_mutex
    make_job = launch_fixture.GuardianLaunchTests.make_job
    admitted = launch_fixture.GuardianLaunchTests.admitted
    row = launch_fixture.GuardianLaunchTests.row
    allocation = launch_fixture.GuardianLaunchTests.allocation
    prepare = launch_fixture.GuardianLaunchTests.prepare
    claim_request = launch_fixture.GuardianLaunchTests.claim_request
    claim = launch_fixture.GuardianLaunchTests.claim
    simulate_wrapper_launch = launch_fixture.GuardianLaunchTests.simulate_wrapper_launch
    bind = launch_fixture.GuardianLaunchTests.bind
    request = retirement_fixture.GuardianRetirementTests.request
    retire = retirement_fixture.GuardianRetirementTests.retire
    archive_count = retirement_fixture.GuardianRetirementTests.archive_count

    def launch_requests(self):
        with closing(sqlite3.connect(self.db)) as connection:
            return connection.execute("""SELECT execution_id,operation,request_id,
                payload_hash,spec_hash,guardian_epoch FROM adaptive_launch_requests
                ORDER BY execution_id,operation""").fetchall()

    def record_claim_only(self, case, request):
        # Model the durable boundary before any fence binding or claim CAS,
        # using the production request writer under its original native owner.
        entry = self.owner._pending[case.snapshot.execution_id]
        with self.owner.lifecycle._scope(entry):
            self.assertFalse(self.owner._record_request(request, case.peer, case.auth))

    def assert_duplicate_without_authority(self, result, state):
        self.assertEqual(result.state, state)
        self.assertTrue(result.duplicate)
        self.assertFalse(result.launch_authorized)

    def test_new_prepare_captures_only_retirement_scope_and_readiness_cannot_undo_drain(self):
        case = self.admitted()
        allocation = self.allocation(case)
        self.owner.begin_drain()
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(case.peer, "duplicate", wraps=case.peer.duplicate) as duplicate, \
                patch.object(self.owner, "_job_factory", wraps=self.owner._job_factory) as create:
            result = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
            self.assertEqual(result.state, "RESERVED")
            self.assertFalse(result.duplicate)
            self.assertFalse(result.launch_authorized)
            before, requests = self.row(case), self.launch_requests()
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0][1:4], ("PrepareExecution", case.prepare_request.request_id,
                                              case.prepare_request.payload_hash()))
            entry = self.owner._pending[case.snapshot.execution_id]
            self.assertTrue(entry.retirement_sealed)
            self.assertFalse(entry.create_attempted)
            self.assertIsNone(entry.job)
            self.assertFalse(before["claim_consumed"])
            self.assertEqual((result.job_name, result.job_nonce), (entry.job_name, entry.creation_nonce))
            record = self.journal.read(case.snapshot.execution_id, creation_nonce=result.job_nonce)
            self.assertEqual(record.wrapper_identity, case.peer.identity)
            self.assertIsNone(record.root_identity)
            self.assertEqual(self.allocation(case), allocation)
            for changed in (replace(case.prepare_request, request_id=str(uuid4())),
                            replace(case.prepare_request, expected_revision=before["state_revision"])):
                with self.assertRaises(LifecycleError):
                    self.owner.prepare_execution(changed, case.peer, case.auth, case.deadline)
                self.assertEqual(self.row(case), before)
                self.assertEqual(self.launch_requests(), requests)
            self.authority.ready = True
            replay = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
            self.assert_duplicate_without_authority(replay, "RESERVED")
            self.assertEqual(self.row(case), before)
            self.assertEqual(self.launch_requests(), requests)
            self.assertFalse(entry.create_attempted)
            retirement = self.request(case)
            self.assertEqual(self.retire(case, retirement).state, "CANCELLED_BEFORE_START")
            self.assert_duplicate_without_authority(self.retire(case, retirement), "CANCELLED_BEFORE_START")
            duplicate.assert_called_once()
            create.assert_not_called()
        terminal = self.row(case)
        record = self.journal.read(case.snapshot.execution_id, creation_nonce=terminal["job_nonce"])
        self.store.assert_retained_terminal(terminal, record)
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertEqual(connection.execute("""SELECT evidence_kind,total_process_count,
                launch_fence_version FROM adaptive_prelaunch_retirements WHERE execution_id=?""",
                (case.snapshot.execution_id,)).fetchall(), [("never-created", None, 0)])
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)
        self.assertTrue(self.owner.retire_completed_pending()[0]["terminal"])
        self.assertEqual(self.owner.retained_execution_ids, ())
        self.assertEqual(self.jobs, [])

    def test_retirement_only_drain_capture_keeps_ten_scope_limit(self):
        cases = [self.admitted() for _ in range(11)]
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(self.owner, "_job_factory", wraps=self.owner._job_factory) as create:
            for case in cases[:10]:
                result = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
                self.assertEqual(result.state, "RESERVED")
                self.assertFalse(result.duplicate)
                self.assertFalse(result.launch_authorized)
            eleventh = cases[-1]
            before, requests = self.row(eleventh), self.launch_requests()
            with patch.object(eleventh.peer, "duplicate", wraps=eleventh.peer.duplicate) as duplicate:
                with self.assertRaisesRegex(LifecycleError, "managed_job_limit_reached"):
                    self.owner.prepare_execution(eleventh.prepare_request, eleventh.peer,
                                                 eleventh.auth, eleventh.deadline)
                duplicate.assert_not_called()
            create.assert_not_called()
        self.assertEqual(len(self.owner.retained_execution_ids), 10)
        self.assertEqual(len(requests), 10)
        self.assertEqual(self.launch_requests(), requests)
        self.assertEqual(self.row(eleventh), before)
        self.assertIsNone(before["job_name"])
        self.assertIsNotNone(self.allocation(eleventh))
        self.assertEqual(self.jobs, [])

    def test_exact_prepared_prepare_replay_survives_lost_readiness_without_recreate(self):
        case = self.admitted()
        original = self.prepare(case)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(case.peer, "duplicate", wraps=case.peer.duplicate) as duplicate, \
                patch.object(self.owner, "_job_factory", wraps=self.owner._job_factory) as create:
            result = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
            duplicate.assert_not_called()
            create.assert_not_called()
        self.assert_duplicate_without_authority(result, "PREPARED")
        self.assertEqual((result.job_name, result.job_nonce), (original.job_name, original.job_nonce))
        self.assertEqual(self.row(case), before)
        self.assertEqual(self.launch_requests(), requests)
        self.assertEqual(len(self.jobs), 1)
        self.assertIsNotNone(self.allocation(case))

    def test_partial_original_prepare_replay_returns_reserved_scope_and_can_retire(self):
        case = self.admitted()
        with patch.object(self.owner, "_initial_record", side_effect=LifecycleError("fixture_prepare_cut")):
            with self.assertRaisesRegex(LifecycleError, "fixture_prepare_cut"):
                self.prepare(case)
        before, requests = self.row(case), self.launch_requests()
        entry = self.owner._pending[case.snapshot.execution_id]
        self.assertEqual(before["state"], "RESERVED")
        self.assertIsNotNone(before["job_name"])
        self.assertFalse(entry.create_attempted)
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(self.owner, "_job_factory", wraps=self.owner._job_factory) as create:
            result = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
            self.assert_duplicate_without_authority(result, "RESERVED")
            self.assertEqual((result.job_name, result.job_nonce), (before["job_name"], before["job_nonce"]))
            self.assertEqual(self.row(case), before)
            self.assertEqual(self.launch_requests(), requests)
            self.assertFalse(entry.create_attempted)
            self.assertIsNotNone(self.allocation(case))
            retired = self.retire(case)
            self.assertEqual(retired.state, "CANCELLED_BEFORE_START")
            self.assertFalse(retired.launch_authorized)
            create.assert_not_called()
        self.assertEqual(self.jobs, [])
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)

    def test_new_claim_is_refused_repeatedly_without_consuming_claim_or_request_slot(self):
        case = self.admitted()
        self.prepare(case)
        request = self.claim_request(case)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(self.store, "bind_launch_fence_locked", wraps=self.store.bind_launch_fence_locked) as fence, \
                patch.object(self.store, "claim_launch_locked", wraps=self.store.claim_launch_locked) as claim:
            for attempt in (request, request, replace(request, request_id=str(uuid4()))):
                with self.assertRaisesRegex(LifecycleError, "guardian_launch_draining"):
                    self.owner.claim_launch(attempt, case.peer, case.auth, case.deadline)
                self.assertEqual(self.row(case), before)
                self.assertEqual(self.launch_requests(), requests)
            fence.assert_not_called()
            claim.assert_not_called()
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assertIsNotNone(self.allocation(case))

    def test_exact_recorded_unconsumed_claim_returns_prepared_without_binding_or_claiming(self):
        case = self.admitted()
        self.prepare(case)
        request = self.claim_request(case)
        self.record_claim_only(case, request)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        with patch.object(self.store, "bind_launch_fence_locked", wraps=self.store.bind_launch_fence_locked) as fence, \
                patch.object(self.store, "claim_launch_locked", wraps=self.store.claim_launch_locked) as claim:
            for _ in range(2):
                result = self.owner.claim_launch(request, case.peer, case.auth, case.deadline)
                self.assert_duplicate_without_authority(result, "PREPARED")
            fence.assert_not_called()
            claim.assert_not_called()
        self.assertEqual(self.row(case), before)
        self.assertEqual(self.launch_requests(), requests)
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assertIsNotNone(self.allocation(case))

    def test_exact_consumed_claim_replay_cannot_redeliver_authority_while_draining(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        result = self.owner.claim_launch(case.claim_request, case.peer, case.auth, case.deadline)
        self.assert_duplicate_without_authority(result, "LAUNCHING")
        self.assertEqual(self.row(case), before)
        self.assertEqual(self.launch_requests(), requests)
        self.assertEqual(case.launches, 0)
        self.assertIsNotNone(self.allocation(case))

    def test_changed_prepare_requests_cannot_replace_original_replay_slot(self):
        case = self.admitted()
        self.prepare(case)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        altered = (replace(case.prepare_request, request_id=str(uuid4())),
                   replace(case.prepare_request, expected_revision=case.prepared.state_revision))
        for request in altered:
            for _ in range(2):
                with self.assertRaises(LifecycleError):
                    self.owner.prepare_execution(request, case.peer, case.auth, case.deadline)
                self.assertEqual(self.row(case), before)
                self.assertEqual(self.launch_requests(), requests)
        result = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
        self.assert_duplicate_without_authority(result, "PREPARED")
        self.assertEqual(len(self.jobs), 1)

    def test_changed_recorded_claim_requests_cannot_seed_a_new_replay(self):
        case = self.admitted()
        self.prepare(case)
        request = self.claim_request(case)
        self.record_claim_only(case, request)
        before, requests = self.row(case), self.launch_requests()
        self.owner.begin_drain()
        self.authority.ready = False
        altered = (replace(request, request_id=str(uuid4())),
                   replace(request, claim_token="x" * 43),
                   replace(request, expected_revision=request.expected_revision + 1))
        for changed in altered:
            for _ in range(2):
                with self.assertRaises(LifecycleError):
                    self.owner.claim_launch(changed, case.peer, case.auth, case.deadline)
                self.assertEqual(self.row(case), before)
                self.assertEqual(self.launch_requests(), requests)
        result = self.owner.claim_launch(request, case.peer, case.auth, case.deadline)
        self.assert_duplicate_without_authority(result, "PREPARED")

    def test_bind_root_handoff_and_exact_replay_continue_without_new_admission_readiness(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        self.owner.begin_drain()
        self.authority.ready = False
        result = self.bind(case)
        self.assertEqual(result.state, "RUNNING")
        self.assertFalse(result.launch_authorized)
        self.assert_duplicate_without_authority(self.bind(case), "RUNNING")
        self.assertEqual(self.row(case)["root_pid"], case.root.identity.pid)
        self.assertIn(case.snapshot.execution_id, self.owner.lifecycle.retained_execution_ids)
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(case.launches, 1)

    def test_preclaim_cancellation_and_exact_replay_continue_while_draining(self):
        case = self.admitted()
        self.prepare(case)
        request = self.request(case)
        self.owner.begin_drain()
        self.authority.ready = False
        result = self.retire(case, request)
        self.assertEqual(result.state, "CANCELLED_BEFORE_START")
        self.assertFalse(result.launch_authorized)
        self.assert_duplicate_without_authority(self.retire(case, request), "CANCELLED_BEFORE_START")
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)

    def test_postclaim_cancel_and_start_failed_continue_while_draining(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        cancel = self.request(case)
        self.owner.begin_drain()
        self.authority.ready = False
        pending = self.retire(case, cancel)
        self.assertEqual(pending.state, "LAUNCHING")
        self.assertFalse(pending.launch_authorized)
        self.assertIsNotNone(self.allocation(case))
        self.assertIsNotNone(self.row(case)["cancel_requested_at"])
        self.assertEqual(self.archive_count(case), 0)
        self.assert_duplicate_without_authority(self.retire(case, cancel), "LAUNCHING")
        failure = self.request(case, failure=True)
        result = self.retire(case, failure)
        self.assertEqual(result.state, "START_FAILED")
        self.assertFalse(result.launch_authorized)
        self.assert_duplicate_without_authority(self.retire(case, failure), "START_FAILED")
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)


if __name__ == "__main__":
    unittest.main()
