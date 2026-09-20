"""Production launch consumer with real admission, SQLite and recovery journal.

All native handles, Jobs, host authority and mutexes are explicit L1 fixtures.
Only the wrapper's post-claim CreateProcess effect is simulated; no process is
launched, no native Set is available, and these tests pass no Windows gate.
Rows enter RESERVED through the atomic Coordinator/ManagedAdmission path, then
the production guardian alone prepares, claims, binds and observes lifecycle.
"""
from contextlib import closing
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.admission import ManagedAdmission
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.launch_transport import (
    BindRootRequest, ClaimLaunchRequest, PrepareExecutionRequest,
)
from sentinel.adaptive.native_job import JobAccess
from sentinel.adaptive.recovery_journal import RecoveryJournal, RecoveryJournalError
from sentinel.adaptive.store import LifecycleError, LifecycleStore, _get_ipc_auth_record
from sentinel.coordinator import Coordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_guardian_lifecycle as lifecycle_fixture
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, NOW, status


LOGON = "S-1-5-5-100-200"
EPOCH = "fixture-production-launch"
GUARDIAN = ProcessIdentity(os.getpid(), 134343072000000101, LOGON)


class ProcessBackend:
    """Separate handle lifetimes reference the same synthetic kernel object."""
    def __init__(self):
        self.handles, self.objects, self.by_pid, self.remote = {}, {}, {}, {}
        self.next_handle = 1000
        self.events = []

    def new_handle(self, state):
        handle = self.next_handle
        self.next_handle += 1
        self.handles[handle] = SimpleNamespace(state=state, closed=False)
        return handle

    def process(self, identity, *, job=None):
        if identity not in self.objects:
            self.objects[identity] = SimpleNamespace(identity=identity, status=IdentityStatus.ALIVE,
                job=job, membership_error=None, wait_error=None, code=0)
        state = self.objects[identity]
        self.by_pid[identity.pid] = state
        return VerifiedProcess(self, self.new_handle(state), identity)

    def state(self, handle):
        entry = self.handles[handle]
        if entry.closed:
            raise IdentityUnavailable("fixture_handle_closed")
        return entry.state

    def identity(self, handle):
        self.events.append(("identity", handle))
        return self.state(handle).identity

    def wait(self, handle):
        state = self.state(handle)
        self.events.append(("wait", handle))
        if state.wait_error is not None:
            raise state.wait_error
        if state.status is IdentityStatus.UNKNOWN:
            raise IdentityUnavailable("fixture_wait_unknown")
        return state.status

    def membership(self, handle, job):
        state = self.state(handle)
        self.events.append(("membership", handle, job))
        if state.membership_error is not None:
            raise state.membership_error
        return state.job is not None if job is None else state.job == job

    def open_transfer_source(self, pid):
        self.events.append(("open_transfer_source", pid))
        return self.new_handle(self.by_pid[pid])

    def duplicate_into(self, locator, output, *, source_process=None):
        if source_process is None:
            state = self.state(locator)
        else:
            peer = self.state(source_process)
            state = self.remote[(peer.identity, locator)]
        output.value = self.new_handle(state)
        self.events.append(("duplicate", locator, source_process, output.value))

    def exit_code(self, handle):
        state = self.state(handle)
        if state.status is not IdentityStatus.DEAD:
            raise IdentityUnavailable("fixture_exit_unknown")
        return state.code

    def close(self, handle):
        self.state(handle)
        self.events.append(("close", handle))
        self.handles[handle].closed = True


class Job:
    """Fresh empty Job query fixture; every control writer traps immediately."""
    def __init__(self, name, nonce, logon, handle, probe):
        self.name, self.nonce, self.logon_sid, self.handle = name, nonce, logon, handle
        self.members, self.writes = [], []
        self.closed = False
        self.probe = probe
        self.query_error = None

    def check(self):
        self.probe()
        if self.closed:
            raise AssertionError("closed fixture Job queried")
        if self.query_error is not None:
            raise self.query_error

    def query_limits(self):
        self.check()
        return SimpleNamespace(limit_flags=0, ui_restrictions=0)

    def query_cpu(self):
        self.check()
        return SimpleNamespace(flags=0, rate_bp=0)

    def accounting(self):
        self.check()
        return SimpleNamespace(active_processes=len(self.members))

    def active_pids(self):
        self.check()
        return list(self.members)

    def set_cpu(self, *args, **kwargs):
        self.writes.append((args, kwargs))
        raise AssertionError("no-cap guardian must never Set")

    set_cpu_control = set_cpu

    def close(self):
        if self.closed:
            raise AssertionError("fixture double Job close")
        self.closed = True


class Authority:
    """L1 cohort/exclusion model; actual allocation checks still use real SQL."""
    def __init__(self, case):
        self.case = case
        self.ready = True
        self.excluded = True
        self.events = []

    def assert_ready(self):
        if not self.ready:
            raise LifecycleError("fixture_host_authority_unavailable")

    def assert_covered(self, row):
        self.case.native_probe()
        actual = self.case.store.query(row["execution_id"], existing_path=True)
        self.case.assertEqual(actual, {key: row[key] for key in actual})
        self.case.assertLessEqual(set(row) - set(actual), {"duplicate", "launch_authorized"})
        for key in set(row) - set(actual):
            self.case.assertIs(type(row[key]), bool)
        if "launch_authorized" in row:
            self.case.assertFalse(row["launch_authorized"])
        auth = _get_ipc_auth_record(self.case.db, row["execution_id"])
        self.case.store.assert_authenticated_allocation(row, caller=auth.wrapper_identity, expected_auth=auth)
        self.events.append(("covered", row["execution_id"]))

    def assert_excluded(self, row):
        self.case.native_probe()
        if not self.excluded:
            raise LifecycleError("fixture_legacy_exclusion_unavailable")
        self.events.append(("excluded", row["execution_id"]))


class Deadline:
    """Explicit in-process deadline seam, never an admission override."""
    def __init__(self):
        self.remaining = 1000

    def remaining_ms(self):
        return self.remaining


class GuardianLaunchTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="sentinel-guardian-launch-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.policy = FixturePolicyProvider(LOGON)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0),
                                       policy_provider=self.policy)
        self.db = self.coordinator.db_path
        self.store = LifecycleStore(self.db, policy_provider=self.policy, existing_path=True)
        self.processes = ProcessBackend()
        self.guardian = self.processes.process(GUARDIAN)
        self.journal_dir = self.directory / "recovery"
        self.journal_dir.mkdir()
        self.journal = RecoveryJournal(self.journal_dir, publisher=lifecycle_fixture.publish_fixture)
        self.jobs, self.cases, self.mutexes = [], [], []
        self.authority = Authority(self)
        self.owner = GuardianLaunchOwner(self.store, self.journal, guardian_epoch=EPOCH,
            authority=self.authority, guardian=self.guardian,
            job_factory=self.make_job, mutex_factory=self.make_mutex)
        cpus = patch("os.cpu_count", return_value=12)
        cpus.start()
        self.addCleanup(cpus.stop)

    def tearDown(self):
        for job in self.jobs:
            self.assertEqual(job.writes, [], "launch/lifecycle must remain no-cap")

    def native_probe(self):
        self.store._policy.assert_held()
        self.assertTrue(self.policy.active)
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.rollback()

    def make_mutex(self, *args, **kwargs):
        value = lifecycle_fixture.Mutex(*args, **kwargs)
        self.mutexes.append(value)
        return value

    def make_job(self, name, nonce, logon, *, access):
        self.native_probe()
        self.assertIs(access, JobAccess.OWNER)
        value = Job(name, nonce, logon, 7000 + len(self.jobs), self.native_probe)
        self.jobs.append(value)
        return value

    def admitted(self, **payload_changes):
        index = len(self.cases)
        identity = ProcessIdentity(GUARDIAN.pid + 100000 + index, 134343072000001000 + index, LOGON)
        current = self.processes.process(identity)
        # Isolated model requests satisfy the Coordinator's existing CPU/RAM
        # minimums; these are not estimates for work on the real host.
        payload = PAYLOAD | {"requested": ResourceDemand(.125, 128 << 20, 256 << 20, 0)} | payload_changes
        with patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=current), \
                patch("sentinel.adaptive.admission.os.getpid", return_value=identity.pid):
            admission = ManagedAdmission.current(**payload)
            self.addCleanup(admission.close)
            snapshot = admission.snapshot()
            result = self.coordinator.admit_managed(admission, status(), config=CONFIG, now=NOW)
            self.assertTrue(result["allowed"], result)
            claim_token = admission.launch_claim_token()
        self.assertEqual(result["state"], "RESERVED")
        peer = self.processes.process(identity)
        case = SimpleNamespace(admission=admission, snapshot=snapshot, peer=peer,
            auth=_get_ipc_auth_record(self.db, snapshot.execution_id), token=claim_token,
            deadline=Deadline(), launches=0, root=None, job=None, prepared=None, claimed=None)
        case.prepare_request = PrepareExecutionRequest(request_id=str(uuid4()),
            execution_id=snapshot.execution_id, spec_hash=snapshot.spec_hash,
            guardian_epoch=EPOCH, expected_revision=result["state_revision"])
        self.cases.append(case)
        return case

    def row(self, case):
        return self.store.query(case.snapshot.execution_id, existing_path=True)

    def allocation(self, case):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            value = connection.execute("SELECT * FROM reservations WHERE execution_id=?",
                                       (case.snapshot.execution_id,)).fetchone()
            return None if value is None else dict(value)

    def prepare(self, case):
        case.prepared = self.owner.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
        case.job = self.owner._pending[case.snapshot.execution_id].job
        return case.prepared

    def claim_request(self, case):
        return ClaimLaunchRequest(request_id=str(uuid4()), execution_id=case.snapshot.execution_id,
            spec_hash=case.snapshot.spec_hash, guardian_epoch=EPOCH,
            expected_revision=case.prepared.state_revision, job_nonce=case.prepared.job_nonce,
            claim_token=case.token)

    def claim(self, case):
        case.claim_request = self.claim_request(case)
        case.claimed = self.owner.claim_launch(case.claim_request, case.peer, case.auth, case.deadline)
        return case.claimed

    def simulate_wrapper_launch(self, case):
        self.assertTrue(case.claimed.launch_authorized)
        self.assertFalse(case.claimed.duplicate)
        self.assertEqual(case.launches, 0, "fixture must never repeat user code")
        case.launches += 1
        identity = ProcessIdentity(GUARDIAN.pid + 200000 + self.cases.index(case),
            134343072000010000 + self.cases.index(case), LOGON)
        case.root = self.processes.process(identity, job=case.job.handle)
        case.locator = 90000 + self.cases.index(case)
        self.processes.remote[(case.peer.identity, case.locator)] = self.processes.objects[identity]
        case.job.members[:] = [identity.pid]
        case.bind_request = BindRootRequest(request_id=str(uuid4()), execution_id=case.snapshot.execution_id,
            spec_hash=case.snapshot.spec_hash, guardian_epoch=EPOCH,
            expected_revision=case.claimed.state_revision, job_nonce=case.prepared.job_nonce,
            root_identity=identity, root_handle_locator=case.locator)

    def bind(self, case):
        return self.owner.bind_root(case.bind_request, case.peer, case.auth, case.deadline)

    def started(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        self.bind(case)
        return case

    def remote_duplicates(self):
        return [event for event in self.processes.events if event[0] == "duplicate" and event[2] is not None]

    def assert_retained(self, case):
        self.assertIsNotNone(self.allocation(case))
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)
        for key, value in case.snapshot.requested.to_dict().items():
            self.assertGreaterEqual(self.row(case)["floor_" + key], value)

    def test_actual_prepare_claim_bind_and_running_observation_have_one_allocation_and_no_set(self):
        case = self.started()
        self.assertEqual(case.launches, 1)
        self.assertEqual(len(self.jobs), 1)
        self.assertEqual(len(self.remote_duplicates()), 1)
        row = self.row(case)
        self.assertEqual(row["state"], "RUNNING")
        self.assertEqual((row["claim_consumed"], row["launch_sealed"], row["launch_in_flight"]), (1, 1, 0))
        manifest = self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        self.assertEqual(manifest.root_identity, case.root.identity)
        self.assertEqual(manifest.reservation.id, row["reservation_id"])
        result = self.owner.lifecycle.reconcile(row["execution_id"], now=NOW + 1)
        self.assertEqual(result.state, "RUNNING")
        self.assertFalse(result.terminal)
        self.assert_retained(case)

    def test_borrowed_peer_and_wrapper_root_close_cannot_discard_guardian_custody(self):
        case = self.admitted()
        self.prepare(case)
        pending = self.owner._pending[case.snapshot.execution_id]
        owned_handle, borrowed_handle = pending.wrapper._handle, case.peer._handle
        self.assertNotEqual(owned_handle, borrowed_handle)
        case.peer.close()
        self.assertEqual(pending.wrapper.observe().status, IdentityStatus.ALIVE)
        case.peer = self.processes.process(case.snapshot.wrapper_identity)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        self.bind(case)
        retained = self.owner.lifecycle._entry(case.snapshot.execution_id)
        self.assertIs(retained.wrapper, pending.wrapper)
        self.assertNotEqual(retained.root._handle, case.root._handle)
        case.root.close()
        case.peer.close()
        self.assertEqual(retained.root.observe().status, IdentityStatus.ALIVE)
        self.assertEqual(self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=NOW + 1).state, "RUNNING")
        self.assert_retained(case)

    def test_exact_prepare_claim_and_bind_replays_never_recreate_or_reauthorize(self):
        case = self.admitted()
        first = self.prepare(case)
        repeated = self.prepare(case)
        self.assertTrue(repeated.duplicate)
        self.assertEqual((repeated.job_name, repeated.job_nonce), (first.job_name, first.job_nonce))
        self.claim(case)
        repeated_claim = self.owner.claim_launch(case.claim_request, case.peer, case.auth, case.deadline)
        self.assertTrue(repeated_claim.duplicate)
        self.assertFalse(repeated_claim.launch_authorized)
        self.simulate_wrapper_launch(case)
        self.bind(case)
        repeated_bind = self.bind(case)
        self.assertTrue(repeated_bind.duplicate)
        self.assertFalse(repeated_bind.launch_authorized)
        self.assertEqual((len(self.jobs), len(self.remote_duplicates()), case.launches), (1, 1, 1))

    def test_same_prepare_request_id_with_changed_payload_is_not_a_replay(self):
        case = self.admitted()
        self.prepare(case)
        changed = replace(case.prepare_request, expected_revision=case.prepared.state_revision)
        with self.assertRaises(LifecycleError):
            self.owner.prepare_execution(changed, case.peer, case.auth, case.deadline)
        self.assertEqual(len(self.jobs), 1)
        self.assertEqual(self.row(case)["state"], "PREPARED")
        self.assertFalse(self.row(case)["claim_consumed"])

    def test_wrong_exact_peer_identity_and_auth_are_rejected_before_create(self):
        case = self.admitted()
        wrong = self.processes.process(replace(case.peer.identity,
            created_filetime_100ns=case.peer.identity.created_filetime_100ns + 1))
        with self.assertRaises(LifecycleError):
            self.owner.prepare_execution(case.prepare_request, wrong, case.auth, case.deadline)
        for auth in (replace(case.auth, ipc_auth_key=b"x" * 32),
                     replace(case.auth, admission_binding_hash="f" * 64),
                     replace(case.auth, reservation_id="wrong-reservation")):
            with self.subTest(auth=auth.reservation_id), self.assertRaises(LifecycleError):
                self.owner.prepare_execution(case.prepare_request, case.peer, auth, case.deadline)
        self.assertEqual(self.jobs, [])
        self.assertIsNone(self.row(case)["job_name"])

    def test_wrong_epoch_spec_or_initial_revision_cannot_prepare(self):
        case = self.admitted()
        for request in (replace(case.prepare_request, guardian_epoch="other-epoch"),
                        replace(case.prepare_request, spec_hash="b" * 64),
                        replace(case.prepare_request, expected_revision=1)):
            with self.assertRaises(LifecycleError):
                self.owner.prepare_execution(request, case.peer, case.auth, case.deadline)
        self.assertEqual(self.jobs, [])
        self.assertIsNone(self.row(case)["job_name"])

    def test_absent_host_authority_and_missing_exclusion_never_create(self):
        case = self.admitted()
        # Exercise the default authority on a distinct consumer, not a bool.
        denied = GuardianLaunchOwner(self.store, self.journal, guardian_epoch=EPOCH,
            guardian=self.guardian, job_factory=self.make_job, mutex_factory=self.make_mutex)
        with self.assertRaises(LifecycleError):
            denied.prepare_execution(case.prepare_request, case.peer, case.auth, case.deadline)
        self.store.evidence_provider = self.owner.evidence_scope
        self.authority.excluded = False
        with self.assertRaises(LifecycleError):
            self.prepare(case)
        self.assertEqual(self.jobs, [])
        self.assert_retained(case)

    def test_ten_prepared_jobs_are_the_maximum_and_eleventh_keeps_its_allocation(self):
        for _ in range(10):
            self.prepare(self.admitted())
        eleventh = self.admitted()
        with self.assertRaisesRegex(LifecycleError, "managed_job_limit_reached"):
            self.prepare(eleventh)
        self.assertEqual(len(self.jobs), 10)
        self.assertEqual(len(self.owner.retained_execution_ids), 10)
        self.assertEqual(self.row(eleventh)["state"], "RESERVED")
        self.assertIsNotNone(self.allocation(eleventh))
        self.assertIsNone(self.row(eleventh)["job_name"])

    def test_create_unknown_retains_scope_and_never_repeats_native_create(self):
        case = self.admitted()
        real_create = self.owner._job_factory
        failure = RuntimeError("fixture_create_ack_unknown")
        def create_then_fail(*args, **kwargs):
            failure.fixture_job = real_create(*args, **kwargs)
            raise failure
        with patch.object(self.owner, "_job_factory", side_effect=create_then_fail) as create:
            with self.assertRaises(RuntimeError) as caught:
                self.prepare(case)
            self.assertIs(caught.exception, failure)
            with self.assertRaises(LifecycleError):
                self.prepare(case)
            create.assert_called_once()
        self.assertFalse(failure.fixture_job.closed)
        self.assertEqual(case.launches, 0)
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assert_retained(case)

    def test_initial_journal_lost_ack_is_reaffirmed_before_the_only_create(self):
        case = self.admitted()
        real_create = self.journal.create
        def publish_then_fail(*args, **kwargs):
            real_create(*args, **kwargs)
            raise RecoveryJournalError("fixture_journal_ack_unknown", publication_may_have_occurred=True)
        with patch.object(self.journal, "create", side_effect=publish_then_fail):
            with self.assertRaises(RecoveryJournalError):
                self.prepare(case)
        self.assertEqual(self.jobs, [])
        self.assert_retained(case)
        with patch.object(self.journal, "reaffirm_initial", wraps=self.journal.reaffirm_initial) as reaffirm:
            result = self.prepare(case)
        reaffirm.assert_called_once()
        self.assertEqual(result.state, "PREPARED")
        self.assertEqual(len(self.jobs), 1)

    def test_journal_failure_before_publication_cannot_create_or_grant_a_launch(self):
        case = self.admitted()
        with patch.object(self.journal, "create", side_effect=RecoveryJournalError("fixture_disk_full")):
            with self.assertRaises(RecoveryJournalError):
                self.prepare(case)
        self.assertEqual(self.jobs, [])
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assert_retained(case)

    def test_mark_prepared_committed_then_lost_ack_reuses_the_same_job(self):
        case = self.admitted()
        original = self.store.mark_prepared
        def committed(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fixture_prepared_ack_unknown")
        with patch.object(self.store, "mark_prepared", side_effect=committed):
            with self.assertRaises(RuntimeError):
                self.prepare(case)
        self.assertEqual(self.row(case)["state"], "PREPARED")
        self.assertEqual(len(self.jobs), 1)
        result = self.prepare(case)
        self.assertTrue(result.duplicate)
        self.assertEqual(len(self.jobs), 1)
        self.assert_retained(case)

    def test_prepared_manifest_read_cleanup_uncertainty_blocks_later_claim(self):
        case = self.admitted()
        self.prepare(case)
        failure = RecoveryJournalError("manifest_read_unavailable")
        failure._journal_cleanup_owner = object()  # Explicit uncertain-fd fixture; no actual handle.
        with patch.object(self.journal, "read", side_effect=failure):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.prepare(case)
        self.assertIs(caught.exception, failure)
        entry = self.owner._pending[case.snapshot.execution_id]
        self.assertIs(entry.journal_cleanup_error, failure)
        with patch.object(self.journal, "read", wraps=self.journal.read) as read:
            with self.assertRaisesRegex(LifecycleError, "guardian_journal_cleanup_unverified"):
                self.prepare(case)
            read.assert_not_called()
        request = self.claim_request(case)
        with self.assertRaisesRegex(LifecycleError, "guardian_journal_cleanup_unverified"):
            self.owner.claim_launch(request, case.peer, case.auth, case.deadline)
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assertEqual(len(self.jobs), 1)
        self.assert_retained(case)

    def test_claim_committed_then_lost_ack_cannot_redeliver_launch_permission(self):
        case = self.admitted()
        self.prepare(case)
        request = self.claim_request(case)
        original = self.store.claim_launch_locked
        def committed(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fixture_claim_ack_unknown")
        with patch.object(self.store, "claim_launch_locked", side_effect=committed):
            with self.assertRaises(RuntimeError):
                self.owner.claim_launch(request, case.peer, case.auth, case.deadline)
        self.assertEqual(self.row(case)["state"], "LAUNCHING")
        replay = self.owner.claim_launch(request, case.peer, case.auth, case.deadline)
        self.assertFalse(replay.launch_authorized)
        self.assertTrue(replay.duplicate)
        self.assertEqual(case.launches, 0)
        self.assertEqual(self.row(case)["launch_in_flight"], 1)
        self.assert_retained(case)

    def test_wrong_claim_nonce_or_token_never_consumes_authority(self):
        case = self.admitted()
        self.prepare(case)
        request = self.claim_request(case)
        for changed in (replace(request, job_nonce="f" * 32), replace(request, claim_token="x" * 43)):
            with self.assertRaises(LifecycleError):
                self.owner.claim_launch(changed, case.peer, case.auth, case.deadline)
        self.assertFalse(self.row(case)["claim_consumed"])
        self.assertEqual(self.row(case)["state"], "PREPARED")
        self.assertEqual(len(self.jobs), 1)

    def test_bind_committed_then_lost_ack_keeps_root_and_transfers_custody_once(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        original = self.store.bind_root
        def committed(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("fixture_bind_ack_unknown")
        with patch.object(self.store, "bind_root", side_effect=committed):
            with self.assertRaises(RuntimeError):
                self.bind(case)
        self.assertEqual(self.row(case)["state"], "RUNNING")
        pending_root = self.owner._pending[case.snapshot.execution_id].root
        result = self.bind(case)
        self.assertEqual(result.state, "RUNNING")
        self.assertTrue(result.duplicate)
        self.assertIs(self.owner.lifecycle._entry(case.snapshot.execution_id).root, pending_root)
        self.assertEqual((len(self.remote_duplicates()), case.launches, len(self.jobs)), (1, 1, 1))
        self.assert_retained(case)

    def test_bind_journal_lost_ack_requires_fresh_publication_before_store_binding(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        original = self.journal.publish
        def published(*args, **kwargs):
            original(*args, **kwargs)
            raise RecoveryJournalError("fixture_bind_journal_unknown", publication_may_have_occurred=True)
        with patch.object(self.journal, "publish", side_effect=published):
            with self.assertRaises(RecoveryJournalError):
                self.bind(case)
        self.assertEqual(self.row(case)["state"], "LAUNCHING")
        with patch.object(self.journal, "publish", wraps=original) as republished:
            result = self.bind(case)
        republished.assert_called_once()
        self.assertEqual(result.state, "RUNNING")
        self.assertEqual((len(self.remote_duplicates()), case.launches, len(self.jobs)), (1, 1, 1))
        self.assert_retained(case)

    def test_bind_wrong_nonce_or_remote_exact_identity_never_binds_root(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        wrong_nonce = replace(case.bind_request, job_nonce="f" * 32)
        with self.assertRaises(LifecycleError):
            self.owner.bind_root(wrong_nonce, case.peer, case.auth, case.deadline)
        wrong_identity = replace(case.root.identity,
            created_filetime_100ns=case.root.identity.created_filetime_100ns + 1)
        changed = replace(case.bind_request, root_identity=wrong_identity)
        with self.assertRaises(IdentityUnavailable):
            self.owner.bind_root(changed, case.peer, case.auth, case.deadline)
        self.assertIsNone(self.row(case)["root_pid"])
        self.assertEqual(self.row(case)["state"], "LAUNCHING")
        self.assertEqual(case.root.observe().status, IdentityStatus.ALIVE)
        self.assert_retained(case)

    def test_dead_root_positive_same_handle_membership_can_bind_then_finish(self):
        case = self.admitted()
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        state = self.processes.objects[case.root.identity]
        state.status, state.code = IdentityStatus.DEAD, 0
        case.job.members.clear()
        self.assertEqual(self.bind(case).state, "RUNNING")
        result = self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=NOW + 1)
        self.assertEqual(result.state, "FINISHED")
        self.assertTrue(result.terminal)
        self.assertIsNone(self.allocation(case))
        self.assertEqual(case.launches, 1)

    def test_dead_root_without_positive_membership_and_unknown_root_cannot_bind(self):
        # Both admissions precede the first injected native failure. The owner
        # then retains/reuses its own pending POLICY guard; no fixture clears it.
        cases = [self.admitted(), self.admitted()]
        for unknown_liveness, case in zip((False, True), cases):
            self.prepare(case)
            self.claim(case)
            self.simulate_wrapper_launch(case)
            state = self.processes.objects[case.root.identity]
            state.status = IdentityStatus.UNKNOWN if unknown_liveness else IdentityStatus.DEAD
            state.membership_error = IdentityUnavailable("fixture_membership_unknown")
            case.job.members.clear()
            with self.subTest(unknown_liveness=unknown_liveness), self.assertRaises(LifecycleError):
                self.bind(case)
            self.assertIsNone(self.row(case)["root_pid"])
            self.assertFalse(self.row(case)["launch_sealed"])
            self.assert_retained(case)

    def test_terminal_bind_read_cleanup_failure_keeps_all_custody(self):
        case = self.started()
        state = self.processes.objects[case.root.identity]
        state.status, state.code = IdentityStatus.DEAD, 0
        case.job.members.clear()
        self.assertTrue(self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=NOW + 1).terminal)
        entry = self.owner.lifecycle._entry(case.snapshot.execution_id)
        failure = RecoveryJournalError("manifest_read_unavailable")
        failure._journal_cleanup_owner = object()  # Explicit uncertain-fd fixture; no actual handle.
        with patch.object(self.journal, "read", side_effect=failure):
            with self.assertRaises(RecoveryJournalError) as caught:
                self.bind(case)
        self.assertIs(caught.exception, failure)
        self.assertIs(entry.journal_cleanup_error, failure)
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_unsettled"):
            self.owner.lifecycle.close_terminal(case.snapshot.execution_id)
        self.assertIs(self.owner.lifecycle._entry(case.snapshot.execution_id), entry)
        self.assertFalse(entry.closed)
        self.assertFalse(case.job.closed)
        self.assertEqual(entry.wrapper.observe().status, IdentityStatus.ALIVE)
        self.assertEqual(entry.root.observe().status, IdentityStatus.DEAD)
        self.assertIsNone(self.allocation(case))

    def test_root_exit_with_late_child_keeps_exact_allocation_until_real_empty(self):
        case = self.started()
        before = self.allocation(case)
        state = self.processes.objects[case.root.identity]
        state.status, state.code = IdentityStatus.DEAD, 7
        case.job.members[:] = [61001]
        result = self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=NOW + 10)
        self.assertEqual((result.state, result.root_exit_code, result.active_processes), ("DRAINING", 7, 1))
        self.assertFalse(result.terminal)
        self.assert_retained(case)
        after = self.allocation(case)
        for key in ("id", "expires_at", "cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(after[key], before[key])
        case.job.members.clear()
        done = self.owner.lifecycle.reconcile(case.snapshot.execution_id, now=NOW + 20)
        self.assertTrue(done.terminal)
        self.assertEqual(done.state, "FINISHED")
        self.assertIsNone(self.allocation(case))
        self.assertEqual((len(self.jobs), len(self.remote_duplicates()), case.launches), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
