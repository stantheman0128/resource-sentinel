"""Post-launch guardian integration: real isolated SQLite and formal journal.

Native processes, Jobs and mutexes below are explicit L1 backends. These tests
exercise the production consumer and retained VerifiedProcess API, not Windows
containment, host capability, a guardian daemon or production deployment.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from sentinel.adaptive.contracts import (
    AllocationKind, CpuControl, CpuControlMode, IdentityStatus, PendingIntent,
    ProcessIdentity, RecoveryManifest,
)
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore
from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease
from tests.fixtures.adaptive_evidence import fixture_evidence_provider
from tests import test_adaptive_lifecycle as fixtures


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
CAP = CpuControl(CpuControlMode.HARD_CAP, 2500)
GUARDIAN = ProcessIdentity(os.getpid(), fixtures.ROOT.created_filetime_100ns + 1,
                           fixtures.WRAPPER.logon_id)
EPOCH = "fixture-production-guardian"


class ProcessBackend:
    """Actual VerifiedProcess retains these explicit synthetic handle entries."""
    def __init__(self):
        self.entries = {}
        self.next_handle = 1000
        self.events = []
        self.on_wait = None

    def process(self, identity, *, job_handle=None):
        handle = self.next_handle
        self.next_handle += 1
        self.entries[handle] = SimpleNamespace(identity=identity,
            state=IdentityStatus.ALIVE, code=0, job=job_handle, closed=False,
            wait_error=None, close_error=None, exit_error=None)
        return VerifiedProcess(self, handle, identity)

    def entry(self, process):
        return self.entries[process._handle]

    def wait(self, handle):
        if self.on_wait is not None:
            self.on_wait()
        entry = self.entries[handle]
        if entry.closed:
            raise IdentityUnavailable("fixture_closed_handle")
        if entry.wait_error is not None:
            raise entry.wait_error
        self.events.append(("wait", handle))
        return entry.state

    def membership(self, handle, job_handle):
        entry = self.entries[handle]
        if entry.closed:
            raise IdentityUnavailable("fixture_closed_handle")
        return entry.job is not None if job_handle is None else entry.job == job_handle

    def exit_code(self, handle):
        entry = self.entries[handle]
        if entry.exit_error is not None:
            raise entry.exit_error
        if entry.state is not IdentityStatus.DEAD or entry.closed:
            raise AssertionError("unverified fixture exit")
        self.events.append(("exit_code", handle))
        return entry.code

    def close(self, handle):
        entry = self.entries[handle]
        self.events.append(("close", handle))
        if entry.close_error is not None:
            raise entry.close_error
        if entry.closed:
            raise AssertionError("fixture double close")
        entry.closed = True


class Job:
    """Explicit native query fixture; it exposes no Set or kill operation."""
    def __init__(self, record, handle):
        self.name, self.nonce = record.job_name, record.creation_nonce
        self.creation_nonce = record.creation_nonce
        self.logon_sid = record.wrapper_identity.logon_id
        self.handle = handle
        self.members = [record.root_identity.pid]
        self.control = {"flags": 0, "rate_bp": 0}
        self.closed = False
        self.query_error = self.close_error = None
        self.on_query = None
        self.close_calls = 0

    def _query(self):
        if self.closed:
            raise AssertionError("closed fixture Job queried")
        if self.on_query is not None:
            self.on_query()
        if self.query_error is not None:
            raise self.query_error

    def accounting(self):
        self._query()
        return SimpleNamespace(active_processes=len(self.members))

    def active_pids(self):
        self._query()
        return list(self.members)

    def query_cpu(self):
        self._query()
        return SimpleNamespace(**self.control)

    def close(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class Mutex:
    def __init__(self, *args, **kwargs):
        self.logon_id = args[0] if args else fixtures.WRAPPER.logon_id
        self.instance_id = args[1] if len(args) > 1 else str(uuid.uuid4())
        self.name = f"Local\\ResourceSentinel.Policy.{self.logon_id}.{self.instance_id}"
        self.acquired = self.closed = False
        self.abandoned = False
        self.release_error = None

    @contextmanager
    def acquire(self, *, timeout_ms=250):
        if self.acquired or self.closed:
            raise AssertionError("fixture mutex unavailable")
        if timeout_ms != 250:
            raise AssertionError("unbounded fixture mutex wait")
        self.acquired = True
        try:
            yield PolicyMutexLease(self.name, self.instance_id, self.logon_id, self.abandoned)
        finally:
            self.release()

    def release(self):
        if not self.acquired:
            raise AssertionError("fixture mutex not held")
        if self.release_error is not None:
            raise self.release_error
        self.acquired = False

    def close(self):
        if self.acquired:
            raise AssertionError("closing held fixture mutex")
        self.closed = True


def publish_fixture(temporary, target, *, replace):
    # Explicit portable namespace seam; no native durability claim is made.
    if replace:
        os.replace(temporary, target)
    else:
        os.link(temporary, target)
        os.unlink(temporary)


class GuardianLifecycleTests(unittest.TestCase):
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.seed_store = self.store
        self.setup_connections = []
        self.seed_records = {}
        self.seed_store.evidence_provider = fixture_evidence_provider(self.seed_evidence)
        self.processes = ProcessBackend()
        self.guardian = self.processes.process(GUARDIAN)
        self.journal_dir = self.directory / "recovery"
        self.journal_dir.mkdir()
        self.journal = RecoveryJournal(self.journal_dir, publisher=publish_fixture)
        self.mutexes = []
        self.cases = []
        self.owner = None

    def connection(self):
        connection = sqlite3.connect(self.db, timeout=3, isolation_level=None)
        connection.row_factory = sqlite3.Row
        self.setup_connections.append(connection)
        self.addCleanup(connection.close)
        return connection

    def make_mutex(self, *args, **kwargs):
        result = Mutex(*args, **kwargs)
        self.mutexes.append(result)
        return result

    def seed_evidence(self, operation, row, caller):
        record = self.seed_records[row["execution_id"]]
        # The first register call observes _registration_row before additive
        # SQL defaults add optional Job columns. It has no native Job scope.
        named = operation == "register_scope" or row.get("job_name") is not None
        return LifecycleEvidence(operation, row["execution_id"], row["state_revision"],
            "explicit-launch-fixture", caller,
            guardian_epoch=EPOCH if named else "",
            job_name=record.job_name if named else None,
            job_nonce=record.creation_nonce if named else None,
            root=record.root_identity if operation == "bind_root" else None,
            active_process_count=0 if operation in {"prepare", "claim"} else None,
            process_ids=() if operation in {"prepare", "claim"} else None,
            launch_sealed=operation == "bind_root", original_cpu_disabled=True,
            durable_manifest=True, legacy_exclusion=True,
            current_cpu_disabled=True, recovery_manifest_settled=True,
            job_creation_never_attempted=operation == "register_scope")

    def seed_started(self, *, kind=AllocationKind.DIRECT, wrapper_identity=None):
        index = len(self.cases)
        wrapper_identity = wrapper_identity or replace(fixtures.WRAPPER, pid=fixtures.WRAPPER.pid + index * 10)
        root_identity = replace(fixtures.ROOT, pid=fixtures.ROOT.pid + index * 10)
        spec = self.spec(kind=kind, wrapper=wrapper_identity)
        nonce = uuid.uuid4().hex
        record = RecoveryManifest.create(execution_id=spec.execution_id,
            reservation=spec.reservation, spec_hash=spec.spec_hash,
            job_name=f"Local\\ResourceSentinel.Job.{spec.execution_id}.{nonce}",
            creation_nonce=nonce, wrapper_identity=wrapper_identity, root_identity=root_identity,
            guardian_identity=GUARDIAN, guardian_epoch=EPOCH,
            original=DISABLED, last_applied=None, pending_intent=None,
            allocated_floor=spec.requested, manifest_seq=1)
        self.seed_records[spec.execution_id] = record
        self.allocate(spec)
        registered = self.seed_store.prepare_registration(spec, caller=wrapper_identity, now=fixtures.NOW)
        guard = self.seed_store._policy.prepare(wrapper_identity.logon_id)
        with self.seed_store._policy.hold(guard):
            scoped = self.seed_store.register_job_scope(spec.execution_id, caller=wrapper_identity,
                expected_revision=registered["state_revision"], guardian_epoch=EPOCH,
                job_name=record.job_name, job_nonce=nonce)
            prepared = self.seed_store.mark_prepared(spec.execution_id, caller=wrapper_identity,
                expected_revision=scoped["state_revision"])
        claimed = self.seed_store.claim_launch(spec.execution_id, caller=wrapper_identity,
            claim_token=registered["claim_token"], spec_hash=spec.spec_hash,
            guardian_epoch=EPOCH, expected_revision=prepared["state_revision"])
        self.seed_store.bind_root(spec.execution_id, caller=wrapper_identity,
            expected_revision=claimed["state_revision"])
        # An explicit prior-launch fixture seeds a formal checksummed file. The
        # real production reader verifies every later adoption/reconcile read;
        # journal publication/durability has its own dedicated test module.
        (self.journal_dir / (spec.execution_id + ".json")).write_text(record.to_json(), encoding="utf-8")
        job = Job(record, 7000 + index)
        wrapper = self.processes.process(wrapper_identity)
        root = self.processes.process(root_identity, job_handle=job.handle)
        case = SimpleNamespace(spec=spec, record=record, job=job, wrapper=wrapper, root=root)
        self.cases.append(case)
        return case

    def start_consumer(self):
        from sentinel.adaptive.guardian_lifecycle import GuardianLifecycle
        self.store = LifecycleStore(self.db, policy_provider=self.policy, existing_path=True)
        self.owner = GuardianLifecycle(self.store, self.journal,
            guardian=self.guardian, mutex_factory=self.make_mutex)
        return self.owner

    def adopt(self, case=None):
        case = self.seed_started() if case is None else case
        if self.owner is None:
            self.start_consumer()
        self.owner.adopt_started(case.spec.execution_id,
            job=case.job, wrapper=case.wrapper, root=case.root)
        return case

    def row(self, case):
        return self.store.query(case.spec.execution_id)

    def allocation(self, case):
        table = "reservations" if case.spec.reservation.kind is AllocationKind.DIRECT else "worker_reservations"
        with closing(sqlite3.connect(self.db)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM " + table + " WHERE id=?", (case.spec.reservation.id,)).fetchone()
            return None if row is None else dict(row)

    def root_exits(self, case, *, code=7, children=()):
        entry = self.processes.entry(case.root)
        entry.state, entry.code = IdentityStatus.DEAD, code
        case.job.members[:] = children

    def assert_custody(self, case):
        self.assertFalse(case.job.closed)
        self.assertIsNotNone(self.allocation(case))
        self.assertIsNotNone(case.root._handle)
        self.assertIsNotNone(case.wrapper._handle)

    def rewrite_manifest(self, case, **changes):
        values = {name: getattr(case.record, name) for name in case.record.__dataclass_fields__
                  if name != "manifest_hash"}
        values.update(changes)
        record = RecoveryManifest.create(**values)
        path = self.journal_dir / (record.execution_id + ".json")
        path.write_text(record.to_json(), encoding="utf-8")
        case.record = record
        return record

    def sql(self, statement, values=()):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute(statement, values)

    def test_running_job_heartbeat_preserves_demand_and_expiry(self):
        case = self.adopt()
        allocation = self.allocation(case)
        row = self.row(case)
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(result.state, "RUNNING")
        self.assertFalse(result.terminal)
        self.assertFalse(result.restore_required)
        self.assertEqual(result.active_processes, 1)
        self.assertEqual(self.row(case)["heartbeat_at"], fixtures.NOW + 10)
        saved = self.allocation(case)
        self.assertEqual(saved["heartbeat_at"], fixtures.NOW + 10)
        for name in ("expires_at", "cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(saved[name], allocation[name])
        for name in ("floor_cpu_units", "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots"):
            self.assertEqual(self.row(case)[name], row[name])
        self.assert_custody(case)

    def test_dead_wrapper_does_not_require_managed_admission_or_release_live_root(self):
        case = self.adopt()
        self.processes.entry(case.wrapper).state = IdentityStatus.DEAD
        with patch("sentinel.adaptive.admission.ManagedAdmission.snapshot",
                   side_effect=AssertionError("guardian called live wrapper context")):
            result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(result.state, "UNCERTAIN_HOLD")
        self.assertFalse(result.terminal)
        self.assertEqual(self.row(case)["hold_reason"], "heartbeat_lost")
        self.assert_custody(case)

    def test_root_exit_with_late_child_retains_allocation_until_actual_empty(self):
        case = self.adopt()
        self.root_exits(case, code=7, children=(4001,))
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual((result.state, result.root_exit_code, result.active_processes),
                         ("DRAINING", 7, 1))
        self.assertFalse(result.terminal)
        self.assertEqual(self.row(case)["root_outcome"], "7")
        self.assert_custody(case)
        case.job.members.clear()
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 20)
        self.assertEqual(result.state, "FINISHED")
        self.assertTrue(result.terminal)
        self.assertIsNone(self.allocation(case))
        self.assertFalse(case.job.closed)
        replay = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 21)
        self.assertEqual(replay, result)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM executions WHERE reservation_id=?",
                                          (case.spec.reservation.id,)).fetchone()[0], 1)
        self.owner.close_terminal(case.spec.execution_id)
        self.assertTrue(case.job.closed)
        self.assertIsNone(case.root._handle)
        self.assertIsNone(case.wrapper._handle)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_short_command_already_dead_before_adoption_uses_committed_binding(self):
        case = self.seed_started()
        self.root_exits(case, code=259)
        self.adopt(case)
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(result.root_exit_code, 259)
        self.assertTrue(result.terminal)
        self.assertIsNone(self.allocation(case))

    def test_live_root_with_empty_member_read_is_not_completion(self):
        case = self.adopt()
        case.job.members.clear()
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertFalse(result.terminal)
        self.assert_custody(case)

    def test_child_seen_at_final_evidence_read_prevents_archive(self):
        case = self.adopt()
        self.root_exits(case, children=(5001,))
        self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        case.job.members.clear()
        original = case.job.active_pids
        reads = []
        def changing_members():
            observed = original()
            reads.append(True)
            if len(reads) == 1:
                # Adversarial late observation: the outer read saw empty,
                # finalization must still consume its own fresh native proof.
                case.job.members.append(5002)
            return observed
        case.job.active_pids = changing_members
        with self.assertRaises(LifecycleError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 20)
        self.assertEqual(self.row(case)["state"], "DRAINING")
        self.assert_custody(case)

    def test_routed_job_uses_same_retained_lifecycle_and_exact_archive(self):
        case = self.seed_started(kind=AllocationKind.ROUTED)
        self.adopt(case)
        self.root_exits(case, children=(4011,))
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(result.state, "DRAINING")
        self.assert_custody(case)
        case.job.members.clear()
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 20)
        self.assertTrue(result.terminal)
        self.assertIsNone(self.allocation(case))
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM routed_executions WHERE reservation_id=?",
                                          (case.spec.reservation.id,)).fetchone()[0], 1)

    def test_cap_requires_restore_even_when_empty_and_root_dead(self):
        case = self.adopt()
        self.root_exits(case)
        case.job.control = {"flags": 5, "rate_bp": 2500}
        with self.assertRaisesRegex(LifecycleError, "external_control_conflict"):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(case.job.control, {"flags": 5, "rate_bp": 2500})
        self.assert_custody(case)

    def test_pending_manifest_intent_keeps_empty_job_custody(self):
        case = self.adopt()
        self.root_exits(case)
        self.rewrite_manifest(case, manifest_seq=2,
            pending_intent=PendingIntent(str(uuid.uuid4()), DISABLED, CAP))
        with self.assertRaisesRegex(LifecycleError, "guardian_restore_slot_unresolved"):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(case.job.control["flags"], 0)
        self.assertEqual(self.row(case)["state"], "DRAINING")
        record = self.journal.read(case.spec.execution_id, creation_nonce=case.record.creation_nonce)
        self.assertIsNone(record.pending_intent)
        self.assertEqual(record.last_applied, DISABLED)
        self.assert_custody(case)

    def test_native_query_failure_keeps_custody_and_full_allocation(self):
        case = self.adopt()
        original = self.allocation(case)
        case.job.query_error = OSError("fixture Job query failed")
        with self.assertRaisesRegex(OSError, "Job query failed"):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(self.allocation(case), original)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assert_custody(case)

    def test_unknown_root_is_hold_not_death(self):
        case = self.adopt()
        self.processes.entry(case.root).wait_error = IdentityUnavailable("fixture_wait_unavailable")
        with self.assertRaises(LifecycleError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(self.row(case)["state"], "UNCERTAIN_HOLD")
        self.assertIsNone(self.row(case)["root_outcome"])
        self.assert_custody(case)

    def test_exit_code_failure_does_not_invent_outcome_or_release(self):
        case = self.adopt()
        self.root_exits(case)
        self.processes.entry(case.root).exit_error = OSError("fixture exit unavailable")
        with self.assertRaises(IdentityUnavailable):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertIsNone(self.row(case)["root_outcome"])
        self.assert_custody(case)

    def test_wrong_manifest_guardian_rejected_but_transferred_handles_retained(self):
        case = self.seed_started()
        self.rewrite_manifest(case, guardian_identity=replace(GUARDIAN, pid=GUARDIAN.pid + 1))
        self.start_consumer()
        with self.assertRaises(LifecycleError):
            self.adopt(case)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assert_custody(case)

    def test_live_root_from_another_job_cannot_be_adopted(self):
        case = self.seed_started()
        self.processes.entry(case.root).job = case.job.handle + 1
        self.start_consumer()
        with self.assertRaises(LifecycleError):
            self.adopt(case)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assert_custody(case)

    def test_unknown_wrapper_handle_is_not_adoption_authority(self):
        case = self.seed_started()
        self.processes.entry(case.wrapper).wait_error = IdentityUnavailable("fixture_wrapper_unavailable")
        self.start_consumer()
        with self.assertRaises(LifecycleError):
            self.adopt(case)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assert_custody(case)

    def test_guardian_must_be_outside_the_adopted_job(self):
        case = self.seed_started()
        self.processes.entry(self.guardian).job = case.job.handle
        self.start_consumer()
        with self.assertRaises(LifecycleError):
            self.adopt(case)
        self.assert_custody(case)

    def test_guardian_and_wrapper_cannot_be_the_same_identity(self):
        case = self.seed_started(wrapper_identity=GUARDIAN)
        self.start_consumer()
        with self.assertRaises(LifecycleError):
            self.adopt(case)
        self.assert_custody(case)

    def test_transient_adoption_read_failure_retries_same_transferred_custody(self):
        case = self.seed_started()
        self.start_consumer()
        with patch.object(self.journal, "read", side_effect=OSError("fixture temporary journal read failure")):
            with self.assertRaises(OSError):
                self.adopt(case)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assert_custody(case)
        self.owner.retry_adoption(case.spec.execution_id)
        result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(result.state, "RUNNING")
        self.assert_custody(case)

    def test_manifest_floor_decrease_is_not_a_new_recovery_baseline(self):
        case = self.adopt()
        lowered = replace(case.record.allocated_floor, physical_bytes=case.record.allocated_floor.physical_bytes - 1)
        self.rewrite_manifest(case, manifest_seq=2, allocated_floor=lowered)
        with self.assertRaises(LifecycleError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assert_custody(case)

    def test_duplicate_adoption_does_not_replace_or_close_original_handles(self):
        case = self.adopt()
        other_job = Job(case.record, 9999)
        other_wrapper = self.processes.process(case.wrapper.identity)
        other_root = self.processes.process(case.root.identity, job_handle=9999)
        with self.assertRaises(LifecycleError):
            self.owner.adopt_started(case.spec.execution_id,
                job=other_job, wrapper=other_wrapper, root=other_root)
        self.assertFalse(other_job.closed)
        self.assertIsNotNone(other_wrapper._handle)
        self.assertIsNotNone(other_root._handle)
        self.assert_custody(case)

    def test_dispatcher_keeps_two_independent_execution_custodies(self):
        first, second = self.seed_started(), self.seed_started()
        self.adopt(first)
        self.adopt(second)
        self.root_exits(first)
        one = self.owner.reconcile(first.spec.execution_id, now=fixtures.NOW + 10)
        two = self.owner.reconcile(second.spec.execution_id, now=fixtures.NOW + 10)
        self.assertTrue(one.terminal)
        self.assertFalse(two.terminal)
        self.assertIsNone(self.allocation(first))
        self.assert_custody(second)

    def test_unsettled_close_is_refused_without_closing_any_handle(self):
        case = self.adopt()
        before = list(self.processes.events)
        with self.assertRaises(LifecycleError):
            self.owner.close_terminal(case.spec.execution_id)
        self.assertEqual(self.processes.events, before)
        self.assert_custody(case)

    def test_archive_fault_rolls_back_terminal_state_and_allocation_release(self):
        case = self.adopt()
        self.root_exits(case, children=(5011,))
        self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        row, allocation = self.row(case), self.allocation(case)
        self.sql("""CREATE TRIGGER fixture_archive_failure BEFORE INSERT ON executions
            BEGIN SELECT RAISE(ABORT, 'fixture archive failed'); END""")
        case.job.members.clear()
        with self.assertRaises(sqlite3.IntegrityError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 20)
        self.assertEqual(self.row(case), row)
        self.assertEqual(self.allocation(case), allocation)
        self.assert_custody(case)
        with self.assertRaises(LifecycleError):
            self.owner.close_terminal(case.spec.execution_id)

    def test_heartbeat_fault_rolls_back_both_observation_timestamps(self):
        case = self.adopt()
        row, allocation = self.row(case), self.allocation(case)
        self.sql("""CREATE TRIGGER fixture_heartbeat_failure BEFORE UPDATE OF heartbeat_at ON reservations
            BEGIN SELECT RAISE(ABORT, 'fixture heartbeat failed'); END""")
        with self.assertRaises(LifecycleError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(self.row(case), row)
        self.assertEqual(self.allocation(case), allocation)
        self.assert_custody(case)

    def test_committed_finalization_lost_ack_reconciles_without_second_archive(self):
        case = self.adopt()
        self.root_exits(case)
        original = self.store.finalize_if_empty
        def lost_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("fixture finalization acknowledgement lost")
        with patch.object(self.store, "finalize_if_empty", side_effect=lost_ack) as finalizer:
            with self.assertRaisesRegex(OSError, "acknowledgement lost"):
                self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertEqual(finalizer.call_count, 1)
        self.assertEqual(self.row(case)["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        self.assertFalse(case.job.closed)
        with self.assertRaises(LifecycleError):
            self.owner.close_terminal(case.spec.execution_id)
        with patch.object(self.store, "finalize_if_empty", side_effect=AssertionError("second finalization")):
            result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 11)
        self.assertTrue(result.terminal)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM executions WHERE reservation_id=?",
                                          (case.spec.reservation.id,)).fetchone()[0], 1)
        self.owner.close_terminal(case.spec.execution_id)
        self.assertTrue(case.job.closed)
        self.assertIsNone(case.root._handle)
        self.assertIsNone(case.wrapper._handle)

    def test_terminal_replay_requires_actual_archive_after_commit_ack_loss(self):
        case = self.adopt()
        self.root_exits(case)
        original = self.store.finalize_if_empty
        def lost_ack(*args, **kwargs):
            original(*args, **kwargs)
            raise OSError("fixture finalization acknowledgement lost")
        with patch.object(self.store, "finalize_if_empty", side_effect=lost_ack):
            with self.assertRaises(OSError):
                self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        # Explicit isolated storage corruption. Missing capacity is insufficient
        # evidence for completion when the exact terminal archive is absent.
        self.sql("DELETE FROM executions WHERE reservation_id=?", (case.spec.reservation.id,))
        with self.assertRaises(LifecycleError):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 11)
        self.assertFalse(case.job.closed)
        self.assertIsNotNone(case.root._handle)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)

    def test_terminal_commit_then_native_policy_cleanup_unknown_poison_retains_custody(self):
        case = self.adopt()
        self.root_exits(case)
        original = self.policy.hold
        failure = OSError("fixture policy release acknowledgement lost")
        @contextmanager
        def lost_cleanup_ack(*args, **kwargs):
            with original(*args, **kwargs) as lease:
                yield lease
            raise failure
        pinned = self.owner._restorer.policy_mutex
        with patch.object(pinned, "acquire", wraps=pinned.acquire) as emergency_acquire:
            with patch.object(self.policy, "hold", side_effect=lost_cleanup_ack):
                with self.assertRaises(OSError) as caught:
                    self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
            self.assertIs(caught.exception, failure)
            self.assertIs(self.owner._restorer.fence_error, failure)
            self.assertIn("policy_scope_cleanup_failed", failure.__notes__)
            row = self.row(case)
            archive = dict(self.connection().execute(
                "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone())
            self.assertEqual(row["state"], "FINISHED")
            self.assertIsNone(self.allocation(case))
            with patch.object(self.policy, "hold", side_effect=AssertionError("must not reacquire POLICY")) as native_hold:
                with patch.object(self.owner._entry(case.spec.execution_id).mutex, "acquire",
                        side_effect=AssertionError("must not reacquire Job")) as job_acquire:
                    with self.assertRaisesRegex(LifecycleError, "guardian_restore_fence_uncertain"):
                        self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 11)
                job_acquire.assert_not_called()
            native_hold.assert_not_called()
            emergency_acquire.assert_not_called()
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_unsettled"):
            self.owner.close_terminal(case.spec.execution_id)
        self.assertFalse(case.job.closed)
        self.assertEqual(case.job.close_calls, 0)
        self.assertIsNotNone(case.root._handle)
        self.assertIsNotNone(case.wrapper._handle)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assertEqual(self.row(case), row)
        self.assertEqual(dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone()), archive)

    def test_terminal_commit_then_sql_nonce_clear_ack_loss_reconciles_after_native_release(self):
        case = self.adopt()
        self.root_exits(case)
        policy = self.store._policy
        original_clear = policy._clear
        failure = sqlite3.OperationalError("fixture nonce clear commit acknowledgement lost")
        cleared = []
        def committed_clear_lost_ack(guard):
            # The actual fixture provider has returned from ReleaseMutex before
            # this SQL-only stage; no unknown native cleanup is being modeled.
            self.assertFalse(self.policy.active)
            self.assertIsNone(policy.current_guard())
            original_clear(guard)
            nonce = self.connection().execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0]
            self.assertIsNone(nonce)
            cleared.append(guard.nonce)
            raise failure
        with patch.object(policy, "_clear", side_effect=committed_clear_lost_ack):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        self.assertIs(caught.exception, failure)
        self.assertEqual(len(cleared), 1)
        self.assertNotIn("policy_scope_cleanup_failed", getattr(failure, "__notes__", ()))
        self.assertIsNone(self.owner._restorer.fence_error)
        row = self.row(case)
        archive = dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone())
        self.assertEqual(row["state"], "FINISHED")
        self.assertIsNone(self.allocation(case))
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_unsettled"):
            self.owner.close_terminal(case.spec.execution_id)
        self.assertFalse(case.job.closed)
        self.assertIsNotNone(case.root._handle)
        self.assertIsNotNone(case.wrapper._handle)
        with patch.object(self.store, "finalize_if_empty", side_effect=AssertionError("must not archive again")) as finalize:
            result = self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 11)
        finalize.assert_not_called()
        self.assertTrue(result.terminal)
        self.assertEqual(self.row(case), row)
        self.assertEqual(dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone()), archive)
        self.assertEqual(self.connection().execute(
            "SELECT count(*) FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone()[0], 1)
        self.assertIsNone(self.owner._restorer.fence_error)
        self.assertIsNone(self.connection().execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])
        self.owner.close_terminal(case.spec.execution_id)
        self.assertTrue(case.job.closed)
        self.assertIsNone(case.root._handle)
        self.assertIsNone(case.wrapper._handle)

    def test_missing_ledger_is_not_recreated_by_policy_or_reconciliation(self):
        case = self.adopt()
        # Close only setup-owned SQLite readers before renaming this isolated DB.
        # The production consumer opens bounded connections, never an idle one.
        for connection in self.setup_connections:
            connection.close()
        missing = self.db.with_name("offline-ledger.db")
        self.db.rename(missing)
        try:
            with self.assertRaises((LifecycleError, sqlite3.Error)):
                self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
            self.assertFalse(self.db.exists())
            self.assertFalse(case.job.closed)
            self.assertIsNotNone(case.root._handle)
        finally:
            missing.rename(self.db)

    def test_policy_and_job_fences_survive_transaction_and_native_queries_precede_it(self):
        case = self.adopt()
        original = self.store._connection
        observed = SimpleNamespace(connections=[], mutations=[], commits=0, cleanups=0)
        testcase = self
        target_tables = {"managed_executions", "reservations", "worker_reservations",
                         "executions", "routed_executions"}
        policy_columns = {"policy_instance_id", "policy_logon_id", "policy_entry_nonce",
                          "policy_binding_initialized"}

        class ObservedConnection:
            def __init__(self, connection):
                self.raw = connection
                self.targeted = False
                self.guard = None

            def __getattr__(self, name):
                return getattr(self.raw, name)

            def require_fences(self):
                current = testcase.store._policy.current_guard()
                testcase.assertIsNotNone(current)
                if self.guard is None:
                    self.guard = current
                testcase.assertIs(current, self.guard)
                testcase.assertTrue(testcase.mutexes[0].acquired)
                testcase.assertFalse(case.job.closed)
                testcase.assertIsNotNone(case.root._handle)
                testcase.assertIsNotNone(case.wrapper._handle)

            def authorize(self, operation, table, column, database, trigger):
                if operation in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}:
                    targeted = (table in target_tables or
                        table == "adaptive_runtime" and column in {"registry_revision", "admission_barrier"})
                    if targeted:
                        # Classify actual SQLite mutation targets, not whether
                        # a guard happens to exist when the transaction starts.
                        self.require_fences()
                        self.targeted = True
                        observed.mutations.append((table, column))
                    else:
                        testcase.assertEqual(operation, sqlite3.SQLITE_UPDATE)
                        testcase.assertEqual(table, "adaptive_runtime")
                        testcase.assertIn(column, policy_columns)
                if operation == sqlite3.SQLITE_TRANSACTION and table in {"COMMIT", "ROLLBACK"} and self.targeted:
                    self.require_fences()
                return sqlite3.SQLITE_OK

            def commit(self):
                if self.targeted:
                    self.require_fences()
                result = self.raw.commit()
                if self.targeted:
                    self.require_fences()
                    observed.commits += 1
                return result

            def rollback(self):
                if self.targeted:
                    self.require_fences()
                result = self.raw.rollback()
                if self.targeted:
                    self.require_fences()
                return result

        def native_read():
            self.assertFalse(any(value.raw.in_transaction for value in observed.connections),
                             "native read occurred inside SQLite transaction")
        case.job.on_query = native_read
        self.processes.on_wait = native_read

        @contextmanager
        def connection(*args, **kwargs):
            proxy = None
            try:
                with original(*args, **kwargs) as conn:
                    proxy = ObservedConnection(conn)
                    conn.set_authorizer(proxy.authorize)
                    observed.connections.append(proxy)
                    try:
                        yield proxy
                    finally:
                        if proxy.targeted:
                            proxy.require_fences()
            finally:
                if proxy is not None:
                    observed.connections.remove(proxy)
                    # The original connection has finished cleanup. Target
                    # transactions retain the same actual fences until here.
                    if proxy.targeted:
                        proxy.require_fences()
                        observed.cleanups += 1

        with patch.object(self.store, "_connection", side_effect=connection):
            self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
            before = self.row(case)
            # Prove this observer would reject an unfenced lifecycle write;
            # SQLite denies it before execution, leaving the real row intact.
            with self.assertRaises(sqlite3.DatabaseError):
                with self.store._connection() as conn:
                    conn.execute("UPDATE managed_executions SET heartbeat_at=heartbeat_at+1 WHERE execution_id=?",
                                 (case.spec.execution_id,))
            self.assertEqual(self.row(case), before)
        self.assertIn(("managed_executions", "heartbeat_at"), observed.mutations)
        self.assertIn(("reservations", "heartbeat_at"), observed.mutations)
        self.assertGreater(observed.commits, 0)
        self.assertGreater(observed.cleanups, 0)
        self.assertFalse(self.mutexes[0].acquired)

    def test_partial_terminal_cleanup_retries_exact_remaining_handles(self):
        case = self.adopt()
        self.root_exits(case)
        self.owner.reconcile(case.spec.execution_id, now=fixtures.NOW + 10)
        root_handle = case.root._handle
        wrapper_handle = case.wrapper._handle
        wrapper_entry = self.processes.entry(case.wrapper)
        wrapper_entry.close_error = IdentityUnavailable("process_handle_close_failed", 5)
        with self.assertRaises(IdentityUnavailable):
            self.owner.close_terminal(case.spec.execution_id)
        self.assertIsNone(case.root._handle)
        self.assertIsNotNone(case.wrapper._handle)
        self.assertFalse(case.job.closed)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        wrapper_entry.close_error = None
        self.owner.close_terminal(case.spec.execution_id)
        self.assertEqual(self.processes.events.count(("close", root_handle)), 1)
        self.assertEqual(self.processes.events.count(("close", wrapper_handle)), 2)
        self.assertTrue(case.job.closed)

    def test_job_mutex_constructor_failure_is_sticky_with_the_original_error(self):
        case = self.seed_started()
        self.start_consumer()
        original = RuntimeError("fixture constructor interruption")
        calls = []
        def factory(*args):
            calls.append(args)
            raise original
        self.owner._mutex_factory = factory
        with self.assertRaises(RuntimeError) as caught:
            self.owner.adopt_started(case.spec.execution_id, job=case.job,
                                     wrapper=case.wrapper, root=case.root)
        self.assertIs(caught.exception, original)
        for _ in range(3):
            with self.assertRaisesRegex(LifecycleError, "guardian_job_mutex_unverified"):
                self.owner.retry_adoption(case.spec.execution_id)
        # No replacement object is allocated while the first outcome is unknown.
        self.assertEqual(len(calls), 1)
        self.assertIs(self.owner._entries[case.spec.execution_id].mutex_error, original)
        self.assertFalse(case.job.closed)

    def test_job_mutex_replacement_waits_for_every_retained_owner(self):
        case = self.adopt()
        entry = self.owner._entries[case.spec.execution_id]
        entry.mutex = None
        class Partial:
            def __init__(self):
                self.attempts, self.error = 0, OSError("fixture close FALSE")
            def close(self):
                self.attempts += 1
                if self.error is not None:
                    raise self.error
        partial = Partial()
        original = NativePolicyMutexError("policy_mutex_identity_unavailable", 5)
        original.add_note("policy_mutex_handle_close_failed win32=6")
        original._policy_mutex_cleanup = (partial,)
        entry.mutex_error = original
        before = len(self.mutexes)
        with self.assertRaisesRegex(LifecycleError, "guardian_job_mutex_unverified"):
            self.owner._job_mutex(entry)
        self.assertEqual((partial.attempts, len(self.mutexes)), (1, before))
        partial.error = None
        entry.mutex = self.owner._job_mutex(entry)
        self.assertEqual((partial.attempts, len(self.mutexes)), (2, before + 1))
        self.assertIsNone(entry.mutex_error)
        self.assertEqual(original._policy_mutex_cleanup, ())


if __name__ == "__main__":
    unittest.main()
