"""P3 flow A to H through the production consumers on one isolated ledger.

Real in this module: Coordinator.admit_managed and ManagedAdmission, the shared
SQLite ledger, the formal RecoveryJournal, GuardianLaunchOwner, its
GuardianLifecycle, GuardianSupervisor.attach with the real RecoveryOwner, and
PolicyCoordinator.hold revalidation.

SYNTHETIC in this module, and therefore no Windows evidence of any kind: the
kernel namespace (mutexes, named Jobs, process handles), the wrapper's
CreateProcess effect, the supervisor process boundary (guardian and supervisor
share this one test process, so the supervisor PID is a fixture value), and the
CPU cap itself. Production has no tightening actuator yet, so the cap is placed
by a labelled fixture that still publishes through the formal journal.

Nothing here measures launch, crash, CPU effect or restore timing. No process
is started or stopped and no live Job, task or runtime setting is touched.
"""
from contextlib import closing, contextmanager
from dataclasses import fields
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import recovery_owner as recovery_module
from sentinel.adaptive.contracts import (
    CpuControl, CpuControlMode, IdentityStatus, PendingIntent, ProcessIdentity, RecoveryManifest,
)
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.guardian_lifecycle import GuardianLifecycle, job_mutex_instance
from sentinel.adaptive.native_job import JobAccess, NativeJobError
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.recovery_journal import RecoveryJournal, RecoveryJournalError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.adaptive.supervisor import GuardianSupervisor
from sentinel.adaptive.windows import NativePolicyMutexError, PolicyMutexLease
from sentinel.coordinator import Coordinator
from tests import test_adaptive_guardian_launch as launch
from tests import test_adaptive_guardian_lifecycle as lifecycle_fixture
from tests.test_adaptive_coordinator import NOW


LOGON, EPOCH, GUARDIAN = launch.LOGON, launch.EPOCH, launch.GUARDIAN
SUPERVISOR = ProcessIdentity(GUARDIAN.pid + 300000, GUARDIAN.created_filetime_100ns + 900, LOGON)
DISABLED = CpuControl(CpuControlMode.DISABLED, None)
CAP = CpuControl(CpuControlMode.HARD_CAP, 2500)
CHILD_PID = 61001
TABLES = ("managed_executions", "reservations", "executions", "adaptive_runtime", "adaptive_control_slot")


class SyntheticKernel:
    """SYNTHETIC object namespace shared by every role in one test."""
    def __init__(self):
        self.owners, self.jobs, self.events = {}, {}, []
        self.next_handle = 7000

    @contextmanager
    def own(self, role, name, lease):
        if name in self.owners:
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.owners[name] = role
        self.events.append((role, name))
        try:
            yield lease
        finally:
            del self.owners[name]


class KernelMutex:
    def __init__(self, kernel, role, logon_id, instance_id):
        self.kernel, self.role, self.logon_id, self.instance_id = kernel, role, logon_id, instance_id
        self.name = PolicyBinding(instance_id, logon_id).name
        self.closed = False

    def acquire(self, *, timeout_ms=250):
        if self.closed or timeout_ms != 250:
            raise AssertionError("fixture mutex misuse")
        return self.kernel.own(self.role, self.name,
            PolicyMutexLease(self.name, self.instance_id, self.logon_id, False))

    def close(self):
        if self.kernel.owners.get(self.name) == self.role:
            raise AssertionError("closing held fixture mutex")
        self.closed = True


class KernelPolicy:
    """The ledger's POLICY provider, on the same synthetic namespace."""
    def __init__(self, kernel, role):
        self.kernel, self.role, self.active = kernel, role, False

    def current_logon(self):
        return LOGON

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        lease = PolicyMutexLease(binding.name, binding.instance_id, binding.logon_id, False)
        with self.kernel.own(self.role, binding.name, lease):
            self.active = True
            try:
                yield lease
            finally:
                self.active = False


class JobView:
    """One handle onto a synthetic named Job. Only disable() can change it."""
    def __init__(self, kernel, name, role):
        self.kernel, self.role = kernel, role
        self.state = kernel.jobs[name]
        self.name, self.nonce, self.logon_sid = name, self.state.nonce, self.state.logon
        self.handle = kernel.next_handle
        kernel.next_handle += 1
        self.state.views += 1
        self.closed = False

    def _live(self):
        if self.closed:
            raise AssertionError("closed fixture Job used")

    def query_limits(self):
        self._live()
        return SimpleNamespace(limit_flags=0, ui_restrictions=0)

    def query_cpu(self):
        self._live()
        return SimpleNamespace(flags=self.state.flags, rate_bp=self.state.rate_bp)

    def accounting(self):
        self._live()
        return SimpleNamespace(active_processes=len(self.state.members))

    def active_pids(self):
        self._live()
        return list(self.state.members)

    @property
    def members(self):
        return self.state.members

    def set_cpu(self, *args, **kwargs):
        raise AssertionError("no production path may tighten in P3")

    set_cpu_control = set_cpu

    def disable(self):
        self._live()
        self.state.disables.append(self.role)
        self.state.flags, self.state.rate_bp = 0, 10000
        return self.query_cpu()

    def close(self):
        self._live()
        self.closed = True
        self.state.views -= 1


class P3FlowTests(unittest.TestCase):
    admitted = launch.GuardianLaunchTests.admitted
    row = launch.GuardianLaunchTests.row
    allocation = launch.GuardianLaunchTests.allocation
    prepare = launch.GuardianLaunchTests.prepare
    claim_request = launch.GuardianLaunchTests.claim_request
    claim = launch.GuardianLaunchTests.claim
    simulate_wrapper_launch = launch.GuardianLaunchTests.simulate_wrapper_launch
    bind = launch.GuardianLaunchTests.bind

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="sentinel-p3-flow-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.kernel = SyntheticKernel()
        self.policy = KernelPolicy(self.kernel, "guardian")
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0),
                                       policy_provider=self.policy)
        self.db = self.coordinator.db_path
        self.store = LifecycleStore(self.db, policy_provider=self.policy, existing_path=True)
        self.processes = launch.ProcessBackend()
        self.guardian = self.processes.process(GUARDIAN)
        journal_dir = self.directory / "recovery"
        journal_dir.mkdir()
        self.journal = RecoveryJournal(journal_dir, publisher=lifecycle_fixture.publish_fixture)
        self.jobs, self.cases = [], []
        self.authority = launch.Authority(self)
        self.owner = GuardianLaunchOwner(self.store, self.journal, guardian_epoch=EPOCH,
            authority=self.authority, guardian=self.guardian, job_factory=self.make_job,
            mutex_factory=lambda *args: KernelMutex(self.kernel, "guardian", *args))
        cpus = patch("os.cpu_count", return_value=12)
        cpus.start()
        self.addCleanup(cpus.stop)
        # SYNTHETIC process boundary: only the recovery module sees this PID.
        boundary = patch.object(recovery_module, "os", SimpleNamespace(getpid=lambda: SUPERVISOR.pid))
        boundary.start()
        self.addCleanup(boundary.stop)
        self.supervisor = None

    def native_probe(self):
        self.store._policy.assert_held()
        self.assertTrue(self.policy.active)

    def make_job(self, name, nonce, logon, *, access):
        self.native_probe()
        self.assertIs(access, JobAccess.OWNER)
        self.kernel.jobs[name] = SimpleNamespace(nonce=nonce, logon=logon, members=[], flags=0,
                                                 rate_bp=0, views=0, disables=[])
        view = JobView(self.kernel, name, "guardian")
        self.jobs.append(view)
        return view

    def open_job(self, name, nonce, logon, *, access):
        self.assertIs(access, JobAccess.CONTROL)
        state = self.kernel.jobs.get(name)
        if state is None or state.nonce != nonce or state.logon != logon:
            raise NativeJobError("job_open_failed")
        # Fence order is observable at the only native reopen.
        self.assertEqual(len([role for role in self.kernel.owners.values() if role == "recovery"]), 3)
        return JobView(self.kernel, name, "recovery")

    def started_with_child(self):
        case = self.admitted()
        self.assertEqual(self.row(case)["state"], "RESERVED")
        self.assertIsNotNone(self.allocation(case))
        self.prepare(case)
        self.claim(case)
        self.simulate_wrapper_launch(case)
        self.bind(case)
        case.job.members.append(CHILD_PID)
        return case

    def attach(self):
        store = LifecycleStore(self.db, policy_provider=KernelPolicy(self.kernel, "supervisor"), existing_path=True)
        self.supervisor = GuardianSupervisor.attach(store, self.journal, guardian=self.guardian,
            guardian_epoch=EPOCH, current=self.processes.process(SUPERVISOR),
            mutex_factory=lambda *args: KernelMutex(self.kernel, "recovery", *args),
            job_opener=self.open_job)
        return self.supervisor

    def root_exits(self, case, code=7):
        state = self.processes.objects[case.root.identity]
        state.status, state.code = IdentityStatus.DEAD, code
        case.job.members.remove(case.root.identity.pid)

    def guardian_dies(self):
        self.processes.objects[GUARDIAN].status = IdentityStatus.DEAD

    def manifest(self, case):
        row = self.row(case)
        return self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])

    def synthetic_cap_without_ack(self, case):
        """SYNTHETIC ACTUATOR: durable intent, native cap, then no journal ACK.

        P5 owns the real tightening path. The intent still goes through the
        formal journal and its control-transition checks.
        """
        old = self.manifest(case)
        state = self.kernel.jobs[old.job_name]
        scope = SimpleNamespace(execution_id=old.execution_id, creation_nonce=old.creation_nonce,
            job_name=old.job_name, reservation=old.reservation, spec_hash=old.spec_hash,
            assert_held=lambda: None,
            query_cpu_control=lambda: CAP if state.flags == 5 else DISABLED)
        values = {item.name: getattr(old, item.name) for item in fields(old) if item.name != "manifest_hash"}
        values.update(manifest_seq=old.manifest_seq + 1, pending_intent=PendingIntent(str(uuid4()), DISABLED, CAP))
        self.journal.publish(RecoveryManifest.create(**values), expected_seq=old.manifest_seq,
                             expected_hash=old.manifest_hash, writer_scope=scope)
        state.flags, state.rate_bp = 5, CAP.cpu_rate_bp

    def snapshot(self):
        with closing(sqlite3.connect(self.db)) as conn:
            return {name: conn.execute("SELECT * FROM " + name).fetchall() for name in TABLES}

    def test_a_to_g_root_exits_first_child_lives_guardian_dies_and_restore_keeps_accounting(self):
        # A + B: shared-ledger admission, guardian-created Job, contained child.
        case = self.started_with_child()
        execution = case.snapshot.execution_id
        self.assertEqual(self.row(case)["state"], "RUNNING")
        self.assertEqual((len(self.jobs), case.launches), (1, 1))
        created = self.manifest(case)
        self.assertEqual((created.guardian_identity, created.guardian_epoch), (GUARDIAN, EPOCH))

        # C: exact process handle and the existing POLICY binding, guardian alive.
        supervisor = self.attach()
        with closing(sqlite3.connect(self.db)) as conn:
            instance, logon = conn.execute(
                "SELECT policy_instance_id,policy_logon_id FROM adaptive_runtime").fetchone()
        self.assertEqual(supervisor.recovery.binding, PolicyBinding(instance, logon))
        self.assertNotEqual(supervisor.recovery._guardian._handle, self.guardian._handle)
        self.assertIn(("guardian", supervisor.recovery.binding.name), self.kernel.events)
        tick = supervisor.tick()
        self.assertEqual((tick.guardian_status, tick.inventory_verified, tick.known_executions,
                          tick.restored_executions), (IdentityStatus.ALIVE, True, (execution,), ()))

        # D: root exits first, the child lives, nothing is released.
        before = self.allocation(case)
        self.root_exits(case)
        drained = self.owner.lifecycle.reconcile(execution, now=NOW + 10)
        self.assertEqual((drained.state, drained.root_exit_code, drained.active_processes, drained.terminal),
                         ("DRAINING", 7, 1, False))
        after = self.allocation(case)
        for key in ("id", "cpu_units", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(after[key], before[key])
        self.synthetic_cap_without_ack(case)

        # E: an unverified or living guardian gives no restore authority.
        self.assertEqual(supervisor.tick().restored_executions, ())
        self.assertEqual(self.kernel.jobs[created.job_name].disables, [])
        self.guardian_dies()

        # F: same three fences, verified reopen, compare, disable, fresh Query.
        ledger = self.snapshot()
        marker = len(self.kernel.events)
        tick = supervisor.tick()
        self.assertEqual((tick.guardian_status, tick.restored_executions, tick.unresolved_executions),
                         (IdentityStatus.DEAD, (execution,), ()))
        job_fence = PolicyBinding(job_mutex_instance(execution, created.creation_nonce), LOGON).name
        self.assertIn(("guardian", job_fence), self.kernel.events[:marker])
        self.assertEqual(self.kernel.events[marker:], [
            ("recovery", supervisor.recovery._instance_binding.name),
            ("recovery", supervisor.recovery.binding.name), ("recovery", job_fence)])
        state = self.kernel.jobs[created.job_name]
        self.assertEqual((state.disables, state.flags), (["recovery"], 0))

        # G: settlement is journal-only and keeps the creator provenance.
        settled = self.manifest(case)
        self.assertEqual((settled.pending_intent, settled.last_applied), (None, DISABLED))
        self.assertEqual((settled.guardian_identity, settled.guardian_epoch), (GUARDIAN, EPOCH))
        self.assertEqual(self.snapshot(), ledger)
        self.assertEqual(self.row(case)["state"], "DRAINING")
        self.assertEqual(state.members, [CHILD_PID])
        with self.assertRaisesRegex(LifecycleError, "supervisor_custody_unsettled"):
            supervisor.close()

        # A second pass is idempotent: no second Set, no new settlement.
        supervisor.tick()
        self.assertEqual(state.disables, ["recovery"])
        self.assertEqual(self.manifest(case), settled)

    def test_h_gap_no_production_owner_can_finish_the_lifecycle_after_guardian_death(self):
        """H is NOT delivered. This pins what the missing transition must replace.

        The child ends naturally, yet nothing may settle the allocation: a
        replacement guardian is refused because the manifest creator is
        immutable, and the restore-only owner has no accounting authority.
        """
        case = self.started_with_child()
        execution = case.snapshot.execution_id
        supervisor = self.attach()
        self.root_exits(case)
        self.owner.lifecycle.reconcile(execution, now=NOW + 10)
        self.guardian_dies()
        self.assertEqual(supervisor.tick().restored_executions, (execution,))
        case.job.members.clear()

        successor = ProcessIdentity(GUARDIAN.pid, GUARDIAN.created_filetime_100ns + 5000, LOGON)
        replacement = GuardianLifecycle(LifecycleStore(self.db, policy_provider=self.policy, existing_path=True),
            self.journal, guardian=self.processes.process(successor),
            mutex_factory=lambda *args: KernelMutex(self.kernel, "successor", *args))
        with self.assertRaisesRegex(LifecycleError, "guardian_custody_binding_mismatch"):
            replacement.adopt_started(execution, job=JobView(self.kernel, case.job.name, "successor"),
                wrapper=self.processes.process(case.peer.identity), root=self.processes.process(case.root.identity))
        # Transferred handles stay owned, but the refused owner has no
        # lifecycle authority: it cannot observe the empty Job into FINISHED.
        with self.assertRaises(LifecycleError):
            replacement.reconcile(execution, now=NOW + 30)
        self.assertEqual(self.row(case)["state"], "DRAINING")
        self.assertIsNotNone(self.allocation(case))
        self.assertEqual(self.manifest(case).guardian_identity, GUARDIAN)
        self.assertFalse(hasattr(supervisor.recovery, "finalize_if_empty"))

    def test_living_guardian_finishes_once_and_the_scope_retires_from_the_concurrent_bound(self):
        case = self.started_with_child()
        execution = case.snapshot.execution_id
        supervisor = self.attach()
        self.assertEqual(supervisor.tick().known_executions, (execution,))
        self.root_exits(case)
        case.job.members.clear()
        done = self.owner.lifecycle.reconcile(execution, now=NOW + 20)
        self.assertEqual((done.state, done.terminal), ("FINISHED", True))
        self.assertEqual(self.owner.lifecycle.reconcile(execution, now=NOW + 21), done)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM executions WHERE outcome='managed_finished'")
                             .fetchone()[0], 1)
        tick = supervisor.tick()
        self.assertEqual((tick.inventory_verified, tick.known_executions), (True, ()))
        supervisor.close()

    def test_contending_recovery_cannot_enter_while_the_policy_fence_is_owned(self):
        case = self.started_with_child()
        supervisor = self.attach()
        self.guardian_dies()
        name = supervisor.recovery.binding.name
        self.kernel.owners[name] = "guardian"
        tick = supervisor.tick()
        self.assertEqual((tick.restored_executions, tick.unresolved_executions),
                         ((), (case.snapshot.execution_id,)))
        self.assertEqual(self.kernel.jobs[case.job.name].disables, [])
        del self.kernel.owners[name]
        self.assertEqual(supervisor.tick().restored_executions, (case.snapshot.execution_id,))


if __name__ == "__main__":
    unittest.main()
