"""Real isolated SQL/POLICY/journal with explicitly synthetic native actors.

No factory, source activation, admission coverage or Windows capability is
established here. Readiness and coverage are named fixture seams. Control lock
ordering, actual exemption synchronization, durable intent and retained cleanup
are exercised against the real implementation; no daily data is opened.
"""
from contextlib import contextmanager, closing
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import experiment_scope as scope
from sentinel.adaptive import experiment_demand, exemption_sync
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.experiment_scope_journal import ScopeJournal
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import CpuState
from sentinel.adaptive.policy import PolicyCoordinator
from sentinel.adaptive.windows import NativePolicyMutexError
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_exemption_sync as exemption_fixture
from tests.test_adaptive_identity import Backend


NOW, LOGON = exemption_fixture.NOW, exemption_fixture.LOGON


class TrackedPolicy(FixturePolicyProvider):
    def __init__(self, name, test):
        super().__init__(LOGON)
        self.name, self.test = name, test

    @contextmanager
    def hold(self, binding, *, timeout_ms=250):
        self.test.probe_writers()
        self.test.events.append("enter:" + self.name)
        self.test.active.append(self.name)
        try:
            with super().hold(binding, timeout_ms=timeout_ms) as lease:
                yield lease
        finally:
            self.test.assertEqual(self.test.active.pop(), self.name)
            self.test.events.append("leave:" + self.name)


class TrackedJobMutex:
    def __init__(self, test):
        self.test, self.close_calls, self.acquire_calls = test, 0, 0
        self.close_failure, self.fail_acquire = None, None

    @contextmanager
    def acquire(self, *, timeout_ms):
        self.acquire_calls += 1
        if self.fail_acquire == self.acquire_calls:
            raise NativePolicyMutexError("policy_mutex_timeout")
        self.test.probe_writers()
        self.test.assertIn(self.test.active, (["daily", "isolated"], ["isolated"]))
        self.test.events.append("enter:job")
        self.test.active.append("job")
        try:
            yield SimpleNamespace(abandoned=False)
        finally:
            self.test.assertEqual(self.test.active.pop(), "job")
            self.test.events.append("leave:job")

    def close(self):
        self.close_calls += 1
        if self.close_failure is not None:
            raise self.close_failure


class ScopeControlTests(unittest.TestCase):
    def setUp(self):
        self.daily_fixture = exemption_fixture.ExemptionSynchronizationTests()
        self.daily_fixture.setUp()
        self.addCleanup(self.daily_fixture.doCleanups)
        self.daily = self.daily_fixture.store
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.isolated = scope._IsolatedStore(self.directory / "s1-scope.sqlite3")
        self.events, self.active = [], []
        self.daily._policy = PolicyCoordinator(self.daily, TrackedPolicy("daily", self))
        self.isolated._policy = PolicyCoordinator(self.isolated, TrackedPolicy("isolated", self))
        # Explicit extra prerequisite for successful control tests. A normal
        # unbound store is separately tested below; this is not activation proof.
        self.daily_fixture.bind()
        self.guardian_backend = Backend()
        guardian_identity = ProcessIdentity(os.getpid(), 134342315823996135, LOGON)
        self.guardian_backend.value, self.guardian_backend.member = guardian_identity, False
        self.guardian = VerifiedProcess(self.guardian_backend, 700, guardian_identity)
        self.addCleanup(self.guardian.close)

        # Concrete original types with fake native backend, never a serialized
        # readiness/admission authority or invocation of prepare().
        self.demand = object.__new__(experiment_demand.DailyExperimentDemand)
        self.demand.declaration = SimpleNamespace(experiment_id=str(uuid4()))
        self.demand.ledger_path = Path(self.daily.db_path).absolute()
        self.demand._admission = SimpleNamespace(_process=self.guardian,
            _submission_policy=self.daily._policy, _experiment_demand=self.demand)
        self.demand._original = Mock()
        experiment_demand._RETAINED[self.demand.declaration.experiment_id] = self.demand
        self.owner = scope.ExperimentNativeScope(_token=scope._NEW)
        owner = self.owner
        owner.demand, owner.scope_id, owner.creation_nonce = self.demand, str(uuid4()), uuid4().hex
        owner.command, owner.guardian = object(), self.guardian
        owner.daily_store, owner._daily_policy = self.daily, self.daily._policy
        owner.deadline, owner.directory = 999999999999.0, self.directory
        owner.job_name = "Local\\ResourceSentinel.Test.Job." + owner.creation_nonce
        owner.ledger_path = self.directory / "s1-scope.sqlite3"
        owner.store, owner.isolated_identity = self.isolated, scope._identity(owner.ledger_path)
        owner._immutable = (owner.demand, owner.command, owner.scope_id, owner.creation_nonce,
            owner.guardian, owner.daily_store, owner._daily_policy, owner.deadline,
            owner.job_name, owner.directory, owner.ledger_path)
        scope._OWNERS[owner.scope_id] = owner
        self.addCleanup(self.remove_originals)
        owner._ready = Mock(side_effect=lambda: self.events.append("ready:synthetic"))
        owner._coverage_locked = Mock(side_effect=self.synthetic_coverage)
        owner._verify_job = Mock(side_effect=lambda **kwargs: self.native_observation("verify"))
        owner.mutex = TrackedJobMutex(self)
        self.cpu = CpuState(0, 0)
        self.set_failure, self.disable_failure = None, None
        self.apply_set, self.apply_disable = True, True
        owner.job = SimpleNamespace(query_cpu=Mock(side_effect=self.query_cpu),
            set_cpu_rate_unverified=Mock(side_effect=self.set_cpu), disable=Mock(side_effect=self.disable_cpu),
            close=Mock(side_effect=self.close_job), closed=False,
            accounting=Mock(return_value=SimpleNamespace(active_processes=0, total_processes=0)))
        for name in ("job", "launch", "mutex", "store"):
            setattr(owner, "_original_" + name, getattr(owner, name))
        owner.journal = ScopeJournal(self.isolated, owner.scope_id)
        wrapper = ProcessIdentity(os.getpid() + 1, guardian_identity.created_filetime_100ns + 1, LOGON)
        self.binding = dict(schema_version=1, experiment_id=self.demand.declaration.experiment_id,
            scope_id=owner.scope_id, daily_execution_id=str(uuid4()), reservation_id=str(uuid4()),
            isolated_ledger_identity=list(owner.isolated_identity), job_name=owner.job_name,
            creation_nonce=owner.creation_nonce, guardian_identity=guardian_identity.to_dict(),
            wrapper_identity=wrapper.to_dict(), command_sha256="a" * 64, source_generation=str(uuid4()),
            source_digest="b" * 64, config_digest="c" * 64, deadline_monotonic_ns=120_000_000_000)
        with owner._scope(daily=False):
            with self.isolated._transaction() as conn:
                owner.journal.initialize_locked(conn, self.binding)
        owner._registered = True
        self.clock = patch.object(scope.time, "time", return_value=NOW)
        self.wall_clock = self.clock.start()
        self.addCleanup(self.clock.stop)
        self.events.clear()

    def remove_originals(self):
        # This UUID is generated and owned only by this synthetic test, also
        # when its negative case temporarily substitutes a foreign sentinel.
        scope._OWNERS.pop(self.owner.scope_id, None)
        experiment_demand._RETAINED.pop(self.demand.declaration.experiment_id, None)

    def probe_writers(self):
        # A real independent writer must acquire both ledgers at each fake
        # native boundary: no SQL transaction is held across native work.
        for store in (self.daily, self.isolated):
            with closing(sqlite3.connect(store.db_path, timeout=0, isolation_level=None)) as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()

    def native_observation(self, name):
        self.probe_writers()
        self.events.append("native:" + name)

    def synthetic_coverage(self, conn, *, restrictive):
        self.assertTrue(restrictive)
        self.assertTrue(conn.in_transaction)
        self.assertEqual(self.active, ["daily", "isolated", "job"])
        self.assertEqual(conn.execute("SELECT mode FROM adaptive_runtime").fetchone()[0], "off")
        self.owner._restriction_lease_deadline = NOW + 3600
        self.events.append("coverage:synthetic")

    def raw_journal(self):
        with closing(sqlite3.connect(self.isolated.db_path, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM adaptive_experiment_scope_journal").fetchone())

    def query_cpu(self):
        self.native_observation("query")
        return self.cpu

    def set_cpu(self, rate):
        self.assertEqual(rate, 2500)
        self.assertEqual(self.active, ["daily", "isolated", "job"])
        self.native_observation("set")
        self.assertEqual(json.loads(self.raw_journal()["pending_target_json"]), dict(flags=5, rate_bp=2500))
        if self.apply_set:
            self.cpu = CpuState(5, 2500)
        if self.set_failure is not None:
            raise self.set_failure

    def disable_cpu(self):
        self.assertEqual(self.active, ["isolated", "job"])
        self.native_observation("disable")
        row = self.raw_journal()
        self.assertEqual(json.loads(row["pending_target_json"]), dict(flags=0, rate_bp=0))
        if self.apply_disable:
            self.cpu = CpuState(0, 0)
        if self.disable_failure is not None:
            raise self.disable_failure

    def close_job(self):
        self.native_observation("close")
        self.owner.job.closed = True

    def grant(self):
        row = self.daily_fixture.record()
        return exemption_sync.grant_record(self.daily_fixture.exemptions, row, now=NOW,
                                          policy_factory=lambda _: self.daily)

    def test_only_exact_integer_2500_is_expressible_before_any_readiness_or_write(self):
        for value in (None, True, 2500.0, "2500", 0, 2499, 2501, 5000):
            with self.subTest(value=value), self.assertRaisesRegex(scope.ExperimentScopeError, "only_explicit_s1_rate"):
                self.owner.set_cpu_rate(value)
        self.owner._ready.assert_not_called()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()
        self.assertIsNone(self.raw_journal()["pending_target_json"])

    def test_control_uses_daily_then_isolated_then_job_and_committed_intent(self):
        self.assertEqual(self.owner.set_cpu_rate(), CpuState(5, 2500))
        enters = [event for event in self.events if event.startswith("enter:")]
        leaves = [event for event in self.events if event.startswith("leave:")]
        self.assertEqual(enters, ["enter:daily", "enter:isolated", "enter:job"])
        self.assertEqual(leaves, ["leave:job", "leave:isolated", "leave:daily"])
        self.assertLess(self.events.index("coverage:synthetic"), self.events.index("native:set"))
        self.assertLess(self.events.index("native:set"), self.events.index("leave:job"))
        self.assertFalse(self.active)
        row = self.raw_journal()
        self.assertEqual(json.loads(row["last_applied_json"]), dict(flags=5, rate_bp=2500))
        self.assertIsNone(row["pending_target_json"])

    def test_real_committed_grant_before_set_prevents_native_restriction(self):
        grant = self.grant()
        self.events.clear()
        with self.assertRaisesRegex(scope.ExperimentScopeError, "user_exemption_active_or_unknown"):
            self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()
        self.assertIsNone(self.raw_journal()["pending_target_json"])
        self.assertEqual(self.daily_fixture.rows()[0]["id"], grant["id"])
        self.assertIsNotNone(self.owner.last_grant_revision)

    def test_real_committed_grant_after_set_restores_same_entire_job(self):
        self.owner.set_cpu_rate()
        original_job = self.owner.job
        grant = self.grant()
        before = self.daily_fixture.rows()
        self.events.clear()
        self.assertEqual(self.owner.observe_control(), CpuState(0, 0))
        self.assertIs(self.owner.job, original_job)
        self.owner.job.disable.assert_called_once()
        self.assertEqual([event for event in self.events if event.startswith("enter:")],
                         ["enter:daily", "enter:isolated", "enter:job", "enter:isolated", "enter:job"])
        self.assertEqual(self.daily_fixture.rows(), before)
        self.assertEqual(before[0]["expires_at"], grant["expires_at"])
        self.assertIsNone(before[0]["revoked_at"])

    def test_restore_ignores_failed_daily_readiness_source_and_daily_guard_quarantine(self):
        self.owner.set_cpu_rate()
        self.owner._ready.side_effect = RuntimeError("synthetic daily readiness failure")
        self.demand._original.side_effect = RuntimeError("synthetic source unavailable")
        self.owner._policy_poison.add("daily")
        self.events.clear()
        self.assertEqual(self.owner.restore(), CpuState(0, 0))
        self.assertEqual([event for event in self.events if event.startswith("enter:")],
                         ["enter:isolated", "enter:job"])
        self.assertIn("daily", self.owner._policy_poison)

    def test_failed_daily_observation_automatically_withdraws_owned_cap(self):
        self.owner.set_cpu_rate()
        original = RuntimeError("synthetic unavailable daily readiness")
        self.owner._ready.side_effect = original
        self.assertEqual(self.owner.observe_control(), CpuState(0, 0))
        self.assertIn(original, self.owner.errors)
        self.owner.job.disable.assert_called_once()

    def test_unknown_set_ack_keeps_durable_target_until_exact_restore(self):
        original = OSError("synthetic Set ACK lost after application")
        self.set_failure = original
        with self.assertRaises(OSError) as raised:
            self.owner.set_cpu_rate()
        self.assertIs(raised.exception, original)
        row = self.raw_journal()
        self.assertIsNone(row["last_applied_json"])
        self.assertEqual(json.loads(row["pending_target_json"]), dict(flags=5, rate_bp=2500))
        with self.assertRaisesRegex(scope.ExperimentScopeError, "control_state_changed"):
            self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_called_once()
        self.assertEqual(self.owner.restore(), CpuState(0, 0))
        self.owner.job.set_cpu_rate_unverified.assert_called_once()
        self.owner.job.disable.assert_called_once()
        self.assertIsNone(self.raw_journal()["pending_target_json"])

    def test_set_failure_before_application_clears_only_through_disabled_readback(self):
        self.apply_set, self.set_failure = False, OSError("synthetic Set failed")
        with self.assertRaises(OSError):
            self.owner.set_cpu_rate()
        self.assertIsNotNone(self.raw_journal()["pending_target_json"])
        self.assertEqual(self.owner.restore(), CpuState(0, 0))
        self.owner.job.disable.assert_not_called()
        self.assertIsNone(self.raw_journal()["pending_target_json"])

    def test_failed_disable_keeps_pending_disabled_intent_and_retry_uses_readback(self):
        self.owner.set_cpu_rate()
        self.disable_failure = OSError("synthetic Disable ACK loss")
        with self.assertRaises(OSError):
            self.owner.restore()
        self.assertEqual(json.loads(self.raw_journal()["pending_target_json"]), dict(flags=0, rate_bp=0))
        self.disable_failure = None
        self.assertEqual(self.owner.restore(), CpuState(0, 0))
        self.owner.job.disable.assert_called_once()  # no repeated write after positive disabled read

    def test_foreign_control_is_not_overwritten_during_restore(self):
        self.owner.set_cpu_rate()
        self.cpu = CpuState(5, 5000)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "external_control_conflict"):
            self.owner.restore()
        self.owner.job.disable.assert_not_called()
        self.assertEqual(json.loads(self.raw_journal()["last_applied_json"]), dict(flags=5, rate_bp=2500))

    def test_new_control_is_rejected_after_close_started(self):
        self.owner._close_started = True
        with self.assertRaisesRegex(scope.ExperimentScopeError, "only_explicit_s1_rate"):
            self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()

    def test_unregistered_scope_cannot_apply_restriction(self):
        self.owner._registered = False
        with self.assertRaisesRegex(scope.ExperimentScopeError, "only_explicit_s1_rate"):
            self.owner.set_cpu_rate()
        self.owner._ready.assert_not_called()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()

    def test_daily_lease_expiring_after_snapshot_blocks_set_and_preserves_pending_intent(self):
        original = self.owner._grants_locked
        def snapshot_then_expire():
            result = original()
            self.wall_clock.return_value = NOW + 3600
            return result
        with patch.object(self.owner, "_grants_locked", side_effect=snapshot_then_expire):
            with self.assertRaisesRegex(scope.ExperimentScopeError, "control_deadline_expired"):
                self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()
        self.assertEqual(json.loads(self.raw_journal()["pending_target_json"]), dict(flags=5, rate_bp=2500))
        self.assertEqual(self.owner.restore(), CpuState(0, 0))
        self.owner.job.disable.assert_not_called()
        self.assertIsNone(self.raw_journal()["pending_target_json"])

    def test_experiment_deadline_crossed_during_snapshot_blocks_adjacent_set(self):
        original = self.owner._grants_locked
        current = [scope.time.monotonic()]
        def snapshot_then_expire():
            result = original()
            current[0] = self.owner.deadline
            return result
        with patch.object(scope.time, "monotonic", side_effect=lambda: current[0]), \
                patch.object(self.owner, "_grants_locked", side_effect=snapshot_then_expire):
            with self.assertRaisesRegex(scope.ExperimentScopeError, "control_deadline_expired"):
                self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()
        self.assertIsNotNone(self.raw_journal()["pending_target_json"])

    def test_foreign_parent_job_blocks_restriction_before_native_set(self):
        self.guardian_backend.member = True
        with self.assertRaisesRegex(scope.ExperimentScopeError, "guardian_foreign_job"):
            self.owner.set_cpu_rate()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()

    def test_replaced_original_scope_registry_cannot_control_or_restore(self):
        scope._OWNERS[self.owner.scope_id] = object()
        for action in (self.owner.set_cpu_rate, self.owner.restore):
            with self.assertRaisesRegex(scope.ExperimentScopeError, "original_binding_changed"):
                action()
        self.owner.job.set_cpu_rate_unverified.assert_not_called()
        self.owner.job.disable.assert_not_called()
        scope._OWNERS[self.owner.scope_id] = self.owner

    def test_replaced_daily_demand_owner_blocks_restore_even_when_source_unavailable(self):
        experiment_demand._RETAINED[self.demand.declaration.experiment_id] = object()
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_demand_custody_changed"):
            self.owner.restore()
        self.owner.job.disable.assert_not_called()

    def test_replaced_immutable_job_name_blocks_restore(self):
        self.owner.job_name += "-foreign"
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_binding_changed"):
            self.owner.restore()
        self.owner.job.disable.assert_not_called()

    def test_native_completion_cannot_be_constructed_from_description(self):
        for supplied in (None, object()):
            with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_required"):
                scope.NativeScopeCompletion(self.owner, "a" * 64, _token=supplied)

    def test_forged_completion_object_cannot_replace_original_capability(self):
        forged = object.__new__(scope.NativeScopeCompletion)
        object.__setattr__(forged, "owner", self.owner)
        object.__setattr__(forged, "digest", "a" * 64)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_changed"):
            forged.assert_original()

    def closed_actors(self, *, job_closed=True):
        owner = self.owner
        owner._actors_close_started = owner._actors_closed = True
        owner._job_close_started = owner._job_closed = job_closed
        owner.job.closed = job_closed
        owner.launch = SimpleNamespace(_closed=True)
        owner._original_launch = owner.launch
        with owner._scope(daily=False):
            with owner.store._transaction() as conn:
                owner.journal.seal_launch_locked(conn, "never_launched")
                owner._terminal_record = owner.journal.finish_locked(conn, None, 0)
        owner.exclusion_binding = SimpleNamespace(_values=lambda: {"fixture": True})
        owner._daily_binding_sha256 = "d" * 64

    def test_mutex_close_ack_loss_is_tombstoned_and_never_closed_again(self):
        self.closed_actors()
        original = OSError("synthetic mutex Close ACK lost")
        self.owner.mutex.close_failure = original
        with self.assertRaises(OSError) as raised:
            self.owner.close_native()
        self.assertIs(raised.exception, original)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "mutex_close_outcome_unknown"):
            self.owner.close_native()
        self.assertEqual(self.owner.mutex.close_calls, 1)
        self.assertFalse(self.owner._native_closed)
        self.assertIsNone(self.owner.completion)

    def test_closed_actor_checkpoint_never_redrains_or_recloses_after_job_lock_timeout(self):
        self.closed_actors(job_closed=False)
        self.owner.launch = SimpleNamespace(_closed=True, drain_once=Mock(), close=Mock(), seal=Mock())
        self.owner._original_launch = self.owner.launch
        self.owner.mutex.fail_acquire = self.owner.mutex.acquire_calls + 1
        with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_timeout"):
            self.owner.close_native()
        self.assertFalse(self.owner._job_closed)
        self.assertTrue(self.owner._actors_closed)
        self.owner.mutex.fail_acquire = None
        result = self.owner.close_native()
        self.assertIs(result, self.owner.completion)
        self.owner.launch.drain_once.assert_not_called()
        self.owner.launch.close.assert_not_called()
        self.owner.launch.seal.assert_not_called()
        self.owner.job.close.assert_called_once()

    def test_partial_actor_close_retry_uses_only_original_remaining_cleanup(self):
        self.closed_actors(job_closed=False)
        self.owner._actors_closed = False
        launcher = SimpleNamespace(_closed=False, seal=Mock(), drain_once=Mock())
        original = OSError("synthetic actor cleanup incomplete")
        attempts = []
        def close():
            attempts.append(launcher)
            if len(attempts) == 1:
                raise original
            launcher._closed = True
        launcher.close = Mock(side_effect=close)
        self.owner.launch = launcher
        self.owner._original_launch = launcher
        with self.assertRaises(OSError) as raised:
            self.owner.close_native()
        self.assertIs(raised.exception, original)
        self.assertTrue(self.owner._actors_close_started)
        self.assertFalse(self.owner._actors_closed)
        self.owner.restore = Mock(side_effect=AssertionError("must not restore/query closed actors again"))
        self.owner.close_native()
        self.assertEqual(attempts, [launcher, launcher])
        launcher.seal.assert_not_called()
        launcher.drain_once.assert_not_called()
        self.owner.restore.assert_not_called()

    def test_partial_job_close_retry_never_requeries_closed_job_handle(self):
        self.closed_actors(job_closed=False)
        original = OSError("synthetic Job transient cleanup incomplete")
        attempts = []
        def close():
            attempts.append(self.owner.job)
            if len(attempts) == 1:
                raise original
            self.owner.job.closed = True
        self.owner.job.close.side_effect = close
        with self.assertRaises(OSError):
            self.owner.close_native()
        self.assertTrue(self.owner._job_close_started)
        self.owner.job.query_cpu.side_effect = AssertionError("closed native Job must not be queried again")
        self.owner._verify_job.side_effect = AssertionError("closed native Job must not be inspected again")
        self.owner.close_native()
        self.assertEqual(len(attempts), 2)
        self.assertIs(attempts[0], attempts[1])

    def test_completion_revalidates_actual_cleanup_and_cannot_be_copied(self):
        self.closed_actors()
        original = self.owner.close_native()
        original.assert_original()
        copied = object.__new__(scope.NativeScopeCompletion)
        object.__setattr__(copied, "owner", original.owner)
        object.__setattr__(copied, "digest", original.digest)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_changed"):
            copied.assert_original()
        self.owner.store.sql_errors.append(OSError("synthetic later cleanup uncertainty"))
        with self.assertRaisesRegex(scope.ExperimentScopeError, "native_cleanup_unverified"):
            original.assert_original()

    def test_completion_rejects_changed_terminal_record(self):
        self.closed_actors()
        original = self.owner.close_native()
        self.owner._terminal_record["state"] = "FINISHED"
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_changed"):
            original.assert_original()

    def test_completion_rejects_changed_exclusion_binding(self):
        self.closed_actors()
        original = self.owner.close_native()
        self.owner.exclusion_binding = SimpleNamespace(_values=lambda: {"fixture": False})
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_changed"):
            original.assert_original()

    def test_completion_rejects_changed_daily_demand_binding_digest(self):
        self.closed_actors()
        original = self.owner.close_native()
        self.owner._daily_binding_sha256 = "e" * 64
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_completion_changed"):
            original.assert_original()

    def test_completed_scope_cannot_swap_in_another_closed_job(self):
        self.closed_actors()
        original = self.owner.close_native()
        self.owner.job = SimpleNamespace(closed=True)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "native_owner_replaced"):
            original.assert_original()

    def test_completed_scope_cannot_swap_in_another_closed_launcher(self):
        self.closed_actors()
        original = self.owner.close_native()
        self.owner.launch = SimpleNamespace(_closed=True)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "native_owner_replaced"):
            original.assert_original()

    def test_partial_uncreated_wrapper_cannot_be_authorized_by_a_duck_typed_owner(self):
        self.owner._registered = False
        self.owner.launch = SimpleNamespace(demand=self.demand, scope_id=self.owner.scope_id,
            command=self.owner.command, wrapper_witness=None, root_witness=None,
            _command_dispatched=False, _wrapper_create_entered=False, process=None)
        self.owner._original_launch = self.owner.launch
        with self.assertRaisesRegex(scope.ExperimentScopeError, "uncreated_wrapper_custody_invalid"):
            self.owner.close_native()
        self.owner.job.close.assert_not_called()
        self.assertIsNone(self.owner.completion)

    def test_unbound_grant_store_cannot_be_used_as_empty_exemption_snapshot(self):
        unbound = exemption_fixture.ExemptionSynchronizationTests()
        unbound.setUp()
        self.addCleanup(unbound.doCleanups)
        # Explicit, isolated ordinary store with no bind_policy_locked call.
        # Exercise the genuine _grants_locked body under its real POLICY.
        subject = scope.ExperimentNativeScope(_token=scope._NEW)
        subject.demand = SimpleNamespace(ledger_path=unbound.db)
        subject.daily_store = unbound.store
        with unbound.held():
            with self.assertRaisesRegex(exemption_sync.ExemptionSyncError, "exemption_binding_intent_missing"):
                subject._grants_locked()
        self.assertIsNone(subject.last_grant_revision)


class IsolatedConnectionCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = scope._IsolatedStore(Path(temporary.name) / "scope.sqlite3")
        self.original_connect = sqlite3.connect
        self.connections = []
        self.addCleanup(self.close_synthetic_connections)

    def close_synthetic_connections(self):
        # The synthetic override never calls SQLite close. Test-only teardown
        # closes those known-open originals directly; production never does this.
        for connection in self.connections:
            sqlite3.Connection.close(connection)

    def connection(self, *args, **kwargs):
        class UnknownClose(sqlite3.Connection):
            close_calls = 0
            def close(self):
                self.close_calls += 1
                raise OSError("synthetic SQLite close ACK loss")
        conn = self.original_connect(*args, **kwargs, factory=UnknownClose)
        self.connections.append(conn)
        return conn

    def test_unknown_connection_close_retains_same_connection_and_blocks_reopen(self):
        with patch.object(scope.sqlite3, "connect", side_effect=self.connection) as connect:
            with self.assertRaises(OSError) as raised:
                with self.store._connection() as original:
                    original.execute("SELECT 1")
            self.assertIs(raised.exception.experiment_scope_sql_owner, self.store)
            self.assertIn(original, self.store.connections.values())
            self.assertEqual(original.close_calls, 1)
            with self.assertRaisesRegex(scope.ExperimentScopeError, "isolated_sql_cleanup_unverified"):
                with self.store._connection():
                    self.fail("quarantined store opened another connection")
            self.assertEqual(connect.call_count, 1)
            self.assertEqual(original.close_calls, 1)

    def test_primary_sql_failure_keeps_its_original_and_unknown_close_obligation(self):
        original = ValueError("synthetic transaction failure")
        with patch.object(scope.sqlite3, "connect", side_effect=self.connection):
            with self.assertRaises(ValueError) as raised:
                with self.store._connection() as conn:
                    raise original
        self.assertIs(raised.exception, original)
        self.assertIs(original.experiment_scope_sql_owner, self.store)
        self.assertIn("experiment_scope_sql_cleanup_unverified", original.__notes__)
        self.assertIn(conn, self.store.connections.values())
        self.assertEqual(conn.close_calls, 1)
        self.assertEqual(len(self.store.sql_errors), 1)

    def test_unknown_connection_open_is_retained_and_never_retried_implicitly(self):
        original = OSError("synthetic SQLite open ACK loss")
        with patch.object(scope.sqlite3, "connect", side_effect=original) as connect:
            with self.assertRaises(OSError):
                with self.store._connection():
                    self.fail("failed open yielded")
            self.assertIn(original, self.store.sql_errors)
            self.assertEqual(list(self.store.connections.values()), [None])
            with self.assertRaisesRegex(scope.ExperimentScopeError, "isolated_sql_cleanup_unverified"):
                with self.store._connection():
                    self.fail("failed open retried")
            connect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
