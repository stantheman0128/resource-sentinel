"""Portable S1 recovery consumer tests: real SQLite, explicit native fixtures.

No native power registration, sampling, Job, process, or daily data is used.
The actual MachineSampler and power witness run against explicit tiny backends;
the actual S1 owner.close path invokes the recovery consumer.
"""
from contextlib import closing, contextmanager
import sqlite3
from types import SimpleNamespace
import unittest
import uuid
from unittest.mock import patch

from sentinel.adaptive.machine_sampler import MachineSampler
from sentinel.adaptive.control_slot import ControlSlotError
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests.test_adaptive_coordinator import CONFIG, NOW, request, status
from tests.test_adaptive_machine_sampler import Backend, endpoint, SECOND, START
from tests import test_adaptive_control_authority as fixtures
from tests.windows.adaptive_execution import S1Runtime
from tests.windows.adaptive_power import NativePowerWitness, PowerContinuityError
from tests.windows.adaptive_recovery import S1Recovery


class PowerBackend:
    def __init__(self, case):
        self.case = case
        self.parameters = None
        self.registrations = self.unregistrations = 0
        self.close_code = 0

    def register(self, parameters, registration):
        self.case.assert_outside_locks()
        self.parameters = parameters
        self.registrations += 1
        registration.value = 701
        return 0

    def unregister(self, registration):
        self.case.assert_outside_locks()
        self.case.assertEqual(registration, 701)
        self.unregistrations += 1
        return self.close_code

    def notify(self, event=4):
        self.parameters.Callback(self.parameters.Context, event, None)


class S1RecoveryTests(unittest.TestCase):
    row = fixtures.S1ControlAuthorityTests.row
    manifest = fixtures.S1ControlAuthorityTests.manifest
    allocation = fixtures.S1ControlAuthorityTests.allocation
    policy_runtime = fixtures.S1ControlAuthorityTests.policy_runtime
    assert_floor_retained = fixtures.S1ControlAuthorityTests.assert_floor_retained
    launch = fixtures.S1ControlAuthorityTests.launch
    running = fixtures.S1ControlAuthorityTests.running
    make_empty = fixtures.S1ControlAuthorityTests.make_empty

    def setUp(self):
        fixtures.S1ControlAuthorityTests.setUp(self)
        self.runtime = S1Runtime(coordinator=self.coordinator, authority=self.control,
            native=self.native, store_factory=lambda path: LifecycleStore(path, policy_provider=self.policy))
        # Reuse the fixture's already atomically admitted exact owner. All
        # subsequent calls are actual runtime/owner/recovery methods.
        self.runtime.owners.append(self.owner)
        self.owner._runtime = self.runtime
        self.clock = SimpleNamespace(now=0.0, tick=START + 10_000, sleeps=[])
        self.power = PowerBackend(self)
        self.backend = Backend(*(endpoint(index) for index in range(6)))
        self.sampler = MachineSampler(backend=self.backend)
        self.sleep_effect = None
        self.recovery = S1Recovery(self.runtime, sampler_factory=lambda: self.sampler,
            power_factory=lambda: NativePowerWitness.open(backend=self.power),
            tick=lambda: self.clock.tick, sleep=self.sleep, monotonic=lambda: self.clock.now)
        self.runtime._recovery = self.recovery
        self.transactions = 0
        self.addCleanup(self.close_power)

    def close_power(self):
        self.power.close_code = 0
        for witness in self.recovery._pending_power:
            witness.close()

    def assert_outside_locks(self):
        self.assertIsNone(self.store._policy.current_guard())
        self.assertFalse(self.owner.mutex is not None and self.owner.mutex.acquired)
        self.assertEqual(getattr(self, "transactions", 0), 0)

    def sleep(self, seconds):
        self.assert_outside_locks()
        self.assertEqual(seconds, 1.0)
        self.clock.sleeps.append(seconds)
        self.clock.now += seconds
        self.clock.tick += int(seconds * SECOND)
        if self.sleep_effect is not None:
            self.sleep_effect(len(self.clock.sleeps))

    def restored_terminal(self):
        self.owner.prepare()
        self.owner.set_cpu_rate(2500)
        self.owner.restore()
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.owner.finalize()

    def sql(self, statement, parameters=()):
        with closing(sqlite3.connect(self.coordinator.db_path)) as connection, connection:
            connection.execute(statement, parameters)

    def assert_held_open(self):
        self.assertEqual(self.policy_runtime()["admission_barrier"], "RECOVERY_HOLD")
        self.assertFalse(self.owner._closed)
        self.assertFalse(self.owner.job.closed)
        self.assertNotIn("job.close", self.events)

    def test_actual_close_collects_five_new_windows_then_cas_before_closing(self):
        self.restored_terminal()
        before = self.policy_runtime()["registry_revision"]
        with patch("tests.windows.adaptive_recovery.project_local_capacity",
                   wraps=__import__("sentinel.accounting", fromlist=["project_local_capacity"]).project_local_capacity) as project:
            self.owner.close()
        self.assertEqual(len(self.clock.sleeps), 5)
        self.assertEqual(self.backend.calls, 6)
        self.assertEqual((self.power.registrations, self.power.unregistrations), (1, 1))
        self.assertEqual(self.policy_runtime()["admission_barrier"], "NONE")
        self.assertEqual(self.policy_runtime()["registry_revision"], before + 1)
        self.assertTrue(self.owner._closed)
        self.assertTrue(self.owner.job.closed)
        self.assertEqual(project.call_count, 1)
        self.assertEqual(project.call_args.args[1]["source"], "fast")
        self.assertEqual(project.call_args.args[1]["jobs"], [])
        self.assertEqual(project.call_args.args[1]["attribution"], {})
        self.runtime._recovery.assert_entry()

    def test_unlimited_cancelled_case_needs_no_native_sample_or_power_registration(self):
        self.owner.finalize()
        self.owner.close()
        self.assertTrue(self.owner._closed)
        self.assertEqual(self.backend.calls, 0)
        self.assertEqual(self.power.registrations, 0)
        self.assertEqual(self.policy_runtime()["admission_barrier"], "NONE")

    def test_restored_slot_does_not_replace_actual_current_job_query(self):
        self.restored_terminal()
        self.owner.job.control = {"flags": 5, "rate_bp": 2500}
        with self.assertRaisesRegex(LifecycleError, "cap_not_restored"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.backend.calls, 0)

    def test_missing_slot_bound_execution_is_rejected_before_inventory(self):
        self.restored_terminal()
        self.sql("DELETE FROM managed_executions WHERE execution_id=?", (self.execution_id,))
        with self.assertRaisesRegex(ControlSlotError, "control_slot_binding_mismatch"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.backend.calls, 0)

    def test_empty_registry_does_not_replace_retained_owner_inventory(self):
        self.restored_terminal()
        # Even loss of both rows cannot erase the original native custody.
        self.sql("DELETE FROM adaptive_control_slot")
        self.sql("DELETE FROM managed_executions WHERE execution_id=?", (self.execution_id,))
        with self.assertRaisesRegex(LifecycleError, "inventory_unknown"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.backend.calls, 0)

    def test_external_terminal_scope_is_not_silently_ignored(self):
        self.restored_terminal()
        # A different registered terminal Job is outside this owner's retained
        # inventory. Even its terminal state cannot substitute for cap evidence.
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.row_factory = sqlite3.Row
            row = dict(conn.execute("SELECT * FROM managed_executions WHERE execution_id=?",
                                    (self.execution_id,)).fetchone())
            nonce = uuid.uuid4().hex
            row.update(execution_id=str(uuid.uuid4()), reservation_id=str(uuid.uuid4()),
                       job_name=self.native.JOB_PREFIX + nonce, job_nonce=nonce)
            conn.execute("INSERT INTO managed_executions(" + ",".join(row) + ") VALUES(" +
                         ",".join("?" for _ in row) + ")", tuple(row.values()))
        with self.assertRaisesRegex(LifecycleError, "inventory_unknown"):
            self.owner.close()
        self.assert_held_open()

    def test_current_job_query_failure_keeps_hold_and_handles(self):
        self.restored_terminal()
        self.owner.job.query_error = OSError("synthetic query unavailable")
        with self.assertRaises(OSError):
            self.owner.close()
        self.assert_held_open()

    def test_journal_pending_intent_keeps_hold(self):
        self.restored_terminal()
        from sentinel.adaptive.contracts import CpuControl, CpuControlMode, PendingIntent
        import uuid
        with self.owner.mutation_scope():
            self.owner._publish(pending_intent=PendingIntent(str(uuid.uuid4()),
                self.owner.record.last_applied, CpuControl(CpuControlMode.HARD_CAP, 2500)))
        with self.assertRaisesRegex(LifecycleError, "manifest_unsettled"):
            self.owner.close()
        self.assert_held_open()

    def test_surviving_member_cannot_be_settled_even_after_terminal_row(self):
        self.restored_terminal()
        self.owner.job.members.append(321)
        with self.assertRaisesRegex(LifecycleError, "job_not_empty"):
            self.owner.close()
        self.assert_held_open()

    def test_generation_change_during_sampling_does_not_clear_hold(self):
        self.restored_terminal()
        self.sleep_effect = lambda _: self.sql(
            "UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1")
        with self.assertRaisesRegex(LifecycleError, "registry_changed"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(len(self.clock.sleeps), 1)

    def test_native_cap_changed_between_windows_keeps_hold(self):
        self.restored_terminal()
        self.sleep_effect = lambda index: setattr(self.owner.job, "control", {"flags": 5, "rate_bp": 2500}) if index == 3 else None
        with self.assertRaisesRegex(LifecycleError, "cap_not_restored"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(len(self.clock.sleeps), 3)

    def test_config_change_during_sampling_does_not_clear_hold(self):
        self.restored_terminal()
        def change(_):
            self.host.capacity = lambda: ({}, dict(CONFIG, local_allocatable_cpu=7))
        self.sleep_effect = change
        with self.assertRaisesRegex(LifecycleError, "config_changed"):
            self.owner.close()
        self.assert_held_open()

    def test_host_readiness_failure_keeps_hold(self):
        self.restored_terminal()
        self.sleep_effect = lambda _: setattr(self.host, "ready_error", LifecycleError("host_changed"))
        with self.assertRaisesRegex(LifecycleError, "host_changed"):
            self.owner.close()
        self.assert_held_open()

    def test_host_readiness_changed_inside_last_native_sample_keeps_hold(self):
        self.restored_terminal()
        original = self.backend.read
        def read():
            result = original()
            if self.backend.calls == 6:
                self.host.ready_error = LifecycleError("final_host_changed")
            return result
        self.backend.read = read
        with self.assertRaisesRegex(LifecycleError, "final_host_changed"):
            self.owner.close()
        self.assert_held_open()

    def test_config_changed_inside_last_native_sample_keeps_hold(self):
        self.restored_terminal()
        original = self.backend.read
        def read():
            result = original()
            if self.backend.calls == 6:
                self.host.capacity = lambda: ({}, dict(CONFIG, local_allocatable_cpu=7))
            return result
        self.backend.read = read
        with self.assertRaisesRegex(LifecycleError, "config_changed"):
            self.owner.close()
        self.assert_held_open()

    def test_observed_suspend_discards_streak_and_invalidates_clock(self):
        self.restored_terminal()
        self.sleep_effect = lambda index: self.power.notify() if index == 3 else None
        old_epoch = self.sampler.clock_epoch
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.assert_held_open()
        self.assertNotEqual(self.sampler.clock_epoch, old_epoch)
        self.assertEqual(len(self.clock.sleeps), 3)

    def test_invalid_middle_sample_cannot_count_as_recovery(self):
        self.restored_terminal()
        self.backend = Backend(endpoint(0), endpoint(1), endpoint(2, cpu=(0, 0, 0)))
        self.sampler = MachineSampler(backend=self.backend)
        with self.assertRaisesRegex(LifecycleError, "sample_invalid"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(len(self.clock.sleeps), 2)

    def test_warmup_failure_does_not_enter_window_loop(self):
        self.restored_terminal()
        self.sampler = MachineSampler(backend=Backend(endpoint(0, memory=None)))
        with self.assertRaisesRegex(LifecycleError, "baseline_unavailable"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(len(self.clock.sleeps), 0)

    def test_stale_sample_is_not_rescued_by_low_cpu(self):
        self.restored_terminal()
        self.sleep_effect = lambda _: setattr(self.clock, "tick", self.clock.tick + 4 * SECOND)
        with self.assertRaisesRegex(LifecycleError, "sample_invalid"):
            self.owner.close()
        self.assert_held_open()

    def test_total_wait_budget_is_bounded_without_retry(self):
        self.restored_terminal()
        self.sleep_effect = lambda _: setattr(self.clock, "now", self.clock.now + 12)
        with self.assertRaisesRegex(LifecycleError, "deadline_expired"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(len(self.clock.sleeps), 1)

    def test_shared_accounting_rejects_invalid_actual_host_policy(self):
        self.restored_terminal()
        self.host.capacity = lambda: ({}, dict(CONFIG, local_allocatable_cpu=0))
        with self.assertRaisesRegex(LifecycleError, "accounting_unreconciled"):
            self.owner.close()
        self.assert_held_open()

    def test_fault_at_actual_barrier_update_rolls_back(self):
        self.restored_terminal()
        self.sql("""CREATE TRIGGER reject_recovery BEFORE UPDATE OF admission_barrier
            ON adaptive_runtime WHEN NEW.admission_barrier='NONE'
            BEGIN SELECT RAISE(ABORT, 'synthetic barrier fault'); END""")
        revision = self.policy_runtime()["registry_revision"]
        with self.assertRaises(sqlite3.IntegrityError):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.policy_runtime()["registry_revision"], revision)

    def test_slow_actual_projection_cannot_publish_none_with_expired_evidence(self):
        self.restored_terminal()
        from sentinel.accounting import project_local_capacity
        def slow(*args, **kwargs):
            result = project_local_capacity(*args, **kwargs)
            self.clock.now += .3
            return result
        revision = self.policy_runtime()["registry_revision"]
        with patch("tests.windows.adaptive_recovery.project_local_capacity", side_effect=slow):
            with self.assertRaisesRegex(LifecycleError, "sample_stale"):
                self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.policy_runtime()["registry_revision"], revision)

    def test_commit_ack_failure_restores_hold_and_retains_native_custody(self):
        self.restored_terminal()
        original = self.recovery._transaction
        @contextmanager
        def lose_ack(store):
            with original(store) as connection:
                yield connection
            raise OSError("synthetic commit acknowledgement lost")
        self.recovery._transaction = lose_ack
        with self.assertRaisesRegex(OSError, "acknowledgement lost"):
            self.owner.close()
        self.assert_held_open()
        self.assertNotIn(self.execution_id, self.recovery._settled)

    def test_power_event_inside_final_transaction_rolls_back(self):
        self.restored_terminal()
        self.sql("""CREATE TRIGGER power_during_cas AFTER UPDATE OF admission_barrier
            ON adaptive_runtime WHEN NEW.admission_barrier='NONE'
            BEGIN SELECT fixture_power_event(); END""")
        original = self.recovery._transaction
        @contextmanager
        def observed(store):
            with original(store) as connection:
                connection.create_function("fixture_power_event", 0, self.power.notify)
                yield connection
        self.recovery._transaction = observed
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.assert_held_open()

    def test_power_unregister_failure_retains_exact_witness_and_hold(self):
        self.restored_terminal()
        self.power.close_code = 5
        original = self.power.unregister
        observed = []
        def unregister(registration):
            # Successful CAS is the linearization point. Unregister is later
            # cleanup, outside locks, so do not assert NONE was never visible.
            observed.append(self.policy_runtime()["admission_barrier"])
            return original(registration)
        self.power.unregister = unregister
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(observed, ["NONE"])
        self.assertEqual(len(self.recovery._pending_power), 1)
        self.assertNotIn(self.execution_id, self.recovery._settled)
        with self.assertRaisesRegex(LifecycleError, "power_cleanup_unverified"):
            self.recovery.assert_entry()

    def test_failed_power_cleanup_retry_requeries_still_retained_job(self):
        self.restored_terminal()
        self.power.close_code = 5
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.power.close_code = 0
        self.owner.job.control = {"flags": 5, "rate_bp": 2500}
        with self.assertRaisesRegex(LifecycleError, "cap_not_restored"):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.power.registrations, 1)
        self.assertEqual(self.backend.calls, 6)

    def test_failed_registration_retains_exception_attached_witness(self):
        self.restored_terminal()
        self.power.close_code = 5
        original = self.power.register
        def failed(parameters, registration):
            original(parameters, registration)
            # Registration succeeds but its inline callback faults. This is
            # known owned registration; failed cleanup must escape on error.
            parameters.Callback(parameters.Context, 9999, None)
            return 0
        self.power.register = failed
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.assert_held_open()
        self.assertEqual(self.power.registrations, 1)
        self.assertEqual(len(self.recovery._pending_power), 1)
        # The unresolved registration must be cleaned before a second open.
        with self.assertRaises(PowerContinuityError):
            self.owner.close()
        self.assertEqual(self.power.registrations, 1)

    def test_shared_projection_keeps_another_real_legacy_allocation(self):
        from tests.test_adaptive_accounting import fast_frame
        with patch("sentinel.coordinator.frame_from_status", return_value=fast_frame(
                cpu=0, physical=16, commit=20, revision=self.policy_runtime()["registry_revision"])):
            admitted = self.coordinator.admit(request(200, cpu=.5, ram=.5), status(), config=CONFIG, now=NOW)
        self.assertTrue(admitted["allowed"], admitted)
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            original = dict(conn.execute("SELECT * FROM reservations WHERE id=?",
                                        (admitted["reservation_id"],)).fetchone())
        self.restored_terminal()
        self.owner.close()
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            saved = dict(conn.execute("SELECT * FROM reservations WHERE id=?",
                                     (admitted["reservation_id"],)).fetchone())
        self.assertEqual(saved, original)

    def test_retry_after_closed_root_and_failed_probe_uses_completed_terminal_witness(self):
        self.running()
        self.owner.set_cpu_rate(2500)
        self.owner.restore()
        self.make_empty()
        self.owner.finalize()
        probe = self.owner.reopen_probe()
        original = probe.close
        attempts = []
        def fail_once():
            attempts.append(True)
            if len(attempts) == 1:
                raise OSError("synthetic probe close failed")
            return original()
        probe.close = fail_once
        with self.assertRaisesRegex(OSError, "probe close failed"):
            self.owner.close()
        self.assertTrue(self.owner.process.closed)
        self.assertFalse(self.owner.job.closed)
        with patch.object(self.owner.process, "full_identity", side_effect=AssertionError("closed root queried")):
            self.owner.close()
        self.assertTrue(self.owner._closed)
        self.assertEqual(self.backend.calls, 6)

    def test_retry_after_closed_mutex_and_failed_admission_cleanup_does_not_reacquire(self):
        self.restored_terminal()
        original = self.admission.close
        attempts = []
        def fail_once():
            attempts.append(True)
            if len(attempts) == 1:
                raise OSError("synthetic admission close failed")
            return original()
        with patch.object(self.admission, "close", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "admission close failed"):
                self.owner.close()
            self.assertTrue(self.owner.mutex.closed)
            with patch.object(self.owner.mutex, "acquire", side_effect=AssertionError("closed mutex acquired")):
                self.owner.close()
        self.assertTrue(self.owner._closed)
        self.assertEqual(self.backend.calls, 6)

    def test_no_sampling_or_native_queries_inside_projection_transaction(self):
        self.restored_terminal()
        original = self.recovery._transaction
        @contextmanager
        def tracked(store):
            with original(store) as conn:
                self.transactions += 1
                try:
                    yield conn
                finally:
                    self.transactions -= 1
        self.recovery._transaction = tracked
        original_read = self.backend.read
        def sample_read():
            self.assert_outside_locks()
            return original_read()
        self.backend.read = sample_read
        original_query = self.owner.job.query_cpu
        def query():
            self.assertEqual(self.transactions, 0)
            return original_query()
        self.owner.job.query_cpu = query
        self.owner.close()
        self.assertTrue(self.owner._closed)


if __name__ == "__main__":
    unittest.main()
