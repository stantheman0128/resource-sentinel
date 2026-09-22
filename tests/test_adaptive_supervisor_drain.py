"""Deliberate supervisor drain preserves custody without replacing children.

Creation and process observations use the existing explicit synthetic fixtures.
The registry cases exercise the production retirement/POLICY operations against
an isolated SQLite ledger and real VerifiedProcess objects with synthetic
backends. No test starts a process or provides native Windows gate evidence.
"""
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import legacy_writer
from sentinel.adaptive import supervisor_host
from sentinel.adaptive import supervisor_reconcile
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_host import SupervisorHostRefused
from tests import test_adaptive_supervisor_host as fixtures


class SupervisorDrainDispatchTests(unittest.TestCase):
    # Reuse fixture construction without inheriting/re-running its test cases.
    setUp = fixtures.SupervisorHostTests.setUp
    build = fixtures.SupervisorHostTests.build
    unregister = fixtures.SupervisorHostTests.unregister
    attach = fixtures.SupervisorHostTests.attach
    witness = fixtures.SupervisorHostTests.witness
    capture_creation = fixtures.SupervisorHostTests.capture_creation
    started = fixtures.SupervisorHostTests.started
    with_helper = fixtures.SupervisorHostTests.with_helper
    observing = fixtures.SupervisorHostTests.observing
    iterate = fixtures.SupervisorHostTests.iterate
    replace = fixtures.SupervisorHostTests.replace

    def test_begin_drain_is_idempotent_and_blocks_both_creation_boundaries(self):
        host = self.build(helper_profile_path=self.helper_profile)
        host.begin_drain()
        host.begin_drain()
        self.assertTrue(host.draining)
        for start in (host._start_guardian, host._start_helper):
            with self.subTest(start=start.__name__):
                with self.assertRaises(SupervisorHostRefused):
                    start()
        self.assertEqual(self.creation.created, [])
        self.assertTrue(host.draining)
        self.assertFalse(self.startup.closed)

    def test_dead_guardian_retires_without_rollover_on_first_and_later_ticks(self):
        host = self.started(max_guardians=3)
        original, supervisor = host.guardian, host.supervisor
        host.begin_drain()
        with patch.object(host, "_rollover_epoch", side_effect=AssertionError("drain must not roll over")):
            first = self.replace(host)
            second = host.run_once()
        self.assertFalse(first["replacement"]["started"])
        self.assertFalse(second["replacement"]["started"])
        self.assertEqual(len(self.creation.created), 1)
        self.assertIs(host.guardian, original)
        self.assertTrue(host._guardian_settled)
        self.assertIsNone(host.supervisor)
        self.assertEqual(supervisor.close_calls, 1)
        self.assertTrue(self.removals)
        self.assertTrue(all(epoch == original.epoch for epoch, _ in self.removals))
        self.assertFalse(self.startup.closed)

    def test_dead_helper_retires_without_replacement_or_affecting_live_guardian(self):
        host = self.with_helper(max_helpers=3)
        guardian, helper = host.guardian, host.helper
        host.begin_drain()
        self.observing(host, IdentityStatus.DEAD)
        first = self.iterate(host)
        second = self.iterate(host)
        self.assertFalse(first["helper"]["started"])
        self.assertFalse(second["helper"]["started"])
        self.assertEqual(len(self.creation.created), 2)
        self.assertIs(host.guardian, guardian)
        self.assertIsNone(host.helper)
        self.assertEqual(host.retired_helpers, [helper])
        self.assertEqual(self.helper_removals, [(helper.pid, 2)])
        self.assertEqual(self.removals, [])
        self.assertFalse(self.startup.closed)

    def test_close_during_live_drain_preserves_supervisor_and_creation_witnesses(self):
        host = self.with_helper()
        guardian, helper, supervisor = host.guardian, host.helper, host.supervisor
        host.begin_drain()
        with self.assertRaises(SupervisorHostRefused):
            host.close()
        self.assertIs(host.guardian, guardian)
        self.assertIs(host.helper, helper)
        self.assertIs(host.supervisor, supervisor)
        self.assertFalse(supervisor.closed)
        self.assertFalse(guardian.process.closed)
        self.assertFalse(helper.process.closed)
        self.assertNotIn(guardian.creation_handle, self.creation.closed)
        self.assertNotIn(helper.creation_handle, self.creation.closed)
        self.assertFalse(self.startup.closed)

    def test_unattached_early_death_keeps_original_creation_capture_during_drain(self):
        host = self.started()
        original = host.guardian
        host.supervisor = None
        original.process.observe = lambda: SimpleNamespace(status=IdentityStatus.DEAD)
        retained = fixtures.Supervisor(original, original.epoch)
        retained.status = IdentityStatus.DEAD
        host.begin_drain()
        with patch.object(host, "_attach", side_effect=AssertionError("cannot reopen an early-dead child")), \
                patch.object(host, "_attach_created", return_value=retained) as attach, \
                patch.object(host, "_rollover_epoch", side_effect=AssertionError("drain must not roll over")):
            host.run_once()
            host.run_once()
        attach.assert_called_once_with(original)
        self.assertIs(host.guardian, original)
        self.assertEqual(retained.close_calls, 1)
        self.assertEqual(len(self.creation.created), 1)
        self.assertFalse(self.startup.closed)

    def test_attach_interrupt_adopts_original_supervisor_before_propagating(self):
        host = self.started()
        original = host.guardian
        host.supervisor = None
        retained = fixtures.Supervisor(original, original.epoch)
        interrupted = KeyboardInterrupt()
        interrupted.supervisor_owner = retained
        with patch("sentinel.adaptive.supervisor.GuardianSupervisor.attach", side_effect=interrupted) as attach:
            with self.assertRaises(KeyboardInterrupt) as caught:
                host._capture_supervisor(original, created=False)
            self.assertIs(caught.exception, interrupted)
            self.assertIs(host.supervisor, retained)
            host.begin_drain()
            host.run_once()
        self.assertEqual(attach.call_count, 1)
        self.assertEqual(retained.ticks, 1)
        self.assertFalse(retained.closed)
        self.assertIs(host.guardian, original)
        self.assertEqual(len(self.creation.created), 1)
        self.assertNotIn(original.creation_handle, self.creation.closed)

    def test_capture_interrupt_retains_partial_without_attempting_cleanup(self):
        host = self.started()
        host.supervisor = None
        partial = fixtures.Supervisor(None, "partial")
        interrupted = KeyboardInterrupt()
        interrupted._recovery_owner = partial
        with patch("sentinel.adaptive.supervisor.GuardianSupervisor.attach", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as caught:
                host._capture_supervisor(host.guardian, created=False)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(len(host.unsettled_captures), 1)
        self.assertIs(host.unsettled_captures[0]["owner"], partial)
        self.assertEqual(partial.close_calls, 0)
        self.assertFalse(partial.closed)
        self.assertTrue(host._operational_recovery_pending())

    def test_partial_cleanup_interrupt_keeps_same_partial_and_cleanup_error(self):
        host = self.started()
        host.supervisor = None
        partial = fixtures.Supervisor(None, "partial")
        interrupted = KeyboardInterrupt()
        partial.close_error = interrupted
        failed_capture = LifecycleError("recovery_capture_binding_unverified")
        failed_capture._recovery_owner = partial
        with patch("sentinel.adaptive.supervisor.GuardianSupervisor.attach", side_effect=failed_capture):
            with self.assertRaises(KeyboardInterrupt) as caught:
                host._capture_supervisor(host.guardian, created=False)
        self.assertIs(caught.exception, interrupted)
        self.assertEqual(partial.close_calls, 1)
        self.assertFalse(partial.closed)
        self.assertEqual(len(host.unsettled_captures), 1)
        self.assertIs(host.unsettled_captures[0]["owner"], partial)
        self.assertIs(host._capture_errors[-1], interrupted)
        self.assertTrue(host._operational_recovery_pending())
        host.begin_drain()
        with self.assertRaises(SupervisorHostRefused):
            host.close()
        self.assertFalse(host.startup.closed)

    def test_guardian_record_constructor_interrupt_keeps_creation_and_witness(self):
        host = self.build()
        interrupted = KeyboardInterrupt()
        with patch.object(supervisor_host, "_Guardian", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as caught:
                host._start_guardian()
        self.assertIs(caught.exception, interrupted)
        self.assertIsNone(host.guardian)
        self.assertEqual(len(host._creation_records), 1)
        retained = host._creation_records[0]
        self.assertEqual(retained["role"], "guardian")
        self.assertIs(retained["error"], interrupted)
        self.assertIs(host._capture_errors[-1], interrupted)
        self.assertEqual(retained["witness"].process.handle, retained["info"].hProcess)
        self.assertFalse(retained["witness"].process.closed)
        self.assertEqual(host.unverified[0]["handle"], retained["info"].hProcess)
        self.assertNotIn(retained["info"].hProcess, self.creation.closed)
        self.assertTrue(host._operational_recovery_pending())
        with self.assertRaises(SupervisorHostRefused):
            host._start_guardian()
        self.assertEqual(len(self.creation.created), 1)

    def test_helper_record_constructor_interrupt_keeps_creation_and_witness(self):
        host = self.build(helper_profile_path=self.helper_profile)
        interrupted = KeyboardInterrupt()
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle", side_effect=self.witness), \
                patch.object(supervisor_host, "_Helper", side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as caught:
                host._start_helper()
        self.assertIs(caught.exception, interrupted)
        self.assertIsNone(host.helper)
        self.assertEqual(len(host._creation_records), 1)
        retained = host._creation_records[0]
        self.assertEqual(retained["role"], "helper")
        self.assertIs(retained["error"], interrupted)
        self.assertIs(host._capture_errors[-1], interrupted)
        self.assertEqual(retained["witness"].handle, retained["info"].hProcess)
        self.assertFalse(retained["witness"].closed)
        self.assertEqual(host.unverified[0]["handle"], retained["info"].hProcess)
        self.assertNotIn(retained["info"].hProcess, self.creation.closed)
        self.assertTrue(host._operational_recovery_pending())
        with self.assertRaises(SupervisorHostRefused):
            host._start_helper()
        self.assertEqual(len(self.creation.created), 1)

    def test_helper_capture_failure_retains_exception_carried_duplicate_cleanup(self):
        host = self.build(helper_profile_path=self.helper_profile)
        cleanup_owner = object()
        failed_capture = RuntimeError("fixture_duplicate_cleanup_pending")
        failed_capture._identity_handle_cleanup = (cleanup_owner,)
        with patch("sentinel.adaptive.identity.VerifiedProcess.duplicate_from_handle", side_effect=failed_capture):
            with self.assertRaises(SupervisorHostRefused):
                host._start_helper()
        self.assertIs(host._capture_errors[-1], failed_capture)
        self.assertIs(host._capture_errors[-1]._identity_handle_cleanup[0], cleanup_owner)
        retained = host._creation_records[0]
        self.assertIs(retained["error"], failed_capture)
        self.assertEqual(host.unverified[0]["handle"], retained["info"].hProcess)
        self.assertNotIn(retained["info"].hProcess, self.creation.closed)
        self.assertTrue(host._operational_recovery_pending())

    def test_broken_diagnostic_write_or_flush_returns_false_without_unwinding(self):
        class BrokenSink:
            def __init__(self, failing_operation):
                self.failing_operation = failing_operation

            def write(self, text):
                if self.failing_operation == "write":
                    raise BrokenPipeError("fixture_closed_sink")
                return len(text)

            def flush(self):
                if self.failing_operation == "flush":
                    raise OSError("fixture_flush_failed")

        for operation in ("write", "flush"):
            with self.subTest(operation=operation):
                sink = BrokenSink(operation)
                self.assertFalse(supervisor_host.emit({"event": "fixture_iteration"}, stream=sink))
                self.assertFalse(supervisor_host.emit({"event": "fixture_draining"}, stream=sink))


class SupervisorDrainRegistryTests(unittest.TestCase):
    # These helpers use a real isolated ledger and retained VerifiedProcess.
    connection = fixtures.SupervisorHostRegistryTests.connection
    setUp = fixtures.SupervisorHostRegistryTests.setUp
    held = fixtures.SupervisorHostRegistryTests.held
    witness = fixtures.SupervisorHostRegistryTests.witness
    attach = fixtures.SupervisorHostRegistryTests.attach
    started = fixtures.SupervisorHostRegistryTests.started
    with_helper = fixtures.SupervisorHostRegistryTests.with_helper
    register = fixtures.SupervisorHostRegistryTests.register
    rows = fixtures.SupervisorHostRegistryTests.rows
    runtime = fixtures.SupervisorHostRegistryTests.runtime
    dead = fixtures.SupervisorHostRegistryTests.dead
    iterate = fixtures.SupervisorHostRegistryTests.iterate

    def test_supervisor_report_cannot_retire_guardian_when_original_witness_is_unknown(self):
        host = self.started()
        self.register(self.process)
        original = host.guardian
        self.supervisors[-1].status = IdentityStatus.DEAD
        self.backend.status = IdentityStatus.UNKNOWN
        host.begin_drain()
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("unknown is not death")):
            record = self.iterate(host)
        self.assertFalse(record["replacement"]["started"])
        self.assertEqual(self.rows(), [("guardian", original.pid)])
        self.assertIs(host.guardian, original)
        self.assertEqual(len(self.creation.created), 1)
        with self.assertRaises(SupervisorHostRefused):
            host.close()
        self.assertNotIn(original.creation_handle, self.creation.closed)
        self.assertFalse(host.startup.closed)

    def test_failed_retirement_reuses_original_guard_before_drain_can_close(self):
        host = self.started(max_guardians=3)
        self.register(self.process)
        original = host.guardian
        host.begin_drain()
        failure = legacy_writer.LegacyMutationError("legacy_infrastructure_registry_unavailable")
        with patch.object(supervisor_reconcile, "unregister_dead_infrastructure_locked", side_effect=failure):
            first = self.dead(host)
        pending = host._registry_retirements[("guardian", id(original))]
        guard = pending.guard
        self.assertIsNotNone(guard)
        self.assertFalse(first["replacement"]["started"])
        self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
        with self.assertRaises(SupervisorHostRefused):
            host.close()
        self.assertFalse(host.startup.closed)
        self.assertNotIn(original.creation_handle, self.creation.closed)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("must reuse retained guard")), \
                patch.object(self.store._policy, "hold", wraps=self.store._policy.hold) as held:
            retried = self.iterate(host)
        self.assertFalse(retried["replacement"]["started"])
        self.assertIs(host._registry_retirements[("guardian", id(original))], pending)
        self.assertTrue(all(call.args[0] is guard for call in held.call_args_list))
        self.assertEqual(held.call_count, 1)
        self.assertEqual(self.rows(), [])
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(len(self.creation.created), 1)
        record = host.close()
        self.assertFalse(record["guardian_left_running"])
        self.assertEqual(record["cleanup_errors"], [])
        self.assertTrue(host.startup.closed)

    def test_live_helper_keeps_original_handles_after_guardian_retirement(self):
        host = self.with_helper()
        self.register(self.process)
        self.register(self.helper_process, role="helper")
        guardian, helper = host.guardian, host.helper
        host.begin_drain()
        self.dead(host)
        self.assertTrue(host._guardian_settled)
        self.assertEqual(self.rows(), [("helper", helper.pid)])
        with self.assertRaises(SupervisorHostRefused):
            host.close()
        self.assertIs(host.guardian, guardian)
        self.assertIs(host.helper, helper)
        self.assertEqual(self.helper_process.observe().status, IdentityStatus.ALIVE)
        self.assertNotIn(helper.creation_handle, self.creation.closed)
        self.assertFalse(host.startup.closed)
        self.assertEqual(len(self.creation.created), 2)

    def test_fully_retired_drain_closes_each_original_handle_once(self):
        host = self.with_helper(max_guardians=3, max_helpers=3)
        self.register(self.process)
        self.register(self.helper_process, role="helper")
        guardian, helper = host.guardian, host.helper
        host.begin_drain()
        self.helper_backend.status = IdentityStatus.DEAD
        observed = self.dead(host)
        self.assertFalse(observed["replacement"]["started"])
        self.assertFalse(observed["helper"]["started"])
        self.assertEqual(self.rows(), [])
        self.assertEqual(len(self.creation.created), 2)
        self.assertIsNone(host.helper)
        self.assertEqual(host.retired_helpers, [helper])
        record = host.close()
        self.assertEqual(host.close(), record)
        self.assertFalse(record["guardian_left_running"])
        self.assertFalse(record["helper_left_running"])
        self.assertEqual(record["cleanup_errors"], [])
        self.assertEqual(record["unverified"], [])
        self.assertEqual(record["unsettled_captures"], [])
        self.assertEqual(self.creation.closed.count(guardian.creation_handle), 1)
        self.assertEqual(self.creation.closed.count(helper.creation_handle), 1)
        self.assertTrue(host.startup.closed)


if __name__ == "__main__":
    unittest.main()
