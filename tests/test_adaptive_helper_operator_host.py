"""Helper operator integration: isolated SQLite and explicit native fixtures.

The actual helper host, operator contracts, enrollment and protected identity
objects run here. Processes, pipe listeners, machine readings and drain replies
are synthetic. These tests do not establish Windows authentication, overhead,
native restoration or capability promotion, and touch no daily runtime.
"""
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import helper_host as cli
from sentinel.adaptive import helper_control_host as module
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.helper_observation import DrainObservationResult, HelperDrainObserver
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.operator_messages import OperatorOperation, OperatorOutcome, OperatorRequest
from sentinel.adaptive.operator_transport import OperatorTransportError
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.store import LifecycleStore
from tests import test_adaptive_helper_host as fixtures


PARENT = ProcessIdentity(7010, 134343072000000010, fixtures.LOGON)
GUARDIAN = ProcessIdentity(7011, 134343072000000011, fixtures.LOGON)
EPOCH = "guardian-operator-helper-fixture"


class Observer:
    """Explicit host sequencing seam; it fabricates no native readback."""
    def __init__(self, **kwargs):
        self.options = kwargs
        self.pending = None
        self.complete = self.cleanup_pending = False
        self.requests = self.ticks = 0

    def request_drain(self):
        self.requests += 1

    def tick(self):
        self.ticks += 1
        return DrainObservationResult("fixture_observing", complete=self.complete)


class Listener:
    def __init__(self, endpoint, *, registry):
        self.endpoint, self.registry = endpoint, registry
        self.closes = 0
        self.error = None

    def close(self):
        self.closes += 1
        if self.error:
            raise self.error


class HelperOperatorHostTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.RunningCase(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.parent = self.fixture.processes.process(PARENT)
        self.guardian = self.fixture.processes.process(GUARDIAN)
        self.fixture.register("guardian", self.guardian)
        self.fixture.connection().execute("UPDATE adaptive_runtime SET active_logon_id=?,guardian_epoch=?,mode='shadow'",
                                          (fixtures.LOGON, EPOCH))
        self.policy_id = self.fixture.connection().execute("SELECT policy_instance_id FROM adaptive_runtime").fetchone()[0]
        self.options = dict(instance_id=str(uuid4()), operator_instance_id=str(uuid4()),
            parent_instance_id=str(uuid4()), policy_instance_id=self.policy_id,
            guardian_epoch=EPOCH, parent_identity=PARENT,
            guardian_endpoint=NativePipeEndpoint(fixtures.LOGON, str(uuid4()), GUARDIAN))
        self.profile_path = fixtures.shadow_profile_file(self.fixture.directory)

    def open_job(self, name, nonce, logon):
        job = self.fixture.open_job(name, nonce, logon)
        job.name, job.nonce, job.logon_sid = name, nonce, logon
        return job

    def build(self, *, observer_factory=Observer):
        host = module.OperationalHelperHost(**self.options,
            data_dir=self.fixture.directory, profile_path=self.profile_path,
            clock=self.fixture.clock, machine_source=self.fixture.machine,
            sleep=self.fixture.sleeps.append, open_job=self.open_job,
            parent_opener=lambda identity: self.parent,
            listener_factory=Listener, observer_factory=observer_factory)
        with patch.object(host, "_capability", return_value=fixtures.SYNTHETIC), \
                patch.object(VerifiedProcess, "current", return_value=self.fixture.process), \
                patch("sentinel.adaptive.store.LifecycleStore", return_value=self.fixture.store):
            self.started = host.start()
        host.operator_service.serve_once = lambda *args, **kwargs: None
        self.host = host
        return host

    def request(self, operation=OperatorOperation.DRAIN, **changes):
        return OperatorRequest(**(dict(request_id=str(uuid4()), operation=operation,
            instance_id=self.options["instance_id"], policy_instance_id=self.policy_id,
            guardian_epoch=EPOCH, expected_registry_revision=0 if operation is OperatorOperation.DRAIN else None)
            | changes))

    def drain(self, host):
        return host.handle_operator(self.request(), caller_identity=PARENT)

    def off(self):
        self.fixture.connection().execute("UPDATE adaptive_runtime SET mode='off',admission_barrier='NONE'")

    def ready(self, host):
        self.drain(host)
        self.off()
        host._drain_observer.complete = True
        host.run_once()
        self.assertTrue(host._drain_ready())

    def test_start_uses_parent_bound_endpoint_and_creates_no_discovery_file(self):
        host = self.build()
        self.assertEqual(host.operator_endpoint.server_identity, fixtures.HELPER)
        self.assertEqual(host.operator_endpoint.instance_id, self.options["operator_instance_id"])
        self.assertEqual(host.operator_service.scope, "helper")
        self.assertEqual(self.started["parent_instance_id"], self.options["parent_instance_id"])
        self.assertFalse((self.fixture.directory / "adaptive-host").exists())
        self.assertFalse(host._drain_requested)
        self.assertEqual(host._drain_observer.ticks, 0)

    def test_describe_and_default_shadow_tick_never_activate_drain_or_client(self):
        host = self.build(observer_factory=HelperDrainObserver)
        reply = host.handle_operator(self.request(OperatorOperation.DESCRIBE), caller_identity=PARENT)
        with patch("sentinel.adaptive.control_transport.ControlProposalClient",
                   side_effect=AssertionError("shadow constructed active client")):
            host.run_once()
        self.assertEqual(reply.scope, "helper")
        self.assertEqual(reply.outcome, OperatorOutcome.COMPLETE)
        self.assertIsNone(reply.native_disabled)
        self.assertFalse(host._drain_requested)
        self.assertIsNone(host._drain_observer._client)
        self.assertIsNone(host._drain_observer._binding)

    def test_only_exact_live_parent_can_latch_helper_drain(self):
        host = self.build()
        for caller in (fixtures.STRANGER, replace(PARENT, created_filetime_100ns=PARENT.created_filetime_100ns + 1)):
            with self.assertRaisesRegex(OperatorTransportError, "parent_binding_mismatch"):
                host.handle_operator(self.request(), caller_identity=caller)
        self.fixture.processes.entries[self.parent._handle].state = IdentityStatus.DEAD
        with self.assertRaisesRegex(cli.HelperHostRefused, "parent_unverified"):
            self.drain(host)
        self.assertFalse(host._drain_requested)

    def test_helper_rejects_restore_audit_and_foreign_target(self):
        host = self.build()
        for operation in (OperatorOperation.RESTORE_ONLY, OperatorOperation.AUDIT):
            with self.assertRaisesRegex(OperatorTransportError, "scope_unsupported"):
                host.handle_operator(self.request(operation), caller_identity=PARENT)
        with self.assertRaisesRegex(OperatorTransportError, "parent_binding_mismatch"):
            host.handle_operator(self.request(instance_id=str(uuid4())), caller_identity=PARENT)
        self.assertFalse(host._drain_requested)

    def test_drain_is_latched_before_ack_and_exact_replay_does_not_reset_it(self):
        host = self.build()
        request = self.request()
        first = host.handle_operator(request, caller_identity=PARENT)
        self.assertTrue(host._drain_requested)
        self.assertIs(host._drain_request, request)
        self.assertEqual(host._drain_observer.ticks, 0)
        self.assertEqual((first.outcome, first.accepted), (OperatorOutcome.PENDING, True))
        host.handle_operator(request, caller_identity=PARENT)
        self.assertIs(host._drain_request, request)
        with self.assertRaisesRegex(OperatorTransportError, "payload_changed"):
            host.handle_operator(replace(request, expected_registry_revision=2), caller_identity=PARENT)
        self.assertTrue(host._drain_requested)

    def test_describe_can_observe_original_drain_but_not_unknown_id(self):
        host = self.build()
        request = self.request()
        host.handle_operator(request, caller_identity=PARENT)
        reply = host.handle_operator(self.request(OperatorOperation.DESCRIBE,
            observe_request_id=request.request_id), caller_identity=PARENT)
        self.assertEqual(reply.host_state, "draining")
        with self.assertRaisesRegex(OperatorTransportError, "request_unknown"):
            host.handle_operator(self.request(OperatorOperation.DESCRIBE,
                observe_request_id=str(uuid4())), caller_identity=PARENT)

    def test_explicit_drain_runs_observation_and_never_shadow_decisions_again(self):
        host = self.build()
        self.drain(host)
        with patch.object(host.shadow, "tick", side_effect=AssertionError("normal policy after drain")):
            host.run_once()
        self.assertEqual(host._drain_observer.ticks, 1)
        self.assertFalse(host._drain_ready())

    def test_active_pending_rpc_is_reconciled_before_frame_only_observation(self):
        host = self.build()
        control = SimpleNamespace(pending=object(), acknowledged=None, _uncertain=False,
                                  _stopping=False, _barrier_execution=None)
        calls = []

        def reconcile():
            calls.append("restore")
            self.assertTrue(control._stopping)
            control.pending = None
            return SimpleNamespace(reason="fixture_restored")

        control.reconcile = reconcile
        host.control = control
        self.drain(host)
        host.run_once()
        self.assertEqual(calls, ["restore"])
        self.assertEqual(host._drain_observer.ticks, 0)
        host.run_once()
        self.assertEqual(host._drain_observer.ticks, 1)

    def test_active_owned_cap_requests_stop_without_running_active_policy(self):
        host = self.build()
        control = SimpleNamespace(pending=None, acknowledged=object(), _uncertain=False, _stopping=False)
        calls = []

        def stop(reason):
            calls.append(reason)
            control.acknowledged = None
            control._barrier_execution = "old-episode-marker"
            return SimpleNamespace(reason="fixture_restored")

        control.request_stop = stop
        control.tick = lambda: self.fail("active policy during drain")
        host.control = control
        self.drain(host)
        host.run_once()
        self.assertEqual(calls, ["mode_off"])
        self.assertFalse(host._restore_pending())
        host.run_once()
        self.assertEqual(host._drain_observer.ticks, 1)

    def test_pending_frame_preserves_query_enrollment_until_ack_reconciliation(self):
        self.fixture.seed(1)
        host = self.build()
        self.drain(host)
        host._drain_observer.pending = object()
        with patch.object(host, "refresh_enrollment", side_effect=AssertionError("replaced pending handle set")):
            host.run_once()
        self.assertEqual(host.jobs.enrolled, (fixtures.execution(1),))
        self.assertEqual(self.fixture.jobs[fixtures.job_name(1)].close_calls, 0)

    def test_pending_frame_can_reconcile_after_natural_scope_retirement(self):
        self.fixture.seed(1)
        host = self.build()
        self.drain(host)
        pending = host._drain_observer.pending = object()
        self.fixture.connection().execute("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?",
                                          (fixtures.execution(1),))
        host.run_once()
        self.assertEqual(host.jobs.enrolled, ())
        self.assertEqual(self.fixture.jobs[fixtures.job_name(1)].close_calls, 1)
        self.assertIs(host._drain_observer.pending, pending)
        self.assertEqual(host._drain_observer.ticks, 1)

    def test_bad_inventory_cannot_complete_or_send_recovery_frames(self):
        self.fixture.seed(1, name="bad-name")
        host = self.build()
        self.drain(host)
        self.off()
        host._drain_observer.complete = True
        result = host.run_once()
        self.assertEqual(result.reason, "helper_drain_inventory_unverified")
        self.assertFalse(host._drain_ready())
        self.assertEqual(host._drain_observer.ticks, 0)

    def test_off_and_barrier_none_are_both_required_for_host_completion(self):
        host = self.build()
        self.drain(host)
        host._drain_observer.complete = True
        host.run_once()
        self.assertFalse(host._drain_ready())
        self.fixture.connection().execute("UPDATE adaptive_runtime SET mode='off',admission_barrier='RECOVERY_HOLD'")
        host.run_once()
        self.assertFalse(host._drain_ready())
        self.off()
        host.run_once()
        self.assertTrue(host._drain_ready())

    def test_real_observer_integration_completes_only_after_live_off_none(self):
        host = self.build(observer_factory=HelperDrainObserver)
        self.drain(host)
        self.off()
        with patch("sentinel.adaptive.control_transport.ObservationClient",
                   side_effect=AssertionError("no frame needed for verified empty off binding")):
            host.run_once()
            self.assertTrue(host._drain_ready())
            result = host.close()
        self.assertEqual(result["event"], "helper_operator_host_closed")
        self.assertTrue(host._closed)
        self.assertTrue(host.registered)

    def test_observer_unknown_cleanup_keeps_query_custody_and_refuses_close(self):
        self.fixture.seed(1)
        host = self.build()
        self.ready(host)
        host._drain_observer.cleanup_pending = True
        with self.assertRaisesRegex(cli.HelperHostRefused, "drain_pending"):
            host.close()
        self.assertEqual(self.fixture.jobs[fixtures.job_name(1)].close_calls, 0)
        self.assertIs(host.process, self.fixture.process)

    def test_query_close_failure_is_quarantined_without_a_second_close(self):
        self.fixture.seed(1)
        host = self.build()
        self.ready(host)
        job = self.fixture.jobs[fixtures.job_name(1)]
        job.close_error = OSError("fixture query close unknown")
        with self.assertRaises(cli.HelperHostRefused):
            host.close()
        retained = host.jobs._retained[0]
        with self.assertRaisesRegex(cli.HelperHostRefused, "cleanup_quarantined"):
            host.close()
        self.assertEqual(job.close_calls, 1)
        self.assertIs(retained.job, job)
        self.assertFalse(host._closed)
        self.assertIs(host.process, self.fixture.process)

    def test_listener_close_failure_retains_parent_and_self_handles(self):
        host = self.build()
        self.ready(host)
        listener = host.operator_listener
        listener.error = OSError("fixture listener cleanup unknown")
        with self.assertRaises(OSError):
            host.close()
        with self.assertRaisesRegex(cli.HelperHostRefused, "cleanup_quarantined"):
            host.close()
        self.assertIs(host.operator_listener, listener)
        self.assertEqual(listener.closes, 1)
        self.assertIs(host.parent_process, self.parent)
        self.assertIs(host.process, self.fixture.process)

    def test_changed_off_barrier_between_readiness_and_close_keeps_host_alive(self):
        host = self.build()
        self.ready(host)
        self.fixture.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaisesRegex(cli.HelperHostRefused, "drain_pending"):
            host.close()
        self.assertFalse(host._closed)

    def test_operator_unknown_pipe_cleanup_is_sticky_and_latches_drain(self):
        host = self.build()
        error = IpcError("fixture_pipe_unknown")
        error.add_note("pipe_peer_close_failed")
        host.operator_service.serve_once = lambda *args, **kwargs: (_ for _ in ()).throw(error)
        host._operator_poll()
        self.assertIs(host._operator_error, error)
        self.assertTrue(host._drain_requested)
        host.operator_service.serve_once = lambda *args, **kwargs: self.fail("reused unverified pipe")
        host._operator_poll()

    def test_operator_idle_timeout_does_not_create_a_drain_or_cleanup_obligation(self):
        host = self.build()
        host.operator_service.serve_once = lambda *args, **kwargs: (_ for _ in ()).throw(IpcError("ipc_timeout"))
        host._operator_poll()
        self.assertFalse(host._drain_requested)
        self.assertIsNone(host._operator_error)

    def test_missing_runtime_report_keeps_proof_fields_unknown(self):
        host = self.build()
        with patch.object(host, "_check_runtime_binding", side_effect=OSError("fixture database unavailable")):
            reply = self.drain(host)
        self.assertEqual(reply.outcome, OperatorOutcome.PENDING)
        self.assertIsNone(reply.native_disabled)
        self.assertIsNone(reply.registry_revision)
        self.assertIsNone(reply.inventory_complete)
        self.assertIsNone(reply.barrier_cleared)

    def test_explicit_active_host_requires_same_guardian_for_control_and_observation(self):
        host = module.OperationalHelperControlHost(**self.options,
            data_dir=self.fixture.directory, endpoint=self.options["guardian_endpoint"], evidence_authority=object())
        self.assertEqual(host.control_guardian_epoch, EPOCH)
        with self.assertRaisesRegex(cli.HelperHostRefused, "control_binding_mismatch"):
            module.OperationalHelperControlHost(**self.options, data_dir=self.fixture.directory,
                endpoint=NativePipeEndpoint(fixtures.LOGON, str(uuid4()), GUARDIAN), evidence_authority=object())

    def test_registration_failure_retains_exact_guard_for_same_owner_retry(self):
        host = cli.HelperHost(data_dir=self.fixture.directory)
        host.store, host.process = self.fixture.store, self.fixture.process
        with patch("sentinel.adaptive.legacy_writer.register_infrastructure_locked",
                   side_effect=OSError("fixture registration transaction failed")):
            with self.assertRaisesRegex(cli.HelperHostRefused, "registry_unavailable"):
                host._register()
        operation, guard = host._registration_operation, host._registration_operation.guard
        self.assertIsNotNone(guard)
        with self.assertRaisesRegex(cli.HelperHostRefused, "registration_pending"):
            host.close()
        with patch.object(host.store._policy, "prepare", side_effect=AssertionError("new guard during retry")):
            host._register()
        self.assertTrue(host.registered)
        self.assertIs(host._registration_operation, operation)
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.pending)

    def test_registration_native_cleanup_failure_stays_quarantined(self):
        host = cli.HelperHost(data_dir=self.fixture.directory)
        host.store, host.process = self.fixture.store, self.fixture.process
        failure = OSError("fixture registration cleanup unknown")
        failure.add_note("policy_scope_cleanup_unverified")
        with patch("sentinel.adaptive.legacy_writer.register_infrastructure_locked", side_effect=failure):
            with self.assertRaises(cli.HelperHostRefused):
                host._register()
        operation = host._registration_operation
        self.assertIs(operation._error, failure)
        self.assertIsNotNone(operation._quarantine)
        with patch.object(host.store._policy, "prepare", side_effect=AssertionError("recreated quarantined guard")):
            with self.assertRaises(cli.HelperHostRefused):
                host._register()
        with self.assertRaisesRegex(cli.HelperHostRefused, "registration_pending"):
            host.close()


class HelperOperatorCliTests(unittest.TestCase):
    def arguments(self):
        return ["--data-dir", "explicit-fixture", "--instance-id", str(uuid4()),
            "--operator-instance-id", str(uuid4()), "--parent-instance-id", str(uuid4()),
            "--policy-instance-id", str(uuid4()), "--guardian-epoch", EPOCH,
            "--parent-pid", str(PARENT.pid), "--parent-created-filetime", str(PARENT.created_filetime_100ns),
            "--parent-logon-id", PARENT.logon_id, "--guardian-pid", str(GUARDIAN.pid),
            "--guardian-created-filetime", str(GUARDIAN.created_filetime_100ns),
            "--guardian-logon-id", GUARDIAN.logon_id, "--guardian-control-instance-id", str(uuid4())]

    def test_complete_cli_locator_preserves_exact_parent_and_guardian_identity(self):
        parsed = cli.build_parser().parse_args(self.arguments())
        values = module.operational_options(parsed)
        self.assertEqual(values["parent_identity"], PARENT)
        self.assertEqual(values["guardian_endpoint"].server_identity, GUARDIAN)
        self.assertEqual(values["operator_instance_id"], parsed.operator_instance_id)

    def test_partial_locator_refuses_without_creating_a_host(self):
        with patch.object(module, "OperationalHelperHost", side_effect=AssertionError("constructed incomplete host")):
            self.assertEqual(cli.main(["--data-dir", "explicit-fixture", "--instance-id", str(uuid4())]), cli.EXIT_REFUSED)

    def test_complete_cli_selects_shadow_operational_host_never_active_host(self):
        sentinel = object()
        with patch.object(module, "OperationalHelperHost", return_value=sentinel) as factory, \
                patch.object(module, "OperationalHelperControlHost", side_effect=AssertionError("active default")), \
                patch.object(module, "run_operational", return_value=0) as run:
            self.assertEqual(cli.main(self.arguments()), 0)
        self.assertEqual(factory.call_count, 1)
        self.assertEqual(run.call_args.args, (sentinel,))

    def test_startup_cleanup_failure_is_retained_instead_of_returning_clean_exit(self):
        failure, cleanup = OSError("fixture startup"), OSError("fixture cleanup")
        host = SimpleNamespace(start=lambda: (_ for _ in ()).throw(failure),
            close=lambda: (_ for _ in ()).throw(cleanup))
        with patch.object(module, "retain_cleanup", return_value="retained") as retained:
            self.assertEqual(module.run_operational(host), "retained")
        self.assertIs(host._startup_error, failure)
        self.assertIs(host._exit_failure, cleanup)
        self.assertIs(retained.call_args.args[0], host)


if __name__ == "__main__":
    unittest.main()
