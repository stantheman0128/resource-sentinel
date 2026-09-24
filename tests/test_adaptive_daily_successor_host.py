"""Fresh successor host custody over actual isolated retirement/succession SQL.

The generation/retirement/transfer, original binding and publication validators
are production code. Only native process/mutex/pipe effects use explicit fixture
owners; a portable thread runs the actual readiness publication boundary. These
tests provide no native activation, authentication or restart evidence.
"""
import copy
from dataclasses import replace
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_activation_host as activation
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor as successor
from sentinel.adaptive.daily_readiness_transport import DailyReadinessService, LedgerFileIdentity
from sentinel.adaptive.pipe_windows import NativePipeListener, _PipeOwner
from sentinel.adaptive.supervisor_host import SupervisorHost
from sentinel.adaptive.supervisor_startup import SupervisorStartup
from tests import test_adaptive_daily_cohort as cohort_fixture
from tests import test_adaptive_daily_activation_host as activation_fixture
from tests import test_adaptive_daily_successor as successor_fixture
from tests import test_adaptive_guardian_launch as process_fixture
from tests import test_adaptive_supervisor_startup as startup_fixture


class PipeBackend:
    """Explicit synthetic handle closure; no operating-system pipe API."""
    def __init__(self):
        self.closed = []
        self.error = None

    def close(self, handle):
        if self.error is not None:
            raise self.error
        self.closed.append(handle)


class DailySuccessorHostTests(unittest.TestCase):
    def setUp(self):
        # Real readiness/service and SupervisorStartup require the actual PID.
        # The process handle/identity observations still come from this explicit
        # synthetic backend, created with that identity from the beginning.
        current = patch.object(cohort_fixture, "SELF", replace(cohort_fixture.SELF, pid=os.getpid()))
        current.start()
        self.addCleanup(current.stop)
        self.fixture = successor_fixture.DailySuccessorTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.operation, self.retirement = self.fixture.operation, self.fixture.retirement
        self.store, self.backend = self.fixture.store, self.fixture.backend
        self.predecessor_host = self.retirement.host
        self.hosts, self.pipe_owners = [], []
        self.pipe_backend = PipeBackend()
        self.addCleanup(self.close_host_fixtures)

        # The older retirement fixture supplies an exact host via __new__ and
        # populates only its retirement fields. Supply missing orchestration
        # defaults without replacing any object pinned by original retirement.
        defaults = activation.DailyActivationHost(self.retirement.owner.manifest,
            self.retirement.owner._config_digest,
            LedgerFileIdentity(*self.retirement.owner.ledger_identity))
        for name, value in defaults.__dict__.items():
            self.predecessor_host.__dict__.setdefault(name, value)
        self.predecessor_host._start_attempted = True
        self.predecessor_host._supervisor_attempted = True
        self.predecessor_host._native_custody_possible = True
        self.predecessor_host._phase = "generation_retired"
        # The fixture initially migrated an isolated empty store. Production
        # activation constructs its same store with existing_path=True.
        self.store.existing_path = True
        self.store._existing_ledger_path = self.fixture.db

    def fresh_host(self):
        if not self.operation._complete:
            self.assertTrue(self.operation.tick())
        host = activation.DailyActivationHost.from_successor(self.operation)
        self.hosts.append(host)
        return host

    def _listener_init(self, listener, endpoint, registry=None):
        # Retain the actual concrete owner in the real bounded registry before
        # publishing its synthetic handle, matching the native ownership shape.
        self.assertIsNotNone(registry)
        host = self.operation._readiness_host
        self.assertIs(host._registry, registry)
        self.assertIs(host._successor_operation, self.operation)
        self.assertTrue(host._readiness_start_attempted)
        owner = object.__new__(_PipeOwner)
        owner.endpoint, owner._registry, owner._api = endpoint, registry, self.pipe_backend
        owner._server_end, owner._pid = True, os.getpid()
        owner._lock = threading.RLock()
        owner._busy = owner._poisoned = owner._handle_close_unknown = False
        owner._proofs = 0
        owner._handle = 7000 + len(self.pipe_owners)
        for name in ("_operation", "_active", "_server_process", "_self_process",
                     "_peer_process", "_accept_operation", "_accept_connection"):
            setattr(owner, name, None)
        owner._accept_stopped = False
        owner._accept_disconnect_entered = owner._accept_disconnected = False
        self.pipe_owners.append(owner)
        registry._retain(owner)
        listener.endpoint, listener._owner = endpoint, owner

    def configure_readiness(self, host):
        if host not in self.hosts:
            self.hosts.append(host)

        def initializer(listener, endpoint, registry=None):
            self._listener_init(listener, endpoint, registry)

        def serve(service, listener, *, timeout_ms):
            self.assertIs(service, host._service)
            self.assertIs(listener, host._listener)
            # This fixture does no protocol I/O. Keep the genuine serving
            # thread alive until its test's original stop event is signaled.
            host._readiness_stop.wait(.01)

        patches = (
            patch.object(NativePipeListener, "__init__", initializer),
            patch.object(DailyReadinessService, "serve_once", serve),
        )
        for replacement in patches:
            replacement.start()
            self.addCleanup(replacement.stop)
        # Stop the original serving thread before restoring its fixture I/O
        # methods; restoring first could cross an unintended native boundary.
        self.addCleanup(self.close_host_fixtures)

    def publish_host(self, host=None):
        """Reusable original published host for successor epoch fixtures."""
        host = self.fresh_host() if host is None else host
        self.configure_readiness(host)
        host._start_readiness()
        self.assertTrue(host._listener_ready.wait(1.0), host._readiness_failure)
        self.assertIsNone(host._readiness_failure)
        self.operation.assert_readiness_published(host.owner)
        return host

    def acquire_supervisor(self, host):
        """Actual startup lease with explicit synthetic current/mutex owners."""
        supervisor = SupervisorHost(data_dir=host.data_dir, journal_dir=host.journal_dir,
                                    child_cwd=host.source_root, telemetry_factory=lambda: None)
        host.supervisor, host._supervisor_attempted = supervisor, True
        supervisor._daily_successor_operation = self.operation
        self.operation.bind_supervisor(supervisor)
        supervisor.store, supervisor.journal = self.store, self.retirement.journal
        native = process_fixture.ProcessBackend()
        current = native.process(host.owner.process.identity)
        self.addCleanup(current.close)
        self.held, self.mutexes = {}, []

        def mutex_factory(logon, instance):
            mutex = startup_fixture.Mutex(self, logon, instance)
            self.mutexes.append(mutex)
            return mutex

        startup = SupervisorStartup(self.store, self.retirement.journal,
                                    current=current, mutex_factory=mutex_factory)
        supervisor.startup = startup
        startup._daily_successor_operation = self.operation
        startup._daily_successor_supervisor = supervisor
        def release_fixture_startup():
            # Fault cases deliberately retain unknown SQL/POLICY custody.
            # Keep the production refusal and all flags, while disposing only
            # these explicitly synthetic native collaborators after assertions.
            try:
                startup.close()
            except Exception:
                epoch = self.operation._guardian_epoch_operation
                pending = (self.operation._quarantine is not None or
                    any(not item.closed or item.close_unknown for item in self.operation._connections) or
                    epoch is not None and (epoch._quarantine is not None or epoch._policy_operation.pending))
                if not pending:
                    raise
                if startup._acquired and startup._scope is not None:
                    startup._scope.__exit__(None, None, None)
                if startup._mutex is not None:
                    startup._mutex.close()
                if startup._current is not None:
                    startup._current.close()

        self.addCleanup(release_fixture_startup)
        startup.acquire()
        self.operation.assert_supervisor(supervisor)
        return supervisor

    def close_host_fixtures(self):
        # Test teardown releases only synthetic handles, and does not set any
        # production completion/unknown flags to manufacture a positive result.
        for host in self.hosts:
            host._readiness_stop.set()
            if host._thread is not None and host._thread.ident is not None:
                host._thread.join(1.0)
                self.assertFalse(host._thread.is_alive())
        for owner in self.pipe_owners:
            owner._registry._forget(owner)

    def test_from_successor_retains_fresh_host_without_reusing_old_custody(self):
        old = self.predecessor_host
        pinned = (old.owner, old.store, old.supervisor, old._thread, old._listener,
                  old._registry, old._service, old._connections, old._retirement)
        with patch.object(activation, "NativePipeRegistry", side_effect=AssertionError("early pipe")), \
                patch.object(activation, "SupervisorHost", side_effect=AssertionError("early supervisor")):
            host = self.fresh_host()
        self.assertIs(self.operation._readiness_host, host)
        self.assertIs(host.owner, self.operation.owner)
        self.assertIs(host.store, self.store)
        self.assertIs(host.guard, self.operation.guard)
        self.assertIs(host._successor_operation, self.operation)
        self.assertEqual((old.owner, old.store, old.supervisor, old._thread, old._listener,
            old._registry, old._service, old._connections, old._retirement), pinned)
        self.assertIsNot(host._connections, old._connections)
        for name in ("_listener_ready", "_thread_stopped", "_readiness_stop"):
            self.assertIsNot(getattr(host, name), getattr(old, name))
            self.assertFalse(getattr(host, name).is_set())
        self.assertFalse(host._start_attempted)
        self.assertFalse(host._migration_attempted)
        self.assertFalse(host._install_attempted)
        self.assertFalse(host._draining)
        self.retirement.assert_successor_predecessor()

    def test_unacknowledged_copied_and_second_host_construction_refuse(self):
        with self.assertRaisesRegex(activation.DailyActivationError, "unacknowledged"):
            activation.DailyActivationHost.from_successor(self.operation)
        with self.assertRaises(successor.DailySuccessorError):
            activation.DailyActivationHost.from_successor(copy.copy(self.operation))
        host = self.fresh_host()
        with self.assertRaisesRegex(activation.DailyActivationError, "already_bound"):
            activation.DailyActivationHost.from_successor(self.operation)
        self.assertIs(self.operation._readiness_host, host)

    def test_request_successor_reuses_exact_registered_operation(self):
        host = self.predecessor_host
        self.assertIs(host.request_successor(), self.operation)
        self.assertIs(host.request_successor(), self.operation)
        self.assertFalse(host.chain_retirement_complete())
        self.assertTrue(host._retirement_complete())
        self.fixture.capture_mock.assert_not_called()

    def test_request_requires_positive_original_retirement(self):
        host = self.predecessor_host
        with patch.object(self.retirement, "_complete", False), \
                self.assertRaisesRegex(activation.DailyActivationError, "requires_retirement"):
            host.request_successor()
        with self.assertRaisesRegex(activation.DailyActivationError, "original_operation_required"):
            copy.copy(host).request_successor()
        self.fixture.capture_mock.assert_not_called()

    def test_substituted_operation_cannot_be_driven(self):
        old = self.predecessor_host
        old.request_successor()
        with patch.object(old, "_successor", copy.copy(self.operation)), \
                self.assertRaisesRegex(activation.DailyActivationError, "operation_changed"):
            old.run_once()
        self.fixture.capture_mock.assert_not_called()

    def test_fresh_host_binding_copy_and_path_substitution_refuse(self):
        host = self.fresh_host()
        with self.assertRaisesRegex(activation.DailyActivationError, "host_changed"):
            copy.copy(host).start()
        for name, value in (("store", object()), ("guard", object()),
                ("journal_dir", Path("changed")), ("manifest", copy.copy(host.manifest)),
                ("ledger_path", Path("changed")), ("expected_config_digest", "0" * 64)):
            with self.subTest(name=name), patch.object(host, name, value), \
                    self.assertRaisesRegex(activation.DailyActivationError, "host_changed"):
                host.start()
        self.assertFalse(host._start_attempted)

    def test_metadata_ack_and_listener_event_alone_do_not_publish_readiness(self):
        host = self.fresh_host()
        with self.assertRaisesRegex(successor.DailySuccessorError, "readiness_not_published"):
            host.owner.assert_ready()
        host._listener_ready.set()
        try:
            with self.assertRaisesRegex(successor.DailySuccessorError, "readiness_not_published"):
                host.owner.assert_ready()
        finally:
            host._listener_ready.clear()

    def test_actual_serving_thread_publishes_only_original_listener(self):
        host = self.publish_host()
        host.owner.assert_ready()
        self.assertIs(self.operation._readiness_pins[0], host._thread)
        self.assertIs(self.operation._readiness_pins[1], host._listener)
        self.assertEqual(host._registry.status().resources, 1)
        self.assertFalse(host._thread_stopped.is_set())
        self.retirement.assert_successor_predecessor()
        for name in ("_listener", "_service", "_registry", "_thread"):
            with self.subTest(name=name), patch.object(host, name, copy.copy(getattr(host, name))), \
                    self.assertRaises(successor.DailySuccessorError):
                host.owner.assert_ready()

    def test_successor_start_skips_cold_install_and_binds_supervisor_before_start(self):
        host = self.fresh_host()
        self.configure_readiness(host)
        native_start = []

        def start_supervisor(supervisor):
            self.assertIs(host.supervisor, supervisor)
            self.assertIs(supervisor._daily_successor_operation, self.operation)
            native_start.append(supervisor)
            raise RuntimeError("fixture fresh supervisor boundary")

        with patch.object(activation, "_MODULE_ROOT", host.source_root), \
                patch.object(activation, "_BASE_PYTHON", Path(sys.executable)), \
                patch.object(activation, "read_host_capability"), \
                patch.object(host, "_migrate_once", side_effect=AssertionError("cold migration")), \
                patch.object(host, "_install_once", side_effect=AssertionError("cold installation")), \
                patch.object(SupervisorHost, "start", start_supervisor), \
                patch.object(SupervisorHost, "begin_drain"), \
                patch.object(SupervisorHost, "request_local_drain"), \
                self.assertRaisesRegex(RuntimeError, "fresh supervisor boundary"):
            host.start()
        self.assertEqual(len(native_start), 1)
        self.assertIs(host.supervisor, native_start[0])
        self.assertFalse(host._migration_attempted)
        self.assertFalse(host._install_attempted)
        self.fixture.capture_mock.assert_called_once()

    def test_listener_factory_failure_retains_partial_owner_and_never_retries(self):
        host = self.fresh_host()
        original = self._listener_init

        def interrupted(listener, endpoint, registry=None):
            original(listener, endpoint, registry)
            raise KeyboardInterrupt("fixture listener return interrupted")

        with patch.object(NativePipeListener, "__init__", interrupted):
            host._start_readiness()
            self.assertTrue(host._thread_stopped.wait(1.0))
        self.assertIsInstance(host._readiness_failure, KeyboardInterrupt)
        self.assertFalse(host._listener_ready.is_set())
        self.assertEqual(host._registry.status().resources, 1)
        self.assertIs(host._registry._resources[id(self.pipe_owners[0])], self.pipe_owners[0])
        with self.assertRaisesRegex(activation.DailyActivationError, "already_attempted"):
            host._start_readiness()
        with self.assertRaises(successor.DailySuccessorError):
            host.owner.assert_ready()

    def test_thread_start_unknown_retains_original_thread_without_replacement(self):
        host = self.fresh_host()
        error = KeyboardInterrupt("fixture thread start uncertain")
        with patch.object(threading.Thread, "start", side_effect=error), self.assertRaises(KeyboardInterrupt):
            host._start_readiness()
        self.assertIs(host._thread, host._readiness_original_thread)
        self.assertIsNotNone(host._service)
        self.assertTrue(host._readiness_start_attempted)
        with self.assertRaisesRegex(activation.DailyActivationError, "already_attempted"):
            host._start_readiness()
        self.assertFalse(host._listener_ready.is_set())

    def test_publication_error_keeps_listener_and_ready_false(self):
        host = self.fresh_host()
        error = RuntimeError("fixture publication interrupted")
        def initializer(listener, endpoint, registry=None):
            self._listener_init(listener, endpoint, registry)
        with patch.object(NativePipeListener, "__init__", initializer), \
                patch.object(self.operation, "publish_readiness_listener", side_effect=error):
            host._start_readiness()
            self.assertTrue(host._thread_stopped.wait(1.0))
        self.assertIs(host._readiness_failure, error)
        self.assertIs(host._listener, host._readiness_original_listener)
        self.assertEqual(host._registry.status().resources, 1)
        self.assertFalse(host._listener_ready.is_set())

    def test_stopped_serving_thread_and_unknown_native_close_block_readiness(self):
        host = self.publish_host()
        host._readiness_stop.set()
        host._thread.join(1.0)
        self.assertFalse(host._thread.is_alive())
        self.pipe_backend.error = RuntimeError("fixture unknown listener close")
        with self.assertRaisesRegex(RuntimeError, "unknown listener close"):
            host._listener.close()
        self.assertTrue(host._listener._owner._handle_close_unknown)
        self.assertEqual(host._registry.status().quarantined, 1)
        with self.assertRaises(successor.DailySuccessorError):
            host.owner.assert_ready()

    def test_original_driver_retains_same_host_after_start_interruption(self):
        old = self.predecessor_host
        old.request_successor()
        error = KeyboardInterrupt("fixture capability interrupted")
        with patch.object(activation.DailyActivationHost, "_assert_prepared_binding"), \
                patch.object(activation, "read_host_capability", side_effect=error), \
                self.assertRaises(KeyboardInterrupt):
            old.run_once()
        host = old._successor_host
        self.hosts.append(host)
        self.assertIs(host, self.operation._readiness_host)
        self.assertIs(host._failure, error)
        self.assertTrue(host._start_attempted)
        old.run_once()
        self.assertIs(old._successor_host, host)
        self.assertFalse(old.chain_retirement_complete())
        self.assertTrue(old._retirement_complete())
        self.fixture.capture_mock.assert_called_once()

    def test_predecessor_run_forever_cannot_exit_while_successor_is_pending(self):
        old = self.predecessor_host
        old.request_successor()
        calls = []

        def tick(previous):
            calls.append(previous)
            if len(calls) == 2:
                raise RuntimeError("fixture end resident loop")
            return {"fixture": "pending"}

        with patch.object(old, "_retained_tick", side_effect=tick), \
                self.assertRaisesRegex(RuntimeError, "end resident loop"):
            old.run_forever()
        self.assertEqual(len(calls), 2)
        self.assertFalse(old.status()["clean_exit_allowed"])

    def test_explicit_post_request_drain_prevents_late_native_start(self):
        old = self.predecessor_host
        old.request_successor()
        old.request_drain()
        with patch.object(activation, "read_host_capability", side_effect=AssertionError("late native start")), \
                self.assertRaisesRegex(activation.DailyActivationError, "successor_draining"):
            old.run_once()
        self.hosts.append(old._successor_host)
        self.assertTrue(old._successor_host._draining)
        self.assertIsNone(old._successor_host._registry)
        self.assertFalse(old.chain_retirement_complete())

    def test_chain_detects_substituted_registered_host(self):
        old = self.predecessor_host
        old.request_successor()
        host = self.fresh_host()
        old._successor_host = host
        with patch.object(old, "_successor_host", copy.copy(host)), \
                self.assertRaisesRegex(activation.DailyActivationError, "host_changed"):
            old.chain_retirement_complete()

    def test_actual_new_supervisor_startup_uses_new_lifetime_owners(self):
        host = self.publish_host()
        supervisor = self.acquire_supervisor(host)
        self.assertIsNot(supervisor, self.predecessor_host.supervisor)
        self.assertIsNot(supervisor.startup, self.predecessor_host.supervisor.startup)
        self.assertIs(supervisor.store, self.retirement.store)
        self.assertIs(supervisor.journal, self.retirement.journal)
        supervisor.startup.assert_held()
        self.retirement.assert_successor_predecessor()
        self.operation.assert_supervisor(supervisor)

    def test_restart_intent_requires_exact_boolean_and_retirement_intent(self):
        arguments = (self.retirement.owner.manifest, self.retirement.owner._config_digest,
                     LedgerFileIdentity(*self.retirement.owner.ledger_identity))
        for retire, restart in ((False, True), (True, 1), (True, None)):
            with self.subTest(retire=retire, restart=restart), \
                    self.assertRaisesRegex(activation.DailyActivationError, "successor_intent_invalid"):
                activation.DailyActivationHost(*arguments, retire_after_drain=retire,
                                              restart_after_retirement=restart)
        host = activation.DailyActivationHost(*arguments, retire_after_drain=True,
                                             restart_after_retirement=True)
        self.assertTrue(host._restart_after_retirement)

    def test_explicit_automatic_intent_requests_one_successor_without_renewal(self):
        old = self.predecessor_host
        old._retire_after_drain = old._restart_after_retirement = True
        self.assertFalse(old.chain_retirement_complete())
        calls = []
        def retain_only(host):
            calls.append(host)
            host._start_attempted = True
        with patch.object(activation.DailyActivationHost, "_start_successor", retain_only), \
                patch.object(activation.DailyActivationHost, "_assert_prepared_binding"):
            old.run_once()
            new = old._successor_host
            self.hosts.append(new)
            # Hold this fixture before serving; a later tick may observe only
            # its retained host, never manufacture another generation/host.
            new._failure = RuntimeError("fixture held before listener")
            old.run_once()
        self.assertEqual(calls, [new])
        self.assertIs(old._successor, self.operation)
        self.assertFalse(new._retire_after_drain)
        self.assertFalse(new._restart_after_retirement)
        self.fixture.capture_mock.assert_called_once()

    def test_interrupt_before_automatic_request_latches_no_late_start(self):
        old = self.predecessor_host
        old._retire_after_drain = old._restart_after_retirement = True
        old._retain_interruption(KeyboardInterrupt())
        self.assertTrue(old._successor_drain_requested)
        with patch.object(activation, "read_host_capability", side_effect=AssertionError("late start")), \
                self.assertRaisesRegex(activation.DailyActivationError, "successor_draining"):
            old.run_once()
        self.hosts.append(old._successor_host)
        self.assertIsNone(old._successor_host._thread)
        self.assertFalse(old.chain_retirement_complete())

    def test_predecessor_freeze_drain_does_not_cancel_explicit_restart_intent(self):
        fixture = activation_fixture.DailyActivationHostTests()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        operation = fixture.retirement_fixture(sealed=False, stopped=False)
        fixture.host._restart_after_retirement = True
        operation.freeze_acknowledged = True
        fixture.host._tick_retirement()
        self.assertTrue(fixture.host._draining)
        self.assertFalse(fixture.host._successor_drain_requested)
        self.assertFalse(fixture.host._successor_creation_attempted)


if __name__ == "__main__":
    unittest.main()
