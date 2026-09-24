"""Isolated SQL and synthetic native-owner assembly; no activation evidence."""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import daily_activation_host as activation
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.capacity_schema import prepare_capacity_schema
from sentinel.adaptive.daily_cohort import CohortUnavailable
from sentinel.adaptive.daily_readiness_transport import DailyReadinessError, LedgerFileIdentity


DIGEST = "a" * 64
MANIFEST = generation.SourceManifest(tuple(generation.SourceEntry(name, DIGEST, 0)
                                         for name in sorted(generation.REQUIRED_PATHS)))


class Connection:
    """Explicit completed-SQL fixture; real SQLite migration is tested below."""
    def __init__(self, name, events):
        self.name, self.events = name, events
        self.close_error = self.commit_error = None
        self.closed = False

    def execute(self, sql):
        self.events.append((self.name, sql))

    def commit(self):
        self.events.append((self.name, "commit"))
        if self.commit_error is not None:
            raise self.commit_error

    def close(self):
        self.events.append((self.name, "close"))
        if self.close_error is not None:
            raise self.close_error
        self.closed = True


class Policy:
    def __init__(self, events):
        self.events = events
        self.guard = object()
        self.exit_error = None

    def prepare(self, logon):
        self.events.append("policy_prepare")
        return self.guard

    @contextmanager
    def hold(self, guard):
        if guard is not self.guard:
            raise AssertionError("changed guard")
        self.events.append("policy_enter")
        yield guard
        self.events.append("policy_exit")
        if self.exit_error is not None:
            raise self.exit_error


class Owner:
    def __init__(self, events):
        self.events = events
        self._activated = False
        self.process = SimpleNamespace(identity=SimpleNamespace(logon_id="S-1-5-5-1-2"))
        self.cohort = Mock(spec=["assert_retired", "assert_retained_retired", "close"])
        self.readiness_endpoint = object()
        self.close_unactivated = Mock()
        self._install_connection = None

    def prepare_install(self, **_):
        self.events.append("owner_prepare")

    def install_locked(self, connection, **_):
        self.events.append("owner_install")
        self._install_connection = connection

    def settle_install_connection(self):
        self.events.append("owner_settle")
        self._install_connection.close()

    def acknowledge_install(self, *, conn):
        self.events.append("owner_ack")
        if not self._install_connection.closed:
            raise AssertionError("ACK before original connection close")
        self._activated = True

    def assert_ready(self):
        self.events.append("owner_ready")
        if not self._activated:
            raise DailyReadinessError("daily_generation_not_activated")


class Retirement:
    """Explicit synthetic operation; this is never a production seal receipt."""
    def __init__(self, host):
        self.host = host
        self.freeze_acknowledged = self.sealed = self.complete = False
        self.phase, self.reason = "freeze_pending", None
        self.tick_calls = self.close_calls = 0
        self.on_tick = self.close_error = None

    def tick(self):
        self.tick_calls += 1
        if self.on_tick is not None:
            self.on_tick()

    def close_owner(self):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error
        if not self.host._readiness_cleanup_complete:
            raise AssertionError("owner closed before keeper cleanup")
        self.complete, self.phase = True, "retired_admission_fenced"


class DailyActivationHostTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.db = self.data / "sentinel.db"
        connection = sqlite3.connect(self.db)
        connection.execute("BEGIN IMMEDIATE")
        prepare_capacity_schema(connection)
        connection.execute("CREATE TABLE queue(id TEXT)")
        connection.execute("CREATE TABLE preserved_exemption(id TEXT)")
        connection.execute("INSERT INTO preserved_exemption VALUES('unchanged')")
        connection.commit()
        connection.close()
        self.ledger = LedgerFileIdentity.capture(self.db)
        location = patch.object(generation, "daily_locations", return_value=(self.root, self.data))
        location.start()
        self.addCleanup(location.stop)
        self.host = activation.DailyActivationHost(MANIFEST, DIGEST, self.ledger)
        self.events = []
        self.owner = Owner(self.events)
        self.host.owner = self.owner
        self.addCleanup(self._close_test_connections)

    def _close_test_connections(self):
        for custody in self.host._connections:
            if isinstance(custody.connection, sqlite3.Connection):
                custody.connection.close()

    def scalar(self, query):
        connection = sqlite3.connect(self.db)
        try:
            result = connection.execute(query).fetchone()
            return None if result is None else result[0]
        finally:
            connection.close()

    def execute(self, sql):
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(sql)
            connection.commit()
        finally:
            connection.close()

    def install_fixture(self, *, exit_error=None, commit_error=None, ack_close_error=None):
        policy = Policy(self.events)
        policy.exit_error = exit_error
        writer = Connection("install", self.events)
        writer.commit_error = commit_error
        ack = Connection("ack", self.events)
        ack.close_error = ack_close_error
        writer_custody, ack_custody = activation._ConnectionCustody(writer), activation._ConnectionCustody(ack)
        self.host._connections.extend((writer_custody, ack_custody))
        stack = (
            patch.object(activation, "LifecycleStore", return_value=SimpleNamespace(_policy=policy)),
            patch.object(self.host, "_open", side_effect=[writer_custody, ack_custody]),
        )
        return policy, writer_custody, ack_custody, stack

    def start_fixture(self, readiness=None):
        def start_readiness():
            self.events.append("readiness_started")
            self.host._listener_ready.set()
        def install():
            self.events.append("generation_installed")
            self.owner._activated = True
            self.host._generation_settled = True
        self.supervisor = Mock()
        self.supervisor._custody_snapshot.return_value = {"settled": False}
        self.supervisor.start.side_effect = lambda: self.events.append("supervisor_start")
        replacements = (
            patch.object(activation, "_PRELOAD", ()),
            patch.object(self.host, "_assert_prepared_binding"),
            patch.object(activation, "read_host_capability"),
            patch.object(generation.DailyGenerationOwner, "capture", return_value=self.owner),
            patch.object(self.host, "_migrate_once", side_effect=lambda: self.events.append("migrated")),
            patch.object(self.host, "_install_once", side_effect=install),
            patch.object(self.host, "_start_readiness", side_effect=start_readiness if readiness is None else readiness),
            patch.object(self.host._listener_ready, "wait"),
            patch.object(activation, "SupervisorHost", return_value=self.supervisor),
        )
        for replacement in replacements:
            replacement.start()
            self.addCleanup(replacement.stop)

    def retirement_fixture(self, *, sealed=True, stopped=True):
        from sentinel.adaptive import daily_retirement
        replacement = patch.object(daily_retirement, "DailyRetirementOperation", Retirement)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.host._start_attempted = self.host._supervisor_attempted = True
        self.host._generation_settled = True
        if self.host.supervisor is None:
            self.host.supervisor = Mock()
            self.host.supervisor._custody_snapshot.return_value = {"settled": False}
        self.host._thread = self.host._readiness_original_thread = Mock()
        self.host._thread.is_alive.return_value = False
        self.host._listener = self.host._readiness_original_listener = Mock()
        self.host._registry = self.host._readiness_original_registry = Mock()
        self.host._registry.status.return_value = SimpleNamespace(resources=0, pending=0, quarantined=0)
        self.host._listener_ready.set()
        if stopped:
            self.host._thread_stopped.set()
        operation = self.host.request_retirement()
        operation.freeze_acknowledged = operation.sealed = sealed
        return operation

    def test_constructor_rejects_bare_manifest_or_ledger_boolean(self):
        with self.assertRaises(activation.DailyActivationError):
            activation.DailyActivationHost({}, DIGEST, self.ledger)
        with self.assertRaises(activation.DailyActivationError):
            activation.DailyActivationHost(MANIFEST, DIGEST, True)

    def test_constructor_uses_only_canonical_daily_locations(self):
        self.assertEqual(self.host.ledger_path, self.db)
        self.assertEqual(self.host.journal_dir, self.data / "adaptive-journal")

    def test_changed_config_refuses_before_capture(self):
        with patch.object(activation, "_MODULE_ROOT", self.root), \
                patch.object(activation, "_BASE_PYTHON", Path(sys.executable)), \
                patch.object(generation, "_fixed_policy_digest", return_value="b" * 64), \
                self.assertRaisesRegex(activation.DailyActivationError, "config_binding_changed"):
            self.host._assert_prepared_binding()

    def test_changed_file_identity_refuses_before_config_or_source(self):
        self.host.expected_ledger_identity = LedgerFileIdentity(1, 2)
        with patch.object(activation, "_MODULE_ROOT", self.root), \
                patch.object(activation, "_BASE_PYTHON", Path(sys.executable)), \
                patch.object(generation, "_fixed_policy_digest") as config, \
                self.assertRaisesRegex(activation.DailyActivationError, "ledger_binding_changed"):
            self.host._assert_prepared_binding()
        config.assert_not_called()

    def test_wrong_installed_source_refuses(self):
        with self.assertRaisesRegex(activation.DailyActivationError, "installed_source_required"):
            self.host._assert_prepared_binding()

    def test_wrong_base_interpreter_refuses(self):
        with patch.object(activation, "_MODULE_ROOT", self.root), \
                patch.object(activation, "_BASE_PYTHON", self.root / "different.exe"), \
                self.assertRaisesRegex(activation.DailyActivationError, "base_python_required"):
            self.host._assert_prepared_binding()

    def test_explicit_additive_migration_stays_off_preserves_other_tables(self):
        with patch.object(self.host, "_assert_prepared_binding"):
            self.host._migrate_once()
        self.owner.cohort.assert_retired.assert_called_once_with()
        self.assertEqual(self.scalar("SELECT mode FROM adaptive_runtime"), "off")
        self.assertEqual(self.scalar("SELECT id FROM preserved_exemption"), "unchanged")
        self.assertTrue(all(item.closed for item in self.host._connections))
        self.assertFalse(self.owner._activated)

    def test_live_queue_blocks_migration_without_deleting_it(self):
        self.execute("INSERT INTO queue VALUES('waiting')")
        with patch.object(self.host, "_assert_prepared_binding"), \
                self.assertRaisesRegex(activation.DailyActivationError, "allocations_not_empty"):
            self.host._migrate_once()
        self.assertEqual(self.scalar("SELECT id FROM queue"), "waiting")
        self.assertIsNone(self.scalar("SELECT name FROM sqlite_master WHERE name='adaptive_runtime'"))
        self.assertFalse(self.host._migration_attempted)

    def test_even_empty_generation_table_forbids_cold_adoption(self):
        self.execute("CREATE TABLE adaptive_daily_generation(generation TEXT)")
        with patch.object(self.host, "_assert_prepared_binding"), \
                self.assertRaisesRegex(activation.DailyActivationError, "existing_generation"):
            self.host._migrate_once()

    def test_cohort_not_retired_prevents_any_sql_open(self):
        self.owner.cohort.assert_retired.side_effect = RuntimeError("synthetic old cohort alive")
        with patch.object(self.host, "_assert_prepared_binding"), \
                patch.object(self.host, "_open") as opened, self.assertRaises(RuntimeError):
            self.host._migrate_once()
        opened.assert_not_called()

    def test_preexisting_control_mode_blocks_migration(self):
        self.execute("CREATE TABLE adaptive_runtime(mode TEXT, admission_barrier TEXT)")
        self.execute("INSERT INTO adaptive_runtime VALUES('canary','NONE')")
        with patch.object(self.host, "_assert_prepared_binding"), \
                self.assertRaisesRegex(activation.DailyActivationError, "empty_off"):
            self.host._migrate_once()

    def test_migration_is_not_replayed(self):
        with patch.object(self.host, "_assert_prepared_binding"):
            self.host._migrate_once()
            with self.assertRaisesRegex(activation.DailyActivationError, "already_attempted"):
                self.host._migrate_once()

    def test_install_ack_follows_original_commit_policy_and_connection_cleanup(self):
        policy, writer, ack, replacements = self.install_fixture()
        with replacements[0], replacements[1]:
            self.host._install_once()
        self.assertIs(self.host.guard, policy.guard)
        self.assertEqual(self.events, ["policy_prepare", "policy_enter", "owner_prepare",
            ("install", "BEGIN IMMEDIATE"), "owner_install", ("install", "commit"),
            "policy_exit", "owner_settle", ("install", "close"), "owner_ack", ("ack", "close")])
        self.assertTrue(writer.closed)
        self.assertTrue(ack.closed)
        self.assertTrue(self.host._generation_settled)

    def test_unknown_commit_never_acknowledges_or_discards_original_connection(self):
        error = sqlite3.OperationalError("synthetic lost commit observation")
        policy, writer, ack, replacements = self.install_fixture(commit_error=error)
        with replacements[0], replacements[1], self.assertRaises(sqlite3.OperationalError):
            self.host._install_once()
        self.assertIs(self.host.guard, policy.guard)
        self.assertIs(self.owner._install_connection, writer.connection)
        self.assertFalse(writer.closed)
        self.assertNotIn("owner_ack", self.events)
        self.assertFalse(self.host._generation_settled)

    def test_policy_cleanup_failure_keeps_guard_and_no_ready_ack(self):
        policy, writer, ack, replacements = self.install_fixture(exit_error=RuntimeError("cleanup"))
        with replacements[0], replacements[1], self.assertRaises(RuntimeError):
            self.host._install_once()
        self.assertIs(self.host.guard, policy.guard)
        self.assertFalse(writer.closed)
        self.assertNotIn("owner_ack", self.events)

    def test_ack_connection_close_unknown_prevents_host_readiness(self):
        policy, writer, ack, replacements = self.install_fixture(ack_close_error=RuntimeError("cleanup"))
        with replacements[0], replacements[1], self.assertRaises(RuntimeError):
            self.host._install_once()
        self.assertTrue(self.owner._activated)
        self.assertTrue(ack.close_unknown)
        self.assertFalse(self.host._generation_settled)
        self.assertFalse(self.host.status()["generation_activation_acknowledged"])

    def test_unknown_connection_close_is_not_retried(self):
        connection = Connection("unknown", self.events)
        connection.close_error = RuntimeError("cleanup")
        owner = activation._ConnectionCustody(connection)
        with self.assertRaises(RuntimeError):
            owner.close()
        with self.assertRaisesRegex(activation.DailyActivationError, "close_unknown"):
            owner.close()
        self.assertEqual(self.events, [("unknown", "close")])

    def test_readiness_starts_before_any_supervisor_child_start(self):
        self.start_fixture()
        self.host.start()
        self.assertEqual(self.events, ["migrated", "generation_installed", "readiness_started", "supervisor_start"])
        self.assertFalse(self.host.status()["clean_exit_allowed"])

    def test_late_listener_does_not_duplicate_thread_or_start_children_early(self):
        self.start_fixture(readiness=lambda: self.events.append("readiness_pending"))
        self.host.start()
        self.supervisor.start.assert_not_called()
        self.host._listener_ready.set()
        self.host.run_once()
        self.host.run_once()
        self.supervisor.start.assert_called_once_with()

    def test_start_is_not_replayed(self):
        self.start_fixture()
        self.host.start()
        with self.assertRaisesRegex(activation.DailyActivationError, "already_attempted"):
            self.host.start()
        self.supervisor.start.assert_called_once_with()

    def test_supervisor_start_failure_keeps_same_recovery_owner(self):
        self.start_fixture()
        failure = RuntimeError("synthetic startup uncertainty")
        self.supervisor.start.side_effect = failure
        with self.assertRaises(RuntimeError):
            self.host.start()
        self.assertIs(self.host.supervisor, self.supervisor)
        self.assertIs(self.host._failure, failure)
        self.host.run_once()
        self.supervisor.run_once.assert_called_once_with()
        self.supervisor.start.assert_called_once_with()
        self.owner.close_unactivated.assert_not_called()

    def test_completed_supervisor_drain_leaves_generation_keeper_resident(self):
        self.start_fixture()
        self.host.start()
        self.supervisor._custody_snapshot.return_value = {"settled": True}
        self.supervisor.close.return_value = {"cleanup_errors": [], "guardian_left_running": False}
        self.host.request_drain()
        result = self.host.run_once()
        self.assertEqual(result["phase"], "generation_keeper_resident")
        self.assertEqual(result["reason"], "daily_generation_retirement_required")
        self.assertFalse(result["clean_exit_allowed"])
        self.assertTrue(self.owner._activated)
        self.owner.close_unactivated.assert_not_called()
        self.host.run_once()
        self.supervisor.close.assert_called_once_with()

    def test_drain_request_failure_does_not_starve_independent_recovery_tick(self):
        self.start_fixture()
        self.host.start()
        before = self.supervisor.run_once.call_count
        self.supervisor.request_local_drain.side_effect = RuntimeError("synthetic contention")
        self.host.request_drain()
        self.host.run_once()
        self.assertEqual(self.supervisor.run_once.call_count, before + 1)
        self.assertIsNotNone(self.host._failure)

    def test_readiness_thread_failure_drains_supervisor_but_retains_owner(self):
        self.start_fixture()
        self.host.start()
        self.host._readiness_failure = DailyReadinessError("pipe_peer_close_failed")
        self.host._thread_stopped.set()
        self.host.run_once()
        self.supervisor.request_local_drain.assert_called()
        self.assertTrue(self.owner._activated)
        self.owner.close_unactivated.assert_not_called()

    def test_readiness_is_one_non_daemon_thread_and_one_private_registry(self):
        self.owner._activated = True
        registry, service, thread = Mock(), Mock(), Mock()
        with patch.object(activation, "NativePipeRegistry", return_value=registry) as registry_class, \
                patch.object(activation, "DailyReadinessService", return_value=service) as service_class, \
                patch.object(activation.threading, "Thread", return_value=thread) as thread_class:
            self.host._start_readiness()
        registry_class.assert_called_once_with(max_resources=1)
        service_class.assert_called_once_with(self.owner.readiness_endpoint, self.owner)
        self.assertIs(thread_class.call_args.kwargs["daemon"], False)
        thread.start.assert_called_once_with()
        self.assertIs(self.host._registry, registry)

    def test_completed_timeout_keeps_original_listener_without_cleanup(self):
        self.host._registry = Mock()
        self.host._registry.status.return_value = SimpleNamespace(resources=1, pending=0, quarantined=0)
        self.host._service = Mock()
        self.host._service.serve_once.side_effect = [DailyReadinessError("pipe_timeout"), KeyboardInterrupt()]
        listener = Mock()
        with patch.object(activation, "NativePipeListener", return_value=listener):
            self.host._serve_readiness()
        self.assertEqual(self.host._service.serve_once.call_count, 2)
        self.assertIs(self.host._listener, listener)
        listener.close.assert_not_called()
        self.assertTrue(self.host._thread_stopped.is_set())

    def test_unknown_pipe_cleanup_stops_new_accept_but_keeps_exact_listener(self):
        self.host._registry = Mock()
        self.host._registry.status.return_value = SimpleNamespace(resources=1, pending=1, quarantined=1)
        self.host._service = Mock()
        failure = DailyReadinessError("pipe_cancel_unsettled")
        self.host._service.serve_once.side_effect = failure
        listener = Mock()
        with patch.object(activation, "NativePipeListener", return_value=listener):
            self.host._serve_readiness()
        self.host._service.serve_once.assert_called_once_with(listener, timeout_ms=1000)
        self.assertIs(self.host._readiness_failure, failure)
        self.assertIs(self.host._listener, listener)
        listener.close.assert_not_called()

    def test_readiness_listener_construction_uncertainty_retains_failure(self):
        self.host._registry = Mock()
        failure = RuntimeError("synthetic listener creation uncertainty")
        with patch.object(activation, "NativePipeListener", side_effect=failure):
            self.host._serve_readiness()
        self.assertIs(self.host._readiness_failure, failure)
        self.assertIs(failure.daily_activation_host, self.host)
        self.assertTrue(self.host._thread_stopped.is_set())

    def test_run_once_before_start_refuses(self):
        with self.assertRaisesRegex(activation.DailyActivationError, "not_started"):
            self.host.run_once()

    def test_known_live_cohort_then_retirement_resumes_same_owner_once(self):
        original_migrate = self.host._migrate_once
        self.start_fixture()
        self.host._migrate_once.side_effect = original_migrate
        live = CohortUnavailable("cohort_ambiguous_consumers_still_alive", self.owner.cohort)
        self.owner.cohort.assert_retired.side_effect = [live, None]
        waiting = self.host.start()
        self.assertEqual(waiting["phase"], "waiting_for_old_cohort")
        self.assertEqual(self.host._connections, [])
        self.assertIsNone(self.host._failure)
        self.host._install_once.assert_not_called()
        self.supervisor.start.assert_not_called()
        original_owner = self.host.owner
        self.host.run_once()
        self.host.run_once()
        self.assertIs(self.host.owner, original_owner)
        generation.DailyGenerationOwner.capture.assert_called_once()
        self.assertEqual(self.owner.cohort.assert_retired.call_count, 2)
        self.assertEqual(self.host._assert_prepared_binding.call_count, 3)
        self.assertEqual(self.host._migrate_once.call_count, 2)
        self.host._install_once.assert_called_once_with()
        self.supervisor.start.assert_called_once_with()
        self.assertEqual(self.scalar("SELECT mode FROM adaptive_runtime"), "off")

    def test_repeated_known_live_cohort_checks_once_per_tick_without_sql(self):
        original_migrate = self.host._migrate_once
        self.start_fixture()
        self.host._migrate_once.side_effect = original_migrate
        self.owner.cohort.assert_retired.side_effect = CohortUnavailable(
            "cohort_ambiguous_consumers_still_alive", self.owner.cohort)
        self.host.start()
        for _ in range(3):
            self.assertEqual(self.host.run_once()["phase"], "waiting_for_old_cohort")
        self.assertEqual(self.owner.cohort.assert_retired.call_count, 4)
        generation.DailyGenerationOwner.capture.assert_called_once()
        self.assertEqual(self.host._connections, [])
        self.host._install_once.assert_not_called()

    def test_unknown_cohort_identity_does_not_enter_retryable_wait(self):
        self.start_fixture()
        error = CohortUnavailable("cohort_retirement_unknown", self.owner.cohort)
        self.host._migrate_once.side_effect = error
        with self.assertRaises(CohortUnavailable):
            self.host.start()
        self.host.run_once()
        self.assertIs(self.host._failure, error)
        self.assertFalse(self.host._waiting_for_cohort)
        self.host._migrate_once.assert_called_once_with()
        generation.DailyGenerationOwner.capture.assert_called_once()

    def test_unknown_sql_outcome_never_replays_migration_or_recaptures_owner(self):
        self.start_fixture()
        error = sqlite3.OperationalError("synthetic commit outcome unknown")
        connection = Connection("uncertain migration", self.events)
        custody = activation._ConnectionCustody(connection)
        def uncertain():
            self.host._migration_attempted = True
            self.host._connections.append(custody)
            raise error
        self.host._migrate_once.side_effect = uncertain
        with self.assertRaises(sqlite3.OperationalError):
            self.host.start()
        for _ in range(3):
            self.host.run_once()
        self.assertIs(self.host._failure, error)
        self.assertIs(self.host._connections[0], custody)
        self.assertFalse(custody.closed)
        self.host._migrate_once.assert_called_once_with()
        generation.DailyGenerationOwner.capture.assert_called_once()
        self.host._install_once.assert_not_called()

    def test_live_refusal_after_possible_mutation_is_not_retryable(self):
        self.start_fixture()
        self.host._migration_attempted = True
        self.host._migrate_once.side_effect = CohortUnavailable(
            "cohort_ambiguous_consumers_still_alive", self.owner.cohort)
        with self.assertRaises(CohortUnavailable):
            self.host.start()
        self.host.run_once()
        self.assertFalse(self.host._waiting_for_cohort)
        self.host._migrate_once.assert_called_once_with()

    def test_waiting_cohort_cannot_be_replaced(self):
        self.start_fixture()
        self.host._migrate_once.side_effect = CohortUnavailable(
            "cohort_ambiguous_consumers_still_alive", self.owner.cohort)
        self.host.start()
        self.owner.cohort = Mock(spec=["assert_retired", "assert_retained_retired", "close"])
        with self.assertRaisesRegex(activation.DailyActivationError, "wait_owner_changed"):
            self.host.run_once()
        self.host._migrate_once.assert_called_once_with()
        self.owner.cohort.assert_retired.assert_not_called()

    def test_drain_during_known_cohort_wait_prevents_later_activation(self):
        self.start_fixture()
        self.host._migrate_once.side_effect = CohortUnavailable(
            "cohort_ambiguous_consumers_still_alive", self.owner.cohort)
        self.host.start()
        self.host.request_drain()
        self.host.run_once()
        self.host._migrate_once.assert_called_once_with()
        self.host._install_once.assert_not_called()
        self.supervisor.start.assert_not_called()

    def test_supervisor_cold_recovery_is_reported_until_actual_progress(self):
        self.start_fixture()
        self.supervisor.start.side_effect = None
        self.supervisor.start.return_value = {"state": "COLD_RECOVERY_HOLD", "reason": "policy_scope_busy"}
        self.supervisor.cold_reason = "policy_scope_busy"
        self.supervisor.run_once.return_value = {"state": "COLD_RECOVERY_HOLD", "reason": "policy_scope_busy"}
        result = self.host.start()
        self.assertEqual(result["phase"], "supervisor_cold_recovery_hold")
        self.assertEqual(result["supervisor_state"], "supervisor_cold_recovery_hold")
        self.assertEqual(result["reason"], "policy_scope_busy")
        self.supervisor.cold_reason = None
        self.supervisor.run_once.return_value = {"attached": True}
        result = self.host.run_once()
        self.assertEqual(result["phase"], "resident")
        self.assertIsNone(result["reason"])

    def test_resident_loop_keeps_original_recovery_after_baseexception(self):
        for interruption in (SystemExit(7), GeneratorExit()):
            with self.subTest(interruption=type(interruption).__name__):
                host = activation.DailyActivationHost(MANIFEST, DIGEST, self.ledger)
                host.owner = self.owner
                host._start_attempted = host._supervisor_attempted = True
                supervisor = host.supervisor = Mock()
                supervisor._custody_snapshot.return_value = {"settled": False}
                supervisor.run_once.side_effect = [interruption, {"attached": True}]
                with patch.object(activation, "emit", return_value=True), \
                        patch.object(activation.time, "sleep"):
                    previous = host._retained_tick()
                    host._retained_tick(previous)
                self.assertIs(host._failure, interruption)
                self.assertIs(host.supervisor, supervisor)
                self.assertIs(host.owner, self.owner)
                self.assertEqual(supervisor.run_once.call_count, 2)
                supervisor.request_local_drain.assert_called()
                supervisor.start.assert_not_called()
                self.owner.close_unactivated.assert_not_called()

    def test_diagnostic_baseexception_keeps_next_original_recovery_tick(self):
        self.start_fixture()
        self.host.start()
        interruption = SystemExit(8)
        before = self.supervisor.run_once.call_count
        with patch.object(activation, "emit", side_effect=[interruption, True]), \
                patch.object(activation.time, "sleep"):
            previous = self.host._retained_tick()
            self.host._retained_tick(previous)
        self.assertIs(self.host._failure, interruption)
        self.assertEqual(self.supervisor.run_once.call_count, before + 2)
        self.supervisor.request_local_drain.assert_called()
        self.owner.close_unactivated.assert_not_called()

    def test_pacing_baseexception_keeps_next_original_recovery_tick(self):
        self.start_fixture()
        self.host.start()
        interruption = GeneratorExit()
        before = self.supervisor.run_once.call_count
        with patch.object(activation, "emit", return_value=True), \
                patch.object(activation.time, "sleep", side_effect=[interruption, None]):
            previous = self.host._retained_tick()
            self.host._retained_tick(previous)
        self.assertIs(self.host._failure, interruption)
        self.assertEqual(self.supervisor.run_once.call_count, before + 2)
        self.supervisor.request_local_drain.assert_called()
        self.owner.close_unactivated.assert_not_called()

    def test_keyboard_interrupt_requests_drain_without_becoming_failure(self):
        self.start_fixture()
        self.host.start()
        before = self.supervisor.run_once.call_count
        with patch.object(activation, "emit", return_value=True), \
                patch.object(activation.time, "sleep", side_effect=[KeyboardInterrupt(), None]):
            previous = self.host._retained_tick()
            self.host._retained_tick(previous)
        self.assertTrue(self.host._draining)
        self.assertIsNone(self.host._failure)
        self.assertEqual(self.supervisor.run_once.call_count, before + 2)
        self.owner.close_unactivated.assert_not_called()

    def test_retirement_intent_requires_actual_boolean(self):
        for value in (1, "yes", None):
            with self.subTest(value=value), self.assertRaisesRegex(
                    activation.DailyActivationError, "retirement_intent_invalid"):
                activation.DailyActivationHost(MANIFEST, DIGEST, self.ledger, retire_after_drain=value)

    def test_retirement_request_requires_existing_activated_supervisor(self):
        with self.assertRaisesRegex(activation.DailyActivationError, "host_not_ready"):
            self.host.request_retirement()
        self.assertIsNone(self.host._retirement)
        self.assertFalse(self.host._retirement_creation_attempted)

    def test_repeated_retirement_request_reuses_original_operation(self):
        operation = self.retirement_fixture()
        self.assertIs(self.host.request_retirement(), operation)
        self.assertIs(self.host.request_retirement(), operation)
        self.assertEqual(operation.tick_calls, 0)

    def test_ordinary_drain_never_creates_retirement_request(self):
        self.start_fixture()
        self.host.start()
        self.host.request_drain()
        self.host.run_once()
        self.assertIsNone(self.host._retirement)
        self.assertFalse(self.host._readiness_stop.is_set())

    def test_keeper_cleanup_rejects_different_operation_and_serialized_claim(self):
        operation = self.retirement_fixture()
        for other in (Retirement(self.host), SimpleNamespace(host=self.host, sealed=True,
                                                            freeze_acknowledged=True, complete=False)):
            with self.subTest(other=type(other).__name__), self.assertRaisesRegex(
                    activation.DailyActivationError, "original_operation_required"):
                self.host.shutdown_native_retirement(other)
        self.assertEqual(operation.close_calls, 0)
        self.host._listener.close.assert_not_called()

    def test_unsealed_or_truthy_claim_does_not_stop_readiness(self):
        operation = self.retirement_fixture(sealed=False)
        for freeze, seal in ((False, False), (True, False), (1, True), (True, 1)):
            operation.freeze_acknowledged, operation.sealed = freeze, seal
            with self.subTest(freeze=freeze, seal=seal), self.assertRaisesRegex(
                    activation.DailyActivationError, "seal_unacknowledged"):
                self.host.shutdown_native_retirement(operation)
        self.assertFalse(self.host._readiness_stop.is_set())
        self.host._thread.join.assert_not_called()

    def test_sealed_retirement_waits_for_original_thread_then_closes_in_order(self):
        operation = self.retirement_fixture(stopped=False)
        events = []
        self.host._thread.join.side_effect = lambda **_: events.append("joined")
        self.host._listener.close.side_effect = lambda: events.append("listener_closed")
        original_close = operation.close_owner
        def close_owner():
            events.append("owner_closed")
            original_close()
        operation.close_owner = close_owner
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertTrue(self.host._readiness_stop.is_set())
        self.assertEqual(events, [])
        self.host._thread_stopped.set()
        self.assertTrue(self.host.shutdown_native_retirement(operation))
        self.assertEqual(events, ["joined", "listener_closed", "owner_closed"])
        self.host._thread.join.assert_called_once_with(timeout=0)
        self.assertTrue(self.host.status()["clean_exit_allowed"])

    def test_finally_signal_without_positive_join_and_death_is_insufficient(self):
        operation = self.retirement_fixture()
        self.host._thread.is_alive.return_value = True
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.host._listener.close.assert_not_called()
        self.assertFalse(self.host._readiness_joined)
        self.assertEqual(operation.close_calls, 0)

    def test_join_exception_retains_original_thread_without_listener_close(self):
        operation = self.retirement_fixture()
        original = self.host._thread
        failure = RuntimeError("synthetic interrupted join")
        original.join.side_effect = failure
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertIs(self.host._thread, original)
        self.assertIs(self.host._retirement_cleanup_error, failure)
        self.host._listener.close.assert_not_called()
        self.assertEqual(operation.close_calls, 0)

    def test_replaced_keeper_thread_cannot_retire_original_operation(self):
        operation = self.retirement_fixture()
        self.host._thread = Mock()
        self.host._thread.is_alive.return_value = False
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.host._thread.join.assert_not_called()
        self.host._listener.close.assert_not_called()
        self.assertEqual(operation.close_calls, 0)

    def test_unknown_listener_close_is_never_reissued(self):
        operation = self.retirement_fixture()
        failure = RuntimeError("synthetic unknown native close")
        self.host._listener.close.side_effect = failure
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertTrue(self.host._readiness_close_unknown)
        self.host._listener.close.assert_called_once_with()
        self.assertEqual(operation.close_calls, 0)
        self.assertFalse(self.host.status()["clean_exit_allowed"])

    def test_unsettled_sql_connection_blocks_native_keeper_close(self):
        operation = self.retirement_fixture()
        custody = activation._ConnectionCustody(Connection("still owned", self.events))
        self.host._connections.append(custody)
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.host._listener.close.assert_not_called()
        self.assertEqual(operation.close_calls, 0)
        custody.close()
        self.assertTrue(self.host.shutdown_native_retirement(operation))

    def test_registry_obligation_blocks_owner_close_without_reclosing_listener(self):
        operation = self.retirement_fixture()
        self.host._registry.status.return_value = SimpleNamespace(resources=1, pending=1, quarantined=0)
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertEqual(operation.close_calls, 0)
        self.host._registry.status.return_value = SimpleNamespace(resources=0, pending=0, quarantined=0)
        self.assertTrue(self.host.shutdown_native_retirement(operation))
        self.host._listener.close.assert_called_once_with()

    def test_boolean_registry_counts_are_not_cleanup_evidence(self):
        operation = self.retirement_fixture()
        self.host._registry.status.return_value = SimpleNamespace(resources=False, pending=False, quarantined=False)
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertFalse(self.host._readiness_cleanup_complete)
        self.assertEqual(operation.close_calls, 0)

    def test_original_operation_owner_close_failure_does_not_claim_completion(self):
        operation = self.retirement_fixture()
        operation.close_error = RuntimeError("synthetic cohort cleanup unknown")
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.assertTrue(self.host._readiness_cleanup_complete)
        self.assertFalse(self.host.status()["clean_exit_allowed"])
        self.assertFalse(operation.complete)
        self.assertIs(self.host._retirement, operation)
        self.assertFalse(self.host.shutdown_native_retirement(operation))
        self.host._listener.close.assert_called_once_with()

    def test_readiness_thread_finishes_current_rpc_then_stops_without_closing(self):
        self.host._registry = Mock()
        self.host._service = Mock()
        self.host._service.serve_once.side_effect = lambda *_args, **_kwargs: self.host._readiness_stop.set()
        listener = Mock()
        with patch.object(activation, "NativePipeListener", return_value=listener):
            self.host._serve_readiness()
        self.host._service.serve_once.assert_called_once_with(listener, timeout_ms=1000)
        self.assertTrue(self.host._thread_stopped.is_set())
        listener.close.assert_not_called()

    def test_freeze_acknowledgement_precedes_supervisor_drain(self):
        operation = self.retirement_fixture(sealed=False, stopped=False)
        events = []
        def freeze():
            events.append("freeze_ack")
            operation.freeze_acknowledged = True
        operation.on_tick = freeze
        self.host.supervisor.request_local_drain.side_effect = lambda: events.append("drain")
        self.host.run_once()
        self.assertEqual(events[0], "freeze_ack")
        self.assertIn("drain", events[1:])
        self.assertEqual(operation.tick_calls, 1)

    def test_pending_freeze_does_not_request_retirement_drain(self):
        operation = self.retirement_fixture(sealed=False, stopped=False)
        self.host.run_once()
        self.host.supervisor.request_local_drain.assert_not_called()
        self.assertFalse(self.host._draining)
        self.assertEqual(operation.tick_calls, 1)

    def test_freeze_failure_preserves_independent_supervisor_recovery(self):
        operation = self.retirement_fixture(sealed=False, stopped=False)
        failure = RuntimeError("synthetic freeze uncertainty")
        def fail():
            raise failure
        operation.on_tick = fail
        self.host.run_once()
        self.assertIs(self.host._failure, failure)
        self.host.supervisor.run_once.assert_called_once_with()
        self.assertIs(self.host._retirement, operation)

    def test_full_retirement_stops_queries_after_seal_and_allows_resident_return(self):
        operation = self.retirement_fixture(sealed=False, stopped=False)
        self.host.supervisor._custody_snapshot.return_value = {"settled": True}
        self.host.supervisor.close.return_value = {"cleanup_errors": [], "guardian_left_running": False}
        def advance():
            if not operation.freeze_acknowledged:
                operation.freeze_acknowledged = True
            elif self.host._supervisor_closed:
                operation.sealed = True
        operation.on_tick = advance
        first = self.host.run_once()
        self.assertTrue(self.host._supervisor_closed)
        self.assertTrue(operation.sealed)
        self.assertFalse(first["clean_exit_allowed"])
        self.host._thread_stopped.set()
        with patch.object(activation, "emit", return_value=True), patch.object(activation.time, "sleep"):
            result = self.host.run_forever()
        self.assertTrue(result["clean_exit_allowed"])
        self.assertTrue(operation.complete)
        self.host.supervisor._custody_snapshot.assert_called_once_with()
        self.host.supervisor.close.assert_called_once_with()
        self.host._listener.close.assert_called_once_with()

    def test_explicit_constructor_intent_requests_retirement_after_supervisor_start(self):
        from sentinel.adaptive import daily_retirement
        self.start_fixture()
        self.host._retire_after_drain = True
        with patch.object(daily_retirement, "DailyRetirementOperation", Retirement):
            self.host.start()
            self.assertIsInstance(self.host._retirement, Retirement)
            self.assertEqual(self.host._retirement.tick_calls, 1)
            self.supervisor.start.assert_called_once_with()


class ActivationRestartCliTests(unittest.TestCase):
    def test_restart_without_retirement_refuses_before_manifest_open(self):
        argv = ["--manifest", "unopened-fixture.json", "--config-digest", DIGEST,
                "--ledger-device", "1", "--ledger-inode", "2", "--restart-after-retirement"]
        with patch.object(Path, "open", side_effect=AssertionError("manifest opened before option validation")), \
                patch.object(sys, "stderr", Mock()), self.assertRaises(SystemExit) as caught:
            activation.main(argv)
        self.assertEqual(caught.exception.code, 2)

    def test_main_passes_intent_but_does_not_accept_an_unretired_chain(self):
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "manifest.json"
            path.write_text(json.dumps(MANIFEST.to_dict()), encoding="utf-8")
            argv = ["--manifest", str(path), "--config-digest", DIGEST,
                    "--ledger-device", "1", "--ledger-inode", "2",
                    "--retire-generation-after-drain", "--restart-after-retirement"]
            returned = []
            retained = []
            class CustodyObserved(BaseException):
                pass
            def run(host):
                returned.append(host)
                return {"clean_exit_allowed": True}  # A serialized claim supplies no authority.
            def tick(host):
                retained.append(host)
                raise CustodyObserved()
            with patch.object(generation, "daily_locations", return_value=(root, root / "data")), \
                    patch.object(activation.DailyActivationHost, "run_forever", run), \
                    patch.object(activation.DailyActivationHost, "_retained_tick", tick), \
                    self.assertRaises(CustodyObserved):
                activation.main(argv)
            self.assertEqual(returned, retained)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]._failure.reason, "daily_activation_unexpected_return")
            self.assertTrue(returned[0]._retire_after_drain)
            self.assertTrue(returned[0]._restart_after_retirement)
            self.assertFalse(returned[0].chain_retirement_complete())


if __name__ == "__main__":
    unittest.main()
