"""Two original generation lifetimes over isolated SQL and synthetic natives.

Retirement, succession, readiness publication, supervisor startup, epoch,
guardian registration and final custody validation are production code. Only
process/mutex/pipe effects are synthetic; the readiness serving thread is real.
This is source integration evidence, not Windows restart or activation proof.
"""
import os
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_activation_host as activation
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_epoch as epoch
from sentinel.adaptive import identity, supervisor_host
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.guardian_registration import GuardianRegistration
from sentinel.adaptive.recovery_owner import RecoveryOwner, RetainedGuardianCreation
from sentinel.adaptive.supervisor_startup import SupervisorStartup
from tests import test_adaptive_daily_successor_host as host_fixture
from tests import test_adaptive_supervisor_startup as startup_fixture
from tests.test_adaptive_guardian_launch import ProcessBackend
from tests.test_adaptive_host_authority import SYNTHETIC


class CreationBackend(ProcessBackend):
    def duplicate_process(self, handle):
        return self.new_handle(self.state(handle))


class Creation:
    """One original raw Create handle and independently duplicated witnesses."""
    def __init__(self, test):
        self.test = test
        self.process = None
        self.calls, self.closed = [], []

    def create(self, executable, arguments, cwd):
        test = self.test
        supervisor = test.fresh.supervisor
        guard = test.store._policy.assert_held()
        test.assertIs(guard, supervisor._initial_start_operation.guard)
        test.assertIsNone(self.process, "a second guardian Create is forbidden")
        self.calls.append((executable, tuple(arguments), cwd, guard))
        # The synthetic child has a distinct creation identity. Its PID uses
        # this interpreter so actual current-process registration checks run.
        self.process = test.native.process(ProcessIdentity(os.getpid(),
            134343072009999999, test.current.identity.logon_id))
        return SimpleNamespace(hProcess=self.process._handle, hThread=900001,
            dwProcessId=self.process.identity.pid, dwThreadId=900002)

    def close_handle(self, handle):
        self.test.assertNotIn(handle, self.closed)
        if handle != 900001:
            self.test.assertIsNotNone(self.process)
            self.test.assertEqual(handle, self.process._handle)
            self.process.close()
        self.closed.append(handle)


class DailySuccessorCycleTests(unittest.TestCase):
    def setUp(self):
        # A previous fault test's original unknown reader must not be adopted.
        self.install(patch.object(generation, "_READINESS_SCOPES", {}))
        self.fixture = host_fixture.DailySuccessorHostTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.transition_fixture = self.fixture.fixture
        self.sql_fixture = self.transition_fixture.fixture
        self.store = self.fixture.store
        self.old = self.fixture.predecessor_host
        self.first_retirement = self.fixture.retirement
        self.operation = self.old.request_successor()
        self.assertIs(self.operation, self.fixture.operation)
        self.first_retirement.assert_successor_predecessor()
        self.assertTrue(self.old._retirement_complete())
        self.assertFalse(self.old.chain_retirement_complete())
        self.assertTrue(self.operation.tick())
        self.fresh = self.fixture.fresh_host()
        self.fixture.configure_readiness(self.fresh)
        self.native = CreationBackend()
        self.current = self.native.process(self.fresh.owner.process.identity)
        self.held, self.mutexes, self.recoveries = {}, [], []
        self.creation = Creation(self)
        self.before_ordinary = self.ordinary_rows()
        self.before_exemptions = self.transition_fixture.exemption_rows()
        self.archive = self.transition_fixture.archives()

        original_init = SupervisorStartup.__init__
        def startup_init(startup, store, journal, **kwargs):
            self.assertEqual(kwargs, {})
            original_init(startup, store, journal, current=self.current,
                          mutex_factory=self.mutex_factory)

        original_capture = RecoveryOwner.capture
        def capture(store, journal, **kwargs):
            owner = original_capture(store, journal, **kwargs,
                current=self.current, mutex_factory=self.mutex_factory,
                job_opener=self.unexpected_job)
            self.recoveries.append(owner)
            return owner

        self.install(patch.object(SupervisorStartup, "__init__", startup_init))
        self.install(patch.object(RecoveryOwner, "capture", side_effect=capture))
        self.install(patch.object(identity, "_backend", return_value=self.native))
        self.install(patch.object(supervisor_host, "_Creation", return_value=self.creation))
        self.install(patch.object(activation, "_MODULE_ROOT", self.fresh.source_root))
        self.install(patch.object(activation, "_BASE_PYTHON", Path(sys.executable)))
        self.install(patch.object(activation, "read_host_capability", return_value=SYNTHETIC))
        self.install(patch.object(supervisor_host, "read_host_capability", return_value=SYNTHETIC))
        self.install(patch.object(supervisor_host.SupervisorHost, "capability_logon",
                                 return_value=self.current.identity.logon_id))
        # Operator RPC endpoints and telemetry are outside this cycle. Their
        # absence supplies no settled flag; child, recovery and startup owners
        # below must still close through their original production methods.
        self.install(patch.object(supervisor_host.SupervisorHost, "_ensure_operations"))
        self.install(patch.object(supervisor_host.SupervisorHost, "_start_telemetry"))
        self.addCleanup(self.close_synthetic_resources)

    def install(self, replacement):
        result = replacement.start()
        self.addCleanup(replacement.stop)
        return result

    def mutex_factory(self, logon, instance):
        mutex = startup_fixture.Mutex(self, logon, instance)
        self.mutexes.append(mutex)
        return mutex

    def unexpected_job(self, *args, **kwargs):
        self.fail("empty source-cycle fixture must never open a native Job")

    def ordinary_rows(self):
        with self.sql_fixture.reader() as conn:
            return {name: tuple(tuple(row) for row in conn.execute(
                'SELECT * FROM "' + name + '" ORDER BY rowid'))
                for name in ("queue", "reservations", "workers", "resource_samples")}

    def audit_rows(self):
        with self.sql_fixture.reader() as conn:
            return tuple(tuple(row) for row in conn.execute(
                'SELECT * FROM "' + epoch.TABLE + '" ORDER BY rowid'))

    def assert_old_connection_fenced(self):
        connection = self.transition_fixture.old_connection
        try:
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute("UPDATE queue SET heartbeat_at=200 WHERE request_key='unrelated'")
        finally:
            connection.rollback()

    def start_and_register(self):
        self.assertFalse(self.old.chain_retirement_complete())
        self.old.run_once()
        self.assertIs(self.old._successor_host, self.fresh)
        self.assertIsNone(self.fresh._failure)
        self.assertTrue(self.fresh._listener_ready.is_set())
        self.assertFalse(self.fresh._thread_stopped.is_set())
        self.operation.assert_readiness_published(self.fresh.owner)
        supervisor = self.fresh.supervisor
        self.assertIsNot(supervisor, self.old.supervisor)
        self.assertIsNot(supervisor.startup, self.old.supervisor.startup)
        self.assertIs(supervisor.store, self.store)
        self.assertIs(supervisor.journal, self.first_retirement.journal)
        supervisor.startup.assert_held()
        self.assertIsNone(supervisor.cold_reason)
        self.assertEqual(supervisor.started_guardians, 1)
        self.assertEqual(len(self.creation.calls), 1)
        self.assertIs(type(supervisor.guardian.creation_witness), RetainedGuardianCreation)
        self.assertIs(supervisor.guardian.process, supervisor.guardian.creation_witness.process)
        self.assertEqual(supervisor.guardian.process.identity, self.creation.process.identity)
        self.assertIsNotNone(supervisor.supervisor)
        self.assertEqual(len(self.recoveries), 1)
        self.assertIs(supervisor.supervisor.recovery, self.recoveries[0])
        self.assertTrue(supervisor._initial_start_result.complete)
        published_epoch = self.operation._guardian_epoch_operation
        published_epoch.assert_complete()
        revision = self.sql_fixture.state()[2]["registry_revision"]
        registration = GuardianRegistration(self.store, supervisor.journal,
            guardian=self.creation.process, guardian_epoch=published_epoch.new_epoch)
        result = registration.tick()
        self.assertTrue(result.complete, result)
        self.registration = registration
        self.assertEqual(self.sql_fixture.state()[2]["registry_revision"], revision + 1)
        self.assertNotEqual(published_epoch.new_epoch,
                            self.transition_fixture.before_runtime["guardian_epoch"])
        self.audit = self.audit_rows()
        self.assertEqual(len(self.audit), 1)
        self.assertEqual(len(self.transition_fixture.archives().entries), 1)
        self.assertFalse(self.old.chain_retirement_complete())
        self.assertFalse(self.fresh.chain_retirement_complete())
        self.assert_old_connection_fenced()
        return supervisor

    def settle_child_and_seal(self):
        supervisor = self.start_and_register()
        operation = self.fresh.request_retirement()
        self.assertIsNot(operation, self.first_retirement)
        self.assertIs(operation.owner, self.fresh.owner)
        self.assertIs(operation.host, self.fresh)
        operation.tick()
        self.assertTrue(operation.freeze_acknowledged, operation.reason)
        self.assertFalse(operation.sealed)
        self.assertFalse(operation.complete)
        self.assertFalse(self.old.chain_retirement_complete())
        self.fresh._drain_current()
        # The original retained process witness observes the synthetic kernel
        # object's death. Neither a PID lookup nor a fabricated settled result
        # enters the supervisor/registry retirement path.
        self.native.objects[self.creation.process.identity].status = IdentityStatus.DEAD
        record = supervisor.run_once()
        self.assertEqual(record["guardian_status"], "dead", record)
        self.assertFalse(record["replacement"]["started"], record)
        self.assertIsNone(record["replacement"]["registry_reason"], record)
        self.assertTrue(supervisor._guardian_settled)
        self.assertTrue(self.recoveries[0]._closed)
        self.assertTrue(supervisor._drain_children_settled())
        # There are no operator endpoints in this fixture; close the actual
        # native child/startup custody through the public supervisor owner.
        closed = supervisor.close()
        self.assertEqual(closed["cleanup_errors"], [])
        self.assertFalse(closed["guardian_left_running"])
        self.assertTrue(supervisor._closed)
        self.assertTrue(supervisor.startup._closed)
        self.assertTrue(supervisor.guardian.creation_witness._closed)
        self.assertEqual(len(self.creation.closed), 2)
        self.assertTrue(supervisor._custody_snapshot()["settled"])
        # Host observes that exact positive close result itself, then performs
        # its own seal, original serving-thread shutdown and native final close.
        self.old.run_once()
        self.assertTrue(self.fresh._supervisor_closed)
        self.assertTrue(operation.sealed, (operation.reason, self.fresh.status()))
        self.assertTrue(self.fresh._thread_stopped.wait(1.0))
        return operation

    def assert_history_preserved(self):
        self.assertEqual(self.transition_fixture.archives(), self.archive)
        self.assertEqual(self.audit_rows(), self.audit)
        self.assertEqual(self.ordinary_rows(), self.before_ordinary)
        self.assertEqual(self.transition_fixture.exemption_rows(), self.before_exemptions)
        self.assertEqual(len(self.creation.calls), 1)
        with self.sql_fixture.reader() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM adaptive_infrastructure").fetchone()[0], 0)
        self.assert_old_connection_fenced()

    def test_two_original_generation_lifetimes_complete_only_after_second_retirement(self):
        second = self.settle_child_and_seal()
        self.old.run_once()
        self.assertTrue(second.complete, (second.reason, self.fresh.status()))
        second.assert_successor_predecessor()
        self.first_retirement.assert_successor_predecessor()
        self.assertIsNot(self.fresh.owner, self.old.owner)
        self.assertIsNot(self.fresh.owner.process, self.old.owner.process)
        self.assertTrue(self.fresh._readiness_joined)
        self.assertTrue(self.fresh._readiness_listener_closed)
        self.assertTrue(self.fresh._readiness_cleanup_complete)
        self.assertEqual(self.fresh._registry.status().resources, 0)
        self.assertTrue(self.old.chain_retirement_complete())
        self.assertTrue(self.old.status()["clean_exit_allowed"])
        row, frozen, runtime = self.sql_fixture.state()
        self.assertEqual(row["generation"], self.fresh.owner.generation)
        self.assertEqual(row["state"], "DRAINING")
        self.assertEqual(frozen["phase"], "SEALED")
        self.assertEqual(runtime["guardian_epoch"], self.operation._guardian_epoch_operation.new_epoch)
        self.assertIsNone(runtime["policy_entry_nonce"])
        self.assertEqual(runtime["mode"], "off")
        self.assert_history_preserved()
        self.old.run_once()  # Original completed chain is an idempotent exit observation.
        self.assertTrue(self.old.chain_retirement_complete())
        self.assert_history_preserved()

    def test_second_listener_close_unknown_keeps_original_chain_resident_without_retry(self):
        error = RuntimeError("fixture_original_second_listener_close_unknown")
        self.fixture.pipe_backend.error = error
        second = self.settle_child_and_seal()
        self.old.run_once()
        self.assertTrue(self.first_retirement.complete)
        self.assertTrue(second.sealed)
        self.assertFalse(second.complete)
        self.assertTrue(self.fresh._readiness_close_attempted)
        self.assertTrue(self.fresh._readiness_close_unknown)
        self.assertIs(self.fresh._retirement_cleanup_error, error)
        self.assertFalse(self.fresh._readiness_cleanup_complete)
        self.assertFalse(self.old.chain_retirement_complete())
        self.assertFalse(self.old.status()["clean_exit_allowed"])
        original = (self.fresh.owner, self.fresh._listener, self.fresh._thread,
                    self.fresh._registry, second)
        with patch.object(self.fixture.pipe_backend, "close",
                side_effect=AssertionError("unknown original handle must not be closed again")):
            self.old.run_once()
        self.assertEqual((self.fresh.owner, self.fresh._listener, self.fresh._thread,
                          self.fresh._registry, self.fresh._retirement), original)
        self.assertFalse(second.complete)
        self.assertFalse(self.old.chain_retirement_complete())
        self.assert_history_preserved()

    def close_synthetic_resources(self):
        # Teardown cannot make any retirement positive: it disposes synthetic
        # collaborators after assertions without altering production flags.
        supervisor = self.fresh.supervisor
        if supervisor is not None:
            if supervisor.supervisor is not None:
                supervisor.supervisor.close()
            for item in supervisor._creation_records:
                witness = item.get("witness")
                if witness is not None:
                    witness.close()
            if supervisor.startup is not None:
                supervisor.startup.close()
        if self.creation.process is not None:
            self.creation.process.close()
        self.current.close()


if __name__ == "__main__":
    unittest.main()
