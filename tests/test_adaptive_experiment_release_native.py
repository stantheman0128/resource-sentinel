"""Original scope completion through daily release, with synthetic native I/O.

ExperimentNativeScope.prepare/close_native, NativeJob ownership, ScopeLaunch
protocol/drain/close, journal, exclusions and release SQL are real. The local
generation attestation, pipe endpoint, process creation and Win32 backends are
explicit portable fixtures; these tests provide no native gate evidence.
"""
from contextlib import closing, contextmanager, ExitStack
import json
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import experiment_exclusion as exclusion
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive import experiment_scope as scope
from sentinel.adaptive import native_launcher
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import CpuState, NativeJob
from sentinel.adaptive.policy import PolicyCoordinator
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_experiment_demand as demand_tests
from tests import test_adaptive_managed_admission as managed_tests
from tests import test_adaptive_native_job as job_tests
from tests import test_adaptive_native_launcher as launcher_tests
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_identity import Backend
from tests.windows import adaptive_scope_launch as launch_module


class _JobMutex:
    """In-process fixture only; no native mutex capability is claimed."""
    def __init__(self, *args):
        self.closed = False

    @contextmanager
    def acquire(self, *, timeout_ms):
        if self.closed:
            raise AssertionError("closed fixture Job mutex reused")
        yield SimpleNamespace(abandoned=False)

    def close(self):
        self.closed = True


class ExperimentNativeReleaseTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.guardian_backend = Backend()
        self.guardian_backend.value, self.guardian_backend.member = IDENTITY, False
        self.guardian = VerifiedProcess(self.guardian_backend, 1700, IDENTITY)
        self.fixture = demand_tests.ExperimentDemandTests()
        self.addCleanup(self.fixture.doCleanups)
        # Capture the actual VerifiedProcess before admission, never substitute
        # the final self witness after an original binding has been published.
        with patch.object(managed_tests, "FakeCurrentProcess", return_value=self.guardian):
            self.fixture.setUp()
        self.coordinator, self.db = self.fixture.coordinator, self.fixture.coordinator.db_path
        self.native = job_tests.NativeJobTests()
        self.native.setUp()
        self.addCleanup(self.native.doCleanups)
        self.native.kernel.accounting = (0,) * 8
        self.native.kernel.membership = [(1, 0, 0, 0, ())] * 100
        self.scopes, self.launchers, self.operations = [], [], []
        self.addCleanup(self.remove_originals)
        self.wrapper_backend = Backend()
        self.wrapper_backend.value = ProcessIdentity(IDENTITY.pid + 101,
            IDENTITY.created_filetime_100ns + 1, IDENTITY.logon_id)
        self.wrapper_backend.member = False
        self.wrapper = VerifiedProcess(self.wrapper_backend, 1701, self.wrapper_backend.value)
        self.root_backend = Backend()
        self.root_backend.value = ProcessIdentity(IDENTITY.pid + 102,
            IDENTITY.created_filetime_100ns + 2, IDENTITY.logon_id)
        self.root_backend.exit_code = Mock(return_value=23)
        self.root = VerifiedProcess(self.root_backend, 1702, self.root_backend.value)
        self.drained = False
        self.exchange_operations = []

        initialize = scope._IsolatedStore.__init__
        def initialize_isolated(store, path):
            initialize(store, path)
            store._policy = PolicyCoordinator(store, FixturePolicyProvider(IDENTITY.logon_id))
        create_job = NativeJob.create
        proof = SimpleNamespace(read_generation=self.fixture.proof.read_generation,
            readiness_scope=generation.readiness_scope, readiness_scopes=generation.readiness_scopes,
            prepare_connection=generation.prepare_connection)
        for change in (
                patch.object(scope, "daily_generation", proof),
                patch.object(exclusion, "daily_generation", self.fixture.proof),
                patch.object(scope.ExperimentNativeScope, "_ready", return_value=None),
                patch.object(scope._IsolatedStore, "__init__", initialize_isolated),
                patch.object(scope, "NativePolicyMutex", _JobMutex),
                patch.object(NativeJob, "create", side_effect=lambda name, nonce, logon_id, **kw:
                    create_job(name, nonce, logon_id, backend=self.native.backend, **kw)),
                patch.object(launch_module.ScopeLaunch, "prepare", side_effect=self.prepare_launcher)):
            self.stack.enter_context(change)

    def remove_originals(self):
        for operation in self.operations:
            cleanup._OPERATIONS.pop(operation.operation_id, None)
        for owner in self.scopes:
            scope._OWNERS.pop(owner.scope_id, None)
        for owner in self.launchers:
            launch_module._OWNERS.pop(owner.scope_id, None)
        # All are this test's synthetic backend handles, including witnesses
        # deliberately never acquired by a failed wrapper-creation branch.
        for owner in (self.root, self.wrapper, self.guardian):
            owner.close()

    def rows(self, table):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.row_factory = sqlite3.Row
            if not conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                return []
            return [dict(row) for row in conn.execute("SELECT * FROM " + table + " ORDER BY rowid")]

    def admitted(self):
        script = self.fixture.scope / "synthetic_worker.py"
        script.write_text("pass\n", encoding="utf-8")
        command = launch_module.ScopeCommand.capture(application=sys.executable,
            arguments=("-I", str(script.resolve())), cwd=self.fixture.scope, fixture_paths=(script,))
        declaration = demand_module.ExperimentDeclaration(str(uuid4()), "S1", command.sha256,
            ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        demand = demand_module.DailyExperimentDemand.capture(declaration, self.fixture.scope)
        self.fixture.owners.append(demand)
        self.assertTrue(self.coordinator.admit_experiment(demand)["allowed"])
        self.assertIs(demand._admission._process, self.guardian)
        self.demand, self.command = demand, command
        self.admitted_rows = {table: self.rows(table) for table in
            ("reservations", "managed_executions", demand_module.TABLE)}
        return demand, command

    def prepare_launcher(self, demand, command, scope_id, nonce, deadline):
        # Same concrete launcher/custody used by the portable launcher tests.
        # Only endpoint preparation is synthetic; seal/drain/close and the
        # authenticated message validator below remain actual implementation.
        owner = launch_module.ScopeLaunch(_token=launch_module._NEW)
        owner.demand, owner.command, owner.scope_id = demand, command, scope_id
        owner.job_nonce, owner.deadline = nonce, deadline
        owner.guardian, owner.guardian_identity = self.guardian, self.guardian.identity
        owner.job_name = "Local\\ResourceSentinel.Test.Job." + nonce
        owner.fixture_sources = ()
        owner.wrapper_command_line = "synthetic-wrapper"
        owner._request_marker = self.fixture.scope / ("request-" + scope_id + ".json")
        owner.registry = SimpleNamespace(status=lambda: SimpleNamespace(resources=0, pending=0, quarantined=0))
        test = self
        class Connection:
            @contextmanager
            def verified_peer(self, expected):
                test.assertEqual(expected, test.wrapper.identity)
                yield SimpleNamespace(identity=expected,
                    duplicate_remote_handle=lambda locator, expected: test.root)

            def close(self):
                pass
        owner.listener = SimpleNamespace(accept=lambda deadline: Connection(), close=Mock())
        original_exchange = owner._exchange
        owner._exchange = lambda operation: self.exchange(owner, original_exchange, operation)
        launch_module._OWNERS[scope_id] = owner
        self.launchers.append(owner)
        return owner

    def exchange(self, owner, original, operation):
        self.exchange_operations.append(operation)
        attempted = operation == "launch" or owner._command_dispatched
        result = dict(schema_version=1, kind="S1ScopeResult", scope_id=owner.scope_id,
            request_id=owner._request_ids[operation], command_sha256=owner.command.sha256,
            attempted=attempted, sealed=operation != "launch",
            creation_outcome="created" if attempted else "not_attempted",
            root=None if not attempted or operation == "drain" else
                dict(identity=self.root.identity.to_dict(), handle_locator=1702),
            local_closed=operation == "drain", reason="scope_observed", launch_provenance=None)
        hello = dict(schema_version=1, kind="S1ScopeHello", scope_id=owner.scope_id,
            wrapper_identity=self.wrapper.identity.to_dict(), command_sha256=owner.command.sha256)
        messages = iter((hello, result, launch_module.receipt_confirmation(result)))
        with patch("sentinel.adaptive.pipe_windows.NativeDeadline.after_ms", return_value=object()), \
                patch("sentinel.adaptive.ipc.read_frame", side_effect=lambda *args: next(messages)), \
                patch("sentinel.adaptive.ipc.write_frame"):
            value = original(operation)
        if operation == "drain":
            self.drained = True
            self.wrapper_backend.state = IdentityStatus.DEAD
        return value

    def create_wrapper(self, launcher, *, native_deadline=None):
        launcher._created = launcher._wrapper_create_entered = True
        launcher.wrapper_witness = self.wrapper
        launcher.process = SimpleNamespace(creation_definitely_absent=False,
            wait=lambda timeout: self.drained, exit_code=lambda: 0, close=Mock())
        return self.wrapper

    def prepared(self):
        demand, command = self.admitted()
        with patch.object(launch_module.ScopeLaunch, "create_inert", autospec=True,
                side_effect=self.create_wrapper):
            owner = scope.ExperimentNativeScope.prepare(demand, command)
        self.scopes.append(owner)
        self.assertTrue(owner._registered)
        self.assertIs(owner.guardian, self.guardian)
        self.assertEqual(len(self.rows(exclusion.TABLE)), 1)
        self.assertEqual(self.rows(exclusion.TABLE)[0]["phase"], "REGISTERED")
        return owner

    def release_completion(self, owner, completion):
        self.assertIs(completion, owner.completion)
        self.assertIs(completion.owner, owner)
        self.assertIs(type(completion), scope.NativeScopeCompletion)
        completion.assert_original()
        frozen = completion.snapshot()
        self.assertIsNotNone(self.guardian._handle)  # Borrowed until daily release.
        for table, rows in self.admitted_rows.items():
            self.assertEqual(self.rows(table), rows)
        excluded = self.rows(exclusion.TABLE)
        with closing(sqlite3.connect(self.db)) as conn:
            row = self.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" + ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        operation = self.demand.prepare_release(completion)
        self.operations.append(operation)
        with patch.object(generation, "_assert_daily_locations"), \
                patch.object(generation, "verify_import_provenance"), \
                patch.object(generation, "_prove_retained_owner_ready",
                    side_effect=AssertionError("release requested new readiness")):
            result = self.coordinator.release_experiment(operation)
            before_replay = self.rows(history.TABLE), self.rows("executions"), self.rows(exclusion.TABLE)
            self.assertEqual(self.coordinator.release_experiment(operation), result)
            self.assertEqual((self.rows(history.TABLE), self.rows("executions"), self.rows(exclusion.TABLE)), before_replay)
        self.assertEqual(result["disposition"], frozen["disposition"])
        self.assertTrue(result["released"])
        receipt = self.rows(history.TABLE)[0]
        record = json.loads(receipt["receipt_json"])
        self.assertEqual(record["completion"], frozen)
        self.assertEqual(record["completion_digest"], completion.digest)
        self.assertEqual(self.rows("reservations"), [])
        self.assertEqual(self.rows("executions")[0]["outcome"], "managed_cancelled_before_start")
        self.assertEqual(self.rows("managed_executions")[0]["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(self.rows(demand_module.TABLE), self.admitted_rows[demand_module.TABLE])
        self.assertEqual(self.guardian_backend.closed, [1700])
        if excluded:
            self.assertEqual(self.rows(exclusion.TABLE), [excluded[0] | dict(
                phase="CLOSED", cleanup_digest=record["cleanup_digest"])])
        else:
            self.assertEqual(self.rows(exclusion.TABLE), [])
        # Data eligibility only: no closed scope consumes the next scope slot.
        # Fresh admission would separately require original daily readiness.
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN")
            observed = history.verify_experiment_history_locked(conn)
            self.assertEqual(observed.active_experiment_ids, frozenset())
            self.assertEqual(observed.completed_execution_ids, frozenset({record["execution_id"]}))
            self.assertTrue(all(json.loads(value)["phase"] == "CLOSED" for value in observed.exclusions_json))
            conn.rollback()
        return record

    def test_documented_wrapper_create_false_releases_original_never_created_scope(self):
        demand, command = self.admitted()
        kernel = launcher_tests.Kernel()
        kernel.create_result, kernel.process_info = 0, (0, 0, 0, 0)
        backend = native_launcher._WindowsBackend(kernel=kernel)
        with patch.object(native_launcher, "_WindowsBackend", return_value=backend), \
                self.assertRaises(native_launcher.NativeLaunchError):
            scope.ExperimentNativeScope.prepare(demand, command)
        owner = demand._native_preparation
        self.scopes.append(owner)
        self.assertTrue(owner.launch.process.creation_definitely_absent)
        self.assertEqual(len([call for call in kernel.calls if call[0] == "CreateProcessW"]), 1)
        self.assertFalse(owner._registered)
        completion = owner.close_native()
        self.assertEqual(completion.snapshot()["disposition"], "WRAPPER_NOT_CREATED")
        self.assertTrue(owner.launch.process._closed)
        self.assertTrue(owner.job.closed)
        self.assertEqual(self.exchange_operations, [])
        self.release_completion(owner, completion)

    def test_registered_never_launched_scope_closes_exact_exclusion_and_releases(self):
        owner = self.prepared()
        completion = owner.close_native()
        self.assertEqual(completion.snapshot()["disposition"], "NEVER_LAUNCHED")
        self.assertEqual(self.exchange_operations, ["seal", "drain"])
        self.assertEqual(self.wrapper_backend.closed, [1701])
        self.assertEqual(self.root_backend.closed, [])
        record = self.release_completion(owner, completion)
        self.assertIsNone(record["completion"]["terminal"]["root"])
        self.assertEqual(record["completion"]["terminal"]["total_processes"], 0)

    def test_finished_original_root_restores_cpu_and_releases_exact_closed_history(self):
        owner = self.prepared()
        self.assertIs(owner.launch_once(), self.root)
        self.assertTrue(owner.launch.root_job_bound)
        with patch.object(owner, "_grants_locked", return_value=SimpleNamespace(leases=())):
            self.assertEqual(owner.set_cpu_rate(), CpuState(5, 2500))
        self.root_backend.state = IdentityStatus.DEAD
        self.native.kernel.accounting = (0, 0, 0, 0, 0, 1, 0, 1)
        completion = owner.close_native()
        frozen = completion.snapshot()
        self.assertEqual(frozen["disposition"], "FINISHED")
        self.assertEqual(frozen["terminal"]["root"], self.root.identity.to_dict())
        self.assertEqual(frozen["terminal"]["root_exit_code"], 23)
        self.assertEqual(frozen["terminal"]["last_applied_cpu"], dict(flags=0, rate_bp=0))
        self.assertIsNone(frozen["terminal"]["pending_target_cpu"])
        self.assertEqual(self.root_backend.closed, [1702])
        self.assertEqual(self.wrapper_backend.closed, [1701])
        self.assertEqual(self.exchange_operations, ["launch", "seal", "drain"])
        self.release_completion(owner, completion)

    def test_other_demand_cannot_adopt_an_original_native_completion(self):
        owner = self.prepared()
        completion = owner.close_native()
        other_backend = Backend()
        other_backend.value = IDENTITY
        other = VerifiedProcess(other_backend, 1703, IDENTITY)
        self.addCleanup(other.close)
        with patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=other):
            foreign = self.fixture.capture()
        with patch.object(sqlite3, "connect", side_effect=AssertionError("wrong completion opened SQL")), \
                self.assertRaisesRegex(cleanup.ExperimentReleaseError, "completion_owner_changed"):
            foreign.prepare_release(completion)
        self.operations.append(foreign._release_operation)
        self.assertIs(completion.owner, owner)
        self.assertIsNone(owner.demand._release_operation)
        self.release_completion(owner, completion)


if __name__ == "__main__":
    unittest.main()
