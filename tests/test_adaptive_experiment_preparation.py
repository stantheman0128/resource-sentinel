"""Original preparation/cleanup source regressions; synthetic native backends.

Real isolated daily admission and SQLite are used. No native process, Job,
pipe, installed daily generation, or Windows capability is exercised.
"""
from contextlib import closing
import sqlite3
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive import experiment_scope as scope
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import ResourceDemand
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import JobAccess, NativeJob, NativeJobError
from sentinel.adaptive.windows import NativePolicyMutexError
from tests import test_adaptive_experiment_demand as demand_tests
from tests.test_adaptive_identity import Backend
from tests.windows.adaptive_scope_launch import ScopeCommand


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = demand_tests.ExperimentDemandTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.scopes = []
        self.addCleanup(self.remove_scopes)

    def remove_scopes(self):
        for owner in self.scopes:
            if scope._OWNERS.get(owner.scope_id) is owner:
                scope._OWNERS.pop(owner.scope_id)

    def admitted(self):
        demand = self.fixture.capture()
        self.assertTrue(self.fixture.coordinator.admit_experiment(demand)["allowed"])
        return demand

    def test_before_native_completion_is_original_sealed_and_accounting_unchanged(self):
        demand = self.admitted()
        before = self.fixture.assert_retained(demand)
        original = demand.seal_without_native()
        self.assertIs(type(original), demand_module.BeforeNativeCompletion)
        original.assert_original()
        self.assertIs(demand.seal_without_native(), original)
        self.assertEqual(original.snapshot()["disposition"], "BEFORE_NATIVE")
        self.assertEqual(original.snapshot()["demand"]["generation"], demand._prepared[0])
        data = original.snapshot()
        data["demand"]["requested"]["cpu_units"] = 0
        self.assertNotEqual(data, original.snapshot())
        self.assertEqual(before, self.fixture.assert_retained(demand))
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "preparation_sealed"):
            self.fixture.coordinator.admit_experiment(demand)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "experiment_native_cleanup_unverified"):
            demand._admission.cancel_reserved(demand.ledger_path,
                reservation_id=before[0]["id"], expected_revision=0)

    def test_before_native_copy_and_changed_generation_are_not_authority(self):
        demand = self.admitted()
        original = demand.seal_without_native()
        copied = object.__new__(demand_module.BeforeNativeCompletion)
        object.__setattr__(copied, "owner", demand)
        object.__setattr__(copied, "digest", original.digest)
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_completion_changed"):
            copied.assert_original()
        demand._prepared[0]["generation"] = str(uuid4())
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_completion_changed"):
            original.assert_original()

    def test_queued_only_seals_without_fabricating_admitted_completion(self):
        demand = self.fixture.capture()
        self.fixture.publish_status(commit=94)
        self.assertFalse(self.fixture.coordinator.admit_experiment(demand)["allowed"])
        with self.assertRaises(demand_module.ExperimentDemandError):
            demand.seal_without_native()
        self.assertTrue(demand._native_preparation_sealed)
        self.assertIsNone(demand._before_native_completion)
        self.assertEqual(self.fixture.fixture.counts(), (1, 0, 0))

    def test_original_unsettled_submission_prevents_completion_and_remains_sealed(self):
        demand = self.admitted()
        demand._admission._submission_transaction["connection_closed"] = False
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "unused_daily_claim_required"):
            demand.seal_without_native()
        self.assertTrue(demand._native_preparation_sealed)
        self.assertIsNone(demand._before_native_completion)

    def test_before_native_rejects_copied_replacement_between_precheck_and_connect(self):
        demand = self.admitted()
        original_connect = sqlite3.connect
        copied = demand.ledger_path.with_name("copied-completion-ledger.sqlite3")
        with closing(original_connect(demand.ledger_path)) as source, closing(original_connect(copied)) as target:
            source.backup(target)
        replacement_identity = demand_module._identity(copied)
        self.assertNotEqual(replacement_identity, demand.ledger_identity)
        opened = []
        def replace_then_connect(*args, **kwargs):
            copied.replace(demand.ledger_path)
            connection = original_connect(*args, **kwargs)
            opened.append(connection)
            return connection
        with patch.object(demand_module.sqlite3, "connect", side_effect=replace_then_connect) as connect:
            with self.assertRaisesRegex(demand_module.ExperimentDemandError, "completion_ledger_changed") as raised:
                demand.seal_without_native()
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(demand_module._identity(demand.ledger_path), replacement_identity)
        self.assertIs(raised.exception.experiment_demand_owner, demand)
        self.assertTrue(demand._native_preparation_sealed)
        self.assertIsNone(demand._before_native_completion)
        self.assertIsNone(demand._seal_connection)
        with self.assertRaises(sqlite3.ProgrammingError):
            opened[0].execute("SELECT 1")
        self.fixture.assert_retained(demand)

    def test_before_native_rejects_foreign_main_with_identical_admitted_metadata(self):
        demand = self.admitted()
        original_connect = sqlite3.connect
        copied = demand.ledger_path.with_name("foreign-completion-ledger.sqlite3")
        with closing(original_connect(demand.ledger_path)) as source, closing(original_connect(copied)) as target:
            source.backup(target)
        def foreign_connection(*args, **kwargs):
            return original_connect(copied.as_uri() + "?mode=ro", **kwargs)
        with patch.object(demand_module.sqlite3, "connect", side_effect=foreign_connection):
            with self.assertRaisesRegex(demand_module.ExperimentDemandError, "completion_ledger_changed"):
                demand.seal_without_native()
        self.assertEqual(demand_module._identity(demand.ledger_path), demand.ledger_identity)
        self.assertTrue(demand._native_preparation_sealed)
        self.assertIsNone(demand._before_native_completion)
        self.assertIsNone(demand._seal_connection)
        self.fixture.assert_retained(demand)

    def test_before_native_unknown_sql_close_is_retained_and_never_reopened(self):
        demand = self.admitted()
        real_connect = sqlite3.connect
        connections = []
        class UnknownClose(sqlite3.Connection):
            def close(self):
                raise OSError("synthetic unknown close")
        def connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs, factory=UnknownClose)
            connections.append(connection)
            return connection
        try:
            with patch.object(demand_module.sqlite3, "connect", side_effect=connect) as opened:
                with self.assertRaisesRegex(OSError, "synthetic unknown close"):
                    demand.seal_without_native()
                self.assertIs(demand._seal_connection, connections[0])
                with self.assertRaises(demand_module.ExperimentDemandError):
                    demand.seal_without_native()
                self.assertEqual(opened.call_count, 1)
            self.assertIsNone(demand._before_native_completion)
            self.fixture.assert_retained(demand)
        finally:
            for connection in connections:
                sqlite3.Connection.close(connection)  # Test-only known fake close.

    def native_demand(self):
        script = self.fixture.scope / "synthetic_worker.py"
        script.write_text("pass\n", encoding="utf-8")
        command = ScopeCommand.capture(application=sys.executable,
            arguments=("-I", str(script.resolve())), cwd=self.fixture.scope, fixture_paths=(script,))
        declaration = demand_module.ExperimentDeclaration(str(uuid4()), "S1", command.sha256,
            ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        demand = demand_module.DailyExperimentDemand.capture(declaration, self.fixture.scope)
        self.fixture.owners.append(demand)
        self.assertTrue(self.fixture.coordinator.admit_experiment(demand)["allowed"])
        # Exact VerifiedProcess type with a portable synthetic handle backend.
        backend = Backend()
        backend.value, backend.member = demand._snapshot.wrapper_identity, False
        guardian = VerifiedProcess(backend, 701, backend.value)
        demand._admission._process = guardian
        self.addCleanup(guardian.close)
        return demand, command

    def failed_original_check(self):
        demand, command = self.native_demand()
        error = scope.ExperimentScopeError("synthetic_first_original_refusal")
        def refuse():
            original = demand._native_preparation
            self.assertIs(type(original), scope.ExperimentNativeScope)
            self.assertIs(scope._OWNERS[original.scope_id], original)
            self.assertTrue(all(state == "not_entered" for state in original._preparation_acquisitions.values()))
            raise error
        with patch.object(demand, "_original", side_effect=refuse):
            with self.assertRaises(scope.ExperimentScopeError) as raised:
                scope.ExperimentNativeScope.prepare(demand, command)
        owner = raised.exception.experiment_scope_owner
        self.scopes.append(owner)
        self.assertIs(raised.exception, error)
        self.assertIs(owner, demand._native_preparation)
        return demand, owner

    def test_original_store_is_retained_before_constructor_opens_sql(self):
        demand, command = self.native_demand()
        initialize = scope._IsolatedStore.__init__
        failure = OSError("synthetic failure after original store initialization")
        def interrupted(store, path):
            owner = demand._native_preparation
            self.assertIs(owner.store, store)
            self.assertIs(owner._original_store, store)
            self.assertEqual(owner._preparation_acquisitions["store"], "entered")
            initialize(store, path)
            self.assertFalse(store.connections)
            raise failure
        with patch.object(scope.ExperimentNativeScope, "_ready", return_value=None), \
                patch.object(scope.ExperimentNativeScope, "_coverage_locked"), \
                patch.object(scope._IsolatedStore, "__init__", interrupted):
            with self.assertRaises(OSError) as raised:
                scope.ExperimentNativeScope.prepare(demand, command)
        owner = demand._native_preparation
        self.scopes.append(owner)
        self.assertIs(raised.exception, failure)
        self.assertIs(type(owner.store), scope._IsolatedStore)
        self.assertIs(raised.exception.experiment_scope_owner, owner)
        completion = owner.close_native()
        self.assertEqual(completion.snapshot()["disposition"], "PREPARATION_CLOSED")
        self.fixture.assert_retained(demand)

    def test_first_original_check_already_has_demand_owned_attempt_and_cannot_retry(self):
        demand, owner = self.failed_original_check()
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "native_preparation_entered"):
            demand.seal_without_native()
        with self.assertRaisesRegex(scope.ExperimentScopeError, "original_scope_occupied"):
            scope.ExperimentNativeScope.prepare(demand, owner.command)
        self.assertIs(demand._native_preparation, owner)
        original = owner.close_native()
        self.assertEqual(original.snapshot()["disposition"], "PREPARATION_CLOSED")
        self.assertIs(owner.close_native(), original)
        self.assertIsNone(original.snapshot()["reservation_id"])
        self.fixture.assert_retained(demand)

    def test_early_completion_is_distinct_from_before_native_and_rejects_demand_swap(self):
        demand, owner = self.failed_original_check()
        completion = owner.close_native()
        self.assertIs(type(completion), scope.NativeScopeCompletion)
        self.assertIsNone(demand._before_native_completion)
        demand._native_preparation = object()
        with self.assertRaises(demand_module.ExperimentDemandError):
            completion.assert_original()

    def test_missing_factory_return_and_unknown_readiness_never_mint_completion(self):
        demand, owner = self.failed_original_check()
        owner._preparation_acquisitions["launch"] = "entered"
        with self.assertRaisesRegex(scope.ExperimentScopeError, "preparation_acquisition_outcome_unknown"):
            owner.close_native()
        self.assertIsNone(owner.completion)
        self.fixture.assert_retained(demand)

    def test_unknown_partial_create_retains_original_and_never_retries_create(self):
        demand, owner = self.failed_original_check()
        job = NativeJob(owner.job_name, owner.creation_nonce, owner.guardian.identity.logon_id,
            JobAccess.OWNER, Mock())
        job._creation.state = "allocation_unknown"
        error = KeyboardInterrupt("synthetic unknown Create")
        error._native_job_initialization_owners = (job,)
        owner._create_attempted = True
        owner._preparation_acquisitions["job"] = "entered"
        owner._retain(error)
        for _ in range(2):
            with self.assertRaises(NativeJobError):
                owner.close_native()
        self.assertIs(owner._partial_job, job)
        self.assertFalse(job.closed)
        job._backend.close.assert_not_called()
        self.assertIsNone(owner.completion)
        self.fixture.assert_retained(demand)

    def test_exact_failed_job_with_positive_original_close_can_complete(self):
        demand, owner = self.failed_original_check()
        job = NativeJob(owner.job_name, owner.creation_nonce, owner.guardian.identity.logon_id,
            JobAccess.OWNER, Mock())
        error = NativeJobError("native_job_create_failed")
        error._native_job_initialization_owners = (job,)
        owner._create_attempted = True
        owner._preparation_acquisitions["job"] = "entered"
        owner._retain(error)
        original = owner.close_native()
        self.assertEqual(original.snapshot()["terminal"]["job_factory"], "failed_retained")
        self.assertTrue(job.closed)
        self.assertIs(owner._partial_job_error, error)
        self.fixture.assert_retained(demand)

    def test_retained_job_wrong_binding_does_not_authorize_absence(self):
        demand, owner = self.failed_original_check()
        job = NativeJob(owner.job_name + "-foreign", owner.creation_nonce, owner.guardian.identity.logon_id,
            JobAccess.OWNER, Mock())
        error = NativeJobError("native_job_create_failed")
        error._native_job_initialization_owners = (job,)
        owner._create_attempted = True
        owner._preparation_acquisitions["job"] = "entered"
        owner._retain(error)
        with self.assertRaisesRegex(scope.ExperimentScopeError, "preparation_acquisition_outcome_unknown"):
            owner.close_native()
        self.assertIsNone(owner.completion)

    def test_known_mutex_constructor_absence_and_unknown_constructor_are_distinct(self):
        demand, owner = self.failed_original_check()
        owner._preparation_acquisitions["mutex"] = "known_absent"
        owner._mutex_construction_error = NativePolicyMutexError("policy_mutex_create_failed")
        original = owner.close_native()
        self.assertEqual(original.snapshot()["acquisitions"]["mutex"], "known_absent")
        owner._mutex_construction_error.add_note("policy_mutex_close_outcome_unknown")
        with self.assertRaisesRegex(scope.ExperimentScopeError, "preparation_cleanup_unverified"):
            original.assert_original()

    def test_partial_store_connection_blocks_completion_without_replacement(self):
        demand, owner = self.failed_original_check()
        original = scope._IsolatedStore.__new__(scope._IsolatedStore)
        original.connections, original.sql_errors = {object(): None}, []
        owner.store = owner._original_store = original
        owner._preparation_acquisitions["store"] = "entered"
        with self.assertRaisesRegex(scope.ExperimentScopeError, "preparation_cleanup_unverified"):
            owner.close_native()
        self.assertIs(owner.store, original)
        self.assertIsNone(owner.completion)


if __name__ == "__main__":
    unittest.main()
