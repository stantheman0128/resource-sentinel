"""Serial provider source tests: real isolated SQL, explicit native seams.

The original VerifiedProcess and legacy PID observer share a synthetic identity.
Source readiness and the POLICY mutex provider are fixture seams; queue,
admission, generation pinning,
settlement, early native preparation, receipts and final self-close remain real.
No native workload, production data, activation or capability gate is exercised.
"""
from contextlib import closing, contextmanager
from copy import copy
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_demand as demands
from sentinel.adaptive import experiment_scope as scopes
from sentinel.adaptive.capability_evidence import LiveCapabilityContext
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.policy import NativePolicyProvider
from sentinel.coordinator import Coordinator
from tests import test_adaptive_experiment_demand as demand_tests
from tests import test_adaptive_managed_admission as managed_tests
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_coordinator import NOW
from tests.test_adaptive_identity import Backend
from tests.windows import adaptive_s1_provider as provider


class S1ProviderTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.backend.value, self.backend.member = IDENTITY, False
        self.process = VerifiedProcess(self.backend, 700, IDENTITY)
        self.fixture = demand_tests.ExperimentDemandTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(managed_tests, "FakeCurrentProcess", return_value=self.process):
            self.fixture.setUp()
        self.context = LiveCapabilityContext("c" * 64, 10, 0, 26100, 12, 1, "4095",
            IDENTITY.logon_id, 1, 0, "3.13.0", 64, "d" * 64, False, "e" * 64)
        self.source = patch.object(provider, "_capture_generation",
            side_effect=lambda case: provider._canonical(self.fixture.generation))
        self.source_mock = self.source.start()
        self.addCleanup(self.source.stop)
        # The real Coordinator also observes the legacy PID/birth projection
        # when pruning queues. Match that native observation to this original
        # synthetic FILETIME; querying the host's real birth would correctly
        # classify the test PID as reused and delete its artificial queue row.
        pid_observation = patch("sentinel.coordinator._default_pid_identity",
            side_effect=lambda pid: (True,
                (self.backend.value.created_filetime_100ns - 116444736000000000) / 10_000_000)
                if pid == self.backend.value.pid else (None, 0.0))
        self.pid_observation = pid_observation.start()
        self.addCleanup(pid_observation.stop)
        # Provider constructs the real Coordinator without test-only arguments.
        # Its normal native POLICY factory is explicitly synthetic here too.
        for override in (patch("sentinel.adaptive.policy.NativePolicyProvider",
                return_value=self.fixture.fixture.policy),
                patch.object(provider, "_base_python", return_value=Path(sys.executable).resolve())):
            override.start()
            self.addCleanup(override.stop)
        self.owner = provider.S1SerialProvider(self.fixture.scope, self.context)
        self.addCleanup(self.remove_originals)

    def remove_originals(self):
        provider._PROVIDERS.pop(id(self.owner), None)
        for case in self.owner._cases:
            if case.demand is not None:
                demands._RETAINED.pop(case.experiment_id, None)
                for name in ("_release_operation", "_admission_settlement", "_unadmitted_cleanup"):
                    operation = getattr(case.demand, name, None)
                    if operation is not None:
                        cleanup._OPERATIONS.pop(operation.operation_id, None)
            if case.scope is not None:
                scopes._OWNERS.pop(case.scope_id, None)

    def start(self, kind="round"):
        case = self.owner.start_case(kind)
        self.assertIs(type(case.demand), demands.DailyExperimentDemand)
        self.assertIs(type(case.coordinator), Coordinator)
        self.assertIsNot(case.coordinator, self.fixture.coordinator)
        self.assertEqual(case.coordinator.db_path, self.fixture.coordinator.db_path)
        return case

    def install_generation(self):
        # The cleanup consumer validates actual persisted rows/canonical SQL.
        # No ordinary capacity authority is installed for this fixture row.
        with closing(sqlite3.connect(self.fixture.coordinator.db_path)) as conn:
            row = self.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for override in (patch.object(generation, "_assert_daily_locations"),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "_prove_retained_owner_ready",
                    side_effect=AssertionError("cleanup requested new readiness"))):
            override.start()
            self.addCleanup(override.stop)

    def admitted_before_prepare(self):
        case = self.start()
        # A changed generation after command capture must still cancel the
        # actual admitted original; it must never rebuild/launch that command.
        self.fixture.generation["generation"] = str(uuid4())
        with patch.object(scopes.ExperimentNativeScope, "prepare") as prepare:
            with self.assertRaisesRegex(provider.S1ProviderError, "admitted_generation_changed"):
                case.poll_admission()
            prepare.assert_not_called()
        self.assertTrue(case._admitted)
        self.assertFalse(case._prepare_entered)
        self.install_generation()
        return case

    def early_partial(self):
        case = self.start()
        failure = RuntimeError("synthetic first native readiness refusal")
        with patch.object(scopes.ExperimentNativeScope, "_ready", side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, "synthetic first native readiness refusal"):
                case.poll_admission()
        self.assertIs(case.scope, case.demand._native_preparation)
        self.assertIs(type(case.scope), scopes.ExperimentNativeScope)
        self.assertIs(failure.experiment_scope_owner, case.scope)
        self.assertEqual(set(case.scope._preparation_acquisitions.values()), {"not_entered"})
        self.install_generation()
        return case

    def test_case_is_retained_before_source_and_capture_with_fixed_command(self):
        real_capture = demands.DailyExperimentDemand.capture
        seen = []
        def source(case):
            self.assertIs(self.owner.current_case, case)
            self.assertIn(case, self.owner._cases)
            return provider._canonical(self.fixture.generation)
        def capture(declaration, directory):
            case = self.owner.current_case
            self.assertIs(case.spec.declaration, declaration)
            self.assertEqual(case.spec.command.sha256, declaration.scope_sha256)
            self.assertEqual(case.directory, directory)
            seen.append(case)
            return real_capture(declaration, directory)
        self.source_mock.side_effect = source
        with patch.object(demands.DailyExperimentDemand, "capture", side_effect=capture):
            case = self.start()
        self.assertEqual(seen, [case])
        args = case.spec.command.arguments
        self.assertEqual(args[0], "-I")
        self.assertEqual(args[1], str(provider._FIXTURE.resolve()))
        self.assertIn("--scope-bound-stdin", args)
        self.assertEqual(args[args.index("--scope-id") + 1], case.scope_id)
        self.assertEqual(args[args.index("--nonce") + 1], case.creation_nonce)
        self.assertEqual(args[args.index("--source-generation") + 1], self.fixture.generation["generation"])
        self.assertNotIn("--deadline-monotonic-ns", args)
        self.assertEqual(case.spec.workers, 4)
        self.assertEqual(case.spec.seconds, 115)
        self.assertEqual(case.spec.declaration.requested.cpu_units, 5.0)
        self.assertEqual(case.spec.declaration.requested.physical_bytes, 1 << 30)
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 0))

    def test_self_stop_and_foreign_parent_are_fixed_distinct_declarations(self):
        case = self.start("self_stop")
        self.assertEqual((case.spec.workers, case.spec.seconds), (1, 2))
        self.assertNotIn("--probe-foreign-host", case.spec.command.arguments)
        case.recover_once()
        # A new synthetic original current-process witness, only for this test.
        process = VerifiedProcess(self.backend, 701, IDENTITY)
        with patch("sentinel.adaptive.admission.VerifiedProcess.current", return_value=process):
            following = self.start("foreign_parent")
        self.assertEqual(following.spec.seconds, 5)
        self.assertIn("--probe-foreign-host", following.spec.command.arguments)
        self.assertNotEqual(case.spec.command.sha256, following.spec.command.sha256)
        self.assertNotEqual(case.scope_id, following.scope_id)

    def test_queued_polls_preserve_actual_context_command_and_no_native_factory(self):
        case = self.start()
        self.fixture.publish_status(commit=94)
        demand, command, snapshot = case.demand, case.spec.command, case.demand._snapshot
        with patch.object(scopes.ExperimentNativeScope, "prepare") as prepare:
            first = case.poll_admission()
            self.assertEqual(first["reason"], "commit_capacity")
            self.assertEqual(self.fixture.fixture.counts(), (1, 0, 0))
            self.fixture.publish_status(now=NOW + 1, commit=94)
            second = case.poll_admission()
        self.assertFalse(first["allowed"])
        self.assertFalse(second["allowed"])
        self.assertEqual(second["reason"], "commit_capacity")
        self.assertEqual(first["request_key"], second["request_key"])
        self.assertIs(case.demand, demand)
        self.assertIs(case.demand._snapshot, snapshot)
        self.assertIs(case.spec.command, command)
        self.pid_observation.assert_called_with(snapshot.wrapper_identity.pid)
        self.assertIsNone(case.demand._native_preparation)
        prepare.assert_not_called()
        self.assertEqual(self.fixture.fixture.counts(), (1, 0, 0))
        with self.assertRaisesRegex(provider.S1ProviderError, "previous_case_unsettled"):
            self.owner.start_case()
        self.assertEqual(self.owner.completed_cases, ())
        self.assertEqual(list(case.directory.glob("*.json")), [])

    def test_queued_to_admitted_uses_same_demand_and_one_registered_scope(self):
        case = self.start()
        self.fixture.publish_status(commit=94)
        queued = case.poll_admission()
        self.assertFalse(queued["allowed"])
        self.assertEqual(queued["reason"], "commit_capacity")
        self.assertEqual(self.fixture.fixture.counts(), (1, 0, 0))
        original = case.demand
        command = case.spec.command
        self.fixture.publish_status(now=NOW + 1)
        failure = RuntimeError("synthetic native boundary")
        with patch.object(scopes.ExperimentNativeScope, "_ready", side_effect=failure), \
                patch.object(scopes.ExperimentNativeScope, "prepare", wraps=scopes.ExperimentNativeScope.prepare) as prepare:
            with self.assertRaisesRegex(RuntimeError, "synthetic native boundary"):
                case.poll_admission()
            with self.assertRaisesRegex(provider.S1ProviderError, "admission_not_available"):
                case.poll_admission()
        self.assertEqual(prepare.call_count, 1)
        self.assertIs(case.demand, original)
        self.assertIs(case.scope.command, command)
        self.assertIs(case.scope.demand, original)
        self.pid_observation.assert_called_with(original._snapshot.wrapper_identity.pid)
        self.assertEqual(self.fixture.fixture.counts(), (0, 1, 1))

    def test_empty_probe_declares_fixed_one_second_duration(self):
        case = self.start("empty_probe")
        self.assertEqual((case.spec.workers, case.spec.seconds), (1, 1))
        self.assertEqual(case.spec.command.arguments[case.spec.command.arguments.index("--seconds") + 1], "1")

    def test_clean_never_submitted_closes_original_without_new_policy(self):
        case = self.start()
        with patch.object(case.coordinator, "abandon_experiment", side_effect=AssertionError), \
                patch.object(case.coordinator, "admit_experiment", side_effect=AssertionError):
            result = case.recover_once()
        self.assertEqual(result["state"], "NOT_SUBMITTED")
        self.assertEqual(result["execution_id"], case._snapshot.execution_id)
        self.assertEqual(self.backend.closed, [700])
        self.assertIsNone(case.demand._native_preparation)
        self.assertEqual(case.recover_once(), result)
        self.assertEqual(self.owner.completed_cases, (case,))

    def test_queued_cleanup_uses_actual_original_abandon_and_final_close(self):
        case = self.start()
        self.fixture.publish_status(commit=94)
        case.poll_admission()
        self.install_generation()
        with patch.object(case.coordinator, "admit_experiment", side_effect=AssertionError), \
                patch.object(scopes.ExperimentNativeScope, "prepare", side_effect=AssertionError):
            result = self.owner.recover_once()
        self.assertEqual(result["state"], "QUEUED_CANCELLED")
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 0))
        self.assertIs(case.abandon_operation, case.demand._unadmitted_cleanup)
        self.assertTrue(case.abandon_operation._completed)
        self.assertTrue(case.demand._closed)
        self.assertEqual(self.backend.closed, [700])

    def test_generation_mismatch_releases_actual_unused_claim_without_prepare(self):
        case = self.admitted_before_prepare()
        result = case.recover_once()
        self.assertEqual(result["disposition"], "BEFORE_NATIVE")
        self.assertIs(type(case.completion), demands.BeforeNativeCompletion)
        self.assertIs(case.release_operation, case.demand._release_operation)
        self.assertTrue(case.release_operation._completed)
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 1))
        self.assertEqual(self.backend.closed, [700])
        self.assertTrue(case.errors)  # Cleanup does not turn this into a passing run.

    def test_original_partial_scope_closes_then_releases_no_new_factory(self):
        case = self.early_partial()
        original = case.scope
        with patch.object(scopes.ExperimentNativeScope, "prepare", side_effect=AssertionError):
            result = case.recover_once()
        self.assertEqual(result["disposition"], "PREPARATION_CLOSED")
        self.assertIs(case.scope, original)
        self.assertIs(case.completion, original.completion)
        self.assertTrue((case.directory / "stop").is_file())
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 1))

    def test_pending_close_cannot_release_and_reuses_same_owner_next_tick(self):
        case = self.early_partial()
        original_close = case.scope.close_native
        with patch.object(case.scope, "close_native", return_value=None) as close, \
                patch.object(case.demand, "prepare_release") as prepare:
            self.assertIsNone(case.recover_once())
            self.assertEqual(close.call_count, 1)
            prepare.assert_not_called()
        self.assertEqual(self.fixture.fixture.counts(), (0, 1, 1))
        with self.assertRaisesRegex(provider.S1ProviderError, "previous_case_unsettled"):
            self.owner.start_case()
        with patch.object(case.scope, "close_native", wraps=original_close) as close:
            result = case.recover_once()
        self.assertTrue(result["released"])
        self.assertEqual(close.call_count, 1)

    def test_stop_marker_failure_still_ticks_original_native_cleanup(self):
        case = self.early_partial()
        error = OSError("synthetic marker failure")
        with patch.object(case, "_stop", side_effect=error), \
                patch.object(case.scope, "close_native", return_value=None) as close:
            self.assertIsNone(case.recover_once())
        close.assert_called_once_with()
        self.assertIn(error, case.errors)
        self.assertFalse(case._closed)

    def test_missing_output_root_cannot_block_original_native_cleanup(self):
        case = self.early_partial()
        failure = FileNotFoundError("synthetic missing output root")
        with patch.object(provider, "_directory", side_effect=failure), \
                patch.object(case.scope, "close_native", return_value=None) as close, \
                patch.object(case.coordinator, "admit_experiment") as admit:
            self.assertIsNone(self.owner.recover_once())
            self.assertIs(self.owner.current_case, case)
            self.assertEqual(self.owner.completed_cases, ())
        close.assert_called_once_with()
        admit.assert_not_called()
        self.assertIn(failure, case.errors)
        self.assertFalse(case._closed)

    def test_positive_cleanup_result_is_available_without_output_root(self):
        case = self.start()
        result = case.recover_once()
        with patch.object(provider, "_directory", side_effect=FileNotFoundError("synthetic missing root")):
            self.assertEqual(case.cleanup_result, result)
            self.assertEqual(self.owner.recover_once(), result)
            self.assertEqual(self.owner.completed_cases, (case,))
            with self.assertRaises(FileNotFoundError):
                self.owner.start_case()

    def test_lost_release_ack_replays_same_operation_after_actual_final_self_close(self):
        case = self.admitted_before_prepare()
        real_release = case.coordinator.release_experiment
        seen = []
        def lost_ack(operation):
            seen.append(operation)
            real_release(operation)
            raise OSError("synthetic release reply lost")
        with patch.object(case.coordinator, "release_experiment", side_effect=lost_ack):
            with self.assertRaisesRegex(OSError, "synthetic release reply lost"):
                case.recover_once()
        self.assertTrue(case.release_operation._completed)
        self.assertFalse(case._closed)
        with patch.object(case.demand, "prepare_release", side_effect=AssertionError):
            result = case.recover_once()
        self.assertEqual(seen, [case.release_operation])
        self.assertTrue(result["released"])
        self.assertEqual(self.backend.closed, [700])

    def test_original_release_operation_is_retained_when_prepare_return_is_lost(self):
        case = self.admitted_before_prepare()
        prepare = case.demand.prepare_release
        def lost(completion):
            prepare(completion)
            raise OSError("synthetic preparation reply lost")
        with patch.object(case.demand, "prepare_release", side_effect=lost):
            with self.assertRaisesRegex(OSError, "synthetic preparation reply lost"):
                case.recover_once()
        operation = case.release_operation
        self.assertIs(operation, case.demand._release_operation)
        with patch.object(case.demand, "prepare_release", side_effect=AssertionError):
            self.assertTrue(case.recover_once()["released"])
        self.assertIs(case.release_operation, operation)

    def test_interrupted_admission_settles_original_guard_then_releases(self):
        case = self.start()
        original = case.coordinator._commit_admission
        def lost(conn, transaction):
            original(conn, transaction)
            raise OSError("synthetic admission COMMIT reply lost")
        with patch.object(case.coordinator, "_commit_admission", side_effect=lost):
            with self.assertRaisesRegex(OSError, "synthetic admission COMMIT reply lost"):
                case.poll_admission()
        guard = case.demand._admission._submission_guard
        self.assertIsNotNone(guard)
        self.install_generation()
        with patch.object(case.coordinator, "admit_experiment", side_effect=AssertionError), \
                patch.object(scopes.ExperimentNativeScope, "prepare", side_effect=AssertionError):
            result = case.recover_once()
        self.assertIs(case.settlement._guard, guard)
        self.assertTrue(case.settlement._settled)
        self.assertEqual(result["disposition"], "BEFORE_NATIVE")
        self.assertIsNone(case.scope)

    def assert_completed_admission_recovered(self, case, *, queued=False):
        inner = case.demand._admission
        original = case.demand._submission_original
        self.assertIsNone(inner._submission_guard)
        self.assertIsNone(inner._submission_policy_error)
        self.assertTrue(original[2]._nonce_clear_confirmed)
        self.assertIs(inner._submission_transaction["connection_closed"], True)
        self.assertTrue(case._admission_failed)
        self.assertFalse(case._prepare_entered)
        self.assertIsNone(case.scope)
        self.assertEqual(self.fixture.fixture.counts(), (1, 0, 0) if queued else (0, 1, 1))
        self.install_generation()
        with patch.object(case.coordinator, "admit_experiment", side_effect=AssertionError("cleanup re-admitted")), \
                patch.object(scopes.ExperimentNativeScope, "prepare", side_effect=AssertionError("cleanup prepared native work")):
            result = case.recover_once()
        self.assertIs(case.settlement._guard, original[2])
        self.assertIs(case.settlement._submission_original, original)
        self.assertIs(case.settlement._completed_return, True)
        self.assertEqual(case.settlement._phases, frozenset({"READ"}))
        self.assertTrue(case.settlement._settled)
        self.assertTrue(case.demand._closed)
        self.assertIsNone(case.scope)
        self.assertEqual(self.backend.closed, [700])
        if queued:
            self.assertEqual(result["state"], "QUEUED_CANCELLED")
            self.assertIs(case.abandon_operation.demand, case.demand)
            self.assertIsNone(case.release_operation)
            self.assertEqual(self.fixture.fixture.counts(), (0, 0, 0))
        else:
            self.assertEqual(result["disposition"], "BEFORE_NATIVE")
            self.assertIs(case.release_operation.demand, case.demand)
            self.assertEqual(self.fixture.fixture.counts(), (0, 0, 1))

    def test_completed_public_admission_reply_loss_settles_then_releases(self):
        case = self.start()
        admit = case.coordinator.admit_experiment
        observed = []
        def lose_reply(demand):
            self.assertTrue(case._admission_failed)
            observed.append(admit(demand))
            raise OSError("synthetic outer admission reply loss")
        with patch.object(case.coordinator, "admit_experiment", side_effect=lose_reply):
            with self.assertRaisesRegex(OSError, "synthetic outer admission reply loss"):
                case.poll_admission()
        self.assertIs(observed[0]["allowed"], True)
        self.assertFalse(case._admitted)
        self.assert_completed_admission_recovered(case)

    def test_completed_public_queue_reply_loss_settles_then_abandons(self):
        case = self.start()
        self.fixture.publish_status(commit=94)
        admit = case.coordinator.admit_experiment
        observed = []
        def lose_reply(demand):
            self.assertTrue(case._admission_failed)
            observed.append(admit(demand))
            raise OSError("synthetic outer queue reply loss")
        with patch.object(case.coordinator, "admit_experiment", side_effect=lose_reply):
            with self.assertRaisesRegex(OSError, "synthetic outer queue reply loss"):
                case.poll_admission()
        self.assertIs(observed[0]["allowed"], False)
        self.assertEqual(observed[0]["reason"], "commit_capacity")
        self.assert_completed_admission_recovered(case, queued=True)

    def test_interrupt_after_actual_admission_result_before_classification_settles(self):
        case = self.start()
        with patch.object(case, "_classify_admission", side_effect=KeyboardInterrupt("synthetic result handoff")) as classify:
            with self.assertRaises(KeyboardInterrupt):
                case.poll_admission()
        self.assertIs(classify.call_args.args[0]["allowed"], True)
        self.assertFalse(case._admitted)
        self.assert_completed_admission_recovered(case)

    def test_interrupt_after_admitted_assignment_before_classification_finishes_settles(self):
        case = self.start()
        assign = provider.S1Case.__setattr__
        def interrupt(owner, name, value):
            if owner is case and name == "_admission_failed" and value is False:
                self.assertTrue(owner._admitted)
                raise KeyboardInterrupt("synthetic classification publication")
            return assign(owner, name, value)
        with patch.object(provider.S1Case, "__setattr__", interrupt):
            with self.assertRaises(KeyboardInterrupt):
                case.poll_admission()
        self.assertTrue(case._admitted)
        self.assert_completed_admission_recovered(case)

    def test_non_boolean_result_after_actual_admission_keeps_original_settlement(self):
        case = self.start()
        admit = case.coordinator.admit_experiment
        def wrong_boolean(demand):
            result = admit(demand)
            return result | {"allowed": 1}
        with patch.object(case.coordinator, "admit_experiment", side_effect=wrong_boolean):
            with self.assertRaisesRegex(provider.S1ProviderError, "admission_result_unverified"):
                case.poll_admission()
        self.assert_completed_admission_recovered(case)

    def test_interrupted_queue_admission_settles_then_abandons_same_context(self):
        case = self.start()
        self.fixture.publish_status(commit=94)
        original = case.coordinator._commit_admission
        def lost(conn, transaction):
            original(conn, transaction)
            raise OSError("synthetic queue COMMIT reply lost")
        with patch.object(case.coordinator, "_commit_admission", side_effect=lost):
            with self.assertRaises(OSError):
                case.poll_admission()
        self.install_generation()
        result = case.recover_once()
        self.assertEqual(result["state"], "QUEUED_CANCELLED")
        self.assertIs(case.settlement.demand, case.demand)
        self.assertIs(case.abandon_operation.demand, case.demand)
        self.assertIsNone(case.release_operation)

    def test_rejected_submission_settles_then_abandons_original_rolled_back_transaction(self):
        case = self.start()
        with patch.object(case.coordinator, "_commit_admission", side_effect=OSError("synthetic precommit refusal")):
            with self.assertRaises(OSError):
                case.poll_admission()
        transaction = case.demand._admission._submission_transaction
        self.assertIs(transaction["commit_attempted"], False)
        self.assertIs(transaction["rolled_back"], True)
        self.install_generation()
        result = case.recover_once()
        self.assertEqual(result["state"], "SUBMISSION_REJECTED")
        self.assertIs(case.settlement._transaction, transaction)
        self.assertIs(case.abandon_operation._transaction, transaction)
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 0))

    def test_unknown_unsubmitted_close_remains_with_original_process_and_no_second_close(self):
        case = self.start()
        self.backend.failure = "close"
        with patch.object(self.backend, "close", wraps=self.backend.close) as close:
            with self.assertRaises(Exception):
                case.recover_once()
            self.assertIsNotNone(case.demand._quarantine)
            with self.assertRaises(Exception):
                case.recover_once()
            self.assertEqual(close.call_count, 1)
        self.assertIs(case.demand._admission._process, self.process)
        self.assertFalse(case._closed)
        self.assertEqual(self.owner.completed_cases, ())

    def test_fixture_failure_before_capture_finishes_only_after_original_source_positive_close(self):
        original = generation._ReadinessScope(self.fixture.coordinator.db_path.resolve())
        original.closed = True
        def observed(case):
            case._source_enter_attempted = True
            case._source_readiness = original
            return provider._canonical(self.fixture.generation)
        self.source_mock.side_effect = observed
        with patch.object(provider.FixtureSource, "capture", side_effect=FileNotFoundError("synthetic missing fixture")), \
                patch.object(demands.DailyExperimentDemand, "capture") as capture:
            with self.assertRaises(FileNotFoundError):
                self.owner.start_case()
            case = self.owner.current_case
            result = case.recover_once()
        capture.assert_not_called()
        self.assertEqual(result["state"], "NO_DEMAND_CAPTURED")
        self.assertIs(result["demand_captured"], False)
        self.assertIsNone(case.demand)
        self.assertTrue(case.errors)
        self.assertEqual(self.fixture.fixture.counts(), (0, 0, 0))

    def test_unknown_source_entry_without_returned_owner_cannot_finish_case(self):
        failure = OSError("synthetic source acquisition unknown")
        def source(case):
            case._source_enter_attempted = True
            raise failure
        self.source_mock.side_effect = source
        with self.assertRaises(OSError):
            self.owner.start_case()
        case = self.owner.current_case
        with self.assertRaisesRegex(provider.S1ProviderError, "partial_source_unsettled"):
            case.recover_once()
        self.assertIs(failure.s1_case_owner, case)
        self.assertEqual(self.owner.completed_cases, ())

    def test_failed_capture_keeps_attached_partial_and_cannot_close_or_replace_it(self):
        actual = demands.DailyExperimentDemand.capture
        original = []
        failure = OSError("synthetic capture interruption")
        def capture(declaration, directory):
            demand = actual(declaration, directory)
            original.append(demand)
            failure.experiment_demand_owner = demand
            raise failure
        with patch.object(demands.DailyExperimentDemand, "capture", side_effect=capture) as capture:
            with self.assertRaises(OSError):
                self.start()
            case = self.owner.current_case
            self.assertIs(case.demand, original[0])
            with self.assertRaisesRegex(provider.S1ProviderError, "partial_factory_unsettled"):
                case.recover_once()
            with self.assertRaisesRegex(provider.S1ProviderError, "previous_case_unsettled"):
                self.owner.start_case()
            self.assertEqual(capture.call_count, 1)
        self.assertEqual(self.backend.closed, [])
        self.assertIs(failure.s1_case_owner, case)

    def test_failed_coordinator_constructor_retains_actual_partial_object(self):
        failure = OSError("synthetic coordinator SQL close unknown")
        retained = []
        def initialize(original, directory):
            retained.append(original)
            raise failure
        with patch.object(Coordinator, "__init__", side_effect=initialize, autospec=True):
            with self.assertRaises(OSError):
                self.start()
        case = self.owner.current_case
        self.assertIs(case.coordinator, retained[0])
        with self.assertRaisesRegex(provider.S1ProviderError, "partial_factory_unsettled"):
            case.recover_once()
        self.assertIs(failure.s1_case_owner, case)
        self.assertEqual(self.backend.closed, [])

    def test_missing_scope_factory_return_without_registered_owner_remains_held(self):
        case = self.start()
        with patch.object(scopes.ExperimentNativeScope, "prepare", side_effect=KeyboardInterrupt) as prepare:
            with self.assertRaises(KeyboardInterrupt):
                case.poll_admission()
            with self.assertRaisesRegex(provider.S1ProviderError, "preparation_owner_unavailable"):
                case.recover_once()
            with self.assertRaisesRegex(provider.S1ProviderError, "admission_not_available"):
                case.poll_admission()
            self.assertEqual(prepare.call_count, 1)
        self.assertEqual(self.fixture.fixture.counts(), (0, 1, 1))

    def test_copied_case_replaced_demand_and_context_duck_type_are_refused(self):
        with self.assertRaisesRegex(provider.S1ProviderError, "exact_provider_and_context_required"):
            provider.S1SerialProvider(self.fixture.scope, Mock(logical_processors=12))
        case = self.start()
        with self.assertRaisesRegex(provider.S1ProviderError, "original_case_changed"):
            copy(case).recover_once()
        case.demand = copy(case.demand)
        with self.assertRaisesRegex(provider.S1ProviderError, "original_case_changed"):
            case.poll_admission()
        case.demand = case._demand_original
        case.recover_once()

    def test_fixture_change_after_capture_refuses_before_admission(self):
        case = self.start()
        with patch.object(provider.ScopeCommand, "verify", side_effect=RuntimeError("synthetic source changed")), \
                patch.object(case.coordinator, "admit_experiment") as admit:
            with self.assertRaisesRegex(RuntimeError, "synthetic source changed"):
                case.poll_admission()
        admit.assert_not_called()
        self.assertEqual(case.recover_once()["state"], "NOT_SUBMITTED")

    def test_failed_cleanup_never_publishes_or_permits_another_case(self):
        case = self.early_partial()
        failure = OSError("synthetic unknown native close")
        with patch.object(case.scope, "close_native", side_effect=failure), \
                patch.object(case.coordinator, "release_experiment") as release:
            with self.assertRaises(OSError):
                case.recover_once()
        release.assert_not_called()
        self.assertIs(failure.s1_case_owner, case)
        self.assertEqual(self.owner.completed_cases, ())
        self.assertEqual(list(case.directory.glob("*.json")), [])
        with self.assertRaisesRegex(provider.S1ProviderError, "case_unsettled"):
            _ = case.cleanup_result
        with self.assertRaisesRegex(provider.S1ProviderError, "previous_case_unsettled"):
            self.owner.start_case()


class SourcePinTests(unittest.TestCase):
    def test_source_pin_requires_original_typed_scope_and_positive_close(self):
        # The provider's generation observation seam is tested separately from
        # the real SQL integration tests above; no row is used as authority.
        fixture = demand_tests.ExperimentDemandTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = generation._ReadinessScope(fixture.coordinator.db_path.resolve())
        original.row = dict(fixture.generation)
        case = Mock(_source_readiness=None)
        @contextmanager
        def opened(path):
            self.assertEqual(path, fixture.coordinator.db_path.resolve())
            yield original
            original.closed = True
        with patch.object(generation, "daily_locations", return_value=(fixture.scope, fixture.fixture.directory)), \
                patch.object(generation, "readiness_scope", side_effect=opened), \
                patch.object(generation, "revalidate_scoped_readiness") as validate:
            captured = provider._capture_generation(case)
        self.assertEqual(json.loads(captured), fixture.generation)
        self.assertIs(case._source_readiness, original)
        validate.assert_called_once_with(fixture.coordinator.db_path.resolve(), expected_generation=fixture.generation)
        self.assertTrue(original.closed)

    def test_source_close_failure_does_not_return_pins_or_discard_owner(self):
        fixture = demand_tests.ExperimentDemandTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = generation._ReadinessScope(fixture.coordinator.db_path.resolve())
        original.row = dict(fixture.generation)
        case = Mock(_source_readiness=None)
        failure = OSError("synthetic source owner close unknown")
        @contextmanager
        def opened(path):
            yield original
            original.error = failure
            raise failure
        with patch.object(generation, "daily_locations", return_value=(fixture.scope, fixture.fixture.directory)), \
                patch.object(generation, "readiness_scope", side_effect=opened), \
                patch.object(generation, "revalidate_scoped_readiness"):
            with self.assertRaises(OSError):
                provider._capture_generation(case)
        self.assertIs(case._source_readiness, original)
        self.assertIs(original.error, failure)


if __name__ == "__main__":
    unittest.main()
