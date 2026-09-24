"""Provider through original scope/release; real isolated SQL, fake native APIs.

Preparation, original Job/launcher custody, completion, receipt and daily release
are actual implementations. Process creation, IPC, Win32 and source attestation
are explicit fixtures. This does not launch a workload or prove a native gate.
"""
from contextlib import closing, ExitStack
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.capability_evidence import LiveCapabilityContext
from sentinel.adaptive.experiment_scope import ExperimentNativeScope, NativeScopeCompletion
from tests import test_adaptive_experiment_release_native as fixtures
from tests.windows import adaptive_s1_provider as provider
from tests.windows.adaptive_scope_launch import ScopeLaunch


class ProviderOriginalScopeTests(unittest.TestCase):
    def test_original_preparation_completion_and_daily_release_then_read_only_replay(self):
        fixture = fixtures.ExperimentNativeReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        demand_fixture = fixture.fixture
        identity = fixture.guardian.identity
        context = LiveCapabilityContext("c" * 64, 10, 0, 26100, 12, 1, "4095",
            identity.logon_id, 1, 0, "3.13.0", 64, "d" * 64, False, "e" * 64)
        with ExitStack() as stack:
            stack.enter_context(patch.object(provider, "_capture_generation",
                side_effect=lambda case: provider._canonical(demand_fixture.generation)))
            stack.enter_context(patch("sentinel.adaptive.policy.NativePolicyProvider",
                return_value=demand_fixture.fixture.policy))
            stack.enter_context(patch("sentinel.coordinator._default_pid_identity",
                side_effect=lambda pid: (True,
                    (identity.created_filetime_100ns - 116444736000000000) / 10_000_000)
                    if pid == identity.pid else (None, 0.0)))
            stack.enter_context(patch.object(provider, "_base_python",
                return_value=Path(sys.executable).resolve()))
            owner = provider.S1SerialProvider(demand_fixture.scope, context)
            self.addCleanup(provider._PROVIDERS.pop, id(owner), None)
            case = owner.start_case("round")
            demand_fixture.owners.append(case.demand)
            with patch.object(ScopeLaunch, "create_inert", autospec=True,
                    side_effect=fixture.create_wrapper) as create_wrapper:
                try:
                    result = case.poll_admission()
                finally:
                    if case.scope is not None:
                        fixture.scopes.append(case.scope)
            self.assertTrue(result["allowed"])
            self.assertIs(type(case.scope), ExperimentNativeScope)
            self.assertIs(case.scope.demand, case.demand)
            self.assertTrue(case.scope._registered)
            self.assertEqual(create_wrapper.call_count, 1)
            self.assertEqual(len(fixture.rows("reservations")), 1)
            self.assertIsNone(case.completion)
            self.assertIs(case.scope.guardian, fixture.guardian)

            # Cleanup validates the real persisted original generation. Only
            # location/import attestation is synthetic; no readiness is minted.
            with closing(sqlite3.connect(fixture.db)) as conn:
                row = demand_fixture.generation
                conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                    key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
                conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                    ",".join("?" for _ in row) + ")", tuple(row.values()))
                generation._install_triggers(conn)
                conn.commit()
            stack.enter_context(patch.object(generation, "_assert_daily_locations"))
            stack.enter_context(patch.object(generation, "verify_import_provenance"))
            stack.enter_context(patch.object(generation, "_prove_retained_owner_ready",
                side_effect=AssertionError("cleanup requested new readiness")))
            try:
                cleaned = case.recover_once()
            finally:
                if case.release_operation is not None:
                    fixture.operations.append(case.release_operation)
            self.assertTrue(cleaned["released"])
            self.assertIs(type(case.completion), NativeScopeCompletion)
            self.assertIs(case.completion.owner, case.scope)
            self.assertIs(case.release_operation.completion, case.completion)
            self.assertTrue(case.scope._native_closed)
            self.assertTrue(case.demand._closed)
            self.assertEqual(case.errors, [])
            self.assertEqual(fixture.rows("reservations"), [])
            self.assertEqual(fixture.guardian_backend.closed, [1700])
            self.assertEqual(fixture.exchange_operations, ["seal", "drain"])
            self.assertEqual(owner.completed_cases, (case,))
            with patch.object(case.coordinator, "release_experiment",
                    side_effect=AssertionError("completed provider repeated release")), \
                    patch.object(case.scope, "close_native",
                    side_effect=AssertionError("completed provider repeated native cleanup")):
                self.assertEqual(owner.recover_once(), cleaned)


if __name__ == "__main__":
    unittest.main()
