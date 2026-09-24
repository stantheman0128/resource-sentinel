"""Actual isolated parent SQL publication; explicitly synthetic native readiness.

No process creation or control. These tests establish original scope custody and
real daily accounting behavior, not a Windows capability or producer gate.
"""
from contextlib import closing, contextmanager
from dataclasses import replace
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation
from sentinel.adaptive import experiment_demand as demand
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import experiment_host_scope as scope
from sentinel.adaptive import experiment_host_creation as creation
from sentinel.adaptive.contracts import ResourceDemand
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.store import LifecycleStore
from tests import test_adaptive_experiment_demand as demand_fixture
from tests import test_adaptive_managed_admission as managed_fixture
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_identity import Backend


class ProductionExperimentScopeTests(unittest.TestCase):
    MEMBER_ROLES = ("supervisor",)
    MEMBER_DEMAND = ResourceDemand(.01, 1 << 20, 1 << 20, 0)

    def setUp(self):
        for registry in ("_READINESS_SCOPES", "_ABSENCE_SCOPES"):
            override = patch.object(daily_generation, registry, {})
            override.start()
            self.addCleanup(override.stop)
        self.backend = Backend()
        self.backend.value = IDENTITY
        self.process = VerifiedProcess(self.backend, 701, IDENTITY)
        self.addCleanup(self.process.close)
        self.fixture = demand_fixture.ExperimentDemandTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(managed_fixture, "FakeCurrentProcess", return_value=self.process):
            self.fixture.setUp()
        self.isolated = self.fixture.scope / "isolated.db"
        self.store = LifecycleStore(self.isolated, policy_provider=self.fixture.fixture.policy)
        initial_guard = self.store._policy.prepare(self.process.identity.logon_id)
        with self.store._policy.hold(initial_guard):
            instance = initial_guard.binding.instance_id
        info = self.isolated.stat()
        spec = ledger.HostScopeSpec(str(uuid4()), "S2", str(self.isolated),
                                   (info.st_dev, info.st_ino), instance)
        self.members = tuple(ledger.MemberClaim(str(uuid4()),
            "workload" if role == "workload" else "infrastructure", role,
            self.MEMBER_DEMAND) for role in self.MEMBER_ROLES)
        self.claim = self.members[0]
        self.plan = scope.ProductionExperimentPlan(spec, self.members)
        declaration = demand.ExperimentDeclaration(str(uuid4()), "S2", self.plan.sha256,
                                                  ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        self.demand = demand.DailyExperimentDemand.capture(declaration, self.fixture.scope)
        self.fixture.owners.append(self.demand)
        self.assertTrue(self.fixture.coordinator.admit_experiment(self.demand)["allowed"])
        self.events = []

        @contextmanager
        def readiness(paths, *, absent_paths):
            self.events.append(("readiness", paths, absent_paths))
            self.assertIsNotNone(self.demand._native_preparation)
            with daily_generation.readiness_scopes(paths, absent_paths=absent_paths):
                yield
            self.events.append(("readiness_closed",))

        self.proof = SimpleNamespace(readiness_scopes=readiness,
            readiness_scope=daily_generation.readiness_scope,
            revalidate_scoped_readiness=Mock(), prepare_connection=daily_generation.prepare_connection,
            revalidate_transaction=daily_generation.revalidate_transaction)
        for override in (patch.object(scope, "daily_generation", self.proof),
                         patch.object(ledger, "daily_generation", self.fixture.proof)):
            override.start()
            self.addCleanup(override.stop)
        self.addCleanup(self.remove_scope)

    def remove_scope(self):
        scope._OWNERS.pop(self.plan.spec.scope_id, None)
        ledger._ORIGINALS.pop(self.demand.declaration.experiment_id, None)

    def prepare(self):
        return scope.ProductionExperimentScope.prepare(self.demand, self.plan)

    def test_original_parent_registers_before_acquisition_and_partitions_one_daily_allocation(self):
        before = self.fixture.assert_retained(self.demand)
        owner = self.prepare()
        self.assertIs(self.demand._native_preparation, owner)
        self.assertIs(owner.registered_scope.preparation, owner)
        self.assertEqual(self.events[0][0], "readiness")
        self.assertEqual(self.events[-1], ("readiness_closed",))
        result = owner.reserve_member(self.claim)
        self.assertEqual(result["member_id"], self.claim.member_id)
        self.assertEqual(json.loads(result["demand_json"]), self.claim.requested.to_dict())
        self.assertEqual(self.fixture.assert_retained(self.demand), before)
        self.assertEqual(owner._sql_attempts, [])
        self.assertIsNone(owner._guard)
        self.assertEqual(self.backend.closed, [])
        with self.assertRaisesRegex(scope.ProductionScopeError, "original_scope_occupied"):
            self.prepare()

    def test_changed_plan_is_refused_before_a_preparation_is_registered(self):
        different = replace(self.plan, members=(replace(self.claim, role="observer"),))
        with self.assertRaisesRegex(scope.ProductionScopeError, "declared_plan_mismatch"):
            scope.ProductionExperimentScope.prepare(self.demand, different)
        self.assertIsNone(self.demand._native_preparation)
        self.assertEqual(self.events, [])

    def test_copied_member_is_not_the_original_declared_operation(self):
        owner = self.prepare()
        with self.assertRaisesRegex(scope.ProductionScopeError, "declared_original_member_required"):
            owner.reserve_member(replace(self.claim))
        self.assertEqual(self.fixture.rows(ledger.MEMBERS_TABLE), [])

    def test_original_replay_does_not_add_a_partition_or_revise_the_registry(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        before = self.fixture.rows("adaptive_runtime")
        registered = owner.registered_scope
        self.assertIs(owner.reconcile_preparation(), owner)
        owner.reserve_member(self.claim)
        self.assertIs(owner.registered_scope, registered)
        self.assertEqual(self.fixture.rows("adaptive_runtime"), before)
        self.assertEqual(len(self.fixture.rows(ledger.MEMBERS_TABLE)), 1)

    def test_sealing_blocks_new_work_and_is_not_daily_completion(self):
        owner = self.prepare()
        owner.seal_new_work()
        with self.assertRaisesRegex(scope.ProductionScopeError, "declared_original_member_required"):
            owner.reserve_member(self.claim)
        with self.assertRaises(demand.ExperimentDemandError):
            self.demand.seal_without_native()
        self.fixture.assert_retained(self.demand)
        self.assertFalse(self.demand._closed)
        self.assertEqual(self.backend.closed, [])

    def test_native_parent_replacement_cannot_publish(self):
        owner = self.prepare()
        original = self.process._handle
        self.process._handle = 999
        try:
            with self.assertRaisesRegex(scope.ProductionScopeError, "original_parent_changed"):
                owner.reserve_member(self.claim)
        finally:
            self.process._handle = original
        self.assertEqual(self.fixture.rows(ledger.MEMBERS_TABLE), [])
        self.assertEqual(self.backend.closed, [])

    def test_sql_publication_failure_retains_original_and_reconciles_without_native_retry(self):
        actual = ledger.declare_scope_locked
        def lost_reply(*args, **kwargs):
            actual(*args, **kwargs)
            raise RuntimeError("synthetic body failure before COMMIT")
        with patch.object(ledger, "declare_scope_locked", side_effect=lost_reply):
            with self.assertRaisesRegex(RuntimeError, "synthetic body failure") as raised:
                self.prepare()
        owner = raised.exception.production_scope_owner
        self.assertIs(self.demand._native_preparation, owner)
        self.assertIs(owner.registered_scope, ledger._ORIGINALS[self.demand.declaration.experiment_id])
        self.assertIsNone(owner._guard)
        self.assertFalse(owner._guard_unknown)
        self.assertTrue(all(item.closed for item in owner._sql_attempts))
        self.assertIs(owner.reconcile_preparation(), owner)
        self.assertEqual(len(self.fixture.rows(ledger.SCOPES_TABLE)), 1)
        self.assertEqual(self.backend.closed, [])

    def test_parent_sql_never_nests_across_the_two_ledgers(self):
        owner = self.prepare()
        with owner._operation():
            with owner._sql(self.demand.ledger_path):
                with self.assertRaisesRegex(scope.ProductionScopeError, "nested_sql"):
                    with owner._sql(self.isolated):
                        self.fail("foreign transaction was opened")

    def test_readiness_cleanup_failure_retains_parent_and_refuses_another_operation(self):
        owner = self.prepare()
        @contextmanager
        def unknown(*args, **kwargs):
            yield
            raise OSError("synthetic readiness close acknowledgement lost")
        with patch.object(self.proof, "readiness_scopes", unknown):
            with self.assertRaises(OSError):
                owner.reserve_member(self.claim)
        with self.assertRaisesRegex(scope.ProductionScopeError, "operation_custody_unsettled"):
            owner.reserve_member(self.claim)
        self.fixture.assert_retained(self.demand)
        self.assertIs(self.demand._native_preparation, owner)

    def test_actual_active_daily_group_selects_isolated_absence_then_restores_daily(self):
        # Actual schema, group/selector, POLICY and SQL; native readiness and
        # loaded-source attestation are explicit collaborators in this test.
        row = self.demand._original_generation_binding()
        with closing(sqlite3.connect(self.demand.ledger_path)) as conn:
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" + ",".join("?" for _ in row) + ")",
                         tuple(row.values()))
            daily_generation._install_triggers(conn)
            conn.commit()
        actual = self.proof.prepare_connection
        selected = []
        def observe(conn, *, role, db_path):
            original = daily_generation._READINESS_LOCAL.scope
            self.assertEqual(original.path, Path(db_path))
            selected.append((Path(db_path), original.row))
            return actual(conn, role=role, db_path=db_path)
        with patch.object(daily_generation, "_assert_daily_locations"), \
                patch.object(daily_generation, "verify_import_provenance"), \
                patch.object(daily_generation, "_prove_retained_owner_ready", return_value=None), \
                patch.object(daily_generation, "_revalidate_remote"), \
                patch.object(self.proof, "prepare_connection", side_effect=observe):
            owner = self.prepare()
            owner.reserve_member(self.claim)
        self.assertIn((self.isolated, None), selected)
        self.assertIn((self.demand.ledger_path, row), selected)
        self.assertTrue(owner._prepared)
        self.assertEqual(len(self.fixture.rows(ledger.MEMBERS_TABLE)), 1)

    def copied_isolated(self):
        replacement = self.isolated.with_name("copied-isolated.db")
        with closing(sqlite3.connect(self.isolated)) as source, \
                closing(sqlite3.connect(replacement)) as target:
            source.backup(target)
        self.assertNotEqual((replacement.stat().st_dev, replacement.stat().st_ino),
                            self.plan.spec.isolated_ledger_identity)
        return replacement

    def test_copied_isolated_between_parent_check_and_group_cannot_be_adopted(self):
        replacement = self.copied_isolated()
        original = self.isolated.with_name("original-isolated.db")
        readiness = self.proof.readiness_scopes
        @contextmanager
        def swap_before_group(*args, **kwargs):
            self.isolated.rename(original)
            replacement.rename(self.isolated)
            try:
                with readiness(*args, **kwargs):
                    yield
            finally:
                self.isolated.rename(replacement)
                original.rename(self.isolated)
        with patch.object(self.proof, "readiness_scopes", swap_before_group), \
                self.assertRaisesRegex(scope.ProductionScopeError, "original_ledger_changed") as raised:
            self.prepare()
        self.assertIs(raised.exception.owner, self.demand._native_preparation)
        self.assertFalse(self.demand._native_preparation._prepared)
        self.assertIsNone(self.demand._native_preparation.registered_scope)
        self.fixture.assert_retained(self.demand)

    def test_isolated_replacement_during_consumer_open_is_refused_before_begin(self):
        owner = self.prepare()
        replacement = self.copied_isolated()
        original = self.isolated.with_name("original-isolated.db")
        connect = sqlite3.connect
        swapped = []
        def replace_then_open(path, *args, **kwargs):
            if path == self.isolated.as_uri() + "?mode=rw":
                self.isolated.rename(original)
                replacement.rename(self.isolated)
                swapped.append(True)
            return connect(path, *args, **kwargs)
        try:
            with patch.object(scope.sqlite3, "connect", side_effect=replace_then_open), \
                    self.assertRaisesRegex(scope.ProductionScopeError, "original_ledger_changed"):
                owner.reconcile_preparation()
        finally:
            if swapped:
                self.isolated.rename(replacement)
                original.rename(self.isolated)
        self.assertEqual(swapped, [True])
        attempt = owner._sql_attempts[-1]
        self.assertTrue(attempt.closed)
        self.assertFalse(attempt.commit_entered)
        self.assertEqual(len(self.fixture.rows(ledger.SCOPES_TABLE)), 1)

    @contextmanager
    def synthetic_creation(self, owner, *, setup=None):
        # Fixed bootstrap/provider remain unimplemented. This command-only
        # seam exercises actual CreationAttempt and scope gates on a synthetic ABI.
        command = creation.ChildCommand(str(Path(sys._base_executable).resolve()),
                                        ("-I", "fixture-inert-child.py"), str(self.fixture.scope))
        entered = []
        def create(*args):
            entered.append(args)
            return 0  # documented FALSE with untouched original output
        def initialize(backend):
            backend.kernel = SimpleNamespace(CreateProcessW=create)
            if setup is not None:
                setup()
        with patch.object(owner, "_inert_command", return_value=command), \
                patch.object(creation._NativeCreation, "__init__", initialize):
            yield entered

    def test_pre_reserved_member_hold_cannot_start_native_creation(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        conn = self.fixture.fixture.conn()
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
        conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',"
            "hold_reason='reservation_expired',state_revision=state_revision+1 WHERE execution_id=?",
            (self.demand._snapshot.execution_id,))
        before = self.fixture.assert_retained(self.demand)
        owner.reserve_member(self.claim)  # exact committed replay stays available
        with self.synthetic_creation(owner) as entered, \
                self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
            owner.create_actor(self.claim)
        self.assertEqual(entered, [])
        self.assertEqual(owner._attempts, {})
        self.assertEqual(self.fixture.assert_retained(self.demand), before)

    def test_pre_reserved_member_sql_expiry_cannot_start_native_creation(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        expiration = self.fixture.rows("reservations")[0]["expires_at"]
        sql = owner._sql_owned
        @contextmanager
        def expired(*args, **kwargs):
            with sql(*args, **kwargs) as conn:
                if args[0] == self.demand.ledger_path:
                    conn.create_function("julianday", 1, lambda _: (expiration + 1) / 86400 + 2440587.5)
                yield conn
        with patch.object(owner, "_sql_owned", expired), self.synthetic_creation(owner) as entered:
            owner.reserve_member(self.claim)
            with self.assertRaisesRegex(ledger.HostLedgerError, "no_new_work"):
                owner.create_actor(self.claim)
        self.assertEqual(entered, [])
        self.assertEqual(owner._attempts, {})
        self.assertEqual(self.fixture.rows("reservations")[0]["expires_at"], expiration)

    def test_backend_setup_consumes_original_monotonic_lease_despite_backward_wall(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        expiration = self.fixture.rows("reservations")[0]["expires_at"]
        mono = [100]
        self.fixture.clock.return_value = expiration - 1
        def consume():
            mono[0] += 2_000_000_000
            self.fixture.clock.return_value = expiration - 100
        with patch.object(scope.time, "monotonic_ns", side_effect=lambda: mono[0]), \
                self.synthetic_creation(owner, setup=consume) as entered, \
                self.assertRaisesRegex(scope.ProductionScopeError, "original_creation_expired"):
            owner.create_actor(self.claim)
        self.assertEqual(entered, [])
        attempt = owner._attempts[self.claim.member_id]
        self.assertFalse(attempt._create_entered)
        self.assertEqual(owner._creation_bounds[self.claim.member_id][0].daily_expires_at, expiration)
        with self.assertRaisesRegex(scope.ProductionScopeError, "new_declared_actor_required"):
            owner.create_actor(self.claim)
        self.fixture.assert_retained(self.demand)

    def test_forward_wall_expiry_refuses_create_without_resetting_monotonic_bound(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        expiration = self.fixture.rows("reservations")[0]["expires_at"]
        self.fixture.clock.return_value = expiration - 1
        def consume():
            self.fixture.clock.return_value = expiration + 1
        with patch.object(scope.time, "monotonic_ns", return_value=100), \
                self.synthetic_creation(owner, setup=consume) as entered, \
                self.assertRaisesRegex(scope.ProductionScopeError, "original_creation_expired"):
            owner.create_actor(self.claim)
        self.assertEqual(entered, [])
        self.assertEqual(owner._creation_bounds[self.claim.member_id][1][-1], expiration)

    def test_backend_setup_isolated_replacement_refuses_final_native_entry(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        replacement = self.copied_isolated()
        original = self.isolated.with_name("original-isolated.db")
        swapped = []
        def replace():
            self.isolated.rename(original)
            replacement.rename(self.isolated)
            swapped.append(True)
        try:
            with self.synthetic_creation(owner, setup=replace) as entered, \
                    self.assertRaisesRegex(scope.ProductionScopeError, "isolated_ledger_changed"):
                owner.create_actor(self.claim)
        finally:
            if swapped:
                self.isolated.rename(replacement)
                original.rename(self.isolated)
        self.assertEqual(swapped, [True])
        self.assertEqual(entered, [])
        attempt = owner._attempts[self.claim.member_id]
        self.assertFalse(attempt._create_entered)
        self.assertEqual(self.fixture.rows(ledger.ACTORS_TABLE), [])
        self.fixture.assert_retained(self.demand)

    def test_live_original_allocation_reaches_single_synthetic_create(self):
        owner = self.prepare()
        owner.reserve_member(self.claim)
        before = self.fixture.assert_retained(self.demand)
        with self.synthetic_creation(owner) as entered, \
                self.assertRaisesRegex(creation.CreationCustodyError, "create_failed"):
            owner.create_actor(self.claim)
        self.assertEqual(len(entered), 1)
        attempt = owner._attempts[self.claim.member_id]
        self.assertTrue(attempt.never_created)
        self.assertIs(attempt._scope_original, owner)
        self.assertEqual(owner._creation_bounds[self.claim.member_id][0].member_id, self.claim.member_id)
        self.assertEqual(self.fixture.assert_retained(self.demand), before)


if __name__ == "__main__":
    unittest.main()
