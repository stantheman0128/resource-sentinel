"""Synthetic source tests for real SQLite demand retention; no native evidence.

Only generation/native identity readiness is modeled. Capacity admission, queue,
reservation, managed lifecycle, expiry, triggers and commit custody are actual
production implementations in isolated temporary directories.
"""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import experiment_demand as bridge
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import ResourceDemand
from sentinel.coordinator import Coordinator
from tests import test_adaptive_managed_admission as managed_tests
from tests.test_adaptive_coordinator import CONFIG, NOW, request, status


class ExperimentDemandTests(unittest.TestCase):
    def setUp(self):
        self.fixture = managed_tests.ManagedAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.coordinator = self.fixture.coordinator
        self.scope_temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.scope_temp.cleanup)
        self.scope = Path(self.scope_temp.name)
        config_bytes = json.dumps(CONFIG, sort_keys=True).encode()
        self.coordinator.db_path.with_name("config.json").write_bytes(config_bytes)
        self.generation = dict(generation=str(uuid4()), state="ACTIVE",
            source_digest="a" * 64, config_digest=hashlib.sha256(config_bytes).hexdigest())
        # This explicitly synthetic collaborator does not install a generation
        # or bypass the production generation implementation at other call sites.
        self.proof = SimpleNamespace(
            daily_locations=Mock(return_value=(self.scope, self.fixture.directory)),
            _assert_daily_locations=Mock(),
            prepare_connection=Mock(side_effect=lambda *a, **k: self.generation["generation"]),
            read_generation=Mock(side_effect=lambda *a: dict(self.generation)))
        override = patch.object(bridge, "daily_generation", self.proof)
        override.start()
        self.addCleanup(override.stop)
        clock = patch("sentinel.coordinator.time.time", return_value=NOW)
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.publish_status()
        self.owners = []
        self.addCleanup(self.remove_synthetic_owners)

    def remove_synthetic_owners(self):
        for owner in self.owners:
            key = owner._immutable[0].experiment_id
            if bridge._RETAINED.get(key) is owner:
                del bridge._RETAINED[key]

    def publish_status(self, *, now=NOW, **kwargs):
        self.clock.return_value = now
        self.coordinator.db_path.with_name("status.json").write_text(
            json.dumps(status(now=now, **kwargs)), encoding="utf-8")

    def capture(self, requested=None):
        declaration = bridge.ExperimentDeclaration(str(uuid4()), "S1", "b" * 64,
            requested or ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        owner = bridge.DailyExperimentDemand.capture(declaration, self.scope)
        self.owners.append(owner)
        return owner

    def rows(self, table):
        return [dict(row) for row in self.fixture.conn().execute("SELECT * FROM " + table)]

    def assert_retained(self, owner):
        self.assertEqual(self.fixture.counts()[1:], (1, 1))
        source, execution, metadata = (self.rows(table)[0]
            for table in ("reservations", "managed_executions", bridge.TABLE))
        declared = owner._immutable[0].requested.to_dict()
        self.assertEqual(source["cpu_units"], declared["cpu_units"])
        self.assertEqual(source["physical_bytes"], declared["physical_bytes"])
        self.assertEqual(source["commit_bytes"], declared["commit_bytes"])
        self.assertEqual(source["io_slots"], declared["io_slots"])
        self.assertEqual(json.loads(metadata["demand_json"]), declared)
        for key, value in declared.items():
            self.assertEqual(execution["requested_" + key], value)
            self.assertEqual(execution["floor_" + key], value)
        return source, execution, metadata

    def test_admission_uses_one_actual_capacity_row_and_never_authorizes_native_scope(self):
        owner = self.capture()
        result = self.coordinator.admit_experiment(owner)
        self.assertTrue(result["allowed"])
        self.assertFalse(result["native_scope_authorized"])
        self.assertFalse(result["launch_authorized"])
        source, execution, metadata = self.assert_retained(owner)
        self.assertEqual((metadata["execution_id"], metadata["reservation_id"]),
            (execution["execution_id"], source["id"]))
        self.assertEqual(metadata["source_generation"], self.generation["generation"])
        self.assertNotIn(owner._admission._claim_token, json.dumps(result))
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "scope_binding_unavailable") as raised:
            owner.require_native_scope()
        self.assertIs(raised.exception.owner, owner)

    def test_public_route_cannot_accept_injected_status_config_or_clock(self):
        owner = self.capture()
        for kwargs in ({"status": status()}, {"config": CONFIG}, {"now": NOW}):
            with self.subTest(kwargs=next(iter(kwargs))), self.assertRaises(TypeError):
                self.coordinator.admit_experiment(owner, **kwargs)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_actual_daily_stale_publication_cannot_grant_capacity(self):
        owner = self.capture()
        self.clock.return_value = NOW + 600
        result = self.coordinator.admit_experiment(owner)
        self.assertFalse(result["allowed"])
        self.assertEqual(self.fixture.counts(), (1, 0, 0))

    def test_daily_mode_must_stay_off(self):
        owner = self.capture()
        self.fixture.conn().execute("UPDATE adaptive_runtime SET mode='canary'")
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "daily_off_required"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_daily_commit_denial_queues_same_original_request_then_admits(self):
        owner = self.capture()
        self.publish_status(commit=94)
        denied = self.coordinator.admit_experiment(owner)
        self.assertEqual(denied["reason"], "commit_capacity")
        self.assertEqual(self.fixture.counts(), (1, 0, 0))
        self.publish_status(now=NOW + 1)
        result = self.coordinator.admit_experiment(owner)
        self.assertTrue(result["allowed"])
        self.assertEqual(result["request_key"], denied["request_key"])
        self.assert_retained(owner)

    def test_exact_replay_keeps_reservation_deadline_and_metadata_unchanged(self):
        owner = self.capture()
        first = self.coordinator.admit_experiment(owner)
        before = self.assert_retained(owner)
        self.publish_status(now=NOW + 1)
        replay = self.coordinator.admit_experiment(owner)
        self.assertTrue(replay["reused"])
        self.assertEqual(replay["reservation_id"], first["reservation_id"])
        self.assertEqual(before, self.assert_retained(owner))

    def test_metadata_failure_rolls_back_all_capacity_and_queue_mutations(self):
        owner = self.capture()
        conn = self.fixture.conn()
        conn.execute("BEGIN IMMEDIATE")
        bridge._schema(conn, create=True)
        conn.execute("COMMIT")
        conn.execute("CREATE TRIGGER injected_metadata_failure BEFORE INSERT ON " + bridge.TABLE +
            " BEGIN SELECT RAISE(ABORT,'injected_metadata_failure'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected_metadata_failure"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))
        self.assertEqual(self.rows(bridge.TABLE), [])
        self.assertTrue(owner._admission._submitted)

    def test_actual_commit_ack_loss_retains_original_guard_and_full_demand(self):
        owner = self.capture()
        original = self.coordinator._commit_admission
        def lose_ack(conn, transaction):
            original(conn, transaction)
            raise OSError("synthetic_admission_ack_lost")
        with patch.object(self.coordinator, "_commit_admission", side_effect=lose_ack):
            with self.assertRaisesRegex(OSError, "synthetic_admission_ack_lost"):
                self.coordinator.admit_experiment(owner)
        guard = owner._admission._submission_guard
        self.assertIsNotNone(guard)
        before = self.assert_retained(owner)
        # Reconcile only the original outstanding guard. Its native release
        # was positive in this fixture; a lost SQL ACK is not permission to
        # substitute a new admission owner or a second allocation.
        settle = self.coordinator._settle_managed_submission
        observed = []
        def retain_then_settle(context):
            observed.append((context, context._submission_guard))
            return settle(context)
        with patch.object(self.coordinator, "_settle_managed_submission", side_effect=retain_then_settle):
            replay = self.coordinator.admit_experiment(owner)
        self.assertTrue(replay["allowed"])
        self.assertTrue(replay["reused"])
        self.assertEqual(observed, [(owner._admission, guard)])
        self.assertIsNone(owner._admission._submission_guard)
        self.assertEqual(before, self.assert_retained(owner))
        self.assertIs(bridge._RETAINED[owner.declaration.experiment_id], owner)

    def test_normal_admission_and_cancel_routes_cannot_consume_bound_context(self):
        owner = self.capture()
        inner = owner._admission
        before = inner._claim_token
        with self.assertRaisesRegex(TypeError, "experiment_original_admission_route_required"):
            self.coordinator.admit_managed(inner, status(), config=CONFIG, now=NOW)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "experiment_native_cleanup_unverified"):
            self.coordinator.cancel_managed(inner, now=NOW)
        with self.assertRaisesRegex(TypeError, "experiment_original_admission_route_required"):
            self.coordinator._admit(inner.snapshot().request, status(), config=CONFIG, now=NOW,
                managed=inner.snapshot(), managed_context=inner)
        self.assertEqual(inner._claim_token, before)
        self.assertFalse(inner._cancel_sealed)

    def test_bound_launch_mac_prepare_payload_cancel_and_close_are_fenced(self):
        owner = self.capture()
        inner, snap = owner._admission, owner._snapshot
        before = inner._claim_token
        actions = (
            inner.launch_claim_token, inner.mark_prepare_attempted, inner.close,
            lambda: inner.verify_launch_payload(command="x", cwd=str(self.scope)),
            lambda: inner._ipc_mac(b"x", execution_id=snap.execution_id,
                spec_hash=snap.spec_hash, caller=snap.wrapper_identity),
            lambda: inner.cancel_reserved(self.coordinator.db_path, reservation_id="x", expected_revision=0))
        for action in actions:
            with self.subTest(action=action), self.assertRaises(ManagedAdmissionUnavailable):
                action()
        self.assertEqual(inner._claim_token, before)
        self.assertFalse(inner._prepare_attempted)
        self.assertFalse(inner._claim_exported)
        self.assertFalse(inner._closed)

    def test_original_declaration_cannot_be_replaced_before_submission_or_while_queued(self):
        for queued in (False, True):
            owner = self.capture()
            if queued:
                self.publish_status(commit=94)
                self.coordinator.admit_experiment(owner)
            owner.declaration = replace(owner.declaration, scope_sha256="c" * 64,
                requested=ResourceDemand(.5, 2 << 30, 3 << 30, 0))
            with self.assertRaisesRegex(bridge.ExperimentDemandError, "original_binding_changed"):
                self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts()[1:], (0, 0))

    def test_only_one_experiment_is_admitted_without_changing_user_exemptions(self):
        first, second = self.capture(), self.capture()
        self.assertTrue(self.coordinator.admit_experiment(first)["allowed"])
        result = self.coordinator.admit_experiment(second)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "experiment_scope_occupied")
        self.assertEqual(self.fixture.counts(), (1, 1, 1))
        self.assert_retained(first)

    def test_old_sql_connection_cannot_delete_release_claim_or_reduce_demand(self):
        old = self.fixture.conn()
        owner = self.capture()
        self.coordinator.admit_experiment(owner)
        statements = (
            "DELETE FROM reservations", "DELETE FROM managed_executions",
            "DELETE FROM " + bridge.TABLE,
            "UPDATE " + bridge.TABLE + " SET revision=revision",
            "UPDATE reservations SET physical_bytes=0,writer_protocol=1,writer_revision=writer_revision+1",
            "UPDATE managed_executions SET floor_commit_bytes=0",
            "UPDATE managed_executions SET state='FINISHED'",
            "UPDATE managed_executions SET state='CANCELLED_BEFORE_START'",
            "UPDATE managed_executions SET state='START_FAILED'",
            "UPDATE managed_executions SET state='PREPARED'",
            "UPDATE managed_executions SET claim_consumed=1",
            "UPDATE managed_executions SET root_pid=123,root_created_filetime_100ns='999'")
        for statement in statements:
            with self.subTest(sql=statement), self.assertRaises(sqlite3.IntegrityError):
                old.execute(statement)
            self.assert_retained(owner)

    def test_expiry_and_owner_death_keep_full_floor_and_block_other_real_admission(self):
        owner = self.capture(ResourceDemand(.5, 4 << 30, 6 << 30, 0))
        self.coordinator.admit_experiment(owner)
        self.coordinator.pid_identity = lambda pid: (False, 0.0)
        later = self.rows("reservations")[0]["expires_at"] + 1
        denied = self.coordinator.admit(request(991, ram=1), status(now=later, used_ram=54),
            config=CONFIG, now=later)
        self.assertFalse(denied["allowed"])
        self.assertIn(denied["reason"], {"ram_capacity", "ram_safety"})
        _, execution, _ = self.assert_retained(owner)
        self.assertEqual(execution["state"], "UNCERTAIN_HOLD")
        self.assertEqual(execution["hold_reason"], "reservation_expired")

    def test_legacy_release_cannot_free_experiment_capacity(self):
        owner = self.capture()
        self.coordinator.admit_experiment(owner)
        self.assertEqual(self.coordinator.release(owner_pid=os.getpid(), now=NOW + 1), 0)
        self.assert_retained(owner)

    def test_expired_replay_is_held_not_renewed(self):
        owner = self.capture()
        self.coordinator.admit_experiment(owner)
        allocation = self.rows("reservations")[0]
        self.publish_status(now=allocation["expires_at"] + 1)
        held = self.coordinator.admit_experiment(owner)
        self.assertFalse(held["allowed"])
        self.assertEqual(held["reason"], "managed_execution_held")
        self.assertEqual(allocation, self.rows("reservations")[0])
        self.assert_retained(owner)

    def test_unknown_empty_table_definition_is_not_repaired(self):
        conn = self.fixture.conn()
        conn.execute(bridge._TABLE_SQL.replace("CHECK(schema_version=1)", ""))
        owner = self.capture()
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "metadata_schema_unknown"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_same_named_ineffective_trigger_is_unknown_even_with_no_rows(self):
        conn = self.fixture.conn()
        conn.execute("BEGIN IMMEDIATE")
        bridge._schema(conn, create=True)
        conn.execute("COMMIT")
        conn.execute("DROP TRIGGER experiment_reservation_delete_guard")
        conn.execute("CREATE TRIGGER experiment_reservation_delete_guard BEFORE DELETE ON reservations BEGIN SELECT 1; END")
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "metadata_guards_unknown"):
            self.coordinator.admit_experiment(self.capture())
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_missing_metadata_cannot_be_repaired_on_an_admitted_replay(self):
        owner = self.capture()
        self.coordinator.admit_experiment(owner)
        conn = self.fixture.conn()
        # Explicit corruption fixture; the normal DELETE is durably fenced.
        conn.execute("DROP TRIGGER experiment_metadata_delete_guard")
        conn.execute("DELETE FROM " + bridge.TABLE)
        conn.execute(bridge._TRIGGER_SQL["experiment_metadata_delete_guard"])
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "replay_metadata_unverified"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts()[1:], (1, 1))

    def test_source_generation_change_and_config_change_refuse_before_writes(self):
        owner = self.capture()
        self.publish_status(commit=94)
        self.coordinator.admit_experiment(owner)
        self.generation["generation"] = str(uuid4())
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "daily_generation_changed"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.fixture.counts(), (1, 0, 0))
        other = self.capture()
        self.coordinator.db_path.with_name("config.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "daily_config_changed"):
            self.coordinator.admit_experiment(other)
        self.assertEqual(self.fixture.counts(), (1, 0, 0))

    def test_missing_live_generation_cannot_grant_capacity(self):
        self.proof.prepare_connection.side_effect = None
        self.proof.prepare_connection.return_value = None
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "daily_generation_unverified"):
            self.coordinator.admit_experiment(self.capture())
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_isolated_control_coordinator_cannot_replace_actual_daily_provider(self):
        owner = self.capture()
        other = Coordinator(self.scope, policy_provider=self.fixture.policy)
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "daily_coordinator_required"):
            other.admit_experiment(owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_failed_native_readiness_cleanup_quarantines_same_original_owner(self):
        owner = self.capture()
        error = OSError("synthetic_readiness_close_unknown")
        native_owner = object()
        error.daily_readiness_current_process = native_owner
        self.proof.prepare_connection.side_effect = error
        with self.assertRaises(OSError):
            self.coordinator.admit_experiment(owner)
        count = self.proof.prepare_connection.call_count
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "original_binding_changed"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.proof.prepare_connection.call_count, count)
        self.assertIs(owner._quarantine[1], error)
        self.assertIs(error.daily_readiness_current_process, native_owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_later_coordinator_readiness_error_retains_nested_native_custody(self):
        owner = self.capture()
        cause = OSError("synthetic_later_native_close_unknown")
        cause.daily_readiness_current_process = object()
        error = RuntimeError("synthetic_readiness_failed")
        error._daily_readiness_cause = cause
        with patch.object(self.coordinator, "_cleanup_observations", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "synthetic_readiness_failed"):
                self.coordinator.admit_experiment(owner)
        count = self.proof.prepare_connection.call_count
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "original_binding_changed"):
            self.coordinator.admit_experiment(owner)
        self.assertEqual(self.proof.prepare_connection.call_count, count)
        self.assertIs(owner._quarantine[1], error)
        self.assertIs(error.experiment_demand_owner, owner)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_unknown_sql_close_cannot_open_a_replacement_preparation(self):
        owner = self.capture()
        actual_connect = sqlite3.connect
        connections = []
        class UncertainClose(sqlite3.Connection):
            attempts = 0
            def close(self):
                self.attempts += 1
                raise OSError("synthetic_sql_close_unknown")
        def connect(*args, **kwargs):
            kwargs["factory"] = UncertainClose
            conn = actual_connect(*args, **kwargs)
            connections.append(conn)
            return conn
        with patch.object(bridge.sqlite3, "connect", side_effect=connect):
            with self.assertRaisesRegex(OSError, "synthetic_sql_close_unknown"):
                self.coordinator.admit_experiment(owner)
            with self.assertRaisesRegex(bridge.ExperimentDemandError, "original_binding_changed"):
                self.coordinator.admit_experiment(owner)
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].attempts, 1)
        self.assertIs(owner._quarantine[0], connections[0])
        # This test's model never invoked a native unknown Close; retire only
        # its synthetic sqlite fixture through the known base implementation.
        sqlite3.Connection.close(connections[0])

    def test_later_coordinator_sql_close_retains_exact_connection_and_quarantines(self):
        owner = self.capture()
        class UncertainClose(sqlite3.Connection):
            attempts = 0
            def close(self):
                self.attempts += 1
                raise OSError("synthetic_coordinator_sql_close_unknown")
        conn = sqlite3.connect(self.coordinator.db_path, isolation_level=None, factory=UncertainClose)
        conn.row_factory = sqlite3.Row
        with patch.object(self.coordinator, "_connect", return_value=conn) as connect:
            with self.assertRaisesRegex(OSError, "synthetic_coordinator_sql_close_unknown") as raised:
                self.coordinator.admit_experiment(owner)
            with self.assertRaisesRegex(bridge.ExperimentDemandError, "original_binding_changed"):
                self.coordinator.admit_experiment(owner)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(conn.attempts, 1)
        self.assertIs(raised.exception._sentinel_connection_cleanup, conn)
        self.assertIs(owner._quarantine[1], raised.exception)
        sqlite3.Connection.close(conn)

    def test_unused_owner_can_close_after_positive_readonly_preparation(self):
        owner = self.capture()
        owner._prepare_submission(self.coordinator)
        owner.close_unsubmitted()
        self.assertTrue(owner._closed)
        self.assertEqual(self.fixture.process.closes, 1)
        self.assertNotIn(owner.declaration.experiment_id, bridge._RETAINED)
        self.assertEqual(self.fixture.counts(), (0, 0, 0))

    def test_admitted_or_queued_owner_cannot_use_unused_close(self):
        owner = self.capture()
        self.coordinator.admit_experiment(owner)
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "native_cleanup_unverified"):
            owner.close_unsubmitted()
        self.assert_retained(owner)
        queued = self.capture()
        self.coordinator.admit_experiment(queued)
        with self.assertRaisesRegex(bridge.ExperimentDemandError, "native_cleanup_unverified"):
            queued.close_unsubmitted()
        self.assertEqual(self.fixture.process.closes, 0)


if __name__ == "__main__":
    unittest.main()
