"""Legacy callers cannot reinterpret managed floors; all state is isolated."""
from dataclasses import replace
import json
import unittest
from unittest.mock import patch

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.store import SchemaVersionError
from sentinel.coordinator import Coordinator, ResourceRequest
from sentinel.maintainer import Maintainer, Task, Worker
from tests import test_adaptive_lifecycle as fixtures
from tests.test_adaptive_coordinator import CONFIG, status


NOW = fixtures.NOW
GIB = fixtures.GIB
BLOCKED = "managed_lifecycle_requires_resource_v2"


class LegacyManagedAccountingTests(unittest.TestCase):
    connection = fixtures.AdaptiveLifecycleTests.connection
    spec = fixtures.AdaptiveLifecycleTests.spec
    allocate = fixtures.AdaptiveLifecycleTests.allocate
    registered = fixtures.AdaptiveLifecycleTests.registered
    running = fixtures.AdaptiveLifecycleTests.running

    def setUp(self):
        fixtures.AdaptiveLifecycleTests.setUp(self)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        self.maintainer = Maintainer(self.directory)
        self.sequence = 0

    def request(self, *, ram=.5, cpu=.25, tool=None):
        self.sequence += 1
        return ResourceRequest(200, 1000.0, "fixture", "fixture command", "MEDIUM", "P2",
                               tool or f"legacy-{self.sequence}", cpu_units=cpu, ram_gib=ram, io_slots=0)

    def worker(self, name="legacy-local", *, remote=False):
        self.maintainer.upsert_worker(Worker(
            id=name, provider="fixture", failure_domain=name, capacity_pool=name, quota_domain=name,
            max_concurrency=32, state="AVAILABLE", automation_level="AUTOMATABLE", os="windows",
            capacity_ram_gib=64, allocatable_ram_gib=58, allocatable_cpu=8, allocatable_disk_gib=100,
            capabilities={"local": not remote, "adapter_ready": True},
            observed_at=NOW, probe_expires_at=NOW + 3600), now=NOW)

    def task(self, *, worker="legacy-local", name=None):
        self.sequence += 1
        return Task(name or f"legacy-task-{self.sequence}", ram_gib=.5, cpu_units=.25, io_slots=0,
                    execution_preference="CLOUD_OK", allowed_worker_ids=(worker,))

    def managed(self, kind=AllocationKind.DIRECT):
        spec, row = self.running(self.spec(kind=kind))
        conn = self.connection()
        conn.execute("""UPDATE managed_executions SET floor_cpu_units=9,
            floor_physical_bytes=?,floor_commit_bytes=? WHERE execution_id=?""",
                     (59 * GIB, 96 * GIB, spec.execution_id))
        table = "reservations" if kind is AllocationKind.DIRECT else "worker_reservations"
        # Age the fixture through the compatible writer protocol; expiry still
        # must not erase a managed floor or authorize legacy admission.
        conn.execute(f"UPDATE {table} SET created_at=?,expires_at=?,"
                     "writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                     (NOW - 1000, NOW - 1, spec.reservation.id))
        return spec, table

    def v2_replay_fixture(self, *, ram=.5, io=0, commit_bytes=None, disk=0):
        self.worker()
        task = replace(self.task(), ram_gib=ram, io_slots=io, commit_bytes=commit_bytes, disk_gib=disk)
        reserved = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertTrue(reserved["reserved"])
        parent, _ = self.running()
        caps = {"local": True, "admission_policy": "resource-v2",
                "admission_config": {**CONFIG, "heavy_io_slots": 2},
                "admission_snapshot": status()}
        self.set_replay_capabilities(caps)
        return task, parent, reserved, caps

    def set_replay_capabilities(self, caps):
        self.connection().execute("UPDATE workers SET capabilities_json=?,"
                                  "writer_protocol=1,writer_revision=writer_revision+1 WHERE id='legacy-local'",
                                  (json.dumps(caps),))

    def corrupt_delete_allocation(self, conn, table, reservation_id):
        """Inject lost storage, restoring its exact guard before any assertion.

        Normal compatible writers cannot delete a live managed allocation.
        This fixture deliberately models damage beneath that writer boundary;
        a savepoint makes dropping/restoring just its DELETE guard atomic.
        """
        self.assertIn(table, ("reservations", "worker_reservations"))
        trigger = f"adaptive_writer_{table}_delete"
        saved = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                             (trigger,)).fetchone()
        self.assertIsNotNone(saved)
        ddl = saved[0]
        conn.execute("SAVEPOINT fixture_storage_corruption")
        try:
            conn.execute(f"DROP TRIGGER {trigger}")
            conn.execute(f"DELETE FROM {table} WHERE id=?", (reservation_id,))
            conn.execute(ddl)
            conn.execute("RELEASE SAVEPOINT fixture_storage_corruption")
        except BaseException:
            conn.execute("ROLLBACK TO SAVEPOINT fixture_storage_corruption")
            conn.execute("RELEASE SAVEPOINT fixture_storage_corruption")
            raise
        self.assertEqual(conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                                      (trigger,)).fetchone()[0], ddl)

    def assert_local_denied(self):
        direct = self.coordinator.admit(self.request(), status(), now=NOW)
        self.assertFalse(direct["allowed"])
        self.assertEqual(direct["reason"], BLOCKED)
        self.worker()
        routed = self.maintainer.route_and_reserve(self.task(), now=NOW)
        self.assertFalse(routed["reserved"])
        self.assertEqual(routed["rejected"]["legacy-local"], BLOCKED)

    def test_direct_legacy_callers_retain_aged_direct_and_routed_floors(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            spec, table = self.managed(kind)
            for config in (None, {}, {"admission_policy": "legacy"}):
                with self.subTest(kind=kind, config=config):
                    result = self.coordinator.admit(self.request(), status(), config=config, now=NOW)
                    self.assertFalse(result["allowed"])
                    self.assertEqual(result["reason"], BLOCKED)
                    row = self.connection().execute(f"SELECT * FROM {table} WHERE id=?", (spec.reservation.id,)).fetchone()
                    self.assertIsNotNone(row)
                    self.assertLess(row["expires_at"], NOW)
                    self.assertEqual(self.store.query(spec.execution_id)["floor_commit_bytes"], 96 * GIB)
        self.assertEqual(len(self.coordinator.snapshot()["queue"]), 6)

    def test_local_router_cannot_replace_floors_with_raw_requested_demand(self):
        self.worker()
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            spec, table = self.managed(kind)
            with self.subTest(kind=kind):
                result = self.maintainer.route_and_reserve(self.task(), now=NOW)
                self.assertFalse(result["reserved"])
                self.assertEqual(result["rejected"]["legacy-local"], BLOCKED)
                self.assertIsNotNone(self.connection().execute(f"SELECT 1 FROM {table} WHERE id=?", (spec.reservation.id,)).fetchone())
                self.assertEqual(self.store.query(spec.execution_id)["floor_physical_bytes"], 59 * GIB)

    def test_runtime_mode_changes_do_not_remove_legacy_compatibility_guard(self):
        self.managed()
        for mode in ("off", "shadow", "canary", "limited"):
            with self.subTest(mode=mode):
                self.connection().execute("UPDATE adaptive_runtime SET mode=?", (mode,))
                self.assert_local_denied()

    def test_legacy_config_cannot_bypass_a_barrier_without_managed_rows(self):
        for barrier in ("CONTROLLING", "RECOVERY_HOLD"):
            with self.subTest(barrier=barrier):
                self.connection().execute("UPDATE adaptive_runtime SET admission_barrier=?", (barrier,))
                self.assert_local_denied()

    def test_ordinary_reservation_reuse_does_not_renew_during_managed_hold(self):
        req = self.request()
        first = self.coordinator.admit(req, status(), now=NOW)
        self.assertTrue(first["allowed"])
        self.managed()
        before = dict(self.connection().execute("SELECT * FROM reservations WHERE id=?", (first["reservation_id"],)).fetchone())
        result = self.coordinator.admit(req, status(now=NOW + 1), now=NOW + 1)
        self.assertEqual((result["allowed"], result["reason"]), (False, BLOCKED))
        after = dict(self.connection().execute("SELECT * FROM reservations WHERE id=?", (first["reservation_id"],)).fetchone())
        self.assertEqual(after, before)

    def test_legacy_handoff_remains_queued_without_changing_existing_reservation(self):
        req = self.request()
        first = self.coordinator.admit(req, status(), now=NOW)
        self.connection().execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (first["reservation_id"],))
        self.managed()
        result = self.coordinator.admit(replace(req, tool_use_id="handoff"), status(), now=NOW)
        self.assertEqual((result["allowed"], result["reason"]), (False, BLOCKED))
        self.assertEqual(self.connection().execute("SELECT tool_use_id FROM reservations WHERE id=?", (first["reservation_id"],)).fetchone()[0], "")
        self.assertEqual(len(self.coordinator.snapshot()["queue"]), 1)

    def test_retry_without_queue_cannot_reuse_ordinary_reservation(self):
        first = self.coordinator.admit(self.request(), status(), now=NOW)
        self.managed()
        result = self.coordinator.retry_queued(first["request_key"], status(), now=NOW)
        self.assertEqual((result["allowed"], result["reason"]), (False, BLOCKED))

    def test_retry_rechecks_barrier_before_publishing_handoff(self):
        req = self.request()
        blocked = self.coordinator.admit(req, {**status(), "light": "RED"}, now=NOW)
        self.assertFalse(blocked["allowed"])
        original = self.coordinator.admit

        def race(*args, **kwargs):
            result = original(*args, **kwargs)
            self.assertTrue(result["allowed"])
            self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
            return result

        with patch.object(self.coordinator, "admit", side_effect=race):
            result = self.coordinator.retry_queued(blocked["request_key"], status(), now=NOW)
        self.assertEqual((result["allowed"], result["reason"]), (False, BLOCKED))
        saved = self.connection().execute("SELECT tool_use_id FROM reservations WHERE id=?", (result["reservation_id"],)).fetchone()
        self.assertEqual(saved[0], req.tool_use_id)

    def test_routed_legacy_reuse_does_not_renew_during_managed_hold(self):
        self.worker()
        task = self.task()
        first = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertTrue(first["reserved"])
        self.managed()
        result = self.maintainer.route_and_reserve(task, now=NOW + 1)
        self.assertEqual((result["reserved"], result["reason"]), (False, BLOCKED))
        saved = self.connection().execute("SELECT heartbeat_at FROM worker_reservations WHERE task_id=?", (task.id,)).fetchone()
        self.assertEqual(saved[0], NOW)

    def test_unknown_routed_worker_cannot_reuse_by_claiming_v2(self):
        self.worker()
        task = self.task()
        self.assertTrue(self.maintainer.route_and_reserve(task, now=NOW)["reserved"])
        self.managed()
        self.connection().execute("UPDATE workers SET capabilities_json=?,"
                                  "writer_protocol=1,writer_revision=writer_revision+1 WHERE id='legacy-local'",
                                  (json.dumps({"admission_policy": "resource-v2"}),))
        result = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertEqual((result["reserved"], result["reason"]), (False, BLOCKED))

    def test_known_local_v2_label_requires_valid_replay_snapshot_and_config(self):
        task, _, reserved, caps = self.v2_replay_fixture()
        for key, values, reason in (
            ("admission_config", (None, {}, [], "invalid"), "policy_config_invalid"),
            ("admission_snapshot", (None, {}, [], "invalid"), "policy_snapshot_unavailable"),
        ):
            for value in values:
                with self.subTest(key=key, value=value):
                    changed = dict(caps)
                    if value is None:
                        changed.pop(key)
                    else:
                        changed[key] = value
                    self.set_replay_capabilities(changed)
                    result = self.maintainer.route_and_reserve(task, now=NOW + 1)
                    self.assertEqual((result["reserved"], result["reason"]), (False, reason))
                    saved = self.connection().execute("SELECT heartbeat_at FROM worker_reservations WHERE id=?",
                                                      (reserved["reservation_id"],)).fetchone()
                    self.assertEqual(saved[0], NOW)

    def test_v2_replay_rejects_stale_evidence_and_invalid_numeric_config(self):
        task, _, _, caps = self.v2_replay_fixture()
        self.set_replay_capabilities({**caps, "admission_snapshot": status(now=NOW - 1000)})
        stale = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertEqual((stale["reserved"], stale["reason"]), (False, "status_stale"))
        self.set_replay_capabilities({**caps, "admission_config": {**CONFIG, "local_allocatable_cpu": "invalid"}})
        invalid = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertEqual((invalid["reserved"], invalid["reason"]), (False, "policy_config_invalid"))

    def test_v2_replay_rejects_managed_floors_already_above_current_budgets(self):
        task, parent, _, _ = self.v2_replay_fixture()
        for column, amount, reason in (("floor_cpu_units", 9, "cpu_capacity"),
                                      ("floor_physical_bytes", 50 * GIB, "ram_capacity"),
                                      ("floor_commit_bytes", 90 * GIB, "commit_capacity")):
            with self.subTest(column=column):
                conn = self.connection()
                conn.execute("UPDATE managed_executions SET floor_cpu_units=1,floor_physical_bytes=?,floor_commit_bytes=? WHERE execution_id=?",
                             (GIB, 2 * GIB, parent.execution_id))
                conn.execute(f"UPDATE managed_executions SET {column}=? WHERE execution_id=?", (amount, parent.execution_id))
                result = self.maintainer.route_and_reserve(task, now=NOW)
                self.assertEqual((result["reserved"], result["reason"]), (False, reason))

    def test_valid_v2_replay_obeys_control_and_recovery_barriers(self):
        task, _, _, _ = self.v2_replay_fixture()
        for barrier in ("CONTROLLING", "RECOVERY_HOLD"):
            with self.subTest(barrier=barrier):
                self.connection().execute("UPDATE adaptive_runtime SET admission_barrier=?", (barrier,))
                result = self.maintainer.route_and_reserve(task, now=NOW)
                self.assertEqual((result["reserved"], result["reason"]), (False, "admission_barrier"))

    def test_valid_v2_replay_at_exact_budget_counts_existing_reservation_once(self):
        task, parent, reserved, _ = self.v2_replay_fixture(ram=2)
        self.connection().execute("UPDATE managed_executions SET floor_physical_bytes=? WHERE execution_id=?",
                                  (40 * GIB, parent.execution_id))
        # Machine 16 + retained parent 40 + the existing routed request 2 = 58.
        result = self.maintainer.route_and_reserve(task, now=NOW + 1)
        self.assertTrue(result["reserved"])
        self.assertTrue(result["reused"])
        self.assertEqual(result["id"], reserved["reservation_id"])
        self.assertEqual(self.connection().execute("SELECT count(*) FROM worker_reservations").fetchone()[0], 1)

    def test_v2_replay_preserves_original_request_disk_pressure_checks(self):
        task, _, _, caps = self.v2_replay_fixture(io=1)
        pressured = status()
        pressured["disk_performance"]["queue_length"] = 100
        self.set_replay_capabilities({**caps, "admission_snapshot": pressured})
        result = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertEqual((result["reserved"], result["reason"]), (False, "io_pressure"))

    def test_v2_replay_rejects_downscaled_resources_even_with_unchanged_spec_hash(self):
        task, _, reserved, _ = self.v2_replay_fixture(ram=2, io=1, commit_bytes=4 * GIB, disk=2)
        conn = self.connection()
        original = dict(conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())
        changes = (
            {"ram_gib": 1, "physical_bytes": GIB},
            {"cpu_units": 0}, {"physical_bytes": GIB}, {"commit_bytes": GIB},
            {"commit_bytes": None}, {"io_slots": 0}, {"disk_gib": 0},
            {"cpu_units": -1}, {"ram_gib": "invalid"}, {"physical_bytes": -1},
            {"commit_bytes": -1}, {"io_slots": -1}, {"disk_gib": -1},
        )
        fields = ("cpu_units", "ram_gib", "physical_bytes", "commit_bytes", "io_slots", "disk_gib")
        for changed in changes:
            with self.subTest(changed=changed):
                values = {field: original[field] for field in fields}
                values.update(changed)
                # Inject a malformed resource shape through a versioned fixture
                # writer so replay validation, not the old-writer fence, is tested.
                conn.execute("UPDATE worker_reservations SET " + ",".join(field + "=?" for field in fields)
                             + ",writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                             (*values.values(), reserved["reservation_id"]))
                before = dict(conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())
                self.assertEqual(before["spec_hash"], original["spec_hash"])
                result = self.maintainer.route_and_reserve(task, now=NOW + 1)
                self.assertEqual((result["reserved"], result["reason"]), (False, "reservation_resource_mismatch"))
                after = dict(conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())
                self.assertEqual(after, before)

    def test_v2_replay_accepts_legacy_null_fields_only_when_effective_demand_matches(self):
        task, _, reserved, _ = self.v2_replay_fixture(ram=2, io=1)
        self.connection().execute("UPDATE worker_reservations SET physical_bytes=NULL,commit_bytes=NULL,io_slots=NULL,"
                                  "writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                  (reserved["reservation_id"],))
        result = self.maintainer.route_and_reserve(task, now=NOW + 1)
        self.assertTrue(result["reserved"])
        self.assertTrue(result["reused"])
        self.assertEqual(result["id"], reserved["reservation_id"])

    def test_exemption_does_not_supply_missing_lifecycle_compatibility(self):
        self.managed()
        with patch("sentinel.coordinator.Exemptions.match", return_value={"id": "fixture", "expires_at": NOW + 100}):
            result = self.coordinator.admit(self.request(), status(), now=NOW)
        self.assertEqual((result["allowed"], result["reason"]), (False, BLOCKED))

    def test_inconsistent_managed_registry_and_orphan_markers_remain_blocked(self):
        for corruption in ("missing_allocation", "missing_registry", "terminal_with_allocation", "invalid_floor"):
            with self.subTest(corruption=corruption):
                spec, table = self.managed()
                conn = self.connection()
                if corruption == "missing_allocation":
                    self.corrupt_delete_allocation(conn, table, spec.reservation.id)
                elif corruption == "missing_registry":
                    conn.execute("DELETE FROM managed_executions WHERE execution_id=?", (spec.execution_id,))
                elif corruption == "terminal_with_allocation":
                    conn.execute("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?", (spec.execution_id,))
                else:
                    conn.execute("UPDATE managed_executions SET floor_commit_bytes=0 WHERE execution_id=?", (spec.execution_id,))
                self.assert_local_denied()
                # Isolate each corrupt shape; no other broken row may mask it.
                self.corrupt_delete_allocation(conn, table, spec.reservation.id)
                conn.execute("DELETE FROM managed_executions WHERE execution_id=?", (spec.execution_id,))

    def test_unknown_schema_cannot_return_legacy_admission(self):
        self.worker()
        self.connection().execute("UPDATE adaptive_runtime SET schema_version=99")
        with self.assertRaises(SchemaVersionError):
            self.coordinator.admit(self.request(), status(), now=NOW)
        with self.assertRaises(SchemaVersionError):
            self.maintainer.route_and_reserve(self.task(), now=NOW)

    def test_explicit_remote_candidates_and_retries_remain_available(self):
        self.worker("remote", remote=True)
        self.managed()
        task = self.task(worker="remote")
        first = self.maintainer.route_and_reserve(task, now=NOW)
        self.assertTrue(first["reserved"])
        self.assertEqual(first["worker_id"], "remote")
        retry = self.maintainer.route_and_reserve(task, now=NOW + 1)
        self.assertTrue(retry["reserved"])
        self.assertTrue(retry["reused"])

    def test_verified_terminal_archive_allows_legacy_again(self):
        spec, running = self.running()
        self.store.finalize_if_empty(spec.execution_id, caller=fixtures.WRAPPER,
                                     expected_revision=running["state_revision"], now=NOW)
        self.assertTrue(self.coordinator.admit(self.request(), status(), now=NOW)["allowed"])
        self.worker()
        self.assertTrue(self.maintainer.route_and_reserve(self.task(), now=NOW)["reserved"])

    def test_without_managed_rows_legacy_grace_and_router_semantics_are_preserved(self):
        first = self.coordinator.admit(self.request(ram=20, cpu=7), status(used_ram=8), now=NOW)
        self.assertTrue(first["allowed"])
        later = NOW + 121
        self.assertTrue(self.coordinator.admit(self.request(ram=20, cpu=7), status(now=later, used_ram=8), now=later)["allowed"])
        self.worker()
        routed = self.maintainer.route_and_reserve(self.task(), now=later)
        self.assertFalse(routed["reserved"])
        self.assertEqual(routed["rejected"]["legacy-local"], "cpu_capacity")

    def test_without_managed_rows_legacy_local_routing_and_reuse_succeed(self):
        self.worker()
        task = self.task()
        self.assertTrue(self.maintainer.route_and_reserve(task, now=NOW)["reserved"])
        self.assertTrue(self.maintainer.route_and_reserve(task, now=NOW + 1)["reused"])

    def test_valid_v2_callers_continue_to_receive_actual_capacity_blockers(self):
        self.managed()
        result = self.coordinator.admit(self.request(), status(), config=CONFIG, now=NOW)
        self.assertFalse(result["allowed"])
        self.assertNotEqual(result["reason"], BLOCKED)
        self.assertIn(result["reason"], {"cpu_capacity", "ram_capacity", "commit_capacity"})


if __name__ == "__main__":
    unittest.main()
