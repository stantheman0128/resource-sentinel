"""Admission-only integration fixtures; no Job or production state is touched."""

import concurrent.futures
import hashlib
import json
import tempfile
import threading
import unittest
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from sentinel.coordinator import Coordinator, ResourceRequest
from sentinel.maintainer import Maintainer, Task, Worker, local_host_identity


NOW = 2_000_000_000.0
GIB = 2**30
CONFIG = dict(admission_policy="resource-v2", local_allocatable_cpu=8,
              local_allocatable_ram_gib=58, local_physical_headroom_gib=4,
              local_commit_headroom_gib=4, heavy_io_slots=4, local_host_id="host-fixture")


def snapshot(now=NOW):
    stamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    return dict(generated_at=stamp, sampled_at=stamp, light="GREEN", cpu_5min_avg=0,
                ram=dict(total_gb=64, free_gb=56),
                memory=dict(commit_used_gib=8, commit_limit_gib=80),
                disks=[dict(drive="C:", free_gb=200)],
                disk_performance=dict(queue_length=0, read_latency_ms=1, write_latency_ms=1),
                resource_policy=dict(mode="resource-v2"))


class AdaptiveMaintainerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.maintainer = Maintainer(self.directory, local_host_id="host-fixture")
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (True, 1000.0),
                                       local_host_id="host-fixture")
        cpus = patch("os.cpu_count", return_value=8)
        cpus.start()
        self.addCleanup(cpus.stop)

    def add_local(self, name="local-a", *, canonical="host-fixture", scope="SHARED_POOL", local=True,
                  admission_config=None):
        caps = dict(adapter_ready=True, admission_policy="resource-v2",
                    admission_snapshot=snapshot(), admission_config=dict(CONFIG))
        if local is not None:
            caps["local"] = local
        if admission_config is not None:
            caps["admission_config"] = admission_config
        if canonical is not None:
            caps.update(canonical_host_id=canonical, host_binding_source="resource-sentinel-local-sync")
        return self.maintainer.upsert_worker(Worker(
            id=name, provider="local", failure_domain=name, capacity_pool=f"pool-{name}",
            capacity_scope=scope, quota_domain=f"quota-{name}", max_concurrency=8,
            state="AVAILABLE", automation_level="AUTOMATABLE", os="windows",
            capacity_ram_gib=64, allocatable_ram_gib=58, allocatable_cpu=8,
            allocatable_disk_gib=150, capabilities=caps, source="resource-sentinel-live",
            observed_at=NOW, probe_expires_at=NOW+3600,
        ), now=NOW)

    @staticmethod
    def task(name, ram=30, *, worker="local-a", preference="LOCAL_REQUIRED", **kwargs):
        return Task(name, ram_gib=ram, cpu_units=.25, io_slots=0,
                    execution_preference=preference, allowed_worker_ids=(worker,), **kwargs)

    @staticmethod
    def direct(pid=100, ram=30):
        return ResourceRequest(pid, 1000.0, "fixture", "fixture command", "MEDIUM", "P2", str(pid),
                               cpu_units=.25, ram_gib=ram, io_slots=0)

    def test_local_aliases_cannot_spend_distinct_physical_pools(self):
        self.add_local()
        self.add_local("local-b")
        self.assertTrue(self.maintainer.route_and_reserve(self.task("first"), now=NOW)["reserved"])
        result = self.maintainer.route_and_reserve(self.task("second", worker="local-b"), now=NOW+1)
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["local-b"], "ram_capacity")

    def test_unbound_legacy_local_alias_is_still_counted(self):
        self.add_local(canonical=None)
        self.add_local("local-b")
        self.assertTrue(self.maintainer.route_and_reserve(self.task("legacy"), now=NOW)["reserved"])
        result = self.maintainer.route_and_reserve(self.task("second", worker="local-b"), now=NOW+1)
        self.assertFalse(result["reserved"])

    def test_per_execution_local_flag_cannot_mint_another_machine(self):
        self.add_local(scope="PER_EXECUTION")
        self.assertTrue(self.maintainer.route_and_reserve(self.task("first"), now=NOW)["reserved"])
        self.assertFalse(self.maintainer.route_and_reserve(self.task("second"), now=NOW+1)["reserved"])

    def test_explicit_conflicting_host_binding_is_not_capacity(self):
        self.add_local(canonical="host-other")
        prospective = self.maintainer.route_and_reserve(self.task("not-started", ram=.5), now=NOW)
        self.assertFalse(prospective["reserved"])
        self.assertEqual(prospective["rejected"]["local-a"], "local_scope_unknown")
        # Keep the conflicting alias represented in the ledger. An unknown
        # scope must not be silently dropped on a later admission.
        with self.maintainer._db() as conn:
            conn.execute("""INSERT INTO worker_reservations
                (id,task_id,worker_id,failure_domain,capacity_pool,ram_gib,cpu_units,disk_gib,
                 created_at,heartbeat_at,expires_at,metadata_json)
                VALUES ('conflict','conflict','local-a','fixture','fixture',1,.25,0,?,?,?,'{}')""",
                (NOW, NOW, NOW+3600))
        result = self.maintainer.route_and_reserve(self.task("new", ram=.5), now=NOW+1)
        self.assertFalse(result["reserved"])

    def test_direct_and_routed_admission_share_one_projection(self):
        self.add_local()
        direct = self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW)
        self.assertTrue(direct["allowed"])
        routed = self.maintainer.route_and_reserve(self.task("routed"), now=NOW+1)
        self.assertFalse(routed["reserved"])
        self.assertEqual(routed["rejected"]["local-a"], "ram_capacity")

    def test_routed_then_direct_uses_same_alias_independent_ledger(self):
        self.add_local("not-default-worker")
        routed = self.maintainer.route_and_reserve(self.task("routed", worker="not-default-worker"), now=NOW)
        self.assertTrue(routed["reserved"])
        direct = self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW+1)
        self.assertFalse(direct["allowed"])
        self.assertEqual(direct["reason"], "ram_capacity")

    def test_concurrent_direct_route_can_reserve_only_one_large_request(self):
        self.add_local()
        barrier = threading.Barrier(2)
        def direct():
            barrier.wait(timeout=5)
            return self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW)["allowed"]
        def routed():
            barrier.wait(timeout=5)
            return self.maintainer.route_and_reserve(self.task("race"), now=NOW)["reserved"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(direct), executor.submit(routed)]
            self.assertEqual(sum(future.result(timeout=15) for future in futures), 1)

    def test_commit_estimate_is_independent_of_physical_request(self):
        self.add_local()
        result = self.maintainer.route_and_reserve(
            self.task("commit-heavy", ram=.5, commit_bytes=72*GIB), now=NOW)
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["local-a"], "commit_capacity")

    def test_canonical_local_without_legacy_flag_obeys_commit_guard_for_cloud_ok(self):
        self.add_local(local=None)
        result = self.maintainer.route_and_reserve(
            self.task("canonical-commit", ram=.5, commit_bytes=72*GIB, preference="CLOUD_OK"), now=NOW)
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["local-a"], "commit_capacity")
        with self.maintainer._db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM worker_reservations").fetchone()[0], 0)

    def test_canonical_local_without_legacy_flag_satisfies_local_required(self):
        self.add_local(local=None)
        result = self.maintainer.route_and_reserve(self.task("canonical-local", ram=.5), now=NOW)
        self.assertTrue(result["reserved"])
        self.assertEqual(result["worker_id"], "local-a")

    def test_conflicting_or_unknown_scope_cannot_route_even_when_cloud_is_allowed(self):
        cases = ((False, "host-fixture"), (True, "host-other"),
                 (None, None), ("false", "host-fixture"), (0, "host-other"), (1, "host-fixture"))
        for index, (local, canonical) in enumerate(cases):
            worker_id = f"ambiguous-{index}"
            with self.subTest(local=local, canonical=canonical):
                self.add_local(worker_id, local=local, canonical=canonical)
                result = self.maintainer.route_and_reserve(
                    self.task(f"ambiguous-task-{index}", ram=.5, worker=worker_id, preference="CLOUD_OK"), now=NOW)
                self.assertFalse(result["reserved"])
                self.assertEqual(result["rejected"][worker_id], "local_scope_unknown")

    def test_canonical_local_and_direct_admission_serialize_one_machine_budget(self):
        self.add_local(local=None)
        barrier = threading.Barrier(2)

        def direct():
            barrier.wait(timeout=5)
            return self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW)["allowed"]

        def routed():
            barrier.wait(timeout=5)
            return self.maintainer.route_and_reserve(
                self.task("canonical-race", preference="CLOUD_OK"), now=NOW)["reserved"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(direct), executor.submit(routed)]
            self.assertEqual(sum(future.result(timeout=15) for future in futures), 1)
        with self.maintainer._db() as conn:
            rows = conn.execute("SELECT COUNT(*) FROM reservations").fetchone()[0]
            rows += conn.execute("SELECT COUNT(*) FROM worker_reservations").fetchone()[0]
        self.assertEqual(rows, 1)

    def test_remote_snapshot_uses_its_pool_and_does_not_rebind_local_ledger(self):
        self.add_local(local=None)
        # A remote host's own config describes its measurements, not this
        # registry's host. The remote allocation must retain its own pool.
        remote_config = {**CONFIG, "local_host_id": "host-other"}
        self.add_local("remote", local=False, canonical="host-other", admission_config=remote_config)
        remote = self.maintainer.route_and_reserve(
            self.task("remote-first", worker="remote", preference="CLOUD_OK", commit_bytes=72*GIB), now=NOW)
        self.assertTrue(remote["reserved"])
        local = self.maintainer.route_and_reserve(self.task("local-after-remote"), now=NOW)
        self.assertTrue(local["reserved"])
        another_remote = self.maintainer.route_and_reserve(
            self.task("remote-second", worker="remote", preference="CLOUD_OK"), now=NOW)
        self.assertFalse(another_remote["reserved"])
        self.assertEqual(another_remote["rejected"]["remote"], "ram_capacity")

    def test_remote_per_execution_pools_keep_per_job_capacity(self):
        self.add_local("remote", local=False, canonical="host-other", scope="PER_EXECUTION")
        for name in ("remote-one", "remote-two"):
            result = self.maintainer.route_and_reserve(
                self.task(name, worker="remote", preference="CLOUD_OK", ram=50), now=NOW)
            self.assertTrue(result["reserved"])

    def test_active_local_worker_cannot_be_relabelled_remote_or_unknown(self):
        original = self.add_local()
        reserved = self.maintainer.route_and_reserve(self.task("live-local"), now=NOW)
        self.assertTrue(reserved["reserved"])
        for binding in ({"local": False, "canonical_host_id": "other-host"},
                        {"local": False, "canonical_host_id": "host-fixture"},
                        {"local": True, "canonical_host_id": "other-host"}, {}):
            caps = {key: value for key, value in original["capabilities"].items()
                    if key not in {"local", "canonical_host_id"}}
            caps.update(binding)
            with self.subTest(binding=binding), self.assertRaisesRegex(
                    ValueError, "worker_locality_change_with_active_reservations"):
                self.maintainer.upsert_worker(replace(Worker(**original), capabilities=caps), now=NOW+1)
        saved = self.maintainer.get_worker("local-a", now=NOW+1)
        self.assertEqual(saved["capabilities"], original["capabilities"])
        direct = self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW+1)
        self.assertFalse(direct["allowed"])
        self.assertEqual(direct["reason"], "ram_capacity")
        with self.maintainer._db() as conn:
            row = conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone()
        self.assertEqual(row["ram_gib"], 30)

    def test_active_remote_worker_cannot_be_relabelled_local_or_unknown(self):
        original = self.add_local("remote", local=False, canonical="other-host")
        reserved = self.maintainer.route_and_reserve(
            self.task("live-remote", worker="remote", preference="CLOUD_OK"), now=NOW)
        self.assertTrue(reserved["reserved"])
        for binding in ({"local": True, "canonical_host_id": "host-fixture"},
                        {"canonical_host_id": "host-fixture"},
                        {"local": False, "canonical_host_id": "host-fixture"}, {}):
            caps = {key: value for key, value in original["capabilities"].items()
                    if key not in {"local", "canonical_host_id"}}
            caps.update(binding)
            with self.subTest(binding=binding), self.assertRaisesRegex(
                    ValueError, "worker_locality_change_with_active_reservations"):
                self.maintainer.upsert_worker(replace(Worker(**original), capabilities=caps), now=NOW+1)
        self.assertEqual(self.maintainer.get_worker("remote", now=NOW+1)["capabilities"], original["capabilities"])
        # The rejected rewrite neither moves remote demand into this host nor
        # releases the reservation in its actual remote capacity pool.
        self.assertTrue(self.coordinator.admit(self.direct(), snapshot(), config=CONFIG, now=NOW+1)["allowed"])
        with self.maintainer._db() as conn:
            self.assertIsNotNone(conn.execute("SELECT 1 FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())

    def test_metadata_refresh_preserves_live_locality_and_allocation(self):
        original = self.add_local(canonical=None)
        reserved = self.maintainer.route_and_reserve(self.task("refresh-local"), now=NOW)
        with self.maintainer._db() as conn:
            before = dict(conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())
        caps = {**original["capabilities"], "canonical_host_id": "host-fixture",
                "admission_snapshot": snapshot(NOW+1), "adapter_note": "refreshed"}
        changed = self.maintainer.upsert_worker(
            replace(Worker(**original), capabilities=caps, state="BUSY", observed_at=NOW+1), now=NOW+1)
        self.assertEqual(changed["capabilities"]["adapter_note"], "refreshed")
        self.assertEqual(self.maintainer.get_worker("local-a", now=NOW+1)["state"], "BUSY")
        with self.maintainer._db() as conn:
            after = dict(conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())
        self.assertEqual(after, before)

    def test_expired_and_bound_rows_still_prevent_locality_change(self):
        original = self.add_local()
        reserved = self.maintainer.route_and_reserve(self.task("hold-local"), now=NOW)
        remote = replace(Worker(**original), capabilities={"local": False, "canonical_host_id": "other-host"})
        with self.maintainer._db() as conn:
            conn.execute("UPDATE worker_reservations SET expires_at=? WHERE id=?", (NOW-1, reserved["reservation_id"]))
        with self.assertRaisesRegex(ValueError, "worker_locality_change_with_active_reservations"):
            self.maintainer.upsert_worker(remote, now=NOW+1)
        with self.maintainer._db() as conn:
            # Simulate a compatible metadata writer leaving an incomplete bind.
            conn.execute("UPDATE worker_reservations SET lifecycle_managed=1,execution_id='uncertain',"
                         "writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                         (reserved["reservation_id"],))
        self.assertEqual(self.maintainer.release(task_id="hold-local", now=NOW+1), 0)
        with self.assertRaisesRegex(ValueError, "worker_locality_change_with_active_reservations"):
            self.maintainer.upsert_worker(remote, now=NOW+2)
        with self.maintainer._db() as conn:
            self.assertIsNotNone(conn.execute("SELECT 1 FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())

    def test_actual_release_allows_later_worker_locality_change(self):
        original = self.add_local()
        self.maintainer.route_and_reserve(self.task("completed-local"), now=NOW)
        self.assertEqual(self.maintainer.release(task_id="completed-local", now=NOW+1), 1)
        remote = replace(Worker(**original), capabilities={"local": False, "canonical_host_id": "other-host"})
        self.maintainer.upsert_worker(remote, now=NOW+2)
        self.assertEqual(self.maintainer.worker_locality(self.maintainer.get_worker("local-a", now=NOW+2)), "remote")

    def test_unknown_or_orphaned_worker_cannot_reclassify_active_demand(self):
        original = self.add_local()
        reserved = self.maintainer.route_and_reserve(self.task("uncertain-local"), now=NOW)
        # Simulate a registry damaged outside the normal upsert API.
        with self.maintainer._db() as conn:
            conn.execute("UPDATE workers SET capabilities_json='{}' WHERE id='local-a'")
        for caps in ({"local": False}, {"local": True}, {"local": True, "canonical_host_id": "other-host"}):
            with self.subTest(caps=caps), self.assertRaisesRegex(
                    ValueError, "worker_locality_change_with_active_reservations"):
                self.maintainer.upsert_worker(replace(Worker(**original), capabilities=caps), now=NOW+1)
        self.maintainer.upsert_worker(replace(Worker(**original), capabilities={"note": "still unknown"}), now=NOW+1)
        with self.maintainer._db() as conn:
            conn.execute("PRAGMA foreign_keys=OFF")
            conn.execute("DELETE FROM workers WHERE id='local-a'")
        with self.assertRaisesRegex(ValueError, "worker_locality_change_with_active_reservations"):
            self.maintainer.upsert_worker(replace(Worker(**original), capabilities={"local": False}), now=NOW+2)
        with self.maintainer._db() as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM workers WHERE id='local-a'").fetchone())
            self.assertIsNotNone(conn.execute("SELECT 1 FROM worker_reservations WHERE id=?", (reserved["reservation_id"],)).fetchone())

    def test_worker_locality_update_serializes_with_local_reservation(self):
        original = self.add_local()
        remote = replace(Worker(**original), capabilities={**original["capabilities"],
                         "local": False, "canonical_host_id": "other-host"})
        barrier = threading.Barrier(2)

        def route():
            barrier.wait(timeout=5)
            return self.maintainer.route_and_reserve(self.task("scope-race"), now=NOW)["reserved"]

        def reclassify():
            barrier.wait(timeout=5)
            try:
                self.maintainer.upsert_worker(remote, now=NOW)
            except ValueError as error:
                self.assertEqual(str(error), "worker_locality_change_with_active_reservations")
                return False
            return True

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            routed, changed = executor.submit(route), executor.submit(reclassify)
            routed, changed = routed.result(timeout=15), changed.result(timeout=15)
        self.assertEqual(int(routed) + int(changed), 1)
        saved = self.maintainer.get_worker("local-a", now=NOW)
        with self.maintainer._db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM worker_reservations WHERE worker_id='local-a'").fetchone()[0]
        self.assertEqual(count, int(routed))
        self.assertEqual(self.maintainer.worker_locality(saved), "local" if routed else "remote")

    def test_explicit_resource_units_and_unmanaged_coverage_are_persisted(self):
        self.add_local()
        result = self.maintainer.route_and_reserve(
            self.task("shape", ram=.5, commit_bytes=2*GIB), now=NOW)
        self.assertTrue(result["reserved"])
        self.assertEqual((result["physical_bytes"], result["commit_bytes"], result["io_slots"]),
                         (GIB//2, 2*GIB, 0))
        self.assertEqual((result["coverage"], result["lifecycle_evidence"]), ("unmanaged", "limited"))
        with self.maintainer._db() as conn:
            row = conn.execute("SELECT * FROM worker_reservations WHERE id=?", (result["reservation_id"],)).fetchone()
        self.assertEqual((row["physical_bytes"], row["commit_bytes"], row["io_slots"]), (GIB//2, 2*GIB, 0))

    def test_execution_bound_allocation_survives_legacy_release_and_ttl(self):
        self.add_local()
        result = self.maintainer.route_and_reserve(self.task("bound", ram=.5), ttl_min=1, now=NOW)
        with self.maintainer._db() as conn:
            # The missing registry is the fault, not the writer's SQL protocol.
            conn.execute("UPDATE worker_reservations SET lifecycle_managed=1,execution_id='missing-registry',"
                         "writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                         (result["reservation_id"],))
        self.assertEqual(self.maintainer.release(task_id="bound", now=NOW+1), 0)
        state = self.maintainer.snapshot(now=NOW+61)
        self.assertEqual([row["id"] for row in state["reservations"]], [result["reservation_id"]])
        retry = self.maintainer.route_and_reserve(self.task("bound", ram=.5), now=NOW+61)
        self.assertFalse(retry["reserved"])
        self.assertEqual(retry["reason"], "execution_bound")

    def test_legacy_unbound_allocation_retains_compatibility_release(self):
        self.add_local()
        self.maintainer.route_and_reserve(self.task("legacy", ram=.5), now=NOW)
        self.assertEqual(self.maintainer.release(task_id="legacy", now=NOW+1), 1)

    def test_legacy_task_hash_is_unchanged_for_default_new_fields(self):
        task = Task("legacy", ram_gib=1).normalized()
        legacy = asdict(task)
        legacy.pop("commit_bytes")
        legacy.pop("io_slots")
        expected = hashlib.sha256(json.dumps(legacy, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        self.assertEqual(Maintainer._spec_hash(task), expected)

    def test_invalid_new_resource_shapes_are_rejected(self):
        for values in ({"commit_bytes": -1}, {"commit_bytes": True}, {"commit_bytes": 1.5},
                       {"io_slots": -1}, {"io_slots": True}, {"cpu_units": float("nan")}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Task("invalid", ram_gib=1, **values).normalized()

    def test_host_binding_does_not_depend_on_worker_alias(self):
        with patch("sentinel.accounting.socket.gethostname", return_value="Fixture-HOST"):
            first = local_host_identity()
        with patch("sentinel.accounting.socket.gethostname", return_value="fixture-host"):
            self.assertEqual(first, local_host_identity())
        self.assertNotIn("fixture", first)


if __name__ == "__main__":
    unittest.main()
