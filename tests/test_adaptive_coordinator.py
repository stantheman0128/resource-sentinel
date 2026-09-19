"""Admission-only integration: no OS controls, real isolated SQLite transactions."""
import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from sentinel.coordinator import Coordinator, ResourceRequest, _default_pid_identity
from sentinel.adaptive.store import SchemaVersionError
from sentinel.maintainer import Maintainer, Task, Worker


NOW = 2_000_000_000.0
CONFIG = dict(admission_policy="resource-v2", local_allocatable_cpu=8,
              local_allocatable_ram_gib=58, local_physical_headroom_gib=4,
              local_commit_headroom_gib=4, heavy_io_slots=1)


def status(*, now=NOW, cpu=0, used_ram=16, commit=20):
    stamp = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    return dict(generated_at=stamp, sampled_at=stamp, light="GREEN", cpu_pct=cpu,
                cpu_5min_avg=cpu, ram=dict(total_gb=64, free_gb=64-used_ram),
                memory=dict(commit_used_gib=commit, commit_limit_gib=96),
                resource_policy=dict(mode="resource-v2"), disks=[dict(drive="C:", free_gb=100)],
                disk_performance=dict(queue_length=0, read_latency_ms=1, write_latency_ms=1))


def request(pid=100, *, cpu=.5, ram=.5, command="fixture", tool="", commit_bytes=None):
    return ResourceRequest(pid, 1000, "test", command, "MEDIUM", "P2", tool or f"tool-{pid}",
                           cpu_units=cpu, ram_gib=ram, io_slots=0, commit_bytes=commit_bytes)


class AdaptiveCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.identities = {100: (True, 1000), 200: (True, 1000), 300: (True, 1000)}
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: self.identities.get(pid))
        self.cpus = patch("os.cpu_count", return_value=12)
        self.cpus.start()
        self.addCleanup(self.cpus.stop)

    def admit(self, req=None, state=None, now=NOW):
        return self.coordinator.admit(req or request(), state or status(now=now), config=CONFIG, now=now)

    def mark_bound(self, reservation_id):
        # An incomplete binding is deliberate fault injection: it must remain
        # protected even if the metadata writer crashed before registry repair.
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("UPDATE reservations SET lifecycle_managed=1,execution_id=? WHERE id=?",
                         ("a" * 32, reservation_id))

    def test_active_allocation_still_counts_after_legacy_grace(self):
        self.assertTrue(self.admit(request(ram=2), status(used_ram=56))["allowed"])
        later = NOW + 121
        result = self.admit(request(200), status(now=later, used_ram=56), now=later)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "ram_capacity")

    def test_direct_physical_and_commit_requests_are_independent(self):
        req = request(ram=1, commit_bytes=5 << 30)
        denied = self.admit(req, status(commit=88))
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reason"], "commit_capacity")
        allowed = self.admit(req, status(commit=87))
        self.assertTrue(allowed["allowed"])
        saved = self.coordinator.snapshot()["reservations"][0]
        self.assertEqual(saved["ram_gib"], 1)
        self.assertEqual(saved["commit_bytes"], 5 << 30)
        self.assertEqual(self.admit(request(200), status(commit=87))["reason"], "commit_capacity")

    def canonical_local_route(self):
        """Default constructors share a host even when config has no host ID."""
        maintainer = Maintainer(self.directory)
        self.assertEqual(maintainer.local_host_id, self.coordinator.local_host_id)
        caps = dict(canonical_host_id=maintainer.local_host_id, adapter_ready=True,
                    admission_policy="resource-v2", admission_config=dict(CONFIG),
                    admission_snapshot=status(used_ram=56))
        maintainer.upsert_worker(Worker(
            id="canonical-local", provider="local", failure_domain="host", capacity_pool="local-pool",
            state="AVAILABLE", automation_level="AUTOMATABLE", max_concurrency=8,
            capacity_ram_gib=64, allocatable_ram_gib=58, allocatable_cpu=8,
            capabilities=caps, observed_at=NOW, probe_expires_at=NOW+3600), now=NOW)
        routed = maintainer.route_and_reserve(
            Task("existing-local", ram_gib=2, cpu_units=.5, io_slots=0,
                 allowed_worker_ids=("canonical-local",), execution_preference="CLOUD_OK"), now=NOW)
        self.assertTrue(routed["reserved"], routed)
        return maintainer, caps

    def test_default_host_binding_counts_canonical_only_local_route(self):
        self.canonical_local_route()
        self.assertNotIn("local_host_id", CONFIG)
        result = self.admit(state=status(used_ram=56))
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "ram_capacity")

    def test_dashboard_style_config_call_retains_static_api_and_host_binding(self):
        with patch("sentinel.coordinator.local_host_identity", return_value="read-only-host"):
            config = Coordinator._config({**CONFIG, "local_host_id": "worker-supplied-host"})
        self.assertEqual(config["local_host_id"], "read-only-host")

    def test_default_host_binding_holds_conflicting_route_on_both_entry_points(self):
        maintainer, caps = self.canonical_local_route()
        caps["local"] = False
        with maintainer._db() as conn:
            conn.execute("UPDATE workers SET capabilities_json=? WHERE id='canonical-local'", (json.dumps(caps),))
        direct = self.admit(state=status(used_ram=56))
        self.assertFalse(direct["allowed"])
        self.assertEqual(direct["reason"], "local_scope_unknown")
        routed = maintainer.route_and_reserve(
            Task("next-local", ram_gib=.5, cpu_units=.5, io_slots=0,
                 allowed_worker_ids=("canonical-local",), execution_preference="CLOUD_OK"), now=NOW)
        self.assertFalse(routed["reserved"])
        self.assertEqual(routed["rejected"]["canonical-local"], "local_scope_unknown")
        # A request cannot relabel the ledger host to hide the conflicting row.
        changed_config = {**CONFIG, "local_host_id": "different-host"}
        changed = self.coordinator.admit(request(200), status(used_ram=56), config=changed_config, now=NOW)
        self.assertFalse(changed["allowed"])
        self.assertEqual(changed["reason"], "local_scope_unknown")

    def test_queued_retry_preserves_explicit_commit_bytes(self):
        req = request(ram=1, commit_bytes=5 << 30)
        denied = self.admit(req, status(commit=88))
        self.assertEqual(self.coordinator.snapshot()["queue"][0]["commit_bytes"], 5 << 30)
        resumed = self.coordinator.retry_queued(denied["request_key"], status(commit=87), config=CONFIG, now=NOW)
        self.assertTrue(resumed["allowed"])
        saved = self.coordinator.snapshot()["reservations"][0]
        self.assertEqual(saved["commit_bytes"], 5 << 30)
        self.assertEqual(saved["spec_hash"], req.spec_hash)

    def test_legacy_handoff_preserves_explicit_commit_bytes(self):
        req = request(ram=1, commit_bytes=5 << 30)
        admitted = self.admit(req)
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (admitted["reservation_id"],))
        handed = self.admit(request(ram=1, commit_bytes=5 << 30, tool="waiter-handoff"))
        self.assertTrue(handed["allowed"])
        self.assertTrue(handed["reused"])
        self.assertEqual(handed["reservation_id"], admitted["reservation_id"])
        self.assertEqual(self.coordinator.snapshot()["reservations"][0]["commit_bytes"], 5 << 30)

    def test_explicit_commit_is_also_respected_by_legacy_request_guard(self):
        result = self.coordinator.admit(request(ram=1, commit_bytes=5 << 30), status(commit=88), now=NOW)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "commit_capacity")

    def test_queue_feasibility_uses_each_requests_commit_amount(self):
        denied = self.admit(request(ram=1, commit_bytes=5 << 30), status(commit=88))
        self.assertFalse(denied["allowed"])
        smaller = self.admit(request(200, ram=1, commit_bytes=1 << 30), status(commit=88))
        self.assertTrue(smaller["allowed"])
        self.assertEqual(len(self.coordinator.snapshot()["queue"]), 1)

    def test_commit_bytes_strict_integer_range_and_legacy_hash_compatibility(self):
        for value in (True, False, 1.0, "1", -1, 1 << 63, float("nan")):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                request(commit_bytes=value).normalized()
        for value in (0, (1 << 63) - 1):
            self.assertEqual(request(commit_bytes=value).normalized().commit_bytes, value)
        self.assertEqual(request().spec_hash, "2f0d5c7b884db1931fa6b6c2768908479bcc718dd24b19d5d78fcd3a9bdb7c5e")
        self.assertEqual(request().spec_hash, request(commit_bytes=None).spec_hash)
        self.assertNotEqual(request().spec_hash, request(commit_bytes=1 << 29).spec_hash)
        self.assertNotEqual(request(commit_bytes=1 << 29).spec_hash, request(commit_bytes=1 << 30).spec_hash)

    def test_commit_change_cannot_mutate_existing_queue_or_reservation(self):
        req = request(ram=1, commit_bytes=5 << 30)
        self.assertFalse(self.admit(req, status(commit=88))["allowed"])
        changed = self.admit(request(ram=1, commit_bytes=4 << 30), status(commit=87))
        self.assertEqual(changed["reason"], "request_spec_mismatch")
        self.assertEqual(self.coordinator.snapshot()["queue"][0]["commit_bytes"], 5 << 30)
        self.assertTrue(self.admit(req, status(commit=87))["allowed"])
        changed = self.admit(request(ram=1, commit_bytes=4 << 30), status(commit=87))
        self.assertEqual(changed["reason"], "request_spec_mismatch")
        self.assertEqual(self.coordinator.snapshot()["reservations"][0]["commit_bytes"], 5 << 30)

    def test_legacy_queue_migration_keeps_default_commit_and_spec_hash(self):
        req = request(cpu=8)
        self.assertFalse(self.admit(req, status(cpu=10))["allowed"])
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("ALTER TABLE queue DROP COLUMN commit_bytes")
        Coordinator(self.directory)
        saved = self.coordinator.snapshot()["queue"][0]
        self.assertIsNone(saved["commit_bytes"])
        self.assertEqual(saved["spec_hash"], req.spec_hash)

    def test_concurrent_constructors_upgrade_legacy_queue_atomically(self):
        req = request(cpu=8)
        self.assertFalse(self.admit(req, status(cpu=10))["allowed"])
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("ALTER TABLE queue DROP COLUMN commit_bytes")
        both_observed_old_queue = Barrier(2)
        observations = []
        original_connect = sqlite3.connect

        class SynchronizedConnection(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                cursor = super().execute(sql, parameters)
                if sql == "PRAGMA table_info(queue)" and not connection.in_transaction:
                    rows = cursor.fetchall()
                    cursor.close()
                    if "commit_bytes" not in {row[1] for row in rows}:
                        observations.append(True)
                        # Force both constructors to read the same old schema.
                        # An ALTER based on that outside observation would race;
                        # migrate_schema must recheck under its writer lock.
                        both_observed_old_queue.wait(timeout=5)
                    return rows
                return cursor

        def connect(*args, **kwargs):
            return original_connect(*args, factory=SynchronizedConnection, **kwargs)

        def initialize(_):
            upgraded = Coordinator(self.directory)
            return upgraded.snapshot()["queue"][0]

        with patch("sentinel.coordinator.sqlite3.connect", side_effect=connect):
            with ThreadPoolExecutor(max_workers=2) as pool:
                rows = list(pool.map(initialize, (1, 2)))
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(row["commit_bytes"] is None and row["spec_hash"] == req.spec_hash for row in rows))
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            self.assertEqual(sum(row[1] == "commit_bytes" for row in conn.execute("PRAGMA table_info(queue)")), 1)

    def test_competing_direct_admissions_cannot_spend_same_capacity(self):
        start = Barrier(2)
        def attempt(pid):
            start.wait(timeout=5)
            return self.admit(request(pid, ram=1), status(used_ram=57))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (100, 200)))
        self.assertEqual(sum(bool(r["allowed"]) for r in results), 1)
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)

    def test_bound_reservation_survives_dead_owner_and_ttl_with_feature_off(self):
        admitted = self.admit()
        self.mark_bound(admitted["reservation_id"])
        self.identities[100] = (False, 0)
        self.assertEqual(self.coordinator.cleanup(config={"admission_policy": "legacy"}, now=NOW+9000), [])
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)

    def test_legacy_release_reports_only_released_unbound_rows(self):
        bound = self.admit(request(tool="bound"))
        self.mark_bound(bound["reservation_id"])
        # Legacy admission remains available; its cleanup cannot remove bound.
        ordinary = self.coordinator.admit(request(command="other", tool="ordinary"), status(), now=NOW)
        self.assertTrue(ordinary["allowed"])
        self.assertEqual(self.coordinator.release(owner_pid=100, now=NOW+1), 1)
        self.assertEqual(self.coordinator.snapshot()["reservations"][0]["id"], bound["reservation_id"])
        self.assertEqual(self.coordinator.release(owner_pid=100, tool_use_id="bound", now=NOW+2), 0)
        self.assertEqual(self.coordinator.release(owner_pid=100, command="fixture", now=NOW+2), 0)

    def test_bound_request_cannot_reenter_legacy_admit_or_retry(self):
        admitted = self.admit()
        self.mark_bound(admitted["reservation_id"])
        before = self.coordinator.snapshot()["reservations"][0]
        for result in (self.admit(now=NOW+1),
                       self.coordinator.retry_queued(request().request_key, status(), now=NOW+1)):
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "managed_reservation_requires_exact_claim")
        self.assertEqual(self.coordinator.snapshot()["reservations"][0], before)

    def test_legacy_signature_handoff_does_not_claim_bound_reservation(self):
        admitted = self.admit()
        self.mark_bound(admitted["reservation_id"])
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (admitted["reservation_id"],))
        other = self.coordinator.admit(request(tool="different-tool"), status(), now=NOW+1)
        self.assertTrue(other["allowed"])
        self.assertFalse(other["reused"])
        self.assertNotEqual(other["reservation_id"], admitted["reservation_id"])

    def test_unknown_identity_holds_but_positive_death_releases_legacy(self):
        admitted = self.admit()
        self.identities[100] = (None, 0)
        self.assertEqual(self.coordinator.cleanup(now=NOW+9000), [])
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)
        self.identities[100] = (False, 0)
        self.assertEqual(self.coordinator.cleanup(now=NOW+9001), [admitted["reservation_id"]])

    def test_identity_exception_keeps_queue_and_reservation(self):
        self.admit()
        self.assertFalse(self.admit(request(200, cpu=8))["allowed"])
        self.coordinator.pid_identity = lambda pid: (_ for _ in ()).throw(PermissionError("unavailable"))
        self.assertEqual(self.coordinator.cleanup(now=NOW+9000), [])
        snap = self.coordinator.snapshot()
        self.assertEqual(len(snap["reservations"]), 1)
        self.assertEqual(len(snap["queue"]), 1)

    def test_process_query_does_not_hold_writer_lock_and_changed_row_is_preserved(self):
        admitted = self.admit()
        observed = []
        def identity(pid):
            with closing(sqlite3.connect(self.coordinator.db_path, timeout=.05)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE reservations SET heartbeat_at=? WHERE id=?", (NOW+1, admitted["reservation_id"]))
            observed.append(pid)
            return False, 0
        self.coordinator.pid_identity = identity
        self.assertEqual(self.coordinator.cleanup(now=NOW+2), [])
        self.assertEqual(observed, [100])
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)

    def test_row_created_during_identity_snapshot_is_not_cleaned_without_observation(self):
        original = self.admit()
        def identity(pid):
            with closing(sqlite3.connect(self.coordinator.db_path, timeout=.05)) as conn, conn:
                conn.row_factory = sqlite3.Row
                row = dict(conn.execute("SELECT * FROM reservations WHERE id=?", (original["reservation_id"],)).fetchone())
                row.update(id="new-row", request_key="new-request", owner_pid=300, expires_at=NOW-1)
                conn.execute(f"INSERT INTO reservations ({','.join(row)}) VALUES ({','.join('?' for _ in row)})", tuple(row.values()))
            return False, 0
        self.coordinator.pid_identity = identity
        self.assertEqual(self.coordinator.cleanup(now=NOW+1), [original["reservation_id"]])
        self.assertEqual(self.coordinator.snapshot()["reservations"][0]["id"], "new-row")

    def test_exemption_lookup_precedes_writer_transaction_and_reservation_counts(self):
        observed = []
        def match(*args, **kwargs):
            with closing(sqlite3.connect(self.coordinator.db_path, timeout=.05)) as conn, conn:
                conn.execute("BEGIN IMMEDIATE")
            observed.append(True)
            return dict(id="test-grant", expires_at=NOW+60)
        with patch("sentinel.coordinator.Exemptions.match", side_effect=match):
            result = self.admit(request(ram=10), status(used_ram=56, commit=95))
        self.assertEqual(result["reason"], "user_exemption")
        self.assertEqual(observed, [True])
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)
        self.assertFalse(self.admit(request(200), status(used_ram=56))["allowed"])

    def test_exemption_cannot_bypass_broken_allocation_binding(self):
        original = self.admit()
        self.mark_bound(original["reservation_id"])
        with patch("sentinel.coordinator.Exemptions.match", return_value=dict(id="test-grant", expires_at=NOW+60)):
            denied = self.admit(request(200), status(now=NOW-1000))
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reason"], "allocation_binding_mismatch")
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)

    def test_valid_exemption_still_bypasses_stale_load_and_reserves(self):
        with patch("sentinel.coordinator.Exemptions.match", return_value=dict(id="test-grant", expires_at=NOW+60)):
            granted = self.admit(state=status(now=NOW-1000, cpu=100, used_ram=63, commit=95))
        self.assertTrue(granted["allowed"])
        self.assertEqual(granted["reason"], "user_exemption")
        self.assertEqual(len(self.coordinator.snapshot()["reservations"]), 1)

    def test_default_process_query_distinguishes_unavailable_from_missing(self):
        import psutil
        for error, expected in [(psutil.AccessDenied(123), None), (psutil.NoSuchProcess(123), False)]:
            with patch("psutil.Process", side_effect=error):
                self.assertIs(_default_pid_identity(123)[0], expected)

    def test_future_schema_is_rejected_before_legacy_ddl(self):
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("UPDATE adaptive_runtime SET schema_version=999")
            conn.execute("DROP TABLE executions")
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=DELETE").fetchone()[0], "delete")
        before = self.coordinator.db_path.read_bytes()
        with self.assertRaises(SchemaVersionError):
            Coordinator(self.directory)
        self.assertEqual(self.coordinator.db_path.read_bytes(), before)
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name='executions'").fetchone())
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "delete")


if __name__ == "__main__":
    unittest.main()
