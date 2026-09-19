"""Portable real-SQLite accounting tests; no Windows control or live data."""
import copy
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

from sentinel.accounting import (
    AccountingError, GIB, frame_from_fast_frame, frame_from_status,
    project_local_capacity, resolve_allocation_source,
    shared_admission_blockers, update_demand_floor,
)

NOW = 2_000_000_000.0
CONFIG = dict(local_allocatable_cpu=12, local_allocatable_ram_gib=58,
              local_physical_headroom_gib=4, local_commit_headroom_gib=4,
              heavy_io_slots=4)


def schema(conn):
    # Minimal actual DB shapes exercise the contract without importing runtime
    # adapters or untracked pressure/collector modules.
    conn.executescript("""
    CREATE TABLE reservations(id TEXT PRIMARY KEY,cpu_units REAL,ram_gib REAL,
      io_slots INTEGER,physical_bytes INTEGER,commit_bytes INTEGER,
      execution_id TEXT,lifecycle_managed INTEGER DEFAULT 0,created_at REAL,expires_at REAL);
    CREATE TABLE workers(id TEXT PRIMARY KEY,capabilities_json TEXT);
    CREATE TABLE worker_reservations(id TEXT PRIMARY KEY,worker_id TEXT,
      cpu_units REAL,ram_gib REAL,io_slots INTEGER,physical_bytes INTEGER,
      commit_bytes INTEGER,execution_id TEXT,lifecycle_managed INTEGER DEFAULT 0,
      capacity_pool TEXT,created_at REAL,expires_at REAL);
    CREATE TABLE managed_executions(execution_id TEXT PRIMARY KEY,
      allocation_kind TEXT,reservation_id TEXT,parent_execution_id TEXT,
      logon_id TEXT,job_name TEXT,state TEXT,state_revision INTEGER,coverage TEXT,
      requested_cpu_units REAL,requested_physical_bytes INTEGER,
      requested_commit_bytes INTEGER,requested_io_slots INTEGER,
      floor_cpu_units REAL,floor_physical_bytes INTEGER,floor_commit_bytes INTEGER,
      floor_io_slots INTEGER);
    CREATE TABLE adaptive_runtime(singleton INTEGER PRIMARY KEY,
      schema_version INTEGER,protocol_version INTEGER,registry_revision INTEGER,
      admission_barrier TEXT,mode TEXT);
    INSERT INTO adaptive_runtime VALUES(1,1,1,1,'NONE','off');
    """)


def status(cpu=0, physical=50, commit=50, total=64):
    stamp = datetime.fromtimestamp(NOW).strftime("%Y-%m-%d %H:%M:%S")
    return dict(generated_at=stamp, sampled_at=stamp, cpu_5min_avg=cpu,
                ram=dict(total_gb=total, free_gb=total-physical),
                memory=dict(commit_used_gib=commit, commit_limit_gib=96),
                resource_policy=dict(mode="resource-v2"),
                disks=[dict(drive="C:", free_gb=100)],
                disk_performance=dict(queue_length=0, read_latency_ms=1, write_latency_ms=1))


def slow_frame(**kwargs):
    return frame_from_status(status(**kwargs), CONFIG, now=NOW, logical_processors=12)


def request(cpu=1, physical=1, commit=None, io=0):
    return SimpleNamespace(cpu_units=cpu, ram_gib=physical,
                           commit_bytes=None if commit is None else int(commit*GIB), io_slots=io)


def insert(conn, table, **values):
    conn.execute(f"INSERT INTO {table}({','.join(values)}) VALUES({','.join('?' for _ in values)})", tuple(values.values()))


def direct(conn, key="r1", cpu=4, physical=8, commit=8, io=0, managed=True):
    execution_id = "exec-" + key if managed else None
    insert(conn, "reservations", id=key, cpu_units=cpu, ram_gib=physical,
           physical_bytes=int(physical*GIB), commit_bytes=int(commit*GIB),
           io_slots=io, execution_id=execution_id, lifecycle_managed=int(managed),
           created_at=NOW-100000, expires_at=NOW-100)
    if managed:
        insert(conn, "managed_executions", execution_id=execution_id,
               allocation_kind="direct", reservation_id=key, parent_execution_id=None,
               logon_id="same-logon", job_name="job-" + key, state="RUNNING",
               state_revision=1, coverage="job_contained",
               requested_cpu_units=cpu, requested_physical_bytes=int(physical*GIB),
               requested_commit_bytes=int(commit*GIB), requested_io_slots=io,
               floor_cpu_units=cpu, floor_physical_bytes=int(physical*GIB),
               floor_commit_bytes=int(commit*GIB), floor_io_slots=io)
    return execution_id


def fast_frame(*, cpu=10, physical=50, commit=50, jobs=None, proofs=None, revision=1, total=64):
    frame = dict(schema_version=1, clock_epoch="clock-one", registry_revision=revision,
                 window_start_tick_100ns="10000000", window_end_tick_100ns="20000000",
                 published_tick_100ns="20100000", validity="valid", errors=[], collection_skew_ms=2,
                 machine=dict(logical_processors=12, processor_groups=1, cpu_busy_units=cpu,
                              physical_total_bytes=int(total*GIB), physical_available_bytes=int((total-physical)*GIB),
                              commit_used_bytes=int(commit*GIB), commit_limit_bytes=96*GIB), jobs=jobs or [])
    return frame_from_fast_frame(frame, now_tick_100ns=21_000_000, clock_epoch="clock-one",
                                 attribution=proofs, disk=slow_frame()["disk"])


def job(execution="exec-r1", cpu=6, physical=6, commit=7, high=6, pid=101):
    value = dict(execution_id=execution, cpu_units=cpu, cpu_uncapped_high_water_units=high,
                 private_working_set_bytes=int(physical*GIB), private_commit_bytes=int(commit*GIB),
                 active_processes=1, membership_complete=True, memory_validity="valid", counter_epoch="counter")
    proof = dict(state_revision=1, counter_epoch="counter", window_start_tick_100ns="10000000",
                 window_end_tick_100ns="20000000",
                 members=[dict(pid=pid, created_filetime_100ns="134000000000000001")])
    return value, proof


class AccountingTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.conn.close)
        schema(self.conn)
        self.conn.execute("BEGIN IMMEDIATE")

    def projection(self, frame=None, config=None):
        return project_local_capacity(self.conn, frame or slow_frame(), config or CONFIG)

    def test_formal_example_a_cap_does_not_create_capacity(self):
        direct(self.conn)
        self.conn.execute("UPDATE managed_executions SET floor_cpu_units=6")
        before, proof = job(cpu=6)
        after = dict(before, cpu_units=3)
        p1 = self.projection(fast_frame(cpu=10, jobs=[before], proofs={"exec-r1": proof}))
        p2 = self.projection(fast_frame(cpu=7, jobs=[after], proofs={"exec-r1": proof}))
        self.assertEqual(p1["errors"], [])
        self.assertEqual(p1["projected"]["cpu_units"], 10)
        self.assertEqual(p2["projected"]["cpu_units"], 10)

    def test_formal_example_b_physical_budget_and_unknown_attribution(self):
        direct(self.conn)
        item, proof = job()
        frame = fast_frame(cpu=6, jobs=[item], proofs={"exec-r1": proof})
        self.assertEqual(self.projection(frame)["projected"]["physical_bytes"], 52*GIB)
        self.assertEqual(shared_admission_blockers(self.conn, request(cpu=0, physical=6), frame, CONFIG), [])
        self.assertIn("ram_capacity", [b["reason"] for b in shared_admission_blockers(self.conn, request(cpu=0, physical=6.1), frame, CONFIG)])
        frame["attribution"] = {}
        self.assertEqual(self.projection(frame)["projected"]["physical_bytes"], 58*GIB)
        small = fast_frame(cpu=6, total=59, jobs=[item], proofs={"exec-r1": proof})
        self.assertEqual(self.projection(small)["budgets"]["physical_bytes"], 55*GIB)

    def test_registry_mismatch_disables_all_subtraction_keeps_new_pending(self):
        direct(self.conn)
        direct(self.conn, "pending", cpu=1, physical=2, commit=2)
        self.conn.execute("UPDATE managed_executions SET state='PREPARED' WHERE execution_id='exec-pending'")
        self.conn.execute("UPDATE adaptive_runtime SET registry_revision=2")
        item, proof = job()
        result = self.projection(fast_frame(jobs=[item], proofs={"exec-r1": proof}))
        self.assertEqual(result["projected"]["physical_bytes"], 60*GIB)
        self.assertIn("registry_revision_mismatch", result["attribution_reasons"])

    def test_uncapped_high_water_visible_before_batched_floor_flush(self):
        direct(self.conn)
        item, proof = job(cpu=3, high=6)
        result = self.projection(fast_frame(cpu=7, jobs=[item], proofs={"exec-r1": proof}))
        self.assertEqual(result["projected"]["cpu_units"], 10)
        self.assertEqual(self.conn.execute("SELECT floor_cpu_units FROM managed_executions").fetchone()[0], 4)

    def test_floor_update_monotone_and_cas(self):
        execution = direct(self.conn)
        floor = update_demand_floor(self.conn, execution, dict(cpu_units=6, physical_bytes=9*GIB), expected_revision=1, uncapped=True)
        self.assertEqual(floor["cpu_units"], 6)
        self.assertEqual(floor["physical_bytes"], 9*GIB)
        self.assertEqual(self.conn.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0], 2)
        with self.assertRaisesRegex(AccountingError, "revision_conflict"):
            update_demand_floor(self.conn, execution, {}, expected_revision=1)
        floor = update_demand_floor(self.conn, execution, dict(cpu_units=1, physical_bytes=1), expected_revision=2, uncapped=True)
        self.assertEqual(floor["cpu_units"], 6)
        self.assertEqual(floor["physical_bytes"], 9*GIB)
        capped = update_demand_floor(self.conn, execution, dict(cpu_units=10), expected_revision=2, uncapped=False)
        self.assertEqual(capped["cpu_units"], 6)

    def test_floor_and_resolution_reject_future_schema_before_any_write(self):
        execution = direct(self.conn)
        before = self.conn.execute("SELECT floor_cpu_units,floor_physical_bytes,floor_commit_bytes,floor_io_slots,state_revision FROM managed_executions").fetchone()
        revision = self.conn.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0]
        for column in ("schema_version", "protocol_version"):
            with self.subTest(column=column):
                self.conn.execute(f"UPDATE adaptive_runtime SET {column}=9")
                with self.assertRaisesRegex(AccountingError, "schema_version_unsupported"):
                    update_demand_floor(self.conn, execution, dict(cpu_units=8, physical_bytes=10*GIB), expected_revision=1, uncapped=True)
                with self.assertRaisesRegex(AccountingError, "schema_version_unsupported"):
                    resolve_allocation_source(self.conn, execution)
                # Assert inside the same still-open transaction: the rejected
                # call did not rely on caller rollback to undo a partial write.
                self.assertEqual(self.conn.execute("SELECT floor_cpu_units,floor_physical_bytes,floor_commit_bytes,floor_io_slots,state_revision FROM managed_executions").fetchone(), before)
                self.assertEqual(self.conn.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0], revision)
                self.conn.execute(f"UPDATE adaptive_runtime SET {column}=1")

    def test_grace_ttl_root_exit_and_unknown_state_preserve_capacity(self):
        direct(self.conn, cpu=1, physical=2, commit=3, io=1)
        for state in ("PREPARED", "LAUNCHING", "START_UNKNOWN", "DRAINING", "UNCERTAIN_HOLD"):
            self.conn.execute("UPDATE managed_executions SET state=?", (state,))
            p = self.projection()
            self.assertEqual(p["errors"], [])
            self.assertEqual(p["projected"]["physical_bytes"], 52*GIB)
            self.assertEqual(p["projected"]["commit_bytes"], 53*GIB)
            self.assertEqual(p["projected"]["io_slots"], 1)

    def test_all_local_aliases_count_across_pools_remote_untouched(self):
        direct(self.conn, cpu=1, physical=1, commit=1, managed=False)
        for i, local in enumerate((True, True, False)):
            insert(self.conn, "workers", id=f"worker{i}", capabilities_json=json.dumps(dict(local=local)))
            insert(self.conn, "worker_reservations", id=f"r{i}", worker_id=f"worker{i}", cpu_units=1,
                   ram_gib=2, capacity_pool=f"pool{i}", created_at=NOW-10000, expires_at=NOW-500)
        result = self.projection()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["projected"]["physical_bytes"], 55*GIB)
        self.assertEqual(result["projected"]["io_slots"], 2)
        self.assertEqual(len(result["allocations"]), 3)

    def test_ambiguous_or_orphaned_scope_holds_instead_of_omitting(self):
        insert(self.conn, "worker_reservations", id="orphan", worker_id="absent", cpu_units=1, ram_gib=2)
        result = self.projection()
        self.assertEqual(result["projected"]["physical_bytes"], 52*GIB)
        self.assertIn("local_scope_unknown", [x["reason"] for x in result["errors"]])

    def test_conflicting_canonical_local_host_fails_closed(self):
        insert(self.conn, "workers", id="wrong", capabilities_json=json.dumps(dict(local=True, canonical_host_id="other")))
        insert(self.conn, "worker_reservations", id="wrong", worker_id="wrong", cpu_units=1, ram_gib=2)
        result = self.projection(config={**CONFIG, "local_host_id": "this"})
        self.assertIn("local_scope_unknown", [x["reason"] for x in result["errors"]])

    def test_shared_pages_incomplete_membership_and_overlap_never_deduct(self):
        direct(self.conn)
        item, proof = job()
        item["memory_validity"] = "unknown"
        frame = fast_frame(jobs=[item], proofs={"exec-r1": proof})
        self.assertEqual(self.projection(frame)["projected"]["physical_bytes"], 58*GIB)
        item["memory_validity"] = "valid"
        item["membership_complete"] = False
        self.assertEqual(self.projection(frame)["projected"]["cpu_units"], 14)
        direct(self.conn, "other", cpu=1, physical=1, commit=1)
        item["membership_complete"] = True
        other, other_proof = job(execution="exec-other", cpu=1, physical=1, commit=1)
        frame = fast_frame(jobs=[item, other], proofs={"exec-r1": proof, "exec-other": other_proof})
        result = self.projection(frame)
        self.assertEqual(result["projected"]["physical_bytes"], 59*GIB)
        self.assertIn("overlapping_membership", result["attribution_reasons"])

    def test_inconsistent_aggregate_resets_entire_resource_not_clamped(self):
        direct(self.conn)
        direct(self.conn, "other", cpu=1, physical=1, commit=1)
        item, proof = job(cpu=6, physical=6)
        other, other_proof = job(execution="exec-other", cpu=5, physical=1, commit=1, high=1, pid=102)
        result = self.projection(fast_frame(cpu=10, jobs=[item, other], proofs={"exec-r1": proof, "exec-other": other_proof}))
        self.assertEqual(result["projected"]["cpu_units"], 17)
        self.assertIn("cpu_units_aggregate_inconsistent", result["attribution_reasons"])
        # Valid independent physical measurements still subtract.
        self.assertEqual(result["projected"]["physical_bytes"], 52*GIB)

    def test_pending_and_unmanaged_cannot_claim_subtraction(self):
        direct(self.conn, managed=False)
        item, proof = job()
        p = self.projection(fast_frame(jobs=[item], proofs={"exec-r1": proof}))
        self.assertEqual(p["projected"]["physical_bytes"], 58*GIB)

    def test_active_barrier_blocks_any_priority_but_no_grant_changes(self):
        self.conn.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        req = request()
        for priority in ("P0", "P1", "P2", "P3"):
            req.priority = priority
            result = shared_admission_blockers(self.conn, req, slow_frame(), CONFIG)
            self.assertEqual(result[0]["reason"], "admission_barrier")
        self.assertEqual(shared_admission_blockers(self.conn, req, slow_frame(), CONFIG, exempt=True), [])

    def test_verified_exemption_bypasses_stale_unknown_load_not_ledger(self):
        snapshot = status(cpu=100, physical=63, commit=95)
        snapshot["sampled_at"] = datetime.fromtimestamp(NOW-600).strftime("%Y-%m-%d %H:%M:%S")
        snapshot.pop("resource_policy")
        frame = frame_from_status(snapshot, CONFIG, now=NOW, logical_processors=12)
        frame["machine"]["commit_used_bytes"] = None
        self.assertTrue(shared_admission_blockers(self.conn, request(), frame, CONFIG))
        self.assertEqual(shared_admission_blockers(self.conn, request(), frame, CONFIG, exempt=True), [])
        self.assertIsNone(project_local_capacity(self.conn, frame, CONFIG)["projected"]["commit_bytes"])
        insert(self.conn, "worker_reservations", id="unverified", worker_id="absent", cpu_units=1, ram_gib=1)
        blocked = shared_admission_blockers(self.conn, request(), frame, CONFIG, exempt=True)
        self.assertIn("local_scope_unknown", [b["reason"] for b in blocked])

    def test_exemption_cannot_bypass_schema_request_or_binding_integrity(self):
        direct(self.conn)
        frame = slow_frame()
        invalid = request(cpu=float("nan"))
        self.assertIn("request_resources_invalid", [b["reason"] for b in shared_admission_blockers(self.conn, invalid, frame, CONFIG, exempt=True)])
        self.conn.execute("UPDATE adaptive_runtime SET schema_version=9")
        self.assertIn("schema_version_unsupported", [b["reason"] for b in shared_admission_blockers(self.conn, request(), frame, CONFIG, exempt=True)])
        self.conn.execute("UPDATE adaptive_runtime SET schema_version=1,mode='active'")
        self.conn.execute("DELETE FROM reservations")
        # Missing fast telemetry must not short-circuit the later ledger read.
        result = shared_admission_blockers(self.conn, request(), frame, CONFIG, exempt=True)
        self.assertIn("allocation_missing", [b["reason"] for b in result])

    def test_no_invented_zero_for_unknown_or_invalid_measurements(self):
        for field, bad, reason in (("cpu_busy_units", 13, "cpu_unknown"),
                                    ("physical_available_bytes", 65*GIB, "ram_unknown"),
                                    ("commit_used_bytes", 97*GIB, "commit_unknown")):
            frame = slow_frame()
            frame["machine"][field] = bad
            self.assertIn(reason, [b["reason"] for b in shared_admission_blockers(self.conn, request(), frame, CONFIG)])

    def test_separate_commit_and_physical_requests(self):
        frame = slow_frame(physical=50, commit=91)
        self.assertEqual(shared_admission_blockers(self.conn, request(physical=6, commit=1), frame, CONFIG), [])
        self.assertIn("commit_capacity", [b["reason"] for b in shared_admission_blockers(self.conn, request(physical=1, commit=2), frame, CONFIG)])

    def test_policy_cannot_weaken_fixed_reserves_or_total_budget(self):
        config = {**CONFIG, "local_allocatable_ram_gib": 999, "local_physical_headroom_gib": 0, "local_commit_headroom_gib": 0}
        p = self.projection(config=config)
        self.assertEqual(p["budgets"]["physical_bytes"], 58*GIB)
        self.assertEqual(p["budgets"]["commit_bytes"], 92*GIB)

    def test_fast_gap_clock_discontinuity_and_slow_fallback_hold(self):
        frame = fast_frame()
        frame["now_tick_100ns"] = 99_000_000
        self.assertIn("telemetry_stale", [b["reason"] for b in shared_admission_blockers(self.conn, request(), frame, CONFIG)])
        frame = fast_frame()
        frame["expected_clock_epoch"] = "other"
        self.assertIn("telemetry_stale", [b["reason"] for b in shared_admission_blockers(self.conn, request(), frame, CONFIG)])
        self.conn.execute("UPDATE adaptive_runtime SET mode='active'")
        self.assertIn("fast_frame_required", [b["reason"] for b in shared_admission_blockers(self.conn, request(), slow_frame(), CONFIG)])

    def test_slow_disk_has_independent_freshness(self):
        snapshot = status()
        snapshot["disk_performance"]["sampled_at"] = datetime.fromtimestamp(NOW-91).strftime("%Y-%m-%d %H:%M:%S")
        frame = frame_from_status(snapshot, CONFIG, now=NOW, logical_processors=12)
        self.assertTrue(frame["fresh"])
        self.assertIn("disk_telemetry_stale", [b["reason"] for b in shared_admission_blockers(self.conn, request(), frame, CONFIG)])

    def test_parent_reuses_one_allocation_cycles_and_cross_logon_rejected(self):
        direct(self.conn)
        insert(self.conn, "managed_executions", execution_id="child", allocation_kind="parent",
               parent_execution_id="exec-r1", logon_id="same-logon", state="RUNNING", state_revision=1)
        self.assertEqual(resolve_allocation_source(self.conn, "child")["reservation_id"], "r1")
        self.assertEqual(len(self.projection()["allocations"]), 1)
        with self.assertRaisesRegex(AccountingError, "parent_has_no_independent_floor"):
            update_demand_floor(self.conn, "child", {}, expected_revision=1)
        self.conn.execute("UPDATE managed_executions SET logon_id='other' WHERE execution_id='child'")
        with self.assertRaisesRegex(AccountingError, "allocation_parent_logon_mismatch"):
            resolve_allocation_source(self.conn, "child")
        self.conn.execute("UPDATE managed_executions SET logon_id='same-logon',parent_execution_id='child' WHERE execution_id='child'")
        with self.assertRaisesRegex(AccountingError, "allocation_parent_invalid"):
            resolve_allocation_source(self.conn, "child")

    def test_released_terminal_metadata_does_not_block_but_orphan_does(self):
        direct(self.conn)
        self.conn.execute("UPDATE managed_executions SET state='FINISHED'")
        self.conn.execute("DELETE FROM reservations")
        self.assertEqual(self.projection()["errors"], [])
        self.conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD'")
        self.assertIn("allocation_missing", [b["reason"] for b in self.projection()["errors"]])

    def test_unknown_schema_and_nontransaction_projection_fail_closed(self):
        self.conn.execute("UPDATE adaptive_runtime SET schema_version=9")
        self.assertIn("schema_version_unsupported", [b["reason"] for b in self.projection()["errors"]])
        self.conn.execute("COMMIT")
        with self.assertRaisesRegex(AccountingError, "transaction_required"):
            self.projection()

    def test_sqlite_competing_direct_and_routed_admissions_serialize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "isolated.db"
            conn = sqlite3.connect(path, isolation_level=None)
            schema(conn)
            insert(conn, "workers", id="local-alias", capabilities_json='{"local":true}')
            conn.close()
            barrier = threading.Barrier(2)

            def admission(kind):
                db = sqlite3.connect(path, isolation_level=None, timeout=5)
                try:
                    barrier.wait(timeout=5)
                    db.execute("BEGIN IMMEDIATE")
                    denied = shared_admission_blockers(db, request(physical=6), slow_frame(), CONFIG)
                    if not denied:
                        if kind == "direct":
                            direct(db, "won-direct", cpu=1, physical=6, commit=6, managed=False)
                        else:
                            insert(db, "worker_reservations", id="won-routed", worker_id="local-alias", cpu_units=1,
                                   ram_gib=6, io_slots=0, physical_bytes=6*GIB, commit_bytes=6*GIB)
                    db.execute("COMMIT")
                    return not denied
                finally:
                    db.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(admission, ("direct", "routed")))
            self.assertEqual(sorted(outcomes), [False, True])
            conn = sqlite3.connect(path, isolation_level=None)
            try:
                conn.execute("BEGIN")
                p = project_local_capacity(conn, slow_frame(), CONFIG)
                self.assertEqual(p["projected"]["physical_bytes"], 56*GIB)
                self.assertEqual(len(p["allocations"]), 1)
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
