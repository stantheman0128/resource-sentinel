"""Real frozen legacy SQL against an isolated migrated SQLite ledger.

No test launches work or authorizes this host through an alternate ledger.
Synthetic lifecycle rows supply explicit fence inputs, not native lifecycle
evidence. The SELECT-only old retry case deliberately remains unsafe: persistent
DML triggers cannot replace coordinated writer and launch-path deployment.
"""
import ast
from datetime import datetime
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from sentinel.adaptive.store import migrate_schema
from tests.fixtures import adaptive_legacy_writers_0b2f378 as legacy


NOW = 2_000_000_000.0
GIB = 1 << 30
PID = 5001
BIRTH = 1234.0
CONFIG = {"local_allocatable_cpu": 8, "local_allocatable_ram_gib": 58,
          "local_commit_headroom_gib": 4, "heavy_io_slots": 1,
          "reservation_ttl_min": 120, "local_worker_id": "fixture-local"}


def status(*, light="GREEN", now=NOW):
    return {"generated_at": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S"),
            "light": light, "cpu_pct": 0, "cpu_5min_avg": 0,
            "ram": {"total_gb": 64, "free_gb": 64},
            "memory": {"commit_used_gib": 0, "commit_limit_gib": 100}}


def worker():
    return legacy.Worker(
        id="fixture-local", provider="fixture", failure_domain="fixture-host",
        capacity_pool="fixture-host", quota_domain="fixture-host", max_concurrency=32,
        state="AVAILABLE", automation_level="AUTOMATABLE", os="windows",
        capacity_ram_gib=64, allocatable_ram_gib=58, allocatable_cpu=8,
        allocatable_disk_gib=100, capabilities={"local": True, "adapter_ready": True},
        observed_at=NOW, probe_expires_at=NOW + 24 * 3600)


class FrozenSourceTests(unittest.TestCase):
    def test_copied_definitions_match_frozen_public_source_hashes(self):
        self.assertEqual(legacy.SOURCE_COMMIT, "0b2f37819a2d4f68299fbec3fe619a4d05ba4749")
        self.assertEqual(set(legacy.SOURCE_BLOBS), {"sentinel/coordinator.py", "sentinel/maintainer.py"})
        source = Path(legacy.__file__).read_text(encoding="utf-8")
        lines = source.splitlines(keepends=True)
        tree = ast.parse(source)
        nodes = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        nodes[target.id] = node
            elif isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                nodes[node.name] = node
                if isinstance(node, ast.ClassDef):
                    for member in node.body:
                        if isinstance(member, ast.FunctionDef):
                            nodes[node.name + "." + member.name] = member
            elif isinstance(node, ast.ImportFrom):
                self.assertFalse((node.module or "").startswith("sentinel"))
            elif isinstance(node, ast.Import):
                self.assertFalse(any(alias.name.startswith("sentinel") for alias in node.names))
        for name, record in legacy.SOURCE_NODES.items():
            with self.subTest(definition=name):
                node = nodes[name]
                start = min([node.lineno] + [item.lineno for item in getattr(node, "decorator_list", ())])
                copied = "".join(lines[start - 1:node.end_lineno])
                self.assertEqual(hashlib.sha256(copied.encode("utf-8")).hexdigest(), record["sha256"])
                self.assertIn(record["path"], legacy.SOURCE_BLOBS)
                self.assertGreaterEqual(record["first_line"], 1)
                self.assertGreaterEqual(record["last_line"], record["first_line"])
        self.assertEqual(legacy.Coordinator.__bases__, (object,))
        self.assertEqual(legacy.Maintainer.__bases__, (object,))


class LegacyWriterFenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        # Original bootstrap, data normalization and SQL all run before the
        # current migration. No current admission helper is used by old code.
        self.direct = legacy.Coordinator(self.directory, pid_identity=lambda pid: (True, BIRTH))
        self.routed = legacy.Maintainer(self.directory)
        self.worker = worker()
        self.routed.upsert_worker(self.worker, now=NOW)
        self.seed_request = self.request("seed-direct")
        direct = self.direct.admit(self.seed_request, status(), config=CONFIG, now=NOW)
        self.assertTrue(direct["allowed"], direct)
        self.direct_id = direct["reservation_id"]
        self.seed_task = self.task("seed-routed")
        routed = self.routed.route_and_reserve(self.seed_task, now=NOW)
        self.assertTrue(routed["reserved"], routed)
        self.routed_id = routed["reservation_id"]
        # Retain an actual old connection and cached UPDATE prepared before
        # triggers exist, to test persistence beyond refreshed Python imports.
        self.preopened = self.direct._connect()
        self.addCleanup(self.preopened.close)
        self.preopened.execute(
            "UPDATE reservations SET heartbeat_at=?,expires_at=?,tool_use_id=? WHERE id=?",
            (NOW, NOW + 7200, self.seed_request.tool_use_id, self.direct_id))
        self.conn = sqlite3.connect(self.db, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        migrate_schema(self.conn)

    @staticmethod
    def request(name):
        return legacy.ResourceRequest(PID, BIRTH, "fixture-repository", "fixture command " + name,
            "MEDIUM", "P2", name, cpu_units=.25, ram_gib=.5, io_slots=0)

    @staticmethod
    def task(name):
        return legacy.Task(name, ram_gib=.5, cpu_units=.25, execution_preference="LOCAL_REQUIRED",
                           allowed_worker_ids=("fixture-local",))

    def row(self, table, identifier):
        result = self.conn.execute(f"SELECT * FROM {table} WHERE id=?", (identifier,)).fetchone()
        return None if result is None else dict(result)

    def counts(self):
        return {table: self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                for table in ("reservations", "worker_reservations", "executions", "routed_executions", "queue")}

    def obligation(self, kind="direct"):
        """Create one synthetic supported-writer obligation in this test DB."""
        table = "reservations" if kind == "direct" else "worker_reservations"
        identifier = self.direct_id if kind == "direct" else self.routed_id
        allocation = self.row(table, identifier)
        execution = str(uuid.uuid4())
        io_slots = allocation.get("io_slots")
        if io_slots is None:
            io_slots = 1 if kind == "routed" else 0
        demand = {"cpu_units": allocation["cpu_units"],
                  "physical_bytes": int(allocation["ram_gib"] * GIB),
                  "commit_bytes": int(allocation["ram_gib"] * GIB),
                  "io_slots": io_slots}
        metadata = {
            "execution_id": execution, "task_id": allocation.get("task_id", "fixture-task-" + execution),
            "session_id": "fixture-session", "principal_id": "fixture-principal", "logon_id": "S-1-5-5-1-2",
            "allocation_kind": kind, "reservation_id": identifier, "parent_execution_id": None,
            "spec_hash": allocation["spec_hash"], "wrapper_pid": PID,
            "wrapper_created_filetime_100ns": "134343072000000001", "role": "background",
            "priority": "P2", "state": "RESERVED", "claim_token_hash": "a" * 64,
            "created_at": NOW, "heartbeat_at": NOW,
            **{"requested_" + name: value for name, value in demand.items()},
            **{"floor_" + name: value for name, value in demand.items()},
        }
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            extra = ",managed_spec_hash=spec_hash" if kind == "direct" else ""
            self.conn.execute(f"""UPDATE {table} SET lifecycle_managed=1,execution_id=?,
                physical_bytes=?,commit_bytes=?,io_slots=?,writer_protocol=1,writer_revision=writer_revision+1{extra}
                WHERE id=?""", (execution, demand["physical_bytes"], demand["commit_bytes"], demand["io_slots"], identifier))
            self.conn.execute("INSERT INTO managed_executions(" + ",".join(metadata) + ") VALUES(" +
                              ",".join("?" for _ in metadata) + ")", tuple(metadata.values()))
            self.conn.commit()
        except BaseException:
            self.conn.rollback()
            raise
        return execution

    def test_no_obligation_keeps_old_direct_admit_reuse_retry_and_release_compatible(self):
        fresh = self.request("ordinary-direct")
        admitted = self.direct.admit(fresh, status(), config=CONFIG, now=NOW)
        self.assertTrue(admitted["allowed"], admitted)
        reused = self.direct.admit(fresh, status(), config=CONFIG, now=NOW + 1)
        self.assertTrue(reused["reused"])
        self.assertEqual(self.row("reservations", admitted["reservation_id"])["writer_protocol"], 0)
        self.assertEqual(self.direct.release(owner_pid=PID, tool_use_id=fresh.tool_use_id, now=NOW + 2), 1)
        queued = self.request("ordinary-queued")
        denied = self.direct.admit(queued, status(light="RED"), config=CONFIG, now=NOW)
        self.assertFalse(denied["allowed"])
        allowed = self.direct.retry_queued(queued.request_key, status(), config=CONFIG, now=NOW + 1)
        self.assertTrue(allowed["allowed"], allowed)
        self.assertEqual(self.row("reservations", allowed["reservation_id"])["tool_use_id"], "")

    def test_no_obligation_keeps_old_routing_heartbeat_worker_upsert_and_release_compatible(self):
        task = self.task("ordinary-routed")
        admitted = self.routed.route_and_reserve(task, now=NOW)
        self.assertTrue(admitted["reserved"], admitted)
        self.assertTrue(self.routed.heartbeat(task.id, now=NOW + 1))
        self.assertTrue(self.routed.route_and_reserve(task, now=NOW + 2)["reused"])
        self.routed.upsert_worker(self.worker, now=NOW + 3)
        self.assertEqual(self.routed.release(task_id=task.id, now=NOW + 4), 1)
        self.assertIsNone(self.row("worker_reservations", admitted["reservation_id"]))

    def test_no_obligation_keeps_old_direct_and_routed_ttl_cleanup_compatible(self):
        self.assertEqual(self.direct.cleanup(config=CONFIG, now=NOW + 7201), [self.direct_id])
        routed = self.routed.route_and_reserve(self.task("after-ordinary-cleanup"), now=NOW + 7201)
        self.assertTrue(routed["reserved"], routed)
        self.assertIsNone(self.row("reservations", self.direct_id))
        self.assertIsNone(self.row("worker_reservations", self.routed_id))
        self.assertEqual(self.counts()["executions"], 1)
        self.assertEqual(self.counts()["routed_executions"], 1)

    def test_managed_obligation_fences_real_old_direct_admission_and_rolls_back_queue(self):
        self.obligation("routed")
        before = self.counts()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
            self.direct.admit(self.request("blocked-direct"), status(), config=CONFIG, now=NOW)
        self.assertEqual(self.counts(), before)

    def test_managed_obligation_fences_real_old_route_admission(self):
        self.obligation("direct")
        before = self.counts()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
            self.routed.route_and_reserve(self.task("blocked-routed"), now=NOW)
        self.assertEqual(self.counts(), before)

    def test_old_direct_reuse_cannot_refresh_supported_row_without_revision_increment(self):
        self.obligation("direct")
        before = self.row("reservations", self.direct_id)
        self.assertEqual(before["writer_protocol"], 1)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
            self.direct.admit(self.seed_request, status(), config=CONFIG, now=NOW + 1)
        self.assertEqual(self.row("reservations", self.direct_id), before)

    def test_old_routed_reuse_and_heartbeat_cannot_refresh_supported_row(self):
        self.obligation("routed")
        before = self.row("worker_reservations", self.routed_id)
        for operation in (lambda: self.routed.route_and_reserve(self.seed_task, now=NOW + 1),
                          lambda: self.routed.heartbeat(self.seed_task.id, now=NOW + 1)):
            with self.subTest(operation=operation), self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
                operation()
            self.assertEqual(self.row("worker_reservations", self.routed_id), before)

    def test_old_worker_upsert_is_fenced_while_obligations_survive(self):
        self.obligation("direct")
        before = self.row("workers", self.worker.id)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required|worker_replace_forbidden"):
            self.routed.upsert_worker(self.worker, now=NOW + 1)
        self.assertEqual(self.row("workers", self.worker.id), before)

    def test_old_owner_release_cannot_delete_managed_direct_or_leave_false_archive(self):
        self.obligation("direct")
        before = self.counts()
        row = self.row("reservations", self.direct_id)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "managed_allocation_release_requires_terminal"):
            self.direct.release(owner_pid=PID, tool_use_id=self.seed_request.tool_use_id, now=NOW + 1)
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.row("reservations", self.direct_id), row)

    def test_old_direct_ttl_cleanup_cannot_delete_or_archive_managed_allocation(self):
        self.obligation("direct")
        before = self.counts()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "managed_allocation_release_requires_terminal"):
            self.direct.cleanup(config=CONFIG, now=NOW + 7201)
        self.assertEqual(self.counts(), before)
        self.assertIsNotNone(self.row("reservations", self.direct_id))

    def test_old_routed_release_and_ttl_cleanup_preserve_managed_floor_and_archive(self):
        self.obligation("routed")
        before = self.counts()
        row = self.row("worker_reservations", self.routed_id)
        for operation in (lambda: self.routed.release(task_id=self.seed_task.id, now=NOW + 1),
                          lambda: self.routed.route_and_reserve(self.task("cleanup-probe"), now=NOW + 7201)):
            with self.subTest(operation=operation), self.assertRaisesRegex(sqlite3.IntegrityError, "managed_allocation_release_requires_terminal"):
                operation()
            self.assertEqual(self.counts(), before)
            self.assertEqual(self.row("worker_reservations", self.routed_id), row)

    def test_fence_applies_to_connection_and_statement_cached_before_migration(self):
        self.obligation("direct")
        before = self.row("reservations", self.direct_id)
        with patch.object(self.direct, "_connect", return_value=self.preopened):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
                self.direct.admit(self.seed_request, status(), config=CONFIG, now=NOW + 1)
        self.assertEqual(self.row("reservations", self.direct_id), before)

    def test_recovery_barrier_alone_fences_old_direct_and_routed_admission(self):
        self.conn.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        before = self.counts()
        for operation in (lambda: self.direct.admit(self.request("hold-direct"), status(), config=CONFIG, now=NOW),
                          lambda: self.routed.route_and_reserve(self.task("hold-routed"), now=NOW)):
            with self.subTest(operation=operation), self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
                operation()
            self.assertEqual(self.counts(), before)

    def test_positive_terminal_fixture_permits_old_delete_without_erasing_lifecycle_record(self):
        execution = self.obligation("direct")
        # This supplies a positive terminal input; it is not a lifecycle proof.
        self.conn.execute("""UPDATE managed_executions SET state='CANCELLED_BEFORE_START',
            launch_sealed=1,launch_in_flight=0,claim_consumed=1,finished_at=? WHERE execution_id=?""", (NOW, execution))
        self.assertEqual(self.direct.release(owner_pid=PID, tool_use_id=self.seed_request.tool_use_id, now=NOW + 1), 1)
        self.assertIsNone(self.row("reservations", self.direct_id))
        self.assertEqual(self.conn.execute("SELECT state FROM managed_executions WHERE execution_id=?", (execution,)).fetchone()[0],
                         "CANCELLED_BEFORE_START")

    def test_negative_select_only_old_retry_still_returns_allowed_and_requires_launch_cutover(self):
        """Expected limitation: SQL DML fencing cannot revoke an old read ACK."""
        self.obligation("direct")
        self.conn.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        before = self.counts()
        row = self.row("reservations", self.direct_id)
        statements = []
        original_connect = self.direct._connect

        def traced_connection():
            connection = original_connect()
            connection.set_trace_callback(statements.append)
            return connection

        with patch.object(self.direct, "_connect", side_effect=traced_connection):
            acknowledgement = self.direct.retry_queued(self.seed_request.request_key,
                status(light="RED"), config=CONFIG, now=NOW + 7201)
        # Deliberately assert the unsafe old behavior rather than modifying its
        # implementation or expectations to claim that migration closes it.
        self.assertEqual(acknowledgement, {"allowed": True, "reservation_id": self.direct_id,
                                          "reused": True, "request_key": self.seed_request.request_key})
        self.assertEqual(len(statements), 2)
        self.assertTrue(all(statement.lstrip().upper().startswith("SELECT ") for statement in statements))
        self.assertEqual(self.counts(), before)
        self.assertEqual(self.row("reservations", self.direct_id), row)


class FirstWriterBootstrapFenceTests(unittest.TestCase):
    """The first upgraded owner must fence peer capacity before it is used."""
    row = LegacyWriterFenceTests.row
    obligation = LegacyWriterFenceTests.obligation
    request = staticmethod(LegacyWriterFenceTests.request)
    task = staticmethod(LegacyWriterFenceTests.task)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"

    def open_connection(self):
        self.conn = sqlite3.connect(self.db, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)

    def require_peer_tables_and_fence(self, tables, capacity_table):
        actual = {row[0] for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue(set(tables) <= actual)
        columns = {row[1] for row in self.conn.execute(f"PRAGMA table_info({capacity_table})")}
        self.assertTrue({"writer_protocol", "writer_revision", "execution_id", "lifecycle_managed"} <= columns)
        trigger = "adaptive_writer_" + capacity_table + "_insert"
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)).fetchone())

    def seed_worker_without_running_peer_constructor(self):
        # Explicit setup against the eagerly created table, not an upgraded
        # stand-in for the old writer being tested after the obligation exists.
        values = legacy.asdict(worker().normalized())
        values["capabilities_json"] = json.dumps(values.pop("capabilities"))
        values.update(updated_at=NOW, writer_protocol=1, writer_revision=0)
        self.conn.execute("INSERT INTO workers(" + ",".join(values) + ") VALUES(" +
                          ",".join("?" for _ in values) + ")", tuple(values.values()))

    def test_coordinator_first_fences_missing_routed_peer_before_old_maintainer_bootstrap(self):
        from sentinel.coordinator import Coordinator

        Coordinator(self.directory, pid_identity=lambda pid: (True, BIRTH))
        self.open_connection()
        self.require_peer_tables_and_fence({"workers", "worker_reservations", "routed_executions"},
                                           "worker_reservations")
        direct = legacy.Coordinator(self.directory, pid_identity=lambda pid: (True, BIRTH))
        admitted = direct.admit(self.request("coordinator-first"), status(), config=CONFIG, now=NOW)
        self.assertTrue(admitted["allowed"], admitted)
        self.direct_id = admitted["reservation_id"]
        self.seed_worker_without_running_peer_constructor()
        self.obligation("direct")
        # This is the first Maintainer constructor, using its actual old DDL.
        old_peer = legacy.Maintainer(self.directory)
        self.require_peer_tables_and_fence({"workers", "worker_reservations", "routed_executions"},
                                           "worker_reservations")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
            old_peer.route_and_reserve(self.task("old-route-after-first-coordinator"), now=NOW)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM worker_reservations").fetchone()[0], 0)

    def test_maintainer_first_fences_missing_direct_peer_before_old_coordinator_bootstrap(self):
        from sentinel.maintainer import Maintainer

        Maintainer(self.directory)
        self.open_connection()
        self.require_peer_tables_and_fence({"reservations", "executions"}, "reservations")
        routed = legacy.Maintainer(self.directory)
        routed.upsert_worker(worker(), now=NOW)
        admitted = routed.route_and_reserve(self.task("maintainer-first"), now=NOW)
        self.assertTrue(admitted["reserved"], admitted)
        self.routed_id = admitted["reservation_id"]
        self.obligation("routed")
        # Queue/sample support may be created here; the capacity table must
        # already exist and retain its triggers throughout this old bootstrap.
        old_peer = legacy.Coordinator(self.directory, pid_identity=lambda pid: (True, BIRTH))
        self.require_peer_tables_and_fence({"reservations", "executions"}, "reservations")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "capacity_writer_protocol_required"):
            old_peer.admit(self.request("old-direct-after-first-maintainer"), status(), config=CONFIG, now=NOW)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM queue").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
