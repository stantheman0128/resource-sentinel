"""Isolated read-only diagnostics: no native probes, control or live databases."""
from __future__ import annotations

from contextlib import closing
import hashlib
import itertools
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from sentinel.adaptive.query import query_adaptive


class AdaptiveQueryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "sentinel.db"

    def create_database(self, count=1, *, version=1, mode="off"):
        with closing(sqlite3.connect(self.database)) as conn:
            conn.executescript("""
                CREATE TABLE adaptive_runtime (
                    singleton INTEGER PRIMARY KEY, schema_version INTEGER,
                    protocol_version INTEGER, mode TEXT, registry_revision INTEGER,
                    admission_barrier TEXT, active_logon_id TEXT, guardian_epoch TEXT);
                CREATE TABLE reservations (
                    id TEXT PRIMARY KEY, execution_id TEXT, lifecycle_managed INTEGER);
                CREATE TABLE managed_executions (
                    execution_id TEXT PRIMARY KEY, allocation_kind TEXT,
                    reservation_id TEXT, parent_execution_id TEXT, state TEXT,
                    state_revision INTEGER, coverage TEXT, launch_in_flight INTEGER,
                    launch_sealed INTEGER, wrapper_pid INTEGER,
                    wrapper_created_filetime_100ns TEXT, root_pid INTEGER,
                    root_created_filetime_100ns TEXT, floor_cpu_units REAL,
                    floor_physical_bytes INTEGER, floor_commit_bytes INTEGER,
                    floor_io_slots INTEGER, hold_reason TEXT,
                    claim_token_hash TEXT, principal_id TEXT, session_id TEXT,
                    raw_command TEXT);
            """)
            conn.execute("INSERT INTO adaptive_runtime VALUES(1,?,1,?,7,'NONE',?,?)",
                         (version, mode, "PRIVATE-LOGON", "PRIVATE-EPOCH"))
            for index in range(count):
                execution_id, reservation_id = f"execution-{index:03d}", f"reservation-{index:03d}"
                conn.execute("INSERT INTO reservations VALUES(?,?,1)", (reservation_id, execution_id))
                conn.execute("""INSERT INTO managed_executions VALUES(
                    ?,'direct',?,NULL,'RUNNING',3,'job_contained',0,1,4242,
                    '134342000123456789',4343,'134342000123456791',2.5,4294967296,
                    6442450944,1,NULL,?,?,?,?)""",
                    (execution_id, reservation_id, "PRIVATE-CLAIM", "PRIVATE-PRINCIPAL",
                     "PRIVATE-SESSION", "PRIVATE-COMMAND"))
            conn.commit()

    def database_fingerprint(self):
        return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in self.root.iterdir() if path.is_file()}

    def test_missing_database_and_cli_do_not_create_directory(self):
        missing = self.root / "does-not-exist"
        result = query_adaptive(missing / "sentinel.db")
        self.assertEqual(result["reason"], "database_missing")
        self.assertFalse(missing.exists())
        script = Path(__file__).resolve().parents[1] / "scripts" / "sentinelctl.py"
        process = subprocess.run([sys.executable, str(script), "--data-dir", str(missing),
                                  "adaptive-query"], capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 2, process.stderr)
        self.assertEqual(json.loads(process.stdout)["reason"], "database_missing")
        self.assertFalse(missing.exists())

    def test_unknown_version_is_unavailable_without_mutation(self):
        self.create_database(version=19)
        before = self.database_fingerprint()
        result = query_adaptive(self.database)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "unsupported_adaptive_schema")
        self.assertEqual(result["executions"], [])
        self.assertEqual(before, self.database_fingerprint())

    def test_absent_adaptive_schema_is_not_migrated(self):
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute("CREATE TABLE legacy_only (id INTEGER)")
            conn.commit()
        before = self.database_fingerprint()
        self.assertEqual(query_adaptive(self.database)["reason"], "adaptive_schema_missing")
        self.assertEqual(before, self.database_fingerprint())

    def test_snapshot_is_sanitized_and_filetime_is_exact_string(self):
        self.create_database()
        before = self.database_fingerprint()
        result = query_adaptive(self.database)
        self.assertTrue(result["available"], result)
        self.assertFalse(result["control_writes"])
        self.assertEqual(result["native_readiness"], "unverified")
        self.assertEqual(result["os_limit_state"], "unverified")
        self.assertEqual(result["recorded_mode"], "off")
        row = result["executions"][0]
        self.assertEqual(row["wrapper"]["created_filetime_100ns"], "134342000123456789")
        self.assertEqual(row["root"]["created_filetime_100ns"], "134342000123456791")
        self.assertEqual(row["allocation"]["recorded_binding"], "recorded_binding_matches")
        self.assertEqual(row["floor"], dict(cpu_units=2.5, physical_bytes=4294967296,
                                           commit_bytes=6442450944, io_slots=1))
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertEqual(before, self.database_fingerprint())

    def test_persisted_mode_does_not_claim_readiness_or_restore(self):
        self.create_database()
        for mode in ("shadow", "canary", "limited"):
            with self.subTest(mode=mode):
                with closing(sqlite3.connect(self.database)) as conn:
                    conn.execute("UPDATE adaptive_runtime SET mode=?", (mode,))
                    conn.commit()
                result = query_adaptive(self.database)
                self.assertEqual(result["recorded_mode"], mode)
                self.assertEqual(result["native_readiness"], "unverified")
                self.assertEqual(result["os_limit_state"], "unverified")
                self.assertFalse(result["control_writes"])

    def test_unknown_mode_and_invalid_singletons_remain_unavailable(self):
        self.create_database()
        cases = (
            ("UPDATE adaptive_runtime SET mode='active'", "invalid_adaptive_schema"),
            ("UPDATE adaptive_runtime SET mode='off',singleton=2", "invalid_adaptive_schema"),
            ("INSERT INTO adaptive_runtime SELECT 1,schema_version,protocol_version,mode,"
             "registry_revision,admission_barrier,active_logon_id,guardian_epoch FROM adaptive_runtime",
             "unsupported_adaptive_schema"),
        )
        for statement, reason in cases:
            with self.subTest(reason=reason, statement=statement):
                with closing(sqlite3.connect(self.database)) as conn:
                    conn.execute(statement)
                    conn.commit()
                before = self.database_fingerprint()
                result = query_adaptive(self.database)
                self.assertFalse(result["available"])
                self.assertEqual(result["reason"], reason)
                self.assertEqual(result["executions"], [])
                self.assertEqual(before, self.database_fingerprint())

    def test_row_limit_and_explicit_exact_filters(self):
        self.create_database(count=8)
        result = query_adaptive(self.database, limit=3)
        self.assertEqual(len(result["executions"]), 3)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["row_limit"], 3)
        exact = query_adaptive(self.database, execution_id="execution-004", reservation_id="reservation-004")
        self.assertEqual([row["execution_id"] for row in exact["executions"]], ["execution-004"])
        self.assertFalse(exact["truncated"])
        mismatch = query_adaptive(self.database, execution_id="execution-004", reservation_id="reservation-005")
        self.assertEqual(mismatch["executions"], [])
        self.assertEqual(query_adaptive(self.database, execution_id="execution")["executions"], [])
        self.assertEqual(query_adaptive(self.database, reservation_id="reservation")["executions"], [])

    def test_invalid_filters_and_limits_never_create_a_database(self):
        for arguments in ({"execution_id": "' OR 1=1 --"}, {"reservation_id": "x" * 129},
                          {"limit": 0}, {"limit": 101}, {"limit": True},
                          {"timeout_ms": 0}, {"timeout_ms": 1001}):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                query_adaptive(self.database, **arguments)
        self.assertFalse(self.database.exists())

    def test_exclusive_lock_wait_is_bounded_and_does_not_write(self):
        self.create_database()
        before = self.database_fingerprint()
        with closing(sqlite3.connect(self.database, isolation_level=None)) as writer:
            writer.execute("BEGIN EXCLUSIVE")
            started = time.monotonic()
            result = query_adaptive(self.database, timeout_ms=30)
            elapsed = time.monotonic() - started
            writer.rollback()
        self.assertEqual(result["reason"], "database_busy", result)
        self.assertLess(elapsed, 1.0)
        self.assertEqual(before, self.database_fingerprint())

    def test_query_work_deadline_discards_partial_results(self):
        self.create_database(count=8)
        clock = itertools.chain([0.0], itertools.repeat(1.0))
        with patch("sentinel.adaptive.query.time.monotonic", side_effect=lambda: next(clock)):
            result = query_adaptive(self.database, timeout_ms=10)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "query_timeout")
        self.assertEqual(result["executions"], [])

    def test_inconsistent_binding_and_unknown_root_are_not_invented(self):
        self.create_database()
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute("UPDATE reservations SET execution_id='another-execution'")
            conn.execute("UPDATE managed_executions SET root_pid=NULL,root_created_filetime_100ns=NULL,"
                         "state='START_UNKNOWN',launch_in_flight=1,launch_sealed=0")
            conn.commit()
        row = query_adaptive(self.database)["executions"][0]
        self.assertEqual(row["allocation"]["recorded_binding"], "allocation_binding_inconsistent")
        self.assertIsNone(row["root"])
        self.assertTrue(row["launch_in_flight"])
        self.assertFalse(row["launch_sealed"])

    def test_real_store_schema_is_readable_without_store_construction(self):
        from sentinel.adaptive.store import migrate_schema
        with closing(sqlite3.connect(self.database, isolation_level=None)) as conn:
            migrate_schema(conn)
        before = self.database_fingerprint()
        result = query_adaptive(self.database)
        self.assertTrue(result["available"], result)
        self.assertEqual(result["executions"], [])
        self.assertEqual(before, self.database_fingerprint())


if __name__ == "__main__":
    unittest.main()
