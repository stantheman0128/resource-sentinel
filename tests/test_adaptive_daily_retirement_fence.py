"""Isolated SQL freeze tests, never native retirement or daily activation."""
import json
import sqlite3
import unittest
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.daily_generation import REQUIRED_PATHS, SourceEntry, SourceManifest
from sentinel.adaptive.daily_retirement_fence import (
    DailyRetirementError, OWNER_BINDING_FIELDS, TABLE, assert_new_capacity_allowed,
    assert_tightening_allowed, install_freeze_locked, read_retirement, seal_freeze_locked,
)
from sentinel.adaptive.policy import PolicyBinding, PolicyGuard
from sentinel.adaptive.store import migrate_schema


LOGON = "S-1-5-5-1-2"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class RetirementFenceTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        migrate_schema(self.conn)
        self.conn.execute("CREATE TABLE queue(request_key TEXT PRIMARY KEY,heartbeat_at REAL)")
        self.guard = PolicyGuard(PolicyBinding(str(uuid4()), LOGON), str(uuid4()))
        self.conn.execute("""UPDATE adaptive_runtime SET policy_instance_id=?,policy_logon_id=?,
            policy_entry_nonce=?,policy_binding_initialized=1,registry_revision=7""",
            (self.guard.binding.instance_id, LOGON, self.guard.nonce))
        manifest = SourceManifest(tuple(SourceEntry(path, "a" * 64, 0) for path in sorted(REQUIRED_PATHS)))
        self.binding = {
            "generation": str(uuid4()), "source_digest": manifest.digest, "config_digest": "b" * 64,
            "source_root": r"C:\fixture\source", "ledger_path": r"C:\fixture\sentinel.db",
            "owner_identity_json": encoded(ProcessIdentity(101, 1234567, LOGON).to_dict()),
            "ledger_identity_json": encoded(["77", "88"]), "readiness_instance_id": str(uuid4()),
        }
        self.conn.execute("""CREATE TABLE adaptive_daily_generation (
            singleton INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL,
            generation TEXT NOT NULL,state TEXT NOT NULL,source_digest TEXT NOT NULL,
            config_digest TEXT NOT NULL,source_manifest_json TEXT NOT NULL,source_root TEXT NOT NULL,
            ledger_path TEXT NOT NULL,owner_identity_json TEXT NOT NULL,ledger_identity_json TEXT NOT NULL,
            readiness_instance_id TEXT NOT NULL)""")
        self.conn.execute("INSERT INTO adaptive_daily_generation VALUES(1,1,?,'ACTIVE',?,?,?,?,?,?,?,?)", (
            self.binding["generation"], self.binding["source_digest"], self.binding["config_digest"],
            encoded(manifest.to_dict()), self.binding["source_root"], self.binding["ledger_path"],
            self.binding["owner_identity_json"], self.binding["ledger_identity_json"],
            self.binding["readiness_instance_id"]))
        generation._install_triggers(self.conn)
        generation.validate_triggers(self.conn)
        # SQL-only authority for this connection and its original complete row.
        # This is explicitly synthetic readiness, not a native generation owner.
        # Keep the real canonical triggers/readers; a changed row must not make
        # this fixture authorize a replacement generation or a DRAINING writer.
        self._sql_generation_row = tuple(self.conn.execute(
            "SELECT * FROM adaptive_daily_generation").fetchone())
        self.conn.create_function("sentinel_daily_generation", 0, self.fixture_generation)
        self.conn.create_function("sentinel_daily_delete_authority", 2, self.fixture_delete_authority)
        self.request_id = str(uuid4())

    def fixture_generation(self):
        current = tuple(self.conn.execute("SELECT * FROM adaptive_daily_generation").fetchone())
        if current == self._sql_generation_row:
            return self._sql_generation_row[2]
        return None

    def fixture_delete_authority(self, table, key):
        return int(table in {"reservations", "queue"} and type(key) is str and bool(key)
                   and self.fixture_generation() == self._sql_generation_row[2])

    def insert(self, table, values):
        self.conn.execute(f"INSERT INTO {table}({','.join(values)}) VALUES({','.join('?' for _ in values)})",
                          tuple(values.values()))

    def direct(self, name="direct"):
        self.insert("reservations", dict(id=name, request_key="request-" + name,
            owner_pid=101, owner_started=1, tool_use_id="tool", repo="fixture", command_signature="fixture",
            command_text="", resource_class="HEAVY", priority="P2", priority_rank=2,
            cpu_units=1, ram_gib=1, io_slots=1, created_at=100, heartbeat_at=100, expires_at=200,
            lease_duration_sec=100, spec_hash="c" * 64, physical_bytes=1 << 30, commit_bytes=1 << 30,
            writer_protocol=1, writer_revision=0))

    def worker(self):
        self.insert("workers", dict(id="worker", provider="fixture", failure_domain="local",
            capacity_scope="SHARED_POOL", capacity_pool="local", max_concurrency=1, quota_domain="local",
            state="AVAILABLE", automation_level="AUTOMATABLE", os="windows", capacity_ram_gib=64,
            allocatable_ram_gib=58, visible_cpu=12, allocatable_cpu=8, disk_free_gib=100,
            allocatable_disk_gib=100, capabilities_json='{"local":true}', trust_domain="local",
            source="fixture", observed_at=100, probe_expires_at=200, updated_at=100,
            writer_protocol=1, writer_revision=0))

    def routed(self):
        self.worker()
        self.insert("worker_reservations", dict(id="routed", task_id="task", worker_id="worker",
            failure_domain="local", capacity_scope="SHARED_POOL", capacity_pool="local", spec_hash="d" * 64,
            ram_gib=1, cpu_units=1, disk_gib=1, created_at=100, heartbeat_at=100, expires_at=200,
            lease_duration_sec=100, metadata_json="{}", physical_bytes=1 << 30, commit_bytes=1 << 30,
            io_slots=1, writer_protocol=1, writer_revision=0))

    def managed(self, *, state="RESERVED", in_flight=0, consumed=0):
        values = dict(execution_id=str(uuid4()), task_id="task", session_id="fixture", principal_id="fixture",
            logon_id=LOGON, allocation_kind="direct", reservation_id="direct", parent_execution_id=None,
            spec_hash="c" * 64, wrapper_pid=101, wrapper_created_filetime_100ns="1234567", role="background",
            priority="P2", state=state, state_revision=0, claim_token_hash="e" * 64, claim_consumed=consumed,
            launch_in_flight=in_flight, created_at=100, heartbeat_at=100)
        for prefix in ("requested_", "floor_"):
            values.update({prefix + "cpu_units": 1, prefix + "physical_bytes": 1 << 30,
                           prefix + "commit_bytes": 1 << 30, prefix + "io_slots": 1})
        self.insert("managed_executions", values)
        return values["execution_id"]

    def freeze(self):
        self.conn.execute("BEGIN IMMEDIATE")
        row = install_freeze_locked(self.conn, self.binding, self.request_id, self.guard)
        self.assertTrue(self.conn.in_transaction)
        self.conn.commit()
        return row

    def expect_sql_blocked(self, sql, parameters=()):
        with self.assertRaisesRegex(sqlite3.IntegrityError, "daily_retirement_frozen"):
            self.conn.execute(sql, parameters)

    def test_freeze_persists_exact_binding_without_changing_mode_revision_or_generation(self):
        self.conn.execute("UPDATE adaptive_runtime SET mode='canary'")
        row = self.freeze()
        self.assertEqual({key: row[key] for key in OWNER_BINDING_FIELDS}, self.binding)
        self.assertEqual((row["phase"], row["seal_digest"], row["freeze_registry_revision"]), ("FROZEN", None, 7))
        self.assertEqual(tuple(self.conn.execute("SELECT mode,registry_revision FROM adaptive_runtime").fetchone()), ("canary", 7))
        self.assertEqual(self.conn.execute("SELECT state FROM adaptive_daily_generation").fetchone()[0], "ACTIVE")
        self.assertEqual(read_retirement(self.conn), row)

    def test_helpers_require_original_transaction_when_generation_exists(self):
        for function in (assert_new_capacity_allowed, assert_tightening_allowed):
            with self.assertRaisesRegex(DailyRetirementError, "transaction_required"):
                function(self.conn)
        with self.assertRaisesRegex(DailyRetirementError, "transaction_required"):
            install_freeze_locked(self.conn, self.binding, self.request_id, self.guard)
        self.conn.execute("BEGIN")
        assert_new_capacity_allowed(self.conn)
        self.conn.rollback()

    def test_absent_generation_and_retirement_preserve_legacy_noop(self):
        conn = sqlite3.connect(":memory:")
        self.addCleanup(conn.close)
        self.assertIsNone(read_retirement(conn))
        assert_new_capacity_allowed(conn)
        assert_tightening_allowed(conn)

    def test_freeze_blocks_existing_reuse_and_tightening_helpers(self):
        self.freeze()
        self.conn.execute("BEGIN")
        for function in (assert_new_capacity_allowed, assert_tightening_allowed):
            with self.assertRaisesRegex(DailyRetirementError, "daily_retirement_frozen"):
                function(self.conn)
        self.conn.rollback()

    def test_same_request_same_guard_replay_is_read_only_different_request_refuses(self):
        row = self.freeze()
        self.conn.execute("BEGIN")
        before = self.conn.total_changes
        self.assertEqual(install_freeze_locked(self.conn, self.binding, self.request_id, self.guard), row)
        self.assertEqual(self.conn.total_changes, before)
        with self.assertRaisesRegex(DailyRetirementError, "request_conflict"):
            install_freeze_locked(self.conn, self.binding, str(uuid4()), self.guard)
        self.conn.rollback()

    def test_new_guard_nonce_cannot_reconstruct_original_freeze_attempt(self):
        self.freeze()
        other = PolicyGuard(self.guard.binding, str(uuid4()))
        self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=?", (other.nonce,))
        self.conn.execute("BEGIN")
        with self.assertRaisesRegex(DailyRetirementError, "request_conflict"):
            install_freeze_locked(self.conn, self.binding, self.request_id, other)
        self.conn.rollback()

    def test_policy_or_owner_binding_mismatch_prevents_schema_creation(self):
        self.conn.execute("BEGIN")
        other = PolicyGuard(self.guard.binding, str(uuid4()))
        with self.assertRaisesRegex(DailyRetirementError, "policy_changed"):
            install_freeze_locked(self.conn, self.binding, self.request_id, other)
        changed = dict(self.binding, config_digest="f" * 64)
        with self.assertRaisesRegex(DailyRetirementError, "generation_changed"):
            install_freeze_locked(self.conn, changed, self.request_id, self.guard)
        self.assertIsNone(read_retirement(self.conn))
        self.conn.rollback()

    def test_direct_and_routed_new_allocations_are_blocked_on_existing_connection(self):
        self.direct()
        self.routed()
        statement = "INSERT INTO reservations SELECT * FROM reservations WHERE id=?"
        # Compile and cache this exact statement before the durable fence exists.
        self.conn.execute(statement, ("absent",))
        self.freeze()
        self.expect_sql_blocked(statement, ("direct",))
        self.expect_sql_blocked("INSERT INTO worker_reservations SELECT * FROM worker_reservations")
        self.expect_sql_blocked("INSERT OR REPLACE INTO reservations SELECT * FROM reservations")

    def test_heartbeat_and_existing_release_remain_usable(self):
        self.direct()
        self.routed()
        self.freeze()
        for table in ("reservations", "worker_reservations"):
            self.conn.execute(f"UPDATE {table} SET heartbeat_at=110,expires_at=210,writer_protocol=1,writer_revision=writer_revision+1")
            self.conn.execute(f"DELETE FROM {table}")
            self.assertEqual(self.conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_request_resources_and_allocation_bindings_cannot_change(self):
        self.direct()
        self.routed()
        self.freeze()
        for table, change in (("reservations", "cpu_units=2"), ("reservations", "ram_gib=0.5"),
                              ("reservations", "owner_pid=999"), ("reservations", "execution_id='new'"),
                              ("worker_reservations", "worker_id='elsewhere'"),
                              ("worker_reservations", "physical_bytes=0")):
            with self.subTest(table=table, change=change):
                self.expect_sql_blocked(f"UPDATE {table} SET {change},writer_revision=writer_revision+1")

    def test_queue_insert_refresh_and_exact_delete_are_not_abandoned_by_freeze(self):
        self.freeze()
        self.conn.execute("INSERT INTO queue VALUES('needed',100)")
        self.conn.execute("INSERT INTO queue VALUES('needed',110) ON CONFLICT(request_key) DO UPDATE SET heartbeat_at=excluded.heartbeat_at")
        self.assertEqual(self.conn.execute("SELECT heartbeat_at FROM queue").fetchone()[0], 110)
        self.conn.execute("DELETE FROM queue WHERE request_key='needed'")

    def test_worker_timestamps_and_deactivation_allowed_relabel_or_reenable_blocked(self):
        self.worker()
        self.freeze()
        self.conn.execute("UPDATE workers SET observed_at=110,probe_expires_at=210,updated_at=110,writer_revision=writer_revision+1")
        self.expect_sql_blocked("UPDATE workers SET allocatable_cpu=9,writer_revision=writer_revision+1")
        self.expect_sql_blocked("UPDATE workers SET capabilities_json='{}',writer_revision=writer_revision+1")
        self.conn.execute("UPDATE workers SET state='OFFLINE',updated_at=120,writer_revision=writer_revision+1")
        self.expect_sql_blocked("UPDATE workers SET state='AVAILABLE',writer_revision=writer_revision+1")
        self.expect_sql_blocked("INSERT OR REPLACE INTO workers SELECT * FROM workers")

    def test_new_managed_execution_and_fresh_launch_are_blocked(self):
        self.direct()
        execution = self.managed(state="PREPARED")
        self.freeze()
        self.expect_sql_blocked("INSERT INTO managed_executions SELECT * FROM managed_executions")
        self.expect_sql_blocked("UPDATE managed_executions SET state='LAUNCHING',launch_in_flight=1,claim_consumed=1,state_revision=1 WHERE execution_id=?", (execution,))
        self.expect_sql_blocked("UPDATE managed_executions SET job_name='new-job',job_nonce='new',guardian_epoch='new'")

    def test_previously_issued_launch_bind_root_is_allowed(self):
        self.direct()
        self.managed(state="START_UNKNOWN", in_flight=1, consumed=1)
        self.freeze()
        self.conn.execute("""UPDATE managed_executions SET state='RUNNING',root_pid=201,
            root_created_filetime_100ns='1234568',launch_in_flight=0,launch_sealed=1,state_revision=1""")
        self.assertEqual(self.conn.execute("SELECT root_pid FROM managed_executions").fetchone()[0], 201)

    def test_terminal_cancel_can_consume_and_destroy_unissued_claim(self):
        self.direct()
        self.managed()
        self.freeze()
        self.conn.execute("""UPDATE managed_executions SET state='CANCELLED_BEFORE_START',finished_at=120,
            launch_sealed=1,launch_in_flight=0,claim_consumed=1,claim_token_hash='',state_revision=1""")
        self.assertEqual(self.conn.execute("SELECT claim_token_hash FROM managed_executions").fetchone()[0], "")
        self.expect_sql_blocked("UPDATE managed_executions SET state='RUNNING',state_revision=2")

    def test_managed_heartbeat_floor_growth_and_holds_remain_possible(self):
        self.direct()
        self.managed(state="RUNNING", consumed=1)
        self.freeze()
        self.conn.execute("UPDATE managed_executions SET heartbeat_at=120,state_revision=state_revision+1")
        self.conn.execute("UPDATE managed_executions SET floor_cpu_units=2,floor_commit_bytes=2147483648,state_revision=state_revision+1")
        self.conn.execute("UPDATE managed_executions SET state='UNCERTAIN_HOLD',hold_reason='heartbeat_lost',state_revision=state_revision+1")
        self.expect_sql_blocked("UPDATE managed_executions SET floor_cpu_units=1,state_revision=state_revision+1")
        self.expect_sql_blocked("UPDATE managed_executions SET requested_cpu_units=2,state_revision=state_revision+1")

    def test_runtime_cleanup_and_off_allowed_but_mode_reactivation_blocked(self):
        self.conn.execute("UPDATE adaptive_runtime SET mode='canary'")
        self.freeze()
        self.conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1,admission_barrier='RECOVERY_HOLD'")
        self.conn.execute("UPDATE adaptive_runtime SET mode='off'")
        self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL,admission_barrier='NONE'")
        self.expect_sql_blocked("UPDATE adaptive_runtime SET mode='canary'")
        self.expect_sql_blocked("UPDATE adaptive_runtime SET mode='shadow'")

    def test_new_control_slot_is_blocked_restoration_and_audit_are_not_guarded(self):
        self.freeze()
        self.expect_sql_blocked("INSERT INTO adaptive_control_slot(singleton,schema_version,slot_state) VALUES(1,1,'HELD')")
        names = {row[0] for row in self.conn.execute("SELECT tbl_name FROM sqlite_master WHERE name GLOB 'adaptive_retirement_*'")}
        self.assertNotIn("adaptive_actions", names)

    def test_missing_or_replaced_guard_is_not_silently_reinstalled(self):
        self.freeze()
        self.conn.execute("DROP TRIGGER adaptive_retirement_reservations_insert")
        with self.assertRaisesRegex(DailyRetirementError, "guards_unverified"):
            read_retirement(self.conn)
        self.conn.execute("BEGIN")
        with self.assertRaisesRegex(DailyRetirementError, "guards_unverified"):
            install_freeze_locked(self.conn, self.binding, self.request_id, self.guard)
        self.conn.rollback()

    def test_missing_or_tampered_generation_guard_refuses_freeze_and_existing_reads(self):
        for frozen in (False, True):
            if frozen:
                self.freeze()
            for tampered in (False, True):
                with self.subTest(frozen=frozen, tampered=tampered):
                    self.conn.execute("BEGIN")
                    try:
                        self.conn.execute("DROP TRIGGER adaptive_daily_queue_insert")
                        if tampered:
                            self.conn.execute("""CREATE TRIGGER adaptive_daily_queue_insert
                                BEFORE INSERT ON queue BEGIN SELECT 1; END""")
                        with self.assertRaisesRegex(generation.DailyGenerationUnavailable,
                                                    "daily_generation_guards_unverified"):
                            generation.read_generation(self.conn)
                        for check in (assert_new_capacity_allowed, assert_tightening_allowed):
                            with self.assertRaisesRegex(DailyRetirementError, "generation_invalid"):
                                check(self.conn)
                        with self.assertRaisesRegex(DailyRetirementError, "generation_invalid"):
                            install_freeze_locked(self.conn, self.binding, self.request_id, self.guard)
                        if frozen:
                            with self.assertRaisesRegex(DailyRetirementError, "generation_invalid"):
                                read_retirement(self.conn)
                        else:
                            self.assertIsNone(self.conn.execute(
                                "SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone())
                    finally:
                        self.conn.rollback()
                    generation.validate_triggers(self.conn)

    def test_synthetic_sql_authority_refuses_changed_generation_or_draining(self):
        self.direct()
        self.conn.execute("INSERT INTO queue VALUES('needed',100)")
        for column, value in (("generation", str(uuid4())), ("state", "DRAINING")):
            with self.subTest(column=column):
                self.conn.execute("BEGIN")
                try:
                    self.conn.execute(f"UPDATE adaptive_daily_generation SET {column}=?", (value,))
                    for sql in ("INSERT INTO queue VALUES('new',100)",
                                "DELETE FROM queue WHERE request_key='needed'",
                                "DELETE FROM reservations WHERE id='direct'"):
                        with self.assertRaisesRegex(sqlite3.IntegrityError, "daily_generation_required"):
                            self.conn.execute(sql)
                    self.assertEqual(self.conn.execute("SELECT count(*) FROM queue").fetchone()[0], 1)
                    self.assertEqual(self.conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
                finally:
                    self.conn.rollback()

    def test_empty_or_wrong_retirement_schema_is_not_absent(self):
        self.conn.execute(f"CREATE TABLE {TABLE}(singleton INTEGER PRIMARY KEY)")
        with self.assertRaisesRegex(DailyRetirementError, "schema_unsupported"):
            read_retirement(self.conn)

    def test_generation_changes_or_malformed_generation_refuse_reads(self):
        self.freeze()
        self.conn.execute("UPDATE adaptive_daily_generation SET config_digest=?", ("f" * 64,))
        with self.assertRaisesRegex(DailyRetirementError, "generation_changed"):
            read_retirement(self.conn)
        self.conn.execute("UPDATE adaptive_daily_generation SET owner_identity_json='{}'")
        with self.assertRaisesRegex(DailyRetirementError, "generation_invalid"):
            read_retirement(self.conn)

    def test_binding_row_cannot_be_deleted_replaced_or_rebound(self):
        self.freeze()
        for sql in (f"DELETE FROM {TABLE}", f"UPDATE {TABLE} SET request_id='{uuid4()}'",
                    f"INSERT OR REPLACE INTO {TABLE} SELECT * FROM {TABLE}"):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "daily_retirement_immutable"):
                self.conn.execute(sql)

    def test_seal_requires_draining_exact_binding_and_current_guard(self):
        row = self.freeze()
        self.conn.execute("BEGIN")
        with self.assertRaisesRegex(DailyRetirementError, "seal_binding_changed"):
            seal_freeze_locked(self.conn, row, "d" * 64, self.guard)
        self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        changed = dict(row, request_id=str(uuid4()))
        with self.assertRaisesRegex(DailyRetirementError, "seal_binding_changed"):
            seal_freeze_locked(self.conn, changed, "d" * 64, self.guard)
        sealed = seal_freeze_locked(self.conn, row, "d" * 64, self.guard)
        self.assertEqual((sealed["phase"], sealed["seal_digest"]), ("SEALED", "d" * 64))
        self.assertTrue(self.conn.in_transaction)
        self.conn.commit()
        self.conn.execute("BEGIN")
        self.assertEqual(seal_freeze_locked(self.conn, row, "d" * 64, self.guard), sealed)
        with self.assertRaisesRegex(DailyRetirementError, "seal_conflict"):
            seal_freeze_locked(self.conn, row, "e" * 64, self.guard)
        with self.assertRaisesRegex(DailyRetirementError, "daily_retirement_frozen"):
            assert_new_capacity_allowed(self.conn)
        self.conn.rollback()

    def test_seal_rollback_preserves_the_original_freeze(self):
        row = self.freeze()
        self.conn.execute("BEGIN")
        self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        seal_freeze_locked(self.conn, row, "d" * 64, self.guard)
        self.conn.rollback()
        self.assertEqual(read_retirement(self.conn), row)
        self.assertEqual(self.conn.execute("SELECT state FROM adaptive_daily_generation").fetchone()[0], "ACTIVE")

    def test_seal_accepts_new_nonce_for_same_original_policy_binding(self):
        row = self.freeze()
        seal_guard = PolicyGuard(self.guard.binding, str(uuid4()))
        self.conn.execute("BEGIN")
        self.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=?", (seal_guard.nonce,))
        self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        sealed = seal_freeze_locked(self.conn, row, "d" * 64, seal_guard)
        self.assertEqual(sealed["phase"], "SEALED")
        self.assertEqual(sealed["freeze_policy_nonce"], self.guard.nonce)
        self.assertNotEqual(sealed["freeze_policy_nonce"], seal_guard.nonce)
        self.conn.rollback()
        self.assertEqual(self.conn.execute("SELECT state FROM adaptive_daily_generation").fetchone()[0], "ACTIVE")

    def test_sealed_row_never_reopens_or_changes_its_digest(self):
        row = self.freeze()
        self.conn.execute("BEGIN")
        self.conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        seal_freeze_locked(self.conn, row, "d" * 64, self.guard)
        self.conn.commit()
        for sql in (f"UPDATE {TABLE} SET phase='FROZEN',seal_digest=NULL",
                    f"UPDATE {TABLE} SET seal_digest='{'e' * 64}'"):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "daily_retirement_immutable"):
                self.conn.execute(sql)


if __name__ == "__main__":
    unittest.main()
