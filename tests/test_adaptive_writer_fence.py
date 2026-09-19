"""Cooperative SQL DML fence tests; not arbitrary-SQL auth or native evidence."""
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.store import LifecycleStore, migrate_schema
from sentinel.adaptive.writers import (
    MAX_WRITER_REVISION, migrate_writer_fence, writer_obligations_present,
)
from sentinel.coordinator import Coordinator
from sentinel.maintainer import Maintainer
from tests.test_adaptive_lifecycle import GIB, NOW, WRAPPER


CAPACITY = ("reservations", "worker_reservations")
PROTOCOL = "capacity_writer_protocol_required"


class WriterFenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.db = self.directory / "sentinel.db"
        # This plain SQLite connection predates every schema/trigger creation.
        self.old = self.connect(self.db)
        # Use real schemas and additive columns, suppressing only fence trigger
        # installation to model stored rows written before enforcement existed.
        # Current schema initialization itself knows the marker columns.
        with patch("sentinel.adaptive.writers._install"):
            Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
            Maintainer(self.directory)
        self.worker = self.worker_row("fixture-local")
        self.insert("workers", self.worker, conn=self.old)
        self.legacy = self.capacity_row("reservations", "pre-fence")
        self.insert("reservations", self.legacy, conn=self.old)
        self.old.execute("UPDATE reservations SET heartbeat_at=? WHERE id=?", (NOW, self.legacy["id"]))
        self.pre_migration = self.rows("reservations", self.old)
        self.store = LifecycleStore(self.db)
        self.new = self.connect(self.db)

    def connect(self, path):
        conn = sqlite3.connect(path, timeout=2, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA recursive_triggers=OFF")
        self.addCleanup(conn.close)
        return conn

    def rows(self, table, conn=None):
        return [dict(row) for row in (conn or self.new).execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def insert(self, table, row, *, conn=None, replace=False):
        conn = conn or self.new
        columns = ",".join(row)
        placeholders = ",".join("?" for _ in row)
        conn.execute(f"INSERT {'OR REPLACE ' if replace else ''}INTO {table} ({columns}) VALUES ({placeholders})",
                     tuple(row.values()))

    def worker_row(self, name=None, *, ack=False, **changes):
        row = dict(id=name or str(uuid4()), provider="fixture", failure_domain="local",
            capacity_scope="SHARED_POOL", capacity_pool="local", max_concurrency=8,
            quota_domain="", state="AVAILABLE", automation_level="AUTOMATABLE", os="windows",
            capacity_ram_gib=64, allocatable_ram_gib=58, visible_cpu=12, allocatable_cpu=8,
            disk_free_gib=100, allocatable_disk_gib=100, capabilities_json='{"local":true}',
            trust_domain="local-private", source="fixture", observed_at=NOW,
            probe_expires_at=NOW + 3600, updated_at=NOW)
        if ack:
            row.update(writer_protocol=1, writer_revision=0)
        return row | changes

    def capacity_row(self, table, name=None, *, ack=False, **changes):
        name = name or str(uuid4())
        common = dict(id=name, spec_hash="a" * 64, cpu_units=1, ram_gib=1,
            io_slots=0, physical_bytes=GIB, commit_bytes=2 * GIB,
            created_at=NOW, heartbeat_at=NOW, expires_at=NOW + 120)
        if table == "reservations":
            row = common | dict(request_key="request-" + name, owner_pid=WRAPPER.pid,
                owner_started=1.0, tool_use_id="tool-" + name, repo="fixture",
                command_signature="safe", command_text="", resource_class="MEDIUM",
                priority="P2", priority_rank=2)
        else:
            row = common | dict(task_id="task-" + name, worker_id="fixture-local",
                failure_domain="local", capacity_scope="SHARED_POOL", capacity_pool="local",
                disk_gib=0, metadata_json="{}")
        if ack:
            row.update(writer_protocol=1, writer_revision=0)
        return row | changes

    def execution_row(self, allocation, table="reservations", **changes):
        execution_id = str(uuid4())
        row = dict(execution_id=execution_id, task_id=allocation.get("task_id", "task-" + execution_id),
            session_id="fixture-session", principal_id="fixture-principal", logon_id=WRAPPER.logon_id,
            allocation_kind="direct" if table == "reservations" else "routed",
            reservation_id=allocation["id"], parent_execution_id=None, spec_hash=allocation["spec_hash"],
            wrapper_pid=WRAPPER.pid, wrapper_created_filetime_100ns=str(WRAPPER.created_filetime_100ns),
            role="background", priority="P2", state="RUNNING", claim_token_hash="b" * 64,
            created_at=NOW, heartbeat_at=NOW, requested_cpu_units=1,
            requested_physical_bytes=GIB, requested_commit_bytes=2 * GIB, requested_io_slots=0,
            floor_cpu_units=1, floor_physical_bytes=GIB, floor_commit_bytes=2 * GIB, floor_io_slots=0,
            guardian_epoch="fixture-guardian", job_name="Local\\ResourceSentinel.Test." + execution_id,
            coverage="job_contained", launch_sealed=1)
        return row | changes

    def managed(self, table="reservations", **changes):
        allocation = self.capacity_row(table, ack=True)
        self.insert(table, allocation)
        execution = self.execution_row(allocation, table, **changes)
        self.insert("managed_executions", execution)
        fields = "execution_id=?,lifecycle_managed=1,writer_protocol=1,writer_revision=writer_revision+1"
        arguments = [execution["execution_id"]]
        if table == "reservations":
            fields += ",managed_spec_hash=?"
            arguments.append(execution["spec_hash"])
        self.new.execute(f"UPDATE {table} SET {fields} WHERE id=?", (*arguments, allocation["id"]))
        return allocation, execution

    def barrier(self, value="RECOVERY_HOLD"):
        self.new.execute("UPDATE adaptive_runtime SET admission_barrier=?", (value,))

    def assert_denied_without_change(self, table, operation, reason=PROTOCOL):
        before = self.rows(table)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "^" + reason + "$"):
            operation()
        self.assertEqual(self.rows(table), before)

    def test_migration_keeps_rows_and_default_markers_and_refreshes_cached_old_connection(self):
        self.assertEqual(self.rows("reservations"), self.pre_migration)
        self.assertEqual(self.pre_migration[0]["writer_protocol"], 0)
        self.assertEqual(self.pre_migration[0]["writer_revision"], 0)
        migrate_schema(self.new)
        self.assertEqual(self.rows("reservations"), self.pre_migration)
        self.managed()
        for conn in (self.old, self.new):
            with self.subTest(connection="old" if conn is self.old else "new"):
                self.assertEqual(conn.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
                self.assert_denied_without_change("reservations", lambda: conn.execute(
                    "UPDATE reservations SET heartbeat_at=? WHERE id=?", (NOW + 1, self.legacy["id"])))

    def test_without_obligations_plain_legacy_insert_update_delete_still_work(self):
        for conn in (self.old, self.new):
            for table in (*CAPACITY, "workers"):
                with self.subTest(connection=id(conn), table=table):
                    row = self.worker_row() if table == "workers" else self.capacity_row(table)
                    self.insert(table, row, conn=conn)
                    field = "updated_at" if table == "workers" else "heartbeat_at"
                    conn.execute(f"UPDATE {table} SET {field}=? WHERE id=?", (NOW + 1, row["id"]))
                    stored = conn.execute(f"SELECT writer_protocol,writer_revision FROM {table} WHERE id=?",
                                          (row["id"],)).fetchone()
                    self.assertEqual(tuple(stored), (0, 0))
                    conn.execute(f"DELETE FROM {table} WHERE id=?", (row["id"],))
                    self.assertIsNone(conn.execute(f"SELECT 1 FROM {table} WHERE id=?", (row["id"],)).fetchone())

    def test_active_managed_obligation_fences_old_insert_and_updates_in_both_ledgers(self):
        self.managed()
        for conn in (self.old, self.new):
            for table in CAPACITY:
                row = self.capacity_row(table)
                self.assert_denied_without_change(table, lambda: self.insert(table, row, conn=conn))
        self.assert_denied_without_change("workers", lambda: self.old.execute(
            "UPDATE workers SET capabilities_json=? WHERE id=?", ('{"local":false}', self.worker["id"])))

    def test_each_barrier_fences_legacy_writers_without_managed_executions(self):
        for barrier in ("CONTROLLING", "RECOVERY_HOLD"):
            self.barrier(barrier)
            for table in (*CAPACITY, "workers"):
                row = self.worker_row() if table == "workers" else self.capacity_row(table)
                self.assert_denied_without_change(table, lambda: self.insert(table, row, conn=self.old))
        self.assertEqual(self.rows("managed_executions"), [])

    def test_missing_runtime_cannot_disable_existing_sql_fence(self):
        self.new.execute("DELETE FROM adaptive_runtime")
        self.assert_denied_without_change("reservations", lambda: self.insert(
            "reservations", self.capacity_row("reservations"), conn=self.old))

    def test_malformed_runtime_versions_or_revision_fail_closed(self):
        for column, value in (("schema_version", 99), ("protocol_version", 99),
                              ("registry_revision", "private-invalid-revision")):
            with self.subTest(column=column):
                original = self.new.execute(f"SELECT {column} FROM adaptive_runtime").fetchone()[0]
                self.new.execute(f"UPDATE adaptive_runtime SET {column}=?", (value,))
                self.assert_denied_without_change("reservations", lambda: self.insert(
                    "reservations", self.capacity_row("reservations"), conn=self.old))
                self.new.execute(f"UPDATE adaptive_runtime SET {column}=?", (original,))

    def test_nonterminal_registry_orphan_protects_new_capacity_without_tagged_allocations(self):
        self.insert("managed_executions", self.execution_row(self.capacity_row("reservations")))
        self.assert_denied_without_change("worker_reservations", lambda: self.insert(
            "worker_reservations", self.capacity_row("worker_reservations"), conn=self.old))

    def assert_direct_orphan_marker_protects_capacity(self, tag):
        # The pre-existing namespace guard independently protects its managed-v1
        # marker; install that stored corruption explicitly in this isolated DB.
        if "tool_use_id" in tag:
            self.new.execute("DROP TRIGGER managed_direct_insert_guard")
        row = self.capacity_row("reservations", ack=True, **tag)
        self.insert("reservations", row)
        self.assert_denied_without_change("worker_reservations", lambda: self.insert(
            "worker_reservations", self.capacity_row("worker_reservations"), conn=self.old))
        self.assert_denied_without_change("reservations", lambda: self.old.execute(
            "DELETE FROM reservations WHERE id=?", (row["id"],)),
            "managed_allocation_release_requires_terminal")

    def test_orphan_execution_tag_protects_other_capacity(self):
        self.assert_direct_orphan_marker_protects_capacity({"execution_id": str(uuid4())})

    def test_orphan_managed_flag_protects_other_capacity(self):
        self.assert_direct_orphan_marker_protects_capacity({"lifecycle_managed": 1})

    def test_orphan_empty_managed_hash_protects_other_capacity(self):
        self.assert_direct_orphan_marker_protects_capacity({"managed_spec_hash": ""})

    def test_orphan_managed_namespace_protects_other_capacity(self):
        self.assert_direct_orphan_marker_protects_capacity({"tool_use_id": "managed-v1:" + str(uuid4())})

    def test_new_tagged_row_requires_protocol_before_any_global_obligation_exists(self):
        row = self.capacity_row("reservations", execution_id=str(uuid4()))
        self.assert_denied_without_change("reservations", lambda: self.insert("reservations", row))

    def test_registry_backreference_protects_an_allocation_even_when_tags_are_missing(self):
        self.insert("managed_executions", self.execution_row(self.legacy))
        self.assert_denied_without_change("reservations", lambda: self.old.execute(
            "DELETE FROM reservations WHERE id=?", (self.legacy["id"],)),
            "managed_allocation_release_requires_terminal")

    def test_malformed_kind_backreference_protects_allocation_with_stripped_tags(self):
        row = self.execution_row(self.legacy, allocation_kind="private-invalid-kind")
        self.new.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self.insert("managed_executions", row)
        finally:
            self.new.execute("PRAGMA ignore_check_constraints=OFF")
        self.assert_denied_without_change("reservations", lambda: self.old.execute(
            "DELETE FROM reservations WHERE id=?", (self.legacy["id"],)),
            "managed_allocation_release_requires_terminal")

    def test_exact_terminal_record_cannot_hide_competing_malformed_backreference(self):
        allocation, _ = self.managed(state="FINISHED")
        other = self.execution_row(allocation, allocation_kind="private-invalid-kind",
                                   state="FINISHED", launch_sealed=1, launch_in_flight=0)
        self.new.execute("PRAGMA ignore_check_constraints=ON")
        try:
            self.insert("managed_executions", other)
        finally:
            self.new.execute("PRAGMA ignore_check_constraints=OFF")
        self.assert_denied_without_change("reservations", lambda: self.old.execute(
            "DELETE FROM reservations WHERE id=?", (allocation["id"],)),
            "managed_allocation_release_requires_terminal")

    def test_valid_opposite_kind_identifier_is_not_a_direct_allocation_binding(self):
        # Direct and routed identifiers are separate namespaces. An actual
        # routed row may legitimately use the same ID as an ordinary direct row.
        self.managed("worker_reservations")
        routed = self.capacity_row("worker_reservations", self.legacy["id"], ack=True)
        self.insert("worker_reservations", routed)
        self.insert("managed_executions", self.execution_row(routed, "worker_reservations"))
        self.old.execute("DELETE FROM reservations WHERE id=?", (self.legacy["id"],))
        self.assertIsNone(self.old.execute("SELECT 1 FROM reservations WHERE id=?", (self.legacy["id"],)).fetchone())
        self.assertIsNotNone(self.old.execute("SELECT 1 FROM worker_reservations WHERE id=?", (routed["id"],)).fetchone())

    def test_clean_terminal_archive_without_allocation_does_not_block_legacy_insert(self):
        row = self.execution_row(self.capacity_row("reservations"), state="FINISHED",
                                 launch_sealed=1, launch_in_flight=0)
        self.insert("managed_executions", row)
        allocation = self.capacity_row("reservations")
        self.insert("reservations", allocation, conn=self.old)
        self.assertIsNotNone(self.old.execute("SELECT 1 FROM reservations WHERE id=?", (allocation["id"],)).fetchone())

    def test_terminal_label_without_positive_seal_does_not_remove_obligation(self):
        self.insert("managed_executions", self.execution_row(self.capacity_row("reservations"),
                    state="FINISHED", launch_sealed=0))
        self.assert_denied_without_change("reservations", lambda: self.insert(
            "reservations", self.capacity_row("reservations"), conn=self.old))

    def test_acknowledged_insert_and_exact_update_advance_marker_without_changing_other_rows(self):
        self.barrier()
        for table in (*CAPACITY, "workers"):
            with self.subTest(table=table):
                row = self.worker_row(ack=True) if table == "workers" else self.capacity_row(table, ack=True)
                self.insert(table, row)
                field = "updated_at" if table == "workers" else "heartbeat_at"
                self.new.execute(f"UPDATE {table} SET {field}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                 (NOW + 1, row["id"]))
                saved = self.new.execute(f"SELECT writer_protocol,writer_revision,{field} FROM {table} WHERE id=?", (row["id"],)).fetchone()
                self.assertEqual(tuple(saved), (1, 1, NOW + 1))

    def test_acknowledged_update_requires_exact_revision_increment(self):
        self.barrier()
        for table in (*CAPACITY, "workers"):
            row = self.worker_row(ack=True) if table == "workers" else self.capacity_row(table, ack=True)
            self.insert(table, row)
            for protocol, revision in ((0, 1), (2, 1), (1, 0), (1, 2), (1, 1.5), (1, b"1"), (1, None)):
                with self.subTest(table=table, protocol=protocol, revision=repr(revision)):
                    self.assert_denied_without_change(table, lambda: self.old.execute(
                        f"UPDATE {table} SET writer_protocol=?,writer_revision=? WHERE id=?",
                        (protocol, revision, row["id"])))

    def test_protected_insert_rejects_wrong_revision_or_protocol(self):
        self.barrier()
        for protocol, revision in ((0, 0), (2, 0), (1, 1), (1, 0.5), (b"1", 0), (None, 0)):
            with self.subTest(protocol=repr(protocol), revision=revision):
                row = self.capacity_row("reservations", writer_protocol=protocol, writer_revision=revision)
                self.assert_denied_without_change("reservations", lambda: self.insert("reservations", row))

    def test_marker_column_constraints_apply_even_without_managed_obligations(self):
        for column, values in (("writer_protocol", (-1, 2147483648, b"1", "invalid", None)),
                               ("writer_revision", (-1, b"0", "invalid", None))):
            for value in values:
                with self.subTest(column=column, value=repr(value)):
                    before = self.rows("reservations")
                    with self.assertRaises(sqlite3.IntegrityError):
                        self.insert("reservations", self.capacity_row("reservations", **{column: value}))
                    self.assertEqual(self.rows("reservations"), before)

    def test_exhausted_counter_cannot_wrap_or_be_reset_during_protection(self):
        self.new.execute("UPDATE reservations SET writer_protocol=1,writer_revision=? WHERE id=?",
                         (MAX_WRITER_REVISION, self.legacy["id"]))
        self.barrier()
        for expression in ("writer_revision+1", "0", str(MAX_WRITER_REVISION)):
            with self.subTest(expression=expression):
                self.assert_denied_without_change("reservations", lambda: self.old.execute(
                    f"UPDATE reservations SET writer_protocol=1,writer_revision={expression} WHERE id=?", (self.legacy["id"],)))

    def test_corrupt_old_counter_cannot_authorize_a_repair_or_new_update(self):
        for value in (-1, 0.5, "corrupt-old-counter", b"0"):
            with self.subTest(value=repr(value)):
                self.new.execute("PRAGMA ignore_check_constraints=ON")
                self.new.execute("UPDATE reservations SET writer_revision=? WHERE id=?", (value, self.legacy["id"]))
                self.new.execute("PRAGMA ignore_check_constraints=OFF")
                self.barrier()
                self.assert_denied_without_change("reservations", lambda: self.old.execute(
                    "UPDATE reservations SET writer_protocol=1,writer_revision=1 WHERE id=?", (self.legacy["id"],)))
                self.barrier("NONE")
                self.new.execute("UPDATE reservations SET writer_revision=0 WHERE id=?", (self.legacy["id"],))

    def assert_active_delete_denied(self, table):
        allocation, _ = self.managed(table)
        self.new.execute(f"UPDATE {table} SET expires_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                         (NOW - 10000, allocation["id"]))
        self.new.execute("UPDATE adaptive_runtime SET mode='off'")
        self.assert_denied_without_change(table, lambda: self.old.execute(f"DELETE FROM {table} WHERE id=?", (allocation["id"],)),
                                         "managed_allocation_release_requires_terminal")

    def test_direct_active_delete_is_not_authorized_by_ttl_or_mode_off(self):
        self.assert_active_delete_denied("reservations")

    def test_routed_active_delete_is_not_authorized_by_ttl_or_mode_off(self):
        self.assert_active_delete_denied("worker_reservations")

    def test_unbound_legacy_delete_remains_possible_during_managed_obligation(self):
        self.managed()
        self.old.execute("DELETE FROM reservations WHERE id=?", (self.legacy["id"],))
        self.assertIsNone(self.old.execute("SELECT 1 FROM reservations WHERE id=?", (self.legacy["id"],)).fetchone())

    def assert_terminal_delete_binding(self, table):
        allocation, execution = self.managed(table, state="FINISHED")
        for changes in ({"launch_sealed": 0}, {"launch_in_flight": 1}, {"spec_hash": "c" * 64},
                        {"reservation_id": "other-reservation"},
                        {"allocation_kind": "routed" if table == "reservations" else "direct"}):
            with self.subTest(changes=changes):
                before = dict(self.new.execute("SELECT * FROM managed_executions WHERE execution_id=?", (execution["execution_id"],)).fetchone())
                setters = ",".join(name + "=?" for name in changes)
                self.new.execute(f"UPDATE managed_executions SET {setters} WHERE execution_id=?", (*changes.values(), execution["execution_id"]))
                self.assert_denied_without_change(table, lambda: self.old.execute(f"DELETE FROM {table} WHERE id=?", (allocation["id"],)),
                                                 "managed_allocation_release_requires_terminal")
                self.new.execute(f"UPDATE managed_executions SET {setters} WHERE execution_id=?", (*(before[name] for name in changes), execution["execution_id"]))
        self.old.execute(f"DELETE FROM {table} WHERE id=?", (allocation["id"],))
        self.assertIsNone(self.old.execute(f"SELECT 1 FROM {table} WHERE id=?", (allocation["id"],)).fetchone())

    def test_direct_release_requires_exact_terminal_binding(self):
        self.assert_terminal_delete_binding("reservations")

    def test_routed_release_requires_exact_terminal_binding(self):
        self.assert_terminal_delete_binding("worker_reservations")

    def assert_replace_collisions(self, table, *, update):
        target, execution = self.managed(table)
        source = self.capacity_row(table, ack=True)
        self.insert(table, source)
        unique = "request_key" if table == "reservations" else "task_id"
        rowid = self.new.execute(f"SELECT rowid FROM {table} WHERE id=?", (target["id"],)).fetchone()[0]
        for column, value in (("id", target["id"]), (unique, target[unique]),
                              ("execution_id", execution["execution_id"]), ("rowid", rowid)):
            with self.subTest(table=table, column=column, update=update):
                self.assertEqual(self.old.execute("PRAGMA recursive_triggers").fetchone()[0], 0)
                if update:
                    operation = lambda: self.old.execute(f"UPDATE OR REPLACE {table} SET {column}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                                        (value, source["id"]))
                else:
                    replacement = self.capacity_row(table, ack=True, **{column: value})
                    operation = lambda: self.insert(table, replacement, conn=self.old, replace=True)
                self.assert_denied_without_change(table, operation, "managed_allocation_replace_forbidden")

    def test_direct_insert_or_replace_cannot_displace_any_bound_unique_key(self):
        self.assert_replace_collisions("reservations", update=False)

    def test_direct_update_or_replace_cannot_displace_any_bound_unique_key(self):
        self.assert_replace_collisions("reservations", update=True)

    def test_routed_insert_or_replace_cannot_displace_any_bound_unique_key(self):
        self.assert_replace_collisions("worker_reservations", update=False)

    def test_routed_update_or_replace_cannot_displace_any_bound_unique_key(self):
        self.assert_replace_collisions("worker_reservations", update=True)

    def test_old_worker_locality_changes_and_referenced_worker_delete_are_fenced(self):
        self.managed("worker_reservations")
        self.assert_denied_without_change("workers", lambda: self.old.execute(
            "UPDATE workers SET capabilities_json=? WHERE id=?", ('{"local":false}', self.worker["id"])))
        self.assert_denied_without_change("workers", lambda: self.old.execute("DELETE FROM workers WHERE id=?", (self.worker["id"],)),
                                         "worker_release_requires_unreferenced")
        self.new.execute("UPDATE workers SET updated_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?", (NOW + 1, self.worker["id"]))
        self.assertEqual(self.new.execute("SELECT capabilities_json FROM workers WHERE id=?", (self.worker["id"],)).fetchone()[0], '{"local":true}')

    def test_referenced_worker_replace_is_denied_even_with_protocol_ack_and_recursion_off(self):
        self.managed("worker_reservations")
        other = self.worker_row(ack=True)
        self.insert("workers", other)
        rowid = self.new.execute("SELECT rowid FROM workers WHERE id=?", (self.worker["id"],)).fetchone()[0]
        for column, value in (("id", self.worker["id"]), ("rowid", rowid)):
            with self.subTest(column=column):
                replacement = self.worker_row(ack=True, capabilities_json='{"local":false}', **{column: value})
                self.assert_denied_without_change("workers", lambda: self.insert(
                    "workers", replacement, conn=self.old, replace=True), "worker_replace_forbidden")
                self.assert_denied_without_change("workers", lambda: self.old.execute(
                    f"UPDATE OR REPLACE workers SET {column}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                    (value, other["id"])), "worker_replace_forbidden")

    def test_obligation_predicate_and_installer_require_caller_transaction(self):
        for operation in (migrate_writer_fence, writer_obligations_present):
            with self.subTest(operation=operation.__name__), self.assertRaises(ValueError):
                operation(self.new)
        self.new.execute("BEGIN")
        self.assertFalse(writer_obligations_present(self.new))
        self.new.rollback()
        self.barrier()
        self.new.execute("BEGIN")
        self.assertTrue(writer_obligations_present(self.new))
        self.new.rollback()

    def test_caller_owned_migration_never_commits_the_outer_transaction(self):
        self.new.execute("BEGIN IMMEDIATE")
        self.new.execute("UPDATE reservations SET heartbeat_at=? WHERE id=?", (NOW + 5, self.legacy["id"]))
        migrate_schema(self.new, in_transaction=True)
        self.assertTrue(self.new.in_transaction)
        self.new.rollback()
        self.assertEqual(self.new.execute("SELECT heartbeat_at FROM reservations WHERE id=?", (self.legacy["id"],)).fetchone()[0], NOW)

    def assert_first_initializer_covers_both_ledgers(self, first, second, orphan_table):
        directory = self.directory / "first-initializer"
        directory.mkdir()
        first(directory)
        old = self.connect(directory / "sentinel.db")
        tables = {row[0] for row in old.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"reservations", "worker_reservations", "workers"} <= tables)
        self.insert("workers", self.worker_row("fixture-local", ack=True), conn=old)
        self.insert(orphan_table, self.capacity_row(orphan_table, ack=True,
                    execution_id=str(uuid4()), lifecycle_managed=1), conn=old)
        other_table = "reservations" if orphan_table == "worker_reservations" else "worker_reservations"
        for refresh in (False, True):
            if refresh:
                second(directory)
            with self.subTest(refresh=refresh), self.assertRaisesRegex(sqlite3.IntegrityError, "^" + PROTOCOL + "$"):
                self.insert(other_table, self.capacity_row(other_table), conn=old)
            self.assertEqual(old.execute(f"SELECT count(*) FROM {other_table}").fetchone()[0], 0)

    def test_coordinator_first_initialization_fences_routed_obligations_immediately(self):
        self.assert_first_initializer_covers_both_ledgers(Coordinator, Maintainer, "worker_reservations")

    def test_maintainer_first_initialization_fences_direct_obligations_immediately(self):
        self.assert_first_initializer_covers_both_ledgers(Maintainer, Coordinator, "reservations")


if __name__ == "__main__":
    unittest.main()
