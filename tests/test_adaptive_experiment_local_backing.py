"""Portable SQL tests for typed isolated experiment backing publication.

These compose the real two-ledger admission fixture: SQLite, managed admission,
original publication owners and persistent guards are real. Native handles,
readiness and POLICY providers are explicit fixtures, never Windows evidence.
The adapter integration is deliberately required; a standalone row factory is
not sufficient to make these tests pass.
"""
from contextlib import closing, contextmanager, ExitStack
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import experiment_local_backing as local
from sentinel.adaptive import experiment_host_ledger as ledger
from sentinel.adaptive import host_authority
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.store import migrate_schema
from tests import test_adaptive_experiment_partition_admission as fixtures
from tests.test_adaptive_coordinator import NOW


class ExperimentLocalBackingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ExperimentPartitionAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.adapter = self.fixture.adapter
        self.context = self.fixture.context
        self.snapshot = self.fixture.snapshot
        self.db_path = self.fixture.coordinator.db_path

    @contextmanager
    def connection(self, *, readonly=False):
        database = Path(self.db_path).resolve().as_uri() + "?mode=ro" if readonly else self.db_path
        with closing(sqlite3.connect(database, uri=readonly, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN")
            try:
                yield conn
            finally:
                conn.rollback()

    def admit(self):
        result = self.adapter.admit_managed(self.context)
        self.assertTrue(result["allowed"])
        return result

    def inventory(self, **bounds):
        with self.connection(readonly=True) as conn:
            return local.read_inventory_locked(conn, **(dict(max_rows=10, max_bytes=1 << 20) | bounds))

    def link(self, execution_id=None, **bounds):
        with self.connection(readonly=True) as conn:
            return local.read_link_locked(conn, execution_id or self.snapshot.execution_id,
                **(dict(max_rows=10, max_bytes=1 << 20) | bounds))

    def assert_no_local_capacity(self):
        self.fixture.assert_empty()
        self.assertEqual(self.inventory().rows, ())

    def test_publication_brackets_actual_admission_in_one_original_transaction(self):
        events, originals = [], {}
        prepare = local.LocalBackingPublication.prepare
        begin = local.begin_locked
        publish = local.publish_locked
        commit = self.fixture.coordinator._commit_admission

        def preparing(*, adapter, context, observation):
            self.assertIs(adapter, self.adapter)
            self.assertIs(context, self.context)
            self.assertIs(adapter._local_backing_observation, observation)
            self.assertFalse(self.fixture.policy.active)
            self.assertEqual(adapter._daily_reads, [])
            self.assertIsNone(context._submission_transaction)
            operation = prepare(adapter=adapter, context=context, observation=observation)
            self.assertIs(adapter._local_backing_publication, operation)
            originals.update(operation=operation, observation=observation)
            events.append("prepare")
            return operation

        def beginning(conn, *, operation, policy, guard):
            self.assertIs(operation, originals["operation"])
            self.assertIs(policy, self.adapter._original_isolated_policy)
            self.assertIs(policy.assert_held(), guard)
            self.assertTrue(conn.in_transaction)
            self.assertEqual(self.adapter._daily_reads, [])
            self.assertIs(self.context._submission_transaction["connection"], conn)
            self.assertIsNone(conn.execute("SELECT 1 FROM managed_executions").fetchone())
            self.assertIsNone(conn.execute("SELECT 1 FROM reservations").fetchone())
            originals.update(conn=conn, transaction=self.context._submission_transaction, guard=guard)
            events.append("begin")
            return begin(conn, operation=operation, policy=policy, guard=guard)

        def publishing(conn, *, operation, policy, guard, admission_result):
            self.assertIs(conn, originals["conn"])
            self.assertIs(guard, originals["guard"])
            self.assertIs(self.context._submission_transaction, originals["transaction"])
            self.assertTrue(conn.in_transaction)
            self.assertEqual(conn.execute("SELECT count(*) FROM managed_executions").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
            value = publish(conn, operation=operation, policy=policy, guard=guard,
                            admission_result=admission_result)
            self.assertIsNotNone(local.read_link_locked(conn, self.snapshot.execution_id,
                max_rows=10, max_bytes=1 << 20))
            events.append("publish")
            return value

        def committing(conn, transaction):
            self.assertIs(conn, originals["conn"])
            self.assertIs(transaction, originals["transaction"])
            events.append("commit")
            return commit(conn, transaction)

        with patch.object(local.LocalBackingPublication, "prepare", side_effect=preparing), \
                patch.object(local, "begin_locked", side_effect=beginning), \
                patch.object(local, "publish_locked", side_effect=publishing), \
                patch.object(self.fixture.coordinator, "_commit_admission", side_effect=committing):
            result = self.admit()
        self.assertEqual(events, ["prepare", "begin", "publish", "commit"])
        self.assertEqual(result["reservation_id"], self.fixture.operation.binding.reservation_id)
        self.assertEqual(self.inventory().rows_used, 1)

    def test_link_is_immutable_bounded_observation_without_secrets_or_authority(self):
        self.admit()
        inventory = self.inventory()
        self.assertIs(type(inventory), local.LocalBackingInventory)
        self.assertIs(type(inventory.rows), tuple)
        self.assertEqual(inventory.rows_used, 1)
        self.assertGreater(inventory.bytes_used, 0)
        self.assertEqual(len(inventory.rows), 1)
        observation = inventory.rows[0]
        self.assertIs(type(observation), local.LocalBackingObservation)
        self.assertIs(type(observation.fields), tuple)
        self.assertTrue(all(type(item) is tuple and len(item) == 2 for item in observation.fields))
        self.assertEqual(observation, self.link())
        row = observation.to_dict()
        self.assertEqual(set(row), set(local.FIELDS))
        encoded = ledger._canonical(row)
        self.assertNotIn(self.snapshot.ipc_auth_key.hex(), encoded)
        self.assertNotIn(self.snapshot.claim_token_hash, encoded)
        for key in ("ipc_auth_key", "claim_token_hash", "command_text", "command", "env"):
            self.assertNotIn(key, row)
        first = local.FIELDS[0]
        row[first] = "mutated detached observation"
        self.assertNotEqual(observation.to_dict()[first], row[first])
        with self.assertRaises((FrozenInstanceError, AttributeError, TypeError)):
            observation.fields = ()
        self.assertIsNone(self.link(str(uuid4())))

    def test_original_replay_and_commit_ack_loss_preserve_same_link_and_local_allocation(self):
        commit = self.fixture.coordinator._commit_admission
        def lose_ack(conn, transaction):
            commit(conn, transaction)
            raise OSError("local_backing_commit_ack_lost")
        with patch.object(self.fixture.coordinator, "_commit_admission", side_effect=lose_ack):
            with self.assertRaisesRegex(OSError, "local_backing_commit_ack_lost"):
                self.adapter.admit_managed(self.context)
        before = self.inventory()
        allocations = self.fixture.rows("reservations")
        self.assertEqual(before.rows_used, 1)
        observed = self.adapter.reconcile_managed(self.context)
        self.assertEqual(observed["state"], "RESERVED")
        result = self.admit()
        self.assertTrue(result["reused"])
        self.assertEqual(self.inventory(), before)
        self.assertEqual(self.fixture.rows("reservations"), allocations)

    def test_failure_after_link_insert_rolls_back_link_and_both_capacity_rows(self):
        daily_before = self.fixture.host.fixture.assert_retained(self.fixture.host.owner)
        publish = local.publish_locked
        entered = []
        def fail_after_publication(conn, **kwargs):
            publish(conn, **kwargs)
            self.assertIsNotNone(local.read_link_locked(conn, self.snapshot.execution_id,
                max_rows=10, max_bytes=1 << 20))
            entered.append(conn)
            raise OSError("local_backing_after_insert_fault")
        with patch.object(local, "publish_locked", side_effect=fail_after_publication):
            with self.assertRaisesRegex(OSError, "local_backing_after_insert_fault"):
                self.adapter.admit_managed(self.context)
        self.assertEqual(len(entered), 1)
        self.assert_no_local_capacity()
        transaction = self.context._submission_transaction
        self.assertTrue(transaction["rolled_back"])
        self.assertTrue(transaction["connection_closed"])
        self.assertEqual(self.fixture.host.fixture.assert_retained(self.fixture.host.owner), daily_before)
        self.assertIsNotNone(self.adapter._local_backing_publication)

    def test_preexisting_managed_row_without_link_cannot_be_upgraded_by_retry(self):
        # Simulate the previous adapter version only while seeding its ordinary
        # managed row. Restore both publication functions before the assertion.
        with patch.object(local, "begin_locked"), patch.object(local, "publish_locked"):
            self.admit()
        before = self.fixture.rows("managed_executions")
        allocations = self.fixture.rows("reservations")
        self.assertEqual(self.inventory().rows, ())
        with self.assertRaises(local.LocalBackingError):
            self.adapter.admit_managed(self.context)
        self.assertEqual(self.fixture.rows("managed_executions"), before)
        self.assertEqual(self.fixture.rows("reservations"), allocations)
        self.assertEqual(self.inventory().rows, ())

    def test_copied_observation_or_replaced_registered_owner_cannot_publish(self):
        self.admit()
        operation = self.adapter._local_backing_publication
        observation = self.adapter._local_backing_observation
        self.assertIs(local.LocalBackingPublication.prepare(adapter=self.adapter,
            context=self.context, observation=observation), operation)
        with self.assertRaises(local.LocalBackingError):
            local.LocalBackingPublication.prepare(adapter=self.adapter, context=self.context,
                                                  observation=replace(observation))
        self.adapter._local_backing_publication = object()
        try:
            with self.assertRaises(local.LocalBackingError):
                local.LocalBackingPublication.prepare(adapter=self.adapter, context=self.context,
                                                      observation=observation)
        finally:
            self.adapter._local_backing_publication = operation
        self.assertEqual(self.inventory().rows_used, 1)

    def test_publish_refuses_replaced_original_submission_transaction(self):
        publish = local.publish_locked
        observed = []
        def copied_transaction(conn, **kwargs):
            original = self.context._submission_transaction
            self.context._submission_transaction = dict(original)
            try:
                observed.append(original)
                return publish(conn, **kwargs)
            finally:
                self.context._submission_transaction = original
        with patch.object(local, "publish_locked", side_effect=copied_transaction):
            with self.assertRaises(local.LocalBackingError):
                self.adapter.admit_managed(self.context)
        self.assertEqual(len(observed), 1)
        self.assert_no_local_capacity()

    def test_locked_publication_does_not_repeat_native_snapshot_or_filesystem_reads(self):
        begin, publish = local.begin_locked, local.publish_locked
        calls = []
        def sql_only(function, label):
            def execute(conn, **kwargs):
                self.assertTrue(conn.in_transaction)
                self.assertEqual(self.adapter._daily_reads, [])
                calls.append(label)
                with ExitStack() as stack:
                    for target, name in ((self.context, "snapshot"), (self.context, "snapshot_for_ledger"),
                            (self.adapter, "_native_binding"), (self.adapter, "_files"),
                            (Path, "stat"), (Path, "resolve")):
                        stack.enter_context(patch.object(target, name,
                            side_effect=AssertionError("native or filesystem observation in isolated SQL")))
                    return function(conn, **kwargs)
            return execute
        with patch.object(local, "begin_locked", side_effect=sql_only(begin, "begin")), \
                patch.object(local, "publish_locked", side_effect=sql_only(publish, "publish")):
            self.admit()
        self.assertEqual(calls, ["begin", "publish"])

    def test_raw_insert_update_and_delete_cannot_manufacture_or_mutate_link(self):
        self.admit()
        before = self.inventory()
        row = before.rows[0].to_dict()
        with self.connection() as conn:
            candidate = dict(row, execution_id=str(uuid4()), reservation_id=uuid4().hex,
                             request_key="e" * 64, member_id=str(uuid4()), wrapper_member_id=str(uuid4()))
            candidate["link_sha256"] = local._digest(candidate)
            # A fresh, structurally valid row has no UNIQUE conflict. It must
            # still fail because this raw connection lacks the original owner.
            for statement, values in (
                    ("INSERT INTO " + local.TABLE + "(" + ",".join(local.FIELDS) + ") VALUES(" +
                     ",".join("?" for _ in local.FIELDS) + ")", tuple(candidate[key] for key in local.FIELDS)),
                    ("UPDATE " + local.TABLE + " SET " + local.FIELDS[0] + "=" + local.FIELDS[0], ()),
                    ("DELETE FROM " + local.TABLE, ())):
                with self.subTest(statement=statement.split()[0]), self.assertRaises(sqlite3.DatabaseError):
                    conn.execute(statement, values)
            conn.commit()
        self.assertEqual(self.inventory(), before)

    def test_unknown_schema_shape_cannot_be_treated_as_absent(self):
        with self.connection() as conn:
            conn.execute("CREATE TABLE " + local.TABLE + "(unknown_version INTEGER)")
            for consumer in ("inventory", "link", "ordinary"):
                with self.subTest(consumer=consumer), self.assertRaises(local.LocalBackingError):
                    if consumer == "inventory":
                        local.read_inventory_locked(conn, max_rows=10, max_bytes=1 << 20)
                    elif consumer == "link":
                        local.read_link_locked(conn, self.snapshot.execution_id,
                            max_rows=10, max_bytes=1 << 20)
                    else:
                        local.assert_ordinary_execution(conn, self.snapshot.execution_id)

    def test_replace_refuses_each_unique_alias_and_rowid_even_with_insert_udf_true(self):
        self.admit()
        before = self.inventory()
        original = before.rows[0].to_dict()
        with self.connection() as conn:
            conn.create_function(local._UDF, -1, lambda *values: 1)
            conn.execute("PRAGMA recursive_triggers=OFF")
            unique_columns = []
            for index in conn.execute("PRAGMA index_list(" + local.TABLE + ")").fetchall():
                if index[2]:
                    columns = tuple(row[2] for row in conn.execute("PRAGMA index_info(" + index[1] + ")"))
                    self.assertEqual(len(columns), 1, "add a composite-alias case if the schema changes")
                    unique_columns.append(columns[0])
            self.assertGreater(len(unique_columns), 1)
            rowid = conn.execute("SELECT rowid FROM " + local.TABLE).fetchone()[0]
            for collision in (*unique_columns, "rowid"):
                candidate = dict(original)
                for number, column in enumerate(unique_columns):
                    value = original[column]
                    candidate[column] = (str(uuid4()) if len(value) == 36 else
                        uuid4().hex if len(value) == 32 else f"{number + 1:064x}")
                if collision != "rowid":
                    candidate[collision] = original[collision]
                # Keep all non-colliding UNIQUE values distinct and use the
                # production link digest; require the immutable guard's error.
                candidate["link_sha256"] = local._digest(candidate)
                fields = (("rowid",) + local.FIELDS) if collision == "rowid" else local.FIELDS
                values = ((rowid,) if collision == "rowid" else ()) + tuple(candidate[key] for key in local.FIELDS)
                with self.subTest(collision=collision), self.assertRaisesRegex(sqlite3.DatabaseError, "immutable"):
                    conn.execute("INSERT OR REPLACE INTO " + local.TABLE + "(" + ",".join(fields) +
                                 ") VALUES(" + ",".join("?" for _ in fields) + ")", values)
            conn.commit()
        self.assertEqual(self.inventory(), before)

    def test_dropped_link_table_keeps_anchor_and_migration_cannot_restore_ordinary_authority(self):
        self.admit()
        managed = self.fixture.base_store.query(self.snapshot.execution_id)
        anchor = local.PREFIX + "initialized"
        with self.connection() as conn:
            conn.execute("DROP TABLE " + local.TABLE)
            self.assertEqual(conn.execute("SELECT tbl_name FROM sqlite_master WHERE name=?",
                                          (anchor,)).fetchone()[0], "managed_executions")
            with self.assertRaises(local.LocalBackingError):
                local.assert_ordinary_execution(conn, self.snapshot.execution_id)
            migrate_schema(conn, in_transaction=True)
            migrate_schema(conn, in_transaction=True)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                           (local.TABLE,)).fetchone())
            self.assertEqual(conn.execute("SELECT tbl_name FROM sqlite_master WHERE name=?",
                                          (anchor,)).fetchone()[0], "managed_executions")
            with self.assertRaises(local.LocalBackingError):
                local.assert_ordinary_execution(conn, self.snapshot.execution_id)
            conn.commit()
        authority = host_authority.HostAuthority(self.fixture.base_store, clock=lambda: NOW)
        with self.assertRaisesRegex(host_authority.HostAuthorityError, "local_backing_schema_invalid"):
            authority.assert_covered(managed)
        with self.assertRaisesRegex(host_authority.HostAuthorityError, "local_backing_schema_invalid"):
            authority.assert_excluded(managed)
        endpoint = NativePipeEndpoint(self.snapshot.logon_id, str(uuid4()),
                                      self.fixture.host.owner._snapshot.wrapper_identity)
        with patch.object(host_authority, "read_host_capability", return_value=object()):
            with self.assertRaisesRegex(host_authority.HostReadinessError, "local_backing_schema_invalid"):
                authority.assert_launch_ready(self.context, managed, endpoint)

    def test_missing_schema_is_allowed_but_partial_and_extra_schema_are_refused(self):
        with self.connection() as conn:
            self.assertIsNone(local.assert_ordinary_execution(conn, self.snapshot.execution_id))
            self.assertIsNone(local.assert_ordinary_execution(conn, "legacy-execution-1"))
            self.assertEqual(local.read_inventory_locked(conn, max_rows=0, max_bytes=0).rows, ())
        self.admit()
        with self.connection() as conn:
            trigger = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
                                   (local.TABLE,)).fetchone()[0]
            conn.execute("DROP TRIGGER " + trigger)
            with self.assertRaises(local.LocalBackingError):
                local.read_inventory_locked(conn, max_rows=10, max_bytes=1 << 20)
            with self.assertRaises(local.LocalBackingError):
                local.assert_ordinary_execution(conn, str(uuid4()))
        with self.connection() as conn:
            conn.execute("CREATE TRIGGER unexpected_local_backing_trigger AFTER INSERT ON " +
                         local.TABLE + " BEGIN SELECT 1; END")
            with self.assertRaises(local.LocalBackingError):
                local.read_link_locked(conn, self.snapshot.execution_id, max_rows=10, max_bytes=1 << 20)
        with self.connection() as conn:
            conn.execute("CREATE INDEX unexpected_local_backing_index ON " + local.TABLE + "(" + local.FIELDS[0] + ")")
            with self.assertRaises(local.LocalBackingError):
                local.assert_ordinary_execution(conn, self.snapshot.execution_id)

    def test_readonly_readers_enforce_remaining_row_and_byte_budget_before_payload(self):
        self.admit()
        expected = self.inventory()
        marker = self.snapshot.execution_id.encode("utf-8")
        def reject_payload(value):
            if value == marker:
                raise AssertionError("exhausted remaining budget materialized link payload")
            return value.decode("utf-8")
        for bounds in (dict(max_rows=0, max_bytes=1 << 20),
                       dict(max_rows=10, max_bytes=0),
                       dict(max_rows=10, max_bytes=expected.bytes_used - 1)):
            for reader in ("inventory", "link"):
                with self.subTest(bounds=bounds, reader=reader), self.connection(readonly=True) as conn:
                    conn.text_factory = reject_payload
                    with self.assertRaises(local.LocalBackingError):
                        if reader == "inventory":
                            local.read_inventory_locked(conn, **bounds)
                        else:
                            local.read_link_locked(conn, self.snapshot.execution_id, **bounds)
        # A conservative SQL byte upper bound may reject before the exact
        # serialized byte charge; sufficient allowance must remain usable.
        self.assertEqual(self.inventory(max_rows=1), expected)
        self.assertEqual(self.link(max_rows=1), expected.rows[0])

    def test_readonly_consumers_never_mutate_schema_data_or_native_state(self):
        self.admit()
        expected = self.inventory()
        with self.connection(readonly=True) as conn:
            changes = conn.total_changes
            schema = tuple(tuple(row) for row in conn.execute("SELECT name,sql FROM sqlite_master ORDER BY name"))
            with patch.object(self.context, "snapshot", side_effect=AssertionError("native snapshot in SQL")), \
                    patch.object(Path, "stat", side_effect=AssertionError("filesystem in SQL")), \
                    patch.object(Path, "resolve", side_effect=AssertionError("filesystem in SQL")):
                self.assertEqual(local.read_inventory_locked(conn, max_rows=10, max_bytes=1 << 20), expected)
                self.assertEqual(local.read_link_locked(conn, self.snapshot.execution_id,
                    max_rows=10, max_bytes=1 << 20), expected.rows[0])
                with self.assertRaisesRegex(local.LocalBackingError,
                        "local_backing_experiment_backed_authority_required"):
                    local.assert_ordinary_execution(conn, self.snapshot.execution_id)
            self.assertEqual(conn.total_changes, changes)
            self.assertEqual(tuple(tuple(row) for row in conn.execute(
                "SELECT name,sql FROM sqlite_master ORDER BY name")), schema)

    def test_terminal_reservation_cleanup_retains_link_and_daily_floor(self):
        result = self.admit()
        before = self.inventory()
        daily_before = self.fixture.host.fixture.assert_retained(self.fixture.host.owner)
        cancelled = self.adapter.cancel_managed(self.context, reservation_id=result["reservation_id"],
                                                expected_revision=0, now=NOW + 1)
        self.assertEqual(cancelled["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(self.fixture.rows("reservations"), [])
        self.assertEqual(self.inventory(), before)
        self.assertEqual(self.link(), before.rows[0])
        with self.connection() as conn:
            with self.assertRaisesRegex(local.LocalBackingError,
                    "local_backing_experiment_backed_authority_required"):
                local.assert_ordinary_execution(conn, self.snapshot.execution_id)
        self.assertEqual(self.fixture.host.fixture.assert_retained(self.fixture.host.owner), daily_before)

    def test_ordinary_host_coverage_exclusion_and_launch_readiness_refuse_experiment_link(self):
        self.admit()
        store = self.fixture.base_store
        row = store.query(self.snapshot.execution_id)
        authority = host_authority.HostAuthority(store, clock=lambda: NOW)
        with self.assertRaisesRegex(host_authority.HostAuthorityError,
                "local_backing_experiment_backed_authority_required"):
            authority.assert_covered(row)
        with self.assertRaisesRegex(host_authority.HostAuthorityError,
                "local_backing_experiment_backed_authority_required"):
            authority.assert_excluded(row)
        endpoint = NativePipeEndpoint(self.snapshot.logon_id, str(uuid4()),
                                      self.fixture.host.owner._snapshot.wrapper_identity)
        # This record only avoids calling the native capability reader; all
        # ledger and typed-backing checks below remain the production code.
        with patch.object(host_authority, "read_host_capability", return_value=object()):
            with self.assertRaisesRegex(host_authority.HostReadinessError,
                    "local_backing_experiment_backed_authority_required"):
                authority.assert_launch_ready(self.context, row, endpoint)


if __name__ == "__main__":
    unittest.main()
