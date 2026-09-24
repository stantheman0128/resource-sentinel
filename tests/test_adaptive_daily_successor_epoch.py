"""Bounded successor epoch SQL; synthetic native fixtures, no guardian Create."""
from contextlib import closing, contextmanager
import copy
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor_epoch as epoch
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_epoch import SettledEpochRollover
from sentinel.adaptive.supervisor_startup import supervisor_instance_binding
from tests import test_adaptive_daily_successor_host as host_fixture


class SuccessorEpochReaderTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:", isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        self.conn.execute("BEGIN")
        binding = PolicyBinding(str(uuid4()), "S-1-5-5-100-200")
        self.row = dict(schema_version=1, attempt_id=str(uuid4()), transition_id=str(uuid4()),
            successor_generation=str(uuid4()), succession_sha256="a" * 64, old_epoch="", new_epoch="guardian-" + uuid4().hex,
            supervisor_pid=101, supervisor_created_filetime_100ns="134343072000000101",
            supervisor_logon_id=binding.logon_id,
            supervisor_instance_id=supervisor_instance_binding(binding).instance_id,
            policy_instance_id=binding.instance_id, policy_logon_id=binding.logon_id,
            previous_revision=7, registry_revision=8, inventory_digest="b" * 64)

    def schema(self):
        self.conn.execute(epoch._SCHEMA)
        for sql in epoch._TRIGGERS.values():
            self.conn.execute(sql)

    def insert(self, value=None):
        value = self.row if value is None else value
        self.conn.execute(f"INSERT INTO {epoch.TABLE} VALUES({','.join('?' for _ in epoch._FIELDS)})",
                          tuple(value[name] for name in epoch._FIELDS))

    def test_absence_is_read_only_and_requires_real_transaction(self):
        before = self.conn.total_changes
        value = epoch.read_successor_guardian_epochs(self.conn, max_rows=0, max_bytes=0)
        self.assertEqual((value.entries, value.rows_used, value.bytes_used), ((), 0, 0))
        self.assertEqual(self.conn.total_changes, before)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM sqlite_master").fetchone()[0], 0)
        self.conn.rollback()
        with self.assertRaisesRegex(LifecycleError, "transaction_required"):
            epoch.read_successor_guardian_epochs(self.conn)

    def test_canonical_scalar_audit_reports_exact_bytes_and_bounds(self):
        self.schema()
        self.insert()
        value = epoch.read_successor_guardian_epochs(self.conn)
        self.assertEqual(value.rows_used, 1)
        self.assertEqual(value.entries[0].to_dict(), self.row)
        self.assertEqual(value.entries[0].values, tuple(self.row[name] for name in epoch._FIELDS))
        self.assertEqual(value.bytes_used, len(epoch._encoded(self.row)))
        self.assertEqual(epoch.read_successor_guardian_epochs(self.conn, max_rows=1, max_bytes=value.bytes_used), value)
        with self.assertRaisesRegex(LifecycleError, "rows_exceeded"):
            epoch.read_successor_guardian_epochs(self.conn, max_rows=0)
        with self.assertRaisesRegex(LifecycleError, "bytes_exceeded"):
            epoch.read_successor_guardian_epochs(self.conn, max_bytes=value.bytes_used - 1)

    def test_mutations_replacements_and_missing_immutable_trigger_refuse(self):
        self.schema()
        self.insert()
        for sql in (f"UPDATE {epoch.TABLE} SET inventory_digest='changed'", f"DELETE FROM {epoch.TABLE}",
                    f"INSERT OR REPLACE INTO {epoch.TABLE} SELECT * FROM {epoch.TABLE}"):
            with self.subTest(sql=sql), self.assertRaisesRegex(sqlite3.IntegrityError, "successor_epoch_immutable"):
                self.conn.execute(sql)
        self.conn.execute(f"DROP TRIGGER {epoch.TABLE}_update")
        with self.assertRaisesRegex(LifecycleError, "schema_unverified"):
            epoch.read_successor_guardian_epochs(self.conn)

    def test_oversized_text_is_classified_before_fetch_and_scalar_types_are_strict(self):
        self.schema()
        self.insert(dict(self.row, inventory_digest="x" * 100000))
        def bounded_text(value):
            if len(value) > 65536:
                raise AssertionError("unbounded audit payload fetched")
            return value.decode("utf-8")
        self.conn.text_factory = bounded_text
        with self.assertRaisesRegex(LifecycleError, "row_invalid"):
            epoch.read_successor_guardian_epochs(self.conn)

    def test_wrong_scalar_binding_revision_or_epoch_refuses(self):
        for changed in (dict(self.row, registry_revision=10), dict(self.row, previous_revision=-1),
                dict(self.row, supervisor_instance_id=str(uuid4())),
                dict(self.row, policy_logon_id="S-1-5-5-9-9"),
                dict(self.row, supervisor_created_filetime_100ns="0134343072000000101"),
                dict(self.row, old_epoch=self.row["new_epoch"]), dict(self.row, new_epoch="")):
            with self.subTest(changed=changed):
                self.conn.execute("SAVEPOINT invalid_row")
                try:
                    self.schema()
                    self.insert(changed)
                    with self.assertRaisesRegex(LifecycleError, "row_invalid"):
                        epoch.read_successor_guardian_epochs(self.conn)
                finally:
                    self.conn.execute("ROLLBACK TO invalid_row")
                    self.conn.execute("RELEASE invalid_row")


class SuccessorGuardianEpochTests(unittest.TestCase):
    def setUp(self):
        # Unknown fixture scopes remain unknown. Isolate their registry for the
        # whole fixture lifetime instead of clearing production custody flags.
        readiness_registry = patch.object(generation, "_READINESS_SCOPES", {})
        readiness_registry.start()
        self.addCleanup(readiness_registry.stop)
        self.fixture = host_fixture.DailySuccessorHostTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.host = self.fixture.publish_host()
        self.supervisor = self.fixture.acquire_supervisor(self.host)
        self.operation, self.store = self.fixture.operation, self.fixture.store
        self.raw_connections = []
        self.addCleanup(self.close_raw_fixtures)
        self.before = self.runtime()
        self.before_rows = self.ordinary_rows()
        self.owner = epoch.SuccessorGuardianEpoch(self.operation, self.supervisor)

    def close_raw_fixtures(self):
        for connection in self.raw_connections:
            sqlite3.Connection.close(connection)  # Fixture release only; original unknown flags stay unchanged.

    def reader(self):
        return self.fixture.fixture.fixture.reader()

    def runtime(self):
        with self.reader() as conn:
            return dict(conn.execute("SELECT * FROM adaptive_runtime").fetchone())

    def ordinary_rows(self):
        with self.reader() as conn:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                     if not row[0].startswith("sqlite_") and row[0] not in {epoch.TABLE, "adaptive_runtime"}]
            return {name: tuple(tuple(row) for row in conn.execute(f'SELECT * FROM "{name}" ORDER BY rowid'))
                    for name in names}

    def audits(self):
        with self.reader() as conn:
            conn.execute("BEGIN")
            return epoch.read_successor_guardian_epochs(conn)

    def assert_complete(self):
        self.assertIsNone(self.owner.assert_complete())
        row = self.audits().entries[0].to_dict()
        runtime = self.runtime()
        self.assertEqual(len(self.audits().entries), 1)
        self.assertEqual(row["attempt_id"], self.owner.attempt_id)
        self.assertEqual(row["transition_id"], self.operation.transition_id)
        self.assertEqual(row["successor_generation"], self.operation.owner.generation)
        self.assertEqual(row["succession_sha256"], self.operation._archive.sha256)
        self.assertEqual(row["inventory_digest"], self.owner._snapshot.digest)
        self.assertEqual(row["old_epoch"], self.before["guardian_epoch"])
        self.assertEqual(row["new_epoch"], self.owner.new_epoch)
        self.assertEqual(row["supervisor_instance_id"], self.supervisor.startup.instance_binding.instance_id)
        self.assertEqual(runtime, dict(self.before, guardian_epoch=self.owner.new_epoch,
            active_logon_id=self.owner.identity.logon_id, registry_revision=self.before["registry_revision"] + 1))
        self.assertEqual(self.ordinary_rows(), self.before_rows)
        self.assertIsNot(self.owner._guard, self.operation.guard)
        self.assertTrue(self.owner._guard._native_exit_confirmed)
        self.assertTrue(self.owner._guard._nonce_clear_attempted)
        self.assertTrue(all(item.closed and not item.close_unknown for item in self.owner._connections))
        self.assertTrue(self.supervisor.startup.acquired)
        self.assertIsNone(self.supervisor.guardian)
        self.assertEqual(self.supervisor.started_guardians, 0)
        with self.reader() as conn:
            conn.execute("BEGIN")
            self.assertEqual(epoch.validate_successor_guardian_epoch(conn, guardian_epoch=self.owner.new_epoch,
                logon_id=self.owner.identity.logon_id, policy_instance_id=self.owner.binding.instance_id), row)

    @contextmanager
    def sql_fault(self, kind):
        connect = sqlite3.connect
        state = dict(raised=False, cas=0, error=None)

        class Fault(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                if " ".join(sql.split()).startswith("UPDATE adaptive_runtime SET guardian_epoch="):
                    connection.fixture_epoch_cas = True
                    state["cas"] += 1
                    if kind == "rollback" and not state["raised"]:
                        state["raised"] = True
                        raise sqlite3.OperationalError("fixture_epoch_before_cas")
                return super().execute(sql, parameters)

            def commit(connection):
                super().commit()
                if kind == "commit_ack" and getattr(connection, "fixture_epoch_cas", False) and not state["raised"]:
                    state["raised"] = True
                    raise sqlite3.OperationalError("fixture_epoch_commit_ack_lost")

            def close(connection):
                if kind == "unknown_close" and getattr(connection, "fixture_epoch_cas", False) and not state["raised"]:
                    state["raised"] = True
                    raise RuntimeError("fixture_epoch_sql_close_unknown")
                return super().close()

        def connecting(*args, **kwargs):
            kwargs["factory"] = Fault
            connection = connect(*args, **kwargs)
            self.raw_connections.append(connection)
            lose_open = kind == "unknown_open" or (
                kind == "unknown_store_open" and "?mode=rw" in str(args[0]))
            if lose_open and not state["raised"]:
                state["raised"] = True
                state["error"] = RuntimeError("fixture_epoch_sql_open_unknown")
                raise state["error"]
            return connection

        with patch.object(sqlite3, "connect", side_effect=connecting):
            yield state

    def test_original_successor_publishes_one_cas_without_old_native_reentry_or_create(self):
        old = self.operation.retirement
        with (patch.object(old.owner.process, "observe", side_effect=AssertionError("closed old self observed")),
              patch.object(old.supervisor.startup, "assert_held", side_effect=AssertionError("closed old startup reused")),
              patch.object(self.supervisor, "_start_guardian", side_effect=AssertionError("guardian Create"))):
            result = self.owner.tick()
        self.assertTrue(result.complete, result)
        self.assert_complete()

    def test_same_attempt_replay_is_read_only_and_does_not_increment_revision(self):
        first = self.owner.tick()
        self.assertTrue(first.complete, first)
        originals = (self.owner.attempt_id, self.owner.new_epoch, self.owner._candidate, self.owner._snapshot,
                     self.owner._guard, self.runtime(), self.audits())
        with patch.object(self.store._policy.provider, "hold", side_effect=AssertionError("new POLICY attempt")):
            self.assertIs(self.owner.tick(), first)
            self.owner.assert_complete()
        self.assertEqual((self.owner.attempt_id, self.owner.new_epoch, self.owner._candidate, self.owner._snapshot,
                          self.owner._guard, self.runtime(), self.audits()), originals)

    def test_copies_or_replaced_original_startup_cannot_publish(self):
        with self.assertRaisesRegex(LifecycleError, "original_operation_required"):
            copy.copy(self.owner).tick()
        with self.assertRaisesRegex(LifecycleError, "original_attempt_already_present"):
            epoch.SuccessorGuardianEpoch(self.operation, self.supervisor)
        startup = self.supervisor.startup
        with patch.object(self.supervisor, "startup", copy.copy(startup)):
            with self.assertRaises(RuntimeError):
                self.owner.tick()
        self.assertEqual(self.runtime(), self.before)
        self.assertEqual(self.audits().entries, ())

    def test_commit_ack_loss_reconciles_exact_audit_without_duplicate_cas(self):
        with self.sql_fault("commit_ack") as fault:
            result = self.owner.tick()
        self.assertTrue(fault["raised"])
        self.assertFalse(result.complete)
        self.assertTrue(result.pending)
        self.assertFalse(self.owner._complete)
        self.assertEqual(len(self.audits().entries), 1)
        candidate, attempt, new_epoch = self.owner._candidate, self.owner.attempt_id, self.owner.new_epoch
        retry = self.owner.tick()
        self.assertTrue(retry.complete, retry)
        self.assertIs(self.owner._candidate, candidate)
        self.assertEqual((self.owner.attempt_id, self.owner.new_epoch), (attempt, new_epoch))
        self.assert_complete()

    def test_failed_cas_rolls_back_audit_and_preserves_original_runtime(self):
        with self.sql_fault("rollback") as fault:
            result = self.owner.tick()
        self.assertTrue(fault["raised"])
        self.assertFalse(result.complete)
        self.assertEqual(self.audits().entries, ())
        runtime = self.runtime()
        self.assertEqual({key: value for key, value in runtime.items() if key != "policy_entry_nonce"},
                         {key: value for key, value in self.before.items() if key != "policy_entry_nonce"})
        self.assertEqual(self.ordinary_rows(), self.before_rows)
        retry = self.owner.tick()
        self.assertTrue(retry.complete, retry)
        self.assert_complete()

    def test_unknown_original_close_retains_same_attempt_and_blocks_retry(self):
        with self.sql_fault("unknown_close") as fault:
            result = self.owner.tick()
        self.assertTrue(fault["raised"])
        self.assertFalse(result.complete)
        self.assertTrue(result.quarantined)
        self.assertIsNotNone(self.owner._error)
        self.assertFalse(self.owner._complete)
        self.assertTrue(any(not item.closed for item in self.owner._connections))
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown close replacement")):
            with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
                self.owner.tick()
        self.assertIsNone(self.supervisor.guardian)

    def test_unknown_readiness_open_retains_original_reader_and_blocks_retry(self):
        with self.sql_fault("unknown_open") as fault:
            result = self.owner.tick()
        self.assertTrue(fault["raised"])
        self.assertFalse(result.complete)
        self.assertTrue(result.quarantined)
        self.assertIs(self.owner._error, fault["error"])
        self.assertIs(self.owner._policy_operation._error, fault["error"])
        scope = self.owner._error.daily_readiness_scope
        self.assertIs(type(scope), generation._ReadinessScope)
        self.assertIs(scope.error, fault["error"])
        self.assertEqual(scope.path, self.store.db_path.resolve())
        self.assertIs(generation._READINESS_SCOPES[id(scope)], scope)
        self.assertIs(scope.pool, generation._READINESS_SCOPES)
        self.assertIs(type(scope.reader), generation._ReadinessReader)
        self.assertTrue(scope.reader.open_attempted)
        self.assertIsNone(scope.reader.connection)
        self.assertFalse(scope.reader.closed)
        self.assertFalse(scope.closed)
        # Readiness precedes the Store opener; that later acquisition did not
        # happen. The original reader above is the actual unknown SQL owner.
        self.assertEqual(self.owner._connections, [])
        self.assertEqual(self.runtime(), self.before)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown readiness acquisition repeated")):
            with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
                self.owner.tick()
        self.assertIs(generation._READINESS_SCOPES[id(scope)], scope)
        self.assertFalse(scope.reader.closed)
        self.assertFalse(scope.closed)
        self.assertEqual(self.audits().entries, ())

    def test_unknown_original_store_open_retains_none_attempt_and_blocks_retry(self):
        with self.sql_fault("unknown_store_open") as fault:
            result = self.owner.tick()
        self.assertTrue(fault["raised"])
        self.assertFalse(result.complete)
        self.assertTrue(result.quarantined)
        self.assertIs(self.owner._error, fault["error"])
        self.assertIs(self.owner._error._daily_successor_epoch, self.owner)
        self.assertEqual(len(self.owner._connections), 1)
        original = self.owner._connections[0]
        self.assertIsNone(original.connection)
        self.assertFalse(original.closed)
        self.assertEqual(self.owner._connection_pins[id(original)], (original, None))
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown acquisition repeated")):
            with self.assertRaisesRegex(LifecycleError, "custody_unsettled"):
                self.owner.tick()
        self.assertIs(self.owner._connections[0], original)
        self.assertIsNone(original.connection)
        self.assertFalse(original.closed)
        self.assertEqual(self.audits().entries, ())

    def test_registration_rejects_changed_generation_policy_epoch_or_revision(self):
        result = self.owner.tick()
        self.assertTrue(result.complete, result)
        with self.reader() as conn:
            conn.execute("BEGIN")
            for logon, policy_id, wanted in (("S-1-5-5-9-9", self.owner.binding.instance_id, self.owner.new_epoch),
                    (self.owner.identity.logon_id, str(uuid4()), self.owner.new_epoch)):
                with self.assertRaisesRegex(LifecycleError, "binding_changed"):
                    epoch.validate_successor_guardian_epoch(conn, guardian_epoch=wanted, logon_id=logon,
                        policy_instance_id=policy_id)
        # This raw isolated writer deliberately corrupts a metadata cell. The
        # read-only consumer must independently detect the current mismatch.
        for table, field, value in (("adaptive_runtime", "guardian_epoch", "foreign-epoch"),
                ("adaptive_runtime", "registry_revision", self.before["registry_revision"] + 2),
                ("adaptive_runtime", "mode", "shadow"),
                (generation._TABLE, "generation", str(uuid4()))):
            with self.subTest(field=field), closing(sqlite3.connect(self.store.db_path)) as conn:
                conn.row_factory = sqlite3.Row
                conn.execute("BEGIN")
                conn.execute(f"UPDATE {table} SET {field}=?", (value,))
                with self.assertRaisesRegex(LifecycleError, "binding_changed"):
                    epoch.validate_successor_guardian_epoch(conn, guardian_epoch=self.owner.new_epoch,
                        logon_id=self.owner.identity.logon_id, policy_instance_id=self.owner.binding.instance_id)
                conn.rollback()

    def test_registration_refuses_a_matching_ordinary_rollover_route(self):
        result = self.owner.tick()
        self.assertTrue(result.complete, result)
        connection = sqlite3.connect(self.store.db_path, isolation_level=None)
        self.addCleanup(connection.close)
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        SettledEpochRollover._audit_schema(connection, create=True)
        identity = self.owner.identity
        connection.execute("INSERT INTO adaptive_epoch_rollovers VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (
            str(uuid4()), "older", self.owner.new_epoch, identity.pid, str(identity.created_filetime_100ns),
            identity.logon_id, self.owner.binding.instance_id, self.owner.binding.logon_id,
            self.before["registry_revision"], self.before["registry_revision"] + 1, 0, "a" * 64))
        with self.assertRaisesRegex(LifecycleError, "ambiguous_audit_route"):
            epoch.validate_successor_guardian_epoch(connection, guardian_epoch=self.owner.new_epoch,
                logon_id=identity.logon_id, policy_instance_id=self.owner.binding.instance_id)
        connection.rollback()


if __name__ == "__main__":
    unittest.main()
