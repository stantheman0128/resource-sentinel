"""Original successor transfers over isolated SQLite and synthetic native owners.

The completed predecessor fixture runs real generation, retirement, inventory,
POLICY and SQL validation. Only the fresh native capture is substituted here;
its return value is an actual owner with a new original synthetic process handle
and RetainedCohort. These tests neither launch native work nor activate daily use.
"""
from contextlib import closing, contextmanager
import copy
import json
import sqlite3
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_successor as successor
from sentinel.adaptive import daily_successor_history as history
from sentinel.adaptive import daily_successor_scope as scope
from sentinel.adaptive.daily_cohort import RetainedCohort
from sentinel.adaptive.daily_retirement_fence import TABLE as FENCE_TABLE, read_retirement
from sentinel.adaptive.windows import NativePolicyMutexError
from sentinel.exemptions import Exemptions
from tests import test_adaptive_daily_successor_predecessor as predecessor_fixture


class DailySuccessorTests(unittest.TestCase):
    def setUp(self):
        self.predecessor = predecessor_fixture.DailySuccessorPredecessorTests()
        self.addCleanup(self.predecessor.doCleanups)
        self.predecessor.setUp()
        self.fixture = self.predecessor.fixture
        self.db, self.store = self.fixture.db, self.fixture.store
        self.backend = self.fixture.backend
        self.captures = []
        self.raw_connections = []
        self.addCleanup(self.close_fixture_resources)

        # Seed genuine unrelated queued work while the original generation is
        # still ACTIVE, through its actual prepared lifecycle connection.
        with self.store._transaction() as conn:
            conn.execute("""INSERT INTO queue(request_key,owner_pid,owner_started,
                tool_use_id,repo,command_signature,command_text,resource_class,
                priority,priority_rank,cpu_units,ram_gib,io_slots,queued_at,heartbeat_at)
                VALUES('unrelated',901,17,'fixture-tool','fixture-repo','signature',
                    'private fixture command','HEAVY','P2',2,1,1,0,100,100)""")
        # This separate isolated file models existing user records. No grant API
        # is called, no real PID is exempted, and no daily file is accessed.
        exemptions = Exemptions(self.fixture.root)
        self.exemptions_path = exemptions.path
        with closing(exemptions._connect()) as conn:
            conn.execute("""INSERT INTO exemptions(id,root_pid,root_started,created_at,
                expires_at,reason,revoked_at)
                VALUES('existing-user-record',901,17,100,700,'fixture authorization',NULL)""")
            conn.commit()

        # Retain an actually prepared pre-retirement connection. Its capacity
        # UDF closes over the original generation; it cannot follow a successor.
        self.old_connection = sqlite3.connect(self.db, isolation_level=None)
        self.old_connection.row_factory = sqlite3.Row
        self.addCleanup(self.old_connection.close)
        generation.prepare_connection(self.old_connection, role="coordinator", db_path=self.db)
        self.retirement = self.predecessor.complete()
        self.before_generation, self.before_fence, self.before_runtime = self.fixture.state()
        self.before_rows = self.ordinary_rows()
        self.before_exemptions = self.exemption_rows()
        self.operation = successor.DailySuccessorOperation(self.retirement)

        capture = patch.object(generation.DailyGenerationOwner, "capture", side_effect=self.capture_owner)
        self.capture_mock = capture.start()
        self.addCleanup(capture.stop)

    def capture_owner(self, *, manifest, source_root, ledger_path):
        old = self.retirement.owner
        self.assertIs(manifest, old.manifest)
        self.assertEqual((source_root, ledger_path), (old.source_root, old.ledger_path))
        process = self.backend.current()
        cohort = RetainedCohort.capture_current(backend=self.backend)
        owner = generation.DailyGenerationOwner(_token=generation._TOKEN, process=process,
            cohort=cohort, manifest=manifest, source_root=source_root, ledger_path=ledger_path)
        self.captures.append(owner)
        return owner

    def close_fixture_resources(self):
        # Faulted real SQLite connections are physically closed ONLY as fixture
        # teardown; never clear production custody flags or claim reconciliation.
        for conn in self.raw_connections:
            sqlite3.Connection.close(conn)
        for owner in self.captures:
            generation._LOCAL_GENERATIONS.pop(owner.generation, None)
            owner.cohort.close()
            owner.process.close()

    def ordinary_rows(self):
        with self.fixture.reader() as conn:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
                     if not row[0].startswith("sqlite_") and row[0] not in {
                         generation._TABLE, FENCE_TABLE, history.TABLE, "adaptive_runtime"}]
            return {name: tuple(tuple(row) for row in conn.execute('SELECT * FROM "' + name + '" ORDER BY rowid'))
                    for name in sorted(names)}

    def exemption_rows(self):
        with closing(sqlite3.connect(self.exemptions_path)) as conn:
            return tuple(conn.execute("SELECT * FROM exemptions ORDER BY id"))

    def archives(self):
        with self.fixture.reader() as conn:
            conn.execute("BEGIN")
            return history.read_successor_history(conn)

    def test_transition_connection_cannot_mutate_before_inventory_and_archive(self):
        operation = self.operation
        with operation.scope():
            operation._capture_owner()
            operation._prepare_guard()
            with operation.policy.hold(operation.guard):
                with operation._connection(transition=True) as conn:
                    for transactional in (False, True):
                        with self.subTest(transactional=transactional):
                            if transactional:
                                conn.execute("BEGIN IMMEDIATE")
                            for statement in (
                                "UPDATE adaptive_daily_generation SET state='ACTIVE' WHERE singleton=1",
                                "DROP TABLE " + FENCE_TABLE,
                                history._SCHEMA,
                            ):
                                with self.assertRaises(sqlite3.DatabaseError):
                                    conn.execute(statement)
                            if transactional:
                                conn.rollback()
        self.assertEqual(self.fixture.state(),
                         (self.before_generation, self.before_fence, self.before_runtime))
        self.assertEqual(self.archives().entries, ())
        self.assertEqual(self.ordinary_rows(), self.before_rows)

    @contextmanager
    def sql_fault(self, fault=None):
        """Use actual SQLite effects; fault only the original effect's ACK/close."""
        original_connect = sqlite3.connect
        operation = self.operation
        state = dict(raised=False, commits=[], closes=[], transfer_writes=0,
                     connections=[])

        class FaultConnection(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                normalized = " ".join(sql.split())
                if normalized.startswith("UPDATE adaptive_runtime SET policy_entry_nonce=?"):
                    connection.fixture_stage = "prepare"
                elif normalized.startswith("UPDATE adaptive_runtime SET policy_entry_nonce=NULL"):
                    connection.fixture_stage = "clear"
                elif normalized.startswith("UPDATE adaptive_daily_generation SET "):
                    connection.fixture_stage = "transfer"
                    state["transfer_writes"] += 1
                    if fault == "rollback_transfer" and not state["raised"]:
                        state["raised"] = True
                        raise sqlite3.OperationalError("fixture_transfer_before_generation_write")
                return super().execute(sql, parameters)

            def commit(connection):
                stage = getattr(connection, "fixture_stage", None)
                super().commit()
                state["commits"].append(stage)
                if stage is not None and fault == "ack_" + stage and not state["raised"]:
                    state["raised"] = True
                    raise sqlite3.OperationalError("fixture_" + stage + "_commit_ack_lost")

            def close(connection):
                stage = getattr(connection, "fixture_stage", None)
                state["closes"].append((stage, None if operation.owner is None else operation.owner._activated))
                if not state["raised"] and (fault == "unknown_close_first" or
                        fault == "unknown_close_clear" and stage == "clear"):
                    state["raised"] = True
                    raise RuntimeError("fixture_original_sql_close_unknown")
                return super().close()

        def connect(*args, **kwargs):
            kwargs["factory"] = FaultConnection
            conn = original_connect(*args, **kwargs)
            state["connections"].append(conn)
            self.raw_connections.append(conn)
            return conn

        with patch.object(sqlite3, "connect", side_effect=connect):
            yield state

    def assert_finished(self):
        """Metadata is acknowledged; no fresh host has published readiness."""
        operation = self.operation
        self.assertTrue(operation._complete)
        self.assertTrue(operation.owner._activated)
        self.assertEqual(operation.phase, "successor_generation_acknowledged")
        row, frozen, runtime = self.fixture.state()
        self.assertEqual(row, operation._successor_row)
        self.assertIsNone(frozen)
        self.assertEqual(runtime, self.before_runtime)
        self.assertEqual(row["state"], "ACTIVE")
        self.assertNotEqual(row["generation"], self.before_generation["generation"])
        self.assertNotEqual(row["readiness_instance_id"], self.before_generation["readiness_instance_id"])
        for field in generation._GENERATION_FIELDS - {"generation", "state", "readiness_instance_id"}:
            self.assertEqual(row[field], self.before_generation[field], field)
        entries = self.archives().entries
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0], operation._archive)
        record = json.loads(entries[0].record)
        self.assertEqual(record["predecessor"], self.before_generation)
        self.assertEqual(record["retirement"], self.before_fence)
        self.assertEqual(record["successor"], row)
        self.assertEqual(record["transition_id"], operation.transition_id)
        self.assertEqual(record["inventory_digest"], self.retirement._seal_inventory_digest)
        self.assertEqual(record["policy"]["nonce"], operation.guard.nonce)
        self.assertEqual(self.ordinary_rows(), self.before_rows)
        self.assertEqual(self.exemption_rows(), self.before_exemptions)
        self.assertTrue(all(item.closed and not item.close_unknown for item in operation._connections))
        self.assertTrue(all(closed for _, closed in operation._bound_connections.values()))
        self.assertIsNone(operation.policy.current_guard())
        self.assertIsNone(operation.policy.current_cleanup_guard())
        self.assertTrue(operation.guard._native_exit_confirmed)
        self.capture_mock.assert_called_once()
        with self.assertRaisesRegex(successor.DailySuccessorError, "readiness_not_published"):
            operation.owner.assert_ready()
        with self.fixture.reader() as conn:
            with self.assertRaisesRegex(successor.DailySuccessorError, "readiness_not_published"):
                generation.prepare_connection(conn, role="coordinator", db_path=self.db)
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("SELECT sentinel_daily_generation()")

    def test_transfer_archives_original_seal_and_preserves_unrelated_rows(self):
        original_process = self.retirement.owner.process
        with self.sql_fault() as observed:
            self.assertTrue(self.operation.tick())
        self.assert_finished()
        self.assertEqual(observed["transfer_writes"], 1)
        self.assertEqual([stage for stage in observed["commits"] if stage is not None],
                         ["prepare", "transfer", "clear"])
        self.assertTrue(observed["closes"])
        self.assertTrue(all(activated is False for _, activated in observed["closes"]))
        self.assertIsNot(self.operation.owner.process, original_process)
        self.assertEqual(self.operation.owner.process.identity, original_process.identity)
        self.assertIsNone(original_process._handle)
        self.assertIsNotNone(self.operation.owner.process._handle)
        self.assertTrue(self.retirement.complete)
        self.assertTrue(self.retirement.host._readiness_joined)
        self.assertTrue(self.retirement.host._readiness_listener_closed)
        self.assertTrue(self.retirement.supervisor._closed)

    def test_completed_replay_preserves_owner_guard_and_archive_without_new_sql_or_capture(self):
        self.operation.tick()
        original = (self.operation.owner, self.operation.guard, self.operation._archive,
                    self.operation.transition_id, tuple(self.backend.opened))
        with patch.object(sqlite3, "connect", side_effect=AssertionError("replay opened SQL")):
            self.assertTrue(self.operation.tick())
        self.assertEqual((self.operation.owner, self.operation.guard, self.operation._archive,
                          self.operation.transition_id, tuple(self.backend.opened)), original)
        self.assert_finished()

    def test_copy_second_operation_and_foreign_thread_cannot_acquire_successor(self):
        clone = copy.copy(self.operation)
        with self.assertRaisesRegex(successor.DailySuccessorError, "original_operation_required"):
            clone.tick()
        with self.assertRaisesRegex(successor.DailySuccessorError, "original_successor_already_present"):
            successor.DailySuccessorOperation(self.retirement)
        with patch.object(successor.threading, "current_thread", return_value=threading.Thread()):
            with self.assertRaisesRegex(successor.DailySuccessorError, "original_operation_required"):
                self.operation.tick()
        self.capture_mock.assert_not_called()
        self.assertIsNone(self.operation.owner)
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))

    def test_foreign_readiness_or_nested_operation_scope_is_refused(self):
        for name in ("scope", "group"):
            with self.subTest(name=name), patch.object(generation._READINESS_LOCAL, name, object(), create=True):
                with self.assertRaisesRegex(successor.DailySuccessorError, "foreign_scope"):
                    with self.operation.scope():
                        self.fail("foreign readiness acquired successor scope")
        with patch.object(scope.CURRENT, "operation", object(), create=True):
            with self.assertRaisesRegex(successor.DailySuccessorError, "nested_operation"):
                with self.operation.scope():
                    self.fail("nested foreign operation acquired successor scope")
        self.capture_mock.assert_not_called()

    def test_metadata_scope_denies_capacity_queue_exemption_and_general_ddl_writes(self):
        with self.operation.scope():
            self.operation._capture_owner()
            self.operation._prepare_guard()
            with self.operation.policy.hold(self.operation.guard):
                for transition in (False, True):
                    with self.subTest(transition=transition), self.operation._connection(transition=transition) as conn:
                        for sql in ("UPDATE queue SET heartbeat_at=200",
                                "DELETE FROM queue WHERE request_key='unrelated'",
                                "DELETE FROM reservations", "DELETE FROM worker_reservations",
                                "UPDATE workers SET state='OFFLINE'",
                                "DELETE FROM managed_executions", "UPDATE adaptive_runtime SET mode='canary'",
                                "CREATE TABLE arbitrary_fixture(x)"):
                            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                                conn.execute(sql)
                        with self.assertRaises(sqlite3.DatabaseError):
                            conn.execute("ATTACH DATABASE ? AS user_exemptions", (str(self.exemptions_path),))
                        with self.assertRaises(sqlite3.OperationalError):
                            conn.execute("SELECT sentinel_daily_generation()")
        self.assertFalse(self.operation.owner._activated)
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))
        self.assertEqual(self.ordinary_rows(), self.before_rows)
        self.assertEqual(self.exemption_rows(), self.before_exemptions)

    def test_prepare_commit_ack_loss_reconciles_same_owner_and_nonce(self):
        with self.sql_fault("ack_prepare") as observed:
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_prepare_commit_ack_lost"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        owner, guard, transition = self.operation.owner, self.operation.guard, self.operation.transition_id
        row, frozen, runtime = self.fixture.state()
        self.assertEqual((row, frozen), (self.before_generation, self.before_fence))
        self.assertEqual(runtime["policy_entry_nonce"], guard.nonce)
        self.assertFalse(owner._activated)
        self.assertFalse(guard._native_exit_confirmed)
        self.assertTrue(self.operation.tick())
        self.assertIs(self.operation.owner, owner)
        self.assertIs(self.operation.guard, guard)
        self.assertEqual(self.operation.transition_id, transition)
        self.assert_finished()

    def test_transfer_commit_ack_loss_reconciles_postimage_without_second_native_hold_or_transfer(self):
        with self.sql_fault("ack_transfer") as observed:
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_transfer_commit_ack_lost"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        owner, archived = self.operation.owner, self.operation._archive
        self.assertFalse(owner._activated)
        self.assertEqual(self.archives().entries, (archived,))
        self.assertIsNone(self.fixture.state()[1])
        self.assertTrue(self.operation.guard._native_exit_confirmed)
        with (patch.object(self.operation.policy.provider, "hold", side_effect=AssertionError("new native POLICY")),
              patch.object(self.operation, "_transfer", side_effect=AssertionError("repeated transfer"))):
            self.assertTrue(self.operation.tick())
        self.assertIs(self.operation.owner, owner)
        self.assertIs(self.operation._archive, archived)
        self.assert_finished()

    def test_transition_ack_retry_keeps_original_cohort_and_candidate_without_rediscovery(self):
        with self.sql_fault("ack_transfer"):
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_transfer_commit_ack_lost"):
                self.operation.tick()
        owner = self.operation.owner
        process, cohort, candidate = owner.process, owner.cohort, self.operation._successor_row
        original_opened = tuple(self.backend.opened)
        original_enumerations = self.backend.enumerations
        # Later activity is not part of the already captured/settled predecessor
        # cohort. Reconciliation must read its exact SQL postimage and retained
        # originals, without taking a new discovery snapshot.
        self.backend.add(303, "python.exe")
        with (patch.object(self.backend, "current", side_effect=AssertionError("new current witness")),
              patch.object(self.backend, "capture", side_effect=AssertionError("new process witness")),
              patch.object(self.backend, "enumerate", side_effect=AssertionError("cohort rediscovery"))):
            self.assertTrue(self.operation.tick())
        self.assertIs(self.operation.owner, owner)
        self.assertIs(owner.process, process)
        self.assertIs(owner.cohort, cohort)
        self.assertIs(self.operation._successor_row, candidate)
        self.assertEqual(tuple(self.backend.opened), original_opened)
        self.assertEqual(self.backend.enumerations, original_enumerations)
        self.assert_finished()

    def test_known_policy_timeout_with_committed_clear_ack_loss_is_retryable(self):
        @contextmanager
        def timeout(binding, *, timeout_ms):
            self.assertIs(binding, self.operation.guard.binding)
            self.assertEqual(timeout_ms, 250)
            raise NativePolicyMutexError("policy_mutex_timeout")
            yield  # The explicit synthetic provider enters no native mutex.

        with (self.sql_fault("ack_clear") as observed,
              patch.object(self.operation.policy.provider, "hold", side_effect=timeout)):
            with self.assertRaisesRegex(NativePolicyMutexError, "policy_mutex_timeout") as caught:
                self.operation.tick()
        self.assertTrue(observed["raised"])
        self.assertIn("clear", observed["commits"])
        self.assertIn("policy_entry_cleanup_failed", caught.exception.__notes__)
        self.assertNotIn("policy_entry_cleanup_unverified", caught.exception.__notes__)
        self.assertIsNone(self.operation._quarantine)
        self.assertTrue(self.operation.guard._native_no_entry_confirmed)
        self.assertFalse(self.operation.guard._native_exit_confirmed)
        self.assertTrue(self.operation.guard._nonce_clear_attempted)
        self.assertFalse(self.operation.guard._nonce_clear_confirmed)
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))
        self.assertEqual(self.archives().entries, ())
        owner, cohort, guard = self.operation.owner, self.operation.owner.cohort, self.operation.guard
        self.assertFalse(owner._activated)
        self.assertTrue(self.operation.tick())
        self.assertIs(self.operation.owner, owner)
        self.assertIs(owner.cohort, cohort)
        self.assertIs(self.operation.guard, guard)
        self.assert_finished()

    def test_positive_close_before_binding_does_not_invent_unowned_connection_cleanup(self):
        original_connect = sqlite3.connect
        opened, closed = [], []

        class BeforeBinding(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                if " ".join(sql.split()).lower() == "pragma database_list":
                    raise sqlite3.OperationalError("fixture_before_connection_binding")
                return super().execute(sql, parameters)

            def close(connection):
                result = super().close()
                closed.append(connection)
                return result

        def connect(*args, **kwargs):
            kwargs["factory"] = BeforeBinding
            conn = original_connect(*args, **kwargs)
            opened.append(conn)
            self.raw_connections.append(conn)
            return conn

        with self.operation.scope():
            with patch.object(sqlite3, "connect", side_effect=connect):
                with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_before_connection_binding") as caught:
                    with self.store._connection():
                        self.fail("faulted original connection was yielded")
        self.assertEqual(len(opened), 1)
        self.assertEqual(closed, opened)
        self.assertNotIn("daily_successor_connection_accounting_failed", getattr(caught.exception, "__notes__", ()))
        self.assertFalse(hasattr(caught.exception, "_daily_successor_connection_closed_error"))
        self.assertFalse(hasattr(caught.exception, "_sentinel_connection_cleanup"))
        self.assertIsNone(self.operation._quarantine)
        self.assertTrue(all(settled for _, settled in self.operation._bound_connections.values()))
        self.capture_mock.assert_not_called()
        self.assertTrue(self.operation.tick())
        self.assert_finished()

    def test_clear_commit_ack_loss_reconciles_null_without_second_clear_or_native_hold(self):
        with self.sql_fault("ack_clear") as observed:
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_clear_commit_ack_lost"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        self.assertIsNone(self.fixture.state()[2]["policy_entry_nonce"])
        self.assertFalse(self.operation.owner._activated)
        self.assertTrue(self.operation.guard._nonce_clear_attempted)
        with (patch.object(self.operation.policy.provider, "hold", side_effect=AssertionError("new native POLICY")),
              patch.object(self.operation.policy, "_clear", side_effect=AssertionError("repeated nonce clear"))):
            self.assertTrue(self.operation.tick())
        self.assert_finished()

    def test_transfer_rollback_restores_original_fence_generation_and_absent_archive(self):
        with self.sql_fault("rollback_transfer") as observed:
            with self.assertRaisesRegex(sqlite3.OperationalError, "fixture_transfer_before_generation_write"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        owner, guard = self.operation.owner, self.operation.guard
        self.assertFalse(owner._activated)
        row, frozen, runtime = self.fixture.state()
        self.assertEqual((row, frozen), (self.before_generation, self.before_fence))
        self.assertIn(runtime["policy_entry_nonce"], (None, guard.nonce))
        self.assertEqual(self.archives().entries, ())
        with self.fixture.reader() as conn:
            generation.validate_triggers(conn)
            self.assertEqual(read_retirement(conn), self.before_fence)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?", (history.TABLE,)).fetchone())
        self.assertEqual(self.ordinary_rows(), self.before_rows)
        self.assertEqual(self.exemption_rows(), self.before_exemptions)
        self.assertTrue(self.operation.tick())
        self.assertIs(self.operation.owner, owner)
        self.assertIs(self.operation.guard, guard)
        self.assert_finished()

    def test_original_read_connection_unknown_close_holds_without_reopen_or_remint(self):
        with self.sql_fault("unknown_close_first") as observed:
            with self.assertRaisesRegex(RuntimeError, "fixture_original_sql_close_unknown"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        owner = self.operation.owner
        self.assertFalse(owner._activated)
        self.assertTrue(any(item.close_unknown for item in self.operation._connections))
        self.assertIsNotNone(self.operation._quarantine)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown SQL owner replaced")):
            with self.assertRaisesRegex(successor.DailySuccessorError, "custody_unsettled"):
                self.operation.tick()
        self.assertIs(self.operation.owner, owner)
        self.capture_mock.assert_called_once()
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))

    def test_original_nonce_clear_connection_unknown_close_blocks_activation_and_retry(self):
        with self.sql_fault("unknown_close_clear") as observed:
            with self.assertRaisesRegex(Exception, "cleanup_failed|fixture_original_sql_close_unknown"):
                self.operation.tick()
        self.assertTrue(observed["raised"])
        self.assertFalse(self.operation.owner._activated)
        self.assertIsNotNone(self.operation._quarantine)
        self.assertTrue(any(not closed for _, closed in self.operation._bound_connections.values()))
        self.assertIsNone(self.fixture.state()[2]["policy_entry_nonce"])
        self.assertEqual(len(self.archives().entries), 1)
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown cleanup connection replaced")):
            with self.assertRaisesRegex(successor.DailySuccessorError, "custody_unsettled"):
                self.operation.tick()
        self.capture_mock.assert_called_once()

    def assert_lost_sql_open(self, connection_scope):
        original_connect = sqlite3.connect
        undisclosed = []
        error = RuntimeError("fixture_sql_open_result_lost")

        def fail_after_open(*args, **kwargs):
            conn = original_connect(*args, **kwargs)
            undisclosed.append(conn)
            self.raw_connections.append(conn)
            # The original connect never returns this object or discloses it on
            # the exception. Production can retain only the pending attempt.
            raise error

        with self.operation.scope():
            self.operation._capture_owner()
            with patch.object(sqlite3, "connect", side_effect=fail_after_open):
                with self.assertRaisesRegex(RuntimeError, "fixture_sql_open_result_lost") as caught:
                    with connection_scope():
                        self.fail("unknown connect returned an owned connection")
        self.assertIs(caught.exception, error)
        self.assertIs(error._daily_successor_operation, self.operation)
        self.assertIn("daily_successor_sql_acquisition_unknown", error.__notes__)
        self.assertIs(self.operation._error, error)
        self.assertIsNotNone(self.operation._quarantine)
        self.assertEqual(len(self.operation._connections), 1)
        attempt = self.operation._connections[0]
        self.assertIsNone(attempt.connection)
        self.assertFalse(attempt.closed)
        self.assertEqual(self.operation._connection_pins[id(attempt)], (attempt, None))
        self.assertEqual(len(undisclosed), 1)
        self.assertEqual(undisclosed[0].execute("SELECT 1").fetchone()[0], 1)
        self.assertFalse(self.operation._complete)
        self.assertFalse(self.operation.owner._activated)
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))
        self.assertEqual(self.archives().entries, ())
        with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown open retried")):
            with self.assertRaisesRegex(successor.DailySuccessorError, "custody_unsettled"):
                self.operation.tick()
        self.assertIs(self.operation._connections[0], attempt)
        self.assertIsNone(attempt.connection)
        self.capture_mock.assert_called_once()

    def test_original_operation_sql_open_result_lost_retains_pending_attempt_without_reopen(self):
        self.assert_lost_sql_open(self.operation._connection)

    def test_original_store_sql_open_result_lost_retains_pending_attempt_without_reopen(self):
        self.assert_lost_sql_open(self.store._connection)

    def test_equal_copies_cannot_replace_original_process_cohort_or_candidate(self):
        with self.operation.scope():
            self.operation._capture_owner()
        owner = self.operation.owner
        original_process, original_cohort = owner.process, owner.cohort
        candidate = self.operation._successor_row
        opened, closed = tuple(self.backend.opened), tuple(self.backend.closed)
        for holder, name, original in ((owner, "process", original_process),
                (owner, "cohort", original_cohort), (self.operation, "_successor_row", candidate)):
            replacement = copy.copy(original)
            self.assertIsNot(replacement, original)
            with self.subTest(name=name), patch.object(holder, name, replacement):
                with self.assertRaisesRegex(successor.DailySuccessorError, "original_owner_changed"):
                    self.operation.tick()
        self.assertIs(owner.process, original_process)
        self.assertIs(owner.cohort, original_cohort)
        self.assertIs(self.operation._successor_row, candidate)
        self.assertEqual((tuple(self.backend.opened), tuple(self.backend.closed)), (opened, closed))
        self.assertFalse(owner._activated)
        self.assertEqual(self.fixture.state(), (self.before_generation, self.before_fence, self.before_runtime))
        self.assertTrue(self.operation.tick())
        self.assert_finished()

    def test_prepared_predecessor_connection_cannot_write_successor_generation(self):
        self.operation.tick()
        with self.assertRaises(sqlite3.DatabaseError):
            self.old_connection.execute("UPDATE queue SET heartbeat_at=200 WHERE request_key='unrelated'")
        self.old_connection.rollback()
        self.assert_finished()


if __name__ == "__main__":
    unittest.main()
