"""Approved pre-BEGIN observations with real isolated SQLite transactions.

These portable tests prove the SQL boundary, not a Windows promotion gate.
"""
from contextlib import ExitStack, contextmanager
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch

from sentinel import coordinator, maintainer
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import daily_readiness_transport as transport
from sentinel.adaptive.contracts import IdentityStatus
from sentinel.adaptive.daily_cohort import RetainedCohort
from sentinel.adaptive.identity import VerifiedProcess
from tests import test_adaptive_daily_readiness_lock_boundary as fixtures


class DailyReadinessTransactionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.DailyReadinessLockBoundaryTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()

    @contextmanager
    def no_external_queries(self, conn):
        """Fail at the real writer connection, including SQLite UDF calls."""
        with ExitStack() as stack:
            for target, name in ((generation, "_ledger_identity"),
                    (generation, "_ledger_matches"), (generation, "_fixed_policy_digest"),
                    (generation, "verify_import_provenance"), (Path, "resolve"),
                    (Path, "stat"), (Path, "lstat"), (Path, "open"),
                    (VerifiedProcess, "observe"), (self.fixture.clock, "tick_ms")):
                original = getattr(target, name)
                def checked(*args, _original=original, _name=name, **kwargs):
                    self.assertFalse(conn.in_transaction, "external query in SQL: " + _name)
                    return _original(*args, **kwargs)
                stack.enter_context(patch.object(target, name, checked))
            yield

    @contextmanager
    def local_owner(self):
        f = self.fixture
        process = VerifiedProcess(f.server_backend, 80, f.identity)
        cohort = RetainedCohort(object(), 100, 10, 5)
        cohort._current = VerifiedProcess(f.server_backend, 81, f.identity)
        with patch.object(f.owner, "process", process), patch.object(f.owner, "cohort", cohort), \
                patch.dict(generation._LOCAL_GENERATIONS, {f.owner.generation: f.owner}):
            yield f.owner

    def test_remote_coordinator_maintainer_and_legacy_sql_do_not_probe(self):
        f = self.fixture
        for consumer in (coordinator.Coordinator, maintainer.Maintainer):
            with self.subTest(consumer=consumer.__name__):
                instance = consumer.__new__(consumer)
                instance.db_path = f.db
                with instance._db() as conn:
                    generation.prepare_connection(conn, role="legacy_writer", db_path=f.db)
                    with self.no_external_queries(conn):
                        conn.execute("BEGIN IMMEDIATE")
                        generation.revalidate_transaction(conn, db_path=f.db)
                        conn.execute("INSERT INTO queue VALUES(?)", (consumer.__name__,))
                        conn.execute("UPDATE queue SET request_key=request_key")
                        conn.execute("DELETE FROM queue")
                        conn.commit()

    def test_local_owner_sql_uses_exact_pins_without_native_or_file_probes(self):
        f = self.fixture
        with self.local_owner(), generation.readiness_scope(f.db):
            f.bind(f.conn)
            with self.no_external_queries(f.conn):
                f.conn.execute("BEGIN IMMEDIATE")
                generation.revalidate_transaction(f.conn, db_path=f.db)
                f.conn.execute("INSERT INTO reservations VALUES('local')")
                f.conn.commit()
        self.assertEqual(f.events.count("rpc"), 0)

    def test_absent_generation_uses_original_connection_metadata_in_sql(self):
        f = self.fixture
        isolated = f.isolated_store()
        with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
            with generation.readiness_scope(isolated.db_path), isolated._connection() as conn:
                with self.no_external_queries(conn):
                    conn.execute("BEGIN IMMEDIATE")
                    generation.revalidate_transaction(conn, db_path=isolated.db_path)
                    conn.commit()
                self.assertIsNone(generation.revalidate_scoped_native_readiness(isolated.db_path))

    def test_expired_and_dead_peer_still_allows_only_original_nonce_cleanup(self):
        f = self.fixture
        policy = f.store._policy
        guard = policy.prepare(f.identity.logon_id)
        with generation.readiness_scope(f.db):
            with policy.hold(guard):
                f.clock.now += 1000
                f.server_backend.status = IdentityStatus.DEAD
            self.assertIsNone(f.conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0])

    def test_nonce_clear_trigger_never_rechecks_native_files_or_source(self):
        f = self.fixture
        policy = f.store._policy
        guard = policy.prepare(f.identity.logon_id)
        with generation.readiness_scope(f.db):
            with policy.hold(guard):
                pass
            # The real cleanup above proves settlement. Reinstall its exact
            # fixture nonce solely to exercise the restrictive cleanup trigger.
            f.conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=?", (guard.nonce,))
            f.conn.commit()
            with generation.readiness_nonce_cleanup(policy, guard):
                policy._held.cleanup_guard = guard
                try:
                    with f.store._connection() as conn:
                        with self.no_external_queries(conn):
                            conn.execute("BEGIN IMMEDIATE")
                            generation.revalidate_transaction(conn, db_path=f.db)
                            conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
                            conn.commit()
                        with self.assertRaises(sqlite3.DatabaseError):
                            conn.execute("INSERT INTO queue VALUES('no-capacity')")
                finally:
                    policy._held.cleanup_guard = None

    def test_prepared_guard_without_native_release_cannot_clear_nonce(self):
        f = self.fixture
        policy = f.store._policy
        guard = policy.prepare(f.identity.logon_id)
        with generation.readiness_scope(f.db):
            for exit_fact, no_entry_fact in ((False, False), (True, True), (1, False)):
                with self.subTest(facts=(exit_fact, no_entry_fact)), \
                        patch.object(guard, "_native_exit_confirmed", exit_fact), \
                        patch.object(guard, "_native_no_entry_confirmed", no_entry_fact):
                    with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "cleanup_not_owned"):
                        policy._clear(guard)
                    self.assertEqual(f.conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0],
                        guard.nonce)

    def test_nonce_trigger_rejects_lost_or_changed_release_fact_after_begin(self):
        f = self.fixture
        policy = f.store._policy
        guard = policy.prepare(f.identity.logon_id)
        # A real native timeout is modeled by an explicit positive no-entry
        # fact; never infer it from a missing handle or an elapsed timer.
        guard._native_no_entry_confirmed = True
        with generation.readiness_scope(f.db), generation.readiness_nonce_cleanup(policy, guard):
            policy._held.cleanup_guard = guard
            try:
                with f.store._connection() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    with patch.object(guard, "_native_no_entry_confirmed", False), \
                            self.assertRaises(sqlite3.DatabaseError):
                        conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=NULL")
                    conn.rollback()
                    self.assertEqual(conn.execute("SELECT policy_entry_nonce FROM adaptive_runtime").fetchone()[0],
                        guard.nonce)
            finally:
                policy._held.cleanup_guard = None

    def test_local_native_handle_cohort_or_registry_replacement_rejects_sql(self):
        f = self.fixture
        with self.local_owner() as local, generation.readiness_scope(f.db):
            f.bind(f.conn)
            changes = ((local.process, "_handle", 999), (local.process, "_backend", object()),
                (local.process, "_lock", threading.Lock()), (local.cohort, "_closing", True),
                (local.cohort, "_unresolved", "unknown"), (local, "_closed", True),
                (local, "_readiness_cleanup_error", RuntimeError("unknown")))
            for owner, field, value in changes:
                with self.subTest(field=field), patch.object(owner, field, value):
                    with self.assertRaises(sqlite3.OperationalError):
                        f.conn.execute("INSERT INTO queue VALUES('changed-original')")
                    f.conn.rollback()
            with patch.dict(generation._LOCAL_GENERATIONS, {local.generation: object()}):
                with self.assertRaises(sqlite3.OperationalError):
                    f.conn.execute("INSERT INTO queue VALUES('changed-registry')")
                f.conn.rollback()

    def test_local_cohort_inventory_interval_and_concurrent_reader_are_not_ttl(self):
        f = self.fixture
        with self.local_owner() as local, generation.readiness_scope(f.db):
            f.bind(f.conn)
            # These are unrelated inventory/reader bookkeeping, not authority
            # renewal or a new readiness owner. Only unknown cleanup is poison.
            local.cohort._completed_observations += 1
            local._readiness_readers[123] = object()
            try:
                f.conn.execute("INSERT INTO queue VALUES('same-native-custody')")
                f.conn.commit()
            finally:
                local._readiness_readers.pop(123)

    def test_remote_original_peer_close_or_poison_rejects_in_sql(self):
        f = self.fixture
        with generation.readiness_scope(f.db) as scope:
            f.bind(f.conn)
            for owner, field, value in ((scope.authority._peer, "_handle", None),
                    (scope.authority, "_close_unknown", True),
                    (scope, "error", RuntimeError("unknown"))):
                with self.subTest(field=field), patch.object(owner, field, value):
                    with self.assertRaises(sqlite3.OperationalError):
                        f.conn.execute("INSERT INTO queue VALUES('closed-original')")
                    f.conn.rollback()

    def test_foreign_connection_cannot_borrow_prepared_binding(self):
        f = self.fixture
        with generation.readiness_scope(f.db):
            f.bind(f.conn)
            with sqlite3.connect(f.db) as other:
                other.execute("BEGIN IMMEDIATE")
                with self.assertRaises(sqlite3.OperationalError):
                    generation.revalidate_transaction(other, db_path=f.db)
                other.rollback()

    def test_native_absence_gate_never_adopts_new_generation(self):
        f = self.fixture
        isolated = f.isolated_store()
        with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
            with generation.readiness_scope(isolated.db_path):
                with patch.object(generation, "read_generation", return_value={"generation": "new"}):
                    with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "generation_changed"):
                        generation.revalidate_scoped_native_readiness(isolated.db_path)

    def test_native_absence_unknown_reader_close_retains_original_scope(self):
        f = self.fixture
        isolated = f.isolated_store()
        with self.assertRaisesRegex(RuntimeError, "fixture close unknown") as caught:
            with generation.readiness_scopes((isolated.db_path,), absent_paths=(isolated.db_path,)):
                with generation.readiness_scope(isolated.db_path) as scope:
                    with patch.object(generation._ReadinessReader, "close",
                            side_effect=RuntimeError("fixture close unknown")):
                        generation.revalidate_scoped_native_readiness(isolated.db_path)
        self.assertIs(caught.exception.daily_readiness_scope, scope)
        self.assertIs(scope.error, caught.exception)
        caught.exception.daily_readiness_native_reader.connection.close()


if __name__ == "__main__":
    unittest.main()
