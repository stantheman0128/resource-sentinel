"""Release dispatch seams and real isolated SQL; no native release proof.

The dispatch tests explicitly replace current_operation with a synthetic owner.
Only experiment_cleanup's original operation validator supplies that authority
in production; these tests establish connection routing and close ordering.
"""
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.policy import PolicyBinding, PolicyCoordinator, PolicyGuard
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from tests import test_adaptive_daily_generation as daily_fixture


class OperationFixture:
    def __init__(self):
        self.events = []
        self.guard = PolicyGuard(PolicyBinding("11111111-1111-4111-8111-111111111111",
                                              "S-1-5-5-1-2"),
                                 "22222222-2222-4222-8222-222222222222")
        self.closed = []

    @contextmanager
    def connection_scope(self, path):
        self.events.append(("scope_enter", path))
        try:
            yield self
        finally:
            self.events.append(("scope_exit", path))

    def bind_connection(self, conn, *, role, db_path):
        self.events.append(("bind", conn, role, db_path))

    def revalidate_connection(self, conn, *, db_path):
        if not conn.in_transaction:
            raise AssertionError("release revalidation requires actual transaction")
        self.events.append(("revalidate", conn, db_path))

    def connection_closed(self, conn):
        try:
            conn.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            self.closed.append(conn)
            return
        raise AssertionError("close notification preceded original SQLite close")

    def prepare_policy(self, policy, logon):
        self.events.append(("prepare", policy, logon))
        return self.guard

    @contextmanager
    def nonce_cleanup(self, policy, guard):
        self.events.append(("clear_enter", policy, guard))
        try:
            yield
        finally:
            self.events.append(("clear_exit", policy, guard))


class ExperimentReleaseHookTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "ledger.db"
        self.store = LifecycleStore.__new__(LifecycleStore)
        self.store.db_path = self.path
        self.store._existing_ledger_path = None
        self.store.existing_path = False
        self.operation = OperationFixture()
        selected = patch("sentinel.adaptive.experiment_cleanup.current_operation",
                         return_value=self.operation)
        self.selected = selected.start()
        self.addCleanup(selected.stop)

    def test_release_scope_and_connections_do_not_acquire_capacity_readiness(self):
        with patch.object(generation, "_owned_readiness_scope",
                          side_effect=AssertionError("fresh readiness acquisition")), \
                patch.object(generation, "read_generation",
                             side_effect=AssertionError("ordinary capacity binding")):
            with self.store._connection() as conn:
                with self.assertRaises(sqlite3.OperationalError):
                    conn.execute("SELECT sentinel_daily_generation()")
                conn.execute("BEGIN")
                generation.revalidate_transaction(conn, db_path=self.path)
                conn.rollback()
        self.assertEqual([event[0] for event in self.operation.events],
                         ["scope_enter", "bind", "revalidate", "scope_exit"])
        self.assertEqual(self.operation.closed, [conn])

    def test_policy_prepare_and_nonce_clear_borrow_the_original_operation(self):
        policy = PolicyCoordinator(self.store)
        with patch.object(self.store, "_transaction",
                          side_effect=AssertionError("ordinary POLICY prepare")):
            self.assertIs(policy.prepare("S-1-5-5-1-2"), self.operation.guard)
        with generation.readiness_nonce_cleanup(policy, self.operation.guard):
            self.assertEqual(self.operation.events[-1][0], "clear_enter")
        self.assertEqual(self.operation.events[-1], ("clear_exit", policy, self.operation.guard))

    def test_positive_close_after_body_failure_notifies_same_original_connection(self):
        primary = RuntimeError("fixture body failure")
        with self.assertRaises(RuntimeError) as caught:
            with self.store._connection() as conn:
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.operation.closed, [conn])

    def test_failed_binding_still_accounts_positive_original_close(self):
        primary = RuntimeError("fixture binding failed")
        with patch.object(self.operation, "bind_connection", side_effect=primary) as bind:
            with self.assertRaises(RuntimeError) as caught:
                with self.store._connection():
                    self.fail("failed binding must not yield")
        self.assertIs(caught.exception, primary)
        self.assertEqual(self.operation.closed, [bind.call_args.args[0]])

    def test_close_notification_uses_the_captured_original_operation(self):
        replacement = OperationFixture()
        with self.store._connection() as conn:
            self.selected.return_value = replacement
        self.assertEqual(self.operation.closed, [conn])
        self.assertEqual(replacement.closed, [])

    def test_failed_original_close_never_notifies_settlement_or_retries(self):
        attempts = []
        connect = sqlite3.connect

        class CloseFailure(sqlite3.Connection):
            def close(self):
                attempts.append(self)
                super().close()
                raise RuntimeError("PRIVATE close outcome")

        def open_original(*args, **kwargs):
            return connect(*args, **kwargs, factory=CloseFailure)

        for primary in (None, RuntimeError("fixture body failure")):
            with self.subTest(body_failure=primary is not None), \
                    patch("sentinel.adaptive.store.sqlite3.connect", side_effect=open_original):
                with self.assertRaises((LifecycleError, RuntimeError)) as caught:
                    with self.store._connection() as conn:
                        if primary is not None:
                            raise primary
                if primary is not None:
                    self.assertIs(caught.exception, primary)
                self.assertIs(caught.exception._sentinel_connection_cleanup, conn)
                self.assertEqual(attempts.count(conn), 1)
                self.assertNotIn(conn, self.operation.closed)


class ExperimentReleaseTriggerTests(unittest.TestCase):
    install = daily_fixture.DailyGenerationTests.install

    def setUp(self):
        daily_fixture.DailyGenerationTests.setUp(self)
        self.install()

    def test_dangling_guards_never_become_absent_generation_fallback(self):
        self.conn.execute("DROP TABLE adaptive_daily_generation")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "guards_unverified"):
            generation.read_generation(self.conn)

    def test_canonical_guards_refuse_missing_modified_and_extra_definitions(self):
        generation.validate_triggers(self.conn)
        name = "adaptive_daily_reservations_delete"
        for replacement in (None, "CREATE TRIGGER " + name +
                            " BEFORE DELETE ON reservations BEGIN SELECT 1; END"):
            with self.subTest(replacement=replacement):
                self.conn.execute("DROP TRIGGER " + name)
                if replacement is not None:
                    self.conn.execute(replacement)
                with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "guards_unverified"):
                    generation.read_generation(self.conn)
                if replacement is not None:
                    self.conn.execute("DROP TRIGGER " + name)
                self.conn.execute(generation._trigger_definitions()[name])
        self.conn.execute("CREATE TRIGGER adaptive_daily_extra BEFORE DELETE ON reservations BEGIN SELECT 1; END")
        with self.assertRaisesRegex(generation.DailyGenerationUnavailable, "guards_unverified"):
            generation.validate_triggers(self.conn)

    def test_only_exact_two_delete_triggers_compile_without_capacity_function(self):
        conn = sqlite3.connect(self.db)
        self.addCleanup(conn.close)
        conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
        conn.commit()
        conn.create_function("sentinel_daily_delete_authority", 2, lambda table, key: 1)
        # Empty DELETE still compiles the complete trigger; the capacity UDF is
        # intentionally absent, including when an unrelated branch would deny.
        conn.execute("DELETE FROM reservations WHERE id='fixture'")
        conn.execute("DELETE FROM queue WHERE request_key='fixture'")
        for statement in ("DELETE FROM workers", "DELETE FROM worker_reservations",
                          "INSERT INTO reservations VALUES('fixture')",
                          "UPDATE reservations SET id='fixture'"):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.OperationalError):
                conn.execute(statement)
        conn.rollback()

    def test_normal_delete_authority_rechecks_generation_on_the_actual_write(self):
        conn = sqlite3.connect(self.db)
        self.addCleanup(conn.close)
        with patch.object(generation, "verify_import_provenance", return_value=self.root):
            generation.prepare_connection(conn, role="coordinator", db_path=self.db)
            conn.execute("INSERT INTO reservations VALUES('original')")
            conn.execute("DELETE FROM reservations WHERE id='original'")
            conn.execute("INSERT INTO reservations VALUES('held')")
            conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING'")
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM reservations WHERE id='held'")
            self.assertEqual(conn.execute("SELECT id FROM reservations").fetchall(), [("held",)])
            conn.rollback()

    def test_generation_function_alone_grants_no_delete_authority(self):
        self.conn.create_function("sentinel_daily_generation", 0, lambda: self.owner.generation)
        with self.assertRaises(sqlite3.OperationalError):
            self.conn.execute("DELETE FROM reservations WHERE id='fixture'")


if __name__ == "__main__":
    unittest.main()
