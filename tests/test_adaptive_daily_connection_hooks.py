"""L1 daily connection hooks; isolated ledgers and synthetic native targets only.

These tests are intended for the prepared connection-wiring patches. They do
not activate a daily generation or establish native readiness evidence.
"""
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sentinel import coordinator, maintainer
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import legacy_writer, store
from tests import test_adaptive_legacy_writer as legacy_fixtures


class RecordingConnection:
    """Explicit connection-order/cleanup seam; does not open a database."""

    def __init__(self, events, *, close_error=None):
        self.events = events
        self.close_error = close_error
        self.in_transaction = False
        self.row_factory = None
        self.close_calls = 0

    def execute(self, sql, *arguments):
        self.events.append(sql)
        if sql.startswith("BEGIN"):
            self.in_transaction = True
        return self

    def commit(self):
        self.events.append("COMMIT")
        self.in_transaction = False

    def rollback(self):
        self.events.append("ROLLBACK")
        self.in_transaction = False

    def close(self):
        self.close_calls += 1
        self.events.append("CLOSE")
        if self.close_error is not None:
            raise self.close_error


class DailyConnectionHookTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.db = self.directory / "sentinel.db"

    def bare_store(self, *, pinned=None):
        # Bypass construction only for connection-order tests. The separate
        # absent-generation test constructs all three real isolated providers.
        owner = store.LifecycleStore.__new__(store.LifecycleStore)
        owner.db_path = self.db
        owner.existing_path = pinned is not None
        owner._existing_ledger_path = pinned
        return owner

    def test_lifecycle_readiness_precedes_begin_and_transaction_body(self):
        events = []
        connection = RecordingConnection(events)
        owner = self.bare_store()

        def gate(actual, *, role, db_path):
            self.assertIs(actual, connection)
            self.assertFalse(actual.in_transaction)
            self.assertEqual((role, db_path), ("lifecycle", self.db))
            events.append("READINESS")

        with patch.object(store.sqlite3, "connect", return_value=connection), \
                patch.object(store, "_check_version", return_value=True), \
                patch.object(generation, "prepare_connection", side_effect=gate) as readiness:
            with owner._transaction():
                events.append("BODY")

        readiness.assert_called_once()
        self.assertLess(events.index("READINESS"), events.index("BEGIN IMMEDIATE"))
        self.assertLess(events.index("BEGIN IMMEDIATE"), events.index("BODY"))
        self.assertEqual(events[-2:], ["COMMIT", "CLOSE"])

    def test_absent_generation_preserves_real_isolated_provider_construction(self):
        original = generation.prepare_connection
        with patch.object(generation, "prepare_connection", wraps=original) as readiness, \
                patch.object(generation, "_prove_retained_owner_ready",
                             side_effect=AssertionError("absent generation has no native owner")), \
                patch.object(generation, "verify_import_provenance",
                             side_effect=AssertionError("absent generation has no import authority")):
            coordinator.Coordinator(self.directory, local_host_id="fixture-host",
                                    pid_identity=lambda pid: (None, 0.0))
            maintainer.Maintainer(self.directory, local_host_id="fixture-host")
            owner = store.LifecycleStore(self.db, local_host_id="fixture-host")
            with owner._transaction() as connection:
                self.assertEqual(connection.execute(
                    "SELECT schema_version FROM adaptive_runtime WHERE singleton=1").fetchone()[0], 1)

        self.assertEqual({call.kwargs["role"] for call in readiness.call_args_list},
                         {"coordinator", "maintainer", "lifecycle"})
        with closing(sqlite3.connect(self.db)) as connection:
            self.assertIsNone(generation.read_generation(connection))

    def test_lifecycle_refusal_closes_without_begin_or_yield(self):
        events = []
        connection = RecordingConnection(events)
        failure = generation.DailyGenerationUnavailable("fixture_daily_not_ready")
        with patch.object(store.sqlite3, "connect", return_value=connection), \
                patch.object(generation, "prepare_connection", side_effect=failure), \
                self.assertRaises(generation.DailyGenerationUnavailable) as caught:
            with self.bare_store()._connection():
                self.fail("refused connection was yielded")
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, ["CLOSE"])
        self.assertEqual(connection.close_calls, 1)

    def test_lifecycle_refusal_retains_primary_when_cleanup_is_uncertain(self):
        events = []
        connection = RecordingConnection(events, close_error=RuntimeError("fixture close uncertain"))
        failure = generation.DailyGenerationUnavailable("fixture_daily_not_ready")
        with patch.object(store.sqlite3, "connect", return_value=connection), \
                patch.object(generation, "prepare_connection", side_effect=failure), \
                self.assertRaises(generation.DailyGenerationUnavailable) as caught:
            with self.bare_store()._connection():
                self.fail("refused connection was yielded")
        self.assertIs(caught.exception, failure)
        self.assertIn("lifecycle_connection_cleanup_failed", failure.__notes__)
        self.assertEqual(events, ["CLOSE"])

    def test_explicit_existing_path_is_the_readiness_target(self):
        events = []
        connection = RecordingConnection(events)
        pinned = (self.directory / "pinned-existing.db").resolve()
        owner = self.bare_store()
        with patch.object(store.sqlite3, "connect", return_value=connection) as connect, \
                patch.object(generation, "prepare_connection") as readiness:
            with owner._connection(existing_path=pinned):
                pass
        readiness.assert_called_once_with(connection, role="lifecycle", db_path=pinned)
        self.assertEqual(connect.call_args.args[0], pinned.as_uri() + "?mode=rw")
        self.assertTrue(connect.call_args.kwargs["uri"])
        self.assertEqual(connection.close_calls, 1)

    def test_capacity_entrypoints_check_readiness_before_schema_or_pragmas(self):
        for module, cls, role in ((coordinator, coordinator.Coordinator, "coordinator"),
                                  (maintainer, maintainer.Maintainer, "maintainer")):
            with self.subTest(role=role):
                events = []
                connection = RecordingConnection(events)
                owner = cls.__new__(cls)
                owner.db_path = self.db

                def gate(actual, *, role, db_path):
                    self.assertIs(actual, connection)
                    self.assertFalse(actual.in_transaction)
                    self.assertEqual(db_path, self.db)
                    events.append(("READINESS", role))

                with patch.object(module.sqlite3, "connect", return_value=connection), \
                        patch.object(module, "check_schema_version",
                                     side_effect=lambda conn: events.append("SCHEMA")), \
                        patch.object(generation, "prepare_connection", side_effect=gate) as readiness:
                    self.assertIs(owner._connect(), connection)
                readiness.assert_called_once_with(connection, role=role, db_path=self.db)
                self.assertEqual(events[:2], [("READINESS", role), "SCHEMA"])
                self.assertTrue(any(isinstance(event, str) and event.startswith("PRAGMA")
                                    for event in events[2:]))
                connection.close()

    def test_capacity_entrypoint_refusal_closes_before_schema_or_pragmas(self):
        for module, cls, role in ((coordinator, coordinator.Coordinator, "coordinator"),
                                  (maintainer, maintainer.Maintainer, "maintainer")):
            with self.subTest(role=role):
                events = []
                connection = RecordingConnection(events)
                owner = cls.__new__(cls)
                owner.db_path = self.db
                failure = generation.DailyGenerationUnavailable("fixture_daily_not_ready")
                with patch.object(module.sqlite3, "connect", return_value=connection), \
                        patch.object(module, "check_schema_version") as schema, \
                        patch.object(generation, "prepare_connection", side_effect=failure), \
                        self.assertRaises(generation.DailyGenerationUnavailable) as caught:
                    owner._connect()
                self.assertIs(caught.exception, failure)
                schema.assert_not_called()
                self.assertEqual(events, ["CLOSE"])


    def test_maintainer_readiness_error_retains_uncertain_connection_cleanup(self):
        connection = RecordingConnection([], close_error=RuntimeError("fixture close uncertain"))
        owner = maintainer.Maintainer.__new__(maintainer.Maintainer)
        owner.db_path = self.db
        failure = generation.DailyGenerationUnavailable("fixture_daily_not_ready")
        with patch.object(maintainer.sqlite3, "connect", return_value=connection), \
                patch.object(generation, "prepare_connection", side_effect=failure), \
                self.assertRaises(generation.DailyGenerationUnavailable) as caught:
            owner._connect()
        self.assertIs(caught.exception, failure)
        self.assertIs(failure._sentinel_connection_cleanup, connection)
        self.assertIn("maintainer_connection_cleanup_failed", failure.__notes__)


class LegacyDailyConnectionHookTests(unittest.TestCase):
    # Reuse explicit fixture helpers without inheriting the other test cases.
    setUp = legacy_fixtures.LegacyWriterTests.setUp
    connection = legacy_fixtures.LegacyWriterTests.connection
    spec = legacy_fixtures.LegacyWriterTests.spec
    allocate = legacy_fixtures.LegacyWriterTests.allocate
    registered = legacy_fixtures.LegacyWriterTests.registered
    held = legacy_fixtures.LegacyWriterTests.held
    assert_native_scope = legacy_fixtures.LegacyWriterTests.assert_native_scope
    runtime = legacy_fixtures.LegacyWriterTests.runtime
    identity = legacy_fixtures.LegacyWriterTests.identity
    candidate = legacy_fixtures.LegacyWriterTests.candidate
    target = legacy_fixtures.LegacyWriterTests.target
    process_factory = legacy_fixtures.LegacyWriterTests.process_factory
    job_factory = legacy_fixtures.LegacyWriterTests.job_factory
    execute = legacy_fixtures.LegacyWriterTests.execute

    def test_lifecycle_cleanup_allowance_cannot_authorize_legacy_setters(self):
        target = self.target()
        roles = []

        def gate(connection, *, role, db_path):
            self.assertFalse(connection.in_transaction)
            self.assertEqual(Path(db_path), self.db)
            roles.append(role)
            # Explicit seam for the pending lifecycle-only allowance. Actual
            # owner/authorizer behavior is covered by daily-generation tests.
            if role == "legacy_writer":
                raise generation.DailyGenerationUnavailable("fixture_install_unacknowledged")

        with patch.object(generation, "prepare_connection", side_effect=gate):
            result = self.execute([self.candidate()])
        self.assertIn("lifecycle", roles)
        self.assertEqual(roles.count("legacy_writer"), 1)
        self.assertFalse(result["available"])
        self.assertEqual(result["reason"], "legacy_registry_or_grants_unavailable")
        self.assertEqual(self.writes, [])
        self.assertEqual(self.job_opens, [])
        self.assertTrue(target.closed)
        self.assertFalse(self.policy.active)

    def test_legacy_readiness_cleanup_uncertainty_is_not_a_safe_skip(self):
        target = self.target()
        failure = generation.DailyGenerationUnavailable("fixture_readiness_cleanup_unknown")
        failure.add_note("fixture native readiness cleanup unverified")

        def gate(connection, *, role, db_path):
            self.assertFalse(connection.in_transaction)
            if role == "legacy_writer":
                raise failure

        with patch.object(generation, "prepare_connection", side_effect=gate), \
                self.assertRaises(generation.DailyGenerationUnavailable) as caught:
            self.execute([self.candidate()])
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.writes, [])
        self.assertEqual(self.job_opens, [])
        self.assertTrue(target.closed)
        self.assertFalse(self.policy.active)

    def test_readiness_time_consumes_the_original_legacy_batch_deadline(self):
        target = self.target()
        original = generation.prepare_connection
        start = self.clock.value
        legacy_calls = []

        def gate(connection, *, role, db_path):
            self.assertFalse(connection.in_transaction)
            if role == "legacy_writer":
                legacy_calls.append(role)
                self.clock.value += legacy_writer.BATCH_SECONDS + .01
            return original(connection, role=role, db_path=db_path)

        with patch.object(generation, "prepare_connection", side_effect=gate):
            result = self.execute([self.candidate()])
        self.assertEqual(legacy_calls, ["legacy_writer"])
        self.assertGreater(self.clock.value - start, legacy_writer.BATCH_SECONDS)
        self.assertEqual(self.writes, [])
        if result["available"]:
            self.assertEqual(result["results"][0]["reason"], "legacy_batch_budget_exhausted")
        else:
            self.assertEqual(result["reason"], "legacy_registry_or_grants_unavailable")
        self.assertTrue(target.closed)

    def test_absent_generation_keeps_existing_synthetic_legacy_mutations(self):
        target = self.target()
        candidate = self.candidate()
        original = generation.prepare_connection
        with patch.object(generation, "prepare_connection", wraps=original) as readiness:
            result = self.execute([candidate])
        self.assertTrue(result["available"])
        self.assertIn("legacy_writer", [call.kwargs["role"] for call in readiness.call_args_list])
        self.assertEqual(self.writes, [(candidate.identity, "priority", "BelowNormal"),
                                      (candidate.identity, "io", 1),
                                      (candidate.identity, "trim", True)])
        self.assertTrue(target.closed)


if __name__ == "__main__":
    unittest.main()
