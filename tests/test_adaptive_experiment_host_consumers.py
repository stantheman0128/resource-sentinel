"""Real isolated legacy/release consumers of the aggregate host ledger.

Admission, SQL, immutable partitions and cleanup operations are production code.
Only process/Job/readiness collaborators are synthetic. No real process is
opened, modified, killed, trimmed or controlled; these are not native gates.
"""
from contextlib import closing
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive import experiment_host_ledger as host
from sentinel.adaptive import experiment_history as history
from sentinel.adaptive import legacy_writer as writer
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.exemption_sync import bind_policy_locked
from sentinel.adaptive.identity import VerifiedProcess
from tests import test_adaptive_experiment_host_ledger as host_fixtures
from tests import test_adaptive_legacy_writer as legacy_fixtures
from tests import test_adaptive_managed_admission as managed_fixtures
from tests.test_adaptive_admission_context import IDENTITY
from tests.test_adaptive_identity import Backend


class ExperimentHostConsumerTests(unittest.TestCase):
    def setUp(self):
        self.backend = Backend()
        self.backend.value = IDENTITY
        self.process = VerifiedProcess(self.backend, 701, IDENTITY)
        self.addCleanup(self.process.close)
        self.fixture = host_fixtures.ExperimentHostLedgerTests()
        self.addCleanup(self.fixture.doCleanups)
        with patch.object(managed_fixtures, "FakeCurrentProcess", return_value=self.process):
            self.fixture.setUp()
        self.demand = self.fixture.owner
        self.db = self.demand.ledger_path

    def legacy(self):
        # Keep the actual same daily ledger and POLICY, not LegacyWriterTests'
        # unrelated setup database. Native targets remain explicit fault models.
        fixture = legacy_fixtures.LegacyWriterTests()
        self.addCleanup(fixture.doCleanups)
        fixture.directory, fixture.db, fixture.store = self.db.parent, self.db, self.fixture.store
        fixture.policy = self.fixture.fixture.fixture.policy
        fixture.exemptions = SimpleNamespace(path=self.db.with_name("exemptions.sqlite3"))
        fixture.clock = legacy_fixtures.SyntheticClock()
        fixture.targets, fixture.jobs = {}, {}
        fixture.writes, fixture.opens, fixture.job_opens = [], [], []
        with self.fixture.locked() as (conn, guard):
            conn.rollback()
            writer.initialize_registry_locked(fixture.store)
            bind_policy_locked(fixture.exemptions, fixture.store)

        def job_factory(name, logon):
            fixture.assert_native_scope()
            self.assertEqual(logon, self.fixture.logon)
            fixture.job_opens.append(name)
            job = legacy_fixtures.SyntheticJob(fixture, name)
            fixture.jobs[name] = job
            return job

        fixture.job_factory = job_factory
        return fixture

    def identity(self, offset=0):
        return ProcessIdentity(20000 + offset, IDENTITY.created_filetime_100ns + 20000 + offset,
                               self.fixture.logon)

    def test_absent_host_registry_preserves_existing_unmanaged_batch(self):
        fixture, identity = self.legacy(), self.identity()
        fixture.target(identity)
        result = fixture.execute([fixture.candidate(identity=identity)])
        self.assertTrue(result["available"], result)
        self.assertEqual(result["results"][0]["status"], "applied")
        self.assertTrue(fixture.writes)
        self.assertIsNone(self.fixture.connection().execute(
            "SELECT 1 FROM sqlite_master WHERE name=?", (host.SCOPES_TABLE,)).fetchone())

    def test_actor_and_both_job_kinds_are_excluded_from_every_legacy_setter(self):
        _, actor = self.fixture.actor(role="helper")
        managed = self.fixture.job()
        query = self.fixture.job(kind="query_only")
        fixture = self.legacy()
        identities = (actor, self.identity(), self.identity(1))
        for action, io_priority in (("demote", 1), ("restore", 2)):
            with self.subTest(action=action):
                fixture.target(actor, priority="BelowNormal")
                for identity, binding in zip(identities[1:], (managed, query)):
                    fixture.target(identity, priority="BelowNormal", member={binding.job_name: True})
                result = fixture.execute([fixture.candidate(identity=identity, action=action,
                    io_priority=io_priority) for identity in identities])
                self.assertTrue(result["available"], result)
                self.assertEqual([item["reason"] for item in result["results"]],
                                 ["legacy_managed_scope"] * 3)
                self.assertEqual(fixture.writes, [])
                self.assertTrue(all(item.closed for item in fixture.targets.values()))
                self.assertTrue(all(item.closed for item in fixture.jobs.values()))

    def test_reserved_but_unpublished_native_attempt_refuses_the_whole_batch(self):
        self.fixture.reserve(role="supervisor")
        fixture, identity = self.legacy(), self.identity()
        fixture.target(identity)
        result = fixture.execute([fixture.candidate(identity=identity)])
        self.assertFalse(result["available"], result)
        self.assertEqual(result["reason"], "legacy_registry_or_grants_unavailable")
        self.assertEqual(fixture.writes, [])
        self.assertEqual(fixture.job_opens, [])
        self.assertTrue(fixture.targets[identity.pid].closed)
        self.fixture.fixture.assert_retained(self.demand)

    def test_real_batch_materializes_shared_experiment_history_once(self):
        _, identity = self.fixture.actor(role="supervisor")
        fixture = self.legacy()
        fixture.target(identity)
        with patch.object(history, "verify_experiment_history_locked",
                          wraps=history.verify_experiment_history_locked) as reader:
            result = fixture.execute([fixture.candidate(identity=identity)])
        self.assertTrue(result["available"], result)
        self.assertEqual(result["results"][0]["reason"], "legacy_managed_scope")
        self.assertEqual(reader.call_count, 1)
        self.assertEqual(fixture.writes, [])

    def test_unknown_query_job_open_prevents_all_setters(self):
        self.fixture.job(kind="query_only")
        fixture, identity = self.legacy(), self.identity()
        fixture.target(identity)
        def unavailable(name, logon):
            raise OSError("synthetic query-only Job is inaccessible")
        result = fixture.execute([fixture.candidate(identity=identity)], job_factory=unavailable)
        self.assertFalse(result["available"], result)
        self.assertEqual(fixture.writes, [])
        self.fixture.fixture.assert_retained(self.demand)

    def test_query_inventory_cannot_extend_original_batch_deadline(self):
        query_owner, _ = self.fixture.actor(role="query_owner")
        for unused in range(40):
            self.fixture.job(kind="query_only", guardian=query_owner)
        fixture, identity = self.legacy(), self.identity()
        fixture.target(identity)
        original_factory = fixture.job_factory
        def delayed(name, logon):
            value = original_factory(name, logon)
            fixture.clock.value += .03
            return value
        result = fixture.execute([fixture.candidate(identity=identity)], job_factory=delayed)
        self.assertFalse(result["available"], result)
        self.assertGreater(len(fixture.job_opens), 0)
        self.assertLess(len(fixture.job_opens), 40)
        self.assertEqual(fixture.writes, [])
        self.assertTrue(all(item.closed for item in fixture.jobs.values()))

    def prepare_release(self):
        # Install the same complete synthetic generation record used at real
        # admission; cleanup runs its actual source-bound generation checks.
        with closing(sqlite3.connect(self.db)) as conn:
            row = self.fixture.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                         ",".join("?" for unused in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for override in (
                patch.object(generation, "_assert_daily_locations"),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "_prove_retained_owner_ready",
                    side_effect=AssertionError("cleanup requested fresh readiness"))):
            override.start()
            self.addCleanup(override.stop)
        completion = self.demand.seal_without_native()
        operation = self.demand.prepare_release(completion)
        self.addCleanup(lambda: cleanup._OPERATIONS.pop(operation.operation_id, None))
        return operation

    def test_actual_before_native_release_cannot_discharge_registered_host_scope(self):
        self.fixture.actor(role="supervisor")
        before = self.fixture.fixture.assert_retained(self.demand)
        host_before = {table: self.fixture.rows(table) for table in host.TABLES}
        operation = self.prepare_release()
        for attempt in range(2):
            with self.subTest(attempt=attempt), self.assertRaisesRegex(
                    cleanup.ExperimentReleaseError, "host_scope_cleanup_unverified"):
                self.fixture.fixture.coordinator.release_experiment(operation)
            self.assertEqual(self.fixture.fixture.assert_retained(self.demand), before)
            self.assertEqual({table: self.fixture.rows(table) for table in host.TABLES}, host_before)
            self.assertFalse(operation._completed)
            self.assertFalse(self.demand._closed)
            self.assertIsNotNone(self.process._handle)
            self.assertEqual(self.backend.closed, [])

    def test_actual_before_native_release_still_works_without_a_host_scope(self):
        operation = self.prepare_release()
        result = self.fixture.fixture.coordinator.release_experiment(operation)
        self.assertIs(result["released"], True)
        self.assertEqual(result["disposition"], "BEFORE_NATIVE")
        self.assertEqual(self.fixture.rows("reservations"), [])
        self.assertTrue(self.demand._closed)
        self.assertEqual(self.backend.closed, [701])


if __name__ == "__main__":
    unittest.main()
