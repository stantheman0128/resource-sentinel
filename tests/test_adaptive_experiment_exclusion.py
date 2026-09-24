"""Portable experiment-exclusion contracts; these are not native gate evidence.

The demand fixture supplies explicit synthetic generation/current-process proof.
Admission, reservations, POLICY ownership, registry SQL and legacy writer flow
remain production implementations on the same isolated temporary daily ledger.
No test opens, creates, controls or closes a real Windows process or Job.
"""
from contextlib import contextmanager
from dataclasses import replace
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import experiment_demand as demand
from sentinel.adaptive import experiment_exclusion as exclusion
from sentinel.adaptive import legacy_writer as writer
from sentinel.adaptive.contracts import ProcessIdentity, ResourceDemand
from sentinel.adaptive.exemption_sync import bind_policy_locked
from sentinel.adaptive.policy import PolicyError
from sentinel.adaptive.store import LifecycleStore, hold_expired_allocations
from tests import test_adaptive_experiment_demand as demand_fixtures
from tests import test_adaptive_legacy_writer as legacy_fixtures


class ExperimentExclusionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = demand_fixtures.ExperimentDemandTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        proof = patch.object(exclusion, "daily_generation", self.fixture.proof)
        proof.start()
        self.addCleanup(proof.stop)
        self.owner = self.fixture.capture()
        self.admitted = self.fixture.coordinator.admit_experiment(self.owner)
        self.assertTrue(self.admitted["allowed"])
        self.db = self.fixture.coordinator.db_path
        metadata = self.fixture.rows(demand.TABLE)[0]
        self.fixture.generation.update(ledger_path=str(self.db), ledger_identity_json=json.dumps(
            [str(value) for value in json.loads(metadata["ledger_identity_json"])]))
        self.store = LifecycleStore(self.db, policy_provider=self.fixture.fixture.policy)
        self.policy = self.store._policy
        self.guardian = self.owner._snapshot.wrapper_identity
        self.wrapper = ProcessIdentity(self.guardian.pid + 100, self.guardian.created_filetime_100ns + 1,
                                       self.guardian.logon_id)
        self.isolated_ledger = self.fixture.scope / "sentinel.db"
        self.isolated_ledger.touch()
        nonce = uuid4().hex
        self.binding = exclusion.ExperimentExclusionBinding(
            experiment_id=self.owner.declaration.experiment_id,
            daily_execution_id=self.admitted["execution_id"],
            reservation_id=self.admitted["reservation_id"],
            source_generation=self.fixture.generation["generation"],
            scope_execution_id=str(uuid4()), isolated_ledger_path=str(self.isolated_ledger),
            isolated_ledger_identity=(1, 2), isolated_policy_instance_id=str(uuid4()),
            job_name="Local\\ResourceSentinel.Test.Job." + nonce, creation_nonce=nonce,
            logon_id=self.guardian.logon_id, guardian_identity=self.guardian,
            wrapper_identity=self.wrapper)

    def connection(self):
        return self.fixture.fixture.conn()

    @contextmanager
    def locked(self):
        guard = self.policy.prepare(self.guardian.logon_id)
        primary = None
        with self.policy.hold(guard):
            conn = self.connection()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn, guard
            except BaseException as error:
                # A synchronous SQL refusal is rolled back before leaving the
                # synthetic POLICY scope; it is not a native uncertainty test.
                primary = error
            finally:
                if conn.in_transaction:
                    conn.rollback()
        if primary is not None:
            raise primary

    def register(self, binding=None):
        with self.locked() as (conn, guard):
            result = exclusion.register_locked(conn, binding or self.binding,
                                               policy=self.policy, guard=guard)
            conn.commit()
            return result

    def inventory(self):
        with self.locked() as (conn, guard):
            return exclusion.read_locked(conn, policy=self.policy, guard=guard)

    def revision(self):
        return self.connection().execute(
            "SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0]

    def rows(self):
        return [dict(row) for row in self.connection().execute("SELECT * FROM " + exclusion.TABLE)]

    def corrupt(self, table, sql, parameters=()):
        """Explicit corruption fixture; restore guards instead of weakening APIs."""
        conn = self.connection()
        triggers = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
                                (table,)).fetchall()
        for trigger in triggers:
            conn.execute('DROP TRIGGER "' + trigger["name"].replace('"', '""') + '"')
        try:
            conn.execute(sql, parameters)
        finally:
            for trigger in triggers:
                conn.execute(trigger["sql"])

    @contextmanager
    def reject_payload_materialization(self, payload):
        """Observe the real SQLite row boundary without replacing registry SQL."""
        open_connection = self.connection

        def guarded_connection():
            conn = open_connection()

            def row_factory(cursor, row):
                if any(isinstance(value, (str, bytes)) and value == payload for value in row):
                    raise AssertionError("corrupt_payload_reached_python_before_domain_refusal")
                return sqlite3.Row(cursor, row)

            conn.row_factory = row_factory
            return conn

        with patch.object(self, "connection", side_effect=guarded_connection):
            yield

    def test_genuinely_absent_registry_is_empty_without_creating_schema(self):
        with self.locked() as (conn, guard):
            self.assertFalse(exclusion.validate_schema_locked(conn))
            inventory = exclusion.read_locked(conn, policy=self.policy, guard=guard)
            self.assertEqual(inventory.bindings, ())
            self.assertEqual(inventory.identities, frozenset())
            self.assertEqual(inventory.job_names, ())
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                          (exclusion.TABLE,)).fetchone())

    def test_available_precreation_check_is_readonly_with_absent_schema(self):
        before = self.revision()
        with self.locked() as (conn, guard):
            exclusion.assert_available_locked(conn, policy=self.policy, guard=guard)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                          (exclusion.TABLE,)).fetchone())
            self.assertEqual(conn.execute(
                "SELECT registry_revision FROM adaptive_runtime WHERE singleton=1").fetchone()[0], before)
        self.assertEqual(self.revision(), before)
        self.fixture.assert_retained(self.owner)

    def test_available_precreation_check_refuses_an_existing_scope(self):
        self.register()
        before, revision = self.rows(), self.revision()
        with self.locked() as (conn, guard):
            with self.assertRaises(exclusion.ExperimentExclusionError):
                exclusion.assert_available_locked(conn, policy=self.policy, guard=guard)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.revision(), revision)

    def test_register_publishes_exact_binding_and_advances_revision_once(self):
        before = self.revision()
        row = self.register()
        self.assertEqual(dict(row), self.rows()[0])
        self.assertEqual(self.revision(), before + 1)
        inventory = self.inventory()
        self.assertEqual(inventory.bindings, (self.binding,))
        self.assertEqual(inventory.job_names, (self.binding.job_name,))
        self.assertEqual(inventory.identities, frozenset((self.guardian, self.wrapper)))
        self.fixture.assert_retained(self.owner)

    def test_exact_replay_preserves_row_and_revision(self):
        original = self.register()
        before = self.revision()
        self.assertEqual(self.register(), original)
        self.assertEqual(self.rows(), [dict(original)])
        self.assertEqual(self.revision(), before)

    def test_real_policy_and_exact_current_guard_are_required(self):
        with self.locked() as (conn, guard):
            with self.assertRaises((exclusion.ExperimentExclusionError, PolicyError, TypeError)):
                exclusion.register_locked(conn, self.binding, policy=Mock(), guard=guard)
            with self.assertRaises((exclusion.ExperimentExclusionError, PolicyError)):
                exclusion.register_locked(conn, self.binding, policy=self.policy,
                                          guard=replace(guard, nonce=str(uuid4())))

    def test_an_unheld_guard_cannot_register_or_read(self):
        with self.locked() as (conn, guard):
            pass
        conn = self.connection()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for operation in (
                lambda: exclusion.register_locked(conn, self.binding, policy=self.policy, guard=guard),
                lambda: exclusion.read_locked(conn, policy=self.policy, guard=guard),
            ):
                with self.subTest(operation=operation), self.assertRaises(
                        (exclusion.ExperimentExclusionError, PolicyError)):
                    operation()
        finally:
            conn.rollback()

    def test_held_policy_without_sql_transaction_is_insufficient(self):
        guard = self.policy.prepare(self.guardian.logon_id)
        with self.policy.hold(guard):
            conn = self.connection()
            for operation in (
                lambda: exclusion.register_locked(conn, self.binding, policy=self.policy, guard=guard),
                lambda: exclusion.read_locked(conn, policy=self.policy, guard=guard),
                lambda: exclusion.validate_schema_locked(conn),
            ):
                with self.subTest(operation=operation), self.assertRaises(exclusion.ExperimentExclusionError):
                    operation()

    def test_missing_demand_metadata_never_becomes_an_empty_inventory(self):
        self.register()
        self.corrupt(demand.TABLE, "DELETE FROM " + demand.TABLE)
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()
        self.assertEqual(len(self.rows()), 1)

    def test_tampered_demand_binding_is_rejected(self):
        self.register()
        self.corrupt(demand.TABLE, "UPDATE " + demand.TABLE + " SET binding_sha256=?", ("0" * 64,))
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()

    def test_embedded_nul_exclusion_text_is_rejected_before_payload_materialization(self):
        original = self.register()
        revision = self.revision()
        for column in ("job_name", "guardian_identity_json"):
            with self.subTest(column=column):
                payload = original[column] + "\x00" + "x" * 8192
                self.corrupt(exclusion.TABLE, "UPDATE " + exclusion.TABLE + " SET " + column + "=?", (payload,))
                damaged = self.rows()
                with self.reject_payload_materialization(payload):
                    with self.assertRaises(exclusion.ExperimentExclusionError):
                        self.inventory()
                self.assertEqual(self.rows(), damaged)
                self.assertEqual(self.revision(), revision)
                self.fixture.assert_retained(self.owner)
                self.corrupt(exclusion.TABLE, "UPDATE " + exclusion.TABLE + " SET " + column + "=?",
                             (original[column],))

    def test_metadata_owner_pid_text_or_blob_is_rejected_before_registration_fetch(self):
        revision = self.revision()
        for payload in ("invalid\x00" + "x" * 8192, b"invalid\x00" + b"x" * 8192):
            with self.subTest(storage_type=type(payload).__name__):
                self.corrupt(demand.TABLE, "UPDATE " + demand.TABLE + " SET owner_pid=?", (payload,))
                metadata = self.fixture.rows(demand.TABLE)
                with self.reject_payload_materialization(payload):
                    with self.assertRaises(exclusion.ExperimentExclusionError):
                        self.register()
                self.assertIsNone(self.connection().execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                                           (exclusion.TABLE,)).fetchone())
                self.assertEqual(self.fixture.rows(demand.TABLE), metadata)
                self.assertEqual(self.revision(), revision)
                self.assertEqual(self.fixture.fixture.counts()[1:], (1, 1))

    def test_metadata_owner_pid_text_or_blob_is_rejected_before_registered_read_fetch(self):
        self.register()
        original, revision = self.rows(), self.revision()
        for payload in ("invalid\x00" + "x" * 8192, b"invalid\x00" + b"x" * 8192):
            with self.subTest(storage_type=type(payload).__name__):
                self.corrupt(demand.TABLE, "UPDATE " + demand.TABLE + " SET owner_pid=?", (payload,))
                metadata = self.fixture.rows(demand.TABLE)
                with self.reject_payload_materialization(payload):
                    with self.assertRaises(exclusion.ExperimentExclusionError):
                        self.inventory()
                self.assertEqual(self.rows(), original)
                self.assertEqual(self.fixture.rows(demand.TABLE), metadata)
                self.assertEqual(self.revision(), revision)
                self.assertEqual(self.fixture.fixture.counts()[1:], (1, 1))

    def test_reduced_managed_floor_is_rejected_without_releasing_reservation(self):
        self.register()
        self.corrupt("managed_executions", "UPDATE managed_executions SET floor_commit_bytes=0 WHERE execution_id=?",
                     (self.binding.daily_execution_id,))
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()
        self.assertEqual(len(self.fixture.rows("reservations")), 1)

    def test_reduced_reservation_demand_is_rejected(self):
        self.register()
        self.corrupt("reservations", "UPDATE reservations SET commit_bytes=0 WHERE id=?",
                     (self.binding.reservation_id,))
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()

    def test_foreign_generation_cannot_register_or_read_existing_scope(self):
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.register(replace(self.binding, source_generation=str(uuid4())))
        self.register()
        self.fixture.generation["generation"] = str(uuid4())
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()

    def test_missing_or_ineffective_guard_is_not_repaired(self):
        self.register()
        conn = self.connection()
        name = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=? LIMIT 1",
                            (exclusion.TABLE,)).fetchone()[0]
        conn.execute('DROP TRIGGER "' + name + '"')
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()
        conn.execute('CREATE TRIGGER "' + name + '" BEFORE UPDATE ON ' + exclusion.TABLE +
                     " BEGIN SELECT 1; END")
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()
        self.assertEqual(len(self.rows()), 1)

    def test_unknown_empty_table_definition_is_rejected(self):
        conn = self.connection()
        conn.execute("CREATE TABLE " + exclusion.TABLE + "(unexpected TEXT)")
        with self.locked() as (conn, guard):
            with self.assertRaises(exclusion.ExperimentExclusionError):
                exclusion.validate_schema_locked(conn)
            with self.assertRaises(exclusion.ExperimentExclusionError):
                exclusion.read_locked(conn, policy=self.policy, guard=guard)

    def test_registered_row_cannot_be_updated_deleted_or_replaced(self):
        self.register()
        before = self.rows()
        conn = self.connection()
        for sql in (
            "UPDATE " + exclusion.TABLE + " SET phase=phase",
            "DELETE FROM " + exclusion.TABLE,
            "INSERT OR REPLACE INTO " + exclusion.TABLE + " SELECT * FROM " + exclusion.TABLE,
        ):
            # Preserve the old raw connection: absent fixed mutation functions
            # must refuse just as a resolved guard's RAISE refuses.
            with self.subTest(sql=sql), self.assertRaises(sqlite3.DatabaseError):
                conn.execute(sql)
            self.assertEqual(self.rows(), before)

    def test_reserved_nonregistered_states_are_unknown_not_empty(self):
        self.register()
        for state in ("CREATED", "CLOSED"):
            with self.subTest(state=state):
                self.corrupt(exclusion.TABLE, "UPDATE " + exclusion.TABLE + " SET phase=?,cleanup_digest=?",
                             (state, "0" * 64 if state == "CLOSED" else None))
                with self.assertRaises(exclusion.ExperimentExclusionError):
                    self.inventory()

    def test_expired_daily_hold_keeps_exact_exclusion_and_full_demand(self):
        self.register()
        allocation = self.fixture.rows("reservations")[0]
        with self.locked() as (conn, guard):
            # Ordinary consumers install this fixed denial; it permits only
            # compilation of the unchanged RESERVED -> HOLD expiry branch.
            conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
            self.assertEqual(hold_expired_allocations(conn, "direct", allocation["expires_at"] + 1), 1)
            conn.commit()
        self.assertEqual(self.fixture.rows("managed_executions")[0]["state"], "UNCERTAIN_HOLD")
        self.assertEqual(self.inventory().bindings, (self.binding,))
        self.assertEqual(self.fixture.rows("reservations")[0], allocation)
        self.fixture.assert_retained(self.owner)

    def test_second_scope_cannot_overwrite_first_or_change_registry_revision(self):
        self.register()
        before, revision = self.rows(), self.revision()
        nonce = uuid4().hex
        other = replace(self.binding, scope_execution_id=str(uuid4()), creation_nonce=nonce,
                        job_name="Local\\ResourceSentinel.Test.Job." + nonce)
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.register(other)
        self.assertEqual(self.rows(), before)
        self.assertEqual(self.revision(), revision)

    def _production_job(self):
        """Real admission plus explicitly synthetic named-Job registry metadata."""
        fixture = self.fixture.fixture
        context = fixture.context(requested=ResourceDemand(.1, 128 * 1024**2, 128 * 1024**2, 0))
        result = fixture.admit(context)
        self.assertTrue(result["allowed"])
        nonce = uuid4().hex
        name = "Local\\ResourceSentinel.Job." + result["execution_id"] + "." + nonce
        conn = self.connection()
        # This synthetic production-row setup has no experiment release right.
        conn.create_function("sentinel_experiment_release_mutation", 4, lambda *args: 0)
        conn.execute("UPDATE managed_executions SET state='RUNNING',job_name=?,job_nonce=? WHERE execution_id=?",
                     (name, nonce, result["execution_id"]))
        return name

    def test_combined_job_limit_allows_ten_and_rejects_eleventh_on_read(self):
        for _ in range(9):
            self._production_job()
        self.register()
        self.assertEqual(self.inventory().job_names, (self.binding.job_name,))
        self._production_job()
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.inventory()

    def test_ten_production_jobs_leave_no_registration_slot(self):
        for _ in range(10):
            self._production_job()
        before = self.revision()
        with self.assertRaises(exclusion.ExperimentExclusionError):
            self.register()
        self.assertEqual(self.revision(), before)

    def test_available_precreation_check_refuses_ten_existing_jobs(self):
        for _ in range(10):
            self._production_job()
        before = self.revision()
        with self.locked() as (conn, guard):
            with self.assertRaises(exclusion.ExperimentExclusionError):
                exclusion.assert_available_locked(conn, policy=self.policy, guard=guard)
            self.assertIsNone(conn.execute("SELECT 1 FROM sqlite_master WHERE name=?",
                                          (exclusion.TABLE,)).fetchone())
        self.assertEqual(self.revision(), before)

    def _legacy_fixture(self):
        # Reuse synthetic target/Job assertions against this SAME daily ledger.
        # Calling LegacyWriterTests.setUp would create an unrelated second DB.
        fixture = legacy_fixtures.LegacyWriterTests()
        self.addCleanup(fixture.doCleanups)
        fixture.directory, fixture.db, fixture.store = self.db.parent, self.db, self.store
        fixture.policy = self.fixture.fixture.policy
        fixture.exemptions = SimpleNamespace(path=self.db.with_name("exemptions.sqlite3"))
        fixture.clock = legacy_fixtures.SyntheticClock()
        fixture.targets, fixture.jobs = {}, {}
        fixture.writes, fixture.opens, fixture.job_opens = [], [], []
        with self.locked() as (conn, guard):
            # These canonical helpers manage their own short transaction.
            conn.rollback()
            writer.initialize_registry_locked(self.store)
            bind_policy_locked(fixture.exemptions, self.store)

        def job_factory(name, logon):
            fixture.assert_native_scope()
            self.assertEqual(logon, self.binding.logon_id)
            fixture.job_opens.append(name)
            job = legacy_fixtures.SyntheticJob(fixture, name)
            fixture.jobs[name] = job
            return job

        fixture.job_factory = job_factory
        return fixture

    def test_real_legacy_batch_excludes_registered_actor_and_job_descendant_from_all_setters(self):
        self.register()
        fixture = self._legacy_fixture()
        descendant = ProcessIdentity(self.guardian.pid + 200, self.guardian.created_filetime_100ns + 2,
                                     self.guardian.logon_id)
        # The wrapper has no managed execution or old infrastructure entry;
        # only the new experiment registry can exclude this actor.
        for action, io_priority in (("demote", 1), ("restore", 2)):
            with self.subTest(action=action):
                fixture.target(self.wrapper, priority="BelowNormal")
                child = fixture.target(descendant, priority="BelowNormal", member={self.binding.job_name: True})
                candidates = [fixture.candidate(identity=identity, action=action, io_priority=io_priority)
                              for identity in (self.wrapper, descendant)]
                result = fixture.execute(candidates)
                self.assertTrue(result["available"], result)
                self.assertEqual([item["reason"] for item in result["results"]],
                                 ["legacy_managed_scope", "legacy_managed_scope"])
                self.assertIn(("membership", self.binding.job_name), child.calls)
                self.assertEqual(fixture.writes, [])


if __name__ == "__main__":
    unittest.main()
