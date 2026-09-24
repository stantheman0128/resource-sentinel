"""Full original admission pin; real SQLite and synthetic authenticated transport.

The existing lock-boundary fixture uses actual VerifiedProcess duplication,
generation validation and SQL hooks with a synthetic pipe/identity backend.
No native experiment, admission release or installed source is exercised.
"""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_demand as demand_module
from sentinel.adaptive.admission import VerifiedProcess
from sentinel.adaptive.contracts import ResourceDemand
from sentinel.coordinator import Coordinator
from tests.test_adaptive_admission_context import FakeCurrentProcess
from tests import test_adaptive_daily_readiness_lock_boundary as readiness_tests


class ExperimentGenerationPinTests(unittest.TestCase):
    def setUp(self):
        self.fixture = readiness_tests.DailyReadinessLockBoundaryTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.db = self.fixture.db
        self.isolated = tempfile.TemporaryDirectory()
        self.addCleanup(self.isolated.cleanup)
        self.db.with_name("status.json").write_text('{"synthetic_status_only":true}', encoding="utf-8")
        self.coordinator = Coordinator.__new__(Coordinator)
        self.coordinator.db_path = self.db
        self.process = FakeCurrentProcess(self.fixture.caller_identity)
        declaration = demand_module.ExperimentDeclaration(str(uuid4()), "S1", "b" * 64,
            ResourceDemand(.5, 1 << 30, 2 << 30, 0))
        # Capture a real ManagedAdmission with only its native-self observation
        # modeled; restore the readiness fixture's exact native witness factory.
        with patch.object(VerifiedProcess, "current", return_value=self.process):
            self.demand = demand_module.DailyExperimentDemand.capture(declaration, Path(self.isolated.name))
        self.addCleanup(lambda: demand_module._RETAINED.pop(declaration.experiment_id, None))

    def prepare(self):
        with generation.readiness_scope(self.db):
            return self.demand._prepare_submission(self.coordinator)

    def test_original_row_comes_from_same_authenticated_sql_snapshot(self):
        bound, checked = [], []
        prepare, revalidate = generation.prepare_connection, generation.revalidate_transaction
        def bind(conn, **kwargs):
            self.assertFalse(conn.in_transaction)
            bound.append(conn)
            return prepare(conn, **kwargs)
        def check(conn, **kwargs):
            self.assertTrue(conn.in_transaction)
            checked.append(conn)
            return revalidate(conn, **kwargs)
        with patch.object(generation, "prepare_connection", side_effect=bind), \
                patch.object(generation, "revalidate_transaction", side_effect=check):
            self.prepare()
        self.assertEqual(len(bound), 1)
        self.assertEqual(checked, bound)
        self.assertEqual(json.loads(self.demand._generation_original),
                         generation.read_generation(self.fixture.conn))
        with self.assertRaises(sqlite3.ProgrammingError):
            bound[0].execute("SELECT 1")
        self.assertEqual(self.fixture.events.count("rpc"), 1)

    def test_endpoint_mutation_with_same_three_digests_refuses_later_admission(self):
        self.prepare()
        original = self.demand._generation_original
        digests = dict(self.demand._prepared[0])
        self.fixture.change("readiness_instance_id", str(uuid4()))
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "daily_generation_changed"):
            self.prepare()
        self.assertEqual(self.demand._generation_original, original)
        self.assertEqual(self.demand._prepared[0], digests)

    def test_source_manifest_bytes_are_pinned_despite_equal_manifest_digest(self):
        self.prepare()
        original = self.demand._generation_original
        manifest = json.loads(json.loads(original)["source_manifest_json"])
        self.fixture.change("source_manifest_json", json.dumps(manifest, indent=2))
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "daily_generation_changed"):
            self.prepare()
        self.assertEqual(self.demand._generation_original, original)

    def test_locked_admission_compares_entire_original_row_on_its_connection(self):
        self.prepare()
        self.fixture.change("readiness_instance_id", str(uuid4()))
        guard = SimpleNamespace(binding=SimpleNamespace(logon_id=self.demand._snapshot.logon_id))
        policy = Mock(spec=["assert_held", "revalidate"])
        policy.assert_held.return_value = guard
        policy.revalidate.return_value = {"mode": "off"}
        # This one test models POLICY ownership; the row comparison uses its
        # actual writer snapshot, before schema or capacity mutation can occur.
        with closing(sqlite3.connect(self.db, isolation_level=None)) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN IMMEDIATE")
            with self.assertRaisesRegex(demand_module.ExperimentDemandError, "daily_generation_changed"):
                self.demand._locked(conn, self.demand._snapshot, policy)
            conn.rollback()

    def test_row_change_between_hook_and_begin_cannot_become_original_pin(self):
        bind = generation.prepare_connection
        def change_after_binding(conn, **kwargs):
            result = bind(conn, **kwargs)
            self.fixture.change("readiness_instance_id", str(uuid4()))
            return result
        with patch.object(generation, "prepare_connection", side_effect=change_after_binding):
            with self.assertRaises(sqlite3.OperationalError):
                self.prepare()
        self.assertIsNone(self.demand._generation_original)
        self.assertIsNone(self.demand._prepared)

    def test_completion_observation_is_an_independent_copy_without_late_sql(self):
        self.prepare()
        original = self.demand._generation_original
        with patch.object(generation, "read_generation", side_effect=AssertionError("late origin read")):
            observation = self.demand._completion_binding()
            observation["generation_binding"]["readiness_instance_id"] = str(uuid4())
            observation["generation_binding"]["source_manifest_json"] = "{}"
            self.assertEqual(self.demand._completion_binding()["generation_binding"], json.loads(original))
        self.assertEqual(self.demand._generation_original, original)

    def test_prepared_owner_missing_original_pin_cannot_adopt_current_row(self):
        self.prepare()
        self.demand._generation_original = None
        with patch.object(generation, "prepare_connection", side_effect=AssertionError("late adoption")):
            with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_generation_required"):
                self.demand._prepare_submission(self.coordinator)
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_generation_required"):
            self.demand._completion_binding()

    def test_partial_retained_pin_is_not_completion_binding(self):
        self.prepare()
        self.demand._generation_original = demand_module._canonical(dict(self.demand._prepared[0]))
        with self.assertRaisesRegex(demand_module.ExperimentDemandError, "original_generation_required"):
            self.demand._completion_binding()

    def test_malformed_generation_row_is_never_pinned(self):
        self.fixture.change("owner_identity_json", "{")
        with self.assertRaises(generation.DailyGenerationUnavailable):
            self.prepare()
        self.assertIsNone(self.demand._generation_original)

    def test_partial_generation_schema_is_never_pinned(self):
        self.fixture.conn.execute("ALTER TABLE adaptive_daily_generation DROP COLUMN readiness_instance_id")
        self.fixture.conn.commit()
        with self.assertRaises(sqlite3.DatabaseError):
            self.prepare()
        self.assertIsNone(self.demand._generation_original)


if __name__ == "__main__":
    unittest.main()
