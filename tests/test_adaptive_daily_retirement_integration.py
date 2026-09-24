"""Real portable daily SQL retirement ordering, with synthetic native owners.

Generation install/readiness routing, POLICY nonce ownership, inventory, freeze,
seal and SQL authorizers are production code over a temporary real ledger. Only
the installed source location/provenance and native ownership are fixtures.
Passing does not establish Windows retirement or authorize daily activation.
"""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.daily_activation_host import DailyActivationHost
from sentinel.adaptive.daily_cohort import RetainedCohort
from sentinel.adaptive.daily_retirement import DailyRetirementOperation
from sentinel.adaptive.daily_retirement_fence import DailyRetirementError, read_retirement
from sentinel.adaptive.legacy_writer import initialize_registry_locked
from sentinel.adaptive.store import LifecycleStore
from sentinel.adaptive.supervisor_host import SupervisorHost
from sentinel.coordinator import Coordinator
from sentinel.maintainer import Maintainer
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests import test_adaptive_daily_cohort as cohort_fixture


class DailyRetirementIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        locations = patch.object(generation, "daily_locations", return_value=(self.root, self.root))
        provenance = patch.object(generation, "verify_import_provenance", return_value=self.root)
        locations.start()
        self.addCleanup(locations.stop)
        provenance.start()
        self.addCleanup(provenance.stop)
        (self.root / "config.json").write_text(json.dumps({
            "admission_policy": "resource-v2", "local_allocatable_ram_gib": 58,
            "local_physical_headroom_gib": 4, "local_commit_headroom_gib": 4,
        }), encoding="utf-8")
        Coordinator(self.root, pid_identity=lambda pid: (None, 0.0))
        Maintainer(self.root)
        self.db = self.root / "sentinel.db"
        self.backend = cohort_fixture.Backend()
        # Only the exact current interpreter appears in this synthetic host.
        # RetainedCohort still performs its actual bounded capture and exclusion.
        self.backend.entries = [item for item in self.backend.entries if item.pid != 201]
        self.process = self.backend.current()
        cohort = RetainedCohort.capture_current(backend=self.backend)
        manifest = generation.SourceManifest(tuple(generation.SourceEntry(name, "a" * 64, 0)
            for name in sorted(generation.REQUIRED_PATHS)))
        self.owner = generation.DailyGenerationOwner(_token=generation._TOKEN,
            process=self.process, cohort=cohort, manifest=manifest,
            source_root=self.root, ledger_path=self.db)
        self.addCleanup(lambda: generation._LOCAL_GENERATIONS.pop(self.owner.generation, None))
        self.store = LifecycleStore(self.db,
            policy_provider=FixturePolicyProvider(self.process.identity.logon_id))
        policy = self.store._policy
        guard = policy.prepare(self.process.identity.logon_id)
        with policy.hold(guard):
            initialize_registry_locked(self.store)
            self.owner.prepare_install(policy=policy, guard=guard)
            writer = sqlite3.connect(self.db, isolation_level=None)
            self.addCleanup(writer.close)
            writer.row_factory = sqlite3.Row
            writer.execute("BEGIN IMMEDIATE")
            self.owner.install_locked(writer, policy=policy, guard=guard)
            writer.commit()
        # Actual POLICY._clear used the install's nonce-only preparation route.
        self.owner.settle_install_connection()
        with self.reader() as reader:
            self.owner.acknowledge_install(conn=reader)
        self.owner.assert_ready()

        supervisor = object.__new__(SupervisorHost)
        supervisor.draining, supervisor._closed = True, True
        supervisor._operational_error = None
        # Explicit synthetic assertion of already closed native infrastructure;
        # no child, pipe, process, Job or supervisor thread is ever created.
        supervisor._drain_children_settled = lambda: True
        supervisor._custody_snapshot = lambda: {
            "settled": True, "remaining_custody": 0,
            "mode_off": True, "barrier_cleared": True,
        }
        host = object.__new__(DailyActivationHost)
        host.owner, host.store, host.supervisor = self.owner, self.store, supervisor
        host.ledger_path = self.db
        host.journal_dir = self.root / "recovery"
        host.journal_dir.mkdir()
        host._generation_settled, host._supervisor_closed = True, True
        host._connections, host._retirement = [], None
        host._readiness_cleanup_complete = host._readiness_joined = True
        host._readiness_listener_closed, host._readiness_close_unknown = True, False
        self.host = host
        self.operation = DailyRetirementOperation(host)
        host._retirement = self.operation

    def reader(self):
        # This context closes its real connection, unlike Connection.__exit__.
        from contextlib import closing
        conn = sqlite3.connect(self.db.as_uri() + "?mode=ro", uri=True, isolation_level=None)
        conn.row_factory = sqlite3.Row
        return closing(conn)

    def state(self):
        with self.reader() as conn:
            return (generation.read_generation(conn), read_retirement(conn),
                    dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()))

    def freeze(self):
        self.operation.tick()
        row, freeze, runtime = self.state()
        self.assertTrue(self.operation.freeze_acknowledged, self.operation.reason)
        self.assertFalse(self.operation.sealed)
        self.assertEqual((row["state"], freeze["phase"]), ("ACTIVE", "FROZEN"))
        self.assertEqual(freeze["request_id"], self.operation.request_id)
        self.assertIsNone(runtime["policy_entry_nonce"])
        self.assertFalse(self.operation._freeze.pending)
        self.assertIsNone(self.store._policy.current_guard())
        return freeze

    def assert_sealed(self, freeze):
        row, sealed, runtime = self.state()
        self.assertTrue(self.operation.sealed, self.operation.reason)
        self.assertFalse(self.operation.complete)
        self.assertEqual((row["state"], sealed["phase"]), ("DRAINING", "SEALED"))
        self.assertEqual(sealed["request_id"], freeze["request_id"])
        self.assertEqual(sealed["freeze_policy_nonce"], freeze["freeze_policy_nonce"])
        self.assertNotEqual(self.operation._seal_guard.nonce, freeze["freeze_policy_nonce"])
        self.assertIsNone(runtime["policy_entry_nonce"])
        self.assertEqual((runtime["mode"], runtime["admission_barrier"]), ("off", "NONE"))
        self.assertFalse(self.operation._seal.pending)
        self.assertIsNone(self.store._policy.current_guard())
        self.assertIsNone(self.store._policy.current_cleanup_guard())
        self.assertTrue(all(item.closed and not item.close_unknown for item in self.host._connections))
        return sealed

    def test_original_operation_completes_real_freeze_inventory_seal_and_nonce_cleanup(self):
        freeze = self.freeze()
        self.operation.tick()
        sealed = self.assert_sealed(freeze)
        # DRAINING cannot reuse the special final cleanup connection after ACK.
        with self.assertRaisesRegex(DailyRetirementError, "daily_retirement_cleanup_not_owned"):
            with self.store._connection():
                self.fail("sealed generation opened an ordinary lifecycle connection")
        with self.reader() as reader, self.assertRaisesRegex(
                generation.DailyGenerationUnavailable, "daily_generation_draining"):
            generation.prepare_connection(reader, role="coordinator", db_path=self.db)
        self.operation.close_owner()
        self.assertTrue(self.operation.complete)
        self.assertTrue(self.owner._closed)
        self.assertIsNone(self.process._handle)
        self.assertEqual(self.operation.phase, "retired_admission_fenced")
        self.assertEqual(self.state()[1], sealed)

    def test_lost_seal_commit_ack_reconciles_same_original_guard_without_second_seal(self):
        freeze = self.freeze()
        fault = {"raised": False, "seal_writes": 0}
        original_connect = sqlite3.connect

        class LostSealCommitAck(sqlite3.Connection):
            def execute(connection, sql, parameters=()):
                if sql.startswith("UPDATE adaptive_daily_generation SET state='DRAINING'"):
                    connection.seal_written = True
                    fault["seal_writes"] += 1
                return super().execute(sql, parameters)

            def commit(connection):
                super().commit()
                if getattr(connection, "seal_written", False) and not fault["raised"]:
                    fault["raised"] = True
                    raise sqlite3.OperationalError("fixture_seal_commit_ack_lost")

        def connect(*args, **kwargs):
            kwargs["factory"] = LostSealCommitAck
            return original_connect(*args, **kwargs)

        # Real connections/SQL/authorizers still run. Only the return after the
        # final real commit is lost; all policy and inventory code is untouched.
        with patch.object(sqlite3, "connect", side_effect=connect):
            self.operation.tick()
            row, sealed, runtime = self.state()
            self.assertTrue(fault["raised"])
            self.assertFalse(self.operation.sealed)
            self.assertTrue(self.operation._seal.pending)
            self.assertEqual((row["state"], sealed["phase"]), ("DRAINING", "SEALED"))
            original_guard = self.operation._seal.guard
            self.assertIs(original_guard, self.operation._seal_guard)
            self.assertEqual(runtime["policy_entry_nonce"], original_guard.nonce)
            self.operation.tick()
            self.assert_sealed(freeze)
            self.assertIs(self.operation._seal_guard, original_guard)
            self.assertEqual(self.state()[1], sealed)
            self.assertEqual(fault["seal_writes"], 1)
        self.operation.close_owner()
        self.assertTrue(self.operation.complete)

    def test_unknown_original_process_close_never_turns_sql_seal_into_completion(self):
        freeze = self.freeze()
        self.operation.tick()
        sealed = self.assert_sealed(freeze)
        original_handle = self.process._handle
        original_close = self.backend.close
        def close(handle):
            if handle == original_handle:
                self.backend.close_attempts.append(handle)
                raise RuntimeError("synthetic interrupted native close")
            return original_close(handle)
        failure = patch.object(self.backend, "close", side_effect=close)
        failure.start()
        self.addCleanup(failure.stop)
        with self.assertRaisesRegex(RuntimeError, "synthetic interrupted native close"):
            self.operation.close_owner()
        self.assertFalse(self.operation.complete)
        self.assertFalse(self.owner._closed)
        self.assertTrue(self.process._close_outcome_unknown)
        self.assertEqual(self.backend.close_attempts.count(original_handle), 1)
        with self.assertRaises((generation.DailyGenerationUnavailable, DailyRetirementError)):
            self.operation.close_owner()
        self.assertEqual(self.backend.close_attempts.count(original_handle), 1)
        self.assertIs(self.owner._retirement_operation, self.operation)
        self.assertIs(self.host.owner, self.owner)
        self.assertEqual(self.state()[1], sealed)
        self.assertIsNone(self.state()[2]["policy_entry_nonce"])


if __name__ == "__main__":
    unittest.main()
