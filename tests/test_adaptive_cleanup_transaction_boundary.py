"""Approved pre-BEGIN boundary on actual successor/cleanup SQLite paths.

Native identities/source attestations come from the existing portable fixtures;
the connections, transactions, original custody and SQL guards are production.
These tests are source evidence only and never establish a Windows native gate.
"""
from contextlib import contextmanager, ExitStack
from pathlib import Path
import sqlite3
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive import experiment_cleanup as cleanup
from sentinel.adaptive.identity import VerifiedProcess
from tests import test_adaptive_daily_successor as successor_tests
from tests import test_adaptive_daily_successor_startup as startup_tests
from tests import test_adaptive_daily_successor_epoch as epoch_tests
from tests import test_adaptive_daily_successor_startup_inventory as startup_inventory_tests
from tests import test_adaptive_experiment_release as release_tests
from tests import test_adaptive_experiment_admission_settlement as settlement_tests
from tests import test_adaptive_experiment_unadmitted_cleanup as abandon_tests
from tests import test_adaptive_experiment_demand as demand_tests


@contextmanager
def outside_sql_probes(test):
    """Fail on actual probes while any same-thread original SQL owner is locked."""
    connections, calls, violations = [], [], []
    thread = threading.current_thread()
    original_connect = sqlite3.connect

    def locked():
        if threading.current_thread() is not thread:
            return False
        for conn in connections:
            try:
                if conn.in_transaction:
                    return True
            except sqlite3.ProgrammingError:  # Positively closed test connection.
                pass
        return False

    def connect(*args, **kwargs):
        conn = original_connect(*args, **kwargs)
        connections.append(conn)
        return conn

    def guarded(name, original):
        def invoke(*args, **kwargs):
            calls.append(name)
            if locked():
                violations.append(name)
                raise AssertionError("external probe inside actual SQL transaction: " + name)
            return original(*args, **kwargs)
        return invoke

    with ExitStack() as stack:
        stack.enter_context(patch.object(sqlite3, "connect", new=connect))
        for target, name in ((Path, "resolve"), (Path, "stat"), (Path, "lstat"), (Path, "open"),
                (VerifiedProcess, "observe"), (generation, "_ledger_identity"),
                (generation, "_fixed_policy_digest"), (generation, "verify_import_provenance"),
                (generation, "_assert_daily_locations")):
            stack.enter_context(patch.object(target, name, new=guarded(name, getattr(target, name))))
        yield connections, calls
    test.assertEqual(violations, [])
    test.assertTrue(connections, "the test must traverse actual SQLite connections")


class CleanupTransactionBoundaryTests(unittest.TestCase):
    def fixture(self, cls):
        value = cls()
        self.addCleanup(value.doCleanups)
        value.setUp()
        return value

    def test_complete_successor_transfer_has_no_file_or_native_probe_under_begin(self):
        fixture = self.fixture(successor_tests.DailySuccessorTests)
        with outside_sql_probes(self) as (_, calls):
            self.assertTrue(fixture.operation.tick())
        self.assertIn("_fixed_policy_digest", calls)
        self.assertIn("observe", calls)
        fixture.assert_finished()

    def test_successor_startup_acquire_and_fresh_inventory_have_no_locked_probes(self):
        fixture = self.fixture(startup_tests.DailySuccessorStartupTests)
        startup = fixture.prepare_startup()
        with outside_sql_probes(self):
            self.assertIs(startup.acquire(), startup)
            startup.assert_fresh()
        self.assertTrue(startup.acquired)
        self.assertTrue(all(item.closed and not item.close_unknown for item in fixture.operation._connections))

    def test_successor_epoch_publication_and_readback_have_no_locked_probes(self):
        fixture = self.fixture(epoch_tests.SuccessorGuardianEpochTests)
        with outside_sql_probes(self):
            result = fixture.owner.tick()
            self.assertTrue(result.complete, result)
            fixture.assert_complete()

    def test_successor_epoch_lost_commit_ack_recovers_same_original_without_locked_probes(self):
        fixture = self.fixture(epoch_tests.SuccessorGuardianEpochTests)
        with outside_sql_probes(self):
            with fixture.sql_fault("commit_ack") as fault:
                result = fixture.owner.tick()
            self.assertTrue(fault["raised"])
            self.assertFalse(result.complete)
            self.assertTrue(result.pending)
            candidate = fixture.owner._candidate
            retry = fixture.owner.tick()
            self.assertTrue(retry.complete, retry)
            self.assertIs(fixture.owner._candidate, candidate)
            fixture.assert_complete()

    def test_successor_startup_original_native_handle_change_under_begin_is_refused(self):
        fixture = startup_inventory_tests.DailySuccessorStartupInventoryTests()
        self.addCleanup(fixture.doCleanups)
        fixture.initialize()
        with fixture.held() as guard:
            snapshot = fixture.capture(guard)
            with fixture.store._transaction() as conn:
                with patch.object(fixture.supervisor.startup._current, "_handle", object()):
                    with self.assertRaisesRegex(RuntimeError, "original_supervisor_changed|local_owner_changed"):
                        fixture.operation.revalidate_startup_inventory(
                            conn, fixture.supervisor, guard, snapshot)

    def test_release_nonce_receipt_capacity_delete_and_readback_use_bound_metadata(self):
        fixture = self.fixture(release_tests.ExperimentReleaseTests)
        with outside_sql_probes(self) as (_, calls):
            result = fixture.release()
        self.assertIn("_fixed_policy_digest", calls)
        fixture.assert_released(result)

    def test_admission_settlement_clears_only_original_nonce_without_locked_probes(self):
        fixture = self.fixture(settlement_tests.ExperimentAdmissionSettlementTests)
        fixture._pending_admission()
        with outside_sql_probes(self):
            result = fixture.coordinator.settle_experiment_admission(fixture.demand)
        self.assertTrue(result["settled"])
        self.assertFalse(result["launch_authorized"])
        self.assertIsNone(fixture.runtime()["policy_entry_nonce"])
        self.assertEqual(settlement_tests._capacity_rows(fixture.db), fixture.before)

    def test_unadmitted_cleanup_removes_exact_queue_under_metadata_guards(self):
        fixture = self.fixture(abandon_tests.ExperimentUnadmittedCleanupTests)
        fixture._queued(foreign=True)
        with outside_sql_probes(self):
            result = fixture.abandon()
        fixture.assert_abandoned(result)

    def test_demand_preparation_reads_publications_before_admission_transaction(self):
        fixture = self.fixture(demand_tests.ExperimentDemandTests)
        demand = fixture.capture()
        with outside_sql_probes(self) as (_, calls):
            result = fixture.coordinator.admit_experiment(demand)
        self.assertTrue(result["allowed"])
        self.assertIn("open", calls)
        fixture.assert_retained(demand)

    def test_before_native_completion_reader_binds_ledger_before_begin(self):
        fixture = self.fixture(demand_tests.ExperimentDemandTests)
        demand = fixture.capture()
        self.assertTrue(fixture.coordinator.admit_experiment(demand)["allowed"])
        with outside_sql_probes(self):
            completion = demand.seal_without_native()
        self.assertIs(completion.owner, demand)
        self.assertIsNone(demand._seal_connection)
        self.assertIsNone(demand._seal_database_metadata)
        fixture.assert_retained(demand)

    def test_cleanup_original_guard_mutation_after_begin_still_refuses(self):
        fixture = self.fixture(release_tests.ExperimentReleaseTests)
        operation = fixture.operation
        with operation._scope("HOLD"):
            guard = operation.prepare_policy(operation.policy, operation._policy_binding.logon_id)
            original_nonce = guard.nonce
            with operation.policy.hold(guard):
                with operation._scope("READ"), operation.store._transaction() as conn:
                    guard.nonce = "changed-after-begin"
                    try:
                        with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "original_guard_changed"):
                            generation.revalidate_transaction(conn, db_path=operation.ledger_path)
                    finally:
                        guard.nonce = original_nonce
        fixture.assert_charged()

    def test_cleanup_preflight_failure_never_opens_a_consumer_connection(self):
        fixture = self.fixture(release_tests.ExperimentReleaseTests)
        with patch.object(generation, "_fixed_policy_digest", return_value="changed"), \
                patch.object(sqlite3, "connect", side_effect=AssertionError("consumer connection opened")):
            with self.assertRaisesRegex(cleanup.ExperimentReleaseError, "ledger_or_config_changed"):
                with fixture.operation._scope("READ"), fixture.operation.store._transaction():
                    self.fail("changed source gained a transaction")
        fixture.assert_charged()


if __name__ == "__main__":
    unittest.main()
