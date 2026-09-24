"""Positive retirement inventory over real isolated ledgers/receipt writers.

Native ownership uses the existing explicit fixture backends. These portable
tests do not establish Windows capability, installed daily state, or native
retirement acceptance.
"""
from contextlib import contextmanager
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import daily_retirement_inventory as inventory
from sentinel.adaptive.legacy_writer import initialize_registry_locked
from sentinel.adaptive.recovery_journal import RecoveryJournalError
from sentinel.adaptive.store import LifecycleError
from tests import test_adaptive_prelaunch_receipt as prelaunch_fixture
from tests import test_adaptive_terminal_receipt as terminal_fixture


class DailyRetirementInventoryTests(unittest.TestCase):
    def fixture(self, kind="finished", *, retired=True):
        cls = (terminal_fixture.TerminalReceiptTests if kind == "finished"
               else prelaunch_fixture.PrelaunchReceiptTests)
        result = cls()
        self.addCleanup(result.doCleanups)
        result.setUp()
        self.addCleanup(result.tearDown)
        case = None
        if retired:
            case = result.retired_case() if kind != "never-created" else result.retired_case(never_created=True)
        return result, case

    @contextmanager
    def held(self, fixture):
        policy = fixture.store._policy
        guard = policy.prepare(policy.current_logon())
        with policy.hold(guard):
            initialize_registry_locked(fixture.store)
            yield guard

    @contextmanager
    def connection(self, fixture):
        connection = sqlite3.connect(fixture.db, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def verify(self, fixture):
        snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
        with fixture.store._transaction() as connection:
            self.assertIsNone(inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot))
        return snapshot

    def queue_request(self, fixture, *, request_key=None, execution_id=None):
        key = request_key or uuid4().hex
        with self.connection(fixture) as connection:
            connection.execute("""INSERT INTO queue(request_key,owner_pid,owner_started,
                repo,command_signature,command_text,resource_class,priority,priority_rank,
                cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,spec_hash,managed_execution_id)
                VALUES(?,100,1.0,'fixture','fixture','','HEAVY','P2',2,1,1,1,1,1,'',?)""",
                (key, execution_id))
        return key

    def test_empty_inventory_needs_real_original_guard_and_exact_schema(self):
        fixture, _ = self.fixture(retired=False)
        with self.assertRaisesRegex(LifecycleError, "original_policy_required"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)
        with self.held(fixture):
            self.verify(fixture)

    def test_finished_receipt_passes_without_reentering_closed_native_owners(self):
        fixture, case = self.fixture()
        with fixture.forbid_native_reentry(case), self.held(fixture):
            self.verify(fixture)

    def test_finished_receipt_refuses_queue_linked_by_managed_execution(self):
        fixture, case = self.fixture()
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            self.queue_request(fixture, execution_id=case.spec.execution_id)
            with self.assertRaisesRegex(LifecycleError, "retired_scope_queued"):
                inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            with fixture.store._transaction() as connection, \
                    self.assertRaisesRegex(LifecycleError, "retired_scope_queued"):
                inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot)

    def test_finished_receipt_refuses_queue_linked_only_by_archive_request_key(self):
        fixture, case = self.fixture()
        with self.connection(fixture) as connection:
            key = connection.execute("SELECT request_key FROM executions WHERE reservation_id=?",
                                     (case.spec.reservation.id,)).fetchone()[0]
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            self.queue_request(fixture, request_key=key)
            with self.assertRaisesRegex(LifecycleError, "retired_scope_queued"):
                inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            with fixture.store._transaction() as connection, \
                    self.assertRaisesRegex(LifecycleError, "retired_scope_queued"):
                inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot)

    def test_unrelated_queue_is_preserved_through_positive_retirement_inventory(self):
        fixture, _ = self.fixture()
        key = self.queue_request(fixture)
        with self.held(fixture):
            self.verify(fixture)
        with self.connection(fixture) as connection:
            rows = connection.execute("SELECT request_key,managed_execution_id FROM queue").fetchall()
        self.assertEqual([tuple(row) for row in rows], [(key, None)])

    def test_both_c2_custody_receipts_pass(self):
        for kind in ("prelaunch", "never-created"):
            with self.subTest(kind=kind):
                fixture, case = self.fixture(kind)
                with fixture.forbid_native_reentry(case), self.held(fixture):
                    self.verify(fixture)

    def test_finished_row_without_closed_custody_receipt_is_not_retired(self):
        fixture, _ = self.fixture(retired=False)
        fixture.finished_case()
        with self.held(fixture), self.assertRaisesRegex(LifecycleError, "terminal_receipt_missing"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_changed_archive_is_not_hidden_by_terminal_row_or_absent_allocation(self):
        fixture, _ = self.fixture()
        with self.connection(fixture) as connection:
            connection.execute("UPDATE executions SET outcome='forged'")
        with self.held(fixture), self.assertRaisesRegex(LifecycleError, "terminal_receipt_archive_unverified"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_oversized_archive_is_bounded_before_existing_receipt_reader(self):
        fixture, _ = self.fixture()
        with self.connection(fixture) as connection:
            connection.execute("UPDATE executions SET outcome=?", ("x" * 65537,))
        with self.held(fixture), patch.object(inventory.terminal_receipt, "_verified_record",
                side_effect=AssertionError("archive was not bounded first")), \
                self.assertRaisesRegex(LifecycleError, "cell_exceeded"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_extra_or_temp_or_subdirectory_journal_entry_refuses(self):
        for kind in ("orphan", "temp", "directory"):
            with self.subTest(kind=kind):
                fixture, _ = self.fixture()
                name = str(uuid4()) + ".json" if kind == "orphan" else ".pending.tmp"
                path = fixture.journal_dir / name
                if kind == "directory":
                    path.mkdir()
                else:
                    path.write_text("{}", encoding="utf-8")
                with self.held(fixture), self.assertRaises(Exception):
                    inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_missing_manifest_blocks_even_with_genuine_receipt(self):
        fixture, case = self.fixture()
        (fixture.journal_dir / (case.spec.execution_id + ".json")).unlink()
        with self.held(fixture), self.assertRaisesRegex(LifecycleError, "journal_scope_missing"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_windows_zero_direntry_identity_uses_strict_path_stat(self):
        fixture, case = self.fixture()
        path = fixture.journal_dir / (case.spec.execution_id + ".json")
        actual = inventory.os.stat(path, follow_symlinks=False)
        zero_identity = SimpleNamespace(st_mode=actual.st_mode,
            st_file_attributes=getattr(actual, "st_file_attributes", 0),
            st_dev=0, st_ino=0, st_nlink=0)
        with self.assertRaisesRegex(RecoveryJournalError, "manifest_path_unsafe"):
            inventory._safe_stat(zero_identity)
        scandir = inventory.os.scandir
        yielded, direntry_stat_calls = [], []

        class ZeroIdentityEntry:
            def __init__(self, entry):
                self.name = entry.name
            def stat(self, *, follow_symlinks=True):
                direntry_stat_calls.append(follow_symlinks)
                return zero_identity

        class Directory:
            def __init__(self, directory):
                self.entries = scandir(directory)
            def __iter__(self):
                for entry in self.entries:
                    yielded.append(entry.name)
                    yield ZeroIdentityEntry(entry)
            def close(self):
                self.entries.close()

        with self.held(fixture), patch.object(inventory.os, "scandir", side_effect=Directory):
            self.verify(fixture)
        self.assertTrue(yielded)
        self.assertEqual(direntry_stat_calls, [])

    def test_unknown_empty_schema_is_not_no_obligation(self):
        for statement in ("CREATE TABLE adaptive_unknown_obligations(value TEXT)",
                          "CREATE TABLE adaptive_experiment_demands(value TEXT)"):
            with self.subTest(statement=statement):
                fixture, _ = self.fixture()
                with self.connection(fixture) as connection:
                    connection.execute(statement)
                with self.held(fixture), self.assertRaisesRegex(Exception, "schema_unknown"):
                    inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_any_experiment_demand_blocks_until_original_completion_api_exists(self):
        from sentinel.adaptive import experiment_demand
        fixture, _ = self.fixture()
        with self.held(fixture):
            with fixture.store._transaction() as connection:
                experiment_demand._schema(connection, create=True)
                values = {key: "fixture" for key in experiment_demand._FIELDS}
                values.update(schema_version=1, owner_pid=1, state="ADMITTED", revision=0)
                connection.execute("INSERT INTO adaptive_experiment_demands(" +
                    ",".join(values) + ") VALUES(" + ",".join("?" for _ in values) + ")", tuple(values.values()))
            with self.assertRaisesRegex(LifecycleError, "experiment_retirement_unimplemented"):
                inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_orphan_action_is_not_covered_by_another_scopes_receipt(self):
        fixture, _ = self.fixture()
        with self.connection(fixture) as connection:
            connection.execute("""INSERT INTO adaptive_actions(guardian_epoch,execution_id,decision_seq,
                action_id,sample_seq,action_state,desired_mode,reason) VALUES(?,?,0,?,0,'INTENDED','hard_cap','fixture')""",
                ("fixture-epoch", str(uuid4()), str(uuid4())))
        with self.held(fixture), self.assertRaisesRegex(LifecycleError, "orphan_scope_record"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_latest_unresolved_action_blocks_genuine_terminal_receipt(self):
        fixture, case = self.fixture()
        row = fixture.row(case)
        with self.connection(fixture) as connection:
            connection.execute("""INSERT INTO adaptive_actions(guardian_epoch,execution_id,decision_seq,
                action_id,sample_seq,action_state,desired_mode,reason) VALUES(?,?,0,?,0,'INTENDED','hard_cap','fixture')""",
                (row["guardian_epoch"], row["execution_id"], str(uuid4())))
        with self.held(fixture), self.assertRaisesRegex(LifecycleError, "action_tail_unsettled"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_same_guard_required_and_snapshot_cannot_be_constructed(self):
        fixture, _ = self.fixture()
        with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
            inventory.RetirementInventorySnapshot()
        with self.held(fixture):
            snapshot = self.verify(fixture)
        with self.held(fixture), fixture.store._transaction() as connection:
            with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot)
            forged = object.__new__(inventory.RetirementInventorySnapshot)
            with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                inventory.revalidate_retirement_inventory(connection, fixture.store, forged)

    def test_changed_receipt_or_registry_revision_invalidates_final_snapshot(self):
        fixture, _ = self.fixture()
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            with fixture.store._transaction() as connection:
                connection.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
                with self.assertRaisesRegex(LifecycleError, "ledger_changed"):
                    inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot)

    def test_final_revalidation_performs_no_journal_io(self):
        fixture, _ = self.fixture()
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            with patch.object(fixture.journal, "read", side_effect=AssertionError("no files in writer transaction")), \
                    patch.object(inventory.os, "scandir", side_effect=AssertionError("no directory scan in writer transaction")), \
                    fixture.store._transaction() as connection:
                inventory.revalidate_retirement_inventory(connection, fixture.store, snapshot)

    def test_aggregate_bound_fails_before_receipt_promotion(self):
        fixture, _ = self.fixture()
        with self.held(fixture), patch.object(inventory, "MAX_BYTES", 1), \
                self.assertRaisesRegex(LifecycleError, "bytes_exceeded"):
            inventory.capture_retirement_inventory(fixture.store, fixture.journal)

    def test_inventory_digest_is_stable_for_exact_guarded_snapshot(self):
        fixture, _ = self.fixture()
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            first = inventory.retirement_inventory_digest(fixture.store, snapshot)
            self.assertRegex(first, r"^[0-9a-f]{64}$")
            self.assertEqual(first, inventory.retirement_inventory_digest(fixture.store, snapshot))
            with fixture.store._transaction() as connection:
                connection.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1")
            later = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            self.assertNotEqual(first, inventory.retirement_inventory_digest(fixture.store, later))

    def test_inventory_digest_requires_original_snapshot_store_and_current_guard(self):
        fixture, _ = self.fixture()
        other, _ = self.fixture(retired=False)
        with self.held(fixture):
            snapshot = inventory.capture_retirement_inventory(fixture.store, fixture.journal)
            forged = object.__new__(inventory.RetirementInventorySnapshot)
            with self.assertRaisesRegex(LifecycleError, "original_snapshot_required"):
                inventory.retirement_inventory_digest(fixture.store, forged)
            with self.assertRaisesRegex(LifecycleError, "snapshot_scope_changed"):
                inventory.retirement_inventory_digest(other.store, snapshot)
        with self.assertRaisesRegex(LifecycleError, "original_policy_required"):
            inventory.retirement_inventory_digest(fixture.store, snapshot)

    def test_read_connection_close_unknown_retains_exact_connection(self):
        fixture, _ = self.fixture()
        connect = inventory.sqlite3.connect
        opened = []

        class CloseUnknown:
            def __init__(self, actual):
                object.__setattr__(self, "actual", actual)
            def __getattr__(self, name):
                return getattr(self.actual, name)
            def __setattr__(self, name, value):
                setattr(self.actual, name, value)
            def close(self):
                raise OSError("fixture reader close acknowledgement unknown")

        def connecting(*args, **kwargs):
            owner = CloseUnknown(connect(*args, **kwargs))
            opened.append(owner)
            return owner

        with self.held(fixture):
            try:
                with patch.object(inventory.sqlite3, "connect", side_effect=connecting):
                    with self.assertRaisesRegex(OSError, "fixture reader close") as raised:
                        inventory.capture_retirement_inventory(fixture.store, fixture.journal)
                self.assertIs(raised.exception._daily_retirement_inventory_connection, opened[0])
                self.assertIn("daily_retirement_inventory_reader_cleanup_unverified", raised.exception.__notes__)
            finally:
                for owner in opened:
                    owner.actual.close()  # Explicit fixture-only cleanup, not a production retry.


if __name__ == "__main__":
    unittest.main()
