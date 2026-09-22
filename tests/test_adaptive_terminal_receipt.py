"""Durable terminal custody receipts over isolated SQLite and native fixtures.

These portable tests exercise the actual retirement and receipt paths. Job,
process and mutex backends are explicit fixtures, not Windows close evidence.
"""
from contextlib import contextmanager
import hashlib
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_reconcile import ReconcileResult
from sentinel.adaptive.terminal_custody import TerminalCustody
from sentinel.adaptive.terminal_receipt import (
    TerminalReceiptOperation, assert_terminal_custody_receipt,
)
from tests import test_adaptive_terminal_custody as fixture


TABLE = "adaptive_terminal_custody_receipts"
OWNERS = ("root", "wrapper", "job", "mutex")


class TerminalReceiptTests(unittest.TestCase):
    # Reuse setup helpers without inheriting another module's test cases.
    setUp = fixture.TerminalCustodyTests.setUp
    spec = fixture.TerminalCustodyTests.spec
    allocate = fixture.TerminalCustodyTests.allocate
    connection = fixture.TerminalCustodyTests.connection
    make_mutex = fixture.TerminalCustodyTests.make_mutex
    seed_evidence = fixture.TerminalCustodyTests.seed_evidence
    seed_started = fixture.TerminalCustodyTests.seed_started
    start_consumer = fixture.TerminalCustodyTests.start_consumer
    adopt = fixture.TerminalCustodyTests.adopt
    row = fixture.TerminalCustodyTests.row
    allocation = fixture.TerminalCustodyTests.allocation
    root_exits = fixture.TerminalCustodyTests.root_exits
    rewrite_manifest = fixture.TerminalCustodyTests.rewrite_manifest
    sql = fixture.TerminalCustodyTests.sql
    finished_case = fixture.TerminalCustodyTests.finished_case
    retire = fixture.TerminalCustodyTests.retire
    forbid_native_reentry = fixture.TerminalCustodyTests.forbid_native_reentry
    process_closes = fixture.TerminalCustodyTests.process_closes
    assert_no_close = fixture.TerminalCustodyTests.assert_no_close
    assert_unfinished = fixture.TerminalCustodyTests.assert_unfinished
    block_wrapper_close = fixture.TerminalCustodyTests.block_wrapper_close

    def runtime(self):
        return dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())

    def receipt_rows(self):
        conn = self.connection()
        present = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                               (TABLE,)).fetchone()
        return [] if present is None else [dict(row) for row in conn.execute("SELECT * FROM " + TABLE)]

    def read_receipt(self, case):
        return assert_terminal_custody_receipt(self.store, self.journal, self.row(case))

    def retired_case(self):
        case = self.finished_case()
        result = self.retire(case)
        self.assertTrue(result.complete, result)
        self.assertEqual(result.closed_owners, OWNERS)
        self.assertEqual(len(self.receipt_rows()), 1)
        return case

    def durable_snapshot(self):
        return tuple(self.connection().iterdump())

    def receipt_operation(self, case):
        return case.retained.terminal_cleanup.receipt_operation

    def test_actual_retirement_writes_canonical_receipt_without_capacity_or_revision_changes(self):
        case = self.finished_case()
        runtime = self.runtime()
        terminal = self.row(case)
        archive = dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone())
        manifest = (self.journal_dir / (case.spec.execution_id + ".json")).read_bytes()
        result = self.retire(case)
        self.assertTrue(result.complete, result)
        self.assertEqual(result.closed_owners, OWNERS)
        receipt, = self.receipt_rows()
        body = json.loads(receipt["receipt_json"])
        self.assertEqual(body["closed_owners"], list(OWNERS))
        self.assertEqual(body["state"], "FINISHED")
        self.assertEqual(receipt["execution_id"], case.spec.execution_id)
        self.assertEqual(receipt["state_revision"], terminal["state_revision"])
        self.assertEqual(receipt["registry_revision"], runtime["registry_revision"])
        self.assertEqual(receipt["guardian_epoch"], terminal["guardian_epoch"])
        self.assertEqual(receipt["receipt_json"], json.dumps(body, ensure_ascii=True,
            sort_keys=True, separators=(",", ":"), allow_nan=False))
        self.assertEqual(receipt["receipt_hash"],
            hashlib.sha256(receipt["receipt_json"].encode("utf-8")).hexdigest())
        self.assertEqual(self.row(case), terminal)
        self.assertEqual(self.runtime(), runtime)
        self.assertIsNone(self.allocation(case))
        self.assertEqual(dict(self.connection().execute(
            "SELECT * FROM executions WHERE reservation_id=?", (case.spec.reservation.id,)).fetchone()), archive)
        self.assertEqual((self.journal_dir / (case.spec.execution_id + ".json")).read_bytes(), manifest)
        self.assertNotIn(case.spec.execution_id, self.owner.retained_execution_ids)
        self.assertIsInstance(self.read_receipt(case), dict)

    def test_partial_close_writes_no_receipt_and_retry_does_not_reenter_job(self):
        case = self.finished_case()
        native = self.block_wrapper_close(case)
        self.assertEqual(self.receipt_rows(), [])
        self.assertIsNone(self.receipt_operation(case))
        native.close_error = None
        with self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assertTrue(result.complete, result)
        self.assertEqual(len(self.receipt_rows()), 1)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 2)
        self.assertEqual(case.job.close_calls, 1)

    def test_retained_operation_reports_changed_completion_and_exact_completed_replay(self):
        case = self.finished_case()
        # Delay only the writer call: actual terminal proof and all four
        # original owner closes still run through production retirement.
        with patch.object(TerminalReceiptOperation, "tick",
                          return_value=ReconcileResult(False, True, False, "fixture_deferred")):
            first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertEqual(first.closed_owners, OWNERS)
        self.assertEqual(self.receipt_rows(), [])
        operation = self.receipt_operation(case)
        with self.forbid_native_reentry(case):
            written = operation.tick(case.retained)
            replayed = operation.tick(case.retained)
        self.assertTrue(written.complete)
        self.assertTrue(written.changed)
        self.assertFalse(written.pending)
        self.assertFalse(written.quarantined)
        self.assertEqual(replayed, written)
        self.assertFalse(operation.pending)
        self.assertIsNone(operation.guard)
        self.assertIn(case.spec.execution_id, self.owner.retained_execution_ids)
        with self.forbid_native_reentry(case):
            self.assertTrue(self.retire(case).complete)
        self.assertEqual(len(self.receipt_rows()), 1)

    def test_unknown_native_close_never_publishes_receipt_or_retries(self):
        case = self.finished_case()
        case.job.close_error = OSError("fixture close acknowledgement unknown")
        first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.quarantined)
        self.assertEqual(self.receipt_rows(), [])
        self.assertIsNone(self.receipt_operation(case))
        case.job.close_error = None
        with self.forbid_native_reentry(case):
            second = self.retire(case)
        self.assertTrue(second.quarantined)
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(self.receipt_rows(), [])

    def test_constructor_rejects_fabricated_custody_before_any_policy_entry(self):
        case = self.finished_case()
        fake = SimpleNamespace(execution_id=case.spec.execution_id,
            proof_published=True, native_complete=True, closed_owners=OWNERS)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no authority")):
            with self.assertRaises(LifecycleError):
                TerminalReceiptOperation(self.owner, fake)
        self.assertEqual(self.receipt_rows(), [])
        self.assert_no_close(case)

    def test_real_custody_without_published_proof_cannot_create_receipt_operation(self):
        case = self.finished_case()
        runtime = self.runtime()
        custody = TerminalCustody(case.retained, self.row(case), case.retained.manifest,
            PolicyBinding(runtime["policy_instance_id"], runtime["policy_logon_id"]))
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no proof")):
            with self.assertRaises(LifecycleError):
                TerminalReceiptOperation(self.owner, custody)
        self.assertEqual(self.receipt_rows(), [])
        self.assert_no_close(case)

    def test_published_proof_with_partial_closed_owners_is_not_a_receipt(self):
        case = self.finished_case()
        self.block_wrapper_close(case)
        custody = case.retained.terminal_cleanup
        self.assertTrue(custody.proof_published)
        self.assertEqual(custody.closed_owners, ("root",))
        with self.assertRaises(LifecycleError):
            TerminalReceiptOperation(self.owner, custody)
        self.assertEqual(self.receipt_rows(), [])

    def test_absent_owners_cannot_substitute_for_all_four_positive_close_results(self):
        case = self.finished_case()
        self.block_wrapper_close(case)
        custody = case.retained.terminal_cleanup
        # Absence may satisfy cleanup bookkeeping but is not four acknowledgements.
        custody.states.update(wrapper="absent", job="absent", mutex="absent")
        self.assertTrue(custody.native_complete)
        with self.assertRaises(LifecycleError):
            TerminalReceiptOperation(self.owner, custody)
        self.assertEqual(self.receipt_rows(), [])

    def test_missing_receipt_does_not_create_table_or_change_ledger(self):
        case = self.finished_case()
        before = self.durable_snapshot()
        with patch.object(self.store, "_transaction", side_effect=AssertionError("read only")), \
                self.forbid_native_reentry(case):
            with self.assertRaises(LifecycleError):
                self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)
        self.assertEqual(self.receipt_rows(), [])

    def test_missing_database_is_not_recreated_by_receipt_reader(self):
        case = self.retired_case()
        row = self.row(case)
        for connection in self.setup_connections:
            connection.close()
        moved = self.db.with_name("retained-evidence.db")
        self.db.rename(moved)
        before = moved.read_bytes()
        with patch.object(self.store, "_transaction", side_effect=AssertionError("read only")):
            with self.assertRaises(LifecycleError):
                assert_terminal_custody_receipt(self.store, self.journal, row)
        self.assertFalse(self.db.exists())
        self.assertEqual(moved.read_bytes(), before)

    def test_reader_uses_durable_receipt_without_native_calls_or_ledger_writes(self):
        case = self.retired_case()
        expected = self.read_receipt(case)
        before = self.durable_snapshot()
        with patch.object(self.store, "_transaction", side_effect=AssertionError("read only")), \
                patch.object(self.store._policy, "prepare", side_effect=AssertionError("no native fence")), \
                patch.object(self.processes, "wait", side_effect=AssertionError("no native observation")), \
                self.forbid_native_reentry(case):
            self.assertEqual(self.read_receipt(case), expected)
        self.assertEqual(self.durable_snapshot(), before)

    def test_historical_receipt_survives_later_runtime_epoch_and_revision(self):
        case = self.retired_case()
        receipt = self.read_receipt(case)
        self.sql("UPDATE adaptive_runtime SET guardian_epoch=?,registry_revision=registry_revision+1",
                 ("later-guardian-epoch",))
        before = self.durable_snapshot()
        self.assertEqual(self.read_receipt(case), receipt)
        self.assertEqual(self.durable_snapshot(), before)

    def test_historical_receipt_rejects_changed_current_policy_instance(self):
        case = self.retired_case()
        self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
        before = self.durable_snapshot()
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)

    def test_historical_receipt_rejects_changed_current_policy_logon(self):
        case = self.retired_case()
        self.sql("UPDATE adaptive_runtime SET policy_logon_id=?", ("S-1-5-5-3-4",))
        before = self.durable_snapshot()
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)

    def test_changed_terminal_row_revision_rejects_even_fresh_caller_row(self):
        case = self.retired_case()
        self.sql("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?",
                 (case.spec.execution_id,))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_valid_replacement_manifest_cannot_reuse_old_custody_receipt(self):
        case = self.retired_case()
        self.rewrite_manifest(case, manifest_seq=case.retained.manifest.manifest_seq + 1)
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_changed_archive_rejects_old_custody_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE executions SET outcome='changed_archive' WHERE reservation_id=?",
                 (case.spec.reservation.id,))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_noncanonical_json_rejected_even_with_matching_updated_hash(self):
        case = self.retired_case()
        receipt, = self.receipt_rows()
        encoded = json.dumps(json.loads(receipt["receipt_json"]), indent=1, sort_keys=True)
        self.sql("UPDATE " + TABLE + " SET receipt_json=?,receipt_hash=? WHERE execution_id=?",
            (encoded, hashlib.sha256(encoded.encode("utf-8")).hexdigest(), case.spec.execution_id))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_hash_mismatch_rejected_without_repairing_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE " + TABLE + " SET receipt_hash=? WHERE execution_id=?",
                 ("0" * 64, case.spec.execution_id))
        before = self.durable_snapshot()
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)

    def test_unknown_schema_version_is_rejected(self):
        case = self.retired_case()
        # Deliberate fixture corruption bypasses the SQL CHECK only on this
        # test connection; production writers retain the enforced constraint.
        conn = self.connection()
        conn.execute("PRAGMA ignore_check_constraints=ON")
        try:
            conn.execute("UPDATE " + TABLE + " SET schema_version=2 WHERE execution_id=?",
                         (case.spec.execution_id,))
        finally:
            conn.execute("PRAGMA ignore_check_constraints=OFF")
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_changed_table_schema_is_rejected_without_migration(self):
        case = self.retired_case()
        self.sql("ALTER TABLE " + TABLE + " ADD COLUMN unexpected TEXT")
        before = self.durable_snapshot()
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)

    def test_committed_receipt_lost_ack_reuses_same_guard_and_inserts_only_once(self):
        case = self.finished_case()
        write = TerminalReceiptOperation._write
        connect = self.store._connection
        statements = []

        @contextmanager
        def traced_connection(**kwargs):
            with connect(**kwargs) as conn:
                conn.set_trace_callback(statements.append)
                yield conn

        def lost_ack(operation, guard):
            write(operation, guard)
            raise sqlite3.OperationalError("fixture_receipt_commit_ack_lost")

        with patch.object(self.store, "_connection", traced_connection):
            with patch.object(TerminalReceiptOperation, "_write", lost_ack):
                first = self.retire(case)
            self.assert_unfinished(first, case)
            self.assertFalse(first.quarantined)
            operation = self.receipt_operation(case)
            guard = operation.guard
            self.assertIsNotNone(guard)
            self.assertTrue(operation.pending)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
            persisted, = self.receipt_rows()
            used = []
            hold = self.store._policy.hold

            @contextmanager
            def record_hold(value):
                used.append(value)
                with hold(value):
                    yield value

            with patch.object(self.store._policy, "prepare", side_effect=AssertionError("retain original guard")), \
                    patch.object(self.store._policy, "hold", record_hold), self.forbid_native_reentry(case):
                result = self.retire(case)
        self.assertTrue(result.complete, result)
        self.assertEqual(used, [guard])
        self.assertEqual(self.receipt_rows(), [persisted])
        inserts = [sql for sql in statements if sql.lstrip().upper().startswith("INSERT INTO " + TABLE.upper())]
        self.assertEqual(len(inserts), 1, inserts)
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.pending)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)

    def test_cleared_nonce_lost_ack_reconciles_exact_receipt_without_new_guard(self):
        case = self.finished_case()
        clear = self.store._policy._clear

        def lost_receipt_clear(guard):
            clear(guard)
            if self.receipt_rows():
                raise sqlite3.OperationalError("fixture_receipt_nonce_ack_lost")

        with patch.object(self.store._policy, "_clear", lost_receipt_clear):
            first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertFalse(first.quarantined)
        operation = self.receipt_operation(case)
        self.assertIsNotNone(operation.guard)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        persisted = self.receipt_rows()
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("no replacement guard")), \
                self.forbid_native_reentry(case):
            result = self.retire(case)
        self.assertTrue(result.complete, result)
        self.assertEqual(self.receipt_rows(), persisted)
        self.assertIsNone(operation.guard)

    def test_missing_receipt_after_lost_ack_never_counts_as_retirement_success(self):
        case = self.finished_case()
        write = TerminalReceiptOperation._write

        def lost_ack(operation, guard):
            write(operation, guard)
            raise sqlite3.OperationalError("fixture_receipt_commit_ack_lost")

        with patch.object(TerminalReceiptOperation, "_write", lost_ack):
            first = self.retire(case)
        self.assert_unfinished(first, case)
        operation = self.receipt_operation(case)
        guard = operation.guard
        self.sql("DELETE FROM " + TABLE)
        with patch.object(TerminalReceiptOperation, "_write", side_effect=sqlite3.OperationalError("write unavailable")), \
                self.forbid_native_reentry(case):
            second = self.retire(case)
        self.assert_unfinished(second, case)
        self.assertIs(operation.guard, guard)
        self.assertEqual(self.receipt_rows(), [])

    def test_native_policy_cleanup_failure_quarantines_receipt_operation_and_retains_entry(self):
        case = self.finished_case()
        hold = self.policy.hold

        @contextmanager
        def unknown_receipt_release(binding, **kwargs):
            with hold(binding, **kwargs) as lease:
                yield lease
            if self.receipt_rows():
                raise RuntimeError("fixture_receipt_native_release_unknown")

        with patch.object(self.policy, "hold", unknown_receipt_release):
            first = self.retire(case)
        self.assert_unfinished(first, case)
        self.assertTrue(first.quarantined)
        operation = self.receipt_operation(case)
        self.assertIsNotNone(operation.guard)
        self.assertTrue(operation.pending)
        self.assertEqual(len(self.receipt_rows()), 1)
        with patch.object(self.store._policy, "hold", side_effect=AssertionError("quarantine cannot reenter")), \
                self.forbid_native_reentry(case):
            second = self.retire(case)
        self.assert_unfinished(second, case)
        self.assertTrue(second.quarantined)
        self.assertEqual(case.job.close_calls, 1)
        self.assertEqual(self.process_closes(case.root_handle), 1)
        self.assertEqual(self.process_closes(case.wrapper_handle), 1)


if __name__ == "__main__":
    unittest.main()
