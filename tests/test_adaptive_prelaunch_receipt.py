"""Rootless post-close receipts over real C2 retirement and isolated SQLite.

All process, Job and mutex effects use explicit fixtures, not native acceptance.
"""
from contextlib import closing, contextmanager, ExitStack
import hashlib
import json
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.contracts import CpuControl, CpuControlMode, RecoveryManifest
from sentinel.adaptive.policy import PolicyBinding
from sentinel.adaptive.prelaunch_receipt import (
    PrelaunchReceiptOperation, assert_closed_custody_receipt,
    assert_prelaunch_custody_receipt,
)
from sentinel.adaptive.store import LifecycleError
from sentinel.adaptive.supervisor_reconcile import ReconcileResult
from tests import test_adaptive_guardian_launch as launch_fixture
from tests import test_adaptive_guardian_retirement as fixture


TABLE = "adaptive_prelaunch_custody_receipts"


class PrelaunchReceiptTests(unittest.TestCase):
    setUp = fixture.GuardianRetirementTests.setUp
    tearDown = fixture.GuardianRetirementTests.tearDown
    native_probe = fixture.GuardianRetirementTests.native_probe
    make_mutex = fixture.GuardianRetirementTests.make_mutex
    make_job = fixture.GuardianRetirementTests.make_job
    admitted = fixture.GuardianRetirementTests.admitted
    row = fixture.GuardianRetirementTests.row
    allocation = fixture.GuardianRetirementTests.allocation
    prepare = fixture.GuardianRetirementTests.prepare
    claim_request = fixture.GuardianRetirementTests.claim_request
    claim = fixture.GuardianRetirementTests.claim
    request = fixture.GuardianRetirementTests.request
    retire = fixture.GuardianRetirementTests.retire
    archive_count = fixture.GuardianRetirementTests.archive_count
    prepared_native_job = fixture.GuardianRetirementTests.prepared_native_job

    @contextmanager
    def connection(self):
        with closing(sqlite3.connect(self.db)) as connection:
            connection.row_factory = sqlite3.Row
            with connection:
                yield connection

    def sql(self, statement, values=()):
        with self.connection() as connection:
            return [dict(row) for row in connection.execute(statement, values).fetchall()]

    def runtime(self):
        return self.sql("SELECT * FROM adaptive_runtime")[0]

    def receipt_rows(self):
        with self.connection() as connection:
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None:
                return []
            return [dict(row) for row in connection.execute("SELECT * FROM " + TABLE)]

    def durable_snapshot(self):
        with self.connection() as connection:
            return tuple(connection.iterdump())

    def read_receipt(self, case):
        return assert_prelaunch_custody_receipt(self.store, self.journal, self.row(case))

    def terminal_case(self, *, never_created=False):
        case = self.admitted()
        if never_created:
            with patch.object(self.owner, "_initial_record", side_effect=LifecycleError("fixture_prepare_cut")):
                with self.assertRaisesRegex(LifecycleError, "fixture_prepare_cut"):
                    self.prepare(case)
        else:
            self.prepare(case)
            self.claim(case)
        self.retire(case, failure=not never_created)
        case.entry = self.owner._pending[case.snapshot.execution_id]
        case.wrapper_handle = case.entry.wrapper._handle
        self.assertIsNone(case.entry.root)
        self.assertIsNone(self.allocation(case))
        self.assertEqual(self.archive_count(case), 1)
        return case

    def close_pending(self, case):
        results = self.owner.retire_completed_pending()
        return next(row for row in results if row["execution_id"] == case.snapshot.execution_id)

    def retired_case(self, *, never_created=False):
        case = self.terminal_case(never_created=never_created)
        result = self.close_pending(case)
        self.assertTrue(result["terminal"], result)
        self.assertNotIn(case.snapshot.execution_id, self.owner.retained_execution_ids)
        self.assertEqual(len(self.receipt_rows()), 1)
        return case

    @contextmanager
    def forbid_native_reentry(self, case):
        with ExitStack() as stack:
            for owner, methods in ((case.entry.wrapper, ("observe", "close")),
                                   (case.entry.mutex, ("acquire", "close"))):
                for method in methods:
                    stack.enter_context(patch.object(owner, method,
                        side_effect=AssertionError("closed original owner reentered")))
            if case.entry.job is not None:
                for method in ("accounting", "active_pids", "query_cpu", "query_limits", "close"):
                    stack.enter_context(patch.object(case.entry.job, method,
                        side_effect=AssertionError("closed original Job reentered")))
            yield

    def test_created_job_start_failed_writes_rootless_receipt_after_actual_closes(self):
        case = self.terminal_case()
        row, runtime = self.row(case), self.runtime()
        archive = self.sql("SELECT * FROM executions")
        manifest = (self.journal_dir / (case.snapshot.execution_id + ".json")).read_bytes()
        with patch.object(case.entry.job, "close", wraps=case.entry.job.close) as close_job, \
                patch.object(case.entry.mutex, "close", wraps=case.entry.mutex.close) as close_mutex:
            self.assertTrue(self.close_pending(case)["terminal"])
            close_job.assert_called_once()
            close_mutex.assert_called_once()
        record, = self.receipt_rows()
        body = json.loads(record["receipt_json"])
        self.assertEqual(body["state"], "START_FAILED")
        self.assertEqual(set(body["closed_owners"]), {"wrapper", "job", "mutex"})
        self.assertIsNone(body.get("root_identity"))
        self.assertEqual(body["root_disposition"], "never-created")
        self.assertEqual(body["job_disposition"], "closed")
        self.assertEqual(record["receipt_json"], json.dumps(body, ensure_ascii=True,
            sort_keys=True, separators=(",", ":"), allow_nan=False))
        self.assertEqual(record["receipt_hash"], hashlib.sha256(record["receipt_json"].encode()).hexdigest())
        self.assertEqual(self.processes.events.count(("close", case.wrapper_handle)), 1)
        self.assertEqual(self.row(case), row)
        self.assertEqual(self.runtime(), runtime)
        self.assertEqual(self.sql("SELECT * FROM executions"), archive)
        self.assertEqual((self.journal_dir / (case.snapshot.execution_id + ".json")).read_bytes(), manifest)
        self.assertIsInstance(self.read_receipt(case), dict)

    def test_never_created_cancel_records_only_real_wrapper_and_mutex_closures(self):
        case = self.retired_case(never_created=True)
        body = self.read_receipt(case)
        self.assertEqual(body["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(set(body["closed_owners"]), {"wrapper", "mutex"})
        self.assertIsNone(body.get("root_identity"))
        self.assertEqual(body["root_disposition"], "never-created")
        self.assertEqual(body["job_disposition"], "never-created")
        self.assertEqual(self.jobs, [])
        self.assertFalse(case.entry.create_attempted)
        self.assertEqual(self.processes.events.count(("close", case.wrapper_handle)), 1)
        self.assertEqual(assert_closed_custody_receipt(self.store, self.journal, self.row(case)), body)

    def test_accounting_terminal_before_native_close_is_not_a_custody_receipt(self):
        case = self.terminal_case()
        before = self.durable_snapshot()
        with patch.object(self.store, "_transaction", side_effect=AssertionError("reader wrote ledger")):
            with self.assertRaises(LifecycleError):
                self.read_receipt(case)
        self.assertEqual(self.receipt_rows(), [])
        self.assertEqual(self.durable_snapshot(), before)
        self.assertFalse(case.entry.job.closed)
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_deferred_receipt_keeps_closed_entry_until_original_operation_completes(self):
        case = self.terminal_case()
        with patch.object(PrelaunchReceiptOperation, "tick",
                return_value=ReconcileResult(False, True, False, "fixture_receipt_deferred")):
            first = self.close_pending(case)
        self.assertFalse(first["terminal"])
        self.assertEqual(self.receipt_rows(), [])
        operation = case.entry.retirement_receipt_operation
        self.assertIsInstance(operation, PrelaunchReceiptOperation)
        self.assertTrue(case.entry.job.closed)
        self.assertTrue(case.entry.mutex.closed)
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)
        with self.forbid_native_reentry(case):
            self.assertTrue(self.close_pending(case)["terminal"])
        self.assertEqual(len(self.receipt_rows()), 1)

    def test_first_verify_read_failure_retains_attached_operation_before_any_close(self):
        case = self.terminal_case()
        failure = LifecycleError("fixture_first_receipt_read_failed")
        attached = []

        def unavailable(*args, **kwargs):
            operation = case.entry.retirement_receipt_operation
            self.assertIsInstance(operation, PrelaunchReceiptOperation)
            self.assertTrue(case.entry.retirement_cleanup_started)
            self.assertEqual(case.entry.closed_handles, set())
            attached.append(operation)
            raise failure

        with patch.object(case.entry.job, "close", wraps=case.entry.job.close) as close_job, \
                patch.object(case.entry.wrapper, "close", wraps=case.entry.wrapper.close) as close_wrapper, \
                patch.object(case.entry.mutex, "close", wraps=case.entry.mutex.close) as close_mutex:
            with patch("sentinel.adaptive.prelaunch_receipt._coverage_read_transaction", side_effect=unavailable):
                self.assertFalse(self.close_pending(case)["terminal"])
            operation = case.entry.retirement_receipt_operation
            self.assertEqual(attached, [operation])
            self.assertIs(operation._error, failure)
            self.assertTrue(case.entry.retirement_cleanup_started)
            self.assertEqual(case.entry.closed_handles, set())
            close_job.assert_not_called()
            close_wrapper.assert_not_called()
            close_mutex.assert_not_called()
            self.assertEqual(self.receipt_rows(), [])
            self.assertTrue(self.close_pending(case)["terminal"])
            self.assertIs(case.entry.retirement_receipt_operation, operation)
            close_job.assert_called_once()
            close_wrapper.assert_called_once()
            close_mutex.assert_called_once()
        self.assertEqual(len(self.receipt_rows()), 1)
        self.assertNotIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_first_verify_reader_cleanup_uncertainty_quarantines_before_any_close(self):
        from sentinel.adaptive.prelaunch_receipt import _coverage_read_transaction as read

        case = self.terminal_case()
        failure = LifecycleError("fixture_first_receipt_read_failed")
        failure.add_note("coverage_reader_cleanup_failed")
        with patch.object(case.entry.job, "close", wraps=case.entry.job.close) as close_job, \
                patch.object(case.entry.wrapper, "close", wraps=case.entry.wrapper.close) as close_wrapper, \
                patch.object(case.entry.mutex, "close", wraps=case.entry.mutex.close) as close_mutex:
            with patch("sentinel.adaptive.prelaunch_receipt._coverage_read_transaction", side_effect=failure):
                self.assertFalse(self.close_pending(case)["terminal"])
            operation = case.entry.retirement_receipt_operation
            self.assertIsInstance(operation, PrelaunchReceiptOperation)
            self.assertIs(operation._error, failure)
            self.assertTrue(case.entry.retirement_cleanup_started)
            self.assertEqual(case.entry.closed_handles, set())
            with patch("sentinel.adaptive.prelaunch_receipt._coverage_read_transaction", wraps=read) as restored:
                for _ in range(2):
                    self.assertFalse(self.close_pending(case)["terminal"])
                    self.assertIs(case.entry.retirement_receipt_operation, operation)
                    self.assertIs(operation._error, failure)
                restored.assert_not_called()
            close_job.assert_not_called()
            close_wrapper.assert_not_called()
            close_mutex.assert_not_called()
        self.assertEqual(self.receipt_rows(), [])
        self.assertEqual(case.entry.closed_handles, set())
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_unknown_native_job_close_cannot_publish_or_retry_receipt(self):
        case, kernel = self.prepared_native_job()
        self.retire(case)
        case.entry = self.owner._pending[case.snapshot.execution_id]
        kernel.close_exceptions[fixture.native_fixture.RETAINED] = RuntimeError("fixture_unknown_close")
        self.assertFalse(self.close_pending(case)["terminal"])
        self.assertEqual(self.receipt_rows(), [])
        kernel.close_exceptions.clear()
        self.assertFalse(self.close_pending(case)["terminal"])
        self.assertEqual(self.receipt_rows(), [])
        self.assertEqual(kernel.calls.count(("CloseHandle", fixture.native_fixture.RETAINED)), 1)
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_fabricated_entry_cannot_construct_postclose_authority(self):
        case = self.terminal_case()
        row, runtime = self.row(case), self.runtime()
        manifest = self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        fake = SimpleNamespace(execution_id=row["execution_id"], root=None,
            retirement_cleanup_started=True, closed_handles={"job", "wrapper", "mutex"})
        binding = PolicyBinding(runtime["policy_instance_id"], runtime["policy_logon_id"])
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("fake acquired authority")):
            with self.assertRaises(LifecycleError):
                PrelaunchReceiptOperation(self.owner, fake, row, manifest, binding)
        self.assertEqual(self.receipt_rows(), [])
        self.assertFalse(case.entry.job.closed)

    def test_reader_cannot_accept_a_fabricated_closed_root_even_with_matching_hash(self):
        case = self.retired_case()
        record, = self.receipt_rows()
        body = json.loads(record["receipt_json"])
        body["closed_owners"].append("root")
        body["root_identity"] = launch_fixture.GUARDIAN.to_dict()
        encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        self.sql("UPDATE " + TABLE + " SET receipt_json=?,receipt_hash=?",
                 (encoded, hashlib.sha256(encoded.encode()).hexdigest()))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_receipt_hash_corruption_is_rejected_without_repair(self):
        case = self.retired_case()
        self.sql("UPDATE " + TABLE + " SET receipt_hash=?", ("0" * 64,))
        before = self.durable_snapshot()
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)
        self.assertEqual(self.durable_snapshot(), before)

    def test_changed_terminal_row_is_rejected_even_with_fresh_caller_row(self):
        case = self.retired_case()
        self.sql("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?",
                 (case.snapshot.execution_id,))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_changed_archive_rejects_old_closed_custody_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE executions SET outcome='fixture_changed_archive'")
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_valid_replacement_manifest_cannot_reuse_postclose_receipt(self):
        case = self.retired_case()
        row = self.row(case)
        manifest = self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        values = {name: getattr(manifest, name) for name in manifest.__dataclass_fields__
                  if name != "manifest_hash"}
        replacement = RecoveryManifest.create(**(values | {"manifest_seq": manifest.manifest_seq + 1}))
        (self.journal_dir / (row["execution_id"] + ".json")).write_text(replacement.to_json(), encoding="utf-8")
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_changed_c2_retirement_receipt_invalidates_postclose_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE adaptive_prelaunch_retirements SET manifest_hash=?", ("f" * 64,))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_last_applied_disabled_cannot_be_reclassified_as_ordinary_c2_custody(self):
        case = self.terminal_case()
        row = self.row(case)
        manifest = self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        values = {name: getattr(manifest, name) for name in manifest.__dataclass_fields__
                  if name != "manifest_hash"}
        altered = RecoveryManifest.create(**(values | {
            "last_applied": CpuControl(CpuControlMode.DISABLED, None),
            "manifest_seq": manifest.manifest_seq + 1}))
        # Deliberately align all ordinary hash bindings in this isolated fixture.
        # The explicit C2 last_applied=None invariant must still refuse closure.
        (self.journal_dir / (row["execution_id"] + ".json")).write_text(altered.to_json(), encoding="utf-8")
        self.sql("UPDATE adaptive_prelaunch_retirements SET manifest_hash=?", (altered.manifest_hash,))
        case.entry.record = altered
        with patch.object(case.entry.job, "close", wraps=case.entry.job.close) as close_job, \
                patch.object(case.entry.wrapper, "close", wraps=case.entry.wrapper.close) as close_wrapper:
            self.assertFalse(self.close_pending(case)["terminal"])
            close_job.assert_not_called()
            close_wrapper.assert_not_called()
        self.assertEqual(self.receipt_rows(), [])
        self.assertIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_historical_receipt_allows_later_epoch_without_native_or_policy_entry(self):
        case = self.retired_case()
        expected = self.read_receipt(case)
        self.sql("UPDATE adaptive_runtime SET guardian_epoch=?,registry_revision=registry_revision+1",
                 ("later-guardian-epoch",))
        before = self.durable_snapshot()
        with patch.object(self.store, "_transaction", side_effect=AssertionError("reader wrote ledger")), \
                patch.object(self.store._policy, "prepare", side_effect=AssertionError("reader acquired native policy")), \
                self.forbid_native_reentry(case):
            self.assertEqual(self.read_receipt(case), expected)
            self.assertEqual(assert_closed_custody_receipt(self.store, self.journal, self.row(case)), expected)
        self.assertEqual(self.durable_snapshot(), before)

    def test_changed_current_policy_instance_invalidates_historical_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE adaptive_runtime SET policy_instance_id=?", (str(uuid4()),))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_changed_current_policy_logon_invalidates_historical_receipt(self):
        case = self.retired_case()
        self.sql("UPDATE adaptive_runtime SET policy_logon_id=?", ("S-1-5-5-3-4",))
        with self.assertRaises(LifecycleError):
            self.read_receipt(case)

    def test_committed_receipt_lost_ack_reuses_guard_without_reclosing_original_owners(self):
        case = self.terminal_case()
        write = PrelaunchReceiptOperation._write
        connect = self.store._connection
        statements = []

        @contextmanager
        def traced_connection(**kwargs):
            with connect(**kwargs) as connection:
                connection.set_trace_callback(statements.append)
                yield connection

        def lost_ack(operation, guard):
            write(operation, guard)
            raise sqlite3.OperationalError("fixture_receipt_commit_ack_lost")

        with patch.object(self.store, "_connection", traced_connection), \
                patch.object(case.entry.job, "close", wraps=case.entry.job.close) as close_job, \
                patch.object(case.entry.mutex, "close", wraps=case.entry.mutex.close) as close_mutex:
            with patch.object(PrelaunchReceiptOperation, "_write", lost_ack):
                first = self.close_pending(case)
            self.assertFalse(first["terminal"])
            operation = case.entry.retirement_receipt_operation
            guard = operation.guard
            self.assertIsNotNone(guard)
            self.assertTrue(operation.pending)
            self.assertIsNotNone(operation._error)
            self.assertEqual(self.runtime()["policy_entry_nonce"], guard.nonce)
            persisted = self.receipt_rows()
            self.assertEqual(len(persisted), 1)
            used, hold = [], self.store._policy.hold

            @contextmanager
            def record_hold(value):
                used.append(value)
                with hold(value):
                    yield value

            with patch.object(self.store._policy, "prepare", side_effect=AssertionError("replacement guard")), \
                    patch.object(self.store._policy, "hold", record_hold), self.forbid_native_reentry(case):
                self.assertTrue(self.close_pending(case)["terminal"])
            close_job.assert_called_once()
            close_mutex.assert_called_once()
        self.assertEqual(used, [guard])
        self.assertEqual(self.receipt_rows(), persisted)
        inserts = [sql for sql in statements if sql.lstrip().upper().startswith("INSERT INTO " + TABLE.upper())]
        self.assertEqual(len(inserts), 1, inserts)
        self.assertIsNone(operation.guard)
        self.assertFalse(operation.pending)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        self.assertEqual(self.processes.events.count(("close", case.wrapper_handle)), 1)
        self.assertNotIn(case.snapshot.execution_id, self.owner.retained_execution_ids)

    def test_cleared_nonce_lost_ack_reconciles_without_replacing_guard_or_reclosing(self):
        case = self.terminal_case(never_created=True)
        clear = self.store._policy._clear

        def lost_ack(guard):
            clear(guard)
            if self.receipt_rows():
                raise sqlite3.OperationalError("fixture_receipt_nonce_ack_lost")

        with patch.object(self.store._policy, "_clear", lost_ack):
            self.assertFalse(self.close_pending(case)["terminal"])
        operation = case.entry.retirement_receipt_operation
        self.assertIsNotNone(operation.guard)
        self.assertIsNone(self.runtime()["policy_entry_nonce"])
        persisted = self.receipt_rows()
        self.assertEqual(len(persisted), 1)
        with patch.object(self.store._policy, "prepare", side_effect=AssertionError("replacement guard")), \
                self.forbid_native_reentry(case):
            self.assertTrue(self.close_pending(case)["terminal"])
        self.assertEqual(self.receipt_rows(), persisted)
        self.assertEqual(self.processes.events.count(("close", case.wrapper_handle)), 1)

    def test_finished_dispatch_preserves_existing_terminal_receipt_contract(self):
        row = {"state": "FINISHED"}
        expected = {"verified": "existing-terminal-reader"}
        with patch("sentinel.adaptive.terminal_receipt.assert_terminal_custody_receipt",
                return_value=expected) as reader:
            self.assertIs(assert_closed_custody_receipt(self.store, self.journal, row), expected)
        reader.assert_called_once_with(self.store, self.journal, row)


if __name__ == "__main__":
    unittest.main()
