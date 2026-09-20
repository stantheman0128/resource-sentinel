"""Unused-credential cancellation with isolated SQLite and native self identity.

The native smoke proves this local pre-handoff path only, never Job readiness.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive.admission import ManagedAdmission, ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.store import (
    LifecycleError, LifecycleEvidence, LifecycleStore, prelaunch_record_hash,
)
from sentinel.coordinator import Coordinator
from sentinel.accounting import update_demand_floor
from tests import test_adaptive_managed_admission as fixtures
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import NOW


class NativeCancelProtocolTests(unittest.TestCase):
    setUp = fixtures.ManagedAdmissionTests.setUp
    context = fixtures.ManagedAdmissionTests.context
    conn = fixtures.ManagedAdmissionTests.conn
    admit = fixtures.ManagedAdmissionTests.admit
    counts = fixtures.ManagedAdmissionTests.counts

    def admitted(self):
        context = self.context()
        admitted = self.admit(context)
        self.assertTrue(admitted["allowed"], admitted)
        return context, admitted

    def cancel(self, context, admitted, **overrides):
        arguments = dict(reservation_id=admitted["reservation_id"],
                         expected_revision=admitted["state_revision"], now=NOW + 1)
        return context.cancel_reserved(self.coordinator.db_path, **(arguments | overrides))

    def assert_sealed(self, context):
        for operation in (context.launch_claim_token,
                          lambda: context.begin_submission(db_path=self.coordinator.db_path),
                          lambda: context.verify_launch_payload(command=PAYLOAD["command"], cwd=PAYLOAD["cwd"])):
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_sealed"):
                operation()
        self.assertIsNone(context._claim_token)
        self.assertIsNone(context._key)

    def test_unused_claim_cancellation_releases_exact_allocation_and_terminal_replays(self):
        context, admitted = self.admitted()
        token_hash = context.snapshot().claim_token_hash
        first = self.cancel(context, admitted)
        self.assertEqual(first["state"], "CANCELLED_BEFORE_START")
        self.assertTrue(first["cancelled"])
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assert_sealed(context)
        replay = self.cancel(context, admitted)
        self.assertEqual(replay, first)
        self.assertEqual(context.snapshot().claim_token_hash, token_hash)
        self.assertEqual(self.conn().execute("SELECT count(*) FROM executions").fetchone()[0], 1)
        self.assertEqual(self.conn().execute("SELECT claim_token_hash FROM managed_executions").fetchone()[0], "")

    def test_exported_claim_cannot_use_local_cancellation_even_when_database_is_reserved(self):
        context, admitted = self.admitted()
        token = context.launch_claim_token()
        self.assertTrue(context._claim_exported)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "launch_claim_already_exported"):
            self.cancel(context, admitted)
        self.assertEqual(context.launch_claim_token(), token)
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertFalse(context._cancel_sealed)

    def test_database_backup_cannot_become_first_cancel_target_or_resubmission_ledger(self):
        context, admitted = self.admitted()
        copied = self.directory / "copied-sentinel.db"
        with closing(sqlite3.connect(copied)) as destination:
            self.conn().backup(destination)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_ledger_mismatch"):
            context.cancel_reserved(copied, reservation_id=admitted["reservation_id"],
                                    expected_revision=0, now=NOW + 1)
        self.assertFalse(context._cancel_sealed)
        self.assertIsNone(context._cancel_target)
        self.assertIsNotNone(context._claim_token)
        copied_coordinator = Coordinator(self.directory, db_path=copied, pid_identity=lambda pid: (None, 0.0),
                                         policy_provider=self.policy)
        from tests.test_adaptive_coordinator import CONFIG, status
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_ledger_mismatch"):
            copied_coordinator.admit_managed(context, status(now=NOW), config=CONFIG, now=NOW)
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertTrue(self.cancel(context, admitted)["cancelled"])
        self.assertEqual(self.counts(), (0, 0, 1))
        with closing(sqlite3.connect(copied)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_wrong_reservation_or_immutable_row_binding_is_rejected(self):
        context, admitted = self.admitted()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_binding_mismatch"):
            self.cancel(context, admitted, reservation_id="not-the-returned-reservation")
        conn = self.conn()
        original = dict(conn.execute("SELECT * FROM managed_executions").fetchone())
        changes = {"admission_binding_hash": "b" * 64, "spec_hash": "c" * 64,
                   "task_id": "different-task", "session_id": "different-session",
                   "principal_id": "different-principal", "wrapper_pid": original["wrapper_pid"] + 1,
                   "requested_commit_bytes": original["requested_commit_bytes"] + 1,
                   "role": "neutral", "priority": "P3"}
        for name, value in changes.items():
            with self.subTest(field=name):
                conn.execute(f"UPDATE managed_executions SET {name}=?", (value,))
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_binding_mismatch"):
                    self.cancel(context, admitted)
                conn.execute(f"UPDATE managed_executions SET {name}=?", (original[name],))
        self.assertFalse(context._cancel_sealed)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_job_guardian_root_claim_and_nonreserved_states_are_not_this_scope(self):
        context, admitted = self.admitted()
        conn = self.conn()
        changes = (("job_name", "Local\\NotOurScope"), ("guardian_epoch", "another-guardian"),
                   ("claim_consumed", 1), ("launch_in_flight", 1), ("launch_sealed", 1),
                   ("state", "PREPARED"), ("state", "UNCERTAIN_HOLD"), ("allocation_kind", "routed"))
        original = dict(conn.execute("SELECT * FROM managed_executions").fetchone())
        for name, value in changes:
            with self.subTest(field=name, value=value):
                conn.execute(f"UPDATE managed_executions SET {name}=?", (value,))
                with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_binding_mismatch"):
                    self.cancel(context, admitted)
                conn.execute(f"UPDATE managed_executions SET {name}=?", (original[name],))
        conn.execute("UPDATE managed_executions SET root_pid=123,root_created_filetime_100ns='134343072000000001'")
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_binding_mismatch"):
            self.cancel(context, admitted)
        self.assertFalse(context._cancel_sealed)

    def test_allocation_binding_and_native_identity_must_match_before_sealing(self):
        context, admitted = self.admitted()
        conn = self.conn()
        original = dict(conn.execute("SELECT * FROM reservations").fetchone())
        for name, value in {"request_key": "wrong", "owner_pid": original["owner_pid"] + 1,
                            "spec_hash": "b" * 64, "commit_bytes": original["commit_bytes"] + 1}.items():
            with self.subTest(field=name):
                # Deliberately model a SQL writer that knows the compatibility
                # protocol. Its marker grants no native/cancellation authority.
                update = (f"UPDATE reservations SET {name}=?,writer_protocol=1,"
                          "writer_revision=writer_revision+1 WHERE id=?")
                try:
                    conn.execute(update, (value, admitted["reservation_id"]))
                    with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_allocation_mismatch"):
                        self.cancel(context, admitted)
                finally:
                    conn.execute(update, (original[name], admitted["reservation_id"]))
        actual = self.process.observed
        self.process.observed = IdentityObservation(actual.identity, IdentityStatus.UNKNOWN, "query_failed")
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
            self.cancel(context, admitted)
        self.process.observed = replace(actual, identity=replace(actual.identity,
            created_filetime_100ns=actual.identity.created_filetime_100ns + 1))
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_mismatch"):
            self.cancel(context, admitted)
        self.process.observed = actual
        with patch("sentinel.adaptive.admission.os.getpid", return_value=os.getpid() + 1):
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_is_not_current_process"):
                self.cancel(context, admitted)
        self.assertFalse(context._cancel_sealed)

    def test_failed_transaction_retains_seal_and_same_cancellation_can_retry(self):
        context, admitted = self.admitted()
        conn = self.conn()
        conn.execute("CREATE TRIGGER refuse_cancel BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'cancel rollback'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cancel rollback"):
            self.cancel(context, admitted)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (0, 1, 1))
        self.assertEqual(conn.execute("SELECT state FROM managed_executions").fetchone()[0], "RESERVED")
        conn.execute("DROP TRIGGER refuse_cancel")
        self.assertTrue(self.cancel(context, admitted)["cancelled"])
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_lost_ack_after_cancel_commit_replays_original_revision_without_new_authority(self):
        context, admitted = self.admitted()
        cancel = LifecycleStore.cancel_before_start

        def lose_ack(store, *args, **kwargs):
            cancel(store, *args, **kwargs)
            raise OSError("reply lost")

        with patch.object(LifecycleStore, "cancel_before_start", lose_ack):
            with self.assertRaisesRegex(OSError, "reply lost"):
                self.cancel(context, admitted)
        self.assert_sealed(context)
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assertTrue(self.cancel(context, admitted)["cancelled"])
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_revision_mismatch"):
            self.cancel(context, admitted, expected_revision=99)

    def test_floor_revision_after_rollback_preserves_latest_cancellation_lost_ack_replay(self):
        context, admitted = self.admitted()
        conn = self.conn()
        conn.execute("CREATE TRIGGER refuse_cancel BEFORE DELETE ON reservations BEGIN SELECT RAISE(ABORT,'cancel rollback'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cancel rollback"):
            self.cancel(context, admitted)
        self.assert_sealed(context)
        self.assertEqual(context._cancel_revision, 0)
        conn.execute("DROP TRIGGER refuse_cancel")
        raised_cpu = context.snapshot().requested.cpu_units + 1
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            floor = update_demand_floor(conn, admitted["execution_id"],
                {"cpu_units": raised_cpu},
                expected_revision=0, valid=True, uncapped=True)
        self.assertEqual(floor["cpu_units"], raised_cpu)
        self.assertEqual(conn.execute("SELECT state_revision FROM managed_executions").fetchone()[0], 1)
        cancel = LifecycleStore.cancel_before_start

        def lose_ack(store, *args, **kwargs):
            cancel(store, *args, **kwargs)
            raise OSError("reply lost after revised cancellation")

        with patch.object(LifecycleStore, "cancel_before_start", lose_ack):
            with self.assertRaisesRegex(OSError, "reply lost after revised cancellation"):
                self.cancel(context, admitted, expected_revision=1)
        self.assert_sealed(context)
        self.assertEqual(context._cancel_revision, 1)
        replay = self.cancel(context, admitted, expected_revision=1)
        self.assertTrue(replay["cancelled"])
        self.assertEqual(replay["state_revision"], 2)
        self.assertEqual(self.counts(), (0, 0, 1))
        self.assertEqual(conn.execute("SELECT count(*) FROM executions").fetchone()[0], 1)

    def test_metadata_claim_or_allocation_race_without_revision_cannot_release(self):
        mutations = (("managed_executions", "admission_binding_hash", "b" * 64),
                     ("managed_executions", "claim_token_hash", "c" * 64),
                     ("managed_executions", "claim_consumed", 1),
                     ("reservations", "request_key", "changed-after-proof"),
                     ("reservations", "owner_pid", 999),
                     ("reservations", "spec_hash", "d" * 64))
        for table, field, value in mutations:
            with self.subTest(table=table, field=field):
                context, admitted = self.admitted()
                conn = self.conn()
                identifier = "execution_id" if table == "managed_executions" else "id"
                target = admitted["execution_id"] if table == "managed_executions" else admitted["reservation_id"]
                original = conn.execute(f"SELECT {field} FROM {table} WHERE {identifier}=?", (target,)).fetchone()[0]
                enter_transaction = LifecycleStore._transaction
                # This adversarial writer knows the SQL compatibility marker;
                # it still cannot bypass the immutable prelaunch digest. Only
                # writer_revision advances, never the lifecycle state_revision.
                writer_stamp = (",writer_protocol=1,writer_revision=writer_revision+1"
                                if table == "reservations" else "")
                update = f"UPDATE {table} SET {field}=?{writer_stamp} WHERE {identifier}=?"

                from contextlib import contextmanager
                @contextmanager
                def change_after_proof(store):
                    # The credential has already been sealed; mutation wins
                    # before BEGIN without incrementing lifecycle revision.
                    self.assertTrue(context._cancel_sealed)
                    conn.execute(update, (value, target))
                    with enter_transaction(store) as transaction:
                        yield transaction

                try:
                    with patch.object(LifecycleStore, "_transaction", change_after_proof):
                        with self.assertRaises(LifecycleError):
                            self.cancel(context, admitted)
                    self.assert_sealed(context)
                    self.assertIsNotNone(conn.execute("SELECT 1 FROM reservations WHERE id=?", (admitted["reservation_id"],)).fetchone())
                finally:
                    # Each subtest owns this exact reservation. Restore its
                    # fixture binding and cancel it before the next admission,
                    # even when an assertion fails, avoiding cascading I/O waits.
                    conn.execute(update, (original, target))
                    self.cancel(context, admitted)

    def test_heartbeat_and_deadline_refresh_do_not_invalidate_unused_claim_proof(self):
        context, admitted = self.admitted()
        conn = self.conn()
        enter_transaction = LifecycleStore._transaction

        from contextlib import contextmanager
        @contextmanager
        def heartbeat_after_proof(store):
            self.assertTrue(context._cancel_sealed)
            conn.execute("UPDATE managed_executions SET heartbeat_at=heartbeat_at+10")
            # A compatible heartbeat advances SQL bookkeeping without changing
            # launch custody; the proof excludes writer_revision, not protocol.
            conn.execute("""UPDATE reservations SET heartbeat_at=heartbeat_at+10,expires_at=?,
                writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?""",
                (NOW - 1, admitted["reservation_id"]))
            with enter_transaction(store) as transaction:
                yield transaction

        with patch.object(LifecycleStore, "_transaction", heartbeat_after_proof):
            self.assertTrue(self.cancel(context, admitted)["cancelled"])
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_native_queries_happen_before_sqlite_writer_transaction(self):
        context, admitted = self.admitted()
        observed = self.process.observe

        def unlocked_native_query():
            with closing(sqlite3.connect(self.coordinator.db_path, timeout=0,
                                         isolation_level=None)) as probe:
                probe.execute("BEGIN IMMEDIATE")
                probe.rollback()
            return observed()

        with patch.object(self.process, "observe", unlocked_native_query):
            self.assertTrue(self.cancel(context, admitted)["cancelled"])

    def test_prelaunch_digest_rejects_malformed_private_hash_or_noncanonical_values(self):
        for claim_hash, allocation in (("not-a-hash", {}), ("g" * 64, {}),
                                        ("a" * 64, {"private": float("nan")}),
                                        ("a" * 64, {"private": object()})):
            with self.subTest(claim_hash=claim_hash, allocation_type=type(allocation).__name__):
                with self.assertRaisesRegex(LifecycleError, "^invalid_prelaunch_record$"):
                    prelaunch_record_hash({}, claim_token_hash=claim_hash, allocation=allocation)

    def test_prelaunch_digest_contract_is_optional_only_for_cancel_and_requires_sha256(self):
        snapshot = self.context().snapshot()
        args = ("cancel", snapshot.execution_id, 0, "contract-only", snapshot.wrapper_identity)
        proof = LifecycleEvidence(*args, prelaunch_record_hash="a" * 64)
        self.assertEqual(proof.prelaunch_record_hash, "a" * 64)
        for digest in ("a" * 63, "G" * 64, 123):
            with self.subTest(digest=digest), self.assertRaisesRegex(ValueError, "invalid_prelaunch_record_hash"):
                LifecycleEvidence(*args, prelaunch_record_hash=digest)
        with self.assertRaisesRegex(ValueError, "invalid_prelaunch_record_hash"):
            LifecycleEvidence("prepare", *args[1:], prelaunch_record_hash="a" * 64)

    def test_cancel_keeps_export_and_close_serialized_until_transaction_finishes(self):
        for competing_action in ("export", "close"):
            with self.subTest(competing_action=competing_action):
                context, admitted = self.admitted()
                inside = threading.Event()
                continue_cancel = threading.Event()
                competitor_entered = threading.Event()
                archive = LifecycleStore._archive_allocation

                def pause_archive(conn, row, now, **kwargs):
                    inside.set()
                    if not continue_cancel.wait(timeout=5):
                        raise RuntimeError("test cancellation wait expired")
                    return archive(conn, row, now, **kwargs)

                def compete():
                    competitor_entered.set()
                    if competing_action == "export":
                        return context.launch_claim_token()
                    return context.close()

                with patch.object(LifecycleStore, "_archive_allocation", staticmethod(pause_archive)):
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        cancelled = pool.submit(self.cancel, context, admitted)
                        try:
                            self.assertTrue(inside.wait(timeout=5))
                            competitor = pool.submit(compete)
                            self.assertTrue(competitor_entered.wait(timeout=5))
                            self.assertFalse(competitor.done())
                        finally:
                            continue_cancel.set()
                        self.assertTrue(cancelled.result(timeout=5)["cancelled"])
                        if competing_action == "export":
                            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_sealed"):
                                competitor.result(timeout=5)
                        else:
                            self.assertIsNone(competitor.result(timeout=5))
                self.assertEqual(self.counts()[1], 0)

    def test_closed_context_cannot_release_its_allocation(self):
        context, admitted = self.admitted()
        context.close()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            self.cancel(context, admitted)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_changed_cancel_target_cannot_release_another_allocation(self):
        context, admitted = self.admitted()
        self.cancel(context, admitted)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "reserved_cancel_target_mismatch"):
            self.cancel(context, admitted, reservation_id="another-reservation")


@unittest.skipUnless(os.name == "nt", "native self cancellation requires Windows")
class NativeReservedCancellationSmokeTests(unittest.TestCase):
    admit = fixtures.ManagedAdmissionTests.admit

    def test_real_retained_self_identity_cancels_only_unused_direct_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            self.coordinator = Coordinator(Path(directory), pid_identity=lambda pid: (None, 0.0))
            with ManagedAdmission.current(**PAYLOAD) as context:
                snapshot = context.snapshot()
                self.assertEqual(snapshot.wrapper_identity.pid, os.getpid())
                admitted = self.admit(context)
                self.assertTrue(admitted["allowed"], admitted)
                cancelled = context.cancel_reserved(self.coordinator.db_path,
                    reservation_id=admitted["reservation_id"], expected_revision=admitted["state_revision"], now=NOW + 1)
                self.assertTrue(cancelled["cancelled"])
                self.assertEqual(cancelled["state"], "CANCELLED_BEFORE_START")
                with closing(sqlite3.connect(self.coordinator.db_path)) as conn:
                    self.assertEqual(conn.execute("SELECT count(*) FROM reservations").fetchone()[0], 0)
                    self.assertEqual(conn.execute("SELECT count(*) FROM executions").fetchone()[0], 1)
                    self.assertEqual(conn.execute("SELECT mode FROM adaptive_runtime").fetchone()[0], "off")


if __name__ == "__main__":
    unittest.main()
