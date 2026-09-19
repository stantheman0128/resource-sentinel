"""Actual isolated ledger coverage; synthetic self identity is only L1 evidence.

No Job/control/host-cohort readiness is exercised. Corruption cases deliberately
change this test's private database, never a daily ledger or its policy.
"""
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus
from sentinel.adaptive.store import LifecycleError, LifecycleStore, hold_expired_allocations
from sentinel.adaptive import store as store_module
from sentinel.accounting import update_demand_floor
from sentinel.coordinator import Coordinator
from tests import test_adaptive_managed_admission as fixtures
from tests.test_adaptive_coordinator import NOW, status
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_execution_owner import SyntheticNative, SyntheticRuntimeAuthority
from tests.windows import adaptive_execution


class AdaptiveLedgerCoverageTests(unittest.TestCase):
    context = fixtures.ManagedAdmissionTests.context
    conn = fixtures.ManagedAdmissionTests.conn
    admit = fixtures.ManagedAdmissionTests.admit

    def setUp(self):
        fixtures.ManagedAdmissionTests.setUp(self)
        self.admission = self.context()
        self.result = self.admit(self.admission)
        self.assertTrue(self.result["allowed"])
        self.store = LifecycleStore(self.coordinator.db_path)
        self.execution_id = self.admission.snapshot().execution_id

    def row(self):
        return self.store.query(self.execution_id)

    def allocation(self):
        return dict(self.conn().execute("SELECT * FROM reservations WHERE id=?",
                                       (self.result["reservation_id"],)).fetchone())

    def assert_covered(self, row=None):
        self.assertIsNone(self.store.assert_admission_covered(self.admission, self.row() if row is None else row))

    def test_real_admission_is_covered_without_new_permission_or_any_write(self):
        before, allocation = self.row(), self.allocation()
        self.assert_covered(before)
        self.assertEqual(self.row(), before)
        self.assertEqual(self.allocation(), allocation)
        self.assertEqual(self.conn().execute("SELECT count(*) FROM reservations").fetchone()[0], 1)

    def test_snapshot_for_ledger_requires_prior_submission_and_exact_path(self):
        unused = self.context()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_not_submitted"):
            unused.snapshot_for_ledger(self.coordinator.db_path)
        other = Coordinator(self.directory / "other", pid_identity=lambda pid: (None, 0.0))
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_ledger_mismatch"):
            self.admission.snapshot_for_ledger(other.db_path)
        expected = self.admission.snapshot()
        alias = self.directory / "other" / ".." / "sentinel.db"
        self.assertEqual(self.admission.snapshot_for_ledger(alias), expected)
        self.assertEqual(self.row()["state"], "RESERVED")

    def test_wrong_store_rejects_before_opening_a_coverage_transaction(self):
        other = Coordinator(self.directory / "other", pid_identity=lambda pid: (None, 0.0))
        wrong = LifecycleStore(other.db_path)
        with patch.object(store_module, "_coverage_read_transaction") as opened:
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_ledger_mismatch"):
                wrong.assert_admission_covered(self.admission, self.row())
        opened.assert_not_called()

    def test_same_canonical_path_survives_cwd_change_between_binding_and_read(self):
        expected = self.row()
        other = Coordinator(self.directory / "other", pid_identity=lambda pid: (None, 0.0))
        canonical = Path(self.coordinator.db_path).resolve()
        selected = []
        verify = self.admission.snapshot_for_ledger
        reader = store_module._coverage_read_transaction
        def verify_then_change_cwd(path):
            selected.append(path)
            snapshot = verify(path)
            os.chdir(other.data_dir)
            return snapshot
        def read_same_path(path):
            selected.append(path)
            return reader(path)
        previous_cwd, previous_path = Path.cwd(), self.store.db_path
        try:
            os.chdir(self.directory)
            self.store.db_path = Path("sentinel.db")
            with patch.object(self.admission, "snapshot_for_ledger", side_effect=verify_then_change_cwd), \
                    patch.object(store_module, "_coverage_read_transaction", side_effect=read_same_path):
                self.assert_covered(expected)
        finally:
            os.chdir(previous_cwd)
            self.store.db_path = previous_path
        self.assertEqual(selected, [canonical, canonical])
        self.assertIs(selected[0], selected[1])
        self.assertTrue(selected[0].is_absolute())

    def test_queued_context_is_not_a_retained_allocation(self):
        queued = self.context()
        result = self.admit(queued, status(commit=94))
        self.assertFalse(result["allowed"])
        expected = self.row() | {"execution_id": queued.snapshot().execution_id}
        with self.assertRaisesRegex(LifecycleError, "execution_not_found"):
            self.store.assert_admission_covered(queued, expected)

    def test_live_identity_is_reverified_and_unknown_cannot_read_as_covered(self):
        expected = self.row()
        before = self.process.observations
        self.assert_covered(expected)
        self.assertEqual(self.process.observations, before + 1)
        self.process.observed = IdentityObservation(self.process.identity, IdentityStatus.UNKNOWN, "fixture_query_failed")
        with patch.object(store_module, "_coverage_read_transaction") as opened:
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "wrapper_identity_not_alive"):
                self.store.assert_admission_covered(self.admission, expected)
        opened.assert_not_called()

    def test_closed_or_duck_typed_context_cannot_supply_coverage(self):
        expected = self.row()
        class Claim:
            def snapshot_for_ledger(inner, _):
                return self.admission.snapshot()
        with self.assertRaisesRegex(LifecycleError, "managed_admission_context_required"):
            self.store.assert_admission_covered(Claim(), expected)
        self.admission.close()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_closed"):
            self.store.assert_admission_covered(self.admission, expected)

    def test_failed_cancel_seals_launch_but_preserves_ledger_verification(self):
        self.conn().execute("""CREATE TRIGGER fixture_reject_cancel BEFORE UPDATE ON managed_executions
            WHEN NEW.state='CANCELLED_BEFORE_START'
            BEGIN SELECT RAISE(ABORT,'fixture_cancel_failed'); END""")
        with self.assertRaisesRegex(sqlite3.IntegrityError, "fixture_cancel_failed"):
            self.admission.cancel_reserved(self.coordinator.db_path,
                reservation_id=self.result["reservation_id"], expected_revision=0, now=NOW + 1)
        self.assertTrue(self.admission._cancel_sealed)
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_sealed"):
            self.admission.launch_claim_token()
        self.assertEqual(self.admission.snapshot_for_ledger(self.coordinator.db_path), self.admission.snapshot())
        self.assert_covered()

    def test_cancelled_context_can_verify_its_ledger_path_but_has_no_live_coverage(self):
        self.admission.cancel_reserved(self.coordinator.db_path,
            reservation_id=self.result["reservation_id"], expected_revision=0, now=NOW + 1)
        self.assertEqual(self.admission.snapshot_for_ledger(self.coordinator.db_path), self.admission.snapshot())
        with self.assertRaisesRegex(LifecycleError, "coverage_execution_terminal"):
            self.store.assert_admission_covered(self.admission, self.row())

    def test_missing_expected_fields_wrong_execution_and_stale_revision_rejected(self):
        expected = self.row()
        partial = dict(expected)
        partial.pop("job_nonce")
        for row, reason in ((partial, "coverage_expected_row_invalid"),
                            (expected | {"execution_id": str(uuid4())}, "coverage_expected_row_mismatch"),
                            (expected | {"state_revision": True}, "coverage_expected_row_mismatch"),
                            (expected | {"state_revision": 1}, "revision_conflict")):
            with self.subTest(reason=reason), self.assertRaisesRegex(LifecycleError, reason):
                self.store.assert_admission_covered(self.admission, row)

    def test_scope_or_state_changed_since_owner_read_cannot_be_accepted(self):
        expected = self.row()
        for changed in ({"job_name": "Local\\ResourceSentinel.Test.Job." + "a" * 32},
                        {"job_nonce": "a" * 32}, {"guardian_epoch": "another-guardian"},
                        {"launch_in_flight": 1}, {"state": "START_UNKNOWN"}):
            with self.subTest(field=next(iter(changed))):
                name, value = next(iter(changed.items()))
                self.conn().execute(f"UPDATE managed_executions SET {name}=? WHERE execution_id=?", (value, self.execution_id))
                with self.assertRaisesRegex(LifecycleError, "coverage_expected_row_mismatch"):
                    self.store.assert_admission_covered(self.admission, expected)
                self.conn().execute(f"UPDATE managed_executions SET {name}=? WHERE execution_id=?", (expected[name], self.execution_id))

    def test_immutable_binding_spec_identity_and_secret_mismatches_fail_after_fresh_read(self):
        original = dict(self.conn().execute("SELECT * FROM managed_executions WHERE execution_id=?", (self.execution_id,)).fetchone())
        for field, value in (("admission_binding_hash", "f" * 64), ("spec_hash", "e" * 64),
                             ("claim_token_hash", "d" * 64), ("ipc_auth_key", b"x" * 32),
                             ("wrapper_pid", self.process.identity.pid + 1),
                             ("wrapper_created_filetime_100ns", str(self.process.identity.created_filetime_100ns + 1)),
                             ("principal_id", "other-principal"), ("requested_commit_bytes", original["requested_commit_bytes"] + 1)):
            with self.subTest(field=field):
                self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?", (value, self.execution_id))
                with self.assertRaisesRegex(LifecycleError, "managed_admission_binding_mismatch"):
                    self.store.assert_admission_covered(self.admission, self.row())
                self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?", (original[field], self.execution_id))

    def test_allocation_request_and_owner_metadata_are_revalidated(self):
        original = self.allocation()
        for field, value in (("owner_pid", original["owner_pid"] + 1),
                             ("owner_started", original["owner_started"] + 1),
                             ("command_signature", "changed-signature"), ("repo", "changed-repo"),
                             ("request_key", "changed-request"), ("spec_hash", "a" * 64),
                             ("commit_bytes", original["commit_bytes"] + 1)):
            with self.subTest(field=field):
                self.conn().execute(f"UPDATE reservations SET {field}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                    (value, original["id"]))
                with self.assertRaises(LifecycleError):
                    self.store.assert_admission_covered(self.admission, self.row())
                self.conn().execute(f"UPDATE reservations SET {field}=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                    (original[field], original["id"]))

    def test_each_floor_must_remain_at_least_original_request(self):
        original = self.row()
        for resource in self.admission.snapshot().requested.to_dict():
            field = "floor_" + resource
            with self.subTest(resource=resource):
                self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?",
                                    (original[field] - 1, self.execution_id))
                with self.assertRaisesRegex(LifecycleError, "demand_floor_invalid"):
                    self.store.assert_admission_covered(self.admission, self.row())
                self.conn().execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?",
                                    (original[field], self.execution_id))

    def test_higher_floor_stays_covered_and_requires_the_new_revision(self):
        before = self.row()
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        update_demand_floor(conn, self.execution_id,
            {"commit_bytes": before["requested_commit_bytes"] + 4096}, expected_revision=0, valid=True, uncapped=False)
        conn.commit()
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.assert_admission_covered(self.admission, before)
        self.assert_covered()

    def test_expired_allocation_in_hold_still_has_coverage(self):
        before = self.allocation()
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        self.assertEqual(hold_expired_allocations(conn, "direct", NOW + 86400), 1)
        conn.commit()
        self.assertEqual(self.row()["state"], "UNCERTAIN_HOLD")
        self.assert_covered()
        self.assertEqual(self.allocation(), before)

    def test_start_unknown_covered_without_treating_allowed_as_liveness(self):
        # Synthetic lost-launch state is ledger fault input, not native proof.
        self.conn().execute("""UPDATE managed_executions SET state='LAUNCHING',claim_consumed=1,
            launch_in_flight=1,state_revision=state_revision+1 WHERE execution_id=?""", (self.execution_id,))
        conn = self.conn()
        conn.execute("BEGIN IMMEDIATE")
        hold_expired_allocations(conn, "direct", NOW + 86400)
        conn.commit()
        self.assertEqual(self.row()["state"], "START_UNKNOWN")
        self.assert_covered()
        self.assertEqual(self.row()["launch_in_flight"], 1)

    def test_missing_allocation_fails_even_when_row_and_context_match(self):
        # Model damaged storage, deliberately bypassing only this isolated DB's
        # release trigger. The production fence itself is tested separately.
        conn = self.conn()
        conn.execute("DROP TRIGGER adaptive_writer_reservations_delete")
        conn.execute("DELETE FROM reservations WHERE id=?", (self.result["reservation_id"],))
        with self.assertRaisesRegex(LifecycleError, "allocation_missing"):
            self.store.assert_admission_covered(self.admission, self.row())

    def test_second_routed_tag_cannot_duplicate_the_direct_allocation(self):
        # Malformed cross-ledger reference, with foreign-key checks disabled on
        # this private injection connection only. No native or worker is used.
        conn = self.conn()
        conn.execute("""INSERT INTO worker_reservations(id,task_id,worker_id,failure_domain,
            capacity_scope,capacity_pool,spec_hash,ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,
            expires_at,metadata_json,execution_id,lifecycle_managed,physical_bytes,commit_bytes,
            io_slots,writer_protocol,writer_revision)
            VALUES('corrupt-routed','corrupt-task','absent-worker','local','SHARED_POOL','local',
            'unused',0,0,0,?,?,?,'{}',?,1,0,0,0,1,0)""", (NOW, NOW, NOW + 120, self.execution_id))
        with self.assertRaisesRegex(LifecycleError, "coverage_allocation_not_unique"):
            self.store.assert_admission_covered(self.admission, self.row())

    def test_non_direct_and_terminal_rows_never_claim_live_direct_coverage(self):
        self.conn().execute("UPDATE managed_executions SET allocation_kind='routed' WHERE execution_id=?", (self.execution_id,))
        with self.assertRaisesRegex(LifecycleError, "coverage_direct_allocation_required"):
            self.store.assert_admission_covered(self.admission, self.row())
        self.conn().execute("UPDATE managed_executions SET allocation_kind='direct',state='FINISHED' WHERE execution_id=?", (self.execution_id,))
        with self.assertRaisesRegex(LifecycleError, "coverage_execution_terminal"):
            self.store.assert_admission_covered(self.admission, self.row())

    def test_one_read_only_connection_and_no_identity_queries_inside_sqlite(self):
        expected, events, connections = self.row(), [], []
        real_connect, real_observe = sqlite3.connect, self.process.observe
        def observed():
            events.append("identity")
            return real_observe()
        def connect(*args, **kwargs):
            events.append("connect")
            self.assertTrue(args[0].endswith("?mode=ro"))
            self.assertTrue(kwargs["uri"])
            conn = real_connect(*args, **kwargs)
            conn.set_trace_callback(events.append)
            connections.append(conn)
            return conn
        with patch.object(self.process, "observe", side_effect=observed), patch.object(store_module.sqlite3, "connect", side_effect=connect):
            self.assert_covered(expected)
        self.assertEqual(events[:2], ["identity", "connect"])
        self.assertEqual(events.count("identity"), 1)
        self.assertEqual(events.count("BEGIN"), 1)
        self.assertEqual(len(connections), 1)
        self.assertFalse(any(sql.startswith(("UPDATE ", "INSERT ", "DELETE ", "ALTER ", "CREATE ", "COMMIT")) for sql in events))
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0].execute("SELECT 1")

    def test_same_snapshot_is_used_when_an_allocation_changes_during_verification(self):
        expected = self.row()
        retry = store_module.retry_managed_admission
        def writer_after_execution_read(conn, snapshot, **kwargs):
            with closing(sqlite3.connect(self.coordinator.db_path, isolation_level=None)) as writer:
                writer.execute("UPDATE reservations SET owner_pid=owner_pid+1,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                               (self.result["reservation_id"],))
            return retry(conn, snapshot, **kwargs)
        with patch.object(store_module, "retry_managed_admission", side_effect=writer_after_execution_read):
            self.assert_covered(expected)
        with self.assertRaisesRegex(LifecycleError, "coverage_allocation_binding_mismatch"):
            self.store.assert_admission_covered(self.admission, expected)

    def test_owner_always_passing_host_callback_cannot_hide_missing_allocation_before_create(self):
        events = []
        authority = SyntheticRuntimeAuthority(events)
        authority.assert_covered = lambda *_: events.append("host_always_passes")
        native = SyntheticNative(self.process.identity, events)
        directory = self.directory / "owner-journal"
        directory.mkdir()
        self.conn().execute("DROP TRIGGER adaptive_writer_reservations_delete")
        self.conn().execute("DELETE FROM reservations WHERE id=?", (self.result["reservation_id"],))
        with self.assertRaisesRegex(LifecycleError, "allocation_missing"):
            adaptive_execution.S1ExecutionOwner(admission=self.admission, store=self.store,
                authority=authority, directory=directory, native=native)
        self.assertEqual(native.create_calls, 0)
        self.assertNotIn("host_always_passes", events)
        self.assertNotIn("job.set_cpu", events)

    def test_owner_real_coverage_rejects_changed_binding_before_control_callback_or_set(self):
        events = []
        authority = SyntheticRuntimeAuthority(events)
        authority.assert_covered = lambda *_: events.append("host_always_passes")
        native = SyntheticNative(self.process.identity, events)
        directory = self.directory / "owner-journal"
        directory.mkdir()
        store = LifecycleStore(self.coordinator.db_path,
            policy_provider=FixturePolicyProvider(self.process.identity.logon_id))
        owner = adaptive_execution.S1ExecutionOwner(admission=self.admission, store=store,
            authority=authority, directory=directory, native=native)
        # Retained objects are explicitly synthetic. Release only this fixture
        # reference after failure assertions; no native custody is discarded.
        self.addCleanup(adaptive_execution._RETAINED_OWNERS.pop, self.execution_id, None)
        owner.prepare()
        self.assertEqual(native.create_calls, 1)
        events.clear()
        self.conn().execute("UPDATE reservations SET request_key='changed-after-prepare',writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                            (self.result["reservation_id"],))
        with self.assertRaisesRegex(LifecycleError, "managed_admission_binding_mismatch"):
            owner.set_cpu_rate(2500)
        self.assertNotIn("host_always_passes", events)
        self.assertNotIn("runtime.authorize_control", events)
        self.assertNotIn("job.set_cpu", events)


if __name__ == "__main__":
    unittest.main()
