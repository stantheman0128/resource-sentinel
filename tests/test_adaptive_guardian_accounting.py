"""Portable retained-ledger tests; synthetic fences prove no native behavior."""
from contextlib import contextmanager, nullcontext
from dataclasses import fields, replace
import sqlite3
import threading
import unittest
from unittest.mock import patch
import uuid

from sentinel.adaptive import store as store_module
from sentinel.adaptive.contracts import (
    AllocationKind, CpuControl, CpuControlMode, ProcessIdentity,
    RecoveryManifest, ReservationRef, ResourceDemand,
)
from sentinel.adaptive.store import LifecycleError, LifecycleEvidence, LifecycleStore
from tests import test_adaptive_lifecycle as lifecycle_fixture


NOW = lifecycle_fixture.NOW
WRAPPER = lifecycle_fixture.WRAPPER
ROOT = lifecycle_fixture.ROOT
GUARDIAN = ProcessIdentity(303, WRAPPER.created_filetime_100ns + 100, WRAPPER.logon_id)
DISABLED = CpuControl(CpuControlMode.DISABLED, None)
RESOURCE_KEYS = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")


class GuardianEvidence:
    """Retains an actual Python lock plus the explicit fixture POLICY scope."""

    def __init__(self, case):
        self.case = case
        self.lock = threading.Lock()
        self.owner = None
        self.active = False
        self.events = []
        self.overrides = {}
        self.before_yield = None
        self.with_policy = True

    def assert_held(self):
        self.case.assertTrue(self.active)
        self.case.assertTrue(self.lock.locked())
        self.case.assertEqual(self.owner, threading.get_ident())
        self.case.store._policy.assert_held()
        self.case.assertTrue(self.case.policy.active)

    def probe_writer_available(self):
        conn = sqlite3.connect(self.case.db, timeout=0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        finally:
            conn.close()

    @contextmanager
    def __call__(self, operation, row, caller):
        self.probe_writer_available()
        scope = self.case.store._publication_scope(caller) if self.with_policy else nullcontext()
        with scope:
            with self.lock:
                self.active = True
                self.owner = threading.get_ident()
                self.events.append("enter")
                try:
                    root = None if row["root_pid"] is None else ProcessIdentity(
                        row["root_pid"], int(row["root_created_filetime_100ns"]), row["logon_id"])
                    proof = LifecycleEvidence(
                        operation, row["execution_id"], row["state_revision"], "guardian-fixture",
                        GUARDIAN if operation == "heartbeat" else caller,
                        guardian_epoch=row["guardian_epoch"], job_name=row["job_name"],
                        job_nonce=row["job_nonce"], root=root,
                        active_process_count=0 if root is None else 1,
                        process_ids=() if root is None else (root.pid,),
                        launch_sealed=bool(row["launch_sealed"]), durable_manifest=True,
                        current_cpu_disabled=True, recovery_manifest_settled=True,
                    )
                    proof = replace(proof, **self.overrides)
                    if self.before_yield is not None:
                        self.before_yield()
                    yield proof
                finally:
                    # SQLite must already have committed/rolled back and closed.
                    self.probe_writer_available()
                    self.events.append("exit")
                    self.active = False
                    self.owner = None


class AdaptiveGuardianAccountingTests(unittest.TestCase):
    # Reuse setup helpers without inheriting/discovering the lifecycle suite.
    connection = lifecycle_fixture.AdaptiveLifecycleTests.connection
    spec = lifecycle_fixture.AdaptiveLifecycleTests.spec
    allocate = lifecycle_fixture.AdaptiveLifecycleTests.allocate
    registered = lifecycle_fixture.AdaptiveLifecycleTests.registered

    def setUp(self):
        lifecycle_fixture.AdaptiveLifecycleTests.setUp(self)
        self.registration_provider = self.store.evidence_provider
        self.evidence = GuardianEvidence(self)

    def enrolled(self, kind=AllocationKind.DIRECT, state="RUNNING"):
        self.store.evidence_provider = self.registration_provider
        spec, registered = self.registered(self.spec(kind=kind))
        row = self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        row = self.store.claim_launch(spec.execution_id, caller=WRAPPER,
            expected_revision=row["state_revision"], claim_token=registered["claim_token"],
            spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        if state == "START_UNKNOWN":
            row = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="launch_ack_lost")
        else:
            row = self.store.bind_root(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"])
            if state == "UNCERTAIN_HOLD":
                row = self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="heartbeat_lost")
            elif state == "DRAINING":
                row = self.store.mark_root_exited(spec.execution_id, caller=WRAPPER,
                    expected_revision=row["state_revision"], exit_code=0)
        nonce = uuid.uuid4().hex
        job_name = f"Local\\ResourceSentinel.Job.{spec.execution_id}.{nonce}"
        self.connection().execute("UPDATE managed_executions SET job_name=?,job_nonce=? WHERE execution_id=?",
                                  (job_name, nonce, spec.execution_id))
        row = self.store.query(spec.execution_id)
        root = None if row["root_pid"] is None else ROOT
        manifest = RecoveryManifest.create(
            execution_id=spec.execution_id, reservation=spec.reservation, spec_hash=spec.spec_hash,
            job_name=job_name, creation_nonce=nonce, wrapper_identity=WRAPPER,
            root_identity=root, guardian_identity=GUARDIAN, guardian_epoch=row["guardian_epoch"],
            original=DISABLED, last_applied=None, pending_intent=None,
            allocated_floor=ResourceDemand(**{name: row["floor_" + name] for name in RESOURCE_KEYS}),
            manifest_seq=0,
        )
        self.store.evidence_provider = self.evidence
        return row, manifest

    @staticmethod
    def changed_manifest(manifest, **updates):
        values = {field.name: getattr(manifest, field.name) for field in fields(manifest)
                  if field.name != "manifest_hash"}
        values.update(updates)
        values["job_name"] = f"Local\\ResourceSentinel.Job.{values['execution_id']}.{values['creation_nonce']}"
        return RecoveryManifest.create(**values)

    def custody(self):
        conn = self.connection()
        return {table: tuple(tuple(row) for row in conn.execute(f"SELECT * FROM {table} ORDER BY rowid"))
                for table in ("adaptive_runtime", "managed_executions", "reservations",
                              "worker_reservations", "workers", "executions", "routed_executions")}

    def allocation(self, row):
        table = "reservations" if row["allocation_kind"] == "direct" else "worker_reservations"
        return dict(self.connection().execute(f"SELECT * FROM {table} WHERE id=?", (row["reservation_id"],)).fetchone())

    def damage(self, table, statement, values=()):
        # Deliberately corrupt only this temporary fixture's chosen source.
        conn = self.connection()
        triggers = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)).fetchall()
        for trigger in triggers:
            conn.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
        conn.execute(statement, values)

    def assert_denied_without_mutation(self, row, manifest, reason=None):
        before = self.custody()
        with self.assertRaises(LifecycleError) as error:
            self.store.assert_retained_allocation(row, manifest)
        if reason is not None:
            self.assertEqual(str(error.exception), reason)
        self.assertEqual(before, self.custody())
        # Catch expected refusal inside borrowed POLICY; do not reset a nonce.
        with self.store._publication_scope(GUARDIAN):
            before = self.custody()
            with self.assertRaises(LifecycleError):
                self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
            self.assertEqual(before, self.custody())

    @contextmanager
    def audited_writer(self):
        real_connect = sqlite3.connect
        evidence = self.evidence

        class AuditedConnection(sqlite3.Connection):
            def commit(self):
                evidence.assert_held()
                evidence.events.append("commit")
                return super().commit()

            def rollback(self):
                evidence.assert_held()
                evidence.events.append("rollback")
                return super().rollback()

            def close(self):
                evidence.assert_held()
                evidence.events.append("close")
                return super().close()

        def connect(target, *args, **kwargs):
            if isinstance(target, str) and target.endswith("?mode=rw"):
                kwargs["factory"] = AuditedConnection
            return real_connect(target, *args, **kwargs)

        with patch.object(store_module.sqlite3, "connect", side_effect=connect):
            yield

    def test_read_assertion_uses_read_only_connection_without_evidence_or_mutation(self):
        row, manifest = self.enrolled()
        before = self.custody()
        real_connect = sqlite3.connect
        calls, statements = [], []

        def connect(target, *args, **kwargs):
            calls.append((target, kwargs.get("uri")))
            conn = real_connect(target, *args, **kwargs)
            conn.set_trace_callback(statements.append)
            return conn

        with patch.object(self.store, "evidence_provider", side_effect=AssertionError("unexpected evidence")):
            with patch.object(store_module.sqlite3, "connect", side_effect=connect):
                self.assertIsNone(self.store.assert_retained_allocation(row, manifest))
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith("?mode=ro"))
        self.assertIs(calls[0][1], True)
        self.assertFalse(any(sql.lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE", "CREATE", "ALTER"))
                             for sql in statements))
        self.assertEqual(before, self.custody())

    def test_direct_and_local_routed_heartbeat_changes_only_observation_and_revisions(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                row, manifest = self.enrolled(kind)
                self.assertNotEqual(GUARDIAN.pid, row["wrapper_pid"])
                self.assertIsNone(self.store.assert_retained_allocation(row, manifest))
                allocation = self.allocation(row)
                self.evidence.events.clear()
                with self.store._publication_scope(GUARDIAN):
                    runtime = dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())
                    with self.audited_writer():
                        result = self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
                    after_runtime = dict(self.connection().execute("SELECT * FROM adaptive_runtime").fetchone())
                    self.assertEqual(after_runtime, {**runtime, "registry_revision": runtime["registry_revision"] + 1})
                self.assertEqual(result, {**row, "heartbeat_at": NOW + 10, "state_revision": row["state_revision"] + 1})
                self.assertEqual(self.allocation(row), {**allocation, "heartbeat_at": NOW + 10,
                    "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 1})
                self.assertEqual(self.evidence.events, ["enter", "commit", "close", "exit"])
                self.assertNotIn("claim_token_hash", result)
                self.assertNotIn("ipc_auth_key", result)
                self.assertIsNone(self.store.assert_retained_allocation(result, manifest))

    def test_zero_membership_keeps_running_allocation_and_does_not_archive(self):
        row, manifest = self.enrolled()
        self.evidence.overrides = {"active_process_count": 0, "process_ids": ()}
        result = self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
        self.assertEqual(result["state"], "RUNNING")
        self.assertIsNone(result["finished_at"])
        self.assertEqual(self.allocation(result)["id"], row["reservation_id"])
        self.assertEqual(self.connection().execute("SELECT count(*) FROM executions").fetchone()[0], 0)

    def test_hold_start_unknown_and_draining_preserve_all_custody_flags(self):
        for state in ("UNCERTAIN_HOLD", "START_UNKNOWN", "DRAINING"):
            with self.subTest(state=state):
                row, manifest = self.enrolled(state=state)
                before = self.allocation(row)
                self.assertIsNone(self.store.assert_retained_allocation(row, manifest))
                result = self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 20)
                self.assertEqual(result, {**row, "heartbeat_at": NOW + 20, "state_revision": row["state_revision"] + 1})
                self.assertEqual(before["expires_at"], self.allocation(row)["expires_at"])

    def test_manifest_binding_matrix_rejected_without_changes(self):
        row, manifest = self.enrolled()
        changes = (
            {"execution_id": str(uuid.uuid4())}, {"creation_nonce": "f" * 32},
            {"reservation": ReservationRef(AllocationKind.DIRECT, str(uuid.uuid4()))},
            {"reservation": ReservationRef(AllocationKind.ROUTED, manifest.reservation.id)},
            {"spec_hash": "b" * 64}, {"wrapper_identity": replace(WRAPPER, pid=WRAPPER.pid + 1)},
            {"root_identity": replace(ROOT, created_filetime_100ns=ROOT.created_filetime_100ns + 1)},
            {"root_identity": None}, {"guardian_epoch": "another-epoch"},
            {"allocated_floor": replace(manifest.allocated_floor, commit_bytes=manifest.allocated_floor.commit_bytes + 1)},
        )
        for change in changes:
            with self.subTest(field=next(iter(change))):
                self.assert_denied_without_mutation(row, self.changed_manifest(manifest, **change), "retained_manifest_mismatch")

    def test_invalid_manifest_and_incomplete_expected_row_fail_closed(self):
        row, manifest = self.enrolled()
        forged = self.changed_manifest(manifest)
        object.__setattr__(forged, "manifest_hash", "0" * 64)
        for value in (manifest.to_dict(), forged):
            with self.subTest(manifest_type=type(value).__name__):
                self.assert_denied_without_mutation(row, value, "retained_manifest_invalid")
        for change in ({"state_revision": True}, {"launch_sealed": True}, {"requested_commit_bytes": -1}):
            with self.subTest(change=change):
                self.assert_denied_without_mutation({**row, **change}, manifest, "retained_expected_row_invalid")
        missing = dict(row)
        del missing["task_id"]
        self.assert_denied_without_mutation(missing, manifest, "retained_expected_row_invalid")

    def test_stale_expected_revision_and_changed_snapshot_are_refused(self):
        row, manifest = self.enrolled()
        self.assert_denied_without_mutation({**row, "state_revision": row["state_revision"] - 1}, manifest, "revision_conflict")
        for change in ({"task_id": "other-task"}, {"state": "DRAINING"},
                       {"requested_cpu_units": row["requested_cpu_units"] + 1}, {"hold_reason": "heartbeat_lost"}):
            with self.subTest(change=change):
                self.assert_denied_without_mutation({**row, **change}, manifest, "retained_expected_row_mismatch")

    def test_vanished_allocation_is_not_recreated(self):
        row, manifest = self.enrolled()
        self.damage("reservations", "DELETE FROM reservations WHERE id=?", (row["reservation_id"],))
        self.assert_denied_without_mutation(row, manifest)
        self.assertEqual(self.connection().execute("SELECT count(*) FROM reservations").fetchone()[0], 0)

    def test_cross_ledger_duplicate_cannot_be_hidden_by_selected_source(self):
        row, manifest = self.enrolled()
        other = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(other)
        self.damage("worker_reservations", "UPDATE worker_reservations SET execution_id=?,lifecycle_managed=1 WHERE id=?",
                    (row["execution_id"], other.reservation.id))
        self.assert_denied_without_mutation(row, manifest, "retained_allocation_not_unique")

    def test_allocation_resource_or_spec_damage_is_not_repaired(self):
        row, manifest = self.enrolled()
        self.damage("reservations", "UPDATE reservations SET cpu_units=cpu_units+1 WHERE id=?", (row["reservation_id"],))
        self.assert_denied_without_mutation(row, manifest)

    def test_runtime_guardian_epoch_and_logon_must_match(self):
        row, manifest = self.enrolled()
        conn = self.connection()
        with self.store._publication_scope(GUARDIAN):
            for column, value in (("guardian_epoch", "wrong-epoch"), ("active_logon_id", "S-1-5-5-8-9")):
                original = conn.execute(f"SELECT {column} FROM adaptive_runtime").fetchone()[0]
                conn.execute(f"UPDATE adaptive_runtime SET {column}=?", (value,))
                try:
                    self.assert_denied_without_mutation(row, manifest, "retained_guardian_epoch_mismatch")
                finally:
                    conn.execute(f"UPDATE adaptive_runtime SET {column}=?", (original,))

    def test_remote_routed_allocation_is_not_local_custody(self):
        row, manifest = self.enrolled(AllocationKind.ROUTED)
        self.damage("workers", "UPDATE workers SET capabilities_json='{}',failure_domain='remote',capacity_pool='remote' WHERE id='local-alias'")
        self.assert_denied_without_mutation(row, manifest)

    def test_unverified_membership_job_root_and_seal_are_refused(self):
        row, manifest = self.enrolled()
        changes = ({"durable_manifest": False}, {"active_process_count": None},
            {"process_ids": None}, {"active_process_count": 0}, {"root": None},
            {"root": replace(ROOT, created_filetime_100ns=ROOT.created_filetime_100ns + 1)},
            {"launch_sealed": False}, {"job_nonce": "f" * 32},
            {"job_name": "Local\\ResourceSentinel.Other"}, {"guardian_epoch": "wrong-epoch"})
        with self.store._publication_scope(GUARDIAN):
            for change in changes:
                with self.subTest(change=change):
                    self.evidence.overrides = change
                    before = self.custody()
                    with self.assertRaisesRegex(LifecycleError, "heartbeat_evidence_unverified|job_scope_evidence_mismatch"):
                        self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
                    self.assertEqual(before, self.custody())

    def test_wrapper_identity_cannot_impersonate_distinct_guardian(self):
        row, manifest = self.enrolled()
        before = self.custody()
        with self.assertRaisesRegex(LifecycleError, "guardian_identity_mismatch"):
            self.store.heartbeat_retained_allocation(row, manifest, caller=WRAPPER, now=NOW + 10)
        self.assertEqual(self.evidence.events, [])
        self.assertEqual(before, self.custody())

    def test_default_provider_denies_manifest_as_authority(self):
        row, manifest = self.enrolled()
        default = LifecycleStore(self.db, policy_provider=self.policy)
        before = self.custody()
        self.assertIsNone(default.assert_retained_allocation(row, manifest))
        with self.assertRaisesRegex(LifecycleError, "native_lifecycle_evidence_unavailable"):
            default.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
        self.assertEqual(before, self.custody())

    def test_heartbeat_requires_provider_to_retain_this_stores_policy(self):
        row, manifest = self.enrolled()
        self.evidence.with_policy = False
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
        self.assertEqual(before, self.custody())

    def test_revision_race_after_native_observation_is_rechecked_in_transaction(self):
        row, manifest = self.enrolled()
        def advance():
            self.connection().execute("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?", (row["execution_id"],))
        self.evidence.before_yield = advance
        before = self.allocation(row)
        with self.store._publication_scope(GUARDIAN):
            with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
                self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
        self.assertEqual(before, self.allocation(row))
        self.assertEqual(self.store.query(row["execution_id"])["heartbeat_at"], row["heartbeat_at"])

    def test_failure_after_allocation_update_rolls_back_under_retained_evidence(self):
        row, manifest = self.enrolled()
        self.connection().execute("""CREATE TRIGGER fixture_reject_heartbeat BEFORE UPDATE OF heartbeat_at
            ON managed_executions BEGIN SELECT RAISE(ABORT,'fixture_heartbeat_failure'); END""")
        with self.store._publication_scope(GUARDIAN):
            before = self.custody()
            with self.audited_writer():
                with self.assertRaisesRegex(LifecycleError, "coverage_registry_unavailable"):
                    self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
            self.assertEqual(before, self.custody())
        self.assertEqual(self.evidence.events, ["enter", "rollback", "close", "exit"])

    def test_heartbeat_clock_regression_preserves_both_heartbeats(self):
        row, manifest = self.enrolled()
        with self.store._publication_scope(GUARDIAN):
            before = self.custody()
            with self.assertRaisesRegex(LifecycleError, "heartbeat_clock_regression"):
                self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW - 1)
            self.assertEqual(before, self.custody())

    def test_missing_database_is_never_created_by_retained_paths(self):
        row, manifest = self.enrolled()
        missing = self.directory / "missing-ledger.db"
        with self.store._publication_scope(GUARDIAN):
            self.store.db_path = missing
            try:
                with self.assertRaises(LifecycleError):
                    self.store.assert_retained_allocation(row, manifest)
                with self.assertRaisesRegex(LifecycleError, "coverage_registry_unavailable"):
                    self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=NOW + 10)
            finally:
                self.store.db_path = self.db
        self.assertFalse(missing.exists())
        self.assertEqual(self.store.query(row["execution_id"]), row)

    def test_existing_only_constructor_rejects_missing_database_without_creation(self):
        missing = self.directory / "never-created.db"
        with self.assertRaisesRegex(LifecycleError, "coverage_registry_unavailable"):
            LifecycleStore(missing, existing_path=True, policy_provider=self.policy,
                           local_host_id=self.store.local_host_id)
        self.assertFalse(missing.exists())

    def test_existing_only_query_and_policy_prepare_cannot_recreate_lost_database(self):
        row, _ = self.enrolled()
        pinned = self.directory / "pinned-existing.db"
        target = sqlite3.connect(pinned)
        try:
            self.connection().backup(target)
        finally:
            target.close()
        existing = LifecycleStore(pinned, existing_path=True, policy_provider=self.policy,
                                  local_host_id=self.store.local_host_id)
        self.assertTrue(existing.existing_path)
        self.assertEqual(existing.query(row["execution_id"]), row)
        pinned.unlink()
        diversion = self.directory / "diverted.db"
        existing.db_path = diversion
        for operation in (lambda: existing.query(row["execution_id"]),
                          lambda: existing._policy.prepare(GUARDIAN.logon_id)):
            with self.subTest(operation=operation):
                with self.assertRaises(LifecycleError):
                    operation()
                self.assertFalse(pinned.exists())
                self.assertFalse(diversion.exists())

    def test_existing_only_readiness_and_transaction_use_the_original_pinned_ledger(self):
        from sentinel.adaptive.daily_generation import readiness_scope
        row, _ = self.enrolled()
        existing = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy,
                                  local_host_id=self.store.local_host_id)
        diversion = self.directory / "unused-diversion.db"
        with readiness_scope(existing._existing_ledger_path):
            existing.db_path = diversion
            with existing._transaction() as conn:
                original = conn.execute("SELECT state FROM managed_executions WHERE execution_id=?",
                                        (row["execution_id"],)).fetchone()
                self.assertEqual(original[0], row["state"])
                main = [item[2] for item in conn.execute("PRAGMA database_list") if item[1] == "main"]
                self.assertEqual(main, [str(self.db.resolve())])
        self.assertFalse(diversion.exists())

    def finished(self, kind=AllocationKind.DIRECT):
        row, manifest = self.enrolled(kind)
        self.evidence.overrides = {"active_process_count": 0, "process_ids": ()}
        allocation = self.allocation(row)
        result = self.store.finalize_if_empty(row["execution_id"], caller=WRAPPER,
            expected_revision=row["state_revision"], now=NOW + 30)
        return result, manifest, allocation

    def test_terminal_assertion_accepts_actual_direct_and_routed_finalization(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                row, manifest, _ = self.finished(kind)
                before = self.custody()
                self.assertIsNone(self.store.assert_retained_terminal(row, manifest))
                with self.assertRaisesRegex(LifecycleError, "retained_execution_inactive"):
                    self.store.assert_retained_allocation(row, manifest)
                self.assertEqual(before, self.custody())

    def test_terminal_assertion_rejects_missing_archive(self):
        row, manifest, _ = self.finished()
        self.connection().execute("DELETE FROM executions WHERE reservation_id=?", (row["reservation_id"],))
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.assert_retained_terminal(row, manifest)
        self.assertEqual(before, self.custody())

    def test_terminal_assertion_rejects_duplicate_or_wrong_archive(self):
        row, manifest, _ = self.finished()
        conn = self.connection()
        archive = dict(conn.execute("SELECT * FROM executions WHERE reservation_id=?", (row["reservation_id"],)).fetchone())
        for column, value in (("outcome", "other"), ("ended_at", NOW + 31), ("cpu_units", 99), ("io_slots", 99)):
            with self.subTest(column=column):
                conn.execute(f"UPDATE executions SET {column}=? WHERE reservation_id=?", (value, row["reservation_id"]))
                before = self.custody()
                with self.assertRaises(LifecycleError):
                    self.store.assert_retained_terminal(row, manifest)
                self.assertEqual(before, self.custody())
                conn.execute(f"UPDATE executions SET {column}=? WHERE reservation_id=?", (archive[column], row["reservation_id"]))
        values = {key: value for key, value in archive.items() if key != "id"}
        conn.execute("INSERT INTO executions(" + ",".join(values) + ") VALUES(" + ",".join("?" for _ in values) + ")", tuple(values.values()))
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.assert_retained_terminal(row, manifest)
        self.assertEqual(before, self.custody())

    def test_terminal_assertion_rejects_surviving_allocation(self):
        row, manifest, allocation = self.finished()
        self.damage("reservations", "INSERT INTO reservations(" + ",".join(allocation) + ") VALUES(" +
            ",".join("?" for _ in allocation) + ")", tuple(allocation.values()))
        before = self.custody()
        with self.assertRaises(LifecycleError):
            self.store.assert_retained_terminal(row, manifest)
        self.assertEqual(before, self.custody())


if __name__ == "__main__":
    unittest.main()
