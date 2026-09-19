"""L1 lifecycle tests with synthetic evidence. They prove no Windows behavior."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from tests.fixtures.adaptive_evidence import FixturePolicyProvider, fixture_evidence_provider
import uuid

from sentinel.adaptive.contracts import (
    AllocationKind, ExecutionSpec, Priority, ProcessIdentity, ReservationRef,
    ResourceDemand, Role,
)
from sentinel.adaptive.store import (
    LifecycleError, LifecycleEvidence, LifecycleStore, SchemaVersionError,
    allocation_is_bound, check_schema_version, hold_bound_allocation,
    hold_expired_allocations, migrate_schema,
)
from sentinel.coordinator import Coordinator
from sentinel.maintainer import Maintainer

NOW = 2_000_000_000.0
GIB = 1 << 30
WRAPPER = ProcessIdentity(101, 134342315823996135, "S-1-5-5-1-2")
ROOT = ProcessIdentity(102, 134342315823996140, "S-1-5-5-1-2")


class SyntheticVerifier:
    """In-memory OS fixture, never used by the production CLI."""
    def __init__(self):
        self.active = 0
        self.sealed = True
        self.parent_membership = True
        self.operations = []

    def __call__(self, operation, row, caller):
        self.operations.append(operation)
        return LifecycleEvidence(
            operation, row["execution_id"], row["state_revision"], "fixture-only", caller,
            guardian_epoch="fixture-guardian", job_name="Local\\ResourceSentinel.Test." + row["execution_id"],
            root=ROOT, active_process_count=self.active,
            process_ids=() if self.active == 0 else (ROOT.pid,), launch_sealed=self.sealed,
            original_cpu_disabled=True, durable_manifest=True, legacy_exclusion=True,
            root_exited=True, parent_membership=self.parent_membership,
        )


class AdaptiveLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        # Use the actual legacy schemas; the test never touches daily data.
        Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0))
        Maintainer(self.directory)
        self.db = self.directory / "sentinel.db"
        self.verifier = SyntheticVerifier()
        self.policy = FixturePolicyProvider(WRAPPER.logon_id)
        self.store = LifecycleStore(self.db, evidence_provider=fixture_evidence_provider(self.verifier),
                                    policy_provider=self.policy)

    def connection(self):
        conn = sqlite3.connect(self.db, timeout=3, isolation_level=None)
        conn.row_factory = sqlite3.Row
        self.addCleanup(conn.close)
        return conn

    def spec(self, *, reservation_id=None, kind=AllocationKind.DIRECT, parent=None,
             execution_id=None, wrapper=WRAPPER, demand=None):
        execution_id = execution_id or str(uuid.uuid4())
        return ExecutionSpec(
            execution_id=execution_id, task_id="task-" + execution_id,
            session_id="fixture-session", principal_id="fixture-principal",
            reservation=ReservationRef(kind, parent or reservation_id or str(uuid.uuid4())),
            parent_execution_id=parent, spec_hash="a" * 64, role=Role.BACKGROUND,
            priority=Priority.P2, requested=demand or ResourceDemand(1.0, GIB, 2 * GIB, 1),
            wrapper_identity=wrapper,
        )

    def allocate(self, spec):
        # Synthetic capacity setup represents a protocol-aware writer, not an
        # old-binary compatibility test. Keep persistent fences enabled.
        conn = self.connection()
        demand = spec.requested
        if spec.reservation.kind == AllocationKind.DIRECT:
            conn.execute("""INSERT INTO reservations(id,request_key,owner_pid,owner_started,
                tool_use_id,repo,command_signature,command_text,resource_class,priority,priority_rank,
                cpu_units,ram_gib,io_slots,created_at,heartbeat_at,expires_at,spec_hash,physical_bytes,commit_bytes,
                writer_protocol,writer_revision)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0)""",
                (spec.reservation.id, uuid.uuid4().hex, 100, 1.0, "tool", "repo-label", "safe-family", "",
                 "MEDIUM", "P2", 2, demand.cpu_units, demand.physical_bytes / GIB, demand.io_slots,
                 NOW, NOW, NOW + 120, spec.spec_hash, demand.physical_bytes, demand.commit_bytes))
        elif spec.reservation.kind == AllocationKind.ROUTED:
            # Reusing this fixture worker makes no write. An INSERT OR IGNORE
            # still runs BEFORE INSERT guards for a referenced worker.
            if conn.execute("SELECT 1 FROM workers WHERE id='local-alias'").fetchone() is None:
                conn.execute("""INSERT INTO workers(id,provider,failure_domain,capacity_scope,capacity_pool,
                    max_concurrency,quota_domain,state,automation_level,os,capacity_ram_gib,allocatable_ram_gib,
                    visible_cpu,allocatable_cpu,disk_free_gib,allocatable_disk_gib,capabilities_json,trust_domain,
                    source,observed_at,probe_expires_at,updated_at,writer_protocol,writer_revision)
                    VALUES('local-alias','alias-provider','local','SHARED_POOL','local',8,'','AVAILABLE',
                    'AUTOMATABLE','windows',64,58,12,8,100,100,'{"local":true}','local-private','test',?,?,?,1,0)""",
                    (NOW, NOW + 3600, NOW))
            conn.execute("""INSERT INTO worker_reservations(id,task_id,worker_id,failure_domain,capacity_scope,
                capacity_pool,spec_hash,ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,expires_at,metadata_json,
                physical_bytes,commit_bytes,io_slots,writer_protocol,writer_revision)
                VALUES(?,?,'local-alias','local','SHARED_POOL','local',?,?,?,?,?,?,?,?,?,?,?,1,0)""",
                (spec.reservation.id, spec.task_id, spec.spec_hash, demand.physical_bytes / GIB,
                 demand.cpu_units, 0, NOW, NOW, NOW + 120, "{}", demand.physical_bytes, demand.commit_bytes, demand.io_slots))

    def registered(self, spec=None):
        spec = spec or self.spec()
        self.allocate(spec)
        return spec, self.store.prepare_registration(spec, caller=spec.wrapper_identity, now=NOW)

    def running(self, spec=None):
        spec, registered = self.registered(spec)
        prepared = self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        claimed = self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=prepared["state_revision"],
            claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        running = self.store.bind_root(spec.execution_id, caller=WRAPPER, expected_revision=claimed["state_revision"])
        return spec, running

    def test_default_store_refuses_self_reported_native_registration(self):
        spec = self.spec()
        self.allocate(spec)
        default = LifecycleStore(self.db)
        with self.assertRaisesRegex(LifecycleError, "native_lifecycle_evidence_unavailable"):
            default.prepare_registration(spec, caller=WRAPPER, now=NOW)
        self.assertFalse(allocation_is_bound(self.connection(), "direct", spec.reservation.id))

    def test_additive_migration_is_idempotent_and_preserves_legacy_bytes(self):
        spec = self.spec()
        self.allocate(spec)
        conn = self.connection()
        before = dict(conn.execute("SELECT * FROM reservations").fetchone())
        migrate_schema(conn)
        migrate_schema(conn)
        self.assertEqual(before, dict(conn.execute("SELECT * FROM reservations").fetchone()))
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertNotIn("adaptive_reservations", tables)

    def test_unknown_schema_rejected_before_any_migration_change(self):
        conn = self.connection()
        conn.execute("UPDATE adaptive_runtime SET schema_version=99")
        schema_before = conn.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall()
        for function in (check_schema_version, migrate_schema):
            with self.assertRaisesRegex(SchemaVersionError, "unsupported_adaptive_schema"):
                function(conn)
        self.assertEqual(schema_before, conn.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall())

    def test_migration_serializes_concurrent_initializers(self):
        legacy_path = self.directory / "legacy-queue.db"
        conn = sqlite3.connect(legacy_path, isolation_level=None)
        try:
            conn.execute("CREATE TABLE queue(request_key TEXT PRIMARY KEY, ram_gib REAL NOT NULL)")
            conn.execute("INSERT INTO queue VALUES('existing-request', 2.0)")
        finally:
            conn.close()
        start = threading.Barrier(2)
        def migrate(_):
            conn = sqlite3.connect(legacy_path, timeout=3, isolation_level=None)
            try:
                start.wait()
                migrate_schema(conn)
            finally:
                conn.close()
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(migrate, range(2)))
        conn = sqlite3.connect(legacy_path, isolation_level=None)
        try:
            self.assertEqual(conn.execute("SELECT count(*) FROM adaptive_runtime").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT request_key,ram_gib,commit_bytes FROM queue").fetchone(),
                             ("existing-request", 2.0, None))
            self.assertEqual([row[1] for row in conn.execute("PRAGMA table_info(queue)")].count("commit_bytes"), 1)
        finally:
            conn.close()

    def test_registration_binds_exact_id_and_retries_do_not_mint_tokens(self):
        spec, first = self.registered()
        again = self.store.prepare_registration(spec, caller=WRAPPER, now=NOW + 1)
        self.assertFalse(again["registered"])
        self.assertIsNone(again["claim_token"])
        self.assertEqual(first["execution_id"], again["execution_id"])
        self.assertTrue(allocation_is_bound(self.connection(), "direct", spec.reservation.id))
        contender = replace(spec, execution_id=str(uuid.uuid4()))
        with self.assertRaisesRegex(LifecycleError, "allocation_already_bound"):
            self.store.prepare_registration(contender, caller=WRAPPER, now=NOW)

    def test_pid_reuse_and_different_logon_cannot_claim_registration(self):
        spec = self.spec()
        self.allocate(spec)
        for caller in (replace(WRAPPER, created_filetime_100ns=WRAPPER.created_filetime_100ns + 1),
                       replace(WRAPPER, logon_id="other-logon")):
            with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
                self.store.prepare_registration(spec, caller=caller, now=NOW)

    def test_mismatched_hash_or_resources_cannot_adopt_capacity(self):
        spec = self.spec()
        self.allocate(spec)
        with self.assertRaisesRegex(LifecycleError, "reservation_spec_mismatch"):
            self.store.prepare_registration(replace(spec, spec_hash="b" * 64), caller=WRAPPER, now=NOW)
        with self.assertRaisesRegex(LifecycleError, "reservation_resource_mismatch"):
            self.store.prepare_registration(replace(spec, requested=ResourceDemand(2, GIB, 2 * GIB, 1)), caller=WRAPPER, now=NOW)

    def test_claim_secret_not_stored_or_returned_in_query(self):
        spec, registered = self.registered()
        token = registered["claim_token"]
        row = dict(self.connection().execute("SELECT * FROM managed_executions").fetchone())
        self.assertEqual(row["claim_token_hash"], hashlib.sha256(token.encode("ascii")).hexdigest())
        self.assertNotIn(token, json.dumps(row))
        self.assertNotIn("claim_token_hash", self.store.query(spec.execution_id))
        self.assertNotIn("command", " ".join(row))

    def test_claim_is_one_use_under_concurrent_duplicate_delivery(self):
        spec, registered = self.registered()
        prepared = self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        start = threading.Barrier(2)
        def claim(_):
            start.wait()
            return self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=prepared["state_revision"],
                claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, range(2)))
        self.assertEqual(sum(item["launch_authorized"] for item in results), 1)
        self.assertEqual(sum(item["duplicate"] for item in results), 1)
        self.assertEqual(self.store.query(spec.execution_id)["launch_in_flight"], 1)

    def test_barrier_rejects_previously_reserved_launch_without_consuming_token(self):
        spec, registered = self.registered()
        self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        self.connection().execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD'")
        with self.assertRaisesRegex(LifecycleError, "launch_barrier_active"):
            self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=1,
                claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_preparation_atomic_ten_job_ceiling_counts_uncertain_jobs(self):
        for index in range(9):
            spec, _ = self.registered()
            prepared = self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
            if index == 0:
                self.store.hold(spec.execution_id, expected_revision=prepared["state_revision"], reason="heartbeat_lost")
        contenders = [self.registered()[0], self.registered()[0]]
        start = threading.Barrier(2)
        def prepare(spec):
            start.wait()
            try:
                return self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)["state"]
            except LifecycleError as error:
                return str(error)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(prepare, contenders))
        self.assertCountEqual(outcomes, ["PREPARED", "managed_job_limit_reached"])
        self.assertEqual(self.connection().execute("SELECT count(*) FROM managed_executions WHERE job_name IS NOT NULL").fetchone()[0], 10)

    def test_stale_claim_revision_is_rejected_before_native_verification(self):
        spec, registered = self.registered()
        self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        self.verifier.operations.clear()
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=0,
                claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        self.assertNotIn("claim", self.verifier.operations)
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_claim_cannot_use_proof_after_concurrent_revision_change(self):
        spec, registered = self.registered()
        self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        def mutate_during_verification(operation, row, caller):
            result = self.verifier(operation, row, caller)
            if operation == "claim":
                self.connection().execute("UPDATE managed_executions SET state_revision=state_revision+1 WHERE execution_id=?", (spec.execution_id,))
            return result
        self.store.evidence_provider = fixture_evidence_provider(mutate_during_verification)
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=1,
                claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        self.assertEqual(self.store.query(spec.execution_id)["claim_consumed"], 0)

    def test_root_exit_does_not_release_live_children(self):
        spec, row = self.running()
        self.verifier.active = 1
        draining = self.store.mark_root_exited(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"], exit_code=7)
        self.assertEqual(draining["state"], "DRAINING")
        self.assertEqual(draining["root_outcome"], "7")
        with self.assertRaisesRegex(LifecycleError, "job_empty_unverified"):
            self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=draining["state_revision"])
        self.assertTrue(allocation_is_bound(self.connection(), "direct", spec.reservation.id))

    def test_expired_running_allocation_holds_without_releasing(self):
        spec, row = self.running()
        conn = self.connection()
        conn.execute("BEGIN IMMEDIATE")
        self.assertEqual(hold_expired_allocations(conn, "direct", NOW + 121), 1)
        conn.commit()
        held = self.store.query(spec.execution_id)
        self.assertEqual(held["state"], "UNCERTAIN_HOLD")
        self.assertEqual(held["floor_commit_bytes"], 2 * GIB)
        self.assertIsNotNone(conn.execute("SELECT id FROM reservations WHERE id=?", (spec.reservation.id,)).fetchone())

    def test_launch_timeout_preserves_in_flight_and_forbids_second_launch(self):
        spec, registered = self.registered()
        self.store.mark_prepared(spec.execution_id, caller=WRAPPER, expected_revision=0)
        launched = self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=1,
            claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        held = self.store.hold(spec.execution_id, expected_revision=launched["state_revision"], reason="launch_ack_lost")
        self.assertEqual(held["state"], "START_UNKNOWN")
        self.assertEqual(held["launch_in_flight"], 1)
        duplicate = self.store.claim_launch(spec.execution_id, caller=WRAPPER, expected_revision=held["state_revision"],
            claim_token=registered["claim_token"], spec_hash=spec.spec_hash, guardian_epoch="fixture-guardian")
        self.assertFalse(duplicate["launch_authorized"])

    def test_empty_without_launch_seal_does_not_release(self):
        spec, row = self.running()
        self.verifier.sealed = False
        with self.assertRaisesRegex(LifecycleError, "job_empty_unverified"):
            self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"])
        self.assertIsNotNone(self.connection().execute("SELECT id FROM reservations").fetchone())

    def test_default_finalizer_cannot_accept_injected_empty_boolean(self):
        spec, row = self.running()
        with self.assertRaisesRegex(LifecycleError, "native_lifecycle_evidence_unavailable"):
            LifecycleStore(self.db).finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"])
        with self.assertRaises(TypeError):
            self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"], job_empty=True)

    def test_positive_empty_finalizes_archives_and_releases_once(self):
        for kind, archive in ((AllocationKind.DIRECT, "executions"), (AllocationKind.ROUTED, "routed_executions")):
            with self.subTest(kind=kind):
                spec, row = self.running(self.spec(kind=kind))
                done = self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"], now=NOW + 1)
                self.assertEqual(done["state"], "FINISHED")
                again = self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=done["state_revision"], now=NOW + 2)
                self.assertEqual(again["state_revision"], done["state_revision"])
                self.assertEqual(self.connection().execute(f"SELECT count(*) FROM {archive} WHERE reservation_id=?", (spec.reservation.id,)).fetchone()[0], 1)

    def test_finished_retry_does_not_need_a_named_job_that_no_longer_exists(self):
        spec, row = self.running()
        done = self.store.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"])
        default = LifecycleStore(self.db)
        replay = default.finalize_if_empty(spec.execution_id, caller=WRAPPER, expected_revision=done["state_revision"])
        self.assertEqual(replay, done)
        with self.assertRaisesRegex(LifecycleError, "caller_identity_mismatch"):
            default.finalize_if_empty(spec.execution_id, caller=replace(WRAPPER, created_filetime_100ns=WRAPPER.created_filetime_100ns + 1),
                expected_revision=done["state_revision"])
        self.assertEqual(self.connection().execute("SELECT count(*) FROM executions").fetchone()[0], 1)

    def test_typed_evidence_rejects_truthy_strings_and_boolean_counts(self):
        spec, registered = self.registered()
        proof = self.verifier("prepare", registered, WRAPPER)
        for name in ("launch_sealed", "original_cpu_disabled", "durable_manifest", "legacy_exclusion", "root_exited", "parent_membership"):
            for malformed in ("false", 1, None):
                with self.subTest(field=name, malformed=malformed):
                    with self.assertRaisesRegex(ValueError, "invalid_evidence_boolean"):
                        replace(proof, **{name: malformed})
        with self.assertRaisesRegex(ValueError, "invalid_evidence_process_count"):
            replace(proof, active_process_count=False)

    def test_sql_floors_reject_fractional_bytes_and_nonfinite_text(self):
        spec, _ = self.registered()
        conn = self.connection()
        for field in ("requested_physical_bytes", "requested_commit_bytes", "requested_io_slots",
                      "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots"):
            for value in (1.5, "NaN", -1):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(sqlite3.IntegrityError):
                        conn.execute(f"UPDATE managed_executions SET {field}=? WHERE execution_id=?", (value, spec.execution_id))
        for value in ("NaN", float("inf"), -1):
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE managed_executions SET floor_cpu_units=? WHERE execution_id=?", (value, spec.execution_id))

    def test_stale_cas_cannot_overwrite_newer_lifecycle_state(self):
        spec, row = self.running()
        self.store.hold(spec.execution_id, expected_revision=row["state_revision"], reason="identity_unknown")
        with self.assertRaisesRegex(LifecycleError, "revision_conflict"):
            self.store.mark_root_exited(spec.execution_id, caller=WRAPPER, expected_revision=row["state_revision"], exit_code=0)

    def test_nested_subspan_shares_allocation_and_parent_empty_finalizes_both(self):
        parent, running = self.running()
        child = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
        registered = self.store.prepare_registration(child, caller=WRAPPER, now=NOW)
        self.assertIsNone(registered["reservation_id"])
        self.assertIsNone(registered["job_name"])
        self.assertEqual(self.connection().execute("SELECT count(*) FROM reservations").fetchone()[0], 1)
        self.store.finalize_if_empty(parent.execution_id, caller=WRAPPER, expected_revision=running["state_revision"])
        self.assertEqual(self.store.query(child.execution_id)["state"], "FINISHED")

    def test_nested_scope_rejects_forged_membership_and_envelope_upgrade(self):
        parent, _ = self.running()
        child = self.spec(kind=AllocationKind.PARENT, parent=parent.execution_id)
        self.verifier.parent_membership = False
        with self.assertRaisesRegex(LifecycleError, "parent_membership_unverified"):
            self.store.prepare_registration(child, caller=WRAPPER, now=NOW)
        self.verifier.parent_membership = True
        with self.assertRaisesRegex(LifecycleError, "nested_budget_upgrade_required"):
            self.store.prepare_registration(replace(child, requested=ResourceDemand(2, GIB, 2 * GIB, 1)), caller=WRAPPER, now=NOW)

    def test_native_verification_occurs_outside_sqlite_write_transaction(self):
        base_verifier = self.verifier
        def verifier(operation, record, caller):
            conn = sqlite3.connect(self.db, timeout=0, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.rollback()
            finally:
                conn.close()
            return base_verifier(operation, record, caller)
        self.store.evidence_provider = fixture_evidence_provider(verifier)
        self.running()

    def test_orphan_binding_and_legacy_release_remain_conservative(self):
        spec, row = self.running()
        conn = self.connection()
        conn.execute("BEGIN IMMEDIATE")
        self.assertEqual(hold_bound_allocation(conn, "direct", spec.reservation.id, "legacy_release_attempt", NOW), 1)
        conn.commit()
        self.assertEqual(self.store.query(spec.execution_id)["state"], "UNCERTAIN_HOLD")
        conn.execute("DELETE FROM managed_executions WHERE execution_id=?", (spec.execution_id,))
        self.assertTrue(allocation_is_bound(conn, "direct", spec.reservation.id))

    def test_routed_provider_name_cannot_override_explicit_nonlocal_scope(self):
        spec = self.spec(kind=AllocationKind.ROUTED)
        self.allocate(spec)
        self.connection().execute("""UPDATE workers SET provider='local',capabilities_json='{\"local\":false}',
            writer_protocol=1,writer_revision=writer_revision+1""")
        with self.assertRaisesRegex(LifecycleError, "nonlocal_allocation"):
            self.store.prepare_registration(spec, caller=WRAPPER, now=NOW)


if __name__ == "__main__":
    unittest.main()
