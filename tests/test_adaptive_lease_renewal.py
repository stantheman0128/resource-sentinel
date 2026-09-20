"""Lease custody in isolated SQLite, using synthetic guardian evidence only."""
from dataclasses import replace
import sqlite3
import unittest
import uuid

from sentinel.adaptive.contracts import AllocationKind
from sentinel.adaptive.store import LifecycleError
from sentinel.maintainer import Maintainer, Task
from tests import test_adaptive_guardian_accounting as guardian_fixture
from tests import test_adaptive_managed_admission as admission_fixture
from tests import test_maintainer as maintainer_fixture


NOW = guardian_fixture.NOW
GUARDIAN = guardian_fixture.GUARDIAN
WRAPPER = guardian_fixture.WRAPPER
GIB = 1 << 30


class AdaptiveLeaseRenewalTests(unittest.TestCase):
    # Borrow helpers, not the TestCase subclass or its discovered tests.
    connection = guardian_fixture.AdaptiveGuardianAccountingTests.connection
    spec = guardian_fixture.AdaptiveGuardianAccountingTests.spec
    registered = guardian_fixture.AdaptiveGuardianAccountingTests.registered
    enrolled = guardian_fixture.AdaptiveGuardianAccountingTests.enrolled
    custody = guardian_fixture.AdaptiveGuardianAccountingTests.custody
    allocation = guardian_fixture.AdaptiveGuardianAccountingTests.allocation
    damage = guardian_fixture.AdaptiveGuardianAccountingTests.damage
    audited_writer = guardian_fixture.AdaptiveGuardianAccountingTests.audited_writer

    def setUp(self):
        guardian_fixture.AdaptiveGuardianAccountingTests.setUp(self)
        self.maintainer = Maintainer(self.directory)
        self.duration = 120.0
        self.initial_expiry = NOW + 120

    def allocate(self, spec):
        """Insert the chosen original duration, including legacy unknown NULL."""
        conn = self.connection()
        demand = spec.requested
        common = dict(id=spec.reservation.id, cpu_units=demand.cpu_units,
            ram_gib=demand.physical_bytes / GIB, physical_bytes=demand.physical_bytes,
            commit_bytes=demand.commit_bytes, io_slots=demand.io_slots,
            created_at=NOW, heartbeat_at=NOW, expires_at=self.initial_expiry,
            lease_duration_sec=self.duration, spec_hash=spec.spec_hash,
            writer_protocol=1, writer_revision=0)
        if spec.reservation.kind is AllocationKind.DIRECT:
            table = "reservations"
            values = common | dict(request_key=uuid.uuid4().hex, owner_pid=100,
                owner_started=1.0, tool_use_id="lease-fixture", repo="fixture-repo",
                command_signature="fixture-family", command_text="", resource_class="MEDIUM",
                priority="P2", priority_rank=2)
        else:
            table = "worker_reservations"
            if conn.execute("SELECT 1 FROM workers WHERE id='lease-local'").fetchone() is None:
                self.maintainer.upsert_worker(maintainer_fixture.worker(
                    "lease-local", 64, local=True, os_name="windows", domain="local",
                    capacity_pool="local"), now=NOW)
            values = common | dict(task_id=spec.task_id, worker_id="lease-local",
                failure_domain="local", capacity_scope="SHARED_POOL", capacity_pool="local",
                disk_gib=0, metadata_json="{}")
        conn.execute("INSERT INTO " + table + "(" + ",".join(values) + ") VALUES(" +
                     ",".join("?" for _ in values) + ")", tuple(values.values()))

    def heartbeat(self, row, manifest, now):
        return self.store.heartbeat_retained_allocation(row, manifest, caller=GUARDIAN, now=now)

    def draining_with_hold(self, kind=AllocationKind.DIRECT):
        row, manifest = self.enrolled(kind, state="UNCERTAIN_HOLD")
        self.evidence.overrides = {"root_exited": True}
        row = self.store.mark_root_exited(row["execution_id"], caller=WRAPPER,
            expected_revision=row["state_revision"], exit_code=0)
        self.evidence.overrides = {}
        return row, manifest

    def test_healthy_running_and_draining_renew_both_actual_capacity_sources(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            for state in ("RUNNING", "DRAINING"):
                with self.subTest(kind=kind, state=state):
                    row, manifest = self.enrolled(kind, state=state)
                    allocation = self.allocation(row)
                    result = self.heartbeat(row, manifest, NOW + 20)
                    self.assertEqual(result, {**row, "heartbeat_at": NOW + 20,
                        "state_revision": row["state_revision"] + 1})
                    self.assertEqual(self.allocation(row), {**allocation,
                        "heartbeat_at": NOW + 20, "expires_at": NOW + 140,
                        "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 1})
                    second = self.heartbeat(result, manifest, NOW + 40)
                    self.assertEqual(second["state"], state)
                    self.assertEqual(self.allocation(row), {**allocation,
                        "heartbeat_at": NOW + 40, "expires_at": NOW + 160,
                        "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 2})

    def test_renewal_never_shortens_a_later_existing_deadline(self):
        # A legacy refresh before enrollment may have left a later expiry.
        self.initial_expiry = NOW + 600
        row, manifest = self.enrolled()
        allocation = self.allocation(row)
        first = self.heartbeat(row, manifest, NOW + 10)
        self.assertEqual(self.allocation(row)["expires_at"], self.initial_expiry)
        self.assertEqual(self.allocation(row)["lease_duration_sec"], allocation["lease_duration_sec"])
        second = self.heartbeat(first, manifest, NOW + 20)
        self.assertEqual(second["state"], "RUNNING")
        self.assertEqual(self.allocation(row)["expires_at"], self.initial_expiry)
        self.assertEqual(self.allocation(row)["lease_duration_sec"], 120.0)

    def test_null_original_duration_is_observation_only_without_inference(self):
        self.duration = None
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                row, manifest = self.enrolled(kind)
                allocation = self.allocation(row)
                result = self.heartbeat(row, manifest, NOW + 20)
                self.assertEqual(result["state"], "RUNNING")
                self.assertEqual(self.allocation(row), {**allocation, "heartbeat_at": NOW + 20,
                    "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 1})
                self.assertIsNone(self.allocation(row)["lease_duration_sec"])

    def test_existing_holds_and_start_unknown_do_not_renew_before_expiry(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            for state in ("UNCERTAIN_HOLD", "START_UNKNOWN"):
                with self.subTest(kind=kind, state=state):
                    row, manifest = self.enrolled(kind, state=state)
                    allocation = self.allocation(row)
                    result = self.heartbeat(row, manifest, NOW + 20)
                    self.assertEqual(result, {**row, "heartbeat_at": NOW + 20,
                        "state_revision": row["state_revision"] + 1})
                    self.assertEqual(self.allocation(row), {**allocation, "heartbeat_at": NOW + 20,
                        "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 1})

    def test_draining_with_retained_hold_reason_cannot_renew(self):
        row, manifest = self.draining_with_hold()
        self.assertEqual((row["state"], row["hold_reason"]), ("DRAINING", "heartbeat_lost"))
        allocation = self.allocation(row)
        result = self.heartbeat(row, manifest, NOW + 20)
        self.assertEqual(result, {**row, "heartbeat_at": NOW + 20,
            "state_revision": row["state_revision"] + 1})
        self.assertEqual(self.allocation(row)["expires_at"], allocation["expires_at"])

    def test_exact_expiry_boundary_enters_hold_without_extending_or_releasing(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            with self.subTest(kind=kind):
                row, manifest = self.enrolled(kind)
                allocation = self.allocation(row)
                self.evidence.overrides = {"active_process_count": 0, "process_ids": ()}
                result = self.heartbeat(row, manifest, allocation["expires_at"])
                self.assertEqual(result, {**row, "state": "UNCERTAIN_HOLD",
                    "hold_reason": "reservation_expired", "heartbeat_at": allocation["expires_at"],
                    "state_revision": row["state_revision"] + 1})
                self.assertEqual(self.allocation(row), {**allocation, "heartbeat_at": allocation["expires_at"],
                    "writer_protocol": 1, "writer_revision": allocation["writer_revision"] + 1})
                self.assertIsNone(result["finished_at"])
                self.evidence.overrides = {}

    def test_expired_launch_in_flight_transitions_to_start_unknown(self):
        row, manifest = self.enrolled(state="START_UNKNOWN")
        # Isolate the pre-hold LAUNCHING state with its real consumed claim.
        self.connection().execute("UPDATE managed_executions SET state='LAUNCHING',hold_reason=NULL WHERE execution_id=?",
                                  (row["execution_id"],))
        row = self.store.query(row["execution_id"])
        allocation = self.allocation(row)
        result = self.heartbeat(row, manifest, NOW + 121)
        self.assertEqual(result, {**row, "state": "START_UNKNOWN", "hold_reason": "reservation_expired",
            "heartbeat_at": NOW + 121, "state_revision": row["state_revision"] + 1})
        self.assertEqual(result["launch_in_flight"], 1)
        self.assertEqual(self.allocation(row)["expires_at"], allocation["expires_at"])

    def test_expiry_preserves_existing_hold_reason_and_every_resource_floor(self):
        row, manifest = self.draining_with_hold(AllocationKind.ROUTED)
        allocation = self.allocation(row)
        result = self.heartbeat(row, manifest, NOW + 121)
        self.assertEqual(result, {**row, "state": "UNCERTAIN_HOLD", "heartbeat_at": NOW + 121,
            "state_revision": row["state_revision"] + 1})
        self.assertEqual(result["hold_reason"], "heartbeat_lost")
        again = self.heartbeat(result, manifest, NOW + 122)
        self.assertEqual(again, {**result, "heartbeat_at": NOW + 122,
            "state_revision": result["state_revision"] + 1})
        self.assertEqual(self.allocation(row)["expires_at"], allocation["expires_at"])

    def test_malformed_duration_and_expiry_fail_without_any_custody_change(self):
        row, manifest = self.enrolled()
        for column, value in (("lease_duration_sec", 0), ("lease_duration_sec", -1),
                ("lease_duration_sec", "not-a-duration"), ("lease_duration_sec", float("inf")),
                ("expires_at", -1), ("expires_at", "not-a-deadline"), ("expires_at", float("inf"))):
            with self.subTest(column=column, value=value):
                self.damage("reservations", f"UPDATE reservations SET {column}=? WHERE id=?", (value, row["reservation_id"]))
                with self.store._publication_scope(GUARDIAN):
                    before = self.custody()
                    with self.assertRaisesRegex(LifecycleError, "allocation_lease_invalid"):
                        self.heartbeat(row, manifest, NOW + 20)
                    self.assertEqual(before, self.custody())
                restored = self.duration if column == "lease_duration_sec" else self.initial_expiry
                self.connection().execute(f"UPDATE reservations SET {column}=? WHERE id=?", (restored, row["reservation_id"]))

    def test_original_duration_is_immutable_for_known_and_null_both_sources(self):
        for kind in (AllocationKind.DIRECT, AllocationKind.ROUTED):
            for duration in (120.0, None):
                with self.subTest(kind=kind, duration=duration):
                    self.duration = duration
                    # Leave this allocation unregistered so the existing
                    # managed-replacement fence cannot mask the lease guard.
                    spec = self.spec(kind=kind)
                    self.allocate(spec)
                    row = {"allocation_kind": kind.value, "reservation_id": spec.reservation.id}
                    table = "reservations" if kind is AllocationKind.DIRECT else "worker_reservations"
                    before = self.custody()
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable_reservation_lease"):
                        self.connection().execute(f"""UPDATE {table} SET lease_duration_sec=240,
                            writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?""", (row["reservation_id"],))
                    self.assertEqual(before, self.custody())
                    replacement = self.allocation(row)
                    replacement.update(lease_duration_sec=240, writer_protocol=1,
                                       writer_revision=replacement["writer_revision"] + 1)
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable_reservation_lease"):
                        self.connection().execute("INSERT OR REPLACE INTO " + table + "(" +
                            ",".join(replacement) + ") VALUES(" + ",".join("?" for _ in replacement) + ")",
                            tuple(replacement.values()))
                    self.assertEqual(before, self.custody())

    def test_renewal_rolls_back_with_lifecycle_failure_under_retained_fences(self):
        row, manifest = self.enrolled()
        self.connection().execute("""CREATE TRIGGER fixture_fail_renewal BEFORE UPDATE OF heartbeat_at
            ON managed_executions BEGIN SELECT RAISE(ABORT,'fixture_renewal_failure'); END""")
        with self.store._publication_scope(GUARDIAN):
            before = self.custody()
            with self.audited_writer():
                with self.assertRaisesRegex(LifecycleError, "coverage_registry_unavailable"):
                    self.heartbeat(row, manifest, NOW + 20)
            self.assertEqual(before, self.custody())
        self.assertEqual(self.evidence.events, ["enter", "rollback", "close", "exit"])

    def test_wrong_guardian_cannot_refresh_observation_or_expiry(self):
        row, manifest = self.enrolled()
        before = self.custody()
        with self.assertRaisesRegex(LifecycleError, "guardian_identity_mismatch"):
            self.store.heartbeat_retained_allocation(row, manifest,
                caller=replace(GUARDIAN, created_filetime_100ns=GUARDIAN.created_filetime_100ns + 1), now=NOW + 20)
        self.assertEqual(before, self.custody())
        self.assertEqual(self.evidence.events, [])

    def test_legacy_maintainer_heartbeat_refuses_managed_routed_row_without_changes(self):
        row, _ = self.enrolled(AllocationKind.ROUTED)
        before = self.custody()
        self.assertIs(self.maintainer.heartbeat(row["task_id"], ttl_min=999, now=NOW + 20), False)
        self.assertEqual(before, self.custody())

    def test_legacy_heartbeat_refuses_stripped_tags_with_damaged_registry_kind(self):
        row, _ = self.enrolled(AllocationKind.ROUTED)
        self.damage("worker_reservations", """UPDATE worker_reservations
            SET execution_id=NULL,lifecycle_managed=0 WHERE id=?""", (row["reservation_id"],))
        conn = self.connection()
        conn.execute("PRAGMA ignore_check_constraints=ON")
        try:
            conn.execute("UPDATE managed_executions SET allocation_kind='damaged-kind' WHERE execution_id=?",
                         (row["execution_id"],))
        finally:
            conn.execute("PRAGMA ignore_check_constraints=OFF")
        before = self.custody()
        self.assertIs(self.maintainer.heartbeat(row["task_id"], ttl_min=999, now=NOW + 20), False)
        self.assertEqual(before, self.custody())


class AdaptiveLeaseProducerTests(unittest.TestCase):
    context = admission_fixture.ManagedAdmissionTests.context
    conn = admission_fixture.ManagedAdmissionTests.conn
    admit = admission_fixture.ManagedAdmissionTests.admit

    def setUp(self):
        admission_fixture.ManagedAdmissionTests.setUp(self)

    def test_managed_direct_captures_original_duration_and_retry_cannot_renew(self):
        context = self.context()
        config = admission_fixture.CONFIG | {"reservation_ttl_min": 2.5}
        result = self.admit(context, config=config)
        self.assertTrue(result["allowed"])
        row = dict(self.conn().execute("SELECT * FROM reservations WHERE id=?", (result["reservation_id"],)).fetchone())
        self.assertEqual(row["lease_duration_sec"], 150.0)
        self.assertEqual(row["expires_at"], NOW + 150)
        retry = self.admit(context, now=NOW + 30,
                           config=admission_fixture.CONFIG | {"reservation_ttl_min": 999})
        self.assertTrue(retry["allowed"])
        self.assertTrue(retry["reused"])
        self.assertEqual(dict(self.conn().execute("SELECT * FROM reservations WHERE id=?", (result["reservation_id"],)).fetchone()), row)

    def test_fresh_local_routed_reservation_captures_original_duration(self):
        maintainer = Maintainer(self.directory)
        maintainer.upsert_worker(maintainer_fixture.worker("fresh-local", 64, local=True,
                                os_name="windows"), now=NOW)
        result = maintainer.route_and_reserve(Task("fresh-lease", ram_gib=1,
            execution_preference="LOCAL_REQUIRED"), ttl_min=3, now=NOW)
        self.assertTrue(result["reserved"])
        row = dict(self.conn().execute("SELECT * FROM worker_reservations WHERE id=?", (result["reservation_id"],)).fetchone())
        self.assertEqual(row["lease_duration_sec"], 180.0)
        self.assertEqual(row["expires_at"], NOW + 180)

    def test_invalid_original_ttls_create_neither_direct_nor_routed_allocations(self):
        maintainer = Maintainer(self.directory)
        maintainer.upsert_worker(maintainer_fixture.worker("fresh-local", 64, local=True,
                                os_name="windows"), now=NOW)
        for ttl in (0, -1, True, float("inf"), float("nan"), 1e308):
            with self.subTest(ttl=ttl):
                with self.assertRaises(ValueError):
                    self.admit(self.context(), config=admission_fixture.CONFIG | {"reservation_ttl_min": ttl})
                with self.assertRaises(ValueError):
                    maintainer.route_and_reserve(Task("invalid-lease", ram_gib=1,
                        execution_preference="LOCAL_REQUIRED"), ttl_min=ttl, now=NOW)
                self.assertEqual(self.conn().execute("SELECT count(*) FROM reservations").fetchone()[0], 0)
                self.assertEqual(self.conn().execute("SELECT count(*) FROM worker_reservations").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
