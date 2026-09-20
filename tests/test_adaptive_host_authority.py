"""Live host authority checks against real isolated SQLite and a real journal.

The ledger, the policy coordinator, the accounting validator, the legacy writer
registry and the managed admission transaction below are the production
modules. The processes, Jobs and mutexes come from the guardian lifecycle
fixture and are explicit in-process backends, as that module states.

The Windows capability preflight is the one check with no fixture. Where a test
needs to get past it, it patches this module's own read_host_capability and
says so at the site. That patch is a synthetic capability record and proves
nothing about this or any other host.
"""
from contextlib import closing, contextmanager
import os
import sqlite3
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sentinel.adaptive import host_authority as module
from sentinel.adaptive.host_authority import (
    HostAuthority, HostAuthorityError, HostCapability, HostCapabilityUnsupported,
    HostReadinessError, read_host_capability,
)
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.store import LifecycleError, LifecycleStore
from sentinel.coordinator import Coordinator
from tests import test_adaptive_guardian_lifecycle as fixture
from tests.fixtures.adaptive_evidence import FixturePolicyProvider
from tests.test_adaptive_admission_context import FakeCurrentProcess, PAYLOAD
from tests.test_adaptive_coordinator import CONFIG, status
from tests.test_adaptive_lifecycle import NOW


CAPABILITY_REASONS = frozenset({
    "host_platform_unsupported", "host_native_api_unavailable",
    "host_parent_job_membership_unknown", "host_foreign_parent_job",
    "host_processor_topology_unsupported", "host_processor_affinity_unknown",
    "host_processor_affinity_restricted", "host_os_version_unavailable"})
# An explicitly synthetic record. It is never produced by a real read.
SYNTHETIC = HostCapability("win32", 10, 0, 26340, 8, 1, "255", os.getpid())


def live_capability_refusal():
    """The live refusal on the machine running these tests, or None."""
    try:
        read_host_capability()
    except HostCapabilityUnsupported as error:
        return error.reason
    return None


@contextmanager
def synthetic_capability():
    """Stand in for the capability preflight to reach the checks behind it."""
    with patch.object(module, "read_host_capability", return_value=SYNTHETIC):
        yield SYNTHETIC


class CapabilityTests(unittest.TestCase):
    def test_this_host_refuses_with_a_typed_reason_or_reports_support(self):
        reason = live_capability_refusal()
        if reason is None:
            self.assertIsInstance(read_host_capability(), HostCapability)
        else:
            self.assertIn(reason, CAPABILITY_REASONS)

    def test_no_check_returns_success_from_a_constant(self):
        # The record carries no readiness field that a caller could trust.
        self.assertNotIn("ready", SYNTHETIC.to_dict())
        self.assertNotIn("supported", SYNTHETIC.to_dict())


class GuardianSurfaceTests(unittest.TestCase):
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    sql = fixture.GuardianLifecycleTests.sql

    def setUp(self):
        fixture.GuardianLifecycleTests.setUp(self)
        self.case = self.seed_started()
        self.execution_id = self.case.spec.execution_id
        self.store = LifecycleStore(self.db, existing_path=True, policy_provider=self.policy)
        self.authority = self.build()

    def build(self, *, guardian=True, now=NOW + 10):
        return HostAuthority(self.store, guardian=self.guardian if guardian else None,
                             clock=lambda: now)

    def row(self):
        return self.store.query(self.execution_id)

    @contextmanager
    def ledger_locked(self):
        """A real exclusive file lock, so every reader gets SQLITE_BUSY."""
        for connection in self.setup_connections:
            connection.close()
        with closing(sqlite3.connect(self.db, timeout=0, isolation_level=None)) as blocker:
            blocker.execute("PRAGMA locking_mode=EXCLUSIVE")
            blocker.execute("BEGIN EXCLUSIVE")
            try:
                yield
            finally:
                blocker.execute("ROLLBACK")

    @contextmanager
    def policy_held(self):
        policy = self.store._policy
        guard = policy.prepare(policy.current_logon())
        with policy.hold(guard):
            yield guard

    def initialize_registry(self):
        from sentinel.adaptive.legacy_writer import initialize_registry_locked

        with self.policy_held():
            initialize_registry_locked(self.store)

    def register_guardian(self):
        from sentinel.adaptive.legacy_writer import (
            initialize_registry_locked, register_infrastructure_locked,
        )
        with self.policy_held():
            initialize_registry_locked(self.store)
            register_infrastructure_locked(self.store, "guardian", self.guardian)

    # --- assert_ready -----------------------------------------------------

    def test_ready_mirrors_the_live_preflight_exactly(self):
        reason = live_capability_refusal()
        if reason is None:
            self.assertIsNone(self.authority.assert_ready())
        else:
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_ready()
            self.assertEqual(caught.exception.reason, reason)
            self.assertIsInstance(caught.exception, LifecycleError)

    def test_ready_refuses_when_job_membership_is_unknown(self):
        unknown = HostCapabilityUnsupported("host_parent_job_membership_unknown", 5)
        with patch.object(module, "read_host_capability", side_effect=unknown):
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_ready()
        self.assertEqual(caught.exception.reason, "host_parent_job_membership_unknown")
        self.assertEqual(caught.exception.win32_error, 5)

    def test_ready_reads_the_host_on_every_call(self):
        with patch.object(module, "read_host_capability", return_value=SYNTHETIC) as reader:
            self.authority.assert_ready()
            self.authority.assert_ready()
        self.assertEqual(reader.call_count, 2)

    # --- assert_covered ---------------------------------------------------

    def test_covered_accepts_a_live_row_with_an_unexpired_lease(self):
        self.assertIsNone(self.authority.assert_covered(self.row()))

    def test_covered_refuses_an_elapsed_lease(self):
        authority = self.build(now=NOW + 3600)
        with self.assertRaises(HostAuthorityError) as caught:
            authority.assert_covered(self.row())
        self.assertEqual(caught.exception.reason, "host_coverage_lease_expired")

    def test_covered_refuses_a_clock_that_precedes_the_heartbeat(self):
        authority = self.build(now=NOW - 5)
        with self.assertRaises(HostAuthorityError) as caught:
            authority.assert_covered(self.row())
        self.assertEqual(caught.exception.reason, "host_coverage_clock_regression")

    def test_covered_refuses_an_unreadable_clock(self):
        authority = HostAuthority(self.store, guardian=self.guardian,
                                  clock=lambda: float("nan"))
        with self.assertRaises(HostAuthorityError) as caught:
            authority.assert_covered(self.row())
        self.assertEqual(caught.exception.reason, "host_coverage_clock_unavailable")

    def test_covered_refuses_a_stale_revision(self):
        row = dict(self.row())
        row["state_revision"] += 1
        with self.assertRaises(HostAuthorityError) as caught:
            self.authority.assert_covered(row)
        self.assertEqual(caught.exception.reason, "host_coverage_row_mismatch")

    def test_covered_refuses_an_execution_the_ledger_does_not_have(self):
        row = dict(self.row())
        row["execution_id"] = "11111111-2222-4333-8444-555555555555"
        with self.assertRaises(HostAuthorityError) as caught:
            self.authority.assert_covered(row)
        self.assertEqual(caught.exception.reason, "host_coverage_execution_missing")

    def test_covered_refuses_a_held_execution(self):
        self.sql("UPDATE managed_executions SET hold_reason='fixture_hold' WHERE execution_id=?",
                 (self.execution_id,))
        with self.assertRaises(HostAuthorityError) as caught:
            self.authority.assert_covered(self.row())
        self.assertEqual(caught.exception.reason, "host_coverage_hold_active")

    def test_covered_refuses_when_the_allocation_cannot_be_validated(self):
        """The accounting refusal is translated, not reinterpreted.

        The ledger will not let a fixture remove the reservation behind an
        active execution: the managed_allocation_release_requires_terminal
        trigger rejects that delete. The refusal is raised here instead, from
        the same validator the production path calls.
        """
        from sentinel.accounting import AccountingError

        with patch.object(module, "validate_active_allocation",
                          side_effect=AccountingError("fixture_allocation_unverified")):
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_covered(self.row())
        self.assertEqual(caught.exception.reason, "host_coverage_allocation_unverified")

    def test_covered_refuses_while_the_ledger_cannot_be_read(self):
        row = self.row()
        with self.ledger_locked():
            with self.assertRaises(HostAuthorityError):
                self.authority.assert_covered(row)

    def test_covered_never_writes(self):
        before = self.connection().execute(
            "SELECT state_revision,heartbeat_at FROM managed_executions WHERE execution_id=?",
            (self.execution_id,)).fetchone()
        self.authority.assert_covered(self.row())
        after = self.connection().execute(
            "SELECT state_revision,heartbeat_at FROM managed_executions WHERE execution_id=?",
            (self.execution_id,)).fetchone()
        self.assertEqual(tuple(before), tuple(after))

    # --- assert_excluded --------------------------------------------------

    def test_excluded_accepts_a_registered_guardian_and_a_live_scope(self):
        self.register_guardian()
        with self.policy_held():
            self.assertIsNone(self.authority.assert_excluded(self.row()))

    def test_excluded_refuses_without_the_policy_scope(self):
        self.register_guardian()
        with self.assertRaises(HostAuthorityError) as caught:
            self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_policy_not_held")

    def test_excluded_refuses_without_a_retained_guardian(self):
        self.register_guardian()
        authority = self.build(guardian=False)
        with self.policy_held():
            with self.assertRaises(HostAuthorityError) as caught:
                authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_guardian_unavailable")

    def test_excluded_refuses_an_unregistered_guardian(self):
        """A readable registry that does not list this guardian still refuses."""
        self.initialize_registry()
        with self.policy_held():
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_guardian_unregistered")

    def test_excluded_refuses_a_row_with_no_job_scope(self):
        self.register_guardian()
        row = dict(self.row())
        row["job_name"] = None
        with self.policy_held():
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_excluded(row)
        self.assertEqual(caught.exception.reason, "host_exclusion_scope_unknown")

    def test_excluded_refuses_when_the_writer_fence_is_missing(self):
        self.register_guardian()
        with patch("sentinel.adaptive.writers.writer_obligations_present", return_value=False):
            with self.policy_held():
                with self.assertRaises(HostAuthorityError) as caught:
                    self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_writer_fence_absent")

    def test_excluded_refuses_when_the_writer_fence_cannot_be_read(self):
        self.register_guardian()
        with patch("sentinel.adaptive.writers.writer_obligations_present",
                   side_effect=ValueError("fixture_fence_unreadable")):
            with self.policy_held():
                with self.assertRaises(HostAuthorityError) as caught:
                    self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_writer_fence_unknown")

    def test_excluded_refuses_when_the_registry_cannot_be_read(self):
        self.register_guardian()
        with patch("sentinel.adaptive.legacy_writer._registry_locked",
                   side_effect=sqlite3.OperationalError("database is locked")):
            with self.policy_held():
                with self.assertRaises(HostAuthorityError) as caught:
                    self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_registry_unavailable")

    def test_excluded_refuses_a_dead_guardian(self):
        from sentinel.adaptive.contracts import IdentityStatus

        self.register_guardian()
        self.processes.entry(self.guardian).state = IdentityStatus.DEAD
        with self.policy_held():
            with self.assertRaises(HostAuthorityError) as caught:
                self.authority.assert_excluded(self.row())
        self.assertEqual(caught.exception.reason, "host_exclusion_guardian_unavailable")


class WrapperSurfaceTests(unittest.TestCase):
    """The wrapper readiness path over a real managed admission transaction."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.process = FakeCurrentProcess()
        self.logon = self.process.identity.logon_id
        self.policy = FixturePolicyProvider(self.logon)
        self.coordinator = Coordinator(self.directory, pid_identity=lambda pid: (None, 0.0),
                                       policy_provider=self.policy)
        current = patch("sentinel.adaptive.admission.VerifiedProcess.current",
                        return_value=self.process)
        current.start()
        self.addCleanup(current.stop)
        cpus = patch("os.cpu_count", return_value=12)
        cpus.start()
        self.addCleanup(cpus.stop)
        self.store = LifecycleStore(self.coordinator.db_path, existing_path=True,
                                    policy_provider=self.policy)
        self.authority = HostAuthority(self.store)
        self.admission = self.admit()
        self.endpoint = NativePipeEndpoint(self.logon, "12345678-1234-4234-8234-1234567890ab",
                                           self.server())

    def server(self):
        from dataclasses import replace

        return replace(self.process.identity, pid=self.process.identity.pid + 1)

    def admit(self):
        from sentinel.adaptive.admission import ManagedAdmission

        admission = ManagedAdmission.current(**PAYLOAD)
        self.addCleanup(admission.close)
        result = self.coordinator.admit_managed(admission, status(now=NOW), now=NOW, config=CONFIG)
        self.assertTrue(result["allowed"])
        self.execution_id = admission.snapshot().execution_id
        return admission

    def row(self):
        return self.store.query(self.execution_id, existing_path=True)

    def test_launch_ready_refuses_on_this_host_before_reading_the_ledger(self):
        reason = live_capability_refusal()
        if reason is None:
            self.skipTest("this host passes the capability preflight")
        row = self.row()
        with patch.object(self.store, "query", side_effect=AssertionError("ledger read before preflight")):
            with self.assertRaises(HostReadinessError) as caught:
                self.authority.assert_launch_ready(self.admission, row, self.endpoint)
        self.assertEqual(caught.exception.reason, reason)

    def test_launch_ready_accepts_a_covered_admission(self):
        with synthetic_capability():
            self.assertIsNone(self.authority.assert_launch_ready(
                self.admission, self.row(), self.endpoint))

    def test_launch_ready_requires_the_real_admission_object(self):
        stand_in = SimpleNamespace(snapshot=lambda: self.admission.snapshot())
        with synthetic_capability():
            with self.assertRaises(HostReadinessError) as caught:
                self.authority.assert_launch_ready(stand_in, self.row(), self.endpoint)
        self.assertEqual(caught.exception.reason, "host_readiness_admission_required")

    def test_launch_ready_refuses_an_endpoint_bound_to_the_wrapper_itself(self):
        endpoint = NativePipeEndpoint(self.logon, "12345678-1234-4234-8234-1234567890ac",
                                      self.process.identity)
        with synthetic_capability():
            with self.assertRaises(HostReadinessError) as caught:
                self.authority.assert_launch_ready(self.admission, self.row(), endpoint)
        self.assertEqual(caught.exception.reason, "host_readiness_endpoint_self_bound")

    def test_launch_ready_refuses_a_row_for_another_execution(self):
        row = dict(self.row())
        row["execution_id"] = "11111111-2222-4333-8444-555555555555"
        with synthetic_capability():
            with self.assertRaises(HostReadinessError) as caught:
                self.authority.assert_launch_ready(self.admission, row, self.endpoint)
        self.assertEqual(caught.exception.reason, "host_readiness_row_mismatch")

    def test_launch_ready_refuses_when_the_ledger_cannot_be_read(self):
        row = self.row()
        with synthetic_capability():
            with patch.object(self.store, "query",
                              side_effect=LifecycleError("coverage_database_busy")):
                with self.assertRaises(HostReadinessError) as caught:
                    self.authority.assert_launch_ready(self.admission, row, self.endpoint)
        self.assertEqual(caught.exception.reason, "coverage_database_busy")

    def test_launch_ready_refuses_a_terminal_execution(self):
        row = self.row()
        with closing(sqlite3.connect(self.coordinator.db_path)) as conn, conn:
            conn.execute("UPDATE managed_executions SET state='FINISHED' WHERE execution_id=?",
                         (self.execution_id,))
        with synthetic_capability():
            with self.assertRaises(HostReadinessError) as caught:
                self.authority.assert_launch_ready(self.admission, row, self.endpoint)
        self.assertEqual(caught.exception.reason, "host_readiness_row_mismatch")


if __name__ == "__main__":
    unittest.main()
