"""Portable S3 authority boundary tests; these establish NO native gate.

The pinned artifacts, native handle backends and original-launch provenance
are explicitly synthetic. Real isolated SQLite rows exercise identity drift;
no workload is launched, OS control changed, daily DB opened for writes, or
production authority installed. Native S3 remains gated by the real provider.
"""
from copy import copy
from contextlib import closing
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.helper_control_host import HelperControlHost
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.launch_scope import RetainedLaunchProvenance
from sentinel.adaptive.launch_topology import OriginalLaunchProvenance
from sentinel.adaptive.native_job import JobAccess, JobAccounting, JobLimits, NativeJob
from tests import test_adaptive_capability_evidence as fixtures
from tests.test_adaptive_guardian_lifecycle import ProcessBackend
from tests.windows import adaptive_admission
from tests.windows.adaptive_recovery_authority import SpikeRecoveryAuthority


class SpikeRecoveryAuthorityTests(unittest.TestCase):
    def setUp(self):
        fixtures.CapabilityEvidenceTests.setUp(self)
        self.data = {key: value for key, value in self.data.items() if key in {"S1", "S2"}}
        self.directory = self.path / "isolated-s3"
        self.directory.mkdir()
        self.ledger = self.directory / "sentinel.db"
        self.processes = ProcessBackend()
        guardian = ProcessIdentity(os.getpid(), 100, fixtures.LOGON)
        wrapper = ProcessIdentity(os.getpid() + 100, 200, fixtures.LOGON)
        root = ProcessIdentity(os.getpid() + 101, 300, fixtures.LOGON)
        self.row.update(principal_id="test-fixture", spec_hash="a" * 64,
            allocation_kind="direct", reservation_id="fixture-reservation",
            job_nonce="b" * 32,
            job_name="Local\\ResourceSentinel.Job." + fixtures.EXECUTION + "." + "b" * 32,
            wrapper_pid=wrapper.pid, wrapper_created_filetime_100ns=str(wrapper.created_filetime_100ns),
            root_pid=root.pid, root_created_filetime_100ns=str(root.created_filetime_100ns))
        # Connection.__exit__ commits/rolls back but does not close the handle.
        # Close explicitly before Windows attempts to remove the isolated DB.
        with closing(sqlite3.connect(self.ledger)) as db, db:
            definitions = ",".join(name + (" INTEGER" if type(value) is int else " TEXT")
                for name, value in self.row.items())
            db.execute("CREATE TABLE fixture (" + definitions + ")")
            db.execute("INSERT INTO fixture VALUES (" + ",".join("?" for _ in self.row) + ")", tuple(self.row.values()))
        self.policy = SimpleNamespace(assert_held=Mock(return_value=None))
        self.store = SimpleNamespace(db_path=self.ledger, existing_path=True,
            _policy=self.policy, query=self._query)
        self.job = NativeJob(self.row["job_name"], self.row["job_nonce"], fixtures.LOGON, JobAccess.OWNER, None)
        self.job._ready = True
        self.job._job.state, self.job._job.value = "owned", 900
        self.job.query_limits = Mock(return_value=JobLimits(0, 0))
        self.job.accounting = Mock(return_value=JobAccounting(1, 1, 1, 1, 0))
        self.guardian = self.processes.process(guardian)
        self.wrapper = self.processes.process(wrapper)
        self.root = self.processes.process(root, job_handle=self.job.handle)
        self.entry = SimpleNamespace(job=self.job, wrapper=self.wrapper, root=self.root,
            validated=True, closed=False, terminal=False, terminal_cleanup=None,
            journal_cleanup_error=None, restore_integrity_error=None, mutex_error=None)
        self.owner = object.__new__(GuardianLaunchOwner)
        self.owner.guardian = self.guardian
        self.owner.store = self.store
        self.owner.guardian_epoch = self.row["guardian_epoch"]
        self.owner.lifecycle = SimpleNamespace(_entries={fixtures.EXECUTION: self.entry},
            guardian=self.guardian, _lock=threading.RLock(), _scope_entry=self.entry,
            _scope_thread=threading.get_ident())
        original = OriginalLaunchProvenance(wrapper, ProcessIdentity(wrapper.pid + 2, 150, fixtures.LOGON),
            root, self.topology)
        self.provenance = RetainedLaunchProvenance(fixtures.EXECUTION, self.row["job_nonce"], original)
        self.owner.launch_provenance_for = Mock(return_value=self.provenance)
        self.coverage = SimpleNamespace(assert_spike_covered=Mock(return_value=None))
        for target, value in (("tests.windows.adaptive_admission.require_continuous_admission", lambda: self.coverage),
                ("sentinel.adaptive.capability_evidence.NativeContextSource", lambda: lambda: self.context),
                ("sentinel.adaptive.capability_evidence.CurrentBuildSource", lambda: lambda: self.build)):
            patcher = patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _query(self, execution_id, *, existing_path=True):
        with closing(sqlite3.connect(self.ledger)) as db, db:
            db.row_factory = sqlite3.Row
            row = db.execute("SELECT * FROM fixture WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise ValueError("execution_not_found")
        return dict(row)

    def _change(self, name, value):
        with closing(sqlite3.connect(self.ledger)) as db, db:
            db.execute("UPDATE fixture SET " + name + "=?", (value,))

    def authority(self, **changes):
        values = dict(profile=self.profile, bundle_directory=self.path,
            expected_bundle_sha256=fixtures.CapabilityEvidenceTests.write(self),
            data_directory=self.directory, clock=lambda: self.now)
        values.update(changes)
        return SpikeRecoveryAuthority(**values)

    def ready(self):
        authority = self.authority()
        authority.bind_existing(self.owner, fixtures.EXECUTION)
        self.assertTrue(authority.assess().eligible)
        return authority

    def control(self, authority, **changes):
        values = dict(profile_revision=self.bundle["profile_revision"],
            logical_processors=self.context.logical_processors, execution_row=dict(self.row),
            guardian_identity=self.guardian.identity)
        values.update(changes)
        return authority.assert_control_eligible(**values)

    def test_default_daily_provider_refuses_without_opening_or_binding_native_owners(self):
        error = adaptive_admission.ContinuousAdmissionUnavailable("continuous_admission_provider_unavailable")
        with patch.object(adaptive_admission, "require_continuous_admission", side_effect=error):
            with self.assertRaises(adaptive_admission.ContinuousAdmissionUnavailable):
                self.authority()
        self.assertEqual(self.processes.events, [])

    def test_caller_cannot_substitute_a_coverage_owner(self):
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "daily_owner_mismatch"):
            self.authority(continuous_admission=SimpleNamespace(assert_spike_covered=lambda **_: None))

    def test_legacy_provider_without_genuine_scope_bridge_is_blocked(self):
        self.coverage = object()
        result = self.authority().assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "recovery_spike_daily_scope_unverified")

    def test_only_real_s1_s2_schema_is_accepted_without_inventing_later_gates(self):
        authority = self.ready()
        result = self.control(authority)
        self.assertEqual(result.purpose, "recovery_spike")
        production = evidence.NativeEvidenceAuthority(profile=self.profile, bundle_directory=self.path,
            expected_bundle_sha256=authority._evidence.expected_bundle_sha256,
            live_context_source=lambda: self.context, build_source=lambda: self.build, clock=lambda: self.now)
        self.assertEqual(production.assess().missing_gates, ("S3", "P4"))
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "authority_scope_invalid"):
            evidence.NativeEvidenceAuthority(profile=self.profile, purpose="recovery_spike")

    def test_global_assessment_can_start_helper_but_never_authorizes_unbound_scope(self):
        authority = self.authority()
        self.assertTrue(authority.assess().eligible)
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "scope_unbound"):
            self.control(authority)

    def test_failed_s1_numeric_measurement_is_not_a_pass_boolean(self):
        self.data["S1"]["rounds"][0]["applied"]["flags"] = 0
        result = self.authority().assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_cpu_readback_failed")

    def test_missing_s2_is_reported(self):
        del self.data["S2"]
        result = self.authority().assess()
        self.assertEqual(result.missing_gates, ("S2",))

    def test_artifact_mutation_invalidates_prepared_authority(self):
        authority = self.ready()
        (self.path / "S1.json").write_bytes(b"{}")
        self.assertFalse(authority.assess().eligible)
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "receipt_unprepared"):
            self.control(authority)

    def test_build_and_context_changes_are_not_accepted_after_initial_success(self):
        original_build, original_context = self.build, self.context
        for kind in ("build", "context"):
            with self.subTest(kind=kind):
                self.build, self.context = original_build, original_context
                authority = self.ready()
                if kind == "build":
                    self.build = evidence.BuildIdentity("1" * 64, "2" * 64)
                else:
                    self.context = replace(self.context, os_build=self.context.os_build + 1)
                self.assertFalse(authority.assess().eligible)

    def test_closed_or_ambiguous_native_owners_invalidate_fresh_receipt(self):
        authority = self.ready()
        self.job._job.state = "close_unknown"
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "native_custody_unavailable"):
            self.control(authority)
        self.job._job.state = "owned"
        for process in (self.guardian, self.wrapper, self.root):
            for field, value in (("_handle", None), ("_close_outcome_unknown", True)):
                previous = getattr(process, field)
                setattr(process, field, value)
                with self.subTest(pid=process.identity.pid, field=field):
                    with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "native_custody_unavailable"):
                        self.control(authority)
                setattr(process, field, previous)

    def test_original_launch_topology_must_match_actual_s2_records(self):
        authority = self.ready()
        changed = replace(self.provenance.provenance,
            topology=replace(self.topology, stdio_types=("disk", "disk", "disk")))
        self.owner.launch_provenance_for.return_value = replace(self.provenance, provenance=changed)
        with self.assertRaisesRegex(Exception, "launch_scope_unverified"):
            self.control(authority)

    def test_observed_only_topology_cannot_borrow_complete_profiles_cases(self):
        partial = replace(self.topology, stdio_types=("disk", "disk", "disk"))
        host = self.data["S2"]["hosts"][0]
        host["measured_topologies"].append(partial.to_dict())
        sample = next(row for row in host["cases"] if row["case"] == "exit_0")
        host["cases"].append({**sample, "topology_sha256": partial.sha256})
        authority = self.ready()
        self.assertEqual(authority.prepared_launch_topologies().topologies, (self.topology,))
        self.owner.launch_provenance_for.return_value = replace(self.provenance,
            provenance=replace(self.provenance.provenance, topology=partial))
        with self.assertRaisesRegex(Exception, "launch_scope_unverified"):
            self.control(authority)

    def test_exact_entry_replacement_is_rejected_even_with_same_job_and_nonce(self):
        authority = self.ready()
        self.owner.lifecycle._entries[fixtures.EXECUTION] = copy(self.entry)
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "custody_changed"):
            self.control(authority)

    def test_unsafe_custody_states_refuse_without_native_queries_inside_assertion(self):
        authority = self.ready()
        for field, value in (("closed", True), ("terminal", True), ("terminal_cleanup", object()),
                ("journal_cleanup_error", RuntimeError()), ("restore_integrity_error", RuntimeError()),
                ("mutex_error", RuntimeError()), ("validated", False)):
            previous = getattr(self.entry, field)
            setattr(self.entry, field, value)
            with self.subTest(field=field):
                with self.assertRaises(evidence.CapabilityEvidenceError):
                    self.control(authority)
            setattr(self.entry, field, previous)
        self.job.accounting.reset_mock()
        self.job.query_limits.reset_mock()
        self.coverage.assert_spike_covered.reset_mock()
        with patch.object(self.store, "query", side_effect=AssertionError("locked SQL")), \
                patch.object(self.guardian, "observe", side_effect=AssertionError("locked native query")), \
                patch.object(authority._evidence, "_load", side_effect=AssertionError("locked file read")):
            self.assertEqual(self.control(authority).purpose, "recovery_spike")
        self.job.accounting.assert_not_called()
        self.job.query_limits.assert_not_called()
        self.coverage.assert_spike_covered.assert_not_called()

    def test_guardian_must_hold_its_exact_lifecycle_scope(self):
        authority = self.ready()
        self.owner.lifecycle._scope_entry = None
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "guardian_scope_required"):
            self.control(authority)

    def test_wrong_execution_identity_or_priority_never_borrows_the_single_scope(self):
        authority = self.ready()
        for field, value in (("execution_id", fixtures.RUN), ("job_nonce", "c" * 32),
                ("wrapper_pid", self.wrapper.identity.pid + 10), ("guardian_epoch", "other"),
                ("role", "foreground"), ("priority", "P1"), ("launch_in_flight", 1)):
            with self.subTest(field=field):
                with self.assertRaises(evidence.CapabilityEvidenceError):
                    self.control(authority, execution_row=self.row | {field: value})

    def test_ledger_identity_changes_fail_refresh(self):
        authority = self.ready()
        self._change("wrapper_created_filetime_100ns", "201")
        self.assertEqual(authority.assess().reason, "recovery_spike_execution_changed")

    def test_daily_admission_failure_invalidates_previous_receipt(self):
        authority = self.ready()
        self.coverage.assert_spike_covered.side_effect = RuntimeError("daily coverage lost")
        self.assertFalse(authority.assess().eligible)
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "receipt_unprepared"):
            self.control(authority)
        self.assertFalse(self.job.closed)
        self.assertIs(self.owner.lifecycle._entries[fixtures.EXECUTION], self.entry)

    def test_refresh_cannot_extend_fixed_120_second_deadline_or_drop_custody(self):
        authority = self.ready()
        start = self.now
        for second in (30, 60, 90, 119):
            self.now = start + second * fixtures.T
            self.assertTrue(authority.assess().eligible)
        self.now = start + 120 * fixtures.T
        self.assertEqual(authority.assess().reason, "recovery_spike_deadline_expired")
        self.assertEqual(authority._start, start)
        self.assertIs(authority._scope.job, self.job)
        self.assertEqual(self.processes.entry(self.root).closed, False)

    def test_late_host_start_cannot_extend_original_case_deadline(self):
        deadline = self.now + 10_000_000
        authority = self.authority(observation_deadline_tick=deadline)
        authority.bind_existing(self.owner, fixtures.EXECUTION)
        self.assertTrue(authority.assess().eligible)
        self.now = deadline
        self.assertEqual(authority.assess().reason, "recovery_spike_deadline_expired")
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "deadline_invalid"):
            self.authority(observation_deadline_tick=self.now + 121 * 10_000_000)

    def test_stale_receipt_and_clock_regression_cannot_restrict(self):
        authority = self.ready()
        self.now += self.profile.sample_max_age_ms * 10_000 + 1
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "receipt_stale"):
            self.control(authority)
        self.now -= 2
        self.assertEqual(authority.assess().reason, "recovery_spike_deadline_expired")

    def test_scope_can_be_bound_only_once_including_a_failed_attempt(self):
        authority = self.authority()
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "original_guardian_required"):
            authority.bind_existing(SimpleNamespace(), fixtures.EXECUTION)
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "scope_already_bound"):
            authority.bind_existing(self.owner, fixtures.EXECUTION)

    def test_daily_directory_and_relative_directory_are_refused(self):
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "isolated_directory_required"):
            self.authority(data_directory=Path("relative"))
        # Point a mocked home at an existing temporary directory to avoid any
        # reliance on the real daily runtime or permissions.
        fake_home = self.path / "home"
        daily = fake_home / ".resource-sentinel"
        daily.mkdir(parents=True)
        with patch.object(Path, "home", return_value=fake_home):
            with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "daily_directory_forbidden"):
                self.authority(data_directory=daily)

    def helper_authority(self):
        helper = object.__new__(HelperControlHost)
        helper._started = True
        helper.store = self.store
        helper.process = self.guardian  # current native process is the helper in this fixture.
        endpoint_guardian = ProcessIdentity(os.getpid() + 900, 90, fixtures.LOGON)
        helper.control_endpoint = SimpleNamespace(server_identity=endpoint_guardian)
        helper.control_guardian_epoch = self.row["guardian_epoch"]
        self.job.access = JobAccess.QUERY
        entry = SimpleNamespace(job=self.job, counter_epoch="query-epoch", unreadable=False,
            cleanup_unverified=False, membership_provable=True)
        helper.jobs = SimpleNamespace(_entries={fixtures.EXECUTION: entry})
        authority = self.authority()
        with patch.object(VerifiedProcess, "open", side_effect=[self.wrapper, self.root]):
            authority.bind_helper(helper, fixtures.EXECUTION)
        self.assertTrue(authority.assess().eligible)
        return authority, helper, entry

    def test_helper_query_binding_proposes_but_cannot_impersonate_guardian_actuator(self):
        authority, helper, entry = self.helper_authority()
        row = {key: self.row[key] for key in ("execution_id", "principal_id", "logon_id", "job_name",
            "job_nonce", "role", "priority", "coverage", "state", "guardian_epoch", "launch_sealed", "launch_in_flight")}
        row["counter_epoch"] = entry.counter_epoch
        self.assertEqual(self.control(authority, execution_row=row,
            guardian_identity=helper.control_endpoint.server_identity).purpose, "recovery_spike")
        with self.assertRaises(evidence.CapabilityEvidenceError):
            self.control(authority, execution_row=row, guardian_identity=helper.process.identity)
        self.owner.launch_provenance_for.assert_not_called()

    def test_helper_reopened_handle_epoch_and_cleanup_uncertainty_refuse(self):
        authority, helper, entry = self.helper_authority()
        row = self.row | {"counter_epoch": entry.counter_epoch}
        identity = helper.control_endpoint.server_identity
        for field, value in (("counter_epoch", "other"), ("cleanup_unverified", True),
                ("membership_provable", False), ("unreadable", True)):
            previous = getattr(entry, field)
            setattr(entry, field, value)
            with self.subTest(field=field):
                with self.assertRaises(evidence.CapabilityEvidenceError):
                    self.control(authority, execution_row=row, guardian_identity=identity)
            setattr(entry, field, previous)
        helper.jobs._entries[fixtures.EXECUTION] = copy(entry)
        with self.assertRaises(evidence.CapabilityEvidenceError):
            self.control(authority, execution_row=row, guardian_identity=identity)

    def test_helper_wrapper_reopen_failure_retains_original_error_and_prior_owner(self):
        authority = self.authority()
        helper = object.__new__(HelperControlHost)
        helper._started, helper.store = True, self.store
        helper.jobs = SimpleNamespace(_entries={fixtures.EXECUTION: object()})
        error = RuntimeError("root open uncertain")
        with patch.object(VerifiedProcess, "open", side_effect=[self.wrapper, error]):
            with self.assertRaises(RuntimeError):
                authority.bind_helper(helper, fixtures.EXECUTION)
        self.assertIs(authority._binding_failure, error)
        self.assertEqual(authority._retained_processes, [self.wrapper])
        self.assertFalse(self.processes.entry(self.wrapper).closed)

    def test_closing_helper_witnesses_invalidates_authority_without_closing_job(self):
        authority, helper, entry = self.helper_authority()
        authority.close_helper_witnesses()
        self.assertEqual(authority._retained_processes, [])
        self.assertFalse(self.job.closed)
        self.assertIs(helper.jobs._entries[fixtures.EXECUTION], entry)
        self.assertFalse(authority.assess().eligible)


if __name__ == "__main__":
    unittest.main()
