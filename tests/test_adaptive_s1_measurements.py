"""Portable S1 measurement tests; never a native capability result.

File observations use actual temporary regular files. Clocks and native APIs
are explicit synthetic seams. The cleanup cases compose real provider,
ExperimentNativeScope, journal, isolated SQLite and original daily release;
only their native/source-location collaborators are fixtures.
"""
from contextlib import closing, ExitStack
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import CpuState, JobAccounting, JobLimits, JobSecurity, NativeJob
from sentinel.adaptive.windows import SecurityObservation
from tests import test_adaptive_experiment_release_native as native_fixtures
from tests import test_adaptive_s1_provider as provider_fixtures
from tests.test_adaptive_identity import Backend, IDENTITY
from tests.windows import adaptive_s1_measurements as measurements
from tests.windows import adaptive_s1_provider as provider
from tests.windows.adaptive_scope_launch import ScopeLaunch
from tests.windows.adaptive_capability_runner import custody_pending


def context():
    return evidence.LiveCapabilityContext("c" * 64, 10, 0, 26100, 12, 1, "4095",
        IDENTITY.logon_id, 1, 0, "3.13.0", 64, "d" * 64, False, "e" * 64)


def security():
    return JobSecurity("S-1-5-21-1-2-3-1000", IDENTITY.logon_id, 0x1004, 1, 2, 1, 0, 0, 0x001F003F, 0)


def stat_copy(value, **changes):
    fields = ("st_dev", "st_ino", "st_size", "st_mode", "st_mtime_ns", "st_ctime_ns",
        "st_birthtime_ns", "st_file_attributes")
    return SimpleNamespace(**({field: getattr(value, field) for field in fields
        if hasattr(value, field)} | changes))


class RegularRecordTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name).resolve() / "record.json"
        self.path.write_bytes(b'{"value":1}')

    def test_reads_actual_regular_file(self):
        self.assertEqual(measurements._regular_record(self.path), {"value": 1})

    def test_windows_path_and_handle_ctime_families_may_differ(self):
        original = os.fstat
        with patch.object(measurements.os, "fstat", side_effect=lambda fd:
                stat_copy(original(fd), st_ctime_ns=original(fd).st_ctime_ns + 123456789)):
            self.assertEqual(measurements._regular_record(self.path), {"value": 1})

    def test_handle_ctime_change_with_unchanged_path_is_refused(self):
        original, calls = os.fstat, []
        def changing(fd):
            calls.append(fd)
            observed = original(fd)
            return stat_copy(observed, st_ctime_ns=observed.st_ctime_ns + len(calls))
        with patch.object(measurements.os, "fstat", side_effect=changing), \
                self.assertRaisesRegex(measurements.NativeRunBlocked, "fixture_file_changed"):
            measurements._regular_record(self.path)

    def test_path_replacement_after_original_open_is_refused(self):
        original = Path.lstat
        calls = []
        def replaced(path, *args, **kwargs):
            observed = original(path, *args, **kwargs)
            if path == self.path:
                calls.append(path)
                if len(calls) == 2:
                    return stat_copy(observed, st_ino=observed.st_ino + 1)
            return observed
        with patch.object(Path, "lstat", replaced), \
                self.assertRaisesRegex(measurements.NativeRunBlocked, "fixture_file_changed"):
            measurements._regular_record(self.path)

    def test_oversize_and_nonregular_refuse_before_open(self):
        self.path.write_bytes(b"x" * (measurements.MAX_RECORD_BYTES + 1))
        for path in (self.path, self.path.parent):
            with self.subTest(path=path.name), patch.object(Path, "open") as opened, \
                    self.assertRaisesRegex(measurements.NativeRunBlocked, "fixture_file_invalid"):
                measurements._regular_record(path)
            opened.assert_not_called()

    def test_redirected_path_refuses_before_open(self):
        original = Path.lstat
        def redirected(path, *args, **kwargs):
            return stat_copy(original(path, *args, **kwargs), st_file_attributes=0x400)
        with patch.object(Path, "lstat", redirected), patch.object(Path, "open") as opened, \
                self.assertRaisesRegex(measurements.NativeRunBlocked, "fixture_file_invalid"):
            measurements._regular_record(self.path)
        opened.assert_not_called()

    def test_duplicate_keys_trailing_data_and_nonobject_are_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{}{}', b'[]'):
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                with self.assertRaises((ValueError, measurements.NativeRunBlocked)):
                    measurements._regular_record(self.path)


class TreeAndExitTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name).resolve()
        self.backends, witnesses = [], []
        for number in range(3):
            backend = Backend()
            backend.value = replace(IDENTITY, pid=IDENTITY.pid + number,
                created_filetime_100ns=IDENTITY.created_filetime_100ns + number)
            witness = VerifiedProcess(backend, 700 + number, backend.value)
            self.addCleanup(witness.close)
            self.backends.append(backend)
            witnesses.append(witness)
        self.guardian, self.wrapper, self.root = witnesses
        self.child = replace(IDENTITY, pid=IDENTITY.pid + 3,
            created_filetime_100ns=IDENTITY.created_filetime_100ns + 3)
        self.deadline = 110_000_000_000
        info = self.directory.stat()
        # These data-only helpers validate records, never grant case authority.
        # Public producer/provider exact-type rejection is tested separately.
        self.case = SimpleNamespace(directory=self.directory, creation_nonce="a" * 32, scope_id="scope",
            provider=SimpleNamespace(context=context()),
            spec=SimpleNamespace(kind="round", workers=2, seconds=115,
                directory_identity=(info.st_dev, info.st_ino),
                generation_json=json.dumps(dict(generation="generation", source_digest="b" * 64)),
                command=SimpleNamespace(arguments=("-I", "fixture.py"),
                    fixture_sources=(SimpleNamespace(path="fixture.py", sha256="c" * 64),))),
            scope=SimpleNamespace(deadline=120., job_name="Local\\ResourceSentinel.Test.Job." + "a" * 32,
                guardian=self.guardian,
                launch=SimpleNamespace(wrapper_witness=self.wrapper, root_witness=self.root)))
        self.manifest = dict(schema_version=1, status="tree_ready", root_identity=self.root.identity.to_dict(),
            child_identities=[self.child.to_dict()], deadline_monotonic_ns=self.deadline,
            **measurements._pins(self.case))
        self.records = {value.pid: self.record(value) for value in (self.root.identity, self.child)}

    def record(self, identity, *, exit=False):
        value = dict(schema_version=1, status="ready", identity=identity.to_dict(), **identity.to_dict(),
            **measurements._pins(self.case), in_expected_job=True, readiness_scope="this_process_only",
            role="root" if identity == self.root.identity else "leaf",
            parent_pid=self.wrapper.identity.pid if identity == self.root.identity else self.root.identity.pid,
            deadline_monotonic_ns=self.deadline, deadline_monotonic=self.deadline / 1_000_000_000,
            maximum_cpu_work_seconds=115., cooperative_cleanup_grace_seconds=4)
        if exit:
            value.update(status="work_complete", reason="stop_file", work_chunks=30,
                elapsed_seconds=90., children_still_alive=0, owned_handles_closed=True)
        return value

    def publish_exits(self):
        for identity in (self.root.identity, self.child):
            (self.directory / f"exit-{identity.pid}.json").write_text(
                json.dumps(self.record(identity, exit=True)), encoding="utf-8")

    def test_root_manifest_matches_children_in_create_order_and_native_pid_set(self):
        tree = measurements._tree(self.case, self.manifest, self.records)
        self.assertEqual(tree.children, (self.child,))
        self.case.scope.job = SimpleNamespace(handle=999,
            active_pids=lambda: tuple(reversed(tuple(tree.pids))),
            accounting=lambda: JobAccounting(2**53 + 1, 7, 2, 2, 0))
        self.assertEqual(measurements._membership(self.case.scope, tree).cpu_100ns, 2**53 + 8)
        self.assertEqual(self.backends[2].opened, [])

    def test_final_child_published_with_manifest_before_complete_scan(self):
        (self.directory / f"ready-{self.root.identity.pid}.json").write_text(
            json.dumps(self.records[self.root.identity.pid]), encoding="utf-8")
        manifest_path = self.directory / "tree-ready.json"
        original_exists, clock = Path.exists, Clock()
        published = []
        def publication(path):
            if path == manifest_path and not original_exists(path):
                (self.directory / f"ready-{self.child.pid}.json").write_text(
                    json.dumps(self.records[self.child.pid]), encoding="utf-8")
                manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
                published.append(True)
            return original_exists(path)
        self.case.scope.assert_covered = Mock()
        self.case.scope.job = SimpleNamespace(handle=999,
            active_pids=lambda: (self.root.identity.pid, self.child.pid),
            accounting=lambda: JobAccounting(1, 2, 2, 2, 0))
        with patch.object(Path, "exists", publication), patch.object(measurements, "time", clock), \
                patch.object(measurements, "_original_scope", return_value=self.case.scope):
            tree = measurements._ready(self.case)
        self.assertEqual(tree.children, (self.child,))
        self.assertEqual(published, [True])
        self.assertEqual(clock.waits, [])

    def test_reused_child_pid_creation_and_pin_mismatch_are_refused(self):
        for changed in (
                {"identity": replace(self.child, created_filetime_100ns=self.child.created_filetime_100ns + 1).to_dict()},
                {"source_digest": "d" * 64}, {"parent_pid": self.wrapper.identity.pid},
                {"deadline_monotonic_ns": self.deadline + 1}, {"in_expected_job": 1}):
            with self.subTest(changed=next(iter(changed))):
                records = dict(self.records)
                records[self.child.pid] = records[self.child.pid] | changed
                with self.assertRaises(measurements.NativeRunBlocked):
                    measurements._tree(self.case, self.manifest, records)

    def test_duplicate_child_and_extended_scope_deadline_are_refused(self):
        for changed in ({"child_identities": [self.root.identity.to_dict()]},
                {"deadline_monotonic_ns": 117_000_000_000}):
            with self.subTest(changed=next(iter(changed))), self.assertRaises(measurements.NativeRunBlocked):
                measurements._tree(self.case, self.manifest | changed, self.records)

    def test_every_child_exit_is_required_and_preserves_original_tree(self):
        tree = measurements._tree(self.case, self.manifest, self.records)
        self.publish_exits()
        result = measurements._exit_records(self.case, tree, None)
        self.assertEqual(set(result), {str(self.root.identity.pid), str(self.child.pid)})
        (self.directory / f"exit-{self.child.pid}.json").unlink()
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "fixture_exit_membership_mismatch"):
            measurements._exit_records(self.case, tree, None)

    def test_child_unclosed_handles_or_changed_identity_cannot_prove_completion(self):
        tree = measurements._tree(self.case, self.manifest, self.records)
        for changed in ({"owned_handles_closed": False}, {"children_still_alive": 1},
                {"identity": replace(self.child, created_filetime_100ns=self.child.created_filetime_100ns + 1).to_dict()}):
            with self.subTest(changed=next(iter(changed))):
                self.publish_exits()
                (self.directory / f"exit-{self.child.pid}.json").write_text(
                    json.dumps(self.record(self.child, exit=True) | changed), encoding="utf-8")
                with self.assertRaises(measurements.NativeRunBlocked):
                    measurements._exit_records(self.case, tree, None)

    def test_foreign_probe_exit_retains_exact_gate_and_reason(self):
        self.case.spec.kind, self.case.spec.workers = "foreign_parent", 1
        probe = self.record(self.root.identity) | {"foreign_gate": dict(
            status="unsupported", reason="host_foreign_parent_job", win32_error=None)}
        record = self.record(self.root.identity, exit=True) | dict(
            reason="foreign_host_probe", foreign_gate=probe["foreign_gate"])
        path = self.directory / f"exit-{self.root.identity.pid}.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        self.assertEqual(measurements._exit_records(self.case, None, probe)[str(self.root.identity.pid)], record)
        record["foreign_gate"] = dict(status="unexpectedly_supported")
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "foreign_exit_changed"):
            measurements._exit_records(self.case, None, probe)


class Clock:
    def __init__(self):
        self.ns = 1_000_000_000
        self.waits = []

    def monotonic_ns(self):
        return self.ns

    def monotonic(self):
        return self.ns / 1_000_000_000

    def sleep(self, seconds):
        self.waits.append(seconds)
        self.ns += round(seconds * 1_000_000_000)


class WindowTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.scope = SimpleNamespace(deadline=120., assert_covered=Mock(),
            job=SimpleNamespace(query_cpu=Mock(return_value=CpuState(0, 0))),
            observe_control=Mock(return_value=CpuState(5, 2500)))
        self.case = SimpleNamespace(scope=self.scope)
        self.tree = SimpleNamespace(deadline_ns=115_000_000_000)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(measurements, "time", self.clock))
        self.stack.enter_context(patch.object(measurements, "_original_scope", return_value=self.scope))
        self.membership = self.stack.enter_context(patch.object(measurements, "_membership",
            side_effect=lambda *args: JobAccounting(2**53 + 1 + self.clock.ns // 100, 7, 2, 2, 0)))

    def test_full_30_seconds_and_raw_integer_cpu_counters(self):
        observed = measurements._window(self.case, self.tree)
        self.assertEqual(observed["end_ns"] - observed["start_ns"], 30_000_000_000)
        self.assertEqual(observed["cpu_start_100ns"], 2**53 + 8 + 10_000_000)
        self.assertEqual(observed["cpu_end_100ns"] - observed["cpu_start_100ns"], 300_000_000)
        self.assertEqual(evidence._window(observed), 1.)
        self.assertEqual(sum(self.clock.waits), 30.)
        self.assertGreaterEqual(self.scope.assert_covered.call_count, 120)

    def test_insufficient_original_cutoff_never_shortens_window(self):
        self.tree.deadline_ns = 31_000_000_000
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "fixed_window_deadline"):
            measurements._window(self.case, self.tree)
        self.assertEqual(self.clock.waits, [])

    def test_capped_window_refuses_early_restore_instead_of_averaging_it(self):
        self.scope.observe_control.side_effect = [CpuState(5, 2500), CpuState(0, 0)]
        with self.assertRaisesRegex(evidence.CapabilityEvidenceError, "cpu_readback_failed"):
            measurements._window(self.case, self.tree, capped=True)
        self.assertEqual(self.clock.waits, [.25])
        self.scope.assert_covered.assert_not_called()

    def test_membership_loss_aborts_before_full_window(self):
        self.membership.side_effect = [JobAccounting(1, 2, 2, 2, 0),
            measurements.NativeRunBlocked("native_s1_job_membership_changed")]
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "membership_changed"):
            measurements._window(self.case, self.tree)
        self.assertEqual(self.clock.waits, [.25])

    def test_scheduler_delay_past_cutoff_is_not_a_valid_30_second_window(self):
        self.clock.sleep = lambda seconds: setattr(self.clock, "ns", 116_000_000_000)
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "work_cutoff_reached"):
            measurements._window(self.case, self.tree)

    def test_three_original_windows_are_nonoverlapping_and_total_90_seconds(self):
        first = measurements._window(self.case, self.tree)
        second = measurements._window(self.case, self.tree, capped=True)
        third = measurements._window(self.case, self.tree)
        self.assertLessEqual(first["end_ns"], second["start_ns"])
        self.assertLessEqual(second["end_ns"], third["start_ns"])
        self.assertEqual(third["end_ns"] - first["start_ns"], 90_000_000_000)


class SecurityObservationTests(unittest.TestCase):
    def test_typed_same_handle_observation_populates_real_values(self):
        observed = security()
        job = SimpleNamespace(query_limits=Mock(return_value=JobLimits(0, 0)),
            query_security=Mock(return_value=observed), query_cpu=Mock(return_value=CpuState(0, 10000)))
        limits, value, cpu = measurements._baseline(SimpleNamespace(job=job), context())
        self.assertIs(value, observed)
        self.assertEqual(limits, dict(limit_flags=0, ui_restrictions=0))
        self.assertEqual(cpu, dict(flags=0, rate_bp=0))  # Inactive native union.
        job.query_security.assert_called_once_with()

    def test_untyped_security_wrong_acl_and_inheritable_handle_are_refused(self):
        for changed in (SimpleNamespace(**asdict(security())), replace(security(), handle_flags=1),
                replace(security(), access_mask=0x1fffff), replace(security(), ace_count=2),
                replace(security(), logon_sid="S-1-5-5-1-2"), replace(security(), descriptor_control=4)):
            job = SimpleNamespace(query_limits=lambda: JobLimits(0, 0),
                query_security=lambda: changed, query_cpu=lambda: CpuState(0, 0))
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    measurements.NativeRunBlocked, "job_security_unverified"):
                measurements._baseline(SimpleNamespace(job=job), context())

    def test_disabled_union_is_ignored_but_control_flags_never_are(self):
        self.assertEqual(measurements._cpu(CpuState(0, 0xffffffff)), dict(flags=0, rate_bp=0))
        with self.assertRaises(evidence.CapabilityEvidenceError):
            measurements._cpu(CpuState(4, 0))
        with self.assertRaises(evidence.CapabilityEvidenceError):
            measurements._cpu(CpuState(0, 0), rate=2500)


class ProducerBoundaryTests(unittest.TestCase):
    def setUp(self):
        fixture = provider_fixtures.S1ProviderTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture, self.owner = fixture, fixture.owner
        self.context, self.directory = fixture.context, fixture.owner.directory

    def test_original_context_and_one_measurement_owner_are_required(self):
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "original_provider_context_required"):
            measurements.produce_s1(SimpleNamespace(), self.directory, self.context)
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "original_measurement_run_required"):
            measurements.S1Measurements(self.owner, self.directory, replace(self.context))
        observed = measurements.S1Measurements(self.owner, self.directory, self.context)
        self.assertIs(self.owner._s1_measurements_owner, observed)
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "original_measurement_run_required"):
            measurements.S1Measurements(self.owner, self.directory, self.context)

    def test_queued_wait_uses_actual_same_original_context_and_no_scope(self):
        run = measurements.S1Measurements(self.owner, self.directory, self.context)
        self.fixture.fixture.publish_status(commit=94)
        case = self.fixture.start()
        command, demand = case.spec.command, case.demand
        stop = RuntimeError("synthetic end of bounded test wait")
        waits = []
        def wait(seconds):
            waits.append(seconds)
            self.assertIs(case.demand, demand)
            self.assertIs(case.spec.command, command)
            self.assertIsNone(case.scope)
            self.assertFalse(case._prepare_entered)
            if len(waits) == 2:
                raise stop
        with patch.object(measurements.time, "sleep", side_effect=wait), \
                patch.object(measurements.ExperimentNativeScope, "prepare") as prepare, \
                self.assertRaises(RuntimeError) as raised:
            run._await(case)
        self.assertIs(raised.exception, stop)
        prepare.assert_not_called()
        self.assertEqual(len(self.fixture.fixture.rows("queue")), 1)
        self.assertEqual(self.fixture.fixture.rows("reservations"), [])
        self.fixture.install_generation()
        self.assertEqual(case.recover_once()["state"], "QUEUED_CANCELLED")

    def test_fixed_three_prerequisites_then_ten_rounds_no_retry(self):
        run = measurements.S1Measurements(self.owner, self.directory, self.context)
        calls = []
        zero = dict(cpu_flags=0, active_processes=0, pending_intents=0, unsettled_handles=0, live_allocations=0)
        def observed(kind, index=None):
            calls.append((kind, index))
            if kind == "self_stop":
                return dict(self_stop_elapsed_ns=2_000_000_000, self_stop_exit_code=0)
            if kind == "empty_probe":
                return dict(cleanup=zero)
            if kind == "foreign_parent":
                return dict(foreign_parent_jobs=1, foreign_parent_launches=0)
            nonce = f"{index:032x}"
            def window(start, rate):
                return dict(start_ns=start, end_ns=start + 30_000_000_000,
                    cpu_start_100ns=0, cpu_end_100ns=rate * 300_000_000,
                    members_start=4, members_end=4)
            return dict(iteration=index, nonce=nonce, denominator=12, rate_bp=2500, worker_count=4,
                initial=dict(flags=0, rate_bp=0), applied=dict(flags=5, rate_bp=2500),
                reopened=dict(flags=5, rate_bp=2500), restored=dict(flags=0, rate_bp=0),
                uncapped_window=window(1, 4), capped_window=window(30_000_000_001, 3),
                restored_window=window(60_000_000_001, 4),
                containment=dict(before_user_code_members=4, extended_limit_flags=0, ui_restrictions=0,
                    reopened_nonce=nonce, allowed_logon_id=self.context.logon_id,
                    protected_dacl=1, allow_ace_count=1, infra_in_work_job=0), cleanup=zero)
        with patch.object(run, "_case", side_effect=observed):
            result = run.run()
        self.assertEqual(calls, [("self_stop", None), ("empty_probe", None), ("foreign_parent", None)] +
            [("round", index) for index in range(10)])
        self.assertEqual(len(result["rounds"]), 10)
        self.assertEqual(self.owner._cases, [])  # Reducer fixture, no native case.
        with patch.object(run, "_case") as repeated, \
                self.assertRaisesRegex(measurements.NativeRunBlocked, "measurement_already_started"):
            run.run()
        repeated.assert_not_called()

    def test_measurement_failure_still_abandons_real_queued_case_and_writes_no_result(self):
        run = measurements.S1Measurements(self.owner, self.directory, self.context)
        self.fixture.fixture.publish_status(commit=94)
        primary = RuntimeError("private measurement failure")
        def after_queue(case):
            self.assertFalse(case.poll_admission()["allowed"])
            self.fixture.install_generation()
            raise primary
        with patch.object(run, "_await", side_effect=after_queue), \
                self.assertRaises(RuntimeError) as raised:
            run._case("round", 0)
        self.assertIs(raised.exception, primary)
        case = self.owner.current_case
        self.assertTrue(case._closed)
        self.assertEqual(case.cleanup_result["state"], "QUEUED_CANCELLED")
        self.assertEqual(self.fixture.fixture.rows("queue"), [])
        self.assertFalse((case.directory / "native-result.json").exists())
        record = (case.directory / "measurement-failure.json").read_text(encoding="utf-8")
        self.assertNotIn("private measurement failure", record)
        self.assertIn(primary, run.errors)

    def test_unknown_original_cleanup_retains_provider_and_never_writes_result(self):
        run = measurements.S1Measurements(self.owner, self.directory, self.context)
        case = self.fixture.start()
        unknown = RuntimeError("synthetic unknown original close")
        unknown._native_close_outcome_unknown = True
        with patch.object(case, "recover_once", side_effect=unknown), \
                self.assertRaises(measurements.NativeRunUnsettled) as raised:
            run._cleanup(case)
        self.assertIs(raised.exception.coverage, self.owner)
        self.assertIs(raised.exception.additional_custody, unknown)
        self.assertIs(self.owner.current_case, case)
        self.assertFalse(case._closed)
        self.assertFalse((case.directory / "native-result.json").exists())
        with self.assertRaises(provider.S1ProviderError):
            self.owner.start_case("round")
        case.recover_once()  # Fixture is known clean after the synthetic seam.


class OriginalCleanupObservationTests(unittest.TestCase):
    def setUp(self):
        fixture = native_fixtures.ExperimentNativeReleaseTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        demand_fixture = fixture.fixture
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for override in (
                patch.object(provider, "_capture_generation", side_effect=lambda case:
                    provider._canonical(demand_fixture.generation)),
                patch("sentinel.adaptive.policy.NativePolicyProvider", return_value=demand_fixture.fixture.policy),
                patch("sentinel.coordinator._default_pid_identity", side_effect=lambda pid: (True,
                    (fixture.guardian.identity.created_filetime_100ns - 116444736000000000) / 10_000_000)
                    if pid == fixture.guardian.identity.pid else (None, 0.0)),
                patch.object(provider, "_base_python", return_value=Path(sys.executable).resolve())):
            self.stack.enter_context(override)
        self.owner = provider.S1SerialProvider(demand_fixture.scope, context())
        self.addCleanup(provider._PROVIDERS.pop, id(self.owner), None)
        self.run = measurements.S1Measurements(self.owner, self.owner.directory, self.owner.context)

    def prepared(self, kind="empty_probe", *, exit_code=0):
        case = self.owner.start_case(kind)
        self.fixture.fixture.owners.append(case.demand)
        with patch.object(ScopeLaunch, "create_inert", autospec=True, side_effect=self.fixture.create_wrapper):
            try:
                self.assertTrue(case.poll_admission()["allowed"])
            finally:
                if case.scope is not None:
                    self.fixture.scopes.append(case.scope)
        if kind != "empty_probe":
            self.assertIs(case.scope.launch_once(), self.fixture.root)
            self.fixture.root_backend.state = IdentityStatus.DEAD
            self.fixture.root_backend.exit_code.return_value = exit_code
            self.fixture.native.kernel.accounting = (17, 19, 0, 0, 0, 1, 0, 1)
        with closing(sqlite3.connect(self.fixture.db)) as conn:
            row = self.fixture.fixture.generation
            conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
            conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                ",".join("?" for _ in row) + ")", tuple(row.values()))
            generation._install_triggers(conn)
            conn.commit()
        for override in (patch.object(generation, "_assert_daily_locations"),
                patch.object(generation, "verify_import_provenance"),
                patch.object(generation, "_prove_retained_owner_ready",
                    side_effect=AssertionError("measurement cleanup requested new readiness"))):
            self.stack.enter_context(override)
        return case

    def close(self, case):
        observed = measurements._empty_before_close(case)
        try:
            self.assertTrue(case.recover_once()["released"])
        finally:
            if case.release_operation is not None:
                self.fixture.operations.append(case.release_operation)
        return observed

    def test_actual_empty_job_completion_and_verified_daily_postimage(self):
        case = self.prepared()
        observed = self.close(case)
        self.assertEqual(observed.accounting, JobAccounting(0, 0, 0, 0, 0))
        terminal = case.completion.snapshot()["terminal"]
        self.assertIs(type(terminal["launch_sealed"]), int)
        self.assertEqual(terminal["launch_sealed"], 1)
        self.assertEqual(measurements._cleanup_observation(case, observed), dict(
            cpu_flags=0, active_processes=0, pending_intents=0, unsettled_handles=0, live_allocations=0))
        self.assertEqual(self.fixture.rows("reservations"), [])
        self.assertEqual(self.fixture.rows("managed_executions")[0]["state"], "CANCELLED_BEFORE_START")
        self.assertEqual(case.release_operation._connections, {})
        self.assertEqual(self.fixture.guardian_backend.closed, [1700])

    def test_registered_journal_seal_requires_exact_integer_one(self):
        case = self.prepared()
        observed = self.close(case)
        original = case.completion.snapshot()
        for seal in (0, True, "1"):
            changed = original | {"terminal": original["terminal"] | {"launch_sealed": seal}}
            with self.subTest(seal=seal), \
                    patch.object(type(case.completion), "snapshot", return_value=changed), \
                    self.assertRaisesRegex(measurements.NativeRunBlocked, "cleanup_native_binding_changed"):
                measurements._cleanup_observation(case, observed)

    def test_missing_actual_preclose_observation_cannot_be_replaced_by_completion(self):
        case = self.prepared()
        self.close(case)
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "original_cleanup_required"):
            measurements._cleanup_observation(case, None)

    def test_finished_root_exit_code_is_actual_and_nonzero_is_failed_measurement(self):
        case = self.prepared("self_stop", exit_code=23)
        observed = self.close(case)
        self.assertEqual(observed.root_exit_code, 23)
        self.assertEqual(case.completion.snapshot()["terminal"]["root_exit_code"], 23)
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "cleanup_workload_exit_unverified"):
            measurements._cleanup_observation(case, observed)
        self.assertTrue(case._closed)  # Failed measurement does not suppress cleanup.

    def test_preclose_lifetime_count_must_match_the_original_terminal_journal(self):
        case = self.prepared()
        observed = self.close(case)
        changed = replace(observed, accounting=replace(observed.accounting, total_processes=1))
        with self.assertRaisesRegex(measurements.NativeRunBlocked, "cleanup_native_binding_changed"):
            measurements._cleanup_observation(case, changed)

    def test_history_postimage_is_revalidated_not_inferred_from_released_boolean(self):
        case = self.prepared()
        observed = self.close(case)
        operation = case.release_operation
        with patch.object(operation, "_verify_committed", side_effect=RuntimeError("changed original history")) as verify, \
                self.assertRaisesRegex(RuntimeError, "changed original history"):
            measurements._cleanup_observation(case, observed)
        verify.assert_called_once()
        self.assertEqual(operation._connections, {})

    def test_unknown_postrelease_read_close_stays_with_original_provider(self):
        case = self.prepared()
        original_observation = measurements._cleanup_observation
        original_connect, opened = sqlite3.connect, []
        class UnknownClose(sqlite3.Connection):
            attempts = 0
            def close(self):
                self.attempts += 1
                raise OSError("synthetic final evidence read close outcome unknown")
        def connect(*args, **kwargs):
            conn = original_connect(*args, **kwargs, factory=UnknownClose)
            opened.append(conn)
            return conn
        def after_release(*args):
            self.assertTrue(case._closed)
            with patch.object(sqlite3, "connect", side_effect=connect):
                return original_observation(*args)
        try:
            with patch.object(measurements, "_cleanup_observation", side_effect=after_release), \
                    self.assertRaises(measurements.NativeRunUnsettled) as raised:
                self.run._cleanup(case)
            self.assertIs(raised.exception.coverage, self.owner)
            self.assertEqual(len(opened), 1)
            self.assertEqual(opened[0].attempts, 1)
            operation = case.release_operation
            self.assertIs(operation._quarantine._sentinel_connection_cleanup, opened[0])
            self.assertTrue(operation._connections)
            self.assertFalse((case.directory / "native-result.json").exists())
            # Parent integration validates completed-case original custody.
            # Neither pending inspection nor recovery may open SQL/reclose.
            with patch.object(sqlite3, "connect", side_effect=AssertionError("unknown close reacquired SQL")):
                with self.assertRaises(Exception):
                    self.owner.recover_once()
                try:
                    pending = custody_pending(self.owner)
                except Exception:
                    pending = True
                self.assertTrue(pending)
            self.assertEqual(opened[0].attempts, 1)
        finally:
            if case.release_operation is not None:
                self.fixture.operations.append(case.release_operation)
            for conn in opened:
                sqlite3.Connection.close(conn)  # Only positively known fixture handles.

    def test_actual_control_probe_principal_retained_and_empty_case_full_cleanup(self):
        original_await = self.run._await
        def ready(case):
            with patch.object(ScopeLaunch, "create_inert", autospec=True, side_effect=self.fixture.create_wrapper):
                try:
                    scope = original_await(case)
                finally:
                    if case.scope is not None:
                        self.fixture.scopes.append(case.scope)
            self.fixture.fixture.owners.append(case.demand)
            self.fixture.native.kernel.open_handle = 702
            self.stack.enter_context(patch.object(scope, "_grants_locked", return_value=SimpleNamespace(leases=())))
            return scope
        real_recover = provider.S1Case.recover_once
        def release(case):
            # Install the fixture's actual persisted row only once capacity
            # work has ended; original cleanup checks its complete real schema.
            if not case._closed and not self.fixture.rows("adaptive_daily_generation"):
                with closing(sqlite3.connect(self.fixture.db)) as conn:
                    row = self.fixture.fixture.generation
                    conn.execute("CREATE TABLE adaptive_daily_generation (" + ",".join(
                        key + (" INTEGER" if type(value) is int else " TEXT") for key, value in row.items()) + ")")
                    conn.execute("INSERT INTO adaptive_daily_generation VALUES(" +
                        ",".join("?" for _ in row) + ")", tuple(row.values()))
                    generation._install_triggers(conn)
                    conn.commit()
                self.stack.enter_context(patch.object(generation, "_assert_daily_locations"))
                self.stack.enter_context(patch.object(generation, "verify_import_provenance"))
            try:
                return real_recover(case)
            finally:
                if case.release_operation is not None and case.release_operation not in self.fixture.operations:
                    self.fixture.operations.append(case.release_operation)
        descriptor = SecurityObservation(**{key: value for key, value in asdict(security()).items()
            if key != "handle_flags"})
        self.fixture.native.security.verify_security = Mock(return_value=descriptor)
        open_job = NativeJob.open
        with patch.object(self.run, "_await", side_effect=ready), \
                patch.object(NativeJob, "open", side_effect=lambda *args, **kwargs:
                    open_job(*args, **kwargs, backend=self.fixture.native.backend)), \
                patch.object(provider.S1Case, "recover_once", release):
            result = self.run._case("empty_probe")
        case = self.owner.current_case
        self.assertTrue(case._closed)
        self.assertEqual(result["cleanup"]["live_allocations"], 0)
        probes = case.scope._probe_attempts
        self.assertEqual(len(probes), 1)
        self.assertTrue(probes[0].owner.closed)
        self.assertNotEqual(probes[0].owner._job.value, case.scope.job._job.value)
        record = json.loads((case.directory / "native-result.json").read_text(encoding="utf-8"))
        self.assertEqual(record["details"]["reopened"], dict(flags=5, rate_bp=2500))
        self.assertEqual(record["details"]["restored"]["flags"], 0)
        self.assertEqual(record["details"]["exits"], {})
        self.assertEqual(self.fixture.rows("reservations"), [])


if __name__ == "__main__":
    unittest.main()
