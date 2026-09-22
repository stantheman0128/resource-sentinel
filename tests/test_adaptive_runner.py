"""Portable checks of P6 orchestration boundaries; no native gate claims."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import replace
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from tests.benchmarks import adaptive_runner as runner
from tests.fixtures import adaptive_workload as workload


@contextmanager
def fabricated_raw_run(*, scope=None, setup_error=None):
    """Pure fault seam: no native provider, process or sampler is executed."""
    scope = Mock() if scope is None else scope
    custody = runner.RawAdmissionCustody(scope, finisher=scope.finish)
    with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
            patch.object(runner, "_real_admission", return_value=custody), \
            patch.object(runner, "_source_state", return_value={}, side_effect=setup_error), \
            patch.object(runner, "_power_plan", return_value="fixed"), \
            patch.object(runner.WindowsFixtureObserver, "measure", return_value={
                "status": "observed", "ab_record_produced": False, "promotion_permitted": False}):
        yield Path(parent) / "run", custody, scope


class FixtureSpecificationTests(unittest.TestCase):
    def test_fixed_workload_shapes_and_resource_estimates(self):
        spec = runner.FixtureSpec("memory_heavy_test", 4, 100)
        self.assertEqual(spec.demand["cpu_units"], 5)
        self.assertEqual(spec.demand["physical_bytes"], 1408 << 20)
        self.assertEqual(spec.demand["commit_bytes"], 1408 << 20)
        self.assertEqual(spec.demand["io_slots"], 0)
        self.assertEqual(runner.FixtureSpec("io_bound_install", 1, 1).demand["io_slots"], 1)

    def test_unimplemented_native_scenarios_are_explicitly_blocked(self):
        for scenario in ("unmanaged_cpu_pressure", "mixed_exempt_background_protected",
                         "mixed_root_and_child_durations"):
            with self.subTest(scenario=scenario), self.assertRaisesRegex(
                    runner.MeasurementBlocked, "native_fixture_unavailable"):
                runner.FixtureSpec(scenario, 1, 1)

    def test_work_and_disk_bounds_cannot_be_loosened_by_cli(self):
        spec = runner.FixtureSpec("cpu_bound_build", 1, 1)
        for changes in ({"tasks": 0}, {"tasks": 5}, {"tasks": True}, {"units": 10001},
                        {"memory_mib": 129}, {"seconds": 91}, {"seconds": True}):
            with self.subTest(changes=changes), self.assertRaises(runner.MeasurementBlocked):
                replace(spec, **changes)
        with self.assertRaisesRegex(runner.MeasurementBlocked, "disk_bound_invalid"):
            runner.FixtureSpec("io_bound_install", 1, 9)

    def test_command_uses_base_python_and_no_user_shell(self):
        spec = runner.FixtureSpec("cpu_bound_build", 2, 30)
        command = runner.fixture_command(spec, Path("fixture space"))
        self.assertEqual(command[0], r"C:\Python313\python.exe")
        self.assertEqual(command[command.index("--directory") + 1], "fixture space")
        self.assertNotIn("py", command)
        self.assertNotIn("--exempt", command)

    def test_reserve_stop_uses_both_physical_and_commit(self):
        demand = runner.FixtureSpec("cpu_bound_build", 1, 1).demand
        good = {"physical_headroom_bytes": (4 << 30) + demand["physical_bytes"],
                "commit_headroom_bytes": (4 << 30) + demand["commit_bytes"]}
        runner._safe_capacity(good, demand)
        for name in good:
            with self.subTest(name=name), self.assertRaisesRegex(
                    runner.MeasurementBlocked, "reserve_stop"):
                runner._safe_capacity({**good, name: good[name] - 1}, demand)


class RealAdmissionBoundaryTests(unittest.TestCase):
    def test_json_or_none_receipt_cannot_enable_a_native_fixture(self):
        for value in (None, {"verified": True}, True, "ready"):
            with self.subTest(value=value), patch(
                    "tests.windows.adaptive_admission.require_continuous_admission", return_value=value):
                with self.assertRaisesRegex(runner.MeasurementBlocked, "retained_continuous_scope_unavailable"):
                    runner._real_admission(runner.FixtureSpec("cpu_bound_build", 1, 1))

    def test_actual_provider_exception_propagates_without_fallback(self):
        from tests.windows.adaptive_admission import ContinuousAdmissionUnavailable
        with patch("tests.windows.adaptive_admission.require_continuous_admission",
                   side_effect=ContinuousAdmissionUnavailable("real_daily_scope_missing")):
            with self.assertRaisesRegex(ContinuousAdmissionUnavailable, "real_daily_scope_missing"):
                runner._real_admission(runner.FixtureSpec("cpu_bound_build", 1, 1))

    def test_missing_native_prerequisite_is_recorded_before_any_launch(self):
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch.object(runner, "_real_admission", side_effect=runner.MeasurementBlocked("daily_consumers_not_handed_off")), \
                patch.object(runner.subprocess, "Popen") as spawn:
            directory = Path(parent) / "new-run"
            result = runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            spawn.assert_not_called()
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["reason"], "daily_consumers_not_handed_off")
            self.assertFalse(result["ab_record_produced"])
            self.assertFalse(result["promotion_permitted"])
            self.assertEqual(json.loads((directory / "raw-run.json").read_text()), result)

    def test_same_evidence_directory_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(runner.MeasurementBlocked, "new_absolute"):
                runner.run_raw_fixture(Path(directory), runner.FixtureSpec("cpu_bound_build", 1, 1))

    def test_raw_measurement_never_becomes_an_ab_pass(self):
        admission = Mock()
        raw = {"status": "observed", "ab_record_produced": False, "promotion_permitted": False,
               "missing_qualifications": ["native_cap_write_audit"]}
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch.object(runner, "_real_admission", return_value=runner.RawAdmissionCustody(
                    admission, finisher=admission.finish)), \
                patch.object(runner, "_source_state", return_value={}), \
                patch.object(runner, "_power_plan", return_value="fixed"), \
                patch.object(runner.WindowsFixtureObserver, "measure", return_value=raw):
            result = runner.run_raw_fixture(Path(parent) / "run", runner.FixtureSpec("cpu_bound_build", 1, 1))
            admission.finish.assert_called_once_with()
            self.assertFalse(result["ab_record_produced"])
            self.assertFalse(result["promotion_permitted"])

    def test_cleanup_failure_retains_exact_original_authority(self):
        admission = Mock()
        admission.finish.side_effect = [runner.MeasurementBlocked("cleanup_unknown"), None]
        raw = {"status": "observed", "ab_record_produced": False, "promotion_permitted": False}
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch.object(runner, "_real_admission", return_value=runner.RawAdmissionCustody(
                    admission, finisher=admission.finish)), \
                patch.object(runner, "_source_state", return_value={}), \
                patch.object(runner, "_power_plan", return_value="fixed"), \
                patch.object(runner.WindowsFixtureObserver, "measure", return_value=raw):
            directory = Path(parent) / "run"
            with self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            pending = caught.exception
            self.assertIs(pending.scope, admission)
            self.assertFalse(json.loads((directory / "raw-run.json").read_text())["admission_cleanup_settled"])
            pending.retry()
            self.assertTrue(json.loads((directory / "cleanup-settled.json").read_text())["admission_cleanup_settled"])
            self.assertEqual(admission.finish.call_count, 2)

    def test_failed_initial_coverage_check_retains_original_validated_finisher(self):
        scope = Mock(spec_set=["assert_covered", "acknowledge_fixture_exit", "finish"])
        primary = KeyboardInterrupt()
        scope.assert_covered.side_effect = primary
        with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=scope), \
                self.assertRaises(runner.RawAcquisitionPending) as caught:
            runner._real_admission(runner.FixtureSpec("cpu_bound_build", 1, 1))
        pending = caught.exception
        self.assertIs(pending.custody.scope, scope)
        self.assertIs(pending.primary, primary)
        scope.finish.assert_not_called()
        pending.custody.finish()
        scope.finish.assert_called_once_with()

    def test_unknown_scope_does_not_get_a_guessed_finish_call(self):
        scope = type("IncompleteScope", (), {"finish": Mock()})()
        with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=scope), \
                self.assertRaises(runner.RawAcquisitionPending) as caught:
            runner._real_admission(runner.FixtureSpec("cpu_bound_build", 1, 1))
        self.assertIs(caught.exception.custody.scope, scope)
        with self.assertRaisesRegex(runner.MeasurementBlocked, "cleanup_api_unavailable"):
            caught.exception.custody.finish()
        scope.finish.assert_not_called()

    def test_provider_partial_acquisition_preserves_all_native_owners(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        scope, extra = Mock(), object()
        primary = NativeRunUnsettled(scope, additional_custody=extra)
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch("tests.windows.adaptive_admission.require_continuous_admission", side_effect=primary), \
                patch.object(runner.subprocess, "Popen") as launch, \
                self.assertRaises(runner.PendingAdmissionCleanup) as caught:
            runner.run_raw_fixture(Path(parent) / "run", runner.FixtureSpec("cpu_bound_build", 1, 1))
        held = caught.exception
        self.assertIs(held.scope, scope)
        self.assertIs(held.primary, primary)
        self.assertIs(held.custody.additional_custody.additional_custody, extra)
        self.assertIsNone(held.custody.finisher)
        launch.assert_not_called()
        scope.finish.assert_not_called()

    def test_native_custody_from_initial_coverage_check_blocks_raw_finish(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        scope = Mock(spec_set=["assert_covered", "acknowledge_fixture_exit", "finish"])
        extra = object()
        primary = NativeRunUnsettled(object(), additional_custody=extra)
        scope.assert_covered.side_effect = primary
        with patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=scope), \
                self.assertRaises(runner.RawAcquisitionPending) as caught:
            runner._real_admission(runner.FixtureSpec("cpu_bound_build", 1, 1))
        custody = caught.exception.custody
        self.assertIs(custody.additional_custody, primary)
        with self.assertRaisesRegex(runner.MeasurementBlocked, "cleanup_api_unavailable"):
            custody.finish()
        scope.finish.assert_not_called()

    def test_initial_coverage_failure_is_cleaned_before_returning_blocked(self):
        scope = Mock(spec_set=["assert_covered", "acknowledge_fixture_exit", "finish"])
        scope.assert_covered.side_effect = runner.MeasurementBlocked("fixture_coverage_failed")
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=scope), \
                patch.object(runner.subprocess, "Popen") as launch:
            result = runner.run_raw_fixture(Path(parent) / "run", runner.FixtureSpec("cpu_bound_build", 1, 1))
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["reason"], "fixture_coverage_failed")
        self.assertTrue(result["admission_cleanup_settled"])
        scope.finish.assert_called_once_with()
        launch.assert_not_called()

    def test_throwing_diagnostic_property_cannot_skip_original_scope_cleanup(self):
        class BadDiagnostic(Exception):
            @property
            def reason(self):
                raise OSError("fixture diagnostic getter failed")
        scope = Mock(spec_set=["assert_covered", "acknowledge_fixture_exit", "finish"])
        scope.assert_covered.side_effect = BadDiagnostic()
        with tempfile.TemporaryDirectory() as parent, patch.object(runner, "_require_platform"), \
                patch("tests.windows.adaptive_admission.require_continuous_admission", return_value=scope):
            result = runner.run_raw_fixture(Path(parent) / "run", runner.FixtureSpec("cpu_bound_build", 1, 1))
        self.assertEqual(result["reason"], "ab_error_reason_unavailable")
        self.assertTrue(result["admission_cleanup_settled"])
        scope.finish.assert_called_once_with()


class RawCleanupFailureTests(unittest.TestCase):
    def test_original_interrupt_cannot_bypass_failed_cleanup(self):
        primary = KeyboardInterrupt()
        with fabricated_raw_run(setup_error=primary) as (directory, custody, scope):
            scope.finish.side_effect = OSError("fixture cleanup failed")
            with self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertIs(caught.exception.custody, custody)
            self.assertIs(caught.exception.primary, primary)
            self.assertFalse(custody.cleanup_complete)

    def test_throwing_cleanup_diagnostic_still_retains_pending_owner(self):
        class BadDiagnostic(Exception):
            @property
            def reason(self):
                raise KeyboardInterrupt()
        with fabricated_raw_run() as (directory, custody, scope):
            primary = BadDiagnostic()
            scope.finish.side_effect = primary
            with self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertIs(caught.exception.custody, custody)
            self.assertIs(caught.exception.primary, primary)
            self.assertEqual(caught.exception.reason, "ab_error_reason_unavailable")

    def test_explicit_native_custody_from_finish_cannot_disappear_on_retry(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        with fabricated_raw_run() as (directory, custody, scope):
            primary = NativeRunUnsettled(object(), additional_custody=object())
            scope.finish.side_effect = [primary, None]
            with self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertIs(custody.additional_custody, primary)
            with self.assertRaisesRegex(runner.MeasurementBlocked, "cleanup_api_unavailable"):
                caught.exception.retry()
            scope.finish.assert_called_once_with()

    def test_explicit_native_custody_from_observer_is_retained_before_finish(self):
        from tests.windows.adaptive_capability_runner import NativeRunUnsettled
        with fabricated_raw_run() as (directory, custody, scope):
            primary = NativeRunUnsettled(object(), additional_custody=object())
            with patch.object(runner.WindowsFixtureObserver, "measure", side_effect=primary), \
                    self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertIs(custody.additional_custody, primary)
            self.assertIs(caught.exception.primary, primary)
            scope.finish.assert_not_called()

    def test_interrupt_inside_finish_retains_same_scope(self):
        for error in (KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(error=type(error).__name__), fabricated_raw_run() as (directory, custody, scope):
                scope.finish.side_effect = error
                with self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                    runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
                self.assertIs(caught.exception.scope, scope)
                self.assertIs(caught.exception.primary, error)

    def test_evidence_failure_does_not_replace_pending_cleanup(self):
        for write_error in (OSError("fixture disk full"), KeyboardInterrupt()):
            with self.subTest(error=type(write_error).__name__), fabricated_raw_run() as (directory, custody, scope):
                scope.finish.side_effect = OSError("fixture cleanup failed")
                with patch.object(runner, "_write_new", side_effect=write_error), \
                        self.assertRaises(runner.PendingAdmissionCleanup) as caught:
                    runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
                self.assertIs(caught.exception.custody, custody)
                self.assertIs(caught.exception.__cause__, write_error)

    def test_evidence_failure_after_positive_cleanup_does_not_refinish(self):
        with fabricated_raw_run() as (directory, custody, scope):
            with patch.object(runner, "_write_new", side_effect=OSError("fixture disk full")), \
                    self.assertRaises(OSError):
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertTrue(custody.cleanup_complete)
            custody.finish()
            scope.finish.assert_called_once_with()

    def test_retry_publication_failure_does_not_repeat_native_finish_or_overwrite(self):
        scope = Mock()
        custody = runner.RawAdmissionCustody(scope, finisher=scope.finish)
        pending = runner.PendingAdmissionCleanup(custody, Path("unused"), {}, "fixture_pending")
        with patch.object(runner, "_write_new", side_effect=OSError("fixture disk full")) as publish:
            first = pending.retry()
            second = pending.retry()
        self.assertIs(first, second)
        self.assertTrue(first["admission_cleanup_settled"])
        self.assertFalse(first["cleanup_evidence_written"])
        self.assertEqual(first["cleanup_evidence_error"], "OSError")
        scope.finish.assert_called_once_with()
        publish.assert_called_once()

    def test_original_interrupt_is_rethrown_only_after_positive_cleanup(self):
        primary = KeyboardInterrupt()
        with fabricated_raw_run(setup_error=primary) as (directory, custody, scope):
            with self.assertRaises(KeyboardInterrupt) as caught:
                runner.run_raw_fixture(directory, runner.FixtureSpec("cpu_bound_build", 1, 1))
            self.assertIs(caught.exception, primary)
            self.assertTrue(custody.cleanup_complete)
            scope.finish.assert_called_once_with()

    def test_broken_pending_console_does_not_discard_recovery(self):
        custody = runner.RawAdmissionCustody(object())
        pending = runner.PendingAdmissionCleanup(custody, Path("unused"), {}, "fixture_pending")
        pending.retry = Mock(return_value={"admission_cleanup_settled": True})
        with patch.object(runner, "run_raw_fixture", side_effect=pending), \
                patch("builtins.print", side_effect=BrokenPipeError("fixture console closed")):
            result = runner.main(["measure-fixture", "--scenario", "cpu_bound_build", "--units", "1",
                                  "--evidence-dir", "unused"])
        self.assertEqual(result, 3)
        pending.retry.assert_called_once_with()


class RawFixtureCustodyTests(unittest.TestCase):
    def test_launch_attempt_is_registered_before_constructor_and_never_replayed(self):
        owner = runner.RawFixtureCustody()
        primary = KeyboardInterrupt()
        def partial_create(*args, **kwargs):
            self.assertEqual(len(owner.launches), 1)
            self.assertIsNone(owner.launches[0]["process"])
            raise primary
        with patch.object(runner.subprocess, "Popen", side_effect=partial_create) as create, \
                self.assertRaises(KeyboardInterrupt):
            owner.launch(["fixture"], stop_file=Path("unused"))
        self.assertIs(owner.launches[0]["error"], primary)
        for _ in range(2):
            with self.assertRaisesRegex(runner.MeasurementBlocked, "fixture_custody_pending"):
                owner.cleanup()
        create.assert_called_once()

    def test_failed_first_cleanup_still_attempts_second_original_child(self):
        owner = runner.RawFixtureCustody()
        first, second = Mock(), Mock()
        with patch.object(runner.subprocess, "Popen", side_effect=[first, second]):
            owner.launch(["first"], stop_file=Path("one"))
            owner.launch(["second"], stop_file=Path("two"))
        with patch.object(runner, "_wait_cooperatively", side_effect=[OSError("fixture stop failed"), None]) as wait, \
                self.assertRaisesRegex(runner.MeasurementBlocked, "fixture_custody_pending"):
            owner.cleanup()
        self.assertEqual([call.args[0] for call in wait.call_args_list], [first, second])
        self.assertFalse(owner.launches[0]["settled"])
        self.assertTrue(owner.launches[1]["settled"])
        with patch.object(runner, "_wait_cooperatively") as wait:
            owner.cleanup()
        wait.assert_called_once_with(first, Path("one"))

    def test_unknown_child_creation_prevents_admission_finish(self):
        scope = Mock()
        custody = runner.RawAdmissionCustody(scope, finisher=scope.finish)
        custody.fixture = runner.RawFixtureCustody()
        with patch.object(runner.subprocess, "Popen", side_effect=OSError("fixture partial creation")), \
                self.assertRaises(OSError):
            custody.fixture.launch(["fixture"], stop_file=Path("unused"))
        with self.assertRaisesRegex(runner.MeasurementBlocked, "fixture_custody_pending"):
            custody.finish()
        self.assertFalse(custody.cleanup_complete)
        scope.finish.assert_not_called()

    def test_already_exited_original_child_needs_no_stop_file_write(self):
        child, stop = Mock(), Mock()
        child.poll.return_value = 0
        stop.touch.side_effect = OSError("fixture disk unavailable")
        runner._wait_cooperatively(child, stop)
        stop.touch.assert_not_called()
        child.wait.assert_not_called()


class ScheduleArtifactTests(unittest.TestCase):
    def test_schedule_has_every_slot_and_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule.json"
            with patch("sys.stdout", new_callable=io.StringIO):
                result = runner.main(["schedule", "--seed", "pre-registered-seed", "--output", str(path)])
                retry = runner.main(["schedule", "--seed", "different", "--output", str(path)])
            self.assertEqual(result, 0)
            self.assertEqual(retry, 3)
            artifact = json.loads(path.read_text())
            self.assertEqual(len(artifact["slots"]), 210)
            self.assertEqual(artifact["seed"], "pre-registered-seed")
            self.assertFalse(artifact["measured"])

    def test_modified_order_is_not_a_new_valid_registered_schedule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "schedule.json"
            with patch("sys.stdout", new_callable=io.StringIO):
                runner.main(["schedule", "--seed", "fixed", "--output", str(path)])
            value = json.loads(path.read_text())
            first = value["slots"][0]
            first["first_variant"], first["second_variant"] = first["second_variant"], first["first_variant"]
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(runner.MeasurementBlocked, "seed_or_inventory_mismatch"):
                runner.load_schedule(path)

    def test_empty_evidence_reports_incomplete_all_scenarios(self):
        with tempfile.TemporaryDirectory() as directory:
            path, records, report = (Path(directory) / name for name in ("schedule.json", "records.json", "report.md"))
            with patch("sys.stdout", new_callable=io.StringIO):
                runner.main(["schedule", "--seed", "fixed", "--output", str(path)])
            records.write_text("[]")
            result = runner.analyze_files(path, records, None, report)
            self.assertEqual(result["verdict"], "INSUFFICIENT_DATA")
            self.assertFalse(result["promotion_permitted"])
            for scenario, _ in runner.DEFAULT_SCENARIOS:
                self.assertIn(scenario, report.read_text(encoding="utf-8"))

    def test_duplicate_json_keys_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for text, reason in (("{\"x\":1,\"x\":2}", "duplicate_json_key"),
                                 ("{\"value\":NaN}", "nonfinite_json_number")):
                path.write_text(text)
                with self.subTest(text=text), self.assertRaisesRegex(runner.MeasurementBlocked, reason):
                    runner._read_json(path)


class PublicWorkloadTests(unittest.TestCase):
    def test_dataset_is_fixed_nonprivate_and_bounded(self):
        first = workload.dataset_bytes()
        self.assertEqual(len(first), 1 << 20)
        self.assertEqual(first, workload.dataset_bytes())
        self.assertEqual(len(workload.dataset_sha256()), 64)

    def test_offline_wheel_has_no_executable_setup_or_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            wheel = workload.wheel_bytes(Path(directory))
            with zipfile.ZipFile(wheel) as archive:
                self.assertNotIn("setup.py", archive.namelist())
                self.assertNotIn("entry_points.txt", " ".join(archive.namelist()))
                metadata = archive.read("sentinel_p6_fixture-1.0.dist-info/METADATA")
                self.assertNotIn(b"Requires-Dist", metadata)
                self.assertEqual(len(archive.read("sentinel_p6_fixture/data.bin")), 8 << 20)
            with self.assertRaises(FileExistsError):
                workload.wheel_bytes(Path(directory))

    def test_fixture_result_cannot_replace_an_old_result(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            workload.write_json(path, {"status": "failed"})
            with self.assertRaises(FileExistsError):
                workload.write_json(path, {"status": "complete"})


if __name__ == "__main__":
    unittest.main()
