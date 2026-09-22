"""Portable checks of P6 orchestration boundaries; no native gate claims."""
from __future__ import annotations

import argparse
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
                patch.object(runner, "_real_admission", return_value=admission), \
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
                patch.object(runner, "_real_admission", return_value=admission), \
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
