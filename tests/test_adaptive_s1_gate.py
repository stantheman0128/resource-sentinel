"""Pure S1 runner guards; these tests make no Windows capability claim."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tests.windows import test_adaptive_job_capability as spike


class S1PrerequisiteGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def make_case(self, failure_stage=None, *, cleanup_failure=False):
        observed = []

        class IsolatedCase(unittest.TestCase):
            evidence = self.directory
            _s1_gate = spike._S1RunGate()

            def stage_body(self, stage):
                observed.append(stage)
                try:
                    if stage == failure_stage and not cleanup_failure:
                        raise RuntimeError("injected native failure")
                finally:
                    if stage == failure_stage and cleanup_failure:
                        raise RuntimeError("injected restore/empty verification failure")

            @spike._s1_stage("fixture_self_stop")
            def test_00(self):
                self.stage_body("fixture_self_stop")

            @spike._s1_stage("empty_job_restore")
            def test_05(self):
                self.stage_body("empty_job_restore")

            @spike._s1_stage("foreign_parent_rejection")
            def test_10(self):
                self.stage_body("foreign_parent_rejection")

            @spike._s1_stage("cpu_effect")
            def test_20(self):
                self.stage_body("cpu_effect")

        return IsolatedCase, observed

    def test_actual_effect_selected_alone_fails_before_job_creation(self):
        case = spike.WindowsJobCapabilitySpike("test_20_ten_create_set_disable_reopen_effect_rounds")
        with patch.object(type(case), "_s1_gate", spike._S1RunGate(), create=True), \
                patch.object(type(case), "evidence", self.directory, create=True), \
                patch.object(spike.OwnedJob, "create") as create:
            with self.assertRaisesRegex(AssertionError, "requires successful fixture_self_stop"):
                case.test_20_ten_create_set_disable_reopen_effect_rounds()
        create.assert_not_called()
        record = json.loads((self.directory / "stage-gate.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertFalse(record["capability_allowlist_eligible"])

    def test_stale_success_files_do_not_supply_same_run_evidence(self):
        (self.directory / "stage-gate.json").write_text(json.dumps({
            "status": "stages_passed", "completed_stages": list(spike.S1_STAGES),
        }))
        case_type, observed = self.make_case()
        with self.assertRaisesRegex(AssertionError, "requires successful fixture_self_stop"):
            case_type("test_20").test_20()
        self.assertEqual(observed, [])

    def test_default_runner_cannot_continue_native_stages_after_prerequisite_failure(self):
        for failed in spike.S1_STAGES[:-1]:
            with self.subTest(stage=failed):
                case_type, observed = self.make_case(failed)
                result = unittest.TestResult()  # Deliberately no failfast.
                unittest.defaultTestLoader.loadTestsFromTestCase(case_type).run(result)
                self.assertFalse(result.wasSuccessful())
                self.assertEqual(observed, list(spike.S1_STAGES[:spike.S1_STAGES.index(failed) + 1]))
                self.assertNotIn("cpu_effect", observed)
                self.assertEqual(case_type._s1_gate.failure["stage"], failed)

    def test_cleanup_failure_never_mints_a_successful_prerequisite(self):
        case_type, observed = self.make_case("empty_job_restore", cleanup_failure=True)
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(case_type).run(result)
        self.assertFalse(result.wasSuccessful())
        self.assertEqual(observed, ["fixture_self_stop", "empty_job_restore"])
        self.assertEqual(case_type._s1_gate.completed, ["fixture_self_stop"])
        self.assertIn("restore/empty", case_type._s1_gate.failure["message"])

    def test_failfast_stops_suite_at_first_native_failure(self):
        case_type, observed = self.make_case("fixture_self_stop")
        result = unittest.TestResult()
        result.failfast = True
        unittest.defaultTestLoader.loadTestsFromTestCase(case_type).run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertTrue(result.shouldStop)
        self.assertEqual(observed, ["fixture_self_stop"])

    def test_reordered_prerequisite_blocks_remaining_run(self):
        case_type, observed = self.make_case()
        with self.assertRaisesRegex(AssertionError, "requires successful fixture_self_stop"):
            case_type("test_05").test_05()
        with self.assertRaisesRegex(AssertionError, "earlier stage failed"):
            case_type("test_00").test_00()
        self.assertEqual(observed, [])

    def test_duplicate_prerequisite_invalidates_run_instead_of_reusing_success(self):
        case_type, observed = self.make_case()
        case_type("test_00").test_00()
        with self.assertRaisesRegex(AssertionError, "requires successful empty_job_restore"):
            case_type("test_00").test_00()
        with self.assertRaisesRegex(AssertionError, "earlier stage failed"):
            case_type("test_05").test_05()
        self.assertEqual(observed, ["fixture_self_stop"])

    def test_publication_failure_blocks_native_body_and_later_promotion(self):
        case_type, observed = self.make_case()
        with patch.object(spike, "_write_json", side_effect=OSError("disk unavailable")):
            with self.assertRaises(OSError):
                case_type("test_00").test_00()
        with self.assertRaisesRegex(AssertionError, "earlier stage failed"):
            case_type("test_20").test_20()
        self.assertEqual(observed, [])
        self.assertEqual(case_type._s1_gate.failure["type"], "OSError")

    def test_publication_failure_after_cleanup_invalidates_completed_token(self):
        case_type, observed = self.make_case()
        publish = spike._write_json
        calls = []

        def fail_second_write(path, record):
            calls.append(record)
            if len(calls) == 2:
                raise OSError("completion record unavailable")
            publish(path, record)

        with patch.object(spike, "_write_json", side_effect=fail_second_write):
            with self.assertRaises(OSError):
                case_type("test_00").test_00()
        with self.assertRaisesRegex(AssertionError, "earlier stage failed"):
            case_type("test_05").test_05()
        self.assertEqual(observed, ["fixture_self_stop"])
        record = json.loads((self.directory / "stage-gate.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertFalse(record["capability_allowlist_eligible"])

    def test_skipped_prerequisite_does_not_unlock_effect(self):
        case_type, observed = self.make_case()
        case = case_type("test_00")
        with patch.object(case, "stage_body", side_effect=unittest.SkipTest("unsupported")):
            with self.assertRaises(unittest.SkipTest):
                case.test_00()
        with self.assertRaisesRegex(AssertionError, "earlier stage failed"):
            case_type("test_20").test_20()
        self.assertEqual(observed, [])

    def test_successful_ordered_run_still_does_not_grant_full_capability(self):
        case_type, observed = self.make_case()
        result = unittest.TestResult()
        unittest.defaultTestLoader.loadTestsFromTestCase(case_type).run(result)
        self.assertTrue(result.wasSuccessful())
        self.assertEqual(observed, list(spike.S1_STAGES))
        record = json.loads((self.directory / "stage-gate.json").read_text())
        self.assertEqual(record["status"], "stages_passed")
        self.assertFalse(record["capability_allowlist_eligible"])

    def test_new_run_has_no_previous_success_tokens(self):
        first, _ = self.make_case()
        unittest.defaultTestLoader.loadTestsFromTestCase(first).run(unittest.TestResult())
        fresh, observed = self.make_case()
        with self.assertRaisesRegex(AssertionError, "requires successful fixture_self_stop"):
            fresh("test_20").test_20()
        self.assertEqual(observed, [])


if __name__ == "__main__":
    unittest.main()
