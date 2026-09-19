"""Public host diagnostics cannot confer control authority or leak private data."""
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from tests.windows import probe_adaptive_ci_host as probe


class PublicHostProbeTests(unittest.TestCase):
    def observation(self, **changes):
        result = dict(in_any_job=False, processor_groups=1, logical_processors=4,
                      process_affinity=15, system_affinity=15, python_bits=64,
                      session_zero=True, os_build=26100, python_version="3.13.7",
                      errors=[])
        result.update(changes)
        return result

    def test_positive_topology_does_not_pass_other_gates(self):
        report = probe.public_report(self.observation(), "win25", "20260913.1.0")
        self.assertTrue(report["topology_candidate"])
        self.assertEqual(report["validity"], "valid")
        for key in ("p1_capability_verified", "continuous_admission_verified",
                    "interactive_context_verified", "control_performed"):
            self.assertIs(report[key], False)

    def test_zero_flags_do_not_make_foreign_job_supported(self):
        report = probe.public_report(self.observation(in_any_job=True, immediate_job_cpu_flags=0))
        self.assertFalse(report["topology_candidate"])
        self.assertIn("foreign_or_unknown_parent_job", report["topology_blockers"])
        self.assertEqual(report["validity"], "valid")

    def test_missing_and_wrong_types_are_unknown(self):
        for key in ("in_any_job", "session_zero", "processor_groups", "logical_processors",
                    "process_affinity", "system_affinity", "python_bits"):
            for value in (None, "0", 0.0):
                with self.subTest(key=key, value=value):
                    report = probe.public_report(self.observation(**{key: value}))
                    self.assertEqual(report["validity"], "unknown")
                    self.assertFalse(report["topology_candidate"])

    def test_affinity_and_processor_shape_rejected(self):
        cases = ({"process_affinity": 3}, {"system_affinity": 7},
                 {"processor_groups": 2}, {"logical_processors": 65}, {"python_bits": 32})
        for changes in cases:
            with self.subTest(changes=changes):
                self.assertFalse(probe.public_report(self.observation(**changes))["topology_candidate"])

    def test_private_and_arbitrary_fields_never_printed(self):
        report = probe.public_report(self.observation(
            authentication_luid="PRIVATE", pid=1234, command_line="PRIVATE", path="PRIVATE",
            python_version="PRIVATE", p1_capability_verified=True,
            errors=[{"stage": "PRIVATE", "win32_error": "PRIVATE", "message": "PRIVATE"}]),
            "PRIVATE", "PRIVATE")
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertNotIn("pid", report)
        self.assertFalse(report["p1_capability_verified"])
        self.assertFalse(report["topology_candidate"])

    def test_native_error_is_preserved_without_promoting_unknown(self):
        report = probe.public_report(self.observation(
            errors=[{"stage": "IsProcessInJob", "win32_error": 5}]))
        self.assertEqual(report["errors"], [{"stage": "IsProcessInJob", "win32_error": 5}])
        self.assertEqual(report["validity"], "unknown")

    def test_valid_unsupported_host_is_successful_observation_only(self):
        with patch.object(probe, "observe", return_value=self.observation(in_any_job=True)):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(probe.main(), 0)
        self.assertFalse(json.loads(output.getvalue())["topology_candidate"])

    def test_native_exception_is_redacted_and_fails(self):
        with patch.object(probe, "observe", side_effect=OSError("PRIVATE")):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(probe.main(), 2)
        self.assertNotIn("PRIVATE", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["validity"], "unknown")

    def test_non_windows_never_loads_native_library(self):
        with patch.object(probe.sys, "platform", "linux"):
            report = probe.public_report(probe.observe())
        self.assertEqual(report["errors"][0]["stage"], "native_platform")
        self.assertFalse(report["topology_candidate"])


if __name__ == "__main__":
    unittest.main()
