"""Actual native entry-point rejection tests; no Win32 calls or fixture work."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.windows import adaptive_admission as admission
from tests.windows import test_adaptive_job_capability as s1
from tests.windows import test_adaptive_launch_compatibility as s2
from tests.windows import test_adaptive_recovery_capability as s3
from tests.fixtures import adaptive_recovery_actor as actor


class ContinuousAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def test_environment_or_alternate_ledger_cannot_unlock_real_s1_setup(self):
        with patch.dict(os.environ, {
                "SENTINEL_ADAPTIVE_WINDOWS_SPIKES": "1",
                "SENTINEL_CONTINUOUS_ADMISSION": "true",
                "SENTINEL_RESERVATION_ID": "pretend-receipt",
                "SENTINEL_DATA_DIR": "alternate-ledger"}), \
                patch.object(s1, "_isolated_evidence_directory", return_value=self.directory), \
                patch.object(s1, "require_supported_host") as host, \
                patch.object(s1.OwnedJob, "create") as create, \
                patch.object(s1.OwnedJob, "set_cpu_rate") as control:
            with self.assertRaisesRegex(admission.ContinuousAdmissionUnavailable, "provider_unavailable"):
                s1.WindowsJobCapabilitySpike.setUpClass()
        host.assert_not_called()
        create.assert_not_called()
        control.assert_not_called()
        record = json.loads((self.directory / "admission-gate.json").read_text())
        self.assertEqual(record["status"], "blocked")
        self.assertEqual(record["reason"], "continuous_admission_provider_unavailable")
        self.assertEqual(record["cpu_control_writes"], 0)
        self.assertFalse(record["capability_allowlist_eligible"])
        self.assertNotIn("reservation_id", record)
        self.assertEqual(s1.WindowsJobCapabilitySpike._s1_gate.completed, [])

    def test_s1_evidence_write_failure_also_prevents_native_setup(self):
        with patch.object(s1, "_isolated_evidence_directory", return_value=self.directory), \
                patch.object(s1, "_write_json", side_effect=[None, OSError("fixture failure")]), \
                patch.object(s1, "require_supported_host") as host, \
                patch.object(s1.OwnedJob, "create") as create:
            with self.assertRaises(OSError):
                s1.WindowsJobCapabilitySpike.setUpClass()
        host.assert_not_called()
        create.assert_not_called()

    def test_s2_setup_cannot_start_independently_of_s1(self):
        with patch.dict(os.environ, {"SENTINEL_ADAPTIVE_SPIKE_DIR": str(self.directory)}), \
                patch.object(s2, "_native") as native, \
                patch.object(s2.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(admission.ContinuousAdmissionUnavailable, "provider_unavailable"):
                s2.WindowsLaunchCompatibility.setUpClass()
        native.assert_not_called()
        launch.assert_not_called()
        record = json.loads((s2.WindowsLaunchCompatibility.evidence / "admission-gate.json").read_text())
        self.assertEqual(record["status"], "blocked")
        self.assertFalse(record["capability_allowlist_eligible"])

    def test_s2_evidence_failure_still_prevents_native_setup(self):
        with patch.dict(os.environ, {"SENTINEL_ADAPTIVE_SPIKE_DIR": str(self.directory)}), \
                patch.object(s2, "write_json", side_effect=OSError("fixture failure")), \
                patch.object(s2, "_native") as native:
            with self.assertRaises(OSError):
                s2.WindowsLaunchCompatibility.setUpClass()
        native.assert_not_called()

    def test_s2_direct_cli_helpers_cannot_bypass_setup_admission(self):
        with patch.dict(os.environ, {"SENTINEL_ADAPTIVE_WINDOWS_SPIKES": "1"}), \
                patch.object(s2, "_native") as native, \
                patch.object(s2.subprocess, "Popen") as launch, \
                patch.object(s2.threading, "Timer") as timer:
            # Even payload decoding is after the real gate. No fabricated
            # fixture authorization file can stand in for lifetime coverage.
            self.assertEqual(s2._launch_host("not-a-receipt"), 125)
            self.assertEqual(s2._console_driver("not-a-receipt"), 125)
        native.assert_not_called()
        launch.assert_not_called()
        timer.assert_not_called()

    def test_s3_setup_cannot_control_independently_of_s1(self):
        with patch.dict(os.environ, {"SENTINEL_ADAPTIVE_WINDOWS_SPIKES": "1"}), \
                patch.object(s3.sys, "platform", "win32"), \
                patch.object(s3.win, "require_supported_host") as host, \
                patch.object(s3.win.OwnedJob, "create") as create, \
                patch.object(s3.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(admission.ContinuousAdmissionUnavailable, "provider_unavailable"):
                s3.RecoveryCapability.setUpClass()
        host.assert_not_called()
        create.assert_not_called()
        launch.assert_not_called()

    def test_direct_s3_guardian_cannot_start_a_new_restriction(self):
        with patch.object(actor, "require_supported_host") as host, \
                patch.object(actor.OwnedJob, "open") as reopen, \
                patch.object(actor.OwnedJob, "set_cpu_rate_unverified") as control:
            with self.assertRaisesRegex(admission.ContinuousAdmissionUnavailable, "provider_unavailable"):
                actor.guardian(self.directory, {})
        host.assert_not_called()
        reopen.assert_not_called()
        control.assert_not_called()

    def test_all_nonrestore_s3_cli_roles_deny_before_case_native_or_launch(self):
        for role in ("worker", "root", "helper", "wrapper", "guardian"):
            with self.subTest(role=role), \
                    patch.object(sys, "argv", ["actor", role, str(self.directory)]), \
                    patch.object(actor, "load_case") as load_case, \
                    patch.object(actor, "mark") as native_report, \
                    patch.object(actor, role) as dispatch, \
                    patch.object(actor, "launch_in_job") as launch, \
                    patch.object(actor.subprocess, "Popen") as popen:
                self.assertEqual(actor.main(), 125)
            load_case.assert_not_called()
            native_report.assert_not_called()
            dispatch.assert_not_called()
            launch.assert_not_called()
            popen.assert_not_called()

    def test_restore_only_cli_is_not_blocked_by_new_admission_failure(self):
        for role in ("restore-a", "restore-b"):
            with self.subTest(role=role), \
                    patch.object(sys, "argv", ["actor", role, str(self.directory)]), \
                    patch.object(actor, "load_case", return_value=(self.directory, {})), \
                    patch.object(actor, "restore", return_value=0) as restore, \
                    patch.object(actor, "require_continuous_admission", side_effect=AssertionError("must not gate recovery")) as guard:
                self.assertEqual(actor.main(), 0)
                restore.assert_called_once_with(self.directory, {}, role)
                guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
