"""Exercise actual S1 orchestration using explicit non-native observations."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import sys

from tests.windows import test_adaptive_job_capability as s1


class S1OwnerIntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.case = s1.WindowsJobCapabilitySpike("test_00_fixture_self_stops_and_job_has_no_other_limits")
        self.events = []
        self.job = SimpleNamespace(handle=11, closed=False, query_cpu=Mock(return_value={"flags": 0, "rate_bp": 0}),
            wait_empty=Mock(return_value=True), active_pids=Mock(return_value=[]))
        self.owner = SimpleNamespace(restore=Mock(side_effect=lambda: self.events.append("restore")),
            finalize=Mock(side_effect=self.finalize), close=Mock(side_effect=self.close),
            _retain=Mock(side_effect=lambda: self.events.append("retain")))
        self.record = {"status": "pass"}

    def finalize(self):
        self.events.append("finalize")
        return {"state": "FINISHED"}

    def close(self):
        self.events.append("close")
        self.job.handle = None
        self.job.closed = True

    def cleanup(self):
        self.case._cleanup(self.owner, self.job, None, self.directory, self.record,
                           s1.time.monotonic() + 120)

    def test_actual_cleanup_restores_then_finalizes_before_close(self):
        self.cleanup()
        self.assertEqual(self.events, ["restore", "finalize", "close"])
        self.assertTrue((self.directory / "stop").exists())
        self.assertEqual(self.record["lifecycle_terminal"], "FINISHED")
        self.assertTrue(self.record["handles_closed"])

    def test_observation_failure_does_not_skip_owner_restore(self):
        self.job.query_cpu.side_effect = [OSError("lost probe"), {"flags": 0, "rate_bp": 0}]
        with self.assertRaisesRegex(AssertionError, "observation query failed"):
            self.cleanup()
        self.owner.restore.assert_called_once_with()
        self.owner.finalize.assert_not_called()
        self.owner.close.assert_not_called()
        self.assertTrue((self.directory / "stop").exists())
        self.assertEqual(self.job.handle, 11)
        self.owner._retain.assert_called_once_with()

    def test_restore_failure_still_requests_stop_and_keeps_custody(self):
        self.owner.restore.side_effect = OSError("restore unverified")
        with self.assertRaisesRegex(AssertionError, "restore/query failed"):
            self.cleanup()
        self.assertTrue((self.directory / "stop").exists())
        self.job.wait_empty.assert_called_once()
        self.owner.finalize.assert_not_called()
        self.owner.close.assert_not_called()
        self.owner._retain.assert_called_once_with()

    def test_finalization_failure_does_not_close_handles(self):
        self.owner.finalize.side_effect = RuntimeError("archive failed")
        with self.assertRaisesRegex(AssertionError, "lifecycle finalization failed"):
            self.cleanup()
        self.owner.restore.assert_called_once_with()
        self.owner.close.assert_not_called()
        self.assertEqual(self.job.handle, 11)
        self.owner._retain.assert_called_once_with()

    def test_actual_case_creation_passes_immutable_payload_and_full_demand(self):
        owner = SimpleNamespace(prepare=Mock(return_value=self.job))
        coverage = SimpleNamespace(open_case=Mock(return_value=owner))
        with patch.object(type(self.case), "coverage", coverage, create=True):
            got_owner, job, command = self.case._open_case(self.directory, 115,
                                                         workers=4, cpu_units=5)
        self.assertIs(got_owner, owner)
        self.assertIs(job, self.job)
        owner.prepare.assert_called_once_with()
        supplied = coverage.open_case.call_args.kwargs
        self.assertEqual(supplied["command"], command)
        self.assertEqual(supplied["requested"].cpu_units, 5)
        self.assertEqual(supplied["requested"].physical_bytes, 1 << 30)
        self.assertEqual(supplied["requested"].commit_bytes, 1 << 30)
        self.assertEqual(supplied["cwd"], str(self.directory))
        self.assertIn(supplied["creation_nonce"], command)

    def test_actual_launch_uses_owner_claim_path(self):
        owner = SimpleNamespace(launch_once=Mock(return_value="synthetic-process"))
        with patch.dict(sys.modules, {"msvcrt": SimpleNamespace(get_osfhandle=lambda fd: fd)}):
            result = self.case._launch(owner, "exact immutable payload", self.directory)
        self.assertEqual(result, "synthetic-process")
        owner.launch_once.assert_called_once()
        self.assertEqual(owner.launch_once.call_args.args, (sys.executable, "exact immutable payload"))
        self.assertEqual(owner.launch_once.call_args.kwargs["cwd"], str(self.directory))


if __name__ == "__main__":
    unittest.main()
