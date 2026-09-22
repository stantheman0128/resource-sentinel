"""Pure S2 producer/reducer tests. These do not establish native capability."""
from copy import deepcopy
import base64
import json
from pathlib import Path
import os
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.launch_topology import LaunchTopology
from tests.windows import adaptive_launch_producer as producer
from tests.fixtures import adaptive_launch_producer_child as child_fixture


def topology():
    return LaunchTopology(1, "powershell51", "a" * 64, "b" * 64, "c" * 64,
        ("pipe", "pipe", "pipe"), (None, None, None), False, "", False,
        None, None, 524288, 256, "job_list_handle_list")


def raw_pair():
    before = {"exit_code": 0, "output_sha256": producer.output_digest(b"", b""),
              "workload": {"literals": [], "membership": None}}
    after = deepcopy(before)
    after.update(started_tick=10, ended_tick=90, workload={"literals": [], "membership": True},
        wrapper={"local_cleanup_closed": True, "launches": 1, "infrastructure_failure": None,
                 "native_calls": ["CreateProcessW:JOB_LIST:HANDLE_LIST"], "cpu_flags": 0,
                 "active_processes": 0, "root_exit_tick": 40, "live_child_count_after_root": 0,
                 "launch_provenance": {"topology": topology().to_dict()}},
        retirement={"provenance": "retired", "bookkeeping_settled": True, "cleanup_complete": True})
    return before, after


class S2ProducerReducerTests(unittest.TestCase):
    def test_retired_actual_observation_reduces_with_original_topology(self):
        before, after = raw_pair()
        record = producer.build_case_record("exit_0", 1, before, after)
        self.assertEqual(record["topology_sha256"], topology().sha256)
        self.assertEqual(record["observations"]["observed_launches"], 1)
        self.assertEqual(set(record["cleanup"].values()), {0})

    def test_channel_digest_distinguishes_split_output(self):
        self.assertNotEqual(producer.output_digest(b"ab", b"c"), producer.output_digest(b"a", b"bc"))

    def test_output_or_exit_difference_is_not_normalized(self):
        for change in ({"exit_code": 7}, {"output_sha256": producer.output_digest(b"x", b"")}):
            before, after = raw_pair()
            after.update(change)
            with self.assertRaisesRegex(producer.S2Unavailable, "semantics"):
                producer.build_case_record("exit_0", 1, before, after)

    def test_root_exit_and_no_allocation_are_not_retirement(self):
        for update in ({"provenance": "native"}, {"bookkeeping_settled": False}, {"cleanup_complete": False}):
            before, after = raw_pair()
            after["retirement"].update(update)
            with self.assertRaisesRegex(producer.S2Unavailable, "retirement"):
                producer.build_case_record("exit_0", 1, before, after)

    def test_cap_or_membership_failure_cannot_be_published(self):
        before, after = raw_pair()
        after["wrapper"]["cpu_flags"] = 5
        with self.assertRaisesRegex(producer.S2Unavailable, "cleanup"):
            producer.build_case_record("exit_0", 1, before, after)
        before, after = raw_pair()
        after["workload"]["membership"] = False
        with self.assertRaisesRegex(producer.S2Unavailable, "membership"):
            producer.build_case_record("exit_0", 1, before, after)

    def test_child_done_timestamp_is_not_native_exit(self):
        before, after = raw_pair()
        after["child"] = {"ended_tick": 50}
        after["wrapper"]["live_child_count_after_root"] = 1
        with self.assertRaisesRegex(producer.S2Unavailable, "child_survival"):
            producer.build_case_record("root_child_survival", 1, before, after)
        after["last_child_exit_tick"] = 60
        record = producer.build_case_record("root_child_survival", 1, before, after)
        self.assertEqual(record["observations"]["last_child_exit_tick"], 60)

    def test_collector_requires_ordered_real_host_observation(self):
        before, after = raw_pair()
        with self.assertRaisesRegex(producer.S2Unavailable, "host_survival"):
            producer.build_case_record("collector_isolation", 1, before, after)
        after.update(collector_fixture_exit_tick=50, guardian_alive_after_collector_tick=60)
        self.assertEqual(producer.build_case_record("collector_isolation", 1, before, after)["observations"][
            "guardian_alive_after_collector_tick"], 60)

    def test_shared_wrong_argument_is_not_legacy_compatibility(self):
        before, after = raw_pair()
        before["workload"]["literals"] = after["workload"]["literals"] = ["mangled"]
        with self.assertRaisesRegex(producer.S2Unavailable, "expected_arguments"):
            producer.build_case_record("embedded_quotes", 1, before, after)

    def test_child_exit_125_is_distinct_from_infrastructure_exit(self):
        before, after = raw_pair()
        before["exit_code"] = after["exit_code"] = 125
        record = producer.build_case_record("child_exit_125", 1, before, after)
        self.assertEqual(record["observations"]["infra_exit_code"], 0)
        self.assertEqual(record["observations"]["observed_launches"], 1)

    def test_infrastructure_rejection_never_borrows_successful_topology(self):
        _, after = raw_pair()
        after.pop("workload")
        after.pop("retirement")
        after["exit_code"] = 125
        after["wrapper"].update(launches=0, infrastructure_failure="cmd_payload_too_large_or_invalid")
        after["wrapper"].pop("launch_provenance")
        after["wrapper"]["native_calls"] = []
        record = producer.build_case_record("infra_exit_125", 1, None, after)
        self.assertIsNone(record["topology_sha256"])
        self.assertEqual(record["observations"]["observed_launches"], 0)
        after["wrapper"]["launches"] = 1
        with self.assertRaisesRegex(producer.S2Unavailable, "prelaunch"):
            producer.build_case_record("infra_exit_125", 1, None, after)

    def test_case_iteration_is_bounded(self):
        before, after = raw_pair()
        for case, iteration in (("typo", 1), ("exit_0", 4), ("exit_0", True), ("fast_exit", 21)):
            with self.assertRaisesRegex(producer.S2Unavailable, "case_invalid"):
                producer.build_case_record(case, iteration, before, after)


class S2ProducerOwnershipTests(unittest.TestCase):
    def test_failing_real_coverage_precedes_discovery_and_native_launch(self):
        coverage = SimpleNamespace(authority=SimpleNamespace(assert_ready=Mock(side_effect=RuntimeError("cohort_missing"))))
        with patch.object(producer, "_discover") as discovery, patch.object(producer, "_run_case") as launch:
            with self.assertRaisesRegex(RuntimeError, "cohort_missing"):
                producer.produce_s2(coverage, "nonexistent", None)
        discovery.assert_not_called()
        launch.assert_not_called()

    def test_pending_original_process_requires_positive_same_object_exit(self):
        process = Mock()
        process.poll.side_effect = [None, 0]
        error = producer.S2CustodyPending("pending", [process])
        self.assertIs(error.pending_processes[0], process)
        self.assertFalse(error.observe_settled())
        self.assertTrue(error.observe_settled())
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_native_close_unknown_never_retries_or_reports_settled(self):
        handle = Mock()
        handle.close.side_effect = OSError("ambiguous")
        with self.assertRaises(producer.S2CustodyPending) as raised:
            producer._close_observers([handle])
        self.assertIs(raised.exception.native_uncertainties[0][0], handle)
        self.assertFalse(raised.exception.observe_settled())
        self.assertFalse(raised.exception.observe_settled())
        handle.close.assert_called_once()

    def test_live_observer_thread_remains_part_of_custody(self):
        thread = Mock()
        thread.is_alive.side_effect = [True, False]
        error = producer.S2CustodyPending("pending", threads=(thread,))
        self.assertFalse(error.observe_settled())
        self.assertTrue(error.observe_settled())

    def test_timeout_retains_wrapper_without_termination(self):
        process = Mock()
        process.pid = 700
        process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 100)
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.subprocess, "Popen", return_value=process):
                try:
                    with self.assertRaises(producer.S2CustodyPending) as raised:
                        producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                            "token", "exit_0", "managed", directory, SimpleNamespace(guardian=guardian), Path("python.exe"))
                    self.assertIn(process, raised.exception.pending_processes)
                    self.assertTrue((directory / "stop").exists())
                    process.kill.assert_not_called()
                    process.terminate.assert_not_called()
                finally:
                    producer._PENDING_PROCESSES.remove(process)

    def test_special_cases_keep_same_canonical_pipe_topology(self):
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        for case in ("exit_0", "null_stdio", "ctrl_c"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                process = Mock(pid=700)
                process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 110)
                directory = Path(temporary)
                with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                        patch.object(producer, "_tick", return_value=1), \
                        patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                        patch.object(producer.subprocess, "Popen", return_value=process) as start:
                    try:
                        with self.assertRaises(producer.S2CustodyPending):
                            producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                                "token", case, "managed", directory, SimpleNamespace(guardian=guardian), Path("python.exe"))
                        payload = json.loads(base64.b64decode(start.call_args.args[0][-1]))
                        self.assertEqual(payload["stdio_profile"], "pipes")
                        self.assertEqual(payload["signal"], case == "ctrl_c")
                        self.assertEqual(start.call_args.kwargs["creationflags"], 0x10)
                    finally:
                        producer._PENDING_PROCESSES.remove(process)

    def test_failed_timeout_evidence_does_not_replace_original_driver_custody(self):
        process = Mock(pid=701)
        process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 110)
        process.poll.return_value = None
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.subprocess, "Popen", return_value=process), \
                    patch.object(producer, "_write", side_effect=OSError("evidence unavailable")), \
                    patch.object(Path, "touch", side_effect=OSError("stop unavailable")):
                try:
                    with self.assertRaises(producer.S2CustodyPending) as raised:
                        producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                            "token", "exit_0", "managed", directory, SimpleNamespace(guardian=guardian), Path("python.exe"))
                    pending = raised.exception
                    self.assertIn(process, pending.pending_processes)
                    self.assertIsInstance(pending.primary_error, subprocess.TimeoutExpired)
                    self.assertEqual(len(pending.diagnostic_errors), 2)
                    self.assertFalse(pending.observe_settled())
                finally:
                    producer._PENDING_PROCESSES.remove(process)

    def test_interrupted_observation_retains_driver_when_stop_write_fails(self):
        process = Mock(pid=702)
        interrupted = KeyboardInterrupt()
        process.communicate.side_effect = interrupted
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.subprocess, "Popen", return_value=process), \
                    patch.object(Path, "touch", side_effect=OSError("stop unavailable")):
                try:
                    with self.assertRaises(producer.S2CustodyPending) as raised:
                        producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                            "token", "exit_0", "managed", directory, SimpleNamespace(guardian=guardian), Path("python.exe"))
                    self.assertIn(process, raised.exception.pending_processes)
                    self.assertIs(raised.exception.primary_error, interrupted)
                    self.assertEqual(len(raised.exception.diagnostic_errors), 1)
                finally:
                    producer._PENDING_PROCESSES.remove(process)


class ConsoleCustodyTests(unittest.TestCase):
    """Portable ownership models; no actual console, child, wait or close."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.native = SimpleNamespace(console_process_ids=Mock(return_value=[os.getpid()]))
        self.shell = SimpleNamespace(poll=Mock(return_value=0), _handle=Mock(),
            stdin=None, stdout=None, stderr=None, kill=Mock(), terminate=Mock())
        self.owner = child_fixture._ConsoleCustody(self.directory, self.native, [], [])
        self.owner.console_verified = self.owner.creation_started = True
        self.owner.shell = self.shell

    def test_live_original_shell_cannot_finish_even_when_console_snapshot_is_empty(self):
        self.shell.poll.return_value = None
        self.assertFalse(self.owner.step())
        self.shell._handle.Close.assert_not_called()
        self.assertIs(self.owner.shell, self.shell)
        self.shell.poll.return_value = 0
        self.assertTrue(self.owner.step())
        self.shell._handle.Close.assert_called_once()
        self.shell.kill.assert_not_called()
        self.shell.terminate.assert_not_called()

    def test_shell_exit_waits_for_surviving_original_console_member(self):
        self.native.console_process_ids.side_effect = [[os.getpid(), 9001], [os.getpid()]]
        self.assertFalse(self.owner.step())
        self.shell._handle.Close.assert_not_called()
        self.assertTrue(self.owner.step())
        self.shell._handle.Close.assert_called_once()

    def test_unknown_console_observation_is_sticky_without_reopen_or_native_close(self):
        self.native.console_process_ids.side_effect = OSError("native unknown")
        self.assertFalse(self.owner.step())
        self.assertTrue(self.owner.quarantined)
        self.native.console_process_ids.side_effect = None
        self.assertFalse(self.owner.step())
        self.native.console_process_ids.assert_called_once()
        self.shell._handle.Close.assert_not_called()

    def test_unknown_native_close_is_sticky_and_keeps_original_handle(self):
        error = OSError("close unknown")
        self.shell._handle.Close.side_effect = error
        self.assertFalse(self.owner.step())
        self.assertFalse(self.owner.step())
        self.assertTrue(self.owner.quarantined)
        self.assertEqual(self.owner.errors["close"], (self.shell._handle, error))
        self.shell._handle.Close.assert_called_once()

    def test_close_ack_interrupt_does_not_replay_successful_native_close(self):
        class InterruptedSet(set):
            def add(self, value):
                raise KeyboardInterrupt()
        self.owner._closed = InterruptedSet()
        with self.assertRaises(KeyboardInterrupt):
            self.owner.step()
        self.assertFalse(self.owner.step())
        self.assertTrue(self.owner.quarantined)
        self.shell._handle.Close.assert_called_once()

    def test_creation_exception_without_returned_owner_cannot_be_normal_exit(self):
        self.owner.shell = None
        self.assertFalse(self.owner.step())
        self.assertTrue(self.owner.quarantined)
        self.native.console_process_ids.assert_not_called()

    def test_evidence_failure_while_child_lives_does_not_exit_resident_cleanup(self):
        self.shell.poll.return_value = None
        raw = {}
        publish = Mock(side_effect=[OSError("evidence full"), None])
        def child_exits(_):
            self.assertFalse(self.owner.settled)
            self.assertIs(self.owner.shell, self.shell)
            self.shell._handle.Close.assert_not_called()
            self.shell.poll.return_value = 0
        with patch.object(child_fixture, "tick", return_value=1), \
                patch.object(child_fixture.time, "sleep", side_effect=child_exits) as sleep:
            self.owner.finish(raw, publish)
        sleep.assert_called_once_with(.25)
        self.assertTrue(self.owner.settled)
        self.assertTrue(raw["cleanup_verified"])
        self.assertEqual(raw["error"], "s2_console_evidence_write_failed")
        self.assertIn("evidence", self.owner.errors)
        self.assertEqual(publish.call_count, 2)

    def test_driver_timeout_waits_resident_for_actual_shell_exit(self):
        from tests.windows import adaptive_win32 as native
        self.shell.poll.return_value = None
        self.shell.communicate = Mock(side_effect=subprocess.TimeoutExpired("shell", 95))
        payload = base64.b64encode(json.dumps({"directory": str(self.directory), "token": "token",
            "shell_args": ["fixture"], "stdio_profile": "pipes"}).encode()).decode()
        def release(_):
            self.shell._handle.Close.assert_not_called()
            self.shell.poll.return_value = 0
        with patch.object(child_fixture, "authorize", return_value=(self.directory, {})), \
                patch.object(child_fixture, "tick", return_value=1), \
                patch.object(native, "console_process_ids", return_value=[os.getpid()]), \
                patch.object(child_fixture.subprocess, "Popen", return_value=self.shell), \
                patch.object(child_fixture.signal, "signal"), \
                patch.object(child_fixture.time, "sleep", side_effect=release) as sleep:
            result = child_fixture.console_driver(payload)
        self.assertEqual(result, 125)
        sleep.assert_called_once_with(.25)
        self.assertTrue(json.loads((self.directory / "console-result.json").read_text("utf-8"))["cleanup_verified"])
        self.shell._handle.Close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
