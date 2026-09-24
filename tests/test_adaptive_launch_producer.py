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
    def setUp(self):
        self.source_pin = {"schema_version": 1, "fixture": "explicit portable pin model"}
        for replacement in (patch.object(producer, "_source_pin", return_value=self.source_pin),
                            patch.object(producer, "_original_process_exit_code", return_value=None),
                            patch.dict(producer._CASE_ATTEMPTS, {}, clear=True)):
            replacement.start()
            self.addCleanup(replacement.stop)

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
        process.poll.return_value = None
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
                process.poll.return_value = None
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
        process.poll.return_value = None
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

    def test_unknown_creation_retains_original_attempt_before_popen(self):
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        failure = KeyboardInterrupt()
        def interrupted(*args, **kwargs):
            self.assertEqual(len(producer._CASE_ATTEMPTS), 1)
            original = next(iter(producer._CASE_ATTEMPTS.values()))
            self.assertTrue(original.create_entered)
            self.assertEqual(tuple(args[0]), original.driver_args)
            raise failure
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.subprocess, "Popen", side_effect=interrupted):
                with self.assertRaises(producer.S2CustodyPending) as raised:
                    producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                        "token", "exit_0", "managed", directory, SimpleNamespace(guardian=guardian), Path("python.exe"))
                attempt, = raised.exception.case_attempts
                self.assertIs(raised.exception.primary_error, failure)
                self.assertIs(producer._CASE_ATTEMPTS[attempt.declaration.attempt_id], attempt)
                self.assertIsNone(attempt.process)
                self.assertFalse(raised.exception.observe_settled())

    def test_interrupted_observer_start_is_retained_before_creation(self):
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        observer = Mock(spec_set=["start", "is_alive"])
        observer.start.side_effect = KeyboardInterrupt()
        observer.is_alive.return_value = False
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.threading, "Thread", return_value=observer), \
                    patch.object(producer.subprocess, "Popen") as popen:
                with self.assertRaises(producer.S2CustodyPending) as raised:
                    producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                        "token", "root_child_survival", "managed", directory,
                        SimpleNamespace(guardian=guardian), Path("python.exe"))
                attempt, = raised.exception.case_attempts
                self.assertIs(attempt.observer, observer)
                self.assertFalse(attempt.observe_local_settlement())
                popen.assert_not_called()

    def test_timeout_retains_late_observer_unknown_close_channel(self):
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        observer = Mock(spec_set=["start", "is_alive"])
        observer.is_alive.return_value = True
        process = Mock(pid=701)
        process.poll.return_value = None
        process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 110)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                    patch.object(producer, "_tick", return_value=1), \
                    patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                    patch.object(producer.threading, "Thread", return_value=observer), \
                    patch.object(producer.subprocess, "Popen", return_value=process):
                try:
                    with self.assertRaises(producer.S2CustodyPending) as raised:
                        producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                            "token", "root_child_survival", "managed", directory,
                            SimpleNamespace(guardian=guardian), Path("python.exe"))
                    pending = raised.exception
                    attempt, = pending.case_attempts
                    original_handle, close_error = object(), OSError("unknown observer close")
                    late = producer.S2CustodyPending("late_native_close",
                        native_uncertainties=((original_handle, close_error),))
                    attempt.observer_errors.append(late)
                    observer.is_alive.return_value = False
                    process.poll.return_value = 0
                    self.assertFalse(pending.observe_settled())
                    self.assertFalse(pending.observe_settled())
                    self.assertIs(attempt.observer_errors[0].native_uncertainties[0][0], original_handle)
                    process._handle.Close.assert_not_called()
                finally:
                    producer._PENDING_PROCESSES.remove(process)

    def test_collector_diagnostic_failure_cannot_skip_original_observer_close(self):
        from tests.windows import adaptive_win32 as native
        identity = {"pid": 11, "created_filetime_100ns": "100"}
        process = Mock(spec_set=["wait", "close"])
        process.wait.return_value = True  # Stop before any fault mutation.
        for close_fails in (False, True):
            with self.subTest(close_fails=close_fails):
                process.reset_mock()
                process.close.side_effect = OSError("unknown close") if close_fails else None
                write_error = OSError("diagnostic unavailable")
                with patch.object(producer, "_read", side_effect=[{"identity": identity}, {"identity": identity}]), \
                        patch.object(native.ProcessHandle, "open", return_value=process), \
                        patch.object(producer, "_write", side_effect=write_error):
                    expected = producer.S2CustodyPending if close_fails else OSError
                    with self.assertRaises(expected) as raised:
                        producer._collector_fault(Path("isolated"), object(), managed=False)
                process.close.assert_called_once()
                if close_fails:
                    self.assertIs(raised.exception.native_uncertainties[0][0], process)
                    self.assertIs(raised.exception.__context__, write_error)
                else:
                    self.assertIs(raised.exception, write_error)

    def test_all_python_and_powershell_hops_carry_same_source_pin(self):
        guardian = SimpleNamespace(guardian_epoch="epoch", host_identity=SimpleNamespace(
            pid=10, created_filetime_100ns=100))
        for mode in ("managed", "baseline"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                process = Mock(pid=700)
                process.poll.return_value = None
                process.communicate.side_effect = subprocess.TimeoutExpired("fixture", 110)
                with patch.object(producer, "_endpoint", return_value=SimpleNamespace(instance_id="endpoint")), \
                        patch.object(producer, "_tick", return_value=1), \
                        patch.object(producer, "_hidden_console_startup", return_value=Mock()), \
                        patch.object(producer.subprocess, "Popen", return_value=process) as popen:
                    try:
                        with self.assertRaises(producer.S2CustodyPending):
                            producer._run_case(Path("powershell.exe"), directory / "bridge.ps1", directory,
                                "token", "exit_0", mode, directory, SimpleNamespace(guardian=guardian),
                                Path("python.exe"), coverage=object())
                        args = popen.call_args.args[0]
                        self.assertEqual(args[1], "-I")
                        self.assertEqual(json.loads(base64.b64decode(args[4])), self.source_pin)
                        console = json.loads(base64.b64decode(args[-1]))
                        self.assertEqual(console["source_pin"], self.source_pin)
                        shell = console["shell_args"]
                        if mode == "baseline":
                            self.assertEqual(shell[1], "-I")
                            holder = json.loads(base64.b64decode(shell[-1]))
                            self.assertEqual(holder["source_pin"], self.source_pin)
                            self.assertIn("-SourcePin", holder["command"])
                        else:
                            self.assertEqual(json.loads(base64.b64decode(shell[-1])), self.source_pin)
                            spec = json.loads(base64.b64decode(shell[shell.index("-Payload") + 1]))
                            self.assertIn(" -I ", spec["command"])
                            self.assertIn("--source-pin " + producer._encode(self.source_pin), spec["command"])
                    finally:
                        producer._PENDING_PROCESSES.remove(process)


class S2CaseAttemptTests(unittest.TestCase):
    def setUp(self):
        replacement = patch.dict(producer._CASE_ATTEMPTS, {}, clear=True)
        replacement.start()
        self.addCleanup(replacement.stop)
        query = patch.object(producer, "_original_process_exit_code", return_value=0)
        self.native_exit = query.start()
        self.addCleanup(query.stop)
        self.owner = producer.S2CaseAttempt(producer.S2CaseDeclaration(
            "unique-attempt", "isolated", "token", "exit_0", "managed", "pipes", "{}"))
        self.process = Mock(spec_set=["poll", "_handle", "returncode"])
        self.process.poll.return_value = 0
        self.owner.pin_launch(("fixed", "arguments"), None)
        self.owner.create_entered = True
        self.owner.bind_process(self.process)

    def test_local_settlement_closes_original_handle_once(self):
        self.assertTrue(self.owner.observe_local_settlement())
        self.assertTrue(self.owner.observe_local_settlement())
        self.process._handle.Close.assert_called_once()
        self.assertIs(self.owner.process, self.process)

    def test_ambiguous_close_remains_owned_without_retry(self):
        self.process._handle.Close.side_effect = KeyboardInterrupt()
        self.assertFalse(self.owner.observe_local_settlement())
        self.assertFalse(self.owner.observe_local_settlement())
        self.process._handle.Close.assert_called_once()
        self.assertFalse(self.owner.local_settled)

    def test_live_original_process_cannot_settle(self):
        self.process.poll.return_value = None
        self.native_exit.return_value = None
        self.assertFalse(self.owner.observe_local_settlement())
        self.process._handle.Close.assert_not_called()

    def test_cached_exit_does_not_replace_positive_original_native_exit(self):
        self.process.poll.return_value = 0
        self.native_exit.return_value = None
        original = self.process._handle
        self.assertFalse(self.owner.observe_local_settlement())
        self.native_exit.assert_called_once_with(original)
        original.Close.assert_not_called()
        self.process.poll.assert_not_called()

    def test_same_popen_replaced_handle_stays_pending_without_query_or_close(self):
        original = self.process._handle
        replacement = Mock(spec_set=["Close"])
        self.process._handle = replacement
        self.process.poll.return_value = 0
        pending = producer.S2CustodyPending("original_handle_changed",
            processes=(self.process,), attempts=(self.owner,))
        self.assertFalse(pending.observe_settled())
        self.assertFalse(pending.observe_settled())
        self.assertIs(self.owner.process, self.process)
        self.assertIs(self.owner._original_process_handle, original)
        self.assertFalse(self.owner.local_settled)
        self.native_exit.assert_not_called()
        self.process.poll.assert_not_called()
        original.Close.assert_not_called()
        replacement.Close.assert_not_called()

    def test_native_wait_failure_keeps_original_handle_open(self):
        self.native_exit.side_effect = OSError("native wait unknown")
        self.assertFalse(self.owner.observe_local_settlement())
        self.assertIs(self.owner._original_process_handle, self.process._handle)
        self.process._handle.Close.assert_not_called()

    def test_original_native_exit_is_recorded_before_close_without_repoll(self):
        self.native_exit.return_value = 7
        pending = producer.S2CustodyPending("finishing", processes=(self.process,), attempts=(self.owner,))
        self.assertTrue(pending.observe_settled())
        self.assertEqual(self.process.returncode, 7)
        self.assertEqual(self.owner.native_exit_code, 7)
        self.process.poll.assert_not_called()
        self.process._handle.Close.assert_called_once()

    def test_terminal_observer_custody_cannot_disappear_from_original_channel(self):
        error = producer.S2CustodyPending("unknown_observer_close", native_uncertainties=((object(), OSError()),))
        self.owner.observer_errors.append(error)
        self.assertFalse(self.owner.observe_local_settlement())
        self.owner.observer_errors.clear()
        self.assertFalse(self.owner.observe_local_settlement())
        self.assertIs(self.owner._observer_terminal_errors[0], error)
        self.native_exit.assert_not_called()
        self.process._handle.Close.assert_not_called()

    def test_replaced_process_and_declaration_are_not_adopted(self):
        self.owner.process = Mock()
        with self.assertRaisesRegex(producer.S2Unavailable, "original_case_attempt"):
            self.owner.observe_local_settlement()
        self.process._handle.Close.assert_not_called()

    def test_serialized_source_pin_is_not_a_producer_bootstrap(self):
        with self.assertRaisesRegex(producer.S2Unavailable, "original_producer_bootstrap"):
            producer._source_pin(SimpleNamespace(entry="tests/windows/run_adaptive_s2.py",
                modules={producer.__name__: producer}, source_pin=lambda: {}))


class ConsoleCustodyTests(unittest.TestCase):
    """Portable ownership models; no actual console, child, wait or close."""
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.native = SimpleNamespace(console_process_ids=Mock(return_value=[os.getpid()]))
        self.shell = SimpleNamespace(poll=Mock(return_value=0), _handle=Mock(),
            stdin=None, stdout=None, stderr=None, kill=Mock(), terminate=Mock())
        query = patch.object(child_fixture, "_original_shell_exit_code", return_value=0)
        self.native_exit = query.start()
        self.addCleanup(query.stop)
        self.owner = child_fixture._ConsoleCustody(self.directory, self.native, [], [])
        self.owner.console_verified = self.owner.creation_started = True
        self.owner.bind_shell(self.shell)

    def test_live_original_shell_cannot_finish_even_when_console_snapshot_is_empty(self):
        self.shell.poll.return_value = None
        self.native_exit.return_value = None
        self.assertFalse(self.owner.step())
        self.shell._handle.Close.assert_not_called()
        self.assertIs(self.owner.shell, self.shell)
        self.shell.poll.return_value = 0
        self.native_exit.return_value = 0
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
        self.native_exit.return_value = None
        raw = {}
        publish = Mock(side_effect=[OSError("evidence full"), None])
        def child_exits(_):
            self.assertFalse(self.owner.settled)
            self.assertIs(self.owner.shell, self.shell)
            self.shell._handle.Close.assert_not_called()
            self.shell.poll.return_value = 0
            self.native_exit.return_value = 0
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
        self.native_exit.return_value = None
        self.shell.communicate = Mock(side_effect=subprocess.TimeoutExpired("shell", 95))
        payload = base64.b64encode(json.dumps({"directory": str(self.directory), "token": "token", "source_pin": {},
            "shell_args": ["fixture"], "stdio_profile": "pipes"}).encode()).decode()
        def release(_):
            self.shell._handle.Close.assert_not_called()
            self.shell.poll.return_value = 0
            self.native_exit.return_value = 0
        with patch.object(child_fixture, "authorize", return_value=(self.directory, {})), \
                patch.object(child_fixture, "assert_source"), \
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

    def test_same_shell_handle_substitution_cannot_close_foreign_or_original(self):
        original = self.shell._handle
        replacement = Mock(spec_set=["Close"])
        self.shell._handle = replacement
        self.assertFalse(self.owner.step())
        self.assertFalse(self.owner.step())
        self.assertTrue(self.owner.quarantined)
        self.assertIs(self.owner._original_shell_handle, original)
        self.native_exit.assert_not_called()
        self.shell.poll.assert_not_called()
        original.Close.assert_not_called()
        replacement.Close.assert_not_called()

    def test_replaced_shell_object_cannot_be_adopted_even_with_same_handle(self):
        original = self.shell
        self.owner.shell = SimpleNamespace(poll=Mock(return_value=0), _handle=original._handle,
                                          stdin=None, stdout=None, stderr=None)
        self.assertFalse(self.owner.step())
        self.assertIs(self.owner._original_shell, original)
        self.native_exit.assert_not_called()
        original._handle.Close.assert_not_called()

    def test_cached_shell_exit_cannot_replace_native_exit_observation(self):
        self.shell.poll.return_value = 7
        self.native_exit.return_value = None
        self.assertFalse(self.owner.step())
        self.native_exit.assert_called_once_with(self.owner._original_shell_handle)
        self.shell.poll.assert_not_called()
        self.shell._handle.Close.assert_not_called()

    def test_native_exit_is_recorded_and_queried_once_before_original_close(self):
        self.native_exit.return_value = 7
        self.assertTrue(self.owner.step())
        self.assertTrue(self.owner.step())
        self.assertEqual(self.shell.returncode, 7)
        self.native_exit.assert_called_once_with(self.owner._original_shell_handle)
        self.shell.poll.assert_not_called()
        self.shell._handle.Close.assert_called_once()


class S2ObserverAndAncestryTests(unittest.TestCase):
    def setUp(self):
        replacement = patch.object(child_fixture, "_OBSERVER_OPEN_CUSTODY", [])
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_producer_retains_exact_failed_open_owner_as_pending(self):
        from tests.windows import adaptive_win32 as native
        owner, primary, cleanup = Mock(), ValueError("validation failed"), OSError("close unknown")
        error = native.RetainedProcessOpenError(owner, primary, cleanup)
        with patch.object(native.ProcessHandle, "open", side_effect=error):
            with self.assertRaises(producer.S2CustodyPending) as raised:
                producer._open_observer(native, 700, "100")
        self.assertIs(raised.exception.native_uncertainties[0][0], owner)
        self.assertIs(raised.exception.native_uncertainties[0][1], error)
        self.assertFalse(raised.exception.observe_settled())
        owner.close.assert_not_called()

    def test_collector_diagnostic_failure_cannot_hide_retained_open_owner(self):
        from tests.windows import adaptive_win32 as native
        owner = Mock()
        native_error = native.RetainedProcessOpenError(owner, ValueError("validation"), OSError("close"))
        diagnostic = OSError("artifact unavailable")
        identity = {"pid": 700, "created_filetime_100ns": "100"}
        with patch.object(producer, "_read", side_effect=[{"identity": identity}, {"identity": identity}]), \
                patch.object(native.ProcessHandle, "open", side_effect=native_error), \
                patch.object(producer, "_write", side_effect=diagnostic):
            with self.assertRaises(producer.S2CustodyPending) as raised:
                producer._collector_fault(Path("isolated"), object(), managed=False)
        pending = raised.exception
        self.assertIs(pending.native_uncertainties[0][0], owner)
        self.assertIs(pending.native_uncertainties[0][1], native_error)
        self.assertEqual(pending.diagnostic_errors, (diagnostic,))
        self.assertFalse(pending.observe_settled())
        owner.close.assert_not_called()

    def test_child_retains_previous_and_failed_observer_without_retry_close(self):
        from tests.windows import adaptive_win32 as native
        previous, owner = Mock(), Mock()
        error = native.RetainedProcessOpenError(owner, ValueError("validation"), OSError("close unknown"))
        held = [previous]
        with patch.object(native.ProcessHandle, "open", side_effect=error):
            with self.assertRaises(child_fixture.S2ObserverOpenPending) as raised:
                child_fixture._open_observer(native, held, 700, "100")
        pending = raised.exception
        self.assertEqual(pending.original_observers, (previous, owner))
        self.assertIs(child_fixture._OBSERVER_OPEN_CUSTODY[0], pending)
        self.assertIs(pending.native_uncertainties[0][0], owner)
        previous.close.assert_not_called()
        owner.close.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            custody = child_fixture._ConsoleCustody(Path(directory), native, held, [])
            custody.remember("primary", pending)
            self.assertFalse(custody.step())
            self.assertTrue(custody.quarantined)
        owner.close.assert_not_called()

    def test_workload_entry_cannot_exit_on_retained_observer_open_failure(self):
        from tests.windows import adaptive_win32 as native
        owner = Mock()
        pending = child_fixture.S2ObserverOpenPending((owner,),
            native.RetainedProcessOpenError(owner, ValueError("validation"), OSError("close")))
        with patch.object(child_fixture, "assert_source"), \
                patch.object(child_fixture, "workload", side_effect=pending), \
                patch.object(child_fixture, "_retain_observer_open_failure") as retain:
            with self.assertRaisesRegex(RuntimeError, "custody_returned_without_completion"):
                child_fixture.main(["--source-pin", "e30=", "workload", "--directory", "isolated", "--token", "test"])
        retain.assert_called_once_with(pending)
        owner.close.assert_not_called()

    def test_ancestry_retains_first_handle_before_its_first_identity_read(self):
        from tests.windows import adaptive_win32 as native
        held, owner = [], Mock()
        def fail():
            self.assertEqual(held, [owner])
            raise OSError("identity unavailable")
        owner.identity.side_effect = fail
        with patch.object(native.ProcessHandle, "open", return_value=owner), \
                patch.object(native, "current_identity") as ambient:
            with self.assertRaisesRegex(OSError, "identity unavailable"):
                child_fixture._owned_console_ancestry(native, held, {"pid": 700, "created_filetime_100ns": "100"})
        self.assertEqual(held, [owner])
        ambient.assert_not_called()

    def test_ancestry_bound_retains_twelve_and_does_not_open_thirteenth(self):
        from tests.windows import adaptive_win32 as native
        held, owners = [], []
        for index in range(12):
            owner = Mock(spec_set=["identity", "wait", "parent_pid", "close"])
            owner.identity.return_value = {"pid": 700 + index, "created_filetime_100ns": str(100 - index)}
            owner.wait.return_value = False
            owner.parent_pid.return_value = 701 + index
            owners.append(owner)
        with patch.object(native.ProcessHandle, "open", side_effect=owners) as opened, \
                patch.object(child_fixture.os, "getpid", return_value=999):
            with self.assertRaisesRegex(RuntimeError, "ancestry_not_owned"):
                child_fixture._owned_console_ancestry(native, held, {"pid": 700, "created_filetime_100ns": "100"})
        self.assertEqual(opened.call_count, 12)
        self.assertEqual(held, owners)
        owners[-1].parent_pid.assert_not_called()

    def test_bounded_ancestry_returns_only_retained_original_identities(self):
        from tests.windows import adaptive_win32 as native
        held = []
        first, parent = Mock(), Mock()
        first.identity.return_value = {"pid": 700, "created_filetime_100ns": "100"}
        first.wait.return_value = False
        first.parent_pid.return_value = 999
        parent.identity.return_value = {"pid": 999, "created_filetime_100ns": "90"}
        parent.wait.return_value = False
        with patch.object(native.ProcessHandle, "open", side_effect=[first, parent]), \
                patch.object(child_fixture.os, "getpid", return_value=999):
            result = child_fixture._owned_console_ancestry(native, held, first.identity.return_value)
        self.assertEqual(set(result), {700, 999})
        self.assertEqual(held, [first, parent])
        parent.parent_pid.assert_not_called()


if __name__ == "__main__":
    unittest.main()
