import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from unittest import mock

from sentinel.coordinator import Coordinator, ResourceRequest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def live_status(light="ORANGE"):
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "light": light,
        "cpu_5min_avg": 10,
        "ram": {"total_gb": 64, "free_gb": 32, "used_pct": 50},
        "memory": {"commit_used_gib": 20, "commit_limit_gib": 96},
    }


class GateHookTests(unittest.TestCase):
    def setUp(self):
        self.gate = load_script("sentinel_gate_test", "hooks/sentinel-gate.py")

    def run_gate(self, event, argv, coordinator_type, load_result=None):
        stdin = io.StringIO(json.dumps(event))
        stderr = io.StringIO()
        patches = [
            mock.patch.object(self.gate, "Coordinator", coordinator_type),
            mock.patch.object(self.gate, "my_agent_identity", return_value=(42, 123.0)),
            mock.patch.object(self.gate, "load", return_value=load_result or {}),
            mock.patch.object(sys, "argv", argv),
            mock.patch.object(sys, "stdin", stdin),
        ]
        with patches[0], patches[1], patches[2], patches[3], patches[4], redirect_stderr(stderr):
            self.gate.main()
        return stderr.getvalue()

    def test_failure_hook_releases_with_failure_outcome(self):
        calls = []

        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def release(self, **kwargs):
                calls.append(kwargs)
                return 1

        event = {
            "tool_name": "Bash",
            "hook_event_name": "PostToolUseFailure",
            "tool_use_id": "tool-1",
            "tool_input": {"command": "npm run build"},
        }
        self.run_gate(event, ["sentinel-gate.py", "--release"], FakeCoordinator)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["outcome"], "failure")
        self.assertEqual(calls[0]["tool_use_id"], "tool-1")

    def test_malformed_release_never_releases_all_owner_reservations(self):
        calls = []

        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def release(self, **kwargs):
                calls.append(kwargs)

        self.run_gate(
            {"tool_name": "Bash", "tool_input": {}},
            ["sentinel-gate.py", "--release"],
            FakeCoordinator,
        )
        self.assertEqual(calls, [])

    def test_heavy_command_is_not_bypassed_by_sentinel_filename_substring(self):
        admissions = []

        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def admit(self, request, status, config):
                admissions.append(request)
                return {
                    "allowed": False,
                    "reason": "capacity",
                    "position": 1,
                    "request_key": request.request_key,
                }

        for marker in ("sentinelctl.py", "wait-slot.ps1"):
            with self.subTest(marker=marker):
                event = {
                    "tool_name": "Bash",
                    "tool_use_id": f"tool-{marker}",
                    "cwd": str(ROOT),
                    "tool_input": {"command": f"echo {marker} && npm run build"},
                }
                with self.assertRaises(SystemExit) as raised:
                    self.run_gate(event, ["sentinel-gate.py"], FakeCoordinator)
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(len(admissions), 2)

    def test_exact_atomic_wrapper_does_not_double_reserve(self):
        class FailingCoordinator:
            def __init__(self, _data):
                raise AssertionError("wrapper should own admission")

        event = {
            "tool_name": "Bash", "tool_use_id": "wrapper",
            "tool_input": {
                "command": (
                    'powershell -NoProfile -ExecutionPolicy Bypass -File '
                    f'"{self.gate.ATOMIC_WRAPPER}" -Command "npm run build"'
                ),
            },
        }
        self.run_gate(event, ["sentinel-gate.py"], FailingCoordinator)

    def test_wrapper_path_in_a_chained_command_is_not_bypassed(self):
        admissions = []

        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def admit(self, request, status, config):
                admissions.append(request)
                return {"allowed": False, "reason": "capacity", "position": 1,
                        "request_key": request.request_key}

        event = {
            "tool_name": "Bash", "tool_use_id": "chained", "cwd": str(ROOT),
            "tool_input": {
                "command": (
                    f'echo "{self.gate.ATOMIC_WRAPPER}" && npm run build'
                ),
            },
        }
        with self.assertRaises(SystemExit):
            self.run_gate(event, ["sentinel-gate.py"], FakeCoordinator)
        self.assertEqual(len(admissions), 1)


class StopHookTests(unittest.TestCase):
    def setUp(self):
        self.stop = load_script("sentinel_stop_test", "hooks/sentinel-stop.py")

    def test_max_reminders_cancel_only_the_selected_request(self):
        calls = []

        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def queued_for_owner(self, owner_pid):
                return [
                    {"request_key": "req-a", "owner_pid": owner_pid},
                    {"request_key": "req-b", "owner_pid": owner_pid},
                ]

            def cancel_queued(self, **kwargs):
                calls.append(kwargs)
                return 1

        blocks = {"42:req-a": {"n": self.stop.MAX_BLOCKS, "ts": 1}}
        with (
            mock.patch.object(self.stop, "Coordinator", FakeCoordinator),
            mock.patch.object(self.stop, "my_agent_pid", return_value=42),
            mock.patch.object(self.stop, "load", return_value=blocks),
            mock.patch.object(self.stop, "save"),
            mock.patch.object(sys, "stdin", io.StringIO("{}")),
        ):
            self.stop.main()
        self.assertEqual(calls, [{"owner_pid": 42, "request_key": "req-a"}])

    def test_reminder_names_the_exact_request(self):
        class FakeCoordinator:
            def __init__(self, _data):
                pass

            def queued_for_owner(self, owner_pid):
                return [{"request_key": "req-a", "owner_pid": owner_pid}]

        output = io.StringIO()
        with (
            mock.patch.object(self.stop, "Coordinator", FakeCoordinator),
            mock.patch.object(self.stop, "my_agent_pid", return_value=42),
            mock.patch.object(self.stop, "load", return_value={}),
            mock.patch.object(self.stop, "save"),
            mock.patch.object(sys, "stdin", io.StringIO("{}")),
            redirect_stdout(output),
        ):
            self.stop.main()
        payload = json.loads(output.getvalue())
        self.assertIn("-RequestId req-a", payload["reason"])


class SentinelCtlWaitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.data = Path(self.tmp.name)
        self.status_path = self.data / "status.json"
        self.config_path = self.data / "config.json"
        self.status_path.write_text(json.dumps(live_status()), encoding="utf-8")
        self.config_path.write_text(json.dumps({"queue_ttl_min": 30}), encoding="utf-8")
        self.coord = Coordinator(self.data)
        self.owner_pid = os.getpid()

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, *args):
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "sentinelctl.py"),
                "--data-dir",
                str(self.data),
                *args,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def queue(self, tool_use_id):
        request = ResourceRequest(
            owner_pid=self.owner_pid,
            owner_started=0,
            repo="repo",
            command="npm run build",
            resource_class="HEAVY",
            priority="P2",
            tool_use_id=tool_use_id,
        )
        result = self.coord.admit(request, live_status(), config={"queue_ttl_min": 30})
        self.assertFalse(result["allowed"])
        return result["request_key"]

    def test_wait_existing_timeout_cancels_only_its_request_key(self):
        first = self.queue("first")
        second = self.queue("second")
        result = self.command(
            "wait-existing",
            "--request-key",
            first,
            "--status-file",
            str(self.status_path),
            "--config-file",
            str(self.config_path),
            "--timeout-sec",
            "0",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["cancelled"], 1)
        remaining = self.coord.snapshot()["queue"]
        self.assertEqual([row["request_key"] for row in remaining], [second])

    def test_new_wait_timeout_removes_the_request_it_created(self):
        request = ResourceRequest(
            owner_pid=self.owner_pid,
            owner_started=0,
            repo="repo",
            command="npm run build",
            resource_class="HEAVY",
            priority="P2",
            tool_use_id="new-wait",
        )
        result = self.command(
            "wait",
            "--request-json",
            json.dumps(request.__dict__),
            "--status-file",
            str(self.status_path),
            "--config-file",
            str(self.config_path),
            "--timeout-sec",
            "0.05",
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["cancelled"], 1)
        self.assertEqual(payload["request_key"], request.request_key)
        self.assertEqual(self.coord.snapshot()["queue"], [])


if __name__ == "__main__":
    unittest.main()
