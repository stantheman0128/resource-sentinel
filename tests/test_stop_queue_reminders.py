"""Stop notifications share one bounded episode without abandoning work."""

import importlib.util
import io
import json
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from sentinel.coordinator import Coordinator, ResourceRequest


ROOT = Path(__file__).resolve().parents[1]


def load_stop_hook():
    spec = importlib.util.spec_from_file_location(
        "sentinel_stop_queue_test", ROOT / "hooks" / "sentinel-stop.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class StopQueueReminderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(self.temporary.cleanup)
        self.data = Path(self.temporary.name)
        self.owner_pid = 4242
        self.owner_started = 123.0
        self.coordinator = Coordinator(
            self.data, pid_identity=lambda _pid: (True, self.owner_started)
        )
        self.stop = load_stop_hook()

    def queue(self, operation):
        request = ResourceRequest(
            owner_pid=self.owner_pid,
            owner_started=self.owner_started,
            repo="test-only",
            command="npm run build --private-description-do-not-display",
            resource_class="HEAVY",
            tool_use_id=operation,
        )
        result = self.coordinator.admit(request, {})
        self.assertFalse(result["allowed"])
        return result["request_key"]

    def claim(self, **overrides):
        arguments = {
            "owner_pid": self.owner_pid,
            "owner_started": self.owner_started,
            "max_reminders": 3,
            "legacy_blocks": {},
        }
        arguments.update(overrides)
        return self.coordinator.claim_stop_reminder(**arguments)

    def run_stop(self, *, legacy=None, identity=None, payload=None):
        output = io.StringIO()
        with (
            mock.patch.object(self.stop, "Coordinator", return_value=self.coordinator),
            mock.patch.object(self.stop, "DATA", self.data),
            mock.patch.object(self.stop, "load", return_value=legacy or {}),
            mock.patch.object(
                self.stop, "my_agent_identity",
                return_value=identity or (self.owner_pid, self.owner_started),
            ),
            mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload or {}))),
            redirect_stdout(output),
        ):
            self.stop.main()
        return json.loads(output.getvalue()) if output.getvalue() else None

    def test_seven_requests_share_three_reminders_and_remain_queued(self):
        keys = {self.queue(f"operation-{index}") for index in range(7)}
        before = self.coordinator.snapshot()
        outputs = [self.run_stop() for _ in range(10)]
        reminders = [output for output in outputs if output]
        self.assertEqual(len(reminders), 3)
        for index, output in enumerate(reminders, start=1):
            self.assertEqual(output["decision"], "block")
            self.assertIn("7 筆排隊請求", output["reason"])
            self.assertIn(f"{index}/3", output["reason"])
            self.assertIn("不會自動取消任何請求", output["reason"])
            self.assertNotIn("private-description", output["reason"])
            self.assertLess(len(output["reason"]), 1600)
        self.assertEqual(self.coordinator.snapshot(), before)
        self.assertEqual(
            {row["request_key"] for row in self.coordinator.queued_for_owner(self.owner_pid)},
            keys,
        )

    def test_message_contains_exact_wait_and_cancel_with_owner(self):
        key = self.queue("operation")
        message = self.run_stop()["reason"]
        self.assertIn(f"wait-existing --request-key {key} --owner-pid {self.owner_pid}", message)
        self.assertIn(f"cancel --request-key {key} --owner-pid {self.owner_pid}", message)
        self.assertIn("--status-file", message)
        self.assertIn("--config-file", message)
        self.assertIn("--timeout-sec 480", message)

    def test_changing_selected_request_does_not_restart_episode(self):
        first = self.queue("first")
        second = self.queue("second")
        self.assertTrue(all(self.claim()["should_block"] for _ in range(3)))
        self.coordinator.cancel_queued(owner_pid=self.owner_pid, request_key=first)
        third = self.queue("third")
        reminder = self.claim()
        self.assertFalse(reminder["should_block"])
        self.assertEqual(reminder["queued_count"], 2)
        self.assertIn(reminder["request_key"], {second, third})

    def test_observed_empty_queue_starts_a_new_episode(self):
        first = self.queue("first")
        for _ in range(3):
            self.claim()
        self.coordinator.cancel_queued(owner_pid=self.owner_pid, request_key=first)
        self.assertFalse(self.claim()["should_block"])
        self.queue("new-episode")
        self.assertEqual(self.claim()["reminder_count"], 1)

    def test_queue_empty_between_hooks_also_starts_a_new_episode(self):
        first = self.queue("first")
        for _ in range(3):
            self.claim()
        self.coordinator.cancel_queued(owner_pid=self.owner_pid, request_key=first)
        self.queue("next-episode")
        self.assertEqual(self.claim()["reminder_count"], 1)

    def test_legacy_request_counts_migrate_without_extra_cycles(self):
        first = self.queue("first")
        second = self.queue("second")
        legacy = {
            f"{self.owner_pid}:{first}": {"n": 2, "ts": time.time()},
            f"{self.owner_pid}:{second}": {"n": 1, "ts": time.time()},
        }
        self.assertIsNone(self.run_stop(legacy=legacy))
        self.assertEqual(len(self.coordinator.queued_for_owner(self.owner_pid)), 2)
        self.assertIsNone(self.run_stop())

    def test_legacy_owner_counter_is_imported_only_once(self):
        self.queue("first")
        legacy = {str(self.owner_pid): {"n": 1, "ts": time.time()}}
        first = self.claim(legacy_blocks=legacy)
        second = self.claim(legacy_blocks=legacy)
        third = self.claim(legacy_blocks=legacy)
        self.assertEqual(first["reminder_count"], 2)
        self.assertEqual(second["reminder_count"], 3)
        self.assertFalse(third["should_block"])

    def test_legacy_owner_counter_does_not_reappear_in_next_episode(self):
        first = self.queue("first")
        legacy = {str(self.owner_pid): {"n": 2, "ts": time.time()}}
        self.assertEqual(self.claim(legacy_blocks=legacy)["reminder_count"], 3)
        self.coordinator.cancel_queued(owner_pid=self.owner_pid, request_key=first)
        self.queue("next-episode")
        self.assertEqual(self.claim(legacy_blocks=legacy)["reminder_count"], 1)

    def test_old_birth_and_unrelated_legacy_keys_do_not_suppress_current_owner(self):
        key = self.queue("current")
        legacy = {
            f"{self.owner_pid}:{key}": {"n": 3, "ts": self.owner_started - 1},
            f"{self.owner_pid}:not-in-current-queue": {"n": 3, "ts": time.time()},
            "other-owner": {"n": 3, "ts": time.time()},
        }
        self.assertEqual(self.claim(legacy_blocks=legacy)["reminder_count"], 1)

    def test_pid_reuse_does_not_select_old_birth_queue(self):
        self.queue("old-process")
        before = self.coordinator.snapshot()
        current = self.claim(owner_started=self.owner_started + 10)
        self.assertFalse(current["should_block"])
        self.assertEqual(current["queued_count"], 0)
        self.assertEqual(self.coordinator.snapshot(), before)

    def test_concurrent_claims_have_only_three_winners(self):
        self.queue("shared")
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(lambda _index: self.claim(), range(12)))
        self.assertEqual(sum(result["should_block"] for result in outcomes), 3)
        self.assertEqual(
            sorted(result["reminder_count"] for result in outcomes if result["should_block"]),
            [1, 2, 3],
        )
        self.assertEqual(len(self.coordinator.queued_for_owner(self.owner_pid)), 1)

    def test_hook_payload_cannot_select_owner_or_reset_counter(self):
        key = self.queue("owned")
        for index in range(4):
            result = self.run_stop(payload={
                "owner_pid": 9876,
                "pid": 9876,
                "owner_started": 999,
                "session_id": f"different-input-{index}",
            })
            if index < 3:
                self.assertIn(f"--request-key {key} --owner-pid {self.owner_pid}", result["reason"])
            else:
                self.assertIsNone(result)

    def test_unknown_identity_does_not_touch_queue_or_counters(self):
        with (
            mock.patch.object(self.stop, "my_agent_identity", return_value=None),
            mock.patch.object(self.stop, "Coordinator") as coordinator,
            mock.patch.object(sys, "stdin", io.StringIO("{}")),
        ):
            self.stop.main()
        coordinator.assert_not_called()

    def test_counter_failure_does_not_cancel_or_release_anything(self):
        fake = mock.Mock()
        fake.claim_stop_reminder.side_effect = OSError("test-only unavailable storage")
        with (
            mock.patch.object(self.stop, "Coordinator", return_value=fake),
            mock.patch.object(self.stop, "load", return_value={}),
            mock.patch.object(self.stop, "my_agent_identity", return_value=(self.owner_pid, self.owner_started)),
            mock.patch.object(sys, "stdin", io.StringIO("{}")),
        ):
            self.stop.main()
        self.assertEqual([call[0] for call in fake.mock_calls], ["claim_stop_reminder"])

    def test_request_hint_rejects_shell_syntax_and_oversized_keys(self):
        for key in ("$(invoke-danger)", "abc; do-something", "abc\nother", "a" * 129):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.stop.request_command("cancel", key, self.owner_pid)


if __name__ == "__main__":
    unittest.main()
