import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from sentinel.coordinator import Coordinator, ResourceRequest, classify_command, redact_command
from sentinel.maintainer import Maintainer, Task, Worker


NOW = 2_000_000_000.0


def status(cpu=10, used_ram=16, light="GREEN", commit_used=20, commit_limit=96):
    return {
        "generated_at": datetime.fromtimestamp(NOW).strftime("%Y-%m-%d %H:%M:%S"),
        "light": light,
        "cpu_5min_avg": cpu,
        "ram": {"total_gb": 64, "free_gb": 64 - used_ram, "used_pct": used_ram / 64 * 100},
        "memory": {"commit_used_gib": commit_used, "commit_limit_gib": commit_limit},
    }


class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.identities = {100: (True, 1000.0), 200: (True, 2000.0), 300: (True, 3000.0)}
        self.coord = Coordinator(
            Path(self.tmp.name),
            pid_identity=lambda pid: self.identities.get(pid, (False, 0.0)),
        )

    def tearDown(self):
        self.tmp.cleanup()

    def req(self, pid, started, command="npm install", priority="P2", cls="HEAVY"):
        return ResourceRequest(pid, started, "repo", command, cls, priority, f"tool-{pid}")

    def test_atomic_capacity_blocks_second_io_heavy_request(self):
        first = self.coord.admit(self.req(100, 1000), status(), now=NOW)
        second = self.coord.admit(self.req(200, 2000), status(), now=NOW + 1)
        self.assertTrue(first["allowed"])
        self.assertFalse(second["allowed"])
        self.assertIn(second["reason"], {"queue_order", "cpu_capacity", "io_capacity"})
        self.assertEqual(len(self.coord.snapshot()["reservations"]), 1)

    def test_commit_default_keeps_four_gib_at_boundary(self):
        result = self.coord.admit(
            self.req(100, 1000), status(cpu=0.1, commit_used=62, commit_limit=74), now=NOW
        )
        self.assertTrue(result["allowed"])

    def test_commit_default_denies_when_four_gib_would_be_consumed(self):
        result = self.coord.admit(
            self.req(100, 1000), status(cpu=0.1, commit_used=62.1, commit_limit=74), now=NOW
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "commit_capacity")

    def test_priority_queue_orders_p0_before_older_p3(self):
        blocker = self.coord.admit(self.req(100, 1000), status(), now=NOW)
        self.assertTrue(blocker["allowed"])
        low = self.coord.admit(self.req(200, 2000, "npm run build", "P3"), status(), now=NOW + 1)
        high = self.coord.admit(self.req(300, 3000, "cargo build", "P0"), status(), now=NOW + 2)
        self.assertFalse(low["allowed"])
        self.assertFalse(high["allowed"])
        self.coord.release(owner_pid=100, tool_use_id="tool-100", now=NOW + 3)
        high_retry = self.coord.admit(self.req(300, 3000, "cargo build", "P0"), status(), now=NOW + 4)
        self.assertTrue(high_retry["allowed"])

    def test_release_is_per_tool_not_whole_agent(self):
        cfg = {"heavy_io_slots": 2, "local_allocatable_cpu": 12, "local_allocatable_ram_gib": 60}
        one = ResourceRequest(100, 1000, "repo", "pytest a::one", "MEDIUM", "P2", "one", io_slots=0)
        two = ResourceRequest(100, 1000, "repo", "pytest b::two", "MEDIUM", "P2", "two", io_slots=0)
        self.assertTrue(self.coord.admit(one, status(), config=cfg, now=NOW)["allowed"])
        self.assertTrue(self.coord.admit(two, status(), config=cfg, now=NOW + 1)["allowed"])
        self.assertEqual(self.coord.release(owner_pid=100, tool_use_id="one", now=NOW + 2), 1)
        remaining = self.coord.snapshot()["reservations"]
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["tool_use_id"], "two")

    def test_identical_parallel_tools_do_not_share_reservation(self):
        cfg = {"heavy_io_slots": 2, "local_allocatable_cpu": 12, "local_allocatable_ram_gib": 60}
        one = ResourceRequest(100, 1000, "repo", "pytest same::test", "MEDIUM", "P2", "one", io_slots=0)
        two = ResourceRequest(100, 1000, "repo", "pytest same::test", "MEDIUM", "P2", "two", io_slots=0)
        self.assertTrue(self.coord.admit(one, status(), config=cfg, now=NOW)["allowed"])
        self.assertTrue(self.coord.admit(two, status(), config=cfg, now=NOW + 1)["allowed"])
        self.assertEqual(len(self.coord.snapshot()["reservations"]), 2)

    def test_dead_owner_cleanup_archives_reservation(self):
        self.assertTrue(self.coord.admit(self.req(100, 1000), status(), now=NOW)["allowed"])
        self.identities[100] = (False, 1000.0)
        removed = self.coord.cleanup(now=NOW + 1)
        self.assertEqual(len(removed), 1)
        self.assertEqual(self.coord.snapshot()["reservations"], [])

    def test_stale_status_fails_closed(self):
        old = status()
        old["generated_at"] = "2000-01-01 00:00:00"
        result = self.coord.admit(self.req(100, 1000), old, now=NOW)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "status_stale")

    def test_classifier(self):
        self.assertEqual(classify_command("git status"), "LIGHT")
        self.assertEqual(classify_command("pytest tests/a.py::test_x"), "MEDIUM")
        self.assertEqual(classify_command("pnpm install"), "HEAVY")
        self.assertEqual(classify_command("docker compose up --build"), "EXTREME")

    def test_negative_resources_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "negative"):
            self.coord.admit(
                ResourceRequest(100, 1000, "repo", "test", cpu_units=-1), status(), now=NOW
            )

    def test_same_request_key_cannot_change_resources(self):
        first = self.coord.admit(self.req(100, 1000), status(), now=NOW)
        self.assertTrue(first["allowed"])
        changed = ResourceRequest(
            100, 1000, "repo", "npm install", "HEAVY", "P2", "tool-100", ram_gib=40
        )
        result = self.coord.admit(changed, status(), now=NOW + 1)
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "request_spec_mismatch")

    def test_local_admission_sees_maintainer_reservations(self):
        maintainer = Maintainer(Path(self.tmp.name))
        maintainer.upsert_worker(Worker(
            id="local-windows", provider="local", failure_domain="host",
            capacity_pool="host", max_concurrency=8, state="AVAILABLE",
            automation_level="AUTOMATABLE", os="windows", capacity_ram_gib=8,
            allocatable_ram_gib=8, visible_cpu=8, allocatable_cpu=8,
            allocatable_disk_gib=20,
            capabilities={"local": True, "adapter_ready": True},
            trust_domain="local-private", observed_at=NOW, probe_expires_at=NOW + 3600,
        ), now=NOW)
        self.assertTrue(maintainer.route_and_reserve(Task(
            "routed", ram_gib=6, execution_preference="LOCAL_REQUIRED"
        ), now=NOW)["reserved"])
        request = ResourceRequest(100, 1000, "repo", "pytest one::test", "MEDIUM", ram_gib=4)
        result = self.coord.admit(
            request, status(used_ram=0), config={"local_allocatable_ram_gib": 8}, now=NOW + 1
        )
        self.assertFalse(result["allowed"])
        self.assertEqual(result["reason"], "ram_capacity")

    def test_maintainer_sees_local_admission_reservations(self):
        request = ResourceRequest(
            100, 1000, "repo", "pytest one::test", "MEDIUM", ram_gib=6, io_slots=0
        )
        self.assertTrue(self.coord.admit(
            request, status(used_ram=0),
            config={"local_allocatable_ram_gib": 8, "local_allocatable_cpu": 8}, now=NOW,
        )["allowed"])
        maintainer = Maintainer(Path(self.tmp.name))
        maintainer.upsert_worker(Worker(
            id="local-windows", provider="local", failure_domain="host",
            capacity_pool="host", max_concurrency=8, state="AVAILABLE",
            automation_level="AUTOMATABLE", os="windows", capacity_ram_gib=8,
            allocatable_ram_gib=8, visible_cpu=8, allocatable_cpu=8,
            allocatable_disk_gib=20,
            capabilities={"local": True, "adapter_ready": True},
            trust_domain="local-private", observed_at=NOW, probe_expires_at=NOW + 3600,
        ), now=NOW)
        routed = maintainer.route_and_reserve(Task(
            "routed-after-direct", ram_gib=4, execution_preference="LOCAL_REQUIRED"
        ), now=NOW + 1)
        self.assertFalse(routed["reserved"])
        self.assertEqual(routed["rejected"]["local-windows"], "ram_capacity")

    def test_persisted_command_redacts_common_secret_forms(self):
        secret = "sk-abcdefghijklmnopqrstuvwxyz"
        request = ResourceRequest(
            100, 1000, "repo", f"npm install TOKEN={secret}", "HEAVY", tool_use_id="secret-tool"
        )
        self.coord.admit(request, status(), now=NOW)
        persisted = self.coord.snapshot()["reservations"][0]["command_text"]
        self.assertNotIn(secret, persisted)
        self.assertIn("<redacted>", persisted)
        self.assertNotIn(secret, redact_command(f"Authorization: Bearer {secret}"))


if __name__ == "__main__":
    unittest.main()
