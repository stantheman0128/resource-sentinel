import tempfile
import unittest
from pathlib import Path

from sentinel.maintainer import Maintainer, Task, Worker


NOW = 2_000_000_000.0


def worker(
    worker_id,
    ram,
    *,
    local=False,
    state="AVAILABLE",
    automation="AUTOMATABLE",
    domain=None,
    capacity_scope="SHARED_POOL",
    capacity_pool=None,
    quota_domain=None,
    max_concurrency=8,
    os_name="linux",
    docker=False,
):
    return Worker(
        id=worker_id,
        provider=worker_id,
        failure_domain=domain or worker_id,
        capacity_scope=capacity_scope,
        capacity_pool=capacity_pool or "",
        max_concurrency=max_concurrency,
        quota_domain=quota_domain or "",
        state=state,
        automation_level=automation,
        os=os_name,
        capacity_ram_gib=ram,
        allocatable_ram_gib=ram,
        visible_cpu=8,
        allocatable_cpu=8,
        allocatable_disk_gib=100,
        capabilities={
            "local": local, "docker": docker, "hardware": local,
            "adapter_ready": True, "enabled": True,
        },
        trust_domain="local-private" if local else "cloud",
        observed_at=NOW,
        probe_expires_at=NOW + 3600,
    )


class MaintainerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.maintainer = Maintainer(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def add_defaults(self):
        self.maintainer.upsert_worker(
            worker("local", 48, local=True, os_name="windows", docker=True), now=NOW
        )
        self.maintainer.upsert_worker(worker("cursor", 12, docker=True), now=NOW)
        self.maintainer.upsert_worker(worker("github", 6, docker=True), now=NOW)

    def test_cloud_preferred_uses_best_fit_cloud(self):
        self.add_defaults()
        result = self.maintainer.route_and_reserve(Task("small", ram_gib=4), now=NOW)
        self.assertTrue(result["reserved"])
        self.assertEqual(result["worker_id"], "github")

    def test_large_memory_routes_to_local(self):
        self.add_defaults()
        result = self.maintainer.route_and_reserve(Task("large", ram_gib=24), now=NOW)
        self.assertTrue(result["reserved"])
        self.assertEqual(result["worker_id"], "local")

    def test_local_required_and_hardware_filter(self):
        self.add_defaults()
        result = self.maintainer.route_and_reserve(
            Task("windows", ram_gib=4, hardware=True, execution_preference="LOCAL_REQUIRED"),
            now=NOW,
        )
        self.assertEqual(result["worker_id"], "local")

    def test_shared_failure_domain_does_not_double_capacity(self):
        self.maintainer.upsert_worker(worker("grok-a", 12, domain="grok-computer"), now=NOW)
        self.maintainer.upsert_worker(worker("grok-b", 12, domain="grok-computer"), now=NOW)
        first = self.maintainer.route_and_reserve(Task("one", ram_gib=8), now=NOW)
        second = self.maintainer.route_and_reserve(Task("two", ram_gib=8), now=NOW + 1)
        self.assertTrue(first["reserved"])
        self.assertFalse(second["reserved"])
        self.assertEqual(second["rejected"]["grok-a"], "ram_capacity")
        self.assertEqual(second["rejected"]["grok-b"], "ram_capacity")

    def test_quota_and_stale_probe_are_excluded(self):
        self.maintainer.upsert_worker(worker("quota", 12, state="QUOTA_EXHAUSTED"), now=NOW)
        stale = worker("stale", 12)
        stale = Worker(**{**stale.__dict__, "probe_expires_at": NOW - 1})
        self.maintainer.upsert_worker(stale, now=NOW)
        result = self.maintainer.route_and_reserve(Task("job", ram_gib=2), now=NOW)
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["quota"], "state_quota_exhausted")
        self.assertEqual(result["rejected"]["stale"], "probe_stale")

    def test_quota_domain_limits_distinct_per_execution_workers(self):
        for worker_id in ("cloud-small", "cloud-large"):
            self.maintainer.upsert_worker(worker(
                worker_id, 16, capacity_scope="PER_EXECUTION",
                capacity_pool=f"{worker_id}-per-job", quota_domain="shared-account",
                max_concurrency=1,
            ), now=NOW)
        first = self.maintainer.route_and_reserve(Task(
            "one", ram_gib=2, allowed_worker_ids=("cloud-small",)
        ), now=NOW)
        second = self.maintainer.route_and_reserve(Task(
            "two", ram_gib=2, allowed_worker_ids=("cloud-large",)
        ), now=NOW + 1)
        self.assertTrue(first["reserved"])
        self.assertFalse(second["reserved"])
        self.assertEqual(second["rejected"]["cloud-large"], "quota_concurrency")
        self.assertEqual(
            self.maintainer.snapshot(now=NOW + 1)["usage_by_quota_domain"]["shared-account"]["jobs"], 1
        )

    def test_release_restores_memory_capacity(self):
        self.maintainer.upsert_worker(worker("cloud", 12), now=NOW)
        first = self.maintainer.route_and_reserve(Task("one", ram_gib=10), now=NOW)
        blocked = self.maintainer.route_and_reserve(Task("two", ram_gib=4), now=NOW + 1)
        self.assertFalse(blocked["reserved"])
        self.assertEqual(self.maintainer.release(task_id="one", now=NOW + 2), 1)
        admitted = self.maintainer.route_and_reserve(Task("two", ram_gib=4), now=NOW + 3)
        self.assertTrue(admitted["reserved"])

    def test_trust_domain_is_hard_requirement(self):
        self.maintainer.upsert_worker(worker("cloud", 12), now=NOW)
        result = self.maintainer.route_and_reserve(
            Task("secret", ram_gib=2, allowed_trust_domains=("local-private",)), now=NOW
        )
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["cloud"], "trust_domain")

    def test_observed_free_memory_preserves_headroom(self):
        constrained = worker("local", 48, local=True, os_name="windows")
        constrained = Worker(**{
            **constrained.__dict__,
            "capabilities": {
                **constrained.capabilities,
                "observed_free_ram_gib": 18,
                "memory_headroom_gib": 16,
            },
        })
        self.maintainer.upsert_worker(constrained, now=NOW)
        result = self.maintainer.route_and_reserve(
            Task("needs-four", ram_gib=4, execution_preference="LOCAL_REQUIRED"), now=NOW
        )
        self.assertFalse(result["reserved"])
        self.assertEqual(result["rejected"]["local"], "observed_ram_headroom")

    def test_per_execution_capacity_is_not_summed_across_fresh_vms(self):
        self.maintainer.upsert_worker(
            worker("runner", 8, capacity_scope="PER_EXECUTION", max_concurrency=2), now=NOW
        )
        first = self.maintainer.route_and_reserve(Task("one", ram_gib=6), now=NOW)
        second = self.maintainer.route_and_reserve(Task("two", ram_gib=6), now=NOW + 1)
        third = self.maintainer.route_and_reserve(Task("three", ram_gib=1), now=NOW + 2)
        self.assertTrue(first["reserved"])
        self.assertTrue(second["reserved"])
        self.assertFalse(third["reserved"])
        self.assertEqual(third["rejected"]["runner"], "concurrency_capacity")

    def test_same_task_id_cannot_change_reserved_spec(self):
        self.maintainer.upsert_worker(worker("cloud", 48), now=NOW)
        self.assertTrue(self.maintainer.route_and_reserve(Task("stable", ram_gib=4), now=NOW)["reserved"])
        changed = self.maintainer.route_and_reserve(Task("stable", ram_gib=40), now=NOW + 1)
        self.assertFalse(changed["reserved"])
        self.assertEqual(changed["reason"], "task_spec_mismatch")

    def test_observed_headroom_subtracts_existing_reservations(self):
        constrained = worker("local", 48, local=True, os_name="windows")
        constrained = Worker(**{
            **constrained.__dict__,
            "capabilities": {
                **constrained.capabilities,
                "observed_free_ram_gib": 30,
                "memory_headroom_gib": 16,
            },
        })
        self.maintainer.upsert_worker(constrained, now=NOW)
        self.assertTrue(self.maintainer.route_and_reserve(
            Task("first", ram_gib=8, execution_preference="LOCAL_REQUIRED"), now=NOW
        )["reserved"])
        second = self.maintainer.route_and_reserve(
            Task("second", ram_gib=8, execution_preference="LOCAL_REQUIRED"), now=NOW + 1
        )
        self.assertFalse(second["reserved"])
        self.assertEqual(second["rejected"]["local"], "observed_ram_headroom")


if __name__ == "__main__":
    unittest.main()
