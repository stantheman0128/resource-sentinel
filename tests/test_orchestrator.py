import json
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from sentinel.adapters import LocalCommandAdapter, ManualAdapter
from sentinel.maintainer import Maintainer, Worker
from sentinel.orchestrator import Orchestrator, TaskSpec
from sentinel.workspace import WorkspaceClaims


NOW = 2_000_000_000.0
BASE_SHA = "a" * 40


class FakeAdapter:
    """Small, controllable adapter used to exercise durable reconciliation."""

    def __init__(self, jobs=None):
        self.jobs = jobs if jobs is not None else {}
        self.cancelled = []

    def capabilities(self):
        return {"adapter": "fake", "automation_level": "AUTOMATABLE"}

    def probe(self):
        return {"available": True, "status": "AVAILABLE"}

    def submit(self, payload, worker=None):
        del worker
        external_id = f"external-{payload['task_id']}"
        self.jobs[external_id] = {
            "job_id": external_id,
            "status": "RUNNING",
            "result": {"task_id": payload["task_id"], "ok": True},
        }
        return {"job_id": external_id, "status": "RUNNING"}

    def status(self, job_id):
        return dict(self.jobs[job_id])

    def cancel(self, job_id):
        self.cancelled.append(job_id)
        self.jobs[job_id]["status"] = "CANCELLED"
        return dict(self.jobs[job_id])

    def collect_result(self, job_id, **kwargs):
        del kwargs
        job = self.jobs[job_id]
        return {"status": job["status"], **job["result"]}


class CountingBlockingAdapter(FakeAdapter):
    """Hold the submit boundary open so concurrent dispatch calls overlap."""

    def __init__(self):
        super().__init__()
        self.submit_calls = 0
        self.submit_entered = threading.Event()
        self.release_submit = threading.Event()
        self._lock = threading.Lock()

    def submit(self, payload, worker=None):
        with self._lock:
            self.submit_calls += 1
        self.submit_entered.set()
        if not self.release_submit.wait(timeout=3):
            raise TimeoutError("test did not release adapter submission")
        return super().submit(payload, worker)


class FlakyCollectAdapter(FakeAdapter):
    """Report provider success while making the first result read transiently fail."""

    def __init__(self):
        super().__init__()
        self.collect_calls = 0

    def collect_result(self, job_id, **kwargs):
        self.collect_calls += 1
        if self.collect_calls == 1:
            raise ConnectionError("provider result is not readable yet")
        return super().collect_result(job_id, **kwargs)


class CrashDuringSubmitAdapter(FakeAdapter):
    """Simulate process death after SUBMITTING is durable but before submit returns."""

    def submit(self, payload, worker=None):
        del payload, worker
        raise SystemExit("simulated scheduler process death")


def make_worker(
    worker_id,
    *,
    adapter="fake",
    local=False,
    automation="AUTOMATABLE",
):
    return Worker(
        id=worker_id,
        provider="local" if local else "test-provider",
        failure_domain=worker_id,
        state="AVAILABLE",
        automation_level=automation,
        os="windows" if local else "linux",
        capacity_ram_gib=8,
        allocatable_ram_gib=8,
        visible_cpu=4,
        allocatable_cpu=4,
        allocatable_disk_gib=20,
        capabilities={
            "adapter": adapter,
            "adapter_ready": True,
            "local": local,
            "hardware": local,
        },
        trust_domain="local-private" if local else "cloud-test",
        observed_at=NOW,
        probe_expires_at=NOW + 3600,
    )


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.tmp.name)
        self.data_dir = self.root / "state"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.maintainer = Maintainer(self.data_dir)
        self.claims = WorkspaceClaims(self.data_dir)

    def tearDown(self):
        self.tmp.cleanup()

    def orchestrator(self, adapters):
        return Orchestrator(
            self.data_dir,
            adapters=adapters,
            maintainer=self.maintainer,
            claims=self.claims,
            clock=lambda: NOW,
        )

    def add_worker(self, worker):
        self.maintainer.upsert_worker(worker, now=NOW)

    def scoped_spec(self, task_id, **overrides):
        values = {
            "id": task_id,
            "prompt": f"perform {task_id}",
            "repo": str(self.repo),
            "base_sha": BASE_SHA,
            "path_scopes": (f"src/{task_id}",),
            "allowed_worker_ids": ("fake-worker",),
            "max_attempts": 1,
        }
        values.update(overrides)
        return TaskSpec(**values)

    def test_submit_is_idempotent_only_for_the_same_normalized_spec(self):
        orch = self.orchestrator({})
        spec = TaskSpec(id="same-id", prompt="first prompt")

        created = orch.submit_task(spec, now=NOW)
        repeated = orch.submit_task(spec, now=NOW + 1)

        self.assertEqual(repeated["id"], created["id"])
        self.assertEqual(len(orch.list_tasks()), 1)
        with self.assertRaisesRegex(ValueError, "(?i)(different|conflict|mismatch)"):
            orch.submit_task(TaskSpec(id="same-id", prompt="changed prompt"), now=NOW + 2)

    def test_dispatch_preserves_explicit_commit_and_io_estimates_in_reservation(self):
        self.add_worker(make_worker("fake-worker"))
        orch = self.orchestrator({"fake": FakeAdapter()})
        requested_commit = 3 * (1 << 30) + 17
        orch.submit_task(TaskSpec(id="explicit-worker-estimates", prompt="fixture workload",
            allowed_worker_ids=("fake-worker",),
            requirements={"ram_gib": 1, "commit_bytes": requested_commit, "io_slots": 0}), now=NOW)
        dispatched = orch.dispatch_one("explicit-worker-estimates", now=NOW)
        self.assertTrue(dispatched["dispatched"], dispatched)
        reservations = self.maintainer.snapshot(now=NOW)["reservations"]
        self.assertEqual(len(reservations), 1)
        self.assertEqual(reservations[0]["commit_bytes"], requested_commit)
        self.assertEqual(reservations[0]["io_slots"], 0)
        self.assertEqual(reservations[0]["physical_bytes"], 1 << 30)

    def test_session_pull_preserves_explicit_commit_and_io_estimates_in_reservation(self):
        self.add_worker(make_worker("local-estimates", local=True))
        orch = self.orchestrator({})
        orch.register_session("estimates-session", agent_kind="codex", owner_pid=123,
            owner_started=1, bound_worker_id="local-estimates", now=NOW)
        requested_commit = 5 * (1 << 30) + 19
        orch.submit_task(TaskSpec(id="explicit-session-estimates", prompt="fixture workload",
            dispatch_mode="SESSION", allowed_worker_ids=("local-estimates",),
            requirements={"ram_gib": 2, "commit_bytes": requested_commit, "io_slots": 2}), now=NOW)
        assigned = orch.session_pull("estimates-session", now=NOW + 1)
        self.assertTrue(assigned["assigned"], assigned)
        reservations = self.maintainer.snapshot(now=NOW + 1)["reservations"]
        self.assertEqual(len(reservations), 1)
        self.assertEqual(reservations[0]["commit_bytes"], requested_commit)
        self.assertEqual(reservations[0]["io_slots"], 2)
        self.assertEqual(reservations[0]["physical_bytes"], 2 * (1 << 30))

    def test_explicit_zero_estimates_do_not_become_truthy_defaults(self):
        self.add_worker(make_worker("fake-worker"))
        orch = self.orchestrator({"fake": FakeAdapter()})
        orch.submit_task(TaskSpec(id="zero-estimates", prompt="fixture with explicit zero estimates",
            allowed_worker_ids=("fake-worker",), requirements={
                "ram_gib": 0, "cpu_units": 0, "disk_gib": 0, "commit_bytes": 0, "io_slots": 0,
            }), now=NOW)
        dispatched = orch.dispatch_one("zero-estimates", now=NOW)
        self.assertTrue(dispatched["dispatched"], dispatched)
        reservation = self.maintainer.snapshot(now=NOW)["reservations"][0]
        for field in ("ram_gib", "cpu_units", "disk_gib", "physical_bytes", "commit_bytes", "io_slots"):
            self.assertEqual(reservation[field], 0, field)

    def test_missing_commit_and_io_estimates_keep_legacy_defaults(self):
        self.add_worker(make_worker("fake-worker"))
        orch = self.orchestrator({"fake": FakeAdapter()})
        orch.submit_task(TaskSpec(id="legacy-estimates", prompt="fixture workload",
            allowed_worker_ids=("fake-worker",), requirements={"ram_gib": 2}), now=NOW)
        dispatched = orch.dispatch_one("legacy-estimates", now=NOW)
        self.assertTrue(dispatched["dispatched"], dispatched)
        reservation = self.maintainer.snapshot(now=NOW)["reservations"][0]
        self.assertEqual(reservation["commit_bytes"], 2 * (1 << 30))
        self.assertEqual(reservation["io_slots"], 1)

    def test_malformed_explicit_estimates_are_rejected_before_task_persistence(self):
        orch = self.orchestrator({})
        for name in ("commit_bytes", "io_slots"):
            for value in (-1, 1.5, "2", True, False, None, float("nan"), float("inf"), 1 << 63):
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(ValueError, f"requirements.{name}"):
                        orch.submit_task(TaskSpec(id="invalid-estimates", prompt="fixture workload",
                            requirements={name: value}), now=NOW)
        self.assertEqual(orch.list_tasks(), [])
        self.assertEqual(self.maintainer.snapshot(now=NOW)["reservations"], [])

    def test_nonfinite_memory_cpu_disk_estimates_are_rejected_before_persistence(self):
        orch = self.orchestrator({})
        for name in ("ram_gib", "cpu_units", "disk_gib"):
            for value in (float("nan"), float("inf"), float("-inf")):
                with self.subTest(name=name, value=value):
                    with self.assertRaisesRegex(ValueError, f"requirements.{name}"):
                        orch.submit_task(TaskSpec(id="nonfinite-estimates", prompt="fixture workload",
                            requirements={name: value}), now=NOW)
        self.assertEqual(orch.list_tasks(), [])

    def test_persisted_malformed_estimates_block_both_entry_points_without_reserving(self):
        self.add_worker(make_worker("local-invalid", local=True))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter})
        orch.register_session("invalid-estimates-session", agent_kind="codex", owner_pid=123,
            owner_started=1, bound_worker_id="local-invalid", now=NOW)
        malformed = ({"commit_bytes": "1000"}, {"io_slots": None},
                     {"io_slots": True}, {"commit_bytes": -1},
                     {"cpu_units": float("nan")}, {"ram_gib": None}, [])
        for mode in ("WORKER", "SESSION"):
            for index, requirements in enumerate(malformed):
                with self.subTest(mode=mode, requirements=requirements):
                    task_id = f"invalid-persisted-{mode.lower()}-{index}"
                    orch.submit_task(TaskSpec(id=task_id, prompt="fixture workload", dispatch_mode=mode,
                        allowed_worker_ids=("local-invalid",)), now=NOW)
                    with orch._db() as conn:
                        conn.execute("UPDATE orchestrator_tasks SET requirements_json=? WHERE id=?",
                            (json.dumps(requirements), task_id))
                    if mode == "WORKER":
                        result = orch.dispatch_one(task_id, now=NOW)
                        self.assertEqual(result["reason"], "invalid_requirements")
                    else:
                        self.assertFalse(orch.session_pull("invalid-estimates-session", now=NOW)["assigned"])
                    task = orch.get_task(task_id)
                    self.assertEqual(task["state"], "BLOCKED")
                    self.assertEqual(task["last_error"], "invalid_requirements")
                    self.assertEqual(task["attempts"], 0)
                    self.assertEqual(self.maintainer.snapshot(now=NOW)["reservations"], [])
                    self.assertEqual(adapter.jobs, {})

    def test_concurrent_dispatch_one_submits_the_same_task_exactly_once(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = CountingBlockingAdapter()
        first = self.orchestrator({"fake": adapter})
        second = self.orchestrator({"fake": adapter})
        spec = TaskSpec(
            id="parallel-dispatch",
            prompt="dispatch once despite concurrent scheduler ticks",
            allowed_worker_ids=("fake-worker",),
        )
        first.submit_task(spec, now=NOW)
        start = threading.Barrier(3)
        results = []
        errors = []

        def dispatch(orch):
            try:
                start.wait(timeout=3)
                results.append(orch.dispatch_one(spec.id, now=NOW + 1))
            except BaseException as exc:  # Surface thread failures in the test process.
                errors.append(exc)

        threads = [
            threading.Thread(target=dispatch, args=(first,)),
            threading.Thread(target=dispatch, args=(second,)),
        ]
        for thread in threads:
            thread.start()
        start.wait(timeout=3)
        submit_entered = adapter.submit_entered.wait(timeout=3)
        adapter.release_submit.set()
        for thread in threads:
            thread.join(timeout=3)

        self.assertTrue(submit_entered, "one dispatcher should reach the adapter")
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(adapter.submit_calls, 1)
        self.assertEqual(len(results), 2)
        self.assertEqual(sum(bool(item.get("dispatched")) for item in results), 1)
        self.assertEqual(len(first.snapshot()["jobs"]), 1)

    def test_local_argv_runs_end_to_end_and_collects_output(self):
        self.add_worker(make_worker("local-worker", adapter="local", local=True))
        orch = self.orchestrator({"local": LocalCommandAdapter()})
        spec = TaskSpec(
            id="local-argv",
            prompt="run a safe argv command",
            execution_preference="LOCAL_REQUIRED",
            allowed_worker_ids=("local-worker",),
            metadata={
                "argv": [sys.executable, "-c", "print('sentinel-local-ok')"],
                "timeout_seconds": 5,
            },
        )
        orch.submit_task(spec, now=NOW)

        dispatched = orch.dispatch_one(spec.id, now=NOW)
        self.assertTrue(dispatched["dispatched"], dispatched)

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            orch.reconcile(now=NOW + 1)
            task = orch.get_task(spec.id)
            if task["state"] in {"DONE", "FAILED"}:
                break
            time.sleep(0.02)

        task = orch.get_task(spec.id)
        self.assertEqual(task["state"], "DONE", task)
        self.assertIn("sentinel-local-ok", task["result"]["stdout"])
        self.assertEqual(self.maintainer.snapshot(now=NOW + 1)["reservations"], [])

    def test_canonical_only_local_worker_dispatches_through_local_adapter(self):
        worker = make_worker("canonical-local", adapter="", local=True)
        caps = {key: value for key, value in worker.capabilities.items() if key != "local"}
        caps["canonical_host_id"] = self.maintainer.local_host_id
        self.add_worker(replace(worker, capabilities=caps))
        adapter = FakeAdapter()
        orch = self.orchestrator({"local": adapter})
        spec = TaskSpec(id="canonical-dispatch", prompt="isolated adapter fixture",
                        execution_preference="LOCAL_REQUIRED", allowed_worker_ids=(worker.id,))
        orch.submit_task(spec, now=NOW)
        result = orch.dispatch_one(spec.id, now=NOW)
        self.assertTrue(result["dispatched"], result)
        self.assertIn(f"external-{spec.id}", adapter.jobs)

    def test_canonical_local_workspace_uses_same_host_context_as_routing(self):
        orch = self.orchestrator({})
        worker = {"id": "canonical-local", "provider": "local",
                  "capabilities": {"canonical_host_id": self.maintainer.local_host_id}}
        workspace = orch._prepare_workspace(
            {"metadata": {"workspace_mode": "claim-only"}}, worker, {"branch": "fixture"})
        self.assertEqual(workspace["mode"], "claim-only")
        self.assertTrue(workspace["ready"])
        self.assertEqual(orch._adapter_name(worker), "local")

    def test_unknown_scope_cannot_choose_an_adapter_or_skip_workspace_checks(self):
        orch = self.orchestrator({})
        for caps in ({"adapter": "fake"},
                     {"local": False, "canonical_host_id": self.maintainer.local_host_id, "adapter": "fake"}):
            worker = {"id": "unknown", "provider": "github", "capabilities": caps}
            with self.subTest(caps=caps):
                with self.assertRaisesRegex(ValueError, "local_scope_unknown"):
                    orch._adapter_name(worker)
                with self.assertRaisesRegex(ValueError, "local_scope_unknown"):
                    orch._prepare_workspace({"metadata": {}}, worker, {})

    def test_remote_host_config_does_not_make_remote_workspace_local(self):
        orch = self.orchestrator({})
        worker = {"id": "remote", "provider": "github", "capabilities": {
            "local": False, "canonical_host_id": "other-host",
            "admission_config": {"local_host_id": "other-host"}}}
        self.assertEqual(orch._adapter_name(worker), "github_actions")
        workspace = orch._prepare_workspace({"metadata": {}}, worker, {"branch": "fixture"})
        self.assertEqual(workspace["mode"], "provider-managed")
        self.assertFalse(workspace["ready"])

    def test_manual_adapter_waits_without_holding_capacity_or_workspace(self):
        # The adapter is callable, so routing may reserve it; the adapter's
        # truthful AWAITING_MANUAL response must then release that reservation.
        self.add_worker(make_worker("manual-worker", adapter="manual"))
        orch = self.orchestrator({"manual": ManualAdapter("manual-test")})
        spec = self.scoped_spec(
            "manual-task",
            path_scopes=("src/manual",),
            allowed_worker_ids=("manual-worker",),
        )
        orch.submit_task(spec, now=NOW)

        dispatched = orch.dispatch_one(spec.id, now=NOW)

        self.assertTrue(dispatched.get("manual"), dispatched)
        self.assertEqual(orch.get_task(spec.id)["state"], "AWAITING_MANUAL")
        self.assertEqual(self.maintainer.snapshot(now=NOW)["reservations"], [])
        claim_snapshot = self.claims.snapshot(now=NOW)
        self.assertEqual(claim_snapshot["active"], [])
        claim = next(item for item in claim_snapshot["claims"] if item["task_id"] == spec.id)
        self.assertNotIn(claim["state"], {"CLAIMED", "RUNNING", "VERIFYING"})

    def test_workspace_conflict_requeues_without_leaking_reservation(self):
        self.add_worker(make_worker("fake-worker"))
        holder = self.claims.claim(
            task_id="existing-owner",
            repo=self.repo,
            base_sha=BASE_SHA,
            paths=("src/shared",),
            owner="other-session",
            worker_id="other-worker",
            now=NOW,
        )
        self.assertTrue(holder["allowed"])
        orch = self.orchestrator({"fake": FakeAdapter()})
        spec = self.scoped_spec("contender", path_scopes=("src/shared/nested",))
        orch.submit_task(spec, now=NOW)

        result = orch.dispatch_one(spec.id, now=NOW)

        self.assertFalse(result["dispatched"])
        self.assertEqual(result["reason"], "claim_conflict")
        self.assertEqual(orch.get_task(spec.id)["state"], "QUEUED")
        reservations = self.maintainer.snapshot(now=NOW)["reservations"]
        self.assertFalse(any(item["task_id"] == spec.id for item in reservations))
        queued = self.claims.snapshot(now=NOW)["queued"]
        self.assertTrue(any(item["task_id"] == spec.id for item in queued))

    def test_stale_routing_without_a_job_recovers_and_releases_all_leases(self):
        self.add_worker(make_worker("fake-worker"))
        orch = self.orchestrator({"fake": FakeAdapter()})
        spec = self.scoped_spec("stale-routing", max_attempts=2)
        orch.submit_task(spec, now=NOW)
        task = orch.get_task(spec.id)

        self.assertTrue(orch._acquire_dispatch_lease(spec.id, now=NOW))
        placement = self.maintainer.route_and_reserve(orch._placement(task), now=NOW)
        claimed, _, _ = orch._claim(task, placement["worker_id"], NOW)
        self.assertTrue(placement["reserved"])
        self.assertTrue(claimed)
        self.assertEqual(len(self.maintainer.snapshot(now=NOW)["reservations"]), 1)
        self.assertEqual(len(self.claims.snapshot(now=NOW)["active"]), 1)
        self.assertEqual(orch.snapshot()["jobs"], [])

        recovered = orch.reconcile_stale_routing(now=NOW + 121, stale_after_sec=120)

        self.assertEqual(recovered, [{"task_id": spec.id, "status": "RETRYABLE"}])
        task = orch.get_task(spec.id)
        self.assertEqual(task["state"], "RETRYABLE")
        self.assertEqual(task["last_error"], "stale_routing_lease")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 121)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 121)["active"], [])

    def test_reconcile_success_releases_resources_and_claim(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter})
        spec = self.scoped_spec("success")
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)
        adapter.jobs[dispatched["external_job_id"]]["status"] = "SUCCEEDED"

        updates = orch.reconcile(now=NOW + 1)

        self.assertEqual(updates[0]["status"], "SUCCEEDED")
        task = orch.get_task(spec.id)
        self.assertEqual(task["state"], "DONE")
        self.assertTrue(task["result"]["ok"])
        self.assertEqual(self.maintainer.snapshot(now=NOW + 1)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 1)["active"], [])

    def test_collect_result_error_stays_running_then_later_reconcile_completes(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = FlakyCollectAdapter()
        orch = self.orchestrator({"fake": adapter})
        spec = self.scoped_spec("flaky-result")
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)
        adapter.jobs[dispatched["external_job_id"]]["status"] = "SUCCEEDED"

        first_updates = orch.reconcile(now=NOW + 1)

        self.assertEqual(first_updates[0]["status"], "COLLECT_ERROR")
        self.assertEqual(orch.get_task(spec.id)["state"], "RUNNING")
        job = next(item for item in orch.snapshot()["jobs"] if item["task_id"] == spec.id)
        self.assertIn("result_collection_pending", job["error_text"])
        self.assertEqual(len(self.maintainer.snapshot(now=NOW + 1)["reservations"]), 1)
        self.assertEqual(len(self.claims.snapshot(now=NOW + 1)["active"]), 1)

        second_updates = orch.reconcile(now=NOW + 2)

        self.assertEqual(second_updates[0]["status"], "SUCCEEDED")
        self.assertEqual(adapter.collect_calls, 2)
        self.assertEqual(orch.get_task(spec.id)["state"], "DONE")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 2)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 2)["active"], [])

    def test_successful_metrics_build_a_percentile_resource_profile(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter})
        spec = self.scoped_spec(
            "profiled", command="python -m unittest 12345678",
            metadata={"execution_signature": "unit-tests"},
        )
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)
        adapter.jobs[dispatched["external_job_id"]].update(
            status="SUCCEEDED",
            result={
                "metrics_available": True,
                "duration_seconds": 12.5,
                "peak_working_set_gib": 3.25,
                "cpu_seconds": 7.0,
                "disk_write_bytes": 4096,
            },
        )
        orch.reconcile(now=NOW + 1)

        profiles = orch.resource_profiles()["profiles"]

        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0]["samples"], 1)
        self.assertEqual(profiles[0]["metrics"]["peak_working_set_gib"]["p95"], 3.25)
        self.assertRegex(profiles[0]["execution_signature"], r"^[a-f0-9]{20}$")

    def test_cloud_phase_string_verification_runs_locally_before_parent_done(self):
        self.add_worker(make_worker("fake-worker"))
        self.add_worker(make_worker("local-worker", adapter="local", local=True))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter, "local": LocalCommandAdapter()})
        verify_command = f'"{sys.executable}" -c "print(\'verification-ok\')"'
        spec = TaskSpec(
            id="cloud-then-local", prompt="cloud phase",
            allowed_worker_ids=("fake-worker",), max_attempts=1,
            verification={"command": verify_command, "timeout_seconds": 5},
        )
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)
        adapter.jobs[dispatched["external_job_id"]]["status"] = "SUCCEEDED"
        orch.reconcile(now=NOW + 1)
        self.assertEqual(orch.get_task(spec.id)["state"], "VERIFYING")

        ticked = orch.tick(limit=1, now=NOW + 2)
        self.assertEqual(ticked["dispatched"][0]["task_id"], f"{spec.id}:verify")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and orch.get_task(spec.id)["state"] == "VERIFYING":
            orch.reconcile(now=NOW + 3)
            time.sleep(0.02)

        parent = orch.get_task(spec.id)
        self.assertEqual(parent["state"], "DONE", parent)
        self.assertIn("verification-ok", parent["result"]["verification_result"]["stdout"])

    def test_reconcile_failure_honors_attempt_limit_and_releases_resources(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter})
        spec = self.scoped_spec("failure", max_attempts=1)
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)
        adapter.jobs[dispatched["external_job_id"]].update(
            status="FAILED", message="provider failed"
        )

        updates = orch.reconcile(now=NOW + 1)

        self.assertEqual(updates[0]["status"], "FAILED")
        task = orch.get_task(spec.id)
        self.assertEqual(task["state"], "FAILED")
        self.assertIn("provider failed", task["last_error"])
        self.assertEqual(self.maintainer.snapshot(now=NOW + 1)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 1)["active"], [])

    def test_cancel_calls_adapter_and_releases_resources_and_claim(self):
        self.add_worker(make_worker("fake-worker"))
        adapter = FakeAdapter()
        orch = self.orchestrator({"fake": adapter})
        spec = self.scoped_spec("cancel")
        orch.submit_task(spec, now=NOW)
        dispatched = orch.dispatch_one(spec.id, now=NOW)

        result = orch.cancel(spec.id, now=NOW + 1)

        self.assertTrue(result["cancelled"])
        self.assertEqual(adapter.cancelled, [dispatched["external_job_id"]])
        self.assertEqual(orch.get_task(spec.id)["state"], "CANCELLED")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 1)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 1)["active"], [])

    def test_restart_reads_persisted_task_and_job_and_can_resume_reconcile(self):
        self.add_worker(make_worker("fake-worker"))
        shared_jobs = {}
        first_adapter = FakeAdapter(shared_jobs)
        first = self.orchestrator({"fake": first_adapter})
        spec = self.scoped_spec("restart")
        first.submit_task(spec, now=NOW)
        dispatched = first.dispatch_one(spec.id, now=NOW)
        shared_jobs[dispatched["external_job_id"]]["status"] = "SUCCEEDED"

        restarted = Orchestrator(
            self.data_dir,
            adapters={"fake": FakeAdapter(shared_jobs)},
            maintainer=Maintainer(self.data_dir),
            claims=WorkspaceClaims(self.data_dir),
            clock=lambda: NOW + 1,
        )
        persisted = restarted.get_task(spec.id)
        snapshot = restarted.snapshot()

        self.assertEqual(persisted["state"], "RUNNING")
        self.assertEqual(persisted["active_job_id"], dispatched["job_id"])
        self.assertTrue(any(job["id"] == dispatched["job_id"] for job in snapshot["jobs"]))
        restarted.reconcile(now=NOW + 1)
        self.assertEqual(restarted.get_task(spec.id)["state"], "DONE")

    def test_session_pull_assigns_matching_agent_and_records_completion(self):
        self.add_worker(make_worker("local-windows", local=True))
        orch = self.orchestrator({})
        orch.register_session(
            "codex-1", agent_kind="codex", owner_pid=123, owner_started=1,
            repo=str(self.repo), bound_worker_id="local-windows", now=NOW,
        )
        spec = TaskSpec(
            id="session-task", prompt="edit the requested scope", repo=str(self.repo),
            base_sha=BASE_SHA, path_scopes=("src/session",), dispatch_mode="SESSION",
            allowed_agent_kinds=("codex",), max_attempts=1,
            metadata={"workspace_mode": "claim-only"},
        )
        orch.submit_task(spec, now=NOW)

        assignment = orch.session_pull("codex-1", now=NOW + 1)
        self.assertTrue(assignment["assigned"], assignment)
        self.assertEqual(assignment["task"]["state"], "ASSIGNED")
        self.assertEqual(assignment["task"]["selected_session_id"], "codex-1")
        self.assertEqual(len(self.maintainer.snapshot(now=NOW + 1)["reservations"]), 1)

        completed = orch.session_complete(
            "codex-1", spec.id, success=True, result={"changed": ["src/session"]}, now=NOW + 2
        )
        self.assertTrue(completed["completed"])
        self.assertEqual(orch.get_task(spec.id)["state"], "DONE")
        self.assertEqual(orch.sessions(session_id="codex-1", now=NOW + 2)[0]["state"], "IDLE")
        self.assertEqual(self.claims.snapshot(now=NOW + 2)["active"], [])
        self.assertEqual(self.maintainer.snapshot(now=NOW + 2)["reservations"], [])

    def test_session_agent_kind_filter_and_close_requeues_assignment(self):
        self.add_worker(make_worker("local-windows", local=True))
        orch = self.orchestrator({})
        orch.register_session(
            "claude-1", agent_kind="claude", owner_pid=456, owner_started=2,
            repo=str(self.repo), now=NOW,
        )
        orch.submit_task(TaskSpec(
            id="codex-only", prompt="codex task", dispatch_mode="SESSION",
            allowed_agent_kinds=("codex",),
        ), now=NOW)
        self.assertEqual(orch.session_pull("claude-1", now=NOW + 1)["reason"], "no_matching_task")

        orch.submit_task(TaskSpec(
            id="claude-task", prompt="claude task", dispatch_mode="SESSION",
            allowed_agent_kinds=("claude",), max_attempts=2,
        ), now=NOW)
        assignment = orch.session_pull("claude-1", now=NOW + 1)
        self.assertTrue(assignment["assigned"], assignment)
        closed = orch.close_session("claude-1", now=NOW + 2)
        self.assertTrue(closed["closed"])
        self.assertEqual(orch.get_task("claude-task")["state"], "RETRYABLE")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 2)["reservations"], [])

    def test_expired_session_assignments_requeue_or_fail_and_release_leases(self):
        # Both aliases share one host. This expiry test needs two simultaneous
        # assignments, so its isolated fixture must explicitly have two slots.
        self.add_worker(replace(make_worker("local-retry", local=True), max_concurrency=2))
        self.add_worker(replace(make_worker("local-fail", local=True), max_concurrency=2))
        orch = self.orchestrator({})
        cases = (
            ("retry", "local-retry", 2, "RETRYABLE"),
            ("fail", "local-fail", 1, "FAILED"),
        )
        for suffix, worker_id, max_attempts, _ in cases:
            session_id = f"codex-{suffix}"
            orch.register_session(
                session_id, agent_kind="codex", owner_pid=100 + max_attempts,
                owner_started=1, repo=str(self.repo), bound_worker_id=worker_id,
                ttl_sec=30, now=NOW,
            )
            orch.submit_task(TaskSpec(
                id=f"expired-{suffix}", prompt=f"exercise expired session {suffix}",
                repo=str(self.repo), base_sha=BASE_SHA,
                path_scopes=(f"src/expired-{suffix}",), dispatch_mode="SESSION",
                allowed_agent_kinds=("codex",), allowed_worker_ids=(worker_id,),
                max_attempts=max_attempts, metadata={"workspace_mode": "claim-only"},
            ), now=NOW)
            assignment = orch.session_pull(session_id, now=NOW + 1)
            self.assertTrue(assignment["assigned"], assignment)

        self.assertEqual(len(self.maintainer.snapshot(now=NOW + 1)["reservations"]), 2)
        self.assertEqual(len(self.claims.snapshot(now=NOW + 1)["active"]), 2)

        updates = orch.reconcile_sessions(now=NOW + 602)

        update_states = {item["task_id"]: item["status"] for item in updates}
        for suffix, _, _, expected_state in cases:
            task_id = f"expired-{suffix}"
            self.assertEqual(update_states[task_id], expected_state)
            self.assertEqual(orch.get_task(task_id)["state"], expected_state)
            self.assertEqual(orch.get_task(task_id)["last_error"], "session_lease_expired")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 602)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 602)["active"], [])

    def test_local_session_aliases_cannot_multiply_single_host_concurrency(self):
        self.add_worker(make_worker("local-first", local=True))
        self.add_worker(make_worker("local-second", local=True))
        orch = self.orchestrator({})
        for suffix in ("first", "second"):
            worker_id = f"local-{suffix}"
            session_id = f"codex-{suffix}"
            orch.register_session(session_id, agent_kind="codex", owner_pid=123,
                owner_started=1, bound_worker_id=worker_id, now=NOW)
            orch.submit_task(TaskSpec(id=f"alias-{suffix}", prompt="fixture workload",
                dispatch_mode="SESSION", allowed_worker_ids=(worker_id,)), now=NOW)
        self.assertTrue(orch.session_pull("codex-first", now=NOW + 1)["assigned"])
        second = orch.session_pull("codex-second", now=NOW + 1)
        self.assertFalse(second["assigned"], second)
        self.assertEqual(orch.get_task("alias-second")["state"], "WAITING_CAPACITY")
        self.assertEqual(len(self.maintainer.snapshot(now=NOW + 1)["reservations"]), 1)
        event = next(event for event in orch.snapshot()["events"]
            if event["task_id"] == "alias-second" and event["event_type"] == "STATE_WAITING_CAPACITY")
        self.assertEqual(json.loads(event["data_json"])["rejected"]["local-second"], "concurrency_capacity")

    def test_unknown_dispatch_requires_resolution_before_retry_can_be_requeued(self):
        self.add_worker(make_worker("fake-worker"))
        orch = self.orchestrator({"fake": CrashDuringSubmitAdapter()})
        spec = self.scoped_spec("unknown-dispatch", max_attempts=2)
        orch.submit_task(spec, now=NOW)

        with self.assertRaisesRegex(SystemExit, "simulated scheduler process death"):
            orch.dispatch_one(spec.id, now=NOW)
        self.assertEqual(orch.get_task(spec.id)["state"], "RESERVED")
        self.assertEqual(len(self.maintainer.snapshot(now=NOW)["reservations"]), 1)
        self.assertEqual(len(self.claims.snapshot(now=NOW)["active"]), 1)

        updates = orch.reconcile(now=NOW + 121)

        self.assertEqual(
            updates,
            [{"task_id": spec.id, "status": "BLOCKED", "reason": "dispatch_outcome_unknown"}],
        )
        self.assertEqual(orch.get_task(spec.id)["state"], "BLOCKED")
        retry = orch.retry(spec.id, now=NOW + 122)
        self.assertFalse(retry["retried"])
        self.assertEqual(retry["reason"], "dispatch_resolution_required")
        self.assertEqual(len(self.maintainer.snapshot(now=NOW + 122)["reservations"]), 1)
        self.assertEqual(len(self.claims.snapshot(now=NOW + 122)["active"]), 1)

        resolved = orch.resolve_dispatch(
            spec.id, confirmed_not_submitted=True, now=NOW + 123,
        )

        self.assertTrue(resolved["resolved"], resolved)
        self.assertEqual(resolved["resolution"], "not_submitted")
        self.assertEqual(resolved["task"]["state"], "RETRYABLE")
        self.assertEqual(self.maintainer.snapshot(now=NOW + 123)["reservations"], [])
        self.assertEqual(self.claims.snapshot(now=NOW + 123)["active"], [])

    def test_process_discovery_refresh_preserves_busy_assignment_policy(self):
        orch = self.orchestrator({})
        orch.register_session(
            "codex-99", agent_kind="codex", owner_pid=99, owner_started=10,
            control_adapter="pull", bound_worker_id="local-windows", max_inflight=3,
            state="BUSY", current_task_id="already-running", now=NOW,
        )
        refreshed = orch.discover_session(
            "codex-99", agent_kind="codex", owner_pid=99, owner_started=10,
            repo=str(self.repo), now=NOW + 1,
        )
        self.assertEqual(refreshed["state"], "BUSY")
        self.assertEqual(refreshed["current_task_id"], "already-running")
        self.assertEqual(refreshed["max_inflight"], 3)

    def test_default_local_adapter_survives_orchestrator_process_boundary(self):
        self.add_worker(make_worker("local-worker", adapter="local", local=True))
        first = Orchestrator(
            self.data_dir, maintainer=self.maintainer, claims=self.claims, clock=lambda: NOW
        )
        spec = TaskSpec(
            id="persistent-local", prompt="run detached local command",
            execution_preference="LOCAL_REQUIRED", allowed_worker_ids=("local-worker",),
            metadata={
                "argv": [sys.executable, "-c", "import time; time.sleep(.1); print('cross-tick-ok')"],
                "timeout_seconds": 5,
            },
        )
        first.submit_task(spec, now=NOW)
        dispatched = first.dispatch_one(spec.id, now=NOW)
        self.assertTrue(dispatched["dispatched"], dispatched)

        restarted = Orchestrator(
            self.data_dir, maintainer=Maintainer(self.data_dir),
            claims=WorkspaceClaims(self.data_dir), clock=lambda: NOW + 1,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and restarted.get_task(spec.id)["state"] == "RUNNING":
            restarted.reconcile(now=NOW + 1)
            time.sleep(0.03)
        task = restarted.get_task(spec.id)
        self.assertEqual(task["state"], "DONE", task)
        self.assertIn("cross-tick-ok", task["result"]["stdout"])


if __name__ == "__main__":
    unittest.main()
