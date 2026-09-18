"""P1 S3 real-Windows recovery spike, disabled unless explicitly opted in.

Run only through normal resource admission in a verified non-foreign-Job host:
  SENTINEL_ADAPTIVE_WINDOWS_SPIKES=1
  SENTINEL_ADAPTIVE_SPIKE_DIR=<isolated directory outside live runtime>
  py -m unittest tests.windows.test_adaptive_recovery_capability

Each fault runs ten times; no option lowers that gate. A non-Windows/foreign host
is unsupported, not a pass. Native query/fencing/restore are real; the filesystem
rendezvous and allocation/grant SQLite rows are a test protocol. They do not
verify production store, IPC, supervisor, exemption, or admission integration.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import unittest
import uuid

from tests.windows import adaptive_win32 as win
from tests.fixtures import adaptive_recovery_actor as actor

ACTOR = Path(actor.__file__).resolve()
FAULTS = (
    "intent_before", "intent_after_set_before", "set_after_query_before",
    "query_after_audit_before", "root_exit_after", "lease_renewal",
    "grant_commit_restore_before", "guardian_takeover",
    "guardian_hang", "wrapper_loss", "grant_before_cap", "audit_unavailable",
)
REPEATS = 10
OBSERVATION_SECONDS = 120


class RecoveryCapability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("SENTINEL_ADAPTIVE_WINDOWS_SPIKES") != "1":
            raise unittest.SkipTest("S3 not tested: explicit Windows spike opt-in absent")
        if sys.platform != "win32":
            raise unittest.SkipTest("S3 unsupported: real Windows APIs required")
        # Reject before creating any Job, launching a fixture, or setting a cap.
        try:
            cls.host = win.require_supported_host()
        except win.UnsupportedCapability as error:
            raise unittest.SkipTest(f"S3 unsupported, not passed: {error}") from error
        root_text = os.environ.get("SENTINEL_ADAPTIVE_SPIKE_DIR")
        if not root_text:
            raise RuntimeError("explicit isolated SENTINEL_ADAPTIVE_SPIKE_DIR required")
        root = Path(root_text).resolve()
        live = (Path.home() / ".resource-sentinel").resolve()
        if root == live or live in root.parents:
            raise RuntimeError("live_runtime_directory_forbidden")
        cls.run = root / ("s3-" + uuid.uuid4().hex)
        cls.run.mkdir(parents=True, exist_ok=False)
        cls.results = []
        actor.write_json(cls.run / "scope.json", {
            "test_only": True, "required_repeats": REPEATS,
            "faults": list(FAULTS), "observation_deadline_seconds": OBSERVATION_SECONDS,
            "host": cls.host, "production_integration": "not_tested",
            "independent_scheduled_task_recovery": "not_tested",
            "restoration_effect": "requires_independent_S1_consumption_results",
            "lease_clock": "QueryInterruptTimePrecise_100ns",
        })

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "run"):
            actor.write_json(cls.run / "results.json", {
                "cases": cls.results, "expected_cases": len(FAULTS) * REPEATS,
                "native_matrix_passed": len(cls.results) == len(FAULTS) * REPEATS
                    and all(item["result"] == "passed" for item in cls.results),
                # Even a green matrix cannot assert missing independent-owner
                # scheduling / full-stack / effect evidence on behalf of P1/P3.
                "S3_gate": "partial_requires_independent_owner_and_S1_evidence",
                "runtime_modified": False,
            })

    def _remaining(self, deadline: float, maximum: float = 10) -> float:
        remaining = min(maximum, deadline - time.monotonic())
        self.assertGreater(remaining, 0, "120s outside observation deadline exceeded")
        return remaining

    def _await(self, case: Path, name: str, deadline: float, maximum: float = 10) -> dict:
        self.assertTrue(actor.wait_file(case / f"{name}.json", self._remaining(deadline, maximum)),
                        f"missing {name}; fixture evidence retained in {case.name}")
        return actor.read_json(case / f"{name}.json")

    def _popen(self, case: Path, role: str, children: dict, streams: list):
        output = (case / f"{role}.stdout").open("wb")
        error = (case / f"{role}.stderr").open("wb")
        streams.extend((output, error))
        child = subprocess.Popen([sys.executable, str(ACTOR), role, str(case)],
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                                 close_fds=True)
        children[role] = child
        return child

    def _workload(self, case: Path, role: str, job, streams: list):
        import msvcrt
        source = open(os.devnull, "rb")
        output = (case / "workload.stdout").open("wb")
        error = (case / "workload.stderr").open("wb")
        streams.extend((source, output, error))
        command = subprocess.list2cmdline([sys.executable, str(ACTOR), role, str(case)])
        return win.launch_in_job(job, sys.executable, command,
            stdin_handle=msvcrt.get_osfhandle(source.fileno()),
            stdout_handle=msvcrt.get_osfhandle(output.fileno()),
            stderr_handle=msvcrt.get_osfhandle(error.fileno()))

    def _fence_fixture_guardian(self, case, config, child, exact_handle):
        ready = actor.read_json(case / "guardian-ready.json")
        self.assertEqual(ready["role"], "guardian")
        self.assertEqual(ready["fixture_version"], 1)
        self.assertEqual(ready["identity"], config["guardian_identity"])
        self.assertEqual(exact_handle.identity(), ready["identity"])
        self.assertEqual(child.pid, ready["identity"]["pid"])
        self.assertIsNone(child.poll())
        # Popen's retained native handle targets this one manager, even if a PID
        # is later reused. It cannot terminate descendants or other agents.
        child.terminate()
        actor.mark(case, "guardian-fixture-terminated", identity=ready["identity"],
                   workload_termination=False)

    def _case(self, fault: str, iteration: int):
        nonce = uuid.uuid4().hex
        case = self.run / nonce
        case.mkdir(exist_ok=False)
        started = time.monotonic()
        deadline = started + OBSERVATION_SECONDS
        result = {"fault": fault, "iteration": iteration, "nonce": nonce,
                  "result": "failed", "restore_verified": False,
                  "job_empty_verified": False, "all_actor_exit_verified": False}
        children, streams, handles = {}, [], []
        job = guardian_handle = root = worker_handle = None
        config = None
        restored = False
        failure = None
        try:
            job = win.OwnedJob.create(nonce)
            count = os.cpu_count()
            self.assertIsNotNone(count)
            config = {"test_only": True, "nonce": nonce, "job_name": job.name,
                      "fault": fault, "rate_bp": math.ceil(10000 / count),
                      "policy_mutex": f"Local\\ResourceSentinel.Test.Mutex.{nonce}.Policy",
                      "mutation_mutex": f"Local\\ResourceSentinel.Test.Mutex.{nonce}.Job"}
            actor.write_json(case / "case.json", config)
            with actor.fixture_store(case):
                pass
            self.assertFalse(job.query_cpu()["flags"] & 1)
            limits = job.query_limits()
            self.assertEqual(limits["limit_flags"], 0)
            self.assertEqual(limits["ui_restrictions"], 0)
            if fault == "wrapper_loss":
                self._popen(case, "wrapper", children, streams)
                self._await(case, "wrapper-ready", deadline)
            else:
                role = "root" if fault == "root_exit_after" else "worker"
                root = self._workload(case, role, job, streams)
                handles.append(root)
            worker = self._await(case, "worker-ready", deadline)
            identity = worker["identity"]
            worker_handle = win.ProcessHandle.open(identity["pid"], identity["created_filetime_100ns"])
            handles.append(worker_handle)
            self.assertTrue(worker_handle.is_in_job(job))
            if fault == "lease_renewal":
                self._popen(case, "helper", children, streams)
                self._await(case, "helper-ready", deadline)
            guardian = self._popen(case, "guardian", children, streams)
            ready = self._await(case, "guardian-ready", deadline)
            config["guardian_identity"] = ready["identity"]
            self.assertEqual(config["guardian_identity"]["pid"], guardian.pid)
            self.assertEqual(ready["role"], "guardian")
            self.assertEqual(ready["fixture_version"], 1)
            guardian_handle = win.ProcessHandle.open(guardian.pid,
                config["guardian_identity"]["created_filetime_100ns"])
            handles.append(guardian_handle)
            actor.write_json(case / "case.json", config)
            # Independent restore-only processes retain the exact old process
            # handle before the crash. No PID re-open after death substitutes it.
            for role in ("restore-a", "restore-b"):
                self._popen(case, role, children, streams)
                self._await(case, f"{role}-ready", deadline)
            (case / "guardian-go").touch(exist_ok=False)
            if fault == "root_exit_after":
                self._await(case, "applied-ack", deadline)
                (case / "root-exit-now").touch(exist_ok=False)
                self._await(case, "root-exit", deadline)
                self.assertTrue(root.wait(self._remaining(deadline)))
                self.assertEqual(root.exit_code(), 7)
                self.assertGreater(job.accounting()["active_processes"], 0)
            elif fault == "guardian_hang":
                self._await(case, "guardian-holding-mutex", deadline)
                # A live guardian cannot be fenced by elapsed TTL alone.
                time.sleep(0.2)
                for role in ("restore-a", "restore-b"):
                    self.assertFalse((case / f"{role}-restored.json").exists())
                # Only this Popen-created, exact-identity test guardian is
                # terminated. Popen holds its own process handle, no /T, PID
                # search, or workload termination occurs.
                self._fence_fixture_guardian(case, config, guardian, guardian_handle)
            self.assertTrue(guardian_handle.wait(self._remaining(deadline, 20)),
                            "guardian did not exit within observation bound")
            death_observed = time.monotonic()
            # An unexpected pre-Set actor error must not look like successful
            # crash recovery merely because the Job was never restricted.
            crash_points = {"intent_before", "intent_after_set_before", "set_after_query_before",
                            "query_after_audit_before", "root_exit_after",
                            "grant_commit_restore_before", "guardian_takeover"}
            if fault in crash_points:
                self.assertEqual(guardian.wait(timeout=self._remaining(deadline)), 71)
                self.assertEqual(self._await(case, "injected", deadline)["point"], fault)
            elif fault == "guardian_hang":
                self.assertNotEqual(guardian.wait(timeout=self._remaining(deadline)), 0)
                self._await(case, "guardian-fixture-terminated", deadline)
            else:
                self.assertEqual(guardian.wait(timeout=self._remaining(deadline)), 0)
            self.assertFalse((case / "guardian-error.json").exists())
            if fault == "intent_before":
                self.assertFalse((case / "manifest.json").exists())
                self.assertFalse((case / "intent-durable.json").exists())
            else:
                self._await(case, "intent-durable", deadline)
                actor.verified_manifest(case, config)
            if fault not in ("intent_before", "intent_after_set_before", "set_after_query_before", "grant_before_cap"):
                self.assertTrue(self._await(case, "applied-ack", deadline)["readback"]["flags"] & 1)
            if fault == "guardian_takeover":
                self._await(case, "restore-a-mutex-held", deadline)
                restore = self._await(case, "restore-b-restored", deadline)
                self.assertTrue(restore["abandoned"], "takeover did not witness mutex owner death")
            else:
                restore = self._await(case, "restore-a-restored", deadline)
                self._await(case, "restore-b-restored", deadline)
            restore_records = [actor.read_json(item) for item in case.glob("*-restored.json")]
            if fault not in ("intent_before", "intent_after_set_before", "grant_before_cap"):
                self.assertTrue(any(record["before"]["flags"] & 1 for record in restore_records),
                                "fault never exposed an enabled cap to native recovery Query")
            else:
                self.assertTrue(all(not record["before"]["flags"] & 1 for record in restore_records))
            if fault not in ("lease_renewal", "wrapper_loss", "audit_unavailable", "grant_before_cap"):
                self.assertLessEqual(time.monotonic() - death_observed, 8,
                                     "guardian-loss restore exceeded 8s normal-scheduling goal")
            after = job.query_cpu()
            self.assertFalse(after["flags"] & 1, "native Query still shows enabled cap")
            restored = True
            result["restore_verified"] = True
            result["final_control"] = after
            result["restore_ack"] = restore
            self.assertGreater(job.accounting()["active_processes"], 0,
                               "Job disappearance is not evidence of cap restoration")
            self.assertIsNone(worker_handle.exit_code(), "workload exited instead of surviving restore")
            previous_cycles = actor.read_json(case / "worker-progress.json")["cycles"]
            progress_deadline = time.monotonic() + self._remaining(deadline, 2)
            while time.monotonic() < progress_deadline:
                if actor.read_json(case / "worker-progress.json")["cycles"] > previous_cycles:
                    break
                time.sleep(0.02)
            self.assertGreater(actor.read_json(case / "worker-progress.json")["cycles"], previous_cycles)
            with sqlite3.connect(case / "fixture.sqlite3") as store:
                self.assertEqual(store.execute("SELECT state FROM allocation WHERE id='own'").fetchone()[0], "held")
                grants = store.execute("SELECT id,state,expires FROM grants").fetchall()
            result["fixture_allocation_before_empty"] = "held"
            result["fixture_grant_slots"] = len(grants)
            if fault in ("grant_commit_restore_before", "grant_before_cap"):
                self.assertEqual(len(grants), 1)
                self.assertEqual(grants[0][1], "recorded")
                self.assertGreater(grants[0][2], time.time())
                grant = self._await(case, "grant-committed", deadline)
                result["grant_record"] = grant
                if fault == "grant_before_cap":
                    self.assertFalse((case / "applied-ack.json").exists())
                    self._await(case, "apply-rejected", deadline)
            if fault == "lease_renewal":
                decision = self._await(case, "helper-decision", deadline)
                ack = self._await(case, "guardian-restored", deadline)
                duration = (int(ack["interrupt_tick_100ns"]) - int(decision["interrupt_tick_100ns"])) / 1e7
                self.assertGreaterEqual(duration, 6)
                self.assertLessEqual(duration, 8)
                result["helper_loss_restore_seconds"] = duration
            if fault == "audit_unavailable":
                self._await(case, "audit-failed", deadline)
                self.assertTrue(self._await(case, "guardian-restored", deadline)["while_db_locked"])
            if fault == "wrapper_loss":
                injected = self._await(case, "wrapper-injected", deadline)
                ack = self._await(case, "guardian-restored", deadline)
                duration = (int(ack["interrupt_tick_100ns"]) - int(injected["interrupt_tick_100ns"])) / 1e7
                self.assertGreaterEqual(duration, 0)
                self.assertLessEqual(duration, 8)
                result["wrapper_loss_restore_seconds"] = duration
            for role, process in children.items():
                expected = 72 if fault == "guardian_takeover" and role == "restore-a" else 0
                if role.startswith("restore-"):
                    self.assertEqual(process.wait(timeout=self._remaining(deadline)), expected)
                elif role == "helper":
                    self.assertEqual(process.wait(timeout=self._remaining(deadline)), 73)
                elif role == "wrapper":
                    self.assertEqual(process.wait(timeout=self._remaining(deadline)), 74)
            self.assertFalse(list(case.glob("*-error.json")), "unexpected fixture actor failure")
            result["result"] = "passed"
        except BaseException as error:
            failure = error
            result["error"] = {"type": type(error).__name__, "reason": str(error)[:300]}
        finally:
            # Freeze: never issue another tightening after any failure. Fallback
            # restoration requires this precise guardian handle to be signaled,
            # plus the same mutate mutex, and only accepts our durable values.
            if job is not None and not restored:
                try:
                    if guardian_handle is not None and not guardian_handle.wait(max(0.01, min(20, deadline - time.monotonic()))):
                        guardian = children.get("guardian")
                        if guardian is None:
                            raise RuntimeError("old_guardian_alive_restore_forbidden")
                        # Unexpected failure does not abandon a cap while a
                        # verified fixture manager is hung. Fence only that own
                        # manager, retain the failure, then attempt real restore.
                        self._fence_fixture_guardian(case, config, guardian, guardian_handle)
                        if not guardian_handle.wait(max(0.01, min(8, deadline - time.monotonic()))):
                            raise RuntimeError("fixture_guardian_death_unverified")
                    if config and "guardian_identity" in config:
                        mutex = win.NamedMutex(config["mutation_mutex"], config["nonce"])
                        try:
                            mutex.acquire(max(0.01, min(10, deadline - time.monotonic())))
                            try:
                                recovery = actor.compare_restore(job, case, config)
                                actor.mark(case, "observer-emergency-restored", **recovery)
                                restored = not recovery["after"]["flags"] & 1
                            finally:
                                mutex.release()
                        finally:
                            mutex.close()
                    else:
                        restored = not job.query_cpu()["flags"] & 1
                    result["restore_verified"] = restored
                except BaseException as error:
                    result["recovery_error"] = {"type": type(error).__name__, "reason": str(error)[:200]}
            # Cooperative fixture termination is separate from restore evidence.
            # It is never used to turn an unverified restore into success.
            (case / "stop").touch(exist_ok=True)
            (case / "root-exit-now").touch(exist_ok=True)
            (case / "wrapper-exit-now").touch(exist_ok=True)
            (case / "helper-go").touch(exist_ok=True)
            (case / "allow-hang-exit").touch(exist_ok=True)
            if job is not None:
                try:
                    empty = job.wait_empty(max(0.01, min(10, deadline - time.monotonic())))
                    result["job_empty_verified"] = bool(empty)
                    if empty:
                        with sqlite3.connect(case / "fixture.sqlite3") as store:
                            store.execute("UPDATE allocation SET state='finished' WHERE id='own'")
                        if result["result"] == "passed":
                            exit_record = actor.read_json(case / "worker-exit.json")
                            if (not exit_record.get("voluntary") or
                                    exit_record.get("reason") != "stop_file" or
                                    worker_handle.exit_code() != 0):
                                raise RuntimeError("workload_did_not_finish_via_cooperative_stop")
                            result["workload_exit"] = exit_record
                except BaseException as error:
                    result["cleanup_error"] = type(error).__name__
                    result["result"] = "failed"
                    if failure is None:
                        failure = error
            alive = []
            for role, process in children.items():
                try:
                    process.wait(timeout=max(0.01, min(30, deadline - time.monotonic())))
                except subprocess.TimeoutExpired:
                    alive.append(role)
            result["remaining_test_actors"] = alive
            result["all_actor_exit_verified"] = not alive
            if not restored or not result["job_empty_verified"] or alive:
                result["result"] = "failed"
                if failure is None:
                    failure = AssertionError("fixture restore/empty/actor-exit verification incomplete")
            for handle in handles:
                handle.close()
            if job is not None:
                job.close()
            for stream in streams:
                stream.close()
            result["elapsed_seconds"] = time.monotonic() - started
            self.results.append(result)
            actor.write_json(case / "result.json", result)
        if failure is not None:
            raise failure

    def test_s3_native_fault_matrix(self):
        # Stop the entire matrix on the first safety/restore failure. Subtests
        # would otherwise continue issuing new caps after a failed invariant.
        for fault in FAULTS:
            for iteration in range(1, REPEATS + 1):
                self._case(fault, iteration)


if __name__ == "__main__":
    unittest.main()
