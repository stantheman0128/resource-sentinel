"""P1 S1 real-Windows capability spike; never part of ordinary control testing.

Explicit invocation (after normal Sentinel admission, in an isolated host):
  SENTINEL_ADAPTIVE_WINDOWS_SPIKES=1
  SENTINEL_ADAPTIVE_SPIKE_DIR=<isolated directory>
  python -m unittest discover -s tests/windows -p test_adaptive_job_capability.py -v

The full supported-host experiment is 10 rounds, each with three fixed 30s
CPU windows (uncapped, hard cap, restored). It deliberately cannot be shortened
by an environment variable and still called the S1 gate. Missing prerequisites
are recorded as unsupported/unverified, never a Windows capability pass.

The workload uses a fixed, bounded worker count sufficient to saturate the cap,
not the whole machine. The rate denominator remains all N logical processors.
For N=12, four busy workers prove a 3-unit cap; request five CPU units through
normal admission (four workers plus one conservative unit for test overhead).
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adaptive_win32 import (  # noqa: E402
    ENABLE, HARD_CAP, OPT_IN, LaunchOutcomeUnknown, OwnedJob,
    UnsupportedCapability, require_supported_host,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "adaptive_cpu_worker.py"
ENABLED = os.name == "nt" and os.environ.get(OPT_IN) == "1"
WINDOW_SECONDS = 30.0
ROUNDS = 10


def _write_json(path, value, *, durable=False):
    temporary = path.with_suffix(".pending")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        if durable:
            stream.flush()
            os.fsync(stream.fileno())
    os.replace(temporary, path)


def _isolated_evidence_directory():
    supplied = os.environ.get("SENTINEL_ADAPTIVE_SPIKE_DIR")
    legacy = os.environ.get("SENTINEL_ADAPTIVE_EVIDENCE_DIR")
    if supplied and legacy and Path(supplied).resolve() != Path(legacy).resolve():
        raise ValueError("conflicting spike/evidence directories")
    supplied = supplied or legacy
    if not supplied:
        raise UnsupportedCapability("explicit isolated SENTINEL_ADAPTIVE_SPIKE_DIR required")
    directory = Path(supplied).resolve()
    production = (Path.home() / ".resource-sentinel").resolve()
    if directory == production or production in directory.parents:
        raise ValueError("production data directory cannot be used for a Windows spike")
    directory.mkdir(parents=True, exist_ok=True)
    run = directory / ("s1-" + uuid.uuid4().hex)
    run.mkdir()
    return run


@unittest.skipUnless(ENABLED, "Windows S1 UNVERIFIED: explicit opt-in on Windows is required")
class WindowsJobCapabilitySpike(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = _isolated_evidence_directory()
        try:
            cls.host = require_supported_host()
        except UnsupportedCapability as exc:
            _write_json(cls.evidence / "host.json", {
                "status": "unsupported", "reason": exc.reason,
                "win32_error": exc.win32_error, "cpu_control_writes": 0,
                "capability_allowlist_eligible": False,
            })
            raise unittest.SkipTest(f"S1 UNSUPPORTED; gate not passed: {exc}") from exc
        _write_json(cls.evidence / "host.json", {
            **cls.host, "status": "preflight_only", "capability_allowlist_eligible": False,
            "disabled_encoding": {"flags": 0, "rate_bp": 10000},
            "unsupported_matrix": ["other Windows hosts not tested by this run",
                                   "RDP/DFSS availability not established by preflight"],
        })

    def _launch(self, job, directory, seconds, workers=1, foreign_probe=False):
        import msvcrt
        args = [sys.executable, str(FIXTURE), "--nonce", job.nonce,
                "--job-name", job.name, "--directory", str(directory),
                "--seconds", str(seconds), "--workers", str(workers)]
        if foreign_probe:
            args.append("--probe-foreign-host")
        from adaptive_win32 import launch_in_job
        with open(os.devnull, "rb") as source, open(os.devnull, "wb") as sink:
            return launch_in_job(job, sys.executable, subprocess.list2cmdline(args),
                cwd=str(directory), stdin_handle=msvcrt.get_osfhandle(source.fileno()),
                stdout_handle=msvcrt.get_osfhandle(sink.fileno()),
                stderr_handle=msvcrt.get_osfhandle(sink.fileno()))

    def _ready(self, directory, count, case_deadline, timeout=10):
        deadline = min(time.monotonic() + timeout, case_deadline)
        while time.monotonic() < deadline:
            records = [json.loads(path.read_text(encoding="utf-8"))
                       for path in directory.glob("ready-*.json")]
            if len(records) == count:
                self.assertTrue(all(record["in_expected_job"] for record in records))
                return records
            time.sleep(0.05)
        self.fail(f"fixture failed to announce {count} contained members within {timeout}s")

    def _cleanup(self, job, process, directory, record, deadline):
        """Restore/query first, then request voluntary stop and verify Job empty.

        Even a restore exception does not skip the independent stop request.
        Failure preserves evidence; it cannot become a success by closing handles.
        """
        errors = []
        try:
            observed = job.query_cpu()
            record["cleanup_before"] = observed
            if observed["flags"] & ENABLE:
                if observed != record.get("intended_cpu"):
                    raise RuntimeError("restore conflict: observed CPU control differs from own intent")
                job.disable()
            record["cleanup_after"] = job.query_cpu()
            if record["cleanup_after"]["flags"] & ENABLE:
                errors.append("CPU restriction still enabled")
        except Exception as exc:
            errors.append(f"restore/query failed: {type(exc).__name__}: {exc}")
        try:
            (directory / "stop").touch(exist_ok=True)
        except Exception as exc:
            errors.append(f"cooperative stop request failed: {type(exc).__name__}: {exc}")
        try:
            record["observation_deadline_expired"] = time.monotonic() >= deadline
            record["job_empty_verified"] = job.wait_empty(max(0, deadline - time.monotonic()))
            if not record["job_empty_verified"]:
                errors.append("Job not verified empty within the absolute 120s case deadline")
            if time.monotonic() > deadline:
                record["observation_deadline_expired"] = True
                errors.append("absolute 120s observation deadline expired")
            record["final_members"] = job.active_pids()
            if process is not None:
                record["root_exit_code"] = process.exit_code()
        except Exception as exc:
            errors.append(f"empty verification failed: {type(exc).__name__}: {exc}")
        if process is not None:
            try:
                process.close()
            except Exception as exc:
                errors.append(f"process handle close failed: {type(exc).__name__}: {exc}")
        try:
            job.close()
        except Exception as exc:
            errors.append(f"Job handle close failed: {type(exc).__name__}: {exc}")
        record["cleanup_errors"] = errors
        record["handles_closed"] = job.handle is None and (process is None or process.handle is None)
        if errors:
            record["status"] = "cleanup_failed"
        elif record["status"] == "running":
            record["status"] = "failed"
        _write_json(directory / "result.json", record)
        if errors:
            self.fail("; ".join(errors))

    def test_00_fixture_self_stops_and_job_has_no_other_limits(self):
        directory = self.evidence / "self-stop"
        directory.mkdir()
        started = time.monotonic()
        deadline = started + 120
        job, process = OwnedJob.create(), None
        record = {"case": "voluntary_self_stop", "status": "running", "nonce": job.nonce,
                  "job_security": job.security, "absolute_observation_seconds": 120}
        try:
            self.assertEqual(job.query_limits(), {"limit_flags": 0, "ui_restrictions": 0})
            self.assertEqual(job.query_cpu()["flags"], 0)
            process = self._launch(job, directory, seconds=2)
            record["root_identity"] = process.identity()
            record["earliest_membership"] = self._ready(directory, 1, deadline)
            self.assertTrue(process.wait(max(0, min(8, deadline - time.monotonic()))),
                            "fixture did not voluntarily exit")
            self.assertEqual(process.exit_code(), 0)
            self.assertTrue(job.wait_empty(max(0, min(2, deadline - time.monotonic()))))
            exit_record = json.loads((directory / f"exit-{process.pid}.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_record["reason"], "self_deadline")
            self.assertLessEqual(exit_record["elapsed_seconds"], 120)
            record["elapsed_seconds"] = time.monotonic() - started
            record["status"] = "pass"
        except LaunchOutcomeUnknown as exc:
            process = exc.process
            raise
        finally:
            self._cleanup(job, process, directory, record, deadline)

    def test_10_parent_job_is_explicitly_unsupported(self):
        directory = self.evidence / "foreign-parent"
        directory.mkdir()
        deadline = time.monotonic() + 120
        job, process = OwnedJob.create(), None
        record = {"case": "foreign_parent_negative", "status": "running", "nonce": job.nonce}
        try:
            process = self._launch(job, directory, seconds=5, foreign_probe=True)
            record["root_identity"] = process.identity()
            self.assertTrue(process.wait(max(0, min(10, deadline - time.monotonic()))))
            self.assertEqual(process.exit_code(), 0)
            probe = json.loads((directory / "foreign-probe.json").read_text(encoding="utf-8"))
            self.assertEqual(probe["foreign_gate"]["status"], "unsupported")
            self.assertIn("parent Job", probe["foreign_gate"]["reason"])
            record["probe"] = probe
            record["status"] = "pass"
        except LaunchOutcomeUnknown as exc:
            process = exc.process
            raise
        finally:
            self._cleanup(job, process, directory, record, deadline)

    def _window(self, job, deadline):
        start = time.monotonic()
        self.assertLessEqual(start + WINDOW_SECONDS, deadline,
                             "insufficient time for a complete fixed window before case deadline")
        initial = job.accounting()
        time.sleep(WINDOW_SECONDS)
        final = job.accounting()
        elapsed = time.monotonic() - start
        return {"elapsed_seconds": elapsed,
                "cpu_seconds": final["cpu_seconds"] - initial["cpu_seconds"],
                "cpu_units": (final["cpu_seconds"] - initial["cpu_seconds"]) / elapsed,
                "active_processes_start": initial["active_processes"],
                "active_processes_end": final["active_processes"]}

    def test_20_ten_create_set_disable_reopen_effect_rounds(self):
        n = self.host["logical_processors"]
        target = n * 0.25
        tolerance = max(0.15, target * 0.10)
        saturation_headroom = 0.25
        # Select once from the known denominator, never from current pressure
        # or after observing outcomes. Saturation means demand exceeds the
        # target's entire acceptance band, not consuming every machine core.
        workers = math.ceil((target + tolerance + saturation_headroom) / 0.90)
        self.assertLessEqual(workers, n)
        workload_cpu_estimate = float(workers)
        admission_cpu_estimate = float(min(n, workers + 1))
        completed = []
        for iteration in range(ROUNDS):
            directory = self.evidence / f"effect-{iteration:02d}"
            directory.mkdir()
            deadline = time.monotonic() + 120
            job, process, reopened = OwnedJob.create(), None, None
            record = {"case": "normal_host_25_percent", "round": iteration,
                      "status": "running", "nonce": job.nonce,
                      "target_cpu_units": target, "denominator_logical_processors": n,
                      "worker_count": workers,
                      "workload_cpu_estimate_units": workload_cpu_estimate,
                      "admission_cpu_estimate_units": admission_cpu_estimate,
                      "cap_effect_tolerance_cpu_units": tolerance,
                      "minimum_saturation_headroom_cpu_units": saturation_headroom,
                      "job_security": job.security, "absolute_observation_seconds": 120,
                      "disabled_encoding": {"flags": 0, "rate_bp": 10000}}
            try:
                self.assertEqual(job.query_limits(), {"limit_flags": 0, "ui_restrictions": 0})
                record["initial_cpu"] = job.query_cpu()
                self.assertEqual(record["initial_cpu"]["flags"], 0)
                process = self._launch(job, directory, seconds=115, workers=workers)
                record["root_identity"] = process.identity()
                record["earliest_membership"] = self._ready(directory, workers, deadline)
                self.assertEqual(set(job.active_pids()), {item["pid"] for item in record["earliest_membership"]})
                record["uncapped"] = self._window(job, deadline)
                self.assertGreaterEqual(record["uncapped"]["cpu_units"], workers * 0.90,
                    "fixture workers not saturated: environment cannot prove the cap effect")
                self.assertGreaterEqual(record["uncapped"]["cpu_units"],
                    target + tolerance + saturation_headroom,
                    "baseline lacks headroom above the cap's full acceptance band")
                record["intended_cpu"] = {"flags": ENABLE | HARD_CAP, "rate_bp": 2500}
                _write_json(directory / "control-intent.json", {
                    "status": "intent_before_set", "job_name": job.name, "nonce": job.nonce,
                    "logon_sid": job.logon_sid, "root_identity": record["root_identity"],
                    "original_cpu": record["initial_cpu"], "target": record["intended_cpu"],
                    "fixture_maximum_lifetime_seconds": 120,
                }, durable=True)
                record["applied"] = job.set_cpu_rate(2500)
                self.assertEqual(record["applied"], {"flags": ENABLE | HARD_CAP, "rate_bp": 2500})
                record["capped"] = self._window(job, deadline)
                self.assertAlmostEqual(record["capped"]["cpu_units"], target,
                    delta=tolerance, msg="actual Job CPU does not match known denominator")
                # Drop the original handle while the Job has live members. This
                # is deliberately not called restoration. Reopen by owned nonce.
                name, nonce = job.name, job.nonce
                job.close()
                reopened = OwnedJob.open(name, nonce)
                job = reopened
                record["reopened_security"] = job.security
                record["reopened_cpu"] = job.query_cpu()
                self.assertEqual(record["reopened_cpu"], record["applied"])
                record["disabled"] = job.disable()
                self.assertEqual(record["disabled"]["flags"] & ENABLE, 0)
                record["restored"] = self._window(job, deadline)
                self.assertGreaterEqual(record["restored"]["cpu_units"],
                                        record["uncapped"]["cpu_units"] * 0.90,
                                        "disabled Query did not restore actual CPU consumption")
                self.assertGreaterEqual(record["restored"]["cpu_units"],
                                        target + tolerance + saturation_headroom,
                                        "restoration is not distinguishable from the capped acceptance band")
                for phase in ("uncapped", "capped", "restored"):
                    self.assertEqual(record[phase]["active_processes_start"], workers)
                    self.assertEqual(record[phase]["active_processes_end"], workers)
                self.assertEqual(job.query_limits(), {"limit_flags": 0, "ui_restrictions": 0})
                record["status"] = "pass"
            except LaunchOutcomeUnknown as exc:
                process = exc.process
                record["status"] = "start_unknown"
                raise
            except BaseException as exc:
                record["status"] = "failed"
                record["failure"] = {"type": type(exc).__name__, "message": str(exc),
                                     "win32_error": getattr(exc, "win32_error", None)}
                raise
            finally:
                # If reopen failed after closing, attempt exactly the same owned
                # object once for restore; never create/adopt a replacement Job.
                if job.handle is None:
                    try:
                        job = OwnedJob.open(name, nonce)
                    except Exception as exc:
                        record["restore_unverified"] = str(exc)
                        record["job_empty_verified"] = False
                        try:
                            (directory / "stop").touch(exist_ok=True)
                        except Exception as stop_exc:
                            record["stop_error"] = str(stop_exc)
                        if process is not None:
                            try:
                                record["root_exit_observed"] = process.wait(max(0, deadline - time.monotonic()))
                            except Exception as wait_exc:
                                record["root_observation_error"] = str(wait_exc)
                            try:
                                process.close()
                            except Exception as close_exc:
                                record["process_close_error"] = str(close_exc)
                        _write_json(directory / "result.json", record)
                        raise
                self._cleanup(job, process, directory, record, deadline)
            completed.append(iteration)
        _write_json(self.evidence / "effect-summary.json", {
            "status": "pass", "supported_case": "normal_host_25_percent",
            "completed_rounds": completed, "cpu_window_seconds": WINDOW_SECONDS,
            "worker_count": workers, "workload_cpu_estimate_units": workload_cpu_estimate,
            "admission_cpu_estimate_units": admission_cpu_estimate,
            "host": self.host, "all_restrictions_withdrawn_and_jobs_empty": True,
            "scope": "only this host/case; other S1 cases and S2/S3 remain separate gates",
        })


if __name__ == "__main__":
    unittest.main()
