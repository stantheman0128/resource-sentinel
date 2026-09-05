"""Detached local-command runner used by the persistent adapter.

The request is consumed from stdin and is never written to the job directory.
Only lifecycle data and bounded output files remain for later reconciliation.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(temp, path)


def terminate_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def drain_stream(
    stream: Any, path: Path, limit: int, state: dict[str, Any]
) -> None:
    """Drain a pipe completely while retaining at most ``limit`` bytes."""
    total = 0
    retained = 0
    try:
        with path.open("wb") as output:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if retained < limit:
                    kept = chunk[: max(0, limit - retained)]
                    output.write(kept)
                    retained += len(kept)
    finally:
        try:
            stream.close()
        except Exception:
            pass
        state.update(total_bytes=total, retained_bytes=retained, truncated=total > retained)


class ProcessTreeMetrics:
    """Best-effort aggregate counters for a changing subprocess tree."""

    def __init__(self, root_pid: int):
        self.root_pid = root_pid
        self.available = False
        self.peak_working_set = 0
        self.peak_private = 0
        self.cpu_seconds = 0.0
        self.peak_cpu_equivalent = 0.0
        self.disk_read_bytes = 0
        self.disk_write_bytes = 0
        self.samples = 0
        self._last: dict[tuple[int, float], tuple[float, int, int]] = {}
        self._last_sample_at: float | None = None

    def sample(self) -> None:
        try:
            import psutil

            root = psutil.Process(self.root_pid)
            processes = [root, *root.children(recursive=True)]
        except Exception:
            return
        now = time.monotonic()
        rss = 0
        private = 0
        interval_cpu = 0.0
        observed = 0
        current: dict[tuple[int, float], tuple[float, int, int]] = {}
        for item in processes:
            try:
                key = (int(item.pid), float(item.create_time()))
                memory = item.memory_info()
                rss += int(memory.rss)
                try:
                    private += int(getattr(item.memory_full_info(), "private", 0) or 0)
                except Exception:
                    pass
                cpu_times = item.cpu_times()
                cpu = float(cpu_times.user + cpu_times.system)
                try:
                    io = item.io_counters()
                    read_bytes, write_bytes = int(io.read_bytes), int(io.write_bytes)
                except Exception:
                    read_bytes, write_bytes = 0, 0
                previous = self._last.get(key, (0.0, 0, 0))
                cpu_delta = max(0.0, cpu - previous[0])
                interval_cpu += cpu_delta
                self.cpu_seconds += cpu_delta
                self.disk_read_bytes += max(0, read_bytes - previous[1])
                self.disk_write_bytes += max(0, write_bytes - previous[2])
                current[key] = (cpu, read_bytes, write_bytes)
                observed += 1
            except Exception:
                continue
        if observed == 0:
            return
        self._last = current
        self.peak_working_set = max(self.peak_working_set, rss)
        self.peak_private = max(self.peak_private, private)
        if self._last_sample_at is not None and now > self._last_sample_at:
            self.peak_cpu_equivalent = max(
                self.peak_cpu_equivalent, interval_cpu / (now - self._last_sample_at)
            )
        self._last_sample_at = now
        self.samples += 1
        self.available = True

    def result(self, duration: float) -> dict[str, Any]:
        if not self.available:
            return {
                "metrics_available": False, "duration_seconds": duration,
                "peak_working_set_gib": None, "peak_private_gib": None,
                "cpu_seconds": None, "average_cpu_equivalent": None,
                "peak_cpu_equivalent": None, "disk_read_bytes": None,
                "disk_write_bytes": None, "metric_samples": 0,
            }
        return {
            "metrics_available": True, "duration_seconds": duration,
            "peak_working_set_gib": self.peak_working_set / 2**30,
            "peak_private_gib": self.peak_private / 2**30 if self.peak_private else None,
            "cpu_seconds": self.cpu_seconds,
            "average_cpu_equivalent": self.cpu_seconds / duration if duration > 0 else 0.0,
            "peak_cpu_equivalent": self.peak_cpu_equivalent,
            "disk_read_bytes": self.disk_read_bytes,
            "disk_write_bytes": self.disk_write_bytes,
            "metric_samples": self.samples,
        }


def run(job_dir: Path) -> int:
    runtime_path = job_dir / "runtime.json"
    result_path = job_dir / "result.json"
    cancel_path = job_dir / "cancel.requested"
    stdout_path = job_dir / "stdout.bin"
    stderr_path = job_dir / "stderr.bin"
    started_at = time.time()
    process: subprocess.Popen[Any] | None = None
    try:
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        command = request["command"]
        shell = bool(request.get("shell"))
        timeout_value = request.get("timeout_seconds")
        timeout = None if timeout_value is None else float(timeout_value)
        max_output_bytes = max(1, int(request.get("max_output_bytes") or 2 * 1024 * 1024))
        options: dict[str, Any] = {}
        if os.name == "nt":
            options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(
            command, shell=shell, cwd=request.get("cwd") or None,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            **options,
        )
        assert process.stdout is not None and process.stderr is not None
        try:
            import psutil

            child_started = float(psutil.Process(process.pid).create_time())
        except Exception:
            child_started = 0.0
        stdout_state: dict[str, Any] = {}
        stderr_state: dict[str, Any] = {}
        drainers = [
            threading.Thread(
                target=drain_stream,
                args=(process.stdout, stdout_path, max_output_bytes, stdout_state),
                daemon=True,
            ),
            threading.Thread(
                target=drain_stream,
                args=(process.stderr, stderr_path, max_output_bytes, stderr_state),
                daemon=True,
            ),
        ]
        for drainer in drainers:
            drainer.start()
        atomic_json(runtime_path, {
            "runner_pid": os.getpid(), "child_pid": process.pid,
            "child_started": child_started, "started_at": started_at, "status": "RUNNING",
        })
        metrics = ProcessTreeMetrics(process.pid)
        deadline = None if timeout is None else time.monotonic() + timeout
        timed_out = False
        while process.poll() is None:
            metrics.sample()
            if deadline is not None and time.monotonic() >= deadline:
                timed_out = True
                terminate_tree(process)
                break
            try:
                wait_for = 0.05 if deadline is None else max(
                    0.001, min(0.05, deadline - time.monotonic())
                )
                process.wait(timeout=wait_for)
            except subprocess.TimeoutExpired:
                pass
        metrics.sample()
        return_code = process.poll()
        for drainer in drainers:
            drainer.join(timeout=2)
        if timed_out:
            status, outcome = "FAILED", "TIMED_OUT"
            message = "execution exceeded timeout_seconds"
        else:
            status = "SUCCEEDED" if return_code == 0 else "FAILED"
            outcome = status
            message = ""
        if cancel_path.exists():
            status, outcome, message = "CANCELLED", "CANCELLED", "execution cancelled"
        ended_at = time.time()
        atomic_json(result_path, {
            "status": status, "outcome": outcome, "return_code": return_code,
            "started_at": started_at, "ended_at": ended_at, "message": message,
            "child_pid": process.pid, "child_started": child_started,
            "output_truncated": bool(stdout_state.get("truncated") or stderr_state.get("truncated")),
            "stdout_total_bytes": int(stdout_state.get("total_bytes") or 0),
            "stderr_total_bytes": int(stderr_state.get("total_bytes") or 0),
            **metrics.result(max(0.0, ended_at - started_at)),
        })
        return 0
    except BaseException as exc:
        if process is not None:
            terminate_tree(process)
        atomic_json(result_path, {
            "status": "FAILED", "outcome": "RUNNER_ERROR", "return_code": None,
            "started_at": started_at, "ended_at": time.time(),
            "message": f"runner_error:{type(exc).__name__}",
        })
        return 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job-dir", required=True)
    args = parser.parse_args()
    return run(Path(args.job_dir).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
