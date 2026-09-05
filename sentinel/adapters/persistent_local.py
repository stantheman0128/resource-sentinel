"""Restart-safe local execution adapter for one-shot scheduler ticks."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .base import AdapterConfigurationError, ExecutionAdapter, JobNotFoundError, TERMINAL_STATUSES, request_dict
from .local import LocalCommandAdapter


JOB_ID = re.compile(r"^[0-9a-f]{32}$")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(temp, path)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None


def process_started_at(pid: int) -> float:
    try:
        import psutil

        return float(psutil.Process(pid).create_time())
    except Exception:
        return 0.0


def pid_alive(pid: int, expected_started: float = 0.0) -> bool:
    if pid <= 0:
        return False
    try:
        import psutil

        process = psutil.Process(pid)
        if expected_started and abs(float(process.create_time()) - expected_started) > 1.0:
            return False
        return process.is_running() and process.status() != psutil.STATUS_ZOMBIE
    except ImportError:
        pass
    except Exception:
        return False
    if expected_started:
        # Without a creation-time-capable backend, fail closed rather than
        # treating a reused PID as the original runner.
        return False
    if os.name == "nt":
        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong)
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        code = ctypes.c_ulong()
        try:
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def terminate_tree(pid: int, expected_started: float = 0.0) -> bool:
    if pid <= 0:
        return False
    if not pid_alive(pid, expected_started):
        return False
    if os.name == "nt":
        subprocess.run(
            ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        try:
            os.kill(pid, 15)
        except ProcessLookupError:
            pass
    return True


class PersistentLocalCommandAdapter(ExecutionAdapter):
    """Run a command through a detached helper and reconcile from disk.

    The request travels once over the helper's stdin.  Job files contain no
    command, prompt, or environment values; credentials are inherited only in
    process memory from ``env_refs`` resolution.
    """

    def __init__(self, state_dir: str | os.PathLike[str], *, max_output_bytes: int = 2 * 1024 * 1024):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.max_output_bytes = int(max_output_bytes)
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")

    def capabilities(self) -> dict[str, Any]:
        return {
            "provider": "local", "adapter": "persistent-local-command",
            "automation_level": "AUTOMATABLE", "restart_safe": True,
            "dispatch_key_is_job_id": True,
            "supports": ["probe", "submit", "status", "cancel", "collect_result", "timeout"],
        }

    def probe(self) -> dict[str, Any]:
        return {"provider": "local", "available": True, "status": "AVAILABLE", "observed_at": time.time()}

    def _dir(self, job_id: str) -> Path:
        if not JOB_ID.fullmatch(str(job_id)):
            raise JobNotFoundError("invalid local job id")
        path = self.state_dir / job_id
        if not path.is_dir():
            raise JobNotFoundError(f"unknown persistent local job: {job_id}")
        return path

    @staticmethod
    def _base(job_id: str, meta: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
        value = {
            "provider": "local", "job_id": job_id,
            "task_id": str(meta.get("task_id") or ""),
            "status": str(status.get("status") or "RUNNING"),
            "outcome": str(status.get("outcome") or status.get("status") or "RUNNING"),
            "started_at": status.get("started_at", meta.get("started_at")),
            "ended_at": status.get("ended_at"),
            "return_code": status.get("return_code"),
            "message": str(status.get("message") or ""),
            "runner_pid": meta.get("runner_pid"), "child_pid": status.get("child_pid"),
        }
        # Keep resource observations in the durable lifecycle response so a
        # restarted orchestrator can build execution profiles from completed
        # jobs.  Missing metrics remain explicit rather than being guessed.
        for name in (
            "metrics_available", "duration_seconds", "peak_working_set_gib",
            "peak_private_gib", "cpu_seconds", "average_cpu_equivalent",
            "peak_cpu_equivalent", "disk_read_bytes", "disk_write_bytes",
            "metric_samples",
            "output_truncated", "stdout_total_bytes", "stderr_total_bytes",
        ):
            if name in status:
                value[name] = status[name]
        return value

    def submit(self, task_payload: Mapping[str, Any], worker: Mapping[str, Any] | Any | None = None) -> dict[str, Any]:
        del worker
        payload = request_dict(task_payload)
        command, shell = LocalCommandAdapter._command(payload)
        environment = LocalCommandAdapter._environment(payload)
        timeout_value = payload.get("timeout_seconds")
        timeout = None if timeout_value is None else float(timeout_value)
        if timeout is not None and timeout <= 0:
            raise AdapterConfigurationError("timeout_seconds must be positive")
        cwd = payload.get("cwd")
        if cwd is not None and not isinstance(cwd, (str, os.PathLike)):
            raise AdapterConfigurationError("cwd must be a path string")
        requested_job_id = str(payload.get("job_id") or "")
        if requested_job_id and not JOB_ID.fullmatch(requested_job_id):
            raise AdapterConfigurationError("job_id must be a 32-character lowercase hex dispatch key")
        job_id = requested_job_id or uuid.uuid4().hex
        job_dir = self.state_dir / job_id
        try:
            job_dir.mkdir()
        except FileExistsError:
            meta = read_json(job_dir / "meta.json") or {}
            requested_task = str(payload.get("task_id") or payload.get("id") or "")
            if meta.get("task_id") and str(meta["task_id"]) != requested_task:
                raise AdapterConfigurationError("dispatch key already belongs to a different task")
            return self.status(job_id)
        request = {
            "command": list(command) if not isinstance(command, str) else command,
            "shell": shell, "cwd": None if cwd is None else os.fspath(cwd),
            "timeout_seconds": timeout,
            "max_output_bytes": self.max_output_bytes,
        }
        options: dict[str, Any] = {}
        if os.name == "nt":
            options["creationflags"] = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                | getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        else:
            options["start_new_session"] = True
        runner = Path(__file__).with_name("local_runner.py")
        process = subprocess.Popen(
            [sys.executable, str(runner), "--job-dir", str(job_dir)],
            env=environment, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, **options,
        )
        assert process.stdin is not None
        runner_started = process_started_at(process.pid)
        try:
            process.stdin.write(json.dumps(request, separators=(",", ":")).encode("utf-8"))
            process.stdin.close()
        except BaseException:
            terminate_tree(process.pid)
            raise
        # The helper is deliberately detached; this Popen object will never be
        # used for lifecycle decisions.  Mark it reaped to avoid a misleading
        # ResourceWarning when a one-shot scheduler process exits.
        process.returncode = 0
        meta = {
            "job_id": job_id, "task_id": str(payload.get("task_id") or payload.get("id") or ""),
            "runner_pid": process.pid, "runner_started": runner_started,
            "started_at": time.time(),
        }
        atomic_json(job_dir / "meta.json", meta)
        return self._base(job_id, meta, {"status": "RUNNING", "outcome": "RUNNING"})

    def status(self, job_id: str) -> dict[str, Any]:
        job_dir = self._dir(job_id)
        meta = read_json(job_dir / "meta.json") or {}
        result = read_json(job_dir / "result.json")
        if result is not None:
            return self._base(job_id, meta, result)
        runtime = read_json(job_dir / "runtime.json") or {}
        runner_pid = int(meta.get("runner_pid") or runtime.get("runner_pid") or 0)
        runner_started = float(meta.get("runner_started") or 0)
        if runner_started > 0 and pid_alive(runner_pid, runner_started):
            return self._base(job_id, meta, {**runtime, "status": "RUNNING", "outcome": "RUNNING"})
        # Process exit and an atomic result rename can be observed in opposite
        # order by antivirus/indexing filters on Windows.  Require two
        # observations separated by a grace interval before declaring LOST.
        missing_path = job_dir / "missing-result.json"
        missing = read_json(missing_path)
        if missing is None:
            atomic_json(missing_path, {"first_observed_at": time.time()})
            return self._base(job_id, meta, {
                **runtime, "status": "RUNNING", "outcome": "RECONCILING",
                "message": "runner exited; waiting for result flush",
            })
        if time.time() - float(missing.get("first_observed_at") or 0) < 2:
            return self._base(job_id, meta, {
                **runtime, "status": "RUNNING", "outcome": "RECONCILING",
                "message": "runner exited; waiting for result flush",
            })
        lost = {
            "status": "FAILED", "outcome": "LOST", "return_code": None,
            "started_at": meta.get("started_at"), "ended_at": time.time(),
            "message": "local runner exited without a result",
        }
        atomic_json(job_dir / "result.json", lost)
        return self._base(job_id, meta, lost)

    def cancel(self, job_id: str) -> dict[str, Any]:
        job_dir = self._dir(job_id)
        current = self.status(job_id)
        if current["status"] in TERMINAL_STATUSES:
            return current
        (job_dir / "cancel.requested").touch()
        meta = read_json(job_dir / "meta.json") or {}
        runtime = read_json(job_dir / "runtime.json") or {}
        child_started = float(runtime.get("child_started") or 0)
        runner_started = float(meta.get("runner_started") or 0)
        if child_started > 0:
            terminate_tree(int(runtime.get("child_pid") or 0), child_started)
        if runner_started > 0:
            terminate_tree(int(meta.get("runner_pid") or 0), runner_started)
        result = {
            "status": "CANCELLED", "outcome": "CANCELLED", "return_code": None,
            "started_at": runtime.get("started_at", meta.get("started_at")),
            "ended_at": time.time(), "message": "execution cancelled",
            "child_pid": runtime.get("child_pid"),
        }
        atomic_json(job_dir / "result.json", result)
        return self._base(job_id, meta, result)

    def collect_result(self, job_id: str, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        result = self.status(job_id)
        if result["status"] not in TERMINAL_STATUSES:
            return {**result, "stdout": None, "stderr": None, "output_truncated": False}
        job_dir = self._dir(job_id)
        output: list[str] = []
        truncated = bool(result.get("output_truncated", False))
        for name in ("stdout.bin", "stderr.bin"):
            try:
                data = (job_dir / name).read_bytes()
            except OSError:
                data = b""
            if len(data) > self.max_output_bytes:
                data = data[: self.max_output_bytes]
                truncated = True
            output.append(data.decode("utf-8", errors="replace"))
        return {**result, "stdout": output[0], "stderr": output[1], "output_truncated": truncated}
