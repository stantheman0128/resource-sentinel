"""Local subprocess adapter with explicit shell and bounded execution."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .base import (
    AdapterConfigurationError,
    ExecutionAdapter,
    JobNotFoundError,
    TERMINAL_STATUSES,
    request_dict,
    validate_env_name,
)


class _BoundedCapture:
    def __init__(self, limit: int):
        self.limit = limit
        self.data = bytearray()
        self.total_bytes = 0
        self.truncated = False
        self.lock = threading.Lock()

    def drain(self, stream: Any) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    break
                with self.lock:
                    self.total_bytes += len(chunk)
                    if len(self.data) < self.limit:
                        self.data.extend(chunk[: self.limit - len(self.data)])
                    self.truncated = self.total_bytes > len(self.data)
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass

    def text(self) -> str:
        with self.lock:
            return bytes(self.data).decode("utf-8", errors="replace")


@dataclass
class _LocalRun:
    job_id: str
    task_id: str
    process: subprocess.Popen[bytes]
    stdout_capture: _BoundedCapture
    stderr_capture: _BoundedCapture
    started_at: float
    timeout_seconds: float | None
    status: str = "RUNNING"
    outcome: str = "RUNNING"
    ended_at: float | None = None
    return_code: int | None = None
    message: str = ""
    timer: threading.Timer | None = None
    stdout_thread: threading.Thread | None = field(default=None, repr=False)
    stderr_thread: threading.Thread | None = field(default=None, repr=False)
    output_cache: tuple[str, str, bool] | None = field(default=None, repr=False)


class LocalCommandAdapter(ExecutionAdapter):
    """Run commands on the current machine without implicit shell parsing.

    The default request form is ``{"argv": ["program", "arg"]}``.  A shell
    is used only when both ``shell: true`` and a string ``command`` are present.
    Child environment secrets use ``env_refs`` as
    ``{"CHILD_NAME": "SOURCE_ENV_NAME"}``; resolved values are never retained
    in adapter state or returned results.
    """

    def __init__(self, *, provider: str = "local", max_output_bytes: int = 2 * 1024 * 1024):
        self.provider = provider
        self.max_output_bytes = int(max_output_bytes)
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self._runs: dict[str, _LocalRun] = {}
        self._lock = threading.RLock()

    def capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "adapter": "local-command",
            "automation_level": "AUTOMATABLE",
            "supports": ["probe", "submit", "status", "cancel", "collect_result", "timeout"],
            "safe_argv_default": True,
            "shell_requires_explicit_opt_in": True,
        }

    def probe(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "available": True,
            "status": "AVAILABLE",
            "observed_at": time.time(),
            "details": {"platform": os.name},
        }

    @staticmethod
    def _command(payload: dict[str, Any]) -> tuple[Sequence[str] | str, bool]:
        shell = bool(payload.get("shell", False))
        if shell:
            command = payload.get("command")
            if not isinstance(command, str) or not command.strip():
                raise AdapterConfigurationError(
                    "shell execution requires a non-empty string command and shell=true"
                )
            return command, True

        argv = payload.get("argv", payload.get("command"))
        if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not argv:
            raise AdapterConfigurationError(
                "local execution requires a non-empty argv sequence; strings require shell=true"
            )
        if not all(isinstance(part, str) and part for part in argv):
            raise AdapterConfigurationError("every argv item must be a non-empty string")
        return tuple(argv), False

    @staticmethod
    def _environment(payload: dict[str, Any]) -> dict[str, str]:
        if payload.get("inherit_all_env"):
            env = os.environ.copy()
        else:
            # Keep only process-launch essentials. Credentials and arbitrary
            # caller state cross the boundary solely through explicit refs.
            allowed = {
                "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC",
                "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE", "HOMEDRIVE",
                "HOMEPATH", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA",
                "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES",
                "USERNAME", "USER", "SHELL", "LANG", "LC_ALL", "TERM",
                "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
            }
            env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        refs = payload.get("env_refs") or {}
        if not isinstance(refs, Mapping):
            raise AdapterConfigurationError("env_refs must map child names to source environment names")
        for child_name, source_name in refs.items():
            child = validate_env_name(child_name, field="env_refs key")
            source = validate_env_name(source_name, field=f"env_refs[{child}]")
            if source not in os.environ:
                raise AdapterConfigurationError(f"required environment variable is missing: {source}")
            env[child] = os.environ[source]
        return env

    def submit(
        self,
        task_payload: Mapping[str, Any],
        worker: Mapping[str, Any] | Any | None = None,
    ) -> dict[str, Any]:
        del worker
        payload = request_dict(task_payload)
        command, shell = self._command(payload)
        timeout_value = payload.get("timeout_seconds")
        timeout_seconds = None if timeout_value is None else float(timeout_value)
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise AdapterConfigurationError("timeout_seconds must be positive")
        cwd = payload.get("cwd")
        if cwd is not None and not isinstance(cwd, (str, os.PathLike)):
            raise AdapterConfigurationError("cwd must be a path string")
        env = self._environment(payload)
        popen_options: dict[str, Any] = {}
        if os.name == "nt":
            popen_options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            popen_options["start_new_session"] = True
        try:
            process = subprocess.Popen(
                command,
                shell=shell,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                **popen_options,
            )
        except Exception:
            raise

        now = time.time()
        stdout_capture = _BoundedCapture(self.max_output_bytes)
        stderr_capture = _BoundedCapture(self.max_output_bytes)
        run = _LocalRun(
            job_id=uuid.uuid4().hex,
            task_id=str(payload.get("task_id") or payload.get("id") or ""),
            process=process,
            stdout_capture=stdout_capture,
            stderr_capture=stderr_capture,
            started_at=now,
            timeout_seconds=timeout_seconds,
        )
        assert process.stdout is not None and process.stderr is not None
        run.stdout_thread = threading.Thread(
            target=stdout_capture.drain, args=(process.stdout,), daemon=True
        )
        run.stderr_thread = threading.Thread(
            target=stderr_capture.drain, args=(process.stderr,), daemon=True
        )
        run.stdout_thread.start()
        run.stderr_thread.start()
        with self._lock:
            self._runs[run.job_id] = run
            if timeout_seconds is not None:
                run.timer = threading.Timer(timeout_seconds, self._expire, args=(run.job_id,))
                run.timer.daemon = True
                run.timer.start()
        return self._status_dict(run)

    def _run(self, job_id: str) -> _LocalRun:
        try:
            return self._runs[job_id]
        except KeyError as exc:
            raise JobNotFoundError(f"unknown local job: {job_id}") from exc

    @staticmethod
    def _stop_process(run: _LocalRun) -> None:
        if run.process.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(
                ["taskkill.exe", "/PID", str(run.process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, check=False,
            )
        else:
            try:
                os.killpg(run.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            run.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                run.process.kill()
            else:
                try:
                    os.killpg(run.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            run.process.wait(timeout=2)

    def _expire(self, job_id: str) -> None:
        with self._lock:
            run = self._runs.get(job_id)
            if run is None or run.status in TERMINAL_STATUSES:
                return
            if run.process.poll() is not None:
                self._refresh(run)
                return
            self._stop_process(run)
            run.return_code = run.process.poll()
            run.status = "FAILED"
            run.outcome = "TIMED_OUT"
            run.message = "execution exceeded timeout_seconds"
            run.ended_at = time.time()
            self._output(run)

    def _refresh(self, run: _LocalRun) -> None:
        if run.status in TERMINAL_STATUSES:
            return
        code = run.process.poll()
        if code is None:
            return
        run.return_code = code
        run.status = "SUCCEEDED" if code == 0 else "FAILED"
        run.outcome = run.status
        run.ended_at = time.time()
        if run.timer is not None:
            run.timer.cancel()
        self._output(run)

    def _status_dict(self, run: _LocalRun) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "job_id": run.job_id,
            "task_id": run.task_id,
            "status": run.status,
            "outcome": run.outcome,
            "started_at": run.started_at,
            "ended_at": run.ended_at,
            "return_code": run.return_code,
            "message": run.message,
        }

    def status(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            run = self._run(job_id)
            self._refresh(run)
            return self._status_dict(run)

    def cancel(self, job_id: str) -> dict[str, Any]:
        with self._lock:
            run = self._run(job_id)
            self._refresh(run)
            if run.status not in TERMINAL_STATUSES:
                self._stop_process(run)
                run.return_code = run.process.poll()
                run.status = "CANCELLED"
                run.outcome = "CANCELLED"
                run.ended_at = time.time()
                if run.timer is not None:
                    run.timer.cancel()
                self._output(run)
            return self._status_dict(run)

    def _output(self, run: _LocalRun) -> tuple[str, str, bool]:
        if run.output_cache is not None:
            return run.output_cache
        if run.status not in TERMINAL_STATUSES:
            return "", "", False
        for thread in (run.stdout_thread, run.stderr_thread):
            if thread is not None:
                thread.join(timeout=2)
        run.output_cache = (
            run.stdout_capture.text(),
            run.stderr_capture.text(),
            bool(run.stdout_capture.truncated or run.stderr_capture.truncated),
        )
        return run.output_cache

    def collect_result(
        self,
        job_id: str,
        *,
        wait: bool = False,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        run = self._run(job_id)
        if wait and run.status not in TERMINAL_STATUSES:
            try:
                run.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                pass
        with self._lock:
            self._refresh(run)
            result = self._status_dict(run)
            stdout, stderr, truncated = self._output(run)
            result.update(
                stdout=stdout if run.status in TERMINAL_STATUSES else None,
                stderr=stderr if run.status in TERMINAL_STATUSES else None,
                output_truncated=truncated,
            )
            return result
