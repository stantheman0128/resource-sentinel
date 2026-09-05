"""Truthful adapter for providers that require a person or UI workflow."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from typing import Any

from .base import ExecutionAdapter, JobNotFoundError, request_dict


class ManualAdapter(ExecutionAdapter):
    """Record manual dispatch without pretending an unsupported API exists."""

    def __init__(self, provider: str, *, instructions: str = "Open the provider UI and dispatch this task."):
        self.provider = provider
        self.instructions = instructions
        self._jobs: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "adapter": "manual",
            "automation_level": "MANUAL",
            "supports": ["record_manual_dispatch", "cancel", "record_result"],
        }

    def probe(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "available": False,
            "status": "AWAITING_MANUAL",
            "observed_at": time.time(),
            "details": {"reason": "no supported programmatic lifecycle configured"},
        }

    def submit(
        self,
        task_payload: Mapping[str, Any],
        worker: Mapping[str, Any] | Any | None = None,
    ) -> dict[str, Any]:
        payload = request_dict(task_payload)
        job_id = uuid.uuid4().hex
        job = {
            "provider": self.provider,
            "job_id": job_id,
            "task_id": str(payload.get("task_id") or payload.get("id") or ""),
            "status": "AWAITING_MANUAL",
            "message": self.instructions,
            "created_at": time.time(),
            "worker_id": self._worker_id(worker),
            "result": None,
        }
        self._jobs[job_id] = job
        return dict(job)

    @staticmethod
    def _worker_id(worker: Mapping[str, Any] | Any | None) -> str | None:
        if isinstance(worker, Mapping):
            value = worker.get("id") or worker.get("worker_id")
        else:
            value = getattr(worker, "id", None)
        return None if value is None else str(value)

    def _job(self, job_id: str) -> dict[str, Any]:
        try:
            return self._jobs[job_id]
        except KeyError as exc:
            raise JobNotFoundError(f"unknown manual job: {job_id}") from exc

    def status(self, job_id: str) -> dict[str, Any]:
        return dict(self._job(job_id))

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        if job["status"] not in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            job.update(status="CANCELLED", message="manual dispatch cancelled", ended_at=time.time())
        return dict(job)

    def record_result(
        self,
        job_id: str,
        result: Any,
        *,
        succeeded: bool = True,
        message: str = "manual result recorded",
    ) -> dict[str, Any]:
        job = self._job(job_id)
        job.update(
            status="SUCCEEDED" if succeeded else "FAILED",
            result=result,
            message=message,
            ended_at=time.time(),
        )
        return dict(job)

    def collect_result(self, job_id: str, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        return dict(self._job(job_id))
