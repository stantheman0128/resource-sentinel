"""Config-driven HTTP adapter skeleton with dependency-injected transport.

This module intentionally ships with no network transport.  Supplying an
explicit test or production transport is required before an HTTP request can
occur, which keeps provider stubs honest and makes all behavior unit-testable.
"""

from __future__ import annotations

import os
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import quote, urljoin

from .base import (
    AdapterConfigurationError,
    ExecutionAdapter,
    JobNotFoundError,
    request_dict,
    validate_env_name,
)


@dataclass(frozen=True)
class HttpEndpoint:
    method: str
    path: str

    def __post_init__(self) -> None:
        method = self.method.upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise AdapterConfigurationError(f"unsupported HTTP method: {self.method}")
        if not self.path:
            raise AdapterConfigurationError("endpoint path is required")
        object.__setattr__(self, "method", method)


@dataclass(frozen=True)
class HttpAdapterConfig:
    provider: str
    base_url: str
    endpoints: Mapping[str, HttpEndpoint | Mapping[str, Any]]
    credential_env_var: str | None = None
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer"
    timeout_seconds: float = 30.0
    automation_level: str = "PARTIAL"
    capability_data: Mapping[str, Any] = field(default_factory=dict)
    id_field: str = "id"
    status_field: str = "status"
    result_field: str = "result"
    message_field: str = "message"
    status_map: Mapping[str, str] = field(default_factory=dict)
    idempotency_header: str = "Idempotency-Key"

    def __post_init__(self) -> None:
        if not self.provider:
            raise AdapterConfigurationError("provider is required")
        if not self.base_url.startswith("https://"):
            raise AdapterConfigurationError("HTTP provider base_url must use https://")
        if self.credential_env_var is not None:
            validate_env_name(self.credential_env_var, field="credential_env_var")
        if self.timeout_seconds <= 0:
            raise AdapterConfigurationError("timeout_seconds must be positive")
        normalized: dict[str, HttpEndpoint] = {}
        for operation, endpoint in self.endpoints.items():
            normalized[operation] = (
                endpoint if isinstance(endpoint, HttpEndpoint) else HttpEndpoint(**dict(endpoint))
            )
        object.__setattr__(self, "endpoints", normalized)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "HttpAdapterConfig":
        return cls(**dict(value))


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    data: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)


class HttpTransport(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: Mapping[str, str],
        json_body: Any,
        timeout: float,
    ) -> HttpResponse: ...


class ConfiguredHttpAdapter(ExecutionAdapter):
    """Generic provider lifecycle mapped by declarative endpoints.

    No urllib/requests implementation is included.  With ``transport=None``
    submissions become ``AWAITING_MANUAL`` and no external operation occurs.
    """

    DEFAULT_STATUS_MAP = {
        "queued": "QUEUED",
        "pending": "QUEUED",
        "running": "RUNNING",
        "in_progress": "RUNNING",
        "succeeded": "SUCCEEDED",
        "success": "SUCCEEDED",
        "completed": "SUCCEEDED",
        "failed": "FAILED",
        "error": "FAILED",
        "cancelled": "CANCELLED",
        "canceled": "CANCELLED",
        "awaiting_manual": "AWAITING_MANUAL",
    }

    def __init__(self, config: HttpAdapterConfig, *, transport: HttpTransport | None = None):
        self.config = config
        self.transport = transport
        self._jobs: dict[str, dict[str, Any]] = {}

    def capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.config.provider,
            "adapter": "configured-http",
            "automation_level": self.config.automation_level,
            "supports": sorted(self.config.endpoints),
            "transport_configured": self.transport is not None,
            "credential_env_var": self.config.credential_env_var,
            "capabilities": dict(self.config.capability_data),
        }

    def _headers(self) -> dict[str, str] | None:
        variable = self.config.credential_env_var
        if variable is None:
            return {"Accept": "application/json", "Content-Type": "application/json"}
        secret = os.environ.get(variable)
        if secret is None:
            return None
        value = f"{self.config.auth_prefix} {secret}".strip()
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            self.config.auth_header: value,
        }

    def _manual_reason(self) -> str | None:
        if self.transport is None:
            return "transport_not_configured"
        if self._headers() is None:
            return f"credential_environment_variable_missing:{self.config.credential_env_var}"
        return None

    @staticmethod
    def _field(data: Any, dotted_name: str, default: Any = None) -> Any:
        current = data
        for part in dotted_name.split("."):
            if not isinstance(current, Mapping) or part not in current:
                return default
            current = current[part]
        return current

    def _mapped_status(self, external: Any, *, default: str) -> str:
        key = str(external or "").strip().lower()
        custom = {str(k).lower(): str(v).upper() for k, v in self.config.status_map.items()}
        return custom.get(key, self.DEFAULT_STATUS_MAP.get(key, default))

    def _url(self, endpoint: HttpEndpoint, job_id: str | None = None) -> str:
        path = endpoint.path
        if "{job_id}" in path:
            if job_id is None:
                raise AdapterConfigurationError("job_id is required for this endpoint")
            path = path.replace("{job_id}", quote(job_id, safe=""))
        return urljoin(self.config.base_url.rstrip("/") + "/", path.lstrip("/"))

    def _request(self, operation: str, *, job_id: str | None = None, body: Any = None) -> HttpResponse:
        endpoint = self.config.endpoints.get(operation)
        if endpoint is None:
            raise AdapterConfigurationError(f"provider endpoint is not configured: {operation}")
        headers = self._headers()
        if self.transport is None or headers is None:
            raise AdapterConfigurationError(self._manual_reason() or "provider is not configured")
        if operation == "submit" and isinstance(body, Mapping) and body.get("job_id"):
            headers = {**headers, self.config.idempotency_header: str(body["job_id"])}
        return self.transport.request(
            method=endpoint.method,
            url=self._url(endpoint, job_id),
            headers=headers,
            json_body=body,
            timeout=self.config.timeout_seconds,
        )

    @staticmethod
    def _response_data(response: HttpResponse) -> Any:
        return response.data if response.data is not None else {}

    def probe(self) -> dict[str, Any]:
        now = time.time()
        reason = self._manual_reason()
        if reason is not None:
            return {
                "provider": self.config.provider,
                "available": False,
                "status": "AWAITING_MANUAL",
                "observed_at": now,
                "details": {"reason": reason},
            }
        if "probe" not in self.config.endpoints:
            return {
                "provider": self.config.provider,
                "available": False,
                "status": "AWAITING_MANUAL",
                "observed_at": now,
                "details": {"reason": "probe_endpoint_not_configured"},
            }
        try:
            response = self._request("probe")
            available = 200 <= response.status_code < 300
            return {
                "provider": self.config.provider,
                "available": available,
                "status": "AVAILABLE" if available else "UNAVAILABLE",
                "observed_at": now,
                "details": {"http_status": response.status_code},
            }
        except Exception as exc:
            return {
                "provider": self.config.provider,
                "available": False,
                "status": "UNAVAILABLE",
                "observed_at": now,
                "details": {"error_type": type(exc).__name__},
            }

    def _manual_job(self, payload: dict[str, Any], reason: str) -> dict[str, Any]:
        job_id = uuid.uuid4().hex
        job = {
            "provider": self.config.provider,
            "job_id": job_id,
            "task_id": str(payload.get("task_id") or payload.get("id") or ""),
            "status": "AWAITING_MANUAL",
            "message": reason,
            "external_job_id": None,
            "created_at": time.time(),
            "result": None,
        }
        self._jobs[job_id] = job
        return dict(job)

    def submit(
        self,
        task_payload: Mapping[str, Any],
        worker: Mapping[str, Any] | Any | None = None,
    ) -> dict[str, Any]:
        del worker
        payload = request_dict(task_payload)
        reason = self._manual_reason()
        if reason is not None:
            return self._manual_job(payload, reason)
        if "submit" not in self.config.endpoints:
            return self._manual_job(payload, "submit_endpoint_not_configured")
        try:
            response = self._request("submit", body=payload)
        except Exception as exc:
            return self._manual_job(payload, f"submit_error:{type(exc).__name__}")
        data = self._response_data(response)
        if not 200 <= response.status_code < 300:
            return self._manual_job(payload, f"submit_http_status:{response.status_code}")
        external_id = self._field(data, self.config.id_field)
        if external_id is None:
            return self._manual_job(payload, "submit_response_missing_job_id")
        job_id = str(external_id)
        status = self._mapped_status(
            self._field(data, self.config.status_field), default="QUEUED"
        )
        job = {
            "provider": self.config.provider,
            "job_id": job_id,
            "external_job_id": job_id,
            "task_id": str(payload.get("task_id") or payload.get("id") or ""),
            "status": status,
            "message": str(self._field(data, self.config.message_field, "") or ""),
            "created_at": time.time(),
            "result": self._field(data, self.config.result_field),
        }
        self._jobs[job_id] = job
        return dict(job)

    def _job(self, job_id: str) -> dict[str, Any]:
        # Provider job ids are durable authority.  Reconstructing this small
        # cache makes one-shot scheduler processes restart-safe.
        if not job_id:
            raise JobNotFoundError(f"missing {self.config.provider} job id")
        if job_id not in self._jobs:
            self._jobs[job_id] = {
                "provider": self.config.provider,
                "job_id": job_id,
                "external_job_id": job_id,
                "task_id": "",
                "status": "QUEUED",
                "message": "reconstructed from durable external job id",
                "created_at": time.time(),
                "result": None,
            }
        return self._jobs[job_id]

    def status(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        if job["status"] in {"AWAITING_MANUAL", "CANCELLED"}:
            return dict(job)
        if "status" not in self.config.endpoints:
            job.update(status="AWAITING_MANUAL", message="status_endpoint_not_configured")
            return dict(job)
        try:
            response = self._request("status", job_id=job["external_job_id"])
            data = self._response_data(response)
            if not 200 <= response.status_code < 300:
                job.update(status="FAILED", message=f"status_http_status:{response.status_code}")
            else:
                job["status"] = self._mapped_status(
                    self._field(data, self.config.status_field), default=job["status"]
                )
                job["message"] = str(
                    self._field(data, self.config.message_field, job.get("message", "")) or ""
                )
                result = self._field(data, self.config.result_field)
                if result is not None:
                    job["result"] = result
        except Exception as exc:
            job.update(status="FAILED", message=f"status_error:{type(exc).__name__}")
        return dict(job)

    def cancel(self, job_id: str) -> dict[str, Any]:
        job = self._job(job_id)
        if job["status"] in {"SUCCEEDED", "FAILED", "CANCELLED"}:
            return dict(job)
        if "cancel" not in self.config.endpoints or self.transport is None:
            job.update(status="AWAITING_MANUAL", message="cancel_requires_manual_action")
            return dict(job)
        try:
            response = self._request("cancel", job_id=job["external_job_id"])
            if 200 <= response.status_code < 300:
                job.update(status="CANCELLED", message="")
            else:
                job.update(status="FAILED", message=f"cancel_http_status:{response.status_code}")
        except Exception as exc:
            job.update(status="FAILED", message=f"cancel_error:{type(exc).__name__}")
        return dict(job)

    def collect_result(self, job_id: str, **kwargs: Any) -> dict[str, Any]:
        del kwargs
        job = self._job(job_id)
        if job["status"] == "AWAITING_MANUAL":
            return dict(job)
        if "collect_result" not in self.config.endpoints:
            if job.get("result") is None:
                job["message"] = "result_endpoint_not_configured"
            return dict(job)
        try:
            response = self._request("collect_result", job_id=job["external_job_id"])
            data = self._response_data(response)
            if 200 <= response.status_code < 300:
                job["result"] = self._field(data, self.config.result_field, data)
                job["status"] = self._mapped_status(
                    self._field(data, self.config.status_field), default=job["status"]
                )
                job["message"] = str(
                    self._field(data, self.config.message_field, job.get("message", "")) or ""
                )
            else:
                job.update(status="FAILED", message=f"result_http_status:{response.status_code}")
        except Exception as exc:
            job.update(status="FAILED", message=f"result_error:{type(exc).__name__}")
        return dict(job)
