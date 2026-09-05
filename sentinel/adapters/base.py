"""Provider-neutral execution adapter contracts.

Public adapter methods deliberately return plain dictionaries so the
orchestrator can persist and exchange them without knowing provider classes.
Secrets are represented only by environment-variable *names*.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any


TERMINAL_STATUSES = {"SUCCEEDED", "FAILED", "CANCELLED"}
KNOWN_STATUSES = {
    "QUEUED",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "AWAITING_MANUAL",
}
ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class AdapterError(RuntimeError):
    """Base exception for adapter configuration and lifecycle failures."""


class JobNotFoundError(AdapterError):
    """Raised when an adapter does not know the requested job id."""


class AdapterConfigurationError(AdapterError):
    """Raised before dispatch when an adapter configuration is unsafe."""


def request_dict(task_payload: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Return a shallow request mapping without accepting arbitrary objects."""

    if isinstance(task_payload, Mapping):
        return dict(task_payload)
    raise TypeError("task_payload must be a mapping")


def validate_env_name(name: str, *, field: str) -> str:
    if not isinstance(name, str) or not ENVIRONMENT_NAME.fullmatch(name):
        raise AdapterConfigurationError(f"{field} must be an environment-variable name")
    return name


class ExecutionAdapter(ABC):
    """Small synchronous interface shared by local and remote workers.

    ``submit`` starts work but does not wait for completion.  ``status``,
    ``cancel`` and ``collect_result`` receive the ``job_id`` returned by
    ``submit``.  ``worker`` is optional routing context and adapters may ignore
    it; accepting it keeps the interface compatible with the maintainer.
    """

    @abstractmethod
    def capabilities(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def probe(self) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def submit(
        self,
        task_payload: Mapping[str, Any],
        worker: Mapping[str, Any] | Any | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def status(self, job_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def cancel(self, job_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def collect_result(self, job_id: str, **kwargs: Any) -> dict[str, Any]:
        raise NotImplementedError
