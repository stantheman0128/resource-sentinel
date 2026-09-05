"""Execution adapters for local, manual, and configured provider workers."""

from .base import (
    AdapterConfigurationError,
    AdapterError,
    ExecutionAdapter,
    JobNotFoundError,
    KNOWN_STATUSES,
    TERMINAL_STATUSES,
)
from .http import (
    ConfiguredHttpAdapter,
    HttpAdapterConfig,
    HttpEndpoint,
    HttpResponse,
    HttpTransport,
)
from .local import LocalCommandAdapter
from .persistent_local import PersistentLocalCommandAdapter
from .manual import ManualAdapter


def default_adapters(state_dir=None):
    """Return safe defaults without enabling any unverified cloud API.

    Provider-specific adapters intentionally remain manual until the caller
    injects a configured HTTP transport (or another supported SDK adapter).
    This prevents a registry entry from being mistaken for working API access.
    """

    return {
        "local": (
            PersistentLocalCommandAdapter(state_dir)
            if state_dir is not None else LocalCommandAdapter()
        ),
        "manual": ManualAdapter("manual-provider"),
        "github_actions": ManualAdapter(
            "github-actions", instructions="Configure a GitHub Actions adapter or dispatch the workflow manually."
        ),
        "cursor": ManualAdapter(
            "cursor", instructions="Configure the Cursor Background Agents API or dispatch in Cursor manually."
        ),
        "claude_remote": ManualAdapter(
            "claude-remote", instructions="Configure a supported Claude remote adapter or dispatch manually."
        ),
        "chatgpt_work": ManualAdapter(
            "chatgpt-work", instructions="Trigger and monitor the Workspace Agent manually; result retrieval may remain manual."
        ),
        "codex_cloud": ManualAdapter(
            "codex-cloud", instructions="Configure a supported Codex Cloud lifecycle adapter or dispatch manually."
        ),
        "grok": ManualAdapter(
            "grok", instructions="Dispatch in the Grok Bot cloud computer and record the result manually."
        ),
    }

__all__ = [
    "AdapterConfigurationError",
    "AdapterError",
    "ConfiguredHttpAdapter",
    "default_adapters",
    "ExecutionAdapter",
    "HttpAdapterConfig",
    "HttpEndpoint",
    "HttpResponse",
    "HttpTransport",
    "JobNotFoundError",
    "KNOWN_STATUSES",
    "LocalCommandAdapter",
    "PersistentLocalCommandAdapter",
    "ManualAdapter",
    "TERMINAL_STATUSES",
]
