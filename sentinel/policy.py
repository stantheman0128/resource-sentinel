"""Shared instructions used by every Sentinel integration."""
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parents[1] / "docs" / "agent-policy.md"


def agent_policy() -> str:
    return POLICY_PATH.read_text(encoding="utf-8").strip()
