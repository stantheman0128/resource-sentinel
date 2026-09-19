# -*- coding: utf-8 -*-
"""Claude Bash hook backed by the atomic Resource Sentinel coordinator."""

import json
import os
import re
import shlex
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from sentinel.coordinator import Coordinator, ResourceRequest, classify_command
from sentinel.command_classification import is_single_static_command


DATA = Path(os.environ.get("USERPROFILE", "")) / ".resource-sentinel"
STATUS = DATA / "status.json"
CONFIG = DATA / "config.json"
WAITER = PROJECT / "scripts" / "wait-slot.ps1"
ATOMIC_WRAPPER = PROJECT / "scripts" / "invoke-sentinel.ps1"
AGENT_EXES = {"claude.exe", "cursor.exe", "codex.exe", "chatgpt.exe"}


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def my_agent_identity():
    try:
        import psutil

        process = psutil.Process()
        for _ in range(32):
            process = process.parent()
            if process is None:
                break
            if process.name().lower() in AGENT_EXES:
                return process.pid, float(process.create_time())
    except Exception:
        pass
    return os.getppid(), 0.0


def block(message):
    sys.stderr.write(message)
    raise SystemExit(2)


def waiter_hint(position, request_key):
    return (
        f"你在佇列第 {position} 位。【不要結束回合】可先做讀檔、小改等輕量步驟；"
        f"之後執行 powershell -NoProfile -ExecutionPolicy Bypass -File \"{WAITER}\" "
        f"-RequestId {request_key}，timeout 設 600000。顯示 your turn 後立刻重跑原指令。"
    )


def release_outcome(inp):
    """Return the terminal outcome without confusing failed hooks with success."""
    if "--release-failure" in sys.argv:
        return "failure"
    if "--outcome" in sys.argv:
        index = sys.argv.index("--outcome")
        if index + 1 < len(sys.argv):
            outcome = sys.argv[index + 1].strip().lower()
            if outcome in {"success", "failure", "cancelled"}:
                return outcome
    event_name = str(inp.get("hook_event_name") or inp.get("hookEventName") or "")
    return "failure" if event_name == "PostToolUseFailure" else "success"


def is_atomic_wrapper(command):
    """Recognize only a direct invocation of the reservation-owning wrapper."""
    if not is_single_static_command(command):
        return False
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        return False
    tokens = [token.strip('"\'') for token in tokens]
    if tokens and tokens[0] == "&":
        tokens = tokens[1:]
    if not tokens or Path(tokens[0]).name.lower() not in {
        "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    }:
        return False
    if any(token in {";", "&&", "||", "|"} for token in tokens):
        return False
    lowered = [token.lower() for token in tokens]
    file_index = 1
    while file_index < len(tokens):
        option = lowered[file_index]
        if option == "-file":
            break
        if option in {"-noprofile", "-nologo", "-noninteractive", "-sta", "-mta"}:
            file_index += 1
        elif option == "-executionpolicy":
            if file_index + 1 >= len(tokens) or lowered[file_index + 1] not in {
                "bypass", "allsigned", "remotesigned", "restricted", "unrestricted", "undefined",
            }:
                return False
            file_index += 2
        elif option == "-windowstyle":
            if file_index + 1 >= len(tokens) or lowered[file_index + 1] not in {
                "hidden", "normal", "minimized", "maximized",
            }:
                return False
            file_index += 2
        else:
            # -Command/-EncodedCommand (including abbreviations), positional
            # scripts and unknown host switches cannot be laundered by a later
            # -File token that is merely part of their payload.
            return False
    if file_index + 1 >= len(tokens):
        return False
    try:
        candidate = Path(tokens[file_index + 1]).resolve(strict=False)
        expected = ATOMIC_WRAPPER.resolve(strict=False)
    except (OSError, ValueError):
        return False
    return os.path.normcase(str(candidate)) == os.path.normcase(str(expected))


def main():
    release_mode = "--release" in sys.argv or "--release-failure" in sys.argv
    try:
        inp = json.load(sys.stdin)
    except Exception:
        inp = {}
    if inp.get("tool_name") and inp.get("tool_name") != "Bash":
        return

    owner_pid, owner_started = my_agent_identity()
    command = ((inp.get("tool_input") or {}).get("command") or "")
    tool_use_id = str(inp.get("tool_use_id") or "")

    if release_mode:
        # Never let a malformed hook event release every reservation for an agent.
        if not tool_use_id and not command:
            return
        Coordinator(DATA).release(
            owner_pid=owner_pid,
            tool_use_id=tool_use_id,
            command=command,
            outcome=release_outcome(inp),
        )
        return

    config = load(CONFIG)
    if is_atomic_wrapper(command):
        # The wrapper performs the same atomic admission itself. Reserving in
        # both layers would make the inner request wait on the outer slot.
        return
    resource_class = classify_command(command, heavy_patterns=config.get("heavy_patterns"))
    if resource_class == "LIGHT":
        return
    coordinator = Coordinator(DATA)

    cwd = inp.get("cwd") or os.getcwd()
    request = ResourceRequest(
        owner_pid=owner_pid,
        owner_started=owner_started,
        repo=os.path.basename(cwd.rstrip("\\/")) or "unknown",
        command=command,
        resource_class=resource_class,
        priority=str(inp.get("sentinel_priority") or os.environ.get("SENTINEL_PRIORITY") or config.get("default_priority") or "P2"),
        tool_use_id=tool_use_id,
    )
    result = coordinator.admit(request, load(STATUS), config=config)
    if result["allowed"]:
        return
    reason = result.get("reason", "capacity")
    block(
        f"[sentinel-gate] {reason}；{resource_class} 工作尚未取得本機 reservation。"
        + waiter_hint(result.get("position", 1), result["request_key"])
    )


if __name__ == "__main__":
    main()
