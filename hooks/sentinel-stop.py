# -*- coding: utf-8 -*-
"""Bounded Stop reminders; reminders never cancel queued work."""

import json
import math
import os
import re
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from sentinel.coordinator import Coordinator

DATA = Path(os.environ.get("USERPROFILE", "")) / ".resource-sentinel"
BLOCKS = DATA / "stop-blocks.json"
CONTROL = PROJECT / "scripts" / "sentinelctl.py"
AGENT_EXES = {"claude.exe", "cursor.exe", "codex.exe", "chatgpt.exe"}
MAX_BLOCKS = 3


def load(path):
    """Read the old counters for migration; SQLite owns new counters."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return {}
        value = json.loads(raw.decode("utf-8-sig"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def my_agent_identity():
    """Resolve an actual ancestor and its birth time, never a hook-supplied PID."""
    try:
        import psutil

        process = psutil.Process().parent()
        fallback = None
        for _ in range(32):
            if process is None:
                break
            birth = float(process.create_time())
            if not math.isfinite(birth) or birth <= 0:
                return None
            identity = (process.pid, birth)
            if fallback is None:
                fallback = identity
            if process.name().lower() in AGENT_EXES:
                return identity
            process = process.parent()
        return fallback
    except Exception:
        # Uncertain identity must not select another session's queue or counters.
        return None


def request_command(verb, request_key, owner_pid):
    # Real request keys are SHA-256 hashes. Keep compatibility with safe test/
    # legacy identifiers without interpolating command text or shell syntax.
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request_key):
        raise ValueError("unsafe request identifier")
    if verb not in {"wait-existing", "cancel"}:
        raise ValueError("unsupported queue operation")
    command = (
        f'py "{CONTROL}" {verb} --request-key {request_key} '
        f"--owner-pid {int(owner_pid)}"
    )
    if verb == "wait-existing":
        command += (
            f' --status-file "{DATA / "status.json"}"'
            f' --config-file "{DATA / "config.json"}" --timeout-sec 480'
        )
    return command


def main():
    try:
        json.load(sys.stdin)
    except Exception:
        pass

    identity = my_agent_identity()
    if identity is None:
        return
    owner_pid, owner_started = identity
    try:
        reminder = Coordinator(DATA).claim_stop_reminder(
            owner_pid=owner_pid,
            owner_started=owner_started,
            max_reminders=MAX_BLOCKS,
            legacy_blocks=load(BLOCKS),
        )
        if not reminder["should_block"]:
            return
        request_key = str(reminder["request_key"])
        wait_command = request_command("wait-existing", request_key, owner_pid)
        cancel_command = request_command("cancel", request_key, owner_pid)
        queued_count = int(reminder["queued_count"])
        count = int(reminder["reminder_count"])
    except Exception:
        # This hook only reminds. Failure cannot grant admission, cancel work,
        # release reservations, or alter exemption leases.
        return

    print(json.dumps({
        "decision": "block",
        "reason": (
            f"[sentinel] 此 session 尚有 {queued_count} 筆排隊請求；"
            f"整個排隊期間共用第 {count}/{MAX_BLOCKS} 次提醒。"
            f"先處理這一筆：{wait_command}（Bash timeout 設 600000），"
            "取得 reservation 後重跑對應原指令；等待期間可做獨立輕量工作。"
            f"若確定放棄這筆請求，執行 {cancel_command}，並向使用者說明原因。"
            "cancel 只取消這筆本人排隊請求。提醒次數用完只停止攔截 Stop，"
            "不會自動取消任何請求，也不表示工作已完成。"
        ),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
