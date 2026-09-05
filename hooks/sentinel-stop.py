# -*- coding: utf-8 -*-
# Resource Sentinel - Stop hook（Stan 2026-08-13 明確核可）
# Session 還在重活佇列裡卻想結束回合 -> 擋回去，命令它跑 waiter 等輪到。
# 防無限迴圈：同一 session 最多擋 3 次，之後移出佇列放行。
import json
import os
import sys
import time
import uuid
from pathlib import Path

PROJECT = Path(r"C:\Users\stans\Projects\resource-sentinel")
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from sentinel.coordinator import Coordinator

DATA = os.path.join(os.environ.get("USERPROFILE", ""), ".resource-sentinel")
BLOCKS = os.path.join(DATA, "stop-blocks.json")
WAITER = ("powershell -NoProfile -ExecutionPolicy Bypass -File "
          "\"C:\\Users\\stans\\Projects\\resource-sentinel\\scripts\\wait-slot.ps1\"")
AGENT_EXES = {"claude.exe", "cursor.exe", "codex.exe"}
MAX_BLOCKS = 3


def load(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def save(path, obj):
    tmp = path + "." + str(os.getpid()) + "." + uuid.uuid4().hex + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        json.dump(obj, f, ensure_ascii=True)
    os.replace(tmp, path)


def my_agent_pid():
    try:
        import psutil
        p = psutil.Process()
        for _ in range(16):
            p = p.parent()
            if p is None:
                break
            if p.name().lower() in AGENT_EXES:
                return p.pid
    except Exception:
        pass
    return os.getppid()


def waiter_command(request_key):
    return f"{WAITER} -RequestId {request_key}"


def main():
    try:
        json.load(sys.stdin)
    except Exception:
        pass

    me = my_agent_pid()
    coordinator = Coordinator(DATA)
    queued = coordinator.queued_for_owner(me)
    if not queued:
        return  # 沒人排隊，正常結束
    request_key = str(queued[0].get("request_key") or "")
    if not request_key:
        return  # 無法精準指定請求時 fail open，不廣域取消。
    now = time.time()

    blocks = load(BLOCKS) or {}
    key = f"{me}:{request_key}"
    n = int(blocks.get(key, {}).get("n", 0)) + 1

    if n > MAX_BLOCKS:
        # 只取消本次提醒的請求，不影響同 session 其他工作。
        coordinator.cancel_queued(owner_pid=me, request_key=request_key)
        blocks.pop(key, None)
        blocks.pop(str(me), None)  # 清掉舊版 owner 級計數。
        save(BLOCKS, blocks)
        return

    blocks[key] = {"n": n, "ts": now}
    for k in list(blocks.keys()):
        if now - blocks[k].get("ts", 0) > 86400:
            del blocks[k]
    save(BLOCKS, blocks)

    print(json.dumps({
        "decision": "block",
        "reason": (
            "[sentinel] 你還在重活佇列裡（第 %d 次提醒，最多 %d 次後自動放行）。"
            "現在執行 %s （Bash timeout 設 600000），它會等到輪到你才返回；"
            "返回後立刻重跑原本被擋的指令。若你決定放棄這個重活，"
            "直接向使用者說明放棄原因即可，第 %d 次之後就不會再攔你。"
            % (n, MAX_BLOCKS, waiter_command(request_key), MAX_BLOCKS)
        ),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
