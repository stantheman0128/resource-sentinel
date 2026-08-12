# -*- coding: utf-8 -*-
# Resource Sentinel - Stop hook（Stan 2026-08-13 明確核可）
# Session 還在重活佇列裡卻想結束回合 -> 擋回去，命令它跑 waiter 等輪到。
# 防無限迴圈：同一 session 最多擋 3 次，之後移出佇列放行。
import json
import os
import sys
import time

DATA = os.path.join(os.environ.get("USERPROFILE", ""), ".resource-sentinel")
QUEUE = os.path.join(DATA, "queue.json")
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
    tmp = path + ".tmp"
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


def main():
    try:
        json.load(sys.stdin)
    except Exception:
        pass

    qdoc = load(QUEUE)
    if not qdoc or not qdoc.get("q"):
        return  # 沒人排隊，正常結束
    me = my_agent_pid()
    now = time.time()
    entry = None
    for e in qdoc["q"]:
        if e.get("pid") == me and now - e.get("ts", 0) <= 600:
            entry = e
            break
    if entry is None:
        return  # 我不在佇列，正常結束

    blocks = load(BLOCKS) or {}
    key = str(me)
    n = int(blocks.get(key, {}).get("n", 0)) + 1

    if n > MAX_BLOCKS:
        # 放棄：移出佇列別擋後面的人，讓 session 正常結束
        qdoc["q"] = [e for e in qdoc["q"] if e.get("pid") != me]
        save(QUEUE, qdoc)
        blocks.pop(key, None)
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
            % (n, MAX_BLOCKS, WAITER, MAX_BLOCKS)
        ),
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
