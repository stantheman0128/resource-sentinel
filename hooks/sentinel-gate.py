# -*- coding: utf-8 -*-
# Resource Sentinel - heavy-job arbiter gate
# PreToolUse(Bash): 重量級指令先申請槽位，燈號/槽位不允許就硬擋（exit 2）
# PostToolUse(Bash): --release 釋放本 session 佔的槽
import json
import os
import re
import sys
import time

DATA = os.path.join(os.environ.get("USERPROFILE", ""), ".resource-sentinel")
STATUS = os.path.join(DATA, "status.json")
SLOTS = os.path.join(DATA, "slots.json")
CONFIG = os.path.join(DATA, "config.json")

AGENT_EXES = {"claude.exe", "cursor.exe", "codex.exe"}
DEFAULT_PATTERNS = [
    r"\b(npm|pnpm|yarn|bun)\s+(install|ci|update|rebuild)\b",
    r"\b(npm|pnpm|yarn|bun)\s+run\s+(build|test)\b",
    r"\bcargo\s+(build|test|install|clippy)\b",
    r"\bpip3?\s+install\b", r"\buv\s+(pip\s+install|sync)\b",
    r"\bgo\s+(build|test|install)\b",
    r"\bdotnet\s+(build|test|restore|publish)\b",
    r"\b(make|cmake|msbuild|ninja)\b",
    r"\b(gradle|gradlew|mvn)\b",
    r"\bpytest\b", r"\bvitest\b(?!.*--related)", r"\bjest\b",
    r"\bdocker\s+(build|compose\s+up)\b",
    r"\b(webpack|vite|next|nuxt|tsup|esbuild)\s+build\b",
    r"\btsc\b(?!\s+--noEmit\s+\S*\.ts)",
]
SLOT_TTL_MIN = 15
HEAVY_SLOTS = 1


def load(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


def save_slots(slots):
    tmp = SLOTS + ".tmp"
    with open(tmp, "w", encoding="ascii") as f:
        json.dump(slots, f, ensure_ascii=True)
    os.replace(tmp, SLOTS)


def pid_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return True  # 查不到就保守當作還活著（讓 TTL 兜底）


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


def clean_slots(slots):
    now = time.time()
    kept = []
    for s in slots:
        if now - s.get("ts", 0) > s.get("ttl_min", SLOT_TTL_MIN) * 60:
            continue  # TTL 到期
        if not pid_alive(s.get("pid", -1)):
            continue  # 佔槽者已死
        kept.append(s)
    return kept


def main():
    release_mode = "--release" in sys.argv
    try:
        inp = json.load(sys.stdin)
    except Exception:
        inp = {}
    if inp.get("tool_name") and inp.get("tool_name") != "Bash":
        return

    me = my_agent_pid()
    slots_doc = load(SLOTS) or {"slots": []}
    slots = clean_slots(slots_doc.get("slots", []))

    if release_mode:
        remaining = [s for s in slots if s.get("pid") != me]
        if len(remaining) != len(slots_doc.get("slots", [])):
            save_slots({"slots": remaining})
        return

    cmd = (inp.get("tool_input") or {}).get("command", "") or ""
    cfg = load(CONFIG) or {}
    patterns = cfg.get("heavy_patterns") or DEFAULT_PATTERNS
    if not any(re.search(p, cmd) for p in patterns):
        if slots != slots_doc.get("slots", []):
            save_slots({"slots": slots})
        return  # 非重活，放行

    status = load(STATUS) or {}
    light = status.get("light", "GREEN")
    # 監控過期就當 GREEN 但提醒（別讓監控失效癱瘓所有工作）
    stale = False
    try:
        gen = time.mktime(time.strptime(status["generated_at"], "%Y-%m-%d %H:%M:%S"))
        stale = (time.time() - gen) > 300
    except Exception:
        stale = True
    if stale:
        light = "GREEN"

    capacity = int(cfg.get("heavy_slots", HEAVY_SLOTS))
    mine = [s for s in slots if s.get("pid") == me]
    others = [s for s in slots if s.get("pid") != me]

    if light == "RED":
        save_slots({"slots": slots})
        sys.stderr.write(
            "[sentinel-gate] 紅燈：機器接近極限，重量級指令一律暫停。"
            "先做輕量工作，幾分鐘後再試；狀態見 %s\\status.md" % DATA)
        sys.exit(2)
    if light == "ORANGE" and not mine:
        save_slots({"slots": slots})
        sys.stderr.write(
            "[sentinel-gate] 橘燈：暫緩新的重量級工作，等進行中的收尾。"
            "稍後重試，或改做輕量步驟。")
        sys.exit(2)
    if not mine and len(others) >= capacity:
        holder = others[0]
        save_slots({"slots": slots})
        sys.stderr.write(
            "[sentinel-gate] 重活槽已被佔用（%s，repo %s）。排隊中：先做輕量步驟，"
            "稍後重試這條指令。" % (holder.get("cmd", "?"), holder.get("repo", "?")))
        sys.exit(2)

    if not mine:
        cwd = inp.get("cwd") or os.getcwd()
        slots.append({
            "pid": me,
            "repo": os.path.basename(cwd.rstrip("\\/")),
            "cmd": cmd[:80],
            "ts": time.time(),
            "ttl_min": int(cfg.get("slot_ttl_min", SLOT_TTL_MIN)),
        })
    save_slots({"slots": slots})
    # YELLOW 的低優先權建議由 UserPromptSubmit hook 給，這裡放行即可


if __name__ == "__main__":
    main()
