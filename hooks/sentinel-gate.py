# -*- coding: utf-8 -*-
# Resource Sentinel - heavy-job arbiter gate (v2: FIFO queue)
# PreToolUse(Bash): 重量級指令申請槽位；沒輪到就進佇列並給等待指令
# PostToolUse(Bash): --release 釋放本 session 的槽
import json
import os
import re
import sys
import time

try:
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

DATA = os.path.join(os.environ.get("USERPROFILE", ""), ".resource-sentinel")
STATUS = os.path.join(DATA, "status.json")
SLOTS = os.path.join(DATA, "slots.json")
QUEUE = os.path.join(DATA, "queue.json")
CONFIG = os.path.join(DATA, "config.json")
LOCK = os.path.join(DATA, ".arb.lock")

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
QUEUE_TTL_MIN = 10
HEAVY_SLOTS = 1
WAITER = os.path.join("C:\\Users\\stans\\Projects\\resource-sentinel",
                      "scripts", "wait-slot.ps1")


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


def acquire_lock():
    for _ in range(30):
        try:
            fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            return True
        except FileExistsError:
            try:
                if time.time() - os.path.getmtime(LOCK) > 30:
                    os.unlink(LOCK)   # stale lock
                    continue
            except OSError:
                pass
            time.sleep(0.05)
    return False   # 拿不到鎖就不擋（可用性優先）


def release_lock():
    try:
        os.unlink(LOCK)
    except OSError:
        pass


def pid_alive(pid):
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        return True


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
    return [s for s in slots
            if now - s.get("ts", 0) <= s.get("ttl_min", SLOT_TTL_MIN) * 60
            and pid_alive(s.get("pid", -1))]


def clean_queue(q):
    now = time.time()
    return [e for e in q
            if now - e.get("ts", 0) <= QUEUE_TTL_MIN * 60
            and pid_alive(e.get("pid", -1))]


def ensure_queued(q, me, repo):
    for e in q:
        if e.get("pid") == me:
            e["ts"] = time.time()   # refresh：還活著還在等
            return q, [x.get("pid") for x in q].index(me) + 1
    q.append({"pid": me, "repo": repo, "ts": time.time()})
    return q, len(q)


def block(msg):
    sys.stderr.write(msg)
    sys.exit(2)


def waiter_hint(pos):
    return ("你在佇列第 %d 位。【不要結束回合、不要只說稍後再試】依序做："
            "(1) 若有可先做的輕量步驟（讀檔、小改、寫文件）先做完它們；"
            "(2) 然後執行 powershell -NoProfile -ExecutionPolicy Bypass -File \"%s\" "
            "並把 Bash timeout 參數設 600000——它會阻塞到輪到你才返回；"
            "(3) 返回顯示 your turn 後，立刻重跑原本被擋的指令。"
            "整段流程不需要使用者介入。" % (pos, WAITER))


def main():
    release_mode = "--release" in sys.argv
    try:
        inp = json.load(sys.stdin)
    except Exception:
        inp = {}
    if inp.get("tool_name") and inp.get("tool_name") != "Bash":
        return

    me = my_agent_pid()

    if release_mode:
        if not acquire_lock():
            return
        try:
            slots_doc = load(SLOTS) or {"slots": []}
            slots = clean_slots(slots_doc.get("slots", []))
            remaining = [s for s in slots if s.get("pid") != me]
            if remaining != slots_doc.get("slots", []):
                save(SLOTS, {"slots": remaining})
        finally:
            release_lock()
        return

    cmd = (inp.get("tool_input") or {}).get("command", "") or ""
    # 等待腳本本身永遠放行（不然沒人等得了）
    if "wait-slot.ps1" in cmd:
        return
    cfg = load(CONFIG) or {}
    patterns = cfg.get("heavy_patterns") or DEFAULT_PATTERNS
    if not any(re.search(p, cmd) for p in patterns):
        return  # 非重活

    status = load(STATUS) or {}
    light = status.get("light", "GREEN")
    try:
        gen = time.mktime(time.strptime(status["generated_at"], "%Y-%m-%d %H:%M:%S"))
        if time.time() - gen > 300:
            light = "GREEN"   # 監控失效時不癱瘓工作
    except Exception:
        light = "GREEN"

    capacity = int(cfg.get("heavy_slots", HEAVY_SLOTS))
    cwd = inp.get("cwd") or os.getcwd()
    repo = os.path.basename(cwd.rstrip("\\/"))

    if not acquire_lock():
        return
    try:
        slots = clean_slots((load(SLOTS) or {"slots": []}).get("slots", []))
        q = clean_queue((load(QUEUE) or {"q": []}).get("q", []))

        if any(s.get("pid") == me for s in slots):
            for s in slots:
                if s.get("pid") == me:
                    s["ts"] = time.time()   # 續租
            save(SLOTS, {"slots": slots})
            save(QUEUE, {"q": [e for e in q if e.get("pid") != me]})
            return  # 已持槽，放行

        if light == "RED":
            q, pos = ensure_queued(q, me, repo)
            save(SLOTS, {"slots": slots}); save(QUEUE, {"q": q})
            block("[sentinel-gate] 紅燈：機器接近極限，重量級指令暫停。" + waiter_hint(pos))
        if light == "ORANGE":
            q, pos = ensure_queued(q, me, repo)
            save(SLOTS, {"slots": slots}); save(QUEUE, {"q": q})
            block("[sentinel-gate] 橘燈：暫緩新的重量級工作。" + waiter_hint(pos))

        head_ok = (not q) or q[0].get("pid") == me
        if len(slots) >= capacity or not head_ok:
            q, pos = ensure_queued(q, me, repo)
            save(SLOTS, {"slots": slots}); save(QUEUE, {"q": q})
            holder = slots[0] if slots else None
            held = ("重活槽被佔用（%s，repo %s）。" % (holder.get("cmd", "?"), holder.get("repo", "?"))
                    if holder else "前面還有人在排。")
            block("[sentinel-gate] " + held + waiter_hint(pos))

        # 輪到我：出隊、佔槽、放行
        q = [e for e in q if e.get("pid") != me]
        slots.append({
            "pid": me, "repo": repo, "cmd": cmd[:80],
            "ts": time.time(),
            "ttl_min": int(cfg.get("slot_ttl_min", SLOT_TTL_MIN)),
        })
        save(SLOTS, {"slots": slots})
        save(QUEUE, {"q": q})
    finally:
        release_lock()


if __name__ == "__main__":
    main()
