# -*- coding: utf-8 -*-
# Resource Sentinel - UserPromptSubmit hook
# 1) 注入一行機器狀態（黃/紅燈升級成警告段）
# 2) 登記本 session 的 claude 進程 pid + cwd，供採集器把進程樹歸因到 repo
import json
import os
import sys
import time

DATA = os.path.join(os.environ.get("USERPROFILE", ""), ".resource-sentinel")
STATUS = os.path.join(DATA, "status.json")
SESSIONS = os.path.join(DATA, "sessions.json")
HISTORY = os.path.join(DATA, "history.json")


def load(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return None


AGENT_EXES = {"claude.exe", "cursor.exe", "codex.exe"}


def find_agent_ancestor():
    """hook 是隔著 shell 被呼叫的，沿祖先鏈找真正的 agent 進程 pid。"""
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
    return os.getppid()  # fallback：至少留個線索


def register_session(cwd):
    """記錄本 session 的 agent 進程 pid 與 cwd。"""
    try:
        ppid = find_agent_ancestor()
        sessions = load(SESSIONS) or {}
        sessions[str(ppid)] = {
            "cwd": cwd,
            "repo": os.path.basename(cwd.rstrip("\\/")) if cwd else "unknown",
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        # 修剪：只留最近 3 天的登記
        cutoff = time.time() - 3 * 86400
        for k in list(sessions.keys()):
            try:
                t = time.mktime(time.strptime(sessions[k]["ts"], "%Y-%m-%d %H:%M:%S"))
                if t < cutoff:
                    del sessions[k]
            except Exception:
                del sessions[k]
        tmp = SESSIONS + ".tmp"
        with open(tmp, "w", encoding="ascii") as f:
            json.dump(sessions, f, ensure_ascii=True)
        os.replace(tmp, SESSIONS)
    except Exception:
        pass  # 登記失敗不影響注入


def main():
    try:
        inp = json.load(sys.stdin)
    except Exception:
        inp = {}
    cwd = inp.get("cwd") or os.getcwd()
    if os.path.isdir(DATA):
        register_session(cwd)

    s = load(STATUS)
    if s is None:
        return  # 監控未安裝/未跑過：保持安靜

    # 過期偵測
    try:
        gen = time.mktime(time.strptime(s["generated_at"], "%Y-%m-%d %H:%M:%S"))
        age_min = (time.time() - gen) / 60
    except Exception:
        age_min = 999
    if age_min > 5:
        print(f"[sentinel] 監控失效：狀態檔最後更新 {s.get('generated_at')}（{age_min:.0f} 分鐘前）。"
              f"排程任務 ResourceSentinel 可能停了，別依賴舊數據。")
        return

    light = s.get("light", "?")
    ram = s.get("ram", {})
    cpu5 = s.get("cpu_5min_avg", "?")
    gpu = s.get("gpu") or {}
    sys_free = ""
    for d in s.get("disks", []) if isinstance(s.get("disks"), list) else [s.get("disks")]:
        if d and d.get("drive") == "C:":
            sys_free = f"｜C槽剩 {d.get('free_gb')}GB"
    gpu_part = f"｜GPU {gpu.get('util_pct')}%" if gpu.get("util_pct") is not None else ""

    # 本 repo 歷史峰值（有帳才報）
    repo = os.path.basename(cwd.rstrip("\\/")) if cwd else ""
    hist_part = ""
    h = load(HISTORY)
    if h and repo in h and h[repo].get("typical_peak_mb"):
        hist_part = f"｜本repo典型峰值 {h[repo]['typical_peak_mb']}MB"

    line = (f"[sentinel] {light}｜RAM {ram.get('used_pct')}%（剩 {ram.get('free_gb')}GB）"
            f"｜CPU5分均 {cpu5}%{gpu_part}{sys_free}{hist_part}")
    print(line)

    if light == "YELLOW":
        print("[sentinel] 黃燈（吃緊）：重量級動作（build、安裝、跑整套測試）改用低優先權跑"
              "（PowerShell: Start-Process -Priority BelowNormal，或 cmd: start /low /b <cmd>），"
              "不要並行開多個重活。")
    elif light == "ORANGE":
        print("[sentinel] 橘燈（很緊）：暫緩新的重量級動作，先收尾進行中的工作。"
              "非跑不可的重活：低優先權、一次只跑一個。開 subagent 前先想清楚必要性。")
    elif light == "RED":
        print("[sentinel] 紅燈：機器接近極限。只做輕量操作（讀檔、小改）。"
              "不要啟動 build、安裝、新 subagent。若你的工作正在快速吃資源，"
              "主動暫停並告知使用者，等燈號回落。詳情讀 "
              + os.path.join(DATA, "status.md"))


if __name__ == "__main__":
    main()
