#!/usr/bin/env python3
"""Guardian on/off demo: the same three agent sessions, with Guardian control off and on.

Three fake agent sessions (CPU-bound Python processes standing in for agent work):
  claude/main-work  focus   the session Stan is working with
  codex/run-tests   normal  a test run in another tool
  cursor/indexing   batch   background work
"No control" = /api/rollback: no caps, normal priority. "Control" = /api/resume_control: pool cap, below_normal
priority and the allocator. Per-session CPU comes from the session jobs' cumulative user + kernel time; foreground
lateness comes from the daemon's probe (a Normal-priority 60 fps loop on the same CPUs as the agents).

Modes:
  default    3 of 12 logical CPUs (25% of the PC), 4 processes per session; 45 s off, then 60 s on.
  --full     every logical CPU, 8 processes per session (2 per CPU). While control is off the whole PC lags.
  --manual   no schedule: the load runs for --minutes and Stan switches control with the button on the dashboard.
             Starts with control on. Ctrl+C ends early. The report splits the time by control state.
Dashboard: http://127.0.0.1:8767/
"""
import argparse
import json
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import winjob as wj  # noqa: E402
from sentinel.guardian.client import home_dir, ping  # noqa: E402

PY = sys.executable
INSTANCE = "onoff"
OFF_S, ON_S, MEASURE_S, SETTLE_S = 45, 60, 30, 10
SESSIONS = [("claude", "main-work", "focus", "Claude 主線開發（重要）"),
            ("codex", "run-tests", "normal", "Codex 跑測試（一般）"),
            ("cursor", "indexing", "batch", "Cursor 背景索引（背景）")]
BURN = ("import subprocess, sys, time\n"
        "n, secs = int(sys.argv[1]), float(sys.argv[2])\n"
        "code = f'import time\\nend=time.perf_counter()+{secs}\\nwhile time.perf_counter()<end: pass'\n"
        "ps = [subprocess.Popen([sys.executable, '-I', '-c', code]) for _ in range(n)]\n"
        "[p.wait() for p in ps]\n")
OUT = Path.home() / ".resource-sentinel" / "audits" / "20261013-session-control"
CREATE_NO_WINDOW = 0x08000000


def acct(job):
    a = job._query(wj.BASIC_AND_IO_ACCOUNTING, wj.BASIC_AND_IO_ACCOUNTING_INFO()).Basic
    return (a.TotalUserTime + a.TotalKernelTime) / 1e7


def summary(cpu, dt, rows):
    p95 = [r["p95"] for r in rows if r["p95"] is not None]
    drop = [r["drop"] for r in rows if r["drop"] is not None]
    return {"seconds": round(dt), "cores": {k: round(v / dt, 2) for k, v in cpu.items()} if dt else {},
            "probe_p95_ms_median": round(statistics.median(p95), 1) if p95 else None,
            "probe_p95_ms_max": max(p95) if p95 else None,
            "drop_pct_mean": round(sum(drop) / len(drop), 1) if drop else None,
            "cap_cores": rows[-1]["cap_cores"] if rows else None}


class Demo:
    def __init__(self, port, full):
        self.port, self.rows, self.jobs, self.stop, self.phase = port, [], {}, False, "setup"
        self.world, self.procs = (wj.NCPU, 8) if full else (3, 4)

    def api(self, path, body=None):
        token = (home_dir(INSTANCE) / "http-token").read_text(encoding="ascii").strip()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=None if body is None else
                                     json.dumps(body).encode(), method="POST" if body is not None else "GET",
                                     headers={"X-Guardian-Token": token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def record(self):
        while not self.stop:
            try:
                s = self.api("/api/state")
                p = s["experience"]["probe"] or {}
                self.rows.append({"t": time.time(), "phase": self.phase, "p95": p.get("lag_p95_ms"),
                                  "drop": p.get("drop_pct"), "control": s["control"], "cap_cores": s["cap_cores"],
                                  "acct": {k: acct(j) for k, j in list(self.jobs.items())}})
            except OSError:
                pass
            time.sleep(1.0)

    def window(self, secs):
        a0, t0 = {k: acct(j) for k, j in self.jobs.items()}, time.time()
        time.sleep(secs)
        a1, t1 = {k: acct(j) for k, j in self.jobs.items()}, time.time()
        return summary({k: a1[k] - a0[k] for k in self.jobs}, t1 - t0, [r for r in self.rows if t0 <= r["t"] <= t1])

    def by_control(self):
        """Split the recorded seconds by control state, skipping SETTLE_S after the load starts and after each switch."""
        cpu, dt, rows = {s: defaultdict(float) for s in (False, True)}, {False: 0.0, True: 0.0}, {False: [], True: []}
        last_change = None
        for a, b in zip(self.rows, self.rows[1:]):
            if not a["acct"] or len(b["acct"]) < len(SESSIONS):
                continue
            if last_change is None or a["control"] != b["control"]:
                last_change = b["t"]
                continue
            if b["t"] - last_change < SETTLE_S:
                continue
            st = b["control"]
            dt[st] += b["t"] - a["t"]
            for k, v in b["acct"].items():
                cpu[st][k] += v - a["acct"].get(k, v)
            rows[st].append(b)
        return summary(cpu[False], dt[False], rows[False]), summary(cpu[True], dt[True], rows[True])

    def start_load(self, secs):
        clients = [subprocess.Popen(
            [PY, "-I", str(ROOT / "scripts" / "srun.py"), "--instance", INSTANCE, "--provider", prov, "--session",
             sess, "--cls", cls, "--est-gib", "0.2", "--", PY, "-I", "-c", BURN, str(self.procs), str(secs)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for prov, sess, cls, _ in SESSIONS]
        deadline = time.time() + 10
        while len(self.jobs) < len(SESSIONS) and time.time() < deadline:
            for prov, sess, _, _ in SESSIONS:
                try:
                    self.jobs.setdefault(f"{prov}/{sess}", wj.Job.open(f"{INSTANCE}.s.{prov}.{sess}",
                                                                         wj.JOB_OBJECT_QUERY))  # acct() reads only
                except OSError:
                    pass
            time.sleep(0.2)
        return clients

    def run(self, keep, manual_minutes):
        if ping(INSTANCE):
            raise SystemExit(f"Guardian instance {INSTANCE} is already running; stop it first")
        log = open(home_dir(INSTANCE).parent / f"{INSTANCE}-daemon.log", "w", encoding="utf-8")
        daemon = subprocess.Popen([PY, "-I", str(ROOT / "scripts" / "guardian.py"), "--instance", INSTANCE,
                                   "--port", str(self.port), "--world-cpus", str(self.world), "--initial-cap", "80",
                                   "--max-cap", "80"], stdout=log, stderr=log, creationflags=CREATE_NO_WINDOW)
        clients = []
        load = f"三個 session 各開 {self.procs} 個吃 CPU 的行程，用 {self.world} 顆 CPU"
        try:
            for _ in range(100):
                if ping(INSTANCE):
                    break
                time.sleep(0.1)
            time.sleep(3.5)
            self.api("/api/state")  # fails here if another program answers on this port
            threading.Thread(target=self.record, daemon=True).start()
            print(f"dashboard: http://127.0.0.1:{self.port}/", flush=True)
            if manual_minutes:
                self.phase = "manual"
                clients = self.start_load(int(manual_minutes * 60) + 10)
                print(f"[{time.strftime('%H:%M:%S')}] 手動模式 {manual_minutes:g} 分鐘：{load}。現在是控管中。\n"
                      "在 dashboard 橫幅上按按鈕切換控管；Ctrl+C 提早結束。", flush=True)
                try:
                    time.sleep(manual_minutes * 60)
                except KeyboardInterrupt:
                    print("提早結束", flush=True)
                return self.by_control()
            self.api("/api/rollback", {})
            self.phase = "off"
            print(f"[{time.strftime('%H:%M:%S')}] 第 1 段，沒有控管（{OFF_S} 秒）：{load}", flush=True)
            clients = self.start_load(OFF_S + ON_S + 10)
            time.sleep(OFF_S - MEASURE_S)
            off = self.window(MEASURE_S)
            self.phase = "on"
            self.api("/api/resume_control", {})
            print(f"[{time.strftime('%H:%M:%S')}] 第 2 段，Guardian 控管（{ON_S} 秒）：同樣的行程繼續跑", flush=True)
            time.sleep(ON_S - MEASURE_S)
            on = self.window(MEASURE_S)
            return off, on
        finally:
            self.stop = True
            for c in clients:
                c.kill()  # closing the client cancels its run job
                c.wait()
            if not keep:
                try:
                    self.api("/api/shutdown", {})
                except OSError:
                    pass
                daemon.wait(15)

    def report(self, off, on):
        cell = lambda x, unit="": f"{'–' if x is None else x}{unit}"  # noqa: E731
        lines = [f"{'':28}{'沒有控管':>10}{'有控管':>10}"]
        for prov, sess, _, label in SESSIONS:
            k = f"{prov}/{sess}"
            lines.append(f"{label:24}{cell(off['cores'].get(k), ' 核'):>10}{cell(on['cores'].get(k), ' 核'):>10}")
        t_off, t_on = (round(sum(x["cores"].values()), 2) if x["cores"] else None for x in (off, on))
        lines.append(f"{'agent 合計':26}{cell(t_off, ' 核'):>10}{cell(t_on, ' 核'):>10}")
        pct = lambda t: None if t is None else round(100 * t / self.world)  # noqa: E731
        lines.append(f"{f'占開放的 {self.world} 顆 CPU':24}{cell(pct(t_off), '%'):>10}{cell(pct(t_on), '%'):>10}")
        lines.append(f"{'前景延遲 p95（中位數）':22}{cell(off['probe_p95_ms_median'], ' ms'):>10}"
                     f"{cell(on['probe_p95_ms_median'], ' ms'):>10}")
        lines.append(f"{'前景掉幀（平均）':24}{cell(off['drop_pct_mean'], '%'):>10}{cell(on['drop_pct_mean'], '%'):>10}")
        lines.append(f"{'量測秒數':26}{cell(off['seconds'], ' 秒'):>10}{cell(on['seconds'], ' 秒'):>10}")
        lines.append(f"有控管時的 agent 上限：{on['cap_cores']} 核（控制器看到前景變卡會再往下降）")
        text = "\n".join(lines)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        OUT.mkdir(parents=True, exist_ok=True)
        meta = {"world_cpus": self.world, "procs_per_session": self.procs}
        (OUT / f"guardian-demo-onoff-{stamp}.json").write_text(json.dumps({**meta, "off": off, "on": on}, indent=1),
                                                                encoding="utf-8")
        (OUT / f"guardian-demo-onoff-{stamp}.md").write_text(
            f"# Guardian 開關對照 {stamp}\n\n{self.world} 顆 CPU，每個 session {self.procs} 個行程\n\n```\n{text}\n```\n",
            encoding="utf-8")
        print("\n" + text, flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=8767)
    ap.add_argument("--full", action="store_true", help="every logical CPU, 8 processes per session: the PC lags "
                                                        "while control is off")
    ap.add_argument("--manual", action="store_true", help="switch control yourself on the dashboard")
    ap.add_argument("--minutes", type=float, default=5, help="how long the load runs in --manual (default 5)")
    ap.add_argument("--keep", action="store_true", help="leave the daemon and dashboard running afterwards")
    a = ap.parse_args()
    d = Demo(a.port, a.full)
    d.report(*d.run(a.keep, a.minutes if a.manual else None))
    if a.keep:
        print(f"\ndashboard 保留在 http://127.0.0.1:{a.port}/ ；關掉：python -I scripts/guardctl.py --instance "
              f"{INSTANCE} shutdown", flush=True)


if __name__ == "__main__":
    main()
