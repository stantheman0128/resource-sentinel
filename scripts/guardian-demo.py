#!/usr/bin/env python3
"""Guardian demo: real jobs, real processes, bounded load (a 3-CPU world, about 25% of a 12-CPU machine).

Starts a separate Guardian instance ("demo", dashboard http://127.0.0.1:8766/), drives synthetic Claude / Codex /
Cursor sessions through the real srun client, changes settings through the real HTTP API, records the dashboard
state every second and writes a JSON + Markdown report. About 5 minutes. Open the dashboard while it runs.

Phases: 1 allocation weights  2 pause a provider  3 switch focus  4 injected lag (fast back-off, slow recovery)
        5 many processes do not buy more CPU  6 real probe with the pool at normal priority  7 memory admission
"""
import argparse
import json
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import home_dir, ping

PY = sys.executable
BURN = ("import subprocess, sys, time\n"
        "n, secs = int(sys.argv[1]), float(sys.argv[2])\n"
        "code = f'import time\\nend=time.perf_counter()+{secs}\\nwhile time.perf_counter()<end: pass'\n"
        "ps = [subprocess.Popen([sys.executable, '-I', '-c', code]) for _ in range(n)]\n"
        "[p.wait() for p in ps]\n")
INSTANCE, PORT = "demo", 8766
OUT = Path.home() / ".resource-sentinel" / "audits" / "20261013-session-control"


class Demo:
    def __init__(self, keep):
        self.keep = keep
        self.rows, self.marks, self.phase = [], [], "setup"
        self.clients = {}
        self.t0 = time.time()
        self.stop = False

    # ---- plumbing ----
    def api(self, path, body=None):
        token = (home_dir(INSTANCE) / "http-token").read_text(encoding="ascii").strip()
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", method="POST" if body is not None else "GET",
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"X-Guardian-Token": token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def start_daemon(self):
        if ping(INSTANCE):
            print("demo Guardian already running; using it")
            return None
        log = open(home_dir(INSTANCE).parent / "demo-daemon.log", "w", encoding="utf-8")
        p = subprocess.Popen([PY, "-I", str(ROOT / "scripts" / "guardian.py"), "--instance", INSTANCE, "--port",
                              str(PORT), "--world-cpus", "3", "--initial-cap", "80"], stdout=log, stderr=log,
                             creationflags=0x08000000)
        for _ in range(100):
            if ping(INSTANCE):
                break
            time.sleep(0.1)
        time.sleep(3.5)
        return p

    def srun(self, name, provider, session, cls, procs, secs, est_gib=None):
        argv = [PY, "-I", str(ROOT / "scripts" / "srun.py"), "--instance", INSTANCE, "--provider", provider,
                "--session", session, "--cls", cls]
        if est_gib:
            argv += ["--est-gib", str(est_gib)]
        argv += ["--", PY, "-I", "-c", BURN, str(procs), str(secs)]
        self.clients[name] = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)

    def kill(self, *names):
        for n in names:
            p = self.clients.pop(n, None)
            if p:
                p.kill()  # the client goes away; the daemon cancels the run job (TerminateJobObject)
                p.wait()

    def record(self):
        while not self.stop:
            try:
                s = self.api("/api/state")
                p = s["experience"]["probe"] or {}
                self.rows.append({"t": round(time.time() - self.t0, 1), "phase": self.phase, "cap": s["cap"],
                                  "cap_cores": s["cap_cores"], "pool": s["pool_cores"], "mode": s["mode"],
                                  "level": s["experience"]["level"], "kind": s["experience"]["kind"],
                                  "p95": p.get("lag_p95_ms"), "drop": p.get("drop_pct"),
                                  "priority": s["pool_priority"], "allocator": s["allocator"],
                                  "sessions": {x["key"]: [x["usage"], x["cap_cores"], x["cls"], x["paused"]]
                                               for x in s["sessions"]},
                                  "queue": [[q["session"], q["reason"]] for q in s["queue"]]})
            except OSError:
                pass
            time.sleep(1.0)

    def enter(self, name, text):
        self.phase = name
        self.marks.append({"t": round(time.time() - self.t0, 1), "phase": name, "text": text})
        print(f"\n[{time.strftime('%H:%M:%S')}] {name}: {text}", flush=True)

    def wait(self, secs):
        time.sleep(secs)

    def avg(self, phase, last_s, keys):
        rows = [r for r in self.rows if r["phase"] == phase]
        if not rows:
            return {}
        t_end = rows[-1]["t"]
        rows = [r for r in rows if r["t"] > t_end - last_s]
        out = {"cap_cores": round(sum(r["cap_cores"] for r in rows) / len(rows), 2),
               "pool": round(sum(r["pool"] for r in rows) / len(rows), 2)}
        for k in keys:
            vals = [r["sessions"].get(k, [0])[0] for r in rows]
            caps = [r["sessions"].get(k, [0, None])[1] for r in rows]
            caps = [c for c in caps if c is not None]
            out[k] = {"cores": round(sum(vals) / len(vals), 2), "cap": round(sum(caps) / len(caps), 2) if caps else None}
        return out

    # ---- the show ----
    def run(self):
        daemon = self.start_daemon()
        threading.Thread(target=self.record, daemon=True).start()
        results = {}
        A, B, C = "claude/alpha", "codex/beta", "cursor/gamma"
        try:
            self.enter("1-allocation-weights", "three sessions, 4 busy processes each, Guardian allocation weights "
                                               "(not Windows WEIGHT_BASED): claude focus 8, codex normal 5, cursor "
                                               "batch 2")
            for n, (prov, sess, cls) in {"A": ("claude", "alpha", "focus"), "B": ("codex", "beta", "normal"),
                                         "C": ("cursor", "gamma", "batch")}.items():
                self.srun(n, prov, sess, cls, 4, 400)
            self.wait(40)
            results["1-allocation-weights"] = self.avg("1-allocation-weights", 20, [A, B, C])

            self.enter("2-pause-provider", "pause every Codex session with one call; others absorb the CPU")
            self.api("/api/provider", {"name": "codex", "paused": True})
            self.wait(20)
            results["2-pause-provider"] = self.avg("2-pause-provider", 12, [A, B, C])
            self.api("/api/provider", {"name": "codex", "paused": False})

            self.enter("3-switch-focus", "Stan moves focus: cursor becomes focus, claude becomes batch")
            self.api("/api/session", {"key": C, "cls": "focus"})
            self.api("/api/session", {"key": A, "cls": "batch"})
            self.wait(20)
            results["3-switch-focus"] = self.avg("3-switch-focus", 12, [A, B, C])
            self.api("/api/session", {"key": C, "cls": "batch"})
            self.api("/api/session", {"key": A, "cls": "focus"})

            self.enter("4-injected-lag", "inject 'foreground degraded' for 12 s: cap x0.8 at most every 3 s, then "
                                         "20 s healthy before +5 points every 10 s")
            self.api("/api/inject", {"level": "degraded", "seconds": 12})
            self.wait(55)
            rows = [r for r in self.rows if r["phase"] == "4-injected-lag"]
            results["4-injected-lag"] = {"cap_trajectory": [[r["t"], r["cap"]] for r in rows]}

            self.enter("5-many-processes", "cancel the three sessions by closing their clients; then codex/wide runs "
                                           "8 processes and cursor/narrow 1, same class")
            self.kill("A", "B", "C")
            self.wait(3)
            st = self.api("/api/state")
            results["5-cancel-check"] = {"live_runs_after_cancel": len(st["runs"]),
                                         "recent": [[r["session"], r["state"]] for r in st["recent_runs"][:3]]}
            self.api("/api/allocator", {"on": False})
            self.srun("D", "codex", "wide", "normal", 8, 400)
            self.srun("E", "cursor", "narrow", "normal", 1, 400)
            self.phase = "5a-allocator-off"
            self.wait(18)
            results["5a-allocator-off"] = self.avg("5a-allocator-off", 10, ["codex/wide", "cursor/narrow"])
            self.api("/api/allocator", {"on": True})
            self.phase = "5b-allocator-on"
            self.wait(18)
            results["5b-allocator-on"] = self.avg("5b-allocator-on", 10, ["codex/wide", "cursor/narrow"])

            self.enter("6-real-probe", "pool priority set to normal (what an unmanaged agent gets): the probe on the "
                                       "same 3 CPUs measures the foreground; then back to below_normal")
            self.api("/api/pool_priority", {"priority": "normal"})
            self.wait(35)
            self.phase = "6b-below-normal"
            self.api("/api/pool_priority", {"priority": "below_normal"})
            self.wait(25)
            for ph in ("6-real-probe", "6b-below-normal"):
                rows = [r for r in self.rows if r["phase"] == ph and r["p95"] is not None]
                results[ph] = {"cap_trajectory": [[r["t"], r["cap"]] for r in rows],
                               "probe_p95_ms": [r["p95"] for r in rows], "probe_drop_pct": [r["drop"] for r in rows],
                               "levels": [r["level"] for r in rows], "pool": [r["pool"] for r in rows]}
            self.kill("D", "E")

            self.enter("7-memory-admission", "a run that says it needs more RAM than is free waits in the queue; "
                                             "nothing is killed. Then hold admission and release it")
            st = self.api("/api/state")
            big = round(st["available_gib"] - 8 + 4, 1)
            self.srun("BIG", "claude", "bigmem", "normal", 1, 5, est_gib=big)
            self.wait(4)
            st = self.api("/api/state")
            results["7-memory-admission"] = {"requested_gib": big, "available_gib": st["available_gib"],
                                             "queue": st["queue"]}
            self.api("/api/hold", {"on": True})
            self.srun("SMALL", "codex", "small", "normal", 1, 3, est_gib=0.2)
            self.wait(3)
            held = self.api("/api/state")["queue"]
            self.api("/api/hold", {"on": False})
            self.wait(2)
            after = self.api("/api/state")
            results["7-hold"] = {"queue_while_held": [[q["session"], q["reason"]] for q in held],
                                 "queue_after_release": [[q["session"], q["reason"]] for q in after["queue"]],
                                 "running_after_release": [r["session"] for r in after["runs"]]}
            self.kill("BIG")
            self.wait(5)
            results["7-after-cancel"] = {"queue": self.api("/api/state")["queue"]}
            results["decisions"] = self.api("/api/state")["decisions"]
        finally:
            self.stop = True
            self.kill(*list(self.clients))
            if daemon and not self.keep:
                try:
                    self.api("/api/shutdown", {})
                except OSError:
                    pass
                daemon.wait(10)
        return results

    def report(self, results):
        OUT.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        jpath = OUT / f"guardian-demo-{stamp}.json"
        jpath.write_text(json.dumps({"marks": self.marks, "results": results, "timeline": self.rows}, indent=1),
                         encoding="utf-8")
        print(f"\nwrote {jpath}")
        r = results
        lines = []
        for ph in ("1-allocation-weights", "2-pause-provider", "3-switch-focus"):
            x = r.get(ph, {})
            lines.append(f"{ph}: pool cap {x.get('cap_cores')} cores, used {x.get('pool')}; " + ", ".join(
                f"{k} used {v['cores']} (ceiling {v['cap']})" for k, v in x.items() if isinstance(v, dict)))
        traj = r.get("4-injected-lag", {}).get("cap_trajectory", [])
        changes = [traj[0]] + [b for a, b in zip(traj, traj[1:]) if a[1] != b[1]] if traj else []
        lines.append(f"4-injected-lag: cap changes (t s, %) {changes}")
        lines.append(f"5-cancel-check: {r.get('5-cancel-check')}")
        for ph in ("5a-allocator-off", "5b-allocator-on"):
            x = r.get(ph, {})
            lines.append(f"{ph}: " + ", ".join(f"{k} used {v['cores']} (ceiling {v['cap']})" for k, v in x.items()
                                                if isinstance(v, dict)))
        for ph in ("6-real-probe", "6b-below-normal"):
            x = r.get(ph, {})
            lines.append(f"{ph}: probe p95 ms {x.get('probe_p95_ms')}; cap {sorted(set(c for _, c in x.get('cap_trajectory', [])))}")
        lines.append(f"7-memory-admission: requested {r.get('7-memory-admission', {}).get('requested_gib')} GiB with "
                     f"{r.get('7-memory-admission', {}).get('available_gib')} GiB available -> queue "
                     f"{[(q['session'], q['reason']) for q in r.get('7-memory-admission', {}).get('queue', [])]}")
        lines.append(f"7-hold: {r.get('7-hold')}")
        lines.append(f"7-after-cancel: queue {r.get('7-after-cancel')}")
        text = "\n".join(lines)
        (OUT / f"guardian-demo-{stamp}.md").write_text("# Guardian demo " + stamp + "\n\n```\n" + text + "\n```\n",
                                                       encoding="utf-8")
        print(text)


def main():
    global PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="leave the demo daemon running afterwards")
    ap.add_argument("--port", type=int, default=PORT, help="dashboard port (default %(default)s)")
    a = ap.parse_args()
    PORT = a.port
    d = Demo(a.keep)
    print(f"dashboard: http://127.0.0.1:{PORT}/  (3-CPU world, at most about 25% of this PC)")
    d.report(d.run())


if __name__ == "__main__":
    main()
