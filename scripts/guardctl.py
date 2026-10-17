#!/usr/bin/env python3
"""Control a running Guardian from any terminal (the dashboard calls the same API).

  guardctl status
  guardctl pause claude/s1 | resume claude/s1 | class claude/s1 focus
  guardctl class claude/s1 exempt [minutes]     no session cap, queue gates skipped, new runs outside the pool
  guardctl queue-order sjf                      class_fifo (default), fifo, sjf, hrrn or fair
  guardctl pause-provider codex | resume-provider codex
  guardctl memory-budget 6 | memory-budget off  agents' private commit together; under pressure trim, then pause
  guardctl memory-trim on|off | memory-pause on|off | memory-limit 8 | memory-limit off   (the limit fails allocations)
  guardctl cap 40 | world 10 | hold on | hold off | inject degraded 30 | priority normal | allocator off
  guardctl desktop off | desktop on                 desktop jobs for the Claude and Codex apps' CLIs
  guardctl cancel <run_id> | rollback | resume-control | shutdown
  guardctl adopt <pid> <provider> [session]     take in a CLI that is already running and has no hook
"""
import argparse
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian.client import home_dir


def call(instance, path, body=None):
    home = home_dir(instance)
    port = json.loads((home / "daemon.json").read_text(encoding="utf-8"))["port"]
    token = (home / "http-token").read_text(encoding="ascii").strip()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method="POST" if body is not None else "GET",
                                 data=None if body is None else json.dumps(body).encode(),
                                 headers={"X-Guardian-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def summary(s):
    lines = [f"mode {s['mode']}  cap {s['cap']:.0f}% of {s['world_cpus']} CPUs = {s['cap_cores']} cores  "
             f"pool {s['pool_cores']} cores  priority {s['pool_priority']}  "
             f"desktop jobs {'on' if s.get('desktop') else 'off'}",
             f"RAM available {s['available_gib']} GiB  commit headroom {s['commit_headroom_gib']} GiB  "
             f"admission {'open' if s['admission']['open'] else 'closed ' + s['admission']['reason']}"
             f"{'  HOLD' if s['admission']['hold'] else ''}  queue order {s.get('queue_order')}",
             f"experience {s['experience']['level']} ({s['experience']['kind']})  probe {s['experience']['probe']}"]
    # what is in effect, then the configured value when it differs: control off leaves it for resume-control
    later = lambda now, conf: f" (configured {conf}, applied when control is on)" if conf != now else ""
    if s.get("memory"):
        m = s["memory"]
        gib = lambda v: "off" if v is None else f"{v:g} GiB"
        hard = gib(m["hard_limit_gib"])
        lines.insert(2, f"agent memory {m['agents_gib']} GiB  budget {gib(m['budget_gib'])}  rung {m['rung']}  "
                        f"trim {'on' if m['trim'] else 'off'}  pause {'on' if m['pause'] else 'off'}  "
                        f"hard limit {hard}{later(hard, gib(m.get('hard_limit_configured_gib', m['hard_limit_gib'])))}"
                        f"  trimmed {m['trimmed_gib']} GiB"
                        + (f"  paused {', '.join(m['paused'])}" if m["paused"] else ""))
    if s.get("agent_priority"):
        a = s["agent_priority"]
        lines.insert(1, f"agent I/O priority {a['io']}{later(a['io'], a.get('io_configured', a['io']))}  "
                        f"memory priority {a['memory']}{later(a['memory'], a.get('memory_configured', a['memory']))}  "
                        f"set on {a['set']} processes{'  refused ' + str(a['refused']) if a['refused'] else ''}")
    for p in s["providers"]:
        lines.append(f"  provider {p['name']:<8} {'PAUSED' if p['paused'] else 'running':<8} {p['cores']} cores")
    for x in s["sessions"]:
        cap = "-" if x["cap_cores"] is None else f"{x['cap_cores']:.2f}"
        lines.append(f"  session {x['key']:<24} {x['cls']:<6} {'PAUSED' if x['paused'] else '':<6} "
                     f"use {x['usage']:.2f} cap {cap} runs {x['runs']}{'  desktop job' if x.get('desktop') else ''}"
                     + (f"  exempt {x['exempt_left_s'] // 60} min left" if x.get("exempt_left_s") is not None else ""))
    for r in s["runs"]:
        lines.append(f"  {r['state']:<8} {r['run_id']} {r['session']:<24} pid {r['pid']} {r['label']!r} ({r['coverage']})")
    for q in s["queue"]:
        est = f", about {q['est_s']} s ({q['est_s_source']})" if q.get("est_s") is not None else ""
        lines.append(f"  queued {q['run_id']} {q['session']} {q['label']!r}{est}: {q['reason']}")
    for a in s["apps"]:
        lines.append(f"  app {a.get('name')}: {a.get('cores')} cores, {a.get('coverage')}")
    o = s.get("outside")
    if o and "error" in o:
        lines.append(f"outside Guardian: {o['error']}")
    elif o:
        lines.append(f"outside Guardian {o['cores']} cores in {o['processes']} processes: "
                     + ", ".join(f"{t['name']} {t['cores']}" for t in o["top"])
                     + (f"  (machine {o['machine_cores']}, in no process {o['unattributed_cores']})"
                        if o.get("machine_cores") is not None else ""))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance", default="main")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("verb")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args(argv)
    v, x = a.verb, a.args
    routes = {
        "pause": lambda: ("/api/session", {"key": x[0], "paused": True}),
        "resume": lambda: ("/api/session", {"key": x[0], "paused": False}),
        "class": lambda: ("/api/session", {"key": x[0], "cls": x[1],
                                           **({"minutes": float(x[2])} if len(x) > 2 else {})}),
        "pause-provider": lambda: ("/api/provider", {"name": x[0], "paused": True}),
        "resume-provider": lambda: ("/api/provider", {"name": x[0], "paused": False}),
        "cap": lambda: ("/api/cap", {"cap": float(x[0])}),
        "world": lambda: ("/api/world", {"cpus": int(x[0])}),
        "hold": lambda: ("/api/hold", {"on": x[0] == "on"}),
        "inject": lambda: ("/api/inject", {"level": x[0], "seconds": int(x[1]) if len(x) > 1 else 30}),
        "priority": lambda: ("/api/pool_priority", {"priority": x[0]}),
        "io-priority": lambda: ("/api/agent_priority", {"io": x[0]}),
        "memory-priority": lambda: ("/api/agent_priority", {"memory": x[0]}),
        "allocator": lambda: ("/api/allocator", {"on": x[0] == "on"}),
        "desktop": lambda: ("/api/desktop", {"on": x[0] == "on"}),
        "cancel": lambda: ("/api/cancel", {"run_id": x[0]}),
        "adopt": lambda: ("/api/adopt", {"pid": int(x[0]), "provider": x[1], "session": x[2] if len(x) > 2 else None}),
        "queue-order": lambda: ("/api/queue_order", {"order": x[0]}),
        "memory-budget": lambda: ("/api/memory", {"budget_gib": None if x[0] == "off" else float(x[0])}),
        "memory-trim": lambda: ("/api/memory", {"trim": x[0] == "on"}),
        "memory-pause": lambda: ("/api/memory", {"pause": x[0] == "on"}),
        "memory-limit": lambda: ("/api/memory", {"hard_limit_gib": None if x[0] == "off" else float(x[0])}),
        "rollback": lambda: ("/api/rollback", {}),
        "resume-control": lambda: ("/api/resume_control", {}),
        "shutdown": lambda: ("/api/shutdown", {}),
    }
    if v == "status":
        s = call(a.instance, "/api/state")
        print(json.dumps(s, indent=1, default=str) if a.json else summary(s))
        return 0
    if v not in routes:
        ap.error(f"unknown verb {v}")
    print(json.dumps(call(a.instance, *routes[v]())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
