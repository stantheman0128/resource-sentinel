#!/usr/bin/env python3
"""Control a running Guardian from any terminal (the dashboard calls the same API).

  guardctl status
  guardctl pause claude/s1 | resume claude/s1 | class claude/s1 focus
  guardctl pause-provider codex | resume-provider codex
  guardctl cap 40 | world 10 | hold on | hold off | inject degraded 30 | priority normal | allocator off
  guardctl cancel <run_id> | rollback | resume-control | shutdown
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
             f"pool {s['pool_cores']} cores  priority {s['pool_priority']}",
             f"RAM available {s['available_gib']} GiB  commit headroom {s['commit_headroom_gib']} GiB  "
             f"admission {'open' if s['admission']['open'] else 'closed ' + s['admission']['reason']}"
             f"{'  HOLD' if s['admission']['hold'] else ''}",
             f"experience {s['experience']['level']} ({s['experience']['kind']})  probe {s['experience']['probe']}"]
    for p in s["providers"]:
        lines.append(f"  provider {p['name']:<8} {'PAUSED' if p['paused'] else 'running':<8} {p['cores']} cores")
    for x in s["sessions"]:
        cap = "-" if x["cap_cores"] is None else f"{x['cap_cores']:.2f}"
        lines.append(f"  session {x['key']:<24} {x['cls']:<6} {'PAUSED' if x['paused'] else '':<6} "
                     f"use {x['usage']:.2f} cap {cap} runs {x['runs']}")
    for q in s["queue"]:
        lines.append(f"  queued {q['run_id']} {q['session']} {q['label']!r}: {q['reason']}")
    for a in s["apps"]:
        lines.append(f"  app {a.get('name')}: {a.get('cores')} cores, {a.get('coverage')}")
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
        "class": lambda: ("/api/session", {"key": x[0], "cls": x[1]}),
        "pause-provider": lambda: ("/api/provider", {"name": x[0], "paused": True}),
        "resume-provider": lambda: ("/api/provider", {"name": x[0], "paused": False}),
        "cap": lambda: ("/api/cap", {"cap": float(x[0])}),
        "world": lambda: ("/api/world", {"cpus": int(x[0])}),
        "hold": lambda: ("/api/hold", {"on": x[0] == "on"}),
        "inject": lambda: ("/api/inject", {"level": x[0], "seconds": int(x[1]) if len(x) > 1 else 30}),
        "priority": lambda: ("/api/pool_priority", {"priority": x[0]}),
        "allocator": lambda: ("/api/allocator", {"on": x[0] == "on"}),
        "cancel": lambda: ("/api/cancel", {"run_id": x[0]}),
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
