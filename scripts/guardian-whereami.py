#!/usr/bin/env python3
"""Is this process (and the agent CLI above it) under Guardian control? Ask an agent to run it as a tool command:
the command inherits the CLI's job, so the answer covers the whole session.

  python -I scripts/guardian-whereami.py [--pid N] [--instance main] [--json] [--out FILE]

First line: the answer. Then the parent chain with each process's priority and job membership. --out also appends
the JSON form to FILE, so a test can read the result instead of trusting an agent's summary of it.
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import providers as PV
from sentinel.guardian import winjob as wj
from sentinel.guardian.client import home_dir, whereis
from sentinel.guardian.daemon import safe


def candidates(chain, instance):
    """(provider, session) names this process may sit in: the launcher's, then any session the adopt hook put one of
    its parents in. Only names; the caller checks each against the job."""
    found = []
    if os.environ.get("GUARDIAN_PROVIDER") and os.environ.get("GUARDIAN_SESSION"):
        found.append((os.environ["GUARDIAN_PROVIDER"], os.environ["GUARDIAN_SESSION"]))
    try:
        lines = (home_dir(instance) / "adopt.log").read_text(encoding="utf-8", errors="replace").splitlines()[-200:]
    except OSError:
        lines = []
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict) or not isinstance(row.get("session"), str) or not row.get("provider"):
            continue
        if row.get("cli_pid") in chain and row["session"]:
            # an adopted row carries the daemon's "provider/session"; a refused one only the hook's own name
            found.append(tuple(row["session"].split("/", 1)) if "/" in row["session"] else
                         (row["provider"], row["session"]))
    # the daemon names jobs after safe(name), not the raw name
    return [(safe(p, "other").lower(), safe(s)) for p, s in found]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, default=os.getpid())
    ap.add_argument("--instance", default=os.environ.get("GUARDIAN_INSTANCE") or "main")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--out", help="also append the JSON result to this file")
    a = ap.parse_args(argv)
    table = wj.process_table()
    chain = [a.pid] + wj.ancestors(a.pid, table)
    rows = []
    for pid in chain[:16]:
        w = whereis(pid, a.instance) or {}
        image = table.get(pid, (0, "?"))[1]
        rows.append({"pid": pid, "image": image, "priority": wj.priority_class(pid), "in_any_job": wj.in_job(pid),
                     "guardian_session": w.get("session"), "in_guardian": w.get("in_guardian"),
                     "desktop": w.get("desktop"), "app": PV.protected_app(image, wj.image_path(pid))})
    me = rows[0] if rows else {}
    up = whereis(a.pid, a.instance) is not None
    pooled = wj.in_named_job(a.pid, f"{a.instance}.AllAgents")
    # a desktop job sits under the app's job, outside the pool; its name holds the desktop CLI's pid
    desk = None if up or pooled else next((f"{p}/desk-{c}" for c in chain[:16] for p in PV.DESKTOP_CLIS
                                           if wj.in_named_job(a.pid, f"{a.instance}.d.{p}.desk-{c}")), None)
    app = next((r["app"] for r in rows if r["app"]), "desktop app")
    if not up and pooled:
        # the daemon's pipe is out of reach (a CLI sandbox can block it), but the jobs themselves answer
        named = next((c for c in candidates(chain, a.instance)
                      if wj.in_named_job(a.pid, f"{a.instance}.s.{c[0]}.{c[1]}")), None)
        me["in_guardian"] = True
        answer = (f"CONTROLLED: session {named[0]}/{named[1]} (instance {a.instance}, read from the job; daemon pipe "
                  f"not reachable from here), priority {me.get('priority')}" if named else
                  f"PARTLY KNOWN: inside Guardian {a.instance}'s pool (daemon pipe not reachable from here, so the "
                  f"session is unknown), priority {me.get('priority')}")
    elif not up and desk:
        me["in_guardian"] = True
        answer = (f"CONTROLLED: session {desk} (desktop job under the {app}'s job, instance {a.instance}, read from "
                  f"the job; daemon pipe not reachable from here), priority {me.get('priority')}")
    elif not up:
        answer = f"NOT CONTROLLED: Guardian {a.instance} is not running"
    elif me.get("guardian_session") and me.get("desktop"):
        answer = (f"CONTROLLED: session {me['guardian_session']} (desktop job under the {app}'s job, instance "
                  f"{a.instance}), priority {me['priority']}")
    elif me.get("guardian_session"):
        answer = f"CONTROLLED: session {me['guardian_session']} (instance {a.instance}), priority {me['priority']}"
    elif me.get("in_guardian"):
        answer = f"PARTLY: inside Guardian {a.instance}'s pool but in no session job, priority {me['priority']}"
    else:
        answer = f"NOT CONTROLLED: this process is outside Guardian {a.instance}'s jobs"
    result = {"answer": answer, "instance": a.instance, "daemon_up": up, "chain": rows}
    if a.out:
        with open(a.out, "a", encoding="utf-8") as f:
            f.write(json.dumps(result) + "\n")
    if a.json:
        print(json.dumps(result))
        return 0 if me.get("in_guardian") else 1
    print(answer)
    for r in rows:
        where = r["guardian_session"] or ("guardian pool" if r["in_guardian"] else
                                          "other job" if r["in_any_job"] else "no job")
        print(f"  {r['pid']:>6}  {r['image'][:28]:28} {str(r['priority']):12} {where}"
              + (f"  [{r['app']}]" if r["app"] else ""))
    return 0 if me.get("in_guardian") else 1


if __name__ == "__main__":
    raise SystemExit(main())
