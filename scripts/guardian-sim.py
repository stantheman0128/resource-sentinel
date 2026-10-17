#!/usr/bin/env python3
"""Replay the agents' cap controller (policy.cap_step) against a CPU model, to compare settings before a live run.

The model, stated rather than measured as a whole:
  - each second the programs outside Guardian need O cores. O comes from a ledger (busy x CPUs minus the agents'
    pool, one row per second) or is a constant.
  - the agents want A cores and run at below normal, so they get min(A, cap, CPUs - O).
  - a one-second probe window is late with a probability set by the CPUs left idle, and the experience is
    degraded when 2 of the last 3 windows are late, as in the daemon. The default probabilities give the degraded
    rates of main's ledger, 2026-10-16 17:31 to 10-17 17:38 (86,036 seconds): 4.11% with under 1 CPU idle,
    1.85% with 1 to 4, 0.06% with 4 or more.
So the sweep says what each setting does under that relation between idle CPUs and lateness, not on its own what
Stan feels; the live A/B (docs/guardian.md) checks the chosen setting on the real probe.

  python scripts/guardian-sim.py --ledger ~/.resource-sentinel/guardian/main/guardian.sqlite3
"""
import argparse
import itertools
import json
import math
import random
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import policy as P  # noqa: E402

# per-window late probability q such that 2-of-3 gives the ledger's degraded rate p: 3q^2(1-q) + q^3 = p
LATE = [(1.0, 0.0411), (4.0, 0.0185), (math.inf, 0.0006)]  # (idle below, degraded rate)


def window_q(p):
    lo, hi = 0.0, 1.0
    for _ in range(60):
        q = (lo + hi) / 2
        lo, hi = (q, hi) if 3 * q * q * (1 - q) + q ** 3 < p else (lo, q)
    return lo


Q = [(edge, window_q(p)) for edge, p in LATE]


def late_q(idle):
    return next(q for edge, q in Q if idle < edge)


def ledger_trace(path, ncpu, seconds, pick):
    """`seconds` consecutive rows of O = busy x ncpu - pool: the window with the highest mean O, or the median one."""
    con = sqlite3.connect(f"file:{Path(path).expanduser().as_posix()}?mode=ro", uri=True)
    con.execute("PRAGMA temp_store=MEMORY")
    o = [max(0.0, b * ncpu - (p or 0.0)) for b, p in
         con.execute("SELECT cpu_busy, pool_cores FROM samples WHERE cpu_busy IS NOT NULL ORDER BY t")]
    con.close()
    if len(o) < seconds:
        raise SystemExit(f"the ledger has {len(o)} samples, fewer than {seconds}")
    acc = list(itertools.accumulate(o, initial=0.0))
    means = sorted(((acc[i + seconds] - acc[i]) / seconds, i) for i in range(0, len(o) - seconds, 60))
    i = means[-1][1] if pick == "busiest" else means[len(means) // 2][1]
    return o[i:i + seconds]


def simulate(cfg, trace, want, cap0, seed, ncpu):
    rng = random.Random(seed)
    st, windows = P.CapState(cap=cap0), []
    late = agent = withheld = 0.0
    backoffs = 0
    for t, other in enumerate(trace):
        free = max(0.0, ncpu - other)
        use = min(want, st.cap / 100 * ncpu, free)
        idle = free - use
        windows.append("warn" if rng.random() < late_q(idle) else "ok")
        exp = P.sustained(windows[-3:])
        late += exp != "ok"
        agent += use
        withheld += max(0.0, min(want, free) - use)
        s = P.Sample(t=float(t), age_s=0.5, cpu_busy=(other + use) / ncpu, pool_cores=use, available_gib=30.0,
                     commit_headroom_gib=50.0, experience=exp, experience_kind="probe", ncpu=ncpu)
        st, d = P.cap_step(st, s, cfg)
        backoffs += bool(d and d["kind"] == "foreground_backoff")
    n = len(trace)
    return {"late_pct": 100 * late / n, "agent_cores": agent / n, "withheld_cores": withheld / n, "backoffs": backoffs}


VARIANTS = {"10-13 controller": {}}
for b in (1.0, 2.0, 3.0):
    VARIANTS[f"no back-off with >={b:g} idle"] = {"backoff_idle_cores": b}
for r, share, spacing in itertools.product((1.0, 2.0), (0.25, 0.5, 0.75), (5, 10)):
    VARIANTS[f"faster recovery >={r:g} idle, share {share}, every {spacing} s"] = {
        "recover_idle_cores": r, "recover_idle_share": share, "increase_spacing_seconds": spacing}
for b, r, share, spacing, f in itertools.product((1.0, 2.0), (1.0, 2.0), (0.5,), (5, 10), (0.5, 0.8, 0.9)):
    VARIANTS[f"both: back-off >={b:g}, recover >={r:g}, share {share}, every {spacing} s, x{f}"] = {
        "backoff_idle_cores": b, "recover_idle_cores": r, "recover_idle_share": share,
        "increase_spacing_seconds": spacing, "decrease_factor": f}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--ledger", help="a Guardian ledger with per-second samples; without it O is --other")
    ap.add_argument("--other", type=float, default=2.0, help="constant load outside Guardian without a ledger")
    ap.add_argument("--seconds", type=int, default=1800)
    ap.add_argument("--ncpu", type=int, default=12)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    traces = ({k: ledger_trace(a.ledger, a.ncpu, a.seconds, k) for k in ("busiest", "median")} if a.ledger
              else {f"constant {a.other:g}": [a.other] * a.seconds})
    scenarios = [(name, tr, want, cap0) for name, tr in traces.items() for want, cap0 in ((4, 10), (9, 50))]
    out = []
    for vname, over in VARIANTS.items():
        cfg = P.merged(P.DEFAULTS, {"cpu": over})
        for name, tr, want, cap0 in scenarios:
            runs = [simulate(cfg, tr, want, cap0, seed, a.ncpu) for seed in range(a.seeds)]
            out.append({"variant": vname, "trace": name, "other_mean": round(sum(tr) / len(tr), 2), "want": want,
                        "cap0": cap0, **{k: round(sum(r[k] for r in runs) / len(runs), 3) for k in runs[0]}})
    if a.json:
        print(json.dumps(out, indent=1))
        return 0
    for name, tr, want, cap0 in scenarios:
        print(f"\n{name} (others use {sum(tr) / len(tr):.2f} cores on average), agents want {want}, cap starts "
              f"at {cap0}%")
        print(f"  {'late %':>7} {'agent':>6} {'withheld':>8} {'back-offs':>9}  variant")
        rows = [r for r in out if (r["trace"], r["want"], r["cap0"]) == (name, want, cap0)]
        for r in sorted(rows, key=lambda r: (r["late_pct"], -r["agent_cores"]))[:12] + [rows[0]]:
            print(f"  {r['late_pct']:7.2f} {r['agent_cores']:6.2f} {r['withheld_cores']:8.2f} {r['backoffs']:9.1f}"
                  f"  {r['variant']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
