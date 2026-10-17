#!/usr/bin/env python3
"""Replay the srun queue (policy.queue_order and the daemon's admission pass) on a synthetic command mix, to
compare queue orders before a live run.

The model, stated rather than measured:
  - commands arrive as a Poisson stream from four sessions (one focus, two normal, one batch), each a test
    (60%, median 20 s, 0.5 GiB), a build (30%, median 120 s, 2 GiB) or a long job (10%, median 900 s, 3 GiB);
    lengths are log-normal.
  - admission has --room GiB (the daemon's RAM room after Stan's 6 GiB and the margin). A run holds its memory
    estimate while it runs, and each second admission walks the waiting runs in the order's sequence and starts
    every one that fits, as admit_once does.
  - a run's length does not change with how many run at once (CPU sharing is left out), and the order sees the
    length only through an estimate with log-normal error, since the median of earlier runs is not exact.
  - fair share counts run seconds per session, where the daemon counts CPU seconds.
--load sets the arrival rate: offered memory-seconds per second over the room.

  python scripts/guardian-queue-sim.py --load 0.9 --seeds 20
"""
import argparse
import json
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import policy as P  # noqa: E402

KINDS = [("test", 0.6, 20, 0.5), ("build", 0.3, 120, 2.0), ("long", 0.1, 900, 3.0)]  # name, share, median s, GiB
SESSIONS = [("s1", "focus"), ("s2", "normal"), ("s3", "normal"), ("s4", "batch")]
SIGMA = 0.8  # spread of the log-normal lengths


def mix(rng, hours, load, room, est_error):
    mean_mem_s = sum(share * med * math.exp(SIGMA ** 2 / 2) * gib for _, share, med, gib in KINDS)
    rate = load * room / mean_mem_s  # arrivals per second
    t, jobs = 0.0, []
    while True:
        t += rng.expovariate(rate)
        if t >= hours * 3600:
            return jobs
        kind, _, med, gib = rng.choices(KINDS, [k[1] for k in KINDS])[0]
        length = max(1, round(med * math.exp(rng.gauss(0, SIGMA))))
        session, cls = rng.choice(SESSIONS)
        jobs.append({"t_request": int(t), "kind": kind, "len": length, "gib": gib, "session": session, "cls": cls,
                     "est_s": length * math.exp(rng.gauss(0, est_error))})


def simulate(jobs, order, room):
    weights = P.DEFAULTS["cpu"]["allocation_weights"]
    used = {s: 0.0 for s, _ in SESSIONS}
    pending, waiting, running, done = sorted(jobs, key=lambda j: j["t_request"]), [], [], []
    i, t = 0, 0
    while i < len(pending) or waiting or running:
        while i < len(pending) and pending[i]["t_request"] <= t:
            waiting.append(dict(pending[i]))
            i += 1
        for j in [j for j in running if j["t_end"] <= t]:
            running.remove(j)
            done.append(j)
        free = room - sum(j["gib"] for j in running)
        for j in waiting:
            j["share"] = used[j["session"]] / weights[j["cls"]]
        for j in P.queue_order(waiting, order, t):
            if j["gib"] <= free:
                free -= j["gib"]
                waiting.remove(j)
                j["t_start"], j["t_end"] = t, t + j["len"]
                running.append(j)
        for j in running:
            used[j["session"]] += 1
        t += 1
    return done


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, math.ceil(q * len(xs)) - 1)] if xs else None


def metrics(done):
    wait = lambda js: [j["t_start"] - j["t_request"] for j in js]
    mean = lambda xs: sum(xs) / len(xs) if xs else None
    w = wait(done)
    return {"runs": len(done), "mean_wait_s": mean(w), "p95_wait_s": pct(w, 0.95), "max_wait_s": max(w),
            "mean_slowdown": mean([(j["t_end"] - j["t_request"]) / j["len"] for j in done]),
            **{f"{c}_mean_wait_s": mean(wait([j for j in done if j["cls"] == c])) for c in ("focus", "batch")},
            **{f"{k}_mean_wait_s": mean(wait([j for j in done if j["kind"] == k])) for k in ("test", "long")}}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--load", type=float, default=0.9, help="offered memory-seconds per second over the room")
    ap.add_argument("--room", type=float, default=6.0, help="GiB admission may hand out")
    ap.add_argument("--hours", type=float, default=4.0)
    ap.add_argument("--est-error", type=float, default=0.5, help="log-normal sigma of the length estimate")
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    out = []
    for order in P.QUEUE_ORDERS:
        rows = [metrics(simulate(mix(random.Random(seed), a.hours, a.load, a.room, a.est_error), order, a.room))
                for seed in range(a.seeds)]
        out.append({"order": order, **{k: round(sum(r[k] for r in rows) / len(rows), 1) for k in rows[0]}})
    if a.json:
        print(json.dumps(out, indent=1))
        return 0
    print(f"load {a.load}, room {a.room} GiB, {a.hours} h of arrivals, estimate error sigma {a.est_error}, "
          f"{a.seeds} seeds (mean over seeds; seconds)")
    cols = {"mean_wait_s": "mean wait", "p95_wait_s": "p95 wait", "max_wait_s": "max wait", "mean_slowdown": "slowdown",
            "focus_mean_wait_s": "focus wait", "batch_mean_wait_s": "batch wait", "test_mean_wait_s": "test wait",
            "long_mean_wait_s": "long wait"}
    print(f"  {'order':<11}" + "".join(f"{h:>12}" for h in cols.values()))
    for r in out:
        print(f"  {r['order']:<11}" + "".join(f"{r[c]:>12}" for c in cols))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
