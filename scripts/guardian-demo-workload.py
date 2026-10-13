#!/usr/bin/env python3
"""Repeatable CPU-heavy work for Guardian demos: worker processes compress data with zlib for a fixed time.

Each run prints one line: throughput, cores actually used, this process's priority class and whether Guardian
control is on for it, with the agents' cap. The same script plays both sides of the demo:
  the agent's work   run by a Claude Code session started through srun (scripts/guardian-demo-claude.py)
  Stan's own work    run in a plain terminal, outside Guardian, to time the same work with control off and on
"""
import argparse
import multiprocessing as mp
import os
import sys
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import winjob as wj  # noqa: E402

PRIORITY_ZH = {"normal": "正常", "below_normal": "低於正常", "above_normal": "高於正常", "idle": "閒置", "high": "高"}


def work(seconds):
    data = os.urandom(1 << 14) * 64  # 1 MiB with repeats, so zlib has real work to do
    cpu0, end, done = time.process_time(), time.perf_counter() + seconds, 0
    while time.perf_counter() < end:
        zlib.compress(data, 6)
        done += len(data)
    return done, time.process_time() - cpu0


def guardian_state(instance):
    """Membership alone says nothing about control: turning control off removes the limits, not the job."""
    try:
        job = wj.Job.open(f"{instance}.AllAgents")
    except OSError:
        return "不在 Guardian 裡"
    try:
        if not wj.in_job(os.getpid(), job.h):
            return "不在 Guardian 裡"
        cpu = job.cpu()
        if cpu["mode"] == "hard_cap":
            return f"Guardian 控管開，agent 上限 {cpu['cores']:.1f} 核"
        return "Guardian 控管關，沒有上限"
    finally:
        job.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seconds", type=float, default=30)
    ap.add_argument("--workers", type=int, default=2 * wj.NCPU, help="worker processes (default 2 per logical CPU)")
    ap.add_argument("--instance", default="onoff", help="Guardian instance to check membership against")
    a = ap.parse_args()
    # a piped stdout (Claude Code's Bash tool) would otherwise get the ANSI code page and show the Chinese as mojibake
    sys.stdout.reconfigure(encoding="utf-8")
    before = wj.priority_class(os.getpid())
    with mp.Pool(a.workers) as pool:
        res = pool.map(work, [a.seconds] * a.workers)
    mib, cpu = sum(r[0] for r in res) / 2 ** 20, sum(r[1] for r in res)
    after = wj.priority_class(os.getpid())  # Guardian's control toggle changes it; an arrow marks a mid-run switch
    prio = PRIORITY_ZH.get(after, "?") if after == before else \
        f"{PRIORITY_ZH.get(before, '?')}→{PRIORITY_ZH.get(after, '?')}"
    print(f"[{time.strftime('%H:%M:%S')}] {a.workers} 個行程跑 {a.seconds:g} 秒：速度 {mib / a.seconds:.0f} MiB/s，"
          f"平均用了 {cpu / a.seconds:.1f} 核，優先權 {prio}，{guardian_state(a.instance)}",
          flush=True)


if __name__ == "__main__":
    main()
