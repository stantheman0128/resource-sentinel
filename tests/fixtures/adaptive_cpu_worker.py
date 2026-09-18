"""Voluntary, constant-memory CPU fixture for isolated P1 experiments only.

Every process has an absolute deadline of at most 120 seconds from the root's
start. A stop file provides cooperative early cleanup. No scheduler kill is
required. A root crash does not remove the descendants' independent deadline.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "windows"))
from adaptive_win32 import (  # noqa: E402
    JOB_PREFIX, OPT_IN, OwnedJob, ProcessHandle, UnsupportedCapability,
    require_supported_host,
)


def _atomic_json(path, value):
    temporary = path.with_suffix(".pending")
    temporary.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--job-name", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=115)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--leaf", action="store_true")
    parser.add_argument("--deadline", type=float)
    parser.add_argument("--probe-foreign-host", action="store_true")
    args = parser.parse_args()
    started = time.monotonic()
    if os.environ.get(OPT_IN) != "1":
        parser.error("explicit Windows spike opt-in is required")
    if not math.isfinite(args.seconds) or not 0 < args.seconds <= 115:
        parser.error("CPU work duration must be in (0, 115], leaving 5s to exit")
    if not 1 <= args.workers <= 64:
        parser.error("fixture allows only 1..64 workers")
    if args.job_name != JOB_PREFIX + args.nonce:
        parser.error("Job name must identify this test nonce")
    if not args.directory.is_absolute() or not args.directory.is_dir():
        parser.error("fixture directory must already exist at an absolute isolated path")
    deadline = started + args.seconds
    if args.deadline is not None:
        if not math.isfinite(args.deadline):
            parser.error("invalid root deadline")
        deadline = min(deadline, args.deadline)
    # This is the fixture's first behavior after argument validation: query its
    # exact identity and membership before spawning children or doing CPU work.
    job = OwnedJob.open(args.job_name, args.nonce)
    process = ProcessHandle.open_current()
    try:
        record = {**process.identity(), "nonce": args.nonce,
                  "role": "leaf" if args.leaf else "root",
                  "in_expected_job": process.is_in_job(job),
                  "parent_pid": process.parent_pid(),
                  "deadline_monotonic": deadline,
                  "maximum_lifetime_seconds": args.seconds}
    finally:
        process.close()
        job.close()
    if not record["in_expected_job"]:
        _atomic_json(args.directory / f"failed-{os.getpid()}.json", record)
        return 31
    if args.probe_foreign_host:
        try:
            require_supported_host()
        except UnsupportedCapability as exc:
            record["foreign_gate"] = {"status": "unsupported", "reason": exc.reason,
                                      "win32_error": exc.win32_error}
            _atomic_json(args.directory / "foreign-probe.json", record)
            return 0
        record["foreign_gate"] = {"status": "unexpectedly_supported"}
        _atomic_json(args.directory / "foreign-probe.json", record)
        return 32
    _atomic_json(args.directory / f"ready-{os.getpid()}.json", record)
    stop_file = args.directory / "stop"
    children = []
    try:
        if not args.leaf:
            for _ in range(args.workers - 1):
                if time.monotonic() >= deadline or stop_file.exists():
                    break
                children.append(subprocess.Popen([
                    sys.executable, str(Path(__file__).resolve()), "--nonce", args.nonce,
                    "--job-name", args.job_name, "--directory", str(args.directory),
                    "--seconds", str(args.seconds), "--workers", "1", "--leaf",
                    "--deadline", str(deadline),
                ], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, close_fds=True))
        value = 1
        while time.monotonic() < deadline and not stop_file.exists():
            # Bounded arithmetic avoids both growing integers and memory load.
            next_check = min(deadline, time.monotonic() + 0.1)
            while time.monotonic() < next_check:
                for _ in range(16384):
                    value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
        reason = "stop_file" if stop_file.exists() else "self_deadline"
    finally:
        # Root finishing naturally also asks descendants to finish voluntarily.
        if not args.leaf:
            stop_file.touch(exist_ok=True)
        for child in children:
            try:
                child.wait(timeout=max(0.0, min(2.0, started + 119 - time.monotonic())))
            except subprocess.TimeoutExpired:
                # Keep evidence. Never turn an observation timeout into a kill.
                pass
    _atomic_json(args.directory / f"exit-{os.getpid()}.json", {
        **record, "reason": reason, "elapsed_seconds": time.monotonic() - started,
        "children_still_alive": sum(child.poll() is None for child in children),
    })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
