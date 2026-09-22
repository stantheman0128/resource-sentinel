"""Small S3 fixture with a live child and an original cooperative deadline.

This module never grants admission or alters a Job. The parent test must launch
it through the real managed wrapper. The scope document is only a locator;
each process verifies actual native membership before consuming CPU. No user
files, memory growth, scheduler process kill or unbounded child fanout.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


_INTERRUPTED = False


def _interrupt(*_):
    global _INTERRUPTED
    _INTERRUPTED = True


def run(directory, *, child=False):
    from sentinel.adaptive.contracts import IdentityStatus, strict_json_loads
    from sentinel.adaptive.identity import VerifiedProcess
    from sentinel.adaptive.native_job import NativeJob, JobAccess
    from tests.windows.adaptive_recovery_runner import CaseSpec, RawEvents, _require, _tick

    directory = Path(directory).resolve(strict=True)
    daily = (Path.home() / ".resource-sentinel").resolve()
    _require(directory != daily and daily not in directory.parents, "s3_workload_daily_directory_forbidden")
    payload = strict_json_loads((directory / "case.json").read_bytes())
    spec = CaseSpec(**{key: payload[key] for key in ("run_id", "case", "iteration", "scope_nonce", "started_tick")})
    spec.check_time(_tick())
    # The runner writes this after a real native Job is present and before
    # invoking CreateProcessW. It is never used as mutation/admission authority.
    scope = strict_json_loads((directory / "job-locator.json").read_bytes())
    label = "child" if child else "root"
    raw = RawEvents(spec, directory / ("workload-" + label + ".jsonl"))
    current, job, descendant = None, None, None
    try:
        current = VerifiedProcess.current()
        observed = current.observe()
        _require(observed.status is IdentityStatus.ALIVE and observed.identity == current.identity,
                 "s3_workload_self_identity_unverified")
        job = NativeJob.open(scope["job_name"], scope["job_nonce"], scope["logon_id"], access=JobAccess.QUERY)
        _require(current.is_in_job(job.handle) is True, "s3_workload_not_contained")
        raw.append("workload_ready", tick=_tick(), role=label, identity=current.identity.to_dict(),
                   execution_id=scope["execution_id"], job_nonce=job.nonce, in_expected_job=True)
        if not child:
            descendant = subprocess.Popen([sys.executable, "-m", "tests.fixtures.adaptive_recovery_workload",
                                            "--directory", str(directory), "--child"])
        seed = b"sentinel-s3-public-fixture" * 128
        reason = "self_deadline"
        while _tick() < spec.deadline_tick:
            if _INTERRUPTED or (directory / "stop-workload").exists():
                reason = "cooperative_stop"
                break
            if not child and (directory / "exit-root").exists():
                # This case intentionally leaves the child in the same Job.
                # The child's original deadline remains unchanged. Root exit
                # is not cleanup; the external observer retains the Job.
                reason = "root_exit_with_live_child"
                break
            if child:
                for _ in range(128):
                    seed = hashlib.sha256(seed).digest()
            else:
                time.sleep(.02)
        raw.append("workload_exiting", tick=_tick(), role=label, reason=reason,
                   child_alive=None if descendant is None else descendant.poll() is None)
        if descendant is not None and reason != "root_exit_with_live_child":
            (directory / "stop-workload").touch(exist_ok=True)
            while descendant.poll() is None:
                try:
                    descendant.wait(timeout=.1)
                except (subprocess.TimeoutExpired, KeyboardInterrupt):
                    pass
        return 0
    finally:
        failures = []
        # Each known owner gets one close attempt even when another fails.
        # An ambiguous close is never retried or lost by process unwinding.
        for owner in (job, current):
            if owner is not None:
                try:
                    owner.close()
                except BaseException as error:
                    failures.append((owner, error))
        if failures:
            from tests.fixtures.adaptive_recovery_host import retain_cleanup
            retain_cleanup((job, current, descendant, failures), failures[0][1])


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--child", action="store_true")
    options = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Windows native fixture required")
    signal.signal(signal.SIGINT, _interrupt)
    return run(options.directory, child=options.child)


if __name__ == "__main__":
    raise SystemExit(main())
