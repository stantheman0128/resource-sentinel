"""Opt-in P1 recovery actors. Never imported by the production scheduler.

All actors operate on one random test Job and one fresh case directory. The
filesystem rendezvous and miniature SQLite store are fixture protocols, not the
planned production IPC, authority, or recovery implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from tests.windows.adaptive_win32 import (  # noqa: E402
    NamedMutex, OwnedJob, ProcessHandle, current_identity, launch_in_job,
    require_supported_host, interrupt_time_100ns,
)


def write_json(path: Path, value: dict) -> None:
    """Durable intent before Set; replace only a file in this fixture directory."""
    raw = json.dumps(value, sort_keys=True, allow_nan=False).encode("utf-8")
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # A concurrent Windows reader may momentarily deny replacement. Bounded
    # retry preserves the fixture's atomic record semantics; no partial write.
    for attempt in range(6):
        try:
            os.replace(temporary, path)
            break
        except PermissionError:
            if attempt == 5:
                raise
            time.sleep(0.02)


def read_json(path: Path) -> dict:
    if path.stat().st_size > 64 * 1024:
        raise ValueError("fixture_record_too_large")
    return json.loads(path.read_text(encoding="utf-8"))


def tick() -> str:
    # Only test orchestration/timing, not a production cross-process lease clock.
    return str(time.monotonic_ns())


def mark(case: Path, name: str, **values: object) -> None:
    write_json(case / f"{name}.json", {"tick_ns": tick(),
               "interrupt_tick_100ns": str(interrupt_time_100ns()), **values})


def wait_file(path: Path, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists():
            return True
        time.sleep(0.01)
    return path.exists()


def load_case(path: Path) -> tuple[Path, dict]:
    if os.environ.get("SENTINEL_ADAPTIVE_WINDOWS_SPIKES") != "1":
        raise RuntimeError("explicit_windows_spike_opt_in_required")
    case = path.resolve(strict=True)
    config = read_json(case / "case.json")
    nonce = config["nonce"]
    if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
        raise ValueError("invalid_fixture_nonce")
    if case.name != nonce or config.get("test_only") is not True:
        raise ValueError("invalid_fixture_directory")
    if not config["job_name"].startswith("Local\\ResourceSentinel.Test."):
        raise ValueError("not_a_test_job")
    return case, config


def manifest_record(config: dict, **updates: object) -> dict:
    value = {
        "schema_version": 1, "test_only": True, "nonce": config["nonce"],
        "job_name": config["job_name"], "execution_id": config["nonce"],
        "original": {"flags": 0, "rate_bp": 10000}, "last_applied": None,
        "pending_intent": None, "guardian_identity": config["guardian_identity"],
        "allocation_floor": {"cpu_units": 1, "physical_bytes": 67108864,
                             "commit_bytes": 67108864, "io_slots": 0},
        "sequence": 1,
    }
    value.update(updates)
    value["sha256"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    return value


def verified_manifest(case: Path, config: dict) -> dict:
    value = read_json(case / "manifest.json")
    digest = value.pop("sha256")
    if hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest() != digest:
        raise ValueError("manifest_hash_mismatch")
    if (value["nonce"], value["job_name"], value["guardian_identity"]) != (
            config["nonce"], config["job_name"], config["guardian_identity"]):
        raise ValueError("manifest_scope_mismatch")
    return value


def same_control(left: dict, right: dict | None) -> bool:
    if right is None:
        return False
    return left["flags"] == right["flags"] and left["rate_bp"] == right["rate_bp"]


def compare_restore(job: OwnedJob, case: Path, config: dict) -> dict:
    """Caller must already hold the mutate mutex and prove writer fencing."""
    before = job.query_cpu()
    if not before["flags"] & 1:
        return {"before": before, "after": before, "set_called": False,
                "result": "RESTORED"}
    manifest = verified_manifest(case, config)
    pending = manifest["pending_intent"]
    possible = [manifest["last_applied"]]
    if pending:
        possible.extend((pending["old"], pending["new"]))
    if not any(same_control(before, item) for item in possible):
        raise RuntimeError("external_control_conflict")
    after = job.disable()  # ABI owns the flags=0, rate=10000 binding.
    if after["flags"] & 1:
        raise RuntimeError("restore_readback_enabled")
    return {"before": before, "after": after, "set_called": True,
            "result": "RESTORED"}


def fixture_store(case: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(case / "fixture.sqlite3", timeout=0.1)
    connection.execute("CREATE TABLE IF NOT EXISTS allocation (id TEXT PRIMARY KEY, state TEXT)")
    connection.execute("CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, state TEXT, expires INTEGER)")
    connection.execute("INSERT OR IGNORE INTO allocation VALUES ('own', 'held')")
    connection.commit()
    return connection


def worker(case: Path, config: dict) -> int:
    # No host eligibility check: this deliberately is the sole workload in Job.
    with_job = OwnedJob.open(config["job_name"], config["nonce"])
    handle = ProcessHandle.open(os.getpid())
    try:
        identity = handle.identity()
        if not handle.is_in_job(with_job):
            raise RuntimeError("workload_not_in_owned_job")
        # The workload does not retain a backup/control handle. Only the test
        # infrastructure owns recovery handles after this membership probe.
        with_job.close()
        mark(case, "worker-ready", identity=identity, membership=True)
        deadline = time.monotonic() + 120
        cycles = 0
        while time.monotonic() < deadline and not (case / "stop").exists():
            cycles += 1
            mark(case, "worker-progress", cycles=cycles, identity=identity)
            time.sleep(0.05)
        mark(case, "worker-exit", voluntary=True, cycles=cycles,
             reason="stop_file" if (case / "stop").exists() else "fixture_deadline")
        return 0
    finally:
        handle.close()
        with_job.close()


def root(case: Path, config: dict) -> int:
    # Ordinary descendant inheritance is the behavior being observed; no assign,
    # suspension, breakaway, parent spoofing, or Job-handle inheritance is used.
    child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                              "worker", str(case)], close_fds=True)
    if not wait_file(case / "worker-ready.json", 10):
        return 125
    mark(case, "root-ready", identity=current_identity(), child_pid=child.pid)
    if not wait_file(case / "root-exit-now", 20):
        return 125
    mark(case, "root-exit", identity=current_identity(), child_pid=child.pid)
    return 7


def helper(case: Path, config: dict) -> int:
    require_supported_host()
    mark(case, "helper-ready", identity=current_identity())
    if not wait_file(case / "helper-go", 20):
        return 125
    # Last valid fixture decision, then process death. No Set-cap API here.
    mark(case, "helper-decision", sequence=2)
    os._exit(73)


def wrapper(case: Path, config: dict) -> int:
    require_supported_host()
    job = OwnedJob.open(config["job_name"], config["nonce"])
    # It deliberately retains its own backup handle until the injected crash.
    command = subprocess.list2cmdline([sys.executable, str(Path(__file__).resolve()),
                                      "worker", str(case)])
    process = launch_in_job(job, sys.executable, command)
    mark(case, "wrapper-ready", identity=current_identity(), root=process.identity())
    if not wait_file(case / "wrapper-exit-now", 20):
        return 125
    mark(case, "wrapper-injected", identity=current_identity(), point="wrapper_loss")
    os._exit(74)


def guardian(case: Path, config: dict) -> int:
    require_supported_host()
    identity = current_identity()
    config = {**config, "guardian_identity": identity}
    # Harness adds the exact identity to immutable case.json before releasing go.
    mark(case, "guardian-ready", identity=identity, role="guardian", fixture_version=1)
    if not wait_file(case / "guardian-go", 20):
        return 125
    config = read_json(case / "case.json")
    if config["guardian_identity"] != identity:
        raise RuntimeError("guardian_identity_mismatch")
    point = config["fault"]
    job = OwnedJob.open(config["job_name"], config["nonce"])
    policy = NamedMutex(config["policy_mutex"], config["nonce"])
    mutation = NamedMutex(config["mutation_mutex"], config["nonce"])
    helper_handle = None
    wrapper_handle = None
    if point == "lease_renewal":
        helper_identity = read_json(case / "helper-ready.json")["identity"]
        helper_handle = ProcessHandle.open(helper_identity["pid"], helper_identity["created_filetime_100ns"])
    if point == "wrapper_loss":
        wrapper_identity = read_json(case / "wrapper-ready.json")["identity"]
        wrapper_handle = ProcessHandle.open(wrapper_identity["pid"], wrapper_identity["created_filetime_100ns"])
    try:
        policy.acquire(5)
        mutation.acquire(5)
        before = job.query_cpu()
        if before["flags"] & 1:
            raise RuntimeError("initial_job_not_disabled")
        if point == "intent_before":
            mark(case, "injected", point=point, readback=before)
            os._exit(71)
        target = {"flags": 5, "rate_bp": config["rate_bp"]}
        manifest = manifest_record(config, pending_intent={"old": before, "new": target})
        write_json(case / "manifest.json", manifest)
        mark(case, "intent-durable", readback=before)
        if point == "intent_after_set_before":
            mark(case, "injected", point=point)
            os._exit(71)
        if point == "grant_before_cap":
            with fixture_store(case) as store:
                store.execute("INSERT INTO grants VALUES ('fixture-grant', 'recorded', ?)",
                              (int(time.time()) + 3600,))
            mark(case, "grant-committed", enforcement="not_applicable")
            # Same policy lock, fresh authoritative fixture read before any Set.
        with fixture_store(case) as store:
            grants = store.execute("SELECT COUNT(*) FROM grants WHERE state='recorded'").fetchone()[0]
        if grants:
            mark(case, "apply-rejected", reason="fixture_grant", readback=job.query_cpu())
            mutation.release()
            policy.release()
            return 0
        # The shared ABI's regular Set helper includes Query. This deliberately
        # raw binding exposes the real Set/Query crash window under durable intent.
        job.set_cpu_rate_unverified(config["rate_bp"])
        if point == "set_after_query_before":
            mark(case, "injected", point=point)
            os._exit(71)
        after = job.query_cpu()
        if not same_control(after, target):
            raise RuntimeError("apply_readback_mismatch")
        mark(case, "applied-ack", readback=after)
        if point == "query_after_audit_before":
            mark(case, "injected", point=point)
            os._exit(71)
        if point == "grant_commit_restore_before":
            with fixture_store(case) as store:
                store.execute("INSERT INTO grants VALUES ('fixture-grant', 'recorded', ?)",
                              (int(time.time()) + 3600,))
            mark(case, "grant-committed", enforcement="restore_pending")
            mark(case, "injected", point=point)
            os._exit(71)
        if point == "guardian_hang":
            mark(case, "guardian-holding-mutex", identity=identity)
            wait_file(case / "allow-hang-exit", 15)
            mark(case, "injected", point=point, voluntary_fault_exit=True)
            os._exit(71)
        mutation.release()
        policy.release()
        if point == "root_exit_after":
            if not wait_file(case / "root-exit.json", 10):
                raise RuntimeError("root_exit_not_observed")
            mark(case, "injected", point=point, active_processes=job.accounting()["active_processes"])
            os._exit(71)
        if point == "guardian_takeover":
            mark(case, "injected", point=point)
            os._exit(71)
        if point == "lease_renewal":
            (case / "helper-go").touch(exist_ok=False)
            if not helper_handle.wait(10):
                raise RuntimeError("helper_did_not_exit")
            decision = read_json(case / "helper-decision.json")
            expiry = int(decision["interrupt_tick_100ns"]) + 60_000_000
            while interrupt_time_100ns() < expiry:
                time.sleep(0.01)
        elif point == "wrapper_loss":
            (case / "wrapper-exit-now").touch(exist_ok=False)
            if not wrapper_handle.wait(10):
                raise RuntimeError("wrapper_did_not_exit")
        elif point == "audit_unavailable":
            # A real exclusive SQLite transaction makes the independent audit
            # connection fail. Restore must not require that transaction.
            with fixture_store(case) as lock:
                lock.execute("BEGIN EXCLUSIVE")
                try:
                    with sqlite3.connect(case / "fixture.sqlite3", timeout=0.02) as audit:
                        audit.execute("UPDATE allocation SET state='audit' WHERE id='own'")
                    raise RuntimeError("expected_audit_lock_failure")
                except sqlite3.OperationalError as error:
                    mark(case, "audit-failed", error=type(error).__name__)
                mutation.acquire(5)
                try:
                    result = compare_restore(job, case, config)
                    mark(case, "guardian-restored", **result, while_db_locked=True)
                finally:
                    mutation.release()
                lock.rollback()
            return 0
        else:
            raise ValueError("unknown_fault_point")
        policy.acquire(5)
        mutation.acquire(5)
        try:
            result = compare_restore(job, case, config)
            mark(case, "guardian-restored", **result)
        finally:
            mutation.release()
            policy.release()
        return 0
    except BaseException:
        # Error reporting cannot substitute for fencing/recovery. The independent
        # outside observer restores after this exact guardian process exits.
        raise
    finally:
        if helper_handle:
            helper_handle.close()
        if wrapper_handle:
            wrapper_handle.close()
        if mutation.acquired:
            mutation.release()
        if policy.acquired:
            policy.release()
        mutation.close()
        policy.close()
        job.close()


def restore(case: Path, config: dict, role: str) -> int:
    require_supported_host()
    old = config["guardian_identity"]
    old_handle = ProcessHandle.open(old["pid"], old["created_filetime_100ns"])
    job = OwnedJob.open(config["job_name"], config["nonce"])
    mutex = NamedMutex(config["mutation_mutex"], config["nonce"])
    mark(case, f"{role}-ready", identity=current_identity(), old_identity=old)
    try:
        if not old_handle.wait(30):
            mark(case, f"{role}-blocked", reason="old_guardian_still_alive")
            return 125
        mark(case, f"{role}-death-confirmed", old_identity=old)
        # Both contenders already have the exact old handle; the second waits
        # until contender one holds the mutex before attempting recovery.
        if role == "restore-b" and config["fault"] == "guardian_takeover":
            if not wait_file(case / "restore-a-mutex-held.json", 10):
                raise RuntimeError("first_contender_did_not_acquire")
        abandoned = mutex.acquire(10)
        if role == "restore-a" and config["fault"] == "guardian_takeover":
            mark(case, "restore-a-mutex-held", abandoned=abandoned)
            # Allow contender B to observe actual mutex ownership then simulate
            # a crash at takeover before any API restoration.
            time.sleep(0.1)
            os._exit(72)
        try:
            result = compare_restore(job, case, config)
            mark(case, f"{role}-restored", abandoned=abandoned, **result)
        finally:
            mutex.release()
        return 0
    finally:
        old_handle.close()
        mutex.close()
        job.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("worker", "root", "helper", "wrapper", "guardian", "restore-a", "restore-b"))
    parser.add_argument("case", type=Path)
    args = parser.parse_args()
    case, config = load_case(args.case)
    try:
        if args.role.startswith("restore-"):
            return restore(case, config, args.role)
        return globals()[args.role](case, config)
    except BaseException as error:
        mark(case, f"{args.role}-error", error=type(error).__name__,
             reason=str(error)[:200], win32_error=getattr(error, "winerror", None))
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
