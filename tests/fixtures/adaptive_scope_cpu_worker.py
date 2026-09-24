"""Pinned, voluntary CPU workload for one guardian-owned native S1 scope.

This fixture never admits, creates/assigns a Job, changes control, or releases
capacity. Its root and leaves independently verify exact identity and membership
before publishing ready or burning CPU. CPU work has a shared <=115 s deadline,
followed by at most four seconds of cooperative child-observation grace.
An uncertain native outcome retains the original owner, idle, without claiming
successful exit or cleanup. That exceptional custody hold is not a bounded run.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid


OPT_IN = "SENTINEL_ADAPTIVE_WINDOWS_SPIKES"
MAX_NS = 115_000_000_000
NONCE = re.compile(r"[0-9a-f]{32}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
JOB_PREFIX = "Local\\ResourceSentinel.Test.Job."
_RETAINED = []


class FixtureError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class RetainedOwnerError(FixtureError):
    def __init__(self, reason, owner):
        self.owner = owner
        super().__init__(reason)


def canonical_uuid(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise FixtureError("fixture_uuid_invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise FixtureError("fixture_uuid_invalid")
    return value


def safe_path(value, *, directory=False):
    path = Path(value)
    if not path.is_absolute():
        raise FixtureError("fixture_absolute_path_required")
    for part in (path, *path.parents):
        observed = part.lstat()
        if stat.S_ISLNK(observed.st_mode) or getattr(observed, "st_file_attributes", 0) & 0x400:
            raise FixtureError("fixture_reparse_path_refused")
    observed = path.stat()
    if not (stat.S_ISDIR(observed.st_mode) if directory else stat.S_ISREG(observed.st_mode)):
        raise FixtureError("fixture_path_type_invalid")
    return path.resolve(strict=True)


def parser():
    result = argparse.ArgumentParser()
    result.add_argument("--canonical-root", required=True, type=Path)
    result.add_argument("--source-generation", required=True)
    result.add_argument("--source-digest", required=True)
    result.add_argument("--fixture-sha256", required=True)
    result.add_argument("--nonce", required=True)
    result.add_argument("--job-name", required=True)
    result.add_argument("--directory", required=True, type=Path)
    result.add_argument("--seconds", type=float, default=115)
    result.add_argument("--workers", type=int, default=1)
    result.add_argument("--leaf", action="store_true")
    result.add_argument("--deadline-monotonic-ns", type=int)
    result.add_argument("--probe-foreign-host", action="store_true")
    return result


def validate(args, started_ns):
    canonical_uuid(args.source_generation)
    if any(type(value) is not str or not HASH.fullmatch(value)
           for value in (args.source_digest, args.fixture_sha256)):
        raise FixtureError("fixture_source_pin_invalid")
    if type(args.nonce) is not str or not NONCE.fullmatch(args.nonce):
        raise FixtureError("fixture_nonce_invalid")
    if args.job_name != JOB_PREFIX + args.nonce:
        raise FixtureError("fixture_job_invalid")
    if (type(args.seconds) not in (int, float) or not math.isfinite(args.seconds)
            or not 0 < args.seconds <= 115):
        raise FixtureError("fixture_duration_invalid")
    if type(args.workers) is not int or not 1 <= args.workers <= 64:
        raise FixtureError("fixture_workers_invalid")
    if args.leaf and (args.workers != 1 or args.deadline_monotonic_ns is None or args.probe_foreign_host):
        raise FixtureError("fixture_leaf_invalid")
    if args.probe_foreign_host and args.workers != 1:
        raise FixtureError("fixture_probe_must_not_spawn")
    deadline = started_ns + int(args.seconds * 1_000_000_000)
    if args.deadline_monotonic_ns is not None:
        supplied = args.deadline_monotonic_ns
        if type(supplied) is not int or not 0 < supplied - started_ns <= MAX_NS:
            raise FixtureError("fixture_deadline_invalid")
        deadline = min(deadline, supplied)
    directory = safe_path(args.directory, directory=True)
    production = (Path.home() / ".resource-sentinel").resolve()
    if directory == production or production in directory.parents:
        raise FixtureError("fixture_directory_must_be_isolated")
    return directory, deadline


def bootstrap(args):
    """Pins are consistency evidence, never a substitute for original admission."""
    if not sys.flags.isolated or os.environ.get(OPT_IN) != "1":
        raise FixtureError("fixture_isolated_opt_in_required")
    if any(name == "sentinel" or name.startswith("sentinel.") or name == "sentinel_daily_bootstrap"
           for name in sys.modules):
        raise FixtureError("fixture_sentinel_preloaded")
    root = safe_path(args.canonical_root, directory=True)
    expected = safe_path(Path.home() / "Projects" / "resource-sentinel", directory=True)
    if root != expected:
        raise FixtureError("fixture_canonical_root_mismatch")
    script = safe_path(Path(__file__).absolute())
    if script.stat().st_size > 256 * 1024 or hashlib.sha256(script.read_bytes()).hexdigest() != args.fixture_sha256:
        raise FixtureError("fixture_source_changed")
    # -I removes cwd, script directory and PYTHONPATH. Refuse another Sentinel
    # provider rather than merely hoping our inserted path wins import order.
    for entry in sys.path:
        if entry and ((Path(entry) / "sentinel").exists() or (Path(entry) / "sentinel_daily_bootstrap.py").exists()):
            raise FixtureError("fixture_ambient_sentinel_path")
    sys.path.insert(0, str(root))
    generation = importlib.import_module("sentinel.adaptive.daily_generation")
    identity = importlib.import_module("sentinel.adaptive.identity")
    jobs = importlib.import_module("sentinel.adaptive.native_job")
    host = importlib.import_module("sentinel.adaptive.host_authority")
    manifest = generation.SourceManifest.capture(root)
    if manifest.digest != args.source_digest:
        raise FixtureError("fixture_source_generation_mismatch")
    generation.verify_import_provenance(manifest, root)
    return SimpleNamespace(identity=identity, jobs=jobs, host=host,
                           generation=generation, manifest=manifest, root=root)


def publish(path, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > 64 * 1024:
        raise FixtureError("fixture_evidence_oversized")
    pending = path.with_suffix(".pending")
    with pending.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    # No overwrite: stale evidence cannot silently become this run's record.
    os.link(pending, path)
    pending.unlink()


def child_command(args, deadline):
    executable = safe_path(Path(getattr(sys, "_base_executable", None) or sys.executable))
    if executable != Path(sys.executable).resolve(strict=True) or executable.name.lower() in {"py.exe", "pyw.exe"}:
        raise FixtureError("fixture_direct_base_python_required")
    return [str(executable), "-I", str(Path(__file__).resolve(strict=True)),
            "--canonical-root", str(args.canonical_root), "--source-generation", args.source_generation,
            "--source-digest", args.source_digest, "--fixture-sha256", args.fixture_sha256,
            "--nonce", args.nonce, "--job-name", args.job_name, "--directory", str(args.directory),
            "--seconds", str(args.seconds), "--workers", "1", "--leaf",
            "--deadline-monotonic-ns", str(deadline)]


class NativeChildren:
    """Original CreateProcess outputs; no PID reopen, breakaway or Job mutation."""
    def __init__(self):
        if os.name != "nt":
            raise FixtureError("fixture_windows_required")
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w = c, w
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        class Startup(c.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                        ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                        ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD),
                        ("wShowWindow", w.WORD), ("cbReserved2", w.WORD), ("lpReserved2", c.POINTER(w.BYTE)),
                        ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]
        class Info(c.Structure):
            _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]
        self.Startup, self.Info = Startup, Info
        self.create = self.kernel.CreateProcessW
        self.create.argtypes = [w.LPCWSTR, w.LPWSTR, w.LPVOID, w.LPVOID, w.BOOL, w.DWORD,
                                w.LPVOID, w.LPCWSTR, c.POINTER(Startup), c.POINTER(Info)]
        self.create.restype = w.BOOL
        self.wait = self.kernel.WaitForSingleObject
        self.wait.argtypes, self.wait.restype = [w.HANDLE, w.DWORD], w.DWORD
        self.close = self.kernel.CloseHandle
        self.close.argtypes, self.close.restype = [w.HANDLE], w.BOOL

    def spawn(self, command, owner):
        info = self.Info()
        entry = {"info": info, "state": "creation_unknown", "closed": set(), "closing": None,
                 "verified": None, "identity": None}
        owner.children.append(entry)  # Publication precedes the native call.
        startup = self.Startup()
        startup.cb = self.c.sizeof(startup)
        try:
            ok = self.create(command[0], self.c.create_unicode_buffer(subprocess.list2cmdline(command)),
                             None, None, False, 0x08000000, None, str(owner.directory),
                             self.c.byref(startup), self.c.byref(info))
        except BaseException as error:
            owner.errors.append(error)
            raise RetainedOwnerError("fixture_child_create_unknown", owner) from error
        if not ok:
            if not any((info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId)):
                entry["state"] = "absent"
                raise FixtureError("fixture_child_create_failed")
            raise RetainedOwnerError("fixture_child_create_unknown", owner)
        if not all((info.hProcess, info.hThread, info.dwProcessId, info.dwThreadId)):
            raise RetainedOwnerError("fixture_child_handles_unknown", owner)
        entry["state"] = "owned"
        entry["verified"] = owner.modules.identity.VerifiedProcess.duplicate_from_handle(
            info.hProcess, expected_pid=int(info.dwProcessId), expected_logon_id=owner.process.identity.logon_id)
        entry["identity"] = entry["verified"].identity.to_dict()
        if entry["verified"].is_in_job(owner.job.handle) is not True:
            raise FixtureError("fixture_child_membership_unverified")
        return entry

    def alive(self, child):
        if child["state"] == "absent":
            return False
        if child["state"] != "owned" or child["closing"] is not None:
            raise FixtureError("fixture_child_custody_unknown")
        try:
            result = self.wait(child["info"].hProcess, 0)
        except BaseException as error:
            raise FixtureError("fixture_child_wait_unknown") from error
        if result not in (0, 258):
            raise FixtureError("fixture_child_wait_unknown")
        return result == 258

    def close_child(self, child):
        if child["state"] in {"absent", "closed"}:
            return
        if self.alive(child):
            raise FixtureError("fixture_child_still_alive")
        if child["verified"] is not None and "verified" not in child["closed"]:
            child["closing"] = "verified"
            child["verified"].close()
            child["closed"].add("verified")
            child["closing"] = None
        for name in ("hThread", "hProcess"):
            if name in child["closed"]:
                continue
            child["closing"] = name
            if not self.close(getattr(child["info"], name)):
                raise FixtureError("fixture_child_close_unknown")
            child["closed"].add(name)
            child["closing"] = None
        child["state"] = "closed"


class WorkloadOwner:
    def __init__(self, args, directory, deadline, modules):
        self.args, self.directory, self.deadline, self.modules = args, directory, deadline, modules
        self.process = self.job = self.native = None
        self.children, self.errors = [], []
        self.closed, self.closing, self.quarantined = set(), None, False
        self.record = None
        _RETAINED.append(self)

    def open(self):
        self.process = self.modules.identity.VerifiedProcess.current()
        self.job = self.modules.jobs.NativeJob.open(self.args.job_name, self.args.nonce,
            self.process.identity.logon_id, access=self.modules.jobs.JobAccess.QUERY)
        if self.process.is_in_job(self.job.handle) is not True:
            raise FixtureError("fixture_membership_unverified")
        self.native = NativeChildren()

    def settle(self):
        if self.quarantined or self.closing is not None:
            return False
        # Original cleanup-bearing errors are never discarded or reconstituted.
        for error in self.errors:
            if any(getattr(error, name, None) for name in (
                    "_native_job_cleanup", "_identity_handle_cleanup", "_native_cleanup_errors",
                    "_native_close_outcome_unknown", "_native_duplicate_outcome_unknown")):
                self.quarantined = True
                return False
        if self.children:
            if any(child["state"] == "creation_unknown" or child.get("closing") is not None
                   for child in self.children):
                self.quarantined = True
                return False
            try:
                if any(self.native.alive(child) for child in self.children if child["state"] != "closed"):
                    return False
            except BaseException as error:
                # Read failure retains originals; only read observation may be
                # retried. No close has started and there is no new creation.
                if len(self.errors) < 16:
                    self.errors.append(error)
                return False
        try:
            if self.children:
                for child in self.children:
                    self.native.close_child(child)
            for name in ("job", "process"):
                resource = getattr(self, name)
                if resource is not None and name not in self.closed:
                    self.closing = name
                    resource.close()
                    self.closed.add(name)
                    self.closing = None
            _RETAINED.remove(self)
            return True
        except BaseException as error:
            self.errors.append(error)
            if (isinstance(error, FixtureError)
                    and error.reason in {"fixture_child_wait_unknown", "fixture_child_still_alive"}
                    and self.closing is None
                    and all(child.get("closing") is None for child in self.children)):
                # close_child rechecks liveness before touching any handle.
                # A failed second read has the same retry rule as the first.
                return False
            self.quarantined = True
            return False


def cpu_work(deadline, stop):
    value, chunks = 1, 0
    while time.monotonic_ns() < deadline and not os.path.lexists(stop):
        for _ in range(4096):
            value = (value * 1664525 + 1013904223) & 0xffffffff
        chunks += 1
    return chunks, "stop_file" if os.path.lexists(stop) else "self_deadline"


def verify_ready(record, *, identity, args, deadline):
    expected = {"identity": identity, "nonce": args.nonce, "job_name": args.job_name,
                "source_generation": args.source_generation, "source_digest": args.source_digest,
                "fixture_sha256": args.fixture_sha256, "deadline_monotonic_ns": deadline,
                "in_expected_job": True, "role": "leaf", "status": "ready", "schema_version": 1}
    if not isinstance(record, dict) or any(type(record.get(key)) is not type(value) or record.get(key) != value
                                          for key, value in expected.items()):
        raise FixtureError("fixture_child_ready_mismatch")


def read_ready(path):
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise FixtureError("fixture_evidence_oversized")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise FixtureError("fixture_evidence_duplicate_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(FixtureError("fixture_evidence_nonfinite")))


def run(args, directory, deadline, modules):
    owner = WorkloadOwner(args, directory, deadline, modules)
    started = time.monotonic_ns()
    stop = directory / "stop"
    primary, result = None, 0
    try:
        owner.open()
        identity = owner.process.identity.to_dict()
        record = {"schema_version": 1, "status": "ready", "identity": identity, **identity,
                  "nonce": args.nonce, "job_name": args.job_name, "in_expected_job": True,
                  "readiness_scope": "this_process_only",
                  "role": "leaf" if args.leaf else "root", "parent_pid": os.getppid(),
                  "source_generation": args.source_generation, "source_digest": args.source_digest,
                  "fixture_sha256": args.fixture_sha256, "deadline_monotonic_ns": deadline,
                  "deadline_monotonic": deadline / 1_000_000_000,
                  "maximum_cpu_work_seconds": args.seconds, "cooperative_cleanup_grace_seconds": 4}
        owner.record = record
        if args.probe_foreign_host:
            try:
                modules.host.read_host_capability()
            except modules.host.HostCapabilityUnsupported as error:
                if error.reason != "host_foreign_parent_job":
                    raise
                record["foreign_gate"] = {"status": "unsupported", "reason": error.reason,
                                          "win32_error": error.win32_error}
            else:
                record["foreign_gate"] = {"status": "unexpectedly_supported"}
                result = 32
            publish(directory / "foreign-probe.json", record)
            reason, chunks = "foreign_host_probe", 0
        else:
            if time.monotonic_ns() >= deadline or os.path.lexists(stop):
                raise FixtureError("fixture_stopped_before_ready")
            publish(directory / f"ready-{identity['pid']}.json", record)
            if not args.leaf:
                command = child_command(args, deadline)
                for _ in range(args.workers - 1):
                    if time.monotonic_ns() >= deadline or os.path.lexists(stop):
                        raise FixtureError("fixture_stopped_before_child")
                    owner.native.spawn(command, owner)
                until = min(deadline, time.monotonic_ns() + 10_000_000_000)
                for child in owner.children:
                    path = directory / f"ready-{child['identity']['pid']}.json"
                    while not path.exists() and time.monotonic_ns() < until and not os.path.lexists(stop):
                        if not owner.native.alive(child):
                            break
                        time.sleep(.01)
                    if not path.exists():
                        raise FixtureError("fixture_child_ready_missing")
                    verify_ready(read_ready(path), identity=child["identity"], args=args, deadline=deadline)
            chunks, reason = cpu_work(deadline, stop)
        if owner.process.is_in_job(owner.job.handle) is not True:
            raise FixtureError("fixture_exit_membership_unverified")
        # This is this process's final report, not proof of its own OS exit.
        # The guardian must still observe exit/Job emptiness on original handles.
        owner.record = {**record, "status": "work_complete", "reason": reason, "work_chunks": chunks}
    except BaseException as error:
        primary = error
        owner.errors.append(error)
    finally:
        if not args.leaf:
            try:
                stop.touch(exist_ok=True)
            except BaseException as error:
                owner.errors.append(error)
                primary = primary or error
        until = deadline + 4_000_000_000
        while not owner.settle() and not owner.quarantined and time.monotonic_ns() < until:
            time.sleep(.01)
        if owner in _RETAINED:
            raise RetainedOwnerError("fixture_native_custody_unsettled", owner) from primary
    if primary is not None:
        raise primary
    publish(directory / f"exit-{owner.record['pid']}.json", {
        **owner.record, "elapsed_seconds": (time.monotonic_ns() - started) / 1_000_000_000,
        "children_still_alive": 0, "owned_handles_closed": True})
    return result


def main(argv=None):
    started = time.monotonic_ns()
    args = parser().parse_args(argv)
    directory, deadline = validate(args, started)
    modules = bootstrap(args)
    try:
        return run(args, directory, deadline, modules)
    except RetainedOwnerError as error:
        # No replacement owner, repeat unknown close, kill or false exit record.
        # Parent guardian keeps the original Job and demand until this resolves.
        try:
            publish(directory / f"pending-{os.getpid()}.json", {"reason": error.reason,
                    "pid": os.getpid(), "source_generation": args.source_generation})
        except BaseException as publication:
            error.owner.errors.append(publication)
        while True:
            try:
                # Only a positive later observation of the same originals may
                # discharge a live-child/read wait. Quarantined writes never retry.
                if error.owner.settle():
                    return 125
                time.sleep(.25)
            except BaseException as interruption:
                if len(error.owner.errors) < 16:
                    error.owner.errors.append(interruption)


if __name__ == "__main__":
    raise SystemExit(main())
