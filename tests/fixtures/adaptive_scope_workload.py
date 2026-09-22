"""Constant-memory CPU root/children with explicit native scope and deadlines.

This is an isolated P6 workload, not an admission provider or scheduler. The
orchestrator must admit and launch it in the expected scope. No process is opened
by PID, no Job is created/assigned/changed, and no process is killed or suspended.
Each child inherits the same absolute deadline, verifies its own scope, and has
an independent cooperative stop check. Managed roots may exit before children;
that observation never means the Job is empty or its capacity can be released.

CPU work stops within the supplied <=115-second deadline (plus a bounded small
arithmetic chunk). Uncertain native handle custody is a failed run, not permission
to drop ownership: the CLI stays idle with its original owner and pending evidence.
That exceptional custody hold is not described as a successfully bounded run.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

if __package__:
    from .win32_ui_probe import ProbeError, publish_json, validate_path
else:
    from win32_ui_probe import ProbeError, publish_json, validate_path


MAX_WORK_NS = 115_000_000_000
SETTLEMENT_GRACE_NS = 2_000_000_000
MAX_CHILDREN = 3
NORMAL = 0x20
BELOW_NORMAL = 0x4000
NONCE = re.compile(r"[0-9a-f]{32}\Z")
JOB_NAME = re.compile(r"Local\\ResourceSentinel\.Job\.([0-9a-f-]{36})\.([0-9a-f]{32})\Z")


class FixtureError(ValueError):
    pass


class RetainedOwnerError(RuntimeError):
    """Keep this exception and its original owner; do not reconstruct from PID."""

    def __init__(self, reason, owner):
        super().__init__(reason)
        self.reason, self.owner = reason, owner


def canonical_uuid(value):
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError):
        raise FixtureError("run_id_invalid") from None
    if parsed.int == 0 or str(parsed) != value:
        raise FixtureError("run_id_invalid")
    return value


def positive_int(value, reason):
    if type(value) is not int or not 0 < value < 1 << 63:
        raise FixtureError(reason)
    return value


def validate_deadline(deadline_ns, now_ns):
    positive_int(deadline_ns, "deadline_invalid")
    positive_int(now_ns, "clock_invalid")
    if not 0 < deadline_ns - now_ns <= MAX_WORK_NS:
        raise FixtureError("deadline_expired_or_too_far")
    return deadline_ns


def duration(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not .05 <= value <= 115:
        raise FixtureError("duration_out_of_range")
    return float(value)


def parse_child_seconds(value):
    if value == "":
        return ()
    try:
        values = tuple(float(item) for item in value.split(","))
    except (ValueError, AttributeError):
        raise FixtureError("child_durations_invalid") from None
    if len(values) > MAX_CHILDREN:
        raise FixtureError("too_many_children")
    return tuple(duration(item) for item in values)


@dataclass(frozen=True)
class Scope:
    mode: str
    job_name: str | None = None
    job_nonce: str | None = None
    priority_class: int = NORMAL

    def __post_init__(self):
        if self.mode not in ("managed", "unmanaged"):
            raise FixtureError("scope_invalid")
        if type(self.priority_class) is not int or self.priority_class not in (NORMAL, BELOW_NORMAL):
            raise FixtureError("priority_invalid")
        if self.mode == "unmanaged":
            if self.job_name is not None or self.job_nonce is not None or self.priority_class != NORMAL:
                raise FixtureError("unmanaged_requires_no_job_and_normal_priority")
        else:
            if type(self.job_nonce) is not str or not NONCE.fullmatch(self.job_nonce):
                raise FixtureError("job_nonce_invalid")
            if self.job_name == "Local\\ResourceSentinel.Test.Job." + self.job_nonce:
                return
            match = JOB_NAME.fullmatch(self.job_name) if isinstance(self.job_name, str) else None
            if match is None or match[2] != self.job_nonce:
                raise FixtureError("job_name_invalid")
            canonical_uuid(match[1])


def verify_context(scope, *, in_any_job, in_expected_job, priority_class):
    if type(in_any_job) is not bool or type(priority_class) is not int:
        raise FixtureError("scope_observation_unknown")
    if priority_class != scope.priority_class:
        raise FixtureError("priority_mismatch")
    if scope.mode == "unmanaged":
        if in_any_job or in_expected_job is not None:
            raise FixtureError("unmanaged_process_is_in_job")
    elif in_any_job is not True or in_expected_job is not True:
        raise FixtureError("expected_job_membership_missing")


def validate_identity(value):
    if not isinstance(value, dict) or set(value) != {"pid", "creation_time_100ns"}:
        raise FixtureError("identity_invalid")
    positive_int(value["pid"], "identity_invalid")
    positive_int(value["creation_time_100ns"], "identity_invalid")
    if value["pid"] > 0xFFFFFFFF:
        raise FixtureError("identity_invalid")
    return value


def verify_child_ready(record, *, run_id, nonce, label, identity, parent_identity,
                       deadline_ns, work_until_ns, scope):
    """A JSON PID is never an adoption mechanism; compare to original handles."""
    if not isinstance(record, dict):
        raise FixtureError("child_ready_invalid")
    expected = {
        "schema_version": 1, "status": "ready", "run_id": run_id,
        "fixture_nonce": nonce, "label": label, "identity": validate_identity(identity),
        "parent_identity": validate_identity(parent_identity), "deadline_ns": deadline_ns,
        "work_until_ns": work_until_ns, "scope": scope.mode,
        "job_name": scope.job_name, "job_nonce": scope.job_nonce,
        "priority_class": scope.priority_class, "scope_verified": True,
    }
    if any(type(record.get(key)) is not type(value) or record.get(key) != value
           for key, value in expected.items()):
        raise FixtureError("child_ready_identity_or_scope_mismatch")
    positive_int(record.get("started_ns"), "child_ready_clock_invalid")
    if not record["started_ns"] < work_until_ns <= deadline_ns:
        raise FixtureError("child_ready_clock_invalid")


def read_ready(path):
    validate_path(path)
    if path.stat().st_size > 8192:
        raise FixtureError("child_ready_too_large")
    with path.open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise FixtureError("child_ready_too_large")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise FixtureError("child_ready_duplicate_key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(FixtureError("child_ready_nonfinite")))


class NativeOwner:
    """Own only this process's query Job and direct CreateProcess return handles."""

    def __init__(self, scope):
        if os.name != "nt":
            raise FixtureError("windows_required")
        import ctypes as c
        from ctypes import wintypes as w
        self.c, self.w, self.scope = c, w, scope
        self.kernel = c.WinDLL("kernel32", use_last_error=True)
        self.job, self.job_state = None, "absent"
        self.children = []
        self.creation_unknown = False

        class STARTUPINFO(c.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                        ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                        ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                        ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                        ("lpReserved2", c.POINTER(w.BYTE)), ("hStdInput", w.HANDLE),
                        ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

        class PROCESS_INFORMATION(c.Structure):
            _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                        ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]
        self.startup_type, self.creation_type = STARTUPINFO, PROCESS_INFORMATION
        def bind(name, args, result):
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = args, result
            return function
        self.current = bind("GetCurrentProcess", [], w.HANDLE)
        self.pid = bind("GetProcessId", [w.HANDLE], w.DWORD)
        self.times = bind("GetProcessTimes", [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4, w.BOOL)
        self.in_job = bind("IsProcessInJob", [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)], w.BOOL)
        self.priority = bind("GetPriorityClass", [w.HANDLE], w.DWORD)
        self.open_job = bind("OpenJobObjectW", [w.DWORD, w.BOOL, w.LPCWSTR], w.HANDLE)
        self.close_handle = bind("CloseHandle", [w.HANDLE], w.BOOL)
        self.wait = bind("WaitForSingleObject", [w.HANDLE, w.DWORD], w.DWORD)
        self.create = bind("CreateProcessW", [w.LPCWSTR, w.LPWSTR, w.LPVOID, w.LPVOID,
                           w.BOOL, w.DWORD, w.LPVOID, w.LPCWSTR, c.POINTER(STARTUPINFO),
                           c.POINTER(PROCESS_INFORMATION)], w.BOOL)

    def open_scope(self):
        if self.scope.mode == "managed":
            self.job_state = "allocation_unknown"
            try:
                self.job = self.open_job(0x0004, False, self.scope.job_name)
            except BaseException:
                raise RetainedOwnerError("job_query_handle_allocation_unknown", self) from None
            self.job_state = "owned" if self.job else "absent"
            if not self.job:
                raise FixtureError("expected_job_open_failed")
        self.context(self.current())

    def identity(self, handle):
        birth, exit_time, kernel, user = (self.w.FILETIME() for _ in range(4))
        pid = self.pid(handle)
        if not pid or not self.times(handle, self.c.byref(birth), self.c.byref(exit_time),
                                    self.c.byref(kernel), self.c.byref(user)):
            raise FixtureError("identity_query_failed")
        return validate_identity({"pid": int(pid),
                                  "creation_time_100ns": (birth.dwHighDateTime << 32) | birth.dwLowDateTime})

    def membership(self, handle, job):
        value = self.w.BOOL()
        if not self.in_job(handle, job, self.c.byref(value)):
            raise FixtureError("membership_query_failed")
        return bool(value.value)

    def context(self, handle):
        priority = self.priority(handle)
        verify_context(self.scope, in_any_job=self.membership(handle, None),
                       in_expected_job=self.membership(handle, self.job) if self.job else None,
                       priority_class=int(priority))
        return int(priority)

    def spawn(self, command, label):
        info = self.creation_type()
        child = {"label": label, "info": info, "identity": None,
                 "process_state": "allocation_unknown", "thread_state": "allocation_unknown",
                 "scope_verified": False, "ready_verified": False, "last_alive": None}
        self.children.append(child)  # Own ambiguous outputs before the native call.
        startup = self.startup_type()
        startup.cb = self.c.sizeof(startup)
        self.creation_unknown = True
        try:
            ok = self.create(command[0], self.c.create_unicode_buffer(subprocess.list2cmdline(command)),
                             None, None, False, 0x08000000, None, None,
                             self.c.byref(startup), self.c.byref(info))
        except BaseException:
            raise RetainedOwnerError("child_creation_outcome_unknown", self) from None
        if not ok:
            if info.hProcess or info.hThread or info.dwProcessId or info.dwThreadId:
                raise RetainedOwnerError("failed_create_has_ambiguous_outputs", self)
            child["process_state"] = child["thread_state"] = "absent"
            self.creation_unknown = False
            raise FixtureError("child_creation_failed")
        if not info.hProcess or not info.hThread or not info.dwProcessId:
            raise RetainedOwnerError("successful_create_has_missing_handles", self)
        child["process_state"] = child["thread_state"] = "owned"
        self.creation_unknown = False
        child["identity"] = self.identity(info.hProcess)
        child["created_observed_ns"] = time.monotonic_ns()
        if child["identity"]["pid"] != info.dwProcessId:
            raise RetainedOwnerError("creation_identity_mismatch", self)
        return child

    def alive(self, child):
        if child["process_state"] != "owned":
            raise RetainedOwnerError("child_handle_not_queryable", self)
        observed = self.wait(child["info"].hProcess, 0)
        if observed not in (0, 0x102):
            raise RetainedOwnerError("child_liveness_unknown", self)
        child["last_alive"] = observed == 0x102
        child["last_observed_ns"] = time.monotonic_ns()
        return child["last_alive"]

    def close_child(self, child):
        for state, field in (("thread_state", "hThread"), ("process_state", "hProcess")):
            if child[state] in ("absent", "closed"):
                continue
            if child[state] != "owned":
                raise RetainedOwnerError("child_handle_cleanup_unknown", self)
            child[state] = "close_unknown"
            try:
                closed = self.close_handle(getattr(child["info"], field))
            except BaseException:
                raise RetainedOwnerError("child_handle_cleanup_unknown", self) from None
            if not closed:
                raise RetainedOwnerError("child_handle_cleanup_unknown", self)
            child[state] = "closed"

    def close_job(self):
        if self.job_state in ("absent", "closed"):
            return
        if self.job_state != "owned":
            raise RetainedOwnerError("query_job_cleanup_unknown", self)
        self.job_state = "close_unknown"
        try:
            closed = self.close_handle(self.job)
        except BaseException:
            raise RetainedOwnerError("query_job_cleanup_unknown", self) from None
        if not closed:
            raise RetainedOwnerError("query_job_cleanup_unknown", self)
        self.job_state = "closed"

    def cleanup(self, *, allow_managed_handoff):
        if self.creation_unknown:
            raise RetainedOwnerError("creation_custody_unresolved", self)
        for child in self.children:
            if child["process_state"] in ("absent", "closed"):
                continue
            alive = self.alive(child)
            if alive and not (allow_managed_handoff and self.scope.mode == "managed"
                              and child["scope_verified"] and child["ready_verified"]):
                raise RetainedOwnerError("live_child_custody_retained", self)
            self.close_child(child)
        self.close_job()

    def finish_known_children(self):
        """Retry only retained read observations; never repeat an uncertain close."""
        if self.creation_unknown or self.job_state not in ("absent", "owned", "closed"):
            return False
        for child in self.children:
            if (child["process_state"] not in ("absent", "owned", "closed")
                    or child["thread_state"] not in ("absent", "owned", "closed")):
                return False
            if child["process_state"] == "owned" and self.alive(child):
                return False
        self.cleanup(allow_managed_handoff=False)
        return True


def child_summary(child):
    return {key: child.get(key) for key in (
        "label", "identity", "scope_verified", "ready_verified", "last_alive",
        "created_observed_ns", "last_observed_ns", "process_state", "thread_state")}


def cpu_work(until_ns, stop_file):
    value, units = 1, 0
    while time.monotonic_ns() < until_ns and not os.path.lexists(stop_file):
        # No arrays, growing integers, user data, or unbounded arithmetic.
        for _ in range(4096):
            value = (value * 1664525 + 1013904223) & 0xFFFFFFFF
        units += 1
    return units, value, "stop_file" if os.path.lexists(stop_file) else "work_deadline"


def run(args, scope, directory):
    owner = NativeOwner(scope)
    started = time.monotonic_ns()
    validate_deadline(args.deadline_ns, started)
    work_until = args.work_until_ns if args.role == "child" else min(
        args.deadline_ns, started + int(duration(args.root_seconds) * 1_000_000_000))
    if type(work_until) is not int or not started < work_until <= args.deadline_ns:
        raise FixtureError("work_deadline_invalid")
    label = "root" if args.role == "root" else f"child-{args.child_index}"
    stop_file = directory / "stop"
    record = {"schema_version": 1, "status": "ready", "run_id": args.run_id,
              "fixture_nonce": args.fixture_nonce, "label": label, "started_ns": started,
              "deadline_ns": args.deadline_ns, "work_until_ns": work_until,
              "scope": scope.mode, "job_name": scope.job_name, "job_nonce": scope.job_nonce,
              "priority_class": scope.priority_class, "scope_verified": False,
              "parent_identity": None, "identity": None, "job_empty": None}
    try:
        owner.open_scope()
        record["identity"] = owner.identity(owner.current())
        record["scope_verified"] = True
        if args.role == "child":
            record["parent_identity"] = validate_identity({
                "pid": args.parent_pid, "creation_time_100ns": args.parent_creation_time_100ns})
        publish_json(directory / f"{label}.ready.json", record)
        if args.role == "root":
            for index, seconds in enumerate(parse_child_seconds(args.child_seconds), 1):
                if os.path.lexists(stop_file) or time.monotonic_ns() >= args.deadline_ns:
                    raise FixtureError("stop_or_deadline_before_child_start")
                child_label = f"child-{index}"
                child_until = min(args.deadline_ns, started + int(seconds * 1_000_000_000))
                command = [sys.executable, str(Path(__file__).resolve()), "--directory", str(directory),
                           "--run-id", args.run_id, "--fixture-nonce", args.fixture_nonce,
                           "--scope", scope.mode, "--deadline-ns", str(args.deadline_ns),
                           "--expected-priority", "normal" if scope.priority_class == NORMAL else "below-normal",
                           "--role", "child", "--child-index", str(index),
                           "--work-until-ns", str(child_until), "--parent-pid", str(record["identity"]["pid"]),
                           "--parent-creation-time-100ns", str(record["identity"]["creation_time_100ns"])]
                if scope.mode == "managed":
                    command += ["--job-name", scope.job_name, "--job-nonce", scope.job_nonce]
                child = owner.spawn(command, child_label)
                publish_json(directory / f"root.{child_label}.created.json", {
                    **record, "status": "child_created", "child": child_summary(child)})
                owner.context(child["info"].hProcess)
                child["scope_verified"] = True
                ready = directory / f"{child_label}.ready.json"
                ready_deadline = min(args.deadline_ns, time.monotonic_ns() + 5_000_000_000)
                while not ready.exists() and time.monotonic_ns() < ready_deadline:
                    if not owner.alive(child) or os.path.lexists(stop_file):
                        break
                    time.sleep(.01)
                if not ready.exists():
                    raise FixtureError("child_ready_missing")
                verify_child_ready(read_ready(ready), run_id=args.run_id, nonce=args.fixture_nonce,
                                   label=child_label, identity=child["identity"],
                                   parent_identity=record["identity"], deadline_ns=args.deadline_ns,
                                   work_until_ns=child_until, scope=scope)
                child["ready_verified"] = True
            publish_json(directory / "root.children.json", {
                **record, "status": "children_verified",
                "children": [child_summary(child) for child in owner.children]})
        units, checksum, reason = cpu_work(work_until, stop_file)
        owner.context(owner.current())
        if scope.mode == "unmanaged":
            # No Job guardian can retain these children: keep original handles.
            while any(owner.alive(child) for child in owner.children):
                if time.monotonic_ns() >= args.deadline_ns + SETTLEMENT_GRACE_NS:
                    raise RetainedOwnerError("unmanaged_child_not_exited_at_deadline", owner)
                time.sleep(.01)
        owner.cleanup(allow_managed_handoff=True)
        return {**record, "status": "observed", "reason": reason,
                "ended_ns": time.monotonic_ns(), "completed_units": units, "checksum": checksum,
                "children": [child_summary(child) for child in owner.children],
                "cleanup_complete": True, "root_exit_proves_scope_empty": False}
    except RetainedOwnerError:
        raise
    except BaseException as exc:
        # All children are ours. Request their voluntary stop, then retain original
        # handles until they actually exit; a timeout never becomes a kill.
        try:
            if owner.children:
                try:
                    with stop_file.open("xb"):
                        pass
                except FileExistsError:
                    pass
                except OSError:
                    raise RetainedOwnerError("cooperative_stop_publication_failed", owner) from None
                while any(owner.alive(child) for child in owner.children
                          if child["process_state"] == "owned"):
                    if time.monotonic_ns() >= args.deadline_ns + SETTLEMENT_GRACE_NS:
                        raise RetainedOwnerError("failed_child_cleanup_deadline", owner) from None
                    time.sleep(.01)
            owner.cleanup(allow_managed_handoff=False)
        except RetainedOwnerError:
            raise
        except BaseException:
            raise RetainedOwnerError("failure_cleanup_interrupted", owner) from None
        raise FixtureError(str(exc) if isinstance(exc, (FixtureError, ProbeError)) else "fixture_failed") from None


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--directory", required=True)
    result.add_argument("--run-id", required=True)
    result.add_argument("--fixture-nonce", required=True)
    result.add_argument("--scope", choices=("managed", "unmanaged"), required=True)
    result.add_argument("--job-name")
    result.add_argument("--job-nonce")
    result.add_argument("--expected-priority", choices=("normal", "below-normal"), default="normal")
    result.add_argument("--deadline-ns", type=int, required=True)
    result.add_argument("--root-seconds", type=float, default=10.0)
    result.add_argument("--child-seconds", default="")
    result.add_argument("--role", choices=("root", "child"), default="root")
    result.add_argument("--child-index", type=int)
    result.add_argument("--work-until-ns", type=int)
    result.add_argument("--parent-pid", type=int)
    result.add_argument("--parent-creation-time-100ns", type=int)
    return result


def validate_args(args):
    canonical_uuid(args.run_id)
    if type(args.fixture_nonce) is not str or not NONCE.fullmatch(args.fixture_nonce):
        raise FixtureError("fixture_nonce_invalid")
    duration(args.root_seconds)
    children = parse_child_seconds(args.child_seconds)
    if args.role == "child":
        if children or type(args.child_index) is not int or not 1 <= args.child_index <= MAX_CHILDREN:
            raise FixtureError("child_role_invalid")
        validate_identity({"pid": args.parent_pid, "creation_time_100ns": args.parent_creation_time_100ns})
        positive_int(args.work_until_ns, "work_deadline_invalid")
    elif any(value is not None for value in (args.child_index, args.work_until_ns,
                                            args.parent_pid, args.parent_creation_time_100ns)):
        raise FixtureError("root_has_child_only_arguments")
    return Scope(args.scope, args.job_name, args.job_nonce,
                 NORMAL if args.expected_priority == "normal" else BELOW_NORMAL)


def main(argv=None):
    args = parser().parse_args(argv)
    directory = None
    label = "root" if args.role == "root" else f"child-{args.child_index}"
    try:
        scope = validate_args(args)
        # Validate the existing directory using a child path; never create folders.
        directory = validate_path(Path(args.directory) / "scope-path-check").parent
        validate_path(directory / f"{label}.ready.json", absent=True)
        validate_path(directory / f"{label}.result.json", absent=True)
        if args.role == "root":
            validate_path(directory / "stop", absent=True)
        result = run(args, scope, directory)
    except RetainedOwnerError as exc:
        pending = {"schema_version": 1, "status": "pending", "reason": exc.reason,
                   "run_id": args.run_id, "fixture_nonce": args.fixture_nonce,
                   "label": label, "children": [child_summary(child) for child in exc.owner.children],
                   "cleanup_complete": False, "root_exit_proves_scope_empty": False}
        try:
            publish_json(directory / f"{label}.pending.json", pending)
        except BaseException:
            pass  # The original owner still stays alive even if evidence I/O fails.
        # No CPU work, retry of uncertain native calls, PID reopening, or forced
        # exit. Known-live children can still settle through the same handles.
        # Allocation/close uncertainty retains custody for original recovery.
        while True:
            try:
                time.sleep(.25)
                if not exc.owner.finish_known_children():
                    continue
                settled = {**pending, "status": "failed", "cleanup_complete": True,
                           "ended_ns": time.monotonic_ns(), "reason": "failed_run_custody_settled",
                           "original_reason": exc.reason,
                           "children": [child_summary(child) for child in exc.owner.children]}
                try:
                    publish_json(directory / f"{label}.result.json", settled)
                except BaseException:
                    pass  # All original handles now have positive cleanup.
                return 2
            except BaseException:
                continue
    except (OSError, FixtureError, ProbeError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, (FixtureError, ProbeError)) else "fixture_io_or_protocol_failed"
        result = {"schema_version": 1, "status": "blocked", "reason": reason,
                  "run_id": args.run_id, "fixture_nonce": args.fixture_nonce,
                  "label": label, "root_exit_proves_scope_empty": False}
    if directory is None:
        print(json.dumps(result), file=sys.stderr)
        return 2
    try:
        publish_json(directory / f"{label}.result.json", result)
    except (OSError, ProbeError):
        return 2
    return 0 if result["status"] == "observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
