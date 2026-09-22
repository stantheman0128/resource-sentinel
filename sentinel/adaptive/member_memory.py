"""Bounded, read-only memory attribution for members of retained QUERY Jobs.

The plan's 256 records / 100 ms budget is shared by the entire capture, not by
each Job. PID lists refresh at most once per two seconds. Between refreshes,
unchanged lifetime TotalProcesses and ActiveProcesses, plus every original
member handle still alive and in the exact Job, prove the cached set complete.
An incomplete set never contributes a partial sum. This is telemetry only;
opening a member grants no launch, accounting, or control authority.

Private resident memory requires PROCESS_MEMORY_COUNTERS_EX2. An older API's
successful return with an untouched extension is not evidence of EX2 support.
The native reader checks the documented patched OS scope, an own-process
positive probe, and a poisoned output layout on every query. Without EX2 both
aggregate fields stay unknown (the current JobFrame memory contract is paired).
Total working set, shared pages, and system-wide process scans are never used.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass, field, replace
import os
import sys
from typing import Mapping

from .contracts import IdentityStatus, ProcessIdentity, UINT64_MAX

MAX_MEMBERS = 256
MAX_JOBS = 10
BUDGET_MS = 100
TICKS_PER_MS = 10_000
MEMBERSHIP_INTERVAL = 2 * 10_000_000


def _uint(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


class MemberMemoryError(RuntimeError):
    def __init__(self, reason, win32_error=None):
        self.reason, self.win32_error = reason, win32_error
        super().__init__(reason)


class NativeScanBudget:
    """One in-process capture owner, optionally shared by query-only shards.

    Shards do not get fresh deadlines or record allowances. Consumers of more
    than one shard must reject all results named by invalid_execution_ids after
    the last shard: a later overlapping Job can invalidate an earlier sum.
    This object contains no measurements and grants no control authority.
    """

    def __init__(self, started_tick, max_members=MAX_MEMBERS, budget_ms=BUDGET_MS):
        if (not _uint(started_tick) or type(max_members) is not int or
                not 1 <= max_members <= MAX_MEMBERS or type(budget_ms) is not int or
                not 1 <= budget_ms <= BUDGET_MS):
            raise ValueError("member_scan_budget_invalid")
        self.started_tick = started_tick
        self.deadline_tick = started_tick + budget_ms * TICKS_PER_MS
        self.max_members = max_members
        self._consumed = 0
        self._exhausted = False
        self._identities = {}
        self._pids = {}
        self._invalid = set()
        self._executions = set()

    @property
    def consumed_members(self):
        return self._consumed

    @property
    def exhausted(self):
        return self._exhausted

    @property
    def invalid_execution_ids(self):
        return frozenset(self._invalid)

    def check(self, now):
        if not _uint(now) or now < self.started_tick or now > self.deadline_tick:
            self._exhausted = True
            raise MemberMemoryError("member_scan_timeout")

    def reserve(self, count):
        if type(count) is not int or count < 0 or self._consumed + count > self.max_members:
            self._exhausted = True
            raise MemberMemoryError("member_limit_exceeded")
        self._consumed += count

    def begin_job(self, execution_id):
        if execution_id in self._executions:
            self._invalid.add(execution_id)
            raise MemberMemoryError("member_overlap")
        self._executions.add(execution_id)

    def claim(self, execution_id, identity):
        old = self._identities.get(identity)
        old_pid = self._pids.get(identity.pid)
        if old is not None and old != execution_id:
            self._invalid.update((old, execution_id))
        if old_pid is not None and old_pid != (execution_id, identity):
            self._invalid.update((old_pid[0], execution_id))
        self._identities[identity] = execution_id
        self._pids[identity.pid] = (execution_id, identity)
        if execution_id in self._invalid:
            raise MemberMemoryError("member_overlap")


@dataclass(frozen=True)
class MemoryScanResult:
    execution_id: str
    private_working_set_bytes: int | None
    private_commit_bytes: int | None
    membership_complete: bool
    reason: str
    attempted_members: int
    started_tick: int
    ended_tick: int
    api_error_code: int | None = None
    total_processes: int | None = None
    active_processes: int | None = None


class _CountersEx2(C.Structure):
    _fields_ = [("cb", C.c_uint32), ("PageFaultCount", C.c_uint32)] + [
        (name, C.c_size_t) for name in (
            "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
            "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage",
            "PagefileUsage", "PeakPagefileUsage", "PrivateUsage", "PrivateWorkingSetSize",
        )] + [("SharedCommitUsage", C.c_uint64)]


def _supported_ex2_os(build, revision):
    # EX2: Win10/11 22H2 + September 2023 CU. A base build alone is insufficient.
    if type(build) is not int or type(revision) is not int or revision < 0:
        return False
    return (build == 19045 and revision >= 3448 or
            build == 22621 and revision >= 2283 or build >= 22631)


def _native_ex2_os():
    if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
        return False
    try:
        import winreg
        version = sys.getwindowsversion()
        if version.major != 10 or version.product_type != 1:
            return False
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", 0,
                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
            revision, kind = winreg.QueryValueEx(key, "UBR")
        return kind == winreg.REG_DWORD and _supported_ex2_os(version.build, revision)
    except (OSError, AttributeError, ValueError):
        return False


class NativeMemoryReader:
    """Query only a borrowed VerifiedProcess handle, under its ownership lock."""

    def __init__(self, *, query=None, supported_os=None, current_handle=None):
        # Explicit callable seams are for portable ABI/failure tests only. No
        # configuration, environment, JSON, or command-line support override.
        self._query = query
        self._os_supported = _native_ex2_os() if supported_os is None else supported_os
        self._current_handle = current_handle
        self._support = None
        if query is None and self._os_supported:
            kernel = C.WinDLL("kernel32", use_last_error=True)
            function = kernel.K32GetProcessMemoryInfo
            function.argtypes = [C.c_void_p, C.c_void_p, C.c_uint32]
            function.restype = C.c_int32
            kernel.GetCurrentProcess.argtypes = []
            kernel.GetCurrentProcess.restype = C.c_void_p
            self._kernel, self._query = kernel, function
            # This pseudohandle is borrowed forever and must never be closed.
            self._current_handle = kernel.GetCurrentProcess()

    def _read_handle(self, handle):
        counters = _CountersEx2()
        C.memset(C.byref(counters), 0xA5, C.sizeof(counters))
        counters.cb = 0  # output size must be written, not echo our input
        poison_size = int.from_bytes(b"\xa5" * C.sizeof(C.c_size_t), "little")
        poison64 = 0xA5A5A5A5A5A5A5A5
        if not self._query(handle, C.byref(counters), C.sizeof(counters)):
            code = C.get_last_error() if os.name == "nt" else None
            raise MemberMemoryError("member_memory_query_failed", code)
        if (counters.cb != C.sizeof(counters) or
                counters.PrivateWorkingSetSize == poison_size or
                counters.SharedCommitUsage == poison64 or
                counters.PrivateUsage == poison_size or
                counters.PrivateWorkingSetSize > counters.WorkingSetSize):
            raise MemberMemoryError("ex2_unavailable")
        return int(counters.PrivateWorkingSetSize), int(counters.PrivateUsage)

    def read(self, process):
        if self._support is None:
            self._support = False
            if self._os_supported and self._query is not None:
                try:
                    private_ws, _ = self._read_handle(self._current_handle)
                    self._support = private_ws > 0
                except MemberMemoryError:
                    pass
        if not self._support:
            raise MemberMemoryError("ex2_unavailable")
        with process._lock:
            if process._handle is None or process._close_outcome_unknown:
                raise MemberMemoryError("inaccessible_identity")
            return self._read_handle(process._handle)


@dataclass
class _Membership:
    job: object
    pids: tuple[int, ...] | None = None
    total: int | None = None
    active: int | None = None
    last_list_tick: int | None = None
    processes: dict = field(default_factory=dict)


class NativeMemberMemoryScanner:
    """One helper's bounded retained member cache; no Set or process spawning.

    A failed/uncertain close remains reachable and blocks reuse of that PID.
    Scanner ownership must outlive those errors. release/close never reissue an
    uncertain close; the helper therefore cannot claim clean shutdown.
    """

    def __init__(self, *, clock, backend=None, open_process=None):
        from .identity import VerifiedProcess
        self._clock = clock
        self._backend = backend
        self._opener = VerifiedProcess._open if open_process is None else open_process
        self._memberships = {}
        self._retained = []
        self._blocked_pids = set()
        self._inflight = None
        self.last_results = ()

    @property
    def retained_uncertain(self):
        return len(self._retained) + (self._inflight is not None)

    @property
    def cached_members(self):
        return sum(len(item.processes) for item in self._memberships.values())

    def _retire(self, membership, pid):
        process = membership.processes.get(pid)
        if process is None:
            return
        # Retain before invoking close. This owner is never removed on an
        # interruption/ambiguous result, and the numeric handle is not retried.
        pending = (pid, process)
        self._retained.append(pending)
        self._blocked_pids.add(pid)
        del membership.processes[pid]
        try:
            process.close()
        except BaseException:
            raise
        else:
            self._retained.remove(pending)
            if not any(item[0] == pid for item in self._retained):
                self._blocked_pids.discard(pid)

    def release(self, execution_id):
        membership = self._memberships.get(execution_id)
        if membership is None:
            return None
        failed = False
        for pid in tuple(membership.processes):
            try:
                self._retire(membership, pid)
            except BaseException:
                failed = True
        del self._memberships[execution_id]
        return "member_cleanup_unverified" if failed else None

    def close(self):
        for execution_id in tuple(self._memberships):
            self.release(execution_id)
        self.retry_cleanup()
        if self.retained_uncertain:
            raise MemberMemoryError("member_cleanup_unverified")

    def retry_cleanup(self):
        """Retry only explicitly known failed closes, at most the cached bound.

        Ambiguous native outcomes are not reissued, even as a method call. The
        original owner and any interrupted acquisition error remain reachable.
        """
        budget = NativeScanBudget(self._clock())
        for pending in tuple(self._retained[:MAX_MEMBERS]):
            try:
                self._now(budget)
            except MemberMemoryError:
                break
            pid, retained = pending
            owners = (getattr(retained, "_identity_handle_cleanup", ())
                      if isinstance(retained, BaseException) else (retained,))
            if not owners:
                continue
            unresolved = []
            for owner in owners:
                try:
                    self._now(budget)
                except MemberMemoryError:
                    unresolved.append(owner)
                    continue
                if (getattr(owner, "_close_outcome_unknown", True) is not False or
                        getattr(owner, "_duplicate_outcome_unknown", False)):
                    unresolved.append(owner)
                    continue
                try:
                    owner.close()
                except BaseException:
                    unresolved.append(owner)
            if isinstance(retained, BaseException):
                retained._identity_handle_cleanup = tuple(unresolved)
            if not unresolved:
                self._retained.remove(pending)
                if not any(item[0] == pid for item in self._retained) and self._inflight != pid:
                    self._blocked_pids.discard(pid)

    def _accounting(self, job):
        reading = job.accounting()
        total, active = reading.total_processes, reading.active_processes
        if not _uint(total) or not _uint(active) or total < active:
            raise MemberMemoryError("membership_changed")
        return total, active

    def _now(self, budget):
        now = self._clock()
        budget.check(now)
        return now

    def _open(self, membership, pid):
        if pid in self._blocked_pids or self._inflight is not None:
            raise MemberMemoryError("member_cleanup_unverified")
        if self.cached_members + len(self._retained) >= MAX_MEMBERS:
            raise MemberMemoryError("member_limit_exceeded")
        # Before entry retain an operation marker. An interrupted open without
        # a returned cleanup witness stays quarantined instead of being retried.
        self._inflight = pid
        process = None
        try:
            process = self._opener(pid)
            # Publish the returned owner before inspecting its identity.
            membership.processes[pid] = process
            self._inflight = None
        except BaseException as error:
            if process is not None and membership.processes.get(pid) is not process:
                self._retained.append((pid, process))
                self._blocked_pids.add(pid)
            owners = getattr(error, "_identity_handle_cleanup", ())
            if owners:
                self._retained.append((pid, error))
                self._blocked_pids.add(pid)
            if isinstance(error, Exception):
                self._inflight = None
            else:
                # Keep both the operation marker and an interrupted native
                # acquisition's attached cleanup owners reachable.
                if not owners:
                    self._retained.append((pid, error))
                self._blocked_pids.add(pid)
                raise
            raise MemberMemoryError("inaccessible_identity", getattr(error, "win32_error", None)) from None
        return process

    def _sample_job(self, execution_id, job, started_tick, budget):
        attempted = 0
        total = active = None
        try:
            budget.begin_job(execution_id)
            now = self._now(budget)
            membership = self._memberships.get(execution_id)
            if membership is None:
                if len(self._memberships) >= MAX_JOBS:
                    raise MemberMemoryError("member_job_limit_exceeded")
                membership = _Membership(job)
                self._memberships[execution_id] = membership
            elif membership.job is not job:
                raise MemberMemoryError("member_identity_changed")
            total, active = self._accounting(job)
            self._now(budget)
            if membership.last_list_tick is not None and now < membership.last_list_tick:
                membership.pids = None
                raise MemberMemoryError("member_scan_timeout")
            refresh = (membership.last_list_tick is None or
                       now - membership.last_list_tick >= MEMBERSHIP_INTERVAL)
            if refresh:
                membership.pids = None
                membership.last_list_tick = self._now(budget)
                pids = job.active_pids()  # native layer: <=4 calls, <=4096 ids
                self._now(budget)
                if (not isinstance(pids, tuple) or len(pids) != active or
                        any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in pids) or
                        len(set(pids)) != len(pids)):
                    raise MemberMemoryError("membership_changed")
                # Reject large membership before opening/querying any process.
                budget.reserve(len(pids))
                for pid in tuple(membership.processes):
                    if pid not in pids:
                        try:
                            self._retire(membership, pid)
                        except Exception:
                            raise MemberMemoryError("member_cleanup_unverified") from None
                        self._now(budget)
                if self._accounting(job) != (total, active):
                    raise MemberMemoryError("membership_changed")
                self._now(budget)
                membership.pids = pids
                membership.total, membership.active = total, active
            else:
                if (membership.pids is None or
                        (membership.total, membership.active) != (total, active)):
                    raise MemberMemoryError("membership_refresh_pending")
                budget.reserve(len(membership.pids))
            if self._backend is None:
                self._backend = NativeMemoryReader()
                self._now(budget)
            private_ws = private_commit = 0
            for pid in membership.pids:
                self._now(budget)
                attempted += 1
                process = membership.processes.get(pid)
                if process is None:
                    process = self._open(membership, pid)
                self._now(budget)
                identity = process.identity
                if (type(identity) is not ProcessIdentity or identity.pid != pid or
                        identity.logon_id != job.logon_sid):
                    raise MemberMemoryError("member_identity_changed")
                budget.claim(execution_id, identity)
                observation = process.observe()
                if observation.identity != identity or observation.status is not IdentityStatus.ALIVE:
                    membership.pids = None
                    if observation.status is IdentityStatus.DEAD:
                        try:
                            self._retire(membership, pid)
                        except Exception:
                            raise MemberMemoryError("member_cleanup_unverified") from None
                    raise MemberMemoryError("member_identity_changed")
                if process.is_in_job(job.handle) is not True:
                    raise MemberMemoryError("membership_changed")
                self._now(budget)
                ws, commit = self._backend.read(process)
                self._now(budget)
                observation = process.observe()
                if (observation.identity != identity or observation.status is not IdentityStatus.ALIVE or
                        process.is_in_job(job.handle) is not True):
                    membership.pids = None
                    raise MemberMemoryError("member_identity_changed")
                if not _uint(ws) or not _uint(commit):
                    raise MemberMemoryError("member_memory_query_failed")
                private_ws += ws
                private_commit += commit
                if not _uint(private_ws) or not _uint(private_commit):
                    raise MemberMemoryError("member_memory_query_failed")
            # An early member can exit while a later one is queried. Holding
            # its process handle may delay the Job's active-count update, so
            # accounting alone is not sufficient evidence that all survived.
            for pid in membership.pids:
                self._now(budget)
                process = membership.processes[pid]
                observation = process.observe()
                if (observation.identity != process.identity or
                        observation.status is not IdentityStatus.ALIVE or
                        process.is_in_job(job.handle) is not True):
                    membership.pids = None
                    raise MemberMemoryError("member_identity_changed")
            self._now(budget)
            if self._accounting(job) != (total, active):
                membership.pids = None
                raise MemberMemoryError("membership_changed")
            end = self._now(budget)
            return MemoryScanResult(execution_id, private_ws, private_commit, True,
                                    "ok", attempted, started_tick, end, None, total, active)
        except Exception as error:
            code = getattr(error, "win32_error", None)
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
                code = None
            reason = error.reason if isinstance(error, MemberMemoryError) else "inaccessible_identity"
            end = self._clock()
            if not _uint(end) or end < started_tick:
                end = started_tick
            return MemoryScanResult(execution_id, None, None, False, reason, attempted,
                                    started_tick, end, code, total, active)

    def scan_frame(self, jobs: Mapping, started_tick, *, budget=None):
        if not isinstance(jobs, Mapping) or len(jobs) > MAX_JOBS or not _uint(started_tick):
            raise ValueError("member_scan_frame_invalid")
        if budget is None:
            budget = NativeScanBudget(started_tick)
        if type(budget) is not NativeScanBudget or started_tick < budget.started_tick:
            raise ValueError("member_scan_budget_invalid")
        self.last_results = ()
        results = tuple(self._sample_job(key, job, started_tick, budget)
                        for key, job in jobs.items())
        self.last_results = tuple(
            replace(result, private_working_set_bytes=None, private_commit_bytes=None,
                    membership_complete=False, reason="member_overlap")
            if result.execution_id in budget.invalid_execution_ids else result for result in results)
        return self.last_results
