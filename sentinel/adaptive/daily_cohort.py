"""Read-only witnesses for potentially loaded daily interpreter consumers.

A filename is only a conservative discovery hint. Every captured interpreter
is *ambiguous*, never a proven Sentinel writer. This module cannot determine
which Python modules or PowerShell scripts another process has loaded, cannot
cover renamed/embedded interpreters, and grants no cutover or activation right.
Its caller must separately establish and retain a reviewed source/entrypoint
cutover fence. A stable snapshot alone cannot exclude a process born and exited
between snapshots. No command lines, prompts or image paths are exported.

Toolhelp32 process snapshots are bounded and read-only. Candidate identity,
image and eventual death use original QUERY_LIMITED_INFORMATION | SYNCHRONIZE
handles. No process control, module injection, PID-based death inference, or
same-logon filtering is used. Native libraries are loaded only on invocation.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import math
import ntpath
import os
import threading
import time

from .contracts import IdentityStatus, ProcessIdentity
from .identity import (VerifiedProcess, _DuplicateCleanup,
                       _retain_cleanup, retry_identity_cleanup)


class CohortUnavailable(RuntimeError):
    """Sanitized failure retaining all custody in ``cohort`` for cleanup."""

    def __init__(self, reason, cohort=None):
        self.reason, self.cohort = reason, cohort
        super().__init__(reason)


@dataclass(frozen=True)
class ProcessEntry:
    """Native snapshot locator, deliberately not an identity or writer proof."""

    pid: int
    image_name: str


@dataclass(frozen=True)
class CohortSummary:
    retained_candidates: int
    ambiguous_potential_consumers: int
    completed_observations: int
    unresolved: bool
    closed: bool


def _basename(value):
    if (not isinstance(value, str) or not value or len(value) > 32767
            or any(ord(char) < 32 for char in value)):
        raise CohortUnavailable("cohort_image_unavailable")
    name = ntpath.basename(value).casefold()
    if not name or name in {".", ".."}:
        raise CohortUnavailable("cohort_image_unavailable")
    return name


def _potential_interpreter(name):
    return (name in {"py.exe", "powershell.exe", "pwsh.exe"}
            or (name.startswith("python") and name.endswith(".exe")))


class RetainedCohort:
    """Keep original witnesses through repeated bounded capture and retirement.

    ``observe_new`` adds potential consumers; it never replaces a live handle.
    ``assert_retired`` performs another stable capture and requires every held
    candidate to be signaled DEAD. It does not certify source freeze, relevance,
    import provenance or safe activation. Collection uncertainty is sticky;
    there is no reset/ignore flag to turn a partial inventory into evidence.

    ``backend`` is an explicit synthetic testing seam, not a CLI plugin. It must
    supply current(), enumerate(max_processes, deadline), capture(pid), image()
    and monotonic(). Production uses the native backend below.
    """

    def __init__(self, backend, max_processes, max_candidates, budget_seconds):
        self._backend = backend
        self._max_processes, self._max_candidates = max_processes, max_candidates
        self._budget_seconds = budget_seconds
        self._current = None
        self._processes = []
        self._failures = []
        self._unresolved = None
        self._completed_observations = 0
        self._closed = False
        self._closing = False
        self._lock = threading.RLock()

    @classmethod
    def capture_current(cls, *, backend=None, max_processes=8192,
                        max_candidates=1024, budget_seconds=5.0):
        if (type(max_processes) is not int or not 1 <= max_processes <= 65536
                or type(max_candidates) is not int
                or not 1 <= max_candidates <= min(max_processes, 4096)
                or type(budget_seconds) not in {int, float}
                or not math.isfinite(budget_seconds)
                or not 0 < budget_seconds <= 30):
            raise ValueError("invalid_cohort_bounds")
        owner = cls(_NativeBackend() if backend is None else backend,
                    max_processes, max_candidates, float(budget_seconds))
        try:
            owner._current = owner._backend.current()
            owner._verify_process(owner._current)
            owner.observe_new()
            return owner
        except BaseException as error:
            raise owner._capture_failure(error) from None

    def _capture_failure(self, error):
        if error not in self._failures:
            self._failures.append(error)
        reason = (error.reason if isinstance(error, CohortUnavailable)
                  else "cohort_native_observation_unavailable")
        self._unresolved = self._unresolved or reason
        if isinstance(error, CohortUnavailable) and error.cohort is self:
            return error
        return CohortUnavailable(reason, self)

    @staticmethod
    def _verify_process(process, pid=None):
        if (not isinstance(process, VerifiedProcess)
                or not isinstance(process.identity, ProcessIdentity)
                or (pid is not None and process.identity.pid != pid)):
            raise CohortUnavailable("cohort_identity_unverified")
        if process.observe().status is not IdentityStatus.ALIVE:
            raise CohortUnavailable("cohort_capture_liveness_unverified")

    def _check_open(self):
        if self._closed or self._closing:
            raise CohortUnavailable("cohort_closed_or_closing", self)
        if self._unresolved is not None:
            raise CohortUnavailable(self._unresolved, self)

    def _budget(self, deadline):
        value = self._backend.monotonic()
        if not math.isfinite(value) or value > deadline:
            raise CohortUnavailable("cohort_capture_budget_exceeded")

    def _inventory(self, deadline):
        records = self._backend.enumerate(self._max_processes, deadline)
        if not isinstance(records, (tuple, list)) or not 1 <= len(records) <= self._max_processes:
            raise CohortUnavailable("cohort_inventory_overflow_or_empty")
        result = {}
        for record in records:
            self._budget(deadline)
            if (not isinstance(record, ProcessEntry) or type(record.pid) is not int
                    or not 0 <= record.pid <= 0xFFFFFFFF or record.pid in result):
                raise CohortUnavailable("cohort_inventory_invalid")
            # System Idle (PID 0) is a Toolhelp entry, never a query candidate.
            result[record.pid] = _basename(record.image_name)
        return result

    def _capture_entry(self, pid, name):
        if pid == self._current.identity.pid:
            self._verify_process(self._current, pid)
            if _basename(self._backend.image(self._current)) != name:
                raise CohortUnavailable("cohort_current_image_mismatch")
            return
        for process in self._processes:
            if process.identity.pid != pid:
                continue
            state = process.observe().status
            if state is IdentityStatus.UNKNOWN:
                raise CohortUnavailable("cohort_retained_identity_unknown")
            if state is IdentityStatus.ALIVE:
                if _basename(self._backend.image(process)) != name:
                    raise CohortUnavailable("cohort_retained_image_mismatch")
                return
        if len(self._processes) >= self._max_candidates:
            raise CohortUnavailable("cohort_candidate_overflow")
        process = self._backend.capture(pid)
        # Own immediately, before validation/image reads or interruption can fail.
        self._processes.append(process)
        self._verify_process(process, pid)
        if _basename(self._backend.image(process)) != name:
            raise CohortUnavailable("cohort_snapshot_identity_changed")
        self._verify_process(process, pid)

    def observe_new(self):
        """Add all newly seen potential interpreters, including other logons."""
        with self._lock:
            self._check_open()
            try:
                start = self._backend.monotonic()
                if not math.isfinite(start):
                    raise CohortUnavailable("cohort_clock_unavailable")
                deadline = start + self._budget_seconds
                self._verify_process(self._current)
                before = self._inventory(deadline)
                if self._current.identity.pid not in before:
                    raise CohortUnavailable("cohort_current_missing")
                # Verify the exact current process even for renamed activators.
                self._capture_entry(self._current.identity.pid,
                                    before[self._current.identity.pid])
                for pid, name in sorted(before.items()):
                    self._budget(deadline)
                    if _potential_interpreter(name):
                        self._capture_entry(pid, name)
                after = self._inventory(deadline)
                if before != after:
                    raise CohortUnavailable("cohort_inventory_changed")
                # A candidate may exit while its PID remains in the snapshot.
                for process in self._processes:
                    if process.identity.pid in before:
                        newer = any(other is not process and other.identity.pid == process.identity.pid
                                    and other.observe().status is IdentityStatus.ALIVE
                                    for other in self._processes)
                        if not newer:
                            self._verify_process(process)
                self._budget(deadline)
                self._completed_observations += 1
            except BaseException as error:
                raise self._capture_failure(error) from None

    def assert_retired(self):
        """Refresh discovery and require positive death; no activation grant."""
        with self._lock:
            self.observe_new()
            self.assert_retained_retired()

    def assert_retained_retired(self):
        """Check original held candidates only, without discovering consumers.

        A caller retaining its own independently established cutover fence may
        recheck the retired old cohort after new-version consumers have started.
        This method has no source-freeze knowledge and cannot replace the fresh
        discovery required at cutover. No freeze flag or authority is minted.
        """
        with self._lock:
            self._check_open()
            try:
                states = [process.observe().status for process in self._processes]
            except BaseException as error:
                raise self._capture_failure(error) from None
            if any(state is IdentityStatus.UNKNOWN for state in states):
                raise self._capture_failure(
                    CohortUnavailable("cohort_retirement_unknown", self))
            if any(state is not IdentityStatus.DEAD for state in states):
                raise CohortUnavailable("cohort_ambiguous_consumers_still_alive", self)

    def summary(self):
        """Counts only: no PID, executable path, command or supposed writer."""
        with self._lock:
            return CohortSummary(len(self._processes), len(self._processes),
                                 self._completed_observations,
                                 self._unresolved is not None, self._closed)

    def close(self):
        """Release witnesses on abandonment; closing is never death evidence."""
        with self._lock:
            if self._closed:
                return
            self._closing = True
            failures = []
            for error in self._failures:
                try:
                    retry_identity_cleanup(error)
                except BaseException as failure:
                    failures.append(failure)
            for process in [*self._processes, self._current]:
                if process is None:
                    continue
                try:
                    process.close()
                except BaseException as failure:
                    failures.append(failure)
            if failures:
                # Original capture errors own any handles that never reached
                # _processes. retry_identity_cleanup keeps unresolved owners on
                # those roots; returned errors must not be appended again.
                # Process close errors likewise already have an owner here.
                # Repeated unknown-close retries therefore stay bounded.
                raise CohortUnavailable("cohort_cleanup_unsettled", self)
            self._closed = True


class _ProcessEntry32W(C.Structure):
    _fields_ = [("dwSize", C.c_uint32), ("cntUsage", C.c_uint32),
                ("th32ProcessID", C.c_uint32), ("th32DefaultHeapID", C.c_size_t),
                ("th32ModuleID", C.c_uint32), ("cntThreads", C.c_uint32),
                ("th32ParentProcessID", C.c_uint32), ("pcPriClassBase", C.c_int32),
                ("dwFlags", C.c_uint32), ("szExeFile", C.c_wchar * 260)]


class _NativeBackend:
    """Lazy Windows x64 Toolhelp32 plus same-handle process image queries."""

    monotonic = staticmethod(time.monotonic)

    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise CohortUnavailable("cohort_platform_unsupported")
        from .identity import _backend, _bind
        self._identity_backend = _backend()
        self._kernel = k = C.WinDLL("kernel32", use_last_error=True)
        _bind(k, "CreateToolhelp32Snapshot", C.c_void_p, C.c_uint32, C.c_uint32)
        _bind(k, "Process32FirstW", C.c_int32, C.c_void_p, C.POINTER(_ProcessEntry32W))
        _bind(k, "Process32NextW", C.c_int32, C.c_void_p, C.POINTER(_ProcessEntry32W))
        _bind(k, "QueryFullProcessImageNameW", C.c_int32, C.c_void_p,
              C.c_uint32, C.c_wchar_p, C.POINTER(C.c_uint32))

    def current(self):
        return VerifiedProcess.current()

    def capture(self, pid):
        # Discovery is the only bootstrap. _open checks native PID/birth/logon
        # once; every subsequent operation uses that same retained handle.
        return VerifiedProcess._open(pid)

    def enumerate(self, max_processes, deadline):
        handle = self._kernel.CreateToolhelp32Snapshot(0x00000002, 0)
        if handle in {None, C.c_void_p(-1).value}:
            raise CohortUnavailable("cohort_snapshot_unavailable")
        owner = _DuplicateCleanup(self._identity_backend, handle)
        try:
            record = _ProcessEntry32W()
            record.dwSize = C.sizeof(record)
            if not self._kernel.Process32FirstW(handle, C.byref(record)):
                raise CohortUnavailable("cohort_snapshot_first_unavailable")
            rows = []
            while True:
                if len(rows) >= max_processes:
                    raise CohortUnavailable("cohort_inventory_overflow_or_empty")
                if self.monotonic() > deadline:
                    raise CohortUnavailable("cohort_capture_budget_exceeded")
                rows.append(ProcessEntry(int(record.th32ProcessID), record.szExeFile))
                record.dwSize = C.sizeof(record)
                if not self._kernel.Process32NextW(handle, C.byref(record)):
                    if C.get_last_error() != 18:  # ERROR_NO_MORE_FILES only.
                        raise CohortUnavailable("cohort_snapshot_next_unavailable")
                    break
        except BaseException as error:
            try:
                owner.close()
            except BaseException:
                _retain_cleanup(error, owner)
            raise
        # A failed/unknown CloseHandle makes collection incomplete and retains
        # the snapshot owner on the original exception for conservative cleanup.
        owner.close()
        return tuple(rows)

    def image(self, process):
        if not isinstance(process, VerifiedProcess):
            raise CohortUnavailable("cohort_identity_unverified")
        with process._lock:
            if process._handle is None or process._close_outcome_unknown:
                raise CohortUnavailable("cohort_image_handle_unavailable")
            size = C.c_uint32(32768)
            image = C.create_unicode_buffer(size.value)
            if not self._kernel.QueryFullProcessImageNameW(
                    process._handle, 0, image, C.byref(size)):
                raise CohortUnavailable("cohort_image_unavailable")
            if not 0 < size.value < len(image):
                raise CohortUnavailable("cohort_image_unavailable")
            return image.value
