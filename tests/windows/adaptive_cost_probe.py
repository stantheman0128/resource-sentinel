"""Measured monitoring cost and reaction time for the 11.2 thresholds.

The probe samples process CPU time and private Commit for PIDs the caller
started, through GetProcessTimes and GetProcessMemoryInfo with
PROCESS_QUERY_LIMITED_INFORMATION only. It cannot enumerate processes, match by
name, or signal anything: there is no such call in this module.

A configured tick or lease interval is not a measurement. ReactionLatency
therefore accepts monotonic stage timestamps only, and a threshold with no
measurement returns NOT_MEASURED instead of a pass.

References: Microsoft Learn GetProcessTimes, GetProcessMemoryInfo and
PROCESS_MEMORY_COUNTERS_EX (PrivateUsage), Process Security and Access Rights.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
import math
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from adaptive_win32 import _api  # noqa: E402  (reuse the bound P1 kernel32)
from sentinel.adaptive import native_launcher as _launcher  # noqa: E402

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
FILETIME_PER_SECOND = 10_000_000
BYTES_PER_MIB = float(1 << 20)
MIN_INTERVAL_SECONDS = 0.05
MAX_INTERVAL_SECONDS = 30.0
OUTCOMES = ("PASS", "FAIL", "NOT_MEASURED")
REACTION_STAGES = ("sample_window_end", "decision", "apply", "query_confirmed")

# Section 11.2, as upper bounds. Nothing here has been measured by this plan.
THRESHOLDS = {
    "monitoring_cpu_units_1_job": 0.05,
    "monitoring_cpu_units_10_jobs": 0.10,
    "monitoring_cpu_units_50_jobs": 0.25,
    "fast_tick_p95_seconds_10_jobs": 0.050,
    "fast_tick_p95_seconds_50_jobs": 0.100,
    "monitoring_private_commit_mib": 160.0,
    "wrapper_host_private_commit_mib": 48.0,
    "wrapper_launch_overhead_p95_seconds": 0.500,
}
_PSAPI = None


class CostProbeError(RuntimeError):
    """Measurement failure; an unmeasured cost is never reported as a number."""


class ReactionLatencyError(ValueError):
    """A reaction time without all four monotonic stages is not evidence."""


class _MemoryCountersEx(C.Structure):
    _fields_ = [("cb", C.c_uint32), ("PageFaultCount", C.c_uint32),
                ("PeakWorkingSetSize", C.c_size_t), ("WorkingSetSize", C.c_size_t),
                ("QuotaPeakPagedPoolUsage", C.c_size_t), ("QuotaPagedPoolUsage", C.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", C.c_size_t), ("QuotaNonPagedPoolUsage", C.c_size_t),
                ("PagefileUsage", C.c_size_t), ("PeakPagefileUsage", C.c_size_t),
                ("PrivateUsage", C.c_size_t)]


def _psapi():
    """Bind only the one documented memory query; reuse kernel32 from the P1 ABI."""
    global _PSAPI
    if _PSAPI is None:
        psapi = C.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.restype = W.BOOL
        psapi.GetProcessMemoryInfo.argtypes = [W.HANDLE, C.POINTER(_MemoryCountersEx), W.DWORD]
        _PSAPI = psapi
    return _PSAPI


def _interval(seconds):
    if type(seconds) not in (int, float) or type(seconds) is bool or not math.isfinite(seconds):
        raise CostProbeError("sampling interval must be a finite number")
    if not MIN_INTERVAL_SECONDS <= seconds <= MAX_INTERVAL_SECONDS:
        raise CostProbeError(
            f"sampling interval must be within [{MIN_INTERVAL_SECONDS}, {MAX_INTERVAL_SECONDS}]s")
    return float(seconds)


@dataclass(frozen=True)
class ProcessCost:
    """Measured cost of one process over one interval."""

    pid: int
    created_filetime_100ns: str
    cpu_seconds: float
    cpu_units: float
    private_commit_mib: float

    def __post_init__(self):
        if type(self.pid) is not int or self.pid <= 0:
            raise CostProbeError("pid must be a positive integer")
        for name in ("cpu_seconds", "cpu_units", "private_commit_mib"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise CostProbeError(f"{name} must be a finite non-negative number")


@dataclass(frozen=True)
class CostSample:
    """One interval over the whole measured set."""

    interval_seconds: float
    per_process: tuple

    def __post_init__(self):
        object.__setattr__(self, "interval_seconds", _interval(self.interval_seconds))
        object.__setattr__(self, "per_process", tuple(self.per_process))
        if not self.per_process:
            raise CostProbeError("a sample covers at least one process")
        for item in self.per_process:
            if not isinstance(item, ProcessCost):
                raise CostProbeError("per_process holds only ProcessCost entries")

    @property
    def total_cpu_units(self):
        return sum(item.cpu_units for item in self.per_process)

    @property
    def total_cpu_seconds(self):
        return sum(item.cpu_seconds for item in self.per_process)

    @property
    def total_private_commit_mib(self):
        return sum(item.private_commit_mib for item in self.per_process)


class CostProbe:
    """Opens exactly the PIDs the caller started, for query access only.

    The caller must pass PIDs of processes it created itself. Each handle keeps
    the creation FILETIME read at open time, and every sample rechecks it, so a
    reused PID fails the measurement instead of being reported as the fixture.
    """

    def __init__(self, pids):
        requested = tuple(pids)
        if not requested or len(set(requested)) != len(requested):
            raise CostProbeError("pass a non-empty set of distinct PIDs you started")
        self._handles = {}
        self._births = {}
        try:
            for pid in requested:
                if type(pid) is not int or type(pid) is bool or pid <= 0:
                    raise CostProbeError("pid must be a positive integer")
                kernel = _api()[0]
                handle = kernel.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if not handle:
                    raise CostProbeError(
                        f"OpenProcess(query limited) failed for {pid}: {C.get_last_error()}")
                self._handles[pid] = handle
                self._births[pid] = self._times(pid)[0]
        except BaseException:
            self.close()
            raise

    def _times(self, pid):
        """Return (created FILETIME, kernel+user 100ns) for one opened process."""
        created, exited, kernel_time, user_time = (_launcher._FileTime() for _ in range(4))
        if not _api()[0].GetProcessTimes(self._handles[pid], C.byref(created), C.byref(exited),
                                         C.byref(kernel_time), C.byref(user_time)):
            raise CostProbeError(f"GetProcessTimes failed for {pid}: {C.get_last_error()}")
        birth = (created.dwHighDateTime << 32) | created.dwLowDateTime
        kernel_100ns = (kernel_time.dwHighDateTime << 32) | kernel_time.dwLowDateTime
        user_100ns = (user_time.dwHighDateTime << 32) | user_time.dwLowDateTime
        return birth, kernel_100ns + user_100ns

    def _private_commit(self, pid):
        counters = _MemoryCountersEx()
        counters.cb = C.sizeof(_MemoryCountersEx)
        if not _psapi().GetProcessMemoryInfo(self._handles[pid], C.byref(counters),
                                             C.sizeof(_MemoryCountersEx)):
            raise CostProbeError(f"GetProcessMemoryInfo failed for {pid}: {C.get_last_error()}")
        return int(counters.PrivateUsage)

    def sample(self, interval_seconds):
        """Measure a CPU time delta over a real interval, never a configured one."""
        seconds = _interval(interval_seconds)
        pids = tuple(self._handles)
        started = time.monotonic()
        first = {pid: self._times(pid) for pid in pids}
        remaining = seconds - (time.monotonic() - started)
        if remaining > 0:
            time.sleep(remaining)
        elapsed = time.monotonic() - started
        costs = []
        for pid in pids:
            birth, busy = self._times(pid)
            if birth != self._births[pid] or birth != first[pid][0]:
                raise CostProbeError(f"creation time of {pid} changed; the PID was reused")
            delta = (busy - first[pid][1]) / FILETIME_PER_SECOND
            if delta < 0:
                raise CostProbeError(f"process CPU time of {pid} went backwards")
            costs.append(ProcessCost(pid, str(birth), delta, delta / elapsed,
                                     self._private_commit(pid) / BYTES_PER_MIB))
        return CostSample(elapsed, tuple(costs))

    def close(self):
        kernel = _api()[0]
        for pid, handle in list(self._handles.items()):
            self._handles.pop(pid, None)
            if handle:
                kernel.CloseHandle(handle)


def measure(pids, interval_seconds):
    """Open, sample once, close. Closing a query handle changes nothing."""
    probe = CostProbe(pids)
    try:
        return probe.sample(interval_seconds)
    finally:
        probe.close()


def percentile(values, fraction):
    """Nearest-rank percentile over a non-empty sequence of finite numbers."""
    if type(fraction) not in (int, float) or type(fraction) is bool \
            or not 0 < float(fraction) <= 1:
        raise CostProbeError("percentile fraction must be within (0, 1]")
    ordered = []
    for value in values:
        if type(value) not in (int, float) or type(value) is bool or not math.isfinite(value):
            raise CostProbeError("percentile needs finite numbers")
        ordered.append(float(value))
    if not ordered:
        raise CostProbeError("percentile needs at least one measurement")
    ordered.sort()
    rank = math.ceil(float(fraction) * len(ordered))
    return ordered[max(1, rank) - 1]


@dataclass(frozen=True)
class ThresholdResult:
    """Closed outcome set; an absent measurement is NOT_MEASURED, never a pass."""

    name: str
    threshold: float
    measured: float | None
    outcome: str

    def __post_init__(self):
        if self.outcome not in OUTCOMES:
            raise CostProbeError(f"outcome must be one of {OUTCOMES}")


def evaluate_threshold(name, measured):
    if name not in THRESHOLDS:
        raise CostProbeError(f"unknown 11.2 threshold: {name}")
    limit = THRESHOLDS[name]
    if measured is None:
        return ThresholdResult(name, limit, None, "NOT_MEASURED")
    if type(measured) not in (int, float) or type(measured) is bool or not math.isfinite(measured):
        raise CostProbeError(f"{name} measurement must be a finite number or None")
    return ThresholdResult(name, limit, float(measured),
                           "PASS" if float(measured) <= limit else "FAIL")


def evaluate_all(measurements):
    """Every 11.2 threshold, with the unmeasured ones explicitly NOT_MEASURED."""
    unknown = set(measurements) - set(THRESHOLDS)
    if unknown:
        raise CostProbeError(f"unknown 11.2 thresholds: {sorted(unknown)}")
    return tuple(evaluate_threshold(name, measurements.get(name)) for name in THRESHOLDS)


@dataclass(frozen=True)
class ReactionLatency:
    """Reaction time decomposed into the four stages, from monotonic readings.

    There is no constructor argument for a configured sample interval, tick
    period or lease duration. Every stage is a measured monotonic timestamp.
    """

    stages: dict

    def __post_init__(self):
        if type(self.stages) is not dict:
            raise ReactionLatencyError("stages must be a dictionary of monotonic readings")
        missing = [stage for stage in REACTION_STAGES if stage not in self.stages]
        if missing:
            raise ReactionLatencyError(f"missing measured stages: {missing}")
        extra = set(self.stages) - set(REACTION_STAGES)
        if extra:
            raise ReactionLatencyError(f"unknown stages: {sorted(extra)}")
        previous = None
        for stage in REACTION_STAGES:
            value = self.stages[stage]
            if type(value) not in (int, float) or type(value) is bool or not math.isfinite(value):
                raise ReactionLatencyError(f"{stage} must be a finite monotonic reading")
            if previous is not None and float(value) <= previous:
                raise ReactionLatencyError(f"{stage} does not come after the previous stage")
            previous = float(value)
        object.__setattr__(self, "stages", {stage: float(self.stages[stage])
                                            for stage in REACTION_STAGES})

    @property
    def total_seconds(self):
        return self.stages[REACTION_STAGES[-1]] - self.stages[REACTION_STAGES[0]]

    @property
    def stage_durations(self):
        return {later: self.stages[later] - self.stages[earlier]
                for earlier, later in zip(REACTION_STAGES, REACTION_STAGES[1:])}


def reaction_p95(records):
    """p95 of measured reaction times; it accepts nothing but real records."""
    values = []
    for record in records:
        if not isinstance(record, ReactionLatency):
            raise ReactionLatencyError("only measured ReactionLatency records are aggregated")
        values.append(record.total_seconds)
    return percentile(values, 0.95)
