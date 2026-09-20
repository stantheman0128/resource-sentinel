"""Bounded read-only machine endpoints, not a FastFrame or control provider.

Each explicit sample reads machine counters a fixed number of times; there is
no worker, timer, process scan, persistence, PDH/CIM, Job query or mutation API.
Two complete endpoints are needed for CPU units. The caller owns scheduling,
freshness checks, accounting, Job coverage and the full recovery warmup gate.

All timestamps use QueryInterruptTimePrecise's 100 ns interrupt-time domain.
An endpoint's measurements lie inside its recorded capture bracket; its end is
the CPU window endpoint. Capture duration is a conservative skew bound, not a
claim of simultaneous measurements. Runtime epochs are newly generated local
continuity identifiers, never OS boot IDs or witnesses for an earlier process.
collection_cost_ms measures that capture bracket, not total helper overhead.
These APIs cannot prove that a short suspend did not occur between endpoints;
an upstream power/continuity witness must call invalidate_clock() on that event.

API references checked against Microsoft documentation:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes
https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getperformanceinfo
https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-performance_information
https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorgroupcount
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getactiveprocessorcount
https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import os
import threading
from uuid import uuid4

from .contracts import FrameError, MachineFrame, RetryClass, Validity


_TICKS_PER_SECOND = 10_000_000
_MIN_WINDOW = _TICKS_PER_SECOND // 2
_MAX_WINDOW = 3 * _TICKS_PER_SECOND // 2
_MAX_AGE = 3 * _TICKS_PER_SECOND
_CAPTURE_BUDGET = _TICKS_PER_SECOND // 10  # Plan's 100 ms sampler work budget.
_UINT64_MAX = (1 << 64) - 1
_DWORD, _WORD, _BOOL = C.c_uint32, C.c_uint16, C.c_int32


class _FileTime(C.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _PerformanceInformation(C.Structure):
    _fields_ = [("cb", _DWORD)] + [
        (name, C.c_size_t) for name in (
            "CommitTotal", "CommitLimit", "CommitPeak", "PhysicalTotal", "PhysicalAvailable",
            "SystemCache", "KernelTotal", "KernelPaged", "KernelNonpaged", "PageSize")
    ] + [("HandleCount", _DWORD), ("ProcessCount", _DWORD), ("ThreadCount", _DWORD)]


def _error(code, stage, *, api_error_code=None, retry=RetryClass.NEW_ATTEMPT):
    return FrameError(code, stage, retry, api_error_code=api_error_code)


class MachineSamplingError(RuntimeError):
    """Sanitized native/concurrent sampling failure; never substitute zeros."""
    def __init__(self, error):
        self.error = error
        super().__init__(error.code + ":" + error.stage)


@dataclass(frozen=True)
class _Snapshot:
    capture_start_tick_100ns: int
    capture_end_tick_100ns: int
    logical_processors: int | None
    processor_groups: int | None
    # GetSystemTimes cumulative (idle, kernel including idle, user), in 100 ns.
    cpu_times: tuple[int, int, int] | None
    # (physical total, physical available, commit used, commit limit, page size).
    # First four fields are page counts; the last field is bytes per page.
    memory_pages: tuple[int, int, int, int, int] | None
    errors: tuple[FrameError, ...] = ()


@dataclass(frozen=True)
class MachineSample:
    machine: MachineFrame | None
    sampler_epoch: str
    clock_epoch: str
    counter_epoch: str
    sample_seq: int
    capture_start_tick_100ns: int | None
    capture_end_tick_100ns: int | None
    window_start_tick_100ns: int | None
    window_end_tick_100ns: int | None
    validity: Validity
    errors: tuple[FrameError, ...]
    reset_required: bool
    collection_cost_ms: float | None

    def is_fresh(self, now_tick_100ns, *, clock_epoch):
        """Conservative machine-only freshness, not admission/control authority.

        The earliest read in the capture bracket must also be within three
        seconds; a slow capture cannot make an older field appear younger.
        """
        return (self.validity is Validity.VALID and self.machine is not None and
                clock_epoch == self.clock_epoch and _uint(now_tick_100ns) and
                self.window_end_tick_100ns is not None and self.capture_start_tick_100ns is not None and
                self.window_end_tick_100ns <= now_tick_100ns and
                0 <= now_tick_100ns - self.capture_start_tick_100ns <= _MAX_AGE)


def _uint(value):
    return type(value) is int and 0 <= value <= _UINT64_MAX


def _bind(dll, name, result, *arguments):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, arguments
    return function


class _WindowsBackend:
    """Fixed-size native reads only; no handles are opened or retained."""
    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise MachineSamplingError(_error("denominator_unknown", "machine_platform", retry=RetryClass.NEVER))
        if C.sizeof(_PerformanceInformation) != 104 or _PerformanceInformation.CommitTotal.offset != 8:
            raise MachineSamplingError(_error("measurement_inconsistent", "machine_memory_abi", retry=RetryClass.NEVER))
        try:
            self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
            self.psapi = p = C.WinDLL("psapi", use_last_error=True)
            # The documented API-set contract resolves on hosts where the
            # kernel32 DLL has no direct QueryInterruptTimePrecise export.
            self.realtime = r = C.WinDLL("api-ms-win-core-realtime-l1-1-1.dll", use_last_error=True)
            _bind(k, "GetSystemTimes", _BOOL, *([C.POINTER(_FileTime)] * 3))
            _bind(r, "QueryInterruptTimePrecise", None, C.POINTER(C.c_uint64))
            _bind(k, "GetActiveProcessorGroupCount", _WORD)
            _bind(k, "GetActiveProcessorCount", _DWORD, _WORD)
            _bind(p, "GetPerformanceInfo", _BOOL, C.POINTER(_PerformanceInformation), _DWORD)
        except (AttributeError, OSError):
            raise MachineSamplingError(_error("telemetry_stale", "machine_native_api", retry=RetryClass.NEVER)) from None

    def tick(self):
        value = C.c_uint64(_UINT64_MAX)
        self.realtime.QueryInterruptTimePrecise(C.byref(value))
        # The documented API returns VOID, so no invented BOOL/GetLastError.
        if value.value == _UINT64_MAX:
            raise MachineSamplingError(_error("clock_discontinuity", "machine_clock"))
        return int(value.value)

    def topology(self):
        groups = int(self.kernel.GetActiveProcessorGroupCount())
        if groups == 0:
            # This API does not document GetLastError on zero.
            raise MachineSamplingError(_error("denominator_unknown", "machine_processor_groups"))
        processors = int(self.kernel.GetActiveProcessorCount(0xFFFF))
        if processors == 0:
            raise MachineSamplingError(_error("denominator_unknown", "machine_processors",
                                               api_error_code=C.get_last_error()))
        return processors, groups

    def cpu_times(self):
        idle, kernel, user = (_FileTime() for _ in range(3))
        if not self.kernel.GetSystemTimes(C.byref(idle), C.byref(kernel), C.byref(user)):
            raise MachineSamplingError(_error("telemetry_stale", "machine_cpu",
                                               api_error_code=C.get_last_error()))
        return tuple((value.high << 32) | value.low for value in (idle, kernel, user))

    def memory_pages(self):
        value = _PerformanceInformation()
        value.cb = C.sizeof(value)
        if not self.psapi.GetPerformanceInfo(C.byref(value), C.sizeof(value)):
            raise MachineSamplingError(_error("telemetry_stale", "machine_memory",
                                               api_error_code=C.get_last_error()))
        if value.cb != C.sizeof(value):
            raise MachineSamplingError(_error("measurement_inconsistent", "machine_memory_size"))
        return tuple(int(getattr(value, name)) for name in (
            "PhysicalTotal", "PhysicalAvailable", "CommitTotal", "CommitLimit", "PageSize"))

    def read(self):
        start = self.tick()
        errors = []

        def read(function):
            try:
                return function()
            except MachineSamplingError as error:
                errors.append(error.error)
                return None

        before = read(self.topology)
        cpu = read(self.cpu_times)
        memory = read(self.memory_pages)
        after = read(self.topology)
        end = self.tick()
        if before != after:
            errors.append(_error("denominator_unknown", "machine_topology_changed"))
        topology = before if before is not None and before == after else (None, None)
        return _Snapshot(start, end, *topology, cpu, memory, tuple(errors))


class MachineSampler:
    """One caller-driven sample per invocation; constant-size baseline state.

    ``backend`` is an explicit in-process fixture seam, not a configuration or
    environment override. Native initialization is lazy until sample(). A
    concurrent invocation raises busy without waiting or fabricating a sequence.
    Invalid complete endpoints seed a new baseline only where noted below; a
    consumer must still reset all pressure/recovery streaks on reset_required.
    """
    def __init__(self, *, backend=None):
        self._backend = backend
        self._previous = None
        self._lock = threading.Lock()
        self.sampler_epoch = str(uuid4())
        self.clock_epoch = str(uuid4())
        self.counter_epoch = str(uuid4())
        self._sample_seq = 0

    def _reset(self, *, clock=False, baseline=None):
        self._previous = baseline
        self.counter_epoch = str(uuid4())
        if clock:
            self.clock_epoch = str(uuid4())

    def _result(self, machine, snapshot, start, validity, errors, reset):
        return MachineSample(machine, self.sampler_epoch, self.clock_epoch, self.counter_epoch,
            self._sample_seq, None if snapshot is None else snapshot.capture_start_tick_100ns,
            None if snapshot is None else snapshot.capture_end_tick_100ns, start,
            None if snapshot is None else snapshot.capture_end_tick_100ns,
            validity, tuple(errors), reset,
            None if snapshot is None else (snapshot.capture_end_tick_100ns - snapshot.capture_start_tick_100ns) / 10_000)

    @staticmethod
    def _memory(snapshot):
        pages = snapshot.memory_pages
        if type(pages) is not tuple or len(pages) != 5 or not all(_uint(value) for value in pages):
            return None
        total, available, committed, limit, page_size = pages
        if (total == 0 or limit == 0 or page_size == 0 or page_size & (page_size - 1) or
                available > total or committed > limit):
            return None
        values = tuple(value * page_size for value in pages[:4])
        return values if all(_uint(value) for value in values) else None

    @staticmethod
    def _cpu(snapshot):
        times = snapshot.cpu_times
        return (times if type(times) is tuple and len(times) == 3 and all(_uint(value) for value in times)
                and times[0] <= times[1] else None)

    def sample(self):
        if not self._lock.acquire(blocking=False):
            raise MachineSamplingError(_error("busy", "machine_sampler", retry=RetryClass.TRANSIENT))
        try:
            self._sample_seq += 1
            try:
                if self._backend is None:
                    self._backend = _WindowsBackend()
                snapshot = self._backend.read()
            except MachineSamplingError as error:
                self._reset(clock=error.error.code == "clock_discontinuity")
                return self._result(None, None, None, Validity.UNKNOWN, (error.error,), True)
            except BaseException:
                # Unexpected backend/programming interruptions must remain
                # visible, but a later call cannot bridge the failed attempt.
                self._reset(clock=True)
                raise
            return self._consume(snapshot)
        finally:
            self._lock.release()

    def invalidate_clock(self):
        """Forget a pair after a caller-observed resume/continuity loss.

        This updates this sampler's local state only. It neither restores caps
        nor acknowledges that the caller completed the required recovery work.
        """
        if not self._lock.acquire(blocking=False):
            raise MachineSamplingError(_error("busy", "machine_sampler", retry=RetryClass.TRANSIENT))
        try:
            self._reset(clock=True)
        finally:
            self._lock.release()

    def _consume(self, snapshot):
        if (type(snapshot) is not _Snapshot or not _uint(snapshot.capture_start_tick_100ns) or
                not _uint(snapshot.capture_end_tick_100ns) or
                snapshot.capture_end_tick_100ns < snapshot.capture_start_tick_100ns or
                type(snapshot.errors) is not tuple or len(snapshot.errors) > 8 or
                any(type(error) is not FrameError for error in snapshot.errors)):
            self._reset(clock=True)
            return self._result(None, None, None, Validity.INVALID,
                                (_error("clock_discontinuity", "machine_capture_invalid"),), True)
        errors = list(snapshot.errors)
        topology = snapshot.logical_processors, snapshot.processor_groups
        topology_valid = (type(topology[0]) is int and 1 <= topology[0] <= 64 and type(topology[1]) is int and topology[1] == 1)
        if not topology_valid:
            errors.append(_error("denominator_unknown", "machine_topology"))
        memory = self._memory(snapshot)
        if memory is None:
            errors.append(_error("measurement_inconsistent" if snapshot.memory_pages is not None else "telemetry_stale", "machine_memory"))
        cpu = self._cpu(snapshot)
        if cpu is None:
            errors.append(_error("measurement_inconsistent" if snapshot.cpu_times is not None else "telemetry_stale", "machine_cpu"))
        cost = snapshot.capture_end_tick_100ns - snapshot.capture_start_tick_100ns
        if cost > _CAPTURE_BUDGET:
            errors.append(_error("observer_budget_exceeded", "machine_capture"))
        previous = self._previous
        start = None if previous is None else previous.capture_end_tick_100ns
        discontinuity = (previous is not None and (
            snapshot.capture_start_tick_100ns < previous.capture_end_tick_100ns or
            snapshot.capture_end_tick_100ns - previous.capture_end_tick_100ns > _MAX_AGE))
        if discontinuity:
            errors.append(_error("clock_discontinuity", "machine_window"))
            start = None
        if errors:
            self._reset(clock=discontinuity or any(error.code == "clock_discontinuity" for error in errors))
            machine = None if not topology_valid else MachineFrame(*topology, None, *(memory or (None,) * 4))
            return self._result(machine, snapshot, start, Validity.UNKNOWN, errors, True)
        # This endpoint is complete. It may be the first endpoint of a new
        # counter/window baseline; no CPU value is synthesized during warmup.
        if previous is None:
            self._previous = snapshot
            return self._result(MachineFrame(*topology, None, *memory), snapshot, None, Validity.UNKNOWN,
                                (_error("sample_window_invalid", "machine_warmup"),), True)
        # CPU calls occur somewhere within both capture brackets. Require the
        # entire possible delta interval, not just end-to-end timestamps, to
        # satisfy 0.5..1.5 s. The normal ~1 s cadence tolerates bounded skew.
        minimum_window = snapshot.capture_start_tick_100ns - previous.capture_end_tick_100ns
        maximum_window = snapshot.capture_end_tick_100ns - previous.capture_start_tick_100ns
        if topology != (previous.logical_processors, previous.processor_groups):
            errors.append(_error("counter_reset", "machine_topology_changed"))
        elif not (_MIN_WINDOW <= minimum_window and maximum_window <= _MAX_WINDOW):
            errors.append(_error("sample_window_invalid", "machine_window"))
        else:
            idle, kernel, user = (now - old for now, old in zip(cpu, previous.cpu_times))
            if min(idle, kernel, user) < 0 or kernel + user == 0:
                errors.append(_error("counter_reset", "machine_cpu_delta"))
            elif kernel < idle:
                errors.append(_error("measurement_inconsistent", "machine_cpu_delta"))
            else:
                # Kernel already includes idle: do not double-count it in the
                # denominator, and do not divide this machine ratio by N again.
                units = ((kernel + user - idle) / (kernel + user)) * topology[0]
        if errors:
            self._reset(baseline=snapshot)
            return self._result(MachineFrame(*topology, None, *memory), snapshot, start,
                                Validity.INVALID, errors, True)
        self._previous = snapshot
        return self._result(MachineFrame(*topology, units, *memory), snapshot, start, Validity.VALID, (), False)
