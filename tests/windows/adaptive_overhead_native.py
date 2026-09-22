"""Native query sources for the isolated P4 observer-cost runner.

No admission, process creation, PID reopening, Job control or native close is
performed here. Every process/Job handle is borrowed from its original owner.
Fifty Jobs are a read-only stress workload, split into production-sized sampler
shards; this does not enroll fifty Jobs into a production guardian.

The current helper has no per-member private-memory reader. Its unknown memory
frames are counted, while inaccessible-identity and scan-timeout cases remain
unmeasured (zero). These sources cannot manufacture the missing P4 gate cases.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass, replace
import os
import threading
from uuid import UUID

from sentinel.adaptive.contracts import (
    Coverage, IdentityStatus, ProcessIdentity, Priority, Role, Validity,
)
from sentinel.adaptive.decision import Mode, PolicyProfile
from sentinel.adaptive.helper import Enrollment, ShadowHelper
from sentinel.adaptive.helper_host import JobHandleSource, MachineObservationSource
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive import identity as native_identity
from sentinel.adaptive import machine_sampler
from sentinel.adaptive import native_launcher
from sentinel.adaptive.native_job import NativeJob, JobAccess
from sentinel.adaptive.sampler import FrameSampler
from tests.windows.adaptive_cost_probe import CostProbe, _MemoryCountersEx, _psapi


_CASE_NAMES = ("membership_added", "membership_removed", "inaccessible_identity",
               "member_scan_timeout", "subtraction_zero_samples", "unsafe_subtractions")
_BREAKAWAY_FLAGS = 0x800 | 0x1000


class NativeOverheadError(RuntimeError):
    """A stable measurement refusal, never a numeric zero or gate success."""


def _platform():
    if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
        raise NativeOverheadError("overhead_native_windows_required")


def _kernel(backend):
    kernel = getattr(backend, "kernel", None)
    if not isinstance(kernel, C.WinDLL):
        raise NativeOverheadError("overhead_native_backend_required")
    return kernel


@dataclass(frozen=True)
class NativeProcessReading:
    identity: ProcessIdentity
    cpu_100ns: int
    private_bytes: int
    handles: int
    peak_private_bytes: int

    def __post_init__(self):
        if type(self.identity) is not ProcessIdentity or any(
                type(getattr(self, name)) is not int or getattr(self, name) < 0
                for name in ("cpu_100ns", "private_bytes", "handles", "peak_private_bytes")):
            raise NativeOverheadError("overhead_native_reading_invalid")
        if self.peak_private_bytes < self.private_bytes:
            raise NativeOverheadError("overhead_native_reading_invalid")


class NativeCostProbe(CostProbe):
    """Borrow original process owners; never invoke CostProbe's PID constructor.

    ``witnesses`` contains VerifiedProcess objects or pairs of an original
    CreatedProcess and its already verified complete ProcessIdentity. Reads hold
    each original owner's lock through full native identity/liveness checks and
    both measurements. A failure is sticky and retains its original exception,
    including uncertainty from transient token cleanup in the identity query.
    The caller continues to own every process handle and its cleanup obligations.
    """

    def __init__(self, witnesses):
        _platform()
        values = tuple(witnesses)
        if not 1 <= len(values) <= 52:
            raise NativeOverheadError("overhead_monitor_count_invalid")
        self._witnesses = []
        self._handles = {}  # Populated only while an original owner is locked.
        self._births = {}
        self._failure = None
        self._lock = threading.Lock()
        identities = set()
        for value in values:
            if type(value) is VerifiedProcess:
                owner, expected = value, value.identity
            elif (type(value) is tuple and len(value) == 2 and
                  type(value[0]) is native_launcher.CreatedProcess and type(value[1]) is ProcessIdentity):
                owner, expected = value
            else:
                raise NativeOverheadError("overhead_original_process_required")
            if type(expected) is not ProcessIdentity or expected in identities or any(
                    identity.pid == expected.pid for identity in identities):
                raise NativeOverheadError("overhead_monitor_identity_invalid")
            _kernel(owner._backend)
            identities.add(expected)
            self._witnesses.append((owner, expected))
        if len({identity.logon_id for identity in identities}) != 1:
            raise NativeOverheadError("overhead_monitor_logon_mismatch")
        self._identity_backend = native_identity._backend()
        self._query_kernel = _kernel(self._identity_backend)
        self._query_kernel.GetProcessHandleCount.argtypes = [C.c_void_p, C.POINTER(C.c_uint32)]
        self._query_kernel.GetProcessHandleCount.restype = C.c_int32
        if (C.sizeof(_MemoryCountersEx) != 80 or _MemoryCountersEx.PrivateUsage.offset != 72 or
                _MemoryCountersEx.PeakPagefileUsage.offset != 64):
            raise NativeOverheadError("overhead_process_memory_abi_invalid")
        self._last_peak_private_bytes = None
        self._native = True

    @property
    def native(self):
        return self._native

    @property
    def failure(self):
        return self._failure

    @staticmethod
    def _handle_locked(owner, expected):
        if type(owner) is VerifiedProcess:
            if owner.identity != expected or owner._close_outcome_unknown or owner._handle is None:
                raise NativeOverheadError("overhead_process_custody_unverified")
            return owner._handle
        if (owner._logon_id != expected.logon_id or owner.pid != expected.pid or owner._closed or
                owner._identity_cleanup):
            raise NativeOverheadError("overhead_process_custody_unverified")
        return owner._live_handle()

    def _verify(self, handle, expected):
        # Check object identity before waiting on a numeric handle. No PID is
        # opened, duplicated or substituted for this original process object.
        if self._identity_backend.identity(handle) != expected:
            raise NativeOverheadError("overhead_process_identity_changed")
        if self._identity_backend.wait(handle) is not IdentityStatus.ALIVE:
            raise NativeOverheadError("overhead_monitor_not_alive")

    def _private_commit(self, pid):
        # Both values come from one actual PROCESS_MEMORY_COUNTERS_EX query.
        # PeakPagefileUsage is the lifetime Commit Charge peak, not peak RSS:
        # https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex
        counters = _MemoryCountersEx()
        counters.cb = C.sizeof(counters)
        if not _psapi().GetProcessMemoryInfo(self._handles[pid], C.byref(counters), C.sizeof(counters)):
            raise NativeOverheadError("overhead_private_commit_unavailable")
        self._last_peak_private_bytes = int(counters.PeakPagefileUsage)
        return int(counters.PrivateUsage)

    def read(self):
        with self._lock:
            if self._failure is not None:
                raise NativeOverheadError("overhead_process_measurement_unresolved") from self._failure
            readings = []
            try:
                for owner, expected in self._witnesses:
                    # VerifiedProcess uses a non-reentrant lock: never call
                    # observe()/close() while this borrowed scope holds it.
                    with owner._lock:
                        handle = self._handle_locked(owner, expected)
                        self._verify(handle, expected)
                        self._handles[expected.pid] = handle
                        try:
                            birth, cpu = self._times(expected.pid)
                            private = self._private_commit(expected.pid)
                        finally:
                            self._handles.pop(expected.pid, None)
                        if birth != expected.created_filetime_100ns:
                            raise NativeOverheadError("overhead_process_identity_changed")
                        count = C.c_uint32()
                        if not self._query_kernel.GetProcessHandleCount(handle, C.byref(count)):
                            raise NativeOverheadError("overhead_handle_count_unavailable")
                        self._verify(handle, expected)
                        if self._handle_locked(owner, expected) != handle:
                            raise NativeOverheadError("overhead_process_custody_changed")
                        readings.append(NativeProcessReading(expected, cpu, private, int(count.value),
                                                             self._last_peak_private_bytes))
                return tuple(readings)
            except BaseException as error:
                self._failure = error
                raise

    def sample(self, interval_seconds):
        # The parent chooses and records its actual 100 ns interval. Inherited
        # CostProbe.sample would mix that domain with a sleeping seconds probe.
        raise NativeOverheadError("overhead_use_native_read_endpoints")

    def close(self):
        """No native ownership was transferred; never close a borrowed handle."""
        return None


class _SetAudit:
    """Observe the real backend DLL boundary and prohibit shadow mutation."""

    def __init__(self, kernel):
        self.kernel = kernel
        self.original = kernel.SetInformationJobObject
        if getattr(self.original, "_overhead_shadow_interposer", False):
            raise NativeOverheadError("overhead_shadow_audit_already_installed")
        self.calls = 0
        self.closed = False
        self.installed = False
        self.lock = threading.Lock()

        def deny(*args):
            with self.lock:
                self.calls += 1
            # Never forward: this borrowed backend belongs only to isolated,
            # query-only fixture Jobs. Shadow has no native Set authority.
            raise NativeOverheadError("overhead_shadow_native_set_attempted")

        deny._overhead_shadow_interposer = True
        self.interposer = deny

    def install(self):
        if self.kernel.SetInformationJobObject is not self.original:
            raise NativeOverheadError("overhead_shadow_audit_changed")
        self.kernel.SetInformationJobObject = self.interposer
        self.installed = True

    def verify(self):
        if not self.installed or self.closed or self.kernel.SetInformationJobObject is not self.interposer:
            raise NativeOverheadError("overhead_shadow_audit_changed")

    def close(self):
        if self.closed:
            return
        current = self.kernel.SetInformationJobObject
        if not self.installed and current is self.original:
            self.closed = True
            return
        # An interrupt may occur after attribute assignment but before the
        # installed flag. The retained original/interposer pair resolves it.
        if current is not self.interposer:
            raise NativeOverheadError("overhead_shadow_audit_changed")
        self.kernel.SetInformationJobObject = self.original
        self.closed = True


class ReadOnlyShadowSampler:
    """Native shadow sampling over up to fifty borrowed QUERY-only fixture Jobs.

    The >10-Job case is five (or more, for a smaller profile) separately bounded
    sampler shards with one actual machine snapshot per tick. It measures the
    read-only stress loop, not a fifty-Job production enrollment. This object
    creates no guardian, process, thread, memory attribution backend or control
    writer. Caller-supplied backends, clocks and claimed measurements are absent.
    """

    def __init__(self, profile, jobs):
        _platform()
        if type(profile) is not PolicyProfile or profile.mode is Mode.ENFORCE:
            raise NativeOverheadError("overhead_shadow_profile_required")
        self.profile = replace(profile, mode=Mode.SHADOW)
        self.jobs = tuple(jobs)
        if not 1 <= len(self.jobs) <= 50:
            raise NativeOverheadError("overhead_job_count_invalid")
        self._lock = threading.RLock()
        self._failure = None
        self._closed = False
        self._audits = []
        self._shards = []
        self._members = {}
        self._observation = None
        self._case_totals = {name: 0 for name in _CASE_NAMES}
        self._native = False
        self._warmup_pending = True
        self._last_tick_warmup = False
        self._clock_backend = machine_sampler._WindowsBackend()
        _kernel(self._clock_backend)
        self._topology = self._clock_backend.topology()
        if not 1 <= self._topology[0] <= 64 or self._topology[1] != 1:
            raise NativeOverheadError("overhead_native_topology_unsupported")
        self._clock = self._clock_backend.tick
        self._machine = machine_sampler.MachineSampler(backend=self._clock_backend)
        self._machine_source = MachineObservationSource(self._machine)
        seen_ids, seen_jobs, seen_names, logons, kernels = set(), set(), set(), set(), {}
        try:
            for item in self.jobs:
                if type(item) is not tuple or len(item) != 2:
                    raise NativeOverheadError("overhead_job_binding_invalid")
                execution_id, job = item
                try:
                    canonical = type(execution_id) is str and str(UUID(execution_id)) == execution_id
                except (TypeError, ValueError, AttributeError):
                    canonical = False
                if (not canonical or execution_id in seen_ids or type(job) is not NativeJob or
                        job.access is not JobAccess.QUERY or id(job) in seen_jobs or job.name in seen_names):
                    raise NativeOverheadError("overhead_query_job_required")
                seen_ids.add(execution_id)
                seen_jobs.add(id(job))
                seen_names.add(job.name)
                logons.add(job.logon_sid)
                kernel = _kernel(job._backend)
                kernels[id(kernel)] = kernel
            if len(logons) != 1:
                raise NativeOverheadError("overhead_job_logon_mismatch")
            for kernel in kernels.values():
                audit = _SetAudit(kernel)
                self._audits.append(audit)  # Retain before the installation cut.
                audit.install()
            size = min(10, self.profile.max_enrolled_jobs)
            for offset in range(0, len(self.jobs), size):
                source = JobHandleSource()
                sampler = FrameSampler(profile=self.profile, backend=source,
                    machine_source=lambda: self._observation, clock=self._clock)
                helper = ShadowHelper(profile=self.profile, sampler=sampler, clock=self._clock, shadow=True)
                for execution_id, job in self.jobs[offset:offset + size]:
                    with job._lock:
                        limits = job.query_limits()
                        control = job.query_cpu()
                        if control.flags & 1:
                            raise NativeOverheadError("overhead_shadow_job_capped")
                        provable = not limits.limit_flags & _BREAKAWAY_FLAGS
                        if not provable:
                            raise NativeOverheadError("overhead_shadow_membership_unverified")
                    source.add(execution_id, job, membership_provable=provable)
                    helper.enroll(Enrollment(execution_id, "p4-native-overhead", Role.BACKGROUND,
                        Priority.P2, Coverage.JOB_CONTAINED, capability_verified=False))
                self._shards.append((source, helper))
            self._native = True
        except BaseException as error:
            self._failure = error
            try:
                self.close()
            except BaseException:
                error._native_overhead_owner = self
                error.add_note("overhead_shadow_audit_cleanup_unverified")
            raise

    @property
    def native(self):
        return self._native

    @property
    def failure(self):
        return self._failure

    @property
    def logical_processors(self):
        return self._topology[0]

    @property
    def last_tick_warmup(self):
        """The single prime tick must be excluded from steady-state evidence."""
        return self._last_tick_warmup

    @property
    def native_set_calls(self):
        with self._lock:
            for audit in self._audits:
                if not self._closed:
                    audit.verify()
            return sum(audit.calls for audit in self._audits)

    @property
    def sampling_cases(self):
        return dict(self._case_totals)

    def tick(self):
        with self._lock:
            if self._closed or self._failure is not None:
                raise NativeOverheadError("overhead_shadow_measurement_unresolved")
            counts = {name: 0 for name in _CASE_NAMES}
            try:
                if self.native_set_calls:
                    raise NativeOverheadError("overhead_shadow_native_set_attempted")
                begin = self._clock()
                for execution_id, job in self.jobs:
                    with job._lock:
                        current = set(job.active_pids())
                        if job.query_cpu().flags & 1:
                            raise NativeOverheadError("overhead_shadow_job_capped")
                    previous = self._members.get(execution_id)
                    if previous is not None:
                        counts["membership_added"] += len(current - previous)
                        counts["membership_removed"] += len(previous - current)
                    self._members[execution_id] = current
                # One machine delta for the whole stress tick. Sampling it
                # once per shard would create invalid sub-millisecond windows.
                # Membership-audit cost remains in the enclosing bracket.
                self._observation = self._machine_source()
                observation = self._observation
                if observation.machine is None or (
                        observation.machine.logical_processors, observation.machine.processor_groups) != self._topology:
                    raise NativeOverheadError("overhead_machine_topology_unverified")
                warmup = (self._warmup_pending and observation.validity is Validity.UNKNOWN and
                    observation.window_start_tick_100ns is None and
                    observation.window_end_tick_100ns is not None and len(observation.errors) == 1 and
                    observation.errors[0].code == "sample_window_invalid" and
                    observation.errors[0].stage == "machine_warmup")
                if not warmup and (observation.validity is not Validity.VALID or observation.errors):
                    raise NativeOverheadError("overhead_machine_sample_unverified")
                for source, helper in self._shards:
                    before = helper.metrics.frames
                    helper.tick()
                    if source.unreadable():
                        raise NativeOverheadError("overhead_job_accounting_unverified")
                    frame = helper.latest_frame
                    if warmup:
                        if frame is not None or helper.metrics.frames != before:
                            raise NativeOverheadError("overhead_warmup_frame_unexpected")
                        continue
                    if frame is None or helper.metrics.frames == before:
                        raise NativeOverheadError("overhead_shadow_fresh_frame_missing")
                    if (frame.validity is not Validity.VALID or
                            len(frame.jobs) != len(source.enrolled) or
                            any(error.code != "memory_attribution_unavailable" for error in frame.errors) or
                            any(job.cpu_units is None or not job.membership_complete or
                                job.active_processes is None for job in frame.jobs)):
                        raise NativeOverheadError("overhead_shadow_frame_unverified")
                    for job in frame.jobs:
                        unknown = (job.memory_validity is not Validity.VALID or
                            job.private_working_set_bytes is None or job.private_commit_bytes is None)
                        if unknown:
                            counts["subtraction_zero_samples"] += 1
                            if (job.private_working_set_bytes is not None or
                                    job.private_commit_bytes is not None):
                                counts["unsafe_subtractions"] += 1
                end = self._clock()
                if end <= begin:
                    raise NativeOverheadError("overhead_native_clock_invalid")
                if self.native_set_calls:
                    raise NativeOverheadError("overhead_shadow_native_set_attempted")
                for name in counts:
                    self._case_totals[name] += counts[name]
                self._warmup_pending = False
                self._last_tick_warmup = warmup
                return begin, end, counts
            except BaseException as error:
                self._failure = error
                raise

    def close(self):
        """Restore only our exact Python interposers; borrowed Jobs stay owned."""
        with self._lock:
            if self._closed:
                return
            errors = []
            for audit in reversed(self._audits):
                try:
                    audit.close()
                except BaseException as error:
                    errors.append(error)
            if errors:
                self._failure = errors[0]
                errors[0]._native_overhead_owner = self
                raise errors[0]
            self._closed = True
