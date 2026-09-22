"""Native query sources for the isolated P4 observer-cost runner.

No admission, process creation, PID reopening, Job control or native close is
performed here. Every process/Job handle is borrowed from its original owner.
Fifty Jobs are a read-only stress workload, split into production-sized sampler
shards; this does not enroll fifty Jobs into a production guardian.

The producer measures the initialized OperationalHelperHost, including its
registry refresh, operator poll and report serialization/write/flush. Additional
query-only shards share that host's actual machine sample and one scan budget.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import os
from pathlib import Path
import stat
import sys
import threading
import time
from uuid import UUID

from sentinel.adaptive.contracts import (
    Coverage, IdentityStatus, ProcessIdentity, Priority, Role, Validity,
)
from sentinel.adaptive.decision import Mode, PolicyProfile
from sentinel.adaptive.helper import Enrollment, ShadowHelper
from sentinel.adaptive.helper_host import HelperHost, JobHandleSource, MachineObservationSource
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
        if not 1 <= len(values) <= 55:
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


class _OriginalBinding:
    """Restore only a retained original binding; never overwrite another owner."""
    def __init__(self, owner, name, replacement):
        self.owner, self.name = owner, name
        self.original, self.replacement = getattr(owner, name), replacement
        self.closed = False

    def install(self):
        if not self._same(getattr(self.owner, self.name), self.original):
            raise NativeOverheadError("overhead_host_binding_changed")
        setattr(self.owner, self.name, self.replacement)

    def verify(self):
        if self.closed or getattr(self.owner, self.name) is not self.replacement:
            raise NativeOverheadError("overhead_host_binding_changed")

    def close(self):
        if self.closed:
            return
        current = getattr(self.owner, self.name)
        if self._same(current, self.original):
            self.closed = True
            return
        if current is not self.replacement:
            raise NativeOverheadError("overhead_host_binding_changed")
        setattr(self.owner, self.name, self.original)
        self.closed = True

    @staticmethod
    def _same(left, right):
        return left is right or (getattr(left, "__self__", None) is not None
            and getattr(left, "__func__", None) is not None
            and getattr(left, "__self__", None) is getattr(right, "__self__", None)
            and getattr(left, "__func__", None) is getattr(right, "__func__", None))


class NativeHelperHostSampler:
    """Measure one original operational shadow host, not a replacement core.

    The aggregate provider owns startup, listeners, the original host and its
    query Jobs. This adapter owns only transparent observation taps, exact
    sleep deferral, Set interposers and extra query-only memory scanner caches.
    Its original host remains resident until provider-managed drain/cleanup.
    """
    def __init__(self, profile, jobs, *, host, report_stream, log_directory):
        from sentinel.adaptive.helper_control_host import OperationalHelperHost
        from sentinel.adaptive.member_memory import NativeMemberMemoryScanner
        from sentinel.adaptive.pipe_windows import NativePipeListener, NativePipeRegistry
        _platform()
        self.host, self.profile, self.jobs = host, profile, tuple(jobs)
        self._failure = None
        self._closed = False
        self._bindings, self._audits, self._shards = [], [], []
        self._members, self._observation, self._budget = {}, None, None
        self._machine_calls = self._poll_calls = self._sleep_calls = 0
        self._pending_tick = None
        self._last_tick_warmup = False
        self._warmup_pending = True
        self._case_totals = dict.fromkeys(_CASE_NAMES, 0)
        self._lock = threading.RLock()
        self._report_stream = report_stream
        self._native = False
        if (type(host) is not OperationalHelperHost or type(profile) is not PolicyProfile
                or profile.mode is not Mode.SHADOW or host.profile != profile
                or not host._started or not host.registered or not host._operator_ready
                or host._drain_requested or host._cleanup_started or host._closed
                or host._sleep is not time.sleep or not 1 <= len(self.jobs) <= 50
                or type(host.process) is not VerifiedProcess or host.process.identity.pid != os.getpid()
                or type(host.parent_process) is not VerifiedProcess
                or type(host.operator_listener) is not NativePipeListener
                or type(host._pipe_registry) is not NativePipeRegistry):
            raise NativeOverheadError("overhead_actual_operational_host_required")
        if (type(host._machine_source) is not MachineObservationSource
                or type(host.sampler) is not FrameSampler or type(host.shadow) is not ShadowHelper
                or host.shadow._sampler is not host.sampler
                or host.sampler._jobs._backend is not host.jobs
                or getattr(host.run_once, "__func__", None) is not OperationalHelperHost.run_once
                or getattr(host._report, "__func__", None) is not HelperHost._report
                or getattr(host._pace, "__func__", None) is not HelperHost._pace
                or getattr(host._operator_poll, "__func__", None) is not OperationalHelperHost._operator_poll
                or getattr(host.refresh_enrollment, "__func__", None) is not OperationalHelperHost.refresh_enrollment
                or host.sampler._machine_source is not host._machine_source
                or type(host.jobs) is not JobHandleSource
                or type(host.jobs.memory_scanner) is not NativeMemberMemoryScanner
                or host.jobs.memory_budget_source is not None
                or host.jobs.memory_scanner._backend is not None
                or host.jobs.memory_scanner.cached_members or host.jobs.retained_uncertain
                or not _OriginalBinding._same(host.jobs.memory_scanner._opener, VerifiedProcess._open)
                or not _OriginalBinding._same(host.jobs.memory_scanner._clock, host._clock)
                or host._opener is not host._open_job):
            # Require fresh native startup. An arbitrary pre-supplied backend,
            # source or warm scanner cache is not evidence provenance.
            raise NativeOverheadError("overhead_native_host_sources_required")
        machine = host._machine_source._sampler
        backend = machine._backend
        if (type(machine) is not machine_sampler.MachineSampler
                or type(backend) is not machine_sampler._WindowsBackend
                or getattr(host._clock, "__self__", None) is not backend
                or getattr(host._clock, "__func__", None) is not machine_sampler._WindowsBackend.tick):
            raise NativeOverheadError("overhead_native_host_clock_required")
        _kernel(backend)
        self._clock, self._topology = host._clock, backend.topology()
        if not 1 <= self._topology[0] <= 64 or self._topology[1] != 1:
            raise NativeOverheadError("overhead_native_topology_unsupported")
        if (profile.sample_interval_ms != 1000 or profile.max_enrolled_jobs != 10
                or type(host.enroll_every_ticks) is not int or host.enroll_every_ticks <= 0
                or type(host.report_every_ticks) is not int or host.report_every_ticks <= 0):
            raise NativeOverheadError("overhead_host_cadence_invalid")
        logs = Path(log_directory).resolve(strict=True)
        stream_path = Path(getattr(report_stream, "name", "")).resolve(strict=True)
        if (report_stream is not sys.stderr or stream_path == logs or logs not in stream_path.parents
                or not report_stream.writable() or getattr(report_stream, "encoding", "").lower().replace("-", "") != "utf8"
                or not stat.S_ISREG(os.fstat(report_stream.fileno()).st_mode)):
            raise NativeOverheadError("overhead_original_report_stream_required")
        self._report_file = os.fstat(report_stream.fileno())
        self._managed = tuple(host.jobs.enrolled)
        items = dict(self.jobs)
        if (len(items) != len(self.jobs) or len(self._managed) != min(len(items), 10)
                or not set(self._managed) <= set(items)):
            raise NativeOverheadError("overhead_managed_scope_invalid")
        self._query_only = tuple(key for key in items if key not in self._managed)
        seen_names, kernels = set(), {}
        try:
            for execution_id, job in self.jobs:
                if (type(execution_id) is not str or str(UUID(execution_id)) != execution_id
                        or type(job) is not NativeJob or job.access is not JobAccess.QUERY
                        or job.name in seen_names or job.logon_sid != host.process.identity.logon_id):
                    raise NativeOverheadError("overhead_query_job_required")
                seen_names.add(job.name)
                kernels[id(_kernel(job._backend))] = _kernel(job._backend)
                with job._lock:
                    if job.query_cpu().flags != 0 or job.query_limits().limit_flags & _BREAKAWAY_FLAGS:
                        raise NativeOverheadError("overhead_shadow_membership_unverified")
            for execution_id, entry in host.jobs._entries.items():
                if entry.job.name != items[execution_id].name or entry.job.access is not JobAccess.QUERY:
                    raise NativeOverheadError("overhead_host_query_binding_invalid")
                kernels[id(_kernel(entry.job._backend))] = _kernel(entry.job._backend)
            for kernel in kernels.values():
                audit = _SetAudit(kernel)
                self._audits.append(audit)
                audit.install()
            self._install_taps()
            for offset in range(0, len(self._query_only), 10):
                source = JobHandleSource()
                scanner = NativeMemberMemoryScanner(clock=self._clock)
                source.configure_memory(scanner, self._budget_source)
                sampler = FrameSampler(profile=profile, backend=source,
                    machine_source=lambda: self._observation, clock=self._clock)
                helper = ShadowHelper(profile=profile, sampler=sampler, clock=self._clock)
                self._shards.append((source, helper, scanner))
                for key in self._query_only[offset:offset + 10]:
                    source.add(key, items[key], membership_provable=True)
                    helper.enroll(Enrollment(key, "p4-query-only-stress", Role.BACKGROUND,
                        Priority.P2, Coverage.JOB_CONTAINED, capability_verified=False))
            self._native = True
        except BaseException as error:
            self._failure = error
            try:
                self.close()
            except BaseException as cleanup:
                error._native_overhead_owner = self
                error.overhead_cleanup = cleanup
            raise

    def _bind(self, owner, name, replacement):
        binding = _OriginalBinding(owner, name, replacement)
        self._bindings.append(binding)  # Retain before the assignment cut.
        binding.install()

    def _install_taps(self):
        self._original_sleep = self.host._sleep
        machine_source = self.host.sampler._machine_source
        poll = self.host._operator_poll

        def machine():
            self._machine_calls += 1
            self._observation = machine_source()
            return self._observation  # Exact original observation, unchanged.

        def operator_poll():
            value = poll()
            self._poll_calls += 1
            return value

        def defer_sleep(seconds):
            if type(seconds) not in (int, float) or not 0 <= seconds <= 1.0:
                raise NativeOverheadError("overhead_host_sleep_invalid")
            self._sleep_calls += 1

        self._bind(self.host, "_sleep", defer_sleep)
        self._bind(self.host.sampler, "_machine_source", machine)
        self._bind(self.host, "_operator_poll", operator_poll)
        self._original_budget_source = self.host.jobs.memory_budget_source
        self._installed_budget_source = self._budget_source
        self.host.jobs.configure_memory(self.host.jobs.memory_scanner, self._installed_budget_source)

    def _budget_source(self):
        return self._budget

    @property
    def native(self):
        return self._native

    @property
    def logical_processors(self):
        return self._topology[0]

    @property
    def last_tick_warmup(self):
        return self._last_tick_warmup

    @property
    def native_set_calls(self):
        for audit in self._audits:
            if not self._closed:
                audit.verify()
        return sum(audit.calls for audit in self._audits)

    def host_record(self, scope_nonce, started_iteration, ticks):
        return dict(identity=self.host.process.identity.to_dict(),
            parent_identity=self.host.parent_identity.to_dict(), instance_id=self.host.instance_id,
            operator_instance_id=self.host.operator_instance_id, scope_nonce=scope_nonce,
            config_revision=self.host.sampler.config_revision, managed_execution_ids=list(self._managed),
            query_only_execution_ids=list(self._query_only), enroll_every_ticks=self.host.enroll_every_ticks,
            report_every_ticks=self.host.report_every_ticks, started_iteration=started_iteration,
            ended_iteration=self.host._iterations, ticks=ticks)

    def _verify_host(self):
        for binding in self._bindings:
            binding.verify()
        if (self.host.jobs.memory_budget_source is not self._installed_budget_source
                or not self.host._operator_ready or self.host._drain_requested
                or self.host._operator_error is not None or self.host._cleanup_started
                or self.host.jobs.enrolled != self._managed or self.host.jobs.retained_uncertain
                or self.host.jobs.unreadable()):
            raise NativeOverheadError("overhead_host_custody_changed")
        audited = {id(audit.kernel) for audit in self._audits}
        if any(id(_kernel(entry.job._backend)) not in audited for entry in self.host.jobs._entries.values()):
            raise NativeOverheadError("overhead_host_query_audit_missing")
        if self.native_set_calls:
            raise NativeOverheadError("overhead_shadow_native_set_attempted")

    def _report_size(self):
        if sys.stderr is not self._report_stream:
            raise NativeOverheadError("overhead_report_stream_changed")
        current = os.fstat(self._report_stream.fileno())
        if (current.st_dev, current.st_ino) != (self._report_file.st_dev, self._report_file.st_ino):
            raise NativeOverheadError("overhead_report_file_changed")
        return current.st_size

    def _frame_cases(self, source, helper, before, warmup, begin, counts):
        frame = helper.latest_frame
        if warmup:
            if frame is not None or helper.metrics.frames != before:
                raise NativeOverheadError("overhead_warmup_frame_unexpected")
            return
        if (frame is None or helper.metrics.frames != before + 1 or source.unreadable()
                or len(frame.jobs) != len(source.enrolled)
                or any(error.code not in {"memory_attribution_unavailable", "observer_budget_exceeded"}
                       for error in frame.errors)
                or any(row.cpu_units is None or not row.membership_complete for row in frame.jobs)):
            raise NativeOverheadError("overhead_shadow_fresh_frame_missing")
        results = {item.execution_id: item for item in source.last_memory_scan}
        if (set(results) != set(source.enrolled) or source.memory_sample_started_tick < begin
                or source.memory_sample_started_tick > self._clock()):
            raise NativeOverheadError("overhead_memory_scan_frame_unverified")
        for row in frame.jobs:
            result = results[row.execution_id]
            total, active = result.total_processes, result.active_processes
            if type(total) is int and type(active) is int and 0 <= active <= total:
                previous = self._members.get(row.execution_id)
                if previous is not None:
                    added = total - previous[0]
                    removed = previous[1] + added - active
                    if added < 0 or removed < 0:
                        raise NativeOverheadError("overhead_membership_counter_reversed")
                    counts["membership_added"] += added
                    counts["membership_removed"] += removed
                self._members[row.execution_id] = (total, active)
            if result.reason in ("inaccessible_identity", "member_scan_timeout"):
                counts[result.reason] += 1
            unknown = (row.memory_validity is not Validity.VALID or
                row.private_working_set_bytes is None or row.private_commit_bytes is None)
            if unknown:
                counts["subtraction_zero_samples"] += 1
                if row.private_working_set_bytes is not None or row.private_commit_bytes is not None:
                    counts["unsafe_subtractions"] += 1
            if result.reason != "ok" and not unknown:
                counts["unsafe_subtractions"] += 1

    def tick(self):
        from sentinel.adaptive.member_memory import NativeScanBudget
        with self._lock:
            if self._closed or self._failure is not None or self._pending_tick is not None:
                raise NativeOverheadError("overhead_host_measurement_unresolved")
            try:
                self._verify_host()
                begin = self._clock()
                self._budget = NativeScanBudget(begin, max_members=256, budget_ms=100)
                counts = dict.fromkeys(_CASE_NAMES, 0)
                self._machine_calls = self._poll_calls = self._sleep_calls = 0
                self._observation = None
                for key, job in self.jobs:
                    with job._lock:
                        if job.query_cpu().flags != 0:
                            raise NativeOverheadError("overhead_shadow_job_capped")
                iteration = self.host._iterations
                before = self.host.shadow.metrics.frames
                report_before = self._report_size()
                outcome = self.host.run_once()
                self.host._report()
                report_bytes = self._report_size() - report_before
                reported = int(self.host._iterations % self.host.report_every_ticks == 0)
                if (self.host._iterations != iteration + 1 or self._machine_calls != 1
                        or self._poll_calls != 1 or self._sleep_calls != 1
                        or bool(reported) != bool(report_bytes > 0) or report_bytes < 0
                        or outcome.released or (outcome.refreshed and not self.host._last_enrollment_complete)):
                    raise NativeOverheadError("overhead_host_iteration_incomplete")
                observation = self._observation
                if observation.machine is None or (
                        observation.machine.logical_processors, observation.machine.processor_groups) != self._topology:
                    raise NativeOverheadError("overhead_machine_topology_unverified")
                warmup = (self._warmup_pending and observation.validity is Validity.UNKNOWN
                    and observation.window_start_tick_100ns is None
                    and observation.window_end_tick_100ns is not None and len(observation.errors) == 1
                    and observation.errors[0].code == "sample_window_invalid"
                    and observation.errors[0].stage == "machine_warmup")
                if not warmup and (observation.validity is not Validity.VALID or observation.errors):
                    raise NativeOverheadError("overhead_machine_sample_unverified")
                self._frame_cases(self.host.jobs, self.host.shadow, before, warmup, begin, counts)
                for source, helper, scanner in self._shards:
                    before = helper.metrics.frames
                    helper.tick()
                    self._frame_cases(source, helper, before, warmup, begin, counts)
                    if scanner.retained_uncertain:
                        raise NativeOverheadError("overhead_member_cleanup_unverified")
                if self._budget.invalid_execution_ids:
                    # Later shard overlap invalidates earlier deductions too.
                    # Do not reinterpret that earlier frame as safe zero.
                    raise NativeOverheadError("overhead_cross_shard_membership_overlap")
                self._verify_host()
                end = self._clock()
                if end <= begin:
                    raise NativeOverheadError("overhead_native_clock_invalid")
                self._pending_tick = [self.host._iterations, int(outcome.refreshed), reported,
                    self._poll_calls, report_bytes, self.host._deadline_100ns, None, None,
                    self.host._skipped_boundaries, None]
                self._warmup_pending = False
                self._last_tick_warmup = warmup
                for name in counts:
                    self._case_totals[name] += counts[name]
                return begin, end, counts
            except BaseException as error:
                self._failure = error
                raise

    def pace(self, assert_covered):
        """Wait to the original host's deadline, outside the measured bracket."""
        with self._lock:
            if self._closed or self._failure is not None or self._pending_tick is None:
                raise NativeOverheadError("overhead_host_pacing_unresolved")
            try:
                assert_covered()
                self._verify_host()
                row = self._pending_tick
                row[6] = self._clock()
                row[9] = max(0, row[6] - row[5])
                if row[6] < row[5]:
                    self._original_sleep((row[5] - row[6]) / 10_000_000)
                row[7] = self._clock()
                if row[7] < max(row[5], row[6]):
                    raise NativeOverheadError("overhead_actual_wait_incomplete")
                assert_covered()
                self._pending_tick = None
                return row
            except BaseException as error:
                self._failure = error
                raise

    def close(self):
        """Restore exact taps, close extra scanner caches, retain every doubt."""
        with self._lock:
            if self._closed:
                return
            errors = []
            for source, helper, scanner in reversed(self._shards):
                try:
                    scanner.close()
                except BaseException as error:
                    errors.append(error)
            for binding in reversed(self._bindings):
                try:
                    binding.close()
                except BaseException as error:
                    errors.append(error)
            if hasattr(self, "_installed_budget_source"):
                try:
                    source = self.host.jobs
                    if source.memory_budget_source is not self._installed_budget_source:
                        raise NativeOverheadError("overhead_memory_budget_binding_changed")
                    source.configure_memory(source.memory_scanner, self._original_budget_source)
                    del self._installed_budget_source
                except BaseException as error:
                    errors.append(error)
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
