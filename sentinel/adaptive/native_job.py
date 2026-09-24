"""Native named Job mechanism with explicit rights and retained cleanup custody.

This module is not admission, enrollment, recovery or actuator authority. The
caller must hold POLICY then the per-Job mutex, persist its launch/control intent,
validate the registered immutable name/nonce and resolve conflicts before writes.
Names and the logon-SID ACL provide same-user governance, not a security sandbox.
No import performs native work. No CLI, test opt-in or host gate lives here.

Creation refuses collisions and verifies a disabled/zero-limit baseline without
writing it. Returned handles are non-inheritable and limited to the requested
role; the temporary ALL_ACCESS creation handle is closed before success. Only
CPU hard-cap/disable writes exist. Close neither restores limits nor proves exit.
Unknown allocation/close outcomes retain custody and cannot be retried blindly.

Security readback reuses windows.py's strict owner/protected single-logon-ACE
validator. Its internal token/readback-buffer cleanup fails closed but does not
retain every dependency allocation; this extraction does not repair that helper.

Native contracts:
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-createjobobjectw
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-openjobobjectw
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_cpu_rate_control_information
https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
from enum import Enum
import os
import re
import threading
from uuid import UUID

from . import windows as _security


_DWORD, _BOOL, _HANDLE = C.c_uint32, C.c_int32, C.c_void_p
# The current Windows SDK includes JOB_OBJECT_IMPERSONATE in ALL_ACCESS.
# This is the descriptor mask, never the final handle's requested access.
_DACL_ACCESS = 0x001F003F
ENABLE, HARD_CAP = 1, 4
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_NAME = re.compile(r"Local\\ResourceSentinel\.Job\.([0-9a-f-]{36})\.([0-9a-f]{32})\Z")
_LOGON = re.compile(r"S-1-5-5-([0-9]{1,10})-([0-9]{1,10})\Z")


class JobAccess(Enum):
    QUERY = 0x00020004
    LAUNCH = 0x00020005
    CONTROL = 0x00020006
    OWNER = 0x00020007


class NativeJobError(RuntimeError):
    def __init__(self, reason, win32_error=None):
        self.reason, self.win32_error = reason, win32_error
        super().__init__(reason)


@dataclass(frozen=True)
class CpuState:
    # Preserve unknown flags/union values: query is observation, not authority.
    flags: int
    rate_bp: int


@dataclass(frozen=True)
class JobLimits:
    limit_flags: int
    ui_restrictions: int


@dataclass(frozen=True)
class JobAccounting:
    user_100ns: int
    kernel_100ns: int
    active_processes: int
    total_processes: int
    total_terminated_processes: int

    @property
    def cpu_100ns(self) -> int:
        return self.user_100ns + self.kernel_100ns


class _SecurityAttributes(C.Structure):
    _fields_ = [("length", _DWORD), ("descriptor", C.c_void_p), ("inherit", _BOOL)]


class _CpuInfo(C.Structure):
    _fields_ = [("ControlFlags", _DWORD), ("CpuRate", _DWORD)]


class _BasicAccounting(C.Structure):
    _fields_ = [("TotalUserTime", C.c_int64), ("TotalKernelTime", C.c_int64),
                ("ThisPeriodTotalUserTime", C.c_int64),
                ("ThisPeriodTotalKernelTime", C.c_int64),
                ("TotalPageFaultCount", _DWORD), ("TotalProcesses", _DWORD),
                ("ActiveProcesses", _DWORD), ("TotalTerminatedProcesses", _DWORD)]


class _BasicLimits(C.Structure):
    _fields_ = [("PerProcessUserTimeLimit", C.c_int64),
                ("PerJobUserTimeLimit", C.c_int64), ("LimitFlags", _DWORD),
                ("MinimumWorkingSetSize", C.c_size_t),
                ("MaximumWorkingSetSize", C.c_size_t),
                ("ActiveProcessLimit", _DWORD), ("Affinity", C.c_size_t),
                ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD)]


class _IoCounters(C.Structure):
    _fields_ = [(key, C.c_uint64) for key in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(C.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", C.c_size_t), ("JobMemoryLimit", C.c_size_t),
                ("PeakProcessMemoryUsed", C.c_size_t), ("PeakJobMemoryUsed", C.c_size_t)]


def _validate(name, nonce, logon_id, access):
    if type(nonce) is not str or _NONCE.fullmatch(nonce) is None:
        raise ValueError("native_job_nonce_invalid")
    if type(name) is not str:
        raise ValueError("native_job_name_invalid")
    if name != "Local\\ResourceSentinel.Test.Job." + nonce:
        match = _NAME.fullmatch(name)
        if match is None or match[2] != nonce:
            raise ValueError("native_job_name_invalid")
        try:
            execution = UUID(match[1])
        except ValueError:
            raise ValueError("native_job_name_invalid") from None
        if execution.int == 0 or str(execution) != match[1]:
            raise ValueError("native_job_name_invalid")
    match = _LOGON.fullmatch(logon_id) if type(logon_id) is str else None
    if match is None or any(int(part) > 0xFFFFFFFF for part in match.groups()):
        raise ValueError("native_job_logon_invalid")
    if type(access) is not JobAccess:
        raise ValueError("native_job_access_invalid")


def _check(result, reason):
    if not result:
        raise NativeJobError(reason, C.get_last_error())


def _valid_handle(value):
    if isinstance(value, C.c_void_p):
        value = value.value
    if type(value) is not int or not 0 < value < 1 << (C.sizeof(C.c_void_p) * 8 - 1):
        raise NativeJobError("native_job_handle_invalid")
    return value


def _security_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _security.NativePolicyMutexError as error:
        failure = NativeJobError("native_job_security_unavailable", error.win32_error)
        for note in getattr(error, "__notes__", ()):
            failure.add_note(note)
        raise failure from None


class _WindowsBackend:
    """Real WinDLL by default; explicit API objects are a portable fixture seam."""
    def __init__(self, *, kernel=None, advapi=None, security=None):
        if kernel is not None:
            if advapi is None or security is None:
                raise ValueError("native_job_fixture_apis_required")
            self.kernel, self.advapi, self.security = kernel, advapi, security
            return
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise NativeJobError("native_job_platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        self.advapi = a = C.WinDLL("advapi32", use_last_error=True)
        self.security = _security_call(_security._backend)
        bind, ptr = _security._bind, C.c_void_p
        bind(k, "CreateJobObjectW", _HANDLE, C.POINTER(_SecurityAttributes), C.c_wchar_p)
        bind(k, "OpenJobObjectW", _HANDLE, _DWORD, _BOOL, C.c_wchar_p)
        bind(k, "GetCurrentProcess", _HANDLE)
        bind(k, "DuplicateHandle", _BOOL, _HANDLE, _HANDLE, _HANDLE,
             C.POINTER(_HANDLE), _DWORD, _BOOL, _DWORD)
        bind(k, "GetHandleInformation", _BOOL, _HANDLE, C.POINTER(_DWORD))
        bind(k, "CloseHandle", _BOOL, _HANDLE)
        bind(k, "LocalFree", ptr, ptr)
        bind(k, "QueryInformationJobObject", _BOOL, _HANDLE, C.c_int32, ptr,
             _DWORD, C.POINTER(_DWORD))
        bind(k, "SetInformationJobObject", _BOOL, _HANDLE, C.c_int32, ptr, _DWORD)
        bind(a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", _BOOL,
             C.c_wchar_p, _DWORD, C.POINTER(ptr), C.POINTER(_DWORD))

    def close(self, handle):
        try:
            result = self.kernel.CloseHandle(handle)
        except BaseException as error:
            error._native_close_outcome_unknown = True
            raise
        if not result:
            error = NativeJobError("native_job_handle_close_failed", C.get_last_error())
            error._known_native_close_failed = True
            raise error

    def free(self, pointer):
        try:
            result = self.kernel.LocalFree(pointer)
        except BaseException as error:
            error._native_close_outcome_unknown = True
            raise
        if result:
            error = NativeJobError("native_job_descriptor_free_failed", C.get_last_error())
            error._known_native_close_failed = True
            raise error


@dataclass
class _Resource:
    kind: str
    value: object = None
    state: str = "absent"


def _retain(error, owner):
    owners = getattr(error, "_native_job_cleanup", ())
    if not any(item is owner for item in owners):
        error._native_job_cleanup = (*owners, owner)


def retry_job_cleanup(error) -> None:
    """Only cleanup known-owned resources; never reopen, recreate or repeat Set."""
    for owner in getattr(error, "_native_job_cleanup", ()):
        owner.close()
    error._native_job_cleanup = ()


class NativeJob:
    """Own a non-inheritable Job handle; queries use that exact retained handle.

    Keep any exception carrying ``_native_job_cleanup`` until cleanup is known.
    Native Set success alone is not APPLIED. A failed/uncertain Set or readback
    retains the same owner without automatic close, retry, restore or reopening.
    Callers retain durable intent and independently authorize each recovery write.
    """
    def __init__(self, name, nonce, logon_id, access, backend):
        self.name, self.nonce, self.logon_sid, self.access = name, nonce, logon_id, access
        self._backend, self._lock = backend, threading.RLock()
        self._ready = False
        self._job = _Resource("handle")
        self._creation = _Resource("handle")
        self._descriptor = _Resource("descriptor")
        self._resources = (self._descriptor, self._creation, self._job)
        self._uncertain_outputs = []

    @classmethod
    def create(cls, name: str, nonce: str, logon_id: str, *,
               access: JobAccess = JobAccess.LAUNCH, backend=None) -> NativeJob:
        _validate(name, nonce, logon_id, access)
        owner = cls(name, nonce, logon_id, access, backend or _WindowsBackend())
        try:
            owner._create()
            return owner
        except BaseException as primary:
            owner._failed_initialization(primary)
            raise

    @classmethod
    def open(cls, name: str, nonce: str, logon_id: str, *,
             access: JobAccess = JobAccess.QUERY, backend=None) -> NativeJob:
        _validate(name, nonce, logon_id, access)
        owner = cls(name, nonce, logon_id, access, backend or _WindowsBackend())
        try:
            owner._job.state = "allocation_unknown"
            owner._job.value = owner._backend.kernel.OpenJobObjectW(access.value, False, name)
            if not owner._job.value:
                owner._job.state = "absent"
                _check(False, "native_job_open_failed")
            owner._job.value = _valid_handle(owner._job.value)
            owner._job.state = "owned"
            owner._verify(owner._job.value)
            owner._ready = True
            return owner
        except BaseException as primary:
            owner._failed_initialization(primary)
            raise

    def _create(self):
        k, a = self._backend.kernel, self._backend.advapi
        owner_sid = _security_call(self._backend.security.current_owner_sid)
        # The helper validates real owner SIDs; injected fixtures must do so too.
        if type(owner_sid) is not str or _security._SID_TEXT.fullmatch(owner_sid) is None:
            raise NativeJobError("native_job_owner_sid_invalid")
        descriptor = C.c_void_p()
        self._uncertain_outputs.append(descriptor)
        self._descriptor.state = "allocation_unknown"
        ok = a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"O:{owner_sid}D:P(A;;0x001f003f;;;{self.logon_sid})", 1, C.byref(descriptor), None)
        if not ok:
            self._descriptor.state = "absent"
            self._uncertain_outputs.remove(descriptor)
            _check(False, "native_job_descriptor_create_failed")
        self._descriptor.value = _valid_handle(descriptor.value)
        self._descriptor.state = "owned"
        self._uncertain_outputs.remove(descriptor)
        attributes = _SecurityAttributes(C.sizeof(_SecurityAttributes), descriptor.value, False)
        C.set_last_error(0)
        self._creation.state = "allocation_unknown"
        self._creation.value = k.CreateJobObjectW(C.byref(attributes), self.name)
        error = C.get_last_error()
        if not self._creation.value:
            self._creation.state = "absent"
            raise NativeJobError("native_job_create_failed", error)
        self._creation.value = _valid_handle(self._creation.value)
        self._creation.state = "owned"
        if error == 183:
            # Collision never becomes authority to query or write this object.
            raise NativeJobError("native_job_name_collision", error)
        self._verify(self._creation.value, owner_sid=owner_sid)
        limits = self._limits(self._creation.value)
        cpu = self._cpu(self._creation.value)
        if limits != JobLimits(0, 0) or cpu.flags != 0:
            raise NativeJobError("native_job_new_baseline_invalid")
        duplicate = _HANDLE()
        self._uncertain_outputs.append(duplicate)
        self._job.state = "allocation_unknown"
        current = k.GetCurrentProcess()
        ok = k.DuplicateHandle(current, self._creation.value, current,
                               C.byref(duplicate), self.access.value, False, 0)
        if not ok:
            # A failed BOOL supplies no ownership guarantee for its output.
            self._job.state = "absent"
            self._uncertain_outputs.remove(duplicate)
            _check(False, "native_job_duplicate_failed")
        self._job.value = _valid_handle(duplicate.value)
        self._job.state = "owned"
        self._uncertain_outputs.remove(duplicate)
        self._verify(self._job.value, owner_sid=owner_sid)
        self._release(self._creation)
        self._release(self._descriptor)
        self._ready = True

    def _verify(self, handle, *, owner_sid=None):
        if owner_sid is None:
            owner_sid = _security_call(self._backend.security.current_owner_sid)
        _security_call(self._backend.security.verify_security, handle,
                       self.logon_sid, owner_sid, access_mask=_DACL_ACCESS)
        flags = _DWORD()
        _check(self._backend.kernel.GetHandleInformation(handle, C.byref(flags)),
               "native_job_handle_information_failed")
        if flags.value & 1:
            raise NativeJobError("native_job_handle_inheritable")

    @property
    def handle(self) -> int:
        with self._lock:
            if not self._ready or self._job.state != "owned":
                raise NativeJobError("native_job_handle_unavailable")
            return self._job.value

    @property
    def closed(self) -> bool:
        """Only handle/buffer cleanup completion, never workload termination."""
        with self._lock:
            return not self._ready and all(resource.state in ("absent", "closed")
                                           for resource in self._resources)

    def _query(self, handle, information_class, result):
        _check(self._backend.kernel.QueryInformationJobObject(handle, information_class,
               C.byref(result), C.sizeof(result), None), "native_job_query_failed")
        return result

    def _cpu(self, handle):
        info = self._query(handle, 15, _CpuInfo())
        return CpuState(int(info.ControlFlags), int(info.CpuRate))

    def _limits(self, handle):
        info = self._query(handle, 9, _ExtendedLimits())
        ui = self._query(handle, 4, _DWORD())
        return JobLimits(int(info.BasicLimitInformation.LimitFlags), int(ui.value))

    def query_cpu(self) -> CpuState:
        with self._lock:
            return self._cpu(self.handle)

    def query_limits(self) -> JobLimits:
        with self._lock:
            return self._limits(self.handle)

    def accounting(self) -> JobAccounting:
        with self._lock:
            info = self._query(self.handle, 1, _BasicAccounting())
            if min(info.TotalUserTime, info.TotalKernelTime,
                   info.ThisPeriodTotalUserTime, info.ThisPeriodTotalKernelTime) < 0:
                raise NativeJobError("native_job_accounting_invalid")
            return JobAccounting(int(info.TotalUserTime), int(info.TotalKernelTime),
                                 int(info.ActiveProcesses), int(info.TotalProcesses),
                                 int(info.TotalTerminatedProcesses))

    def active_pids(self) -> tuple[int, ...]:
        """A bounded snapshot, never a lifecycle seal or proof of future emptiness."""
        with self._lock:
            handle, count = self.handle, 64
            for _ in range(4):
                class ProcessList(C.Structure):
                    _fields_ = [("assigned", _DWORD), ("listed", _DWORD),
                                ("pids", C.c_size_t * count)]
                info = ProcessList()
                ok = self._backend.kernel.QueryInformationJobObject(
                    handle, 3, C.byref(info), C.sizeof(info), None)
                if ok and info.assigned == info.listed <= count:
                    pids = tuple(int(pid) for pid in info.pids[:info.listed])
                    if any(not 0 < pid <= 0xFFFFFFFF for pid in pids) or len(set(pids)) != len(pids):
                        raise NativeJobError("native_job_membership_invalid")
                    return pids
                error = C.get_last_error()
                if not ok and error != 234:
                    raise NativeJobError("native_job_membership_failed", error)
                count = max(count * 2, int(info.assigned))
                if count > 4096:
                    break
            raise NativeJobError("native_job_membership_unstable")

    def _set(self, flags, rate_bp):
        if self.access not in (JobAccess.CONTROL, JobAccess.OWNER):
            raise NativeJobError("native_job_control_access_required")
        info = _CpuInfo(flags, rate_bp)
        try:
            _check(self._backend.kernel.SetInformationJobObject(
                self.handle, 15, C.byref(info), C.sizeof(info)), "native_job_cpu_set_failed")
        except BaseException as error:
            _retain(error, self)
            raise

    def set_cpu_rate_unverified(self, rate_bp: int) -> None:
        """Native Set boundary only; caller must query before acknowledging it."""
        if type(rate_bp) is not int or not 1 <= rate_bp <= 10000:
            raise ValueError("native_job_cpu_rate_invalid")
        with self._lock:
            self._set(ENABLE | HARD_CAP, rate_bp)

    def set_cpu_rate(self, rate_bp: int) -> CpuState:
        with self._lock:
            self.set_cpu_rate_unverified(rate_bp)
            try:
                observed = self.query_cpu()
                if observed != CpuState(ENABLE | HARD_CAP, rate_bp):
                    raise NativeJobError("native_job_cpu_set_readback_mismatch")
                return observed
            except BaseException as error:
                _retain(error, self)
                raise

    def disable(self) -> CpuState:
        with self._lock:
            self._set(0, 10000)
            try:
                observed = self.query_cpu()
                # The disabled union value is unused, not required to be zero.
                if observed.flags & ENABLE:
                    raise NativeJobError("native_job_cpu_disable_readback_mismatch")
                return observed
            except BaseException as error:
                _retain(error, self)
                raise

    def _release(self, resource):
        if resource.state in ("absent", "closed"):
            return
        if resource.state != "owned":
            raise NativeJobError("native_job_cleanup_outcome_unknown")
        # Publish quarantine before the call. Only a known failure permits retry.
        resource.state = "close_unknown"
        try:
            release = self._backend.free if resource.kind == "descriptor" else self._backend.close
            release(resource.value)
        except BaseException as error:
            if getattr(error, "_known_native_close_failed", False) is True:
                resource.state = "owned"
            raise
        # Tombstone first: interrupted local publication never causes double-close.
        resource.state = "closed"

    def close(self) -> None:
        """Release only these handles/buffers; never disable or infer Job exit."""
        with self._lock:
            self._ready = False
            primary = None
            for resource in self._resources:
                try:
                    self._release(resource)
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note("native_job_additional_cleanup_unverified")
            if primary is not None:
                _retain(primary, self)
                raise primary

    def _failed_initialization(self, primary):
        # Retain the actual acquisition even when its cleanup succeeds. A
        # caller receiving no factory result must not infer either absence or
        # unresolved custody from that fact alone. This observation is separate
        # from _native_job_cleanup, which contains only still-unsettled owners.
        # Reused exception objects must not overwrite an earlier original.
        originals = getattr(primary, "_native_job_initialization_owners", ())
        if not any(owner is self for owner in originals):
            primary._native_job_initialization_owners = (*originals, self)
        try:
            self.close()
        except BaseException as cleanup:
            primary.add_note("native_job_initialization_cleanup_unverified")
            primary._native_job_cleanup_error = cleanup
            _retain(primary, self)
