"""Opt-in, test-only Win32 ABI for the P1 capability experiments.

No production imports this module. Importing it performs no Win32 operation.
It cannot break away, assign an already-running process, suspend, terminate,
trim, or set non-CPU Job limits. Closing a handle is never a restore operation.
The caller must keep its manifest and disable/query before final cleanup.

References: Microsoft Learn UpdateProcThreadAttribute, CreateProcessW,
JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, and Job Objects (see P1 preflight).
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from functools import lru_cache
import math
import os
import re
import sys
import time
import uuid

from sentinel.adaptive import native_launcher as _launcher

OPT_IN = "SENTINEL_ADAPTIVE_WINDOWS_SPIKES"
JOB_PREFIX = "Local\\ResourceSentinel.Test.Job."
MUTEX_PREFIX = "Local\\ResourceSentinel.Test.Mutex."
ENABLE = 0x1
HARD_CAP = 0x4
_API = None
_INVALID_HANDLE = C.c_void_p(-1).value


class UnsupportedCapability(RuntimeError):
    def __init__(self, reason, win32_error=None):
        self.reason = reason
        self.win32_error = win32_error
        super().__init__(f"{reason}; win32_error={win32_error}")


LaunchOutcomeUnknown = _launcher.LaunchOutcomeUnknown


class _SecurityAttributes(C.Structure):
    _fields_ = [("nLength", W.DWORD), ("lpSecurityDescriptor", C.c_void_p),
                ("bInheritHandle", W.BOOL)]


class _SidAndAttributes(C.Structure):
    _fields_ = [("Sid", C.c_void_p), ("Attributes", W.DWORD)]


class _TokenGroups(C.Structure):
    _fields_ = [("GroupCount", W.DWORD), ("Groups", _SidAndAttributes * 1)]


class _Acl(C.Structure):
    _fields_ = [("revision", W.BYTE), ("sbz1", W.BYTE), ("size", W.WORD),
                ("ace_count", W.WORD), ("sbz2", W.WORD)]


class _AllowedAce(C.Structure):
    _fields_ = [("type", W.BYTE), ("flags", W.BYTE), ("size", W.WORD),
                ("mask", W.DWORD), ("sid_start", W.DWORD)]


class _CpuInfo(C.Structure):
    _fields_ = [("ControlFlags", W.DWORD), ("CpuRate", W.DWORD)]


class _BasicAccounting(C.Structure):
    _fields_ = [("TotalUserTime", C.c_int64), ("TotalKernelTime", C.c_int64),
                ("ThisPeriodTotalUserTime", C.c_int64),
                ("ThisPeriodTotalKernelTime", C.c_int64),
                ("TotalPageFaultCount", W.DWORD), ("TotalProcesses", W.DWORD),
                ("ActiveProcesses", W.DWORD), ("TotalTerminatedProcesses", W.DWORD)]


class _BasicLimits(C.Structure):
    _fields_ = [("PerProcessUserTimeLimit", C.c_int64),
                ("PerJobUserTimeLimit", C.c_int64), ("LimitFlags", W.DWORD),
                ("MinimumWorkingSetSize", C.c_size_t),
                ("MaximumWorkingSetSize", C.c_size_t),
                ("ActiveProcessLimit", W.DWORD), ("Affinity", C.c_size_t),
                ("PriorityClass", W.DWORD), ("SchedulingClass", W.DWORD)]


class _IoCounters(C.Structure):
    _fields_ = [(key, C.c_uint64) for key in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _ExtendedLimits(C.Structure):
    _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                ("ProcessMemoryLimit", C.c_size_t), ("JobMemoryLimit", C.c_size_t),
                ("PeakProcessMemoryUsed", C.c_size_t),
                ("PeakJobMemoryUsed", C.c_size_t)]


# Shared ABI classes are required: ctypes validates pointer class identity,
# not merely equal sizes, when the launcher uses this adapter's bound DLL.
_StartupInfo = _launcher._StartupInfo
_StartupInfoEx = _launcher._StartupInfoEx
_ProcessInfo = _launcher._ProcessInfo


class _ProcessBasicInfo(C.Structure):
    _fields_ = [("ExitStatus", W.LONG), ("PebBaseAddress", C.c_void_p),
                ("AffinityMask", C.c_size_t), ("BasePriority", W.LONG),
                ("UniqueProcessId", C.c_size_t),
                ("InheritedFromUniqueProcessId", C.c_size_t)]


def _bind(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, args
    return fn


def _api():
    global _API
    if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
        raise UnsupportedCapability("requires 64-bit Python on Windows")
    if _API is not None:
        return _API
    k = C.WinDLL("kernel32", use_last_error=True)
    a = C.WinDLL("advapi32", use_last_error=True)
    n = C.WinDLL("ntdll", use_last_error=True)
    ptr = C.c_void_p
    _bind(k, "GetCurrentProcess", W.HANDLE)
    _bind(k, "GetCurrentProcessId", W.DWORD)
    _bind(k, "CloseHandle", W.BOOL, W.HANDLE)
    _bind(k, "LocalFree", ptr, ptr)
    _bind(k, "IsProcessInJob", W.BOOL, W.HANDLE, W.HANDLE, C.POINTER(_launcher._BOOL))
    _bind(k, "GetActiveProcessorGroupCount", W.WORD)
    _bind(k, "GetActiveProcessorCount", W.DWORD, W.WORD)
    _bind(k, "GetProcessAffinityMask", W.BOOL, W.HANDLE,
          C.POINTER(C.c_size_t), C.POINTER(C.c_size_t))
    _bind(k, "CreateJobObjectW", W.HANDLE, C.POINTER(_SecurityAttributes), W.LPCWSTR)
    _bind(k, "OpenJobObjectW", W.HANDLE, W.DWORD, W.BOOL, W.LPCWSTR)
    _bind(k, "QueryInformationJobObject", W.BOOL, W.HANDLE, C.c_int,
          ptr, W.DWORD, C.POINTER(W.DWORD))
    _bind(k, "SetInformationJobObject", W.BOOL, W.HANDLE, C.c_int, ptr, W.DWORD)
    _bind(k, "OpenProcess", W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
    _bind(k, "GetProcessTimes", W.BOOL, W.HANDLE, C.POINTER(_launcher._FileTime),
          C.POINTER(_launcher._FileTime), C.POINTER(_launcher._FileTime), C.POINTER(_launcher._FileTime))
    _bind(k, "GetExitCodeProcess", W.BOOL, W.HANDLE, C.POINTER(_launcher._DWORD))
    _bind(k, "WaitForSingleObject", W.DWORD, W.HANDLE, W.DWORD)
    _bind(k, "GetStdHandle", W.HANDLE, W.DWORD)
    _bind(k, "DuplicateHandle", W.BOOL, W.HANDLE, W.HANDLE, W.HANDLE,
          C.POINTER(W.HANDLE), W.DWORD, W.BOOL, W.DWORD)
    _bind(k, "InitializeProcThreadAttributeList", W.BOOL, ptr, W.DWORD,
          W.DWORD, C.POINTER(C.c_size_t))
    _bind(k, "UpdateProcThreadAttribute", W.BOOL, ptr, W.DWORD, C.c_size_t,
          ptr, C.c_size_t, ptr, ptr)
    _bind(k, "DeleteProcThreadAttributeList", None, ptr)
    _bind(k, "CreateProcessW", W.BOOL, W.LPCWSTR, W.LPWSTR, ptr, ptr,
          W.BOOL, W.DWORD, ptr, W.LPCWSTR, C.POINTER(_StartupInfoEx),
          C.POINTER(_ProcessInfo))
    _bind(k, "CreateMutexW", W.HANDLE, C.POINTER(_SecurityAttributes),
          W.BOOL, W.LPCWSTR)
    _bind(k, "ReleaseMutex", W.BOOL, W.HANDLE)
    _bind(k, "GetConsoleProcessList", W.DWORD, C.POINTER(W.DWORD), W.DWORD)
    _bind(a, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, C.POINTER(W.HANDLE))
    _bind(a, "GetTokenInformation", W.BOOL, W.HANDLE, C.c_int, ptr,
          W.DWORD, C.POINTER(W.DWORD))
    _bind(a, "ConvertSidToStringSidW", W.BOOL, ptr, C.POINTER(ptr))
    _bind(a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", W.BOOL,
          W.LPCWSTR, W.DWORD, C.POINTER(ptr), C.POINTER(W.DWORD))
    _bind(a, "GetSecurityInfo", W.DWORD, W.HANDLE, C.c_int, W.DWORD,
          C.POINTER(ptr), C.POINTER(ptr), C.POINTER(ptr), C.POINTER(ptr), C.POINTER(ptr))
    _bind(a, "GetSecurityDescriptorControl", W.BOOL, ptr, C.POINTER(W.WORD), C.POINTER(W.DWORD))
    _bind(a, "GetAce", W.BOOL, ptr, W.DWORD, C.POINTER(ptr))
    _bind(n, "NtQueryInformationProcess", W.LONG, W.HANDLE, C.c_int,
          ptr, W.ULONG, C.POINTER(W.ULONG))
    _API = (k, a, n)
    return _API


def _check(ok, operation):
    if not ok:
        error = C.get_last_error()
        exc = OSError(error, operation)
        exc.win32_error = error
        raise exc


def _opt_in():
    if os.environ.get(OPT_IN) != "1":
        raise UnsupportedCapability(f"control requires explicit {OPT_IN}=1")


def _nonce(nonce):
    if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise ValueError("test nonce must be 32 lowercase hexadecimal characters")
    return nonce


def _timeout_ms(timeout):
    if not math.isfinite(timeout) or timeout < 0 or timeout > 120:
        raise ValueError("test wait must be finite and between 0 and 120 seconds")
    return int(math.ceil(timeout * 1000))


def require_supported_host():
    """Read-only capability preflight; unknown and any parent Job fail closed."""
    k, _, _ = _api()
    in_job = _launcher._BOOL()
    if not k.IsProcessInJob(k.GetCurrentProcess(), None, C.byref(in_job)):
        raise UnsupportedCapability("parent Job membership unknown", C.get_last_error())
    if in_job.value:
        raise UnsupportedCapability("foreign/unknown parent Job: denominator unsupported")
    groups = int(k.GetActiveProcessorGroupCount())
    count = int(k.GetActiveProcessorCount(0xFFFF))
    if groups != 1 or not 1 <= count <= 64:
        raise UnsupportedCapability("requires one processor group with 1..64 processors")
    process_mask, system_mask = C.c_size_t(), C.c_size_t()
    if not k.GetProcessAffinityMask(k.GetCurrentProcess(), C.byref(process_mask),
                                    C.byref(system_mask)):
        raise UnsupportedCapability("affinity unknown", C.get_last_error())
    if process_mask.value != system_mask.value or system_mask.value.bit_count() != count:
        raise UnsupportedCapability("restricted/unknown processor affinity")
    version = sys.getwindowsversion()
    return {"platform": sys.platform, "os_build": version.build,
            "os_major": version.major, "os_minor": version.minor,
            "logical_processors": count, "processor_groups": groups,
            "process_affinity": str(process_mask.value), "in_parent_job": False,
            "python_bits": 64, "pid": os.getpid()}


def _sid_string(sid):
    k, a, _ = _api()
    result = C.c_void_p()
    _check(a.ConvertSidToStringSidW(sid, C.byref(result)), "ConvertSidToStringSidW")
    try:
        return C.wstring_at(result)
    finally:
        k.LocalFree(result)


def _token_sid(information_class):
    k, a, _ = _api()
    token = W.HANDLE()
    _check(a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, C.byref(token)),
           "OpenProcessToken")
    try:
        size = W.DWORD()
        a.GetTokenInformation(token, information_class, None, 0, C.byref(size))
        if not 0 < size.value <= 65536:
            raise UnsupportedCapability("logon SID token size unavailable")
        buf = C.create_string_buffer(size.value)
        _check(a.GetTokenInformation(token, information_class, buf, size, C.byref(size)),
               "GetTokenInformation(SID)")
        if information_class == 28:  # TokenLogonSid -> TOKEN_GROUPS
            groups = C.cast(buf, C.POINTER(_TokenGroups)).contents
            if groups.GroupCount != 1:
                raise UnsupportedCapability("expected exactly one logon SID")
            return _sid_string(groups.Groups[0].Sid)
        return _sid_string(C.cast(buf, C.POINTER(_SidAndAttributes)).contents.Sid)
    finally:
        k.CloseHandle(token)


def _logon_sid():
    sid = _token_sid(28)
    if not re.fullmatch(r"S-1-5-5-\d+-\d+", sid):
        raise UnsupportedCapability("unexpected logon SID format")
    return sid


def _verify_object_security(handle, logon_sid, all_access):
    """Read actual kernel object owner/DACL; creation arguments are not proof."""
    k, a, _ = _api()
    owner, dacl, descriptor = C.c_void_p(), C.c_void_p(), C.c_void_p()
    error = a.GetSecurityInfo(handle, 6, 0x1 | 0x4, C.byref(owner), None,
                              C.byref(dacl), None, C.byref(descriptor))
    if error:
        raise UnsupportedCapability("cannot verify owned test object security", int(error))
    try:
        if not owner or not dacl or _sid_string(owner) != _token_sid(1):
            raise UnsupportedCapability("test object owner/DACL mismatch")
        control, revision = W.WORD(), W.DWORD()
        _check(a.GetSecurityDescriptorControl(descriptor, C.byref(control), C.byref(revision)),
               "GetSecurityDescriptorControl")
        acl = C.cast(dacl, C.POINTER(_Acl)).contents
        if not control.value & 0x1000 or acl.ace_count != 1:
            raise UnsupportedCapability("test object must have a protected single-ACE DACL")
        ace_pointer = C.c_void_p()
        _check(a.GetAce(dacl, 0, C.byref(ace_pointer)), "GetAce")
        ace = C.cast(ace_pointer, C.POINTER(_AllowedAce)).contents
        # Windows documentation/SDKs expose both Job all-access variants. Both
        # remain an exclusive grant to this verified logon SID; retain the exact
        # returned mask as evidence instead of treating SDK drift as new scope.
        accepted_masks = {0x10000000, all_access}
        if all_access == 0x1F003F:
            accepted_masks.add(0x1F001F)
        if (ace.type != 0 or ace.flags != 0 or ace.size < C.sizeof(_AllowedAce)
                or ace.mask not in accepted_masks
                or _sid_string(ace_pointer.value + _AllowedAce.sid_start.offset) != logon_sid):
            raise UnsupportedCapability("test object grants rights outside the expected logon SID")
        return {"owner_matches_current_user": True, "protected_dacl": True,
                "ace_count": 1, "allowed_logon_sid": logon_sid,
                "access_mask": int(ace.mask)}
    finally:
        k.LocalFree(descriptor)


class _LogonSecurity:
    def __init__(self):
        self.logon_sid = _logon_sid()
        self.descriptor = C.c_void_p()
        _, a, _ = _api()
        _check(a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            f"D:P(A;;GA;;;{self.logon_sid})", 1, C.byref(self.descriptor), None),
            "ConvertStringSecurityDescriptorToSecurityDescriptorW")
        self.attributes = _SecurityAttributes(C.sizeof(_SecurityAttributes),
                                              self.descriptor, False)

    def close(self):
        if self.descriptor:
            _api()[0].LocalFree(self.descriptor)
            self.descriptor = C.c_void_p()


class ProcessHandle:
    def __init__(self, handle, pid):
        self.handle, self.pid = handle, int(pid)
        self._identity_cleanup = []

    @classmethod
    def open(cls, pid, expected_created_filetime_100ns=None, terminate=False):
        # No termination method is provided. The optional access bit is only for
        # independently reviewed fixture-only fault injectors.
        k, _, _ = _api()
        rights = 0x100000 | 0x1000 | 0x0400 | (0x0001 if terminate else 0)
        handle = k.OpenProcess(rights, False, int(pid))
        _check(handle, "OpenProcess")
        process = cls(handle, pid)
        try:
            identity = process.identity()
            if expected_created_filetime_100ns is not None and (
                identity["created_filetime_100ns"] != str(expected_created_filetime_100ns)
            ):
                raise ValueError("exact process identity mismatch; PID may have been reused")
            return process
        except BaseException:
            process.close()
            raise

    @classmethod
    def open_current(cls):
        return cls.open(os.getpid())

    def identity(self):
        created, exited, kernel, user = (_launcher._FileTime() for _ in range(4))
        _check(_api()[0].GetProcessTimes(self.handle, C.byref(created), C.byref(exited),
                                        C.byref(kernel), C.byref(user)), "GetProcessTimes")
        birth = (created.dwHighDateTime << 32) | created.dwLowDateTime
        return {"pid": self.pid, "created_filetime_100ns": str(birth)}

    def full_identity(self, *, expected_logon_id):
        """Query the retained original object, including after a natural exit.

        The existing two-field identity() format remains diagnostic-compatible.
        This full identity is still not enrollment or launch-claim authority.
        """
        from sentinel.adaptive.identity import VerifiedProcess

        try:
            verified = VerifiedProcess.duplicate_from_handle(
                self.handle, expected_pid=self.pid, expected_logon_id=expected_logon_id)
            observed = verified.identity
            verified.close()
            return observed
        except BaseException as error:
            # The enclosing LaunchOutcomeUnknown retains this original owner.
            # Its existing close() path also retries any failed duplicate close.
            self._identity_cleanup.append(error)
            raise

    def parent_pid(self):
        # Test-only evidence: parent PID is not parent identity. Hold/compare a
        # separately opened parent FILETIME before using it for any fault action.
        info, size = _ProcessBasicInfo(), W.ULONG()
        status = _api()[2].NtQueryInformationProcess(self.handle, 0, C.byref(info),
                                                    C.sizeof(info), C.byref(size))
        if status != 0 or size.value != C.sizeof(info):
            raise UnsupportedCapability(f"process ancestry query unavailable: NTSTATUS={status}")
        return int(info.InheritedFromUniqueProcessId)

    def is_in_job(self, job):
        result = _launcher._BOOL()
        _check(_api()[0].IsProcessInJob(self.handle, job.handle, C.byref(result)),
               "IsProcessInJob")
        return bool(result.value)

    def wait(self, timeout):
        result = _api()[0].WaitForSingleObject(self.handle, _timeout_ms(timeout))
        if result == 0:
            return True
        if result == 258:
            return False
        _check(False, "WaitForSingleObject(process)")

    def exit_code(self):
        if not self.wait(0):
            return None
        result = _launcher._DWORD()
        _check(_api()[0].GetExitCodeProcess(self.handle, C.byref(result)), "GetExitCodeProcess")
        return int(result.value)

    def close(self):
        from sentinel.adaptive.identity import retry_identity_cleanup

        for error in self._identity_cleanup:
            retry_identity_cleanup(error)
        self._identity_cleanup.clear()
        if self.handle:
            _check(_api()[0].CloseHandle(self.handle), "CloseHandle(process)")
            self.handle = None


def current_identity():
    process = ProcessHandle.open_current()
    try:
        return process.identity()
    finally:
        process.close()


@lru_cache(maxsize=1)
def _realtime_api():
    # Official API-set contract: kernel32 lacks the direct export on some
    # Windows hosts. Do not silently replace this with a different clock.
    # https://learn.microsoft.com/en-us/uwp/win32-and-com/win32-apis
    realtime = C.WinDLL("api-ms-win-core-realtime-l1-1-1.dll", use_last_error=True)
    _bind(realtime, "QueryInterruptTimePrecise", None, C.POINTER(C.c_uint64))
    return realtime


def interrupt_time_100ns():
    """Boot-relative interrupt time, including sleep, for test lease deadlines."""
    value = C.c_uint64((1 << 64) - 1)
    _realtime_api().QueryInterruptTimePrecise(C.byref(value))
    if value.value == (1 << 64) - 1:
        raise UnsupportedCapability("precise interrupt time unavailable")
    return int(value.value)


def console_process_ids():
    k, _, _ = _api()
    count = 64
    for _ in range(3):
        buf = (W.DWORD * count)()
        found = int(k.GetConsoleProcessList(buf, count))
        if found == 0:
            raise UnsupportedCapability("console process list unavailable", C.get_last_error())
        if found <= count:
            return list(buf[:found])
        if found > 1024:
            break
        count = found
    raise UnsupportedCapability("console membership exceeds bounded stable snapshot")


class OwnedJob:
    def __init__(self, handle, name, nonce, logon_sid):
        self.handle, self.name, self.nonce = handle, name, nonce
        self.logon_sid = logon_sid
        self.security = None

    @classmethod
    def create(cls, nonce=None):
        _opt_in()
        require_supported_host()
        nonce = _nonce(nonce or uuid.uuid4().hex)
        name = JOB_PREFIX + nonce
        security = _LogonSecurity()
        k, _, _ = _api()
        try:
            C.set_last_error(0)
            handle = k.CreateJobObjectW(C.byref(security.attributes), name)
            error = C.get_last_error()
            _check(handle, "CreateJobObjectW")
            if error == 183:
                k.CloseHandle(handle)
                raise ValueError("test Job name collision; existing object not adopted")
            job = cls(handle, name, nonce, security.logon_sid)
            try:
                job.security = _verify_object_security(handle, security.logon_sid, 0x1F003F)
                if job.query_limits() != {"limit_flags": 0, "ui_restrictions": 0}:
                    raise UnsupportedCapability("new Job unexpectedly has non-CPU limits")
                if job.query_cpu()["flags"] != 0:
                    raise UnsupportedCapability("new Job unexpectedly has CPU control")
                return job
            except BaseException:
                job.close()
                raise
        finally:
            security.close()

    @classmethod
    def open(cls, name, nonce):
        if name != JOB_PREFIX + _nonce(nonce):
            raise ValueError("name/nonce does not identify an owned test Job")
        k, _, _ = _api()
        handle = k.OpenJobObjectW(0x0001 | 0x0002 | 0x0004 | 0x00020000, False, name)
        _check(handle, "OpenJobObjectW")
        try:
            job = cls(handle, name, nonce, _logon_sid())
            job.security = _verify_object_security(handle, job.logon_sid, 0x1F003F)
            return job
        except BaseException:
            k.CloseHandle(handle)
            raise

    def _query(self, information_class, result):
        _check(_api()[0].QueryInformationJobObject(self.handle, information_class,
               C.byref(result), C.sizeof(result), None), "QueryInformationJobObject")
        return result

    def query_cpu(self):
        info = self._query(15, _CpuInfo())
        return {"flags": int(info.ControlFlags), "rate_bp": int(info.CpuRate)}

    def query_limits(self):
        info = self._query(9, _ExtendedLimits())
        ui = self._query(4, W.DWORD())
        return {"limit_flags": int(info.BasicLimitInformation.LimitFlags),
                "ui_restrictions": int(ui.value)}

    def set_cpu_rate(self, rate_bp):
        self.set_cpu_rate_unverified(rate_bp)
        observed = self.query_cpu()
        if observed != {"flags": ENABLE | HARD_CAP, "rate_bp": rate_bp}:
            raise RuntimeError(f"CPU set readback mismatch: {observed}")
        return observed

    def set_cpu_rate_unverified(self, rate_bp):
        """S3 durable-intent fault injection only: Set boundary before Query.

        Success means API returned success, never APPLIED/verified. The caller
        must retain its intent for restore even if killed before readback.
        """
        _opt_in()
        if isinstance(rate_bp, bool) or not isinstance(rate_bp, int) or not 1 <= rate_bp <= 10000:
            raise ValueError("CPU hard-cap rate must be integer basis points in 1..10000")
        info = _CpuInfo(ENABLE | HARD_CAP, rate_bp)
        _check(_api()[0].SetInformationJobObject(self.handle, 15, C.byref(info), C.sizeof(info)),
               "SetInformationJobObject(CPU hard cap)")

    def disable(self):
        _opt_in()
        # rate=0 is invalid. With ENABLE clear the union's returned value is not
        # required to be 0 or 10000; the behavioral effect needs a separate test.
        info = _CpuInfo(0, 10000)
        _check(_api()[0].SetInformationJobObject(self.handle, 15, C.byref(info), C.sizeof(info)),
               "SetInformationJobObject(CPU disabled)")
        observed = self.query_cpu()
        if observed["flags"] & ENABLE:
            raise RuntimeError(f"CPU disable readback remains enabled: {observed}")
        return observed

    def accounting(self):
        info = self._query(1, _BasicAccounting())
        return {"cpu_seconds": (info.TotalUserTime + info.TotalKernelTime) / 10_000_000,
                "active_processes": int(info.ActiveProcesses),
                "total_processes": int(info.TotalProcesses)}

    def active_pids(self):
        count = 64
        for _ in range(4):
            class ProcessList(C.Structure):
                _fields_ = [("assigned", W.DWORD), ("listed", W.DWORD),
                            ("pids", C.c_size_t * count)]
            info = ProcessList()
            ok = _api()[0].QueryInformationJobObject(self.handle, 3, C.byref(info),
                                                    C.sizeof(info), None)
            if ok and info.assigned <= info.listed <= count:
                return [int(pid) for pid in info.pids[:info.listed]]
            error = C.get_last_error()
            if not ok and error != 234:  # ERROR_MORE_DATA: bounded retry
                _check(False, "QueryInformationJobObject(ProcessIdList)")
            count = max(count * 2, int(info.assigned))
            if count > 4096:
                break
        raise UnsupportedCapability("Job membership exceeds bounded stable snapshot")

    def wait_empty(self, timeout):
        _timeout_ms(timeout)
        deadline = time.monotonic() + timeout
        while True:
            if self.accounting()["active_processes"] == 0 and not self.active_pids():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.05, remaining))

    def close(self):
        """Only close this handle. Never claim that closing clears OS limits."""
        if self.handle:
            _check(_api()[0].CloseHandle(self.handle), "CloseHandle(Job)")
            self.handle = None


def launch_in_job(job, application, command_line, *, cwd=None,
                  stdin_handle=None, stdout_handle=None, stderr_handle=None):
    """Create exactly once, atomically in Job, with an explicit stdio allowlist.

    No shell parsing, suspended fallback, retry, parent spoofing, new process
    group, or breakaway. The caller supplies its exact application/command line.
    On a post-create check failure, LaunchOutcomeUnknown retains the process.
    """
    _opt_in()
    require_supported_host()
    return _launcher.launch_in_job(job, application, command_line, cwd=cwd,
        stdin_handle=stdin_handle, stdout_handle=stdout_handle, stderr_handle=stderr_handle,
        backend=_launcher._WindowsBackend(kernel=_api()[0]))


class NamedMutex:
    """Test-only policy/Job fencing mutex with a protected logon-SID DACL.

    acquire returns True for WAIT_ABANDONED, False for normal acquisition;
    timeout raises TimeoutError, so neither return value means failure.
    """
    def __init__(self, name, nonce):
        expected = MUTEX_PREFIX + _nonce(nonce)
        if name not in (expected, expected + ".Policy", expected + ".Job"):
            raise ValueError("mutex must have the exact owned test nonce and allowed role")
        _opt_in()
        security = _LogonSecurity()
        self.handle, self.acquired = None, False
        self.name, self.nonce, self.logon_sid = name, nonce, security.logon_sid
        try:
            self.handle = _api()[0].CreateMutexW(C.byref(security.attributes), False, name)
            _check(self.handle, "CreateMutexW")
            self.security = _verify_object_security(self.handle, self.logon_sid, 0x1F0001)
        except BaseException:
            if self.handle:
                _api()[0].CloseHandle(self.handle)
                self.handle = None
            raise
        finally:
            security.close()

    def acquire(self, timeout):
        if self.acquired:
            raise RuntimeError("recursive test mutex acquisition is not allowed")
        result = _api()[0].WaitForSingleObject(self.handle, _timeout_ms(timeout))
        if result in (0, 0x80):
            self.acquired = True
            return result == 0x80
        if result == 258:
            raise TimeoutError("test mutex acquisition timed out")
        _check(False, "WaitForSingleObject(mutex)")

    def release(self):
        if not self.acquired:
            raise RuntimeError("cannot release an unowned test mutex")
        _check(_api()[0].ReleaseMutex(self.handle), "ReleaseMutex")
        self.acquired = False

    def close(self):
        if self.acquired:
            raise RuntimeError("release the test mutex before closing")
        if self.handle:
            _check(_api()[0].CloseHandle(self.handle), "CloseHandle(mutex)")
            self.handle = None
