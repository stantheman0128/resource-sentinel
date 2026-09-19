"""Read-only native process identity, retained for same-handle observations.

An identity proves which process was observed, not who sent an IPC request or
who owns an allocation. This module neither enrolls work nor enables a P1 gate.
No float epoch, PID-only fallback, process enumeration or control API is used.
Handles are limited to QUERY_LIMITED_INFORMATION | SYNCHRONIZE. The caller must
retain the context until its decision completes; a snapshot is not a launch fence.
"""
from __future__ import annotations

import ctypes as C
from functools import lru_cache
import os
import re
import threading

from .contracts import IdentityObservation, IdentityStatus, ProcessIdentity


class IdentityUnavailable(RuntimeError):
    """Sanitized failure; no absence or API error is interpreted as death."""

    def __init__(self, reason: str, win32_error: int | None = None):
        self.reason, self.win32_error = reason, win32_error
        super().__init__(reason)


_DWORD = C.c_uint32
_HANDLE = C.c_void_p
_BOOL = C.c_int32
_PROCESS_ACCESS = 0x1000 | 0x100000
_MAX_TOKEN_BYTES = 64 * 1024
_LOGON_SID = re.compile(r"S-1-5-5-([0-9]{1,10})-([0-9]{1,10})\Z")


class _FileTime(C.Structure):
    _fields_ = [("low", _DWORD), ("high", _DWORD)]


class _SidAndAttributes(C.Structure):
    _fields_ = [("sid", C.c_void_p), ("attributes", _DWORD)]


class _TokenGroups(C.Structure):
    _fields_ = [("count", _DWORD), ("groups", _SidAndAttributes * 1)]


def _bind(dll, name, result, *arguments):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, arguments
    return function


def _check(result, reason):
    if not result:
        raise IdentityUnavailable(reason, C.get_last_error())


class _WindowsBackend:
    """No background threads and no writes to another process or a Job."""

    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise IdentityUnavailable("native_identity_platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        self.security = a = C.WinDLL("advapi32", use_last_error=True)
        _bind(k, "OpenProcess", _HANDLE, _DWORD, _BOOL, _DWORD)
        _bind(k, "GetProcessId", _DWORD, _HANDLE)
        _bind(k, "GetProcessTimes", _BOOL, _HANDLE, *([C.POINTER(_FileTime)] * 4))
        _bind(k, "WaitForSingleObject", _DWORD, _HANDLE, _DWORD)
        _bind(k, "IsProcessInJob", _BOOL, _HANDLE, _HANDLE, C.POINTER(_BOOL))
        _bind(k, "CloseHandle", _BOOL, _HANDLE)
        _bind(k, "LocalFree", C.c_void_p, C.c_void_p)
        _bind(a, "OpenProcessToken", _BOOL, _HANDLE, _DWORD, C.POINTER(_HANDLE))
        _bind(a, "GetTokenInformation", _BOOL, _HANDLE, C.c_int, C.c_void_p,
              _DWORD, C.POINTER(_DWORD))
        _bind(a, "ConvertSidToStringSidW", _BOOL, C.c_void_p, C.POINTER(C.c_void_p))

    def open_process(self, pid):
        handle = self.kernel.OpenProcess(_PROCESS_ACCESS, False, pid)
        _check(handle, "process_open_unavailable")
        return handle

    def close(self, handle):
        _check(self.kernel.CloseHandle(handle), "process_handle_close_failed")

    def identity(self, handle):
        pid = self.kernel.GetProcessId(handle)
        _check(pid, "process_identity_unavailable")
        created, exited, kernel, user = (_FileTime() for _ in range(4))
        _check(self.kernel.GetProcessTimes(handle, C.byref(created), C.byref(exited),
                                           C.byref(kernel), C.byref(user)),
               "process_birth_unavailable")
        birth = (created.high << 32) | created.low
        # Query the target's primary token, never the calling thread's token.
        token = _HANDLE()
        _check(self.security.OpenProcessToken(handle, 0x0008, C.byref(token)),
               "process_token_unavailable")
        try:
            logon = self._logon_sid(token)
        finally:
            self.close(token)
        return ProcessIdentity(int(pid), birth, logon)

    def _logon_sid(self, token):
        required = _DWORD()
        success = self.security.GetTokenInformation(token, 28, None, 0, C.byref(required))
        if success or C.get_last_error() != 122:
            raise IdentityUnavailable("logon_sid_unavailable", C.get_last_error())
        size = int(required.value)
        if not C.sizeof(_TokenGroups) <= size <= _MAX_TOKEN_BYTES:
            raise IdentityUnavailable("logon_sid_invalid")
        buffer = C.create_string_buffer(size)
        _check(self.security.GetTokenInformation(token, 28, buffer, size, C.byref(required)),
               "logon_sid_unavailable")
        if not C.sizeof(_TokenGroups) <= required.value <= size:
            raise IdentityUnavailable("logon_sid_invalid")
        groups = _TokenGroups.from_buffer(buffer)
        sid = groups.groups[0].sid
        start, end = C.addressof(buffer), C.addressof(buffer) + required.value
        if (groups.count != 1 or groups.groups[0].attributes & 0xC0000000 != 0xC0000000
                or not sid or not start <= sid <= end - 8):
            raise IdentityUnavailable("logon_sid_invalid")
        # Validate SID's variable length before allowing the native converter
        # to dereference it. SID revision 1 has at most 15 DWORD subauthorities.
        header = C.string_at(sid, 8)
        length = 8 + header[1] * 4
        if header[0] != 1 or header[1] > 15 or sid + length > end:
            raise IdentityUnavailable("logon_sid_invalid")
        text = C.c_void_p()
        _check(self.security.ConvertSidToStringSidW(sid, C.byref(text)), "logon_sid_unavailable")
        try:
            result = C.wstring_at(text.value)
        finally:
            if self.kernel.LocalFree(text):
                raise IdentityUnavailable("logon_sid_free_failed")
        match = _LOGON_SID.fullmatch(result)
        if match is None or any(int(value) > 0xFFFFFFFF for value in match.groups()):
            raise IdentityUnavailable("logon_sid_invalid")
        return result

    def wait(self, handle):
        # Never wait for a duration while holding a policy/SQLite lock.
        result = self.kernel.WaitForSingleObject(handle, 0)
        if result == 0:
            return IdentityStatus.DEAD
        if result == 258:
            return IdentityStatus.ALIVE
        raise IdentityUnavailable("process_wait_unavailable", C.get_last_error())

    def membership(self, handle, job_handle):
        member = _BOOL()
        _check(self.kernel.IsProcessInJob(handle, job_handle, C.byref(member)),
               "membership_unknown")
        return bool(member.value)


@lru_cache(maxsize=1)
def _backend():
    return _WindowsBackend()


class VerifiedProcess:
    """Own one limited-right handle; never reopen its PID for later checks.

    ``open`` verifies an expected full identity. ``current`` bootstraps the
    wrapper's own native identity, without trusting an environment variable.
    This object is not IPC peer authentication or a reservation adoption token.
    """

    def __init__(self, backend, handle, identity):
        self._backend, self._handle, self._identity = backend, handle, identity
        self._lock = threading.Lock()

    @property
    def identity(self) -> ProcessIdentity:
        return self._identity

    @classmethod
    def _open(cls, pid, expected=None):
        backend = _backend()
        handle = backend.open_process(pid)
        try:
            observed = backend.identity(handle)
            if observed.pid != pid or (expected is not None and observed != expected):
                raise IdentityUnavailable("identity_mismatch")
            return cls(backend, handle, observed)
        except BaseException:
            backend.close(handle)
            raise

    @classmethod
    def open(cls, expected: ProcessIdentity):
        if not isinstance(expected, ProcessIdentity):
            raise TypeError("exact_process_identity_required")
        return cls._open(expected.pid, expected)

    @classmethod
    def current(cls):
        return cls._open(os.getpid())

    def observe(self) -> IdentityObservation:
        with self._lock:
            if self._handle is None:
                return IdentityObservation(self.identity, IdentityStatus.UNKNOWN, "identity_handle_closed")
            try:
                return IdentityObservation(self.identity, self._backend.wait(self._handle))
            except IdentityUnavailable as error:
                return IdentityObservation(self.identity, IdentityStatus.UNKNOWN, error.reason)

    def is_in_job(self, job_handle: int | None) -> bool | None:
        """Same-process-handle query; None result means unknown, never false.

        A None argument asks about any inherited Job. A specific query requires
        a Job handle held by the trusted caller for this entire call. No Job is
        opened by name here and the supplied Job handle is never closed here.
        """
        if job_handle is not None and (type(job_handle) is not int or
                not 0 < job_handle < 1 << (8 * C.sizeof(C.c_void_p))):
            raise ValueError("invalid_job_handle")
        with self._lock:
            if self._handle is None:
                return None
            try:
                if self._backend.wait(self._handle) is not IdentityStatus.ALIVE:
                    return None
                member = self._backend.membership(self._handle, job_handle)
                # Exit may race the query. This only bounds the observation;
                # it cannot promise that a process stays alive afterward.
                if self._backend.wait(self._handle) is not IdentityStatus.ALIVE:
                    return None
                return member
            except IdentityUnavailable:
                return None

    def close(self):
        with self._lock:
            if self._handle is not None:
                self._backend.close(self._handle)
                self._handle = None

    def __enter__(self):
        with self._lock:
            if self._handle is None:
                raise IdentityUnavailable("identity_handle_closed")
        return self

    def __exit__(self, *_):
        self.close()


def observe_identity(expected: ProcessIdentity) -> IdentityObservation:
    """One-shot diagnostics only; use VerifiedProcess for lifecycle decisions."""
    if not isinstance(expected, ProcessIdentity):
        raise TypeError("exact_process_identity_required")
    try:
        with VerifiedProcess.open(expected) as process:
            return process.observe()
    except IdentityUnavailable as error:
        return IdentityObservation(expected, IdentityStatus.UNKNOWN, error.reason)
