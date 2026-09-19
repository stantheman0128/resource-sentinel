"""Bounded native policy mutex; no Job, launcher or control APIs.

The held mutex serializes cooperating Sentinel writers. A lease, including an
abandoned lease, is not lifecycle or launch authority. Callers must reconcile
protected state after abandonment before making any mutation decision.

API references (checked against Microsoft Learn):
https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexexw
https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-object-security-and-access-rights
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
from functools import lru_cache
import os
import re
import threading
from uuid import UUID

from .contracts import IdentityStatus
from .identity import IdentityUnavailable, VerifiedProcess


_DWORD = C.c_uint32
_WORD = C.c_uint16
_BYTE = C.c_uint8
_BOOL = C.c_int32
_HANDLE = C.c_void_p
# SYNCHRONIZE | READ_CONTROL. MUTEX_MODIFY_STATE is reserved for future use;
# ReleaseMutex requires ownership by the current thread, not that reserved bit.
_ACCESS = 0x00100000 | 0x00020000
_PREFIX = "Local\\ResourceSentinel.Policy."
_LOGON_SID = re.compile(r"S-1-5-5-([0-9]{1,10})-([0-9]{1,10})\Z")
_SID_TEXT = re.compile(r"S-1-[0-9]+(?:-[0-9]+){1,15}\Z")
_THREAD_NAMES = set()
_THREAD_NAMES_LOCK = threading.Lock()


class NativePolicyMutexError(RuntimeError):
    """Stable reason plus optional numeric Win32 error, with no private values."""
    def __init__(self, reason: str, win32_error: int | None = None):
        self.reason = reason
        self.win32_error = win32_error
        super().__init__(reason)


@dataclass(frozen=True)
class PolicyMutexLease:
    name: str
    instance_id: str
    logon_id: str
    abandoned: bool


class _SecurityAttributes(C.Structure):
    _fields_ = [("length", _DWORD), ("descriptor", C.c_void_p), ("inherit", _BOOL)]


class _SidAndAttributes(C.Structure):
    _fields_ = [("sid", C.c_void_p), ("attributes", _DWORD)]


class _Acl(C.Structure):
    _fields_ = [("revision", _BYTE), ("reserved", _BYTE), ("size", _WORD),
                ("ace_count", _WORD), ("reserved2", _WORD)]


class _AceHeader(C.Structure):
    _fields_ = [("kind", _BYTE), ("flags", _BYTE), ("size", _WORD), ("mask", _DWORD)]


def _bind(dll, name, result, *arguments):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, arguments
    return function


def _check(success, reason):
    if not success:
        raise NativePolicyMutexError(reason, C.get_last_error())


def _cleanup_note(primary, reason, cleanup):
    code = getattr(cleanup, "win32_error", None)
    suffix = f" win32={code}" if type(code) is int else ""
    primary.add_note(reason + suffix)


@contextmanager
def _owned_resource(value, release, reason):
    """Preserve the original failure when native resource cleanup also fails."""
    try:
        yield value
    except BaseException as primary:
        try:
            release(value)
        except BaseException as cleanup:
            _cleanup_note(primary, reason, cleanup)
        raise
    else:
        release(value)


class _WindowsMutexBackend:
    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise NativePolicyMutexError("policy_mutex_platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        self.security = a = C.WinDLL("advapi32", use_last_error=True)
        ptr = C.c_void_p
        _bind(k, "GetCurrentProcess", _HANDLE)
        _bind(k, "CreateMutexExW", _HANDLE, C.POINTER(_SecurityAttributes), C.c_wchar_p, _DWORD, _DWORD)
        _bind(k, "WaitForSingleObject", _DWORD, _HANDLE, _DWORD)
        _bind(k, "ReleaseMutex", _BOOL, _HANDLE)
        _bind(k, "CloseHandle", _BOOL, _HANDLE)
        _bind(k, "LocalFree", ptr, ptr)
        _bind(a, "OpenProcessToken", _BOOL, _HANDLE, _DWORD, C.POINTER(_HANDLE))
        _bind(a, "GetTokenInformation", _BOOL, _HANDLE, C.c_int, ptr, _DWORD, C.POINTER(_DWORD))
        _bind(a, "ConvertSidToStringSidW", _BOOL, ptr, C.POINTER(ptr))
        _bind(a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", _BOOL,
              C.c_wchar_p, _DWORD, C.POINTER(ptr), C.POINTER(_DWORD))
        _bind(a, "GetSecurityInfo", _DWORD, _HANDLE, C.c_int, _DWORD,
              *([C.POINTER(ptr)] * 5))
        _bind(a, "GetSecurityDescriptorLength", _DWORD, ptr)
        _bind(a, "GetSecurityDescriptorControl", _BOOL, ptr, C.POINTER(_WORD), C.POINTER(_DWORD))

    def close(self, handle):
        _check(self.kernel.CloseHandle(handle), "policy_mutex_handle_close_failed")

    def free(self, pointer):
        C.set_last_error(0)
        if self.kernel.LocalFree(pointer):
            raise NativePolicyMutexError("policy_mutex_security_free_failed", C.get_last_error())

    def _sid_text(self, pointer, start, end):
        if not pointer or not start <= pointer <= end - 8:
            raise NativePolicyMutexError("policy_mutex_sid_invalid")
        header = C.string_at(pointer, 8)
        size = 8 + header[1] * 4
        if header[0] != 1 or header[1] > 15 or pointer + size > end:
            raise NativePolicyMutexError("policy_mutex_sid_invalid")
        text = C.c_void_p()
        _check(self.security.ConvertSidToStringSidW(pointer, C.byref(text)), "policy_mutex_sid_unavailable")
        with _owned_resource(text, self.free, "policy_mutex_security_free_failed"):
            result = C.wstring_at(text.value)
            if len(result) > 184 or _SID_TEXT.fullmatch(result) is None:
                raise NativePolicyMutexError("policy_mutex_sid_invalid")
            return result, size

    def current_owner_sid(self):
        # Query the current process's primary token, never an impersonation
        # token or a PID supplied by a client. TOKEN_QUERY is sufficient.
        token = _HANDLE()
        _check(self.security.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, C.byref(token)),
               "policy_mutex_token_unavailable")
        with _owned_resource(token, self.close, "policy_mutex_token_close_failed"):
            required = _DWORD()
            success = self.security.GetTokenInformation(token, 1, None, 0, C.byref(required))
            if success or C.get_last_error() != 122:
                raise NativePolicyMutexError("policy_mutex_owner_unavailable", C.get_last_error())
            if not C.sizeof(_SidAndAttributes) <= required.value <= 65536:
                raise NativePolicyMutexError("policy_mutex_owner_invalid")
            size = required.value
            buffer = C.create_string_buffer(size)
            _check(self.security.GetTokenInformation(token, 1, buffer, size, C.byref(required)),
                   "policy_mutex_owner_unavailable")
            if not C.sizeof(_SidAndAttributes) <= required.value <= size:
                raise NativePolicyMutexError("policy_mutex_owner_invalid")
            owner = _SidAndAttributes.from_buffer(buffer).sid
            start = C.addressof(buffer)
            return self._sid_text(owner, start, start + required.value)[0]

    def verify_security(self, handle, logon_id, owner_sid):
        owner, dacl, descriptor = (C.c_void_p() for _ in range(3))
        # SE_KERNEL_OBJECT=6, OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION.
        code = self.security.GetSecurityInfo(handle, 6, 0x0001 | 0x0004,
            C.byref(owner), None, C.byref(dacl), None, C.byref(descriptor))
        if code:
            raise NativePolicyMutexError("policy_mutex_security_unavailable", int(code))
        with _owned_resource(descriptor, self.free, "policy_mutex_security_free_failed"):
            if not descriptor.value:
                raise NativePolicyMutexError("policy_mutex_security_invalid")
            size = int(self.security.GetSecurityDescriptorLength(descriptor))
            if not 20 <= size <= 65536:
                raise NativePolicyMutexError("policy_mutex_security_invalid")
            start, end = descriptor.value, descriptor.value + size
            if self._sid_text(owner.value, start, end)[0] != owner_sid:
                raise NativePolicyMutexError("policy_mutex_owner_mismatch")
            control, revision = _WORD(), _DWORD()
            _check(self.security.GetSecurityDescriptorControl(descriptor, C.byref(control), C.byref(revision)),
                   "policy_mutex_security_unavailable")
            # Require a present, protected DACL; no inherited/defaulted grant.
            if (control.value & 0x1004 != 0x1004 or control.value & 0x0009 or
                    not dacl.value or not start <= dacl.value <= end - C.sizeof(_Acl)):
                raise NativePolicyMutexError("policy_mutex_dacl_mismatch")
            acl = _Acl.from_address(dacl.value)
            if (acl.revision != 2 or acl.reserved != 0 or acl.reserved2 != 0 or
                    acl.ace_count != 1 or acl.size < C.sizeof(_Acl) + C.sizeof(_AceHeader) + 8 or
                    dacl.value + acl.size > end):
                raise NativePolicyMutexError("policy_mutex_dacl_mismatch")
            ace_pointer = dacl.value + C.sizeof(_Acl)
            ace = _AceHeader.from_address(ace_pointer)
            if (ace.kind != 0 or ace.flags != 0 or ace.mask != _ACCESS or
                    ace.size != acl.size - C.sizeof(_Acl)):
                raise NativePolicyMutexError("policy_mutex_dacl_mismatch")
            sid, sid_size = self._sid_text(ace_pointer + C.sizeof(_AceHeader),
                                          ace_pointer + C.sizeof(_AceHeader), ace_pointer + ace.size)
            if sid != logon_id or ace.size != C.sizeof(_AceHeader) + sid_size:
                raise NativePolicyMutexError("policy_mutex_dacl_mismatch")

    def create(self, name, logon_id, owner_sid):
        descriptor = C.c_void_p()
        sddl = f"O:{owner_sid}D:P(A;;0x{_ACCESS:08x};;;{logon_id})"
        _check(self.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, C.byref(descriptor), None), "policy_mutex_security_build_failed")
        handle = None
        try:
            with _owned_resource(descriptor, self.free, "policy_mutex_security_free_failed"):
                attributes = _SecurityAttributes(C.sizeof(_SecurityAttributes), descriptor, False)
                # No initial ownership, inheritance, ALL_ACCESS or retry with
                # broader rights. Existing same-name objects require readback.
                handle = self.kernel.CreateMutexExW(C.byref(attributes), name, 0, _ACCESS)
                _check(handle, "policy_mutex_create_failed")
                self.verify_security(handle, logon_id, owner_sid)
            return handle
        except BaseException as primary:
            if handle is not None:
                try:
                    self.close(handle)
                except BaseException as cleanup:
                    _cleanup_note(primary, "policy_mutex_handle_close_failed", cleanup)
            raise

    def wait(self, handle, timeout_ms):
        result = int(self.kernel.WaitForSingleObject(handle, timeout_ms))
        if result == 0:
            return False
        if result == 0x80:
            return True
        if result == 0x102:
            raise NativePolicyMutexError("policy_mutex_timeout")
        if result == 0xFFFFFFFF:
            raise NativePolicyMutexError("policy_mutex_wait_failed", C.get_last_error())
        raise NativePolicyMutexError("policy_mutex_wait_invalid")

    def release(self, handle):
        _check(self.kernel.ReleaseMutex(handle), "policy_mutex_release_failed")


@lru_cache(maxsize=1)
def _backend():
    return _WindowsMutexBackend()


class NativePolicyMutex:
    """Own a logon-scoped handle and bounded, nonrecursive acquisition contexts.

    ``with NativePolicyMutex(logon_id, instance_id) as mutex`` owns its handle.
    ``with mutex.acquire(timeout_ms=250) as lease`` owns the native mutex until
    that inner scope exits; only the acquiring native thread may release it.
    WAIT_ABANDONED still grants ownership and is exposed as ``lease.abandoned``.

    Each object supports one pending/owned lease. Concurrent calls on it fail
    busy; separate same-name objects can contend using the bounded OS wait.
    Closing a waiting or owned handle is refused. Release failure preserves
    owned state, never pretending that persistent state is safe or unlocked.
    """
    def __init__(self, logon_id: str, instance_id: str):
        match = _LOGON_SID.fullmatch(logon_id) if isinstance(logon_id, str) else None
        if match is None or any(int(value) > 0xFFFFFFFF for value in match.groups()):
            raise NativePolicyMutexError("policy_mutex_logon_invalid")
        try:
            parsed = UUID(instance_id) if isinstance(instance_id, str) else None
            valid_instance = parsed is not None and parsed.int != 0 and str(parsed) == instance_id
        except (ValueError, AttributeError):
            valid_instance = False
        if not valid_instance:
            raise NativePolicyMutexError("policy_mutex_instance_invalid")
        self._logon_id, self._instance_id = logon_id, instance_id
        self._name = f"{_PREFIX}{logon_id}.{instance_id}"
        self._state_lock = threading.Lock()
        self._waiting = False
        self._owner = None
        self._owner_native_id = None
        self._handle = None
        self._creator_pid = os.getpid()
        self._api = _backend()
        try:
            with VerifiedProcess.current() as current:
                if (current.identity.pid != self._creator_pid or
                        current.identity.logon_id != logon_id or
                        current.observe().status is not IdentityStatus.ALIVE):
                    raise NativePolicyMutexError("policy_mutex_current_logon_mismatch")
                owner_sid = self._api.current_owner_sid()
                self._handle = self._api.create(self._name, logon_id, owner_sid)
        except BaseException as primary:
            if self._handle is not None:
                try:
                    self._api.close(self._handle)
                    self._handle = None
                except BaseException as cleanup:
                    _cleanup_note(primary, "policy_mutex_handle_close_failed", cleanup)
            if isinstance(primary, IdentityUnavailable):
                raise NativePolicyMutexError("policy_mutex_identity_unavailable", primary.win32_error) from None
            raise

    @property
    def name(self):
        return self._name

    @property
    def instance_id(self):
        return self._instance_id

    @property
    def logon_id(self):
        return self._logon_id

    def _check_open(self):
        if self._creator_pid != os.getpid():
            raise NativePolicyMutexError("policy_mutex_foreign_process")
        if self._handle is None:
            raise NativePolicyMutexError("policy_mutex_closed")

    def _wait(self, timeout_ms):
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 5000:
            raise NativePolicyMutexError("policy_mutex_timeout_invalid")
        owner = threading.current_thread()
        key = (owner, self._name)
        with self._state_lock:
            self._check_open()
            if self._owner is owner:
                raise NativePolicyMutexError("policy_mutex_recursive_entry")
            if self._waiting or self._owner is not None:
                raise NativePolicyMutexError("policy_mutex_busy")
            with _THREAD_NAMES_LOCK:
                if key in _THREAD_NAMES:
                    raise NativePolicyMutexError("policy_mutex_recursive_entry")
                _THREAD_NAMES.add(key)
            self._waiting = True
            handle = self._handle
        try:
            abandoned = self._api.wait(handle, timeout_ms)
            if type(abandoned) is not bool:
                raise NativePolicyMutexError("policy_mutex_wait_outcome_unknown")
        except BaseException as primary:
            if (isinstance(primary, NativePolicyMutexError) and
                    primary.reason in {"policy_mutex_timeout", "policy_mutex_wait_failed"}):
                with self._state_lock:
                    self._waiting = False
                    with _THREAD_NAMES_LOCK:
                        _THREAD_NAMES.discard(key)
            else:
                # An interruption may hide the return from a successful native
                # wait. Keep this handle quarantined: do not claim unowned,
                # release an uncertain owner or permit concurrent close/reuse.
                _cleanup_note(primary, "policy_mutex_wait_outcome_unknown", primary)
            raise
        with self._state_lock:
            self._waiting = False
            self._owner = owner
            self._owner_native_id = threading.get_native_id()
        return PolicyMutexLease(self._name, self._instance_id, self._logon_id, abandoned)

    def _release(self):
        with self._state_lock:
            self._check_open()
            if (self._waiting or self._owner is not threading.current_thread() or
                    self._owner_native_id != threading.get_native_id()):
                raise NativePolicyMutexError("policy_mutex_not_owner_thread")
            self._api.release(self._handle)
            with _THREAD_NAMES_LOCK:
                _THREAD_NAMES.discard((self._owner, self._name))
            self._owner = None
            self._owner_native_id = None

    @contextmanager
    def acquire(self, timeout_ms: int = 250):
        """Wait 0..5000 OS-wait milliseconds; retain ownership through the body.

        Modern Windows excludes low-power time from this native wait timeout;
        the value does not promise wall-clock completion during sleep/stalls.
        """
        lease = self._wait(timeout_ms)
        try:
            yield lease
        except BaseException as primary:
            try:
                self._release()
            except BaseException as cleanup:
                _cleanup_note(primary, "policy_mutex_release_failed", cleanup)
            raise
        else:
            self._release()

    def close(self):
        with self._state_lock:
            if self._handle is None:
                return
            self._check_open()
            if self._waiting or self._owner is not None:
                raise NativePolicyMutexError("policy_mutex_busy")
            self._api.close(self._handle)
            self._handle = None

    def __enter__(self):
        with self._state_lock:
            self._check_open()
        return self

    def __exit__(self, kind, primary, tb):
        if primary is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException as cleanup:
                _cleanup_note(primary, "policy_mutex_handle_close_failed", cleanup)
        return False
