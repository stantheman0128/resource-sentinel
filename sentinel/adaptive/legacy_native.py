"""Retained native handles for the existing collector's mutation gate.

This backend is not authority to mutate. The caller must hold POLICY, verify
the current registry/exemptions, exclude managed Jobs/infrastructure, and apply
its batch deadline before calling a writer. No process is reopened by PID after
identity verification. Imports do not load DLLs, open handles or enable control.

Only existing priority/I/O/trim operations are represented. In particular,
ProcessIoPriority class 33 is the old collector's undocumented compatibility
operation, not a new adaptive actuator or a supported Windows capability claim.
No Job creation/assignment/control, process termination or fallback is present.

Cleanup ownership here covers the mutation handle, its identity duplicate and
the opened Job. Existing identity/security helpers also allocate token/security
buffers: their cleanup errors fail this operation closed, but those helpers do
not retain every failed allocation for retry or preserve every original error.
This module does not claim to repair that existing dependency limitation.

Win32 references checked against Microsoft documentation:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getpriorityclass
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setpriorityclass
https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-emptyworkingset
https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-openjobobjectw
https://learn.microsoft.com/en-us/windows/win32/api/jobapi/nf-jobapi-isprocessinjob
https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from functools import lru_cache
import os
import re
import threading
from uuid import UUID

from .contracts import IdentityStatus, ProcessIdentity
from .identity import IdentityUnavailable, VerifiedProcess, retry_identity_cleanup
from .native_job import JobAccess, NativeJob
from . import windows as _security


_DWORD, _BOOL, _HANDLE = C.c_uint32, C.c_int32, C.c_void_p
_PROCESS_QUERY_SYNC = 0x1000 | 0x100000
_PROCESS_SET_INFORMATION = 0x0200
_PROCESS_SET_QUOTA = 0x0100
_JOB_QUERY_READ_CONTROL = 0x0004 | 0x00020000
# Match Sentinel's existing protected single-ACE Job descriptor. This is the
# descriptor's allowed mask; OpenJobObject requests QUERY|READ_CONTROL only.
# Current Microsoft winnt.h includes JOB_OBJECT_IMPERSONATE (0x20) in ALL_ACCESS;
# the Learn access-rights table still lists the older 0x1F001F mask.
_JOB_DACL_ACCESS = 0x001F003F
_PRIORITIES = {"Idle": 0x40, "BelowNormal": 0x4000, "Normal": 0x20,
               "AboveNormal": 0x8000, "High": 0x80, "RealTime": 0x100}
_OPERATIONS = frozenset(("priority", "io_priority", "trim"))
_JOB_NAME = re.compile(r"Local\\ResourceSentinel\.Job\.([0-9a-f-]{36})\.([0-9a-f]{32})\Z")
_EXPERIMENT_JOB_NAME = re.compile(r"Local\\ResourceSentinel\.Test\.Job\.([0-9a-f]{32})\Z")


class NativeLegacyError(RuntimeError):
    """Sanitized failure; an error is never a successful write or absent Job."""
    def __init__(self, reason, win32_error=None, *, ntstatus=None):
        self.reason, self.win32_error, self.ntstatus = reason, win32_error, ntstatus
        super().__init__(reason)


def _check(success, reason):
    if not success:
        raise NativeLegacyError(reason, C.get_last_error())


def _retain(error, owner):
    pending = getattr(error, "_legacy_native_cleanup", ())
    if not any(item is owner for item in pending):
        error._legacy_native_cleanup = (*pending, owner)


def retry_legacy_cleanup(error):
    """Retry only failed handle cleanup retained on an earlier exception.

    This never repeats a mutation or opens a process/Job. Callers must retain
    the exception while cleanup is unresolved, including initialization errors.
    """
    for owner in getattr(error, "_legacy_native_cleanup", ()):
        owner.close()
    error._legacy_native_cleanup = ()
    retry_identity_cleanup(error)


def _security_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _security.NativePolicyMutexError as error:
        failure = NativeLegacyError("legacy_job_security_unavailable", error.win32_error)
        for note in getattr(error, "__notes__", ()):
            failure.add_note(note)
        raise failure from None


def _validate_logon(logon_id):
    match = _security._LOGON_SID.fullmatch(logon_id) if isinstance(logon_id, str) else None
    if match is None or any(int(part) > 0xFFFFFFFF for part in match.groups()):
        raise ValueError("legacy_logon_sid_required")


class _WindowsBackend:
    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise NativeLegacyError("legacy_native_platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        bind = _security._bind
        bind(k, "OpenProcess", _HANDLE, _DWORD, _BOOL, _DWORD)
        bind(k, "OpenJobObjectW", _HANDLE, _DWORD, _BOOL, C.c_wchar_p)
        bind(k, "CloseHandle", _BOOL, _HANDLE)
        bind(k, "GetPriorityClass", _DWORD, _HANDLE)
        bind(k, "SetPriorityClass", _BOOL, _HANDLE, _DWORD)
        bind(k, "IsProcessInJob", _BOOL, _HANDLE, _HANDLE, C.POINTER(_BOOL))
        bind(k, "K32EmptyWorkingSet", _BOOL, _HANDLE)
        # The old collector already invokes this undocumented information class.
        # Resolve only when explicitly used; its absence cannot disable the
        # other operations or trigger an alternative writer.
        self._nt_set = None

    def open_process(self, pid, access):
        handle = self.kernel.OpenProcess(access, False, pid)
        _check(handle, "legacy_process_open_failed")
        return handle

    def open_job(self, name, logon_id):
        handle = self.kernel.OpenJobObjectW(_JOB_QUERY_READ_CONTROL, False, name)
        _check(handle, "legacy_job_open_failed")
        return handle

    def verify_job(self, handle, logon_id):
        security = _security_call(_security._backend)
        owner_sid = _security_call(security.current_owner_sid)
        _security_call(security.verify_security, handle, logon_id, owner_sid,
                       access_mask=_JOB_DACL_ACCESS)

    def membership(self, process, job):
        result = _BOOL()
        _check(self.kernel.IsProcessInJob(process, job, C.byref(result)), "legacy_membership_unknown")
        return bool(result.value)

    def priority(self, handle):
        value = self.kernel.GetPriorityClass(handle)
        _check(value, "legacy_priority_query_failed")
        return value

    def set_priority(self, handle, value):
        _check(self.kernel.SetPriorityClass(handle, value), "legacy_priority_set_failed")

    def set_io_priority(self, handle, level):
        if self._nt_set is None:
            try:
                self._ntdll = C.WinDLL("ntdll", use_last_error=True)
                self._nt_set = _security._bind(self._ntdll, "NtSetInformationProcess", C.c_int32,
                                               _HANDLE, C.c_int32, C.c_void_p, _DWORD)
            except (OSError, AttributeError):
                raise NativeLegacyError("legacy_io_priority_unsupported") from None
        value = _DWORD(level)
        status = C.c_int32(self._nt_set(handle, 33, C.byref(value), C.sizeof(value))).value
        # NT_SUCCESS accepts success/informational values; warnings and errors
        # both have the sign bit set. GetLastError does not describe NTSTATUS.
        if status < 0:
            raise NativeLegacyError("legacy_io_priority_set_failed", ntstatus=status & 0xFFFFFFFF)

    def trim(self, handle):
        _check(self.kernel.K32EmptyWorkingSet(handle), "legacy_trim_failed")

    def close(self, handle):
        _check(self.kernel.CloseHandle(handle), "legacy_handle_close_failed")


@lru_cache(maxsize=1)
def _backend():
    return _WindowsBackend()


class NativeLegacyJob:
    """Retain an existing registered Job for membership queries only.

    Name format and ACL checks are not registry enrollment. The caller obtains
    this exact name/logon from its freshly authenticated registry under POLICY.
    """
    def __init__(self, backend, handle, name, logon_id):
        self._backend, self._handle = backend, handle
        self.name, self.logon_id = name, logon_id
        self._lock = threading.RLock()
        self._closing = False

    @classmethod
    def open(cls, name, logon_id):
        if type(name) is str and _EXPERIMENT_JOB_NAME.fullmatch(name):
            # Only the fresh daily experiment registry enrolls this namespace.
            # This opener contributes query custody, never registration/launch.
            return _NativeExperimentLegacyJob.open(name, logon_id)
        match = _JOB_NAME.fullmatch(name) if isinstance(name, str) else None
        if match is None:
            raise ValueError("legacy_registered_job_name_required")
        execution = UUID(match.group(1))
        if not execution.int or str(execution) != match.group(1):
            raise ValueError("legacy_registered_job_name_required")
        # ProcessIdentity alone permits general identifier text in this field;
        # opening a native object requires the exact Windows logon-SID form.
        _validate_logon(logon_id)
        backend = _backend()
        owner = cls(backend, backend.open_job(name, logon_id), name, logon_id)
        try:
            backend.verify_job(owner._handle, logon_id)
            return owner
        except BaseException as primary:
            try:
                owner.close()
            except BaseException:
                _retain(primary, owner)
                primary.add_note("legacy_job_initialization_cleanup_failed")
            raise

    @contextmanager
    def _borrow(self, logon_id):
        with self._lock:
            if self._closing or self._handle is None or self.logon_id != logon_id:
                raise NativeLegacyError("legacy_job_unavailable")
            yield self._handle

    def close(self):
        with self._lock:
            self._closing = True
            if self._handle is not None:
                try:
                    self._backend.close(self._handle)
                except BaseException as error:
                    _retain(error, self)
                    raise
                self._handle = None

    def __enter__(self):
        with self._borrow(self.logon_id):
            return self

    def __exit__(self, kind, primary, trace):
        try:
            self.close()
        except BaseException:
            if primary is None:
                raise
            _retain(primary, self)
            primary.add_note("legacy_job_cleanup_failed")


class _NativeExperimentLegacyJob(NativeLegacyJob):
    """Independently owned QUERY handle for a registered original test Job.

    Canonical NativeJob owns verification and uncertain-close quarantine. This
    adapter never adopts, duplicates by assignment, or closes a guardian handle.
    """
    def __init__(self, native):
        self._native = native
        self.name, self.logon_id = native.name, native.logon_sid
        self._lock = threading.RLock()
        self._closing = False

    @classmethod
    def open(cls, name, logon_id):
        match = _EXPERIMENT_JOB_NAME.fullmatch(name) if type(name) is str else None
        if match is None:
            raise ValueError("legacy_registered_test_job_name_required")
        _validate_logon(logon_id)
        # NativeJob.open verifies owner, exact protected DACL, namespace/nonce,
        # and noninheritance before returning its retained query-only owner.
        native = NativeJob.open(name, match.group(1), logon_id, access=JobAccess.QUERY)
        try:
            return cls(native)
        except BaseException as error:
            # A failed adapter allocation must retain the new native owner.
            owners = getattr(error, "_native_job_cleanup", ())
            if not any(owner is native for owner in owners):
                error._native_job_cleanup = (*owners, native)
            error.add_note("legacy_job_initialization_cleanup_failed")
            raise

    @contextmanager
    def _borrow(self, logon_id):
        with self._lock, self._native._lock:
            if self._closing or self.logon_id != logon_id:
                raise NativeLegacyError("legacy_job_unavailable")
            yield self._native.handle

    def close(self):
        with self._lock:
            self._closing = True
            try:
                self._native.close()
            except BaseException as error:
                _retain(error, self)
                raise


class NativeLegacyProcess:
    """Own a mutation handle and its verified limited-right identity duplicate.

    A failed close disables further observations/writes and retains failed
    ownership for retry. No finalizer silently retries or reopens the PID.
    """
    def __init__(self, backend, handle, expected, operations):
        self._backend, self._handle = backend, handle
        self._identity, self._operations = expected, operations
        self._verified = None
        self._lock = threading.RLock()
        self._closing = False

    @property
    def identity(self):
        return self._identity

    @classmethod
    def open(cls, expected, *, operations=_OPERATIONS):
        if not isinstance(expected, ProcessIdentity):
            raise TypeError("exact_process_identity_required")
        _validate_logon(expected.logon_id)
        if type(operations) not in (tuple, list, set, frozenset) or any(type(item) is not str for item in operations):
            raise ValueError("legacy_operations_invalid")
        operations = frozenset(operations)
        if not operations <= _OPERATIONS:
            raise ValueError("legacy_operations_invalid")
        access = _PROCESS_QUERY_SYNC
        if operations & {"priority", "io_priority"}:
            access |= _PROCESS_SET_INFORMATION
        if "trim" in operations:
            access |= _PROCESS_SET_QUOTA
        backend = _backend()
        owner = cls(backend, backend.open_process(expected.pid, access), expected, operations)
        try:
            owner._verified = VerifiedProcess.duplicate_from_handle(owner._handle,
                expected_pid=expected.pid, expected_logon_id=expected.logon_id)
            if owner._verified.identity != expected:
                raise NativeLegacyError("legacy_identity_mismatch")
            owner._require_alive()
            return owner
        except BaseException as primary:
            try:
                owner.close()
            except BaseException:
                _retain(primary, owner)
                primary.add_note("legacy_process_initialization_cleanup_failed")
            raise

    def _alive(self):
        if self._closing or self._handle is None or self._verified is None:
            return None
        observed = self._verified.observe()
        if observed.identity != self.identity:
            return None
        return {IdentityStatus.ALIVE: True, IdentityStatus.DEAD: False}.get(observed.status)

    def _require_alive(self):
        state = self._alive()
        if state is not True:
            raise NativeLegacyError("legacy_process_exited" if state is False else "legacy_identity_unavailable")

    def _require_operation(self, operation):
        if operation not in self._operations:
            raise NativeLegacyError("legacy_operation_not_opened")
        self._require_alive()

    def alive(self):
        """True/False/None; only a signaled exact retained process means False."""
        with self._lock:
            return self._alive()

    def is_in_job(self, job):
        """Tri-state membership on the retained mutation handle, never a PID."""
        if job is not None and not isinstance(job, NativeLegacyJob):
            raise TypeError("retained_legacy_job_required")
        with self._lock:
            if self._alive() is not True:
                return None
            try:
                if job is None:
                    result = self._backend.membership(self._handle, None)
                else:
                    with job._borrow(self.identity.logon_id) as handle:
                        result = self._backend.membership(self._handle, handle)
                return result if type(result) is bool and self._alive() is True else None
            except (NativeLegacyError, IdentityUnavailable):
                return None

    def priority(self):
        with self._lock:
            self._require_alive()
            value = self._backend.priority(self._handle)
            self._require_alive()
            for name, constant in _PRIORITIES.items():
                if type(value) is int and value == constant:
                    return name
            raise NativeLegacyError("legacy_priority_unknown")

    def set_priority(self, name):
        if not isinstance(name, str) or name not in _PRIORITIES:
            raise ValueError("legacy_priority_invalid")
        with self._lock:
            self._require_operation("priority")
            self._backend.set_priority(self._handle, _PRIORITIES[name])
            self._require_alive()
            if self._backend.priority(self._handle) != _PRIORITIES[name]:
                raise NativeLegacyError("legacy_priority_readback_mismatch")

    def set_io_priority(self, level):
        if type(level) is not int or level not in {1, 2}:
            raise ValueError("legacy_io_priority_invalid")
        with self._lock:
            self._require_operation("io_priority")
            self._backend.set_io_priority(self._handle, level)

    def trim(self):
        with self._lock:
            self._require_operation("trim")
            self._backend.trim(self._handle)

    def close(self):
        with self._lock:
            self._closing = True
            primary = None
            if self._verified is not None:
                try:
                    self._verified.close()
                    self._verified = None
                except BaseException as error:
                    primary = error
            # A failed duplicate close must not skip closing the mutation
            # handle. Keep each failed owner independently for a later retry.
            if self._handle is not None:
                try:
                    self._backend.close(self._handle)
                    self._handle = None
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note("legacy_mutation_handle_cleanup_failed")
            if primary is not None:
                _retain(primary, self)
                raise primary

    def __enter__(self):
        with self._lock:
            self._require_alive()
        return self

    def __exit__(self, kind, primary, trace):
        try:
            self.close()
        except BaseException:
            if primary is None:
                raise
            _retain(primary, self)
            primary.add_note("legacy_process_cleanup_failed")
