"""One native JOB_LIST launch with retained process and cleanup custody.

This is a mechanism, not enrollment/capability/admission authority. Its caller
must already hold an approved single-use launch claim and the exact owned Job
handle throughout this call. The S1 adapter retains its existing opt-in and
foreign-host gates; no production CLI or configuration enables this operation.
No Job is created and no post-start assignment is used: JOB_LIST associates the
process during creation. No process is suspended, terminated or retried.

The CreateProcess result handle is retained for identity, membership and exit.
Failed post-create verification or ancillary cleanup raises LaunchOutcomeUnknown
with that same owner. Closing a handle never proves the process or Job is empty.
DeleteProcThreadAttributeList is VOID: an exception makes its cleanup uncertain;
that allocation is quarantined, not blindly deleted a second time.

Native contracts:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-deleteprocthreadattributelist
"""
from __future__ import annotations

import ctypes as C
import math
import os
import re
import threading

from .identity import VerifiedProcess, retry_identity_cleanup


_DWORD, _BOOL, _HANDLE = C.c_uint32, C.c_int32, C.c_void_p
_INVALID_HANDLE = C.c_void_p(-1).value
_SID = re.compile(r"S-1-5-5-([0-9]{1,10})-([0-9]{1,10})")


class NativeLaunchError(RuntimeError):
    def __init__(self, reason, win32_error=None):
        self.reason, self.win32_error = reason, win32_error
        super().__init__(reason)


class LaunchOutcomeUnknown(RuntimeError):
    """No retry: creation may have occurred; retain this exact process owner."""
    def __init__(self, process, cause):
        self.process, self.cause = process, cause
        super().__init__("native_launch_outcome_unknown")


class _FileTime(C.Structure):
    _fields_ = [("dwLowDateTime", _DWORD), ("dwHighDateTime", _DWORD)]


class _StartupInfo(C.Structure):
    _fields_ = [("cb", _DWORD), ("lpReserved", C.c_wchar_p),
                ("lpDesktop", C.c_wchar_p), ("lpTitle", C.c_wchar_p),
                ("dwX", _DWORD), ("dwY", _DWORD), ("dwXSize", _DWORD),
                ("dwYSize", _DWORD), ("dwXCountChars", _DWORD),
                ("dwYCountChars", _DWORD), ("dwFillAttribute", _DWORD),
                ("dwFlags", _DWORD), ("wShowWindow", C.c_uint16),
                ("cbReserved2", C.c_uint16), ("lpReserved2", C.POINTER(C.c_ubyte)),
                ("hStdInput", _HANDLE), ("hStdOutput", _HANDLE), ("hStdError", _HANDLE)]


class _StartupInfoEx(C.Structure):
    _fields_ = [("StartupInfo", _StartupInfo), ("lpAttributeList", C.c_void_p)]


class _ProcessInfo(C.Structure):
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE),
                ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


def _handle(value):
    if isinstance(value, C.c_void_p):
        value = value.value
    if type(value) is not int or not 0 < value < 1 << (C.sizeof(C.c_void_p) * 8 - 1):
        raise ValueError("native_handle_invalid")
    return value


def _logon(value):
    match = _SID.fullmatch(value) if type(value) is str else None
    if match is None or any(int(part) > 0xFFFFFFFF for part in match.groups()):
        raise ValueError("native_logon_invalid")
    return value


def _bind(api, name, result, *args):
    function = getattr(api, name)
    function.restype, function.argtypes = result, args


class _WindowsBackend:
    """Real WinDLL by default; explicit in-process kernel seam for fixtures."""
    def __init__(self, *, kernel=None):
        if kernel is not None:
            self.kernel = kernel
            return
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise NativeLaunchError("native_launch_platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        ptr = C.c_void_p
        _bind(k, "GetCurrentProcess", _HANDLE)
        _bind(k, "GetStdHandle", _HANDLE, _DWORD)
        _bind(k, "DuplicateHandle", _BOOL, _HANDLE, _HANDLE, _HANDLE,
              C.POINTER(_HANDLE), _DWORD, _BOOL, _DWORD)
        _bind(k, "CloseHandle", _BOOL, _HANDLE)
        _bind(k, "InitializeProcThreadAttributeList", _BOOL, ptr, _DWORD, _DWORD, C.POINTER(C.c_size_t))
        _bind(k, "UpdateProcThreadAttribute", _BOOL, ptr, _DWORD, C.c_size_t, ptr, C.c_size_t, ptr, ptr)
        _bind(k, "DeleteProcThreadAttributeList", None, ptr)
        _bind(k, "CreateProcessW", _BOOL, C.c_wchar_p, C.c_wchar_p, ptr, ptr,
              _BOOL, _DWORD, ptr, C.c_wchar_p, C.POINTER(_StartupInfoEx), C.POINTER(_ProcessInfo))
        _bind(k, "GetProcessTimes", _BOOL, _HANDLE, *([C.POINTER(_FileTime)] * 4))
        _bind(k, "IsProcessInJob", _BOOL, _HANDLE, _HANDLE, C.POINTER(_BOOL))
        _bind(k, "WaitForSingleObject", _DWORD, _HANDLE, _DWORD)
        _bind(k, "GetExitCodeProcess", _BOOL, _HANDLE, C.POINTER(_DWORD))

    def check(self, result, stage):
        if not result:
            raise NativeLaunchError(stage, C.get_last_error())

    def close(self, handle):
        try:
            result = self.kernel.CloseHandle(handle)
        except BaseException as error:
            # A Python exception may arrive after native close succeeded. The
            # numeric handle could already be reused; never retry that value.
            error._native_close_outcome_unknown = True
            raise
        if not result:
            error = NativeLaunchError("native_handle_close_failed", C.get_last_error())
            error._known_native_close_failed = True
            raise error


def _remember(primary, secondary):
    primary.add_note("native_launch_cleanup_unverified")
    retained = getattr(primary, "_native_cleanup_errors", [])
    retained.append(secondary)
    primary._native_cleanup_errors = retained


class CreatedProcess:
    """Own only returned/duplicated handles; never reopen a PID or kill work."""
    def __init__(self, backend, expected_logon_id):
        self._backend, self._logon_id = backend, expected_logon_id
        self._lock = threading.RLock()
        self.handle, self.pid = None, 0
        self._thread = None
        self._stdio = []
        self._duplicate_uncertainty = []
        self._attributes = None
        self._attribute_values = None
        self._attributes_initialized = False
        self._attribute_initialization_uncertain = False
        self._attribute_cleanup_uncertain = False
        self._unknown_closes = set()
        self._closed_handles = set()
        self._identity_cleanup = []
        self._creation_outcome = "not_attempted"
        self._unverified_process_info = _ProcessInfo()
        self._closed = False

    def _live_handle(self):
        if self.handle is None:
            raise NativeLaunchError("created_process_handle_unavailable")
        if self.handle in self._unknown_closes or self.handle in self._closed_handles:
            raise NativeLaunchError("created_process_handle_quarantined")
        return self.handle

    def identity(self):
        with self._lock:
            values = [_FileTime() for _ in range(4)]
            self._backend.check(self._backend.kernel.GetProcessTimes(
                self._live_handle(), *(C.byref(value) for value in values)), "created_process_times_failed")
            birth = (values[0].dwHighDateTime << 32) | values[0].dwLowDateTime
            return {"pid": self.pid, "created_filetime_100ns": str(birth)}

    def full_identity(self, *, expected_logon_id):
        with self._lock:
            if _logon(expected_logon_id) != self._logon_id:
                raise NativeLaunchError("created_process_logon_mismatch")
            try:
                verified = VerifiedProcess.duplicate_from_handle(self._live_handle(),
                    expected_pid=self.pid, expected_logon_id=self._logon_id)
                observed = verified.identity
                verified.close()
                return observed
            except BaseException as error:
                self._identity_cleanup.append(error)
                raise

    def is_in_job(self, job):
        with self._lock:
            handle = _handle(job.handle)
            result = _BOOL()
            self._backend.check(self._backend.kernel.IsProcessInJob(
                self._live_handle(), handle, C.byref(result)), "created_process_membership_failed")
            return bool(result.value)

    def wait(self, timeout):
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or
                not 0 <= timeout <= 120):
            raise ValueError("native_wait_invalid")
        with self._lock:
            result = self._backend.kernel.WaitForSingleObject(self._live_handle(), int(math.ceil(timeout * 1000)))
            if result == 0:
                return True
            if result == 258:
                return False
            raise NativeLaunchError("created_process_wait_failed", C.get_last_error())

    def exit_code(self):
        with self._lock:
            if not self.wait(0):
                return None
            result = _DWORD()
            self._backend.check(self._backend.kernel.GetExitCodeProcess(
                self._live_handle(), C.byref(result)), "created_process_exit_failed")
            return int(result.value)

    def _cleanup_transient(self):
        errors = []
        if self._duplicate_uncertainty:
            errors.append(NativeLaunchError("stdio_duplicate_quarantined"))
        if self._thread is not None:
            try:
                self._close_handle(self._thread)
                self._thread = None
            except BaseException as error:
                errors.append(error)
        if self._attribute_initialization_uncertain:
            errors.append(NativeLaunchError("attribute_initialization_quarantined"))
        elif self._attributes_initialized:
            if self._attribute_cleanup_uncertain:
                errors.append(NativeLaunchError("attribute_cleanup_quarantined"))
            else:
                try:
                    self._backend.kernel.DeleteProcThreadAttributeList(self._attributes)
                    self._attributes_initialized = False
                    self._attributes = None
                    self._attribute_values = None
                except BaseException as error:
                    self._attribute_cleanup_uncertain = True
                    errors.append(error)
        else:
            self._attributes = None
            self._attribute_values = None
        for handle in tuple(self._stdio):
            try:
                self._close_handle(handle)
                self._stdio.remove(handle)
            except BaseException as error:
                errors.append(error)
        if errors:
            for error in errors[1:]:
                _remember(errors[0], error)
            raise errors[0]

    def _close_handle(self, handle):
        if handle in self._closed_handles:
            return  # Native close succeeded, but caller publication may have been interrupted.
        if handle in self._unknown_closes:
            raise NativeLaunchError("native_handle_close_quarantined")
        # Publish uncertainty before invoking native code, not only in its
        # exception handler. Interruption can occur after native success too.
        self._unknown_closes.add(handle)
        try:
            self._backend.close(handle)
        except BaseException as error:
            if getattr(error, "_known_native_close_failed", False):
                self._unknown_closes.discard(handle)
            raise
        self._closed_handles.add(handle)
        self._unknown_closes.discard(handle)

    def close(self):
        with self._lock:
            if self._closed:
                return
            errors = []
            try:
                self._cleanup_transient()
            except BaseException as error:
                errors.append(error)
            for error in tuple(self._identity_cleanup):
                try:
                    retry_identity_cleanup(error)
                    self._identity_cleanup.remove(error)
                except BaseException as failure:
                    errors.append(failure)
            if errors:
                for error in errors[1:]:
                    _remember(errors[0], error)
                errors[0].cleanup_owner = self
                raise errors[0]
            if self._creation_outcome in {"unknown", "created"} and self.handle is None:
                error = NativeLaunchError("created_process_handle_unavailable")
                error.cleanup_owner = self
                raise error
            if self.handle is not None:
                try:
                    self._close_handle(self.handle)
                except BaseException as error:
                    error.cleanup_owner = self
                    raise
                self.handle = None
            self._closed = True


def retry_launch_cleanup(error):
    """Explicit exact-resource cleanup only; never repeat launch or native Set."""
    owner = error.process if isinstance(error, LaunchOutcomeUnknown) else getattr(error, "cleanup_owner", None)
    if not isinstance(owner, CreatedProcess):
        raise ValueError("native_cleanup_owner_missing")
    owner.close()


def launch_in_job(job, application, command_line, *, cwd=None,
                  stdin_handle=None, stdout_handle=None, stderr_handle=None, backend=None):
    """Perform one native attempt; caller holds the Job and launch authority.

    ``backend`` is an explicit in-process fixture seam. No serialized readiness,
    environment switch or status file can construct authorization here. All
    post-create errors retain process custody, including failed cleanup after
    successful identity/membership checks. Uncertain creation is never retried.
    """
    job_handle, logon_id = _handle(job.handle), _logon(job.logon_sid)
    if type(application) is not str or not os.path.isabs(application) or "\x00" in application:
        raise ValueError("native_application_invalid")
    if type(command_line) is not str or "\x00" in command_line:
        raise ValueError("native_command_line_invalid")
    if cwd is not None and (type(cwd) is not str or not os.path.isabs(cwd) or "\x00" in cwd):
        raise ValueError("native_directory_invalid")
    # Reject unpaired/explicit surrogate code points without constructing an
    # exception that retains the private payload as UnicodeEncodeError.object.
    if any(0xD800 <= ord(char) <= 0xDFFF for value in (application, command_line, cwd or "") for char in value):
        raise ValueError("native_launch_encoding_invalid")
    if len(command_line.encode("utf-16-le")) // 2 + 1 > 32767:
        raise ValueError("native_command_line_too_large")
    backend = _WindowsBackend() if backend is None else backend
    owner = CreatedProcess(backend, logon_id)
    k, primary = backend.kernel, None
    info = owner._unverified_process_info  # Retain native outputs before entering CreateProcessW.
    try:
        for supplied, selector in zip((stdin_handle, stdout_handle, stderr_handle), (-10, -11, -12)):
            source = _handle(k.GetStdHandle(selector & 0xFFFFFFFF) if supplied is None else supplied)
            if source == job_handle:
                raise ValueError("job_handle_cannot_be_standard_io")
            copied = _HANDLE()
            owner._duplicate_uncertainty.append(copied)  # Publish custody before the native boundary.
            duplicated = k.DuplicateHandle(k.GetCurrentProcess(), source, k.GetCurrentProcess(),
                C.byref(copied), 0, True, 0x0002)
            if duplicated:
                owner._stdio.append(_handle(copied.value))
            owner._duplicate_uncertainty.remove(copied)
            backend.check(duplicated, "stdio_duplicate_failed")
        size = C.c_size_t()
        C.set_last_error(0)
        sized = k.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
        if sized or C.get_last_error() != 122 or not 0 < size.value <= 65536:
            raise NativeLaunchError("attribute_list_size_invalid", C.get_last_error())
        owner._attributes = C.create_string_buffer(size.value)
        owner._attribute_initialization_uncertain = True
        try:
            initialized = k.InitializeProcThreadAttributeList(owner._attributes, 2, 0, C.byref(size))
        except BaseException:
            raise
        if initialized:
            owner._attributes_initialized = True
        owner._attribute_initialization_uncertain = False
        backend.check(initialized, "attribute_list_initialize_failed")
        jobs, handles = (_HANDLE * 1)(job_handle), (_HANDLE * 3)(*owner._stdio)
        owner._attribute_values = (jobs, handles)  # lpValue lives through Delete, including quarantine.
        backend.check(k.UpdateProcThreadAttribute(owner._attributes, 0, 0x0002000D, jobs,
            C.sizeof(jobs), None, None), "job_list_attribute_failed")
        backend.check(k.UpdateProcThreadAttribute(owner._attributes, 0, 0x00020002, handles,
            C.sizeof(handles), None, None), "handle_list_attribute_failed")
        startup = _StartupInfoEx()
        startup.StartupInfo.cb = C.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x00000100
        startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = owner._stdio
        startup.lpAttributeList = C.cast(owner._attributes, C.c_void_p)
        mutable_command = C.create_unicode_buffer(command_line)
        owner._creation_outcome = "unknown"
        try:
            created = k.CreateProcessW(application, mutable_command, None, None, True,
                0x00080000, None, cwd, C.byref(startup), C.byref(info))
        except BaseException:
            # Keep the raw result privately, but unknown/undefined output cannot
            # authorize operations or closing a possibly unrelated handle value.
            owner._unverified_process_info = info
            raise
        owner._creation_outcome = "created" if created else "not_created"
        if created:
            owner.handle, owner.pid, owner._thread = info.hProcess, int(info.dwProcessId), info.hThread
        # On documented FALSE, PROCESS_INFORMATION has no ownership guarantee.
        # Never interpret its contents as handles to close or inspect.
        backend.check(created, "create_process_failed")
        _handle(owner.handle)
        _handle(owner._thread)
        if owner.pid <= 0:
            raise NativeLaunchError("created_process_pid_invalid")
        owner.full_identity(expected_logon_id=logon_id)
        # Retained original object, including the valid fast-exit case; no PID
        # reopen and no liveness assumption from successful identity alone.
        member = _BOOL()
        backend.check(k.IsProcessInJob(owner.handle, job_handle, C.byref(member)), "created_process_membership_failed")
        if not member.value:
            raise NativeLaunchError("created_process_membership_mismatch")
    except BaseException as error:
        primary = error
    try:
        owner._cleanup_transient()
    except BaseException as cleanup:
        if primary is None:
            primary = cleanup
        else:
            _remember(primary, cleanup)
    if primary is not None:
        if owner._creation_outcome in {"created", "unknown"}:
            raise LaunchOutcomeUnknown(owner, primary) from primary
        if (owner._thread is not None or owner._stdio or owner._attributes_initialized or
                owner._attribute_initialization_uncertain or owner._duplicate_uncertainty):
            primary.cleanup_owner = owner
        raise primary
    return owner
