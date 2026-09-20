"""Read-only native process identity, retained for same-handle observations.

An identity proves which process was observed, not who sent an IPC request or
who owns an allocation. This module neither enrolls work nor enables a P1 gate.
No float epoch, PID-only fallback, process enumeration or control API is used.
VerifiedProcess handles are limited to QUERY_LIMITED_INFORMATION | SYNCHRONIZE.
Cross-process transfer briefly opens a separately owned exact source-process
handle with PROCESS_DUP_HANDLE as well. It never changes normal handle rights.
The caller must retain the context until its decision completes; a snapshot is
not a launch fence or authenticated IPC peer proof.
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


def _retain_cleanup(error, owner):
    """Retain ownership on a failure without replacing its original reason."""
    pending = getattr(error, "_identity_handle_cleanup", ())
    if not any(item is owner for item in pending):
        error._identity_handle_cleanup = (*pending, owner)


def retry_identity_cleanup(error: BaseException) -> None:
    """Retry handles retained by a failed identity operation, never its source.

    A failed close leaves its owner attached to the original exception. Only a
    known FALSE result can be retried. An uncertain completion is quarantined:
    the numeric handle may already belong to a different object. Successful
    earlier closes are idempotent. One quarantined owner must not prevent the
    independent cleanup of another known handle. This grants no identity or
    authority to any unresolved owner.
    """
    first_error = None
    unresolved = []
    for owner in getattr(error, "_identity_handle_cleanup", ()):
        try:
            owner.close()
        except BaseException as failure:
            if first_error is None:
                first_error = failure
            unresolved.append(owner)
    error._identity_handle_cleanup = tuple(unresolved)
    if first_error is not None:
        for owner in unresolved:
            _retain_cleanup(first_error, owner)
        raise first_error


def _known_close_failure(error):
    # These existing backend errors represent explicit failed Win32 results.
    # Retain compatibility with the original portable backend's close_unavailable
    # reason; the real backend always emits process_handle_close_failed for FALSE.
    # An exception raised by the native invocation overrides this with unknown,
    # even when that exception happens to be IdentityUnavailable itself.
    return (isinstance(error, IdentityUnavailable)
            and error.reason in {"process_handle_close_failed", "close_unavailable"}
            and not getattr(error, "_native_close_outcome_unknown", False)
            and (getattr(error, "_native_close_failed", False) is True or
                 (type(error.win32_error) is int and 0 < error.win32_error <= 0xFFFFFFFF)))


def _close_retained(owner):
    """Close under the owner's lock; never reuse an uncertain numeric handle."""
    if owner._close_outcome_unknown:
        error = IdentityUnavailable("process_handle_close_outcome_unknown")
        error._native_close_outcome_unknown = True
        _retain_cleanup(error, owner)
        raise error
    if owner._handle is None:
        return
    # Publish quarantine before native entry, covering an interruption after a
    # successful CloseHandle but before local ownership can be retired.
    owner._close_outcome_unknown = True
    try:
        owner._backend.close(owner._handle)
    except BaseException as error:
        if _known_close_failure(error):
            owner._close_outcome_unknown = False
        else:
            error._native_close_outcome_unknown = True
        _retain_cleanup(error, owner)
        raise
    try:
        owner._handle = None
        owner._close_outcome_unknown = False
    except BaseException as error:
        error._native_close_outcome_unknown = True
        _retain_cleanup(error, owner)
        raise


class _DuplicateCleanup:
    """Own only the newly opened/duplicated handle until identity is verified."""

    def __init__(self, backend, handle):
        self._backend, self._handle = backend, handle
        self._lock = threading.Lock()
        self._close_outcome_unknown = False

    def close(self):
        with self._lock:
            _close_retained(self)


class _TransferDuplicate(_DuplicateCleanup):
    """Own the output cell before DuplicateHandle can publish a local handle.

    An invocation exception or invalid completion leaves the output quarantined.
    A nonzero output on explicit FALSE is not documented ownership evidence;
    never close it speculatively. Keeping this owner records unresolved custody.
    """

    def __init__(self, backend):
        super().__init__(backend, None)
        self._output = _HANDLE()
        self._duplicate_outcome_unknown = True

    def acquire(self, locator, *, source_process=None):
        try:
            self._backend.duplicate_into(locator, self._output,
                                         source_process=source_process)
        except BaseException as error:
            if (getattr(error, "_native_duplicate_failed", False) is True
                    and self._output.value is None):
                self._duplicate_outcome_unknown = False
            else:
                error._native_duplicate_outcome_unknown = True
                _retain_cleanup(error, self)
            raise
        value = self._output.value
        if type(value) is not int or not 0 < value < 1 << (8 * C.sizeof(C.c_void_p) - 1):
            error = IdentityUnavailable("process_duplicate_outcome_unknown")
            error._native_duplicate_outcome_unknown = True
            _retain_cleanup(error, self)
            raise error
        self._handle = value
        self._duplicate_outcome_unknown = False

    def close(self):
        with self._lock:
            if self._duplicate_outcome_unknown:
                error = IdentityUnavailable("process_duplicate_outcome_unknown")
                error._native_duplicate_outcome_unknown = True
                _retain_cleanup(error, self)
                raise error
            _close_retained(self)


def _transfer_cleanup(primary, *owners):
    """Attempt known cleanup once; preserve the operation's original failure."""
    for owner in owners:
        if owner is None or any(item is owner for item in
                                getattr(primary, "_identity_handle_cleanup", ())):
            continue
        try:
            owner.close()
        except BaseException:
            _retain_cleanup(primary, owner)


_DWORD = C.c_uint32
_HANDLE = C.c_void_p
_BOOL = C.c_int32
_PROCESS_ACCESS = 0x1000 | 0x100000
_TRANSFER_SOURCE_ACCESS = _PROCESS_ACCESS | 0x0040
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
        _bind(k, "GetCurrentProcess", _HANDLE)
        _bind(k, "DuplicateHandle", _BOOL, _HANDLE, _HANDLE, _HANDLE,
              C.POINTER(_HANDLE), _DWORD, _BOOL, _DWORD)
        _bind(k, "GetProcessId", _DWORD, _HANDLE)
        _bind(k, "GetProcessTimes", _BOOL, _HANDLE, *([C.POINTER(_FileTime)] * 4))
        _bind(k, "WaitForSingleObject", _DWORD, _HANDLE, _DWORD)
        _bind(k, "GetExitCodeProcess", _BOOL, _HANDLE, C.POINTER(_DWORD))
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

    def open_transfer_source(self, pid):
        handle = self.kernel.OpenProcess(_TRANSFER_SOURCE_ACCESS, False, pid)
        _check(handle, "process_transfer_source_unavailable")
        return handle

    def duplicate_into(self, locator, output, *, source_process=None):
        current = self.kernel.GetCurrentProcess()
        source = current if source_process is None else source_process
        # Explicit bounded query rights; no inherited handle, SAME_ACCESS,
        # CLOSE_SOURCE or remote target handle is ever requested.
        result = self.kernel.DuplicateHandle(source, locator, current,
            C.byref(output), _PROCESS_ACCESS, False, 0)
        if not result:
            error = IdentityUnavailable("process_duplicate_unavailable", C.get_last_error())
            error._native_duplicate_failed = True
            raise error

    def duplicate_process(self, source_handle):
        copied = _HANDLE()
        current = self.kernel.GetCurrentProcess()
        # Options zero is essential: neither SAME_ACCESS nor CLOSE_SOURCE.
        # The borrowed source stays owned by the caller on success and failure.
        _check(self.kernel.DuplicateHandle(current, source_handle, current,
                                           C.byref(copied), _PROCESS_ACCESS, False, 0),
               "process_duplicate_unavailable")
        _check(copied.value, "process_duplicate_unavailable")
        return copied.value

    def close(self, handle):
        try:
            result = self.kernel.CloseHandle(handle)
        except BaseException as error:
            # Python/ctypes failure does not establish that CloseHandle failed.
            # Preserve its exception and tell retained owners never to reclose.
            error._native_close_outcome_unknown = True
            raise
        if not result:
            error = IdentityUnavailable("process_handle_close_failed", C.get_last_error())
            error._native_close_failed = True
            error._native_close_outcome_unknown = False
            raise error

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

    def exit_code(self, handle):
        code = _DWORD()
        _check(self.kernel.GetExitCodeProcess(handle, C.byref(code)),
               "process_exit_code_unavailable")
        return int(code.value)


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
        self._close_outcome_unknown = False

    @property
    def identity(self) -> ProcessIdentity:
        return self._identity

    @classmethod
    def _open(cls, pid, expected=None):
        backend = _backend()
        handle = backend.open_process(pid)
        owner = _DuplicateCleanup(backend, handle)
        try:
            observed = backend.identity(handle)
            if observed.pid != pid or (expected is not None and observed != expected):
                raise IdentityUnavailable("identity_mismatch")
            result = cls(backend, handle, observed)
            owner._handle = None
            return result
        except BaseException as error:
            try:
                owner.close()
            except BaseException:
                _retain_cleanup(error, owner)
            raise

    @classmethod
    def open(cls, expected: ProcessIdentity):
        if not isinstance(expected, ProcessIdentity):
            raise TypeError("exact_process_identity_required")
        return cls._open(expected.pid, expected)

    @classmethod
    def current(cls):
        return cls._open(os.getpid())

    def _require_transfer_source_locked(self):
        if self._close_outcome_unknown:
            raise IdentityUnavailable("process_handle_close_outcome_unknown")
        if self._handle is None:
            raise IdentityUnavailable("identity_handle_closed")
        try:
            alive = self._backend.wait(self._handle) is IdentityStatus.ALIVE
        except Exception:
            raise IdentityUnavailable("process_transfer_source_unverified") from None
        if not alive:
            raise IdentityUnavailable("process_transfer_source_unverified")

    def duplicate(self):
        """Retain this exact process independently of a borrowed scope.

        The caller still supplies authentication/provenance (for example an
        active verified_peer scope). This method grants no IPC or launch rights.
        Ordinary limited query rights are explicitly requested for the copy.
        A process can already be dead; this operation makes no liveness claim.
        """
        with self._lock:
            if self._close_outcome_unknown:
                raise IdentityUnavailable("process_handle_close_outcome_unknown")
            if self._handle is None:
                raise IdentityUnavailable("identity_handle_closed")
            copied = _TransferDuplicate(self._backend)
            result = None
            try:
                copied.acquire(self._handle)
                if self._backend.identity(copied._handle) != self.identity:
                    raise IdentityUnavailable("identity_mismatch")
                result = VerifiedProcess(self._backend, copied._handle, self.identity)
                copied._handle = None
                return result
            except BaseException as primary:
                # An interruption after retiring the temporary owner must keep
                # the newly constructed owner, even if return never completed.
                owner = result if result is not None and copied._handle is None else copied
                _transfer_cleanup(primary, owner)
                raise

    def duplicate_remote_handle(self, locator: int, *, expected: ProcessIdentity):
        """Copy one process handle from an independently authenticated peer.

        Invoke only while the transport's verified_peer scope is held. ``self``
        is that retained live peer, not a process selected by wire PID. Locator
        and expected identity are untrusted consistency inputs: the temporary
        DUP_HANDLE source is pinned to this peer's exact birth/logon, and the
        copied root must match all expected identity fields before publication.

        The root can already be dead; its PID is never reopened. Verify process
        type/identity before any wait on the copied locator, since an arbitrary
        locator could refer to a synchronization object. This does not establish
        creation provenance or Job membership; the guardian must verify those.
        On uncertain duplication or failed cleanup, preserve the exception and
        its retained cleanup owners. A quarantined output cannot be retried as
        a close or interpreted as a successful transfer.
        """
        if (type(locator) is not int or
                not 0 < locator < 1 << (8 * C.sizeof(C.c_void_p) - 1)):
            raise ValueError("invalid_remote_process_handle")
        if type(expected) is not ProcessIdentity:
            raise TypeError("exact_process_identity_required")
        if expected.logon_id != self.identity.logon_id:
            raise IdentityUnavailable("identity_mismatch")
        with self._lock:
            self._require_transfer_source_locked()
            source = copied = result = None
            try:
                # Only the independently retained peer PID may be reopened to
                # acquire DUP_HANDLE. It cannot replace the original evidence.
                handle = self._backend.open_transfer_source(self.identity.pid)
                source = _DuplicateCleanup(self._backend, handle)
                if self._backend.identity(handle) != self.identity:
                    raise IdentityUnavailable("identity_mismatch")
                if self._backend.wait(handle) is not IdentityStatus.ALIVE:
                    raise IdentityUnavailable("process_transfer_source_unverified")
                self._require_transfer_source_locked()
                copied = _TransferDuplicate(self._backend)
                copied.acquire(locator, source_process=handle)
                if self._backend.identity(copied._handle) != expected:
                    raise IdentityUnavailable("identity_mismatch")
                self._require_transfer_source_locked()
                if self._backend.wait(handle) is not IdentityStatus.ALIVE:
                    raise IdentityUnavailable("process_transfer_source_unverified")
                # Retire the stronger temporary capability before returning a
                # normal limited-right root owner; a close failure is not ACK.
                source.close()
                result = VerifiedProcess(self._backend, copied._handle, expected)
                copied._handle = None
                return result
            except BaseException as primary:
                owner = result if result is not None and copied._handle is None else copied
                _transfer_cleanup(primary, owner, source)
                raise

    @classmethod
    def duplicate_from_handle(cls, source_handle: int, *, expected_pid: int,
                              expected_logon_id: str):
        """Verify a borrowed process handle without reopening a reusable PID.

        The caller must keep the original real handle open and prevent concurrent
        close/reuse until duplication completes. Only a new noninheritable,
        limited-right duplicate is owned here. Expected fields are consistency
        checks, not proof of creation provenance or allocation ownership. A
        signaled process may still be identified; no liveness is inferred.

        On failure the original is untouched. If closing the duplicate also
        fails, retain the original exception and call retry_identity_cleanup
        for a known failure; uncertain close completion stays quarantined. No
        unverified VerifiedProcess is returned.
        """
        if (type(source_handle) is not int or
                not 0 < source_handle < 1 << (8 * C.sizeof(C.c_void_p) - 1)):
            raise ValueError("invalid_borrowed_process_handle")
        if type(expected_pid) is not int or not 0 < expected_pid <= 0xFFFFFFFF:
            raise ValueError("invalid_expected_pid")
        match = _LOGON_SID.fullmatch(expected_logon_id) if isinstance(expected_logon_id, str) else None
        if match is None or any(int(value) > 0xFFFFFFFF for value in match.groups()):
            raise ValueError("invalid_expected_logon_id")
        backend = _backend()
        handle = backend.duplicate_process(source_handle)
        owner = _DuplicateCleanup(backend, handle)
        try:
            observed = backend.identity(handle)
            if (observed.pid != expected_pid or
                    observed.logon_id != expected_logon_id):
                raise IdentityUnavailable("identity_mismatch")
            result = cls(backend, handle, observed)
            owner._handle = None  # ownership transfers only after verification
            return result
        except BaseException as error:
            try:
                owner.close()
            except BaseException:
                _retain_cleanup(error, owner)
            raise

    def observe(self) -> IdentityObservation:
        with self._lock:
            if self._close_outcome_unknown:
                return IdentityObservation(self.identity, IdentityStatus.UNKNOWN,
                                           "process_handle_close_outcome_unknown")
            if self._handle is None:
                return IdentityObservation(self.identity, IdentityStatus.UNKNOWN, "identity_handle_closed")
            try:
                return IdentityObservation(self.identity, self._backend.wait(self._handle))
            except IdentityUnavailable as error:
                return IdentityObservation(self.identity, IdentityStatus.UNKNOWN, error.reason)

    def exit_code(self) -> int:
        """Read an exited process's DWORD from the same retained exact handle.

        WaitForSingleObject must first confirm termination. The value 259 is
        then a legitimate exit code, not a liveness test. Limited query rights
        suffice for GetExitCodeProcess; SYNCHRONIZE supplies the prior wait.
        The owner lock prevents close/reuse across both native observations.
        This neither proves a Job empty nor authorizes releasing its capacity.
        """
        with self._lock:
            if self._close_outcome_unknown:
                error = IdentityUnavailable("process_handle_close_outcome_unknown")
                error._native_close_outcome_unknown = True
                _retain_cleanup(error, self)
                raise error
            if self._handle is None:
                raise IdentityUnavailable("identity_handle_closed")
            try:
                state = self._backend.wait(self._handle)
            except Exception:
                raise IdentityUnavailable("process_exit_unverified") from None
            if state is not IdentityStatus.DEAD:
                raise IdentityUnavailable("process_exit_unverified")
            try:
                code = self._backend.exit_code(self._handle)
            except Exception as error:
                win32 = getattr(error, "win32_error", None)
                if type(win32) is not int or not 0 <= win32 <= 0xFFFFFFFF:
                    win32 = None
                raise IdentityUnavailable("process_exit_code_unavailable", win32) from None
            if type(code) is not int or not 0 <= code <= 0xFFFFFFFF:
                raise IdentityUnavailable("process_exit_code_invalid")
            return code

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
            if self._handle is None or self._close_outcome_unknown:
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

    def query_owned_job_membership(self, job_handle: int) -> bool | None:
        """Query one held Job against this retained exact process, even exited.

        The trusted caller retains a real JOB_OBJECT_QUERY handle throughout.
        This reports only IsProcessInJob's current native result; it establishes
        neither liveness nor historical membership. False/unknown must not be
        inferred into a positive bind from root exit or expected Job metadata.
        Post-exit positive membership remains an empirical native gate.
        """
        if (type(job_handle) is not int or
                not 0 < job_handle < 1 << (8 * C.sizeof(C.c_void_p) - 1)):
            raise ValueError("invalid_job_handle")
        with self._lock:
            if self._handle is None or self._close_outcome_unknown:
                return None
            try:
                member = self._backend.membership(self._handle, job_handle)
                return member if type(member) is bool else None
            except Exception:
                return None

    def close(self):
        with self._lock:
            _close_retained(self)

    def __enter__(self):
        with self._lock:
            if self._close_outcome_unknown:
                error = IdentityUnavailable("process_handle_close_outcome_unknown")
                error._native_close_outcome_unknown = True
                _retain_cleanup(error, self)
                raise error
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
