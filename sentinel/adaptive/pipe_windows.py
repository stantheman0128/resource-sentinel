"""Local, single-instance overlapped Named Pipe transport; no dispatch or Jobs.

The protocol layer supplies bounded frames, exact expected identities, tokens,
idempotency and a response receipt before disconnect. Transport timeout never
proves that a request was not applied. No FlushFileBuffers, implicit retry of a
request, synchronous worker thread, PIPE_NOWAIT or arbitrary pipe path is used.

CancelIoEx only requests cancellation. The capped registry strongly owns every
pipe and pending OVERLAPPED/event/buffer until completion is positively known.
Unknown completion poisons the endpoint; bounded reaping observes the original
operation without reissuing it. No finalizer frees an outstanding I/O buffer.

Native waits exclude sleep; deadlines use sleep-inclusive GetTickCount64 and
are checked after every completion. Waits use short finite slices. Scheduling,
kernel API stalls and sleep cannot provide a hard wall-clock completion bound.
In particular, local CreateFileW has no cancellable open/deadline parameter.

Microsoft API references:
https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getoverlappedresultex
https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
from functools import lru_cache
import os
import threading
from uuid import UUID

from .contracts import IdentityStatus, ProcessIdentity
from .identity import IdentityUnavailable, VerifiedProcess
from . import windows as _security


MAX_TRANSFER = 256 * 1024 + 4
_PIPE_ACCESS = 0x0012019F  # FILE_GENERIC_READ | FILE_GENERIC_WRITE (includes instance creation).
_CLIENT_ACCESS = 0x00120083  # SYNCHRONIZE | READ_CONTROL | READ_ATTRIBUTES | READ/WRITE_DATA.
_INVALID_HANDLE = C.c_void_p(-1).value
_DWORD, _HANDLE, _BOOL = C.c_uint32, C.c_void_p, C.c_int32
_SLICE_MS = 25
_DEADLINE_KEY = object()
_REGISTRY_LOCK = threading.Lock()
_PROCESS_RESOURCES = {}


class NativePipeError(RuntimeError):
    """Sanitized transport failure, never lifecycle/launch authority."""
    def __init__(self, reason, win32_error=None, *, io_pending=False):
        self.reason = reason
        self.win32_error = win32_error
        self.io_pending = io_pending
        super().__init__(reason)


def _check(success, reason):
    if not success:
        raise NativePipeError(reason, C.get_last_error())


def _native_security(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except _security.NativePolicyMutexError as error:
        raise NativePipeError(error.reason.replace("policy_mutex_", "pipe_", 1), error.win32_error) from None


def _close_identity(process):
    try:
        process.close()
    except IdentityUnavailable as error:
        raise NativePipeError("pipe_identity_close_failed", error.win32_error) from None


@dataclass(frozen=True)
class NativePipeEndpoint:
    logon_id: str
    instance_id: str
    server_identity: ProcessIdentity

    def __post_init__(self):
        match = _security._LOGON_SID.fullmatch(self.logon_id) if isinstance(self.logon_id, str) else None
        if match is None or any(int(value) > 0xFFFFFFFF for value in match.groups()):
            raise NativePipeError("pipe_logon_invalid")
        try:
            parsed = UUID(self.instance_id) if isinstance(self.instance_id, str) else None
            valid = parsed is not None and parsed.int != 0 and str(parsed) == self.instance_id
        except (ValueError, AttributeError):
            valid = False
        if not valid:
            raise NativePipeError("pipe_instance_invalid")
        if not isinstance(self.server_identity, ProcessIdentity) or self.server_identity.logon_id != self.logon_id:
            raise NativePipeError("pipe_server_identity_invalid")

    @property
    def name(self):
        return f"\\\\.\\pipe\\ResourceSentinel.IPC.{self.logon_id}.{self.instance_id}"


class NativeDeadline:
    """One process-local, sleep-inclusive deadline shared by all RPC phases."""
    def __init__(self, api, start, duration, key=None):
        if key is not _DEADLINE_KEY:
            raise NativePipeError("pipe_deadline_factory_required")
        self._api, self._start, self._end = api, start, start + duration
        self._pid = os.getpid()

    @classmethod
    def after_ms(cls, timeout_ms):
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 5000:
            raise NativePipeError("pipe_deadline_invalid")
        api = _backend()
        return cls(api, api.tick_ms(), timeout_ms, _DEADLINE_KEY)

    def remaining_ms(self):
        if self._pid != os.getpid():
            raise NativePipeError("pipe_foreign_process")
        now = self._api.tick_ms()
        if type(now) is not int or now < self._start:
            raise NativePipeError("pipe_clock_invalid")
        return max(0, self._end - now)

    def require(self):
        remaining = self.remaining_ms()
        if remaining <= 0:
            raise NativePipeError("pipe_timeout")
        return remaining


def _deadline(value):
    if not isinstance(value, NativeDeadline):
        raise NativePipeError("pipe_deadline_required")
    return value


class _Overlapped(C.Structure):
    _fields_ = [("internal", C.c_size_t), ("internal_high", C.c_size_t),
                ("offset", _DWORD), ("offset_high", _DWORD), ("event", _HANDLE)]


class _Operation:
    """Private non-repr storage retained before any native I/O can reference it."""
    def __init__(self, kind, size=0, payload=None):
        self.kind, self.size = kind, size
        self.buffer = C.create_string_buffer(size) if size else None
        if payload is not None:
            C.memmove(self.buffer, payload, size)
        self.overlapped = _Overlapped()
        self.transferred = _DWORD()
        self.event = None
        self.started = False
        self.completed = False
        self.error = None


class _WindowsPipeBackend:
    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8 or C.sizeof(_Overlapped) != 32:
            raise NativePipeError("pipe_platform_unsupported")
        self.security = _native_security(_security._backend)
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        bind, ptr = _security._bind, C.c_void_p
        bind(k, "CreateNamedPipeW", _HANDLE, C.c_wchar_p, *([_DWORD] * 6), C.POINTER(_security._SecurityAttributes))
        bind(k, "CreateFileW", _HANDLE, C.c_wchar_p, _DWORD, _DWORD, ptr, _DWORD, _DWORD, _HANDLE)
        bind(k, "WaitNamedPipeW", _BOOL, C.c_wchar_p, _DWORD)
        bind(k, "ConnectNamedPipe", _BOOL, _HANDLE, C.POINTER(_Overlapped))
        bind(k, "DisconnectNamedPipe", _BOOL, _HANDLE)
        bind(k, "CreateEventW", _HANDLE, ptr, _BOOL, _BOOL, C.c_wchar_p)
        bind(k, "ReadFile", _BOOL, _HANDLE, ptr, _DWORD, C.POINTER(_DWORD), C.POINTER(_Overlapped))
        bind(k, "WriteFile", _BOOL, _HANDLE, ptr, _DWORD, C.POINTER(_DWORD), C.POINTER(_Overlapped))
        bind(k, "GetOverlappedResultEx", _BOOL, _HANDLE, C.POINTER(_Overlapped), C.POINTER(_DWORD), _DWORD, _BOOL)
        bind(k, "CancelIoEx", _BOOL, _HANDLE, C.POINTER(_Overlapped))
        bind(k, "CloseHandle", _BOOL, _HANDLE)
        bind(k, "GetTickCount64", C.c_uint64)
        bind(k, "GetNamedPipeClientProcessId", _BOOL, _HANDLE, C.POINTER(_DWORD))
        bind(k, "GetNamedPipeServerProcessId", _BOOL, _HANDLE, C.POINTER(_DWORD))

    def tick_ms(self):
        return int(self.kernel.GetTickCount64())

    def close(self, handle):
        _check(self.kernel.CloseHandle(handle), "pipe_handle_close_failed")

    def create_event(self):
        handle = self.kernel.CreateEventW(None, True, False, None)
        _check(handle, "pipe_event_create_failed")
        return handle

    def owner_sid(self):
        return _native_security(self.security.current_owner_sid)

    def verify_security(self, handle, endpoint):
        _native_security(self.security.verify_security, handle, endpoint.logon_id,
                         self.owner_sid(), access_mask=_PIPE_ACCESS)

    def create_listener(self, endpoint, owner):
        descriptor = C.c_void_p()
        sddl = f"O:{self.owner_sid()}D:P(A;;0x{_PIPE_ACCESS:08x};;;{endpoint.logon_id})"
        _check(self.security.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, C.byref(descriptor), None), "pipe_security_build_failed")
        with _security._owned_resource(descriptor,
                lambda pointer: _native_security(self.security.free, pointer), "pipe_security_free_failed"):
            attributes = _security._SecurityAttributes(C.sizeof(_security._SecurityAttributes), descriptor, False)
            # Attach the created handle before readback/free can fail. The
            # registry retains this owner if subsequent close also fails.
            handle = self.kernel.CreateNamedPipeW(endpoint.name, 3 | 0x40000000 | 0x00080000,
                0x00000008, 1, 4096, 4096, 250, C.byref(attributes))
            if handle == _INVALID_HANDLE:
                handle = None
            owner._handle = handle
            _check(handle, "pipe_create_failed")
            self.verify_security(handle, endpoint)
        return handle

    def open_client(self, endpoint, deadline):
        while True:
            deadline.require()
            # Read/write data and query rights, without CREATE_PIPE_INSTANCE;
            # identification SQOS prevents implicit delegation/impersonation.
            handle = self.kernel.CreateFileW(endpoint.name, _CLIENT_ACCESS, 0, None, 3,
                                             0x40000000 | 0x00100000 | 0x00010000, None)
            if handle != _INVALID_HANDLE and handle is not None:
                return handle
            error = C.get_last_error()
            if error != 231:  # ERROR_PIPE_BUSY; absence does not spawn/retry a server.
                raise NativePipeError("pipe_open_failed", error)
            remaining = deadline.require()
            if not self.kernel.WaitNamedPipeW(endpoint.name, min(_SLICE_MS, remaining)):
                error = C.get_last_error()
                if error != 121:  # ERROR_SEM_TIMEOUT.
                    raise NativePipeError("pipe_wait_available_failed", error)

    def peer_pid(self, handle, server_end):
        pid = _DWORD()
        call = self.kernel.GetNamedPipeClientProcessId if server_end else self.kernel.GetNamedPipeServerProcessId
        _check(call(handle, C.byref(pid)), "pipe_peer_unavailable")
        if pid.value <= 0:
            raise NativePipeError("pipe_peer_invalid")
        return int(pid.value)

    def disconnect(self, handle):
        if not self.kernel.DisconnectNamedPipe(handle):
            error = C.get_last_error()
            if error != 233:  # Already disconnected, not evidence of process death.
                raise NativePipeError("pipe_disconnect_failed", error)

    def start(self, handle, operation):
        operation.started = True
        pointer = C.byref(operation.overlapped)
        if operation.kind == "connect":
            success = self.kernel.ConnectNamedPipe(handle, pointer)
        else:
            call = self.kernel.ReadFile if operation.kind == "read" else self.kernel.WriteFile
            success = call(handle, operation.buffer, operation.size, None, pointer)
        error = 0 if success else C.get_last_error()
        if operation.kind == "connect" and (success or error == 535):
            operation.completed = True  # ERROR_PIPE_CONNECTED is a valid early connection.
        elif success:
            operation.completed = True
            if not self.kernel.GetOverlappedResultEx(handle, pointer, C.byref(operation.transferred), 0, False):
                operation.error = C.get_last_error()
        elif error != 997:  # FALSE + ERROR_IO_PENDING is the sole pending start result.
            operation.completed, operation.error = True, error

    def observe(self, handle, operation, timeout_ms=0):
        if operation.completed:
            return True
        success = self.kernel.GetOverlappedResultEx(handle, C.byref(operation.overlapped),
            C.byref(operation.transferred), timeout_ms, False)
        error = 0 if success else C.get_last_error()
        if success or error in {995, 109, 232, 233, 38, 234}:
            operation.completed = True
            operation.error = None if success else error
            return True
        if error in {996, 258, 192}:  # INCOMPLETE, WAIT_TIMEOUT, IO_COMPLETION.
            return False
        # An unclassified query/API error is not proof that the original I/O
        # completed; retain the original storage for later observation.
        raise NativePipeError("pipe_completion_unavailable", error, io_pending=True)

    def cancel(self, handle, operation):
        if not self.kernel.CancelIoEx(handle, C.byref(operation.overlapped)):
            error = C.get_last_error()
            if error != 1168:  # NOT_FOUND is still followed by completion observation.
                raise NativePipeError("pipe_cancel_failed", error, io_pending=True)


@lru_cache(maxsize=1)
def _backend():
    return _WindowsPipeBackend()


@dataclass(frozen=True)
class PipeRegistryStatus:
    resources: int
    pending: int
    quarantined: int


class NativePipeRegistry:
    """Strong ownership, capped before allocation/issue; includes idle listeners.

    No background thread is created. Call reap from an existing bounded loop;
    unverified operations keep their slot and storage, including at shutdown.
    """
    def __init__(self, max_resources=128):
        if type(max_resources) is not int or not 1 <= max_resources <= 128:
            raise NativePipeError("pipe_registry_limit_invalid")
        self._limit, self._pid = max_resources, os.getpid()
        self._lock = threading.Lock()
        self._resources = {}
        self._cursor = 0

    def _retain(self, resource):
        with _REGISTRY_LOCK, self._lock:
            if self._pid != os.getpid():
                raise NativePipeError("pipe_foreign_process")
            if len(self._resources) >= self._limit or len(_PROCESS_RESOURCES) >= 128:
                raise NativePipeError("pipe_busy")
            self._resources[id(resource)] = resource
            _PROCESS_RESOURCES[id(resource)] = resource

    def _forget(self, resource):
        with _REGISTRY_LOCK, self._lock:
            self._resources.pop(id(resource), None)
            _PROCESS_RESOURCES.pop(id(resource), None)

    def status(self):
        with self._lock:
            values = tuple(self._resources.values())
        return PipeRegistryStatus(len(values), sum(item._operation is not None for item in values),
                                  sum(item._poisoned for item in values))

    def reap(self, deadline, max_ops=128):
        deadline = _deadline(deadline)
        if type(max_ops) is not int or not 1 <= max_ops <= 128:
            raise NativePipeError("pipe_reap_limit_invalid")
        with self._lock:
            values = tuple(self._resources.values())
            if values:
                cursor = self._cursor % len(values)
                values = values[cursor:] + values[:cursor]
                self._cursor = (cursor + min(max_ops, len(values))) % len(values)
        for resource in values[:max_ops]:
            if deadline.remaining_ms() <= 0:
                break
            resource._reap()
        return self.status()


_GLOBAL_REGISTRY = NativePipeRegistry()


class _PipeOwner:
    def __init__(self, endpoint, registry, server_end):
        if not isinstance(endpoint, NativePipeEndpoint):
            raise NativePipeError("pipe_endpoint_required")
        self.endpoint, self._server_end = endpoint, server_end
        self._api = _backend()
        self._registry = _GLOBAL_REGISTRY if registry is None else registry
        if not isinstance(self._registry, NativePipeRegistry):
            raise NativePipeError("pipe_registry_required")
        self._lock = threading.RLock()
        self._pid = os.getpid()
        self._handle = self._operation = self._active = self._server_process = None
        self._self_process = self._peer_process = None
        self._busy, self._poisoned, self._proofs = True, False, 0
        self._registry._retain(self)

    def _verify_current(self):
        try:
            current = self._self_process = VerifiedProcess.current()
            if (current.identity.pid != os.getpid() or current.identity.logon_id != self.endpoint.logon_id or
                    current.observe().status is not IdentityStatus.ALIVE or
                    (self._server_end and current.identity != self.endpoint.server_identity)):
                raise NativePipeError("pipe_current_identity_mismatch")
            _close_identity(current)
            self._self_process = None
        except IdentityUnavailable as error:
            raise NativePipeError("pipe_identity_unavailable", error.win32_error) from None

    def _check(self):
        if self._pid != os.getpid():
            raise NativePipeError("pipe_foreign_process")
        if self._handle is None:
            raise NativePipeError("pipe_closed")
        if self._poisoned:
            raise NativePipeError("pipe_quarantined", io_pending=self._operation is not None)

    @contextmanager
    def _using(self, connection=None):
        with self._lock:
            self._check()
            if self._busy or (connection is not None and self._active is not connection):
                raise NativePipeError("pipe_busy")
            self._busy = True
        try:
            yield
        finally:
            with self._lock:
                self._busy = False

    def _retire_operation(self):
        operation = self._operation
        if operation is None:
            return
        if not operation.completed:
            raise NativePipeError("pipe_io_pending", io_pending=True)
        if operation.event is not None:
            self._api.close(operation.event)
            operation.event = None
        self._operation = None

    def _run(self, kind, deadline, size=0, payload=None):
        deadline.require()
        operation = _Operation(kind, size, payload)
        # Registry already retains this owner. Attach every buffer before
        # event acquisition and before entering a call that can issue I/O.
        self._operation = operation
        try:
            operation.event = self._api.create_event()
            operation.overlapped.event = operation.event
            self._api.start(self._handle, operation)
            while not operation.completed:
                self._api.observe(self._handle, operation, min(_SLICE_MS, deadline.require()))
            deadline.require()  # Do not accept a completion arriving after sleep/deadline.
            if operation.error is not None:
                raise NativePipeError("pipe_io_failed", operation.error)
            count = int(operation.transferred.value)
            if kind != "connect" and not 0 < count <= size:
                raise NativePipeError("pipe_transfer_invalid")
            result = bytes(operation.buffer.raw[:count]) if kind == "read" else count
            self._retire_operation()
            return result
        except BaseException as primary:
            if not operation.started:
                operation.completed = True
            if not operation.completed:
                try:
                    self._api.cancel(self._handle, operation)
                except BaseException as cleanup:
                    _security._cleanup_note(primary, "pipe_cancel_failed", cleanup)
                try:
                    # Never append a new deadline to an expired request. A
                    # zero-time observation still handles cancellation races.
                    self._api.observe(self._handle, operation, min(_SLICE_MS, deadline.remaining_ms()))
                except BaseException as cleanup:
                    _security._cleanup_note(primary, "pipe_completion_unverified", cleanup)
            if operation.completed:
                try:
                    self._retire_operation()
                except BaseException as cleanup:
                    self._poisoned = True
                    _security._cleanup_note(primary, "pipe_event_close_failed", cleanup)
            else:
                self._poisoned = True
                _security._cleanup_note(primary, "pipe_io_outcome_unknown", primary)
                if isinstance(primary, NativePipeError):
                    primary.io_pending = True
            raise

    def _dispose(self):
        # Caller holds _lock, and must have exclusive access to this owner.
        if self._operation is not None or self._proofs:
            raise NativePipeError("pipe_io_pending", io_pending=self._operation is not None)
        if self._handle is not None:
            self._api.close(self._handle)
            self._handle = None
        if self._server_process is not None:
            _close_identity(self._server_process)
            self._server_process = None
        if self._self_process is not None:
            _close_identity(self._self_process)
            self._self_process = None
        if self._peer_process is not None:
            _close_identity(self._peer_process)
            self._peer_process = None
        if self._active is not None:
            self._active._closed = True
            self._active = None
        self._registry._forget(self)

    def _failed_initialization(self, primary):
        with self._lock:
            self._busy, self._poisoned = False, True
            try:
                self._dispose()
            except BaseException as cleanup:
                _security._cleanup_note(primary, "pipe_initialization_cleanup_failed", cleanup)

    def _reap(self):
        with self._lock:
            if self._pid != os.getpid() or self._busy or self._proofs or not self._poisoned:
                return
            self._busy = True
            try:
                if self._operation is not None:
                    if not self._api.observe(self._handle, self._operation, 0):
                        return
                    self._retire_operation()
                self._dispose()
            except (NativePipeError, IdentityUnavailable):
                # Remains counted/retained; status never claims successful cleanup.
                pass
            finally:
                self._busy = False


class NativePipeListener:
    """One reusable server instance, retained until explicit successful close.

    The connection borrower must finish its protocol receipt before disconnect.
    There is no internal request queue, worker pool, or automatic dispatcher.
    All calls must occur outside SQLite transactions and OS policy locks.
    """
    def __init__(self, endpoint, registry=None):
        if not isinstance(endpoint, NativePipeEndpoint):
            raise NativePipeError("pipe_endpoint_required")
        self.endpoint = endpoint
        owner = self._owner = _PipeOwner(endpoint, registry, True)
        try:
            owner._verify_current()
            owner._handle = owner._api.create_listener(endpoint, owner)
            owner._busy = False
        except BaseException as primary:
            owner._failed_initialization(primary)
            raise

    def accept(self, deadline):
        deadline = _deadline(deadline)
        owner = self._owner
        with owner._using():
            if owner._active is not None:
                raise NativePipeError("pipe_busy")
            try:
                owner._run("connect", deadline)
                connection = NativePipeConnection(owner)
                owner._active = connection
                return connection
            except BaseException as primary:
                if owner._operation is None and not owner._poisoned:
                    try:
                        owner._api.disconnect(owner._handle)
                    except BaseException as cleanup:
                        owner._poisoned = True
                        _security._cleanup_note(primary, "pipe_disconnect_failed", cleanup)
                raise

    def close(self):
        owner = self._owner
        with owner._lock:
            if owner._pid != os.getpid():
                raise NativePipeError("pipe_foreign_process")
            if owner._busy or owner._active is not None or owner._operation is not None or owner._proofs:
                raise NativePipeError("pipe_busy", io_pending=owner._operation is not None)
            try:
                owner._dispose()
            except BaseException:
                # Keep any remaining native handles reachable and eligible
                # for bounded reaping, including a partially completed close.
                owner._poisoned = True
                raise

    def __enter__(self):
        with self._owner._lock:
            self._owner._check()
        return self

    def __exit__(self, kind, primary, tb):
        if primary is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException as cleanup:
                _security._cleanup_note(primary, "pipe_listener_close_failed", cleanup)
        return False


class NativePipeConnection:
    """One borrowed server connection or one owned client connection.

    Expected server process handle stays retained throughout client lifetime.
    verified_peer holds an additional exact process handle and blocks pipe
    close/reuse through the caller's proof scope; it does not authorize an RPC.
    """
    def __init__(self, owner):
        self._owner, self._closed, self._failed = owner, False, False

    @classmethod
    def connect(cls, endpoint, deadline, registry=None):
        deadline = _deadline(deadline)
        if not isinstance(endpoint, NativePipeEndpoint):
            raise NativePipeError("pipe_endpoint_required")
        deadline.require()
        owner = _PipeOwner(endpoint, registry, False)
        try:
            owner._verify_current()
            owner._server_process = VerifiedProcess.open(endpoint.server_identity)
            if owner._server_process.observe().status is not IdentityStatus.ALIVE:
                raise NativePipeError("pipe_server_unavailable")
            owner._handle = owner._api.open_client(endpoint, deadline)
            owner._api.verify_security(owner._handle, endpoint)
            if (owner._api.peer_pid(owner._handle, False) != endpoint.server_identity.pid or
                    owner._server_process.observe().status is not IdentityStatus.ALIVE):
                raise NativePipeError("pipe_server_identity_mismatch")
            deadline.require()
            connection = cls(owner)
            owner._active, owner._busy = connection, False
            return connection
        except BaseException as primary:
            owner._failed_initialization(primary)
            if isinstance(primary, IdentityUnavailable):
                error = NativePipeError("pipe_identity_unavailable", primary.win32_error)
                for note in getattr(primary, "__notes__", ()):
                    error.add_note(note)
                raise error from None
            raise

    def _check(self):
        if self._closed:
            raise NativePipeError("pipe_connection_closed")
        if self._failed:
            raise NativePipeError("pipe_connection_failed")
        self._owner._check()
        server = self._owner._server_process
        if server is not None and server.observe().status is not IdentityStatus.ALIVE:
            raise NativePipeError("pipe_server_unavailable")

    def read_exact(self, size, deadline):
        if type(size) is not int or not 1 <= size <= MAX_TRANSFER:
            raise NativePipeError("pipe_size_invalid")
        deadline = _deadline(deadline)
        owner = self._owner
        with owner._using(self):
            self._check()
            try:
                result, offset = bytearray(size), 0
                while offset < size:
                    part = owner._run("read", deadline, size - offset)
                    result[offset:offset + len(part)] = part
                    offset += len(part)
                deadline.require()
                return bytes(result)
            except BaseException:
                self._failed = True
                raise

    def write_all(self, payload, deadline):
        if type(payload) is not bytes or not 1 <= len(payload) <= MAX_TRANSFER:
            raise NativePipeError("pipe_size_invalid")
        deadline = _deadline(deadline)
        owner = self._owner
        with owner._using(self):
            self._check()
            try:
                offset = 0
                while offset < len(payload):
                    offset += owner._run("write", deadline, len(payload) - offset, payload[offset:])
                deadline.require()
            except BaseException:
                self._failed = True
                raise

    def peer_pid(self):
        with self._owner._using(self):
            self._check()
            return self._owner._api.peer_pid(self._owner._handle, self._owner._server_end)

    @contextmanager
    def verified_peer(self, expected):
        if not isinstance(expected, ProcessIdentity) or expected.logon_id != self._owner.endpoint.logon_id:
            raise NativePipeError("pipe_peer_identity_invalid")
        owner, primary = self._owner, None
        with owner._lock:
            self._check()
            if owner._busy or owner._proofs or owner._active is not self:
                raise NativePipeError("pipe_busy")
            owner._proofs += 1
        try:
            if self.peer_pid() != expected.pid:
                raise NativePipeError("pipe_peer_identity_mismatch")
            try:
                process = owner._peer_process = VerifiedProcess.open(expected)
            except IdentityUnavailable as error:
                raise NativePipeError("pipe_identity_unavailable", error.win32_error) from None
            if process.observe().status is not IdentityStatus.ALIVE or self.peer_pid() != expected.pid:
                raise NativePipeError("pipe_peer_identity_mismatch")
            yield process
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if owner._peer_process is not None:
                    owner._peer_process.close()
                    owner._peer_process = None
            except BaseException as cleanup:
                owner._poisoned = True
                if primary is None:
                    raise NativePipeError("pipe_peer_close_failed", getattr(cleanup, "win32_error", None)) from None
                _security._cleanup_note(primary, "pipe_peer_close_failed", cleanup)
            finally:
                with owner._lock:
                    owner._proofs -= 1

    def close(self):
        if self._closed:
            return
        owner = self._owner
        with owner._lock:
            if owner._pid != os.getpid():
                raise NativePipeError("pipe_foreign_process")
            if owner._busy or owner._proofs or owner._operation is not None:
                raise NativePipeError("pipe_busy", io_pending=owner._operation is not None)
            if owner._active is not self:
                raise NativePipeError("pipe_connection_closed")
            try:
                if owner._server_end and not owner._poisoned:
                    owner._api.disconnect(owner._handle)
                    owner._active, self._closed = None, True
                else:
                    owner._dispose()
            except BaseException:
                # An abandoned borrower can otherwise leave a retained but
                # permanently busy listener. Poison before propagating the
                # original failure; only reap/close may retire its resources.
                owner._poisoned = True
                raise

    def __enter__(self):
        with self._owner._lock:
            self._check()
        return self

    def __exit__(self, kind, primary, tb):
        if primary is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException as cleanup:
                _security._cleanup_note(primary, "pipe_connection_close_failed", cleanup)
        return False
