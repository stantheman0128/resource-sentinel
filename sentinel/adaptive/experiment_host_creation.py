"""Original child-creation custody for a ProductionExperimentScope.

This is not a general launcher or a serializable capability. The original scope
registers an attempt before any native entry and supplies the fixed inert child
command. Its gate owns readiness, durable pending exclusion, POLICY and release
ordering. This module proves only creation/handle custody, never Job emptiness,
role authentication, allocation completion or release of the daily reservation.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import ntpath
import os
import threading

from .contracts import IdentityStatus
from .identity import VerifiedProcess, retry_identity_cleanup
from .supervisor_host import _ProcessInformation, _StartupInfoW, quote_argument


class CreationCustodyError(RuntimeError):
    def __init__(self, reason, owner=None, win32_error=None):
        self.reason = "production_creation_" + reason
        self.creation_attempt = owner
        self.win32_error = win32_error
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise CreationCustodyError(reason, owner)


@dataclass(frozen=True, repr=False)
class ChildCommand:
    """Immutable command DATA. Possessing this value grants no native authority."""

    executable: str
    arguments: tuple[str, ...]
    cwd: str

    def __post_init__(self):
        if (type(self.executable) is not str or type(self.cwd) is not str or
                type(self.arguments) is not tuple or len(self.arguments) > 128 or
                any(type(value) is not str or "\0" in value
                    for value in (self.executable, self.cwd, *self.arguments)) or
                not ntpath.isabs(self.executable) or not ntpath.isabs(self.cwd)):
            _fail("command_invalid")
        text = " ".join(quote_argument(value) for value in (self.executable, *self.arguments))
        if len(text.encode("utf-16-le")) // 2 + 1 > 32767:
            _fail("command_too_long")


class _NativeCreation:
    """Fixed plain CreateProcessW binding; never a caller-supplied callback."""

    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            _fail("platform_unsupported")
        self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
        k.CreateProcessW.restype = C.c_int
        k.CreateProcessW.argtypes = [C.c_wchar_p, C.c_wchar_p, C.c_void_p,
            C.c_void_p, C.c_int, C.c_uint32, C.c_void_p, C.c_wchar_p,
            C.POINTER(_StartupInfoW), C.POINTER(_ProcessInformation)]
        k.CloseHandle.restype, k.CloseHandle.argtypes = C.c_int, [C.c_void_p]
        k.WaitForSingleObject.restype = C.c_uint32
        k.WaitForSingleObject.argtypes = [C.c_void_p, C.c_uint32]

    def create_into(self, attempt):
        arguments = (attempt.command.executable, attempt._command_buffer,
            None, None, False, 0, None, attempt.command.cwd,
            C.byref(attempt._startup), C.byref(attempt._info))
        # Recheck at the actual native boundary, after loading the fixed ABI.
        CreationAttempt._gate(attempt, attempt._scope)
        CreationAttempt._assert_launch_inputs(attempt)
        attempt._create_state = "unknown"
        attempt._create_entered = True
        return self.kernel.CreateProcessW(*arguments)

    def close(self, handle):
        return self.kernel.CloseHandle(handle)

    def wait(self, handle):
        value = self.kernel.WaitForSingleObject(handle, 0)
        if value == 0:
            return IdentityStatus.DEAD
        if value == 0x102:
            return IdentityStatus.ALIVE
        return IdentityStatus.UNKNOWN


_TOKEN = object()


class CreationAttempt:
    """One original member's single CreateProcess attempt, retained by its scope."""

    def __init__(self, *, _token=None):
        if _token is not _TOKEN:
            _fail("scope_factory_required")
        self._lock = threading.RLock()
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._create_state = "prepared"
        self._create_entered = False
        self._capture_state = "not_started"
        self._capture_error = None
        self._capture_cleanup_owners = ()
        self._capture_cleanup_closed = set()
        self._process = None
        self._process_pin = None
        self._backend = self._backend_original = None
        self._raw_pin = None
        self._process_closed = self._thread_closed = False
        self._process_close_unknown = self._thread_close_unknown = False
        self._native_settled = False
        self._duplicate_closed = False
        self._duplicate_close_unknown = False
        self._dead = False
        self._errors = []

    def __reduce__(self):
        raise TypeError("original_creation_attempt_not_serializable")

    @classmethod
    def _prepare(cls, scope, member, command):
        """Pure-memory original-scope factory; publish owner before native work."""
        from .experiment_host_scope import ProductionExperimentScope
        from .experiment_host_ledger import MemberClaim
        if cls is not CreationAttempt or type(scope) is not ProductionExperimentScope:
            _fail("original_scope_required")
        with scope._lock:
            ProductionExperimentScope._assert_ledger_original(scope, scope.demand, scope.spec)
            if (not scope._prepared or scope._sealed or type(member) is not MemberClaim or
                    not any(item is member for item in scope.plan.members) or
                    type(command) is not ChildCommand or member.member_id in scope._attempts):
                _fail("original_member_required")
            owner = cls(_token=_TOKEN)
            owner._scope = owner._scope_original = scope
            owner._attempts_original = scope._attempts
            owner.member = owner._member_original = member
            owner.command = owner._command_original = command
            owner._command_pin = (command.executable, command.arguments, command.cwd)
            owner._member_id = member.member_id
            owner._lock_original = owner._lock
            # These exact output objects are retained BEFORE any CreateProcess,
            # DuplicateHandle, native identity observation, or DLL loading.
            owner._info = owner._info_original = _ProcessInformation()
            owner._startup = owner._startup_original = _StartupInfoW()
            owner._startup.cb = C.sizeof(_StartupInfoW)
            owner._command_buffer = owner._buffer_original = C.create_unicode_buffer(
                " ".join(quote_argument(value) for value in (command.executable, *command.arguments)))
            owner._command_text = owner._command_buffer.value
            owner._startup_bytes = bytes(owner._startup)
            scope._attempts[member.member_id] = owner
            return owner

    @property
    def process(self):
        return self._process

    @property
    def never_created(self):
        return self._create_state == "never_created"

    @property
    def native_settled(self):
        return self._native_settled

    def _retain(self, error):
        if not any(item is error for item in self._errors):
            self._errors.append(error)
        error.creation_attempt = self
        from .experiment_host_scope import ProductionExperimentScope
        ProductionExperimentScope._retain(self._scope_original, error)

    def assert_original(self, scope):
        """Pure-memory provenance check, including unchanged raw output custody."""
        from .experiment_host_scope import ProductionExperimentScope
        if (type(self) is not CreationAttempt or type(scope) is not ProductionExperimentScope or
                scope is not self._scope_original or self._scope is not scope or
                scope._attempts is not self._attempts_original or
                scope._attempts.get(self._member_id) is not self or
                self.member is not self._member_original or self.member.member_id != self._member_id or
                not any(item is self.member for item in scope.plan.members) or
                self.command is not self._command_original or
                (self.command.executable, self.command.arguments, self.command.cwd) != self._command_pin or
                self._lock is not self._lock_original or self._pid != os.getpid() or
                self._thread is not threading.current_thread() or
                self._info is not self._info_original or self._startup is not self._startup_original or
                self._command_buffer is not self._buffer_original or
                self._backend is not self._backend_original or
                (self._backend is not None and type(self._backend) is not _NativeCreation)):
            _fail("original_attempt_required", self)
        ProductionExperimentScope._assert_ledger_original(scope, scope.demand, scope.spec)
        if self._raw_pin is not None and CreationAttempt._raw_values(self) != self._raw_pin:
            _fail("creation_output_changed", self)
        if self._process_pin is not None:
            process, backend, handle, lock, identity = self._process_pin
            if (self._process is not process or type(process) is not VerifiedProcess or
                    process._backend is not backend or process._lock is not lock or
                    process.identity is not identity or
                    (process._handle != (None if self._duplicate_closed else handle))):
                _fail("identity_owner_changed", self)
        elif self._process is not None:
            _fail("identity_capture_outcome_unknown", self)
        return self

    def _gate(self, scope):
        from .experiment_host_scope import ProductionExperimentScope
        CreationAttempt.assert_original(self, scope)
        # Class-dispatched: an instance callback cannot manufacture authority.
        ProductionExperimentScope._assert_creation_gate(scope, self)

    def _raw_values(self):
        return (self._info.hProcess, self._info.hThread,
                self._info.dwProcessId, self._info.dwThreadId)

    def _assert_launch_inputs(self):
        if (self._command_buffer.value != self._command_text or
                bytes(self._startup) != self._startup_bytes or
                CreationAttempt._raw_values(self) != (None, None, 0, 0)):
            _fail("native_inputs_changed", self)

    def create(self, scope):
        with self._lock:
            CreationAttempt._gate(self, scope)
            if self._create_state != "prepared" or self._native_settled:
                _fail("create_not_repeatable", self)
            # Retain the fixed backend before its constructor can enter native.
            self._backend = self._backend_original = object.__new__(_NativeCreation)
            try:
                _NativeCreation.__init__(self._backend)
                CreationAttempt._gate(self, scope)
                CreationAttempt._assert_launch_inputs(self)
                value = _NativeCreation.create_into(self._backend, self)
                raw = CreationAttempt._raw_values(self)
                if type(value) in (int, bool) and value == 0 and raw == (None, None, 0, 0):
                    self._create_state = "never_created"
                    _fail("create_failed", self)
                if (type(value) not in (int, bool) or not value or
                        any(type(handle) is not int or not 0 < handle < 1 << 63 for handle in raw[:2]) or
                        any(type(pid) is not int or not 0 < pid <= 0xFFFFFFFF for pid in raw[2:])):
                    _fail("create_outcome_unknown", self)
                self._raw_pin = raw
                self._create_state = "created"
                return self
            except BaseException as error:
                if self._create_state == "prepared" and not self._create_entered:
                    # The final readiness/input fence can refuse before native
                    # entry. Retire this attempt; do not retry it or invent an
                    # unknown child when CreateProcessW was never reached.
                    self._create_state = "never_created"
                self._retain(error)
                raise

    def capture_identity(self, scope):
        with self._lock:
            CreationAttempt._gate(self, scope)
            if (self._create_state != "created" or self._capture_state != "not_started" or
                    self._process_closed or self._process_close_unknown or self._native_settled):
                _fail("capture_not_repeatable", self)
            self._capture_state = "unknown"
            try:
                self._process = VerifiedProcess.duplicate_from_handle(self._raw_pin[0],
                    expected_pid=self._raw_pin[2], expected_logon_id=scope.process.identity.logon_id)
                process = self._process
                if type(process) is not VerifiedProcess:
                    _fail("identity_owner_invalid", self)
                self._process_pin = (process, process._backend, process._handle,
                                     process._lock, process.identity)
                self._capture_state = "captured"
                return process
            except BaseException as error:
                self._capture_error = error
                # The duplicate helper retains its preowned output on all native
                # uncertainty. Keep the whole error even after attached cleanup.
                owners = getattr(error, "_identity_handle_cleanup", ())
                self._capture_cleanup_owners = tuple((owner, owner._backend,
                    owner._handle, owner._lock) for owner in owners)
                if getattr(error, "_identity_capture_cleanup_complete", False) is True:
                    self._capture_state = "failed_settled"
                elif owners:
                    self._capture_state = "failed_retained"
                self._retain(error)
                raise

    def observe_exit(self, scope):
        with self._lock:
            CreationAttempt.assert_original(self, scope)
            if self._dead:
                return IdentityStatus.DEAD
            if self._create_state != "created" or self._process_closed or self._process_close_unknown:
                return IdentityStatus.UNKNOWN
            try:
                if self._process is not None:
                    if self._process._handle != self._process_pin[2] or self._process._close_outcome_unknown:
                        return IdentityStatus.UNKNOWN
                    value = self._process.observe().status
                else:
                    value = _NativeCreation.wait(self._backend, self._raw_pin[0])
                if value is IdentityStatus.DEAD:
                    self._dead = True
                return value if type(value) is IdentityStatus else IdentityStatus.UNKNOWN
            except BaseException as error:
                self._retain(error)
                raise

    def _close_raw(self, kind, handle):
        unknown, closed = "_" + kind + "_close_unknown", "_" + kind + "_closed"
        if getattr(self, unknown):
            _fail(kind + "_close_outcome_unknown", self)
        if getattr(self, closed):
            return
        setattr(self, unknown, True)
        value = _NativeCreation.close(self._backend, handle)
        if type(value) in (int, bool) and value == 0:
            setattr(self, unknown, False)  # positive FALSE: original is retryable
            _fail(kind + "_close_failed", self)
        if type(value) not in (int, bool) or not value:
            _fail(kind + "_close_outcome_unknown", self)
        setattr(self, closed, True)
        setattr(self, unknown, False)

    def settle_native(self, scope):
        """Retire original native custody only; never release any capacity."""
        with self._lock:
            CreationAttempt.assert_original(self, scope)
            if self._native_settled:
                return
            if self._create_state == "prepared" and not self._create_entered:
                self._create_state = "never_created"
            if self.never_created:
                self._native_settled = True
                return
            if self._create_state != "created" or CreationAttempt.observe_exit(self, scope) is not IdentityStatus.DEAD:
                _fail("actor_exit_unverified", self)
            failures = []
            if self._capture_error is not None:
                try:
                    # Empty cleanup alone is not proof: an interruption between
                    # a successful callee return and assignment can lose the
                    # returned owner without carrying any error attributes.
                    if (self._capture_state == "unknown" or
                            getattr(self._capture_error, "_identity_capture_nested_cleanup_unsettled", False)):
                        _fail("identity_capture_outcome_unknown", self)
                    for index, (owner, backend, handle, lock) in enumerate(self._capture_cleanup_owners):
                        if (owner._backend is not backend or owner._lock is not lock or
                                owner._handle != (None if index in self._capture_cleanup_closed else handle)):
                            _fail("identity_cleanup_owner_changed", self)
                    if any(not any(owner is pin[0] for pin in self._capture_cleanup_owners)
                           for owner in getattr(self._capture_error, "_identity_handle_cleanup", ())):
                        _fail("identity_cleanup_owner_changed", self)
                    try:
                        retry_identity_cleanup(self._capture_error)
                    finally:
                        # Independent successful cleanup remains acknowledged
                        # even when another retained duplicate is quarantined.
                        for index, (owner, *_) in enumerate(self._capture_cleanup_owners):
                            if (owner._handle is None and not owner._close_outcome_unknown and
                                    not getattr(owner, "_duplicate_outcome_unknown", False)):
                                self._capture_cleanup_closed.add(index)
                    if self._capture_state == "failed_retained":
                        if any(owner._handle is not None or owner._close_outcome_unknown or
                               getattr(owner, "_duplicate_outcome_unknown", False)
                               for owner, *_ in self._capture_cleanup_owners):
                            _fail("identity_capture_outcome_unknown", self)
                        self._capture_state = "failed_settled"
                except BaseException as error:
                    failures.append(error)
            if self._process is not None:
                try:
                    if self._duplicate_close_unknown:
                        _fail("duplicate_close_outcome_unknown", self)
                    if not self._duplicate_closed:
                        self._duplicate_close_unknown = True
                        try:
                            self._process.close()
                        except BaseException:
                            if (self._process._handle == self._process_pin[2] and
                                    not self._process._close_outcome_unknown):
                                self._duplicate_close_unknown = False
                            raise
                        self._duplicate_closed = True
                        self._duplicate_close_unknown = False
                except BaseException as error:
                    failures.append(error)
            for kind, handle in (("thread", self._raw_pin[1]), ("process", self._raw_pin[0])):
                try:
                    CreationAttempt._close_raw(self, kind, handle)
                except BaseException as error:
                    failures.append(error)
            if failures:
                for error in failures:
                    self._retain(error)
                raise failures[0]
            self._native_settled = True
