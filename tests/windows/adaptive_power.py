"""Retained suspend/resume notification witness for isolated S1 recovery.

This observes notifications only: no sleep request, control, database, worker,
or readiness promotion. A stable token does not establish callback delivery
latency or satisfy the native P5 sleep/resume gate.

Official ABI references (Powrprof DWORD results, not User32 BOOL results):
https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification
https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerunregistersuspendresumenotification
https://learn.microsoft.com/en-us/windows/win32/api/powrprof/ns-powrprof-device_notify_subscribe_parameters
https://learn.microsoft.com/en-us/windows/win32/api/powrprof/nc-powrprof-device_notify_callback_routine
"""
from __future__ import annotations

import ctypes as C
from itertools import count
import os
import threading


_DWORD, _HANDLE = C.c_uint32, C.c_void_p
# CFUNCTYPE only permits portable explicit fixtures to build the same shape.
# The default native backend rejects non-Windows before loading any library.
_CALLBACK_TYPE = getattr(C, "WINFUNCTYPE", C.CFUNCTYPE)(_DWORD, _HANDLE, _DWORD, _HANDLE)
_EVENTS = frozenset({0x0004, 0x0007, 0x0012})  # suspend, resume, automatic resume
_CONTEXTS = count(1)
_RETAINED = {}


class PowerContinuityError(RuntimeError):
    def __init__(self, reason, error_code=None):
        self.reason, self.error_code = reason, error_code
        super().__init__(reason)


def _dispatch(context, event_type, setting):
    """Never dereference Context/Setting or let an exception cross the C ABI."""
    witness = None
    try:
        witness = _RETAINED.get(context)
        if witness is None:
            return 6  # ERROR_INVALID_HANDLE; a retired/unknown context is inert
        return witness._notification(event_type)
    except BaseException:
        if witness is not None:
            witness._faulted = True  # sticky, allocation-free failure marker
        return 31  # ERROR_GEN_FAILURE


# A callback may already be queued when unregister returns. The official API
# does not document an in-flight drain. Keep this trampoline for module lifetime
# and never reuse or dereference numeric contexts, even after a witness closes.
_CALLBACK = _CALLBACK_TYPE(_dispatch)


class _SubscribeParameters(C.Structure):
    _fields_ = [("Callback", _CALLBACK_TYPE), ("Context", _HANDLE)]


class _WindowsBackend:
    def __init__(self, *, dll=None):
        # An injected DLL is a private, explicit ABI-test seam, never a fallback.
        if dll is None:
            if os.name != "nt":
                raise PowerContinuityError("power_platform_unsupported")
            try:
                dll = C.WinDLL("Powrprof.dll", use_last_error=True)
            except (OSError, AttributeError):
                raise PowerContinuityError("power_api_unavailable") from None
        try:
            self._register = dll.PowerRegisterSuspendResumeNotification
            self._register.restype = _DWORD
            self._register.argtypes = [_DWORD, _HANDLE, C.POINTER(_HANDLE)]
            self._unregister = dll.PowerUnregisterSuspendResumeNotification
            self._unregister.restype = _DWORD
            self._unregister.argtypes = [_HANDLE]
        except AttributeError:
            raise PowerContinuityError("power_api_unavailable") from None
        self._dll = dll

    def register(self, parameters, registration):
        return int(self._register(2, C.cast(C.byref(parameters), _HANDLE), C.byref(registration)))

    def unregister(self, registration):
        # HPOWERNOTIFY is not a kernel HANDLE; never pass it to CloseHandle.
        return int(self._unregister(_HANDLE(registration)))


class NativePowerWitness:
    """Retain registration/callback state; tokens are in-process identities.

    Register before taking the recovery baseline. Every observed notification
    replaces the generation; callback uncertainty invalidates this witness.
    snapshot/assert_current perform no native I/O and never wait for a lock.
    close must run outside POLICY/Job/DB scopes. Failed unregister retains the
    exact registration and roots and invalidates tokens. Known nonzero DWORD
    failures can be retried; unknown unregister completion cannot safely reuse
    that opaque value and retains roots without another native unregister.
    """
    def __init__(self, backend):
        self._backend = backend
        self._registration = _HANDLE()
        self._context = next(_CONTEXTS)
        if self._context >= 1 << (8 * C.sizeof(_HANDLE)):
            raise PowerContinuityError("power_context_exhausted")
        self._parameters = _SubscribeParameters(_CALLBACK, self._context)
        self._generation = object()
        self._phase = "registering"
        self._faulted = False
        self._state_lock = threading.Lock()
        self._close_lock = threading.Lock()

    @classmethod
    def open(cls, *, backend=None):
        witness = cls(_WindowsBackend() if backend is None else backend)
        # Strong ownership begins before the API can call back, including a
        # callback delivered inline during registration or an uncertain return.
        _RETAINED[witness._context] = witness
        try:
            try:
                code = witness._backend.register(witness._parameters, witness._registration)
            except Exception:
                raise PowerContinuityError("power_registration_unavailable") from None
            if type(code) is not int or code != 0 or not witness._registration.value:
                failure = PowerContinuityError("power_registration_failed", code if type(code) is int else None)
                witness._failed_open(failure, known_failure=type(code) is int and code != 0)
                raise failure
            with witness._state_lock:
                failed = witness._faulted
                if not failed:
                    witness._phase = "active"
            if failed:
                failure = PowerContinuityError("power_callback_failed")
                witness._failed_open(failure, registered=True)
                raise failure
            return witness
        except BaseException as primary:
            if witness._context in _RETAINED:
                witness._faulted = True
                if witness._phase == "registering":
                    witness._phase = "registration_unknown"
                primary.power_witness = witness
            raise

    def _failed_open(self, failure, *, known_failure=False, registered=False):
        if registered:
            try:
                self.close()
            except BaseException:
                failure.add_note("power_registration_cleanup_failed")
                failure.power_witness = self
        elif known_failure and self._registration.value is None:
            self._phase, self._generation = "closed", None
            _RETAINED.pop(self._context, None)
            self._parameters = None
        else:
            # Output on a failed/unknown registration is not documented as an
            # owned registration. Likewise success without a handle cannot be
            # cleaned by guessing. Retain roots, never unregister such a value.
            self._faulted = True
            self._phase = "registration_unknown"
            failure.add_note("power_registration_outcome_unknown")
            failure.power_witness = self

    def _notification(self, event_type):
        # Callbacks do only bounded in-memory invalidation. Contention is an
        # observation failure, never a reason to block the notification thread.
        if not self._state_lock.acquire(blocking=False):
            self._faulted = True
            return 31
        try:
            if type(event_type) is not int or event_type not in _EVENTS:
                self._faulted = True
                return 87  # ERROR_INVALID_PARAMETER
            self._generation = object()
            return 0
        finally:
            self._state_lock.release()

    def _current(self, token=None, *, checking=False):
        if not self._state_lock.acquire(blocking=False):
            self._faulted = True
            raise PowerContinuityError("power_observation_contended")
        try:
            if self._faulted:
                raise PowerContinuityError("power_callback_failed")
            if self._phase != "active" or self._registration.value is None:
                raise PowerContinuityError("power_witness_unavailable")
            current = self._generation
            if current is None or (checking and token is not current):
                raise PowerContinuityError("power_continuity_changed")
            return current
        finally:
            self._state_lock.release()

    def snapshot(self):
        return self._current()

    def assert_current(self, token):
        self._current(token, checking=True)

    def close(self):
        with self._close_lock:
            with self._state_lock:
                if self._phase == "closed":
                    return
                if self._phase in {"registration_unknown", "unregister_unknown"}:
                    failure = PowerContinuityError("power_registration_outcome_unknown" if
                        self._phase == "registration_unknown" else "power_unregister_outcome_unknown")
                    failure.power_witness = self
                    raise failure
                # Until a validated failure or final retirement is published,
                # any interruption must prohibit reuse of this opaque value.
                self._phase, self._generation = "unregister_unknown", None
                registration = self._registration.value
            if registration is None:
                failure = PowerContinuityError("power_registration_outcome_unknown")
                failure.power_witness = self
                raise failure
            try:
                code = self._backend.unregister(registration)
            except BaseException as primary:
                self._faulted = True
                self._phase = "unregister_unknown"
                if not isinstance(primary, Exception):
                    primary.power_witness = self
                    raise
                failure = PowerContinuityError("power_unregister_outcome_unknown")
                failure.power_witness = self
                raise failure from None
            if type(code) is not int or code != 0:
                self._faulted = True
                unknown = type(code) is not int
                if unknown:
                    self._phase = "unregister_unknown"
                else:
                    self._phase = "closing"  # a positive failed result permits retry
                failure = PowerContinuityError("power_unregister_outcome_unknown" if unknown else "power_unregister_failed",
                                               code if type(code) is int else None)
                failure.power_witness = self
                raise failure
            with self._state_lock:
                self._phase, self._generation = "closed", None
                self._registration.value = None
                _RETAINED.pop(self._context, None)
                self._parameters = None

    def __enter__(self):
        self.snapshot()
        return self

    def __exit__(self, kind, error, traceback):
        if error is None:
            self.close()
        else:
            try:
                self.close()
            except BaseException:
                error.add_note("power_witness_cleanup_failed")
                error.power_witness = self
        return False
