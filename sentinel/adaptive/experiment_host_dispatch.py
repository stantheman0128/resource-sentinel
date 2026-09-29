"""Original parent listener for the four fixed experiment protocols.

There is no worker thread or callback registry: the original scope thread polls
and dispatches outside POLICY/SQL. A failed accept, constructor or native close
keeps the same listener and attempt reachable through the original scope.
"""
from __future__ import annotations

import os
import threading

from . import experiment_host_transport as child
from .contracts import ContractViolation
from .experiment_backing_transport import ExperimentBackingService
from .experiment_job_publication import ExperimentJobService
from .experiment_host_retirement_transport import ExperimentHostRetirementService
from .pipe_windows import NativeDeadline, NativePipeListener, NativePipeRegistry


class ProductionHostDispatcherError(child.ExperimentChildError):
    pass


def _fail(reason, owner=None):
    error = ProductionHostDispatcherError("experiment_dispatch_" + reason)
    error.experiment_host_dispatcher = owner
    raise error


_TOKEN = object()
_ORIGINALS = {}
_SERVICE_TYPES = (
    ("_transport_service", child.ExperimentChildService, "ExperimentChildHello"),
    ("_backing_service", ExperimentBackingService, "ExperimentBackingHello"),
    ("_job_service", ExperimentJobService, "ExperimentJobHello"),
    ("_retirement_service", ExperimentHostRetirementService, "ExperimentHostRetirementHello"),
)


class ProductionHostDispatcher:
    def __init__(self, owner, *, _token=None):
        if _token is not _TOKEN:
            _fail("original_factory_required")
        self.owner = owner
        self.endpoint = owner._transport_endpoint
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._registry = NativePipeRegistry()
        self._services = []
        self._services_pin = ()
        self._attempts = []
        self._errors = []
        self._listener = self._listener_owner = self._listener_pin = None
        self._listener_initialized = self._listener_closed = False
        self._opened = self._closing = self._closed = self._busy = False
        self._base_pin = (owner, self.endpoint, self._registry, self._services,
                          self._attempts, self._errors)
        _ORIGINALS[id(self)] = self

    def __reduce__(self):
        raise TypeError("production_dispatcher_not_serializable")

    @classmethod
    def open(cls, owner):
        from .experiment_host_scope import ProductionExperimentScope
        if cls is not ProductionHostDispatcher or type(owner) is not ProductionExperimentScope:
            _fail("original_scope_required")
        child._no_mutex()
        ProductionExperimentScope._assert_transport_original(owner, owner._transport_endpoint)
        if owner._host_dispatcher is not None:
            dispatcher = owner._host_dispatcher
            if type(dispatcher) is not cls:
                _fail("original_dispatcher_changed")
            dispatcher.assert_ready()
            return dispatcher
        dispatcher = cls(owner, _token=_TOKEN)
        # Register before service construction and, critically, before CreateNamedPipe.
        owner._host_dispatcher = dispatcher
        try:
            for attribute, service_type, _kind in _SERVICE_TYPES:
                service = getattr(owner, attribute)
                if service is None:
                    service = service_type.__new__(service_type)
                    dispatcher._services.append(service)
                    dispatcher._services_pin = tuple(dispatcher._services)
                    service_type.__init__(service, dispatcher.endpoint, owner)
                else:
                    if (type(service) is not service_type or service.owner is not owner or
                            service.endpoint is not dispatcher.endpoint or service.attempts):
                        _fail("original_service_required", dispatcher)
                    dispatcher._services.append(service)
                    dispatcher._services_pin = tuple(dispatcher._services)
            listener = NativePipeListener.__new__(NativePipeListener)
            dispatcher._listener = listener
            NativePipeListener.__init__(listener, dispatcher.endpoint, registry=dispatcher._registry)
            dispatcher._listener_initialized = True
            native = dispatcher._listener_owner = listener._owner
            dispatcher._listener_pin = (listener, native, native._api, native._registry, native._lock)
            dispatcher._opened = True
            dispatcher.assert_ready()
            return dispatcher
        except BaseException as error:
            dispatcher._errors.append(error)
            error.experiment_host_dispatcher = dispatcher
            raise

    def _original(self):
        owner, endpoint, registry, services, attempts, errors = self._base_pin
        if (type(self) is not ProductionHostDispatcher or _ORIGINALS.get(id(self)) is not self or
                owner._host_dispatcher is not self or self.owner is not owner or
                self.endpoint is not endpoint or owner._transport_endpoint is not endpoint or
                self._registry is not registry or self._services is not services or
                self._attempts is not attempts or self._errors is not errors or
                self._pid != os.getpid() or self._thread is not threading.current_thread() or
                len(services) != len(self._services_pin) or
                any(a is not b for a, b in zip(services, self._services_pin))):
            _fail("original_changed", self)
        for service, (attribute, service_type, _kind) in zip(services, _SERVICE_TYPES):
            if (type(service) is not service_type or getattr(owner, attribute) is not service or
                    service.owner is not owner or service.endpoint is not endpoint):
                _fail("original_service_changed", self)
        if self._listener_pin is not None:
            listener, native, api, native_registry, lock = self._listener_pin
            if (self._listener is not listener or listener._owner is not native or
                    self._listener_owner is not native or native._api is not api or
                    native._registry is not native_registry or native_registry is not registry or
                    native._lock is not lock or listener.endpoint is not endpoint or
                    native.endpoint is not endpoint):
                _fail("original_listener_changed", self)

    def assert_ready(self):
        from .experiment_host_scope import ProductionExperimentScope
        self._original()
        child._no_mutex()
        if (not self._opened or self._closing or self._closed or self._busy or
                not self._listener_initialized or len(self._services) != len(_SERVICE_TYPES)):
            _fail("listener_unavailable", self)
        if any(attempt.cleanup_pending for attempt in self._attempts):
            _fail("original_attempt_pending", self)
        ProductionExperimentScope._assert_transport_original(self.owner, self.endpoint)
        self._listener_owner._check()

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _new_attempt(self):
        if len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
            _fail("attempt_limit", self)
        attempt = child._Attempt()
        self._attempts.append(attempt)
        attempt.channel_origin = self._listener
        attempt.channel_started = True
        return attempt

    def _dispatch(self, connection, deadline, attempt):
        try:
            hello = child._read(connection, deadline, limit=child.MAX_HELLO_BYTES)
        except ContractViolation:
            _fail("hello_invalid", self)
        if type(hello) is not dict or type(hello.get("kind")) is not str:
            _fail("hello_invalid", self)
        for service, (_attribute, service_type, kind) in zip(self._services, _SERVICE_TYPES):
            if hello["kind"] == kind:
                # The concrete protocol verifies shape, peer, MAC and exact owner.
                service_type._serve_connection(service, connection, deadline, attempt, hello=hello)
                return
        _fail("protocol_unknown", self)

    def _consume(self, connection, deadline, attempt):
        with child._settled_scope(connection, attempt, "channel") as original:
            self._dispatch(original, deadline, attempt)
        attempt.channel_settled = True
        child._remaining(deadline)
        attempt.seal()

    def serve_once(self, *, timeout_ms=1000):
        self.assert_ready()
        child._timeout(timeout_ms)
        deadline = NativeDeadline.after_ms(timeout_ms)
        attempt = self._new_attempt()
        self._busy = True
        try:
            self._consume(self._listener.accept(deadline), deadline, attempt)
        except BaseException as error:
            attempt.fail(error)
            self._errors.append(error)
            error.experiment_host_dispatcher = self
            raise
        finally:
            self._busy = False

    def poll_once(self, *, timeout_ms=1000):
        """An idle original accept stays pending; it is neither failure nor exit."""
        self.assert_ready()
        child._timeout(timeout_ms)
        if len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
            _fail("attempt_limit", self)
        deadline = NativeDeadline.after_ms(timeout_ms)
        self._busy = True
        attempt = None
        try:
            connection = self._listener.poll_accept()
            if connection is None:
                return False
            attempt = self._new_attempt()
            self._consume(connection, deadline, attempt)
            return True
        except BaseException as error:
            if attempt is not None:
                attempt.fail(error)
            self._errors.append(error)
            error.experiment_host_dispatcher = self
            raise
        finally:
            self._busy = False

    def close(self):
        """Close original native custody without asking for fresh admission."""
        self._original()
        child._no_mutex()
        if self._closed:
            self.assert_closed()
            return
        self._closing = True
        if self._busy or any(attempt.cleanup_pending for attempt in self._attempts):
            _fail("original_attempt_pending", self)
        if not self._listener_initialized:
            # Failed native initialization retains its own partial owner. Never
            # infer absence merely from the constructor not returning.
            _fail("original_initialization_unsettled", self)
        for service in self._services:
            for attempt in service.attempts:
                if (not any(attempt is item for item in self._attempts) or attempt.cleanup_pending):
                    _fail("original_service_attempt_pending", self)
        try:
            if self._listener.stop_accept() is not True:
                # The original cancellation is still live. Repeated zero-time
                # observations must not allocate retained exception tracebacks.
                return False
            if not self._listener_closed:
                self._listener.close()
                self._listener_closed = True
            self._assert_native_closed()
            self._closed = True
        except BaseException as error:
            self._errors.append(error)
            error.experiment_host_dispatcher = self
            raise

    def _assert_native_closed(self):
        native = self._listener_owner
        if (native is None or not self._listener_closed or native._handle_close_unknown or
                native._busy or native._proofs or
                any(getattr(native, name) is not None for name in (
                    "_handle", "_operation", "_active", "_server_process", "_self_process",
                    "_peer_process", "_accept_operation", "_accept_connection")) or
                self._registry.status().resources != 0):
            _fail("original_native_custody_pending", self)

    def assert_closed(self):
        self._original()
        if not self._closed or not self._closing or self._busy:
            _fail("original_close_required", self)
        if any(attempt.cleanup_pending for attempt in self._attempts):
            _fail("original_attempt_pending", self)
        for service in self._services:
            for attempt in service.attempts:
                if not any(attempt is item for item in self._attempts) or attempt.cleanup_pending:
                    _fail("original_service_attempt_pending", self)
        self._assert_native_closed()
