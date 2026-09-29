"""Fixed parent mux over real Scope/SQLite, with explicit native/I/O fixtures.

Production services parse the one retained hello and own authentication. Real
registry objects retain synthetic pipe owners; no listener, process or Job is
created through Win32 and these tests do not establish a native capability.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import hmac
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_child_host as child_host
from sentinel.adaptive import experiment_host_dispatch as dispatch
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive import pipe_windows as pipes
from sentinel.adaptive.ipc import IpcError
from tests import test_adaptive_experiment_role_release as role_fixture
from tests import test_adaptive_experiment_host_transport as pipe_fixture
from tests import test_adaptive_experiment_host_scope as scope_fixture
from tests.test_adaptive_ipc import canonical, wire_frame


class ProductionHostDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = role_fixture.ExperimentRoleReleaseTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.owner = self.fixture.owner
        self.listeners, self.pending, self.events = [], [], []
        self.construct_error = self.close_error = None
        self.polls = 0
        # The real registry and _PipeOwner preserve the production pin layout.
        # Only OS construction/accept/close effects are explicit fixtures.
        def initialize(listener, endpoint, registry=None):
            self.assertIsNotNone(self.owner._host_dispatcher)
            self.assertIs(self.owner._host_dispatcher._listener, listener)
            self.assertIsNone(self.owner._active_sql)
            self.assertIsNone(self.owner._guard)
            listener.endpoint = endpoint
            listener._owner = pipes._PipeOwner(endpoint, registry, True)
            listener._owner._handle = 700 + len(self.listeners)
            listener._owner._busy = False
            self.listeners.append(listener)
            self.events.append("listener_initialized")
            if self.construct_error is not None:
                raise self.construct_error
        def accept(listener, deadline):
            self.assertIsNone(self.owner._active_sql)
            self.assertIsNone(self.owner._guard)
            self.assertGreater(deadline.remaining_ms(), 0)
            return self._take_connection(listener)
        def poll(listener):
            self.polls += 1
            return self._take_connection(listener) if self.pending else None
        def stop(listener):
            listener._owner._accept_stopped = True
            return True
        def close(listener):
            self.events.append("listener_close")
            native = listener._owner
            if self.close_error is not None:
                native._handle_close_unknown = True
                raise self.close_error
            self.assertIsNone(native._active)
            native._handle = None
            native._registry._forget(native)
        for name, method in (("__init__", initialize), ("accept", accept),
                             ("poll_accept", poll), ("stop_accept", stop), ("close", close)):
            override = patch.object(pipes.NativePipeListener, name, method)
            override.start()
            self.addCleanup(override.stop)
        self.addCleanup(self.forget_fixture_registry_owners)

    def forget_fixture_registry_owners(self):
        # Uncertain synthetic outcomes remain retained through each assertion.
        # Removing test-only Python objects is not a production close receipt.
        for listener in self.listeners:
            listener._owner._registry._forget(listener._owner)
        original = self.owner._host_dispatcher
        if original is not None:
            dispatch._ORIGINALS.pop(id(original), None)
        for publication in self.owner._registration_publications.values():
            child_host._PUBLICATIONS.pop(publication._key, None)

    def _take_connection(self, listener):
        self.assertTrue(self.pending)
        connection = self.pending.pop(0)
        listener._owner._active = connection
        original = connection.on_channel_close
        def settled():
            if original is not None:
                original()
            if connection.channel_error is None:
                listener._owner._active = None
        connection.on_channel_close = settled
        return connection

    def queue_child(self, *, close_error=None):
        request, registration, peer = self.fixture.original_request(self.fixture.guardian)
        state = {}
        def mac(purpose, result=None):
            value = dict(domain="ResourceSentinel/experiment-child-ipc/v1/" + purpose,
                request=request.to_dict(), challenge=state["challenge"])
            if purpose != "proof":
                value["result"] = result
            return hmac.new(registration.auth_key, canonical(value), hashlib.sha256).hexdigest()
        def write(connection, message):
            self.fixture.assert_settled()
            if message["kind"] == "ExperimentChildChallenge":
                state["challenge"] = message
                connection.enqueue(dict(version=1, kind="ExperimentChildProof", request_id=request.request_id,
                    nonce=message["nonce"], mac=mac("proof")))
            elif message["kind"] == "ExperimentChildResult":
                self.assertEqual(message["mac"], mac("result", message["result"]))
                connection.enqueue(dict(version=1, kind="ExperimentChildReceipt", request_id=request.request_id,
                    nonce=message["nonce"], mac=mac("receipt", message["result"])))
        hello = dict(version=1, kind="ExperimentChildHello", request_id=request.request_id,
                     caller=registration.manifest.child_identity.to_dict())
        connection = pipe_fixture.Pipe(registration.manifest.child_identity,
            wire_frame(hello) + wire_frame(request.to_dict()), on_write=write,
            on_read=lambda conn, size: self.fixture.assert_settled())
        connection.channel_error = close_error
        self.pending.append(connection)
        return connection, request, registration

    def test_factory_retains_exact_owner_before_listener_and_reuses_it(self):
        original_service = self.fixture.service
        dispatcher = self.owner.open_dispatcher()
        self.assertIs(dispatcher, self.owner._host_dispatcher)
        self.assertIs(type(dispatcher), dispatch.ProductionHostDispatcher)
        self.assertIs(dispatcher._services[0], original_service)
        self.assertIs(self.owner.open_dispatcher(), dispatcher)
        self.assertEqual(len(self.listeners), 1)
        self.assertEqual(dispatcher._registry.status().resources, 1)
        dispatcher.close()
        self.assertIsNone(dispatcher.assert_closed())
        self.assertEqual(dispatcher._registry.status().resources, 0)

    def test_blocking_child_dispatch_authenticates_and_shares_one_original_attempt(self):
        dispatcher = self.owner.open_dispatcher()
        before = self.fixture.host.fixture.assert_retained(self.owner.demand)
        connection, request, registration = self.queue_child()
        self.assertIsNone(dispatcher.serve_once())
        self.assertTrue(connection.closed)
        self.assertIs(self.owner._accepted_children[request.request_id], registration)
        self.assertIs(self.owner._released_roles[self.fixture.guardian.member_id][0], self.fixture.guardian_role)
        self.assertEqual(len(dispatcher.attempts), 1)
        attempt = dispatcher.attempts[0]
        self.assertIs(type(attempt), child._Attempt)
        self.assertIs(self.fixture.service.attempts[0], attempt)
        self.assertIs(attempt.channel_origin, dispatcher._listener)
        self.assertIs(attempt.connection, connection)
        self.assertFalse(attempt.cleanup_pending)
        self.assertTrue(attempt.exchange_complete)
        self.assertEqual(self.fixture.host.fixture.assert_retained(self.owner.demand), before)
        dispatcher.close()
        dispatcher.assert_closed()

    def test_fixed_four_routes_receive_same_hello_and_actual_protocol_rejects_invalid_body(self):
        dispatcher = self.owner.open_dispatcher()
        _, registration, _ = self.fixture.original_request(self.fixture.guardian)
        for index, (attribute, service_type, kind) in enumerate(dispatch._SERVICE_TYPES):
            with self.subTest(kind=kind):
                hello = dict(version=1, kind=kind, request_id=registration.manifest.request_id,
                             caller=registration.manifest.child_identity.to_dict())
                pipe = pipe_fixture.Pipe(registration.manifest.child_identity,
                                         wire_frame(hello) + wire_frame({}))
                self.pending.append(pipe)
                original = service_type._serve_connection
                calls = []
                def observed(service, connection, deadline, attempt, *, hello=None):
                    calls.append((service, connection, attempt, hello))
                    return original(service, connection, deadline, attempt, hello=hello)
                with patch.object(service_type, "_serve_connection", observed), self.assertRaises(IpcError):
                    dispatcher.serve_once()
                self.assertEqual(len(calls), 1)
                service, connection, attempt, observed_hello = calls[0]
                self.assertIs(service, getattr(self.owner, attribute))
                self.assertIs(connection, pipe)
                self.assertEqual(observed_hello, hello)
                self.assertIs(attempt, dispatcher.attempts[index])
                self.assertIs(service.attempts[-1], attempt)
                self.assertEqual(sum(item is attempt for item in service.attempts), 1)
                self.assertEqual(pipe.reads, [4, len(canonical(hello)), 4, 2])
                self.assertTrue(pipe.closed)
                self.assertFalse(attempt.cleanup_pending)
        self.assertEqual(self.owner._accepted_children, {})
        dispatcher.close()
        dispatcher.assert_closed()

    def test_unknown_and_malformed_hello_never_route_to_any_service(self):
        dispatcher = self.owner.open_dispatcher()
        actor = self.fixture.children[self.fixture.guardian.member_id][0].process.identity
        for hello in ({"kind": "arbitrary-handler"}, [], {"kind": 1}):
            with self.subTest(hello=hello):
                self.pending.append(pipe_fixture.Pipe(actor, wire_frame(hello)))
                with ExitStack() as stack:
                    for _, service_type, _ in dispatch._SERVICE_TYPES:
                        stack.enter_context(patch.object(service_type, "_serve_connection",
                            side_effect=AssertionError("unrecognized hello reached a service")))
                    with self.assertRaises(dispatch.ProductionHostDispatcherError):
                        dispatcher.serve_once()
        self.assertTrue(all(not service.attempts for service in dispatcher._services))
        self.assertEqual(len(dispatcher.attempts), 3)
        dispatcher.close()

    def test_idle_poll_keeps_listener_and_registry_without_attempt_leaks_then_handles_child(self):
        dispatcher = self.owner.open_dispatcher()
        for _ in range(100):
            self.assertIs(dispatcher.poll_once(timeout_ms=10), False)
        self.assertEqual(self.polls, 100)
        self.assertEqual(dispatcher.attempts, ())
        self.assertTrue(all(not service.attempts for service in dispatcher._services))
        self.assertEqual(dispatcher._registry.status().resources, 1)
        self.assertEqual(len(self.listeners), 1)
        self.queue_child()
        self.assertIs(dispatcher.poll_once(timeout_ms=100), True)
        self.assertEqual(len(dispatcher.attempts), 1)
        dispatcher.close()

    def test_copied_dispatcher_and_changed_original_endpoint_or_registry_are_rejected(self):
        dispatcher = self.owner.open_dispatcher()
        copied = object.__new__(dispatch.ProductionHostDispatcher)
        copied.__dict__.update(dispatcher.__dict__)
        with self.assertRaises(dispatch.ProductionHostDispatcherError):
            copied.assert_ready()
        for field, changed in (("endpoint", replace(dispatcher.endpoint)),
                               ("_registry", pipes.NativePipeRegistry())):
            original = getattr(dispatcher, field)
            try:
                setattr(dispatcher, field, changed)
                with self.subTest(field=field), self.assertRaises(dispatch.ProductionHostDispatcherError):
                    dispatcher.poll_once()
            finally:
                setattr(dispatcher, field, original)
        self.assertEqual(dispatcher.attempts, ())
        dispatcher.close()

    def test_uncertain_channel_close_keeps_shared_attempt_and_blocks_close_or_replacement(self):
        dispatcher = self.owner.open_dispatcher()
        failure = OSError("fixture_channel_close_unknown")
        connection, _, _ = self.queue_child(close_error=failure)
        with self.assertRaises(OSError) as caught:
            dispatcher.serve_once()
        self.assertIs(caught.exception, failure)
        attempt = dispatcher.attempts[0]
        self.assertIs(attempt, self.fixture.service.attempts[0])
        self.assertIs(attempt.connection, connection)
        self.assertTrue(attempt.cleanup_pending)
        for operation in (dispatcher.close, dispatcher.assert_closed, self.owner.open_dispatcher):
            with self.assertRaises(dispatch.ProductionHostDispatcherError):
                operation()
        self.assertIs(self.owner._host_dispatcher, dispatcher)
        self.assertEqual(dispatcher._registry.status().resources, 1)
        self.assertEqual(len(self.listeners), 1)

    def test_uncertain_listener_close_retains_native_owner_and_never_reports_closed(self):
        dispatcher = self.owner.open_dispatcher()
        native = dispatcher._listener_owner
        self.close_error = OSError("fixture_listener_close_unknown")
        with self.assertRaises(OSError) as caught:
            dispatcher.close()
        self.assertIs(caught.exception.experiment_host_dispatcher, dispatcher)
        self.assertIs(dispatcher._listener_owner, native)
        self.assertEqual(dispatcher._registry.status().resources, 1)
        with self.assertRaises(dispatch.ProductionHostDispatcherError):
            dispatcher.assert_closed()
        with self.assertRaises(dispatch.ProductionHostDispatcherError):
            self.owner.open_dispatcher()
        self.assertEqual(len(self.listeners), 1)

    def test_registration_publication_runs_only_after_original_listener_is_ready(self):
        attempt, registration, _ = self.fixture.children[self.fixture.guardian.member_id]
        def publish(publication):
            self.assertIs(publication.registration, registration)
            self.owner._host_dispatcher.assert_ready()
            self.events.append("private_publication")
            return publication.target
        with patch.object(child_host.ChildRegistrationPublication, "publish", publish):
            target = self.owner.publish_child_registration(attempt,
                permitted_member_ids=registration.manifest.permitted_member_ids)
        self.assertEqual(self.events, ["listener_initialized", "private_publication"])
        self.assertEqual(target, self.owner._registration_publications[self.fixture.guardian.member_id].target)
        self.owner._host_dispatcher.close()

    def test_constructor_failure_retains_partial_listener_and_prevents_private_publication(self):
        self.construct_error = OSError("fixture_listener_constructor_unknown")
        attempt, registration, _ = self.fixture.children[self.fixture.guardian.member_id]
        with patch.object(child_host.ChildRegistrationPublication, "prepare") as publish:
            with self.assertRaises(OSError) as caught:
                self.owner.publish_child_registration(attempt,
                    permitted_member_ids=registration.manifest.permitted_member_ids)
        publish.assert_not_called()
        dispatcher = self.owner._host_dispatcher
        self.assertIs(caught.exception.experiment_host_dispatcher, dispatcher)
        self.assertIs(dispatcher._listener, self.listeners[0])
        self.assertEqual(dispatcher._registry.status().resources, 1)
        with self.assertRaises(dispatch.ProductionHostDispatcherError):
            self.owner.open_dispatcher()
        self.assertEqual(len(self.listeners), 1)
        self.assertEqual(self.owner._registration_publications, {})

    def test_pending_accept_cancellation_retains_owner_without_growing_diagnostics(self):
        dispatcher = self.owner.open_dispatcher()
        listener, native = dispatcher._listener, dispatcher._listener_owner
        errors = tuple(dispatcher._errors)
        with patch.object(pipes.NativePipeListener, "stop_accept", side_effect=[False] * 20 + [True]):
            for _ in range(20):
                self.assertIs(dispatcher.close(), False)
                self.assertTrue(dispatcher._closing)
                self.assertFalse(dispatcher._closed)
                self.assertIs(dispatcher._listener, listener)
                self.assertIs(dispatcher._listener_owner, native)
                self.assertEqual(tuple(dispatcher._errors), errors)
                self.assertEqual(dispatcher.attempts, ())
                self.assertEqual(dispatcher._registry.status().resources, 1)
            self.assertNotIn("listener_close", self.events)
            dispatcher.close()
        dispatcher.assert_closed()
        self.assertEqual(tuple(dispatcher._errors), errors)
        self.assertEqual(self.events.count("listener_close"), 1)
        self.assertEqual(dispatcher._registry.status().resources, 0)
        self.assertEqual(len(self.listeners), 1)

    def test_virgin_scope_can_open_before_any_actor_registration(self):
        host = scope_fixture.ProductionExperimentScopeTests()
        host.setUp()
        self.addCleanup(host.doCleanups)
        virgin = host.prepare()
        self.assertIsNone(virgin._transport_endpoint)
        original = self.owner
        self.owner = virgin
        try:
            dispatcher = virgin.open_dispatcher()
            self.addCleanup(dispatch._ORIGINALS.pop, id(dispatcher), None)
            self.assertIs(dispatcher.endpoint, virgin._transport_endpoint)
            self.assertEqual(dispatcher.endpoint.server_identity, virgin.process.identity)
            self.assertEqual(virgin._child_registrations, {})
            dispatcher.close()
            dispatcher.assert_closed()
        finally:
            self.owner = original
