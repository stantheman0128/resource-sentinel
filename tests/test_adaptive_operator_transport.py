"""Conservative operator RPC over explicit synthetic pipe/identity fixtures.

These tests exercise the real client, service and typed contracts. The pipe
models completed byte transfers and retained peers; it supplies no Windows
authentication, capability, restoration or drain acceptance evidence. No DB,
runtime configuration, helper registration or native control is used here.
"""
from dataclasses import replace
import hashlib
import struct
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import operator_transport as transport
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, MAX_MESSAGE_BYTES, ProcessIdentity
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.operator_messages import (
    MAX_OPERATOR_REQUESTS, OperatorOperation, OperatorOutcome, OperatorReply, OperatorRequest,
)
from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeError
from tests.test_adaptive_ipc import Clock, Connection, Listener, canonical, wire_frame


INSTANCE = "0aadef58-91ae-44d4-a31f-0ec97975b146"
POLICY = "05b6a036-a6cd-49ae-8125-cfd43c996aa0"
ENDPOINT = "5ec1e614-9dd9-47db-b54b-8ec9767b36aa"
REQUEST = "47fe8a64-1e71-45b1-b7a7-10361e4b4d65"
EPOCH = "guardian-operator-fixture"
LOGON = "S-1-5-5-100-200"
CALLER = ProcessIdentity(23001, 134343072000000001, LOGON)
SERVER = ProcessIdentity(23002, 134343072000000007, LOGON)
NONCE = "c" * 64


def request(operation=OperatorOperation.DRAIN, **changes):
    values = dict(request_id=REQUEST, operation=operation, instance_id=INSTANCE,
                  policy_instance_id=POLICY, guardian_epoch=EPOCH,
                  expected_registry_revision=4 if operation is OperatorOperation.DRAIN else None)
    return OperatorRequest(**(values | changes))


def reply_for(value, *, scope="instance", **changes):
    values = dict(request_id=value.request_id, operation=value.operation,
                  instance_id=value.instance_id, policy_instance_id=value.policy_instance_id,
                  guardian_epoch=value.guardian_epoch, outcome=OperatorOutcome.PENDING,
                  scope=scope, reason="fixture_retained_work", accepted=True, desired_mode="off",
                  host_state="rollback_draining", inventory_complete=False,
                  native_disabled=None, bookkeeping_settled=False, slot_released=None,
                  barrier_cleared=False, cleanup_settled=False, remaining_executions=2,
                  remaining_custody=3, registry_revision=4)
    return OperatorReply(**(values | changes))


def digest(value):
    return hashlib.sha256(canonical(value.to_dict())).hexdigest()


def hello(value, caller=CALLER):
    return {"version": 1, "kind": "OperatorHello", "request_id": value.request_id,
            "caller": caller.to_dict()}


def envelope(value):
    return {"version": 1, "kind": "OperatorRequest", "request_id": value.request_id,
            "request": value.to_dict()}


def challenge(value, endpoint, *, caller=CALLER, scope="instance", **changes):
    return {"version": 1, "kind": "OperatorChallenge", "request_id": value.request_id,
            "nonce": NONCE, "endpoint_id": endpoint.instance_id,
            "instance_id": value.instance_id, "policy_instance_id": value.policy_instance_id,
            "guardian_epoch": value.guardian_epoch, "operation": value.operation.value,
            "scope": scope, "payload_hash": digest(value),
            "server": endpoint.server_identity.to_dict(), "client": caller.to_dict(), **changes}


def response(value, endpoint, *, scope="instance", **changes):
    return {"version": 1, "kind": "OperatorReply", "request_id": value.request_id,
            "nonce": NONCE, "endpoint_id": endpoint.instance_id, "payload_hash": digest(value),
            "reply": reply_for(value, scope=scope).to_dict(), **changes}


class LoopbackEnd(Connection):
    """One-thread byte-pair fixture; the first client read pumps the service."""

    def __init__(self, peer, *, pump=None):
        super().__init__(peer)
        self.pump = pump

    def read_exact(self, size, deadline):
        if not self.incoming and self.pump is not None:
            pump, self.pump = self.pump, None
            pump()
        return super().read_exact(size, deadline)


class OperatorTransportTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        clock = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.endpoint = NativePipeEndpoint(LOGON, ENDPOINT, SERVER)
        self.calls = []
        self.callers = []
        self.handler_change = None
        self.connection = None
        self.service = self.make_service()
        self.client = self.make_client()

    def handler(self, value, *, caller_identity):
        self.assertTrue(self.connection.peer_held)
        self.assertEqual(caller_identity, self.connection.retained.identity)
        self.calls.append(value)
        self.callers.append(caller_identity)
        result = reply_for(value, scope=self.service_scope)
        return result if self.handler_change is None else self.handler_change(result)

    def make_service(self, *, scope="instance", **changes):
        self.service_scope = scope
        values = dict(instance_id=INSTANCE, policy_instance_id=POLICY,
                      guardian_epoch=EPOCH, handler=self.handler, scope=scope)
        return transport.OperatorService(self.endpoint, **(values | changes))

    def make_client(self, *, caller=CALLER, scope="instance", **changes):
        values = dict(caller_process_or_identity=caller, instance_id=INSTANCE,
                      policy_instance_id=POLICY, guardian_epoch=EPOCH, scope=scope)
        return transport.OperatorClient(self.endpoint, **(values | changes))

    def service_connection(self, value=None, *, caller=CALLER, peer=None,
                           hello_change=None, request_change=None, on_write=None, on_read=None):
        value = request() if value is None else value
        initial = hello(value, caller)
        payload = envelope(value)
        if hello_change:
            initial = hello_change(initial)
        if request_change:
            payload = request_change(payload)
        self.connection = Connection(caller if peer is None else peer,
            wire_frame(initial) + wire_frame(payload), on_write=on_write, on_read=on_read)
        return self.connection

    def serve(self, connection=None, *, timeout_ms=1000):
        connection = self.connection if connection is None else connection
        return self.service.serve_once(Listener(self.endpoint, connection), timeout_ms=timeout_ms)

    def client_connection(self, value=None, *, peer=SERVER, caller=CALLER,
                          scope="instance", challenge_change=None, response_change=None,
                          on_write=None):
        value = request() if value is None else value

        def respond(connection, outgoing):
            self.assertTrue(connection.peer_held)
            if on_write:
                on_write(connection, outgoing)
            if outgoing["kind"] == "OperatorRequest":
                first = challenge(value, self.endpoint, caller=caller, scope=scope)
                final = response(value, self.endpoint, scope=scope)
                if challenge_change:
                    first = challenge_change(first)
                if response_change:
                    final = response_change(final)
                if first is not None:
                    connection.enqueue(first)
                if final is not None:
                    connection.enqueue(final)

        self.connection = Connection(peer, on_write=respond)
        return self.connection

    def call_client(self, value=None, *, client=None, timeout_ms=1000):
        value = request() if value is None else value
        client = self.client if client is None else client
        with patch.object(transport.NativePipeConnection, "connect", return_value=self.connection) as connect:
            result = client.request(value, timeout_ms=timeout_ms)
            self.assertEqual(connect.call_count, 1)
            return result

    def assert_service_refuses(self, connection=None):
        before = len(self.calls)
        with self.assertRaises((IpcError, NativePipeError)):
            self.serve(connection)
        self.assertEqual(len(self.calls), before)

    def test_all_closed_operations_cross_real_client_and_service_with_retained_peer(self):
        for operation in OperatorOperation:
            with self.subTest(operation=operation):
                value = request(operation, request_id=str(uuid4()))
                server_end = LoopbackEnd(CALLER)
                client_end = LoopbackEnd(SERVER, pump=lambda: self.serve(server_end))
                server_end.on_write = lambda _connection, message: client_end.enqueue(message)
                client_end.on_write = lambda _connection, message: server_end.enqueue(message)
                self.connection = server_end
                with patch.object(transport.NativePipeConnection, "connect", return_value=client_end) as connect:
                    result = self.client.request(value)
                self.assertEqual(result, reply_for(value))
                self.assertEqual(connect.call_count, 1)
                self.assertEqual(self.calls[-1], value)
                self.assertEqual(self.callers[-1], CALLER)
                self.assertEqual(server_end.verified, [CALLER])
                self.assertEqual(client_end.verified, [SERVER])
                self.assertFalse(server_end.peer_held)
                self.assertFalse(client_end.peer_held)
                self.assertTrue(server_end.closed)
                self.assertTrue(client_end.closed)

    def test_wire_hash_covers_full_request_and_keeps_independent_facts(self):
        self.service_connection()
        result = self.serve()
        self.assertEqual(result.outcome, OperatorOutcome.PENDING)
        self.assertTrue(result.accepted)
        self.assertIsNone(result.native_disabled)
        self.assertFalse(result.bookkeeping_settled)
        self.assertEqual(result.remaining_custody, 3)
        sent_challenge, sent_reply = self.connection.writes
        self.assertEqual(sent_challenge["payload_hash"], digest(request()))
        self.assertEqual(sent_reply["payload_hash"], digest(request()))
        self.assertEqual(sent_reply["nonce"], sent_challenge["nonce"])
        self.assertEqual(sent_challenge["scope"], "instance")
        self.assertEqual(sent_reply["reply"], result.to_dict())
        self.assertTrue(all(item is self.connection.deadlines[0] for item in self.connection.deadlines))

    def test_same_logon_new_cli_can_observe_original_operation_without_replaying_mutation(self):
        self.service_connection()
        self.serve()
        other = replace(CALLER, pid=CALLER.pid + 10,
                        created_filetime_100ns=CALLER.created_filetime_100ns + 10)
        observe = request(OperatorOperation.DESCRIBE, request_id=str(uuid4()), observe_request_id=REQUEST)
        self.service_connection(observe, caller=other)
        result = self.serve()
        self.assertEqual(result.operation, OperatorOperation.DESCRIBE)
        self.assertEqual(self.callers, [CALLER, other])
        self.assertEqual(self.calls[-1].observe_request_id, REQUEST)

    def test_service_authenticates_hello_identity_before_reading_operator_payload(self):
        stages = []
        connection = self.service_connection(on_read=lambda conn, size: stages.append(conn.peer_held))
        self.serve()
        self.assertEqual(stages, [False, False, True, True])
        self.assertEqual(connection.verified, [CALLER])

    def test_foreign_logon_pid_reuse_and_claimed_caller_mismatch_never_read_request(self):
        identities = (replace(CALLER, logon_id="S-1-5-5-200-300"),
                      replace(CALLER, created_filetime_100ns=CALLER.created_filetime_100ns + 1),
                      replace(CALLER, pid=CALLER.pid + 1))
        for identity in identities:
            with self.subTest(identity=identity):
                connection = self.service_connection(peer=identity)
                self.assert_service_refuses()
                self.assertEqual(len(connection.reads), 2)
                self.assertEqual(connection.writes, [])
        connection = self.service_connection(caller=identities[0])
        self.assert_service_refuses()
        self.assertEqual(len(connection.reads), 2)

    def test_changed_peer_identity_pid_or_death_after_challenge_refuses_before_callback(self):
        def change_pid(conn):
            conn.pid += 1

        def change_identity(conn):
            conn.retained.identity = replace(CALLER, created_filetime_100ns=CALLER.created_filetime_100ns + 1)

        def die(conn):
            conn.retained.observation = IdentityObservation(CALLER, IdentityStatus.DEAD)

        for mutation in (change_pid, change_identity, die):
            with self.subTest(mutation=mutation.__name__):
                self.service_connection(on_write=lambda conn, _message: mutation(conn))
                self.assert_service_refuses()
                self.assertEqual(len(self.connection.writes), 1)

    def test_unknown_or_changed_peer_after_handler_prevents_reply(self):
        for status in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            with self.subTest(status=status):
                self.service_connection(request(request_id=str(uuid4())))

                def lose_peer(result):
                    self.connection.retained.observation = IdentityObservation(CALLER, status,
                        "fixture_identity_unavailable" if status is IdentityStatus.UNKNOWN else None)
                    return result

                self.handler_change = lose_peer
                before = len(self.calls)
                with self.assertRaises((IpcError, NativePipeError)):
                    self.serve()
                self.assertEqual(len(self.calls), before + 1)
                self.assertEqual([value["kind"] for value in self.connection.writes], ["OperatorChallenge"])

    def test_hello_is_strict_small_and_versioned_before_native_authentication(self):
        changes = (lambda value: value | {"unexpected": True},
                   lambda value: {key: item for key, item in value.items() if key != "caller"},
                   lambda value: value | {"version": True}, lambda value: value | {"version": 2},
                   lambda value: value | {"kind": "ControlProposalRequest"},
                   lambda value: value | {"caller": {"pid": CALLER.pid}},
                   lambda value: value | {"request_id": "00000000-0000-0000-0000-000000000000"})
        for change in changes:
            with self.subTest(change=change):
                connection = self.service_connection(hello_change=change)
                self.assert_service_refuses()
                self.assertEqual(connection.verified, [])
        for size in (0, 2049, MAX_MESSAGE_BYTES + 1):
            with self.subTest(size=size):
                self.connection = Connection(CALLER, struct.pack("<I", size))
                self.assert_service_refuses()
                self.assertEqual(self.connection.reads, [4])
                self.assertEqual(self.connection.verified, [])

    def test_request_closed_shape_and_target_binding_reject_privilege_escalation(self):
        changes = (lambda value: value | {"user_authorized": True},
                   lambda value: value | {"version": 2}, lambda value: value | {"kind": "ControlProposalRequest"},
                   lambda value: value | {"request_id": str(uuid4())},
                   lambda value: value | {"request": value["request"] | {"command": "private-marker"}},
                   lambda value: value | {"request": value["request"] | {"operation": "apply"}},
                   lambda value: value | {"request": value["request"] | {"instance_id": str(uuid4())}},
                   lambda value: value | {"request": value["request"] | {"policy_instance_id": str(uuid4())}},
                   lambda value: value | {"request": value["request"] | {"guardian_epoch": "replacement-epoch"}})
        for change in changes:
            with self.subTest(change=change):
                self.service_connection(request_change=change)
                self.assert_service_refuses()
                self.assertEqual(self.connection.writes, [])

    def test_oversized_authenticated_request_refuses_before_body_allocation(self):
        self.connection = Connection(CALLER, wire_frame(hello(request())) + struct.pack("<I", MAX_MESSAGE_BYTES + 1))
        self.assert_service_refuses()
        self.assertEqual(self.connection.reads[-1], 4)
        self.assertEqual(len(self.connection.reads), 3)
        self.assertEqual(self.connection.verified, [CALLER])

    def test_malformed_json_duplicate_keys_and_truncation_refuse_without_callback(self):
        bad_payloads = (b"{", b"[]", b'{"version":1,"version":1}', b"\xff")
        for stage in ("hello", "request"):
            for payload in bad_payloads:
                with self.subTest(stage=stage, payload=payload):
                    prefix = b"" if stage == "hello" else wire_frame(hello(request()))
                    self.connection = Connection(CALLER, prefix + struct.pack("<I", len(payload)) + payload)
                    self.assert_service_refuses()
                    self.assertEqual(self.connection.writes, [])
            for suffix in (b"\x01\x00", struct.pack("<I", 10) + b"{}"):
                with self.subTest(stage=stage, truncated=suffix):
                    prefix = b"" if stage == "hello" else wire_frame(hello(request()))
                    self.connection = Connection(CALLER, prefix + suffix)
                    self.assert_service_refuses()

    def test_exact_mutation_replay_reenters_same_owner_for_progress(self):
        original = request()
        for _ in range(2):
            self.service_connection(original)
            self.serve()
        self.assertEqual(self.calls, [original, original])
        self.assertEqual(self.callers, [CALLER, CALLER])

    def test_request_id_is_bound_to_original_payload_and_peer_before_owner_callback(self):
        self.service_connection()
        self.serve()
        for changed in (replace(request(), expected_registry_revision=5),
                        replace(request(), operation=OperatorOperation.RESTORE_ONLY)):
            with self.subTest(changed=changed):
                self.service_connection(changed)
                self.assert_service_refuses()
        other = replace(CALLER, pid=CALLER.pid + 10)
        self.service_connection(caller=other)
        self.assert_service_refuses()
        self.assertEqual(len(self.calls), 1)

    def test_callback_failure_keeps_request_binding_and_exact_retry_available(self):
        def failed(_result):
            raise OSError("private-marker-must-not-escape")

        self.handler_change = failed
        self.service_connection()
        with self.assertRaises(Exception):
            self.serve()
        self.assertEqual(len(self.calls), 1)
        self.handler_change = None
        self.service_connection(replace(request(), expected_registry_revision=5))
        self.assert_service_refuses()
        self.service_connection()
        self.serve()
        self.assertEqual(self.calls, [request(), request()])

    def test_owner_interrupt_and_reply_disconnect_leave_exact_retry_bound(self):
        for interrupted in (True, False):
            with self.subTest(interrupted=interrupted):
                value = request(request_id=str(uuid4()))
                if interrupted:
                    def interrupt(_result):
                        raise KeyboardInterrupt()

                    self.handler_change = interrupt
                    self.service_connection(value)
                    with self.assertRaises(KeyboardInterrupt):
                        self.serve()
                else:
                    self.handler_change = None

                    def disconnect(_connection, message):
                        if message["kind"] == "OperatorReply":
                            raise OSError("observer_disconnected")

                    self.service_connection(value, on_write=disconnect)
                    with self.assertRaises(OSError):
                        self.serve()
                self.handler_change = None
                self.service_connection(replace(value, expected_registry_revision=5))
                self.assert_service_refuses()
                self.service_connection(value)
                self.serve()
                self.assertEqual(self.calls[-2:], [value, value])

    def test_bounded_mutation_bindings_never_evict_original_unknown_owner_request(self):
        first = request()
        for index in range(MAX_OPERATOR_REQUESTS):
            value = first if index == 0 else request(request_id=str(uuid4()))
            self.service_connection(value)
            self.serve()
        self.assertEqual(len(self.calls), MAX_OPERATOR_REQUESTS)
        self.service_connection(request(request_id=str(uuid4())))
        self.assert_service_refuses()
        # Read-only observations and exact progress retries remain available.
        self.service_connection(request(OperatorOperation.DESCRIBE, request_id=str(uuid4()), observe_request_id=REQUEST))
        self.serve()
        self.service_connection(first)
        self.serve()
        self.assertEqual(self.calls[-1], first)
        self.assertEqual(len(self.calls), MAX_OPERATOR_REQUESTS + 2)

    def test_read_binding_collision_cannot_turn_observation_into_mutation(self):
        first = request(OperatorOperation.DESCRIBE)
        self.service_connection(first)
        self.serve()
        self.service_connection(request())
        self.assert_service_refuses()
        # The bounded recent-read cache may rotate, but mutation bindings persist.
        mutation = request(request_id=str(uuid4()))
        self.service_connection(mutation)
        self.serve()
        for _ in range(transport.MAX_READ_BINDINGS + 1):
            self.service_connection(request(OperatorOperation.DESCRIBE, request_id=str(uuid4())))
            self.serve()
        self.service_connection(replace(mutation, expected_registry_revision=5))
        self.assert_service_refuses()
        self.service_connection(mutation)
        self.serve()
        self.assertEqual(self.calls[-1], mutation)

    def test_helper_scope_exposes_only_describe_and_drain_and_never_claims_instance(self):
        self.service = self.make_service(scope="helper")
        for operation in (OperatorOperation.DESCRIBE, OperatorOperation.DRAIN):
            self.service_connection(request(operation, request_id=str(uuid4())))
            self.assertEqual(self.serve().scope, "helper")
        for operation in (OperatorOperation.RESTORE_ONLY, OperatorOperation.AUDIT):
            self.service_connection(request(operation, request_id=str(uuid4())))
            self.assert_service_refuses()

    def test_owner_reply_must_match_exact_request_operation_target_and_scope(self):
        changes = (dict(request_id=str(uuid4())), dict(operation=OperatorOperation.AUDIT),
                   dict(instance_id=str(uuid4())), dict(policy_instance_id=str(uuid4())),
                   dict(guardian_epoch="replacement-epoch"), dict(scope="guardian"))
        for change in changes:
            with self.subTest(change=change):
                self.service_connection(request(request_id=str(uuid4())))
                self.handler_change = lambda result: replace(result, **change)
                with self.assertRaises(IpcError):
                    self.serve()
                self.assertEqual(len(self.connection.writes), 1)
        self.handler_change = lambda _result: {"accepted": True}
        self.service_connection(request(request_id=str(uuid4())))
        with self.assertRaises(IpcError):
            self.serve()
        self.assertEqual(len(self.connection.writes), 1)

    def test_deadline_expired_after_challenge_prevents_callback(self):
        self.service_connection(on_write=lambda _connection, _message: setattr(self.clock, "now", 2000))
        self.assert_service_refuses()
        self.assertEqual(len(self.connection.writes), 1)

    def test_final_liveness_check_cannot_start_handler_after_deadline(self):
        self.service_connection()
        observation = self.connection.retained.observation
        observed = 0

        def slow_final_observation():
            nonlocal observed
            observed += 1
            if observed == 3:
                self.clock.now = 2000
            return observation

        self.connection.retained.observe = slow_final_observation
        self.assert_service_refuses()
        self.assertEqual(observed, 3)
        self.assertEqual(len(self.connection.writes), 1)

    def test_expired_callback_never_publishes_reply_and_keeps_original_replay(self):
        self.service_connection()

        def slow_owner(result):
            self.clock.now = 2000
            return result

        self.handler_change = slow_owner
        with self.assertRaises(IpcError):
            self.serve()
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(len(self.connection.writes), 1)
        self.handler_change = None
        self.service_connection()
        self.serve()
        self.assertEqual(self.calls, [request(), request()])

    def test_client_pins_server_before_sending_even_hello(self):
        for peer in (replace(SERVER, created_filetime_100ns=SERVER.created_filetime_100ns + 1),
                     replace(SERVER, logon_id="S-1-5-5-200-300")):
            with self.subTest(peer=peer):
                self.client_connection(peer=peer)
                with self.assertRaises(transport.OperatorTransportError) as raised:
                    self.call_client()
                self.assertFalse(raised.exception.outcome_unknown)
                self.assertEqual(self.connection.writes, [])

    def test_client_sends_only_hello_and_closed_request_with_one_connection(self):
        self.client_connection()
        self.assertEqual(self.call_client(), reply_for(request()))
        self.assertEqual(self.connection.writes, [hello(request()), envelope(request())])
        self.assertEqual(self.connection.verified, [SERVER])
        self.assertTrue(self.connection.closed)

    def test_client_validates_every_challenge_binding_and_strict_shape(self):
        changes = (dict(request_id=str(uuid4())), dict(nonce="not-a-nonce"),
                   dict(endpoint_id=str(uuid4())), dict(instance_id=str(uuid4())),
                   dict(policy_instance_id=str(uuid4())), dict(guardian_epoch="replacement-epoch"),
                   dict(operation="describe"), dict(scope="guardian"), dict(payload_hash="d" * 64),
                   dict(server=replace(SERVER, pid=SERVER.pid + 1).to_dict()),
                   dict(client=replace(CALLER, created_filetime_100ns=CALLER.created_filetime_100ns + 1).to_dict()),
                   dict(version=True), dict(extra=None))
        for change in changes:
            with self.subTest(change=change):
                self.client_connection(challenge_change=lambda value: value | change)
                with self.assertRaises(transport.OperatorTransportError) as raised:
                    self.call_client()
                self.assertTrue(raised.exception.outcome_unknown)

    def test_client_refuses_old_challenge_without_binding_fields(self):
        for field in ("scope", "operation", "payload_hash", "policy_instance_id", "guardian_epoch"):
            with self.subTest(field=field):
                self.client_connection(challenge_change=lambda value: {key: item for key, item in value.items() if key != field})
                with self.assertRaises(transport.OperatorTransportError):
                    self.call_client()

    def test_client_validates_reply_nonce_payload_endpoint_and_typed_binding(self):
        changes = (lambda value: value | {"nonce": "d" * 64},
                   lambda value: value | {"payload_hash": "d" * 64},
                   lambda value: value | {"endpoint_id": str(uuid4())},
                   lambda value: value | {"request_id": str(uuid4())},
                   lambda value: value | {"reply": value["reply"] | {"scope": "guardian"}},
                   lambda value: value | {"reply": value["reply"] | {"guardian_epoch": "replacement-epoch"}},
                   lambda value: value | {"reply": value["reply"] | {"operation": "audit"}},
                   lambda value: value | {"reply": value["reply"] | {"instance_id": str(uuid4())}},
                   lambda value: value | {"reply": value["reply"] | {"policy_instance_id": str(uuid4())}},
                   lambda value: value | {"reply": value["reply"] | {"request_id": str(uuid4())}},
                   lambda value: value | {"reply": value["reply"] | {"command": "private-marker"}},
                   lambda value: value | {"version": 2})
        for change in changes:
            with self.subTest(change=change):
                self.client_connection(response_change=change)
                with self.assertRaises(transport.OperatorTransportError) as raised:
                    self.call_client()
                self.assertTrue(raised.exception.outcome_unknown)

    def test_client_target_mismatch_refuses_before_connecting(self):
        for change in (dict(instance_id=str(uuid4())), dict(policy_instance_id=str(uuid4())),
                       dict(guardian_epoch="replacement-epoch")):
            with self.subTest(change=change):
                with patch.object(transport.NativePipeConnection, "connect") as connect:
                    with self.assertRaises(transport.OperatorTransportError) as raised:
                        self.client.request(replace(request(), **change))
                self.assertFalse(raised.exception.outcome_unknown)
                connect.assert_not_called()

    def test_lost_mutation_ack_is_unknown_with_one_attempt_and_no_silent_retry(self):
        self.client_connection(response_change=lambda _value: None)
        with patch.object(transport.NativePipeConnection, "connect", return_value=self.connection) as connect:
            with self.assertRaises(transport.OperatorTransportError) as raised:
                self.client.request(request())
        self.assertTrue(raised.exception.outcome_unknown)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual(len(self.connection.writes), 2)

    def test_failed_hello_is_clean_unavailable_but_possible_request_write_is_unknown(self):
        for failed_kind, expected_unknown in (("OperatorHello", False), ("OperatorRequest", True)):
            with self.subTest(failed_kind=failed_kind):
                def fail(_connection, message):
                    if message["kind"] == failed_kind:
                        raise OSError("private-marker-must-not-escape")

                self.client_connection(on_write=fail)
                with self.assertRaises(transport.OperatorTransportError) as raised:
                    self.call_client()
                self.assertEqual(raised.exception.outcome_unknown, expected_unknown)
                self.assertNotIn("private-marker", str(raised.exception))

    def test_authenticated_reply_does_not_hide_unknown_connection_cleanup(self):
        self.client_connection()
        cleanup_error = OSError("private-cleanup-marker")

        def failed_close(connection, *_arguments):
            connection.closed = True
            raise cleanup_error

        with patch.object(Connection, "__exit__", failed_close):
            with self.assertRaises(transport.OperatorTransportError) as raised:
                self.call_client()
        self.assertTrue(raised.exception.outcome_unknown)
        self.assertIs(raised.exception._operator_cause, cleanup_error)
        self.assertNotIn("private-cleanup-marker", str(raised.exception))

    def test_client_connect_failure_is_clean_unavailable_and_attempted_once(self):
        with patch.object(transport.NativePipeConnection, "connect", side_effect=NativePipeError("pipe_unavailable")) as connect:
            with self.assertRaises(transport.OperatorTransportError) as raised:
                self.client.request(request())
        self.assertFalse(raised.exception.outcome_unknown)
        self.assertEqual(connect.call_count, 1)

    def test_read_only_reply_loss_is_unverified_after_possible_request_delivery(self):
        value = request(OperatorOperation.DESCRIBE)
        self.client_connection(value, response_change=lambda _value: None)
        with self.assertRaises(transport.OperatorTransportError) as raised:
            self.call_client(value)
        self.assertTrue(raised.exception.outcome_unknown)

    def test_interrupt_preserves_delivery_uncertainty_without_wrapping_interrupt(self):
        for failed_kind, expected_unknown in (("OperatorHello", False), ("OperatorRequest", True)):
            with self.subTest(failed_kind=failed_kind):
                def interrupt(_connection, message):
                    if message["kind"] == failed_kind:
                        raise KeyboardInterrupt()

                self.client_connection(on_write=interrupt)
                with self.assertRaises(KeyboardInterrupt) as raised:
                    self.call_client()
                self.assertEqual(raised.exception.operator_outcome_unknown, expected_unknown)
                self.assertTrue(self.connection.closed)
                self.assertFalse(self.connection.peer_held)

    def test_client_scope_is_exact_including_guardian_only_replies(self):
        self.client = self.make_client(scope="guardian")
        self.client_connection(scope="guardian")
        self.assertEqual(self.call_client().scope, "guardian")
        self.client_connection(scope="instance")
        with self.assertRaises(transport.OperatorTransportError):
            self.call_client()


if __name__ == "__main__":
    unittest.main()
