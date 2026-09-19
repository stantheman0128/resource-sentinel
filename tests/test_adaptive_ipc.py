"""Portable query-protocol tests; no native transport or control acceptance.

The explicit connections below model completed reads/writes and held peers.
NativeDeadline uses an injected clock, while transport completion/cancellation
belongs to the separate pipe tests. MAC expectations are independently encoded
from the wire contract rather than using the implementation's MAC helpers.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import hmac
import json
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive import ipc
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.pipe_windows import NativeDeadline, NativePipeEndpoint, NativePipeError


EXECUTION = "5ec1e614-9dd9-47db-b54b-8ec9767b36aa"
OTHER_EXECUTION = "a9dc1135-f64f-45aa-a296-154cff23090d"
REQUEST_ID = "47fe8a64-1e71-45b1-b7a7-10361e4b4d65"
OTHER_REQUEST = "65f2b66f-228a-473d-b9db-71ea68cfa963"
INSTANCE = "0aadef58-91ae-44d4-a31f-0ec97975b146"
OTHER_INSTANCE = "05b6a036-a6cd-49ae-8125-cfd43c996aa0"
LOGON = "S-1-5-5-100-200"
CLIENT = ProcessIdentity(23001, 134343072000000001, LOGON)
SERVER = ProcessIdentity(23002, 134343072000000007, LOGON)
SPEC = "a" * 64
KEY = bytes(range(32))
NONCE = "b" * 64


def request(operation="QueryExecution", **changes):
    return {"version": 1, "kind": "Request", "request_id": REQUEST_ID,
            "operation": operation, "execution_id": EXECUTION, "spec_hash": SPEC, **changes}


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def wire_frame(value):
    payload = canonical(value)
    return struct.pack("<I", len(payload)) + payload


def wire_mac(purpose, message, challenge, result=None, *, key=KEY):
    transcript = {"domain": "ResourceSentinel/query-ipc/v1/" + purpose,
                  "request": message, "challenge": challenge}
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, canonical(transcript), hashlib.sha256).hexdigest()


def correlated(kind, message, challenge, mac):
    return {"version": 1, "kind": kind, "request_id": message["request_id"],
            "nonce": challenge["nonce"], "mac": mac}


def query_result(**changes):
    return {"available": True, "implementation_mode": "admission-only",
            "native_readiness": "unverified", "control_writes": False,
            "os_limit_state": "unverified", "recorded_mode": "off",
            "executions": [{"execution_id": EXECUTION,
                "allocation": {"kind": "direct", "reservation_id": "reservation-one",
                    "parent_execution_id": None, "recorded_binding": "recorded_binding_matches"},
                "state": "RESERVED", "state_revision": 0, "coverage": "unmanaged",
                "launch_in_flight": False, "launch_sealed": False,
                "wrapper": {"pid": CLIENT.pid, "created_filetime_100ns": str(CLIENT.created_filetime_100ns)},
                "root": None, "floor": {"cpu_units": 1, "physical_bytes": 512 << 20,
                    "commit_bytes": 768 << 20, "io_slots": 0}, "hold_reason": None}],
            "truncated": False, "reason": "ok", "schema_version": 1,
            "protocol_version": 1, "registry_revision": 4,
            "admission_barrier": "NONE", "row_limit": 1, **changes}


def readiness_result(**changes):
    return {"execution_id": EXECUTION, "implementation_mode": "admission-only",
            "native_readiness": "unverified", "control_writes": False,
            "os_limit_state": "unverified", "recorded_mode": "off",
            "admission_barrier": "NONE", "registry_revision": 4, "reason": "ok", **changes}


class Clock:
    def __init__(self):
        self.now = 1000

    def tick_ms(self):
        return self.now


class RetainedPeer:
    def __init__(self, identity):
        self.identity = identity
        self.observation = IdentityObservation(identity, IdentityStatus.ALIVE)

    def observe(self):
        return self.observation


class Connection:
    """Explicit fixture: no production class accepts this as a native handle."""
    def __init__(self, peer, incoming=b"", *, on_write=None, on_read=None):
        self.retained = RetainedPeer(peer)
        self.pid = peer.pid
        self.incoming = bytearray(incoming)
        self.on_write, self.on_read = on_write, on_read
        self.reads, self.writes, self.deadlines, self.verified = [], [], [], []
        self.peer_held = False
        self.closed = False

    def enqueue(self, message):
        self.incoming.extend(wire_frame(message))

    def read_exact(self, size, deadline):
        self.reads.append(size)
        self.deadlines.append(deadline)
        payload = bytes(self.incoming[:size])
        del self.incoming[:size]
        if self.on_read is not None:
            self.on_read(self, size)
        return payload

    def write_all(self, payload, deadline):
        self.deadlines.append(deadline)
        size = struct.unpack("<I", payload[:4])[0]
        if len(payload) != size + 4:
            raise AssertionError("fixture received malformed frame")
        message = json.loads(payload[4:])
        self.writes.append(message)
        if self.on_write is not None:
            self.on_write(self, message)

    def peer_pid(self):
        return self.pid

    @contextmanager
    def verified_peer(self, expected):
        self.verified.append(expected)
        if self.retained.identity != expected:
            raise NativePipeError("pipe_peer_unverified")
        self.peer_held = True
        try:
            yield self.retained
        finally:
            self.peer_held = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True


class Listener:
    def __init__(self, endpoint, connection):
        self.endpoint, self.connection = endpoint, connection
        self.accepted = []

    @contextmanager
    def accept(self, deadline):
        self.accepted.append(deadline)
        with self.connection:
            yield self.connection


class QueryContext:
    def __init__(self):
        self.calls = []
        self.launch_claim_token = Mock(side_effect=AssertionError("query must not export launch claim"))
        self.cancel_reserved = Mock(side_effect=AssertionError("query must not cancel allocation"))

    def snapshot(self):
        return SimpleNamespace(execution_id=EXECUTION, spec_hash=SPEC,
                               wrapper_identity=CLIENT, logon_id=LOGON)

    def _ipc_mac(self, transcript, *, execution_id, spec_hash, caller):
        if (execution_id, spec_hash, caller) != (EXECUTION, SPEC, CLIENT):
            raise AssertionError("query credential requested for another execution")
        self.calls.append(json.loads(transcript))
        return hmac.new(KEY, transcript, hashlib.sha256).hexdigest()


class IpcTestCase(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        clock = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.endpoint = NativePipeEndpoint(LOGON, INSTANCE, SERVER)

    def deadline(self, duration=1000):
        return NativeDeadline.after_ms(duration)


class FramingTests(IpcTestCase):
    def test_invalid_length_is_rejected_before_body_read(self):
        for size in (0, ipc.MAX_MESSAGE_BYTES + 1, 0xFFFFFFFF):
            with self.subTest(size=size):
                connection = Connection(CLIENT, struct.pack("<I", size) + b"private-body-marker")
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_frame_length$"):
                    ipc.read_frame(connection, self.deadline())
                self.assertEqual(connection.reads, [4])
                self.assertEqual(connection.incoming, b"private-body-marker")

    def test_short_prefix_and_body_are_not_accepted(self):
        for payload in (b"\x01\x00", struct.pack("<I", 5) + b"{}"):
            with self.subTest(payload=payload), self.assertRaisesRegex(ipc.IpcError, "^ipc_truncated_frame$"):
                ipc.read_frame(Connection(CLIENT, payload), self.deadline())

    def test_strict_json_rejects_duplicate_nonfinite_invalid_utf8_and_nondictionaries(self):
        for payload in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{"x":"\xff"}',
                        b'[]', b'null', b'{"x":' + b'[' * 80 + b'0' + b']' * 80 + b'}'):
            with self.subTest(payload=payload[:30]), self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_json$"):
                ipc.read_frame(Connection(CLIENT, struct.pack("<I", len(payload)) + payload), self.deadline())

    def test_encoder_bounds_payload_and_rejects_nonfinite_values(self):
        for value in ({"secret": "x" * ipc.MAX_MESSAGE_BYTES}, {"number": float("nan")}):
            with self.subTest(kind=next(iter(value))), self.assertRaises(ipc.IpcError):
                ipc.encode_frame(value)

    def test_prefix_cannot_refresh_expired_deadline_for_body(self):
        deadline = self.deadline(20)
        connection = Connection(CLIENT, wire_frame({"ok": True}),
                                on_read=lambda *_: setattr(self.clock, "now", 1020))
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_deadline_exceeded$"):
            ipc.read_frame(connection, deadline)
        self.assertEqual(connection.reads, [4])

    def test_multiple_frames_share_one_deadline_without_partial_read_reset(self):
        deadline = self.deadline(70)
        connection = Connection(CLIENT, wire_frame({"first": True}) + wire_frame({"second": True}),
                                on_read=lambda *_: setattr(self.clock, "now", self.clock.now + 20))
        self.assertEqual(ipc.read_frame(connection, deadline), {"first": True})
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_deadline_exceeded$"):
            ipc.read_frame(connection, deadline)
        self.assertEqual(connection.deadlines, [deadline] * 4)

    def test_write_checks_deadline_after_completion(self):
        connection = Connection(CLIENT, on_write=lambda *_: setattr(self.clock, "now", 1020))
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_deadline_exceeded$"):
            ipc.write_frame(connection, {"ok": True}, self.deadline(20))
        self.assertEqual(len(connection.writes), 1)


class ServiceTests(IpcTestCase):
    def setUp(self):
        super().setUp()
        self.record = SimpleNamespace(execution_id=EXECUTION, spec_hash=SPEC,
                                     wrapper_identity=CLIENT, ipc_auth_key=KEY)
        self.result = query_result()
        auth = patch.object(ipc, "_get_ipc_auth_record", return_value=self.record)
        dispatch = patch.object(ipc, "authenticated_query", side_effect=self.dispatch)
        self.auth = auth.start()
        self.query = dispatch.start()
        self.addCleanup(auth.stop)
        self.addCleanup(dispatch.stop)
        self.service = ipc.LifecycleQueryService("unused-private-db", self.endpoint)

    def dispatch(self, path, execution_id, record, *, timeout_ms):
        self.assertTrue(self.connection.peer_held)
        self.assertEqual(path, "unused-private-db")
        self.assertEqual(execution_id, EXECUTION)
        self.assertIs(record, self.record)
        self.assertGreater(timeout_ms, 0)
        self.assertLessEqual(timeout_ms, 250)
        return deepcopy(self.result)

    def connection_for(self, message=None, *, proof_transform=None, receipt_transform=None, peer=CLIENT):
        message = request() if message is None else message
        challenge = None

        def respond(connection, outgoing):
            nonlocal challenge
            if outgoing["kind"] == "Challenge":
                challenge = outgoing
                proof = correlated("Proof", message, challenge, wire_mac("proof", message, challenge))
                connection.enqueue(proof if proof_transform is None else proof_transform(proof, challenge))
            elif outgoing["kind"] == "Result":
                self.assertTrue(connection.peer_held)
                self.assertEqual(outgoing["mac"], wire_mac("result", message, challenge, outgoing["result"]))
                receipt = correlated("Receipt", message, challenge,
                                     wire_mac("receipt", message, challenge, outgoing["result"]))
                connection.enqueue(receipt if receipt_transform is None else receipt_transform(receipt, outgoing))

        self.connection = Connection(peer, wire_frame(message), on_write=respond)
        self.listener = Listener(self.endpoint, self.connection)
        return self.connection

    def serve(self, **kwargs):
        return self.service.serve_once(self.listener, **kwargs)

    def test_authenticated_query_reads_once_and_holds_peer_through_receipt(self):
        connection = self.connection_for()
        result = self.serve()
        self.assertEqual(result, {"request_id": REQUEST_ID, "execution_id": EXECUTION,
            "operation": "QueryExecution", "receipt_verified": True, "control_writes": False})
        self.auth.assert_called_once()
        self.query.assert_called_once()
        self.assertEqual(connection.verified, [CLIENT])
        self.assertEqual([message["kind"] for message in connection.writes], ["Challenge", "Result"])
        self.assertTrue(connection.closed)
        self.assertFalse(connection.peer_held)
        self.assertTrue(all(value is self.listener.accepted[0] for value in connection.deadlines))

    def test_mutations_unknown_fields_and_protocol_mismatch_are_rejected_before_database(self):
        messages = [request(operation=name) for name in
                    ("ClaimLaunch", "GrantExemption", "Cancel", "SetCpuRate", "RegisterExecution")]
        messages += [request(owner_pid=CLIENT.pid), request(version=True), request(version=2)]
        for message in messages:
            with self.subTest(message=message):
                connection = self.connection_for(message)
                with self.assertRaises(ipc.IpcError):
                    self.serve()
                self.assertEqual(connection.writes, [])
        self.auth.assert_not_called()
        self.query.assert_not_called()

    def test_wrong_spec_or_logon_does_not_challenge_or_dispatch(self):
        for changes in ({"spec_hash": "c" * 64},
                        {"wrapper_identity": replace(CLIENT, logon_id="S-1-5-5-300-400")}):
            with self.subTest(changes=changes):
                self.auth.return_value = SimpleNamespace(**(vars(self.record) | changes))
                connection = self.connection_for()
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_binding_mismatch$"):
                    self.serve()
                self.assertEqual(connection.writes, [])
        self.query.assert_not_called()

    def test_execution_selector_does_not_authorize_another_wrappers_native_identity(self):
        other = replace(CLIENT, pid=CLIENT.pid + 10)
        self.auth.return_value = SimpleNamespace(execution_id=OTHER_EXECUTION, spec_hash=SPEC,
                                                wrapper_identity=other, ipc_auth_key=KEY)
        connection = self.connection_for(request(execution_id=OTHER_EXECUTION))
        with self.assertRaisesRegex(NativePipeError, "^pipe_peer_unverified$"):
            self.serve()
        self.assertEqual(connection.verified, [other])
        self.assertEqual(connection.writes, [])
        self.query.assert_not_called()

    def test_wrong_mac_or_domain_never_dispatches(self):
        for purpose in ("wrong-key", "result", "receipt"):
            with self.subTest(purpose=purpose):
                def corrupt(proof, challenge):
                    proof["mac"] = (wire_mac("proof", request(), challenge, key=b"z" * 32)
                                    if purpose == "wrong-key" else wire_mac(purpose, request(), challenge))
                    return proof
                self.connection_for(proof_transform=corrupt)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_authentication_failed$"):
                    self.serve()
        self.query.assert_not_called()

    def test_proof_is_bound_to_request_operation_endpoint_and_exact_identities(self):
        for field in ("request_id", "execution_id", "operation", "spec_hash", "endpoint_id", "server", "client"):
            with self.subTest(field=field):
                def tamper(proof, challenge):
                    signed_request, signed_challenge = request(), deepcopy(challenge)
                    if field in {"request_id", "execution_id", "operation", "spec_hash"}:
                        signed_request[field] = {"request_id": OTHER_REQUEST, "execution_id": OTHER_EXECUTION,
                            "operation": "GetReadiness", "spec_hash": "c" * 64}[field]
                    elif field == "endpoint_id":
                        signed_challenge[field] = OTHER_INSTANCE
                    else:
                        signed_challenge[field]["created_filetime_100ns"] = str(134343072000000009)
                    proof["mac"] = wire_mac("proof", signed_request, signed_challenge)
                    return proof
                self.connection_for(proof_transform=tamper)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_authentication_failed$"):
                    self.serve()
        self.query.assert_not_called()

    def test_fresh_connection_challenge_rejects_captured_proof_with_same_request(self):
        captured = []
        def capture(proof, _):
            captured.append(deepcopy(proof))
            return proof
        with patch.object(ipc.secrets, "token_hex", side_effect=["b" * 64, "c" * 64]) as random_nonce:
            self.connection_for(proof_transform=capture)
            self.serve()
            self.connection_for(proof_transform=lambda *_: captured[0])
            with self.assertRaisesRegex(ipc.IpcError, "^ipc_response_binding_mismatch$"):
                self.serve()
        self.assertEqual(random_nonce.call_count, 2)
        self.query.assert_called_once()

    def test_replayed_mac_with_current_nonce_still_fails_authentication(self):
        captured = []
        def capture(proof, _):
            captured.append(proof["mac"])
            return proof

        with patch.object(ipc.secrets, "token_hex", side_effect=["b" * 64, "c" * 64]):
            self.connection_for(proof_transform=capture)
            self.serve()
            connection = self.connection_for(proof_transform=lambda proof, _: proof | {"mac": captured[0]})
            # Correlation is current; only binding the fresh challenge into the
            # MAC can distinguish this captured credential from a valid proof.
            with self.assertRaisesRegex(ipc.IpcError, "^ipc_authentication_failed$"):
                self.serve()
        self.query.assert_called_once()
        self.assertTrue(connection.closed)

    def test_phase_reflection_is_rejected_without_dispatch(self):
        self.connection_for(proof_transform=lambda proof, _: proof | {"kind": "Receipt"})
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_unexpected_message$"):
            self.serve()
        self.query.assert_not_called()

    def test_native_peer_lost_after_proof_cannot_dispatch(self):
        for failure in ("pid", "birth", "unknown", "dead"):
            with self.subTest(failure=failure):
                def change_peer(proof, _):
                    if failure == "pid":
                        self.connection.pid += 1
                    elif failure == "birth":
                        self.connection.retained.observation = IdentityObservation(
                            replace(CLIENT, created_filetime_100ns=CLIENT.created_filetime_100ns + 1), IdentityStatus.ALIVE)
                    else:
                        self.connection.retained.observation = IdentityObservation(
                            CLIENT, IdentityStatus.UNKNOWN if failure == "unknown" else IdentityStatus.DEAD,
                            "query_failed" if failure == "unknown" else None)
                    return proof
                connection = self.connection_for(proof_transform=change_peer)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_peer_unverified$"):
                    self.serve()
                self.assertTrue(connection.closed)
        self.query.assert_not_called()

    def test_corrupt_or_reflected_receipt_cannot_report_success_or_redispatch(self):
        for failure in ("mac", "result-domain", "kind", "request_id"):
            with self.subTest(failure=failure):
                self.query.reset_mock()
                def corrupt(receipt, result):
                    receipt.update({"mac": "0" * 64} if failure == "mac" else
                        {"mac": result["mac"]} if failure == "result-domain" else
                        {"kind": "Proof"} if failure == "kind" else {"request_id": OTHER_REQUEST})
                    return receipt
                connection = self.connection_for(receipt_transform=corrupt)
                with self.assertRaises(ipc.IpcError):
                    self.serve()
                self.query.assert_called_once()
                self.assertEqual(len(connection.writes), 2)
                self.assertTrue(connection.closed)

    def test_peer_change_after_readback_prevents_result_publication(self):
        def readback(*args, **kwargs):
            result = self.dispatch(*args, **kwargs)
            self.connection.pid += 1
            return result

        self.query.side_effect = readback
        connection = self.connection_for()
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_peer_unverified$"):
            self.serve()
        self.query.assert_called_once()
        self.assertEqual(len(connection.writes), 1)
        self.assertTrue(connection.closed)

    def test_valid_receipt_completes_even_when_client_exits_immediately_after_sending(self):
        connection = self.connection_for()

        def disconnected_pid():
            raise NativePipeError("pipe_peer_pid_unavailable")

        def after_receipt_body(connection, _):
            if len(connection.reads) == 6:
                self.assertTrue(connection.peer_held)
                connection.retained.observation = IdentityObservation(CLIENT, IdentityStatus.DEAD)
                connection.peer_pid = disconnected_pid

        connection.on_read = after_receipt_body
        result = self.serve()
        self.assertIs(result["receipt_verified"], True)
        self.assertIs(result["control_writes"], False)
        self.assertEqual(connection.retained.observation.status, IdentityStatus.DEAD)
        self.assertTrue(connection.closed)
        self.assertFalse(connection.peer_held)
        self.query.assert_called_once()

    def test_invalid_proof_does_not_read_a_second_attempt(self):
        def extra(proof, _):
            self.connection.enqueue(proof | {"mac": "0" * 64})
            return proof
        connection = self.connection_for(proof_transform=extra)
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_authentication_failed$"):
            self.serve()
        self.assertTrue(connection.incoming)
        self.assertEqual(len(connection.reads), 4)
        self.query.assert_not_called()

    def test_readiness_never_infers_control_from_recorded_mode(self):
        for mode in ("off", "shadow", "canary", "limited"):
            with self.subTest(mode=mode):
                self.result = query_result(recorded_mode=mode)
                connection = self.connection_for(request("GetReadiness"))
                self.serve()
                result = connection.writes[-1]["result"]
                self.assertEqual(result["execution_id"], EXECUTION)
                self.assertEqual(result["recorded_mode"], mode)
                self.assertEqual(result["native_readiness"], "unverified")
                self.assertEqual(result["os_limit_state"], "unverified")
                self.assertIs(result["control_writes"], False)
                self.assertNotIn("executions", result)

    def test_private_columns_or_false_readiness_are_not_written_as_result(self):
        for field in ("ipc_auth_key", "command", "native_readiness", "control_writes", "os_limit_state"):
            with self.subTest(field=field):
                self.result = query_result()
                if field in {"ipc_auth_key", "command"}:
                    self.result["executions"][0][field] = "private-secret-marker"
                else:
                    self.result[field] = True if field == "control_writes" else "ready"
                connection = self.connection_for()
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_result$") as error:
                    self.serve()
                self.assertEqual([item["kind"] for item in connection.writes], ["Challenge"])
                self.assertNotIn("private-secret-marker", str(error.exception))

    def test_readback_for_different_wrapper_cannot_be_signed_as_own_result(self):
        for field, value in (("pid", CLIENT.pid + 1),
                             ("created_filetime_100ns", str(CLIENT.created_filetime_100ns + 1))):
            with self.subTest(field=field):
                self.result = query_result()
                self.result["executions"][0]["wrapper"][field] = value
                connection = self.connection_for()
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_result_owner_mismatch$"):
                    self.serve()
                self.assertEqual([item["kind"] for item in connection.writes], ["Challenge"])

    def test_database_time_consumes_same_deadline_and_no_result_is_sent_after_expiry(self):
        def lookup(*args, **kwargs):
            self.clock.now += 990
            return self.record

        def expired_dispatch(*args, **kwargs):
            self.assertEqual(kwargs["timeout_ms"], 10)
            result = self.dispatch(*args, **kwargs)
            self.clock.now += 10
            return result

        self.auth.side_effect = lookup
        self.query.side_effect = expired_dispatch
        connection = self.connection_for()
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_deadline_exceeded$"):
            self.serve(timeout_ms=1000)
        self.query.assert_called_once()
        self.assertEqual([item["kind"] for item in connection.writes], ["Challenge"])
        self.assertTrue(all(item is self.listener.accepted[0] for item in connection.deadlines))

    def test_endpoint_mismatch_never_accepts_a_connection(self):
        self.connection_for()
        self.listener.endpoint = replace(self.endpoint, instance_id=OTHER_INSTANCE)
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_endpoint_mismatch$"):
            self.serve()
        self.assertEqual(self.listener.accepted, [])
        self.auth.assert_not_called()


class ClientTests(IpcTestCase):
    def setUp(self):
        super().setUp()
        self.context = QueryContext()
        self.client = ipc.ManagedExecutionClient(self.context, self.endpoint)

    def connection_for(self, *, challenge_transform=None, response_transform=None, result=None, peer=SERVER):
        message, challenge = None, None
        result = query_result() if result is None else result

        def respond(connection, outgoing):
            nonlocal message, challenge
            if outgoing["kind"] == "Request":
                message = outgoing
                challenge = {"version": 1, "kind": "Challenge", "request_id": outgoing["request_id"],
                    "nonce": NONCE, "endpoint_id": INSTANCE, "server": SERVER.to_dict(), "client": CLIENT.to_dict()}
                if challenge_transform is not None:
                    challenge = challenge_transform(challenge)
                connection.enqueue(challenge)
            elif outgoing["kind"] == "Proof":
                self.assertEqual(outgoing["mac"], wire_mac("proof", message, challenge))
                response = {**correlated("Result", message, challenge, wire_mac("result", message, challenge, result)),
                            "result": deepcopy(result)}
                connection.enqueue(response if response_transform is None else response_transform(response, outgoing))
            elif outgoing["kind"] == "Receipt":
                self.assertEqual(outgoing["mac"], wire_mac("receipt", message, challenge, result))

        self.connection = Connection(peer, on_write=respond)
        return self.connection

    def run_query(self):
        with patch.object(ipc.NativePipeConnection, "connect", return_value=self.connection) as connect:
            result = self.client.query_execution(request_id=REQUEST_ID)
        self.assertEqual(connect.call_count, 1)
        self.assertIs(connect.call_args.args[0], self.endpoint)
        return result

    def test_query_uses_only_own_execution_separate_key_and_one_connection(self):
        connection = self.connection_for()
        self.assertEqual(self.run_query(), query_result())
        self.assertEqual(connection.writes[0], request())
        self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof", "Receipt"])
        self.assertTrue(connection.closed)
        self.assertEqual(len({id(deadline) for deadline in connection.deadlines}), 1)
        self.assertEqual([item["domain"] for item in self.context.calls],
                         ["ResourceSentinel/query-ipc/v1/" + purpose for purpose in ("proof", "result", "receipt")])
        self.context.launch_claim_token.assert_not_called()
        self.context.cancel_reserved.assert_not_called()
        self.assertNotIn(KEY.hex(), json.dumps(connection.writes))

    def test_readiness_uses_same_authenticated_exchange_and_exact_execution(self):
        connection = self.connection_for(result=readiness_result(recorded_mode="canary"))
        with patch.object(ipc.NativePipeConnection, "connect", return_value=connection):
            result = self.client.get_readiness(request_id=REQUEST_ID)
        self.assertEqual(result, readiness_result(recorded_mode="canary"))
        self.assertEqual(connection.writes[0], request("GetReadiness"))
        self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof", "Receipt"])
        self.context.launch_claim_token.assert_not_called()
        self.context.cancel_reserved.assert_not_called()

    def test_authenticated_readiness_for_another_execution_is_rejected(self):
        connection = self.connection_for(result=readiness_result(execution_id=OTHER_EXECUTION))
        with patch.object(ipc.NativePipeConnection, "connect", return_value=connection):
            with self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_result$"):
                self.client.get_readiness(request_id=REQUEST_ID)
        self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])

    def test_native_server_is_verified_before_sending_execution_selector(self):
        connection = self.connection_for(peer=replace(SERVER, created_filetime_100ns=SERVER.created_filetime_100ns + 1))
        with self.assertRaisesRegex(NativePipeError, "^pipe_peer_unverified$"):
            self.run_query()
        self.assertEqual(connection.writes, [])
        self.assertEqual(self.context.calls, [])

    def test_challenge_cannot_introduce_server_client_endpoint_or_request_identity(self):
        for field in ("server", "client", "endpoint_id", "request_id"):
            with self.subTest(field=field):
                self.context.calls.clear()
                def change(challenge):
                    if field in {"server", "client"}:
                        challenge[field]["pid"] += 1
                    else:
                        challenge[field] = OTHER_INSTANCE if field == "endpoint_id" else OTHER_REQUEST
                    return challenge
                connection = self.connection_for(challenge_transform=change)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_challenge_binding_mismatch$"):
                    self.run_query()
                self.assertEqual([item["kind"] for item in connection.writes], ["Request"])
                self.assertEqual(self.context.calls, [])

    def test_corrupt_result_and_reflected_proof_mac_are_rejected_without_receipt(self):
        for failure in ("tampered-result", "mac", "proof-domain", "nonce", "request_id", "kind"):
            with self.subTest(failure=failure):
                def corrupt(response, proof):
                    if failure == "tampered-result":
                        response["result"]["registry_revision"] += 1
                    elif failure == "mac":
                        response["mac"] = "0" * 64
                    elif failure == "proof-domain":
                        response["mac"] = proof["mac"]
                    else:
                        response[{"nonce": "nonce", "request_id": "request_id", "kind": "kind"}[failure]] = {
                            "nonce": "c" * 64, "request_id": OTHER_REQUEST, "kind": "Receipt"}[failure]
                    return response
                connection = self.connection_for(response_transform=corrupt)
                with self.assertRaises(ipc.IpcError):
                    self.run_query()
                self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])
                self.assertTrue(connection.closed)

    def test_authenticated_false_control_or_private_result_is_still_rejected(self):
        for result in (query_result(control_writes=True), query_result(native_readiness="ready"),
                       query_result(os_limit_state="disabled"), query_result(private_command="private-secret-marker")):
            with self.subTest(field=result):
                connection = self.connection_for(result=result)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_result$") as error:
                    self.run_query()
                self.assertNotIn("private-secret-marker", str(error.exception))
                self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])

    def test_valid_mac_does_not_authorize_malformed_nested_diagnostic_values(self):
        cases = (
            (("floor", "cpu_units"), True),
            (("floor", "commit_bytes"), -1),
            (("wrapper", "created_filetime_100ns"), CLIENT.created_filetime_100ns),
            (("allocation", "kind"), "routed"),
            (("allocation", "recorded_binding"), {"private": "private-secret-marker"}),
            (("state",), {}),
            (("launch_in_flight",), 1),
            (("hold_reason",), "private-secret-marker"),
            (("root",), {"pid": SERVER.pid, "created_filetime_100ns": "0"}),
        )
        for path, value in cases:
            with self.subTest(path=path):
                result = query_result()
                target = result["executions"][0]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                connection = self.connection_for(result=result)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_invalid_result$") as error:
                    self.run_query()
                self.assertNotIn("private-secret-marker", str(error.exception))
                self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])

    def test_valid_mac_does_not_authorize_result_for_a_different_wrapper(self):
        for field, value in (("pid", CLIENT.pid + 1),
                             ("created_filetime_100ns", str(CLIENT.created_filetime_100ns + 1))):
            with self.subTest(field=field):
                result = query_result()
                result["executions"][0]["wrapper"][field] = value
                connection = self.connection_for(result=result)
                with self.assertRaisesRegex(ipc.IpcError, "^ipc_result_owner_mismatch$"):
                    self.run_query()
                self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])

    def test_server_becoming_unknown_after_proof_prevents_result_acceptance(self):
        def lose_peer(response, _):
            self.connection.retained.observation = IdentityObservation(SERVER, IdentityStatus.UNKNOWN, "query_failed")
            return response

        connection = self.connection_for(response_transform=lose_peer)
        with self.assertRaisesRegex(ipc.IpcError, "^ipc_peer_unverified$"):
            self.run_query()
        self.assertEqual([item["kind"] for item in connection.writes], ["Request", "Proof"])
        self.assertTrue(connection.closed)

    def test_different_logon_never_connects(self):
        endpoint = NativePipeEndpoint("S-1-5-5-300-400", INSTANCE,
                                      replace(SERVER, logon_id="S-1-5-5-300-400"))
        client = ipc.ManagedExecutionClient(self.context, endpoint)
        with patch.object(ipc.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(ipc.IpcError, "^ipc_binding_mismatch$"):
                client.query_execution(request_id=REQUEST_ID)
        connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
