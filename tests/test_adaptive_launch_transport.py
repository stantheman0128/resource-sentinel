"""Launch RPC protocol/real admitted-credential tests; no native launch evidence.

ManagedAdmission, Coordinator and SQLite authentication are real isolated code.
The explicit pipe fixture models completed byte transfers, not Win32 I/O. The
fixed test owner revalidates SQLite auth and emits synthetic typed results; the
guardian launch suite separately covers mutation and handle ownership. Expected
MAC bytes are independently constructed from the published wire contract.
"""
from dataclasses import FrozenInstanceError, replace
import hashlib
import hmac
import json
import struct
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import launch_transport as transport
from sentinel.adaptive.admission import ManagedAdmissionUnavailable
from sentinel.adaptive.contracts import IdentityObservation, IdentityStatus, ProcessIdentity
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeError
from sentinel.adaptive.store import LifecycleError, authenticated_query
from tests import test_adaptive_managed_admission as admission_fixtures
from tests.test_adaptive_admission_context import PAYLOAD
from tests.test_adaptive_coordinator import NOW
from tests.test_adaptive_ipc import Clock, Connection, Listener, canonical, wire_frame


EPOCH = "guardian-launch-fixture"
NONCE = "0123456789abcdef" * 2
CHALLENGE = "c" * 64
INSTANCE = "0aadef58-91ae-44d4-a31f-0ec97975b146"
EXECUTION = "5ec1e614-9dd9-47db-b54b-8ec9767b36aa"
REQUEST = "47fe8a64-1e71-45b1-b7a7-10361e4b4d65"
ROOT = ProcessIdentity(49001, 134343072000000009, "S-1-5-5-100-200")


def common(**changes):
    return dict(request_id=REQUEST, execution_id=EXECUTION, spec_hash="a" * 64,
                guardian_epoch=EPOCH, expected_revision=0) | changes


def mac(key, purpose, message, challenge, result=None, *, domain="launch-ipc"):
    transcript = {"domain": "ResourceSentinel/" + domain + "/v1/" + purpose,
                  "request": message, "challenge": challenge}
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, canonical(transcript), hashlib.sha256).hexdigest()


def envelope(kind, request, challenge, digest):
    return {"version": 1, "kind": kind, "request_id": request["request_id"],
            "nonce": challenge["nonce"], "mac": digest}


class LaunchCodecTests(unittest.TestCase):
    def requests(self):
        return (transport.PrepareExecutionRequest(**common()),
                transport.ClaimLaunchRequest(**common(), job_nonce=NONCE, claim_token="t" * 43),
                transport.BindRootRequest(**common(), job_nonce=NONCE,
                    root_identity=ROOT, root_handle_locator=440))

    def test_roundtrip_exact_typed_requests_and_independent_whole_payload_digest(self):
        for request in self.requests():
            with self.subTest(operation=request.operation):
                self.assertEqual(type(request).from_dict(request.to_dict()), request)
                self.assertEqual(transport.decode_request(request.to_dict()), request)
                self.assertEqual(request.payload_hash(), hashlib.sha256(canonical(request.to_dict())).hexdigest())
                with self.assertRaises(FrozenInstanceError):
                    request.request_id = str(uuid4())
        self.assertNotIn("t" * 43, repr(self.requests()[1]))
        self.assertEqual(self.requests()[2].to_dict()["root_handle_locator"], "440")

    def test_wire_rejects_extra_raw_payload_and_cross_operation_fields(self):
        for request in self.requests():
            for extra in ({"command": PAYLOAD["command"]}, {"cwd": PAYLOAD["cwd"]},
                          {"env": {"PRIVATE": "marker"}}, {"handler": "arbitrary"}, {"unexpected": None}):
                with self.subTest(operation=request.operation, extra=tuple(extra)), self.assertRaises(IpcError):
                    transport.decode_request(request.to_dict() | extra)
        claim = self.requests()[1].to_dict()
        with self.assertRaises(IpcError):
            transport.decode_request(claim | {"operation": "PrepareExecution"})
        with self.assertRaises(IpcError):
            transport.PrepareExecutionRequest.from_dict(claim)

    def test_old_or_unrecognized_launch_fence_protocol_is_rejected(self):
        request = self.requests()[1].to_dict()
        unfenced = dict(request)
        unfenced.pop("launch_fence_version")
        with self.assertRaises(IpcError):
            transport.decode_request(unfenced)
        for version in (None, True, 0, 2, "1"):
            with self.subTest(version=version), self.assertRaises(IpcError):
                transport.decode_request(request | {"launch_fence_version": version})

    def test_retirement_requests_contain_no_claim_or_asserted_native_evidence(self):
        for cls in (transport.CancelBeforeStartRequest, transport.StartFailedRequest):
            request = cls(**common(), job_nonce=NONCE)
            self.assertEqual(transport.decode_request(request.to_dict()), request)
            for extra in ({"launch_failed": True}, {"user_code_started": False}, {"claim_token": "t" * 43}):
                with self.subTest(operation=request.operation, extra=extra), self.assertRaises(IpcError):
                    transport.decode_request(request.to_dict() | extra)

    def test_wire_rejects_invalid_version_identifiers_epoch_revision_and_operation(self):
        base = self.requests()[0].to_dict()
        for change in ({"version": True}, {"version": 2}, {"kind": "Request"}, {"operation": "QueryExecution"},
                       {"request_id": "00000000-0000-0000-0000-000000000000"},
                       {"execution_id": EXECUTION.upper()}, {"spec_hash": "A" * 64},
                       {"guardian_epoch": "two words"}, {"guardian_epoch": "x" * 129},
                       {"expected_revision": True}, {"expected_revision": -1}, {"expected_revision": 1 << 63}):
            with self.subTest(change=change), self.assertRaises(IpcError):
                transport.decode_request(base | change)

    def test_root_locator_is_canonical_decimal_not_pid_or_pseudo_handle(self):
        request = self.requests()[2].to_dict()
        for locator in (440, True, "0", "-1", "0440", "+440", "440.0", " 440", "1e3",
                        str(1 << (8 * struct.calcsize("P") - 1)), "9" * 40):
            with self.subTest(locator=locator), self.assertRaises(IpcError):
                transport.decode_request(request | {"root_handle_locator": locator})
        for locator in (False, 0, -1, 1.0):
            with self.subTest(locator=locator), self.assertRaises(IpcError):
                transport.BindRootRequest(**common(), job_nonce=NONCE, root_identity=ROOT,
                                          root_handle_locator=locator)

    def test_payload_hash_changes_for_each_launch_binding_and_root_identity_component(self):
        claim = self.requests()[1]
        changes = (dict(request_id=str(uuid4())), dict(execution_id=str(uuid4())), dict(spec_hash="b" * 64),
                   dict(guardian_epoch="another-epoch"), dict(expected_revision=1),
                   dict(job_nonce="f" * 32), dict(claim_token="u" * 43))
        for change in changes:
            with self.subTest(change=tuple(change)):
                self.assertNotEqual(claim.payload_hash(), replace(claim, **change).payload_hash())
        bound = self.requests()[2]
        for change in (dict(root_handle_locator=444), dict(root_identity=replace(ROOT, pid=ROOT.pid + 1)),
                       dict(root_identity=replace(ROOT, created_filetime_100ns=ROOT.created_filetime_100ns + 1)),
                       dict(root_identity=replace(ROOT, logon_id="S-1-5-5-200-300"))):
            self.assertNotEqual(bound.payload_hash(), replace(bound, **change).payload_hash())

    def test_result_never_allows_authorized_duplicate_or_arbitrary_job_name(self):
        result = transport.LaunchResult(EXECUTION, "a" * 64, EPOCH, "LAUNCHING", 2,
            f"Local\\ResourceSentinel.Job.{EXECUTION}.{NONCE}", NONCE, True, False)
        self.assertEqual(transport.LaunchResult.from_dict(result.to_dict()), result)
        for change in ({"duplicate": True}, {"launch_authorized": 1}, {"state": "PREPARED"},
                       {"job_name": "Global\\unrelated"}, {"job_nonce": "f" * 32},
                       {"state_revision": True}, {"command": "private"}):
            with self.subTest(change=change), self.assertRaises(IpcError):
                transport.LaunchResult.from_dict(result.to_dict() | change)


class LedgerOwner:
    """Fixed synthetic operation results, but actual admitted-auth revalidation."""
    def __init__(self, test):
        self.test, self.calls = test, []
        self.before_auth = self.after_auth = None
        self.result_change = None

    def _call(self, expected, request, peer, auth_record, deadline):
        case = self.test
        case.assertEqual(request.operation, expected)
        case.assertTrue(case.connection.peer_held)
        case.assertIs(peer, case.connection.retained)
        case.assertEqual(auth_record.wrapper_identity, case.snapshot.wrapper_identity)
        case.assertEqual(auth_record.ipc_auth_key, case.snapshot.ipc_auth_key)
        case.assertGreater(deadline.remaining_ms(), 0)
        if self.before_auth:
            self.before_auth()
        # A fixture cannot certify native mutation. This real readonly check
        # proves the exact persisted private record reaches the fixed owner.
        authenticated_query(case.coordinator.db_path, request.execution_id, auth_record)
        self.calls.append((expected, request, deadline))
        if self.after_auth:
            self.after_auth()
        result = case.result_for(request)
        return result if self.result_change is None else self.result_change(result)

    def prepare_execution(self, request, peer, *, auth_record, deadline):
        return self._call("PrepareExecution", request, peer, auth_record, deadline)

    def claim_launch(self, request, peer, *, auth_record, deadline):
        return self._call("ClaimLaunch", request, peer, auth_record, deadline)

    def bind_root(self, request, peer, *, auth_record, deadline):
        return self._call("BindRoot", request, peer, auth_record, deadline)

    def retire_before_start(self, request, peer, *, auth_record, deadline):
        return self._call(request.operation, request, peer, auth_record, deadline)


class LaunchTransportTests(unittest.TestCase):
    context = admission_fixtures.ManagedAdmissionTests.context
    conn = admission_fixtures.ManagedAdmissionTests.conn
    admit = admission_fixtures.ManagedAdmissionTests.admit
    counts = admission_fixtures.ManagedAdmissionTests.counts

    def setUp(self):
        admission_fixtures.ManagedAdmissionTests.setUp(self)
        self.context_value = self.context(requested=replace(PAYLOAD["requested"], io_slots=0))
        admitted = self.admit(self.context_value)
        self.assertTrue(admitted["allowed"], admitted)
        self.snapshot = self.context_value.snapshot()
        self.clock = Clock()
        clock = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        caller = self.snapshot.wrapper_identity
        self.server = replace(caller, pid=caller.pid + 10000,
                              created_filetime_100ns=caller.created_filetime_100ns + 7)
        self.endpoint = NativePipeEndpoint(caller.logon_id, INSTANCE, self.server)
        self.owner = LedgerOwner(self)
        self.service = transport.LaunchService(self.coordinator.db_path, self.endpoint, self.owner)
        self.client = transport.ManagedLaunchClient(self.context_value, self.endpoint, guardian_epoch=EPOCH)

    def request(self, operation="PrepareExecution", **changes):
        values = common(execution_id=self.snapshot.execution_id, spec_hash=self.snapshot.spec_hash) | changes
        if operation == "ClaimLaunch":
            return transport.ClaimLaunchRequest(**values, job_nonce=NONCE,
                                                 claim_token=self.context_value._claim_token)
        if operation == "BindRoot":
            return transport.BindRootRequest(**values, job_nonce=NONCE,
                root_identity=replace(ROOT, logon_id=self.snapshot.logon_id), root_handle_locator=440)
        if operation in {"CancelBeforeStart", "StartFailed"}:
            cls = transport.CancelBeforeStartRequest if operation == "CancelBeforeStart" else transport.StartFailedRequest
            return cls(**values, job_nonce=NONCE)
        return transport.PrepareExecutionRequest(**values)

    def result_for(self, request):
        state = {"PrepareExecution": "PREPARED", "ClaimLaunch": "LAUNCHING", "BindRoot": "RUNNING",
                 "CancelBeforeStart": "CANCELLED_BEFORE_START", "StartFailed": "START_FAILED"}[request.operation]
        return transport.LaunchResult(request.execution_id, request.spec_hash, request.guardian_epoch, state,
            request.expected_revision + 1, f"Local\\ResourceSentinel.Job.{request.execution_id}.{NONCE}", NONCE,
            request.operation == "ClaimLaunch", False)

    def service_connection(self, request=None, *, proof_transform=None, receipt_transform=None,
                           peer=None, on_challenge=None):
        request = self.request() if request is None else request
        message = request.to_dict()
        challenge = None
        def respond(connection, outgoing):
            nonlocal challenge
            self.assertTrue(connection.peer_held)
            if outgoing["kind"] == "LaunchChallenge":
                challenge = outgoing
                if on_challenge:
                    on_challenge(connection, outgoing)
                proof = envelope("LaunchProof", message, challenge,
                                 mac(self.snapshot.ipc_auth_key, "proof", message, challenge))
                connection.enqueue(proof if proof_transform is None else proof_transform(proof, challenge))
            elif outgoing["kind"] == "LaunchResult":
                self.assertEqual(outgoing["mac"], mac(self.snapshot.ipc_auth_key, "result", message,
                                                     challenge, outgoing["result"]))
                receipt = envelope("LaunchReceipt", message, challenge,
                    mac(self.snapshot.ipc_auth_key, "receipt", message, challenge, outgoing["result"]))
                if receipt_transform:
                    receipt = receipt_transform(receipt)
                if receipt is not None:
                    connection.enqueue(receipt)
        self.connection = Connection(self.snapshot.wrapper_identity if peer is None else peer,
                                     wire_frame(message), on_write=respond)
        return self.connection

    def serve(self, connection, *, timeout_ms=1000):
        return self.service.serve_once(Listener(self.endpoint, connection), timeout_ms=timeout_ms)

    def client_connection(self, *, result_transform=None, challenge_transform=None,
                          peer=None, receipt_error=False, on_request=None, after_proof=None):
        message = challenge = None
        def respond(connection, outgoing):
            nonlocal message, challenge
            self.assertTrue(connection.peer_held)
            if outgoing["kind"] == "LaunchRequest":
                message = outgoing
                if on_request:
                    on_request(connection, outgoing)
                challenge = {"version": 1, "kind": "LaunchChallenge", "request_id": message["request_id"],
                    "nonce": CHALLENGE, "endpoint_id": self.endpoint.instance_id, "guardian_epoch": EPOCH,
                    "server": self.server.to_dict(), "client": self.snapshot.wrapper_identity.to_dict()}
                if challenge_transform:
                    challenge = challenge_transform(challenge)
                connection.enqueue(challenge)
            elif outgoing["kind"] == "LaunchProof":
                self.assertEqual(outgoing["mac"], mac(self.snapshot.ipc_auth_key, "proof", message, challenge))
                if after_proof:
                    after_proof(connection)
                result = self.result_for(transport.decode_request(message)).to_dict()
                response = envelope("LaunchResult", message, challenge,
                    mac(self.snapshot.ipc_auth_key, "result", message, challenge, result)) | {"result": result}
                if result_transform:
                    response = result_transform(response, message, challenge)
                if response is not None:
                    connection.enqueue(response)
            elif outgoing["kind"] == "LaunchReceipt":
                if receipt_error:
                    raise OSError("private-fixture-failure-must-not-escape")
                result = self.result_for(transport.decode_request(message)).to_dict()
                self.assertEqual(outgoing["mac"], mac(self.snapshot.ipc_auth_key, "receipt", message, challenge, result))
        self.connection = Connection(self.server if peer is None else peer, on_write=respond)
        return self.connection

    def call_client(self, operation="PrepareExecution", *, timeout_ms=1000):
        with patch.object(transport.NativePipeConnection, "connect", return_value=self.connection) as connect:
            arguments = dict(expected_revision=0, request_id=REQUEST, timeout_ms=timeout_ms)
            if operation == "PrepareExecution":
                result = self.client.prepare_execution(**arguments)
            elif operation == "ClaimLaunch":
                result = self.client.claim_launch(**arguments, job_nonce=NONCE)
            elif operation == "CancelBeforeStart":
                result = self.client.cancel_before_start(**arguments, job_nonce=NONCE)
            elif operation == "StartFailed":
                result = self.client.start_failed(**arguments, job_nonce=NONCE)
            else:
                result = self.client.bind_root(**arguments, job_nonce=NONCE,
                    root_identity=replace(ROOT, logon_id=self.snapshot.logon_id), root_handle_locator=440)
            self.assertEqual(connect.call_count, 1)
            return result

    def test_service_uses_real_durable_credentials_for_all_fixed_methods_and_holds_peer(self):
        before = tuple(self.conn().execute("SELECT state,state_revision,claim_consumed FROM managed_executions").fetchone())
        for operation in ("PrepareExecution", "ClaimLaunch", "BindRoot", "CancelBeforeStart", "StartFailed"):
            with self.subTest(operation=operation):
                connection = self.service_connection(self.request(operation))
                result = self.serve(connection)
                self.assertEqual(result["operation"], operation)
                self.assertTrue(result["receipt_verified"])
                self.assertEqual(self.owner.calls[-1][0], operation)
                self.assertFalse(connection.peer_held)
                self.assertTrue(connection.closed)
                self.assertTrue(all(d is self.owner.calls[-1][2] for d in connection.deadlines))
        self.assertEqual(len(self.owner.calls), 5)
        self.assertEqual(tuple(self.conn().execute("SELECT state,state_revision,claim_consumed FROM managed_executions").fetchone()), before)

    def test_client_uses_actual_managed_private_mac_and_never_exports_raw_command(self):
        for operation in ("PrepareExecution", "BindRoot", "ClaimLaunch", "CancelBeforeStart", "StartFailed"):
            with self.subTest(operation=operation):
                self.client_connection()
                result = self.call_client(operation)
                self.assertIs(type(result), transport.LaunchResult)
                self.assertEqual(result.execution_id, self.snapshot.execution_id)
                self.assertEqual([v["kind"] for v in self.connection.writes],
                                 ["LaunchRequest", "LaunchProof", "LaunchReceipt"])
                text = json.dumps(self.connection.writes)
                self.assertNotIn(PAYLOAD["command"], text)
                self.assertNotIn("private-cwd-marker", text)
                self.assertNotIn(self.snapshot.ipc_auth_key.hex(), text)
                self.assertTrue(self.connection.closed)
        self.assertTrue(self.context_value._claim_exported)

    def test_client_never_exports_claim_or_writes_before_exact_server_pin(self):
        for peer in (replace(self.server, pid=self.server.pid + 1),
                     replace(self.server, created_filetime_100ns=self.server.created_filetime_100ns + 1),
                     replace(self.server, logon_id="S-1-5-5-200-300")):
            with self.subTest(peer=peer):
                self.client_connection(peer=peer)
                with self.assertRaises(transport.LaunchTransportError) as caught:
                    self.call_client("ClaimLaunch")
                self.assertFalse(caught.exception.launch_outcome_unknown)
                self.assertFalse(self.context_value._claim_exported)
                self.assertEqual(self.connection.writes, [])

    def test_claim_is_exported_only_inside_live_server_scope(self):
        self.client_connection()
        original = self.context_value.launch_claim_token
        def checked_claim():
            self.assertTrue(self.connection.peer_held)
            self.assertEqual(self.connection.verified, [self.server])
            return original()
        with patch.object(self.context_value, "launch_claim_token", side_effect=checked_claim) as exported:
            self.call_client("ClaimLaunch")
        self.assertEqual(exported.call_count, 1)

    def test_prepare_preserves_unexported_claim_but_refuses_reserved_cancellation(self):
        self.client_connection()
        self.call_client()
        self.assertFalse(self.context_value._claim_exported)
        row = self.conn().execute("SELECT reservation_id FROM managed_executions").fetchone()
        with self.assertRaisesRegex(ManagedAdmissionUnavailable, "prepare_already_attempted"):
            self.context_value.cancel_reserved(self.coordinator.db_path,
                reservation_id=row[0], expected_revision=0, now=NOW + 1)
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_direct_prepare_fences_cancellation_before_connect_and_keeps_retry(self):
        row = self.conn().execute("SELECT reservation_id FROM managed_executions").fetchone()
        def connection_failure(*_):
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "prepare_already_attempted"):
                self.context_value.cancel_reserved(self.coordinator.db_path,
                    reservation_id=row[0], expected_revision=0, now=NOW + 1)
            raise OSError("fixture connection failed before write")
        with patch.object(transport.NativePipeConnection, "connect", side_effect=connection_failure) as connect:
            with self.assertRaises(transport.LaunchTransportError) as caught:
                self.client.prepare_execution(expected_revision=0, request_id=REQUEST)
        self.assertFalse(caught.exception.launch_outcome_unknown)
        connect.assert_called_once()
        self.assertEqual(self.counts(), (0, 1, 1))
        self.client_connection()
        result = self.call_client()
        self.assertEqual(result.state, "PREPARED")
        self.assertEqual(self.counts(), (0, 1, 1))

    def test_sealed_cancellation_refuses_direct_prepare_before_connect(self):
        row = self.conn().execute("SELECT reservation_id FROM managed_executions").fetchone()
        result = self.context_value.cancel_reserved(self.coordinator.db_path,
            reservation_id=row[0], expected_revision=0, now=NOW + 1)
        self.assertTrue(result["cancelled"])
        with patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(ManagedAdmissionUnavailable, "managed_admission_sealed"):
                self.client.prepare_execution(expected_revision=0, request_id=REQUEST)
        connect.assert_not_called()
        self.assertEqual(self.counts(), (0, 0, 1))

    def test_stable_request_id_is_required_before_connection_for_exact_replay(self):
        with patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaises(TypeError):
                self.client.prepare_execution(expected_revision=0)
            with self.assertRaises(transport.LaunchTransportError) as caught:
                self.client.prepare_execution(expected_revision=0, request_id=None)
        self.assertFalse(caught.exception.launch_outcome_unknown)
        connect.assert_not_called()

    def test_service_refuses_wrong_peer_pid_birth_and_logon_before_challenge(self):
        caller = self.snapshot.wrapper_identity
        for peer in (replace(caller, pid=caller.pid + 1),
                     replace(caller, created_filetime_100ns=caller.created_filetime_100ns + 1),
                     replace(caller, logon_id="S-1-5-5-200-300")):
            with self.subTest(peer=peer), self.assertRaisesRegex(NativePipeError, "pipe_peer_unverified"):
                connection = self.service_connection(peer=peer)
                self.serve(connection)
            self.assertEqual(connection.writes, [])
            self.assertEqual(self.owner.calls, [])

    def test_service_refuses_unknown_or_exited_peer_before_owner(self):
        for state in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            with self.subTest(state=state):
                connection = self.service_connection()
                connection.retained.observation = IdentityObservation(
                    self.snapshot.wrapper_identity, state, "fixture_unknown" if state is IdentityStatus.UNKNOWN else None)
                with self.assertRaisesRegex(IpcError, "ipc_peer_unverified"):
                    self.serve(connection)
                self.assertEqual(self.owner.calls, [])

    def test_query_domain_proof_cannot_authorize_launch(self):
        message = self.request().to_dict()
        connection = self.service_connection(proof_transform=lambda proof, challenge:
            proof | {"mac": mac(self.snapshot.ipc_auth_key, "proof", message, challenge, domain="query-ipc")})
        with self.assertRaisesRegex(IpcError, "launch_auth_failed"):
            self.serve(connection)
        self.assertEqual(self.owner.calls, [])

    def test_claim_proof_covers_private_token_and_cannot_be_reused_after_token_mutation(self):
        request = self.request("ClaimLaunch")
        signed = request.to_dict() | {"claim_token": "q" * 43}
        connection = self.service_connection(request, proof_transform=lambda proof, challenge:
            proof | {"mac": mac(self.snapshot.ipc_auth_key, "proof", signed, challenge)})
        with self.assertRaisesRegex(IpcError, "launch_auth_failed"):
            self.serve(connection)
        self.assertEqual(self.owner.calls, [])

    def test_unknown_execution_wrong_spec_and_foreign_root_logon_never_get_challenge(self):
        requests = (self.request(execution_id=str(uuid4())), self.request(spec_hash="f" * 64),
            replace(self.request("BindRoot"), root_identity=replace(ROOT, logon_id="S-1-5-5-200-300")))
        for request in requests:
            with self.subTest(request=request), self.assertRaises((IpcError, LifecycleError)):
                connection = self.service_connection(request)
                self.serve(connection)
            self.assertEqual(connection.writes, [])
            self.assertEqual(self.owner.calls, [])

    def test_proof_binds_epoch_request_operation_execution_spec_revision_nonce_locator_and_root(self):
        request = self.request("BindRoot")
        message = request.to_dict()
        variants = ({"guardian_epoch": "foreign-epoch"}, {"request_id": str(uuid4())},
            {"operation": "ClaimLaunch"}, {"execution_id": str(uuid4())}, {"spec_hash": "e" * 64},
            {"expected_revision": 1}, {"job_nonce": "e" * 32}, {"root_handle_locator": "444"},
            {"root_identity": replace(request.root_identity, created_filetime_100ns=request.root_identity.created_filetime_100ns + 1).to_dict()})
        for change in variants:
            with self.subTest(change=tuple(change)):
                connection = self.service_connection(request, proof_transform=lambda proof, challenge, c=change:
                    proof | {"mac": mac(self.snapshot.ipc_auth_key, "proof", message | c, challenge)})
                with self.assertRaisesRegex(IpcError, "launch_auth_failed"):
                    self.serve(connection)
        self.assertEqual(self.owner.calls, [])

    def test_durable_key_change_during_handshake_reaches_owner_as_stale_auth_and_is_rejected(self):
        self.owner.before_auth = lambda: self.conn().execute(
            "UPDATE managed_executions SET ipc_auth_key=?", (b"z" * 32,))
        connection = self.service_connection()
        with self.assertRaisesRegex(LifecycleError, "ipc_auth_binding_changed"):
            self.serve(connection)
        self.assertEqual(self.owner.calls, [])
        self.assertEqual([v["kind"] for v in connection.writes], ["LaunchChallenge"])

    def test_deadline_expiry_after_challenge_write_prevents_proof_read_and_owner_call(self):
        connection = self.service_connection(on_challenge=lambda *_: setattr(self.clock, "now", 2000))
        with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
            self.serve(connection)
        self.assertEqual(len(connection.reads), 2)
        self.assertEqual(self.owner.calls, [])

    def test_deadline_expiry_after_proof_body_read_prevents_owner_call(self):
        connection = self.service_connection()
        def expire_after_proof(connection, size):
            if len(connection.reads) == 4:
                self.clock.now = 2000
        connection.on_read = expire_after_proof
        with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
            self.serve(connection)
        self.assertEqual(len(connection.reads), 4)
        self.assertEqual(self.owner.calls, [])

    def test_owner_uses_same_deadline_and_late_completion_does_not_send_success(self):
        self.owner.after_auth = lambda: setattr(self.clock, "now", 2000)
        connection = self.service_connection()
        with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
            self.serve(connection)
        self.assertEqual(len(self.owner.calls), 1)
        self.assertEqual([v["kind"] for v in connection.writes], ["LaunchChallenge"])

    def test_missing_receipt_never_repeats_owner_operation_or_erases_outcome(self):
        connection = self.service_connection(receipt_transform=lambda _: None)
        with self.assertRaisesRegex(IpcError, "ipc_truncated_frame"):
            self.serve(connection)
        self.assertEqual(len(self.owner.calls), 1)
        self.assertEqual([v["kind"] for v in connection.writes], ["LaunchChallenge", "LaunchResult"])
        self.assertTrue(connection.closed)

    def test_invalid_receipt_does_not_repeat_owner(self):
        connection = self.service_connection(receipt_transform=lambda value: value | {"mac": "0" * 64})
        with self.assertRaisesRegex(IpcError, "launch_receipt_invalid"):
            self.serve(connection)
        self.assertEqual(len(self.owner.calls), 1)

    def test_transport_does_not_cache_duplicate_delivery(self):
        request = self.request()
        for _ in range(2):
            self.serve(self.service_connection(request))
        self.assertEqual(len(self.owner.calls), 2)
        self.assertEqual(self.owner.calls[0][1].payload_hash(), self.owner.calls[1][1].payload_hash())

    def test_service_rejects_result_with_wrong_binding_or_wrong_operation_state(self):
        for change in (dict(spec_hash="b" * 64), dict(guardian_epoch="wrong-epoch"),
                       dict(state="RUNNING"), dict(state="LAUNCHING", launch_authorized=True)):
            with self.subTest(change=change):
                self.owner.result_change = lambda result, c=change: replace(result, **c)
                connection = self.service_connection()
                with self.assertRaises(IpcError):
                    self.serve(connection)
                self.assertEqual([v["kind"] for v in connection.writes], ["LaunchChallenge"])

    def test_changed_challenge_fails_before_proof_and_reports_no_mutation(self):
        for change in ({"guardian_epoch": "wrong-epoch"}, {"endpoint_id": str(uuid4())},
                       {"server": replace(self.server, created_filetime_100ns=self.server.created_filetime_100ns + 1).to_dict()}):
            with self.subTest(change=tuple(change)):
                self.client_connection(challenge_transform=lambda value, c=change: value | c)
                with self.assertRaises(transport.LaunchTransportError) as caught:
                    self.call_client()
                self.assertFalse(caught.exception.launch_outcome_unknown)
                self.assertEqual([v["kind"] for v in self.connection.writes], ["LaunchRequest"])

    def test_missing_result_is_uncertain_and_has_no_automatic_retry(self):
        self.client_connection(result_transform=lambda *_: None)
        with patch.object(transport.NativePipeConnection, "connect", return_value=self.connection) as connect:
            with self.assertRaises(transport.LaunchTransportError) as caught:
                self.client.claim_launch(expected_revision=0, job_nonce=NONCE, request_id=REQUEST)
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertEqual(connect.call_count, 1)
        self.assertEqual([v["kind"] for v in self.connection.writes], ["LaunchRequest", "LaunchProof"])

    def test_partial_proof_write_is_already_uncertain(self):
        self.client_connection(after_proof=lambda _: (_ for _ in ()).throw(OSError("partial fixture")))
        with self.assertRaises(transport.LaunchTransportError) as caught:
            self.call_client("ClaimLaunch")
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertEqual(caught.exception.reason, "launch_rpc_failed")

    def test_invalid_result_mac_or_authenticated_semantics_never_returns_authority(self):
        def wrong_scope(response, message, challenge):
            result = response["result"] | {"guardian_epoch": "wrong-epoch"}
            return response | {"result": result,
                "mac": mac(self.snapshot.ipc_auth_key, "result", message, challenge, result)}
        for transform in (lambda response, *_: response | {"mac": "0" * 64}, wrong_scope):
            with self.subTest(transform=transform):
                self.client_connection(result_transform=transform)
                with self.assertRaises(transport.LaunchTransportError) as caught:
                    self.call_client("ClaimLaunch")
                self.assertTrue(caught.exception.launch_outcome_unknown)
                self.assertEqual([v["kind"] for v in self.connection.writes], ["LaunchRequest", "LaunchProof"])

    def test_receipt_failure_keeps_uncertainty_without_sensitive_exception_text(self):
        self.client_connection(receipt_error=True)
        with self.assertRaises(transport.LaunchTransportError) as caught:
            self.call_client("ClaimLaunch")
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertEqual(str(caught.exception), "launch_rpc_failed")
        self.assertNotIn(self.context_value._claim_token, repr(caught.exception))

    def test_sanitized_cleanup_failure_retains_exact_error_and_native_cleanup_owner(self):
        self.client_connection()
        native_owner = object()
        original = OSError("private-cleanup-failure-must-not-escape")
        original._identity_handle_cleanup = (native_owner,)
        class CleanupFailure(Connection):
            def __exit__(self, *_):
                raise original
        self.connection = CleanupFailure(self.server, on_write=self.connection.on_write)
        with self.assertRaises(transport.LaunchTransportError) as caught:
            self.call_client("ClaimLaunch")
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertEqual(str(caught.exception), "launch_rpc_failed")
        self.assertIs(caught.exception._transport_cleanup_error, original)
        self.assertIs(caught.exception._transport_cleanup_error._identity_handle_cleanup[0], native_owner)
        self.assertNotIn("private-cleanup", repr(caught.exception))

    def test_deadline_rechecked_after_successful_native_cleanup_before_authority_returns(self):
        self.client_connection()
        clock = self.clock
        class SlowCleanup(Connection):
            def __exit__(self, *_):
                self.closed = True
                clock.now = 2000
        self.connection = SlowCleanup(self.server, on_write=self.connection.on_write)
        with self.assertRaisesRegex(transport.LaunchTransportError, "ipc_deadline_exceeded") as caught:
            self.call_client("ClaimLaunch")
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertTrue(self.connection.closed)

    def test_peer_dies_after_challenge_client_does_not_send_proof(self):
        def died(challenge):
            self.connection.retained.observation = IdentityObservation(self.server, IdentityStatus.DEAD)
            return challenge
        self.client_connection(challenge_transform=died)
        with self.assertRaises(transport.LaunchTransportError) as caught:
            self.call_client()
        self.assertFalse(caught.exception.launch_outcome_unknown)
        self.assertEqual([v["kind"] for v in self.connection.writes], ["LaunchRequest"])

    def test_one_deadline_covers_client_all_phases_and_late_receipt_does_not_return(self):
        self.client_connection()
        original = self.connection.on_write
        def slow_receipt(connection, outgoing):
            original(connection, outgoing)
            if outgoing["kind"] == "LaunchReceipt":
                self.clock.now = 2000
        self.connection.on_write = slow_receipt
        with self.assertRaises(transport.LaunchTransportError) as caught:
            self.call_client()
        self.assertTrue(caught.exception.launch_outcome_unknown)
        self.assertTrue(all(d is self.connection.deadlines[0] for d in self.connection.deadlines))
