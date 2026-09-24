"""Portable authenticated protocol/custody tests; no native acceptance evidence.

The concrete transport runs against completed in-memory pipe transfers and real
VerifiedProcess wrappers with explicit fake native backends. Parent methods are
patched on the exact ProductionExperimentScope class, not accepted as callbacks
by production code. These tests never activate a daily generation or use a DB.
"""
from contextlib import contextmanager
from dataclasses import replace
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import pickle
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from sentinel.adaptive import experiment_host_transport as transport
from sentinel.adaptive import experiment_host_scope as scope_module
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.identity import IdentityUnavailable, VerifiedProcess
from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeError
from tests.test_adaptive_ipc import Clock, Connection, Listener, canonical, wire_frame


LOGON = "S-1-5-5-100-200"
CHILD = ProcessIdentity(os.getpid(), 134343072000000001, LOGON)
PARENT = ProcessIdentity(os.getpid() + 1, 134343072000000002, LOGON)
ENDPOINT_ID = "5ec1e614-9dd9-47db-b54b-8ec9767b36aa"
SCOPE = "0aadef58-91ae-44d4-a31f-0ec97975b146"
GENERATION = "47fe8a64-1e71-45b1-b7a7-10361e4b4d65"
DAILY_POLICY = "65f2b66f-228a-473d-b9db-71ea68cfa963"
ISOLATED_POLICY = "05b6a036-a6cd-49ae-8125-cfd43c996aa0"
MEMBER = "a9dc1135-f64f-45aa-a296-154cff23090d"
REQUEST = "138b341e-87b0-4715-8b48-1d75d9c0f50a"
OTHER = "32d9f1ba-9749-43d5-ba1f-840522283f79"
KEY = bytes(range(32))
NONCE = "e" * 64


def wire_mac(purpose, request, challenge, result=None, *, domain="experiment-child-ipc", key=KEY):
    transcript = {"domain": "ResourceSentinel/" + domain + "/v1/" + purpose,
                  "request": request, "challenge": challenge}
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, canonical(transcript), hashlib.sha256).hexdigest()


class Backend:
    def __init__(self, identity):
        self.subject = identity
        self.status = IdentityStatus.ALIVE
        self.closed = []
        self.copies = []
        self.copy_error = self.close_error = None
        self.copy_output = 72
        self.on_copy = None

    def wait(self, handle):
        if handle in self.closed:
            return IdentityStatus.UNKNOWN
        return self.status

    def identity(self, _handle):
        return self.subject

    def duplicate_into(self, source, output, *, source_process=None):
        self.copies.append(source)
        if self.on_copy is not None:
            self.on_copy()
        output.value = self.copy_output
        if self.copy_error is not None:
            raise self.copy_error

    def close(self, handle):
        self.closed.append(handle)
        if self.close_error is not None:
            raise self.close_error


class Pipe(Connection):
    """Completed I/O fixture with independent peer and channel close failures."""
    def __init__(self, identity, incoming=b"", **kwargs):
        super().__init__(identity, incoming, **kwargs)
        self.backend = Backend(identity)
        self.retained = VerifiedProcess(self.backend, 71, identity)
        self.peer_error = self.channel_error = None
        self.on_channel_close = None

    @contextmanager
    def verified_peer(self, expected):
        self.verified.append(expected)
        if self.retained.identity != expected:
            raise NativePipeError("pipe_peer_unverified")
        self.peer_held = True
        primary = None
        try:
            yield self.retained
        except BaseException as error:
            primary = error
            raise
        finally:
            self.peer_held = False
            if self.peer_error is not None:
                if primary is None:
                    raise self.peer_error
                primary.fixture_peer_cleanup = self.peer_error
            else:
                self.retained.close()

    def __exit__(self, _kind, error, _traceback):
        if self.on_channel_close is not None:
            self.on_channel_close()
        if self.channel_error is not None:
            if error is not None:
                error.fixture_channel_cleanup = self.channel_error
            else:
                raise self.channel_error
        else:
            self.closed = True


class ExperimentTransportTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.endpoint = NativePipeEndpoint(LOGON, ENDPOINT_ID, PARENT)
        self.manifest = transport.ExperimentChildManifest(
            self.endpoint, CHILD, SCOPE, "a" * 64, "b" * 64, GENERATION, "c" * 64, "d" * 64,
            str(root / "daily.db"), transport.LedgerFileIdentity(7, 101), DAILY_POLICY,
            str(root / "isolated.db"), transport.LedgerFileIdentity(7, 102), ISOLATED_POLICY,
            MEMBER, "wrapper", (MEMBER,), REQUEST)
        self.registration = transport.ExperimentChildRegistration(self.manifest, KEY)
        self.request = transport.BindExperimentChildRequest(self.manifest)
        self.child_backend = Backend(CHILD)
        self.child = VerifiedProcess(self.child_backend, 41, CHILD)
        self.parent_backend = Backend(PARENT)
        self.parent = VerifiedProcess(self.parent_backend, 42, PARENT)
        self.owner = object.__new__(scope_module.ProductionExperimentScope)
        self.clock = Clock()
        self.retained_services = []
        self.accepted = []
        self.registrations = []
        for replacement in (
                patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock),
                patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=False),
                patch.object(transport.secrets, "token_hex", return_value=NONCE),
                patch.dict(transport._ORIGINAL_CLIENTS, {}, clear=True),
                patch.object(scope_module.ProductionExperimentScope, "_assert_transport_original",
                             lambda owner, endpoint: self.assert_parent(owner, endpoint)),
                patch.object(scope_module.ProductionExperimentScope, "_retain_child_transport",
                             lambda owner, service: self.retained_services.append((owner, service))),
                patch.object(scope_module.ProductionExperimentScope, "_transport_child_registration",
                             lambda owner, request, peer: self.lookup(owner, request, peer)),
                patch.object(scope_module.ProductionExperimentScope, "_accept_transport_child",
                             lambda owner, request, peer, registration: self.accept(owner, request, peer, registration))):
            replacement.start()
            self.addCleanup(replacement.stop)
        with patch.object(transport.os, "getpid", return_value=PARENT.pid):
            self.service = transport.ExperimentChildService(self.endpoint, self.owner)
        self.client = transport.ExperimentChildClient(self.registration, self.child)
        self.connection = None

    def assert_parent(self, owner, endpoint):
        self.assertIs(owner, self.owner)
        self.assertEqual(endpoint, self.endpoint)
        return self.parent

    def lookup(self, owner, request, peer):
        self.assertIs(owner, self.owner)
        self.assertTrue(self.connection.peer_held)
        self.assertIs(peer, self.connection.retained)
        if request.manifest != self.manifest:
            raise transport.ExperimentChildError("original_registration_changed")
        self.registrations.append(request)
        return self.registration

    def accept(self, owner, request, peer, registration):
        self.assertIs(owner, self.owner)
        self.assertIs(registration, self.registration)
        self.assertTrue(self.connection.peer_held)
        self.assertIs(peer, self.connection.retained)
        self.accepted.append(request)

    def challenge(self, **changes):
        return {"version": 1, "kind": "ExperimentChildChallenge", "request_id": REQUEST,
                "nonce": NONCE, "endpoint_id": ENDPOINT_ID, "server": PARENT.to_dict(),
                "client": CHILD.to_dict(), **changes}

    def message(self, kind, purpose, *, result=None, **changes):
        value = {"version": 1, "kind": kind, "request_id": REQUEST, "nonce": NONCE,
                 "mac": wire_mac(purpose, self.request.to_dict(), self.challenge(), result), **changes}
        if result is not None and kind == "ExperimentChildResult":
            value["result"] = result
        return value

    def server_pipe(self, *, request=None, proof=None, receipt=None, peer=CHILD):
        result = {"bound_manifest": self.manifest.to_dict()}
        hello = {"version": 1, "kind": "ExperimentChildHello", "request_id": REQUEST,
                 "caller": CHILD.to_dict()}
        frames = (hello, self.request.to_dict() if request is None else request,
                  self.message("ExperimentChildProof", "proof") if proof is None else proof,
                  self.message("ExperimentChildReceipt", "receipt", result=result) if receipt is None else receipt)
        return Pipe(peer, b"".join(wire_frame(frame) for frame in frames))

    def client_pipe(self, *, challenge=None, response=None, peer=PARENT):
        result = {"bound_manifest": self.manifest.to_dict()}
        return Pipe(peer, wire_frame(self.challenge() if challenge is None else challenge) +
                    wire_frame(self.message("ExperimentChildResult", "result", result=result)
                               if response is None else response))

    def serve(self, connection):
        self.connection = connection
        with patch.object(transport.os, "getpid", return_value=PARENT.pid):
            return self.service.serve_once(Listener(self.endpoint, connection))

    def bind(self, connection):
        with patch.object(transport.NativePipeConnection, "connect", return_value=connection):
            return self.client.bind()

    def test_manifest_round_trip_and_credentials_are_not_exported(self):
        wire = self.request.to_dict()
        self.assertEqual(transport.BindExperimentChildRequest.from_dict(wire), self.request)
        self.assertNotIn("auth_key", json.dumps(wire))
        self.assertNotIn(repr(KEY), repr(self.registration))
        with self.assertRaisesRegex(transport.ExperimentChildError, "original_binding_required"):
            transport.ExperimentChildBinding(self.client)

    def test_manifest_rejects_unknown_fields_roles_and_unbounded_members(self):
        for change in ({"role": "arbitrary_worker"}, {"permitted_member_ids": (MEMBER, MEMBER)},
                       {"permitted_member_ids": tuple([MEMBER] * 129)},
                       {"daily_policy_instance_id": ISOLATED_POLICY},
                       {"daily_ledger_identity": self.manifest.isolated_ledger_identity},
                       {"scope_nonce": "short"}):
            with self.subTest(change=change), self.assertRaises((transport.IpcError, ValueError)):
                replace(self.manifest, **change)
        value = self.manifest.to_dict() | {"capacity_granted": True}
        with self.assertRaises(transport.ExperimentChildError):
            transport.ExperimentChildManifest.from_dict(value)
        self.assertEqual(replace(self.manifest, permitted_member_ids=()).permitted_member_ids, ())

    def test_service_verifies_created_peer_before_body_and_accepts_only_after_mac(self):
        connection = self.server_pipe()
        self.assertIsNone(self.serve(connection))
        self.assertEqual(len(self.registrations), 1)
        self.assertEqual(self.accepted, [self.request])
        self.assertEqual(self.retained_services, [(self.owner, self.service)])
        self.assertTrue(connection.closed)
        self.assertTrue(self.service.attempts[0].peer_settled)
        self.assertTrue(self.service.attempts[0].channel_settled)
        result = {"bound_manifest": self.manifest.to_dict()}
        self.assertEqual(connection.writes, [self.challenge(),
            self.message("ExperimentChildResult", "result", result=result)])

    def test_wrong_or_dead_peer_never_reads_binding_body(self):
        for peer, status in ((replace(CHILD, created_filetime_100ns=CHILD.created_filetime_100ns + 1), IdentityStatus.ALIVE),
                             (CHILD, IdentityStatus.DEAD), (CHILD, IdentityStatus.UNKNOWN)):
            with self.subTest(peer=peer, status=status):
                connection = self.server_pipe(peer=peer)
                connection.backend.status = status
                with self.assertRaises(transport.ExperimentChildError):
                    self.serve(connection)
                self.assertEqual(len(connection.reads), 2)
                self.assertEqual(connection.writes, [])
        self.assertEqual(self.registrations, [])
        self.assertEqual(self.accepted, [])

    def test_oversized_hello_rejects_before_allocating_or_authenticating(self):
        connection = Pipe(CHILD, struct.pack("<I", transport.MAX_HELLO_BYTES + 1) + b"private")
        with self.assertRaises(transport.ExperimentChildError):
            self.serve(connection)
        self.assertEqual(connection.reads, [4])
        self.assertEqual(connection.verified, [])

    def test_cross_domain_proof_cannot_bind(self):
        proof = self.message("ExperimentChildProof", "proof",
            mac=wire_mac("proof", self.request.to_dict(), self.challenge(), domain="launch-ipc"))
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.serve(self.server_pipe(proof=proof))
        self.assertIn("authentication_failed", str(caught.exception.original_error))
        self.assertEqual(self.accepted, [])

    def test_changed_manifest_with_same_request_id_never_accepts(self):
        mutations = ({"scope_nonce": "f" * 64}, {"source_generation": OTHER},
                     {"config_digest": "f" * 64}, {"plan_sha256": "f" * 64},
                     {"daily_ledger_identity": transport.LedgerFileIdentity(8, 103)},
                     {"isolated_policy_instance_id": OTHER}, {"role": "helper"},
                     {"permitted_member_ids": ()})
        for changes in mutations:
            with self.subTest(changes=changes):
                request = transport.BindExperimentChildRequest(replace(self.manifest, **changes))
                with self.assertRaises(transport.ExperimentChildError):
                    self.serve(self.server_pipe(request=request.to_dict()))
        self.assertEqual(self.accepted, [])

    def test_lost_receipt_keeps_original_accepted_attempt(self):
        connection = self.server_pipe(receipt=self.message("ExperimentChildReceipt", "receipt", mac="0" * 64))
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.serve(connection)
        self.assertEqual(self.accepted, [self.request])
        self.assertTrue(caught.exception.attempt.accepted)
        self.assertIs(caught.exception.attempt, self.service.attempts[0])
        self.assertIs(caught.exception.attempt.connection, connection)

    def test_client_duplicates_inside_original_peer_and_returns_after_cleanup(self):
        connection = self.client_pipe()
        connection.backend.on_copy = lambda: self.assertTrue(connection.peer_held)
        binding = self.bind(connection)
        self.assertIs(type(binding), transport.ExperimentChildBinding)
        self.assertIsNot(binding._peer, connection.retained)
        self.assertTrue(connection.closed)
        self.assertEqual(connection.backend.closed, [71])
        self.assertEqual(binding._peer._handle, 72)
        self.assertTrue(binding.custody_pending)
        self.assertIsNone(binding.revalidate(self.manifest, role="wrapper", member_id=MEMBER))
        self.assertEqual([message["kind"] for message in connection.writes],
                         ["ExperimentChildHello", "BindExperimentChild", "ExperimentChildProof", "ExperimentChildReceipt"])
        self.assertEqual(connection.writes[2], self.message("ExperimentChildProof", "proof"))
        self.clock.now += 2000
        # The RPC deadline is not a TTL pretending to retire the child.
        self.assertIsNone(binding.revalidate(self.manifest, role="wrapper"))
        with self.assertRaises(TypeError):
            pickle.dumps(binding)
        binding.close()
        self.assertEqual(connection.backend.closed, [71, 72])
        self.assertFalse(binding.custody_pending)
        binding.close()
        self.assertEqual(connection.backend.closed, [71, 72])

    def test_client_wrong_parent_sends_no_frames_or_credential_proof(self):
        connection = self.client_pipe(peer=replace(PARENT, created_filetime_100ns=PARENT.created_filetime_100ns + 1))
        with self.assertRaises(transport.ExperimentChildError):
            self.bind(connection)
        self.assertEqual(connection.writes, [])
        self.assertEqual(connection.backend.copies, [])

    def test_wrong_challenge_or_result_never_duplicates(self):
        connection = self.client_pipe(challenge=self.challenge(endpoint_id=OTHER))
        with self.assertRaises(transport.ExperimentChildError):
            self.bind(connection)
        self.assertEqual(connection.backend.copies, [])
        self.assertEqual([message["kind"] for message in connection.writes],
                         ["ExperimentChildHello", "BindExperimentChild"])

    def test_native_mutex_refuses_client_and_service_before_rpc(self):
        connection = self.client_pipe()
        with patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=True), \
                patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(transport.ExperimentChildError, "lock_held"):
                self.client.bind()
            with self.assertRaisesRegex(transport.ExperimentChildError, "lock_held"):
                self.service.serve_once(Listener(self.endpoint, connection))
        connect.assert_not_called()
        self.assertEqual(self.service.attempts, ())

    def test_connect_unknown_before_return_keeps_original_registry_and_pending_attempt(self):
        failure = NativePipeError("pipe_identity_unavailable")
        failure.add_note("pipe initialization cleanup unknown")
        with patch.object(transport.NativePipeConnection, "connect", side_effect=failure) as connect:
            with self.assertRaises(transport.ExperimentChildError) as caught:
                self.client.bind()
        binding = caught.exception.binding
        self.assertIs(caught.exception.original_error, failure)
        self.assertIsNone(binding._attempt.connection)
        self.assertTrue(binding._attempt.channel_started)
        self.assertIs(binding._attempt.channel_origin, binding._registry)
        self.assertIs(connect.call_args.kwargs["registry"], binding._registry)
        self.assertTrue(binding.custody_pending)
        with self.assertRaisesRegex(transport.ExperimentChildError, "cleanup_pending"):
            binding.close()
        with self.assertRaisesRegex(transport.ExperimentChildError, "original_attempt_retained"):
            self.client.bind()

    def test_unknown_duplicate_output_retains_original_and_cannot_retry_or_close(self):
        connection = self.client_pipe()
        failure = RuntimeError("synthetic_duplicate_unknown")
        connection.backend.copy_error = failure
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.bind(connection)
        binding = caught.exception.binding
        self.assertIs(caught.exception.original_error, failure)
        self.assertIs(binding._attempt.error, failure)
        self.assertIs(binding._attempt.error_owners[0], failure._identity_handle_cleanup[0])
        original = failure._identity_handle_cleanup[0]
        self.assertEqual(original._output.value, 72)
        self.assertIsNone(binding._peer)
        self.assertTrue(binding.custody_pending)
        with self.assertRaisesRegex(transport.ExperimentChildError, "cleanup_pending"):
            binding.close()
        with self.assertRaisesRegex(transport.ExperimentChildError, "original_attempt_retained"):
            self.client.bind()
        other = transport.ExperimentChildClient(self.registration, self.child)
        with self.assertRaisesRegex(transport.ExperimentChildError, "original_attempt_retained"):
            other.bind()
        self.assertEqual(connection.backend.copies, [71])
        self.assertEqual(connection.backend.closed, [71])
        with patch.object(original, "_output", ctypes.c_void_p(72)):
            with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                binding.close()

    def test_explicit_failed_duplicate_with_zero_output_has_no_partial_native_owner(self):
        connection = self.client_pipe()
        failure = IdentityUnavailable("process_duplicate_unavailable", 5)
        failure._native_duplicate_failed = True
        connection.backend.copy_error = failure
        connection.backend.copy_output = None
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.bind(connection)
        binding = caught.exception.binding
        self.assertEqual(binding._attempt.error_owners, ())
        # The attempted RPC is still not replayed, even when native duplication failed cleanly.
        self.assertFalse(binding._attempt.exchange_complete)
        self.assertEqual(connection.backend.closed, [71])
        self.assertTrue(binding._attempt.peer_settled)
        self.assertTrue(binding._attempt.channel_settled)
        self.assertFalse(binding.custody_pending)
        binding.close()
        self.assertFalse(binding.custody_pending)
        with self.assertRaisesRegex(transport.ExperimentChildError, "original_attempt_retained"):
            self.client.bind()

    def test_peer_and_channel_close_failure_keep_both_original_errors(self):
        connection = self.client_pipe()
        peer_error, channel_error = RuntimeError("peer_unknown"), RuntimeError("channel_unknown")
        connection.peer_error, connection.channel_error = peer_error, channel_error
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.bind(connection)
        binding = caught.exception.binding
        self.assertIs(caught.exception.original_error, peer_error)
        self.assertEqual(peer_error._experiment_transport_cleanup, (channel_error,))
        self.assertTrue(binding.custody_pending)
        self.assertIsNotNone(binding._peer)
        self.assertFalse(binding._issued)
        with self.assertRaisesRegex(transport.ExperimentChildError, "cleanup_pending"):
            binding.close()
        self.assertEqual(connection.backend.closed, [])

    def test_channel_close_and_late_deadline_never_issue_binding(self):
        connection = self.client_pipe()
        connection.on_channel_close = lambda: setattr(self.clock, "now", self.clock.now + 1001)
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.bind(connection)
        self.assertFalse(caught.exception.binding._issued)
        self.assertTrue(caught.exception.binding.custody_pending)
        self.assertTrue(connection.closed)

    def test_final_liveness_failure_cannot_later_activate_failed_binding(self):
        connection = self.client_pipe()
        connection.on_channel_close = lambda: setattr(connection.backend, "status", IdentityStatus.UNKNOWN)
        with self.assertRaises(transport.ExperimentChildError) as caught:
            self.bind(connection)
        binding = caught.exception.binding
        self.assertFalse(binding._issued)
        connection.backend.status = IdentityStatus.ALIVE
        with self.assertRaisesRegex(transport.ExperimentChildError, "binding_unavailable"):
            binding.revalidate(self.manifest, role="wrapper")
        binding.close()
        self.assertFalse(binding.custody_pending)

    def test_same_identity_duplicate_or_handle_replacement_is_refused_before_close(self):
        connection = self.client_pipe()
        binding = self.bind(connection)
        original = binding._peer
        with patch.object(binding, "_peer", VerifiedProcess(connection.backend, 72, PARENT)):
            with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                binding.close()
        replacement = VerifiedProcess(connection.backend, 72, PARENT)
        with patch.object(binding, "_peer", replacement), \
                patch.object(binding, "_peer_pin", transport._NativePin(replacement)):
            with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                binding.close()
        with patch.object(original, "_handle", 99):
            with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                binding.revalidate(self.manifest, role="wrapper")
            with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                binding.close()
            with patch.object(binding, "_peer_pin", transport._NativePin(original)):
                with self.assertRaisesRegex(transport.ExperimentChildError, "original_native_custody_changed"):
                    binding.close()
        self.assertEqual(connection.backend.closed, [71])
        binding.close()

    def test_unknown_owned_peer_close_is_sticky_even_if_handle_state_is_changed(self):
        connection = self.client_pipe()
        binding = self.bind(connection)
        error = RuntimeError("synthetic_owned_close_unknown")
        connection.backend.close_error = error
        with self.assertRaises(RuntimeError) as caught:
            binding.close()
        self.assertIs(caught.exception, error)
        self.assertIs(error.experiment_child_binding, binding)
        with patch.object(binding._peer, "_close_outcome_unknown", False):
            with self.assertRaisesRegex(transport.ExperimentChildError, "cleanup_pending"):
                binding.close()
        self.assertTrue(binding.custody_pending)
        self.assertEqual(connection.backend.closed.count(72), 1)

    def test_changed_role_member_parent_liveness_or_thread_cannot_use_binding(self):
        connection = self.client_pipe()
        binding = self.bind(connection)
        with self.assertRaisesRegex(transport.ExperimentChildError, "binding_unavailable"):
            binding.revalidate(self.manifest, role="guardian")
        with self.assertRaisesRegex(transport.ExperimentChildError, "member_not_permitted"):
            binding.revalidate(self.manifest, role="wrapper", member_id=OTHER)
        connection.backend.status = IdentityStatus.DEAD
        with self.assertRaisesRegex(transport.ExperimentChildError, "parent_unavailable"):
            binding.revalidate(self.manifest, role="wrapper")
        connection.backend.status = IdentityStatus.ALIVE
        errors = []
        def check():
            try:
                binding.revalidate(self.manifest, role="wrapper")
            except BaseException as error:
                errors.append(error)
        thread = threading.Thread(target=check)
        thread.start()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIn("original_binding_changed", str(errors[0]))
        binding.close()


if __name__ == "__main__":
    unittest.main()
