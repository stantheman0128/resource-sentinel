"""Portable fixed backing protocol tests; no native or daily activation claim.

Actual child binding and ManagedAdmission objects use explicit fake process and
pipe backends. Parent methods are patched on the exact production class; their
durable SQL/replay behavior has separate connected parent tests. Wire MACs here
are independently computed. No fixture result is evidence of actual capacity.
"""
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import pickle
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import admission
from sentinel.adaptive import experiment_backing_transport as transport
from sentinel.adaptive import experiment_host_backing as backing
from sentinel.adaptive import experiment_host_scope as scope
from sentinel.adaptive import experiment_host_transport as child
from sentinel.adaptive.contracts import Priority, ResourceDemand, Role
from sentinel.adaptive.pipe_windows import NativePipeError
from tests import test_adaptive_experiment_host_transport as child_fixture
from tests.test_adaptive_ipc import Listener, canonical, wire_frame


REQUEST = "6f2f7e0e-682f-4ea4-91cf-8b7f689c18bf"
MEMBER = child_fixture.OTHER
RESERVATION = "isolated-fixed-reservation"
KEY = child_fixture.KEY


def wire_mac(purpose, request, challenge, result=None, *, domain="experiment-backing-ipc"):
    value = dict(domain="ResourceSentinel/" + domain + "/v1/" + purpose,
                 request=request, challenge=challenge)
    if purpose != "proof":
        value["result"] = result
    return hmac.new(KEY, canonical(value), hashlib.sha256).hexdigest()


class BackingTransportTests(unittest.TestCase):
    def setUp(self):
        self.host = child_fixture.ExperimentTransportTests()
        self.host.setUp()
        self.addCleanup(self.host.doCleanups)
        self.host.manifest = replace(self.host.manifest, permitted_member_ids=(MEMBER,))
        self.host.registration = child.ExperimentChildRegistration(self.host.manifest, KEY)
        self.host.request = child.BindExperimentChildRequest(self.host.manifest)
        self.host.client = child.ExperimentChildClient(self.host.registration, self.host.child)
        self.binding = self.host.bind(self.host.client_pipe())
        with patch.object(admission.VerifiedProcess, "current", return_value=self.host.child):
            self.context = admission.ManagedAdmission.current(command="private-command-marker", cwd=self.host.directory.name,
                repo_identifier="fixture-repo", requested=ResourceDemand(.1, 64 << 20, 64 << 20, 0),
                role=Role.BACKGROUND, priority=Priority.P2)
        self.snapshot = self.context.snapshot()
        self.retained_services, self.registration_calls, self.publication_calls = [], [], []
        self.original_operations = {}
        self.accepted = True
        self.fail_after_publication = None
        self.channel = None
        for replacement in (
                patch.dict(transport._PUBLICATIONS, {}, clear=True),
                patch.object(scope.ProductionExperimentScope, "_retain_backing_transport",
                             lambda owner, service: self.retained_services.append((owner, service))),
                patch.object(scope.ProductionExperimentScope, "_transport_backing_registration",
                             lambda owner, request, peer: self.registration(owner, request, peer)),
                patch.object(scope.ProductionExperimentScope, "_publish_transport_backing",
                             lambda owner, request, peer, registration: self.publish_parent(owner, request, peer, registration))):
            replacement.start()
            self.addCleanup(replacement.stop)
        self.operation = transport.ExperimentBackingPublication.prepare(self.binding, self.context,
            member_id=MEMBER, reservation_id=RESERVATION, request_id=REQUEST)
        self.request = self.operation.request
        with patch.object(child.os, "getpid", return_value=child_fixture.PARENT.pid):
            self.service = transport.ExperimentBackingService(self.host.endpoint, self.host.owner)

    def observation(self, request=None):
        request = self.request if request is None else request
        return backing.BackingObservation(request.manifest.scope_id, request.member_id,
            request.manifest.actor_member_id, request.binding, 7, "f" * 64, 2000000000.0)

    def result(self, request=None):
        value = self.observation(request)
        return dict(scope_id=value.scope_id, member_id=value.member_id, wrapper_member_id=value.wrapper_member_id,
            binding=value.binding.to_dict(), registered_revision=value.registered_revision,
            binding_sha256=value.binding_sha256, daily_expires_at=value.daily_expires_at)

    def challenge(self, request=None, **changes):
        request = self.request if request is None else request
        return dict(version=1, kind="ExperimentBackingChallenge", request_id=request.request_id,
            nonce=child_fixture.NONCE, endpoint_id=request.manifest.endpoint.instance_id,
            server=request.manifest.endpoint.server_identity.to_dict(), client=request.manifest.child_identity.to_dict(),
            payload_sha256=request.payload_sha256, **changes)

    def envelope(self, kind, purpose, *, request=None, result=None, mac=None):
        request = self.request if request is None else request
        value = dict(version=1, kind=kind, request_id=request.request_id, nonce=child_fixture.NONCE,
            mac=mac or wire_mac(purpose, request.to_dict(), self.challenge(request), result))
        if kind == "ExperimentBackingResult":
            value["result"] = result
        return value

    def client_pipe(self, *, result=None, peer=child_fixture.PARENT, response=None):
        result = self.result() if result is None else result
        response = self.envelope("ExperimentBackingResult", "result", result=result) if response is None else response
        return child_fixture.Pipe(peer, wire_frame(self.challenge()) + wire_frame(response))

    def server_pipe(self, *, request=None, peer=child_fixture.CHILD, proof=None, receipt=None):
        request = self.request if request is None else request
        result = self.result(request)
        hello = dict(version=1, kind="ExperimentBackingHello", request_id=request.request_id,
                     caller=request.manifest.child_identity.to_dict())
        proof = self.envelope("ExperimentBackingProof", "proof", request=request) if proof is None else proof
        receipt = (self.envelope("ExperimentBackingReceipt", "receipt", request=request, result=result)
                   if receipt is None else receipt)
        return child_fixture.Pipe(peer, b"".join(wire_frame(value) for value in
            (hello, request.to_dict(), proof, receipt)))

    def registration(self, owner, request, peer):
        self.assertIs(owner, self.host.owner)
        self.assertIs(peer, self.channel.retained)
        self.assertTrue(self.channel.peer_held)
        if not self.accepted or request.manifest != self.host.manifest:
            raise transport.ExperimentBackingTransportError("original_child_not_accepted")
        self.registration_calls.append(request)
        return self.host.registration

    def publish_parent(self, owner, request, peer, registration):
        self.registration(owner, request, peer)
        self.assertIs(registration, self.host.registration)
        self.publication_calls.append(request)
        prior = self.original_operations.get(request.request_id)
        if prior is None:
            self.original_operations[request.request_id] = (
                request.payload_sha256, request.observation.parent_snapshot, object(), self.observation(request))
        elif prior[0] != request.payload_sha256:
            raise transport.ExperimentBackingTransportError("original_payload_changed")
        if self.fail_after_publication is not None:
            raise self.fail_after_publication
        return self.original_operations[request.request_id][3]

    def serve(self, connection):
        self.channel = connection
        with patch.object(child.os, "getpid", return_value=child_fixture.PARENT.pid):
            return self.service.serve_once(Listener(self.host.endpoint, connection))

    def publish(self, connection):
        with patch.object(transport.NativePipeConnection, "connect", return_value=connection):
            return self.operation.publish()

    def test_observation_omits_credentials_payload_and_unneeded_attribution(self):
        encoded = json.dumps(self.request.to_dict())
        for omitted in ("ipc_auth_key", "claim_token", self.snapshot.ipc_auth_key.hex(), self.snapshot.claim_token_hash,
                        "private-command-marker", self.snapshot.task_id, self.snapshot.session_id, self.snapshot.principal_id):
            self.assertNotIn(omitted, encoded)
        decoded = transport.PublishExperimentBackingRequest.from_dict(self.request.to_dict())
        self.assertEqual(decoded.binding, backing._snapshot_binding(self.snapshot, RESERVATION))
        self.assertIs(type(decoded.observation.parent_snapshot), admission.ManagedAdmissionSnapshot)
        self.assertEqual(decoded.observation.parent_snapshot.ipc_auth_key, b"")
        self.assertEqual(decoded.observation.parent_snapshot.claim_token_hash, "")
        self.assertEqual(decoded.observation.parent_snapshot.request.command, "")
        self.assertIsNot(decoded.observation.parent_snapshot, self.snapshot)
        self.assertIsNot(decoded.observation.parent_snapshot, self.context)
        with self.assertRaises(TypeError):
            pickle.dumps(self.operation)

    def test_unknown_observation_fields_and_changed_digest_are_rejected(self):
        wire = self.request.to_dict()
        wire["observation"]["ipc_auth_key"] = "0" * 64
        with self.assertRaises(transport.ExperimentBackingTransportError):
            transport.PublishExperimentBackingRequest.from_dict(wire)
        wire = self.request.to_dict()
        wire["payload_sha256"] = "0" * 64
        with self.assertRaisesRegex(transport.ExperimentBackingTransportError, "payload_digest_mismatch"):
            transport.PublishExperimentBackingRequest.from_dict(wire)

    def test_only_exact_original_context_and_wrapper_member_are_accepted(self):
        with self.assertRaisesRegex(transport.ExperimentBackingTransportError, "original_child_context_required"):
            transport.ExperimentBackingPublication.prepare(self.binding, self.snapshot,
                member_id=MEMBER, reservation_id=RESERVATION, request_id=REQUEST)
        with self.assertRaises(child.ExperimentChildError):
            transport.ExperimentBackingPublication.prepare(self.binding, self.context,
                member_id=str(uuid4()), reservation_id=RESERVATION, request_id=REQUEST)
        with self.assertRaisesRegex(transport.ExperimentBackingTransportError, "original_publication_retained"):
            transport.ExperimentBackingPublication.prepare(self.binding, self.context,
                member_id=MEMBER, reservation_id=RESERVATION, request_id=str(uuid4()))

    def test_copy_of_snapshot_cannot_replace_local_original_before_rpc(self):
        with patch.object(self.context, "_snapshot", replace(self.snapshot)), \
                patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(transport.ExperimentBackingTransportError, "original_publication_changed"):
                self.operation.publish()
        connect.assert_not_called()

    def test_prior_admission_or_unsettled_submission_cannot_be_backfilled(self):
        for field, value in (("_submitted", True), ("_admission_db_path", Path(self.host.directory.name)),
                             ("_submission_transaction", {}), ("_claim_exported", True),
                             ("_submission_prepare_unknown", True)):
            with self.subTest(field=field), patch.object(self.context, field, value), \
                    patch.object(transport.NativePipeConnection, "connect") as connect:
                with self.assertRaises((transport.ExperimentBackingTransportError, admission.ManagedAdmissionUnavailable)):
                    self.operation.publish()
                connect.assert_not_called()

    def test_client_returns_observation_after_original_peer_and_channel_cleanup(self):
        connection = self.client_pipe()
        self.assertEqual(self.publish(connection), self.observation())
        self.assertTrue(connection.closed)
        self.assertEqual(connection.backend.closed, [71])
        self.assertEqual(connection.backend.copies, [])
        self.assertEqual([message["kind"] for message in connection.writes],
                         ["ExperimentBackingHello", "PublishExperimentBacking", "ExperimentBackingProof", "ExperimentBackingReceipt"])
        self.assertEqual(connection.writes[2], self.envelope("ExperimentBackingProof", "proof"))
        self.assertIs(self.context.snapshot(), self.snapshot)
        self.assertFalse(self.context._submitted)
        self.assertFalse(self.context._claim_exported)

    def test_wrong_parent_sends_no_message_or_authentication_proof(self):
        wrong = replace(child_fixture.PARENT, created_filetime_100ns=child_fixture.PARENT.created_filetime_100ns + 1)
        connection = self.client_pipe(peer=wrong)
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.publish(connection)
        self.assertEqual(connection.writes, [])

    def test_server_authenticates_before_body_and_calls_fixed_parent_after_proof(self):
        connection = self.server_pipe()
        self.assertIsNone(self.serve(connection))
        self.assertEqual(len(self.publication_calls), 1)
        self.assertEqual(self.retained_services, [(self.host.owner, self.service)])
        self.assertTrue(connection.closed)
        self.assertEqual(connection.writes, [self.challenge(),
            self.envelope("ExperimentBackingResult", "result", result=self.result())])

    def test_wrong_peer_never_reads_body_or_calls_parent(self):
        wrong = replace(child_fixture.CHILD, created_filetime_100ns=child_fixture.CHILD.created_filetime_100ns + 1)
        connection = self.server_pipe(peer=wrong)
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.serve(connection)
        self.assertEqual(len(connection.reads), 2)
        self.assertEqual(self.registration_calls, [])
        self.assertEqual(self.publication_calls, [])

    def test_unaccepted_child_and_cross_domain_mac_cannot_publish(self):
        self.accepted = False
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.serve(self.server_pipe())
        self.accepted = True
        proof = self.envelope("ExperimentBackingProof", "proof", mac=wire_mac("proof", self.request.to_dict(),
            self.challenge(), domain="experiment-child-ipc"))
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.serve(self.server_pipe(proof=proof))
        self.assertEqual(self.publication_calls, [])

    def test_parent_lost_ack_replay_reuses_one_original_snapshot_and_operation(self):
        self.fail_after_publication = RuntimeError("synthetic_commit_reply_lost")
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.serve(self.server_pipe())
        original = self.original_operations[REQUEST]
        self.fail_after_publication = None
        self.assertIsNone(self.serve(self.server_pipe()))
        self.assertIs(self.original_operations[REQUEST], original)
        self.assertEqual(len(self.original_operations), 1)
        changed = replace(self.request, reservation_id="different-reservation")
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.serve(self.server_pipe(request=changed))
        self.assertIs(self.original_operations[REQUEST], original)

    def test_clean_lost_response_retries_same_child_request_without_reminting(self):
        first = self.client_pipe()
        first.incoming = bytearray(wire_frame(self.challenge()))  # parent may have committed; reply is absent
        with self.assertRaises(transport.ExperimentBackingTransportError) as caught:
            self.publish(first)
        self.assertTrue(caught.exception.attempt.accepted)
        self.assertFalse(caught.exception.attempt.cleanup_pending)
        original_request, original_snapshot = self.operation.request, self.operation._snapshot
        second = self.client_pipe()
        self.assertEqual(self.publish(second), self.observation())
        self.assertIs(self.operation.request, original_request)
        self.assertIs(self.operation._snapshot, original_snapshot)
        self.assertEqual(first.writes[1], second.writes[1])

    def test_channel_close_unknown_prevents_retry_and_does_not_close_child_binding(self):
        connection = self.client_pipe()
        failure = RuntimeError("synthetic_channel_close_unknown")
        connection.channel_error = failure
        with self.assertRaises(transport.ExperimentBackingTransportError) as caught:
            self.publish(connection)
        self.assertIs(caught.exception.original_error, failure)
        self.assertIs(caught.exception.transport_owner, self.operation)
        with patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(transport.ExperimentBackingTransportError, "original_cleanup_pending"):
                self.operation.publish()
        connect.assert_not_called()
        self.assertIsNone(self.binding.revalidate(self.host.manifest, role="wrapper", member_id=MEMBER))

    def test_failed_connect_retains_original_registry_before_return(self):
        failure = NativePipeError("pipe_initialization_unknown")
        with patch.object(transport.NativePipeConnection, "connect", side_effect=failure) as connect:
            with self.assertRaises(transport.ExperimentBackingTransportError) as caught:
                self.operation.publish()
        self.assertIs(caught.exception.original_error, failure)
        self.assertIsNone(caught.exception.attempt.connection)
        self.assertTrue(caught.exception.attempt.cleanup_pending)
        self.assertIs(connect.call_args.kwargs["registry"], self.operation._registry)

    def test_mutex_held_rejects_before_client_or_server_rpc(self):
        with patch("sentinel.adaptive.windows.current_thread_holds_mutex", return_value=True), \
                patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(child.ExperimentChildError, "lock_held"):
                self.operation.publish()
            with self.assertRaisesRegex(child.ExperimentChildError, "lock_held"):
                self.service.serve_once(Listener(self.host.endpoint, self.server_pipe()))
        connect.assert_not_called()
        self.assertEqual(self.service.attempts, ())

    def test_mac_valid_but_changed_backing_result_is_rejected(self):
        result = self.result()
        result["binding"] = result["binding"] | {"reservation_id": "foreign"}
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.publish(self.client_pipe(result=result))
        self.assertIsNone(self.operation._result)

    def test_late_cleanup_cannot_return_a_publication_observation(self):
        connection = self.client_pipe()
        connection.on_channel_close = lambda: setattr(self.host.clock, "now", self.host.clock.now + 1001)
        with self.assertRaises(transport.ExperimentBackingTransportError):
            self.publish(connection)
        self.assertIsNone(self.operation._result)
        self.assertTrue(connection.closed)


if __name__ == "__main__":
    unittest.main()
