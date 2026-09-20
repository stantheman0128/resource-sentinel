"""Helper-to-guardian proposal transport over an explicit pipe fixture.

The ledger, the lifecycle store, the control slot, the policy coordinator, the
recovery journal, the exemption ledger, the infrastructure registry and
GuardianControl are the production modules against real temporary files. The
pipe connections, the Job, the processes and the mutexes are explicitly
synthetic: they model completed byte transfers, answer queries and count calls,
and they contain nothing.

Passing here is evidence about this transport's authentication and binding
decisions. It is not evidence about Windows Job containment, host support,
native Named Pipe I/O or timing. This machine cannot run the native path,
because a foreign parent Job blocks the supported host check.

Every ledger mode write below is a fixture write into an isolated test database.
Nothing here promotes a mode and no production configuration is read or changed.
"""
from contextlib import contextmanager
from dataclasses import replace
import struct
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import control_transport as transport
from sentinel.adaptive.contracts import (
    ApplyAck, ApplyResult, IdentityObservation, IdentityStatus, MAX_MESSAGE_BYTES,
    ProcessIdentity, Validity,
)
from sentinel.adaptive.decision import ControllerSnapshot, DecisionAction
from sentinel.adaptive.ipc import IpcError
from sentinel.adaptive.legacy_writer import initialize_registry_locked, register_infrastructure_locked
from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeError
from sentinel.adaptive.proposal_builder import build_control_proposal
from tests import test_adaptive_decision as decisions
from tests import test_adaptive_guardian_control as control_fixture
from tests import test_adaptive_guardian_lifecycle as fixture
from tests.test_adaptive_ipc import Clock, Connection, Listener, wire_frame


BASE = control_fixture.BASE
EPOCH = fixture.EPOCH
LOGON = fixture.fixtures.WRAPPER.logon_id
SERVER = fixture.GUARDIAN
HELPER = ProcessIdentity(fixture.fixtures.WRAPPER.pid + 5000,
                         fixture.fixtures.WRAPPER.created_filetime_100ns + 11, LOGON)
SECOND_HELPER = ProcessIdentity(HELPER.pid + 1, HELPER.created_filetime_100ns + 3, LOGON)
INSTANCE = "0aadef58-91ae-44d4-a31f-0ec97975b146"
CHALLENGE_NONCE = "c" * 64
CONFIG_REVISION = "c" * 64


def refusal_ack(proposal, **changes):
    """The shape GuardianControl._reject produces, built here independently."""
    values = dict(request_id=proposal.request_id, action_id=None,
                  execution_id=proposal.execution_id, guardian_epoch=proposal.guardian_epoch,
                  policy_epoch=proposal.policy_epoch, decision_seq=proposal.decision_seq,
                  result=ApplyResult.REJECTED, applied_flags=None, applied_rate_bp=None,
                  applied_validity=Validity.UNKNOWN, queried_tick_100ns=None,
                  lease_deadline_tick_100ns=None, intervention_deadline_tick_100ns=None,
                  reason="fixture_refusal", win32_error=None)
    return ApplyAck(**(values | changes))


class RecordingControl:
    """Explicit stand-in for GuardianControl. It applies nothing and counts."""

    def __init__(self):
        self.calls = []
        self.transform = None

    def apply(self, proposal):
        self.calls.append(proposal)
        ack = refusal_ack(proposal)
        return ack if self.transform is None else self.transform(ack)


class LoopbackEnd(Connection):
    """One end of a synthetic pipe pair. No handle, no thread, no Win32 call.

    The peer is served lazily on the first read, so the real client and the real
    service run to completion in one thread in their actual order.
    """

    def __init__(self, peer, *, pump=None):
        super().__init__(peer)
        self.pump = pump

    def read_exact(self, size, deadline):
        if not self.incoming and self.pump is not None:
            pump, self.pump = self.pump, None
            pump()
        return super().read_exact(size, deadline)


class ControlTransportTests(unittest.TestCase):
    # Reuse setup and helpers; never inherit another module's test methods.
    setUp = fixture.GuardianLifecycleTests.setUp
    spec = fixture.GuardianLifecycleTests.spec
    allocate = fixture.GuardianLifecycleTests.allocate
    connection = fixture.GuardianLifecycleTests.connection
    make_mutex = fixture.GuardianLifecycleTests.make_mutex
    seed_evidence = fixture.GuardianLifecycleTests.seed_evidence
    seed_started = fixture.GuardianLifecycleTests.seed_started
    row = fixture.GuardianLifecycleTests.row
    sql = fixture.GuardianLifecycleTests.sql
    start = control_fixture.GuardianControlTests.start
    policy_held = control_fixture.GuardianControlTests.policy_held
    runtime = control_fixture.GuardianControlTests.runtime
    slot = control_fixture.GuardianControlTests.slot
    actions = control_fixture.GuardianControlTests.actions
    proposal = control_fixture.GuardianControlTests.proposal

    # --- fixture plumbing ----------------------------------------------------

    def prepare(self, *, mode="canary", helpers=1, role="helper", registry=True, real_control=False):
        case = self.start(mode=mode)
        self.clock = Clock()
        clock = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.endpoint = NativePipeEndpoint(LOGON, INSTANCE, SERVER)
        if registry:
            with self.policy_held():
                initialize_registry_locked(self.store)
            for identity in (HELPER, SECOND_HELPER)[:helpers]:
                process = self.processes.process(identity)
                with self.policy_held():
                    self.assertTrue(register_infrastructure_locked(self.store, role, process))
        self.recorder = RecordingControl()
        self.owner_under_test = self.control if real_control else self.recorder
        self.service = transport.ControlProposalService(self.db, self.endpoint, self.owner_under_test)
        return case

    def built_proposal(self, case, *, seq=1, sample_seq=1, request_id=None, **changes):
        """One proposal built by the production builder from a real decision.

        The enforce profile is constructed in memory. validate_policy_profile
        still refuses enforce from a configuration file, and no configuration is
        read here.
        """
        execution = case.spec.execution_id
        profile = decisions.ENFORCE
        candidates = (decisions.candidate(execution_id=execution),)
        jobs = (decisions.job(execution_id=execution),)
        state = ControllerSnapshot.initial()
        for second in range(0, 7):
            state = decisions.tick(profile, state, second,
                                   decisions.LOW_BUSY if second < 5 else decisions.HIGH_BUSY,
                                   candidates=candidates, jobs=jobs).next_snapshot
        decision = decisions.tick(profile, state, 7, decisions.HIGH_BUSY,
                                  candidates=candidates, jobs=jobs)
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        self.assertEqual(decision.victim_execution_id, execution)
        runtime = self.runtime()
        values = dict(request_id=str(uuid4()) if request_id is None else request_id,
                      guardian_epoch=EPOCH, policy_epoch=runtime["policy_instance_id"],
                      sampler_epoch="sampler-a", clock_epoch="clock-a",
                      config_revision=CONFIG_REVISION,
                      registry_revision=runtime["registry_revision"], exemption_revision_seen=0,
                      decision_seq=seq, sample_seq=sample_seq,
                      sample_window_end_tick_100ns=BASE, decision_tick_100ns=BASE)
        return build_control_proposal(decision, **(values | changes))

    def service_pipe(self, proposal=None, *, peer=None, payload=None, on_write=None):
        if payload is None:
            payload = wire_frame(transport.request_envelope(proposal))
        self.pipe = Connection(HELPER if peer is None else peer, payload, on_write=on_write)
        return self.pipe

    def serve(self, *, timeout_ms=1000):
        return self.service.serve_once(Listener(self.endpoint, self.pipe), timeout_ms=timeout_ms)

    def client_pipe(self, proposal, *, peer=None, challenge_change=None, ack_change=None,
                    ack=None, drop_ack=False):
        def respond(connection, outgoing):
            if outgoing["kind"] != "ControlProposalRequest":
                return
            challenge = {"version": 1, "kind": "ControlChallenge",
                         "request_id": outgoing["request_id"], "nonce": CHALLENGE_NONCE,
                         "endpoint_id": INSTANCE, "guardian_epoch": proposal.guardian_epoch,
                         "server": SERVER.to_dict(), "client": HELPER.to_dict()}
            if challenge_change is not None:
                challenge = challenge_change(challenge)
            connection.enqueue(challenge)
            if drop_ack:
                return
            payload = (refusal_ack(proposal) if ack is None else ack).to_dict()
            if ack_change is not None:
                payload = ack_change(payload)
            connection.enqueue({"version": 1, "kind": "ControlAck",
                                "request_id": outgoing["request_id"],
                                "nonce": challenge["nonce"], "ack": payload})
        self.pipe = Connection(SERVER if peer is None else peer, on_write=respond)
        return self.pipe

    @contextmanager
    def connected(self):
        with patch.object(transport.NativePipeConnection, "connect", return_value=self.pipe) as connect:
            self.connect = connect
            yield

    def call_client(self, proposal, *, timeout_ms=1000, caller=None):
        client = transport.ControlProposalClient(
            self.endpoint, caller_process_or_identity=HELPER if caller is None else caller)
        with self.connected():
            return client.propose(proposal, timeout_ms=timeout_ms)

    def loopback(self, proposal, *, timeout_ms=1000):
        """Real client to real service to the owner, over the synthetic pair."""
        server_end = Connection(HELPER)
        client_end = LoopbackEnd(SERVER)
        client_end.on_write = lambda connection, message: server_end.enqueue(message)
        server_end.on_write = lambda connection, message: client_end.enqueue(message)
        self.served = None

        def pump():
            self.served = self.service.serve_once(Listener(self.endpoint, server_end),
                                                  timeout_ms=timeout_ms)
        client_end.pump = pump
        self.pipe = client_end
        self.server_end = server_end
        return self.call_client(proposal, timeout_ms=timeout_ms)

    # --- caller authentication -----------------------------------------------

    def test_service_refuses_when_no_helper_is_registered(self):
        case = self.prepare(helpers=0)
        self.service_pipe(self.proposal(case))
        with self.assertRaisesRegex(transport.ControlTransportError, "control_helper_unregistered"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.pipe.writes, [])
        # Refused before any request byte was read.
        self.assertEqual(self.pipe.reads, [])

    def test_service_refuses_a_process_registered_under_another_role(self):
        case = self.prepare(role="supervisor")
        self.service_pipe(self.proposal(case))
        with self.assertRaisesRegex(transport.ControlTransportError, "control_helper_unregistered"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])

    def test_service_refuses_two_registered_helpers_rather_than_choosing(self):
        case = self.prepare(helpers=2)
        self.service_pipe(self.proposal(case))
        with self.assertRaisesRegex(transport.ControlTransportError, "control_helper_ambiguous"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])

    def test_service_refuses_an_unavailable_or_malformed_registry(self):
        case = self.prepare()
        proposal = self.proposal(case)
        self.sql("ALTER TABLE adaptive_infrastructure ADD COLUMN trusted INTEGER")
        self.service_pipe(proposal)
        with self.assertRaisesRegex(transport.ControlTransportError, "control_registry_invalid"):
            self.serve()
        self.sql("DROP TABLE adaptive_infrastructure")
        self.service_pipe(proposal)
        with self.assertRaisesRegex(transport.ControlTransportError, "control_registry_unavailable"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])

    def test_service_refuses_a_peer_that_is_not_the_registered_process(self):
        case = self.prepare()
        for peer in (replace(HELPER, pid=HELPER.pid + 1),
                     replace(HELPER, created_filetime_100ns=HELPER.created_filetime_100ns + 1),
                     fixture.fixtures.WRAPPER):
            with self.subTest(peer=peer):
                self.service_pipe(self.proposal(case), peer=peer)
                with self.assertRaisesRegex(NativePipeError, "pipe_peer_unverified"):
                    self.serve()
                self.assertEqual(self.recorder.calls, [])
                self.assertEqual(self.pipe.writes, [])
                self.assertEqual(self.pipe.reads, [])

    def test_service_refuses_an_exited_or_unknown_peer_before_the_owner(self):
        case = self.prepare()
        for state in (IdentityStatus.DEAD, IdentityStatus.UNKNOWN):
            with self.subTest(state=state):
                self.service_pipe(self.proposal(case))
                self.pipe.retained.observation = IdentityObservation(
                    HELPER, state, "fixture_unknown" if state is IdentityStatus.UNKNOWN else None)
                with self.assertRaisesRegex(IpcError, "ipc_peer_unverified"):
                    self.serve()
                self.assertEqual(self.recorder.calls, [])

    # --- wire format ---------------------------------------------------------

    def test_service_refuses_malformed_and_cross_bound_messages(self):
        case = self.prepare()
        proposal = self.proposal(case)
        message = transport.request_envelope(proposal)
        variants = (
            (message | {"version": 2}, "ipc_protocol_mismatch"),
            (message | {"kind": "LaunchRequest"}, "ipc_unexpected_message"),
            (message | {"extra": 1}, "ipc_invalid_envelope"),
            (message | {"request_id": str(uuid4())}, "control_request_binding_mismatch"),
            (message | {"proposal": "text"}, "control_invalid_proposal"),
            (message | {"proposal": {k: v for k, v in message["proposal"].items() if k != "reason"}},
             "control_invalid_proposal"),
            (message | {"proposal": message["proposal"] | {"command": "private"}},
             "control_invalid_proposal"),
            (message | {"proposal": message["proposal"] | {"decision_seq": -1}},
             "control_invalid_proposal"),
        )
        for value, reason in variants:
            with self.subTest(reason=reason):
                self.service_pipe(payload=wire_frame(value))
                with self.assertRaisesRegex(IpcError, reason):
                    self.serve()
                self.assertEqual(self.recorder.calls, [])

    def test_service_refuses_an_oversized_frame_before_reading_a_body(self):
        self.prepare()
        self.service_pipe(payload=struct.pack("<I", MAX_MESSAGE_BYTES + 1) + b"private-body-marker")
        with self.assertRaisesRegex(IpcError, "ipc_invalid_frame_length"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.pipe.reads, [4])

    def test_service_refuses_a_listener_for_another_endpoint(self):
        case = self.prepare()
        self.service_pipe(self.proposal(case))
        other = NativePipeEndpoint(LOGON, str(uuid4()), SERVER)
        with self.assertRaisesRegex(transport.ControlTransportError, "control_endpoint_mismatch"):
            self.service.serve_once(Listener(other, self.pipe))
        self.assertEqual(self.recorder.calls, [])

    # --- deadline and owner call ---------------------------------------------

    def test_deadline_expiry_after_the_challenge_write_prevents_the_owner_call(self):
        case = self.prepare()
        self.service_pipe(self.proposal(case),
                          on_write=lambda *_: setattr(self.clock, "now", 2000))
        with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual([value["kind"] for value in self.pipe.writes], ["ControlChallenge"])

    def test_owner_is_called_once_and_the_service_caches_nothing(self):
        case = self.prepare()
        proposal = self.proposal(case)
        for _ in range(2):
            self.service_pipe(proposal)
            ack = self.serve()
            self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual([call.request_id for call in self.recorder.calls],
                         [proposal.request_id] * 2)
        self.assertEqual([value["kind"] for value in self.pipe.writes],
                         ["ControlChallenge", "ControlAck"])

    def test_service_refuses_to_send_an_acknowledgement_bound_to_another_request(self):
        case = self.prepare()
        proposal = self.proposal(case)
        for change in (dict(execution_id=str(uuid4())), dict(request_id=str(uuid4())),
                       dict(guardian_epoch="another-epoch"), dict(policy_epoch="another-policy"),
                       dict(decision_seq=proposal.decision_seq + 1)):
            with self.subTest(change=tuple(change)):
                self.recorder.transform = lambda ack, c=change: replace(ack, **c)
                self.service_pipe(proposal)
                with self.assertRaisesRegex(transport.ControlTransportError,
                                            "control_ack_binding_mismatch"):
                    self.serve()
                self.assertEqual([value["kind"] for value in self.pipe.writes], ["ControlChallenge"])

    # --- client --------------------------------------------------------------

    def test_client_sends_one_proposal_and_returns_the_bound_acknowledgement(self):
        case = self.prepare()
        proposal = self.proposal(case)
        self.client_pipe(proposal)
        ack = self.call_client(proposal)
        self.assertEqual(ack.request_id, proposal.request_id)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual([value["kind"] for value in self.pipe.writes], ["ControlProposalRequest"])
        self.assertEqual(self.connect.call_count, 1)
        self.assertTrue(self.pipe.closed)

    def test_client_refuses_a_server_that_is_not_the_pinned_guardian(self):
        case = self.prepare()
        proposal = self.proposal(case)
        for peer in (replace(SERVER, pid=SERVER.pid + 1),
                     replace(SERVER, created_filetime_100ns=SERVER.created_filetime_100ns + 1)):
            with self.subTest(peer=peer):
                self.client_pipe(proposal, peer=peer)
                with self.assertRaises(transport.ControlTransportError) as caught:
                    self.call_client(proposal)
                self.assertFalse(caught.exception.outcome_unknown)
                self.assertEqual(self.pipe.writes, [])

    def test_client_refuses_a_challenge_bound_to_anything_else(self):
        case = self.prepare()
        proposal = self.proposal(case)
        changes = ({"endpoint_id": str(uuid4())}, {"guardian_epoch": "another-epoch"},
                   {"request_id": str(uuid4())},
                   {"server": replace(SERVER, pid=SERVER.pid + 2).to_dict()},
                   {"client": replace(HELPER, pid=HELPER.pid + 2).to_dict()})
        for change in changes:
            with self.subTest(change=tuple(change)):
                self.client_pipe(proposal, challenge_change=lambda value, c=change: value | c)
                with self.assertRaises(transport.ControlTransportError) as caught:
                    self.call_client(proposal)
                self.assertTrue(caught.exception.outcome_unknown)
                self.assertEqual([value["kind"] for value in self.pipe.writes],
                                 ["ControlProposalRequest"])

    def test_client_refuses_an_acknowledgement_bound_to_another_proposal(self):
        case = self.prepare()
        proposal = self.proposal(case)
        for change in ({"execution_id": str(uuid4())}, {"request_id": str(uuid4())},
                       {"guardian_epoch": "another-epoch"}, {"policy_epoch": "another-policy"},
                       {"decision_seq": proposal.decision_seq + 1}):
            with self.subTest(change=tuple(change)):
                self.client_pipe(proposal, ack_change=lambda value, c=change: value | c)
                with self.assertRaisesRegex(transport.ControlTransportError,
                                            "control_ack_binding_mismatch") as caught:
                    self.call_client(proposal)
                self.assertTrue(caught.exception.outcome_unknown)

    def test_client_refuses_a_response_correlated_to_another_nonce(self):
        case = self.prepare()
        proposal = self.proposal(case)
        self.client_pipe(proposal)
        original = self.pipe.on_write

        def tamper(connection, outgoing):
            original(connection, outgoing)
            if outgoing["kind"] == "ControlProposalRequest":
                # Rewrite only the response nonce, leaving the challenge intact.
                connection.incoming.clear()
                connection.enqueue({"version": 1, "kind": "ControlChallenge",
                                    "request_id": proposal.request_id, "nonce": CHALLENGE_NONCE,
                                    "endpoint_id": INSTANCE,
                                    "guardian_epoch": proposal.guardian_epoch,
                                    "server": SERVER.to_dict(), "client": HELPER.to_dict()})
                connection.enqueue({"version": 1, "kind": "ControlAck",
                                    "request_id": proposal.request_id, "nonce": "d" * 64,
                                    "ack": refusal_ack(proposal).to_dict()})
        self.pipe.on_write = tamper
        with self.assertRaisesRegex(transport.ControlTransportError,
                                    "control_response_binding_mismatch"):
            self.call_client(proposal)

    def test_client_reports_an_unknown_outcome_and_never_retries_by_itself(self):
        case = self.prepare()
        proposal = self.proposal(case)
        self.client_pipe(proposal, drop_ack=True)
        with self.assertRaises(transport.ControlTransportError) as caught:
            self.call_client(proposal)
        self.assertTrue(caught.exception.outcome_unknown)
        self.assertEqual(self.connect.call_count, 1)
        self.assertEqual([value["request_id"] for value in self.pipe.writes],
                         [proposal.request_id])

    def test_a_failure_before_the_connection_is_not_an_unknown_outcome(self):
        case = self.prepare()
        proposal = self.proposal(case)
        self.client_pipe(proposal)
        client = transport.ControlProposalClient(self.endpoint, caller_process_or_identity=HELPER)
        with patch.object(transport.NativePipeConnection, "connect",
                          side_effect=IpcError("ipc_deadline_exceeded")):
            with self.assertRaises(transport.ControlTransportError) as caught:
                client.propose(proposal)
        self.assertFalse(caught.exception.outcome_unknown)
        self.assertEqual(str(caught.exception), "ipc_deadline_exceeded")
        self.assertEqual(self.pipe.writes, [])

    def test_a_deadline_reached_at_the_write_boundary_stays_unknown(self):
        """No byte left, and the client still reports the outcome as unknown.

        The write is the point after which the guardian may have seen the
        proposal, so the uncertainty is claimed from the moment the write is
        entered. That direction is deliberate: it can only make a proposer
        resynchronize when it did not have to.
        """
        case = self.prepare()
        proposal = self.proposal(case)
        self.client_pipe(proposal)
        original = self.pipe.verified_peer

        @contextmanager
        def slow_verification(expected):
            with original(expected) as peer:
                self.clock.now = 2000
                yield peer
        self.pipe.verified_peer = slow_verification
        with self.assertRaisesRegex(transport.ControlTransportError, "ipc_deadline_exceeded") as caught:
            self.call_client(proposal)
        self.assertTrue(caught.exception.outcome_unknown)
        self.assertEqual(self.pipe.writes, [])

    def test_client_requires_a_typed_proposal_and_a_same_logon_caller(self):
        self.prepare()
        with self.assertRaisesRegex(transport.ControlTransportError, "control_client_logon_mismatch"):
            transport.ControlProposalClient(self.endpoint,
                caller_process_or_identity=replace(HELPER, logon_id="S-1-5-5-200-300"))
        with self.assertRaisesRegex(transport.ControlTransportError, "control_caller_identity_required"):
            transport.ControlProposalClient(self.endpoint, caller_process_or_identity=HELPER.pid)
        client = transport.ControlProposalClient(self.endpoint, caller_process_or_identity=HELPER)
        with patch.object(transport.NativePipeConnection, "connect") as connect:
            with self.assertRaisesRegex(transport.ControlTransportError, "control_proposal_required"):
                client.propose({"request_id": str(uuid4())})
        connect.assert_not_called()

    # --- end to end against the production consumer --------------------------

    def test_ledger_mode_off_refuses_the_proposal_with_zero_native_set(self):
        case = self.prepare(mode="off", real_control=True)
        proposal = self.built_proposal(case)
        ack = self.loopback(proposal)
        self.assertEqual(ack.result, ApplyResult.REJECTED)
        self.assertEqual(ack.reason, "control_mode_unavailable")
        self.assertIsNone(ack.action_id)
        self.assertEqual(ack.to_dict(), self.served.to_dict())
        self.assertEqual(case.job.sets, 0)
        self.assertEqual([call for call in case.job.calls if call[0] in {"set", "disable"}], [])
        self.assertEqual(self.control.backend_calls, [])
        self.assertIsNone(self.slot())
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        self.assertEqual(self.actions(), [])

    def test_eligible_canary_applies_once_and_a_retried_request_repeats_the_ack(self):
        case = self.prepare(mode="canary", real_control=True)
        proposal = self.built_proposal(case)
        ack = self.loopback(proposal)
        self.assertEqual(ack.result, ApplyResult.APPLIED)
        self.assertEqual(ack.applied_rate_bp, proposal.target.cpu_rate_bp)
        self.assertEqual(ack.applied_flags, 5)
        self.assertIs(ack.applied_validity, Validity.VALID)
        self.assertEqual(ack.to_dict(), self.served.to_dict())
        self.assertEqual(case.job.sets, 1)
        self.assertEqual(self.slot()["slot_state"], "HELD")
        self.assertEqual(self.runtime()["admission_barrier"], "CONTROLLING")
        # The same request id and the same sequence, sent again over a second
        # connection. GuardianControl owns that idempotency; the transport adds
        # no cache of its own.
        again = self.loopback(proposal)
        self.assertEqual(again.to_dict(), ack.to_dict())
        self.assertEqual(again.action_id, ack.action_id)
        self.assertEqual(case.job.sets, 1)
        self.assertEqual([row["action_state"] for row in self.actions()], ["APPLIED"])

    def test_unregistered_caller_never_reaches_guardian_control(self):
        case = self.prepare(mode="canary", helpers=0, real_control=True)
        proposal = self.built_proposal(case)
        with patch.object(self.control, "apply", wraps=self.control.apply) as applied:
            with self.assertRaisesRegex(transport.ControlTransportError,
                                        "control_helper_unregistered"):
                self.loopback(proposal)
        applied.assert_not_called()
        self.assertEqual(case.job.sets, 0)
        self.assertEqual(self.control.backend_calls, [])
        self.assertIsNone(self.slot())
        self.assertEqual(self.actions(), [])


if __name__ == "__main__":
    unittest.main()
