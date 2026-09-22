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
from contextlib import closing, contextmanager
from dataclasses import replace
import sqlite3
import struct
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import control_transport as transport
from sentinel.adaptive.contracts import (
    ApplyAck, ApplyResult, IdentityObservation, IdentityStatus, MAX_MESSAGE_BYTES,
    ProcessIdentity, Validity,
)
from sentinel.adaptive.control_messages import (ControlFrameAck, ControlFrameRequest, ControlFrameResult,
    ControlObservation, ControlRestoreRequest, RestoreAck, RestoreOutcome)
from sentinel.adaptive.decision import ControllerSnapshot, DecisionAction, next_state
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


def operation_ack(request):
    """Explicit transport-owner fixture; its observations prove no native gate."""
    if type(request) is ControlFrameRequest:
        frame = request.frame
        return ControlFrameAck(request.request_id, request.guardian_epoch, request.policy_epoch,
            frame.sampler_epoch, frame.clock_epoch, frame.sample_seq, frame.registry_revision,
            frame.config_revision, tuple(ControlFrameResult(job.execution_id,
                ControlObservation.UNCAPPED, frame.published_tick_100ns, False, "fixture_uncapped")
                for job in frame.jobs))
    if type(request) is ControlRestoreRequest:
        return RestoreAck(request.request_id, request.guardian_epoch, request.policy_epoch,
            request.execution_id, RestoreOutcome.UNVERIFIED, None, None, None, None,
            None, None, Validity.UNKNOWN, None, "fixture_restore_unverified", None)
    return refusal_ack(request)


class RecordingControl:
    """Explicit stand-in for GuardianControl. It applies nothing and counts."""

    def __init__(self):
        self.calls = []
        self.helpers = []
        self.transform = None

    def apply(self, proposal, *, helper_identity):
        self.calls.append(proposal)
        self.helpers.append(helper_identity)
        ack = refusal_ack(proposal)
        return ack if self.transform is None else self.transform(ack)

    def observe_control_frame(self, request, *, helper_identity):
        self.calls.append(request)
        self.helpers.append(helper_identity)
        ack = operation_ack(request)
        return ack if self.transform is None else self.transform(ack)

    def restore_control_request(self, request, *, helper_identity):
        return self.observe_control_frame(request, helper_identity=helper_identity)


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
    spec = control_fixture.GuardianControlTests.spec
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
        self.helper_identity = HELPER
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

    def built_proposal(self, case, *, seq=1, sample_seq=8, request_id=None, **changes):
        """One proposal built by the production builder from a real decision.

        The enforce profile is constructed in memory. validate_policy_profile
        still refuses enforce from a configuration file, and no configuration is
        read here.
        """
        execution = case.spec.execution_id
        profile = decisions.ENFORCE
        baseline = 8 / 3
        candidates = (decisions.candidate(execution_id=execution, uncapped_samples=(baseline,) * 5),)
        jobs = (decisions.job(execution_id=execution, cpu_units=baseline,
            private_working_set_bytes=case.spec.requested.physical_bytes,
            private_commit_bytes=case.spec.requested.commit_bytes, active_processes=1),)
        state = ControllerSnapshot.initial()
        for second in range(8):
            moment = BASE + (second - 7) * decisions.TICKS_PER_SECOND
            frame = decisions.frame(sample_seq - 7 + second, moment, 6.0 if second < 5 else 7.6,
                jobs=jobs, config_revision=self.control.config_revision,
                registry_revision=self.runtime()["registry_revision"])
            frame = replace(frame, machine=replace(frame.machine, logical_processors=8))
            decision = next_state(profile=profile, snapshot=state, frame=frame, candidates=candidates,
                now_tick_100ns=moment)
            state = decision.next_snapshot
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        self.assertEqual(decision.victim_execution_id, execution)
        runtime = self.runtime()
        values = dict(request_id=str(uuid4()) if request_id is None else request_id,
                      guardian_epoch=EPOCH, policy_epoch=runtime["policy_instance_id"],
                      sampler_epoch="sampler-a", clock_epoch="clock-a",
                      config_revision=self.control.config_revision,
                      registry_revision=runtime["registry_revision"], exemption_revision_seen=0,
                      decision_seq=seq, sample_seq=sample_seq,
                      sample_window_end_tick_100ns=BASE, decision_tick_100ns=BASE)
        return build_control_proposal(decision, **(values | changes))

    def managed_frame_request(self, case, *, seq, window_end):
        job = decisions.job(case.spec.execution_id, cpu_units=8 / 3,
            private_working_set_bytes=case.spec.requested.physical_bytes,
            private_commit_bytes=case.spec.requested.commit_bytes, active_processes=len(case.job.members))
        frame = decisions.frame(seq, window_end, 7.6, jobs=(job,),
            config_revision=self.control.config_revision, registry_revision=self.runtime()["registry_revision"])
        frame = replace(frame, machine=replace(frame.machine, logical_processors=8))
        return ControlFrameRequest(str(uuid4()), EPOCH, self.runtime()["policy_instance_id"], frame)

    def warmup_via_transport(self, case, proposal):
        saved = self.ticks
        for index in range(5):
            self.ticks = proposal.sample_window_end_tick_100ns - (4 - index) * decisions.TICKS_PER_SECOND
            request = self.managed_frame_request(case, seq=proposal.sample_seq - 4 + index, window_end=self.ticks)
            ack = self.loopback(request)
            self.assertEqual(ack.results[0].observation, ControlObservation.UNCAPPED)
        self.ticks = saved

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
            if outgoing["kind"] not in {"ControlProposalRequest", "ControlFrameRequest", "ControlRestoreRequest"}:
                return
            challenge = {"version": 1, "kind": "ControlChallenge",
                         "request_id": outgoing["request_id"], "nonce": CHALLENGE_NONCE,
                         "endpoint_id": INSTANCE, "guardian_epoch": proposal.guardian_epoch,
                         "policy_epoch": proposal.policy_epoch, "operation": outgoing["kind"],
                         "server": SERVER.to_dict(), "client": HELPER.to_dict()}
            if challenge_change is not None:
                challenge = challenge_change(challenge)
            connection.enqueue(challenge)
            if drop_ack:
                return
            payload = (operation_ack(proposal) if ack is None else ack).to_dict()
            if ack_change is not None:
                payload = ack_change(payload)
            connection.enqueue({"version": 1, "kind": "ControlAck",
                                "request_id": outgoing["request_id"],
                                "guardian_epoch": proposal.guardian_epoch, "policy_epoch": proposal.policy_epoch,
                                "operation": outgoing["kind"],
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
            if type(proposal) is ControlFrameRequest:
                return client.observe_uncapped(proposal.frame, request_id=proposal.request_id,
                    guardian_epoch=proposal.guardian_epoch, policy_epoch=proposal.policy_epoch, timeout_ms=timeout_ms)
            if type(proposal) is ControlRestoreRequest:
                return client.request_restore(proposal.execution_id, request_id=proposal.request_id,
                    guardian_epoch=proposal.guardian_epoch, policy_epoch=proposal.policy_epoch,
                    reason=proposal.reason, timeout_ms=timeout_ms)
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

    def damage_registry(self, statement, values=()):
        """Write a row the table's own CHECK constraints would refuse.

        A damaged ledger is the case under test, so the constraints are switched
        off on this one fixture connection only.
        """
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("PRAGMA ignore_check_constraints=ON")
            self.assertEqual(conn.execute(statement, values).rowcount, 1)

    def refuse_damaged_helper_row(self, assignment):
        case = self.prepare()
        self.damage_registry("UPDATE adaptive_infrastructure SET " + assignment +
                             " WHERE role='helper'")
        self.service_pipe(self.proposal(case))
        with self.assertRaisesRegex(transport.ControlTransportError, "control_registry_invalid"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.pipe.writes, [])
        self.assertEqual(self.pipe.reads, [])

    def test_service_refuses_a_helper_row_with_another_schema_version(self):
        self.refuse_damaged_helper_row("schema_version=2")

    def test_service_refuses_a_helper_row_whose_creation_time_is_not_a_number(self):
        self.refuse_damaged_helper_row("created_filetime_100ns='not-a-filetime'")

    def test_service_refuses_a_helper_row_whose_pid_is_not_positive(self):
        self.refuse_damaged_helper_row("pid=0")

    def test_service_refuses_a_registry_that_names_the_guardian_as_the_helper(self):
        case = self.prepare(helpers=0)
        with self.policy_held():
            self.assertTrue(register_infrastructure_locked(
                self.store, "helper", self.processes.process(SERVER)))
        self.service_pipe(self.proposal(case), peer=SERVER)
        with self.assertRaisesRegex(transport.ControlTransportError,
                                    "control_helper_identity_invalid"):
            self.serve()
        self.assertEqual(self.recorder.calls, [])
        self.assertEqual(self.pipe.reads, [])

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

    def test_deadline_expiry_during_final_peer_check_prevents_every_owner_operation(self):
        case = self.prepare()
        original_live = transport._live

        def slow_final_check(connection, retained, expected):
            original_live(connection, retained, expected)
            if connection.writes:
                self.clock.now = 2000

        for request in (self.proposal(case), self.frame_request(case), self.restore_request(case)):
            with self.subTest(operation=type(request).__name__):
                self.clock.now = 0
                self.service_pipe(request)
                with patch.object(transport, "_live", side_effect=slow_final_check) as peer_check:
                    with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
                        self.serve()
                self.assertEqual(peer_check.call_count, 3)
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
                   {"policy_epoch": "another-policy"}, {"operation": "ControlRestoreRequest"},
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
                                    "policy_epoch": proposal.policy_epoch, "operation": "ControlProposalRequest",
                                    "server": SERVER.to_dict(), "client": HELPER.to_dict()})
                connection.enqueue({"version": 1, "kind": "ControlAck",
                                    "request_id": proposal.request_id, "nonce": "d" * 64,
                                    "guardian_epoch": proposal.guardian_epoch, "policy_epoch": proposal.policy_epoch,
                                    "operation": "ControlProposalRequest",
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

    # --- typed frame/restore union ------------------------------------------

    def frame_request(self, case, *, jobs=None):
        frame = decisions.frame(11, BASE, 8.0,
            jobs=(decisions.job(case.spec.execution_id),) if jobs is None else jobs,
            registry_revision=self.runtime()["registry_revision"], config_revision=CONFIG_REVISION)
        return ControlFrameRequest(str(uuid4()), EPOCH, self.runtime()["policy_instance_id"], frame)

    def restore_request(self, case):
        return ControlRestoreRequest(str(uuid4()), EPOCH, self.runtime()["policy_instance_id"],
            case.spec.execution_id, "mode_off")

    def test_new_operations_roundtrip_and_receive_authenticated_helper_identity(self):
        case = self.prepare()
        requests = (self.frame_request(case), self.restore_request(case), self.proposal(case))
        for request in requests:
            ack = self.loopback(request)
            self.assertEqual(ack, operation_ack(request))
            self.assertEqual(ack, self.served)
        self.assertEqual(self.recorder.calls, list(requests))
        self.assertEqual(self.recorder.helpers, [HELPER] * 3)
        self.assertEqual(case.job.sets, 0)

    def test_one_frame_rpc_carries_ten_unique_aggregates(self):
        case = self.prepare()
        jobs = tuple(decisions.job(str(uuid4())) for _ in range(10))
        request = self.frame_request(case, jobs=jobs)
        ack = self.loopback(request)
        self.assertEqual(len(ack.results), 10)
        self.assertEqual(self.recorder.calls, [request])
        self.assertEqual([message["kind"] for message in self.pipe.writes], ["ControlFrameRequest"])

    def test_new_operations_authenticate_before_reading_request(self):
        case = self.prepare(helpers=0)
        for request in (self.frame_request(case), self.restore_request(case)):
            self.service_pipe(request)
            with self.assertRaisesRegex(IpcError, "control_helper_unregistered"):
                self.serve()
            self.assertEqual(self.pipe.reads, [])
            self.assertEqual(self.recorder.calls, [])

    def test_new_operations_reject_injected_pid_command_and_force_fields(self):
        case = self.prepare()
        for request in (self.frame_request(case), self.restore_request(case)):
            for extra in ({"pid": HELPER.pid}, {"command": "private"}, {"force": True}):
                self.service_pipe(payload=wire_frame(transport.request_envelope(request) | extra))
                with self.assertRaisesRegex(IpcError, "ipc_invalid_envelope"):
                    self.serve()
                self.assertEqual(self.recorder.calls, [])

    def test_mixed_old_proposal_envelope_and_challenge_are_refused(self):
        case = self.prepare()
        request = self.proposal(case)
        old = transport.request_envelope(request)
        old.pop("policy_epoch")
        self.service_pipe(payload=wire_frame(old))
        with self.assertRaisesRegex(IpcError, "ipc_invalid_envelope"):
            self.serve()
        self.client_pipe(request, challenge_change=lambda value: {key: item for key, item in value.items() if key != "operation"})
        with self.assertRaisesRegex(IpcError, "ipc_invalid_envelope") as caught:
            self.call_client(request)
        self.assertTrue(caught.exception.outcome_unknown)
        self.assertEqual(self.recorder.calls, [])

    def test_frame_and_restore_challenges_bind_kind_and_policy_epoch(self):
        case = self.prepare()
        for request in (self.frame_request(case), self.restore_request(case)):
            for changed in ({"operation": "ControlProposalRequest"}, {"policy_epoch": "another-policy"}):
                self.client_pipe(request, challenge_change=lambda value, c=changed: value | c)
                with self.assertRaisesRegex(IpcError, "control_challenge_binding_mismatch") as caught:
                    self.call_client(request)
                self.assertTrue(caught.exception.outcome_unknown)
                self.assertEqual(len(self.pipe.writes), 1)

    def test_frame_ack_rejects_other_sampler_clock_sequence_or_unrequested_job(self):
        case = self.prepare()
        request = self.frame_request(case)
        original = operation_ack(request)
        variants = ({"sampler_epoch": "other-sampler"}, {"clock_epoch": "other-clock"},
            {"sample_seq": request.frame.sample_seq + 1},
            {"results": (replace(original.results[0], execution_id=str(uuid4())),)})
        for change in variants:
            self.client_pipe(request, ack=replace(original, **change))
            with self.assertRaisesRegex(IpcError, "control_ack_binding_mismatch"):
                self.call_client(request)

    def test_frame_ack_can_report_new_authoritative_revision_and_missing_result(self):
        case = self.prepare()
        request = self.frame_request(case)
        ack = replace(operation_ack(request), registry_revision=request.frame.registry_revision + 1,
            config_revision="d" * 64, results=())
        self.client_pipe(request, ack=ack)
        self.assertEqual(self.call_client(request), ack)

    def test_restore_ack_rejects_another_execution_and_inconsistent_restored_claim(self):
        case = self.prepare()
        request = self.restore_request(case)
        self.client_pipe(request, ack=replace(operation_ack(request), execution_id=str(uuid4())))
        with self.assertRaisesRegex(IpcError, "control_ack_binding_mismatch"):
            self.call_client(request)
        self.client_pipe(request, ack_change=lambda value: value | {"result": "RESTORED"})
        with self.assertRaisesRegex(IpcError, "control_invalid_ack"):
            self.call_client(request)

    def test_owner_cannot_answer_frame_with_an_apply_or_restore_ack(self):
        case = self.prepare()
        frame_request = self.frame_request(case)
        for wrong in (refusal_ack(self.proposal(case)), operation_ack(self.restore_request(case))):
            self.recorder.transform = lambda ack, answer=wrong: answer
            self.service_pipe(frame_request)
            with self.assertRaisesRegex(IpcError, "control_invalid_ack"):
                self.serve()
            self.assertEqual([message["kind"] for message in self.pipe.writes], ["ControlChallenge"])

    def test_new_operations_lost_ack_stays_unknown_and_does_not_retry(self):
        case = self.prepare()
        for request in (self.frame_request(case), self.restore_request(case)):
            self.client_pipe(request, drop_ack=True)
            with self.assertRaises(IpcError) as caught:
                self.call_client(request)
            self.assertTrue(caught.exception.outcome_unknown)
            self.assertEqual(self.connect.call_count, 1)
            self.assertEqual([message["request_id"] for message in self.pipe.writes], [request.request_id])

    def test_new_operations_interrupt_preserves_unknown_outcome(self):
        case = self.prepare()
        request = self.restore_request(case)
        self.client_pipe(request)
        interruption = KeyboardInterrupt()
        with patch.object(transport, "read_frame", side_effect=interruption):
            with self.assertRaises(KeyboardInterrupt) as caught:
                self.call_client(request)
        self.assertIs(caught.exception, interruption)
        self.assertTrue(interruption.control_outcome_unknown)
        self.assertEqual(self.connect.call_count, 1)

    def test_new_operations_deadline_after_challenge_prevents_owner_call(self):
        case = self.prepare()
        for request in (self.frame_request(case), self.restore_request(case)):
            self.clock.now = 0
            self.service_pipe(request, on_write=lambda *_: setattr(self.clock, "now", 2000))
            with self.assertRaisesRegex(IpcError, "ipc_deadline_exceeded"):
                self.serve()
            self.assertEqual(self.recorder.calls, [])

    def test_request_closed_union_refuses_nonstring_kind_and_cross_epoch(self):
        case = self.prepare()
        for changed in ({"kind": []}, {"kind": "ForceClear"}, {"guardian_epoch": "other"}, {"policy_epoch": "other"}):
            value = transport.request_envelope(self.proposal(case)) | changed
            self.service_pipe(payload=wire_frame(value))
            with self.assertRaises(IpcError):
                self.serve()
        self.assertEqual(self.recorder.calls, [])

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
        self.warmup_via_transport(case, proposal)
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

    def test_full_frame_apply_restore_uncapped_barrier_path_preserves_allocation(self):
        case = self.prepare(mode="canary", real_control=True)
        proposal = self.built_proposal(case)
        self.warmup_via_transport(case, proposal)
        original = dict(self.connection().execute("SELECT * FROM reservations WHERE execution_id=?",
                                                (case.spec.execution_id,)).fetchone())
        applied = self.loopback(proposal)
        self.assertEqual(applied.result, ApplyResult.APPLIED)
        before = len(self.control._samples[case.spec.execution_id])
        self.ticks = BASE + decisions.TICKS_PER_SECOND
        capped = self.managed_frame_request(case, seq=proposal.sample_seq + 1, window_end=self.ticks)
        observed = self.loopback(capped)
        self.assertEqual(observed.results[0].observation, ControlObservation.CAPPED)
        self.assertEqual(len(self.control._samples[case.spec.execution_id]), before)
        restored = self.loopback(self.restore_request(case))
        self.assertEqual(restored.result, RestoreOutcome.RESTORED)
        self.assertTrue(restored.native_disabled and restored.bookkeeping_settled and restored.slot_released)
        self.assertFalse(restored.barrier_cleared)
        self.assertEqual(self.runtime()["admission_barrier"], "RECOVERY_HOLD")
        for index in range(5):
            self.ticks = BASE + (index + 2) * decisions.TICKS_PER_SECOND
            fresh = self.managed_frame_request(case, seq=proposal.sample_seq + 2 + index, window_end=self.ticks)
            observed = self.loopback(fresh)
            self.assertEqual(observed.results[0].observation, ControlObservation.UNCAPPED)
            if index < 4:
                self.assertFalse(observed.results[0].barrier_cleared)
        self.assertTrue(observed.results[0].barrier_cleared)
        self.assertEqual(observed.registry_revision, self.runtime()["registry_revision"])
        self.assertEqual(self.runtime()["admission_barrier"], "NONE")
        retained = dict(self.connection().execute("SELECT * FROM reservations WHERE execution_id=?",
                                                (case.spec.execution_id,)).fetchone())
        for key in ("id", "execution_id", "cpu_units", "ram_gib", "physical_bytes", "commit_bytes"):
            self.assertEqual(retained[key], original[key])
        self.assertEqual([row["action_state"] for row in self.actions()], ["APPLIED", "RESTORED"])

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
