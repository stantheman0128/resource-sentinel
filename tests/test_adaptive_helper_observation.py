"""Synthetic drain-observation contracts; no native effects or timing claims.

Uses the production FrameSampler over explicit synthetic counter/clock sources.
The frame-only guardian stand-in counts new request IDs and changes an in-memory
binding. Its five-frame behavior is a fixture, not native recovery evidence.
"""
from dataclasses import FrozenInstanceError, replace
from types import MappingProxyType
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import control_transport as transport
from sentinel.adaptive.control_messages import ControlFrameAck, ControlFrameRequest, ControlFrameResult, ControlObservation
from sentinel.adaptive.contracts import TICKS_PER_SECOND, Validity
from sentinel.adaptive.decision import Mode
from sentinel.adaptive.helper_observation import HelperDrainObserver
from sentinel.adaptive.sampler import FrameSampler
from tests.test_adaptive_helper import ClockStub, SyntheticJobBackend, SyntheticMachineSource, profile, BASE_TICK
from tests.test_adaptive_helper_control import EX, ENDPOINT, HELPER, POLICY, SyntheticBindingSource


class FrameOnlyFixtureClient:
    def __init__(self, fixture):
        self.fixture = fixture
        self.requests = []
        self.replies = {}
        self.clear_after = None
        self.lose_reply = False
        self.interrupt_reply = False
        self.bad_request = self.missing_results = self.bad_config = self.bad_query = False
        self.observation = ControlObservation.UNCAPPED
        self.claim_barrier_cleared = False

    def observe_uncapped(self, frame, **values):
        self.requests.append((frame, dict(values)))
        if values["request_id"] not in self.replies:
            if self.clear_after is not None and len(self.replies) + 1 >= self.clear_after:
                self.fixture.source.binding = replace(self.fixture.source.binding,
                    admission_barrier="NONE", registry_revision=self.fixture.source.binding.registry_revision + 1)
            query = self.fixture.clock() if self.observation in (ControlObservation.UNCAPPED, ControlObservation.CAPPED) else None
            results = tuple(ControlFrameResult(job.execution_id, self.observation, query,
                self.claim_barrier_cleared and self.observation is ControlObservation.UNCAPPED,
                "synthetic_observation") for job in frame.jobs)
            ack = ControlFrameAck(values["request_id"], values["guardian_epoch"], values["policy_epoch"],
                frame.sampler_epoch, frame.clock_epoch, frame.sample_seq,
                self.fixture.source.binding.registry_revision, frame.config_revision, results)
            self.replies[values["request_id"]] = ack
        ack = self.replies[values["request_id"]]
        if self.lose_reply:
            raise TimeoutError("synthetic_lost_ack")
        if self.interrupt_reply:
            raise KeyboardInterrupt("synthetic_interrupted_ack")
        if self.bad_request:
            ack = replace(ack, request_id=str(uuid4()))
        if self.bad_config:
            ack = replace(ack, config_revision="f" * 64)
        if self.missing_results:
            ack = replace(ack, results=())
        if self.bad_query:
            ack = replace(ack, results=tuple(replace(result,
                queried_tick_100ns=frame.window_end_tick_100ns - 1) for result in ack.results))
        return ack


class ObserverFixture:
    def __init__(self, *, mode=Mode.OFF):
        self.profile = profile(mode=mode)
        self.clock = ClockStub(BASE_TICK, step=0)
        self.backend = SyntheticJobBackend({EX: 2.0})
        self.machine = SyntheticMachineSource(self.clock)
        self.sampler = FrameSampler(profile=self.profile, backend=self.backend,
            machine_source=self.machine, clock=self.clock)
        self.sampler.enroll(EX)
        self.source = SyntheticBindingSource(self.sampler.config_revision)
        self.source.binding = replace(self.source.binding, mode="off", admission_barrier="RECOVERY_HOLD")
        self.client = FrameOnlyFixtureClient(self)
        self.constructed = 0
        self.sender_restore_pending = False
        self.second = 0
        def factory(endpoint, identity):
            if endpoint != ENDPOINT or identity != HELPER:
                raise AssertionError("wrong endpoint")
            self.constructed += 1
            return self.client
        self.observer = HelperDrainObserver(profile=self.profile, sampler=self.sampler,
            binding_source=self.source, client_factory=factory, clock=self.clock,
            restore_pending=lambda: self.sender_restore_pending)

    def tick(self, *, seconds=1):
        self.second += seconds
        self.backend.advance(seconds)
        self.clock.set(BASE_TICK + self.second * TICKS_PER_SECOND)
        return self.observer.tick()

    def start_frame(self):
        self.observer.request_drain()
        self.tick()  # real sampler needs its first counter endpoint.
        return self.tick()


class DrainObserverTests(unittest.TestCase):
    def test_off_and_shadow_without_explicit_request_have_zero_source_sample_client(self):
        for mode in (Mode.OFF, Mode.SHADOW):
            fixture = ObserverFixture(mode=mode)
            with patch.object(fixture.source, "read", side_effect=AssertionError("read before drain")):
                self.assertEqual(fixture.tick().reason, "helper_drain_not_requested")
            self.assertEqual(fixture.constructed, 0)
            self.assertEqual(fixture.backend.reads, 0)
            self.assertEqual(fixture.sampler.sample_seq, 0)
            self.assertFalse(fixture.observer.drain_pending)

    def test_explicit_off_hold_sends_five_actual_frames_before_live_clear(self):
        fixture = ObserverFixture()
        fixture.client.clear_after = 5
        fixture.observer.request_drain()
        outcomes = [fixture.tick() for _ in range(6)]
        self.assertFalse(outcomes[0].sampled)
        self.assertTrue(all(result.sampled for result in outcomes[1:]))
        self.assertTrue(outcomes[-1].complete)
        self.assertFalse(fixture.observer.drain_pending)
        self.assertEqual(len(fixture.client.requests), 5)
        frames = [frame for frame, _ in fixture.client.requests]
        self.assertEqual(len({frame.sample_seq for frame in frames}), 5)
        self.assertTrue(all(frame.validity is Validity.VALID and frame.jobs[0].cpu_units == 2.0 for frame in frames))
        self.assertTrue(all(frame.registry_revision == 17 for frame in frames))
        self.assertNotEqual(fixture.source.binding.registry_revision, frames[-1].registry_revision)

    def test_ack_claim_of_clear_does_not_replace_live_barrier(self):
        fixture = ObserverFixture()
        fixture.client.claim_barrier_cleared = True
        for _ in range(8):
            fixture.observer.request_drain()
            result = fixture.tick()
        self.assertTrue(result.acknowledged)
        self.assertFalse(result.complete)
        self.assertTrue(fixture.observer.drain_pending)

    def test_live_none_completes_without_client_only_when_sender_obligation_exactly_false(self):
        for pending in (True, None, 0, "false"):
            fixture = ObserverFixture()
            fixture.source.binding = replace(fixture.source.binding, admission_barrier="NONE")
            fixture.sender_restore_pending = pending
            fixture.observer.request_drain()
            self.assertFalse(fixture.tick().complete)
        fixture = ObserverFixture()
        fixture.source.binding = replace(fixture.source.binding, admission_barrier="NONE")
        fixture.observer.request_drain()
        self.assertTrue(fixture.tick().complete)
        self.assertEqual(fixture.constructed, 0)
        self.assertEqual(fixture.backend.reads, 0)

    def test_completion_is_rechecked_and_new_hold_is_not_ignored(self):
        fixture = ObserverFixture()
        fixture.source.binding = replace(fixture.source.binding, admission_barrier="NONE")
        fixture.observer.request_drain()
        self.assertTrue(fixture.tick().complete)
        fixture.source.binding = replace(fixture.source.binding, admission_barrier="RECOVERY_HOLD")
        self.assertFalse(fixture.tick().complete)
        self.assertTrue(fixture.observer.drain_pending)

    def test_canary_or_shadow_none_cannot_complete_before_off_commit(self):
        for mode in ("canary", "limited", "shadow"):
            fixture = ObserverFixture()
            fixture.source.binding = replace(fixture.source.binding, mode=mode, admission_barrier="NONE")
            fixture.observer.request_drain()
            self.assertFalse(fixture.tick().complete)
            fixture.source.binding = replace(fixture.source.binding, mode="off")
            self.assertTrue(fixture.tick().complete)

    def test_source_failure_or_changed_capture_never_sends_old_frame(self):
        fixture = ObserverFixture()
        fixture.start_frame()
        previous = len(fixture.client.requests)
        fixture.machine.machine_available = False
        self.assertFalse(fixture.tick().sampled)
        self.assertEqual(len(fixture.client.requests), previous)
        fixture.machine.machine_available = True
        fixture.source.changed = True
        fixture.tick()
        self.assertEqual(len(fixture.client.requests), previous)
        self.assertIsNone(fixture.observer.pending)

    def test_counter_epoch_change_prevents_sending_mismatched_retained_job(self):
        fixture = ObserverFixture()
        fixture.start_frame()
        previous = len(fixture.client.requests)
        fixture.backend.reset_counter(EX)
        fixture.tick()
        self.assertEqual(fixture.tick().reason, "helper_drain_frame_unavailable")
        self.assertEqual(len(fixture.client.requests), previous)

    def test_lost_ack_replays_immutable_frame_uuid_without_sampling(self):
        fixture = ObserverFixture()
        fixture.client.lose_reply = True
        result = fixture.start_frame()
        self.assertTrue(result.uncertain)
        pending, samples, reads = fixture.observer.pending, fixture.sampler.sample_seq, fixture.backend.reads
        with self.assertRaises(FrozenInstanceError):
            pending.request_id = str(uuid4())
        fixture.tick()
        self.assertIs(fixture.observer.pending, pending)
        self.assertEqual(fixture.sampler.sample_seq, samples)
        self.assertEqual(fixture.backend.reads, reads)
        fixture.client.lose_reply = False
        result = fixture.tick()
        self.assertTrue(result.acknowledged)
        self.assertFalse(result.sampled)
        self.assertIsNone(fixture.observer.pending)
        self.assertEqual({values["request_id"] for _, values in fixture.client.requests}, {pending.request_id})
        self.assertTrue(all(frame is pending.frame for frame, _ in fixture.client.requests))

    def test_interrupt_preserves_pending_payload_and_uncertainty(self):
        fixture = ObserverFixture()
        fixture.client.interrupt_reply = True
        fixture.observer.request_drain()
        fixture.tick()
        with self.assertRaises(KeyboardInterrupt):
            fixture.tick()
        pending = fixture.observer.pending
        self.assertIsNotNone(pending)
        fixture.client.interrupt_reply = False
        self.assertTrue(fixture.tick().acknowledged)
        self.assertEqual(fixture.client.requests[-1][1]["request_id"], pending.request_id)

    def test_stale_retry_is_only_old_receipt_and_does_not_count_as_new_sample(self):
        fixture = ObserverFixture()
        fixture.client.lose_reply = True
        fixture.start_frame()
        pending = fixture.observer.pending
        fixture.client.lose_reply = False
        result = fixture.tick(seconds=10)
        self.assertTrue(result.acknowledged)
        self.assertFalse(result.sampled)
        self.assertFalse(result.complete)
        self.assertEqual(fixture.sampler.sample_seq, pending.frame.sample_seq)
        self.assertEqual(len(fixture.client.replies), 1)
        self.assertFalse(fixture.tick().sampled)  # delta gap must warm up again.

    def test_retired_scope_does_not_prevent_exact_pending_ack_reconciliation(self):
        fixture = ObserverFixture()
        fixture.client.lose_reply = True
        fixture.start_frame()
        pending = fixture.observer.pending
        fixture.sampler.release(EX)
        fixture.source.binding = replace(fixture.source.binding, executions=(), admission_barrier="NONE",
                                         registry_revision=18)
        fixture.client.lose_reply = False
        result = fixture.tick()
        self.assertTrue(result.acknowledged)
        self.assertTrue(result.complete)
        self.assertIs(fixture.client.requests[-1][0], pending.frame)
        self.assertEqual(fixture.client.requests[-1][1]["request_id"], pending.request_id)

    def test_native_cleanup_custody_blocks_retry_and_completion(self):
        fixture = ObserverFixture()
        cause = OSError("synthetic pending native cleanup")
        cause._identity_handle_cleanup = (object(),)
        failure = transport.ControlTransportError("control_rpc_failed", outcome_unknown=True)
        failure._control_cause = cause
        fixture.observer.request_drain()
        fixture.tick()
        with patch.object(fixture.client, "observe_uncapped", side_effect=failure) as send:
            self.assertTrue(fixture.tick().uncertain)
            pending = fixture.observer.pending
            self.assertTrue(fixture.observer.cleanup_pending)
            fixture.source.binding = replace(fixture.source.binding, admission_barrier="NONE")
            self.assertEqual(fixture.tick().reason, "helper_drain_cleanup_pending")
            self.assertEqual(send.call_count, 1)
            self.assertIs(fixture.observer.pending, pending)
            self.assertIs(fixture.observer._cleanup_failure, failure)
            self.assertFalse(fixture.observer.complete)

    def test_wrong_missing_config_or_query_ack_stays_pending(self):
        for field in ("bad_request", "missing_results", "bad_config", "bad_query"):
            fixture = ObserverFixture()
            setattr(fixture.client, field, True)
            with self.subTest(field=field):
                self.assertTrue(fixture.start_frame().uncertain)
                pending = fixture.observer.pending
                fixture.tick()
                self.assertIs(fixture.observer.pending, pending)
                self.assertFalse(fixture.observer.complete)

    def test_definitive_rejected_frame_consumes_request_but_cannot_release(self):
        fixture = ObserverFixture()
        fixture.client.observation = ControlObservation.REJECTED
        result = fixture.start_frame()
        self.assertEqual(result.reason, "helper_drain_observation_rejected")
        self.assertTrue(result.acknowledged)
        self.assertFalse(result.complete)
        self.assertIsNone(fixture.observer.pending)
        old = fixture.client.requests[-1][1]["request_id"]
        fixture.tick()
        self.assertNotEqual(fixture.client.requests[-1][1]["request_id"], old)

    def test_changed_epoch_or_job_nonce_does_not_adopt_pending_request(self):
        for change in ("guardian_epoch", "job_nonce"):
            fixture = ObserverFixture()
            fixture.client.lose_reply = True
            fixture.start_frame()
            pending = fixture.observer.pending
            if change == "guardian_epoch":
                fixture.source.binding = replace(fixture.source.binding, guardian_epoch="replacement")
            else:
                row = dict(fixture.source.binding.executions[0], job_nonce="b" * 32)
                fixture.source.binding = replace(fixture.source.binding, executions=(MappingProxyType(row),))
            calls = len(fixture.client.requests)
            fixture.tick()
            self.assertIs(fixture.observer.pending, pending)
            self.assertEqual(len(fixture.client.requests), calls)

    def test_frame_only_factory_cannot_return_active_control_client(self):
        fixture = ObserverFixture()
        fixture.client.propose = lambda *_: self.fail("restrictive proposal")
        self.assertEqual(fixture.start_frame().reason, "helper_drain_frame_only_client_required")
        self.assertFalse(fixture.client.requests)
        self.assertIsNone(fixture.observer.pending)

    def test_restore_obligation_error_does_not_claim_completion(self):
        fixture = ObserverFixture()
        fixture.source.binding = replace(fixture.source.binding, admission_barrier="NONE")
        def unknown():
            raise OSError("synthetic unavailable")
        fixture.observer.restore_pending = unknown
        fixture.observer.request_drain()
        self.assertFalse(fixture.tick().complete)
        self.assertEqual(fixture.constructed, 0)


class ObservationTransportTests(unittest.TestCase):
    def test_frame_client_has_no_active_api_and_creates_no_active_client(self):
        with patch.object(transport.ControlProposalClient, "__init__", side_effect=AssertionError("active client")):
            client = transport.ObservationClient(ENDPOINT, caller_process_or_identity=HELPER)
        self.assertFalse(hasattr(client, "propose"))
        self.assertFalse(hasattr(client, "request_restore"))
        self.assertFalse(hasattr(client, "_send"))

    def test_frame_client_uses_shared_authenticated_exchange_with_frame_request(self):
        fixture = ObserverFixture()
        fixture.start_frame()
        frame = fixture.client.requests[-1][0]
        request_id = str(uuid4())
        client = transport.ObservationClient(ENDPOINT, caller_process_or_identity=HELPER)
        marker = object()
        with patch.object(transport, "_send_operation", return_value=marker) as exchange:
            self.assertIs(client.observe_uncapped(frame, request_id=request_id,
                guardian_epoch="guardian-fixture", policy_epoch=POLICY, timeout_ms=500), marker)
        args, kwargs = exchange.call_args
        self.assertEqual(args[:2], (ENDPOINT, HELPER))
        self.assertIs(type(args[2]), ControlFrameRequest)
        self.assertIs(args[2].frame, frame)
        self.assertEqual(args[2].request_id, request_id)
        self.assertEqual(kwargs, {"timeout_ms": 500})

    def test_wrong_logon_and_invalid_frame_refuse_before_exchange(self):
        with self.assertRaisesRegex(transport.ControlTransportError, "logon_mismatch"):
            transport.ObservationClient(ENDPOINT, caller_process_or_identity=replace(HELPER, logon_id="S-1-5-5-7-8"))
        client = transport.ObservationClient(ENDPOINT, caller_process_or_identity=HELPER)
        with patch.object(transport, "_send_operation", side_effect=AssertionError("wire called")):
            with self.assertRaisesRegex(transport.ControlTransportError, "invalid_frame_request"):
                client.observe_uncapped(None, request_id=str(uuid4()), guardian_epoch="guardian-fixture", policy_epoch=POLICY)

    def test_shared_exchange_preserves_private_native_failure_cause(self):
        fixture = ObserverFixture()
        fixture.start_frame()
        frame = fixture.client.requests[-1][0]
        request = ControlFrameRequest(str(uuid4()), "guardian-fixture", POLICY, frame)
        cause = OSError("synthetic native owner")
        cause._identity_handle_cleanup = (object(),)
        with patch.object(transport.NativeDeadline, "after_ms", side_effect=cause):
            with self.assertRaises(transport.ControlTransportError) as caught:
                transport._send_operation(ENDPOINT, HELPER, request, timeout_ms=500)
        self.assertIs(caught.exception._control_cause, cause)


if __name__ == "__main__":
    unittest.main()
