"""Experimental control dispatch: real two-ledger authority, explicit fixtures.

ControlProposalService, GuardianControl.apply, the infrastructure registry and
the original authority use production code and real temporary SQLite files.
Processes, pipe I/O, clocks, the retained Job entry and its mutation scope are
synthetic. Selected tests replace _apply_locked with a recording consumer to
inspect the actual boundary; off/shadow tests keep that consumer real. None of
these tests proves native containment, Set capability, recovery or timing.
"""
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from sentinel.adaptive import control_transport as transport
from sentinel.adaptive.contracts import (ApplyResult, ControlProposal, CpuControlMode, CpuTarget,
    IdentityObservation, IdentityStatus, ProcessIdentity)
from sentinel.adaptive.control_messages import ControlFrameRequest
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.guardian_control import GuardianControl
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.legacy_writer import initialize_registry_locked, register_infrastructure_locked
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleStore
from tests import test_adaptive_control_transport as control_fixtures
from tests import test_adaptive_decision as decision_fixtures
from tests import test_adaptive_experiment_host_authority as authority_fixtures
from tests import test_adaptive_experiment_host_transport as native_fixtures
from tests.test_adaptive_ipc import Clock, Connection, Listener, wire_frame


class ExperimentControlDispatchTests(unittest.TestCase):
    def setUp(self):
        self.fixture = authority_fixtures.ExperimentHostAuthorityTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.admit()
        # Coordinator's create-capable store is not a guardian startup proof.
        # Open the already-created fixture ledger before the original typed
        # authority pins its exact store; keep the real existing-path guard.
        original_store = self.fixture.store
        self.fixture.store = LifecycleStore(original_store.db_path, existing_path=True,
            policy_provider=self.fixture.fixture.policy, local_host_id=original_store.local_host_id)
        self.authority, self.binding = self.fixture.guardian()
        self.execution_id = self.fixture.execution_id
        guardian = self.fixture.guardian_identity
        identity = ProcessIdentity(guardian.pid + 4000, guardian.created_filetime_100ns + 11,
                                   guardian.logon_id)
        self.helper = VerifiedProcess(native_fixtures.Backend(identity), 41, identity)
        self.addCleanup(self.helper.close)
        self.endpoint = NativePipeEndpoint(guardian.logon_id, str(uuid4()), guardian)
        self.clock = Clock()
        override = patch("sentinel.adaptive.pipe_windows._backend", return_value=self.clock)
        override.start()
        self.addCleanup(override.stop)
        directory = Path(self.fixture.store.db_path).parent / "control-journal"
        directory.mkdir()
        self.owner = GuardianLaunchOwner(self.fixture.store, RecoveryJournal(directory),
            guardian_epoch="fixture-experiment-guardian", authority=self.authority,
            guardian=self.fixture.guardian_process)
        self.assessments = []

        def assess():
            self.assert_unlocked()
            self.assessments.append(True)
            return SimpleNamespace(eligible=True, reason="fixture_capability_only")

        self.control = GuardianControl(self.owner, profile=decision_fixtures.SHADOW,
            clock=lambda: 10_000_000, capability_authority=SimpleNamespace(assess=assess),
            native_capability_source=lambda: SimpleNamespace(logical_processors=12, processor_groups=1))
        self.entry = SimpleNamespace(execution_id=self.execution_id)
        self.calls, self.operations = [], []

        @contextmanager
        def synthetic_job_scope(entry):
            self.assertIs(entry, self.entry)
            self.assertTrue(self.fixture.host.fixture.fixture.policy.active)
            self.assertFalse(self.fixture.fixture.policy.active)
            self.assertEqual(self.fixture.fixture.daily_transactions, [])
            with self.fixture.isolated_policy():
                yield

        for override in (
            patch.object(self.control.lifecycle, "_entry", return_value=self.entry),
            patch.object(self.control.lifecycle, "_scope", synthetic_job_scope),
        ):
            override.start()
            self.addCleanup(override.stop)
        self.service = transport.ControlProposalService(self.fixture.store, self.endpoint, self.control)

    def prepare(self, *, publish_job=True):
        if publish_job:
            job = self.fixture.publish_job()
            self.fixture.register_isolated_job(self.authority, job)
        with self.authority.new_work_scope(self.execution_id, operation="prepare"):
            with self.fixture.isolated_policy():
                initialize_registry_locked(self.fixture.store)
                register_infrastructure_locked(self.fixture.store, "helper", self.helper)

    def proposal(self, **changes):
        request = ControlProposal(str(uuid4()), self.execution_id, self.owner.guardian_epoch,
            self.binding.manifest.isolated_policy_instance_id, "sampler-a", "clock-a", "a" * 64,
            0, 0, 1, 1, 10_000_000, 10_000_000,
            CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, 2.0, 2500, 8), "fixture_proposal")
        return replace(request, **changes)

    def assert_unlocked(self):
        self.assertIsNone(self.authority._active)
        self.assertFalse(self.fixture.host.fixture.fixture.policy.active)
        self.assertFalse(self.fixture.fixture.policy.active)
        self.assertEqual(self.fixture.fixture.daily_transactions, [])

    def pipe_for(self, request, *, payload=None, on_write=None):
        def check_write(pipe, message):
            self.assert_unlocked()
            if on_write is not None:
                on_write(pipe, message)
        self.pipe = Connection(self.helper.identity,
            wire_frame(transport.request_envelope(request)) if payload is None else payload,
            on_write=check_write, on_read=lambda *_: self.assert_unlocked())
        return self.pipe

    def serve(self):
        return self.service.serve_once(Listener(self.endpoint, self.pipe), timeout_ms=1000)

    def retained_floor(self):
        host = self.fixture.host
        return host.fixture.assert_retained(host.owner)

    def record_consumer(self):
        def apply_locked(proposal, entry, episode, now, helper_identity, assessment_error):
            self.calls.append(proposal)
            self.operations.append(self.authority._active.operation)
            self.assertIsNone(assessment_error)
            self.assertTrue(self.pipe.peer_held)
            self.assertEqual(helper_identity, self.helper.identity)
            self.assertEqual([item["kind"] for item in self.pipe.writes], ["ControlChallenge"])
            self.assertTrue(self.fixture.host.fixture.fixture.policy.active)
            self.assertTrue(self.fixture.fixture.policy.active)
            self.assertEqual(self.fixture.fixture.daily_transactions, [])
            row = self.fixture.store.query(proposal.execution_id, existing_path=True)
            self.authority.assert_covered(row)
            self.authority.assert_excluded(row)
            return control_fixtures.refusal_ack(proposal)
        override = patch.object(self.control, "_apply_locked", side_effect=apply_locked)
        override.start()
        self.addCleanup(override.stop)

    def test_authenticated_proposal_acquires_daily_then_isolated_and_exits_before_reply(self):
        self.prepare()
        self.record_consumer()
        before = self.retained_floor()
        request = self.proposal(reason="renew")  # Caller text confers no renewal state.
        self.pipe_for(request)
        self.assertEqual(self.serve(), control_fixtures.refusal_ack(request))
        self.assertEqual(self.operations, ["restrict"])
        self.assertEqual(self.assessments, [True])
        self.assertEqual([item["kind"] for item in self.pipe.writes], ["ControlChallenge", "ControlAck"])
        self.assertEqual(self.retained_floor(), before)
        self.assert_unlocked()

    def test_retained_episode_selects_renew_and_restored_episode_selects_restrict(self):
        self.prepare()
        self.record_consumer()
        episode = SimpleNamespace(restored=False, acks={})
        self.control._episodes[self.execution_id] = episode
        self.pipe_for(self.proposal())
        self.serve()
        episode.restored = True
        self.pipe_for(self.proposal(decision_seq=2))
        self.serve()
        self.assertEqual(self.operations, ["renew", "restrict"])

    def test_missing_daily_job_publication_denies_before_consumer_and_keeps_capacity(self):
        self.prepare(publish_job=False)
        self.record_consumer()
        before = self.retained_floor()
        self.pipe_for(self.proposal())
        ack = self.serve()
        self.assertEqual(ack.reason, "experiment_host_daily_job_required")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.retained_floor(), before)

    def test_unknown_original_cleanup_denies_before_consumer(self):
        self.prepare()
        self.record_consumer()
        attempt = {"returned": False, "error": RuntimeError("fixture_unsettled")}
        self.authority._body_attempt = attempt
        self.pipe_for(self.proposal())
        ack = self.serve()
        self.assertEqual(ack.reason, "experiment_host_cleanup_unverified")
        self.assertIs(self.authority._body_attempt, attempt)
        self.assertEqual(self.calls, [])

    def test_peer_death_after_challenge_cannot_assess_or_acquire_daily_scope(self):
        self.prepare()
        def dead(pipe, message):
            pipe.retained.observation = IdentityObservation(self.helper.identity, IdentityStatus.DEAD)
        self.pipe_for(self.proposal(), on_write=dead)
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("scope before authentication")):
            with self.assertRaises(transport.IpcError):
                self.serve()
        self.assertEqual(self.assessments, [])

    def test_malformed_typed_proposal_cannot_assess_or_acquire_daily_scope(self):
        self.prepare()
        request = self.proposal()
        wire = transport.request_envelope(request)
        wire["proposal"]["execution_id"] = "invalid"
        self.pipe_for(request, payload=wire_frame(wire))
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("scope before decoding")):
            with self.assertRaises(transport.ControlTransportError):
                self.serve()
        self.assertEqual(self.assessments, [])
        self.assertEqual(self.pipe.writes, [])

    def test_cached_ack_needs_neither_new_assessment_nor_daily_readiness(self):
        self.prepare()
        request = self.proposal()
        expected = control_fixtures.refusal_ack(request)
        self.control._proposal_payloads[request.request_id] = (self.helper.identity, self.control._digest(request))
        self.control._episodes[self.execution_id] = SimpleNamespace(restored=False,
            acks={request.decision_seq: (request.request_id, expected)}, helper_identity=self.helper.identity)
        self.binding._peer._backend.status = IdentityStatus.DEAD
        self.authority._body_attempt = {"returned": False, "error": RuntimeError("fixture_unsettled")}
        self.pipe_for(request)
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("replay acquired scope")):
            self.assertIs(self.serve(), expected)
        self.assertEqual(self.assessments, [])

    def test_ordinary_authority_keeps_existing_consumer_dispatch(self):
        self.prepare()
        self.owner.authority = SimpleNamespace()  # Explicit ordinary collaborator fixture.
        request = self.proposal()
        expected = control_fixtures.refusal_ack(request)
        self.pipe_for(request)
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("ordinary scope changed")), \
                patch.object(self.control.lifecycle, "_scope", return_value=nullcontext()), \
                patch.object(self.control, "_apply_locked", return_value=expected) as consumer:
            self.assertIs(self.serve(), expected)
        consumer.assert_called_once()
        self.assertEqual(self.assessments, [True])

    def assert_mode_denied(self, mode):
        self.prepare()
        # Isolated fixture data only; no daily or production mode is changed.
        with sqlite3.connect(self.fixture.store.db_path) as conn:
            conn.execute("UPDATE adaptive_runtime SET mode=?", (mode,))
        self.pipe_for(self.proposal())
        before = self.retained_floor()
        ack = self.serve()
        self.assertIs(ack.result, ApplyResult.REJECTED)
        self.assertEqual(self.control.backend_calls, [])
        self.assertEqual(self.retained_floor(), before)
        if mode in {"off", "shadow"}:
            # The real _apply_locked rejects the mode. Its failed inner scope
            # remains conservatively retained by the original authority.
            self.assertEqual(str(self.authority._body_attempt["error"]), "control_mode_unavailable")
        else:
            self.assertEqual(ack.reason, "experiment_host_isolated_new_work_blocked")

    def test_off_keeps_real_consumer_unable_to_set(self):
        self.assert_mode_denied("off")

    def test_shadow_keeps_real_consumer_unable_to_set(self):
        self.assert_mode_denied("shadow")

    def test_fixture_canary_mode_cannot_upgrade_experimental_authority(self):
        self.assert_mode_denied("canary")

    def test_empty_frame_remains_available_with_dead_parent_and_unknown_cleanup(self):
        self.prepare()
        self.binding._peer._backend.status = IdentityStatus.DEAD
        self.authority._body_attempt = {"returned": False, "error": RuntimeError("fixture_unsettled")}
        with sqlite3.connect(self.fixture.store.db_path) as conn:
            revision = conn.execute("SELECT registry_revision FROM adaptive_runtime").fetchone()[0]
        frame = decision_fixtures.frame(1, 10_000_000, 1.0, jobs=(),
            config_revision=self.control.config_revision, registry_revision=revision)
        request = ControlFrameRequest(str(uuid4()), self.owner.guardian_epoch,
            self.binding.manifest.isolated_policy_instance_id, frame)
        self.pipe_for(request)
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("frame gated on daily")):
            ack = self.serve()
        self.assertEqual(ack.results, ())
        self.assertEqual(self.control._latest_frame, frame)
        self.assertEqual(self.assessments, [])

    def test_restore_and_expiry_consumer_do_not_acquire_new_daily_scope(self):
        self.prepare()
        self.binding._peer._backend.status = IdentityStatus.DEAD
        self.authority._body_attempt = {"returned": False, "error": RuntimeError("fixture_unsettled")}
        episode = SimpleNamespace(restored=False, lease_deadline_tick_100ns=None)
        self.control._episodes[self.execution_id] = episode
        restored = []
        def restore(entry, observed, reason):
            self.assert_unlocked()
            self.assertIs(entry, self.entry)
            self.assertIs(observed, episode)
            restored.append(reason)
            return "fixture_retained_restore"
        with patch.object(self.authority, "new_work_scope", side_effect=AssertionError("restore gated on daily")), \
                patch.object(self.control.lifecycle, "_scope", return_value=nullcontext()), \
                patch.object(self.control, "_restore_locked", side_effect=restore):
            self.assertEqual(self.control.request_restore(self.execution_id, reason="fixture_restore"),
                             "fixture_retained_restore")
            self.assertEqual(self.control.tick(10_000_000),
                ((self.execution_id, "lease_expired", "fixture_retained_restore"),))
        self.assertEqual(restored, ["fixture_restore", "lease_expired"])
        self.assertEqual(self.assessments, [])


if __name__ == "__main__":
    unittest.main()
