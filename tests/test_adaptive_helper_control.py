"""Active sender contracts over production sampling and explicit synthetic RPC.

No Windows effects, capability approvals or timing gates are claimed. Binding
reader cases use real isolated read-only SQLite transactions.
"""
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import ApplyAck, ApplyResult, ProcessIdentity, TICKS_PER_SECOND, Validity
from sentinel.adaptive.control_messages import ControlFrameAck, ControlFrameResult, ControlObservation, RestoreAck, RestoreOutcome
from sentinel.adaptive.decision import Mode
from sentinel.adaptive.helper_control import ControlBindingSnapshot, ControlBindingSource, HelperControl, HelperControlError
from sentinel.adaptive.helper_control_host import HelperControlHost
from sentinel.adaptive.pipe_windows import NativePipeEndpoint
from sentinel.adaptive.sampler import FrameBinding, FrameSampler
from tests.test_adaptive_helper import ClockStub, SyntheticJobBackend, SyntheticMachineSource, profile, execution, BASE_TICK, HIGH_BUSY

EX = execution(1)
LOGON = 'S-1-5-5-1-2'
HELPER = ProcessIdentity(7001, 134343072000000001, LOGON)
GUARDIAN = ProcessIdentity(7002, 134343072000000002, LOGON)
ENDPOINT = NativePipeEndpoint(LOGON, '20000000-0000-4000-8000-000000000001', GUARDIAN)
POLICY = '30000000-0000-4000-8000-000000000001'


def execution_row():
    return dict(execution_id=EX, principal_id='fixture', logon_id=LOGON,
        job_name=f'Local\\ResourceSentinel.Job.{EX}.{"a"*32}', job_nonce='a'*32,
        role='background', priority='P2', coverage='job_contained', state='RUNNING',
        state_revision=3, guardian_epoch='guardian-fixture', launch_sealed=1, launch_in_flight=0,
        counter_epoch='counter-1')


class SyntheticAuthority:
    def __init__(self):
        self.calls = []
        self.allowed = True

    def assert_control_eligible(self, **values):
        self.calls.append(values)
        if not self.allowed:
            raise HelperControlError('fixture_capability_unavailable')
        return SimpleNamespace(config_revision=values['profile_revision'],
                               logical_processors=values['logical_processors'])


class SyntheticBindingSource:
    def __init__(self, revision):
        self.binding = ControlBindingSnapshot(ENDPOINT, HELPER, 'guardian-fixture', POLICY,
            17, revision, 'canary', 'NONE', (MappingProxyType(execution_row()),))
        self.changed = False

    def read(self, ids):
        return self.binding

    def confirm_unchanged(self, binding):
        return not self.changed and self.binding == binding

    def exemption_revision(self, binding):
        return 23


class SyntheticClient:
    def __init__(self, fixture):
        self.f = fixture
        self.frames, self.proposals, self.restores = [], [], []
        self.active_ack = None
        self.lose_proposal = self.lose_frame = False
        self.bad_ack = self.unverified_restore = False
        self.bad_renew_action = self.renew_changed_target = False
        self.barrier_cleared = True
        self.frame_revision_delta = 0
        self.missing_results = False

    def observe_uncapped(self, frame, **kwargs):
        self.frames.append((frame, kwargs))
        if self.lose_frame:
            raise TimeoutError('synthetic_lost_frame_reply')
        results = () if self.missing_results else tuple(ControlFrameResult(j.execution_id,
            ControlObservation.CAPPED if self.active_ack else ControlObservation.UNCAPPED,
            self.f.clock(), self.barrier_cleared and not self.active_ack, 'fixture') for j in frame.jobs)
        return ControlFrameAck(kwargs['request_id'], kwargs['guardian_epoch'], kwargs['policy_epoch'],
            frame.sampler_epoch, frame.clock_epoch, frame.sample_seq,
            frame.registry_revision+self.frame_revision_delta, frame.config_revision, results)

    def propose(self, proposal, **kwargs):
        self.proposals.append(proposal)
        now = self.f.clock()
        deadline = (self.active_ack.intervention_deadline_tick_100ns if self.active_ack else
                    proposal.decision_tick_100ns+self.f.profile.intervention_max_ms*10000)
        result = ApplyResult.RENEWED if self.active_ack and self.active_ack.applied_rate_bp == proposal.target.cpu_rate_bp else ApplyResult.APPLIED
        action_id = self.active_ack.action_id if result is ApplyResult.RENEWED else str(uuid4())
        if result is ApplyResult.RENEWED and self.bad_renew_action:
            action_id = str(uuid4())
        if self.active_ack and self.renew_changed_target and result is ApplyResult.APPLIED:
            result, action_id = ApplyResult.RENEWED, self.active_ack.action_id
        ack = ApplyAck(proposal.request_id, action_id, proposal.execution_id, proposal.guardian_epoch,
            proposal.policy_epoch, proposal.decision_seq, result, 5, proposal.target.cpu_rate_bp,
            Validity.VALID, now, min(now+15_000_000, deadline), deadline, 'fixture', None)
        self.active_ack = ack
        if self.lose_proposal:
            raise TimeoutError('synthetic_lost_apply_reply')
        return replace(ack, request_id=str(uuid4())) if self.bad_ack else ack

    def request_restore(self, execution_id, **kwargs):
        self.restores.append((execution_id, kwargs))
        if self.unverified_restore:
            return RestoreAck(kwargs['request_id'], kwargs['guardian_epoch'], kwargs['policy_epoch'],
                execution_id, RestoreOutcome.UNVERIFIED, None, None, None, None, None, None,
                Validity.UNKNOWN, None, 'fixture', None)
        self.active_ack = None
        return RestoreAck(kwargs['request_id'], kwargs['guardian_epoch'], kwargs['policy_epoch'],
            execution_id, RestoreOutcome.RESTORED, True, True, True, self.barrier_cleared, 0, None,
            Validity.VALID, self.f.clock(), 'fixture', None)


class DriverFixture:
    def __init__(self):
        self.profile = profile(mode=Mode.SHADOW)
        self.clock = ClockStub(BASE_TICK, step=0)
        self.backend = SyntheticJobBackend({EX:6.0})
        self.machine = SyntheticMachineSource(self.clock, HIGH_BUSY)
        self.sampler = FrameSampler(profile=self.profile, backend=self.backend,
            machine_source=self.machine, clock=self.clock)
        self.sampler.enroll(EX)
        self.source = SyntheticBindingSource(self.sampler.config_revision)
        self.authority = SyntheticAuthority()
        self.client = SyntheticClient(self)
        self.constructed = 0
        def factory(endpoint, identity):
            self.constructed += 1
            assert endpoint == ENDPOINT and identity == HELPER
            return self.client
        self.driver = HelperControl(profile=self.profile, sampler=self.sampler,
            binding_source=self.source, evidence_authority=self.authority,
            client_factory=factory, clock=self.clock)
        self.second = 0

    def tick(self):
        self.second += 1
        self.backend.advance(1)
        self.clock.set(BASE_TICK+self.second*TICKS_PER_SECOND)
        return self.driver.tick()

    def until_proposal(self):
        for _ in range(30):
            result = self.tick()
            if self.client.proposals:
                return result
        raise AssertionError('synthetic warmup did not produce a proposal')


class SenderTests(unittest.TestCase):
    def test_off_and_shadow_never_construct_client(self):
        for mode in ('off','shadow'):
            f = DriverFixture()
            f.source.binding = replace(f.source.binding, mode=mode)
            self.assertEqual(f.tick().reason, 'helper_control_mode_inactive')
            self.assertEqual(f.constructed, 0)
            self.assertEqual(f.sampler.sample_seq, 0)

    def test_missing_evidence_has_no_client_or_proposal(self):
        f = DriverFixture()
        f.authority.allowed = False
        for _ in range(8):
            f.tick()
        self.assertEqual(f.constructed, 0)
        self.assertFalse(f.client.proposals)

    def test_real_sample_bound_to_authoritative_revision_and_original_profile(self):
        f = DriverFixture()
        result = f.until_proposal()
        self.assertTrue(result.acknowledged)
        proposal = f.client.proposals[0]
        self.assertEqual(proposal.registry_revision, 17)
        self.assertNotEqual(proposal.registry_revision, f.sampler.enrollment_generation)
        self.assertEqual(proposal.config_revision, f.sampler.config_revision)
        self.assertEqual(proposal.exemption_revision_seen, 23)
        self.assertEqual(f.driver.acknowledged.target, proposal.target)
        self.assertEqual(f.driver.snapshot.active.execution_id, EX)

    def test_lost_apply_ack_retains_immutable_intent_and_no_applied_state(self):
        f = DriverFixture()
        f.client.lose_proposal = True
        self.assertTrue(f.until_proposal().uncertain)
        operation = f.driver.pending
        self.assertIsNone(f.driver.acknowledged)
        self.assertIsNone(f.driver.snapshot.active)
        f.tick()
        self.assertIs(f.driver.pending, operation)
        self.assertEqual(len(f.client.proposals), 1)
        self.assertTrue(f.driver.reconcile().acknowledged)
        self.assertFalse(f.driver.drain_pending)

    def test_mismatched_ack_cannot_advance_state(self):
        f = DriverFixture()
        f.client.bad_ack = True
        self.assertTrue(f.until_proposal().uncertain)
        self.assertIsNone(f.driver.snapshot.active)
        self.assertIsNone(f.driver.acknowledged)

    def test_gap_never_reuses_old_frame_and_restores_owned_episode(self):
        f = DriverFixture()
        f.until_proposal()
        previous = len(f.client.proposals)
        f.machine.machine_available = False
        self.assertTrue(f.tick().acknowledged)
        self.assertEqual(len(f.client.proposals), previous)
        self.assertEqual(len(f.client.restores), 1)
        self.assertIsNone(f.driver.acknowledged)

    def test_unknown_restore_remains_sticky_and_reuses_request(self):
        f = DriverFixture()
        f.until_proposal()
        f.client.unverified_restore = True
        self.assertTrue(f.driver.request_stop().uncertain)
        request_id = f.driver.pending.request_id
        f.driver.reconcile()
        self.assertEqual(f.driver.pending.request_id, request_id)
        self.assertIsNotNone(f.driver.acknowledged)
        self.assertTrue(f.driver.drain_pending)

    def test_delayed_restore_verification_anchors_cooldown_to_native_query(self):
        f = DriverFixture()
        f.until_proposal()
        proposed = replace(f.driver.snapshot, active=None,
            cooldown_execution_id=EX,
            cooldown_until_tick_100ns=f.clock()+f.profile.victim_cooldown_ms*10000)
        f.client.unverified_restore = True
        self.assertTrue(f.driver._restore('fixture', proposed).uncertain)
        f.clock.set(f.clock()+(f.profile.victim_cooldown_ms+10000)*10000)
        f.client.unverified_restore = False
        restored_at = f.clock()
        self.assertTrue(f.driver.reconcile().acknowledged)
        self.assertEqual(f.driver.snapshot.cooldown_until_tick_100ns,
                         restored_at+f.profile.victim_cooldown_ms*10000)

    def test_revision_change_during_capture_sends_nothing(self):
        f = DriverFixture()
        f.source.changed = True
        for _ in range(4):
            f.tick()
        self.assertEqual(f.constructed, 0)

    def test_sample_from_reopened_or_wrong_job_cannot_be_relabelled(self):
        f = DriverFixture()
        row = dict(f.source.binding.executions[0], counter_epoch='different-retained-handle')
        f.source.binding = replace(f.source.binding, executions=(MappingProxyType(row),))
        for _ in range(4):
            result = f.tick()
        self.assertEqual(result.reason, 'helper_sample_job_binding_changed')
        self.assertEqual(f.constructed, 0)

    def test_frame_revision_change_is_resampled_not_relabelled(self):
        f = DriverFixture()
        f.client.frame_revision_delta = 1
        for _ in range(8):
            result = f.tick()
        self.assertEqual(result.reason, 'helper_frame_registry_changed')
        self.assertFalse(result.uncertain)
        self.assertFalse(f.client.proposals)
        self.assertTrue(all(frame.registry_revision == 17 for frame,_ in f.client.frames))

    def test_missing_frame_result_cannot_establish_disabled_inventory(self):
        f = DriverFixture()
        f.client.missing_results = True
        for _ in range(8):
            result = f.tick()
        self.assertEqual(result.reason, 'helper_inventory_unverified')
        self.assertFalse(f.client.proposals)

    def test_lost_frame_reply_reconciles_same_request_without_capping(self):
        f = DriverFixture()
        f.client.lose_frame = True
        f.tick()
        f.tick()
        original = f.driver.pending
        self.assertEqual(original.kind, 'frame')
        f.client.lose_frame = False
        result = f.driver.reconcile()
        self.assertEqual(result.reason, 'helper_observation_reconciled')
        self.assertEqual(f.client.frames[-1][1]['request_id'], original.request_id)
        self.assertFalse(f.client.proposals)

    def test_restore_not_gated_by_missing_evidence_and_mode_off_keeps_barrier_observations(self):
        f = DriverFixture()
        f.until_proposal()
        f.client.barrier_cleared = False
        self.assertTrue(f.driver.request_stop().acknowledged)
        self.assertTrue(f.driver.drain_pending)
        f.authority.allowed = False
        f.source.binding = replace(f.source.binding, mode='off', admission_barrier='RECOVERY_HOLD')
        proposals = len(f.client.proposals)
        self.assertEqual(f.tick().reason, 'helper_barrier_observing')
        f.client.barrier_cleared = True
        self.assertEqual(f.tick().reason, 'helper_barrier_cleared')
        self.assertFalse(f.driver.drain_pending)
        self.assertEqual(len(f.client.proposals), proposals)

    def test_expired_ack_triggers_restore_not_renewal(self):
        f = DriverFixture()
        f.until_proposal()
        f.clock.set(f.driver.acknowledged.ack.lease_deadline_tick_100ns)
        self.assertTrue(f.driver.tick().acknowledged)
        self.assertEqual(len(f.client.proposals), 1)
        self.assertEqual(len(f.client.restores), 1)

    def test_renewal_preserves_action_identity(self):
        f = DriverFixture()
        f.until_proposal()
        original = f.driver.acknowledged.ack.action_id
        self.assertTrue(f.tick().acknowledged)
        self.assertEqual(f.driver.acknowledged.ack.result, ApplyResult.RENEWED)
        self.assertEqual(f.driver.acknowledged.ack.action_id, original)

    def test_renewal_with_different_action_is_not_applied_state(self):
        f = DriverFixture()
        f.until_proposal()
        original = f.driver.acknowledged
        f.client.bad_renew_action = True
        self.assertEqual(f.tick().reason, 'helper_apply_action_mismatch')
        self.assertIs(f.driver.acknowledged, original)

    def test_changed_native_target_cannot_be_acknowledged_as_renewal(self):
        f = DriverFixture()
        f.until_proposal()
        original_rate = f.driver.acknowledged.ack.applied_rate_bp
        f.client.renew_changed_target = True
        for _ in range(12):
            result = f.tick()
            if result.uncertain:
                break
        self.assertEqual(result.reason, 'helper_apply_action_mismatch')
        self.assertEqual(f.driver.acknowledged.ack.applied_rate_bp, original_rate)

    def test_evidence_gaps_preserve_verified_restore_cooldown(self):
        for cause in ('registry','frame','frame_revision'):
            with self.subTest(cause=cause):
                f = DriverFixture()
                f.until_proposal()
                self.assertTrue(f.driver._restore('fixture').acknowledged)
                deadline = f.driver.snapshot.cooldown_until_tick_100ns
                if cause == 'registry':
                    f.source.changed = True
                elif cause == 'frame':
                    f.machine.machine_available = False
                else:
                    f.client.frame_revision_delta = 1
                f.tick()
                self.assertEqual(f.driver.snapshot.cooldown_execution_id, EX)
                self.assertEqual(f.driver.snapshot.cooldown_until_tick_100ns, deadline)
                f.source.changed = False
                f.machine.machine_available = True
                f.client.frame_revision_delta = 0
                for _ in range(8):
                    f.tick()
                self.assertLess(f.clock(), deadline)
                self.assertEqual(len(f.client.proposals), 1)

    def test_sampler_rejects_foreign_profile_and_enrollment_binding(self):
        f = DriverFixture()
        for binding in (FrameBinding(17, 'a'*64, (EX,)),
                        FrameBinding(17, f.sampler.config_revision, ())):
            with self.assertRaises(ValueError):
                f.sampler.sample(binding=binding)


class HostReceiptRefreshTests(unittest.TestCase):
    def host(self, fixture, assess):
        host = HelperControlHost(data_dir='synthetic-unused', endpoint=ENDPOINT,
            guardian_epoch='guardian-fixture', evidence_authority=fixture.authority,
            sleep=lambda seconds: None)
        host._started = True  # Explicit fixture seam: no host/native startup.
        host.control, host.sampler, host.profile = fixture.driver, fixture.sampler, fixture.profile
        host.jobs = SimpleNamespace(unreadable=lambda: (), enrolled=(EX,))
        host._pace = lambda: 0
        host.refresh_enrollment = lambda: None
        fixture.authority.assess = assess
        return host

    @staticmethod
    def advance(fixture):
        fixture.second += 1
        fixture.backend.advance(1)
        fixture.clock.set(BASE_TICK+fixture.second*TICKS_PER_SECOND)

    def test_active_host_refreshes_before_capture_on_every_tick(self):
        f = DriverFixture()
        events = []
        def assess():
            events.append('refresh')
            return SimpleNamespace(eligible=True)
        original = f.sampler.sample
        def sample(**kwargs):
            events.append('capture')
            return original(**kwargs)
        f.sampler.sample = sample
        host = self.host(f, assess)
        for _ in range(2):
            self.advance(f)
            host.run_once()
        self.assertEqual(events, ['refresh','capture','refresh','capture'])

    def test_inactive_runtime_does_not_refresh_or_construct_client(self):
        for mode in ('off','shadow'):
            f = DriverFixture()
            f.source.binding = replace(f.source.binding, mode=mode)
            calls = []
            host = self.host(f, lambda: calls.append('unexpected'))
            self.advance(f)
            host.run_once()
            self.assertFalse(calls)
            self.assertEqual(f.constructed, 0)

    def test_failed_refresh_restores_without_using_previously_allowed_receipt(self):
        for raises in (False, True):
            f = DriverFixture()
            f.until_proposal()
            def assess():
                if raises:
                    raise RuntimeError('synthetic_prepare_failure')
                return SimpleNamespace(eligible=False)
            host = self.host(f, assess)
            self.advance(f)
            host.run_once()
            self.assertEqual(len(f.client.proposals), 1)
            self.assertEqual(len(f.client.restores), 1)
            self.assertIsNone(f.driver.acknowledged)

    def test_pending_restore_and_post_restore_observations_skip_refresh(self):
        f = DriverFixture()
        f.until_proposal()
        f.client.unverified_restore = True
        f.driver.request_stop()
        calls = []
        host = self.host(f, lambda: calls.append('unexpected'))
        f.client.unverified_restore = False
        f.client.barrier_cleared = False
        self.advance(f)
        host.run_once()
        f.source.binding = replace(f.source.binding, mode='off', admission_barrier='RECOVERY_HOLD')
        self.advance(f)
        host.run_once()
        # The reconciliation iteration performed no sampling. The first later
        # sample spans two seconds and must rebuild its 0.5–1.5s CPU baseline;
        # it cannot be presented as a valid uncapped observation.
        self.assertEqual(host._control_last.reason, 'helper_frame_unavailable')
        self.advance(f)
        host.run_once()
        self.assertFalse(calls)
        self.assertEqual(host._control_last.reason, 'helper_barrier_observing')


class BindingReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'sentinel.db'
        self.source = ControlBindingSource(self.path, endpoint=ENDPOINT, helper_identity=HELPER,
            guardian_epoch='guardian-fixture', profile=profile(mode=Mode.SHADOW),
            retained_binding=lambda execution_id: (execution_row()['job_name'], 'a'*32, LOGON, 'counter-1'))
        self.conn = sqlite3.connect(self.path)
        self.addCleanup(self.conn.close)
        self.conn.execute('''CREATE TABLE adaptive_runtime(singleton,schema_version,protocol_version,
            registry_revision,mode,guardian_epoch,active_logon_id,policy_instance_id,
            policy_logon_id,policy_binding_initialized,admission_barrier)''')
        self.conn.execute('INSERT INTO adaptive_runtime VALUES(1,1,1,31,?,?,?,?,?,1,?)',
            ('canary','guardian-fixture',LOGON,POLICY,LOGON,'NONE'))
        self.conn.execute('CREATE TABLE adaptive_infrastructure(role,pid,created_filetime_100ns,logon_id,schema_version)')
        for role, peer in (('helper',HELPER),('guardian',GUARDIAN)):
            self.conn.execute('INSERT INTO adaptive_infrastructure VALUES(?,?,?,?,1)',
                (role,peer.pid,str(peer.created_filetime_100ns),peer.logon_id))
        row = execution_row()
        self.conn.execute('CREATE TABLE managed_executions('+','.join(row)+')')
        self.conn.execute('INSERT INTO managed_executions VALUES('+','.join('?' for _ in row)+')', tuple(row.values()))
        self.conn.commit()

    def test_snapshot_contains_real_revision_and_exact_enrollment_only(self):
        snapshot = self.source.read((EX,))
        self.assertEqual(snapshot.registry_revision, 31)
        self.assertEqual(snapshot.execution_ids, (EX,))
        self.assertEqual(snapshot.executions[0]['job_nonce'], 'a'*32)
        self.assertTrue(self.source.confirm_unchanged(snapshot))
        self.conn.execute('UPDATE adaptive_runtime SET registry_revision=32')
        self.conn.commit()
        self.assertFalse(self.source.confirm_unchanged(snapshot))

    def test_ambiguous_helper_fails_without_database_mutation(self):
        self.conn.execute("INSERT INTO adaptive_infrastructure SELECT * FROM adaptive_infrastructure WHERE role='helper'")
        self.conn.commit()
        before = self.path.read_bytes()
        with self.assertRaises(HelperControlError):
            self.source.read((EX,))
        self.assertEqual(self.path.read_bytes(), before)

    def test_changed_job_nonce_and_unsealed_launch_fail_closed(self):
        for field,value in [('job_nonce','b'*32),('launch_sealed',0)]:
            with self.subTest(field=field):
                self.conn.execute(f'UPDATE managed_executions SET {field}=?', (value,))
                self.conn.commit()
                with self.assertRaises(HelperControlError):
                    self.source.read((EX,))
                self.conn.execute(f'UPDATE managed_executions SET {field}=?', (execution_row()[field],))
                self.conn.commit()

    def test_ledger_cannot_rebind_a_retained_query_handle_to_a_new_job(self):
        self.conn.execute('UPDATE managed_executions SET job_nonce=?,job_name=?',
            ('b'*32, f'Local\\ResourceSentinel.Job.{EX}.{"b"*32}'))
        self.conn.commit()
        with self.assertRaisesRegex(HelperControlError, 'retained_job_binding_changed'):
            self.source.read((EX,))

    def test_missing_database_is_not_created(self):
        self.source.db_path = self.path.with_name('absent.db')
        with self.assertRaises(Exception):
            self.source.read((EX,))
        self.assertFalse(self.source.db_path.exists())


if __name__ == '__main__':
    unittest.main()
