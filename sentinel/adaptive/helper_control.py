"""ACK-driven helper control, separate from the zero-send shadow observer.

This module holds query-only sampling state and sends typed intentions. It owns
no native actuator, reservation release or writer authority. Missing evidence,
uncertain replies and a changed binding prevent further restriction.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
import sqlite3
import time
from types import MappingProxyType
from uuid import UUID, uuid4

from .contracts import (ApplyAck, ApplyResult, ContractViolation, Coverage,
                        CpuTarget, Priority, ProcessIdentity, Role, TICKS_PER_SECOND,
                        Validity, MAX_ENROLLED_JOBS)
from .control_messages import (ControlFrameAck, ControlObservation, RestoreAck,
                               RestoreOutcome)
from .decision import (ControllerSnapshot, ControllerState, DecisionAction, Mode,
                       VictimCandidate, next_state)
from .pipe_windows import NativePipeEndpoint
from .proposal_builder import build_control_proposal
from .sampler import FrameBinding, FrameSampler, profile_revision
from .store import LifecycleError, _ipc_read_transaction

TICKS_PER_MS = TICKS_PER_SECOND // 1000
_ACTIVE_MODES = {'canary', 'limited'}


class HelperControlError(LifecycleError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ControlBindingSnapshot:
    endpoint: NativePipeEndpoint
    helper_identity: ProcessIdentity
    guardian_epoch: str
    policy_epoch: str
    registry_revision: int
    config_revision: str
    mode: str
    admission_barrier: str
    executions: tuple

    @property
    def execution_ids(self):
        return tuple(row['execution_id'] for row in self.executions)

    def frame_binding(self):
        return FrameBinding(self.registry_revision, self.config_revision, self.execution_ids)


class ControlBindingSource:
    """One real read transaction binds registry, enrolled scopes and identities.

    The endpoint is supplied by the owner of discovery; it is never guessed from
    a PID or Job name. The agreed profile hash is pinned at construction, and a
    frame ACK independently confirms the guardian's copy of that hash.
    """

    def __init__(self, db_path, *, endpoint, helper_identity, guardian_epoch, profile, retained_binding):
        if (not isinstance(endpoint, NativePipeEndpoint)
                or not isinstance(helper_identity, ProcessIdentity)
                or helper_identity.logon_id != endpoint.logon_id
                or helper_identity == endpoint.server_identity):
            raise HelperControlError('helper_binding_identity_invalid')
        if type(guardian_epoch) is not str or not 1 <= len(guardian_epoch) <= 128:
            raise HelperControlError('helper_binding_epoch_invalid')
        self.db_path = Path(db_path)
        self.endpoint, self.helper_identity = endpoint, helper_identity
        self.guardian_epoch = guardian_epoch
        self.config_revision = profile_revision(profile)
        if not callable(retained_binding):
            raise HelperControlError('helper_retained_binding_source_required')
        self.retained_binding = retained_binding

    def read(self, execution_ids):
        ids = tuple(execution_ids)
        FrameBinding(0, self.config_revision, ids)
        with _ipc_read_transaction(self.db_path, timeout_ms=250) as conn:
            runtime = conn.execute('''SELECT registry_revision,
                substr(mode,1,9) AS mode, substr(guardian_epoch,1,129) AS guardian_epoch,
                substr(active_logon_id,1,129) AS active_logon_id,
                substr(policy_instance_id,1,37) AS policy_instance_id,
                substr(policy_logon_id,1,129) AS policy_logon_id,
                policy_binding_initialized, substr(admission_barrier,1,20) AS admission_barrier
                FROM adaptive_runtime WHERE singleton=1''').fetchone()
            if (runtime is None or runtime['guardian_epoch'] != self.guardian_epoch
                    or runtime['active_logon_id'] != self.endpoint.logon_id
                    or runtime['policy_logon_id'] != self.endpoint.logon_id
                    or runtime['policy_binding_initialized'] != 1
                    or runtime['mode'] not in {'off', 'shadow', 'canary', 'limited'}
                    or runtime['admission_barrier'] not in {'NONE','CONTROLLING','RECOVERY_HOLD'}):
                raise HelperControlError('helper_runtime_binding_invalid')
            try:
                if str(UUID(runtime['policy_instance_id'])) != runtime['policy_instance_id']:
                    raise ValueError
                FrameBinding(runtime['registry_revision'], self.config_revision, ids)
            except (ValueError, TypeError, ContractViolation):
                raise HelperControlError('helper_runtime_binding_invalid') from None
            for role, expected in (('helper', self.helper_identity), ('guardian', self.endpoint.server_identity)):
                peers = conn.execute('''SELECT pid, substr(created_filetime_100ns,1,21) AS birth,
                    substr(logon_id,1,129) AS logon_id, schema_version FROM adaptive_infrastructure
                    WHERE role=? AND logon_id=? LIMIT 2''', (role, self.endpoint.logon_id)).fetchall()
                if len(peers) != 1 or peers[0]['schema_version'] != 1:
                    raise HelperControlError('helper_registry_identity_invalid')
                try:
                    actual = ProcessIdentity.from_dict(dict(pid=peers[0]['pid'],
                        created_filetime_100ns=peers[0]['birth'], logon_id=peers[0]['logon_id']))
                except (ContractViolation, ValueError, TypeError):
                    raise HelperControlError('helper_registry_identity_invalid') from None
                if actual != expected:
                    raise HelperControlError('helper_registry_identity_changed')
            rows = []
            for execution_id in ids:
                row = conn.execute('''SELECT substr(execution_id,1,37) AS execution_id,
                    substr(principal_id,1,129) AS principal_id, substr(logon_id,1,129) AS logon_id,
                    substr(job_name,1,257) AS job_name, substr(job_nonce,1,33) AS job_nonce,
                    substr(role,1,33) AS role, substr(priority,1,9) AS priority,
                    substr(coverage,1,33) AS coverage, substr(state,1,33) AS state,
                    state_revision, substr(guardian_epoch,1,129) AS guardian_epoch,
                    launch_sealed, launch_in_flight FROM managed_executions WHERE execution_id=?''',
                    (execution_id,)).fetchone()
                if (row is None or row['execution_id'] != execution_id
                        or row['logon_id'] != self.endpoint.logon_id
                        or row['guardian_epoch'] != self.guardian_epoch
                        or row['coverage'] != 'job_contained'
                        or row['state'] not in {'RUNNING','DRAINING'}
                        or row['launch_sealed'] != 1 or row['launch_in_flight'] != 0
                        or type(row['state_revision']) is not int or row['state_revision'] < 0
                        or not row['principal_id'] or len(row['principal_id']) > 128
                        or len(row['job_nonce'] or '') != 32
                        or any(c not in '0123456789abcdef' for c in row['job_nonce'])
                        or row['job_name'] != f"Local\\ResourceSentinel.Job.{execution_id}.{row['job_nonce']}"):
                    raise HelperControlError('helper_execution_binding_invalid')
                try:
                    Role(row['role']), Priority(row['priority'])
                except ValueError:
                    raise HelperControlError('helper_execution_binding_invalid') from None
                held = self.retained_binding(execution_id)
                if (type(held) is not tuple or len(held) != 4
                        or held[:3] != (row['job_name'], row['job_nonce'], row['logon_id'])
                        or type(held[3]) is not str or not 1 <= len(held[3]) <= 128):
                    raise HelperControlError('helper_retained_job_binding_changed')
                rows.append(MappingProxyType(dict(row, counter_epoch=held[3])))
        return ControlBindingSnapshot(self.endpoint, self.helper_identity, self.guardian_epoch,
            runtime['policy_instance_id'], runtime['registry_revision'], self.config_revision,
            runtime['mode'], runtime['admission_barrier'], tuple(rows))

    def confirm_unchanged(self, snapshot):
        return self.read(snapshot.execution_ids) == snapshot

    def exemption_revision(self, snapshot):
        # Informational last-seen revision only; guardian re-reads all grants
        # itself under POLICY. No exemption payloads are read by this helper.
        conn = None
        deadline = time.monotonic() + .25
        try:
            path = self.db_path.with_name('exemptions.sqlite3').absolute().as_uri() + '?mode=ro'
            conn = sqlite3.connect(path, uri=True, timeout=.25)
            conn.execute('PRAGMA query_only=ON')
            conn.execute('PRAGMA trusted_schema=OFF')
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
            rows = conn.execute('''SELECT revision, substr(policy_instance_id,1,37),
                substr(policy_logon_id,1,129), coordination_required, schema_version
                FROM exemption_sync LIMIT 2''').fetchall()
            if (len(rows) != 1 or type(rows[0][0]) is not int or rows[0][0] < 0
                    or rows[0][1:] != (snapshot.policy_epoch, self.endpoint.logon_id, 1, 1)
                    or time.monotonic() >= deadline):
                raise HelperControlError('helper_exemption_revision_unavailable')
            return rows[0][0]
        except (sqlite3.Error, OSError):
            raise HelperControlError('helper_exemption_revision_unavailable') from None
        finally:
            if conn is not None:
                conn.close()


@dataclass(frozen=True)
class PendingOperation:
    kind: str
    request_id: str
    binding: ControlBindingSnapshot
    execution_id: str | None
    payload: object
    next_snapshot: ControllerSnapshot | None
    started_tick_100ns: int = 0


@dataclass(frozen=True)
class AppliedEpisode:
    execution_id: str
    target: CpuTarget
    ack: ApplyAck


@dataclass(frozen=True)
class ControlTickResult:
    reason: str
    sampled: bool = False
    operation: str | None = None
    acknowledged: bool = False
    uncertain: bool = False


class HelperControl:
    """Single-flight sender. A pending intention is never applied state."""

    def __init__(self, *, profile, sampler, binding_source, evidence_authority,
                 client_factory, clock):
        if not isinstance(sampler, FrameSampler) or not callable(clock):
            raise HelperControlError('helper_control_sources_invalid')
        if profile_revision(profile) != sampler.config_revision:
            raise HelperControlError('helper_control_profile_mismatch')
        self.profile, self.sampler = profile, sampler
        self.source, self.authority, self.clock = binding_source, evidence_authority, clock
        self._factory, self._client = client_factory, None
        self.snapshot = ControllerSnapshot.initial()
        self.pending = self.acknowledged = None
        self.uncertain_operation = None
        self._binding = None
        self._history = {}
        self._seq = 0
        self._stopping = False
        self._uncertain = False
        self._last_observation = None
        self._barrier_execution = None

    @property
    def drain_pending(self):
        return self.pending is not None or self.acknowledged is not None or self._barrier_execution is not None

    @property
    def restoration_only(self):
        """A host must not refresh restrictive eligibility while draining."""
        return self._stopping or self._barrier_execution is not None

    def evidence_unavailable(self):
        """Failed outside-lock refresh cannot reuse a prior cached receipt."""
        if self.pending is not None or self._uncertain:
            return self._result('helper_operation_requires_reconciliation')
        return self._fault('capability_evidence_unavailable')

    def _result(self, reason, *, sampled=False, operation=None, acknowledged=False):
        return ControlTickResult(reason, sampled, operation, acknowledged, self._uncertain)

    def _uncertain_result(self, reason):
        self._uncertain = True
        self._history.clear()
        return self._result(reason)

    def _ensure_client(self, binding):
        if self._client is None:
            if binding.mode not in _ACTIVE_MODES:
                raise HelperControlError('helper_control_mode_inactive')
            self._client = self._factory(binding.endpoint, binding.helper_identity)
        return self._client

    def _capability(self, binding, row, processors):
        if self.authority is None:
            raise HelperControlError('capability_evidence_unavailable')
        proof = self.authority.assert_control_eligible(profile_revision=binding.config_revision,
            logical_processors=processors, execution_row=row,
            guardian_identity=binding.endpoint.server_identity)
        if (proof is None or getattr(proof, 'config_revision', None) != binding.config_revision
                or getattr(proof, 'logical_processors', None) != processors):
            raise HelperControlError('capability_evidence_binding_mismatch')
        return proof

    def _candidates(self, binding, frame):
        candidates = []
        for row in binding.executions:
            verified = False
            try:
                self._capability(binding, row, frame.machine.logical_processors)
                verified = True
            except Exception:
                pass  # An ineligible candidate is never converted to supported.
            candidates.append(VictimCandidate(row['execution_id'], row['principal_id'],
                Role(row['role']), Priority(row['priority']), Coverage(row['coverage']), False,
                verified, tuple(self._history.get(row['execution_id'], ()))))
        return tuple(candidates)

    def _frame_ack(self, request_id, binding, frame, ack):
        if (not isinstance(ack, ControlFrameAck) or ack.request_id != request_id
                or ack.guardian_epoch != binding.guardian_epoch or ack.policy_epoch != binding.policy_epoch
                or ack.sampler_epoch != frame.sampler_epoch or ack.clock_epoch != frame.clock_epoch
                or ack.sample_seq != frame.sample_seq or ack.config_revision != binding.config_revision):
            raise HelperControlError('helper_frame_ack_mismatch')
        # A barrier clear may legitimately advance this revision. Resample;
        # never amend the old frame's authority to match the reply.
        if ack.registry_revision != binding.registry_revision:
            raise HelperControlError('helper_frame_registry_changed')
        sequence = (frame.sampler_epoch, frame.clock_epoch, frame.sample_seq)
        if self._last_observation == sequence:
            raise HelperControlError('helper_frame_replayed')
        self._last_observation = sequence
        by_id = {r.execution_id: r for r in ack.results}
        if set(by_id) - {job.execution_id for job in frame.jobs}:
            raise HelperControlError('helper_frame_ack_scope_mismatch')
        now = self.clock()
        for job in frame.jobs:
            result = by_id.get(job.execution_id)
            history = self._history.setdefault(job.execution_id, deque(maxlen=self.profile.baseline_samples))
            expected = (ControlObservation.CAPPED if self.acknowledged is not None
                        and self.acknowledged.execution_id == job.execution_id else ControlObservation.UNCAPPED)
            if (result is None or result.observation is not expected
                    or result.queried_tick_100ns is None
                    or not frame.window_end_tick_100ns <= result.queried_tick_100ns <= now):
                raise HelperControlError('helper_inventory_unverified')
            valid = (result is not None and result.observation is ControlObservation.UNCAPPED
                and result.queried_tick_100ns is not None
                and frame.window_end_tick_100ns <= result.queried_tick_100ns <= now
                and now-frame.window_end_tick_100ns <= self.profile.sample_max_age_ms*TICKS_PER_MS
                and job.membership_complete and job.cpu_units is not None
                and (self.acknowledged is None or self.acknowledged.execution_id != job.execution_id))
            if valid:
                history.append(job.cpu_units)
            elif self.acknowledged is None or self.acknowledged.execution_id != job.execution_id:
                history.clear()

    def tick(self):
        if self._stopping and (self.acknowledged is not None or self.pending is not None):
            return self.request_stop()
        if self._uncertain or self.pending is not None:
            return self._result('helper_operation_requires_reconciliation')
        if self.acknowledged is not None and self.clock() >= self.acknowledged.ack.lease_deadline_tick_100ns:
            return self._restore('helper_lease_expired')
        try:
            binding = self.source.read(self.sampler.enrolled)
        except Exception:
            return self._fault('helper_binding_unavailable')
        if self._barrier_execution is not None and binding.admission_barrier == 'NONE':
            self._barrier_execution = None
        observing_drain = self._barrier_execution is not None
        if self._stopping and not observing_drain:
            return self._result('helper_stopped')
        if self.profile.mode is Mode.OFF and self.acknowledged is None and not observing_drain:
            return self._result('helper_control_profile_off')
        if binding.mode not in _ACTIVE_MODES and not observing_drain:
            if self.acknowledged is not None:
                return self.request_stop('mode_off')
            return self._result('helper_control_mode_inactive')  # zero client construction
        if self._binding is not None and (binding.endpoint != self._binding.endpoint
                or binding.guardian_epoch != self._binding.guardian_epoch
                or binding.policy_epoch != self._binding.policy_epoch):
            return self._fault('helper_binding_epoch_changed')
        self._binding = binding
        self._history = {key: history for key, history in self._history.items()
                         if key in binding.execution_ids}
        try:
            result = self.sampler.sample(binding=binding.frame_binding())
            frame = result.frame
            if frame is None or result.reset_required or frame.validity is not Validity.VALID:
                return self._fault('helper_frame_unavailable')
            if ({job.execution_id: job.counter_epoch for job in frame.jobs} !=
                    {row['execution_id']:row.get('counter_epoch') for row in binding.executions}):
                return self._fault('helper_sample_job_binding_changed')
            if not self.source.confirm_unchanged(binding):
                return self._fault('helper_binding_changed_during_capture')
            candidates = self._candidates(binding, frame) if not observing_drain else ()
            if not observing_drain and not any(c.capability_verified for c in candidates):
                return self._fault('capability_evidence_unavailable')
            client = self._ensure_client(binding)
            request_id = str(uuid4())
            self.pending = PendingOperation('frame', request_id, binding, None, frame, None)
            ack = client.observe_uncapped(frame, request_id=request_id,
                guardian_epoch=binding.guardian_epoch, policy_epoch=binding.policy_epoch, timeout_ms=500)
            self._frame_ack(request_id, binding, frame, ack)
            self.pending = None
            if observing_drain:
                cleared = any(r.execution_id == self._barrier_execution and r.barrier_cleared
                              for r in ack.results)
                if cleared:
                    self._barrier_execution = None
                return self._result('helper_barrier_cleared' if cleared else 'helper_barrier_observing',
                                    sampled=True, operation='frame', acknowledged=True)
            if not self.source.confirm_unchanged(binding):
                return self._fault('helper_binding_changed_after_observation')
            if self.acknowledged is None and binding.admission_barrier != 'NONE':
                return self._fault('helper_admission_barrier_pending')
            decision_tick = self.clock()
            decision = next_state(profile=replace(self.profile, mode=Mode.ENFORCE),
                snapshot=self.snapshot, frame=frame, candidates=self._candidates(binding, frame),
                now_tick_100ns=decision_tick)
            if decision.action is DecisionAction.REQUEST_RESTORE:
                return self._restore(decision.reason, decision.next_snapshot)
            if decision.action in (DecisionAction.OBSERVE, DecisionAction.NO_POLICY_ACTION):
                self.snapshot = decision.next_snapshot
                return self._result(decision.reason, sampled=True)
            row = next(r for r in binding.executions if r['execution_id'] == decision.victim_execution_id)
            self._capability(binding, row, frame.machine.logical_processors)
            revision = self.source.exemption_revision(binding)
            if not self.source.confirm_unchanged(binding):
                return self._fault('helper_binding_changed_before_proposal')
            self._seq += 1
            proposal = build_control_proposal(decision, request_id=str(uuid4()),
                guardian_epoch=binding.guardian_epoch, policy_epoch=binding.policy_epoch,
                sampler_epoch=frame.sampler_epoch, clock_epoch=frame.clock_epoch,
                config_revision=binding.config_revision, registry_revision=binding.registry_revision,
                exemption_revision_seen=revision, decision_seq=self._seq, sample_seq=frame.sample_seq,
                sample_window_end_tick_100ns=frame.window_end_tick_100ns,
                decision_tick_100ns=decision_tick, active_target=(self.acknowledged.target
                    if decision.action is DecisionAction.RENEW and self.acknowledged else None))
            self.pending = PendingOperation('proposal', proposal.request_id, binding,
                proposal.execution_id, proposal, decision.next_snapshot)
            ack = client.propose(proposal, timeout_ms=500)
            return self._apply_ack(ack)
        except Exception as error:
            if self.pending is not None:
                # A revision-only frame reply has no restrictive side effect;
                # discard that observation and obtain a new authoritative frame.
                if self.pending.kind == 'frame' and getattr(error, 'reason', '') in {
                        'helper_frame_registry_changed', 'helper_inventory_unverified'}:
                    self.pending = None
                    return self._fault(error.reason)
                return self._uncertain_result('helper_control_reply_unverified')
            return self._fault('helper_control_evidence_unavailable')

    def _apply_ack(self, ack):
        operation = self.pending
        proposal = operation.payload
        if (not isinstance(ack, ApplyAck) or ack.request_id != proposal.request_id
                or ack.execution_id != proposal.execution_id or ack.decision_seq != proposal.decision_seq
                or ack.guardian_epoch != proposal.guardian_epoch or ack.policy_epoch != proposal.policy_epoch):
            return self._uncertain_result('helper_apply_ack_mismatch')
        if ack.result not in (ApplyResult.APPLIED, ApplyResult.RENEWED):
            return self._uncertain_result('helper_apply_not_verified')
        now = self.clock()
        if (ack.applied_validity is not Validity.VALID or ack.applied_flags != 5
                or ack.applied_rate_bp != proposal.target.cpu_rate_bp
                or ack.queried_tick_100ns is None or not proposal.decision_tick_100ns <= ack.queried_tick_100ns <= now
                or not now < ack.lease_deadline_tick_100ns <= ack.intervention_deadline_tick_100ns
                or operation.next_snapshot.active is None
                or ack.intervention_deadline_tick_100ns > operation.next_snapshot.active.deadline_tick_100ns
                or (self.acknowledged is not None and ack.intervention_deadline_tick_100ns !=
                    self.acknowledged.ack.intervention_deadline_tick_100ns)):
            return self._uncertain_result('helper_apply_readback_mismatch')
        if self.acknowledged is None and ack.result is not ApplyResult.APPLIED:
            return self._uncertain_result('helper_initial_ack_not_applied')
        if self.acknowledged is not None:
            previous = self.acknowledged.ack
            changed = ack.applied_rate_bp != previous.applied_rate_bp
            if ((not changed and (ack.result is not ApplyResult.RENEWED or ack.action_id != previous.action_id))
                    or (changed and (ack.result is not ApplyResult.APPLIED or ack.action_id == previous.action_id))):
                return self._uncertain_result('helper_apply_action_mismatch')
        active = replace(operation.next_snapshot.active, deadline_tick_100ns=ack.intervention_deadline_tick_100ns)
        self.snapshot = replace(operation.next_snapshot, active=active)
        self.acknowledged = AppliedEpisode(proposal.execution_id, proposal.target, ack)
        self.pending = None
        return self._result('helper_applied', sampled=True, operation='proposal', acknowledged=True)

    def _fault(self, reason):
        self._history.clear()
        if self.acknowledged is not None:
            return self._restore(reason)
        self._reset_observation()
        return self._result(reason)

    def _reset_observation(self):
        # Evidence may need warmup again; a prior verified restoration's victim
        # cooldown survives telemetry, registry and capability interruptions.
        previous = self.snapshot
        self.snapshot = ControllerSnapshot(state=ControllerState.WARMUP,
            cooldown_execution_id=previous.cooldown_execution_id,
            cooldown_until_tick_100ns=previous.cooldown_until_tick_100ns)

    def request_stop(self, reason='mode_off'):
        self._stopping = True
        if self.acknowledged is None and self.pending is None and self._barrier_execution is not None:
            return self.tick()
        return self._restore(reason)

    def reconcile(self):
        """One bounded restore attempt, never a newly disguised cap retry."""
        if self.pending is not None and self.pending.kind == 'frame' and self.acknowledged is None:
            operation = self.pending
            try:
                ack = self._client.observe_uncapped(operation.payload, request_id=operation.request_id,
                    guardian_epoch=operation.binding.guardian_epoch, policy_epoch=operation.binding.policy_epoch,
                    timeout_ms=500)
                self._frame_ack(operation.request_id, operation.binding, operation.payload, ack)
            except Exception as error:
                if getattr(error, 'reason', '') not in {'helper_frame_registry_changed', 'helper_inventory_unverified'}:
                    return self._uncertain_result('helper_observation_reconciliation_required')
            self.pending = None
            self._uncertain = False
            self._history.clear()
            self._reset_observation()
            return self._result('helper_observation_reconciled')
        return self._restore('helper_outcome_uncertain')

    def _restore(self, reason, next_snapshot=None):
        operation = self.pending
        execution_id = (self.acknowledged.execution_id if self.acknowledged else
                        operation.execution_id if operation else None)
        if execution_id is None:
            if self._uncertain:
                return self._result('helper_observation_reconciliation_required')
            return self._result('helper_no_owned_episode')
        binding = operation.binding if operation else self._binding
        if operation is None or operation.kind != 'restore':
            self.uncertain_operation = operation
            operation = PendingOperation('restore', str(uuid4()), binding, execution_id,
                                         reason, next_snapshot, self.clock())
            self.pending = operation
        try:
            # No current capability/profile/frame proof gates owned recovery.
            ack = self._client.request_restore(execution_id, request_id=operation.request_id,
                guardian_epoch=binding.guardian_epoch, policy_epoch=binding.policy_epoch,
                reason=operation.payload, timeout_ms=500)
            if (not isinstance(ack, RestoreAck) or ack.request_id != operation.request_id
                    or ack.execution_id != execution_id or ack.guardian_epoch != binding.guardian_epoch
                    or ack.policy_epoch != binding.policy_epoch or ack.result is not RestoreOutcome.RESTORED
                    or ack.native_disabled is not True or ack.bookkeeping_settled is not True
                    or ack.slot_released is not True or ack.applied_validity is not Validity.VALID
                    or ack.applied_flags is None or ack.applied_flags & 1
                    or ack.queried_tick_100ns is None
                    or not operation.started_tick_100ns <= ack.queried_tick_100ns <= self.clock()):
                return self._uncertain_result('helper_restore_unverified')
            restored = operation.next_snapshot or ControllerSnapshot(state=ControllerState.COOLDOWN)
            # A proposed restore may have waited through uncertain replies.
            # Start no earlier than the verified native restoration query, and
            # preserve that original query time when the ACK is replayed.
            self.snapshot = replace(restored, state=ControllerState.COOLDOWN, active=None,
                cooldown_execution_id=execution_id,
                cooldown_until_tick_100ns=max(restored.cooldown_until_tick_100ns,
                    ack.queried_tick_100ns+self.profile.victim_cooldown_ms*TICKS_PER_MS))
            self.pending = self.acknowledged = self.uncertain_operation = None
            self._uncertain = False
            self._history.clear()
            self._barrier_execution = None if ack.barrier_cleared is True else execution_id
            return self._result('helper_restored_barrier_pending' if ack.barrier_cleared is not True
                                else 'helper_restored', operation='restore', acknowledged=True)
        except Exception:
            return self._uncertain_result('helper_restore_unverified')
