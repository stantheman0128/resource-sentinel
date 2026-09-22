"""Guardian-side consumer of ControlProposal: the only normal CPU actuator.

This is the plan section 8.3 apply path. The helper decides and proposes; it has
no Set, and neither does the supervisor or the wrapper. Every proposal reaching
this module is re-checked here under POLICY against the authorities that own
each fact, because a proposal is a request and never an authorization.

Order is fixed and observable: durable intent, native Set, native Query, then
the acknowledgement, then one batched audit commit. A write failure of the
durable intent means no Set happens at all. A failed or unreadable Query never
produces an applied acknowledgement; it forces compare-and-restore instead.

Locks follow plan section 7.5: the existing PolicyCoordinator first, then the
lifecycle's own per-Job mutation scope, then one short SQLite transaction inside
it. No second lock is invented here.

What this module never does: it never enables a mode, never grants, extends,
revokes or ignores a user exemption, never terminates or suspends a workload,
never caps memory, never resizes a worker, and never reports the reduced CPU of
a Job it capped as released capacity. Lowered usage under our own cap is a
measurement, not headroom.

Restriction requires explicit measured capability evidence. Configured timing
and synthetic backend tests do not themselves establish native support.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields, replace
from enum import Enum
import hashlib
import math
import statistics
import time
from uuid import uuid4

from .contracts import (ApplyAck, ApplyResult, ContractViolation, ControlProposal, CpuControl,
                        CpuControlMode, FastFrame, IdentityStatus, PendingIntent,
                        ProcessIdentity, RecoveryManifest, Validity)
from .control_slot import ControlAction, UncappedSample
from .decision import PolicyProfile, lease_deadline_tick, target_rate
from .sampler import profile_revision
from .guardian_restore import _JournalScope
from .store import ControlSlotRejected, LifecycleError, LifecycleEvidence


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
TICKS_PER_MS = 10_000
_ELIGIBLE_MODES = frozenset({"canary", "limited"})


class GrantRelation(Enum):
    """How one user exemption lease relates to the scope we would restrict."""

    APPLICABLE = "applicable"
    UNRELATED = "unrelated"
    UNKNOWN = "unknown"


class _UnknownScope:
    """Default evaluator: no lease is ever proven unrelated, so nothing applies.

    Deciding that a grant does not cover a Job needs native process and job
    membership evidence this module does not have. Without a provided evaluator
    every lease stays UNKNOWN and every proposal is refused, which is the
    conservative direction.
    """

    def relation(self, control, entry, row, lease):
        return GrantRelation.UNKNOWN


class _Episode:
    """One control episode: at most one cap, one slot, one intervention bound."""

    def __init__(self, *, execution_id, slot_id, guardian_epoch, policy_epoch,
                 intervention_deadline_tick_100ns, target, decision_seq, sample_seq):
        self.execution_id, self.slot_id = execution_id, slot_id
        self.guardian_epoch, self.policy_epoch = guardian_epoch, policy_epoch
        self.intervention_deadline_tick_100ns = intervention_deadline_tick_100ns
        self.target = target
        self.decision_seq, self.sample_seq = decision_seq, sample_seq
        self.lease_deadline_tick_100ns = None
        self.applied = None
        self.restored = False
        self.acks = {}
        self.baseline_cpu_units = None
        self.level = 1
        self.last_change_tick_100ns = None
        self.helper_identity = None
        self.high_since_tick_100ns = None
        self.low_since_tick_100ns = None
        self.active_action_id = None


class GuardianControl:
    """Consume ControlProposal inside one GuardianLaunchOwner's custody.

    ``exemptions`` is the real grant authority handle; without it no proposal
    can be accepted, because an unreadable exemption authority is a refusal.
    ``scope`` evaluates whether a grant covers the scope we would restrict;
    its default proves nothing and therefore refuses. ``clock`` supplies
    interrupt ticks in 100ns units; establishing clock continuity and the
    matching clock epoch is the caller's obligation, not this module's claim.
    """

    def __init__(self, owner, *, profile, exemptions=None, scope=None, clock=None,
                 capability_authority=None, floor_publisher=None, native_capability_source=None):
        if not isinstance(profile, PolicyProfile):
            raise ContractViolation("profile: typed policy profile required")
        if clock is not None and not callable(clock):
            raise ContractViolation("clock: interrupt tick source required")
        self.owner = owner
        self.lifecycle = owner.lifecycle
        self.store = owner.store
        self.journal = owner.journal
        self.profile = profile
        self.config_revision = profile_revision(profile)
        self.capability_authority = capability_authority
        self.floor_publisher = floor_publisher
        if native_capability_source is None:
            from .host_authority import read_host_capability
            native_capability_source = read_host_capability
        self.native_capability_source = native_capability_source
        self._draining = False
        self.exemptions = exemptions
        self.scope = _UnknownScope() if scope is None else scope
        self._clock_backend = None
        self.clock = clock if clock is not None else self._interrupt_tick
        self.backend_calls = []
        self._episodes = {}
        self._samples = {}
        self._actions = {}
        self._seq_floor = {}
        self._latest_frame = None
        self._helper_identity = None
        self._frame_executions = set()
        self._frame_requests = {}
        self._restore_requests = {}
        self._proposal_payloads = {}
        self._high_streak = 0
        self._frame_failure = None
        self._latest_frame_ack = None
        self.lifecycle._terminal_control = self
        # Serve control_begin ourselves and delegate everything else to the
        # provider already installed. No production provider yields this
        # operation for an adopted execution, and neither guardian.py nor
        # guardian_lifecycle.py is modified to add one.
        self._delegate = owner.store.evidence_provider
        owner.store.evidence_provider = self._evidence_scope

    def _interrupt_tick(self):
        if self._clock_backend is None:
            from .machine_sampler import _WindowsBackend
            self._clock_backend = _WindowsBackend()
        return self._clock_backend.tick()

    # --- evidence ------------------------------------------------------------

    @contextmanager
    def _evidence_scope(self, operation, row, caller):
        if operation != "control_begin":
            with self._delegate(operation, row, caller) as evidence:
                yield evidence
            return
        entry = self.lifecycle._entry(row["execution_id"])
        with self.lifecycle._scope(entry):
            if not entry.validated:
                raise LifecycleError("guardian_custody_unverified")
            manifest = self.lifecycle._manifest(entry, row)
            if caller != manifest.wrapper_identity:
                raise LifecycleError("guardian_evidence_caller_mismatch")
            count, members = self.lifecycle._members(entry)
            control = self.lifecycle._control(entry)
            observed = entry.root.observe()
            if observed.identity != manifest.root_identity or observed.status is IdentityStatus.UNKNOWN:
                raise LifecycleError("guardian_root_unverified")
            if observed.status is IdentityStatus.ALIVE and entry.root.is_in_job(entry.job.handle) is not True:
                raise LifecycleError("guardian_root_membership_unverified")
            # The host collaborator owns legacy CPU/IO/trim writer exclusion.
            # Its assertion is the authority; no constant stands in for it.
            self.owner._authority("assert_excluded", row)
            settled = (entry.restore_candidate is None and entry.journal_cleanup_error is None and
                       manifest.pending_intent is None and manifest.last_applied in (None, DISABLED))
            yield LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex,
                caller, guardian_epoch=manifest.guardian_epoch, job_name=manifest.job_name,
                job_nonce=manifest.creation_nonce, root=manifest.root_identity,
                active_process_count=count, process_ids=members, launch_sealed=bool(row["launch_sealed"]),
                durable_manifest=True, legacy_exclusion=True, original_cpu_disabled=control == DISABLED,
                current_cpu_disabled=control == DISABLED, recovery_manifest_settled=settled,
                job_creation_never_attempted=False)

    # --- small helpers -------------------------------------------------------

    def _runtime(self):
        guard = self.store._policy.assert_held()
        with self.store._connection() as conn:
            return self.store._policy.revalidate(conn, guard)

    def _reject(self, proposal, reason):
        return ApplyAck(proposal.request_id, None, proposal.execution_id, self.owner.guardian_epoch,
                        proposal.policy_epoch, proposal.decision_seq, ApplyResult.REJECTED,
                        None, None, Validity.UNKNOWN, None, None, None, reason, None)

    def _unverified(self, proposal, reason, *, win32_error=None):
        return ApplyAck(proposal.request_id, None, proposal.execution_id, self.owner.guardian_epoch,
                        proposal.policy_epoch, proposal.decision_seq, ApplyResult.UNVERIFIED,
                        None, None, Validity.UNKNOWN, None, None, None, reason, win32_error)

    def _record(self, execution_id, action):
        self._actions.setdefault(execution_id, []).append(action)

    def _flush(self, execution_id, row):
        """One batched audit commit; a full buffer is never silently dropped."""
        actions = tuple(self._actions.get(execution_id, ()))
        if not actions:
            return 0
        written = self.store.record_control_actions_locked(execution_id,
            caller=self.lifecycle._entry(execution_id).wrapper.identity,
            expected_revision=row["state_revision"], actions=actions)
        self._actions[execution_id] = []
        return written

    def _exemptions(self, entry, row):
        """Re-read the grant authority under POLICY; unreadable means refuse."""
        from .exemption_sync import snapshot_locked
        if self.exemptions is None:
            raise LifecycleError("exemption_authority_unavailable")
        try:
            snapshot = snapshot_locked(self.exemptions, lifecycle_store=self.store, now=time.time())
        except Exception:
            raise LifecycleError("exemption_authority_unavailable") from None
        for lease in snapshot.leases:
            relation = self.scope.relation(self, entry, row, lease)
            if relation is not GrantRelation.UNRELATED:
                raise LifecycleError("execution_exempt" if relation is GrantRelation.APPLICABLE
                                     else "exemption_scope_unknown")
        return snapshot

    def _eligible(self, proposal, entry, row, runtime, guard):
        """Everything the guardian re-proves itself before any native Set."""
        if runtime["mode"] not in _ELIGIBLE_MODES:
            raise LifecycleError("control_mode_unavailable")
        if self._draining:
            raise LifecycleError("guardian_draining")
        if proposal.guardian_epoch != self.owner.guardian_epoch or runtime["guardian_epoch"] != row["guardian_epoch"]:
            raise LifecycleError("guardian_epoch_stale")
        if proposal.policy_epoch != guard.binding.instance_id:
            raise LifecycleError("policy_epoch_stale")
        if proposal.registry_revision != runtime["registry_revision"]:
            raise LifecycleError("registry_revision_stale")
        if row["role"] != "background" or row["priority"] not in {"P2", "P3"}:
            raise LifecycleError("control_execution_ineligible")
        if row["state"] not in {"RUNNING", "DRAINING"} or row["coverage"] != "job_contained":
            raise LifecycleError("control_execution_ineligible")
        if not row["launch_sealed"] or row["launch_in_flight"]:
            raise LifecycleError("control_launch_unsealed")
        if proposal.target.mode is not CpuControlMode.HARD_CAP:
            raise LifecycleError("control_target_invalid")

    def _fresh(self, proposal, now_tick_100ns):
        age = now_tick_100ns - proposal.sample_window_end_tick_100ns
        if not 0 <= age <= self.profile.sample_max_age_ms * TICKS_PER_MS:
            raise LifecycleError("sample_window_expired")
        if not proposal.sample_window_end_tick_100ns <= proposal.decision_tick_100ns <= now_tick_100ns:
            raise LifecycleError("decision_tick_invalid")

    @staticmethod
    def _digest(value):
        return hashlib.sha256(value.to_json().encode("utf-8")).hexdigest()

    def _validate_frame(self, frame, now):
        if type(frame) is not FastFrame or frame.validity is not Validity.VALID:
            raise LifecycleError("control_frame_invalid")
        if frame.config_revision != self.config_revision:
            raise LifecycleError("config_revision_stale")
        if any(error.code != "memory_attribution_unavailable" for error in frame.errors):
            raise LifecycleError("control_frame_errors")
        age = now - frame.window_end_tick_100ns
        window = frame.window_end_tick_100ns - frame.window_start_tick_100ns
        if (not 0 <= age <= self.profile.sample_max_age_ms * TICKS_PER_MS
                or frame.published_tick_100ns > now
                or not self.profile.cpu_window_min_ms * TICKS_PER_MS <= window <= self.profile.cpu_window_max_ms * TICKS_PER_MS
                or frame.collection_skew_ms > self.profile.attribution_max_skew_ms
                or frame.collection_cost_ms > self.profile.sampler_work_budget_ms):
            raise LifecycleError("control_frame_window_invalid")
        machine = frame.machine
        if (machine.logical_processors is None or machine.processor_groups != 1
                or machine.cpu_busy_units is None or not 0 <= machine.cpu_busy_units <= machine.logical_processors
                or sum(job.cpu_units or 0 for job in frame.jobs) > machine.cpu_busy_units):
            raise LifecycleError("control_frame_denominator_invalid")

    def _resource_pressure(self, frame):
        machine = frame.machine
        reserve = 4 * (1 << 30)
        if (machine.physical_available_bytes < reserve or
                machine.physical_total_bytes - machine.physical_available_bytes > 58 * (1 << 30)
                or machine.commit_limit_bytes - machine.commit_used_bytes < reserve):
            raise LifecycleError("control_memory_pressure")

    def begin_drain(self):
        with self.owner._lock:
            self._draining = True

    def _invalidate_frames(self, reason):
        self._latest_frame = self._latest_frame_ack = None
        self._frame_executions.clear()
        self._samples.clear()
        self._high_streak = 0
        self._frame_requests.clear()
        for execution, episode in tuple(self._episodes.items()):
            if not episode.restored:
                try:
                    self.request_restore(execution, reason=reason)
                except BaseException as error:
                    self._frame_failure = error
                    raise

    def observe_control_frame(self, request, *, helper_identity):
        from .control_messages import (ControlFrameRequest, ControlFrameAck, ControlFrameResult,
                                       ControlObservation)
        if type(request) is not ControlFrameRequest or type(helper_identity) is not ProcessIdentity:
            raise LifecycleError("control_frame_request_invalid")
        with self.owner._lock:
            frame = request.frame
            digest = self._digest(request)
            cached = self._frame_requests.get(request.request_id)
            if cached is not None:
                if cached[:2] != (helper_identity, digest):
                    raise LifecycleError("control_request_payload_changed")
                return cached[2]
            if self._helper_identity is not None and self._helper_identity != helper_identity:
                self._invalidate_frames("control_helper_changed")
            self._helper_identity = helper_identity
            now = self.clock()
            try:
                self._validate_frame(frame, now)
                native = self.native_capability_source()
                if (native.logical_processors != frame.machine.logical_processors or native.processor_groups != 1):
                    raise LifecycleError("control_denominator_mismatch")
                previous = self._latest_frame
                if previous is not None:
                    if (previous.sampler_epoch, previous.clock_epoch) != (frame.sampler_epoch, frame.clock_epoch):
                        self._invalidate_frames("control_clock_or_sampler_changed")
                    elif frame.sample_seq == previous.sample_seq:
                        if self._digest(frame) != self._digest(previous):
                            raise LifecycleError("control_frame_payload_changed")
                        return replace(self._latest_frame_ack, request_id=request.request_id)
                    elif (frame.sample_seq != previous.sample_seq + 1 or
                          frame.window_end_tick_100ns <= previous.window_end_tick_100ns or
                          frame.window_start_tick_100ns != previous.window_end_tick_100ns):
                        self._invalidate_frames("control_frame_continuity_lost")
                self._resource_pressure(frame)
            except Exception as error:
                self._frame_failure = error
                self._invalidate_frames("control_frame_invalid")
                return self._rejected_frame(request, "control_frame_invalid")
            # Scope-free runtime read is a consistency input; each retained
            # scope below revalidates this snapshot inside native POLICY.
            with self.store._connection() as conn:
                runtime = self.store._policy._runtime(conn)
                binding = self.store._policy._binding(runtime, helper_identity.logon_id)
            if (binding is None or request.policy_epoch != binding.instance_id or
                    request.guardian_epoch != self.owner.guardian_epoch or
                    runtime["guardian_epoch"] != self.owner.guardian_epoch or
                    runtime["registry_revision"] != frame.registry_revision):
                self._invalidate_frames("control_frame_binding_stale")
                return self._rejected_frame(request, "control_frame_binding_stale")
            represented = {job.execution_id for job in frame.jobs}
            for execution in tuple(self._samples):
                if execution not in represented:
                    self._samples[execution] = []
            for execution, episode in tuple(self._episodes.items()):
                if execution not in represented and not episode.restored:
                    self.request_restore(execution, reason="control_frame_scope_missing")
            results, accepted = [], set()
            for job in frame.jobs:
                try:
                    entry = self.lifecycle._entry(job.execution_id)
                    with self.lifecycle._scope(entry):
                        current = self._runtime()
                        if current["registry_revision"] != frame.registry_revision:
                            raise LifecycleError("registry_revision_stale")
                        row = self.store.query(job.execution_id, existing_path=True)
                        self.lifecycle._manifest(entry, row)
                        count, _ = self.lifecycle._members(entry)
                        if (not job.membership_complete or job.cpu_units is None or
                                job.active_processes != count):
                            raise LifecycleError("control_frame_membership_unverified")
                        actual = self.lifecycle._control(entry)
                        observed = self.clock()
                        if actual == DISABLED and self.floor_publisher is not None:
                            remember = getattr(self.floor_publisher, "remember_uncapped_locked", None)
                            if not callable(remember):
                                raise LifecycleError("control_floor_publisher_unavailable")
                            remember(entry, frame)
                    if actual == DISABLED:
                        self.observe_uncapped(job.execution_id, frame)
                        observation = ControlObservation.UNCAPPED
                    else:
                        episode = self._episodes.get(job.execution_id)
                        if episode is None or episode.restored or actual != episode.applied:
                            raise LifecycleError("external_control_conflict")
                        observation = ControlObservation.CAPPED
                    accepted.add(job.execution_id)
                    cleared = False
                    episode = self._episodes.get(job.execution_id)
                    if observation is ControlObservation.UNCAPPED and episode is not None and episode.restored:
                        try:
                            clear = self.clear_admission_barrier(job.execution_id, now_tick_100ns=now)
                            cleared = clear["admission_barrier"] == "NONE"
                        except LifecycleError:
                            pass
                    results.append(ControlFrameResult(job.execution_id, observation, observed, cleared, "control_frame_observed"))
                except Exception as error:
                    self._frame_failure = error
                    self._samples[job.execution_id] = []
                    episode = self._episodes.get(job.execution_id)
                    if episode is not None and not episode.restored:
                        try:
                            self.request_restore(job.execution_id, reason="control_frame_scope_unverified")
                        except BaseException as restore_error:
                            error.guardian_control_restore_error = restore_error
                            if not isinstance(restore_error, Exception):
                                raise
                    results.append(ControlFrameResult(job.execution_id, ControlObservation.UNVERIFIED,
                                                       None, False, "control_frame_scope_unverified"))
            self._latest_frame, self._frame_executions = frame, accepted
            high = frame.machine.cpu_busy_units / frame.machine.logical_processors * 100 >= self.profile.high_cpu_pct
            self._high_streak = self._high_streak + 1 if high else 0
            for episode in self._episodes.values():
                if episode.restored:
                    continue
                if high:
                    if episode.high_since_tick_100ns is None:
                        episode.high_since_tick_100ns = frame.window_start_tick_100ns
                else:
                    episode.high_since_tick_100ns = None
                low = frame.machine.cpu_busy_units / frame.machine.logical_processors * 100 < self.profile.recovery_cpu_pct
                episode.low_since_tick_100ns = ((episode.low_since_tick_100ns or frame.window_start_tick_100ns)
                                                if low else None)
            with self.store._connection() as conn:
                revision = self.store._policy._runtime(conn)["registry_revision"]
            ack = ControlFrameAck(request.request_id, self.owner.guardian_epoch, request.policy_epoch,
                frame.sampler_epoch, frame.clock_epoch, frame.sample_seq, revision, self.config_revision, tuple(results))
            self._latest_frame_ack = ack
            self._frame_requests[request.request_id] = (helper_identity, digest, ack)
            if len(self._frame_requests) > 64:
                del self._frame_requests[next(iter(self._frame_requests))]
            return ack

    def _rejected_frame(self, request, reason):
        from .control_messages import ControlFrameAck, ControlFrameResult, ControlObservation
        with self.store._connection() as conn:
            revision = self.store._policy._runtime(conn)["registry_revision"]
        frame = request.frame
        return ControlFrameAck(request.request_id, self.owner.guardian_epoch, request.policy_epoch,
            frame.sampler_epoch, frame.clock_epoch, frame.sample_seq, revision, self.config_revision,
            tuple(ControlFrameResult(job.execution_id, ControlObservation.REJECTED, None, False, reason)
                  for job in frame.jobs))

    def _frame_for(self, proposal, helper_identity, now, row):
        if type(helper_identity) is not ProcessIdentity or helper_identity != self._helper_identity:
            raise LifecycleError("control_helper_binding_invalid")
        frame = self._latest_frame
        if frame is None or proposal.execution_id not in self._frame_executions:
            raise LifecycleError("control_frame_unavailable")
        self._validate_frame(frame, now)
        self._resource_pressure(frame)
        if (proposal.config_revision != frame.config_revision or
                proposal.registry_revision != frame.registry_revision or
                proposal.sampler_epoch != frame.sampler_epoch or proposal.clock_epoch != frame.clock_epoch or
                proposal.sample_seq != frame.sample_seq or
                proposal.sample_window_end_tick_100ns != frame.window_end_tick_100ns):
            raise LifecycleError("control_frame_binding_mismatch")
        if proposal.target.denominator_logical_processors != frame.machine.logical_processors:
            raise LifecycleError("control_denominator_mismatch")
        verifier = getattr(self.capability_authority, "assert_control_eligible", None)
        if not callable(verifier):
            raise LifecycleError("control_capability_evidence_unavailable")
        receipt = verifier(profile_revision=self.config_revision,
            logical_processors=frame.machine.logical_processors, execution_row=dict(row),
            guardian_identity=self.owner.guardian.identity)
        if (getattr(receipt, "logical_processors", None) != frame.machine.logical_processors or
                getattr(receipt, "config_revision", None) != self.config_revision):
            raise LifecycleError("control_capability_binding_mismatch")
        if (not callable(getattr(self.floor_publisher, "prepare_locked", None)) or
                not callable(getattr(self.floor_publisher, "remember_uncapped_locked", None))):
            raise LifecycleError("control_floor_publisher_unavailable")
        return frame

    # --- apply ---------------------------------------------------------------

    def apply(self, proposal, *, helper_identity, now_tick_100ns=None):
        """Consume one proposal. The returned ApplyAck is the only outcome.

        A retry at the same sequence returns the original acknowledgement and
        extends nothing. A replay of that sequence under a different request is
        refused outright rather than reinterpreted.
        """
        if not isinstance(proposal, ControlProposal):
            raise ContractViolation("proposal: typed control proposal required")
        # Evidence loading/probing belongs outside POLICY and the Job mutex.
        # The verifier used under those fences is a bounded cached-receipt
        # check; an exact acknowledgement replay requires no new authority.
        assessment_error = None
        if proposal.request_id not in self._proposal_payloads:
            assessor = getattr(self.capability_authority, "assess", None)
            if not callable(assessor):
                assessment_error = LifecycleError("control_capability_evidence_unavailable")
            else:
                try:
                    assessment = assessor()
                    if getattr(assessment, "eligible", None) is not True:
                        assessment_error = LifecycleError(getattr(assessment, "reason", "control_capability_evidence_unavailable"))
                except Exception as error:
                    assessment_error = error
        now = self.clock() if now_tick_100ns is None else now_tick_100ns
        if type(now) is not int or now < 0:
            raise ContractViolation("now_tick_100ns: unsigned interrupt tick required")
        with self.owner._lock:
            digest = self._digest(proposal)
            previous = self._proposal_payloads.get(proposal.request_id)
            binding = (helper_identity, digest)
            if previous is not None and previous != binding:
                return self._reject(proposal, "control_request_payload_changed")
            episode = self._episodes.get(proposal.execution_id)
            if episode is not None and proposal.decision_seq in episode.acks:
                request_id, ack = episode.acks[proposal.decision_seq]
                if request_id != proposal.request_id:
                    return self._reject(proposal, "decision_seq_replayed")
                if helper_identity != episode.helper_identity or previous != binding:
                    return self._reject(proposal, "control_helper_binding_invalid")
                # The original acknowledgement, byte for byte. No renewal.
                return ack
            floor = self._seq_floor.get(proposal.execution_id)
            if floor is not None and proposal.decision_seq <= floor:
                return self._reject(proposal, "decision_seq_stale")
            try:
                entry = self.lifecycle._entry(proposal.execution_id)
            except LifecycleError as error:
                return self._reject(proposal, str(error))
            try:
                with self.lifecycle._scope(entry):
                    result = self._apply_locked(proposal, entry, episode, now, helper_identity, assessment_error)
                    self._proposal_payloads[proposal.request_id] = binding
                    if len(self._proposal_payloads) > 128:
                        del self._proposal_payloads[next(iter(self._proposal_payloads))]
                    return result
            except ControlSlotRejected as error:
                return self._reject(proposal, str(error))
            except LifecycleError as error:
                if getattr(error, "__notes__", ()):
                    raise
                return self._reject(proposal, str(error))

    def _apply_locked(self, proposal, entry, episode, now, helper_identity, assessment_error):
        guard = self.store._policy.assert_held()
        runtime = self._runtime()
        row = self.store.query(proposal.execution_id, existing_path=True)
        self._eligible(proposal, entry, row, runtime, guard)
        self._fresh(proposal, now)
        self._exemptions(entry, row)
        self.owner._authority("assert_excluded", row)
        slot = self.store.query_control_slot_locked()
        if slot is not None and slot["slot_state"] == "HELD" and slot["execution_id"] != proposal.execution_id:
            raise ControlSlotRejected("control_slot_occupied")
        if episode is not None and not episode.restored and episode.applied is None:
            raise LifecycleError("control_episode_unverified")
        if assessment_error is not None:
            if episode is not None and not episode.restored:
                self._restore_locked(entry, episode, "control_capability_evidence_unavailable")
            raise LifecycleError(str(assessment_error))
        frame = self._frame_for(proposal, helper_identity, now, row)
        # Bind the full payload before any durable intent/native action, so a
        # lost audit acknowledgement cannot turn its exact retry into a new
        # request. Invalid proofs above never acquire this binding.
        self._proposal_payloads[proposal.request_id] = (helper_identity, self._digest(proposal))
        if len(self._proposal_payloads) > 128:
            del self._proposal_payloads[next(iter(self._proposal_payloads))]
        if episode is not None and not episode.restored:
            return self._renew_locked(proposal, entry, episode, row, now, frame)
        return self._begin_locked(proposal, entry, row, runtime, guard, now, frame, helper_identity)

    def _restriction_tick(self, proposal, frame, row, helper_identity, *, lease, intervention):
        now = self.clock()
        self._fresh(proposal, now)
        self._frame_for(proposal, helper_identity, now, row)
        if now >= lease or now >= intervention:
            raise LifecycleError("control_lease_expired")
        return now

    def _begin_locked(self, proposal, entry, row, runtime, guard, now, frame, helper_identity):
        # The exemption authority and the legacy writer exclusion are re-read
        # here, under POLICY, and never carried over from the proposal.
        snapshot = self._exemptions(entry, row)
        self.owner._authority("assert_excluded", row)
        samples = self._samples.get(proposal.execution_id, ())[-self.profile.baseline_samples:]
        if (len(samples) < self.profile.baseline_samples or self._high_streak < self.profile.high_samples
                or any(sample.sampler_epoch != frame.sampler_epoch or sample.clock_epoch != frame.clock_epoch for sample in samples)):
            raise LifecycleError("control_warmup_incomplete")
        baseline = statistics.median(sample.cpu_units for sample in samples)
        current_job = next(job for job in frame.jobs if job.execution_id == proposal.execution_id)
        if (baseline < self.profile.victim_min_cpu_units or
                current_job.cpu_units < self.profile.victim_min_cpu_units or
                current_job.cpu_units < frame.machine.cpu_busy_units * self.profile.victim_min_machine_busy_fraction):
            raise LifecycleError("control_victim_too_small")
        expected = target_rate(baseline_cpu_units=baseline, fraction=self.profile.retreat_l1_fraction,
            logical_processors=frame.machine.logical_processors, floor_cpu_units=self.profile.cap_floor_cpu_units)
        if proposal.target != expected:
            raise LifecycleError("control_target_invalid")
        desired = CpuControl(CpuControlMode.HARD_CAP, proposal.target.cpu_rate_bp)
        intervention = proposal.decision_tick_100ns + self.profile.intervention_max_ms * TICKS_PER_MS
        # Plan 13.2. Arithmetic only; everything it depends on was proven above.
        lease = lease_deadline_tick(self.profile, now_tick_100ns=now,
            sample_window_end_tick_100ns=proposal.sample_window_end_tick_100ns,
            intervention_deadline_tick_100ns=intervention)
        slot_id = str(uuid4())
        # The slot is the at-most-one-capped-Job rule and the admission barrier
        # transition. A second victim is refused here, never worked around.
        result = self.store.begin_control_slot_locked(proposal.execution_id,
            caller=entry.wrapper.identity, expected_revision=row["state_revision"],
            slot_id=slot_id, exemption_revision=snapshot.revision)
        if result["duplicate"] or result["slot_state"] != "HELD":
            raise LifecycleError("control_slot_ack_unverified")
        episode = _Episode(execution_id=proposal.execution_id, slot_id=slot_id,
            guardian_epoch=self.owner.guardian_epoch, policy_epoch=guard.binding.instance_id,
            intervention_deadline_tick_100ns=intervention, target=desired,
            decision_seq=proposal.decision_seq, sample_seq=proposal.sample_seq)
        self._episodes[proposal.execution_id] = episode
        episode.baseline_cpu_units = baseline
        episode.last_change_tick_100ns = now
        episode.high_since_tick_100ns = now
        episode.helper_identity = helper_identity
        self._samples[proposal.execution_id] = []
        self._seq_floor[proposal.execution_id] = proposal.decision_seq
        action_id = str(uuid4())
        row = self.store.query(proposal.execution_id, existing_path=True)
        try:
            row = self.floor_publisher.prepare_locked(entry, row, frame, uncapped=True)
            record = self._publish_intent(entry, row, action_id, desired)
        except BaseException:
            # No Set was attempted, but the publication may still have landed.
            # Settle it through compare-and-restore rather than assuming it did
            # not. If that also fails the slot stays HELD, which blocks
            # admission until a later retry resolves it.
            self._release_unused(entry, episode)
            raise
        try:
            self._restriction_tick(proposal, frame, row, helper_identity, lease=lease, intervention=intervention)
            self.backend_calls.append(("set", proposal.execution_id, desired.cpu_rate_bp))
            entry.job.set_cpu_rate_unverified(desired.cpu_rate_bp)
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_set_failed", error)
            if not isinstance(error, Exception):
                raise
            return self._unverified(proposal, "control_set_failed")
        try:
            self.backend_calls.append(("query", proposal.execution_id))
            observed = self.lifecycle._control(entry)
            raw = entry.job.query_cpu()
            queried = self.clock()
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_query_unavailable", error)
            if not isinstance(error, Exception):
                raise
            return self._unverified(proposal, "control_query_unavailable")
        if observed != desired or raw.flags != 5 or raw.rate_bp != desired.cpu_rate_bp:
            # An unreadable or mismatched readback is never an applied ACK.
            self._fault(proposal, entry, episode, "control_readback_mismatch", None)
            return self._unverified(proposal, "control_readback_mismatch")
        try:
            self._settle_intent(entry, record, observed)
            self._restriction_tick(proposal, frame, row, helper_identity, lease=lease, intervention=intervention)
        except BaseException as error:
            # Without the settled manifest the cap is live while the journal
            # still shows a pending intent. It is withdrawn through the same
            # compare-and-restore the Set and Query faults use, and nothing is
            # acknowledged as applied.
            self._fault(proposal, entry, episode, "control_settle_failed", error)
            if not isinstance(error, Exception):
                raise
            return self._unverified(proposal, "control_settle_failed")
        episode.lease_deadline_tick_100ns = lease
        episode.applied = observed
        episode.active_action_id = action_id
        episode.last_change_tick_100ns = queried
        ack = ApplyAck(proposal.request_id, action_id, proposal.execution_id,
            self.owner.guardian_epoch, episode.policy_epoch, proposal.decision_seq,
            ApplyResult.APPLIED, raw.flags, raw.rate_bp, Validity.VALID, queried, lease,
            intervention, proposal.reason, None)
        episode.acks[proposal.decision_seq] = (proposal.request_id, ack)
        self._record(proposal.execution_id, ControlAction(
            self.owner.guardian_epoch, proposal.execution_id, proposal.decision_seq, action_id,
            proposal.sample_seq, "APPLIED", "hard_cap", desired.cpu_rate_bp, raw.flags, raw.rate_bp,
            queried, lease, intervention, proposal.reason, None))
        self.backend_calls.append(("audit", proposal.execution_id))
        self._flush(proposal.execution_id, self.store.query(proposal.execution_id, existing_path=True))
        return ack

    def _renew_locked(self, proposal, entry, episode, row, now, frame):
        """Extend the lease of the same execution, slot and epoch. No Set."""
        if episode.applied is None or episode.lease_deadline_tick_100ns is None:
            # A cap that was never verified and durably settled is not a cap
            # this consumer may acknowledge or extend. Such an episode is
            # restored by the next sweep, never renewed here.
            raise LifecycleError("control_episode_unverified")
        if proposal.decision_seq <= episode.decision_seq:
            raise LifecycleError("decision_seq_stale")
        if (proposal.policy_epoch != episode.policy_epoch or
                proposal.guardian_epoch != episode.guardian_epoch):
            raise LifecycleError("policy_epoch_stale")
        if proposal.sample_seq <= episode.sample_seq:
            raise LifecycleError("sample_seq_stale")
        changed = CpuControl(CpuControlMode.HARD_CAP, proposal.target.cpu_rate_bp) != episode.target
        slot = self.store.query_control_slot_locked()
        if (slot is None or slot["slot_id"] != episode.slot_id or slot["slot_state"] != "HELD" or
                slot["execution_id"] != proposal.execution_id):
            raise LifecycleError("control_slot_recovery_unverified")
        self._exemptions(entry, row)
        self.owner._authority("assert_excluded", row)
        if now >= episode.lease_deadline_tick_100ns:
            self._restore_locked(entry, episode, "lease_expired")
            raise LifecycleError("control_lease_expired")
        if now >= episode.intervention_deadline_tick_100ns:
            raise LifecycleError("intervention_deadline_reached")
        lease = lease_deadline_tick(self.profile, now_tick_100ns=now,
            sample_window_end_tick_100ns=proposal.sample_window_end_tick_100ns,
            intervention_deadline_tick_100ns=episode.intervention_deadline_tick_100ns)
        self.backend_calls.append(("query", proposal.execution_id))
        observed = self.lifecycle._control(entry)
        raw = entry.job.query_cpu()
        queried = self.clock()
        if observed != episode.target or raw.flags != 5 or raw.rate_bp != episode.target.cpu_rate_bp:
            self._fault(proposal, entry, episode, "control_readback_mismatch", None)
            return self._unverified(proposal, "control_readback_mismatch")
        if changed or proposal.reason in {"retreat_level_2", "recovery_level_1", "recovery_baseline"}:
            return self._change_target_locked(proposal, entry, episode, row, frame, now, lease)
        try:
            row = self.floor_publisher.prepare_locked(entry, row, frame, uncapped=False)
            self._restriction_tick(proposal, frame, row, episode.helper_identity,
                lease=episode.lease_deadline_tick_100ns, intervention=episode.intervention_deadline_tick_100ns)
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_floor_update_failed", error)
            raise
        action_id = episode.active_action_id
        if action_id is None:
            raise LifecycleError("control_applied_action_unverified")
        episode.lease_deadline_tick_100ns = lease
        episode.decision_seq, episode.sample_seq = proposal.decision_seq, proposal.sample_seq
        self._seq_floor[proposal.execution_id] = proposal.decision_seq
        ack = ApplyAck(proposal.request_id, action_id, proposal.execution_id,
            self.owner.guardian_epoch, episode.policy_epoch, proposal.decision_seq,
            ApplyResult.RENEWED, raw.flags, raw.rate_bp, Validity.VALID, queried, lease,
            episode.intervention_deadline_tick_100ns, proposal.reason, None)
        episode.acks[proposal.decision_seq] = (proposal.request_id, ack)
        if len(episode.acks) > 64:
            del episode.acks[min(episode.acks)]
        self._record(proposal.execution_id, ControlAction(
            self.owner.guardian_epoch, proposal.execution_id, proposal.decision_seq, action_id,
            proposal.sample_seq, "RENEWED", "hard_cap", episode.target.cpu_rate_bp, raw.flags,
            raw.rate_bp, queried, lease, episode.intervention_deadline_tick_100ns,
            proposal.reason, None))
        self.backend_calls.append(("audit", proposal.execution_id))
        self._flush(proposal.execution_id, self.store.query(proposal.execution_id, existing_path=True))
        return ack

    def _change_target_locked(self, proposal, entry, episode, row, frame, now, lease):
        if now - episode.last_change_tick_100ns < self.profile.normal_change_min_interval_ms * TICKS_PER_MS:
            raise LifecycleError("control_change_too_soon")
        baseline = episode.baseline_cpu_units
        denominator = frame.machine.logical_processors
        l1 = target_rate(baseline_cpu_units=baseline, fraction=self.profile.retreat_l1_fraction,
                        logical_processors=denominator, floor_cpu_units=self.profile.cap_floor_cpu_units)
        l2 = target_rate(baseline_cpu_units=baseline, fraction=self.profile.retreat_l2_fraction,
                        logical_processors=denominator, floor_cpu_units=self.profile.cap_floor_cpu_units)
        baseline_target = (None if baseline >= denominator else
            type(proposal.target)("cpu_rate", CpuControlMode.HARD_CAP, baseline,
                                  math.ceil(10000 * baseline / denominator), denominator))
        next_level = None
        if (episode.level == 1 and not getattr(episode, "recovering", False) and proposal.target == l2 and
                proposal.reason != "recovery_level_1" and episode.high_since_tick_100ns is not None and
                frame.window_end_tick_100ns - episode.high_since_tick_100ns >= self.profile.retreat_l2_after_ms * TICKS_PER_MS):
            next_level = 2
        elif episode.level == 2 and proposal.target == l1 and proposal.reason == "recovery_level_1":
            if (episode.low_since_tick_100ns is not None and
                    frame.window_end_tick_100ns - episode.low_since_tick_100ns >= self.profile.recovery_continuous_ms * TICKS_PER_MS):
                next_level = 1
        elif episode.level == 1 and proposal.target == baseline_target and proposal.reason == "recovery_baseline":
            # The first outward step needs low-pressure qualification. Once
            # recovery started, rising CPU cannot trap the Job in a cap.
            if (getattr(episode, "recovering", False) or episode.low_since_tick_100ns is not None and
                    frame.window_end_tick_100ns - episode.low_since_tick_100ns >= self.profile.recovery_continuous_ms * TICKS_PER_MS):
                next_level = 0
        if next_level is None:
            raise LifecycleError("control_target_transition_invalid")
        desired = CpuControl(CpuControlMode.HARD_CAP, proposal.target.cpu_rate_bp)
        native_change = desired != episode.target
        action_id = str(uuid4()) if native_change else episode.active_action_id
        if action_id is None:
            raise LifecycleError("control_applied_action_unverified")
        try:
            row = self.floor_publisher.prepare_locked(entry, row, frame, uncapped=False)
            record = (self._publish_intent(entry, row, action_id, desired, expected=episode.applied)
                      if native_change else None)
            self._restriction_tick(proposal, frame, row, episode.helper_identity,
                lease=episode.lease_deadline_tick_100ns, intervention=episode.intervention_deadline_tick_100ns)
            if native_change:
                self.backend_calls.append(("set", proposal.execution_id, desired.cpu_rate_bp))
                entry.job.set_cpu_rate_unverified(desired.cpu_rate_bp)
            observed = self.lifecycle._control(entry)
            raw = entry.job.query_cpu()
            queried = self.clock()
            if observed != desired or raw.flags != 5 or raw.rate_bp != desired.cpu_rate_bp:
                raise LifecycleError("control_readback_mismatch")
            if native_change:
                self._settle_intent(entry, record, observed)
            self._restriction_tick(proposal, frame, row, episode.helper_identity,
                lease=episode.lease_deadline_tick_100ns, intervention=episode.intervention_deadline_tick_100ns)
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_target_change_failed", error)
            if not isinstance(error, Exception):
                raise
            return self._unverified(proposal, "control_target_change_failed")
        episode.target = episode.applied = desired
        episode.active_action_id = action_id
        episode.level = next_level
        episode.recovering = proposal.reason in {"recovery_level_1", "recovery_baseline"}
        episode.last_change_tick_100ns = queried
        episode.lease_deadline_tick_100ns = lease
        episode.decision_seq, episode.sample_seq = proposal.decision_seq, proposal.sample_seq
        self._seq_floor[proposal.execution_id] = proposal.decision_seq
        outcome = ApplyResult.APPLIED if native_change else ApplyResult.RENEWED
        ack = ApplyAck(proposal.request_id, action_id, proposal.execution_id, self.owner.guardian_epoch,
            episode.policy_epoch, proposal.decision_seq, outcome, raw.flags, raw.rate_bp,
            Validity.VALID, queried, lease, episode.intervention_deadline_tick_100ns, proposal.reason, None)
        episode.acks[proposal.decision_seq] = (proposal.request_id, ack)
        if len(episode.acks) > 64:
            del episode.acks[min(episode.acks)]
        self._record(proposal.execution_id, ControlAction(self.owner.guardian_epoch, proposal.execution_id,
            proposal.decision_seq, action_id, proposal.sample_seq, outcome.value, "hard_cap", desired.cpu_rate_bp,
            raw.flags, raw.rate_bp, queried, lease, episode.intervention_deadline_tick_100ns, proposal.reason, None))
        self._flush(proposal.execution_id, self.store.query(proposal.execution_id, existing_path=True))
        return ack

    # --- durable intent ------------------------------------------------------

    def _publish_intent(self, entry, row, action_id, desired, *, expected=DISABLED):
        """Write the recovery intent before the Set, or refuse to Set at all."""
        record = self.lifecycle._manifest(entry, row)
        effective = record.last_applied or record.original
        if effective != expected or record.pending_intent is not None:
            raise LifecycleError("control_manifest_unsettled")
        values = {item.name: getattr(record, item.name) for item in fields(record)
                  if item.name != "manifest_hash"}
        values.update(manifest_seq=record.manifest_seq + 1,
                      pending_intent=PendingIntent(action_id, effective, desired))
        following = RecoveryManifest.create(**values)
        entry.restore_previous, entry.restore_candidate = record, following
        self.backend_calls.append(("intent", entry.execution_id, action_id))
        try:
            self.journal.publish(following, expected_seq=record.manifest_seq,
                expected_hash=record.manifest_hash,
                writer_scope=_JournalScope(self.lifecycle._restorer, entry, record))
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise
        # Only a positive publication ACK settles this candidate.
        entry.manifest = following
        entry.restore_previous = entry.restore_candidate = None
        return following

    def _settle_intent(self, entry, record, observed):
        values = {item.name: getattr(record, item.name) for item in fields(record)
                  if item.name != "manifest_hash"}
        values.update(manifest_seq=record.manifest_seq + 1, pending_intent=None, last_applied=observed)
        following = RecoveryManifest.create(**values)
        entry.restore_previous, entry.restore_candidate = record, following
        self.backend_calls.append(("settle", entry.execution_id))
        try:
            self.journal.publish(following, expected_seq=record.manifest_seq,
                expected_hash=record.manifest_hash,
                writer_scope=_JournalScope(self.lifecycle._restorer, entry, record))
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise
        entry.manifest = following
        entry.restore_previous = entry.restore_candidate = None
        return following

    def _release_unused(self, entry, episode):
        """Give back a slot that never carried a cap; the barrier stays honest."""
        episode.lease_deadline_tick_100ns = None
        try:
            self._restore_locked(entry, episode, "intent_write_failed")
        except BaseException as error:
            # An unresolved slot stays HELD and the barrier stays raised. That
            # is the conservative outcome; nothing here forces it open.
            self._frame_failure = error
            if not isinstance(error, Exception):
                raise

    # --- faults and restore --------------------------------------------------

    def _fault(self, proposal, entry, episode, reason, error):
        """Any fault leads to compare-and-restore through the existing path."""
        episode.lease_deadline_tick_100ns = None
        try:
            self._restore_locked(entry, episode, reason)
        except BaseException as restore_error:
            self._frame_failure = restore_error
            if error is not None:
                error.guardian_control_restore_error = restore_error
            if not isinstance(restore_error, Exception):
                raise

    def _restore_locked(self, entry, episode, reason):
        result = self.lifecycle._restorer.locked(entry,
            self.store.query(entry.execution_id, existing_path=True))
        self._samples[entry.execution_id] = []
        episode.lease_deadline_tick_100ns = None
        self._audit_restore(entry, episode, reason)
        episode.restored = True
        return result

    def _audit_restore(self, entry, episode, reason):
        raw = entry.job.query_cpu()
        tick = self.clock()
        if raw.flags & 1:
            raise LifecycleError("restore_unverified")
        if entry.terminal:
            self._reconcile_terminal_audit(entry)
        if getattr(episode, "restore_action", None) is None:
            seq = episode.decision_seq + 1
            self._seq_floor[entry.execution_id] = seq
            episode.restore_action = ControlAction(
                self.owner.guardian_epoch, entry.execution_id, seq, str(uuid4()),
                episode.sample_seq, "RESTORED", "disabled", None, raw.flags, raw.rate_bp,
                tick, None, episode.intervention_deadline_tick_100ns, reason, None)
            self._record(entry.execution_id, episode.restore_action)
        self.backend_calls.append(("audit", entry.execution_id))
        self._flush(entry.execution_id, self.store.query(entry.execution_id, existing_path=True))

    def request_restore(self, execution_id, *, reason="request_restore"):
        """REQUEST_RESTORE and every other withdrawal reach the same path."""
        with self.owner._lock:
            entry = self.lifecycle._entry(execution_id)
            episode = self._episodes.get(execution_id)
            if episode is None or episode.restored:
                return None
            with self.lifecycle._scope(entry):
                return self._restore_locked(entry, episode, reason)

    def restore_control_request(self, request, *, helper_identity):
        from .control_messages import ControlRestoreRequest, RestoreAck, RestoreOutcome
        if type(request) is not ControlRestoreRequest or type(helper_identity) is not ProcessIdentity:
            raise LifecycleError("control_restore_request_invalid")
        if (request.guardian_epoch != self.owner.guardian_epoch or
                helper_identity.logon_id != self.owner.guardian.identity.logon_id):
            raise LifecycleError("control_restore_binding_invalid")
        with self.owner._lock:
            digest = self._digest(request)
            previous = self._restore_requests.get(request.request_id)
            if previous is not None and previous != (helper_identity, digest):
                raise LifecycleError("control_request_payload_changed")
            self._restore_requests[request.request_id] = (helper_identity, digest)
            if len(self._restore_requests) > 64:
                del self._restore_requests[next(iter(self._restore_requests))]
            native = bookkeeping = released = cleared = None
            flags = rate = queried = None
            validity = Validity.UNKNOWN
            reason, outcome = "control_restore_unverified", RestoreOutcome.UNVERIFIED
            try:
                entry = self.lifecycle._entry(request.execution_id)
                episode = self._episodes.get(request.execution_id)
                with self.lifecycle._scope(entry):
                    runtime = self._runtime()
                    guard = self.store._policy.assert_held()
                    if request.policy_epoch != guard.binding.instance_id:
                        raise LifecycleError("policy_epoch_stale")
                    if episode is not None and not episode.restored:
                        result = self._restore_locked(entry, episode, request.reason)
                        bookkeeping, released = result.bookkeeping_settled, result.slot_released
                    else:
                        row = self.store.query(request.execution_id, existing_path=True)
                        record = self.lifecycle._manifest(entry, row, terminal=row["state"] == "FINISHED")
                        # Absence of an in-memory episode proves nothing about
                        # native settings or durable responsibility.
                        if record.pending_intent is not None or record.last_applied not in (None, DISABLED):
                            result = self.lifecycle._restorer.locked(entry, row)
                            bookkeeping, released = result.bookkeeping_settled, result.slot_released
                        else:
                            bookkeeping = True
                    raw = entry.job.query_cpu()
                    actual = self.lifecycle._control(entry)
                    queried = self.clock()
                    flags, rate = raw.flags, raw.rate_bp
                    validity = Validity.VALID
                    native = actual == DISABLED and not raw.flags & 1
                    slot = self.store.query_control_slot_locked()
                    released = (slot is None or slot["execution_id"] != request.execution_id or
                                slot["slot_state"] == "RESTORED")
                    fresh = self._runtime()
                    cleared = fresh["admission_barrier"] == "NONE"
                    if native and bookkeeping and released:
                        outcome, reason = RestoreOutcome.RESTORED, "control_restored"
            except Exception as error:
                self._frame_failure = error
                outcome, reason = RestoreOutcome.UNVERIFIED, "control_restore_unverified"
                bookkeeping = released = cleared = None
                # No partial state is promoted to RESTORED. The retained
                # exception keeps any failed native or journal owner reachable.
            return RestoreAck(request.request_id, self.owner.guardian_epoch, request.policy_epoch,
                request.execution_id, outcome, native, bookkeeping, released, cleared,
                flags, rate, validity, queried, reason, None)

    def tick(self, now_tick_100ns):
        """Host-callable expiry sweep; no helper message is needed to restore.

        An expired lease, a reached intervention deadline and a ledger mode that
        left canary or limited all end the episode the same way: compare and
        restore, release the slot, and leave the barrier in RECOVERY_HOLD.
        """
        if type(now_tick_100ns) is not int or now_tick_100ns < 0:
            raise ContractViolation("now_tick_100ns: unsigned interrupt tick required")
        outcomes = []
        with self.owner._lock:
            for execution_id, episode in list(self._episodes.items()):
                if episode.restored:
                    continue
                if self.lifecycle.terminal_cleanup_started(execution_id):
                    # The lifecycle published cleanup only after the exact
                    # disabled/terminal/slot proof and clean fence exit. Its
                    # observer already settled this episode before any close.
                    raise LifecycleError("guardian_terminal_control_unsettled")
                entry = self.lifecycle._entry(execution_id)
                with self.lifecycle._scope(entry):
                    reason = None
                    if (episode.lease_deadline_tick_100ns is None or
                            now_tick_100ns >= episode.lease_deadline_tick_100ns):
                        reason = "lease_expired"
                    elif now_tick_100ns >= episode.intervention_deadline_tick_100ns:
                        reason = "intervention_deadline"
                    elif self._runtime()["mode"] not in _ELIGIBLE_MODES:
                        reason = "control_mode_unavailable"
                    elif self._draining:
                        reason = "guardian_draining"
                    else:
                        try:
                            self._exemptions(entry,
                                self.store.query(execution_id, existing_path=True))
                        except LifecycleError as error:
                            # A grant that appears while we hold a cap withdraws
                            # it. We never grant, extend or revoke anything.
                            reason = str(error)
                    if reason is not None:
                        outcomes.append((execution_id, reason,
                                         self._restore_locked(entry, episode, reason)))
        return tuple(outcomes)

    # --- admission barrier ---------------------------------------------------

    def observe_uncapped(self, execution_id, frame):
        """Pair one frame with this guardian's own Query showing no cap.

        A JobFrame carries no capped flag, so uncapped is knowledge the
        controller holds, not a wire field. A usage drop is never accepted as
        proof; only an actual disabled readback taken with the frame counts.
        """
        if not isinstance(frame, FastFrame):
            raise ContractViolation("frame: typed fast frame required")
        with self.owner._lock:
            entry = self.lifecycle._entry(execution_id)
            with self.lifecycle._scope(entry):
                if self.lifecycle._control(entry) != DISABLED:
                    raise LifecycleError("uncapped_sample_capped")
                observed = self.clock()
            job = next((item for item in frame.jobs if item.execution_id == execution_id), None)
            if job is None or job.cpu_units is None or not job.membership_complete:
                raise LifecycleError("uncapped_sample_incomplete")
            sample = UncappedSample(execution_id, frame.sampler_epoch, frame.clock_epoch,
                frame.sample_seq, frame.window_start_tick_100ns, frame.window_end_tick_100ns,
                observed, job.cpu_units)
            samples = self._samples.setdefault(execution_id, [])
            if samples:
                prior = samples[-1]
                if (prior.sampler_epoch, prior.clock_epoch) != (sample.sampler_epoch, sample.clock_epoch):
                    samples.clear()
                elif sample.sample_seq == prior.sample_seq:
                    if (sample.window_start_tick_100ns, sample.window_end_tick_100ns, sample.cpu_units) != (
                            prior.window_start_tick_100ns, prior.window_end_tick_100ns, prior.cpu_units):
                        raise LifecycleError("uncapped_sample_payload_changed")
                    return prior
                elif (sample.sample_seq < prior.sample_seq or
                      sample.window_start_tick_100ns < prior.window_end_tick_100ns):
                    raise LifecycleError("uncapped_sample_replayed")
            samples.append(sample)
            del samples[:-64]
            return sample

    def clear_admission_barrier(self, execution_id, *, now_tick_100ns=None):
        """Plan 7.4. Complete evidence or the barrier stays. No TTL, no force."""
        now = self.clock() if now_tick_100ns is None else now_tick_100ns
        if type(now) is not int or now < 0:
            raise ContractViolation("now_tick_100ns: unsigned interrupt tick required")
        with self.owner._lock:
            entry = self.lifecycle._entry(execution_id)
            episode = self._episodes.get(execution_id)
            if episode is None or not episode.restored:
                raise LifecycleError("control_episode_unrestored")
            deferred = None
            with self.lifecycle._scope(entry):
                runtime = self._runtime()
                row = self.store.query(execution_id, existing_path=True)
                try:
                    result = self.store.clear_recovery_hold_locked(execution_id,
                        caller=entry.wrapper.identity, expected_revision=row["state_revision"],
                        expected_registry_revision=runtime["registry_revision"],
                        slot_id=episode.slot_id,
                        uncapped_samples=tuple(self._samples.get(execution_id, ())),
                        now_tick_100ns=now,
                        required_samples=self.profile.admission_release_uncapped_samples,
                        sample_max_age_ms=self.profile.sample_max_age_ms)
                except LifecycleError as error:
                    if (str(error) != "off_inventory_recovery_pending" or getattr(error, "__notes__", ())
                            or getattr(error.__cause__, "__notes__", ())):
                        raise
                    # The known inventory-wide owner must finish this clear.
                    # Leave POLICY cleanly so its audit and the next real frame
                    # can proceed; uncertain SQL/native cleanup still escapes.
                    deferred = error
            if deferred is not None:
                raise deferred
            return result

    def clear_finished_admission_barrier(self, execution_id, *, now=None):
        """Plan 7.4 clarification C3, for a Job this guardian already finished.

        The sibling above needs five fresh uncapped samples, which a Job with no
        process can never produce. This path accepts instead the evidence the
        lifecycle already committed: a FINISHED row and the settled journal
        manifest that commit required. The guardian host retries this path for
        its retained finished scope; a helper request alone cannot manufacture
        terminal evidence. Complete evidence or the barrier stays.
        """
        with self.owner._lock:
            return self.lifecycle.settle_finished_barrier(execution_id, now=now)

    def _terminal_prepare_locked(self, entry):
        """Audit lifecycle-initiated native restoration before proof exits."""
        self.store._policy.assert_held()
        episode = self._episodes.get(entry.execution_id)
        if episode is not None and not episode.restored:
            self._audit_restore(entry, episode, "terminal_lifecycle_restored")

    def _reconcile_terminal_audit(self, entry):
        """Resolve the original terminal audit even if a safety tick retries it."""
        self.store._policy.assert_held()
        pending = tuple(self._actions.get(entry.execution_id, ()))
        if pending:
            from .control_slot import _ACTION_FIELDS
            with self.store._connection() as conn:
                table = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_actions'").fetchone()
                if table is None:
                    found = (None,) * len(pending)
                elif table[0] != "table":
                    raise LifecycleError("control_actions_schema_unsupported")
                else:
                    found = tuple(conn.execute("SELECT " + ",".join(_ACTION_FIELDS) +
                        " FROM adaptive_actions WHERE guardian_epoch=? AND execution_id=? AND decision_seq=?",
                        (action.guardian_epoch, action.execution_id, action.decision_seq)).fetchone()
                        for action in pending)
            if any(row is not None for row in found):
                if any(row is None or tuple(row) != tuple(getattr(action, key) for key in _ACTION_FIELDS)
                       for row, action in zip(found, pending)):
                    raise LifecycleError("guardian_terminal_audit_binding_changed")
                # The exact original atomic batch committed before its ACK
                # failed. Preserve action IDs; never append another restore.
                self._actions[entry.execution_id] = []

    def _terminal_cleanup_published(self, entry):
        """Pure local notification following complete native/durable proof.

        It grants no proof itself and is never exposed by the wire protocol.
        Native readback and restoration audit have already completed inside the
        lifecycle's proof scope; no more Job queries are allowed during close.
        """
        episode = self._episodes.get(entry.execution_id)
        if episode is not None:
            episode.restored = True
            episode.lease_deadline_tick_100ns = None
        self._samples.pop(entry.execution_id, None)
        self._frame_executions.discard(entry.execution_id)
