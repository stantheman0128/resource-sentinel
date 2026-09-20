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

Nothing wires a host process to this consumer yet, and this machine cannot
produce native evidence because a foreign parent Job blocks the supported-host
check. Timing here is configured, never measured.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from enum import Enum
import time
from uuid import uuid4

from .contracts import (ApplyAck, ApplyResult, ContractViolation, ControlProposal, CpuControl,
                        CpuControlMode, FastFrame, IdentityStatus, PendingIntent,
                        RecoveryManifest, Validity)
from .control_slot import ControlAction, UncappedSample
from .decision import PolicyProfile, lease_deadline_tick
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


class GuardianControl:
    """Consume ControlProposal inside one GuardianLaunchOwner's custody.

    ``exemptions`` is the real grant authority handle; without it no proposal
    can be accepted, because an unreadable exemption authority is a refusal.
    ``scope`` evaluates whether a grant covers the scope we would restrict;
    its default proves nothing and therefore refuses. ``clock`` supplies
    interrupt ticks in 100ns units; establishing clock continuity and the
    matching clock epoch is the caller's obligation, not this module's claim.
    """

    def __init__(self, owner, *, profile, exemptions=None, scope=None, clock=None):
        if not isinstance(profile, PolicyProfile):
            raise ContractViolation("profile: typed policy profile required")
        if clock is not None and not callable(clock):
            raise ContractViolation("clock: interrupt tick source required")
        self.owner = owner
        self.lifecycle = owner.lifecycle
        self.store = owner.store
        self.journal = owner.journal
        self.profile = profile
        self.exemptions = exemptions
        self.scope = _UnknownScope() if scope is None else scope
        self.clock = clock if clock is not None else (lambda: time.perf_counter_ns() // 100)
        self.backend_calls = []
        self._episodes = {}
        self._samples = {}
        self._actions = {}
        self._seq_floor = {}
        # Serve control_begin ourselves and delegate everything else to the
        # provider already installed. No production provider yields this
        # operation for an adopted execution, and neither guardian.py nor
        # guardian_lifecycle.py is modified to add one.
        self._delegate = owner.store.evidence_provider
        owner.store.evidence_provider = self._evidence_scope

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

    # --- apply ---------------------------------------------------------------

    def apply(self, proposal, *, now_tick_100ns=None):
        """Consume one proposal. The returned ApplyAck is the only outcome.

        A retry at the same sequence returns the original acknowledgement and
        extends nothing. A replay of that sequence under a different request is
        refused outright rather than reinterpreted.
        """
        if not isinstance(proposal, ControlProposal):
            raise ContractViolation("proposal: typed control proposal required")
        now = self.clock() if now_tick_100ns is None else now_tick_100ns
        if type(now) is not int or now < 0:
            raise ContractViolation("now_tick_100ns: unsigned interrupt tick required")
        with self.owner._lock:
            episode = self._episodes.get(proposal.execution_id)
            if episode is not None and proposal.decision_seq in episode.acks:
                request_id, ack = episode.acks[proposal.decision_seq]
                if request_id != proposal.request_id:
                    return self._reject(proposal, "decision_seq_replayed")
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
                    return self._apply_locked(proposal, entry, episode, now)
            except ControlSlotRejected as error:
                return self._reject(proposal, str(error))
            except LifecycleError as error:
                if getattr(error, "__notes__", ()):
                    raise
                return self._reject(proposal, str(error))

    def _apply_locked(self, proposal, entry, episode, now):
        guard = self.store._policy.assert_held()
        runtime = self._runtime()
        row = self.store.query(proposal.execution_id, existing_path=True)
        self._eligible(proposal, entry, row, runtime, guard)
        self._fresh(proposal, now)
        if episode is not None and not episode.restored:
            return self._renew_locked(proposal, entry, episode, row, now)
        return self._begin_locked(proposal, entry, row, runtime, guard, now)

    def _begin_locked(self, proposal, entry, row, runtime, guard, now):
        # The exemption authority and the legacy writer exclusion are re-read
        # here, under POLICY, and never carried over from the proposal.
        snapshot = self._exemptions(entry, row)
        self.owner._authority("assert_excluded", row)
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
        self._seq_floor[proposal.execution_id] = proposal.decision_seq
        action_id = str(uuid4())
        row = self.store.query(proposal.execution_id, existing_path=True)
        try:
            record = self._publish_intent(entry, row, action_id, desired)
        except BaseException:
            # No Set was attempted, but the publication may still have landed.
            # Settle it through compare-and-restore rather than assuming it did
            # not. If that also fails the slot stays HELD, which blocks
            # admission until a later retry resolves it.
            self._release_unused(entry, episode)
            raise
        try:
            self.backend_calls.append(("set", proposal.execution_id, desired.cpu_rate_bp))
            entry.job.set_cpu_rate_unverified(desired.cpu_rate_bp)
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_set_failed", error)
            return self._unverified(proposal, "control_set_failed")
        try:
            self.backend_calls.append(("query", proposal.execution_id))
            observed = self.lifecycle._control(entry)
            queried = self.clock()
            raw = entry.job.query_cpu()
        except BaseException as error:
            self._fault(proposal, entry, episode, "control_query_unavailable", error)
            return self._unverified(proposal, "control_query_unavailable")
        if observed != desired or raw.flags != 5 or raw.rate_bp != desired.cpu_rate_bp:
            # An unreadable or mismatched readback is never an applied ACK.
            self._fault(proposal, entry, episode, "control_readback_mismatch", None)
            return self._unverified(proposal, "control_readback_mismatch")
        try:
            self._settle_intent(entry, record, observed)
        except BaseException as error:
            # Without the settled manifest the cap is live while the journal
            # still shows a pending intent. It is withdrawn through the same
            # compare-and-restore the Set and Query faults use, and nothing is
            # acknowledged as applied.
            self._fault(proposal, entry, episode, "control_settle_failed", error)
            return self._unverified(proposal, "control_settle_failed")
        episode.lease_deadline_tick_100ns = lease
        episode.applied = observed
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

    def _renew_locked(self, proposal, entry, episode, row, now):
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
        if CpuControl(CpuControlMode.HARD_CAP, proposal.target.cpu_rate_bp) != episode.target:
            # Escalating or relaxing an existing cap is a second action the plan
            # does not define here. Refuse rather than invent a transition.
            raise LifecycleError("control_target_change_unsupported")
        slot = self.store.query_control_slot_locked()
        if (slot is None or slot["slot_id"] != episode.slot_id or slot["slot_state"] != "HELD" or
                slot["execution_id"] != proposal.execution_id):
            raise LifecycleError("control_slot_recovery_unverified")
        self._exemptions(entry, row)
        self.owner._authority("assert_excluded", row)
        if now >= episode.intervention_deadline_tick_100ns:
            raise LifecycleError("intervention_deadline_reached")
        lease = lease_deadline_tick(self.profile, now_tick_100ns=now,
            sample_window_end_tick_100ns=proposal.sample_window_end_tick_100ns,
            intervention_deadline_tick_100ns=episode.intervention_deadline_tick_100ns)
        self.backend_calls.append(("query", proposal.execution_id))
        observed = self.lifecycle._control(entry)
        queried = self.clock()
        raw = entry.job.query_cpu()
        if observed != episode.target or raw.flags != 5:
            self._fault(proposal, entry, episode, "control_readback_mismatch", None)
            return self._unverified(proposal, "control_readback_mismatch")
        action_id = str(uuid4())
        episode.lease_deadline_tick_100ns = lease
        episode.decision_seq, episode.sample_seq = proposal.decision_seq, proposal.sample_seq
        self._seq_floor[proposal.execution_id] = proposal.decision_seq
        ack = ApplyAck(proposal.request_id, action_id, proposal.execution_id,
            self.owner.guardian_epoch, episode.policy_epoch, proposal.decision_seq,
            ApplyResult.RENEWED, raw.flags, raw.rate_bp, Validity.VALID, queried, lease,
            episode.intervention_deadline_tick_100ns, proposal.reason, None)
        episode.acks[proposal.decision_seq] = (proposal.request_id, ack)
        self._record(proposal.execution_id, ControlAction(
            self.owner.guardian_epoch, proposal.execution_id, proposal.decision_seq, action_id,
            proposal.sample_seq, "RENEWED", "hard_cap", episode.target.cpu_rate_bp, raw.flags,
            raw.rate_bp, queried, lease, episode.intervention_deadline_tick_100ns,
            proposal.reason, None))
        self.backend_calls.append(("audit", proposal.execution_id))
        self._flush(proposal.execution_id, self.store.query(proposal.execution_id, existing_path=True))
        return ack

    # --- durable intent ------------------------------------------------------

    def _publish_intent(self, entry, row, action_id, desired):
        """Write the recovery intent before the Set, or refuse to Set at all."""
        record = self.lifecycle._manifest(entry, row)
        effective = record.last_applied or record.original
        if effective != DISABLED or record.pending_intent is not None:
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
        except BaseException:
            # An unresolved slot stays HELD and the barrier stays raised. That
            # is the conservative outcome; nothing here forces it open.
            pass

    # --- faults and restore --------------------------------------------------

    def _fault(self, proposal, entry, episode, reason, error):
        """Any fault leads to compare-and-restore through the existing path."""
        episode.lease_deadline_tick_100ns = None
        try:
            self._restore_locked(entry, episode, reason)
        except BaseException as restore_error:
            if error is not None:
                error.guardian_control_restore_error = restore_error

    def _restore_locked(self, entry, episode, reason):
        result = self.lifecycle._restorer.locked(entry,
            self.store.query(entry.execution_id, existing_path=True))
        episode.restored = True
        episode.lease_deadline_tick_100ns = None
        self._audit_restore(entry, episode, reason)
        return result

    def _audit_restore(self, entry, episode, reason):
        raw = entry.job.query_cpu()
        tick = self.clock()
        if raw.flags & 1:
            raise LifecycleError("restore_unverified")
        seq = episode.decision_seq + 1
        self._seq_floor[entry.execution_id] = seq
        self._record(entry.execution_id, ControlAction(
            self.owner.guardian_epoch, entry.execution_id, seq, str(uuid4()),
            episode.sample_seq, "RESTORED", "disabled", None, raw.flags, raw.rate_bp,
            tick, None, episode.intervention_deadline_tick_100ns, reason, None))
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
            with self.lifecycle._scope(entry):
                runtime = self._runtime()
                row = self.store.query(execution_id, existing_path=True)
                return self.store.clear_recovery_hold_locked(execution_id,
                    caller=entry.wrapper.identity, expected_revision=row["state_revision"],
                    expected_registry_revision=runtime["registry_revision"],
                    slot_id=episode.slot_id,
                    uncapped_samples=tuple(self._samples.get(execution_id, ())),
                    now_tick_100ns=now,
                    required_samples=self.profile.admission_release_uncapped_samples,
                    sample_max_age_ms=self.profile.sample_max_age_ms)
