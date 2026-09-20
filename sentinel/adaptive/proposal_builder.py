"""Pure translation of one policy Decision into a typed ControlProposal.

This is the seam the plan's section 6.5 pseudo code leaves open between
``helper_tick`` and ``guardian_apply``. The decision layer in decision.py names
an action, a victim and a CPU target. A ControlProposal additionally carries the
epochs, revisions, sequence numbers and sample window that the guardian
revalidates. Those facts belong to the caller that owns the sampler, the ledger
and the registry, so every one of them is an explicit keyword here. A missing
keyword is a TypeError and a wrong one is a typed refusal. Nothing is defaulted,
inferred or carried over from a previous call.

Nothing in this module queries Windows, opens a database, reads a clock or
imports a native module. Building a proposal authorizes nothing: the guardian
rereads exemptions, mode, ownership, identity and API readback on its own, and a
proposal that passes every check here can still be rejected there.

This module is deliberately not imported by helper.py. The helper's zero Set
property is structural, and the helper stays a module that records decisions
rather than one that can construct a control message.

Two actions of decision.DecisionAction do not become a proposal:

  - OBSERVE and NO_POLICY_ACTION are not control at all, so the result is None.
  - REQUEST_RESTORE has no proposal form. guardian_control.GuardianControl
    refuses every target whose mode is not hard_cap, and it withdraws a cap
    through its own ``request_restore`` entry point instead. A proposal carrying
    a disabled target would therefore be a message that is always rejected, so
    this module refuses to build one rather than imitate a restore path.
"""

from __future__ import annotations

from .contracts import ContractViolation, ControlProposal, CpuControlMode, CpuTarget
from .decision import Decision, DecisionAction


class ProposalBuildError(ContractViolation):
    """A refusal naming the input that is missing, conflicting or unusable."""


CONTROL_ACTIONS = frozenset({DecisionAction.PROPOSE_L1, DecisionAction.PROPOSE_L2,
                             DecisionAction.RENEW, DecisionAction.REQUEST_RESTORE})


def _target(decision: Decision, active_target) -> CpuTarget:
    """The typed target this proposal carries, or a refusal.

    A renewal decision carries no target of its own, because decision.py renews
    the lease of a cap that is already applied. The applied target has to be
    supplied by the caller that holds the episode, and guessing one would risk
    proposing a different ceiling under the name of a renewal.
    """
    if decision.action is DecisionAction.RENEW:
        if decision.target is not None:
            raise ProposalBuildError("target: a renewal carries no new target")
        if not isinstance(active_target, CpuTarget):
            raise ProposalBuildError("active_target: the applied cap must be supplied")
        target = active_target
    else:
        if not isinstance(decision.target, CpuTarget):
            raise ProposalBuildError("target: the decision carries no typed target")
        if active_target is not None and active_target != decision.target:
            raise ProposalBuildError("active_target: conflicts with the decision target")
        target = decision.target
    if target.mode is not CpuControlMode.HARD_CAP:
        raise ProposalBuildError("target: only a hard cap can be proposed")
    return target


def build_control_proposal(decision: Decision, *, request_id: str, guardian_epoch: str,
                           policy_epoch: str, sampler_epoch: str, clock_epoch: str,
                           config_revision: str, registry_revision: int,
                           exemption_revision_seen: int, decision_seq: int, sample_seq: int,
                           sample_window_end_tick_100ns: int, decision_tick_100ns: int,
                           active_target: CpuTarget | None = None) -> ControlProposal | None:
    """Build the proposal for one decision, or return None when there is none.

    The victim comes from the decision itself. There is no parameter that can
    point a proposal at another execution, because retargeting a cap is a policy
    step and this module performs none.

    Only an executable decision becomes a proposal. decision.Decision marks a
    cap or a renewal executable in enforce mode alone; in shadow mode it carries
    would_apply and the caller records it instead. Refusing here keeps a shadow
    run structurally unable to emit a control message.

    The sample and clock identifiers are taken on trust from the caller. This
    module never sees the FastFrame the decision was made from, so it cannot
    prove that sampler_epoch, clock_epoch, sample_seq and the sample window
    describe that same frame. The caller owns that binding, and the guardian
    rechecks freshness against its own clock.
    """
    if not isinstance(decision, Decision):
        raise ProposalBuildError("decision: typed policy decision required")
    if decision.action not in CONTROL_ACTIONS:
        return None
    if decision.action is DecisionAction.REQUEST_RESTORE:
        raise ProposalBuildError("action: a restore is not carried by a proposal")
    if not decision.executable:
        raise ProposalBuildError("decision: only an executable decision may be proposed")
    execution_id = decision.victim_execution_id
    if execution_id is None:
        raise ProposalBuildError("victim_execution_id: a proposal needs one victim")
    return ControlProposal(request_id=request_id, execution_id=execution_id,
                           guardian_epoch=guardian_epoch, policy_epoch=policy_epoch,
                           sampler_epoch=sampler_epoch, clock_epoch=clock_epoch,
                           config_revision=config_revision, registry_revision=registry_revision,
                           exemption_revision_seen=exemption_revision_seen,
                           decision_seq=decision_seq, sample_seq=sample_seq,
                           sample_window_end_tick_100ns=sample_window_end_tick_100ns,
                           decision_tick_100ns=decision_tick_100ns,
                           target=_target(decision, active_target), reason=decision.reason)
