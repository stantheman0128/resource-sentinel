"""Pure builder tests: real decisions from decision.py, no I/O and no native code.

Every decision below comes from the production state machine driven by the
shared fixtures in test_adaptive_decision, so the builder is exercised against
the shapes the policy layer actually produces. The enforce profile is
constructed in memory; validate_policy_profile still refuses enforce from a
configuration file, and nothing here reads or writes configuration.
"""
from dataclasses import replace
import unittest
from uuid import uuid4

from sentinel.adaptive.contracts import ContractViolation, ControlProposal, CpuControlMode, CpuTarget
from sentinel.adaptive.decision import ControllerSnapshot, DecisionAction
from sentinel.adaptive.proposal_builder import ProposalBuildError, build_control_proposal
from tests import test_adaptive_decision as decisions
from tests.test_adaptive_helper import PACKAGE, imported_modules


EXECUTION = decisions.EXEC_A
GUARDIAN_EPOCH = "fixture-guardian-epoch"
POLICY_EPOCH = "0aadef58-91ae-44d4-a31f-0ec97975b146"
BASE = decisions.BASE_TICK


def bindings(**changes):
    return dict(request_id=str(uuid4()), guardian_epoch=GUARDIAN_EPOCH, policy_epoch=POLICY_EPOCH,
                sampler_epoch="sampler-a", clock_epoch="clock-a", config_revision="c" * 64,
                registry_revision=3, exemption_revision_seen=0, decision_seq=1, sample_seq=1,
                sample_window_end_tick_100ns=BASE, decision_tick_100ns=BASE) | changes


def cap_decision(profile=None):
    """Drive the real controller to one executable level 1 cap decision."""
    profile = decisions.ENFORCE if profile is None else profile
    state = decisions.settle(profile)
    for second in (5, 6):
        state = decisions.tick(profile, state, second, decisions.HIGH_BUSY).next_snapshot
    return decisions.tick(profile, state, 7, decisions.HIGH_BUSY)


def renew_decision():
    state = cap_decision().next_snapshot
    return decisions.tick(decisions.ENFORCE, state, 8, decisions.HIGH_BUSY)


class BuilderTests(unittest.TestCase):
    def test_level_one_cap_becomes_a_proposal_carrying_the_decision_target(self):
        decision = cap_decision()
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        values = bindings()
        proposal = build_control_proposal(decision, **values)
        self.assertIs(type(proposal), ControlProposal)
        self.assertEqual(proposal.execution_id, EXECUTION)
        self.assertEqual(proposal.target, decision.target)
        self.assertIs(proposal.target.mode, CpuControlMode.HARD_CAP)
        self.assertEqual(proposal.reason, decision.reason)
        for name, value in values.items():
            self.assertEqual(getattr(proposal, name), value, name)
        # Nothing the decision layer knows about a lease reaches the wire; the
        # guardian owns the lease and derives it from its own clock.
        self.assertNotIn("lease", proposal.to_dict())

    def test_level_two_cap_becomes_a_proposal_with_the_escalated_target(self):
        profile = decisions.ENFORCE
        state = cap_decision().next_snapshot
        decision = None
        for second in range(8, 20):
            decision = decisions.tick(profile, state, second, decisions.HIGH_BUSY)
            state = decision.next_snapshot
            if decision.action is DecisionAction.PROPOSE_L2:
                break
        self.assertIs(decision.action, DecisionAction.PROPOSE_L2)
        proposal = build_control_proposal(decision, **bindings(decision_seq=11, sample_seq=11))
        self.assertEqual(proposal.target, decision.target)
        self.assertEqual(proposal.decision_seq, 11)

    def test_renewal_requires_the_applied_target_and_never_invents_one(self):
        decision = renew_decision()
        self.assertIs(decision.action, DecisionAction.RENEW)
        self.assertIsNone(decision.target)
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(decision, **bindings(decision_seq=2, sample_seq=2))
        applied = cap_decision().target
        proposal = build_control_proposal(decision, **bindings(decision_seq=2, sample_seq=2),
                                          active_target=applied)
        self.assertEqual(proposal.target, applied)
        self.assertEqual(proposal.decision_seq, 2)

    def test_normal_recovery_baseline_action_is_executable_but_shadow_is_not(self):
        state = cap_decision().next_snapshot
        decision = None
        for second in range(8, 40):
            decision = decisions.tick(decisions.ENFORCE, state, second, decisions.LOW_BUSY)
            state = decision.next_snapshot
            if decision.action is DecisionAction.PROPOSE_BASELINE:
                break
        self.assertIs(decision.action, DecisionAction.PROPOSE_BASELINE)
        proposal = build_control_proposal(decision, **bindings())
        self.assertEqual(proposal.target, decision.target)
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(replace(decision, executable=False, would_apply=True), **bindings())

    def test_restore_has_no_proposal_form_and_is_refused(self):
        capped = cap_decision().next_snapshot
        decision = decisions.tick(decisions.EXAMPLE, capped, 8, decisions.HIGH_BUSY)
        self.assertIs(decision.action, DecisionAction.REQUEST_RESTORE)
        self.assertTrue(decision.executable)
        with self.assertRaises(ProposalBuildError) as caught:
            build_control_proposal(decision, **bindings(decision_seq=2, sample_seq=2))
        self.assertIn("restore", str(caught.exception))

    def test_observe_and_no_policy_action_produce_no_proposal(self):
        observing = decisions.tick(decisions.ENFORCE, decisions.settle(decisions.ENFORCE), 5,
                                   decisions.LOW_BUSY)
        self.assertIs(observing.action, DecisionAction.OBSERVE)
        idle = decisions.tick(decisions.EXAMPLE, ControllerSnapshot.initial(), 5, decisions.LOW_BUSY)
        self.assertIs(idle.action, DecisionAction.NO_POLICY_ACTION)
        for decision in (observing, idle):
            self.assertIsNone(build_control_proposal(decision, **bindings()))

    def test_shadow_cap_is_refused_because_it_is_not_executable(self):
        decision = cap_decision(decisions.SHADOW)
        self.assertIs(decision.action, DecisionAction.PROPOSE_L1)
        self.assertTrue(decision.would_apply)
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(decision, **bindings())

    def test_conflicting_or_untyped_target_is_refused(self):
        decision = cap_decision()
        other = replace(decision.target, target_cpu_units=3.0, cpu_rate_bp=2500)
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(decision, **bindings(), active_target=other)
        disabled = CpuTarget("cpu_rate", CpuControlMode.DISABLED, None, None, None)
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(replace(decision, target=disabled), **bindings())
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(replace(decision, target=None), **bindings())

    def test_missing_victim_untyped_decision_and_missing_binding_are_refused(self):
        decision = cap_decision()
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(replace(decision, victim_execution_id=None), **bindings())
        with self.assertRaises(ProposalBuildError):
            build_control_proposal(object(), **bindings())
        for missing in ("request_id", "guardian_epoch", "registry_revision", "decision_seq",
                        "sample_window_end_tick_100ns"):
            values = bindings()
            del values[missing]
            with self.subTest(missing=missing), self.assertRaises(TypeError):
                build_control_proposal(decision, **values)

    def test_invalid_binding_values_fail_the_contract_rather_than_being_coerced(self):
        decision = cap_decision()
        for change in (dict(request_id="not-a-uuid"), dict(guardian_epoch="two words"),
                       dict(config_revision="C" * 64), dict(registry_revision=-1),
                       dict(decision_seq=True), dict(sample_window_end_tick_100ns=BASE + 1)):
            with self.subTest(change=tuple(change)), self.assertRaises(ContractViolation):
                build_control_proposal(decision, **bindings(**change))

    def test_a_stale_sample_cannot_be_proposed_as_a_cap(self):
        decision = cap_decision()
        with self.assertRaises(ContractViolation):
            build_control_proposal(decision, **bindings(
                sample_window_end_tick_100ns=BASE, decision_tick_100ns=BASE + 4 * 10_000_000))


class BuilderIsolationTests(unittest.TestCase):
    """The helper must stay unable to construct or send a control message."""

    def test_helper_imports_neither_the_builder_nor_the_transport(self):
        imports = imported_modules(PACKAGE / "helper.py")
        self.assertNotIn("sentinel.adaptive.proposal_builder", imports)
        self.assertNotIn("sentinel.adaptive.control_transport", imports)

    def test_builder_imports_only_the_pure_layers(self):
        self.assertEqual(imported_modules(PACKAGE / "proposal_builder.py"),
                         {"__future__", "sentinel.adaptive.contracts", "sentinel.adaptive.decision"})


if __name__ == "__main__":
    unittest.main()
