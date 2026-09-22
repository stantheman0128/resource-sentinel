"""Portable S3 reducer/custody tests; synthetic records prove no native gate."""
from copy import deepcopy
from dataclasses import asdict, fields
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sentinel.adaptive.contracts import (
    AllocationKind, ControlProposal, CpuControl, CpuControlMode, CpuTarget, IdentityStatus,
    PendingIntent, ProcessIdentity, RecoveryManifest, ReservationRef, ResourceDemand,
)
from sentinel.adaptive.control_slot import ControlAction
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.guardian_lifecycle import job_mutex_instance
from sentinel.adaptive.policy import PolicyBinding
from tests.windows import adaptive_recovery_runner as runner


RUN = "61c69f2d-ded8-49c0-8320-912633c346bf"
EXECUTION = "95a9131d-eedc-493e-8839-a6820e2eed5e"
TICK = runner.TICKS_PER_SECOND
GUARDIAN = ProcessIdentity(101, 134342315823996135, "S-1-5-5-100-200").to_dict()
WRAPPER = ProcessIdentity(102, 134342315823996136, "S-1-5-5-100-200").to_dict()
HELPER = ProcessIdentity(103, 134342315823996137, "S-1-5-5-100-200").to_dict()
ROOT = ProcessIdentity(104, 134342315823996138, "S-1-5-5-100-200").to_dict()
SUPERVISOR = ProcessIdentity(105, 134342315823996139, "S-1-5-5-100-200").to_dict()
RECOVERY_A = ProcessIdentity(106, 134342315823996140, "S-1-5-5-100-200").to_dict()
RECOVERY_B = ProcessIdentity(107, 134342315823996141, "S-1-5-5-100-200").to_dict()
JOB_FENCE = PolicyBinding(job_mutex_instance(EXECUTION, "b" * 32), GUARDIAN["logon_id"]).name
CONTROL_CASES = {"intent_before", "intent_after_set_before", "set_after_query_before",
                 "query_after_audit_before", "lease_renewal", "guardian_hang"}
ACTION = "3102e3d0-f0d3-4e21-b6b3-84cbe2dbdd7e"


def synthetic_cutpoint(case):
    """Structurally valid records only; no native authority or observation."""
    desired = CpuControl(CpuControlMode.HARD_CAP, 2500)
    disabled = CpuControl(CpuControlMode.DISABLED, None)
    renewal = case == "lease_renewal"
    audited = case in {"query_after_audit_before", "lease_renewal"}
    pending = case in {"intent_after_set_before", "set_after_query_before", "guardian_hang"}
    decision = (2 if renewal else 1) * TICK + 1
    proposal = ControlProposal(RUN, EXECUTION, "guardian-original", "policy-original", "sampler-original",
        "clock-original", "f" * 64, 1, 1, 2 if renewal else 1, 2 if renewal else 1,
        decision, decision, CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, 1.0, 2500, 4), "retreat_level_1")
    manifest = RecoveryManifest.create(execution_id=EXECUTION,
        reservation=ReservationRef(AllocationKind.DIRECT, "original-reservation"), spec_hash="e" * 64,
        job_name=f"Local\\ResourceSentinel.Job.{EXECUTION}.{'b' * 32}", creation_nonce="b" * 32,
        wrapper_identity=ProcessIdentity.from_dict(WRAPPER), root_identity=ProcessIdentity.from_dict(ROOT),
        guardian_identity=ProcessIdentity.from_dict(GUARDIAN), guardian_epoch=proposal.guardian_epoch,
        original=disabled, last_applied=desired if audited else None,
        pending_intent=PendingIntent(ACTION, disabled, desired) if pending else None,
        allocated_floor=ResourceDemand(1.0, 1024, 2048, 0), manifest_seq=2 if audited else (1 if pending else 0))
    action = None if not audited else ControlAction(proposal.guardian_epoch, EXECUTION, proposal.decision_seq,
        ACTION, proposal.sample_seq, "RENEWED" if renewal else "APPLIED", "hard_cap", 2500, 5, 2500,
        int(2.5 * TICK), (7 if renewal else 6) * TICK, 60 * TICK, proposal.reason, None)
    return dict(actor_identity=GUARDIAN, boundary="set_after_query_before" if case == "guardian_hang" else case,
        manifest=manifest.to_dict(), proposal=proposal.to_dict(), action_id=ACTION, desired=desired.to_dict(),
        action=None if action is None else asdict(action),
        native_set_attempt_id="first" if case in {"set_after_query_before", "guardian_hang"} else None,
        previous_lease_deadline_tick_100ns=6 * TICK if renewal else None)


def change_manifest(cut, **changes):
    """Rehash intentional synthetic changes so tests also exercise bindings."""
    manifest = RecoveryManifest.from_dict(cut["manifest"])
    values = {field.name: getattr(manifest, field.name) for field in fields(manifest) if field.name != "manifest_hash"}
    cut["manifest"] = RecoveryManifest.create(**(values | changes)).to_dict()


def evidence(case="set_after_query_before"):
    spec = runner.CaseSpec(RUN, case, 1, "a" * 32, TICK)
    def record(event, seconds, **values):
        return dict(run_id=RUN, case=case, iteration=1, scope_nonce="a" * 32,
                    event=event, tick=int(seconds * TICK), point=case,
                    execution_id=EXECUTION, job_nonce="b" * 32) | values
    observations = [record("native_query", 2, execution_id=EXECUTION, job_nonce="b" * 32,
        cpu_flags=5, active_processes=2, direct_allocations=1, routed_allocations=0,
        archive_outcomes=[], slot={"slot_state": "HELD", "execution_id": EXECUTION}),
        record("native_query", 5, execution_id=EXECUTION, job_nonce="b" * 32,
        cpu_flags=0, active_processes=1, direct_allocations=1, routed_allocations=0,
        archive_outcomes=[], slot={"slot_state": "RESTORED", "execution_id": EXECUTION})]
    role, identity = ("wrapper", WRAPPER) if case == "wrapper_loss" else ("guardian", GUARDIAN)
    source = "retained_wrapper_witness" if case == "wrapper_loss" else "retained_creation_witness"
    events = [record("instrumentation_ready", 1, native_writers=["guardian", "retained_supervisor"]),
              record("fault_injected", 3, role=role, actor_identity=identity),
              record("fault_observed", 4, role=role, observed_identity=identity, source=source),
              record("cpu_write", 2, before_tick=TICK + 1, execution_id=EXECUTION,
                     job_nonce="b" * 32, desired_flags=5, desired_rate_bp=2500, attempt_id="first", role="guardian")]
    events.append(dict(events[-1], event="cpu_write_attempt", tick=TICK + 1))
    if case in CONTROL_CASES:
        events.append(record("control_cutpoint", 2.75, **synthetic_cutpoint(case)))
    if case in {"intent_before", "intent_after_set_before"}:
        events[:] = [row for row in events if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        observations[0]["cpu_flags"] = 0
    if case == "root_exit_after":
        events[1]["root_identity"] = ROOT
        events.append(record("root_exit_observed", 2.5, observed_identity=ROOT,
                             source="retained_root_witness", active_processes=1, exit_code=7))
    if case == "guardian_hang":
        events[2]["effect"] = "hung_alive"
        events.append(record("guardian_fenced", 4.5, observed_identity=GUARDIAN,
                             source="retained_creation_witness"))
    if case == "audit_unavailable":
        events[2].update(effect="audit_write_failed", source="audit_write_exception", sqlite_errorcode=5)
        events.extend([record("audit_lock_acquired", 2.5, source="sqlite_transaction"),
                       record("audit_lock_released", 5.5, source="sqlite_transaction")])
    if case in {"grant_before_cap", "grant_commit_restore_before"}:
        grant = dict(exemption_id="fixture-grant", root_identity=ROOT, revision=1,
                     created_at=100.0, expires_at=3700.0, revoked_at=None, active_count=1)
        events.extend([record("exemption_commit_observed", 2.5, **grant),
                       record("exemption_final_observed", 5.5, **grant)])
        if case == "grant_before_cap":
            events[2].update(effect="restriction_rejected", source="guardian_control_rejection")
    if case == "guardian_takeover":
        events.extend([record("takeover_owner_lost", 4.25, observed_identity=RECOVERY_A,
                              source="retained_creation_witness", fence_name=JOB_FENCE),
                       record("recovery_fence_acquired", 4.5, actor_identity=RECOVERY_B,
                              source="native_mutex_wait", abandoned=True, wait_result=128, fence_name=JOB_FENCE)])
    if case == "recovery_owner_race":
        events.extend([record("recovery_contender_ready", 2.25, actor_identity=RECOVERY_A,
                              source="retained_creation_witness"),
                       record("recovery_contender_ready", 2.5, actor_identity=RECOVERY_B,
                              source="retained_creation_witness"),
                       record("recovery_fence_acquired", 4.25, actor_identity=RECOVERY_A,
                              source="native_mutex_wait", wait_result=0, fence_name=JOB_FENCE),
                       record("recovery_fence_contended", 4.5, actor_identity=RECOVERY_B,
                              source="native_mutex_wait", wait_result=258, fence_name=JOB_FENCE)])
    if case == "independent_supervisor_recovery":
        events.extend([record("independent_recovery_ready", 2.5, actor_identity=SUPERVISOR,
                              guardian_identity=GUARDIAN, helper_identity=HELPER, wrapper_identity=WRAPPER,
                              source="retained_creation_witness"),
                       record("actor_death_observed", 4, role="helper", observed_identity=HELPER,
                              source="retained_creation_witness"),
                       record("actor_death_observed", 4, role="wrapper", observed_identity=WRAPPER,
                              source="retained_creation_witness"),
                       record("independent_recovery_alive", 4.5, observed_identity=SUPERVISOR,
                              source="retained_creation_witness")])
    cleanup = dict.fromkeys(("cpu_flags", "active_processes", "pending_intents",
                            "unsettled_handles", "live_allocations"), 0)
    return spec, observations, events, cleanup


class RecoveryReducerTests(unittest.TestCase):
    def reduce(self, data, ended=6 * TICK):
        spec, observations, events, cleanup = data
        return runner.reduce_case(spec, observations=observations, events=events,
                                  cleanup=cleanup, ended_tick=ended)

    def test_original_fault_and_disabled_live_child_are_distinct_observations(self):
        value = self.reduce(evidence())
        self.assertEqual(value["observations"]["remaining_members_before_stop"], 1)
        self.assertEqual(value["observations"]["fault_tick"], 3 * TICK)
        self.assertEqual(value["observations"]["disabled_query_tick"], 5 * TICK)
        self.assertEqual(value["cleanup"]["unsettled_handles"], 0)

    def test_missing_fault_effect_cannot_be_assumed_from_request(self):
        data = evidence()
        data[2][:] = [row for row in data[2] if row["event"] != "fault_observed"]
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "effect_unverified"):
            self.reduce(data)

    def test_generic_or_other_fault_effect_cannot_validate_requested_case(self):
        for change in ({"point": "wrapper_loss"}, {"execution_id": RUN},
                       {"job_nonce": "c" * 32}, {"role": "helper"},
                       {"observed_identity": WRAPPER}, {"source": "pid_lookup"}):
            with self.subTest(change=change):
                data = evidence()
                next(row for row in data[2] if row["event"] == "fault_observed").update(change)
                with self.assertRaises(runner.RecoveryRunUnavailable):
                    self.reduce(data)
        data = evidence()
        observed = next(row for row in data[2] if row["event"] == "fault_observed")
        for field in ("point", "execution_id", "job_nonce", "role", "observed_identity", "source"):
            observed.pop(field)
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "scope_mismatch"):
            self.reduce(data)

    def test_all_case_specific_synthetic_evidence_is_required_not_a_native_gate(self):
        for case in runner.S3_CASES:
            with self.subTest(case=case):
                data = evidence(case)
                if case in {"intent_before", "intent_after_set_before", "grant_before_cap"}:
                    data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
                    data[1][0]["cpu_flags"] = 0
                self.assertEqual(self.reduce(data)["case"], case)

    def test_six_control_faults_require_one_original_source_cutpoint(self):
        for case in CONTROL_CASES:
            for duplicate in (False, True):
                with self.subTest(case=case, duplicate=duplicate):
                    data = evidence(case)
                    cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                    if duplicate:
                        data[2].append(deepcopy(cut))
                    else:
                        data[2].remove(cut)
                    with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "control_cutpoint_unverified"):
                        self.reduce(data)

    def test_source_cutpoint_requires_complete_typed_hashed_records(self):
        for field in ("manifest", "proposal", "desired", "action_id", "actor_identity", "boundary",
                      "action", "native_set_attempt_id", "previous_lease_deadline_tick_100ns"):
            with self.subTest(field=field):
                data = evidence()
                cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                cut.pop(field)
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "fields_missing"):
                    self.reduce(data)
        data = evidence()
        cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
        cut["manifest"]["manifest_seq"] += 1
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "contract_invalid"):
            self.reduce(data)
        data = evidence()
        cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
        cut["proposal"]["sample_window_end_tick_100ns"] = "invalid"
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "contract_invalid"):
            self.reduce(data)

    def test_control_cutpoint_cannot_borrow_another_actor_epoch_or_scope(self):
        changes = ({"boundary": "intent_before"}, {"actor_identity": WRAPPER},
                   {"tick": 3 * TICK + 1}, {"execution_id": RUN}, {"job_nonce": "c" * 32})
        for change in changes:
            with self.subTest(change=change):
                data = evidence()
                next(row for row in data[2] if row["event"] == "control_cutpoint").update(change)
                with self.assertRaises(runner.RecoveryRunUnavailable):
                    self.reduce(data)
        for change in ({"guardian_identity": ProcessIdentity.from_dict(WRAPPER)},
                       {"guardian_epoch": "different-guardian"}, {"root_identity": None},
                       {"execution_id": RUN, "job_name": f"Local\\ResourceSentinel.Job.{RUN}.{'b' * 32}"}):
            with self.subTest(manifest_change=change):
                data = evidence()
                cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                change_manifest(cut, **change)
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "binding_unverified"):
                    self.reduce(data)

    def test_intent_boundaries_distinguish_preimage_from_publication_ack(self):
        disabled, cap = CpuControl(CpuControlMode.DISABLED, None), CpuControl(CpuControlMode.HARD_CAP, 2500)
        for case in ("intent_before", "intent_after_set_before", "set_after_query_before"):
            with self.subTest(case=case):
                data = evidence(case)
                cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                pending = PendingIntent(ACTION, disabled, cap) if case == "intent_before" else None
                change_manifest(cut, pending_intent=pending)
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "intent_.*unverified"):
                    self.reduce(data)
        data = evidence("intent_after_set_before")
        cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
        cut["action_id"] = RUN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "published_intent_unverified"):
            self.reduce(data)

    def test_intent_fault_cannot_hide_any_earlier_restrictive_set(self):
        for case in ("intent_before", "intent_after_set_before"):
            with self.subTest(case=case):
                data = evidence(case)
                for row in evidence()[2]:
                    if row["event"] in {"cpu_write", "cpu_write_attempt"}:
                        data[2].append(dict(row, case=case, point=case))
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "set_before_intent_fault"):
                    self.reduce(data)

    def test_set_cutpoint_requires_same_original_completed_native_attempt(self):
        for case in ("set_after_query_before", "guardian_hang"):
            for change in ({"native_set_attempt_id": "another-attempt"}, {"tick": TICK + 2},
                           {"native_set_attempt_id": None}):
                with self.subTest(case=case, change=change):
                    data = evidence(case)
                    next(row for row in data[2] if row["event"] == "control_cutpoint").update(change)
                    with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "native_set_unverified"):
                        self.reduce(data)
        data = evidence()
        for row in data[2]:
            if row["event"] in {"cpu_write", "cpu_write_attempt"}:
                row["role"] = "retained_supervisor"
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "native_set_unverified"):
            self.reduce(data)

    def test_query_and_renewal_require_original_matching_control_action(self):
        changes = ({"action_state": "RESTORED"}, {"action_state": "REJECTED"}, {"action_id": RUN},
                   {"decision_seq": 90}, {"sample_seq": 90}, {"decision_seq": True},
                   {"execution_id": RUN}, {"guardian_epoch": "other"}, {"desired_mode": "disabled"},
                   {"desired_rate_bp": 2000}, {"applied_flags": 0}, {"applied_rate_bp": 2000},
                   {"reason": "different-reason"}, {"win32_error": 5})
        for case in ("query_after_audit_before", "lease_renewal"):
            for change in changes:
                with self.subTest(case=case, change=change):
                    data = evidence(case)
                    cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                    cut["action"].update(change)
                    with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "action_unverified"):
                        self.reduce(data)
            data = evidence(case)
            cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
            change_manifest(cut, last_applied=CpuControl(CpuControlMode.DISABLED, None))
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "settled_manifest_unverified"):
                self.reduce(data)

    def test_query_action_requires_actual_set_readback_and_live_bounded_lease(self):
        for change in ({"applied_tick_100ns": TICK + 2}, {"applied_tick_100ns": 3 * TICK},
                       {"lease_deadline_tick_100ns": 2 * TICK}, {"lease_deadline_tick_100ns": 8 * TICK},
                       {"intervention_deadline_tick_100ns": 100 * TICK}):
            with self.subTest(change=change):
                data = evidence("query_after_audit_before")
                cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                cut["action"].update(change)
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "query_.*unverified"):
                    self.reduce(data)

    def test_renewal_proves_actual_extension_of_same_lease_without_another_set(self):
        for previous in (None, True, 2 * TICK, 7 * TICK, 8 * TICK):
            with self.subTest(previous=previous):
                data = evidence("lease_renewal")
                cut = next(row for row in data[2] if row["event"] == "control_cutpoint")
                cut["previous_lease_deadline_tick_100ns"] = previous
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "lease_renewal_unverified"):
                    self.reduce(data)
        data = evidence("lease_renewal")
        first = next(row for row in data[2] if row["event"] == "cpu_write")
        extra = dict(first, attempt_id="unwanted-renewal-set", before_tick=2 * TICK + 2, tick=2 * TICK + 3)
        data[2].extend((dict(extra, event="cpu_write_attempt", tick=extra["before_tick"]), extra))
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "lease_renewal_unverified"):
            self.reduce(data)

    def test_special_cases_cannot_borrow_ordinary_guardian_death(self):
        required = {
            "root_exit_after": "root_exit_observed", "guardian_hang": "guardian_fenced",
            "audit_unavailable": "audit_lock_acquired", "grant_before_cap": "exemption_final_observed",
            "grant_commit_restore_before": "exemption_commit_observed",
            "guardian_takeover": "takeover_owner_lost",
            "recovery_owner_race": "recovery_contender_ready",
            "independent_supervisor_recovery": "actor_death_observed",
        }
        for case, event in required.items():
            with self.subTest(case=case):
                data = evidence(case)
                data[2][:] = [row for row in data[2] if row["event"] != event]
                with self.assertRaises(runner.RecoveryRunUnavailable):
                    self.reduce(data)

    def test_wrapper_loss_requires_original_wrapper_death_not_guardian_death(self):
        data = evidence("wrapper_loss")
        self.assertEqual(self.reduce(data)["case"], "wrapper_loss")
        next(row for row in data[2] if row["event"] == "fault_observed").update(
            role="guardian", observed_identity=GUARDIAN, source="retained_creation_witness")
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "actor_role_mismatch"):
            self.reduce(data)

    def test_root_death_after_fault_or_no_live_child_is_not_requested_cutpoint(self):
        for change in ({"tick": 4 * TICK}, {"active_processes": 0}, {"observed_identity": GUARDIAN},
                       {"observed_identity": WRAPPER}, {"exit_code": None}):
            with self.subTest(change=change):
                data = evidence("root_exit_after")
                next(row for row in data[2] if row["event"] == "root_exit_observed").update(change)
                with self.assertRaises(runner.RecoveryRunUnavailable):
                    self.reduce(data)

    def test_audit_failure_must_still_exist_when_native_restore_is_queried(self):
        data = evidence("audit_unavailable")
        next(row for row in data[2] if row["event"] == "audit_lock_released")["tick"] = 4 * TICK
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "during_audit_failure"):
            self.reduce(data)
        data = evidence("audit_unavailable")
        next(row for row in data[2] if row["event"] == "fault_observed")["sqlite_errorcode"] = 0
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "audit_failure"):
            self.reduce(data)

    def test_takeover_requires_different_successor_and_actual_abandoned_wait(self):
        for change in ({"actor_identity": RECOVERY_A}, {"wait_result": 0}, {"abandoned": False},
                       {"fence_name": "unrelated-fixture-mutex"}):
            data = evidence("guardian_takeover")
            next(row for row in data[2] if row["event"] == "recovery_fence_acquired").update(change)
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "takeover_owner_death"):
                self.reduce(data)

    def test_race_requires_distinct_original_contenders_and_native_contention(self):
        data = evidence("recovery_owner_race")
        ready = [row for row in data[2] if row["event"] == "recovery_contender_ready"]
        ready[1]["actor_identity"] = ready[0]["actor_identity"]
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "race_not_exercised"):
            self.reduce(data)
        data = evidence("recovery_owner_race")
        next(row for row in data[2] if row["event"] == "recovery_fence_contended")["wait_result"] = 0
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "race_fence"):
            self.reduce(data)
        data = evidence("recovery_owner_race")
        next(row for row in data[2] if row["event"] == "recovery_fence_contended")["fence_name"] = "unrelated-fixture-mutex"
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "race_fence"):
            self.reduce(data)

    def test_common_loss_requires_same_preexisting_supervisor_and_all_lost_actors(self):
        data = evidence("independent_supervisor_recovery")
        next(row for row in data[2] if row["event"] == "independent_recovery_alive")["observed_identity"] = RECOVERY_A
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "original_owner"):
            self.reduce(data)
        data = evidence("independent_supervisor_recovery")
        next(row for row in data[2] if row["event"] == "actor_death_observed")["observed_identity"] = GUARDIAN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "common_failure"):
            self.reduce(data)

    def test_grant_keeps_original_scope_deadline_and_atomic_slot_count(self):
        for change in ({"root_identity": WRAPPER}, {"expires_at": 7300.0},
                       {"revoked_at": 200.0}, {"active_count": 4}, {"revision": 0}):
            with self.subTest(change=change):
                data = evidence("grant_commit_restore_before")
                next(row for row in data[2] if row["event"] == "exemption_final_observed").update(change)
                with self.assertRaises(runner.RecoveryRunUnavailable):
                    self.reduce(data)

    def test_recap_after_first_disabled_query_cannot_be_hidden_by_final_cleanup(self):
        data = evidence()
        first = next(row for row in data[2] if row["event"] == "cpu_write")
        recap = dict(first, attempt_id="recap", before_tick=5 * TICK + 1, tick=5 * TICK + 2)
        data[2].extend([dict(recap, event="cpu_write_attempt", tick=recap["before_tick"]), recap])
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "restriction_after_restore"):
            self.reduce(data)

    def test_cap_already_removed_before_fault_is_not_recovery(self):
        data = evidence()
        first = next(row for row in data[2] if row["event"] == "cpu_write")
        disabled = dict(first, desired_flags=0, desired_rate_bp=0, attempt_id="early-restore",
                        before_tick=2 * TICK + 1, tick=2 * TICK + 2)
        data[2].extend([dict(disabled, event="cpu_write_attempt", tick=disabled["before_tick"]), disabled])
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "initial_native_set_unverified"):
            self.reduce(data)

    def test_writer_instrumentation_must_precede_first_actual_attempt(self):
        data = evidence()
        next(row for row in data[2] if row["event"] == "instrumentation_ready")["tick"] = 3 * TICK
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "instrumentation_unverified"):
            self.reduce(data)

    def test_allowed_role_does_not_permit_terminating_another_original_actor(self):
        data = evidence()
        fault = next(row for row in data[2] if row["event"] == "fault_injected")
        data[2].append(dict(fault, event="process_fault_termination", actor_identity=WRAPPER,
                           original_creation_handle_verified=True))
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
            self.reduce(data)

    def test_job_empty_or_query_before_death_does_not_prove_restore(self):
        for update in ({"active_processes": 0}, {"tick": 4 * TICK}, {"cpu_flags": 5}):
            data = evidence()
            data[1][-1].update(update)
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "restore_query_missing"):
                self.reduce(data)

    def test_single_fault_eight_second_bound_includes_detection_latency(self):
        data = evidence()
        next(row for row in data[2] if row["event"] == "fault_observed")["tick"] = 11 * TICK
        data[1][-1]["tick"] = 12 * TICK
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "too_slow"):
            self.reduce(data, ended=13 * TICK)

    def test_common_failure_claims_only_eventual_recovery(self):
        data = evidence("independent_supervisor_recovery")
        data[1][-1]["tick"] = 110 * TICK
        value = self.reduce(data, ended=111 * TICK)
        self.assertEqual(value["observations"]["disabled_query_tick"], 110 * TICK)

    def test_common_failure_cannot_extend_external_observation_deadline(self):
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "observation_deadline"):
            self.reduce(evidence("independent_supervisor_recovery"), ended=122 * TICK)

    def test_child_survival_keeps_exact_original_allocation(self):
        for update in ({"direct_allocations": 0}, {"routed_allocations": 1},
                       {"archive_outcomes": ["managed_finished"]}):
            data = evidence()
            data[1][-1].update(update)
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
                self.reduce(data)

    def test_foreign_slot_and_scope_are_not_filtered_out(self):
        data = evidence()
        data[1][0]["slot"]["execution_id"] = RUN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "foreign_control_slot"):
            self.reduce(data)
        data = evidence()
        data[1][0]["job_nonce"] = "f" * 32
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "scope_binding_changed"):
            self.reduce(data)

    def test_replayed_run_event_is_rejected(self):
        data = evidence()
        data[2][-1]["run_id"] = EXECUTION
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "binding_changed"):
            self.reduce(data)

    def test_fault_on_other_job_cannot_borrow_disabled_query(self):
        data = evidence()
        next(row for row in data[2] if row["event"] == "fault_injected")["job_nonce"] = "c" * 32
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "fault_scope_mismatch"):
            self.reduce(data)

    def test_already_disabled_job_with_no_original_set_is_not_recovery(self):
        data = evidence()
        data[1][0]["cpu_flags"] = 0
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "initial_native_set_unverified"):
            self.reduce(data)

    def test_fault_before_set_does_not_require_a_cap_that_was_never_applied(self):
        data = evidence("intent_after_set_before")
        data[1][0]["cpu_flags"] = 0
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        self.assertEqual(self.reduce(data)["observations"]["disabled_flags"], 0)

    def test_grant_commit_cannot_be_followed_by_a_new_restriction(self):
        data = evidence("grant_before_cap")
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "restriction_after_exemption"):
            self.reduce(data)
        data[2][:] = [row for row in data[2] if row["event"] not in {"cpu_write", "cpu_write_attempt"}]
        data[1][0]["cpu_flags"] = 0
        self.assertEqual(self.reduce(data)["observations"]["disabled_flags"], 0)

    def test_missing_writer_instrumentation_is_unknown_not_zero(self):
        data = evidence()
        data[2].pop(0)
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "instrumentation_missing"):
            self.reduce(data)

    def test_overlapping_writers_and_foreign_writes_fail(self):
        data = evidence()
        event = dict(data[2][0], event="cpu_write", before_tick=2 * TICK,
                     tick=3 * TICK, execution_id=EXECUTION, job_nonce="b" * 32,
                     attempt_id="second", desired_flags=5, desired_rate_bp=2500, role="retained_supervisor")
        other = dict(event, before_tick=2 * TICK + 1, attempt_id="third")
        data[2].extend((dict(event, event="cpu_write_attempt", tick=event["before_tick"]), event,
                       dict(other, event="cpu_write_attempt", tick=other["before_tick"]), other))
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
            self.reduce(data)
        del data[2][-2:]
        data[2][-1]["execution_id"] = data[2][-2]["execution_id"] = RUN
        with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
            self.reduce(data)

    def test_fault_termination_of_workload_or_pid_only_target_is_not_recovery(self):
        for role, verified in (("workload", True), ("guardian", False)):
            data = evidence()
            data[2].append(dict(data[2][-1], event="process_fault_termination", role=role,
                               original_creation_handle_verified=verified))
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "safety_invariant_failed"):
                self.reduce(data)

    def test_uncertain_or_missing_set_completion_invalidates_evidence(self):
        for missing in (True, False):
            data = evidence()
            completion = next(row for row in data[2] if row["event"] == "cpu_write")
            if missing:
                data[2].remove(completion)
            else:
                completion["event"] = "cpu_write_unknown"
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "instrumentation_unverified"):
                self.reduce(data)

    def test_cleanup_missing_field_false_or_nonzero_never_passes(self):
        for invalid in (None, False, 1):
            data = evidence()
            if invalid is None:
                del data[3]["unsettled_handles"]
            else:
                data[3]["unsettled_handles"] = invalid
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "cleanup_unverified"):
                self.reduce(data)

    def test_original_case_bounds_and_boolean_timestamp(self):
        for iteration in (0, 11, True):
            with self.assertRaises(runner.RecoveryRunUnavailable):
                runner.CaseSpec(RUN, "intent_before", iteration, "a" * 32, TICK)
        with self.assertRaises(runner.RecoveryRunUnavailable):
            runner.CaseSpec(RUN, "intent_before", 1, "a" * 32, True)


class RawRecoveryLogTests(unittest.TestCase):
    def test_log_is_bounded_bound_and_new_only(self):
        spec = evidence()[0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            log = runner.RawEvents(spec, path)
            value = log.append("fault_observed", tick=4 * TICK)
            self.assertEqual(runner.read_actor_events(path, spec), [value])
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "already_exists"):
                runner.RawEvents(spec, path)
            with patch.object(runner, "MAX_EVENTS", 1):
                with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "limit"):
                    log.append("fault_observed", tick=5 * TICK)

    def test_partial_record_cannot_be_used_as_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "raw.jsonl"
            path.write_bytes(b'{"tick":5}')
            with self.assertRaisesRegex(runner.RecoveryRunUnavailable, "incomplete"):
                runner.read_actor_events(path, evidence()[0])

    def test_immutable_artifact_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            runner.write_new(path, {"status": "failed"})
            with self.assertRaises(FileExistsError):
                runner.write_new(path, {"status": "passed"})


class ActorCustodyTests(unittest.TestCase):
    def actors(self):
        actor = object.__new__(subprocess.Popen)
        actor.pid, actor.returncode = 100, None
        actor._child_created = False
        actor._handle = Mock()
        actor.poll = Mock(return_value=None)
        witness = object.__new__(VerifiedProcess)
        witness._identity = ProcessIdentity(100, 900, "S-1-5-5-1-2")
        witness.observe = Mock(return_value=SimpleNamespace(identity=witness.identity, status=IdentityStatus.ALIVE))
        witness.close = Mock()
        return actor, witness

    def test_live_actor_prevents_positive_cleanup_and_never_closes(self):
        actor, witness = self.actors()
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        self.assertFalse(custody.settle_exited())
        witness.close.assert_not_called()
        actor._handle.Close.assert_not_called()

    def test_verified_native_death_and_original_popen_exit_close_once(self):
        actor, witness = self.actors()
        actor.poll.return_value = 0
        witness.observe.return_value.status = IdentityStatus.DEAD
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        self.assertTrue(custody.settle_exited())
        self.assertTrue(custody.settle_exited())
        witness.close.assert_called_once()
        actor._handle.Close.assert_called_once()

    def test_unknown_close_quarantines_without_reclose(self):
        actor, witness = self.actors()
        actor.poll.return_value = 0
        witness.observe.return_value.status = IdentityStatus.DEAD
        witness.close.side_effect = KeyboardInterrupt()
        custody = runner.ActorCustody()
        custody.retain("supervisor", actor, witness)
        with self.assertRaises(KeyboardInterrupt):
            custody.settle_exited()
        self.assertFalse(custody.settle_exited())
        witness.close.assert_called_once()
        actor._handle.Close.assert_not_called()


if __name__ == "__main__":
    unittest.main()
