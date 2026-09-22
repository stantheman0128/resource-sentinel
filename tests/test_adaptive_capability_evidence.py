"""Synthetic verifier fixtures; NO native capability or promotion is measured.

The positive fixture deliberately simulates native producer bytes and injects
its host/build/clock sources. Accepting these bytes proves verifier arithmetic
and binding only. No OS Job, workload, control Set, shell, or production data
directory is opened. Real artifacts must be produced by the native gate suite.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel.adaptive import capability_evidence as ce
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.decision import Mode, validate_policy_profile
from sentinel.adaptive.sampler import profile_revision


ROOT = Path(__file__).resolve().parents[1]
RUN = "c0a701b1-7462-4c8d-9001-a2de45a1bc11"
EXECUTION = "c0a701b1-7462-4c8d-9001-a2de45a1bc12"
LOGON = "S-1-5-5-100-200"
T = 10_000_000
MIB = 1 << 20


def sha(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def cleanup():
    return dict(cpu_flags=0, active_processes=0, pending_intents=0,
                unsettled_handles=0, live_allocations=0)


def cpu(rate=None):
    return {"flags": 0 if rate is None else 5, "rate_bp": 0 if rate is None else rate}


def identity(pid):
    return {"pid": pid, "created_filetime_100ns": str(100000 + pid), "logon_id": LOGON}


def window(start, units, counter):
    return dict(start_ns=start * 1_000_000_000, end_ns=(start + 30) * 1_000_000_000,
                cpu_start_100ns=counter, cpu_end_100ns=counter + units * 30 * T,
                members_start=4, members_end=4)


def s1_data():
    rows = []
    for index in range(10):
        nonce = f"{index + 1:032x}"
        rows.append(dict(iteration=index, nonce=nonce, denominator=8, rate_bp=2500,
            worker_count=4, initial=cpu(), applied=cpu(2500), reopened=cpu(2500),
            restored=cpu(), uncapped_window=window(0, 4, 0),
            capped_window=window(31, 2, 120 * T), restored_window=window(62, 4, 180 * T),
            containment=dict(before_user_code_members=4, extended_limit_flags=0,
                ui_restrictions=0, reopened_nonce=nonce, allowed_logon_id=LOGON,
                protected_dacl=1, allow_ace_count=1, infra_in_work_job=0), cleanup=cleanup()))
    return dict(prerequisites=dict(self_stop_elapsed_ns=1_000_000_000,
        self_stop_exit_code=0, empty_restore=cleanup(), foreign_parent_jobs=1,
        foreign_parent_launches=0), rounds=rows)


def case_rows(recovery):
    result = []
    for case, count in (ce.S3_CASES if recovery else ce.S2_CASES).items():
        for iteration in range(1, count + 1):
            observations = dict(started_tick=1, ended_tick=100 * T,
                wrong_pid_mutations=0, workload_kills=0, premature_releases=0)
            if recovery:
                observations.update(fault_tick=T, fault_observed_tick=2 * T,
                    disabled_query_tick=3 * T, disabled_flags=0,
                    remaining_members_before_stop=1, writer_overlap_count=0,
                    slot_owner_count=1, fault_observations=1,
                    scope_nonce=f"{len(result) + 1:032x}")
            else:
                exit_code = {"exit_7": 7, "child_exit_125": 125, "infra_exit_125": 125}.get(case, 0)
                launches = 0 if case == "infra_exit_125" else 1
                observations.update(expected_exit_code=exit_code, observed_exit_code=exit_code,
                    expected_output_sha256="a" * 64, observed_output_sha256="a" * 64,
                    expected_launches=launches, observed_launches=launches,
                    membership_mismatches=0, root_exit_tick=T, last_child_exit_tick=2 * T,
                    live_child_count_after_root=1, collector_fixture_exit_tick=T,
                    guardian_alive_after_collector_tick=2 * T,
                    infra_exit_code=125 if case == "infra_exit_125" else 0)
            result.append(dict(case=case, iteration=iteration, observations=observations,
                               cleanup=cleanup()))
    return result


def p4_data(profile=None):
    if profile is None:
        profile = replace(validate_policy_profile(json.loads(
            (ROOT / "config/adaptive.example.json").read_text(encoding="utf-8"))), mode=Mode.ENFORCE)
    scales = []
    for jobs in (1, 10, 50):
        processes = [dict(identity=identity(100 + index),
            roles=(["helper"] if index == 0 else ["guardian"] if index == 1 else
                ["accounting_keeper", "daily_activation", "supervisor"] if index == 2 else ["waiting_wrapper"]),
            cpu_start_100ns=0, cpu_end_100ns=T) for index in range(jobs + 3)]
        peaks = [45 * MIB, 45 * MIB, 10 * MIB] + [20 * MIB] * jobs
        executions = [f"{jobs:08x}-1000-4000-8000-{index + 1:012x}" for index in range(jobs)]
        host = dict(identity=identity(100), parent_identity=identity(102),
            instance_id=f"{jobs:08x}-2000-4000-8000-000000000001",
            operator_instance_id=f"{jobs:08x}-2000-4000-8000-000000000002",
            scope_nonce=f"{jobs:032x}", config_revision=profile_revision(profile),
            managed_execution_ids=executions[:10], query_only_execution_ids=executions[10:],
            enroll_every_ticks=5, report_every_ticks=10, started_iteration=0, ended_iteration=600,
            ticks=[[second + 1, int(second > 0 and second % 5 == 0),
                int((second + 1) % 10 == 0), 1, 512 if (second + 1) % 10 == 0 else 0,
                (second + 1) * T, second * T + 100_000, (second + 1) * T, 0, 0]
                for second in range(600)])
        scales.append(dict(jobs=jobs, started_tick=0, ended_tick=600 * T,
            processes=processes, samples=[[second * T, second * T + 100_000,
                90 * MIB, 20 * MIB, 100 * MIB, sum(peaks), list(peaks)] for second in range(600)],
            host_loop=host,
            native_set_calls=0, sampling_cases=dict(membership_added=1, membership_removed=1,
                inaccessible_identity=1, member_scan_timeout=1, subtraction_zero_samples=1,
                unsafe_subtractions=0)))
    idle = dict(private_bytes=100 * MIB, handles=20, rows=3, log_bytes=1024)
    return dict(scales=scales, wrapper_cold_ns=[100_000_000] * 10,
        wrapper_warm_ns=[50_000_000] * 10, leak=dict(started_tick=0, ended_tick=3600 * T,
        idle_before=idle, idle_after=deepcopy(idle), observations=[
            [second * T, 100 * MIB, 20, 3, 1024] for second in (0, 1800, 3600)]))


def p5_data():
    def rows(fields, reaction=False):
        output = []
        for index in range(10):
            row = {name: (index * 10 + position + 1) * T for position, name in enumerate(fields)}
            row.update(scope_nonce=f"{index + 1:032x}", query=cpu(3750) if reaction else cpu())
            if reaction:
                row["baseline_cpu_units"] = 4
            output.append(row)
        return output
    return dict(reaction=rows(("sample_end", "decision", "apply", "query_confirmed"), True),
        helper_loss=rows(("last_valid_decision", "disabled_query")),
        guardian_loss=rows(("guardian_exit_confirmed", "disabled_query")),
        grant_restore=rows(("grant_commit", "disabled_query")),
        invariants={name: 0 for name in ce._ZERO_INVARIANTS},
        grants=dict(concurrent_attempts=8, maximum_live_leases=3, deadline_extensions=0,
                    early_root_exit_releases=0))


def p6_data():
    pairs = []
    for scenario in ce._SCENARIOS:
        for comparison in ce._COMPARISONS:
            for index in range(10):
                baseline = dict(foreground_p95_ms=40, makespan_s=100,
                                throughput_units_min=60, queue_wait_p95_ms=2)
                candidate = baseline | {"foreground_p95_ms": 30 if scenario == "CPU_CONTENTION" else 40}
                pairs.append(dict(scenario=scenario, comparison=comparison, pair_index=index,
                    order="AB" if index % 2 == 0 else "BA", fixed_conditions_sha256="c" * 64,
                    baseline=baseline, candidate=candidate, unrelated_caps=0,
                    new_admission_reserve_losses=0, api_errors=0, unrestored_caps=0))
    return dict(order_seed=0, fixed_conditions_sha256="c" * 64, pairs=pairs)


class CapabilityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sentinel-synthetic-capability-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.profile = replace(validate_policy_profile(json.loads(
            (ROOT / "config/adaptive.example.json").read_text(encoding="utf-8"))), mode=Mode.ENFORCE)
        self.build = ce.BuildIdentity("a" * 64, "b" * 64)
        self.context = ce.LiveCapabilityContext("c" * 64, 10, 0, 26100, 8, 1, "255",
            LOGON, 1, 0, "3.12.9", 64, "d" * 64, False,
            sha(("powershell51\0" + "e" * 64 + "\n").encode()))
        self.now = 1000 * T
        from sentinel.adaptive.launch_topology import LaunchTopology
        self.topology = LaunchTopology(1, "powershell51", "e" * 64, "d" * 64, "f" * 64,
            ("pipe", "pipe", "pipe"), (None, None, None), False, "", False,
            None, None, 0x80000, 0x100, "job_list_handle_list")
        launch_cases = [row | {"topology_sha256": None if row["case"] == "infra_exit_125"
            else self.topology.sha256} for row in case_rows(False)]
        self.data = {"S1": s1_data(), "S2": {"hosts": [dict(name="powershell51",
            executable_sha256="e" * 64, measured_topologies=[self.topology.to_dict()], cases=launch_cases)]},
            "S3": {"cases": case_rows(True)}, "P4": p4_data(self.profile), "P5": p5_data()}
        self.bundle = dict(schema_version=1, kind="native_capability_bundle", run_id=RUN,
            evidence_source="native", build=asdict(self.build), context=asdict(self.context),
            profile_revision=profile_revision(self.profile), artifacts=[])
        self.row = dict(execution_id=EXECUTION, role="background", priority="P2",
            coverage="job_contained", state="RUNNING", guardian_epoch="epoch-a", logon_id=LOGON,
            launch_sealed=1, launch_in_flight=0)
        self.guardian = ProcessIdentity(999, 888, LOGON)

    def write(self):
        self.bundle["artifacts"] = []
        for gate, data in self.data.items():
            payload = encoded(dict(schema_version=1, run_id=RUN, gate=gate,
                                   evidence_source="native", data=data))
            (self.path / (gate + ".json")).write_bytes(payload)
            self.bundle["artifacts"].append(dict(gate=gate, path=gate + ".json", sha256=sha(payload)))
        payload = encoded(self.bundle)
        (self.path / "bundle.json").write_bytes(payload)
        return sha(payload)

    def authority(self, **changes):
        # Explicitly fabricated provenance; this is NOT a native implementation
        # and must never be installed by a production host/producer.
        def synthetic_launch_scope(**binding):
            return ce.VerifiedLaunchScope(**binding, measured_topology_sha256="f" * 64,
                                          actual_topology_sha256="f" * 64)
        values = dict(profile=self.profile, bundle_directory=self.path,
            expected_bundle_sha256=self.write(), live_context_source=lambda: self.context,
            build_source=lambda: self.build, clock=lambda: self.now,
            launch_scope_source=synthetic_launch_scope)
        values.update(changes)
        return ce.NativeEvidenceAuthority(**values)

    def assert_eligible(self, authority):
        return authority.assert_control_eligible(profile_revision=profile_revision(self.profile),
            logical_processors=8, execution_row=self.row, guardian_identity=self.guardian)

    def failed_gate(self, gate, reason, purpose="isolated_canary"):
        result = self.authority(purpose=purpose).assess()
        self.assertFalse(result.eligible)
        self.assertIn(gate + ":" + reason, result.failed_gates)

    def test_synthetic_bytes_exercise_positive_canary_and_trial_without_native_claim(self):
        for purpose in ("isolated_canary", "p6_trial"):
            with self.subTest(purpose=purpose):
                authority = self.authority(purpose=purpose)
                result = authority.assess()
                self.assertTrue(result.eligible, result)
                self.assertEqual(self.assert_eligible(authority).purpose, purpose)
                self.assertEqual(result.scope_notes, ("50_job_stress:measured_within_budget",))

    def test_missing_evidence_and_unpinned_evidence_default_deny(self):
        missing = ce.NativeEvidenceAuthority(profile=self.profile).assess()
        self.assertFalse(missing.eligible)
        self.assertEqual(missing.reason, "capability_evidence_missing")
        self.assertEqual(self.authority(expected_bundle_sha256=None).assess().reason,
                         "capability_evidence_unpinned")

    def test_helper_proposal_view_does_not_bypass_guardian_launch_gate(self):
        authority = self.authority(launch_scope_source=None)
        self.assertTrue(authority.assess().eligible)
        self.assertEqual(self.assert_eligible(ce.HelperProposalEvidence(authority)).config_revision,
                         profile_revision(self.profile))
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "launch_scope_unverified"):
            self.assert_eligible(authority)

    def test_retained_scope_source_matches_actual_pinned_topology_without_hash_injection(self):
        from types import SimpleNamespace
        from sentinel.adaptive.launch_topology import OriginalLaunchProvenance
        from sentinel.adaptive.launch_scope import RetainedLaunchProvenance, RetainedLaunchScopeSource
        authority = self.authority(launch_scope_source=None)
        proof = OriginalLaunchProvenance(ProcessIdentity(20, 200, LOGON),
            ProcessIdentity(10, 100, LOGON), ProcessIdentity(30, 300, LOGON), self.topology)
        retained = RetainedLaunchProvenance(EXECUTION, "a" * 32, proof)
        source = RetainedLaunchScopeSource(owner=SimpleNamespace(launch_provenance_for=lambda _: retained),
            authority=authority)
        authority.launch_scope_source = source
        self.assertTrue(authority.assess().eligible)
        self.assert_eligible(authority)
        retained = replace(retained, provenance=replace(proof,
            topology=replace(self.topology, command_host_image_sha256="0" * 64)))
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "launch_scope_unverified"):
            self.assert_eligible(authority)
        self.assertIsNone(authority._scope_failure)
        retained = replace(retained, provenance=proof)
        self.assert_eligible(authority)

    def test_measured_topology_is_derived_from_validated_pinned_s2(self):
        authority = self.authority()
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "receipt_unprepared"):
            authority.prepared_launch_topologies()
        self.assertTrue(authority.assess().eligible)
        prepared = authority.prepared_launch_topologies()
        self.assertEqual(prepared.topologies, (self.topology,))
        with patch.object(authority, "_load", side_effect=AssertionError("file I/O")), \
             patch.object(authority, "context_source", side_effect=AssertionError("native probe")):
            self.assertIs(authority.prepared_launch_topologies(), prepared)
        self.now += 4 * T
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "receipt_stale"):
            authority.prepared_launch_topologies()

    def test_missing_topology_reference_does_not_certify_execution_scope(self):
        self.data["S2"]["hosts"][0]["cases"][0]["topology_sha256"] = "0" * 64
        self.failed_gate("S2", "capability_launch_topology_unmeasured")

    def test_partial_secondary_topology_does_not_borrow_full_case_matrix(self):
        host = self.data["S2"]["hosts"][0]
        secondary = replace(self.topology, stdio_types=("disk", "pipe", "pipe"))
        host["measured_topologies"].append(secondary.to_dict())
        host["cases"].append(deepcopy(host["cases"][0]) | {"topology_sha256": secondary.sha256})
        authority = self.authority()
        self.assertTrue(authority.assess().eligible)
        self.assertEqual(authority.prepared_launch_topologies().topologies, (self.topology,))
        host["cases"][0]["topology_sha256"] = secondary.sha256
        host["cases"].pop()  # split one required case away from the original profile
        self.failed_gate("S2", "capability_topology_case_matrix_incomplete")

    def test_unlaunched_infrastructure_refusal_cannot_claim_topology(self):
        row = next(row for row in self.data["S2"]["hosts"][0]["cases"] if row["case"] == "infra_exit_125")
        row["topology_sha256"] = self.topology.sha256
        self.failed_gate("S2", "capability_unlaunched_topology_claim")

    def test_unobserved_topology_and_other_python_image_refuse(self):
        host = self.data["S2"]["hosts"][0]
        host["measured_topologies"].append(replace(self.topology, command_host_image_sha256="0" * 64).to_dict())
        self.failed_gate("S2", "capability_launch_topology_unmeasured")
        host["measured_topologies"] = [replace(self.topology, python_image_sha256="0" * 64).to_dict()]
        self.failed_gate("S2", "capability_launch_topology_mismatch")

    def test_assert_never_refreshes_and_requires_prepared_receipt(self):
        authority = self.authority()
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "receipt_unprepared"):
            self.assert_eligible(authority)
        self.assertTrue(authority.assess().eligible)
        with patch.object(authority, "assess", side_effect=AssertionError("I/O under lock")), \
             patch.object(authority, "context_source", side_effect=AssertionError("probe under lock")), \
             patch.object(authority, "build_source", side_effect=AssertionError("scan under lock")):
            self.assert_eligible(authority)

    def test_expired_and_backward_clock_receipts_deny(self):
        for adjustment in (31 * T // 10, -1):
            authority = self.authority()
            self.assertTrue(authority.assess().eligible)
            self.now += adjustment
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "receipt_stale"):
                self.assert_eligible(authority)

    def test_failed_refresh_invalidates_prior_receipt(self):
        authority = self.authority()
        self.assertTrue(authority.refresh().eligible)
        self.build = ce.BuildIdentity("f" * 64, "b" * 64)
        self.assertEqual(authority.refresh().reason, "capability_build_mismatch")
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "receipt_unprepared"):
            self.assert_eligible(authority)

    def test_immutable_gate_arithmetic_is_cached_but_host_still_refreshed(self):
        authority = self.authority()
        self.assertTrue(authority.assess().eligible)
        with patch.object(ce, "_s1", side_effect=AssertionError("repeat gate")):
            self.assertTrue(authority.assess().eligible)
        self.context = replace(self.context, os_build=26101)
        self.assertEqual(authority.assess().reason, "capability_host_context_mismatch")

    def test_source_host_and_profile_must_match(self):
        for target, name, value in (("build", "producer_sha256", "f" * 64),
                ("context", "python_sha256", "f" * 64), ("context", "logon_id", "S-1-5-5-100-201"),
                ("context", "session_protocol", 2)):
            with self.subTest(target=target, name=name):
                old = self.bundle[target][name]
                self.bundle[target][name] = value
                self.assertFalse(self.authority().assess().eligible)
                self.bundle[target][name] = old
        self.bundle["profile_revision"] = "f" * 64
        self.assertEqual(self.authority().assess().reason, "capability_profile_mismatch")

    def test_synthetic_marker_cannot_be_loaded_as_native(self):
        self.bundle["evidence_source"] = "synthetic"
        self.assertEqual(self.authority().assess().reason, "capability_evidence_not_native")

    def test_changed_pinned_bytes_deny(self):
        authority = self.authority()
        self.assertTrue(authority.assess().eligible)
        with (self.path / "S1.json").open("ab") as stream:
            stream.write(b" ")
        self.assertEqual(authority.assess().reason, "capability_evidence_changed")

    def test_context_numeric_boolean_is_not_equal_to_a_valid_native_integer(self):
        self.bundle["context"]["processor_groups"] = True
        self.assertEqual(self.authority().assess().reason, "capability_context_unsupported")

    def test_manifest_pin_and_artifact_hash_are_checked(self):
        self.assertEqual(self.authority(expected_bundle_sha256="f" * 64).assess().reason,
                         "capability_bundle_hash_mismatch")
        authority = self.authority()
        (self.path / "S1.json").write_bytes(b"{}")
        self.assertEqual(authority.assess().reason, "capability_artifact_hash_mismatch")

    def test_duplicate_json_and_path_traversal_deny(self):
        authority = self.authority()
        self.bundle["artifacts"][0]["path"] = "../S1.json"
        payload = encoded(self.bundle)
        (self.path / "bundle.json").write_bytes(payload)
        authority.expected_bundle_sha256 = sha(payload)
        self.assertEqual(authority.assess().reason, "capability_artifact_reference_invalid")
        payload = b'{"schema_version":1,"schema_version":1}'
        (self.path / "bundle.json").write_bytes(payload)
        authority.expected_bundle_sha256 = sha(payload)
        self.assertFalse(authority.assess().eligible)

    def test_missing_required_gate_visible(self):
        del self.data["S3"]
        result = self.authority().assess()
        self.assertEqual(result.missing_gates, ("S3",))

    def test_s1_rejects_missing_round_duplicate_nonce_and_impossible_consumption(self):
        original = deepcopy(self.data["S1"])
        for mutation, reason in (
            (lambda: self.data["S1"]["rounds"].pop(), "capability_measurement_missing"),
            (lambda: self.data["S1"]["rounds"][1].update(nonce=self.data["S1"]["rounds"][0]["nonce"]), "capability_case_identity_invalid"),
            (lambda: self.data["S1"]["rounds"][0]["uncapped_window"].update(cpu_end_100ns=1000 * T), "capability_cpu_window_invalid"),
            (lambda: self.data["S1"]["rounds"][0]["containment"].update(extended_limit_flags=0x2000), "capability_safety_invariant_failed")):
            self.data["S1"] = deepcopy(original)
            mutation()
            self.failed_gate("S1", reason)

    def test_s1_readback_effect_and_cleanup_are_required(self):
        self.data["S1"]["rounds"][0]["restored"]["flags"] = 5
        self.failed_gate("S1", "capability_cpu_readback_failed")
        self.data["S1"]["rounds"][0]["restored"] = cpu()
        self.data["S1"]["rounds"][0]["cleanup"]["active_processes"] = 1
        self.failed_gate("S1", "capability_cleanup_unverified")

    def test_s2_hosts_and_child_survival_required(self):
        self.data["S2"]["hosts"][0]["executable_sha256"] = "f" * 64
        self.failed_gate("S2", "capability_launch_topology_mismatch")
        self.data["S2"]["hosts"][0]["executable_sha256"] = "e" * 64
        row = next(r for r in self.data["S2"]["hosts"][0]["cases"] if r["case"] == "root_child_survival")
        row["observations"]["live_child_count_after_root"] = 0
        self.failed_gate("S2", "capability_child_survival_unverified")

    def test_s3_named_case_without_observed_fault_cannot_pass(self):
        self.data["S3"]["cases"][0]["observations"]["fault_observations"] = 0
        self.failed_gate("S3", "capability_measurement_invalid")

    def test_p4_one_sample_cannot_claim_ten_minutes(self):
        self.data["P4"]["scales"][0]["samples"] = [[0, 1, 0, 0]]
        self.failed_gate("P4", "capability_measurement_missing")

    def test_p4_duplicate_ticks_cannot_dilute_p95(self):
        samples = self.data["P4"]["scales"][1]["samples"]
        samples.insert(1, deepcopy(samples[0]))
        self.failed_gate("P4", "capability_cost_coverage_incomplete")

    def test_p4_missing_waiting_wrapper_or_shadow_write_denies(self):
        self.data["P4"]["scales"][0]["processes"][-1]["roles"] = ["helper"]
        self.failed_gate("P4", "capability_monitor_coverage_incomplete")
        self.data["P4"] = p4_data(self.profile)
        self.data["P4"]["scales"][0]["native_set_calls"] = 1
        self.failed_gate("P4", "capability_safety_invariant_failed")

    def test_p4_failed_fifty_job_stress_does_not_invalidate_ten_job_scope(self):
        self.data["P4"]["scales"][2]["processes"][0]["cpu_end_100ns"] = 600 * T
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)
        self.assertEqual(result.scope_notes, ("50_job_stress:failed_outside_allowed_scope",))

    def test_p4_ten_job_overhead_failure_denies(self):
        self.data["P4"]["scales"][1]["processes"][0]["cpu_end_100ns"] = 600 * T
        self.failed_gate("P4", "capability_observer_budget_failed")

    def test_p4_core_only_trace_without_actual_host_denies(self):
        del self.data["P4"]["scales"][0]["host_loop"]
        self.failed_gate("P4", "capability_schema_invalid")

    def test_p4_every_observer_role_is_required(self):
        original = deepcopy(self.data["P4"])
        for role in ("supervisor", "accounting_keeper", "daily_activation"):
            with self.subTest(role=role):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["processes"][2]["roles"].remove(role)
                self.failed_gate("P4", "capability_monitor_coverage_incomplete")

    def test_p4_cohosted_observer_roles_are_measured_once(self):
        scale = self.data["P4"]["scales"][0]
        # One CPU row carrying three resident roles is within .05 units;
        # charging that same process three times would exceed the existing cap.
        scale["processes"][2]["cpu_end_100ns"] = 15 * T
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)

    def test_p4_distinct_observer_processes_are_all_charged(self):
        scale = self.data["P4"]["scales"][0]
        scale["processes"][2]["roles"] = ["supervisor"]
        for pid, role in ((200, "accounting_keeper"), (201, "daily_activation")):
            scale["processes"].append(dict(identity=identity(pid), roles=[role],
                cpu_start_100ns=0, cpu_end_100ns=T))
        for sample in scale["samples"]:
            sample[6][2] = 4 * MIB
            sample[6].extend([3 * MIB, 3 * MIB])
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)
        scale["processes"][-1]["cpu_end_100ns"] = 40 * T
        self.failed_gate("P4", "capability_observer_budget_failed")

    def test_p4_duplicate_identity_or_pid_cannot_be_charged_as_another_monitor(self):
        original = deepcopy(self.data["P4"])
        for same_birth in (True, False):
            with self.subTest(same_birth=same_birth):
                self.data["P4"] = deepcopy(original)
                processes = self.data["P4"]["scales"][0]["processes"]
                processes[2]["identity"] = deepcopy(processes[0]["identity"])
                if not same_birth:
                    processes[2]["identity"]["created_filetime_100ns"] = "999999"
                self.failed_gate("P4", "capability_monitor_identity_invalid")

    def test_p4_roles_must_be_sorted_unique_and_only_supported_aliases(self):
        original = deepcopy(self.data["P4"])
        for roles in (["supervisor", "accounting_keeper", "daily_activation"],
                      ["supervisor", "supervisor"], ["helper", "supervisor"],
                      ["waiting_wrapper", "supervisor"], ["unmeasured_observer"]):
            with self.subTest(roles=roles):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["processes"][2]["roles"] = roles
                self.failed_gate("P4", "capability_monitor_identity_invalid")

    def test_p4_every_memory_aggregate_is_derived_from_unique_processes(self):
        original = deepcopy(self.data["P4"])
        for index in (2, 3, 4, 5):
            with self.subTest(field=index):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["samples"][0][index] += 1
                self.failed_gate("P4", "capability_monitor_memory_mismatch")

    def test_p4_peak_vector_cannot_omit_an_observer(self):
        self.data["P4"]["scales"][0]["samples"][0][6].pop()
        self.failed_gate("P4", "capability_measurement_missing")

    def test_p4_extra_resident_commit_uses_existing_memory_budget(self):
        sample = self.data["P4"]["scales"][0]["samples"][0]
        sample[6][2] += 61 * MIB
        sample[4] += 61 * MIB
        sample[5] += 61 * MIB
        self.failed_gate("P4", "capability_observer_budget_failed")

    def test_p4_host_binding_cannot_substitute_identity_parent_profile_or_endpoint(self):
        original = deepcopy(self.data["P4"])
        changes = (("identity", identity(999)), ("parent_identity", identity(999)),
            ("config_revision", "0" * 64), ("scope_nonce", "not-a-scope"))
        for field, value in changes:
            with self.subTest(field=field):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["host_loop"][field] = value
                self.failed_gate("P4", "capability_host_loop_binding_invalid")
        self.data["P4"] = deepcopy(original)
        host = self.data["P4"]["scales"][0]["host_loop"]
        host["operator_instance_id"] = host["instance_id"]
        self.failed_gate("P4", "capability_host_loop_binding_invalid")

    def test_p4_query_stress_cannot_overlap_managed_scope(self):
        host = self.data["P4"]["scales"][2]["host_loop"]
        host["query_only_execution_ids"][0] = host["managed_execution_ids"][0]
        self.failed_gate("P4", "capability_host_loop_scope_invalid")

    def test_p4_host_iteration_range_must_match_every_sample(self):
        self.data["P4"]["scales"][0]["host_loop"]["ended_iteration"] += 1
        self.failed_gate("P4", "capability_host_loop_coverage_incomplete")

    def test_p4_host_iteration_refresh_report_and_operator_are_observed(self):
        original = deepcopy(self.data["P4"])
        for position, field, value in ((0, 0, 2), (5, 1, 0), (9, 2, 0),
                                       (0, 3, 0), (9, 4, 0), (0, 4, 512)):
            with self.subTest(position=position, field=field):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["host_loop"]["ticks"][position][field] = value
                self.failed_gate("P4", "capability_host_loop_coverage_incomplete")

    def test_p4_host_flags_are_numeric_observations_not_booleans(self):
        self.data["P4"]["scales"][0]["host_loop"]["ticks"][0][1] = False
        self.failed_gate("P4", "capability_measurement_invalid")

    def test_p4_nondefault_host_cadences_and_original_iteration_are_verified(self):
        host = self.data["P4"]["scales"][0]["host_loop"]
        host.update(started_iteration=17, ended_iteration=617,
                    enroll_every_ticks=7, report_every_ticks=13)
        for offset, tick in enumerate(host["ticks"]):
            iteration = 18 + offset
            tick[0] = iteration
            tick[1] = int(iteration > 1 and (iteration - 1) % 7 == 0)
            tick[2] = int(iteration % 13 == 0)
            tick[4] = 512 if tick[2] else 0
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)

    def test_p4_zero_actual_refresh_or_report_total_cannot_pass(self):
        original = deepcopy(self.data["P4"])
        for cadence, index in (("enroll_every_ticks", 1), ("report_every_ticks", 2)):
            with self.subTest(cadence=cadence):
                self.data["P4"] = deepcopy(original)
                host = self.data["P4"]["scales"][0]["host_loop"]
                host[cadence] = 3600
                for tick in host["ticks"]:
                    tick[index] = 0
                    if index == 2:
                        tick[4] = 0
                self.failed_gate("P4", "capability_host_loop_coverage_incomplete")

    def test_p4_pacing_cannot_hide_wait_inside_tick_or_cross_next_sample(self):
        original = deepcopy(self.data["P4"])
        for position, field, value in ((0, 5, 0), (0, 6, 1), (0, 7, 100_000),
                                       (0, 7, T + 1), (0, 9, 1), (599, 7, 600 * T + 1)):
            with self.subTest(position=position, field=field):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["host_loop"]["ticks"][position][field] = value
                self.failed_gate("P4", "capability_host_loop_pacing_invalid")

    def test_p4_wait_overrun_is_exact_not_a_hidden_zero(self):
        tick = self.data["P4"]["scales"][0]["host_loop"]["ticks"][0]
        tick[5] = 50_000
        tick[9] = 50_000
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)
        tick[9] = 0
        self.failed_gate("P4", "capability_host_loop_pacing_invalid")

    def test_p4_complete_raw_trace_uses_fixed_larger_artifact_bound(self):
        payload = encoded(dict(schema_version=1, run_id=RUN, gate="P4",
            evidence_source="native", data=self.data["P4"]))
        self.assertGreater(len(payload), ce._MAX_BYTES)
        self.assertLessEqual(len(payload), ce._P4_MAX_BYTES)
        result = self.authority().assess()
        self.assertTrue(result.eligible, result)

    def test_p4_artifact_over_fixed_bound_is_refused(self):
        self.data["P4"] = {"padding": "x" * ce._P4_MAX_BYTES}
        result = self.authority().assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_evidence_oversized")

    def test_p4_filename_and_payload_cannot_expand_another_expected_gate_bound(self):
        authority = self.authority()
        raw = (self.path / "P4.json").read_bytes()
        self.bundle["artifacts"] = [dict(gate="S1", path="P4.json", sha256=sha(raw))]
        payload = encoded(self.bundle)
        (self.path / "bundle.json").write_bytes(payload)
        authority.expected_bundle_sha256 = sha(payload)
        result = authority.assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_evidence_oversized")

    def test_p4_expected_gate_still_rejects_wrong_gate_envelope(self):
        authority = self.authority()
        raw = encoded(dict(schema_version=1, run_id=RUN, gate="S1",
            evidence_source="native", data={}))
        (self.path / "P4.json").write_bytes(raw)
        next(item for item in self.bundle["artifacts"] if item["gate"] == "P4")["sha256"] = sha(raw)
        payload = encoded(self.bundle)
        (self.path / "bundle.json").write_bytes(payload)
        authority.expected_bundle_sha256 = sha(payload)
        result = authority.assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_artifact_binding_invalid")

    def test_p4_truncated_trace_cannot_pass_even_with_matching_hash(self):
        authority = self.authority()
        raw = (self.path / "P4.json").read_bytes()[:-1]
        (self.path / "P4.json").write_bytes(raw)
        next(item for item in self.bundle["artifacts"] if item["gate"] == "P4")["sha256"] = sha(raw)
        payload = encoded(self.bundle)
        (self.path / "bundle.json").write_bytes(payload)
        authority.expected_bundle_sha256 = sha(payload)
        result = authority.assess()
        self.assertFalse(result.eligible)
        self.assertEqual(result.reason, "capability_evidence_unavailable")

    def test_p4_artifact_decoder_keeps_protocol_limits_separate(self):
        payload = encoded({"gate": "P4", "padding": "x" * ce._MAX_BYTES})
        self.assertEqual(ce._artifact_json_loads(payload, expected_gate="P4")["gate"], "P4")
        for decoder in (ce.strict_json_loads,
                        lambda value: ce._artifact_json_loads(value, expected_gate="S1")):
            with self.assertRaisesRegex(ValueError, "message too large"):
                decoder(payload)

    def test_p4_artifact_decoder_enforces_exact_fixed_bound(self):
        payload = encoded({"padding": "x" * (ce._P4_MAX_BYTES - len(encoded({"padding": ""})))})
        self.assertEqual(len(payload), ce._P4_MAX_BYTES)
        self.assertEqual(len(ce._artifact_json_loads(payload, expected_gate="P4")["padding"]),
                         ce._P4_MAX_BYTES - len(encoded({"padding": ""})))
        with self.assertRaisesRegex(ValueError, "message too large"):
            ce._artifact_json_loads(payload + b" ", expected_gate="P4")

    def test_p4_large_artifact_decoder_preserves_duplicate_and_number_rejection(self):
        prefix = b'{"padding":"' + b"x" * ce._MAX_BYTES + b'",'
        for suffix in (b'"same":1,"same":2}', b'"number":NaN}', b'"number":Infinity}',
                       b'"number":-Infinity}', b'"number":1e999}'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                ce._artifact_json_loads(prefix + suffix, expected_gate="P4")

    def test_p4_large_artifact_decoder_preserves_depth_utf8_and_truncation_rejection(self):
        prefix = b'{"padding":"' + b"x" * ce._MAX_BYTES + b'",'
        suffixes = (b'"nested":' + b"[" * 65 + b"0" + b"]" * 65 + b"}",
                    b'"text":"\xff"}', b'"unfinished":')
        for suffix in suffixes:
            with self.subTest(suffix=suffix[:20]), self.assertRaises(ValueError):
                ce._artifact_json_loads(prefix + suffix, expected_gate="P4")
        with self.assertRaisesRegex(ValueError, "object required"):
            ce._artifact_json_loads(b"[]", expected_gate="P4")

    def test_p4_artifact_decoder_preserves_exact_integers_and_string_brackets(self):
        value = {"padding": "x" * ce._MAX_BYTES, "integer": (1 << 63) - 1,
                 "text": '[{\\"}]' * 100, "flag": True}
        parsed = ce._artifact_json_loads(encoded(value), expected_gate="P4")
        self.assertEqual(parsed, value)
        self.assertIs(type(parsed["integer"]), int)
        self.assertIs(type(parsed["flag"]), bool)
        # The decoder preserves types; the existing typed measurement boundary
        # continues rejecting bools, floats and integers outside its range.
        original = deepcopy(self.data["P4"])
        for number in (True, 1.0, 1 << 63):
            with self.subTest(number=number):
                self.data["P4"] = deepcopy(original)
                self.data["P4"]["scales"][0]["processes"][0]["cpu_end_100ns"] = number
                self.failed_gate("P4", "capability_measurement_invalid")

    def test_p5_all_equal_timestamps_and_missing_disabled_readback_deny(self):
        original = deepcopy(self.data["P5"])
        row = self.data["P5"]["reaction"][0]
        for name in ("sample_end", "decision", "apply", "query_confirmed"):
            row[name] = T
        self.failed_gate("P5", "capability_clock_order_invalid", "p6_trial")
        self.data["P5"] = original
        self.data["P5"]["helper_loss"][0]["query"] = cpu(2500)
        self.failed_gate("P5", "capability_cpu_readback_failed", "p6_trial")

    def test_p5_restore_deadline_is_maximum_not_average(self):
        self.data["P5"]["guardian_loss"][0]["disabled_query"] = 10 * T
        self.failed_gate("P5", "capability_restore_latency_failed", "p6_trial")

    def test_p6_explicit_arithmetic_precedes_named_unresolved_promotion(self):
        self.data["P6"] = p6_data()
        self.failed_gate("P6", "p6_promotion_policy_unresolved", "limited")
        for pair in self.data["P6"]["pairs"]:
            if pair["scenario"] == "CPU_CONTENTION" and pair["comparison"] == "A1_B":
                pair["candidate"]["foreground_p95_ms"] = 39
        self.failed_gate("P6", "capability_ab_cpu_benefit_failed", "limited")

    def test_exact_execution_binding_and_frame_binding_required(self):
        authority = self.authority()
        self.assertTrue(authority.assess().eligible)
        for field, value in (("role", "interactive"), ("priority", "P1"),
                ("coverage", "unmanaged"), ("launch_in_flight", 1),
                ("launch_sealed", True), ("logon_id", "S-1-5-5-1-2")):
            old = self.row[field]
            self.row[field] = value
            with self.subTest(field=field), self.assertRaises(ce.CapabilityEvidenceError):
                self.assert_eligible(authority)
            self.row[field] = old
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "frame_binding_mismatch"):
            authority.assert_control_eligible(profile_revision=profile_revision(self.profile),
                logical_processors=4, execution_row=self.row, guardian_identity=self.guardian)

    def test_default_launch_scope_denies_even_when_global_evidence_passes(self):
        authority = self.authority(launch_scope_source=None)
        self.assertTrue(authority.assess().eligible)
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_launch_scope_unverified"):
            self.assert_eligible(authority)

    def test_launch_scope_requires_typed_matching_execution_and_topology(self):
        def scope(**binding):
            values = binding | dict(measured_topology_sha256="f" * 64,
                                    actual_topology_sha256="f" * 64)
            values.update(change)
            return ce.VerifiedLaunchScope(**values)
        for change in ({"actual_topology_sha256": "e" * 64},
                {"execution_id": RUN}, {"host_fingerprint": "e" * 64},
                {"bundle_sha256": "e" * 64}, {"config_revision": "e" * 64}):
            authority = self.authority(launch_scope_source=scope)
            self.assertTrue(authority.assess().eligible)
            with self.subTest(change=change), self.assertRaisesRegex(
                    ce.CapabilityEvidenceError, "capability_launch_scope_unverified"):
                self.assert_eligible(authority)
        authority = self.authority(launch_scope_source=lambda **_: {"supported": True})
        self.assertTrue(authority.assess().eligible)
        with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_launch_scope_unverified"):
            self.assert_eligible(authority)

    def test_launch_scope_exception_is_retained_and_not_retried(self):
        error = RuntimeError("synthetic scope provenance unavailable")
        calls = []
        def scope(**_):
            calls.append(1)
            raise error
        authority = self.authority(launch_scope_source=scope)
        self.assertTrue(authority.assess().eligible)
        for _ in range(2):
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "capability_launch_scope_unverified"):
                self.assert_eligible(authority)
        self.assertIs(authority._scope_failure, error)
        self.assertEqual(len(calls), 1)

    def test_native_source_retains_uncertain_identity_owner_and_never_reopens(self):
        source = ce.NativeContextSource()
        failure = RuntimeError("synthetic ambiguous native acquisition")
        with patch.object(ce, "read_host_capability", return_value=object()), \
             patch.object(ce.VerifiedProcess, "current", side_effect=failure) as current:
            with self.assertRaises(RuntimeError):
                source()
            self.assertIs(source._failure, failure)
            with self.assertRaisesRegex(ce.CapabilityEvidenceError, "cleanup_unknown"):
                source()
            self.assertEqual(current.call_count, 1)


if __name__ == "__main__":
    unittest.main()
