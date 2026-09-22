"""Pure reducer tests. Every native-shaped observation here is fabricated.

The explicit receipt tests exercise binding arithmetic only; they are neither
native measurements nor capability/promotion evidence. No process is launched.
"""
from dataclasses import replace
import hashlib
import unittest

from sentinel.adaptive.contracts import Priority, ProcessIdentity, Role
from tests.benchmarks.adaptive_ab import (
    CacheState, Comparison, EvidenceSource, FixedConditions, HeadroomAttribution,
    Preconditions, ScenarioClass, Variant, build_schedule,
)
from tests.benchmarks.adaptive_measurements import (
    ApiErrorObservation, ArtifactPin, CapAuditTrace, CapEvent, DemandTrace,
    GrantAuditTrace, GrantLease, GrantWindow, LifecycleProof, MachineSample,
    MeasurementError, MembershipSample, MembershipTrace, NativeRunProvenance,
    ProcessSample, ProcessTrace, RawRunTrace, SamplingPlan, StateInterval,
    UiSample, UiTrace, reduce_metrics, reduce_run, trace_sha256, verify_native_provenance,
)


SECOND = 1000000000
MIB = 1024 * 1024
CLOCK = "fabricated-boot-qpc-monotonic-ns"
START, END = 10 * SECOND, 14 * SECOND
MONITOR = ProcessIdentity(10, 100, "fixture-logon")
WRAPPER = ProcessIdentity(11, 101, "fixture-logon")
PROBE = ProcessIdentity(12, 102, "fixture-logon")
ROOT = ProcessIdentity(13, 103, "fixture-logon")
CHILD = ProcessIdentity(14, 104, "fixture-logon")


def sha(name):
    return hashlib.sha256(name.encode()).hexdigest()


def counter(identity, tick, cpu, peak):
    return ProcessSample(identity, CLOCK, tick, tick, cpu, peak * MIB, peak * MIB)


def cap(sequence, tick, operation="query", flags=0, rate=0, state="OBSERVING", restore=None):
    return CapEvent(sequence, "execution-one", MONITOR, tick, tick // 100,
                    operation, flags, rate, state, True, restore)


def fixture_trace():
    conditions = FixedConditions(
        "fixture-commit", "windows-fixture", 8, "fixture-power", CacheState.WARM, False,
        sha("dataset"), 1, sha("UI"), sha("collector"),
        tuple((variant, sha(variant.value)) for variant in Variant))
    sampling = SamplingPlan(1100000000, 1100000000, 600000000, 100000000, sha("sampling"))
    points = tuple(int(value * SECOND) for value in (9.99, 10.99, 11.99, 12.99, 13.99, 14.01))
    machine = tuple(MachineSample(CLOCK, tick, tick, 8192 * MIB, 8192 * MIB,
                                 16384 * MIB, 32768 * MIB,
                                 HeadroomAttribution.WITHIN_RESERVE,
                                 HeadroomAttribution.WITHIN_RESERVE, "machine") for tick in points)
    ui_samples = tuple(UiSample(index + 1, START + index * 500000000,
                                START + index * 500000000 + 20000000,
                                START + index * 500000000 + 21000000,
                                START + index * 500000000 + 25000000,
                                START + index * 500000000 + 26000000) for index in range(8))
    probe = UiTrace(PROBE, CLOCK, 9 * SECOND, 15 * SECOND, True, 0x20,
                    ui_samples, True, "probe")
    processes = (
        ProcessTrace(MONITOR, "monitor", None, 0, 20 * SECOND, False, False,
                     tuple(counter(MONITOR, tick, 1000000 + index * 200000, 128)
                           for index, tick in enumerate(points)), "costs"),
        ProcessTrace(WRAPPER, "wrapper", "task-one", 0, 20 * SECOND, False, False,
                     tuple(counter(WRAPPER, tick, 500000 + index * 80000, 32)
                           for index, tick in enumerate(points)), "costs"),
        ProcessTrace(PROBE, "probe", None, 9 * SECOND, 15 * SECOND, False, False,
                     tuple(counter(PROBE, tick, 100 + index * 20, 8)
                           for index, tick in enumerate(points)), "costs"),
        ProcessTrace(ROOT, "workload", "task-one", 11 * SECOND, 12 * SECOND, True, True,
                     (counter(ROOT, 11 * SECOND, 100, 10), counter(ROOT, 12 * SECOND, 2000000, 10)), "costs"),
        ProcessTrace(CHILD, "workload", "task-one", 11100000000, END, True, True,
                     tuple(counter(CHILD, tick, 100 + index * 3000000, 20)
                           for index, tick in enumerate((11100000000, 12100000000, 13100000000, END))), "costs"),
    )
    demand = DemandTrace("task-one", "execution-one", ROOT, START, 11 * SECOND,
                         12 * SECOND, END, 6, 6, 0, 6, "owned_job", WRAPPER,
                         Role.BACKGROUND, Priority.P2, "lifecycle")
    audit = CapAuditTrace(CLOCK, 9800000000, 14200000000, (MONITOR,), ("execution-one",),
                          (cap(1, points[0]), cap(2, points[-1])), True, True, "write", "query")
    lifecycle = LifecycleProof("task-one", "execution-one", "owned_job", (ROOT, CHILD),
                               14100000000, points[-1], True, True, "lifecycle", ())
    artifacts = tuple(ArtifactPin(name, sha(name)) for name in
                      ("probe", "costs", "machine", "lifecycle", "write", "query", "grants", "membership"))
    grants = GrantAuditTrace(CLOCK, "fixture-policy", "fixture-epoch", "fixture-logon",
                             ("execution-one",), 9800000000, 14200000000,
                             (GrantWindow(CLOCK, "fixture-policy", "fixture-epoch", 0,
                                          9800000000, 14200000000, (), True),), True, "grants")
    return RawRunTrace(
        "fixture-episode", CLOCK, conditions, Preconditions(True, True, True, True),
        START, END, sampling, probe, (demand,), machine, (MONITOR,), (WRAPPER,),
        processes, audit, (StateInterval(CLOCK, "OBSERVING", START, END),), grants,
        (lifecycle,), (), artifacts)


def unmanaged_trace():
    trace = fixture_trace()
    demand = replace(trace.demands[0], covered_units=0, scope_kind="verified_fixture_tree")
    membership = tuple(MembershipTrace(
        process.identity, tuple(MembershipSample(process.identity, CLOCK,
                                                  point.capture_start_ns, point.capture_end_ns, True, True)
                                 for point in process.samples), True, "membership")
                       for process in trace.processes if process.role == "workload")
    proof = replace(trace.lifecycle[0], scope_kind="verified_fixture_tree",
                    observed_disabled_ns=None, no_job_membership=membership)
    audit = replace(trace.cap_audit, execution_ids=(), events=())
    return replace(trace, demands=(demand,), lifecycle=(proof,), cap_audit=audit)


def schedule():
    return build_schedule([("cpu_bound_build", ScenarioClass.CPU_CONTENTION)],
                           "fixture-seed", comparisons=[Comparison.A1_B])


def provenance(trace, slot=None, variant=Variant.B, purpose="comparison"):
    return NativeRunProvenance(trace.run_id, trace.clock_id, trace_sha256(trace),
                               sha("producer"), sha("host"), trace.artifacts,
                               slot.slot_id if slot is not None else None,
                               variant, "fixture-seed", purpose)


class ArithmeticTests(unittest.TestCase):
    def test_complete_demand_to_last_child_timing_includes_queue(self):
        metrics = reduce_metrics(fixture_trace())
        self.assertEqual(metrics.makespan_s, 4.0)
        self.assertEqual(metrics.queue_wait_p50_s, 1.0)
        self.assertEqual(metrics.queue_wait_p95_s, 1.0)
        self.assertEqual(metrics.completed_units_per_min, 90.0)
        self.assertEqual(metrics.foreground_p95_ms, 20.0)
        self.assertEqual(metrics.foreground_p50_ms, 20.0)
        self.assertEqual(metrics.foreground_p99_ms, 20.0)

    def test_monitor_cpu_and_commit_include_wrapper_but_exclude_workload_probe(self):
        metrics = reduce_metrics(fixture_trace())
        self.assertAlmostEqual(metrics.monitor_cpu_units, .035)
        self.assertEqual(metrics.monitor_commit_mib, 160.0)
        self.assertEqual(metrics.peak_private_commit_mib, 30.0)
        self.assertEqual(metrics.peak_physical_mib, 8192.0)
        self.assertEqual(metrics.min_physical_headroom_mib, 8192.0)
        self.assertEqual(metrics.min_commit_headroom_mib, 16384.0)
        self.assertEqual(metrics.coverage_fraction, 1.0)

    def test_actual_api_errors_are_counted_not_dropped(self):
        trace = fixture_trace()
        trace = replace(trace, api_errors=(ApiErrorObservation(CLOCK, 12 * SECOND,
                                                               "fixture_query", 5, "query"),))
        self.assertEqual(reduce_metrics(trace).api_errors, 1)

    def test_unmanaged_control_coverage_can_be_zero_with_complete_observations(self):
        metrics = reduce_metrics(unmanaged_trace())
        self.assertEqual(metrics.coverage_fraction, 0.0)
        self.assertEqual(metrics.monitor_commit_mib, 160.0)

    def test_native_shaped_fixture_defaults_to_synthetic(self):
        plan = schedule()
        record = reduce_run(fixture_trace(), schedule=plan, slot=plan.slots[0], variant=Variant.B)
        self.assertIs(record.evidence_source, EvidenceSource.SYNTHETIC)
        self.assertIn("authenticity", record.note)


class IdentityAndCoverageTests(unittest.TestCase):
    def test_pid_reuse_in_one_process_counter_is_rejected(self):
        trace = fixture_trace()
        process = trace.processes[0]
        changed = replace(process.samples[2], identity=replace(MONITOR, created_filetime_100ns=999))
        process = replace(process, samples=process.samples[:2] + (changed,) + process.samples[3:])
        with self.assertRaisesRegex(MeasurementError, "exact identity"):
            reduce_metrics(replace(trace, processes=(process,) + trace.processes[1:]))

    def test_absent_wrapper_or_monitor_is_not_zero_cost(self):
        trace = fixture_trace()
        for role in ("wrapper", "monitor"):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, processes=tuple(item for item in trace.processes
                                                             if item.role != role)))

    def test_absent_child_cost_cannot_disappear_after_root_exit(self):
        trace = fixture_trace()
        with self.assertRaisesRegex(MeasurementError, "exact lifecycle members"):
            reduce_metrics(replace(trace, processes=trace.processes[:-1]))

    def test_duplicate_process_identity_cannot_be_double_counted(self):
        trace = fixture_trace()
        with self.assertRaisesRegex(MeasurementError, "double accounting"):
            reduce_metrics(replace(trace, processes=trace.processes + (trace.processes[0],)))

    def test_missing_or_reversed_cpu_counter_is_not_replaced_with_zero(self):
        trace = fixture_trace()
        process = trace.processes[0]
        for value in (None, -1, 5):
            changed = replace(process.samples[2], cpu_time_100ns=value)
            candidate = replace(process, samples=process.samples[:2] + (changed,) + process.samples[3:])
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, processes=(candidate,) + trace.processes[1:]))

    def test_cost_capture_gap_and_clock_domain_mismatch_fail_closed(self):
        trace = fixture_trace()
        process = trace.processes[0]
        for samples in (process.samples[:1] + process.samples[3:],
                        (replace(process.samples[0], clock_id="other-boot"),) + process.samples[1:]):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, processes=(replace(process, samples=samples),)
                                      + trace.processes[1:]))

    def test_final_cost_counter_before_child_completion_is_not_complete(self):
        trace = fixture_trace()
        child = trace.processes[-1]
        with self.assertRaisesRegex(MeasurementError, "final process counter"):
            reduce_metrics(replace(trace, processes=trace.processes[:-1]
                                  + (replace(child, samples=child.samples[:-1]),)))

    def test_machine_gap_or_stale_endpoints_fail_closed(self):
        trace = fixture_trace()
        for samples in (trace.machine[1:], trace.machine[:-1], trace.machine[:1] + trace.machine[3:]):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, machine=samples))

    def test_ui_sequence_clock_scope_and_priority_must_all_be_verified(self):
        trace = fixture_trace()
        variants = (
            replace(trace.probe, outside_all_jobs=False),
            replace(trace.probe, priority_class=0x80),
            replace(trace.probe, clock_id="other-boot"),
            replace(trace.probe, samples=(replace(trace.probe.samples[0], sequence=2),)
                    + trace.probe.samples[1:]),
            replace(trace.probe, samples=(replace(trace.probe.samples[0], dispatch_ns=START - 1),)
                    + trace.probe.samples[1:]),
        )
        for probe in variants:
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, probe=probe))

    def test_ui_idle_gaps_cannot_be_hidden_by_percentile_reduction(self):
        trace = fixture_trace()
        reduced = tuple(replace(point, sequence=index + 1)
                        for index, point in enumerate(trace.probe.samples[::3]))
        with self.assertRaisesRegex(MeasurementError, "UI temporal coverage"):
            reduce_metrics(replace(trace, probe=replace(trace.probe, samples=reduced)))

    def test_state_intervals_must_cover_whole_window(self):
        trace = fixture_trace()
        with self.assertRaisesRegex(MeasurementError, "control state endpoint"):
            reduce_metrics(replace(trace, states=(StateInterval(CLOCK, "OBSERVING", START, 12 * SECOND),)))


class LifecycleAndAttributionTests(unittest.TestCase):
    def test_root_exit_is_not_child_empty_or_capacity_release(self):
        trace = fixture_trace()
        for proof in (replace(trace.lifecycle[0], observed_empty_ns=12 * SECOND),
                      replace(trace.lifecycle[0], bookkeeping_settled=False),
                      replace(trace.lifecycle[0], custody_cleanup_complete=False),
                      replace(trace.lifecycle[0], members=(ROOT,))):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, lifecycle=(proof,)))

    def test_run_end_cannot_omit_surviving_child_or_queue_time(self):
        trace = fixture_trace()
        for candidate in (replace(trace, started_ns=11 * SECOND),
                          replace(trace, ended_ns=12 * SECOND)):
            with self.assertRaises(MeasurementError):
                reduce_metrics(candidate)

    def test_unknown_attribution_is_not_a_measured_answer(self):
        trace = fixture_trace()
        point = replace(trace.machine[1], physical_available_bytes=3000 * MIB,
                        physical_used_bytes=(16384 - 3000) * MIB,
                        physical_attribution=HeadroomAttribution.UNKNOWN)
        with self.assertRaisesRegex(MeasurementError, "attribution unknown"):
            reduce_metrics(replace(trace, machine=(trace.machine[0], point) + trace.machine[2:]))

    def test_overbooking_is_not_hidden_by_a_lower_external_minimum(self):
        trace = fixture_trace()
        first = replace(trace.machine[1], physical_available_bytes=3000 * MIB,
                        physical_used_bytes=(16384 - 3000) * MIB,
                        physical_attribution=HeadroomAttribution.NEW_ADMISSION)
        second = replace(trace.machine[2], physical_available_bytes=2000 * MIB,
                         physical_used_bytes=(16384 - 2000) * MIB,
                         physical_attribution=HeadroomAttribution.UNMANAGED)
        metrics = reduce_metrics(replace(trace, machine=(trace.machine[0], first, second) + trace.machine[3:]))
        self.assertEqual(metrics.min_physical_headroom_mib, 2000.0)
        self.assertIs(metrics.physical_headroom_attribution, HeadroomAttribution.NEW_ADMISSION)
        self.assertIs(metrics.commit_headroom_attribution, HeadroomAttribution.WITHIN_RESERVE)

    def test_thermal_and_precondition_uncertainty_cannot_be_native_success(self):
        trace = fixture_trace()
        with self.assertRaisesRegex(MeasurementError, "preconditions"):
            reduce_metrics(replace(trace, preconditions=Preconditions(True, True, None, True)))
        with self.assertRaisesRegex(MeasurementError, "thermal or power anomaly"):
            reduce_metrics(replace(trace, conditions=replace(trace.conditions, thermal_or_power_anomaly=True)))


class CapEvidenceTests(unittest.TestCase):
    def capped(self):
        trace = fixture_trace()
        events = (
            cap(1, 9990000000),
            cap(2, 11 * SECOND, "set", 5, 2500, "CAPPED_L1"),
            cap(3, 11001000000, "query", 5, 2500, "CAPPED_L1"),
            cap(4, 12 * SECOND, "set", 5, 10000, "RECOVERING"),
            cap(5, 12001000000, "query", 5, 10000, "RECOVERING"),
            cap(6, 13 * SECOND, "set", restore=12900000000),
            cap(7, 13010000000),
            cap(8, 14010000000),
        )
        return replace(trace, cap_audit=replace(trace.cap_audit, events=events))

    def test_recoving_baseline_and_restore_latency_use_native_events(self):
        metrics = reduce_metrics(self.capped())
        self.assertEqual(len(metrics.native_cap_intervals), 2)
        self.assertEqual(metrics.native_cap_intervals[1].state, "RECOVERING")
        self.assertEqual(metrics.native_cap_intervals[1].rate_bp, 10000)
        self.assertEqual(metrics.native_cap_intervals[1].seconds, 1.0)
        self.assertAlmostEqual(metrics.restore_time_s, .11)

    def test_native_readback_mismatch_fails_instead_of_trusting_config(self):
        trace = self.capped()
        events = list(trace.cap_audit.events)
        events[2] = replace(events[2], rate_bp=4000)
        with self.assertRaisesRegex(MeasurementError, "readback differs"):
            reduce_metrics(replace(trace, cap_audit=replace(trace.cap_audit, events=tuple(events))))

    def test_missing_write_audit_or_readback_coverage_cannot_claim_zero_caps(self):
        trace = fixture_trace()
        for audit in (replace(trace.cap_audit, complete_write_audit=False),
                      replace(trace.cap_audit, complete_query_coverage=False),
                      replace(trace.cap_audit, events=trace.cap_audit.events[:1])):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, cap_audit=audit))

    def test_set_without_matching_query_does_not_become_complete_evidence(self):
        trace = self.capped()
        events = tuple(replace(event, sequence=index + 1)
                       for index, event in enumerate(trace.cap_audit.events[:2] + trace.cap_audit.events[3:]))
        with self.assertRaisesRegex(MeasurementError, "matching readback"):
            reduce_metrics(replace(trace, cap_audit=replace(trace.cap_audit, events=events)))

    def test_native_clock_epoch_change_and_wrong_writer_identity_fail(self):
        trace = self.capped()
        for changed in (replace(trace.cap_audit.events[2], tick_100ns=110010000 + 50000000),
                        replace(trace.cap_audit.events[2], writer_identity=ROOT)):
            events = trace.cap_audit.events[:2] + (changed,) + trace.cap_audit.events[3:]
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, cap_audit=replace(trace.cap_audit, events=events)))


class UnmanagedMembershipTests(unittest.TestCase):
    def test_no_named_job_uses_actual_live_membership_not_zero_flags_query(self):
        trace = unmanaged_trace()
        trace = replace(trace, cap_audit=replace(trace.cap_audit, writer_identities=()))
        self.assertEqual(trace.cap_audit.events, ())
        self.assertEqual(trace.cap_audit.execution_ids, ())
        self.assertIsNone(trace.lifecycle[0].observed_disabled_ns)
        metrics = reduce_metrics(trace)
        self.assertTrue(metrics.native_cap_audit_complete)
        self.assertEqual(metrics.native_cap_intervals, ())
        self.assertEqual(metrics.coverage_fraction, 0.0)

    def test_fabricated_disabled_query_for_absent_job_is_rejected(self):
        trace = unmanaged_trace()
        for candidate in (
            replace(trace, cap_audit=fixture_trace().cap_audit),
            replace(trace, lifecycle=(replace(trace.lifecycle[0], observed_disabled_ns=END),)),
        ):
            with self.assertRaises(MeasurementError):
                reduce_metrics(candidate)

    def test_no_job_status_requires_every_original_member_and_live_endpoints(self):
        trace = unmanaged_trace()
        proof = trace.lifecycle[0]
        membership = proof.no_job_membership[0]
        invalid = (
            replace(membership, complete_lifetime_scope_audit=False),
            replace(membership, samples=membership.samples[:1]),
            replace(membership, samples=(replace(membership.samples[0], outside_all_jobs=False),)
                    + membership.samples[1:]),
            replace(membership, samples=membership.samples[:-1]
                    + (replace(membership.samples[-1], process_alive=False),)),
            replace(membership, samples=(replace(membership.samples[0], identity=CHILD),)
                    + membership.samples[1:]),
        )
        for item in invalid:
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, lifecycle=(replace(proof,
                    no_job_membership=(item,) + proof.no_job_membership[1:]),)))
        with self.assertRaisesRegex(MeasurementError, "every member"):
            reduce_metrics(replace(trace, lifecycle=(replace(proof,
                no_job_membership=proof.no_job_membership[:1]),)))


class RoleAndGrantEvidenceTests(unittest.TestCase):
    def capped(self):
        return CapEvidenceTests().capped()

    def with_grant(self, trace, *, granted_ns=10500000000, deadline_ns=13500000000,
                   revoked_ns=None, owner=WRAPPER):
        lease = GrantLease("explicit-test-grant", owner, ("execution-one",),
                            "explicit-isolated-test-authorization", granted_ns, deadline_ns,
                            1900000000000000000, revoked_ns, "grants")
        window = replace(trace.grant_audit.windows[0], revision=1, leases=(lease,))
        return replace(trace, grant_audit=replace(trace.grant_audit, windows=(window,)))

    def test_only_background_p2_or_p3_can_have_native_caps(self):
        trace = self.capped()
        for role, priority in ((Role.PROTECTED, Priority.P2), (Role.NEUTRAL, Priority.P3),
                               (Role.BACKGROUND, Priority.P0), (Role.BACKGROUND, Priority.P1)):
            with self.assertRaisesRegex(MeasurementError, "targeted protected"):
                reduce_metrics(replace(trace, demands=(replace(trace.demands[0], role=role,
                                                                 priority=priority),)))
        allowed = replace(trace, demands=(replace(trace.demands[0], priority=Priority.P3),))
        self.assertEqual(len(reduce_metrics(allowed).native_cap_intervals), 2)

    def test_unknown_role_priority_or_missing_scope_provenance_is_rejected(self):
        trace = self.capped()
        for demand in (replace(trace.demands[0], role="background"),
                       replace(trace.demands[0], priority="P2"),
                       replace(trace.demands[0], scope_artifact_name="missing")):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, demands=(demand,)))

    def test_live_grant_before_cap_and_grant_committed_mid_cap_both_reject_p6_trace(self):
        for granted in (10500000000, 11500000000, 12500000000):
            with self.assertRaisesRegex(MeasurementError, "overlaps live"):
                reduce_metrics(self.with_grant(self.capped(), granted_ns=granted))

    def test_original_expiry_or_explicit_revocation_at_cap_start_has_no_overlap(self):
        expired = self.with_grant(self.capped(), granted_ns=10 * SECOND, deadline_ns=11 * SECOND)
        revoked = self.with_grant(self.capped(), granted_ns=10 * SECOND,
                                  deadline_ns=15 * SECOND, revoked_ns=11 * SECOND)
        self.assertEqual(len(reduce_metrics(expired).native_cap_intervals), 2)
        self.assertEqual(len(reduce_metrics(revoked).native_cap_intervals), 2)

    def test_wrong_pid_start_owner_and_missing_authorization_are_not_valid_grant_evidence(self):
        trace = self.with_grant(self.capped())
        window = trace.grant_audit.windows[0]
        for lease in (replace(window.leases[0], owner_identity=replace(WRAPPER, created_filetime_100ns=999)),
                      replace(window.leases[0], authorization_id=""),
                      replace(window.leases[0], scope_execution_ids=("unknown-execution",))):
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, grant_audit=replace(trace.grant_audit,
                    windows=(replace(window, leases=(lease,)),))))

    def test_grant_epoch_scope_revision_and_transition_gaps_fail_closed(self):
        trace = fixture_trace()
        window = trace.grant_audit.windows[0]
        candidates = (
            replace(trace.grant_audit, epoch="unknown-epoch"),
            replace(trace.grant_audit, execution_ids=("unknown-execution",)),
            replace(trace.grant_audit, complete_transition_audit=False),
            replace(trace.grant_audit, windows=(replace(window, complete_scope=False),)),
            replace(trace.grant_audit, windows=(replace(window, started_ns=window.started_ns + 1),)),
            replace(trace.grant_audit, windows=(replace(window, revision=2, ended_ns=12 * SECOND),
                                               replace(window, revision=1, started_ns=12 * SECOND))),
        )
        for audit in candidates:
            with self.assertRaises(MeasurementError):
                reduce_metrics(replace(trace, grant_audit=audit))

    def test_retry_cannot_renew_original_grant_deadline_in_evidence(self):
        trace = self.with_grant(fixture_trace())
        window = trace.grant_audit.windows[0]
        first = replace(window, ended_ns=12 * SECOND)
        second = replace(window, revision=2, started_ns=12 * SECOND,
                         leases=(replace(window.leases[0], original_deadline_ns=15 * SECOND),))
        with self.assertRaisesRegex(MeasurementError, "deadline changed"):
            reduce_metrics(replace(trace, grant_audit=replace(trace.grant_audit, windows=(first, second))))


class ProvenanceTests(unittest.TestCase):
    def test_explicit_receipt_preserves_binding_without_proving_native_apis(self):
        trace, plan = fixture_trace(), schedule()
        receipt = provenance(trace, plan.slots[0])
        record = reduce_run(trace, schedule=plan, slot=plan.slots[0], variant=Variant.B,
                            provenance=receipt)
        self.assertIs(record.evidence_source, EvidenceSource.MEASURED)
        self.assertIn("promotion remain outside", record.note)

    def test_plain_json_measured_label_is_not_a_native_receipt(self):
        trace, plan = fixture_trace(), schedule()
        with self.assertRaisesRegex(MeasurementError, "typed native provenance"):
            reduce_run(trace, schedule=plan, slot=plan.slots[0], variant=Variant.B,
                        provenance={"evidence_source": "measured"})

    def test_mutated_counter_artifact_or_slot_invalidates_receipt(self):
        trace, plan = fixture_trace(), schedule()
        receipt = provenance(trace, plan.slots[0])
        for changed in (replace(receipt, trace_sha256="0" * 64),
                        replace(receipt, artifacts=receipt.artifacts[:-1]),
                        replace(receipt, slot_id=plan.slots[1].slot_id),
                        replace(receipt, variant=Variant.A1),
                        replace(receipt, seed="changed")):
            with self.assertRaises(MeasurementError):
                reduce_run(trace, schedule=plan, slot=plan.slots[0], variant=Variant.B,
                            provenance=changed)

    def test_calibration_has_distinct_run_identity_and_no_comparison_slot(self):
        trace = replace(fixture_trace(), run_id="independent-calibration-run")
        receipt = provenance(trace, variant=Variant.A1, purpose="noise_calibration")
        verify_native_provenance(trace, receipt, variant=Variant.A1, seed="fixture-seed")
        with self.assertRaisesRegex(MeasurementError, "calibration cannot claim"):
            verify_native_provenance(trace, replace(receipt, slot_id=schedule().slots[0].slot_id))
        with self.assertRaisesRegex(MeasurementError, "purpose differs"):
            verify_native_provenance(trace, replace(receipt, purpose="comparison"))


if __name__ == "__main__":
    unittest.main()
