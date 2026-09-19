"""Synthetic protocol tests only; these do not establish Windows capability."""

from dataclasses import FrozenInstanceError, replace
import json
import math
import unittest

from sentinel.adaptive.contracts import (
    AllocationKind, ApplyAck, ApplyResult, ContractViolation, ControlProposal, CpuControl, CpuControlMode,
    CpuTarget, EnforcementState, ExecutionSpec, FastFrame, FrameError, GrantAck, GrantState,
    IdentityObservation, IdentityStatus, JobFrame, LaunchClaimState, LifecycleAck, LifecycleState,
    MachineFrame, MAX_JSON_DEPTH, MAX_MESSAGE_BYTES, PendingIntent, Priority,
    ProcessIdentity, RecoveryManifest, ReservationRef, ResourceDemand, RetryClass,
    Role, RootOutcome, TICKS_PER_SECOND, UINT64_MAX, Validity, derive_lease_deadline,
    make_spec_hash, strict_json_loads,
)


EXECUTION = "10000000-0000-4000-8000-000000000001"
PARENT = "10000000-0000-4000-8000-000000000002"
ACTION = "20000000-0000-4000-8000-000000000001"
GIB = 1 << 30
IDENTITY = ProcessIdentity(4100, 134343072000000001, "logon-a")
DEMAND = ResourceDemand(4.0, 8 * GIB, 8 * GIB, 1)
DISABLED = CpuControl(CpuControlMode.DISABLED, None)
CAP = CpuControl(CpuControlMode.HARD_CAP, 2500)
TARGET = CpuTarget("cpu_rate", CpuControlMode.HARD_CAP, 3.0, 2500, 12)
RESTORE_TARGET = CpuTarget("cpu_rate", CpuControlMode.DISABLED, None, None, None)


def spec(**changes):
    values = dict(execution_id=EXECUTION, task_id="task-a", session_id="session-a",
                  principal_id="principal-a", reservation=ReservationRef(AllocationKind.DIRECT, "r-a"),
                  parent_execution_id=None, spec_hash="a" * 64, role=Role.BACKGROUND,
                  priority=Priority.P2, requested=DEMAND, wrapper_identity=IDENTITY)
    return ExecutionSpec(**(values | changes))


def job(**changes):
    values = dict(execution_id=EXECUTION, cpu_units=6.0, cpu_uncapped_high_water_units=6.0,
                  private_working_set_bytes=6 * GIB, private_commit_bytes=7 * GIB,
                  active_processes=8, membership_complete=True, memory_validity=Validity.VALID,
                  counter_epoch="job-counter-a")
    return JobFrame(**(values | changes))


def frame(**changes):
    values = dict(sampler_epoch="sampler-a", clock_epoch="clock-a", sample_seq=83,
                  window_start_tick_100ns=812340000000, window_end_tick_100ns=812350000000,
                  published_tick_100ns=812350180000, sampled_at_utc="2026-09-19T03:00:00Z",
                  config_revision="b" * 64, registry_revision=17,
                  machine=MachineFrame(12, 1, 10.9, 64 * GIB, 20 * GIB, 56 * GIB, 96 * GIB),
                  jobs=(job(),), validity=Validity.VALID, errors=(),
                  collection_cost_ms=18.0, collection_skew_ms=22.0)
    return FastFrame(**(values | changes))


def proposal(**changes):
    values = dict(execution_id=EXECUTION, request_id=ACTION, guardian_epoch="guardian-a",
                  policy_epoch="policy-a", sampler_epoch="sampler-a", clock_epoch="clock-a",
                  config_revision="b" * 64, registry_revision=17, exemption_revision_seen=5,
                  decision_seq=8, sample_seq=83,
                  sample_window_end_tick_100ns=10 * TICKS_PER_SECOND, decision_tick_100ns=11 * TICKS_PER_SECOND,
                  target=TARGET, reason="cpu_high")
    return ControlProposal(**(values | changes))


def manifest(**changes):
    nonce = "f" * 32
    values = dict(execution_id=EXECUTION, job_name=f"Local\\ResourceSentinel.Job.{EXECUTION}.{nonce}",
                  creation_nonce=nonce, wrapper_identity=IDENTITY,
                  root_identity=ProcessIdentity(4200, 134343072010000002, "logon-a"),
                  guardian_identity=ProcessIdentity(4300, 134343072020000003, "logon-a"),
                  guardian_epoch="guardian-a", original=DISABLED, last_applied=None,
                  pending_intent=PendingIntent(ACTION, DISABLED, CAP),
                  allocated_floor=DEMAND, manifest_seq=1)
    return RecoveryManifest.create(**(values | changes))


class ProcessIdentityTests(unittest.TestCase):
    def test_full_filetime_roundtrip_and_pid_reuse(self):
        wire = IDENTITY.to_dict()
        self.assertEqual(wire["created_filetime_100ns"], "134343072000000001")
        self.assertEqual(ProcessIdentity.from_json(IDENTITY.to_json()), IDENTITY)
        # Adjacent ticks exceed JS integer precision but remain distinct identities.
        other = replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1)
        self.assertNotEqual(IDENTITY, other)
        self.assertNotEqual(IDENTITY.to_json(), other.to_json())

    def test_wire_filetime_requires_canonical_decimal_not_float_or_number(self):
        for bad in (IDENTITY.created_filetime_100ns, float(IDENTITY.created_filetime_100ns),
                    "+134343072000000001", "0134343072000000001", "1.0", "1e17", "-1", "0", "١", str(UINT64_MAX + 1)):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(ContractViolation):
                ProcessIdentity.from_dict(IDENTITY.to_dict() | {"created_filetime_100ns": bad})

    def test_constructor_rejects_approximate_identity_and_bool_pid(self):
        for changes in ({"pid": True}, {"pid": 0}, {"pid": 1 << 32},
                        {"created_filetime_100ns": float(IDENTITY.created_filetime_100ns)},
                        {"logon_id": ""}, {"logon_id": "logon\nprivate"}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                replace(IDENTITY, **changes)

    def test_unknown_identity_is_not_dead_and_requires_reason(self):
        with self.assertRaises(ContractViolation):
            IdentityObservation(IDENTITY, IdentityStatus.UNKNOWN)
        observed = IdentityObservation(IDENTITY, IdentityStatus.UNKNOWN, "access_denied")
        self.assertEqual(IdentityObservation.from_json(observed.to_json()), observed)
        self.assertIsNot(observed.status, IdentityStatus.DEAD)

    def test_records_are_immutable(self):
        with self.assertRaises(FrozenInstanceError):
            IDENTITY.pid = 3


class ResourceAndSpecTests(unittest.TestCase):
    def test_bytes_are_integer_cpu_finite_and_io_nonnegative(self):
        for name, value in (("cpu_units", float("nan")), ("cpu_units", float("inf")),
                            ("cpu_units", -1), ("cpu_units", True), ("physical_bytes", 1.5),
                            ("commit_bytes", -1), ("io_slots", True), ("io_slots", -1),
                            ("physical_bytes", UINT64_MAX + 1), ("physical_bytes", 1 << 63),
                            ("cpu_units", 1e308)):
            with self.subTest(name=name), self.assertRaises(ContractViolation):
                replace(DEMAND, **{name: value})
        # Large valid requests remain intact; admission decides host feasibility.
        self.assertEqual(ResourceDemand(1000, 128 * GIB, 128 * GIB, 0).physical_bytes, 128 * GIB)

    def test_execution_spec_roundtrip_version_and_unknown_fields(self):
        record = spec()
        self.assertEqual(ExecutionSpec.from_json(record.to_json()), record)
        for bad in (True, 0, 2, "1"):
            with self.subTest(version=bad), self.assertRaises(ContractViolation):
                ExecutionSpec.from_dict(record.to_dict() | {"schema_version": bad})
        for extra in ("command", "cwd", "env", "root_identity", "control_eligible"):
            with self.subTest(extra=extra), self.assertRaises(ContractViolation):
                ExecutionSpec.from_dict(record.to_dict() | {extra: "must not persist"})

    def test_nested_reference_is_exact_and_no_direct_double_allocation(self):
        nested = spec(reservation=ReservationRef(AllocationKind.PARENT, PARENT), parent_execution_id=PARENT)
        self.assertEqual(nested.reservation.id, PARENT)
        for changes in ({"parent_execution_id": PARENT},
                        {"reservation": ReservationRef(AllocationKind.PARENT, PARENT)},
                        {"parent_execution_id": EXECUTION, "reservation": ReservationRef(AllocationKind.PARENT, EXECUTION)}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                spec(**changes)

    def test_unknown_roles_priorities_and_allocation_kinds_rejected(self):
        record = spec().to_dict()
        for name, value in (("role", "interactive"), ("priority", "LIGHT"), ("priority", 2)):
            with self.subTest(name=name), self.assertRaises(ContractViolation):
                ExecutionSpec.from_dict(record | {name: value})
        with self.assertRaises(ContractViolation):
            ReservationRef.from_dict({"kind": "third_ledger", "id": "r"})

    def test_spec_hash_binds_command_cwd_resources_and_caller_without_disclosure(self):
        arguments = dict(key=b"K" * 32, command="tool --secret private-token", cwd="C:\\Private\\repo",
                         repo_identifier="repo-hash-a", requested=DEMAND, role=Role.BACKGROUND,
                         priority=Priority.P2, parent_execution_id=None, caller=IDENTITY)
        digest = make_spec_hash(**arguments)
        self.assertRegex(digest, r"^[a-f0-9]{64}$")
        self.assertEqual(digest, make_spec_hash(**arguments))
        # Cwd normalization does not rewrite shell syntax or argument quoting.
        self.assertEqual(digest, make_spec_hash(**(arguments | {"cwd": "c:/private/repo/."})))
        for changes in ({"command": "tool --secret another-token"}, {"cwd": "C:\\Other"},
                        {"repo_identifier": "repo-hash-b"}, {"requested": replace(DEMAND, commit_bytes=9 * GIB)},
                        {"role": Role.NEUTRAL}, {"priority": Priority.P3},
                        {"parent_execution_id": PARENT}, {"caller": replace(IDENTITY, created_filetime_100ns=IDENTITY.created_filetime_100ns + 1)},
                        {"key": b"L" * 32}):
            with self.subTest(changes=tuple(changes)):
                self.assertNotEqual(digest, make_spec_hash(**(arguments | changes)))
        stored = spec(spec_hash=digest).to_json()
        self.assertNotIn("private-token", stored)
        self.assertNotIn("Private", stored)
        self.assertNotIn("tool --secret", stored)
        for changes in ({"key": b"short"}, {"cwd": "relative"}, {"cwd": "C:relative"}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                make_spec_hash(**(arguments | changes))


class FastFrameTests(unittest.TestCase):
    def test_roundtrip_and_clock_ticks_use_decimal_strings(self):
        record = frame()
        self.assertEqual(FastFrame.from_json(record.to_json()), record)
        self.assertIsInstance(record.to_dict()["window_end_tick_100ns"], str)
        with self.assertRaises(ContractViolation):
            FastFrame.from_dict(record.to_dict() | {"window_end_tick_100ns": record.window_end_tick_100ns})

    def test_machine_bounds_reject_not_clamp(self):
        original = frame().machine
        for changes in ({"cpu_busy_units": 12.1}, {"cpu_busy_units": -0.1},
                        {"physical_available_bytes": 65 * GIB}, {"commit_used_bytes": 97 * GIB},
                        {"logical_processors": 0}, {"processor_groups": True}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                replace(original, **changes)

    def test_unknown_measurement_requires_null_validity_and_reason(self):
        incomplete = replace(frame().machine, commit_limit_bytes=None)
        error = FrameError("telemetry_stale", "machine", RetryClass.TRANSIENT)
        with self.assertRaises(ContractViolation):
            frame(machine=incomplete, errors=(error,))
        with self.assertRaises(ContractViolation):
            frame(machine=incomplete, validity=Validity.UNKNOWN)
        unknown = frame(machine=incomplete, validity=Validity.UNKNOWN, errors=(error,))
        self.assertIsNone(unknown.to_dict()["machine"]["commit_limit_bytes"])
        self.assertEqual(FastFrame.from_json(unknown.to_json()), unknown)

    def test_memory_unknown_can_coexist_with_valid_machine_but_not_silent(self):
        item = job(private_working_set_bytes=None, private_commit_bytes=None, memory_validity=Validity.UNKNOWN)
        with self.assertRaises(ContractViolation):
            frame(jobs=(item,))
        error = FrameError("memory_attribution_unavailable", "job", RetryClass.TRANSIENT, EXECUTION)
        self.assertIs(frame(jobs=(item,), errors=(error,)).validity, Validity.VALID)
        with self.assertRaises(ContractViolation):
            job(membership_complete=False)

    def test_bound_jobs_and_errors_without_process_lists(self):
        record = frame()
        with self.assertRaises(ContractViolation):
            replace(record, jobs=(job(), job()))
        with self.assertRaises(ContractViolation):
            FastFrame.from_dict(record.to_dict() | {"jobs": record.to_dict()["jobs"] * 11})
        with self.assertRaises(ContractViolation):
            FastFrame.from_dict(record.to_dict() | {"processes": []})
        with self.assertRaises(ContractViolation):
            replace(record, errors=(FrameError("db_busy", "registry", RetryClass.TRANSIENT),) * 65)

    def test_clock_order_and_timestamp_validation(self):
        record = frame()
        for changes in ({"window_start_tick_100ns": record.window_end_tick_100ns},
                        {"published_tick_100ns": record.window_end_tick_100ns - 1},
                        {"sample_seq": -1}, {"sampled_at_utc": "2026-09-19T03:00:00"},
                        {"collection_cost_ms": math.inf}, {"collection_skew_ms": math.nan}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                replace(record, **changes)

    def test_inconsistent_aggregate_is_preserved_for_accounting_to_zero_subtraction(self):
        # §7.2 requires per-resource zero subtraction, not truncated telemetry.
        record = frame(jobs=(job(cpu_units=11.5),))
        self.assertGreater(record.jobs[0].cpu_units, record.machine.cpu_busy_units)


class ControlAndRecoveryTests(unittest.TestCase):
    def test_disabled_and_hard_cap_are_distinct_typed_states(self):
        for mode, rate in ((CpuControlMode.DISABLED, 0), (CpuControlMode.DISABLED, 10000),
                           (CpuControlMode.HARD_CAP, None), (CpuControlMode.HARD_CAP, 0),
                           (CpuControlMode.HARD_CAP, 10001), (CpuControlMode.HARD_CAP, True)):
            with self.subTest(mode=mode), self.assertRaises(ContractViolation):
                CpuControl(mode, rate)
        self.assertEqual(CpuControl.from_json(DISABLED.to_json()), DISABLED)
        with self.assertRaises(ContractViolation):
            CpuControl.from_dict({"mode": "weight", "cpu_rate_bp": 10})

    def test_proposal_roundtrip_binds_all_epochs_and_has_no_pid_actuator(self):
        record = proposal()
        self.assertEqual(ControlProposal.from_json(record.to_json()), record)
        with self.assertRaises(ContractViolation):
            ControlProposal.from_dict(record.to_dict() | {"pid": 1})
        with self.assertRaises(ContractViolation):
            ControlProposal.from_dict(record.to_dict() | {"set_information_class": 9})

    def test_stale_proposal_and_helper_supplied_lease_rejected(self):
        for changes in ({"sample_window_end_tick_100ns": 7 * TICKS_PER_SECOND},
                        {"sample_window_end_tick_100ns": 12 * TICKS_PER_SECOND}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                proposal(**changes)
        # Safety restore remains representable when source telemetry is stale.
        self.assertEqual(proposal(target=RESTORE_TARGET, sample_window_end_tick_100ns=0).target, RESTORE_TARGET)
        with self.assertRaises(ContractViolation):
            ControlProposal.from_dict(proposal().to_dict() | {"lease_deadline_tick_100ns": "999999999999"})

    def test_target_includes_consistent_denominator_units_and_kind(self):
        for changes in ({"kind": "io_priority"}, {"target_cpu_units": math.inf},
                        {"target_cpu_units": 0}, {"target_cpu_units": 12},
                        {"denominator_logical_processors": None}, {"cpu_rate_bp": 2499}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                replace(TARGET, **changes)
        self.assertEqual(CpuTarget.from_json(TARGET.to_json()), TARGET)
        with self.assertRaises(ContractViolation):
            replace(RESTORE_TARGET, target_cpu_units=0)

    def test_guardian_lease_is_bounded_by_sample_and_original_intervention(self):
        # A one-second-old sample does not receive six fresh seconds from now.
        self.assertEqual(derive_lease_deadline(now_tick_100ns=11 * TICKS_PER_SECOND,
                         sample_window_end_tick_100ns=10 * TICKS_PER_SECOND,
                         intervention_deadline_tick_100ns=60 * TICKS_PER_SECOND), 16 * TICKS_PER_SECOND)
        self.assertEqual(derive_lease_deadline(now_tick_100ns=11 * TICKS_PER_SECOND,
                         sample_window_end_tick_100ns=10 * TICKS_PER_SECOND,
                         intervention_deadline_tick_100ns=12 * TICKS_PER_SECOND), 12 * TICKS_PER_SECOND)
        for sample, now, deadline in ((0, 4, 10), (12, 11, 60), (10, 11, 11), (10, 11, 72)):
            with self.subTest(now=now, deadline=deadline), self.assertRaises(ContractViolation):
                derive_lease_deadline(now_tick_100ns=now * TICKS_PER_SECOND,
                                      sample_window_end_tick_100ns=sample * TICKS_PER_SECOND,
                                      intervention_deadline_tick_100ns=deadline * TICKS_PER_SECOND)

    def test_manifest_roundtrip_and_pending_set_before_ack_recoverability(self):
        record = manifest()
        self.assertEqual(RecoveryManifest.from_json(record.to_json()), record)
        self.assertIsNone(record.last_applied)
        self.assertEqual(record.pending_intent.new, CAP)
        self.assertEqual(record.original, DISABLED)

    def test_manifest_integrity_detects_state_floor_nonce_identity_tampering(self):
        record = manifest().to_dict()
        for name, value in (("manifest_seq", 2), ("creation_nonce", "e" * 32),
                            ("allocated_floor", DEMAND.to_dict() | {"physical_bytes": 1}),
                            ("guardian_identity", IDENTITY.to_dict()),
                            ("last_applied", CAP.to_dict())):
            with self.subTest(name=name), self.assertRaises(ContractViolation):
                RecoveryManifest.from_dict(record | {name: value})

    def test_manifest_rejects_cross_logon_or_foreign_original(self):
        for changes in ({"guardian_identity": replace(IDENTITY, logon_id="logon-b")},
                        {"original": CAP}, {"job_name": "Global\\foreign"},
                        {"pending_intent": PendingIntent(ACTION, CAP, DISABLED)}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                manifest(**changes)

    def test_error_records_are_codes_not_raw_diagnostics(self):
        with self.assertRaises(ContractViolation):
            FrameError("raw command output", "api", RetryClass.NEVER)
        with self.assertRaises(ContractViolation):
            FrameError("api_set_failed", "api\nsecret", RetryClass.NEVER)


class JsonBoundaryTests(unittest.TestCase):
    def test_reject_duplicate_nonfinite_overflow_and_wrong_encoding(self):
        for payload in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}',
                        '{"x":1e9999}', b'\xff', '{"x":1}'.encode("utf-16"), '[]', '{'):
            with self.subTest(kind=type(payload).__name__), self.assertRaises(ContractViolation):
                strict_json_loads(payload)

    def test_message_and_nesting_bounds(self):
        with self.assertRaises(ContractViolation):
            strict_json_loads('{"x":"' + "a" * MAX_MESSAGE_BYTES + '"}')
        with self.assertRaises(ContractViolation):
            strict_json_loads('{"x":' + '[' * MAX_JSON_DEPTH + '0' + ']' * MAX_JSON_DEPTH + '}')
        # String contents, including escaped quotes, do not consume depth.
        brackets = '[' * 2000 + '\\"' + ']' * 2000
        self.assertEqual(strict_json_loads(json.dumps({"x": brackets}))["x"], brackets)

    def test_errors_do_not_echo_secret_values(self):
        secret = "secret-string-that-must-not-be-repeated"
        with self.assertRaises(ContractViolation) as caught:
            ExecutionSpec.from_dict(spec().to_dict() | {"command": secret})
        self.assertNotIn(secret, str(caught.exception))


class AcknowledgementTests(unittest.TestCase):
    def applied_ack(self, **changes):
        values = dict(request_id=ACTION, action_id=ACTION, execution_id=EXECUTION,
                      guardian_epoch="guardian-a", policy_epoch="policy-a", decision_seq=8,
                      result=ApplyResult.APPLIED, applied_flags=5, applied_rate_bp=2500,
                      applied_validity=Validity.VALID, queried_tick_100ns=11 * TICKS_PER_SECOND,
                      lease_deadline_tick_100ns=16 * TICKS_PER_SECOND,
                      intervention_deadline_tick_100ns=60 * TICKS_PER_SECOND,
                      reason="cpu_high", win32_error=None)
        return ApplyAck(**(values | changes))

    def test_applied_ack_requires_readback_and_same_action_for_renewal_field(self):
        ack = self.applied_ack()
        self.assertEqual(ApplyAck.from_json(ack.to_json()), ack)
        for changes in ({"applied_flags": None}, {"queried_tick_100ns": None},
                        {"applied_validity": Validity.UNKNOWN}, {"action_id": None},
                        {"applied_flags": 0}, {"win32_error": 5},
                        {"lease_deadline_tick_100ns": None}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ContractViolation):
                self.applied_ack(**changes)
        renewed = self.applied_ack(result=ApplyResult.RENEWED)
        self.assertEqual(renewed.action_id, ack.action_id)

    def test_restored_requires_disabled_readback_and_unverified_uses_null(self):
        ack = self.applied_ack(result=ApplyResult.RESTORED, applied_flags=0,
                              applied_rate_bp=10000, lease_deadline_tick_100ns=None)
        self.assertEqual(ApplyAck.from_json(ack.to_json()), ack)
        self.assertEqual(replace(ack, applied_flags=4, applied_rate_bp=0).result, ApplyResult.RESTORED)
        with self.assertRaises(ContractViolation):
            replace(ack, applied_flags=5)
        unknown = self.applied_ack(result=ApplyResult.UNVERIFIED, applied_flags=None,
                                  applied_rate_bp=None, applied_validity=Validity.UNKNOWN,
                                  queried_tick_100ns=None, lease_deadline_tick_100ns=None,
                                  win32_error=5)
        self.assertIsNone(unknown.to_dict()["applied_rate_bp"])
        # Restore outcome can be unverified despite a valid Query of the old cap.
        known_remaining_cap = self.applied_ack(result=ApplyResult.UNVERIFIED,
                                              lease_deadline_tick_100ns=None, win32_error=5)
        self.assertEqual(known_remaining_cap.applied_flags, 5)
        self.assertIs(known_remaining_cap.applied_validity, Validity.VALID)

    def test_grant_ack_keeps_original_expiry_and_pending_is_not_active(self):
        ack = GrantAck("grant-a", GrantState.RECORDED, 1789000000.25, 5,
                       EnforcementState.RESTORE_PENDING, (EXECUTION,))
        self.assertEqual(GrantAck.from_json(ack.to_json()), ack)
        self.assertEqual(ack.to_dict()["expires_at"], 1789000000.25)
        with self.assertRaises(ContractViolation):
            replace(ack, grant_state=GrantState.ACTIVE)

    def test_root_success_does_not_claim_job_empty_or_release(self):
        ack = LifecycleAck(EXECUTION, ReservationRef(AllocationKind.DIRECT, "r-a"),
                           LifecycleState.DRAINING, 5, LaunchClaimState.SEALED,
                           RootOutcome.SUCCESS, False)
        self.assertEqual(LifecycleAck.from_json(ack.to_json()), ack)
        with self.assertRaises(ContractViolation):
            replace(ack, state=LifecycleState.FINISHED)
        self.assertIs(replace(ack, state=LifecycleState.FINISHED, job_empty_verified=True).state,
                      LifecycleState.FINISHED)


if __name__ == "__main__":
    unittest.main()
