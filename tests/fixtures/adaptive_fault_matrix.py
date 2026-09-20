"""Coverage map from every section 9 fault row to real test evidence.

One entry per row of the section 9 table. Each row names existing test ids
(module.Class.test_name) with their 11.1 evidence level, or says UNVERIFIED
with the reason. A portable suite is L1 by construction, so only a test under
tests.windows may claim a native level; that rule is enforced here, not trusted.

An entry is a claim about what a named test proves. Where the reading of an
existing test was uncertain the row stays UNVERIFIED, and a row that is only
partly covered records the remaining gap.
"""
from __future__ import annotations

from dataclasses import dataclass
import importlib
import unittest

from tests.fixtures.adaptive_fault_record import EVIDENCE_LEVELS

UNVERIFIED = "UNVERIFIED"
NATIVE_MODULE_PREFIX = "tests.windows."


class FaultMatrixError(ValueError):
    """The map must fail loudly rather than overstate coverage."""


@dataclass(frozen=True)
class TestEvidence:
    """One existing test id and the level of evidence it can produce."""

    test_id: str
    level: str

    def __post_init__(self):
        parts = self.test_id.split(".")
        if len(parts) < 3:
            raise FaultMatrixError(f"{self.test_id} is not module.Class.test_name")
        module, class_name, method = ".".join(parts[:-2]), parts[-2], parts[-1]
        if not module.startswith("tests.") or not class_name[:1].isupper() \
                or not method.startswith("test_"):
            raise FaultMatrixError(f"{self.test_id} is not a tests.* module.Class.test_name id")
        if self.level not in EVIDENCE_LEVELS:
            raise FaultMatrixError(f"{self.test_id} has an unknown evidence level {self.level}")
        if self.level != "L1" and not module.startswith(NATIVE_MODULE_PREFIX):
            raise FaultMatrixError(f"{self.test_id} is portable, so it cannot claim {self.level}")

    @property
    def module(self):
        return ".".join(self.test_id.split(".")[:-2])

    def resolve(self):
        """Import the module and return the bound test method, or fail."""
        parts = self.test_id.split(".")
        try:
            module = importlib.import_module(".".join(parts[:-2]))
        except ImportError as error:
            raise FaultMatrixError(f"{self.test_id} module is missing: {error}") from error
        case = getattr(module, parts[-2], None)
        if not isinstance(case, type) or not issubclass(case, unittest.TestCase):
            raise FaultMatrixError(f"{self.test_id} does not name a TestCase class")
        method = getattr(case, parts[-1], None)
        if not callable(method):
            raise FaultMatrixError(f"{self.test_id} does not name a test method")
        return method


@dataclass(frozen=True)
class FaultRow:
    """One section 9 row: either test evidence or an explicit UNVERIFIED."""

    fault_id: str
    fault: str
    evidence: tuple = ()
    unverified_reason: str = ""
    gap: str = ""

    def __post_init__(self):
        if not self.fault_id or not self.fault:
            raise FaultMatrixError("a row needs a stable id and the section 9 label")
        object.__setattr__(self, "evidence", tuple(self.evidence))
        for item in self.evidence:
            if not isinstance(item, TestEvidence):
                raise FaultMatrixError(f"{self.fault_id} lists a non TestEvidence entry")
        if bool(self.evidence) == bool(self.unverified_reason):
            raise FaultMatrixError(
                f"{self.fault_id} needs either test evidence or an UNVERIFIED reason")

    @property
    def status(self):
        """UNVERIFIED, L1_ONLY, or NATIVE with the strongest level reached.

        The level is part of the word so that a row backed only by portable
        tests cannot be read as native evidence.
        """
        if self.unverified_reason:
            return UNVERIFIED
        strongest = max(item.level for item in self.evidence)
        return "L1_ONLY" if strongest == "L1" else "NATIVE_" + strongest

    @property
    def levels(self):
        return tuple(sorted({item.level for item in self.evidence}))


def _row(fault_id, fault, *evidence, gap=""):
    return FaultRow(fault_id, fault, tuple(evidence), gap=gap)


def _unverified(fault_id, fault, reason):
    return FaultRow(fault_id, fault, (), reason)


def _l1(test_id):
    return TestEvidence(test_id, "L1")


# Transcribed in section 9 table order. The unit test checks that the map has
# exactly these ids, in this order, so a new row cannot be silently dropped.
SECTION_NINE_ROWS = (
    ("helper_crash_or_stall", "helper crash／loop卡住"),
    ("guardian_crash", "guardian crash"),
    ("guardian_alive_ipc_lost", "guardian alive但IPC失聯"),
    ("wrapper_dies_before_prepared", "wrapper PREPARED前死"),
    ("wrapper_dies_launching", "wrapper LAUNCHING中死／ACK遺失"),
    ("wrapper_dies_running", "wrapper RUNNING中死"),
    ("root_exited_grandchild_alive", "root成功exit但grandchild存活"),
    ("collector_crash_timeout_restart", "collector crash／超時／重啟"),
    ("sentinel_db_busy", "sentinel.db busy／locked"),
    ("exemption_db_locked_or_corrupt", "exemption DB locked/corrupt"),
    ("disk_full_or_manifest_write_failure", "disk full／read-only／manifest寫失敗"),
    ("ipc_disconnect_duplicate_reorder_oversize", "IPC斷線／重複／亂序／過大message"),
    ("sleep_resume", "sleep/resume"),
    ("utc_clock_jump", "UTC clock jump"),
    ("pid_reuse_or_unreadable_birth", "PID reuse／birth讀不到"),
    ("grant_versus_set_race", "grant與Set競爭"),
    ("grant_on_one_child_of_the_job", "grant在同Job的一個child"),
    ("revoke_expiry_versus_old_decision", "revoke／expiry與舊decision競爭"),
    ("set_success_query_differs", "Set success但Query不同"),
    ("cap_present_effect_unprovable", "Query cap存在但CPU效果無法證明"),
    ("foreign_or_nested_job_dfss", "foreign/nested Job／DFSS"),
    ("topology_or_processor_group_change", "topology／processor group改變"),
    ("monitoring_cost_over_budget", "monitoring成本超預算"),
    ("old_binary_or_collector_restart", "old binary／old collector重新啟動"),
    ("external_program_changes_job_cap", "外部程式改Job cap"),
    ("all_recovery_owners_lost", "同時失去所有recovery owners"),
)

_ENTRIES = (
    _unverified(
        "helper_crash_or_stall", "helper crash／loop卡住",
        "no test drives a helper crash to a Query-confirmed disabled cap; "
        "tests.test_adaptive_recovery_timing models the guardian-loss clock only, "
        "so the 8s helper-loss deadline of 11.2 is NOT_MEASURED"),
    _row(
        "guardian_crash", "guardian crash",
        _l1("tests.test_adaptive_recovery_timing.RecoveryTimingEvidenceTests"
            ".test_late_observer_cannot_restart_guardian_loss_clock"),
        _l1("tests.test_adaptive_recovery_timing.RecoveryTimingEvidenceTests"
            ".test_exact_eight_seconds_passes_but_one_tick_later_fails"),
        gap="the 8s deadline is modeled from supplied observation times; no real "
            "guardian was killed on Windows and timed"),
    _row(
        "guardian_alive_ipc_lost", "guardian alive但IPC失聯",
        _l1("tests.test_adaptive_ipc.ServiceTests.test_native_peer_lost_after_proof_cannot_dispatch"),
        _l1("tests.test_adaptive_recovery_timing.RecoveryTimingEvidenceTests"
            ".test_forced_stop_uses_request_before_termination_not_marker_publish"),
        gap="the bounded grace before stopping the verified guardian is not measured "
            "against a live unresponsive peer"),
    _row(
        "wrapper_dies_before_prepared", "wrapper PREPARED前死",
        _l1("tests.test_adaptive_prelaunch.AdaptivePrelaunchTests"
            ".test_reserved_cancel_releases_only_exact_direct_or_routed_allocation"),
        _l1("tests.test_adaptive_prelaunch.AdaptivePrelaunchTests"
            ".test_prepared_empty_without_seal_or_never_started_evidence_retains_capacity")),
    _row(
        "wrapper_dies_launching", "wrapper LAUNCHING中死／ACK遺失",
        _l1("tests.test_adaptive_guardian_launch.GuardianLaunchTests"
            ".test_mark_prepared_committed_then_lost_ack_reuses_the_same_job"),
        _l1("tests.test_adaptive_lease_renewal.AdaptiveLeaseRenewalTests"
            ".test_expired_launch_in_flight_transitions_to_start_unknown"),
        gap="每個CreateProcess邊界 is covered natively only by the opt-in "
            "tests.windows launch suites, which do not run in this portable suite"),
    _row(
        "wrapper_dies_running", "wrapper RUNNING中死",
        _l1("tests.test_adaptive_guardian_lifecycle.GuardianLifecycleTests"
            ".test_dead_wrapper_does_not_require_managed_admission_or_release_live_root")),
    _row(
        "root_exited_grandchild_alive", "root成功exit但grandchild存活",
        _l1("tests.test_adaptive_guardian_restore.GuardianRestoreTests"
            ".test_reconcile_consumes_restore_when_root_exits_but_child_lives"),
        _l1("tests.test_adaptive_guardian_restore.GuardianRestoreTests"
            ".test_reconcile_restores_then_terminalizes_only_verified_empty_job")),
    _unverified(
        "collector_crash_timeout_restart", "collector crash／超時／重啟",
        "no test crashes or restarts the collector; tests.test_adaptive_legacy_writer_fence "
        "covers old and new writer fencing, which is a different claim"),
    _row(
        "sentinel_db_busy", "sentinel.db busy／locked",
        _l1("tests.test_adaptive_policy_fencing.AdaptivePolicyFencingTests"
            ".test_real_sqlite_busy_after_acquisition_denies_without_clearing_nonce"),
        _l1("tests.test_adaptive_supervisor.SupervisorTests"
            ".test_real_busy_is_retried_but_a_readable_schema_contradiction_is_sticky")),
    _row(
        "exemption_db_locked_or_corrupt", "exemption DB locked/corrupt",
        _l1("tests.test_adaptive_control_authority.S1ControlAuthorityTests"
            ".test_exemption_database_read_failure_withdraws_existing_cap"),
        _l1("tests.test_adaptive_legacy_writer.LegacyWriterTests"
            ".test_corrupt_revocation_is_not_interpreted_as_no_active_grant")),
    _row(
        "disk_full_or_manifest_write_failure", "disk full／read-only／manifest寫失敗",
        _l1("tests.test_adaptive_execution_owner.S1ExecutionOwnerTests"
            ".test_initial_journal_write_failure_never_creates_job_or_releases_floor"),
        _l1("tests.test_adaptive_guardian_restore.GuardianRestoreTests"
            ".test_journal_failure_before_publish_preserves_disabled_native_and_unsettled_slot"),
        gap="write failures are injected in process; no real full or read-only volume "
            "was used"),
    _row(
        "ipc_disconnect_duplicate_reorder_oversize", "IPC斷線／重複／亂序／過大message",
        _l1("tests.test_adaptive_ipc.FramingTests.test_invalid_length_is_rejected_before_body_read"),
        _l1("tests.test_adaptive_ipc.ServiceTests"
            ".test_replayed_mac_with_current_nonce_still_fails_authentication"),
        _l1("tests.test_adaptive_ipc.FramingTests"
            ".test_multiple_frames_share_one_deadline_without_partial_read_reset")),
    _row(
        "sleep_resume", "sleep/resume",
        _l1("tests.test_adaptive_power.PowerWitnessTests"
            ".test_each_suspend_resume_notification_invalidates_the_prior_token"),
        _l1("tests.test_adaptive_recovery.S1RecoveryTests"
            ".test_observed_suspend_discards_streak_and_invalidates_clock"),
        gap="no real machine sleep and resume cycle was executed"),
    _row(
        "utc_clock_jump", "UTC clock jump",
        _l1("tests.test_adaptive_decision.FailClosedTests.test_backwards_clock_is_refused"),
        _l1("tests.test_adaptive_machine_sampler.MachineSamplerTests"
            ".test_long_gap_and_clock_backward_rotate_continuity_and_require_fresh_endpoints")),
    _row(
        "pid_reuse_or_unreadable_birth", "PID reuse／birth讀不到",
        _l1("tests.test_adaptive_identity.IdentityTests"
            ".test_a_single_tick_pid_reuse_or_different_logon_rejected_and_closed"),
        _l1("tests.test_adaptive_control_authority.NativeGrantScopeFixtureTests"
            ".test_missing_birth_dead_process_and_reused_parent_remain_unknown"),
        gap="the bare-PID attack fixture of section 9 runs against in-process doubles"),
    _row(
        "grant_versus_set_race", "grant與Set競爭",
        _l1("tests.test_adaptive_control_authority.S1ControlAuthorityTests"
            ".test_new_grant_restores_existing_cap_before_rejecting_further_control"),
        _l1("tests.test_adaptive_control_authority.S1ControlAuthorityTests"
            ".test_capped_wait_observes_new_grant_between_polls_and_invalidates_window"),
        _l1("tests.test_adaptive_control_authority.S1ControlAuthorityTests"
            ".test_three_atomic_grants_and_repeat_keep_original_deadlines")),
    _row(
        "grant_on_one_child_of_the_job", "grant在同Job的一個child",
        _l1("tests.test_adaptive_control_authority.NativeGrantScopeFixtureTests"
            ".test_live_granted_job_member_protects_whole_job")),
    _row(
        "revoke_expiry_versus_old_decision", "revoke／expiry與舊decision競爭",
        _l1("tests.test_adaptive_exemption_sync.ExemptionSynchronizationTests"
            ".test_finite_revocation_removes_only_that_lease_and_permits_the_next_grant"),
        _l1("tests.test_adaptive_contracts.ControlAndRecoveryTests"
            ".test_stale_proposal_and_helper_supplied_lease_rejected")),
    _row(
        "set_success_query_differs", "Set success但Query不同",
        _l1("tests.test_adaptive_guardian_restore.GuardianRestoreTests"
            ".test_set_readback_still_enabled_does_not_publish_or_release"),
        _l1("tests.test_adaptive_native_job.NativeJobTests"
            ".test_set_readback_mismatch_retains_live_owner_without_restore_or_retry")),
    _unverified(
        "cap_present_effect_unprovable", "Query cap存在但CPU效果無法證明",
        "a saturated canary is L2 evidence; the S1 cpu_effect stage is blocked before "
        "setup by ContinuousAdmissionUnavailable, so no CPU effect was ever measured"),
    _row(
        "foreign_or_nested_job_dfss", "foreign/nested Job／DFSS",
        _l1("tests.test_adaptive_ci_host_probe.PublicHostProbeTests"
            ".test_zero_flags_do_not_make_foreign_job_supported"),
        _l1("tests.test_adaptive_ci_host_probe.PublicHostProbeTests"
            ".test_positive_topology_does_not_pass_other_gates"),
        gap="DFSS itself is UNVERIFIED: no test observes a DFSS host"),
    _row(
        "topology_or_processor_group_change", "topology／processor group改變",
        _l1("tests.test_adaptive_machine_sampler.MachineSamplerTests"
            ".test_topology_change_invalidates_pair_and_seeds_new_counter_epoch"),
        _l1("tests.test_adaptive_machine_sampler.MachineSamplerAbiTests"
            ".test_endpoint_read_detects_topology_change_with_fixed_bounded_queries"),
        gap="cap restore after a real processor group change was not exercised"),
    _unverified(
        "monitoring_cost_over_budget", "monitoring成本超預算",
        "no monitoring cost test exists; the P4 module tests/test_adaptive_cost_bounds.py "
        "is absent, so every 11.2 cost threshold is NOT_MEASURED"),
    _row(
        "old_binary_or_collector_restart", "old binary／old collector重新啟動",
        _l1("tests.test_adaptive_legacy_writer_fence.LegacyWriterFenceTests"
            ".test_old_direct_reuse_cannot_refresh_supported_row_without_revision_increment"),
        _l1("tests.test_adaptive_legacy_mode.LegacyManagedAccountingTests"
            ".test_unknown_routed_worker_cannot_reuse_by_claiming_v2")),
    _row(
        "external_program_changes_job_cap", "外部程式改Job cap",
        _l1("tests.test_adaptive_guardian_restore.GuardianRestoreTests"
            ".test_readable_conflicting_cpu_state_never_overwrites_external_value"),
        _l1("tests.test_adaptive_recovery.S1RecoveryTests"
            ".test_native_cap_changed_between_windows_keeps_hold")),
    _unverified(
        "all_recovery_owners_lost", "同時失去所有recovery owners",
        "no test removes helper, guardian and wrapper together; "
        "tests.test_adaptive_supervisor covers the independent supervisor in isolation, "
        "which is not the same claim"),
)

FAULT_MATRIX = {row.fault_id: row for row in _ENTRIES}
if len(FAULT_MATRIX) != len(_ENTRIES):
    raise FaultMatrixError("duplicate fault id in the section 9 map")


def render_markdown():
    """Render the map as a Markdown table for the release checklist."""
    lines = ["| Fault | Status | Evidence | Level | Reason / gap |",
             "|---|---|---|---|---|"]
    for fault_id, label in SECTION_NINE_ROWS:
        row = FAULT_MATRIX[fault_id]
        evidence = "<br>".join(item.test_id for item in row.evidence) or "-"
        levels = ", ".join(row.levels) or "-"
        note = row.unverified_reason or row.gap or "-"
        lines.append(f"| {label} | {row.status} | {evidence} | {levels} | {note} |")
    return "\n".join(lines)
