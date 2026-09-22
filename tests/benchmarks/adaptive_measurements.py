"""Strict arithmetic over bounded, native-producer observations for P6.

No API here measures Windows or authorizes a capability/promotion. There is no
JSON-to-measured conversion. A caller supplies typed observations; without an
explicit, trace-bound producer provenance receipt the resulting record remains
synthetic. A receipt identifies retained native artifacts, not their authenticity:
the actual Windows producer and later evidence verifier own that boundary.

All observation envelopes use one pinned monotonic_ns clock. Process CPU deltas
bracket the run (or the process's complete lifetime) and deliberately include the
bounded collection tails. Commit cost is the sum of observed per-process native
high-water values. Both are conservative measurements, never missing-to-zero
estimates. The UI statistic is posted-message dispatch delay; internal paint
timings are validated and retained but are not presented as visible screen delay.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from sentinel.adaptive.contracts import Priority, ProcessIdentity, Role
from tests.benchmarks.adaptive_ab import (
    BenchmarkDataError, EvidenceSource, FixedConditions, HeadroomAttribution,
    NativeCapInterval, OrderPosition, PairSlot, Preconditions, RunMetrics,
    RunRecord, Schedule, Variant, percentile, validate_schedule,
)


MAX_POINTS = 10000
MAX_PROCESSES = 1024
MAX_TRACE_BYTES = 16 * 1024 * 1024
MIB = 1024 * 1024
RESERVE_BYTES = 4 * 1024 * MIB


class MeasurementError(BenchmarkDataError):
    """Missing or contradictory evidence; no partial measured result is issued."""


def _require(condition, reason):
    if not condition:
        raise MeasurementError(reason)


def _integer(value, name, minimum=0, maximum=(1 << 63) - 1):
    _require(type(value) is int and minimum <= value <= maximum, f"{name}: invalid integer")


def _text(value, name):
    _require(type(value) is str and 0 < len(value) <= 200, f"{name}: invalid text")


def _digest(value, name):
    _require(type(value) is str and len(value) == 64
             and all(char in "0123456789abcdef" for char in value), f"{name}: invalid SHA256")


def _tuple(values, cls, name, maximum=MAX_POINTS, allow_empty=False):
    _require(type(values) is tuple and len(values) <= maximum
             and (allow_empty or bool(values)), f"{name}: bounded tuple required")
    _require(all(type(value) is cls for value in values), f"{name}: exact typed observations required")


def _identity(value):
    _require(type(value) is ProcessIdentity, "exact process identity required")


@dataclass(frozen=True)
class ArtifactPin:
    name: str
    sha256: str


@dataclass(frozen=True)
class SamplingPlan:
    """Cadences and collection envelopes pinned before the benchmark starts."""
    max_machine_gap_ns: int
    max_process_gap_ns: int
    max_ui_idle_gap_ns: int
    max_capture_span_ns: int
    sha256: str


@dataclass(frozen=True)
class UiSample:
    sequence: int
    enqueued_ns: int
    dispatch_ns: int
    paint_requested_ns: int
    paint_ns: int
    paint_finished_ns: int


@dataclass(frozen=True)
class UiTrace:
    identity: ProcessIdentity
    clock_id: str
    started_ns: int
    ended_ns: int
    outside_all_jobs: bool
    priority_class: int
    samples: tuple[UiSample, ...]
    cleanup_complete: bool
    artifact_name: str


@dataclass(frozen=True)
class DemandTrace:
    task_id: str
    execution_id: str
    root_identity: ProcessIdentity
    submitted_ns: int
    started_ns: int
    root_exited_ns: int
    finished_ns: int
    expected_units: int
    completed_units: int
    exit_code: int
    # Completed work units inside the precise managed Job/control scope. This
    # may honestly be zero for A0 or unmanaged work. It is NOT observation
    # completeness: all identities/counters/lifecycle proofs remain mandatory.
    covered_units: int
    scope_kind: str  # owned_job or verified_fixture_tree; never PID-only absence
    owner_identity: ProcessIdentity
    role: Role
    priority: Priority
    scope_artifact_name: str


@dataclass(frozen=True)
class MachineSample:
    clock_id: str
    capture_start_ns: int
    capture_end_ns: int
    physical_used_bytes: int
    physical_available_bytes: int
    commit_used_bytes: int
    commit_limit_bytes: int
    physical_attribution: HeadroomAttribution
    commit_attribution: HeadroomAttribution
    artifact_name: str


@dataclass(frozen=True)
class ProcessSample:
    identity: ProcessIdentity
    clock_id: str
    capture_start_ns: int
    capture_end_ns: int
    cpu_time_100ns: int
    private_commit_bytes: int
    peak_private_commit_bytes: int


@dataclass(frozen=True)
class ProcessTrace:
    identity: ProcessIdentity
    role: str  # monitor, wrapper, workload, probe
    task_id: str | None
    lifetime_start_ns: int
    lifetime_end_ns: int
    born_during_run: bool
    exited_during_run: bool
    # Birth and final CPU counters must be native retained-handle observations.
    samples: tuple[ProcessSample, ...]
    artifact_name: str


@dataclass(frozen=True)
class CapEvent:
    sequence: int
    execution_id: str
    writer_identity: ProcessIdentity
    observed_ns: int
    tick_100ns: int
    operation: str  # set or query
    flags: int
    rate_bp: int
    state: str
    succeeded: bool
    restore_requested_ns: int | None = None


@dataclass(frozen=True)
class CapAuditTrace:
    clock_id: str
    started_ns: int
    ended_ns: int
    writer_identities: tuple[ProcessIdentity, ...]
    execution_ids: tuple[str, ...]
    events: tuple[CapEvent, ...]
    complete_write_audit: bool
    complete_query_coverage: bool
    write_artifact_name: str
    query_artifact_name: str


@dataclass(frozen=True)
class StateInterval:
    clock_id: str
    state: str
    started_ns: int
    ended_ns: int


@dataclass(frozen=True)
class MembershipSample:
    """Actual IsProcessInJob(NULL) on the original still-live process handle."""
    identity: ProcessIdentity
    clock_id: str
    capture_start_ns: int
    capture_end_ns: int
    outside_all_jobs: bool
    process_alive: bool


@dataclass(frozen=True)
class MembershipTrace:
    identity: ProcessIdentity
    samples: tuple[MembershipSample, ...]
    complete_lifetime_scope_audit: bool
    artifact_name: str


@dataclass(frozen=True)
class GrantLease:
    """An explicitly authorized scoped lease observed from the original ledger.

    Deadline_ns is the original deadline correlated to this run's monotonic
    clock; original_deadline_utc_ns preserves the authority's original value.
    No field grants, renews, revokes, or changes a lease.
    """
    grant_id: str
    owner_identity: ProcessIdentity
    scope_execution_ids: tuple[str, ...]
    authorization_id: str
    granted_ns: int
    original_deadline_ns: int
    original_deadline_utc_ns: int
    revoked_ns: int | None
    artifact_name: str


@dataclass(frozen=True)
class GrantWindow:
    clock_id: str
    policy_instance_id: str
    epoch: str
    revision: int
    started_ns: int
    ended_ns: int
    leases: tuple[GrantLease, ...]
    complete_scope: bool


@dataclass(frozen=True)
class GrantAuditTrace:
    clock_id: str
    policy_instance_id: str
    epoch: str
    logon_id: str
    execution_ids: tuple[str, ...]
    started_ns: int
    ended_ns: int
    windows: tuple[GrantWindow, ...]
    complete_transition_audit: bool
    artifact_name: str


@dataclass(frozen=True)
class LifecycleProof:
    task_id: str
    execution_id: str
    scope_kind: str
    members: tuple[ProcessIdentity, ...]
    observed_empty_ns: int
    # No Job exists for verified_fixture_tree: None is required and native
    # membership proof is used instead of fabricating QueryJob(flags=0).
    observed_disabled_ns: int | None
    bookkeeping_settled: bool
    custody_cleanup_complete: bool
    artifact_name: str
    no_job_membership: tuple[MembershipTrace, ...]


@dataclass(frozen=True)
class ApiErrorObservation:
    clock_id: str
    observed_ns: int
    operation: str
    error_code: int
    artifact_name: str


@dataclass(frozen=True)
class RawRunTrace:
    run_id: str
    clock_id: str
    conditions: FixedConditions
    preconditions: Preconditions
    started_ns: int
    ended_ns: int
    sampling: SamplingPlan
    probe: UiTrace
    demands: tuple[DemandTrace, ...]
    machine: tuple[MachineSample, ...]
    monitor_identities: tuple[ProcessIdentity, ...]
    wrapper_identities: tuple[ProcessIdentity, ...]
    processes: tuple[ProcessTrace, ...]
    cap_audit: CapAuditTrace
    states: tuple[StateInterval, ...]
    grant_audit: GrantAuditTrace
    lifecycle: tuple[LifecycleProof, ...]
    api_errors: tuple[ApiErrorObservation, ...]
    artifacts: tuple[ArtifactPin, ...]


@dataclass(frozen=True)
class NativeRunProvenance:
    """Explicit producer receipt, not a security token or promotion permission.

    Only the concrete native producer should issue this after it has retained
    and hashed the listed artifacts. Deserializing a caller's declaration of
    'measured' never constructs this receipt automatically.
    """
    run_id: str
    clock_id: str
    trace_sha256: str
    producer_sha256: str
    host_sha256: str
    artifacts: tuple[ArtifactPin, ...]
    slot_id: str | None
    variant: Variant
    seed: str
    purpose: str  # comparison or noise_calibration; latter binds its distinct run_id


def trace_sha256(trace: RawRunTrace) -> str:
    _require(type(trace) is RawRunTrace, "typed raw trace required")
    try:
        payload = json.dumps(asdict(trace), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise MeasurementError("trace serialization invalid") from error
    _require(len(payload) <= MAX_TRACE_BYTES, "trace exceeds 16 MiB")
    return hashlib.sha256(payload).hexdigest()


def _window(start, end, name, allow_equal=False):
    _integer(start, f"{name} start")
    _integer(end, f"{name} end")
    _require(start <= end if allow_equal else start < end, f"{name}: invalid clock order")


def _capture(point, trace):
    _require(point.clock_id == trace.clock_id, "capture clock identity differs")
    _window(point.capture_start_ns, point.capture_end_ns, "capture", allow_equal=True)
    _require(point.capture_end_ns - point.capture_start_ns <= trace.sampling.max_capture_span_ns,
             "capture envelope exceeds pinned bound")


def _artifact_map(trace):
    _tuple(trace.artifacts, ArtifactPin, "artifacts", 256)
    result = {}
    for pin in trace.artifacts:
        _text(pin.name, "artifact name")
        _digest(pin.sha256, "artifact")
        _require(pin.name not in result, "duplicate artifact name")
        result[pin.name] = pin.sha256
    return result


def _has_artifact(name, artifacts):
    _require(type(name) is str and name in artifacts, "raw artifact pin missing")


def _validate_machine(trace, artifacts):
    _tuple(trace.machine, MachineSample, "machine samples")
    _require(len(trace.machine) >= 2, "machine endpoints missing")
    previous, physical_total = None, None
    for point in trace.machine:
        _capture(point, trace)
        _has_artifact(point.artifact_name, artifacts)
        for field in ("physical_used_bytes", "physical_available_bytes", "commit_used_bytes", "commit_limit_bytes"):
            _integer(getattr(point, field), field)
        _require(point.commit_used_bytes <= point.commit_limit_bytes, "Commit counters contradict")
        total = point.physical_used_bytes + point.physical_available_bytes
        _require(total > 0 and (physical_total is None or physical_total == total),
                 "physical capacity changed or counters contradict")
        physical_total = total
        for resource, value in (("physical", point.physical_available_bytes),
                                ("commit", point.commit_limit_bytes - point.commit_used_bytes)):
            attribution = getattr(point, f"{resource}_attribution")
            _require(type(attribution) is HeadroomAttribution
                     and attribution is not HeadroomAttribution.UNKNOWN, "headroom attribution unknown")
            _require(value >= RESERVE_BYTES or attribution is not HeadroomAttribution.WITHIN_RESERVE,
                     "reserve attribution contradicts raw value")
        if previous is not None:
            _require(point.capture_start_ns >= previous.capture_end_ns, "machine observations overlap or reverse")
            _require(point.capture_start_ns - previous.capture_end_ns <= trace.sampling.max_machine_gap_ns,
                     "machine temporal coverage gap")
        previous = point
    first, last = trace.machine[0], trace.machine[-1]
    _require(first.capture_end_ns <= trace.started_ns and last.capture_start_ns >= trace.ended_ns,
             "machine samples do not bracket complete run")
    _require(trace.started_ns - first.capture_end_ns <= trace.sampling.max_machine_gap_ns
             and last.capture_start_ns - trace.ended_ns <= trace.sampling.max_machine_gap_ns,
             "machine endpoint coverage stale")


def _validate_probe(trace, artifacts):
    probe = trace.probe
    _require(type(probe) is UiTrace, "typed UI trace required")
    _identity(probe.identity)
    _require(probe.clock_id == trace.clock_id, "UI clock identity differs")
    _window(probe.started_ns, probe.ended_ns, "UI lifetime")
    _require(probe.started_ns <= trace.started_ns and probe.ended_ns >= trace.ended_ns,
             "UI probe does not cover complete run")
    _require(probe.outside_all_jobs is True and type(probe.priority_class) is int
             and probe.priority_class == 0x20, "UI probe scope or Normal priority unverified")
    _require(probe.cleanup_complete is True, "UI cleanup unverified")
    _has_artifact(probe.artifact_name, artifacts)
    _tuple(probe.samples, UiSample, "UI samples")
    previous = None
    selected = []
    for index, point in enumerate(probe.samples, 1):
        _require(type(point.sequence) is int and point.sequence == index, "UI sequence incomplete")
        times = (point.enqueued_ns, point.dispatch_ns, point.paint_requested_ns,
                 point.paint_ns, point.paint_finished_ns)
        for value in times:
            _integer(value, "UI timestamp")
        _require(list(times) == sorted(times), "UI clock order invalid")
        _require(probe.started_ns <= times[0] and times[-1] <= probe.ended_ns, "UI sample outside probe lifetime")
        if previous is not None:
            _require(point.enqueued_ns >= previous.paint_finished_ns, "UI pairs overlap")
            _require(point.enqueued_ns - previous.paint_finished_ns <= trace.sampling.max_ui_idle_gap_ns,
                     "UI temporal coverage gap")
        if trace.started_ns <= point.enqueued_ns <= trace.ended_ns:
            selected.append((point.dispatch_ns - point.enqueued_ns) / 1_000_000.0)
        previous = point
    _require(bool(selected), "no UI observations during complete run")
    _require(probe.samples[0].enqueued_ns <= trace.started_ns + trace.sampling.max_ui_idle_gap_ns
             and probe.samples[-1].paint_finished_ns >= trace.ended_ns - trace.sampling.max_ui_idle_gap_ns,
             "UI endpoint coverage missing")
    return selected


def _validate_work(trace, artifacts):
    _tuple(trace.demands, DemandTrace, "demands", MAX_PROCESSES)
    _tuple(trace.lifecycle, LifecycleProof, "lifecycle", MAX_PROCESSES)
    _require(len(trace.demands) == trace.conditions.task_count, "task count differs from pinned conditions")
    demands, proofs = {}, {}
    for demand in trace.demands:
        _text(demand.task_id, "task ID")
        _text(demand.execution_id, "execution ID")
        _identity(demand.root_identity)
        _identity(demand.owner_identity)
        _require(type(demand.role) is Role and type(demand.priority) is Priority,
                 "demand role or priority unknown")
        _has_artifact(demand.scope_artifact_name, artifacts)
        _require(demand.task_id not in demands, "duplicate task identity")
        for field in ("submitted_ns", "started_ns", "root_exited_ns", "finished_ns", "expected_units",
                      "completed_units", "covered_units"):
            _integer(getattr(demand, field), field)
        _require(trace.started_ns <= demand.submitted_ns <= demand.started_ns
                 <= demand.root_exited_ns <= demand.finished_ns <= trace.ended_ns,
                 "workload timeline outside complete demand window")
        _require(demand.expected_units > 0 and demand.completed_units == demand.expected_units
                 and 0 <= demand.covered_units <= demand.completed_units, "workload completion or coverage unknown")
        _require(type(demand.exit_code) is int and demand.exit_code == 0, "workload exit unsuccessful")
        _require(demand.scope_kind in ("owned_job", "verified_fixture_tree"), "workload scope unverified")
        _require(demand.scope_kind != "verified_fixture_tree" or demand.covered_units == 0,
                 "unmanaged fixture tree cannot claim precise Job/control coverage")
        demands[demand.task_id] = demand
    _require(len({item.execution_id for item in trace.demands}) == len(demands), "duplicate execution identity")
    _require(min(item.submitted_ns for item in trace.demands) == trace.started_ns
             and max(item.finished_ns for item in trace.demands) == trace.ended_ns,
             "run window must include first demand through last surviving child completion")
    for proof in trace.lifecycle:
        _require(proof.task_id in demands and proof.task_id not in proofs, "lifecycle inventory differs")
        demand = demands[proof.task_id]
        _require(proof.execution_id == demand.execution_id and proof.scope_kind == demand.scope_kind,
                 "lifecycle scope identity differs")
        _tuple(proof.members, ProcessIdentity, "lifecycle members", MAX_PROCESSES)
        _require(len(set(proof.members)) == len(proof.members) and demand.root_identity in proof.members,
                 "lifecycle exact membership incomplete")
        _integer(proof.observed_empty_ns, "empty observation")
        _require(proof.observed_empty_ns >= demand.finished_ns,
                 "root exit cannot prove child cleanup")
        if demand.scope_kind == "owned_job":
            _integer(proof.observed_disabled_ns, "disabled observation")
            _require(proof.observed_disabled_ns >= demand.finished_ns,
                     "stale readback cannot prove child cleanup")
        else:
            _require(proof.observed_disabled_ns is None, "unmanaged tree has no Job disabled readback")
        _require(proof.bookkeeping_settled is True and proof.custody_cleanup_complete is True,
                 "lifecycle accounting or custody cleanup unsettled")
        _has_artifact(proof.artifact_name, artifacts)
        _tuple(proof.no_job_membership, MembershipTrace, "no-Job membership", MAX_PROCESSES, allow_empty=True)
        if demand.scope_kind == "owned_job":
            _require(not proof.no_job_membership, "owned Job cannot substitute no-Job membership proof")
        proofs[proof.task_id] = proof
    _require(set(proofs) == set(demands), "lifecycle proof missing")
    return demands, proofs


def _validate_processes(trace, artifacts, demands, proofs):
    _tuple(trace.processes, ProcessTrace, "process inventory", MAX_PROCESSES)
    _tuple(trace.monitor_identities, ProcessIdentity, "expected monitor inventory", MAX_PROCESSES)
    _tuple(trace.wrapper_identities, ProcessIdentity, "expected wrapper inventory", MAX_PROCESSES)
    _require(len(set(trace.monitor_identities + trace.wrapper_identities))
             == len(trace.monitor_identities) + len(trace.wrapper_identities),
             "expected infrastructure inventory duplicates identity")
    seen, members = set(), {key: set() for key in demands}
    monitor_cpu, monitor_commit, workload_commit = 0, 0, 0
    roles = set()
    for process in trace.processes:
        _identity(process.identity)
        _require(process.identity.logon_id == trace.probe.identity.logon_id, "process logon identity differs")
        _require(process.identity not in seen, "duplicate process identity or double accounting")
        seen.add(process.identity)
        _require(process.role in ("monitor", "wrapper", "workload", "probe"), "unknown process role")
        roles.add(process.role)
        _has_artifact(process.artifact_name, artifacts)
        _window(process.lifetime_start_ns, process.lifetime_end_ns, "process lifetime")
        _require(type(process.born_during_run) is bool and type(process.exited_during_run) is bool,
                 "process endpoint provenance unknown")
        _require(not process.born_during_run or process.lifetime_start_ns >= trace.started_ns,
                 "birth flag contradicts retained process lifetime")
        _require(not process.exited_during_run or process.lifetime_end_ns <= trace.ended_ns,
                 "exit flag contradicts retained process lifetime")
        lower = max(trace.started_ns, process.lifetime_start_ns)
        upper = min(trace.ended_ns, process.lifetime_end_ns)
        _require(lower < upper, "process does not overlap measured run")
        if process.lifetime_start_ns > trace.started_ns:
            _require(process.born_during_run, "process late enrollment misses CPU history")
        if process.lifetime_end_ns < trace.ended_ns:
            _require(process.exited_during_run, "process observation ended before workload")
        _tuple(process.samples, ProcessSample, "process samples")
        _require(len(process.samples) >= 2, "process counter endpoints missing")
        previous = None
        for point in process.samples:
            _capture(point, trace)
            _require(point.identity == process.identity, "process counter exact identity changed")
            for field in ("cpu_time_100ns", "private_commit_bytes", "peak_private_commit_bytes"):
                _integer(getattr(point, field), field)
            _require(point.peak_private_commit_bytes >= point.private_commit_bytes,
                     "native private Commit peak contradicts current counter")
            if previous is not None:
                _require(point.capture_start_ns >= previous.capture_end_ns, "process observations reverse")
                _require(point.capture_start_ns - previous.capture_end_ns <= trace.sampling.max_process_gap_ns,
                         "process temporal coverage gap")
                _require(point.cpu_time_100ns >= previous.cpu_time_100ns
                         and point.peak_private_commit_bytes >= previous.peak_private_commit_bytes,
                         "process counter epoch reset")
            previous = point
        first, last = process.samples[0], process.samples[-1]
        if process.born_during_run:
            _require(first.capture_start_ns >= process.lifetime_start_ns
                     and first.capture_end_ns - process.lifetime_start_ns <= trace.sampling.max_process_gap_ns,
                     "native birth counter missing")
            cpu = last.cpu_time_100ns  # Native lifetime counter, no guessed initial zero.
        else:
            _require(first.capture_end_ns <= lower and lower - first.capture_end_ns <= trace.sampling.max_process_gap_ns,
                     "initial process counter does not bracket run")
            cpu = last.cpu_time_100ns - first.cpu_time_100ns
        _require(last.capture_start_ns >= upper
                 and last.capture_start_ns - upper <= trace.sampling.max_process_gap_ns,
                 "final process counter does not bracket full lifetime")
        peak = max(point.peak_private_commit_bytes for point in process.samples)
        if process.role in ("monitor", "wrapper"):
            _require(process.task_id is None or process.task_id in demands, "monitor task identity unknown")
            monitor_cpu += cpu
            monitor_commit += peak
        elif process.role == "workload":
            _require(process.task_id in demands, "workload counter without exact task membership")
            demand = demands[process.task_id]
            _require(process.born_during_run and process.exited_during_run
                     and demand.started_ns <= process.lifetime_start_ns
                     and process.lifetime_end_ns <= demand.finished_ns,
                     "workload membership or surviving-child lifetime incomplete")
            if process.identity == demand.root_identity:
                _require(process.lifetime_end_ns == demand.root_exited_ns,
                         "root exit differs from retained process observation")
            members[process.task_id].add(process.identity)
            workload_commit += peak
        else:
            _require(process.identity == trace.probe.identity and process.task_id is None, "UI process identity differs")
    _require("monitor" in roles and "probe" in roles, "monitor or UI process coverage absent")
    _require({item.identity for item in trace.processes if item.role == "monitor"}
             == set(trace.monitor_identities), "monitor counter inventory incomplete")
    _require({item.identity for item in trace.processes if item.role == "wrapper"}
             == set(trace.wrapper_identities), "wrapper counter inventory incomplete")
    for task_id, proof in proofs.items():
        _require(members[task_id] == set(proof.members), "process costs do not cover exact lifecycle members")
        _require(demands[task_id].owner_identity in seen, "original scoped owner absent from exact observed inventory")
    return monitor_cpu, monitor_commit, workload_commit


def _validate_no_job_membership(trace, artifacts, demands, proofs):
    processes = {item.identity: item for item in trace.processes}
    for task_id, demand in demands.items():
        if demand.scope_kind != "verified_fixture_tree":
            continue
        proof = proofs[task_id]
        _require({item.identity for item in proof.no_job_membership} == set(proof.members)
                 and len(proof.no_job_membership) == len(proof.members),
                 "unmanaged tree requires original membership observations for every member")
        for member in proof.no_job_membership:
            _identity(member.identity)
            _require(member.complete_lifetime_scope_audit is True, "native membership lifetime coverage unknown")
            _has_artifact(member.artifact_name, artifacts)
            _tuple(member.samples, MembershipSample, "native membership samples")
            _require(len(member.samples) >= 2, "native membership endpoints missing")
            process = processes[member.identity]
            previous = None
            for sample in member.samples:
                _capture(sample, trace)
                _require(sample.identity == member.identity, "native membership process identity changed")
                _require(sample.outside_all_jobs is True and sample.process_alive is True,
                         "live native IsProcessInJob(NULL)=False not established")
                _require(process.lifetime_start_ns <= sample.capture_start_ns
                         and sample.capture_end_ns <= process.lifetime_end_ns,
                         "membership observation outside original live lifetime")
                if previous is not None:
                    _require(sample.capture_start_ns >= previous.capture_end_ns
                             and sample.capture_start_ns - previous.capture_end_ns
                             <= trace.sampling.max_process_gap_ns, "native membership coverage gap")
                previous = sample
            _require(member.samples[0].capture_end_ns - process.lifetime_start_ns
                     <= trace.sampling.max_capture_span_ns
                     and process.lifetime_end_ns - member.samples[-1].capture_start_ns
                     <= trace.sampling.max_capture_span_ns,
                     "native membership birth or last-live endpoint missing")


def _validate_grants(trace, artifacts, demands):
    audit = trace.grant_audit
    _require(type(audit) is GrantAuditTrace and audit.clock_id == trace.clock_id,
             "grant audit clock or schema unknown")
    _text(audit.policy_instance_id, "grant policy instance")
    _text(audit.epoch, "grant epoch")
    _require(audit.logon_id == trace.probe.identity.logon_id, "grant logon differs")
    _tuple(audit.execution_ids, str, "grant scoped inventory", MAX_PROCESSES)
    _require(len(set(audit.execution_ids)) == len(audit.execution_ids)
             and set(audit.execution_ids) == {item.execution_id for item in demands.values()},
             "grant execution scope unknown or incomplete")
    _window(audit.started_ns, audit.ended_ns, "grant audit")
    _require(audit.started_ns <= trace.cap_audit.started_ns and audit.ended_ns >= trace.cap_audit.ended_ns
             and audit.complete_transition_audit is True, "grant revision coverage incomplete")
    _has_artifact(audit.artifact_name, artifacts)
    _tuple(audit.windows, GrantWindow, "grant windows")
    cursor, previous_revision, previous_leases = audit.started_ns, None, None
    seen = {}
    executions = {item.execution_id: item for item in demands.values()}
    for window in audit.windows:
        _require(window.clock_id == audit.clock_id and window.policy_instance_id == audit.policy_instance_id
                 and window.epoch == audit.epoch and window.complete_scope is True,
                 "grant scope or epoch unknown")
        _integer(window.revision, "grant revision")
        _window(window.started_ns, window.ended_ns, "grant window")
        _require(window.started_ns == cursor and window.ended_ns <= audit.ended_ns,
                 "grant temporal coverage gap")
        _tuple(window.leases, GrantLease, "scoped grant leases", 3, allow_empty=True)
        _require(len({lease.grant_id for lease in window.leases}) == len(window.leases), "duplicate grant identity")
        if previous_revision is not None:
            _require(window.revision >= previous_revision, "grant revision regressed")
            _require(window.revision != previous_revision or window.leases == previous_leases,
                     "grant snapshot changed without revision")
        for lease in window.leases:
            _text(lease.grant_id, "grant ID")
            _identity(lease.owner_identity)
            _text(lease.authorization_id, "explicit grant authorization")
            _tuple(lease.scope_execution_ids, str, "grant lease scope", MAX_PROCESSES)
            _require(len(set(lease.scope_execution_ids)) == len(lease.scope_execution_ids)
                     and set(lease.scope_execution_ids).issubset(executions), "grant lease scope unknown")
            _require(all(executions[identity].owner_identity == lease.owner_identity
                         for identity in lease.scope_execution_ids), "grant original owner identity differs")
            _require(set(lease.scope_execution_ids) == {identity for identity, demand in executions.items()
                                                       if demand.owner_identity == lease.owner_identity},
                     "grant omits an execution with the same original owner")
            _window(lease.granted_ns, lease.original_deadline_ns, "original grant deadline")
            _integer(lease.original_deadline_utc_ns, "original UTC deadline", 1)
            _has_artifact(lease.artifact_name, artifacts)
            if lease.revoked_ns is not None:
                _integer(lease.revoked_ns, "grant revocation", lease.granted_ns)
            stable = (lease.owner_identity, lease.scope_execution_ids, lease.authorization_id, lease.granted_ns,
                      lease.original_deadline_ns, lease.original_deadline_utc_ns, lease.artifact_name)
            if lease.grant_id in seen:
                old_stable, old_lease = seen[lease.grant_id]
                _require(stable == old_stable, "original grant identity or deadline changed")
                _require(old_lease.revoked_ns is None or old_lease.revoked_ns == lease.revoked_ns,
                         "grant revocation reversed or changed")
            seen[lease.grant_id] = stable, lease
        cursor, previous_revision, previous_leases = window.ended_ns, window.revision, window.leases
    _require(cursor == audit.ended_ns, "grant audit endpoint missing")
    return tuple(item[1] for item in seen.values())


def _validate_caps(trace, artifacts, demands, proofs, grants):
    audit = trace.cap_audit
    _require(type(audit) is CapAuditTrace and audit.clock_id == trace.clock_id, "cap audit clock unknown")
    _window(audit.started_ns, audit.ended_ns, "cap audit")
    _require(audit.started_ns <= trace.started_ns and audit.ended_ns >= trace.ended_ns,
             "cap audit does not cover complete demand window")
    _require(audit.complete_write_audit is True and audit.complete_query_coverage is True,
             "complete native write audit and Query coverage required")
    owned = {item.execution_id: item for item in demands.values() if item.scope_kind == "owned_job"}
    _tuple(audit.writer_identities, ProcessIdentity, "cap writers", 32, allow_empty=not owned)
    _require(len(set(audit.writer_identities)) == len(audit.writer_identities), "duplicate cap writer identity")
    _tuple(audit.execution_ids, str, "cap execution inventory", MAX_PROCESSES, allow_empty=True)
    _require(len(set(audit.execution_ids)) == len(audit.execution_ids)
             and set(audit.execution_ids) == set(owned),
             "cap audit execution inventory incomplete")
    _has_artifact(audit.write_artifact_name, artifacts)
    _has_artifact(audit.query_artifact_name, artifacts)
    _tuple(audit.events, CapEvent, "cap events", allow_empty=not owned)
    _require(set(audit.writer_identities).issubset(set(trace.monitor_identities + trace.wrapper_identities)),
             "cap writer absent from cost inventory")
    current, opened, first_query, last_query, intervals, restore_times = {}, {}, {}, {}, [], []
    pending_write = set()
    previous_ns, previous_tick = -1, -1
    restore_request = {}
    for index, event in enumerate(audit.events, 1):
        _require(type(event.sequence) is int and event.sequence == index, "cap event sequence incomplete")
        _require(event.execution_id in audit.execution_ids and event.writer_identity in audit.writer_identities,
                 "cap writer or execution exact identity differs")
        _integer(event.observed_ns, "cap observed timestamp")
        _integer(event.tick_100ns, "cap native timestamp")
        _require(audit.started_ns <= event.observed_ns <= audit.ended_ns
                 and event.observed_ns >= previous_ns and event.tick_100ns >= previous_tick,
                 "cap event clock order invalid")
        if previous_ns >= 0:
            _require(abs((event.tick_100ns - previous_tick) * 100
                         - (event.observed_ns - previous_ns)) <= 2 * trace.sampling.max_capture_span_ns,
                     "cap native and observer clock deltas disagree")
        _require(event.operation in ("set", "query") and event.succeeded is True, "cap API outcome unknown or failed")
        _integer(event.flags, "cap flags", 0, (1 << 32) - 1)
        _integer(event.rate_bp, "cap rate", 0, 10000)
        _text(event.state, "cap state")
        _require(not event.flags & 1 or event.rate_bp > 0, "enabled cap rate missing")
        identity = event.execution_id
        if event.restore_requested_ns is not None:
            _integer(event.restore_requested_ns, "restore request")
            _require(event.restore_requested_ns <= event.observed_ns, "restore request occurs after observation")
            restore_request.setdefault(identity, event.restore_requested_ns)
        if event.operation == "query":
            if identity in current:
                _require(current[identity] == (event.flags, event.rate_bp), "native readback differs from write audit")
            else:
                _require(not event.flags & 1 and event.observed_ns <= trace.started_ns,
                         "initial native disabled readback missing")
                current[identity] = (event.flags, event.rate_bp)
            first_query.setdefault(identity, event)
            last_query[identity] = event
            pending_write.discard(identity)
            if not event.flags & 1 and identity in restore_request:
                restore_times.append((event.observed_ns - restore_request.pop(identity)) / 1e9)
        else:
            _require(identity in first_query, "native Set precedes initial scope audit")
            _require(identity not in pending_write, "native Set has no matching readback")
            pending_write.add(identity)
            if identity in opened:
                old = opened.pop(identity)
                for grant in grants:
                    if identity not in grant.scope_execution_ids:
                        continue
                    until = min(grant.original_deadline_ns, grant.revoked_ns
                                if grant.revoked_ns is not None else grant.original_deadline_ns)
                    overlaps = (old.observed_ns < until and event.observed_ns > grant.granted_ns)
                    if old.observed_ns == event.observed_ns:
                        overlaps = grant.granted_ns <= old.observed_ns < until
                    _require(not overlaps, "native cap overlaps live explicitly authorized grant")
                intervals.append(NativeCapInterval(identity, old.tick_100ns, event.tick_100ns,
                                                    old.flags, old.rate_bp, old.state))
            current[identity] = (event.flags, event.rate_bp)
            if event.flags & 1:
                _require(owned[identity].role is Role.BACKGROUND
                         and owned[identity].priority in (Priority.P2, Priority.P3),
                         "native cap targeted protected, neutral or foreground-priority work")
                opened[identity] = event
        previous_ns, previous_tick = event.observed_ns, event.tick_100ns
    _require(not opened and not restore_request and not pending_write,
             "cap, readback or restore remains outstanding")
    for identity in audit.execution_ids:
        _require(identity in first_query and identity in last_query
                 and last_query[identity].observed_ns >= trace.ended_ns
                 and not last_query[identity].flags & 1, "final native disabled readback missing")
    for proof in proofs.values():
        if proof.scope_kind == "owned_job":
            _require(last_query[proof.execution_id].observed_ns >= proof.observed_disabled_ns,
                     "lifecycle disabled proof absent from native readback trace")
    return tuple(intervals), max(restore_times) if restore_times else None


def reduce_metrics(trace: RawRunTrace) -> RunMetrics:
    """Reduce runs/repeats; private Commit is a sum-of-peaks upper bound.

    The upper bound is not a simultaneous batch peak. Raw per-process samples
    stay available so the report can distinguish them from machine physical use.
    """
    _require(type(trace) is RawRunTrace, "typed raw trace required")
    _text(trace.run_id, "run ID")
    _text(trace.clock_id, "monotonic clock identity")
    raw_digest = trace_sha256(trace)
    _require(type(trace.conditions) is FixedConditions and type(trace.preconditions) is Preconditions,
             "fixed conditions or preconditions missing")
    _require(trace.conditions.thermal_or_power_anomaly is False,
             "thermal or power anomaly invalidates paired measurement")
    _require(all(value is True for value in asdict(trace.preconditions).values()),
             "between-run preconditions not independently verified")
    _window(trace.started_ns, trace.ended_ns, "complete run")
    _require(type(trace.sampling) is SamplingPlan, "pinned sampling plan missing")
    for field in ("max_machine_gap_ns", "max_process_gap_ns", "max_ui_idle_gap_ns", "max_capture_span_ns"):
        _integer(getattr(trace.sampling, field), field, 1, 60 * 1000000000)
    _digest(trace.sampling.sha256, "sampling plan")
    artifacts = _artifact_map(trace)
    _validate_machine(trace, artifacts)
    ui = _validate_probe(trace, artifacts)
    demands, proofs = _validate_work(trace, artifacts)
    cpu, monitor_commit, workload_commit = _validate_processes(trace, artifacts, demands, proofs)
    _validate_no_job_membership(trace, artifacts, demands, proofs)
    _require(type(trace.cap_audit) is CapAuditTrace, "typed cap audit required")
    grants = _validate_grants(trace, artifacts, demands)
    intervals, restore = _validate_caps(trace, artifacts, demands, proofs, grants)
    _tuple(trace.states, StateInterval, "control states")
    state_times, cursor = {}, trace.started_ns
    for state in trace.states:
        _require(state.clock_id == trace.clock_id and state.started_ns == cursor, "control state coverage gap")
        _text(state.state, "state")
        _window(state.started_ns, state.ended_ns, "state")
        _require(state.ended_ns <= trace.ended_ns, "control state exceeds run")
        state_times[state.state] = state_times.get(state.state, 0) + (state.ended_ns - state.started_ns) / 1e9
        cursor = state.ended_ns
    _require(cursor == trace.ended_ns, "control state endpoint missing")
    _tuple(trace.api_errors, ApiErrorObservation, "API errors", allow_empty=True)
    for error in trace.api_errors:
        _integer(error.observed_ns, "API error observation")
        _require(error.clock_id == trace.clock_id and trace.started_ns <= error.observed_ns <= trace.ended_ns,
                 "API error clock outside run")
        _text(error.operation, "API operation")
        _integer(error.error_code, "API error code", 1, (1 << 32) - 1)
        _has_artifact(error.artifact_name, artifacts)
    physical = min(trace.machine, key=lambda point: point.physical_available_bytes)
    commit = min(trace.machine, key=lambda point: point.commit_limit_bytes - point.commit_used_bytes)
    def attribution(resource):
        deficits = {getattr(point, f"{resource}_attribution") for point in trace.machine
                    if (point.physical_available_bytes if resource == "physical" else
                        point.commit_limit_bytes - point.commit_used_bytes) < RESERVE_BYTES}
        if HeadroomAttribution.NEW_ADMISSION in deficits:
            return HeadroomAttribution.NEW_ADMISSION
        if not deficits:
            return HeadroomAttribution.WITHIN_RESERVE
        return next(iter(deficits)) if len(deficits) == 1 else HeadroomAttribution.MIXED_EXTERNAL
    waits = [(item.started_ns - item.submitted_ns) / 1e9 for item in trace.demands]
    seconds = (trace.ended_ns - trace.started_ns) / 1e9
    units = sum(item.completed_units for item in trace.demands)
    return RunMetrics(
        foreground_p50_ms=percentile(ui, 50), foreground_p95_ms=percentile(ui, 95),
        foreground_p99_ms=percentile(ui, 99), makespan_s=seconds,
        completed_units_per_min=units * 60 / seconds,
        queue_wait_p50_s=percentile(waits, 50), queue_wait_p95_s=percentile(waits, 95),
        time_in_state_s=tuple(state_times.items()), peak_private_commit_mib=workload_commit / MIB,
        peak_physical_mib=max(point.physical_used_bytes for point in trace.machine) / MIB,
        min_physical_headroom_mib=physical.physical_available_bytes / MIB,
        min_commit_headroom_mib=(commit.commit_limit_bytes - commit.commit_used_bytes) / MIB,
        monitor_cpu_units=cpu / 1e7 / seconds, monitor_commit_mib=monitor_commit / MIB,
        api_errors=len(trace.api_errors), restore_time_s=restore,
        coverage_fraction=sum(item.covered_units for item in trace.demands) / units,
        physical_headroom_attribution=attribution("physical"),
        commit_headroom_attribution=attribution("commit"),
        physical_headroom_evidence_id=f"raw-physical:{raw_digest}",
        commit_headroom_evidence_id=f"raw-commit:{raw_digest}",
        native_cap_intervals=intervals, native_cap_audit_complete=True,
        native_cap_write_audit_sha256=artifacts[trace.cap_audit.write_artifact_name],
        native_cap_readback_sha256=artifacts[trace.cap_audit.query_artifact_name])


def verify_native_provenance(trace: RawRunTrace, provenance: NativeRunProvenance, *,
                             slot: PairSlot | None = None, variant: Variant | None = None,
                             seed: str | None = None, purpose: str = "noise_calibration") -> None:
    """Verify an explicit producer receipt without inventing comparison slots.

    Calibration run_id must be the orchestrator's independently derived episode
    identity (registration/comparison/scenario/pair/repeat/variant). The caller
    checks that expected run_id before entering here. Optional variant/seed
    arguments additionally compare the receipt to that preregistered episode.
    This only verifies bindings, not whether the producer really called Windows.
    """
    _require(type(trace) is RawRunTrace, "typed raw trace required")
    digest = trace_sha256(trace)
    _require(type(provenance) is NativeRunProvenance, "typed native provenance receipt required")
    _require(provenance.run_id == trace.run_id and provenance.clock_id == trace.clock_id
             and provenance.trace_sha256 == digest and provenance.artifacts == trace.artifacts,
             "native provenance not bound to this raw trace")
    _require(purpose in ("noise_calibration", "comparison") and provenance.purpose == purpose,
             "native evidence purpose differs")
    _require(type(provenance.variant) is Variant, "native variant identity invalid")
    _text(provenance.seed, "native schedule seed")
    _require(variant is None or provenance.variant is variant, "native variant differs from episode")
    _require(seed is None or provenance.seed == seed, "native seed differs from episode")
    if purpose == "comparison":
        _require(type(slot) is PairSlot and provenance.slot_id == slot.slot_id,
                 "native provenance slot identity differs")
    else:
        _require(slot is None and provenance.slot_id is None, "calibration cannot claim comparison slot")
    _digest(provenance.producer_sha256, "native producer")
    _digest(provenance.host_sha256, "native host")


def reduce_run(trace: RawRunTrace, *, schedule: Schedule, slot: PairSlot,
               variant: Variant, provenance: NativeRunProvenance | None = None) -> RunRecord:
    validate_schedule(schedule)
    _require(type(slot) is PairSlot and slot in schedule.slots, "slot absent from pinned schedule")
    _require(type(variant) is Variant and variant in (slot.first_variant, slot.second_variant),
             "variant absent from comparison")
    metrics = reduce_metrics(trace)
    digest = trace_sha256(trace)
    evidence = EvidenceSource.SYNTHETIC
    if provenance is not None:
        verify_native_provenance(trace, provenance, slot=slot, variant=variant, seed=schedule.seed,
                                 purpose="comparison")
        evidence = EvidenceSource.MEASURED
    return RunRecord(
        run_id=trace.run_id, scenario=slot.scenario, scenario_class=slot.scenario_class,
        variant=variant, pair_index=slot.pair_index,
        order_position=OrderPosition.FIRST if variant is slot.first_variant else OrderPosition.SECOND,
        seed=schedule.seed, evidence_source=evidence, conditions=trace.conditions,
        preconditions=trace.preconditions, metrics=metrics, comparison=slot.comparison, slot_id=slot.slot_id,
        note=f"raw trace {digest}; CPU includes bounded collection tails; private Commit is sum-of-process-peaks "
             "upper bound, not simultaneous peak; "
             "native artifact authenticity and promotion remain outside this reducer")
