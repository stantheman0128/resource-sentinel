"""One preregistered P6 matrix and its original native experiment custody.

This is deliberately a serial experiment coordinator, not an actuator, plugin
loader or replacement admission controller. Native authority comes only from
the real daily provider's in-process P6 bridge. JSON files describe plans and
observations; they never construct that bridge or authorize a control write.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import heapq
import json
import math
import os
from pathlib import Path
import re
import time
from uuid import UUID, uuid4, uuid5

from tests.benchmarks.adaptive_ab import (
    COMPARISON_VARIANTS, CacheState, Comparison, DEFAULT_SCENARIOS, EvidenceSource,
    HeadroomAttribution, NEUTRAL_RULE_SCENARIOS,
    MIN_PAIRS_PER_SCENARIO, NoiseEvidence, ScenarioClass, Variant, Verdict,
    analyze_comparison, build_schedule, overall_verdict, render_report,
    run_record_to_dict,
)


SCHEMA_VERSION = 1
MAX_PAIRS = 100
MAX_ARTIFACT_BYTES = 16 << 20
MAX_EPISODE_EVENTS = 24
CALIBRATION_PAIRS = 10
_UUID_NAMESPACE = UUID("d8185a28-70ee-4c1d-b229-fa3a4973cc9e")
_SAFE_REASON = re.compile(r"[a-z][a-z0-9_.:]{0,127}\Z")


class MatrixUnavailable(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class MatrixUnsettled(MatrixUnavailable):
    """An original pass/episode owner that cannot be replaced after uncertainty."""
    def __init__(self, owner, episode=None, *, cause=None, unverified_custody=None,
                 retained_coverage=None, owner_closed=False):
        self.owner, self.episode, self.primary = owner, episode, cause
        self.unverified_custody = unverified_custody
        self.retained_coverage = retained_coverage
        self.owner_closed = owner_closed
        super().__init__("p6_original_custody_unsettled")

    def recover_once(self):
        if not self.owner_closed:
            if self.episode is not None and self.episode.cleanup_complete is not True:
                self.episode.restore_and_drain()
            self.owner.recover_once()
            if self.episode is not None and self.episode.cleanup_complete is not True:
                return False
            if self.unverified_custody is not None or custody_unsettled(self.owner):
                return False
            self.owner.close()
            if custody_unsettled(self.owner):
                return False
            self.owner_closed = True
        if self.unverified_custody is not None:
            return False
        # The pass must settle its original daily authority as well. Preserve
        # that object until this is observed; do not invent an ownership transfer
        # or call guessed cleanup methods on a different native API.
        return not coverage_custody_unsettled(self.retained_coverage)


def custody_unsettled(owner):
    """Only exact False is settlement; missing/failed metadata retains custody."""
    try:
        return getattr(owner, "pending_custody", None) is not False
    except BaseException:
        return True


def coverage_custody_unsettled(coverage):
    if coverage is None:
        return False
    try:
        marker = getattr(coverage, "pending_custody", None)
    except BaseException:
        return True
    if type(marker) is bool:
        return marker
    from tests.windows.adaptive_execution import S1Runtime
    if type(coverage) is S1Runtime:
        from tests.windows.adaptive_capability_runner import custody_pending
        return custody_pending(coverage)
    return True


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def write_new(path, value):
    payload = canonical(value)
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise MatrixUnavailable("p6_artifact_size_exceeded")
    with Path(path).open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(payload).hexdigest()


def _sha256(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _uuid(value):
    try:
        return type(value) is str and UUID(value).int != 0 and str(UUID(value)) == value
    except (ValueError, TypeError):
        return False


def safe_reason(error):
    reason = getattr(error, "reason", None)
    return reason if type(reason) is str and _SAFE_REASON.fullmatch(reason) else "p6_native_operation_failed"


class EpisodePurpose(str, Enum):
    CALIBRATION = "noise_calibration"
    COMPARISON = "comparison"


@dataclass(frozen=True)
class BaselinePoint:
    """Actual between-run observation; never admission or cleanup authority."""
    clock_id: str
    conditions_sha256: str
    window_start_ns: int
    window_end_ns: int
    cpu_units: float
    commit_used_bytes: int
    physical_available_bytes: int
    commit_available_bytes: int
    prior_native_scopes_empty: bool | None
    owned_caps_disabled: bool | None
    original_custody_settled: bool | None
    artifact_sha256: str

    def validate(self):
        if (type(self.clock_id) is not str or not 1 <= len(self.clock_id) <= 200 or
                not _sha256(self.conditions_sha256) or not _sha256(self.artifact_sha256)):
            raise MatrixUnavailable("p6_baseline_identity_invalid")
        if (type(self.window_start_ns) is not int or type(self.window_end_ns) is not int or
                not 0 <= self.window_start_ns < self.window_end_ns or
                not 500_000_000 <= self.window_end_ns - self.window_start_ns <= 1_500_000_000):
            raise MatrixUnavailable("p6_baseline_window_invalid")
        if (type(self.cpu_units) not in (int, float) or not math.isfinite(self.cpu_units) or self.cpu_units < 0 or
                any(type(value) is not int or value < 0 for value in (self.commit_used_bytes,
                    self.physical_available_bytes, self.commit_available_bytes))):
            raise MatrixUnavailable("p6_baseline_measurement_invalid")
        if any(value is not True for value in (self.prior_native_scopes_empty,
                self.owned_caps_disabled, self.original_custody_settled)):
            raise MatrixUnavailable("p6_baseline_native_cleanup_unverified")
        if self.physical_available_bytes < 4 << 30 or self.commit_available_bytes < 4 << 30:
            raise MatrixUnavailable("p6_baseline_reserve_unavailable")


@dataclass(frozen=True)
class BaselineEnvelope:
    """Observed idle envelope, fixed before treatment; no guessed tolerance."""
    points: tuple[BaselinePoint, ...]

    def __post_init__(self):
        if type(self.points) is not tuple or len(self.points) != 10:
            raise MatrixUnavailable("p6_baseline_ten_reference_windows_required")
        _baseline_sequence(self.points)

    def accepts(self, current):
        """Five actual clean windows within the reference CPU/Commit maxima."""
        if type(current) is not tuple or len(current) != 5:
            raise MatrixUnavailable("p6_baseline_five_return_windows_required")
        _baseline_sequence(current)
        reference = self.points[-1]
        if (current[0].window_start_ns < reference.window_end_ns or
                any(point.clock_id != reference.clock_id or point.conditions_sha256 != reference.conditions_sha256
                    for point in current)):
            raise MatrixUnavailable("p6_baseline_reference_changed")
        return all(point.cpu_units <= max(item.cpu_units for item in self.points) and
                   point.commit_used_bytes <= max(item.commit_used_bytes for item in self.points)
                   for point in current)


def _baseline_sequence(points):
    previous = None
    for point in points:
        if type(point) is not BaselinePoint:
            raise MatrixUnavailable("p6_baseline_typed_points_required")
        point.validate()
        if previous is not None and (point.clock_id != previous.clock_id or
                point.conditions_sha256 != previous.conditions_sha256 or
                point.window_start_ns != previous.window_end_ns):
            raise MatrixUnavailable("p6_baseline_gap_or_identity_change")
        previous = point


@dataclass(frozen=True)
class ScenarioSpec:
    """Fixed public workload and role scope, never a grant or a launch receipt."""
    name: str
    scenario_class: ScenarioClass
    worker_count: int
    units_per_worker: int
    memory_mib_per_worker: int
    managed_roles: tuple[str, ...]
    unmanaged_workers: int = 0
    root_seconds: int | None = None
    child_seconds: tuple[int, ...] = ()
    requires_explicit_test_grant: bool = False
    maximum_work_seconds: int = 90

    @property
    def required_managed_jobs(self):
        return len(self.managed_roles)

    @property
    def task_count(self):
        """Independently launched commands; children remain part of their task."""
        return len(self.managed_roles) + self.unmanaged_workers

    def __post_init__(self):
        known = dict(DEFAULT_SCENARIOS)
        if known.get(self.name) is not self.scenario_class:
            raise MatrixUnavailable("p6_scenario_binding_invalid")
        integers = (self.worker_count, self.units_per_worker, self.memory_mib_per_worker,
                    self.unmanaged_workers, self.maximum_work_seconds)
        if any(type(value) is not int for value in integers):
            raise MatrixUnavailable("p6_scenario_work_invalid")
        if not 1 <= self.worker_count <= 4 or not 1 <= self.units_per_worker <= 10000:
            raise MatrixUnavailable("p6_scenario_work_invalid")
        if not 1 <= self.memory_mib_per_worker <= 128 or not 0 <= self.unmanaged_workers <= 4:
            raise MatrixUnavailable("p6_scenario_work_invalid")
        if type(self.managed_roles) is not tuple or not 1 <= len(self.managed_roles) <= 3:
            raise MatrixUnavailable("p6_scenario_roles_invalid")
        if any(role not in {"background", "protected", "exempt"} for role in self.managed_roles):
            raise MatrixUnavailable("p6_scenario_roles_invalid")
        if type(self.requires_explicit_test_grant) is not bool or (
                ("exempt" in self.managed_roles) != self.requires_explicit_test_grant):
            raise MatrixUnavailable("p6_scenario_grant_scope_invalid")
        if not 5 <= self.maximum_work_seconds <= 90:
            raise MatrixUnavailable("p6_scenario_deadline_invalid")
        if self.root_seconds is not None and (type(self.root_seconds) is not int or
                not 1 <= self.root_seconds < self.maximum_work_seconds):
            raise MatrixUnavailable("p6_scenario_lifetime_invalid")
        if type(self.child_seconds) is not tuple or len(self.child_seconds) > 3 or any(
                type(value) is not int or not 1 <= value < self.maximum_work_seconds
                for value in self.child_seconds):
            raise MatrixUnavailable("p6_scenario_lifetime_invalid")


SCENARIOS = (
    ScenarioSpec("cpu_bound_build", ScenarioClass.CPU_CONTENTION, 4, 10000, 32, ("background",)),
    ScenarioSpec("io_bound_install", ScenarioClass.IO_BOUND, 1, 4, 32, ("background",)),
    ScenarioSpec("memory_heavy_test", ScenarioClass.MEMORY_HEAVY, 1, 1000, 128, ("background",)),
    ScenarioSpec("no_pressure_idle", ScenarioClass.NO_PRESSURE, 1, 1000, 32, ("background",)),
    ScenarioSpec("unmanaged_cpu_pressure", ScenarioClass.UNMANAGED_CPU_PRESSURE,
                 1, 1000, 32, ("background",), unmanaged_workers=4),
    ScenarioSpec("mixed_exempt_background_protected", ScenarioClass.MIXED_ROLES,
                 1, 10000, 32, ("background", "exempt", "protected"), requires_explicit_test_grant=True),
    ScenarioSpec("mixed_root_and_child_durations", ScenarioClass.MIXED_DURATIONS,
                 1, 10000, 32, ("background",), root_seconds=2, child_seconds=(1, 15)),
)


@dataclass(frozen=True)
class MatrixRegistration:
    """Pinned source/conditions description created before native experiments."""
    registration_id: str
    order_seed: str
    pairs_per_scenario: int
    source_sha256: tuple[tuple[str, str], ...]
    profile_sha256: str
    capability_bundle_sha256: str
    baseline_source_sha256: str
    cache_state: CacheState = CacheState.WARM
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if (not _uuid(self.registration_id) or type(self.schema_version) is not int or
                self.schema_version != SCHEMA_VERSION or type(self.cache_state) is not CacheState):
            raise MatrixUnavailable("p6_registration_identity_invalid")
        if type(self.order_seed) is not str or not 1 <= len(self.order_seed) <= 200:
            raise MatrixUnavailable("p6_registration_seed_invalid")
        if type(self.pairs_per_scenario) is not int or not MIN_PAIRS_PER_SCENARIO <= self.pairs_per_scenario <= MAX_PAIRS:
            raise MatrixUnavailable("p6_registration_pair_count_invalid")
        if any(not _sha256(value) for value in (self.profile_sha256,
                self.capability_bundle_sha256, self.baseline_source_sha256)):
            raise MatrixUnavailable("p6_registration_digest_invalid")
        if type(self.source_sha256) is not tuple or not 1 <= len(self.source_sha256) <= 256:
            raise MatrixUnavailable("p6_registration_source_invalid")
        names = []
        for name, value in self.source_sha256:
            path = Path(name)
            if (type(name) is not str or len(name) > 256 or path.is_absolute() or
                    ".." in path.parts or not _sha256(value)):
                raise MatrixUnavailable("p6_registration_source_invalid")
            names.append(name)
        if len(names) != len(set(names)):
            raise MatrixUnavailable("p6_registration_source_invalid")

    @property
    def schedule(self):
        return build_schedule(DEFAULT_SCENARIOS, self.order_seed, self.pairs_per_scenario)

    @property
    def sha256(self):
        return digest(asdict(self))


@dataclass(frozen=True)
class EpisodeSpec:
    registration_sha256: str
    run_id: str
    comparison: Comparison
    scenario: ScenarioSpec
    pair_index: int
    variant: Variant
    purpose: EpisodePurpose
    repeat_index: int | None = None

    def __post_init__(self):
        if not _sha256(self.registration_sha256) or not _uuid(self.run_id):
            raise MatrixUnavailable("p6_episode_identity_invalid")
        if type(self.scenario) is not ScenarioSpec or type(self.comparison) is not Comparison or type(self.variant) is not Variant:
            raise MatrixUnavailable("p6_episode_scope_invalid")
        if type(self.pair_index) is not int or not 0 <= self.pair_index < MAX_PAIRS:
            raise MatrixUnavailable("p6_episode_pair_invalid")
        if self.variant not in COMPARISON_VARIANTS[self.comparison]:
            raise MatrixUnavailable("p6_episode_variant_invalid")
        if self.purpose is EpisodePurpose.CALIBRATION:
            if (self.variant is not COMPARISON_VARIANTS[self.comparison][0] or
                    type(self.repeat_index) is not int or self.repeat_index not in (0, 1) or
                    self.pair_index >= CALIBRATION_PAIRS):
                raise MatrixUnavailable("p6_calibration_episode_invalid")
        elif self.purpose is not EpisodePurpose.COMPARISON or self.repeat_index is not None:
            raise MatrixUnavailable("p6_episode_purpose_invalid")


def episode_spec(registration, comparison, scenario, pair_index, variant, purpose, repeat_index=None):
    identity = [registration.registration_id, comparison.value, scenario.name, pair_index,
                variant.value, purpose.value, repeat_index]
    run_id = str(uuid5(_UUID_NAMESPACE, canonical(identity).decode("utf-8")))
    return EpisodeSpec(registration.sha256, run_id, comparison, scenario, pair_index,
                       variant, purpose, repeat_index)


def required_episodes(registration):
    """Preregister all independent calibration observations before comparisons."""
    scenarios = {item.name: item for item in SCENARIOS}
    result = []
    for scenario in SCENARIOS:
        for comparison in Comparison:
            baseline = COMPARISON_VARIANTS[comparison][0]
            for pair in range(CALIBRATION_PAIRS):
                for repeat in range(2):
                    result.append(episode_spec(registration, comparison, scenario, pair, baseline,
                                               EpisodePurpose.CALIBRATION, repeat))
    for slot in registration.schedule.slots:
        for variant in (slot.first_variant, slot.second_variant):
            result.append(episode_spec(registration, slot.comparison, scenarios[slot.scenario],
                                       slot.pair_index, variant, EpisodePurpose.COMPARISON))
    return tuple(result)


def parse_registration(value):
    if type(value) is not dict or set(value) != set(MatrixRegistration.__dataclass_fields__):
        raise MatrixUnavailable("p6_registration_schema_invalid")
    value = dict(value)
    pins = value["source_sha256"]
    if type(pins) is not list or any(type(pair) is not list or len(pair) != 2 for pair in pins):
        raise MatrixUnavailable("p6_registration_source_invalid")
    value["source_sha256"] = tuple(tuple(pair) for pair in pins)
    try:
        value["cache_state"] = CacheState(value["cache_state"])
        return MatrixRegistration(**value)
    except (ValueError, TypeError) as error:
        raise MatrixUnavailable("p6_registration_schema_invalid") from error


def source_pins(root):
    """Hash source bytes actually used, including uncommitted implementation."""
    root = Path(root)
    paths = [*sorted((root / "sentinel" / "adaptive").glob("*.py")),
             root / "sentinel" / "coordinator.py", root / "sentinel" / "maintainer.py",
             root / "sentinel" / "exemptions.py", root / "scripts" / "collect.ps1",
             root / "scripts" / "invoke-sentinel.ps1", root / "scripts" / "sentinelctl.py",
             *sorted((root / "tests" / "benchmarks").glob("adaptive_*.py")),
             *sorted((root / "tests" / "windows").glob("adaptive_*.py")),
             *sorted((root / "tests" / "fixtures").glob("adaptive_*.py")),
             root / "tests" / "fixtures" / "win32_ui_probe.py"]
    if not 1 <= len(paths) <= 256:
        raise MatrixUnavailable("p6_registration_source_bound")
    return tuple((str(path.relative_to(root)).replace("\\", "/"),
                  hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths)


def create_registration(*, root, order_seed, pairs_per_scenario, profile_path,
                        capability_bundle, baseline_source_manifest, cache_state):
    return MatrixRegistration(str(uuid4()), order_seed, pairs_per_scenario, source_pins(root),
        hashlib.sha256(Path(profile_path).read_bytes()).hexdigest(),
        hashlib.sha256(Path(capability_bundle).read_bytes()).hexdigest(),
        hashlib.sha256(Path(baseline_source_manifest).read_bytes()).hexdigest(), CacheState(cache_state))


class MatrixJournal:
    """Bounded phase records, without high-frequency fsync or private commands."""
    def __init__(self, directory, registration):
        self.directory = Path(directory)
        if not self.directory.is_absolute() or self.directory.exists():
            raise MatrixUnavailable("p6_new_isolated_directory_required")
        if any(part.casefold() == ".resource-sentinel" for part in self.directory.parts):
            raise MatrixUnavailable("p6_daily_directory_forbidden")
        for ancestor in (self.directory.parent, *self.directory.parent.parents):
            info = ancestor.lstat()
            if not ancestor.is_dir() or ancestor.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise MatrixUnavailable("p6_directory_redirected")
        self.directory.mkdir()
        self.registration = registration
        self.events = 0
        self.maximum = len(required_episodes(registration)) * MAX_EPISODE_EVENTS + 20
        write_new(self.directory / "registration.json", asdict(registration))
        write_new(self.directory / "schedule.json", {
            "seed": registration.order_seed, "pairs_per_scenario": registration.pairs_per_scenario,
            "slots": [asdict(slot) for slot in registration.schedule.slots],
            "episodes": [asdict(item) for item in required_episodes(registration)]})
        self.path = self.directory / "phases.jsonl"
        self.path.touch(exist_ok=False)

    def event(self, phase, *, spec=None, reason=None, artifact_sha256=None):
        if self.events >= self.maximum:
            raise MatrixUnavailable("p6_phase_journal_bound")
        if phase not in {"pass_started", "episode_intent", "episode_opened", "baseline_verified",
                         "launch_attempted", "observations_complete", "cleanup_pending", "cleanup_settled",
                         "record_written", "episode_failed", "pass_failed", "pass_complete"}:
            raise MatrixUnavailable("p6_phase_invalid")
        row = {"sequence": self.events, "phase": phase, "monotonic_ns": time.monotonic_ns(),
               "registration_sha256": self.registration.sha256,
               "run_id": None if spec is None else spec.run_id, "reason": reason,
               "artifact_sha256": artifact_sha256}
        with self.path.open("ab") as stream:
            stream.write(canonical(row) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        self.events += 1


@dataclass(frozen=True)
class NativeEpisodeObservation:
    """Raw typed observations, not permission to act or an adopted owner."""
    trace: object
    provenance: object


def assert_episode_safety(spec, metrics):
    """Stop this pass on concrete safety evidence before launching another run."""
    if metrics.api_errors:
        raise MatrixUnavailable("p6_native_api_errors_observed")
    # Unmanaged work can be measured completely while its precise Job-control
    # coverage is zero. The reducer separately requires complete observations.
    if metrics.native_cap_audit_complete is not True:
        raise MatrixUnavailable("p6_native_coverage_incomplete")
    intervals = metrics.native_cap_intervals
    if intervals and (spec.variant in (Variant.A0, Variant.A1) or
            spec.scenario.scenario_class in NEUTRAL_RULE_SCENARIOS):
        raise MatrixUnavailable("p6_unrelated_native_cap_observed")
    active, ends = {}, []
    for index, interval in enumerate(sorted(intervals, key=lambda item: item.start_tick_100ns)):
        while ends and ends[0][0] < interval.start_tick_100ns:
            _, _, previous = heapq.heappop(ends)
            active[previous] -= 1
            if active[previous] == 0:
                del active[previous]
        # Zero-duration ENABLE events still count. An ordering too coarse
        # to distinguish two victims is unverified, never a free pass.
        if any(identity != interval.execution_id for identity in active):
            raise MatrixUnavailable("p6_multiple_native_victims_observed")
        active[interval.execution_id] = active.get(interval.execution_id, 0) + 1
        heapq.heappush(ends, (interval.end_tick_100ns, index, interval.execution_id))
    for resource in ("physical", "commit"):
        cause = getattr(metrics, f"{resource}_headroom_attribution")
        if cause is HeadroomAttribution.UNKNOWN:
            raise MatrixUnavailable("p6_headroom_attribution_unverified")
        if (getattr(metrics, f"min_{resource}_headroom_mib") < 4096 and
                cause is HeadroomAttribution.NEW_ADMISSION):
            raise MatrixUnavailable("p6_new_admission_reserve_loss")


class MatrixOrchestrator:
    """Sequential variant lifetimes owned by the same original native bridge.

    A pass owner is acquired before construction by the trusted native entry.
    It registers episode custody before open_episode can cause side effects.
    No timeout, failed artifact write or observer exception replaces that owner.
    """
    def __init__(self, *, owner, journal, registration, retained_coverage=None):
        self.owner, self.journal, self.registration = owner, journal, registration
        self.retained_coverage = retained_coverage
        self.current = None
        self.records = []
        self.calibration = {}
        self.completed = []
        self._started = False
        self._owner_closed = False

    def _cleanup(self, episode, spec):
        if episode.cleanup_complete is not True:
            episode.restore_and_drain()
        if episode.cleanup_complete is not True:
            self.journal.event("cleanup_pending", spec=spec)
            raise MatrixUnsettled(self.owner, episode)
        if custody_unsettled(self.owner):
            # Pending here means additional unknown custody, not this positively
            # cleaned episode's immutable evidence object.
            raise MatrixUnsettled(self.owner, episode)
        self.journal.event("cleanup_settled", spec=spec)

    def _run_episode(self, spec):
        from tests.benchmarks.adaptive_measurements import reduce_metrics, reduce_run
        self.owner.assert_unchanged()
        if custody_unsettled(self.owner):
            raise MatrixUnsettled(self.owner, self.current)
        self.journal.event("episode_intent", spec=spec)
        directory = self.journal.directory / spec.run_id
        directory.mkdir()
        write_new(directory / "intent.json", asdict(spec))
        episode = None
        try:
            # The native bridge registers its original authority before any
            # creation/mutation inside this call. open cannot mean "already
            # started the command": start() below is the only launch attempt.
            episode = self.owner.open_episode(spec=spec, directory=directory)
            self.current = episode
            if episode.run_id != spec.run_id:
                raise MatrixUnavailable("p6_episode_owner_mismatch")
            self.journal.event("episode_opened", spec=spec)
            episode.verify_baseline()
            self.journal.event("baseline_verified", spec=spec)
            self.journal.event("launch_attempted", spec=spec)
            episode.start()
            episode.observe()
            self.journal.event("observations_complete", spec=spec)
            self._cleanup(episode, spec)
            observed = episode.finish_trace()
            if type(observed) is not NativeEpisodeObservation or observed.trace.run_id != spec.run_id:
                raise MatrixUnavailable("p6_episode_trace_mismatch")
            metrics = reduce_metrics(observed.trace)
            assert_episode_safety(spec, metrics)
            if (observed.trace.conditions.cache_state is not self.registration.cache_state or
                    observed.trace.conditions.task_count != spec.scenario.task_count):
                raise MatrixUnavailable("p6_preregistered_conditions_mismatch")
            # Both reductions retain full validation. Independent calibration
            # runs are never relabelled as comparison slots.
            if spec.purpose is EpisodePurpose.CALIBRATION:
                from tests.benchmarks.adaptive_measurements import verify_native_provenance
                verify_native_provenance(observed.trace, observed.provenance, variant=spec.variant,
                                         seed=self.registration.order_seed, purpose="noise_calibration")
                key = (spec.comparison, spec.scenario.name, spec.pair_index)
                self.calibration.setdefault(key, {})[spec.repeat_index] = (spec, observed.trace, metrics)
                artifact = {"run_id": spec.run_id, "purpose": spec.purpose.value,
                            "trace_sha256": digest(asdict(observed.trace)), "metrics": asdict(metrics),
                            "evidence_source": "measured"}
            else:
                slot = next(item for item in self.registration.schedule.slots
                            if item.comparison is spec.comparison and item.scenario == spec.scenario.name
                            and item.pair_index == spec.pair_index)
                record = reduce_run(observed.trace, schedule=self.registration.schedule, slot=slot,
                                    variant=spec.variant, provenance=observed.provenance)
                if record.evidence_source is not EvidenceSource.MEASURED:
                    raise MatrixUnavailable("p6_native_record_not_measured")
                self.records.append(record)
                artifact = run_record_to_dict(record)
            sha = write_new(directory / "record.json", artifact)
            self.completed.append(spec.run_id)
            self.journal.event("record_written", spec=spec, artifact_sha256=sha)
            self.current = None
        except BaseException as primary:
            try:
                self.journal.event("episode_failed", spec=spec, reason=safe_reason(primary))
            except BaseException:
                pass
            if episode is not None:
                try:
                    self._cleanup(episode, spec)
                except BaseException as cleanup_error:
                    raise MatrixUnsettled(self.owner, episode, cause=primary) from cleanup_error
            if custody_unsettled(self.owner):
                raise MatrixUnsettled(self.owner, episode, cause=primary) from primary
            raise

    def _noise(self):
        values = {}
        for scenario in SCENARIOS:
            for comparison in Comparison:
                pairs = []
                for index in range(CALIBRATION_PAIRS):
                    pair = self.calibration.get((comparison, scenario.name, index), {})
                    if set(pair) != {0, 1}:
                        raise MatrixUnavailable("p6_noise_matrix_incomplete")
                    pairs.append((pair[0], pair[1]))
                conditions = pairs[0][0][1].conditions
                if any(item[1].conditions != conditions for pair in pairs for item in pair):
                    raise MatrixUnavailable("p6_noise_conditions_changed")
                noise = NoiseEvidence(comparison=comparison, scenario=scenario.name,
                    seed=self.registration.order_seed, variant=COMPARISON_VARIANTS[comparison][0],
                    conditions=conditions, evidence_source=EvidenceSource.MEASURED,
                    evidence_id="noise-" + digest([comparison.value, scenario.name, self.registration.sha256]),
                    foreground_p95_pairs_ms=tuple((left[2].foreground_p95_ms, right[2].foreground_p95_ms)
                                                  for left, right in pairs),
                    makespan_pairs_s=tuple((left[2].makespan_s, right[2].makespan_s) for left, right in pairs),
                    repeat_run_ids=tuple((left[0].run_id, right[0].run_id) for left, right in pairs))
                values[(comparison, scenario.name)] = noise
        return values

    def run(self):
        if self._started:
            raise MatrixUnavailable("p6_pass_replay_forbidden")
        self._started = True
        required = required_episodes(self.registration)
        try:
            self.owner.assert_unchanged()
            self.journal.event("pass_started")
            for spec in required:
                self._run_episode(spec)
            if len(self.completed) != len(required) or set(self.completed) != {item.run_id for item in required}:
                raise MatrixUnavailable("p6_pass_inventory_incomplete")
            noise = self._noise()
            analyses = [analyze_comparison(self.records, comparison, scenario.name, scenario.scenario_class,
                        schedule=self.registration.schedule, noise=noise[(comparison, scenario.name)])
                        for scenario in SCENARIOS for comparison in Comparison]
            self.owner.assert_unchanged()
            self.owner.close()
            if custody_unsettled(self.owner):
                raise MatrixUnsettled(self.owner)
            self._owner_closed = True
            if coverage_custody_unsettled(self.retained_coverage):
                raise MatrixUnsettled(self.owner, retained_coverage=self.retained_coverage, owner_closed=True)
            write_new(self.journal.directory / "records.json", [run_record_to_dict(item) for item in self.records])
            write_new(self.journal.directory / "noise.json", [asdict(item) for item in noise.values()])
            with (self.journal.directory / "report.md").open("x", encoding="utf-8") as stream:
                stream.write(render_report(analyses, self.registration.order_seed))
            result = {"schema_version": 1, "status": "measured_matrix_complete",
                      "registration_sha256": self.registration.sha256,
                      "completed_episodes": len(self.completed), "comparison_records": len(self.records),
                      "required_scenarios": len(SCENARIOS), "required_comparisons": len(Comparison),
                      "paired_runs_per_scenario_comparison": self.registration.pairs_per_scenario,
                      "verdict": overall_verdict(analyses).value, "all_custody_settled": True,
                      "promotion_permitted": False}
            write_new(self.journal.directory / "result.json", result)
            self.journal.event("pass_complete")
            return result
        except BaseException as primary:
            try:
                self.journal.event("pass_failed", reason=safe_reason(primary))
                write_new(self.journal.directory / "failure.json", {
                    "schema_version": 1, "status": "failed", "reason": safe_reason(primary),
                    "completed_episodes": len(self.completed), "required_episodes": len(required),
                    "remaining_run_ids": [item.run_id for item in required if item.run_id not in self.completed],
                    "promotion_permitted": False})
            except BaseException:
                pass
            if isinstance(primary, MatrixUnsettled):
                raise
            if self._owner_closed:
                # Artifact publication failure after positive close is a failed
                # experiment, not permission to query or close old handles.
                raise
            try:
                self.owner.recover_once()
                if custody_unsettled(self.owner):
                    raise MatrixUnsettled(self.owner, self.current, cause=primary)
                self.owner.close()
                if custody_unsettled(self.owner):
                    raise MatrixUnsettled(self.owner, self.current, cause=primary)
                self._owner_closed = True
            except BaseException as cleanup_error:
                if isinstance(cleanup_error, MatrixUnsettled):
                    raise
                raise MatrixUnsettled(self.owner, self.current, cause=primary) from cleanup_error
            raise


def run_native_matrix(registration, directory):
    """Only the actual daily provider may supply the original native P6 bridge."""
    from tests.windows.adaptive_admission import require_continuous_admission
    from tests.windows.adaptive_capability_runner import base_python, NativeRunUnsettled
    if os.name != "nt":
        raise MatrixUnavailable("p6_windows_external_console_required")
    base_python()
    journal = MatrixJournal(directory, registration)
    coverage = owner = candidate = coordinator = None
    try:
        coverage = require_continuous_admission()
        bridge = getattr(coverage, "open_p6_pass", None)
        if not callable(bridge):
            raise MatrixUnavailable("p6_native_scope_bridge_unavailable")
        candidate = bridge(registration=registration, directory=journal.directory)
        if (candidate is None or isinstance(candidate, (bool, int, str, dict, list, tuple)) or
                any(not callable(getattr(candidate, name, None)) for name in
                    ("open_episode", "assert_unchanged", "recover_once", "close")) or
                type(getattr(candidate, "pending_custody", None)) is not bool):
            error = MatrixUnavailable("p6_original_pass_owner_required")
            # Preserve an unexpected object too; a provider must keep any
            # pre-return custody, but its invalid return is not a new owner.
            error.additional_custody = candidate
            raise error
        owner = candidate
        coordinator = MatrixOrchestrator(owner=owner, journal=journal, registration=registration,
                                         retained_coverage=coverage)
        result = coordinator.run()
        if coverage_custody_unsettled(coverage):
            raise MatrixUnsettled(owner, retained_coverage=coverage, owner_closed=True)
        return result
    except MatrixUnsettled as pending:
        if coverage is not None and coverage is not pending.owner:
            pending.retained_coverage = coverage
        raise
    except BaseException as primary:
        # Logging must never mask a custody-bearing exception or throw away the
        # object already acquired. Preserve the original error and owners first.
        retained = None
        if isinstance(primary, NativeRunUnsettled):
            retained = MatrixUnsettled(primary.coverage, cause=primary,
                                       unverified_custody=primary.additional_custody)
        if owner is not None and custody_unsettled(owner):
            retained = MatrixUnsettled(owner, cause=primary)
        elif owner is not None and (coordinator is None or not coordinator._owner_closed):
            # A pass may hold its original registration/fence even with no
            # workload pending. Constructor/early failures must close that
            # owner too, without duplicating an already confirmed close.
            try:
                owner.close()
                if custody_unsettled(owner):
                    retained = MatrixUnsettled(owner, cause=primary)
            except BaseException:
                retained = MatrixUnsettled(owner, cause=primary)
        if retained is None and coverage_custody_unsettled(coverage):
            retained = MatrixUnsettled(coverage, cause=primary)
        if retained is None and owner is None and candidate is not None and not isinstance(
                candidate, (bool, int, str, dict, list, tuple)):
            retained = MatrixUnsettled(coverage, cause=primary, unverified_custody=candidate)
        elif retained is not None and owner is None and candidate is not None and not isinstance(
                candidate, (bool, int, str, dict, list, tuple)):
            retained.unverified_custody = candidate
        if retained is not None:
            if coverage is not None and coverage is not retained.owner:
                retained.retained_coverage = coverage
            if isinstance(primary, NativeRunUnsettled) and primary.additional_custody is not None:
                if retained.unverified_custody is None:
                    retained.unverified_custody = primary.additional_custody
                elif retained.unverified_custody is not primary.additional_custody:
                    retained.unverified_custody = (retained.unverified_custody, primary.additional_custody)
        try:
            write_new(journal.directory / "entry-failure.json", {
                "schema_version": 1, "status": "pending" if retained is not None else "blocked",
                "reason": safe_reason(primary), "original_custody_retained": retained is not None,
                "promotion_permitted": False})
        except BaseException:
            primary.add_note("p6_entry_failure_evidence_write_failed")
        if retained is not None:
            raise retained from primary
        raise
