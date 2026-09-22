"""Bounded per-Job sampling that turns backend readings into a FastFrame.

This is the P4 sampler of the adaptive scheduler plan
(docs/planning/adaptive-scheduler/IMPLEMENTATION-PLAN.md sections 5.3, 5.4 and
5.5). It holds no Windows code of its own: a caller supplies a per-Job reading
backend and a machine observation source, and this module only turns successive
readings into the inputs decision.py consumes.

Bounds that this module enforces, from plan section 5.5:
  - at most ten enrolled Jobs, and one bounded reading per enrolled Job per
    sample, so there is no whole machine process scan, no CIM and no spawn;
  - one capture bracket per sample, measured with the caller's clock, and an
    observer_budget_exceeded error when the bracket exceeds the work budget;
  - a CPU delta needs two valid endpoints of the same counter epoch inside the
    configured 0.5 to 1.5 s window; anything else yields no CPU value.

Nothing here applies, requests or acknowledges a control. There is no Set path,
no journal and no admission or capacity output: a Job whose rate fell because it
was capped simply reports a lower measured value, which no consumer of this
module may read as free capacity.

The helper's optional begin_sample hook performs one managed-member memory
batch, bounded across all Jobs. A reading without complete private working set
and private commit bytes remains unknown plus memory_attribution_unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import json
from typing import Protocol
from uuid import UUID, uuid4

from .contracts import (
    ContractViolation, FastFrame, FrameError, JobFrame, MachineFrame, MAX_ENROLLED_JOBS,
    RetryClass, TICKS_PER_SECOND, UINT64_MAX, Validity,
)
from .decision import PolicyProfile

TICKS_PER_MS = TICKS_PER_SECOND // 1000
MAX_FRAME_ERRORS = 64


def _uint(value) -> bool:
    return type(value) is int and 0 <= value <= UINT64_MAX


def _error(code: str, stage: str, *, execution_id=None,
           retry: RetryClass = RetryClass.NEW_ATTEMPT) -> FrameError:
    return FrameError(code, stage, retry, execution_id=execution_id)


def profile_revision(profile: PolicyProfile) -> str:
    """Stable digest of a profile's values; integrity only, not authentication."""
    if not isinstance(profile, PolicyProfile):
        raise ContractViolation("profile: typed profile required")
    values = {}
    for field in fields(PolicyProfile):
        value = getattr(profile, field.name)
        if isinstance(value, tuple):
            value = [item.value for item in value]
        values[field.name] = getattr(value, "value", value)
    payload = json.dumps(values, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class JobSamplingError(RuntimeError):
    """Sanitized per-Job read failure; a failed read never becomes a zero."""

    def __init__(self, error: FrameError):
        self.error = error
        super().__init__(error.code + ":" + error.stage)


@dataclass(frozen=True)
class JobReading:
    """One bounded accounting read of one enrolled Job.

    cpu_100ns is the Job's cumulative user plus kernel CPU time, which is what
    QueryInformationJobObject's basic accounting returns and what
    native_job.NativeJob.accounting() already exposes over a handle the caller
    holds. counter_epoch changes whenever the backend can no longer relate this
    reading to the previous one, which invalidates the delta.

    Memory fields are optional: a complete bounded member scan may be unavailable.
    None means unknown, never zero.
    """

    cpu_100ns: int | None
    active_processes: int | None
    membership_complete: bool
    counter_epoch: str
    private_working_set_bytes: int | None = None
    private_commit_bytes: int | None = None

    def __post_init__(self):
        for name in ("cpu_100ns", "active_processes", "private_working_set_bytes",
                     "private_commit_bytes"):
            value = getattr(self, name)
            if value is not None and not _uint(value):
                raise ContractViolation(f"{name}: unsigned integer or null required")
        if type(self.membership_complete) is not bool:
            raise ContractViolation("membership_complete: bool required")
        if not isinstance(self.counter_epoch, str) or not 1 <= len(self.counter_epoch) <= 128:
            raise ContractViolation("counter_epoch: bounded identifier required")


class JobAccountingSource(Protocol):
    """Per-Job accounting over a handle or scope the caller already holds.

    read receives only the enrolled execution id and performs one accounting
    query. Optional begin_sample(started_tick, execution_ids) may query members
    of those retained Jobs within one shared 256-record/100-ms bound. It must
    never scan the entire machine, and memory failure must leave read usable for
    CPU accounting. The backend owns every handle and uncertain cleanup owner.
    """

    def read(self, execution_id: str) -> JobReading:
        ...


@dataclass(frozen=True)
class _Baseline:
    cpu_100ns: int
    counter_epoch: str
    end_tick_100ns: int


@dataclass(frozen=True)
class JobSample:
    jobs: tuple[JobFrame, ...]
    errors: tuple[FrameError, ...]
    reset_required: bool
    capture_start_tick_100ns: int
    capture_end_tick_100ns: int


class JobSampler:
    """Enrollment plus successive readings for at most ten Jobs.

    The sampler keeps one small baseline per enrolled Job and nothing else. It
    starts no thread and owns no handle: the caller's backend owns those.
    """

    def __init__(self, *, backend, profile: PolicyProfile, clock):
        if not isinstance(profile, PolicyProfile):
            raise ContractViolation("profile: typed profile required")
        if not callable(clock) or not callable(getattr(backend, "read", None)):
            raise ContractViolation("backend/clock: readable sources required")
        self._backend = backend
        self._profile = profile
        self._clock = clock
        self._baselines: dict[str, _Baseline | None] = {}
        # Monotone per-Job observed maximum. It never falls, so a rate that drops
        # under a cap cannot be republished as newly available capacity.
        self._high_water: dict[str, float] = {}

    @property
    def enrolled(self) -> tuple[str, ...]:
        return tuple(self._baselines)

    def enroll(self, execution_id: str) -> None:
        limit = min(self._profile.max_enrolled_jobs, MAX_ENROLLED_JOBS)
        try:
            canonical = isinstance(execution_id, str) and str(UUID(execution_id)) == execution_id
        except (ValueError, AttributeError, TypeError):
            canonical = False
        if not canonical:
            raise ContractViolation("execution_id: canonical UUID required")
        if execution_id in self._baselines:
            raise ContractViolation("execution_id: already enrolled")
        if len(self._baselines) >= limit:
            raise ContractViolation("enrolled: at most max_enrolled_jobs Jobs")
        self._baselines[execution_id] = None
        self._high_water[execution_id] = 0.0

    def release(self, execution_id: str) -> None:
        self._baselines.pop(execution_id, None)
        self._high_water.pop(execution_id, None)

    def invalidate_clock(self) -> None:
        """Forget every baseline after a caller observed resume or reset.

        This clears local state only. It restores no cap and proves nothing
        about what the rest of the system still has to reconcile.
        """
        for execution_id in self._baselines:
            self._baselines[execution_id] = None

    def _tick(self) -> int:
        value = self._clock()
        if not _uint(value):
            raise ContractViolation("clock: unsigned interrupt tick required")
        return value

    def sample(self) -> JobSample:
        start = self._tick()
        frames: list[JobFrame] = []
        errors: list[FrameError] = []
        reset = False
        begin = getattr(self._backend, "begin_sample", None)
        if begin is not None:
            # The native JobHandleSource handles ordinary memory failures here,
            # retaining cleanup while leaving every Job CPU query available.
            begin(start, tuple(self._baselines))
        for execution_id in tuple(self._baselines):
            frame, job_errors, job_reset = self._one(execution_id)
            frames.append(frame)
            errors.extend(job_errors)
            reset = reset or job_reset
        end = self._tick()
        if end < start:
            self._baselines = {key: None for key in self._baselines}
            return JobSample((), (_error("clock_discontinuity", "job_capture"),), True, start, start)
        if end - start > self._profile.sampler_work_budget_ms * TICKS_PER_MS:
            errors.append(_error("observer_budget_exceeded", "job_capture"))
            reset = True
        return JobSample(tuple(frames), tuple(errors[:MAX_FRAME_ERRORS]), reset, start, end)

    def _one(self, execution_id: str):
        """One enrolled Job: read, relate to its baseline, emit its aggregate."""
        errors: list[FrameError] = []
        reset = False
        end = self._tick()
        try:
            reading = self._backend.read(execution_id)
        except JobSamplingError as failure:
            reading = None
            errors.append(failure.error)
        if reading is not None and not isinstance(reading, JobReading):
            raise ContractViolation("backend: typed JobReading required")

        previous = self._baselines.get(execution_id)
        cpu_units = None
        if reading is None or reading.cpu_100ns is None:
            errors.append(_error("telemetry_stale", "job_cpu", execution_id=execution_id))
            self._baselines[execution_id] = None
            reset = True
        else:
            baseline = _Baseline(reading.cpu_100ns, reading.counter_epoch, end)
            code = self._delta_problem(previous, baseline)
            if code is not None:
                errors.append(_error(code, "job_cpu_delta", execution_id=execution_id))
                reset = True
            else:
                span = baseline.end_tick_100ns - previous.end_tick_100ns
                cpu_units = (baseline.cpu_100ns - previous.cpu_100ns) / span
            self._baselines[execution_id] = baseline

        membership = bool(reading.membership_complete) if reading is not None else False
        active = reading.active_processes if reading is not None else None
        if not membership or active is None:
            membership = False
            errors.append(_error("membership_unknown", "job_membership", execution_id=execution_id))
        working_set = reading.private_working_set_bytes if reading is not None else None
        commit = reading.private_commit_bytes if reading is not None else None
        memory = Validity.VALID
        if not membership or working_set is None or commit is None:
            memory, working_set, commit = Validity.UNKNOWN, None, None
            errors.append(_error("memory_attribution_unavailable", "job_memory",
                                 execution_id=execution_id, retry=RetryClass.AFTER_RECONCILIATION))
        counter_epoch = reading.counter_epoch if reading is not None else "unavailable"
        high_water = self._high_water.get(execution_id, 0.0)
        if cpu_units is not None:
            high_water = max(high_water, cpu_units)
            self._high_water[execution_id] = high_water
        frame = JobFrame(execution_id, cpu_units, high_water or None, working_set, commit,
                         active if membership else None, membership, memory, counter_epoch)
        return frame, errors, reset

    def _delta_problem(self, previous: _Baseline | None, current: _Baseline) -> str | None:
        """Plan section 5.4: a delta needs two endpoints of one counter epoch."""
        if previous is None:
            return "sample_window_invalid"
        if previous.counter_epoch != current.counter_epoch:
            return "counter_reset"
        if current.cpu_100ns < previous.cpu_100ns:
            return "counter_reset"
        span = current.end_tick_100ns - previous.end_tick_100ns
        if not (self._profile.cpu_window_min_ms * TICKS_PER_MS <= span
                <= self._profile.cpu_window_max_ms * TICKS_PER_MS):
            return "sample_window_invalid"
        return None


@dataclass(frozen=True)
class MachineObservation:
    """Whole machine endpoint as a caller's machine sampler reports it.

    The field names match sentinel.adaptive.machine_sampler.MachineSample, so an
    adapter over that sampler is a field copy. This module does not import it,
    because the shadow helper must stay portable and free of native code.
    """

    machine: MachineFrame | None
    clock_epoch: str
    window_start_tick_100ns: int | None
    window_end_tick_100ns: int | None
    validity: Validity
    errors: tuple[FrameError, ...] = ()
    reset_required: bool = False

    def __post_init__(self):
        if self.machine is not None and not isinstance(self.machine, MachineFrame):
            raise ContractViolation("machine: typed MachineFrame or null required")
        if not isinstance(self.clock_epoch, str) or not 1 <= len(self.clock_epoch) <= 128:
            raise ContractViolation("clock_epoch: bounded identifier required")
        for name in ("window_start_tick_100ns", "window_end_tick_100ns"):
            value = getattr(self, name)
            if value is not None and not _uint(value):
                raise ContractViolation(f"{name}: unsigned tick or null required")
        if not isinstance(self.validity, Validity):
            raise ContractViolation("validity: typed validity required")
        if type(self.errors) is not tuple or len(self.errors) > MAX_FRAME_ERRORS:
            raise ContractViolation("errors: bounded immutable errors required")


@dataclass(frozen=True)
class FrameResult:
    """A frame, or an explicit reason why this sample produced none."""

    frame: FastFrame | None
    reason: str
    errors: tuple[FrameError, ...]
    reset_required: bool
    collection_cost_ms: float


@dataclass(frozen=True)
class FrameBinding:
    """Pre-capture authority snapshot, not the local enrollment generation.

    The active caller reads this from one bounded registry transaction and
    verifies that transaction's facts again after capture. Construction alone
    confers no control authority. Shadow callers omit it entirely.
    """

    registry_revision: int
    config_revision: str
    execution_ids: tuple[str, ...]

    def __post_init__(self):
        if not _uint(self.registry_revision):
            raise ContractViolation("registry_revision: unsigned integer required")
        if (type(self.config_revision) is not str or len(self.config_revision) != 64
                or any(c not in '0123456789abcdef' for c in self.config_revision)):
            raise ContractViolation("config_revision: profile digest required")
        if (type(self.execution_ids) is not tuple or len(self.execution_ids) > MAX_ENROLLED_JOBS
                or len(set(self.execution_ids)) != len(self.execution_ids)):
            raise ContractViolation("execution_ids: bounded distinct identities required")
        for value in self.execution_ids:
            try:
                valid = type(value) is str and str(UUID(value)) == value
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ContractViolation("execution_ids: canonical UUID required")


class FrameSampler:
    """One sample per call: machine endpoint, enrolled Jobs, then one FastFrame.

    sample_seq increments only when a frame is produced. A tick that produced no
    frame therefore leaves no sequence hole, but the missing second still shows
    up to decision.py as a window that is too long, which fails closed.
    """

    def __init__(self, *, profile: PolicyProfile, backend, machine_source, clock,
                 sampler_epoch: str | None = None):
        if not callable(machine_source):
            raise ContractViolation("machine_source: callable observation source required")
        self._profile = profile
        self._jobs = JobSampler(backend=backend, profile=profile, clock=clock)
        self._machine_source = machine_source
        self._clock = clock
        self.sampler_epoch = sampler_epoch or str(uuid4())
        self.config_revision = profile_revision(profile)
        self.registry_revision = 0
        self._sample_seq = 0

    @property
    def enrolled(self) -> tuple[str, ...]:
        return self._jobs.enrolled

    @property
    def sample_seq(self) -> int:
        return self._sample_seq

    @property
    def enrollment_generation(self) -> int:
        """Local topology counter; never an authoritative registry revision."""
        return self.registry_revision

    def enroll(self, execution_id: str) -> None:
        self._jobs.enroll(execution_id)
        self.registry_revision += 1

    def release(self, execution_id: str) -> None:
        self._jobs.release(execution_id)
        self.registry_revision += 1

    def invalidate_clock(self) -> None:
        self._jobs.invalidate_clock()

    def sample(self, *, binding: FrameBinding | None = None) -> FrameResult:
        if binding is not None:
            if (not isinstance(binding, FrameBinding)
                    or binding.config_revision != self.config_revision
                    or set(binding.execution_ids) != set(self.enrolled)):
                raise ContractViolation("binding: current profile and exact enrollment required")
        generation = self.enrollment_generation
        start = self._clock()
        observation = self._machine_source()
        if not isinstance(observation, MachineObservation):
            raise ContractViolation("machine_source: typed MachineObservation required")
        jobs = self._jobs.sample()
        end = self._clock()
        cost_ms = max(0, end - start) / TICKS_PER_MS
        if generation != self.enrollment_generation:
            return FrameResult(None, "enrollment_changed_during_capture", (), True, cost_ms)
        errors = tuple(observation.errors) + jobs.errors
        reset = observation.reset_required or jobs.reset_required

        window_start = observation.window_start_tick_100ns
        window_end = observation.window_end_tick_100ns
        if observation.machine is None or window_start is None or window_end is None:
            return FrameResult(None, "machine_window_unavailable", errors[:MAX_FRAME_ERRORS],
                               True, cost_ms)
        if not window_start < window_end:
            return FrameResult(None, "machine_window_invalid", errors[:MAX_FRAME_ERRORS], True, cost_ms)

        skew = abs(jobs.capture_end_tick_100ns - window_end)
        if skew > self._profile.attribution_max_skew_ms * TICKS_PER_MS:
            errors += (_error("measurement_inconsistent", "frame_skew"),)
        errors = errors[:MAX_FRAME_ERRORS]
        validity = self._validity(observation, jobs, errors)
        published = max(window_end, jobs.capture_end_tick_100ns, end)
        try:
            frame = FastFrame(
                sampler_epoch=self.sampler_epoch, clock_epoch=observation.clock_epoch,
                sample_seq=self._sample_seq + 1, window_start_tick_100ns=window_start,
                window_end_tick_100ns=window_end, published_tick_100ns=published,
                sampled_at_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                config_revision=self.config_revision,
                registry_revision=self.registry_revision if binding is None else binding.registry_revision,
                machine=observation.machine, jobs=jobs.jobs, validity=validity, errors=errors,
                collection_cost_ms=cost_ms, collection_skew_ms=skew / TICKS_PER_MS)
        except ContractViolation:
            # A frame we cannot build is a frame we do not publish. The sequence
            # is not consumed, so no consumer sees a hole it cannot explain.
            return FrameResult(None, "frame_contract_rejected", errors, True, cost_ms)
        self._sample_seq += 1
        return FrameResult(frame, "sampled", errors, reset, cost_ms)

    @staticmethod
    def _validity(observation: MachineObservation, jobs: JobSample,
                  errors: tuple[FrameError, ...]) -> Validity:
        if observation.validity is Validity.INVALID:
            return Validity.INVALID
        complete = all(getattr(observation.machine, field.name) is not None
                       for field in fields(MachineFrame))
        if (observation.validity is not Validity.VALID or not complete or jobs.reset_required
                or any(error.code != "memory_attribution_unavailable" for error in errors)):
            return Validity.UNKNOWN
        return Validity.VALID
