"""Versioned, bounded data contracts for the admission-only foundation.

These types validate data, not authority: a valid PID, frame, proposal, or
manifest is not proof of OS identity, freshness, eligibility, or ownership.
There are deliberately no process queries, file writes, or actuator calls here.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
import json
import math
import ntpath
import re
from typing import Any
from uuid import UUID

SCHEMA_VERSION = 1
MAX_MESSAGE_BYTES = 256 * 1024
MAX_JSON_DEPTH = 64
MAX_ENROLLED_JOBS = 10
UINT64_MAX = (1 << 64) - 1
TICKS_PER_SECOND = 10_000_000


class ContractViolation(ValueError):
    """A structural contract failed; messages contain field names, not values."""


class LifecycleState(str, Enum):
    NEW = "NEW"
    QUEUED = "QUEUED"
    RESERVED = "RESERVED"
    PREPARED = "PREPARED"
    LAUNCHING = "LAUNCHING"
    RUNNING = "RUNNING"
    DRAINING = "DRAINING"
    FINISHED = "FINISHED"
    CANCELLED_BEFORE_START = "CANCELLED_BEFORE_START"
    START_FAILED = "START_FAILED"
    START_UNKNOWN = "START_UNKNOWN"
    UNCERTAIN_HOLD = "UNCERTAIN_HOLD"


class AllocationKind(str, Enum):
    DIRECT = "direct"
    ROUTED = "routed"
    PARENT = "parent"


class Role(str, Enum):
    BACKGROUND = "background"
    PROTECTED = "protected"
    NEUTRAL = "neutral"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Coverage(str, Enum):
    UNMANAGED = "unmanaged"
    JOB_CONTAINED = "job_contained"


class Validity(str, Enum):
    VALID = "valid"
    UNKNOWN = "unknown"
    INVALID = "invalid"


class IdentityStatus(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


class RetryClass(str, Enum):
    NEVER = "never"
    TRANSIENT = "transient"
    AFTER_RECONCILIATION = "after_reconciliation"
    NEW_ATTEMPT = "new_attempt"


ERROR_CODES = frozenset("""
identity_unavailable identity_mismatch membership_unknown foreign_job_unsupported
job_list_unsupported cpu_rate_unsupported denominator_unknown telemetry_stale
counter_reset clock_discontinuity exemption_unknown exemption_restore_pending
registry_unavailable db_busy storage_unavailable ipc_timeout guardian_unavailable
launch_outcome_unknown api_set_failed api_readback_mismatch external_control_conflict
restore_unverified observer_budget_exceeded launch_payload_too_large revision_conflict
request_exceeds_host_budget memory_attribution_unavailable measurement_inconsistent
sample_window_invalid busy
""".split())


def _integer(value: Any, name: str, minimum: int = 0, maximum: int = UINT64_MAX) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractViolation(f"{name}: integer out of range")


def _number(value: Any, name: str, maximum: float | None = None) -> None:
    if type(value) not in (int, float):
        raise ContractViolation(f"{name}: finite nonnegative number required")
    try:
        valid = math.isfinite(value) and value >= 0 and (maximum is None or value <= maximum)
    except OverflowError:
        valid = False
    if not valid:
        raise ContractViolation(f"{name}: finite nonnegative number required")


def _text(value: Any, name: str, maximum: int = 128) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise ContractViolation(f"{name}: bounded nonempty text required")
    if any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ContractViolation(f"{name}: invalid text")


def _identifier(value: Any, name: str) -> None:
    _text(value, name)
    if not re.fullmatch(r"[A-Za-z0-9_.:@-]+", value):
        raise ContractViolation(f"{name}: opaque identifier required")


def _uuid(value: Any, name: str) -> None:
    _text(value, name, 36)
    try:
        if str(UUID(value)) != value:
            raise ValueError
    except (ValueError, AttributeError):
        raise ContractViolation(f"{name}: canonical UUID required") from None


def _hash(value: Any, name: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ContractViolation(f"{name}: SHA256 hex required")


def _enum(value: Any, enum_type: type[Enum], name: str) -> None:
    if not isinstance(value, enum_type):
        raise ContractViolation(f"{name}: typed enum required")


def _read_enum(value: Any, enum_type: type[Enum], name: str) -> Any:
    if not isinstance(value, str):
        raise ContractViolation(f"{name}: enum string required")
    try:
        return enum_type(value)
    except ValueError:
        raise ContractViolation(f"{name}: unsupported value") from None


def _decimal(value: Any, name: str, minimum: int = 0) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ContractViolation(f"{name}: canonical decimal string required")
    result = int(value)
    _integer(result, name, minimum)
    return result


def _object(value: Any, cls: type) -> dict:
    if type(value) is not dict:
        raise ContractViolation(f"{cls.__name__}: object required")
    expected = {field.name for field in fields(cls)}
    if set(value) != expected:
        raise ContractViolation(f"{cls.__name__}: missing or unknown fields")
    return dict(value)


def _version(value: Any) -> None:
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ContractViolation("schema_version: unsupported version")


def _typed(value: Any, cls: type, name: str) -> None:
    if not isinstance(value, cls):
        raise ContractViolation(f"{name}: typed contract required")


def _wire(value: Any, name: str = "") -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Contract):
        return {f.name: _wire(getattr(value, f.name), f.name) for f in fields(value)}
    if isinstance(value, tuple):
        return [_wire(item) for item in value]
    if name.endswith("tick_100ns") or name == "created_filetime_100ns":
        return str(value) if value is not None else None
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractViolation("JSON: duplicate key")
        result[key] = value
    return result


def strict_json_loads(payload: str | bytes) -> dict:
    """Bounded protocol decoder; unknown fields are rejected by each type."""
    if not isinstance(payload, (str, bytes)):
        raise ContractViolation("JSON: UTF-8 payload required")
    try:
        size = len(payload.encode("utf-8")) if isinstance(payload, str) else len(payload)
        if size > MAX_MESSAGE_BYTES:
            raise ContractViolation("JSON: message too large")
        def invalid_constant(_: str) -> None:
            raise ContractViolation("JSON: nonstandard number")
        def finite_float(text: str) -> float:
            value = float(text)
            if not math.isfinite(value):
                raise ContractViolation("JSON: nonfinite number")
            return value
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="strict")
        # Bound nesting independently of the interpreter's configurable recursion
        # limit. Brackets inside JSON strings are data, including escaped quotes.
        depth = 0
        quoted = False
        escaped = False
        for char in payload:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise ContractViolation("JSON: nesting too deep")
            elif char in "]}":
                depth -= 1
        result = json.loads(payload, object_pairs_hook=_pairs, parse_constant=invalid_constant,
                            parse_float=finite_float)
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ContractViolation):
            raise
        raise ContractViolation("JSON: malformed payload") from None
    if type(result) is not dict:
        raise ContractViolation("JSON: object required")
    return result


class Contract:
    def to_dict(self) -> dict:
        return _wire(self)

    def to_json(self) -> str:
        payload = _canonical(self.to_dict())
        if len(payload) > MAX_MESSAGE_BYTES:
            raise ContractViolation("JSON: message too large")
        return payload.decode("utf-8")

    @classmethod
    def from_json(cls, payload: str | bytes):
        return cls.from_dict(strict_json_loads(payload))


@dataclass(frozen=True)
class ProcessIdentity(Contract):
    pid: int
    created_filetime_100ns: int
    logon_id: str

    def __post_init__(self):
        _integer(self.pid, "pid", 1, (1 << 32) - 1)
        _integer(self.created_filetime_100ns, "created_filetime_100ns", 1)
        _identifier(self.logon_id, "logon_id")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["created_filetime_100ns"] = _decimal(data["created_filetime_100ns"], "created_filetime_100ns", 1)
        return cls(**data)


@dataclass(frozen=True)
class IdentityObservation(Contract):
    identity: ProcessIdentity
    status: IdentityStatus
    reason: str | None = None

    def __post_init__(self):
        _typed(self.identity, ProcessIdentity, "identity")
        _enum(self.status, IdentityStatus, "status")
        if self.reason is not None:
            _identifier(self.reason, "reason")
        if self.status is IdentityStatus.UNKNOWN and self.reason is None:
            raise ContractViolation("reason: unknown identity requires reason")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["identity"] = ProcessIdentity.from_dict(data["identity"])
        data["status"] = _read_enum(data["status"], IdentityStatus, "status")
        return cls(**data)


@dataclass(frozen=True)
class ResourceDemand(Contract):
    cpu_units: float
    physical_bytes: int
    commit_bytes: int
    io_slots: int

    def __post_init__(self):
        _number(self.cpu_units, "cpu_units")
        if self.cpu_units >= 1e308:
            raise ContractViolation("cpu_units: exceeds persisted numeric range")
        for name in ("physical_bytes", "commit_bytes", "io_slots"):
            _integer(getattr(self, name), name, 0, (1 << 63) - 1)

    @classmethod
    def from_dict(cls, value: dict):
        return cls(**_object(value, cls))


@dataclass(frozen=True)
class ReservationRef(Contract):
    kind: AllocationKind
    id: str

    def __post_init__(self):
        _enum(self.kind, AllocationKind, "kind")
        _identifier(self.id, "id")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["kind"] = _read_enum(data["kind"], AllocationKind, "kind")
        return cls(**data)


@dataclass(frozen=True)
class ExecutionSpec(Contract):
    execution_id: str
    task_id: str
    session_id: str
    principal_id: str
    reservation: ReservationRef
    parent_execution_id: str | None
    spec_hash: str
    role: Role
    priority: Priority
    requested: ResourceDemand
    wrapper_identity: ProcessIdentity
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        _uuid(self.execution_id, "execution_id")
        for name in ("task_id", "session_id", "principal_id"):
            _identifier(getattr(self, name), name)
        _typed(self.reservation, ReservationRef, "reservation")
        _hash(self.spec_hash, "spec_hash")
        _enum(self.role, Role, "role")
        _enum(self.priority, Priority, "priority")
        _typed(self.requested, ResourceDemand, "requested")
        _typed(self.wrapper_identity, ProcessIdentity, "wrapper_identity")
        if self.parent_execution_id is not None:
            _uuid(self.parent_execution_id, "parent_execution_id")
            if self.parent_execution_id == self.execution_id:
                raise ContractViolation("parent_execution_id: self-parent")
        if self.reservation.kind is AllocationKind.PARENT:
            if self.parent_execution_id is None or self.reservation.id != self.parent_execution_id:
                raise ContractViolation("reservation: parent reference mismatch")
        elif self.parent_execution_id is not None:
            raise ContractViolation("reservation: nested execution requires parent allocation")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["reservation"] = ReservationRef.from_dict(data["reservation"])
        data["role"] = _read_enum(data["role"], Role, "role")
        data["priority"] = _read_enum(data["priority"], Priority, "priority")
        data["requested"] = ResourceDemand.from_dict(data["requested"])
        data["wrapper_identity"] = ProcessIdentity.from_dict(data["wrapper_identity"])
        return cls(**data)


def make_spec_hash(*, key: bytes, command: str, cwd: str, repo_identifier: str,
                   requested: ResourceDemand, role: Role, priority: Priority,
                   parent_execution_id: str | None, caller: ProcessIdentity) -> str:
    """Hash an in-memory launch payload; never return or retain command/cwd.

    The caller supplies its stable canonical repo identifier and a locally kept
    random key. Windows cwd spelling is normalized without resolving symlinks;
    this is a digest binding, not proof of filesystem identity.
    """
    if type(key) is not bytes or not 32 <= len(key) <= 128:
        raise ContractViolation("key: local 32..128 byte key required")
    # Shell syntax/newlines remain exact. Only NUL/surrogates cannot be launched.
    if not isinstance(command, str) or not command or len(command) > 32767:
        raise ContractViolation("command: bounded launch text required")
    if any(c == "\0" or 0xD800 <= ord(c) <= 0xDFFF for c in command):
        raise ContractViolation("command: invalid launch text")
    _text(cwd, "cwd", 32767)
    drive, path = ntpath.splitdrive(cwd)
    if not drive or not path.startswith(("\\", "/")):
        raise ContractViolation("cwd: absolute Windows path required")
    _identifier(repo_identifier, "repo_identifier")
    _typed(requested, ResourceDemand, "requested")
    _enum(role, Role, "role")
    _enum(priority, Priority, "priority")
    _typed(caller, ProcessIdentity, "caller")
    if parent_execution_id is not None:
        _uuid(parent_execution_id, "parent_execution_id")
    payload = {"schema_version": SCHEMA_VERSION, "domain": "sentinel.execution-spec",
               "command": command, "cwd": ntpath.normcase(ntpath.normpath(cwd)),
               "repo_identifier": repo_identifier, "requested": requested.to_dict(),
               "role": role.value, "priority": priority.value,
               "parent_execution_id": parent_execution_id, "caller": caller.to_dict()}
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class FrameError(Contract):
    code: str
    stage: str
    retry: RetryClass
    execution_id: str | None = None
    action_id: str | None = None
    api_error_code: int | None = None

    def __post_init__(self):
        if not isinstance(self.code, str) or self.code not in ERROR_CODES:
            raise ContractViolation("code: unsupported error code")
        _identifier(self.stage, "stage")
        _enum(self.retry, RetryClass, "retry")
        for name in ("execution_id", "action_id"):
            if getattr(self, name) is not None:
                _uuid(getattr(self, name), name)
        if self.api_error_code is not None:
            _integer(self.api_error_code, "api_error_code", 0, (1 << 32) - 1)

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["retry"] = _read_enum(data["retry"], RetryClass, "retry")
        return cls(**data)


@dataclass(frozen=True)
class MachineFrame(Contract):
    logical_processors: int
    processor_groups: int
    cpu_busy_units: float | None
    physical_total_bytes: int | None
    physical_available_bytes: int | None
    commit_used_bytes: int | None
    commit_limit_bytes: int | None

    def __post_init__(self):
        _integer(self.logical_processors, "logical_processors", 1, 4096)
        _integer(self.processor_groups, "processor_groups", 1, 64)
        if self.cpu_busy_units is not None:
            _number(self.cpu_busy_units, "cpu_busy_units", self.logical_processors)
        for name in ("physical_total_bytes", "physical_available_bytes", "commit_used_bytes", "commit_limit_bytes"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name, 1 if name in ("physical_total_bytes", "commit_limit_bytes") else 0)
        for used, total in ((self.physical_available_bytes, self.physical_total_bytes),
                            (self.commit_used_bytes, self.commit_limit_bytes)):
            if used is not None and total is not None and used > total:
                raise ContractViolation("machine: inconsistent memory bounds")

    @classmethod
    def from_dict(cls, value: dict):
        return cls(**_object(value, cls))


@dataclass(frozen=True)
class JobFrame(Contract):
    execution_id: str
    cpu_units: float | None
    cpu_uncapped_high_water_units: float | None
    private_working_set_bytes: int | None
    private_commit_bytes: int | None
    active_processes: int | None
    membership_complete: bool
    memory_validity: Validity
    counter_epoch: str

    def __post_init__(self):
        _uuid(self.execution_id, "execution_id")
        for name in ("cpu_units", "cpu_uncapped_high_water_units"):
            if getattr(self, name) is not None:
                _number(getattr(self, name), name)
        for name in ("private_working_set_bytes", "private_commit_bytes", "active_processes"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name)
        if type(self.membership_complete) is not bool:
            raise ContractViolation("membership_complete: bool required")
        _enum(self.memory_validity, Validity, "memory_validity")
        _identifier(self.counter_epoch, "counter_epoch")
        if self.membership_complete and self.active_processes is None:
            raise ContractViolation("active_processes: complete membership requires count")
        if self.memory_validity is Validity.VALID and (
                not self.membership_complete or self.private_working_set_bytes is None or self.private_commit_bytes is None):
            raise ContractViolation("memory_validity: valid memory requires complete measurement")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["memory_validity"] = _read_enum(data["memory_validity"], Validity, "memory_validity")
        return cls(**data)


@dataclass(frozen=True)
class FastFrame(Contract):
    sampler_epoch: str
    clock_epoch: str
    sample_seq: int
    window_start_tick_100ns: int
    window_end_tick_100ns: int
    published_tick_100ns: int
    sampled_at_utc: str
    config_revision: str
    registry_revision: int
    machine: MachineFrame
    jobs: tuple[JobFrame, ...]
    validity: Validity
    errors: tuple[FrameError, ...]
    collection_cost_ms: float
    collection_skew_ms: float
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        for name in ("sampler_epoch", "clock_epoch"):
            _identifier(getattr(self, name), name)
        _hash(self.config_revision, "config_revision")
        for name in ("sample_seq", "registry_revision", "window_start_tick_100ns", "window_end_tick_100ns", "published_tick_100ns"):
            _integer(getattr(self, name), name)
        if not self.window_start_tick_100ns < self.window_end_tick_100ns <= self.published_tick_100ns:
            raise ContractViolation("frame: invalid clock order")
        _text(self.sampled_at_utc, "sampled_at_utc", 40)
        try:
            parsed = datetime.fromisoformat(self.sampled_at_utc.replace("Z", "+00:00"))
            if not self.sampled_at_utc.endswith("Z") or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
                raise ValueError
        except ValueError:
            raise ContractViolation("sampled_at_utc: UTC ISO timestamp required") from None
        _typed(self.machine, MachineFrame, "machine")
        _enum(self.validity, Validity, "validity")
        if type(self.jobs) is not tuple or len(self.jobs) > MAX_ENROLLED_JOBS:
            raise ContractViolation("jobs: at most ten immutable aggregates")
        if type(self.errors) is not tuple or len(self.errors) > 64:
            raise ContractViolation("errors: bounded immutable errors required")
        for job in self.jobs:
            _typed(job, JobFrame, "jobs")
        for error in self.errors:
            _typed(error, FrameError, "errors")
        if len({job.execution_id for job in self.jobs}) != len(self.jobs):
            raise ContractViolation("jobs: duplicate execution")
        machine_unknown = any(getattr(self.machine, f.name) is None for f in fields(self.machine))
        if self.validity is Validity.VALID and machine_unknown:
            raise ContractViolation("validity: valid frame requires machine measurements")
        incomplete = machine_unknown or self.validity is not Validity.VALID or any(
            job.cpu_units is None or job.memory_validity is not Validity.VALID or not job.membership_complete
            for job in self.jobs)
        if incomplete and not self.errors:
            raise ContractViolation("errors: unavailable measurement requires reason")
        _number(self.collection_cost_ms, "collection_cost_ms")
        _number(self.collection_skew_ms, "collection_skew_ms")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        for name in ("window_start_tick_100ns", "window_end_tick_100ns", "published_tick_100ns"):
            data[name] = _decimal(data[name], name)
        data["machine"] = MachineFrame.from_dict(data["machine"])
        if type(data["jobs"]) is not list or len(data["jobs"]) > MAX_ENROLLED_JOBS:
            raise ContractViolation("jobs: bounded list required")
        if type(data["errors"]) is not list or len(data["errors"]) > 64:
            raise ContractViolation("errors: bounded list required")
        data["jobs"] = tuple(JobFrame.from_dict(job) for job in data["jobs"])
        data["errors"] = tuple(FrameError.from_dict(error) for error in data["errors"])
        data["validity"] = _read_enum(data["validity"], Validity, "validity")
        return cls(**data)


class CpuControlMode(str, Enum):
    DISABLED = "disabled"
    HARD_CAP = "hard_cap"


@dataclass(frozen=True)
class CpuControl(Contract):
    mode: CpuControlMode
    cpu_rate_bp: int | None

    def __post_init__(self):
        _enum(self.mode, CpuControlMode, "mode")
        if self.mode is CpuControlMode.DISABLED:
            if self.cpu_rate_bp is not None:
                raise ContractViolation("cpu_rate_bp: disabled is a distinct state")
        else:
            _integer(self.cpu_rate_bp, "cpu_rate_bp", 1, 10000)

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["mode"] = _read_enum(data["mode"], CpuControlMode, "mode")
        return cls(**data)


@dataclass(frozen=True)
class CpuTarget(Contract):
    """A desired CPU ceiling; denominator validity still requires native proof."""
    kind: str
    mode: CpuControlMode
    target_cpu_units: float | None
    cpu_rate_bp: int | None
    denominator_logical_processors: int | None

    def __post_init__(self):
        if self.kind != "cpu_rate":
            raise ContractViolation("kind: only cpu_rate supported")
        _enum(self.mode, CpuControlMode, "mode")
        if self.mode is CpuControlMode.DISABLED:
            if any(value is not None for value in (self.target_cpu_units, self.cpu_rate_bp, self.denominator_logical_processors)):
                raise ContractViolation("target: disabled has no units/rate/denominator")
        else:
            _integer(self.denominator_logical_processors, "denominator_logical_processors", 1, 4096)
            _number(self.target_cpu_units, "target_cpu_units", self.denominator_logical_processors)
            if self.target_cpu_units <= 0 or self.target_cpu_units >= self.denominator_logical_processors:
                raise ContractViolation("target_cpu_units: effective ceiling required")
            _integer(self.cpu_rate_bp, "cpu_rate_bp", 1, 10000)
            expected = math.ceil(10000 * self.target_cpu_units / self.denominator_logical_processors)
            if self.cpu_rate_bp != expected:
                raise ContractViolation("cpu_rate_bp: denominator conversion mismatch")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["mode"] = _read_enum(data["mode"], CpuControlMode, "mode")
        return cls(**data)


@dataclass(frozen=True)
class ControlProposal(Contract):
    request_id: str
    execution_id: str
    guardian_epoch: str
    policy_epoch: str
    sampler_epoch: str
    clock_epoch: str
    config_revision: str
    registry_revision: int
    exemption_revision_seen: int
    decision_seq: int
    sample_seq: int
    sample_window_end_tick_100ns: int
    decision_tick_100ns: int
    target: CpuTarget
    reason: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        for name in ("execution_id", "request_id"):
            _uuid(getattr(self, name), name)
        for name in ("guardian_epoch", "policy_epoch", "sampler_epoch", "clock_epoch", "reason"):
            _identifier(getattr(self, name), name)
        _hash(self.config_revision, "config_revision")
        for name in ("registry_revision", "exemption_revision_seen", "decision_seq", "sample_seq",
                     "sample_window_end_tick_100ns", "decision_tick_100ns"):
            _integer(getattr(self, name), name)
        _typed(self.target, CpuTarget, "target")
        if self.sample_window_end_tick_100ns > self.decision_tick_100ns:
            raise ContractViolation("proposal: decision predates sample")
        if self.target.mode is CpuControlMode.HARD_CAP:
            if self.decision_tick_100ns - self.sample_window_end_tick_100ns > 3 * TICKS_PER_SECOND:
                raise ContractViolation("proposal: sample already stale at decision")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        for name in ("sample_window_end_tick_100ns", "decision_tick_100ns"):
            data[name] = _decimal(data[name], name)
        data["target"] = CpuTarget.from_dict(data["target"])
        return cls(**data)


def derive_lease_deadline(*, now_tick_100ns: int, sample_window_end_tick_100ns: int,
                          intervention_deadline_tick_100ns: int) -> int:
    """Pure guardian calculation, never an authorization or a renewal decision.

    The caller must establish clock continuity, current authoritative exemption,
    fresh sequence and the immutable original intervention deadline first.
    """
    for name, value in (("now_tick_100ns", now_tick_100ns),
                        ("sample_window_end_tick_100ns", sample_window_end_tick_100ns),
                        ("intervention_deadline_tick_100ns", intervention_deadline_tick_100ns)):
        _integer(value, name)
    if not 0 <= now_tick_100ns - sample_window_end_tick_100ns <= 3 * TICKS_PER_SECOND:
        raise ContractViolation("lease: fresh same-clock sample required")
    if not now_tick_100ns < intervention_deadline_tick_100ns <= now_tick_100ns + 60 * TICKS_PER_SECOND:
        raise ContractViolation("lease: active bounded intervention required")
    return min(now_tick_100ns + 6 * TICKS_PER_SECOND,
               sample_window_end_tick_100ns + 6 * TICKS_PER_SECOND,
               intervention_deadline_tick_100ns)


class ApplyResult(str, Enum):
    APPLIED = "APPLIED"
    RENEWED = "RENEWED"
    RESTORED = "RESTORED"
    REJECTED = "REJECTED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class ApplyAck(Contract):
    request_id: str
    action_id: str | None
    execution_id: str
    guardian_epoch: str
    policy_epoch: str
    decision_seq: int
    result: ApplyResult
    applied_flags: int | None
    applied_rate_bp: int | None
    applied_validity: Validity
    queried_tick_100ns: int | None
    lease_deadline_tick_100ns: int | None
    intervention_deadline_tick_100ns: int | None
    reason: str
    win32_error: int | None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        for name in ("request_id", "execution_id"):
            _uuid(getattr(self, name), name)
        if self.action_id is not None:
            _uuid(self.action_id, "action_id")
        for name in ("guardian_epoch", "policy_epoch", "reason"):
            _identifier(getattr(self, name), name)
        _integer(self.decision_seq, "decision_seq")
        _enum(self.result, ApplyResult, "result")
        _enum(self.applied_validity, Validity, "applied_validity")
        for name in ("queried_tick_100ns", "lease_deadline_tick_100ns", "intervention_deadline_tick_100ns"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name)
        if self.win32_error is not None:
            _integer(self.win32_error, "win32_error", 0, (1 << 32) - 1)
        if self.applied_validity is not Validity.VALID:
            if self.applied_flags is not None or self.applied_rate_bp is not None:
                raise ContractViolation("applied: unknown readback cannot claim values")
        else:
            _integer(self.applied_flags, "applied_flags", 0, (1 << 32) - 1)
            if self.applied_rate_bp is not None:
                _integer(self.applied_rate_bp, "applied_rate_bp", 0, 10000)
            if self.queried_tick_100ns is None:
                raise ContractViolation("queried_tick_100ns: verified readback requires timestamp")
        if self.result in (ApplyResult.APPLIED, ApplyResult.RENEWED):
            if (self.action_id is None or self.applied_validity is not Validity.VALID
                    or self.applied_flags != 5 or self.applied_rate_bp is None
                    or self.applied_rate_bp < 1 or self.win32_error is not None):
                raise ContractViolation("result: active acknowledgement requires verified hard cap")
            if (self.lease_deadline_tick_100ns is None or self.intervention_deadline_tick_100ns is None
                    or not self.queried_tick_100ns < self.lease_deadline_tick_100ns <= self.intervention_deadline_tick_100ns):
                raise ContractViolation("result: active acknowledgement requires lease")
        elif self.result is ApplyResult.RESTORED:
            if (self.action_id is None or self.applied_validity is not Validity.VALID
                    or self.applied_flags & 1 or self.win32_error is not None
                    or self.lease_deadline_tick_100ns is not None):
                raise ContractViolation("result: restoration requires verified disabled readback")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        for name in ("queried_tick_100ns", "lease_deadline_tick_100ns", "intervention_deadline_tick_100ns"):
            if data[name] is not None:
                data[name] = _decimal(data[name], name)
        data["result"] = _read_enum(data["result"], ApplyResult, "result")
        data["applied_validity"] = _read_enum(data["applied_validity"], Validity, "applied_validity")
        return cls(**data)


class GrantState(str, Enum):
    RECORDED = "recorded"
    ACTIVE = "active"
    REVOKED = "revoked"


class EnforcementState(str, Enum):
    RESTORED = "restored"
    RESTORE_PENDING = "restore_pending"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class GrantAck(Contract):
    """expires_at is the original authority's UTC Unix timestamp in seconds."""
    grant_id: str
    grant_state: GrantState
    expires_at: float
    exemption_revision: int
    enforcement_state: EnforcementState
    owned_execution_ids: tuple[str, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        _identifier(self.grant_id, "grant_id")
        _enum(self.grant_state, GrantState, "grant_state")
        _number(self.expires_at, "expires_at")
        _integer(self.exemption_revision, "exemption_revision")
        _enum(self.enforcement_state, EnforcementState, "enforcement_state")
        if type(self.owned_execution_ids) is not tuple or len(self.owned_execution_ids) > MAX_ENROLLED_JOBS:
            raise ContractViolation("owned_execution_ids: bounded immutable list required")
        for value in self.owned_execution_ids:
            _uuid(value, "owned_execution_ids")
        if len(set(self.owned_execution_ids)) != len(self.owned_execution_ids):
            raise ContractViolation("owned_execution_ids: duplicate execution")
        if self.grant_state is GrantState.ACTIVE and self.enforcement_state is EnforcementState.RESTORE_PENDING:
            raise ContractViolation("grant_state: pending enforcement must remain recorded")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["grant_state"] = _read_enum(data["grant_state"], GrantState, "grant_state")
        data["enforcement_state"] = _read_enum(data["enforcement_state"], EnforcementState, "enforcement_state")
        if type(data["owned_execution_ids"]) is not list or len(data["owned_execution_ids"]) > MAX_ENROLLED_JOBS:
            raise ContractViolation("owned_execution_ids: bounded list required")
        data["owned_execution_ids"] = tuple(data["owned_execution_ids"])
        return cls(**data)


class LaunchClaimState(str, Enum):
    UNCLAIMED = "unclaimed"
    IN_FLIGHT = "in_flight"
    SEALED = "sealed"


class RootOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LifecycleAck(Contract):
    execution_id: str
    reservation: ReservationRef
    state: LifecycleState
    state_revision: int
    launch_claim_state: LaunchClaimState
    root_outcome: RootOutcome | None
    job_empty_verified: bool | None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        _uuid(self.execution_id, "execution_id")
        _typed(self.reservation, ReservationRef, "reservation")
        _enum(self.state, LifecycleState, "state")
        _integer(self.state_revision, "state_revision")
        _enum(self.launch_claim_state, LaunchClaimState, "launch_claim_state")
        if self.root_outcome is not None:
            _enum(self.root_outcome, RootOutcome, "root_outcome")
        if self.job_empty_verified is not None and type(self.job_empty_verified) is not bool:
            raise ContractViolation("job_empty_verified: bool or null required")
        if self.state is LifecycleState.FINISHED and (
                self.job_empty_verified is not True or self.launch_claim_state is not LaunchClaimState.SEALED):
            raise ContractViolation("state: finished requires sealed launch and verified empty Job")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["reservation"] = ReservationRef.from_dict(data["reservation"])
        data["state"] = _read_enum(data["state"], LifecycleState, "state")
        data["launch_claim_state"] = _read_enum(data["launch_claim_state"], LaunchClaimState, "launch_claim_state")
        if data["root_outcome"] is not None:
            data["root_outcome"] = _read_enum(data["root_outcome"], RootOutcome, "root_outcome")
        return cls(**data)


@dataclass(frozen=True)
class PendingIntent(Contract):
    action_id: str
    old: CpuControl
    new: CpuControl

    def __post_init__(self):
        _uuid(self.action_id, "action_id")
        _typed(self.old, CpuControl, "old")
        _typed(self.new, CpuControl, "new")

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["old"] = CpuControl.from_dict(data["old"])
        data["new"] = CpuControl.from_dict(data["new"])
        return cls(**data)


@dataclass(frozen=True)
class RecoveryManifest(Contract):
    execution_id: str
    reservation: ReservationRef
    spec_hash: str
    job_name: str
    creation_nonce: str
    wrapper_identity: ProcessIdentity
    root_identity: ProcessIdentity | None
    guardian_identity: ProcessIdentity
    guardian_epoch: str
    original: CpuControl
    last_applied: CpuControl | None
    pending_intent: PendingIntent | None
    allocated_floor: ResourceDemand
    manifest_seq: int
    manifest_hash: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _version(self.schema_version)
        _uuid(self.execution_id, "execution_id")
        _typed(self.reservation, ReservationRef, "reservation")
        if self.reservation.kind is AllocationKind.PARENT:
            raise ContractViolation("reservation: nested subspan cannot own a Job")
        _hash(self.spec_hash, "spec_hash")
        if not isinstance(self.creation_nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", self.creation_nonce):
            raise ContractViolation("creation_nonce: random 128-bit nonce required")
        # The nonce is part of the name, preventing execution-name reuse.
        if self.job_name != f"Local\\ResourceSentinel.Job.{self.execution_id}.{self.creation_nonce}":
            raise ContractViolation("job_name: execution/nonce binding mismatch")
        for name in ("wrapper_identity", "guardian_identity"):
            _typed(getattr(self, name), ProcessIdentity, name)
        if self.root_identity is not None:
            _typed(self.root_identity, ProcessIdentity, "root_identity")
        identities = (self.wrapper_identity, self.guardian_identity) + (() if self.root_identity is None else (self.root_identity,))
        if len({identity.logon_id for identity in identities}) != 1:
            raise ContractViolation("identity: manifest crosses logon scope")
        _identifier(self.guardian_epoch, "guardian_epoch")
        _typed(self.original, CpuControl, "original")
        if self.original.mode is not CpuControlMode.DISABLED:
            raise ContractViolation("original: own Job must start disabled")
        if self.last_applied is not None:
            _typed(self.last_applied, CpuControl, "last_applied")
        if self.pending_intent is not None:
            _typed(self.pending_intent, PendingIntent, "pending_intent")
            if self.pending_intent.old != (self.last_applied or self.original):
                raise ContractViolation("pending_intent: old control mismatch")
        _typed(self.allocated_floor, ResourceDemand, "allocated_floor")
        _integer(self.manifest_seq, "manifest_seq")
        _hash(self.manifest_hash, "manifest_hash")
        if not hmac.compare_digest(self.manifest_hash, self.content_hash()):
            raise ContractViolation("manifest_hash: content mismatch")

    def content_hash(self) -> str:
        data = self.to_dict()
        data.pop("manifest_hash")
        return hashlib.sha256(_canonical(data)).hexdigest()

    @classmethod
    def create(cls, **values):
        """Construct a checksummed record; hash is integrity, not authentication."""
        if "manifest_hash" in values:
            raise ContractViolation("manifest_hash: computed by create")
        values.setdefault("schema_version", SCHEMA_VERSION)
        data = {name: _wire(value, name) for name, value in values.items()}
        values["manifest_hash"] = hashlib.sha256(_canonical(data)).hexdigest()
        return cls(**values)

    @classmethod
    def from_dict(cls, value: dict):
        data = _object(value, cls)
        data["reservation"] = ReservationRef.from_dict(data["reservation"])
        for name in ("wrapper_identity", "guardian_identity"):
            data[name] = ProcessIdentity.from_dict(data[name])
        if data["root_identity"] is not None:
            data["root_identity"] = ProcessIdentity.from_dict(data["root_identity"])
        for name in ("original", "last_applied"):
            if data[name] is not None:
                data[name] = CpuControl.from_dict(data[name])
        if data["pending_intent"] is not None:
            data["pending_intent"] = PendingIntent.from_dict(data["pending_intent"])
        data["allocated_floor"] = ResourceDemand.from_dict(data["allocated_floor"])
        return cls(**data)
