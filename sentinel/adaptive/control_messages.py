"""Bounded frame/restore control messages; typed data is not control authority."""
from dataclasses import dataclass
from enum import Enum
import re

from .contracts import (Contract, ContractViolation, FastFrame, MAX_ENROLLED_JOBS,
    SCHEMA_VERSION, Validity, _decimal, _enum, _hash, _identifier, _integer,
    _object, _read_enum, _typed, _uuid, _version)


def _binding(value):
    _version(value.schema_version)
    _uuid(value.request_id, "request_id")
    _identifier(value.guardian_epoch, "guardian_epoch")
    _identifier(value.policy_epoch, "policy_epoch")


def _reason(value):
    if type(value) is not str or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value):
        raise ContractViolation("reason: stable bounded code required")


def _boolean(value, name, *, unknown=False):
    if type(value) is not bool and not (unknown and value is None):
        raise ContractViolation(f"{name}: boolean required")


@dataclass(frozen=True)
class ControlFrameRequest(Contract):
    request_id: str
    guardian_epoch: str
    policy_epoch: str
    frame: FastFrame
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        _typed(self.frame, FastFrame, "frame")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        data["frame"] = FastFrame.from_dict(data["frame"])
        return cls(**data)


@dataclass(frozen=True)
class ControlRestoreRequest(Contract):
    request_id: str
    guardian_epoch: str
    policy_epoch: str
    execution_id: str
    reason: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        _uuid(self.execution_id, "execution_id")
        _reason(self.reason)

    @classmethod
    def from_dict(cls, value):
        return cls(**_object(value, cls))


class ControlObservation(str, Enum):
    UNCAPPED = "UNCAPPED"
    CAPPED = "CAPPED"
    REJECTED = "REJECTED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class ControlFrameResult(Contract):
    execution_id: str
    observation: ControlObservation
    queried_tick_100ns: int | None
    barrier_cleared: bool
    reason: str

    def __post_init__(self):
        _uuid(self.execution_id, "execution_id")
        _enum(self.observation, ControlObservation, "observation")
        _boolean(self.barrier_cleared, "barrier_cleared")
        _reason(self.reason)
        if self.queried_tick_100ns is not None:
            _integer(self.queried_tick_100ns, "queried_tick_100ns")
        if self.observation in (ControlObservation.UNCAPPED, ControlObservation.CAPPED) and self.queried_tick_100ns is None:
            raise ContractViolation("observation: native observation requires query time")
        if self.barrier_cleared and self.observation is not ControlObservation.UNCAPPED:
            raise ContractViolation("barrier_cleared: requires uncapped observation")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        data["observation"] = _read_enum(data["observation"], ControlObservation, "observation")
        if data["queried_tick_100ns"] is not None:
            data["queried_tick_100ns"] = _decimal(data["queried_tick_100ns"], "queried_tick_100ns")
        return cls(**data)


@dataclass(frozen=True)
class ControlFrameAck(Contract):
    request_id: str
    guardian_epoch: str
    policy_epoch: str
    sampler_epoch: str
    clock_epoch: str
    sample_seq: int
    registry_revision: int
    config_revision: str
    results: tuple[ControlFrameResult, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        _identifier(self.sampler_epoch, "sampler_epoch")
        _identifier(self.clock_epoch, "clock_epoch")
        _integer(self.sample_seq, "sample_seq")
        _integer(self.registry_revision, "registry_revision")
        _hash(self.config_revision, "config_revision")
        if type(self.results) is not tuple or len(self.results) > MAX_ENROLLED_JOBS:
            raise ContractViolation("results: at most ten immutable results required")
        for result in self.results:
            _typed(result, ControlFrameResult, "results")
        if len({item.execution_id for item in self.results}) != len(self.results):
            raise ContractViolation("results: duplicate execution")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        if type(data["results"]) is not list or len(data["results"]) > MAX_ENROLLED_JOBS:
            raise ContractViolation("results: bounded list required")
        data["results"] = tuple(ControlFrameResult.from_dict(item) for item in data["results"])
        return cls(**data)


class RestoreOutcome(str, Enum):
    RESTORED = "RESTORED"
    REJECTED = "REJECTED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class RestoreAck(Contract):
    request_id: str
    guardian_epoch: str
    policy_epoch: str
    execution_id: str
    result: RestoreOutcome
    native_disabled: bool | None
    bookkeeping_settled: bool | None
    slot_released: bool | None
    barrier_cleared: bool | None
    applied_flags: int | None
    applied_rate_bp: int | None
    applied_validity: Validity
    queried_tick_100ns: int | None
    reason: str
    win32_error: int | None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        _uuid(self.execution_id, "execution_id")
        _enum(self.result, RestoreOutcome, "result")
        _enum(self.applied_validity, Validity, "applied_validity")
        _reason(self.reason)
        for name in ("native_disabled", "bookkeeping_settled", "slot_released", "barrier_cleared"):
            _boolean(getattr(self, name), name, unknown=True)
        if self.win32_error is not None:
            _integer(self.win32_error, "win32_error", 0, (1 << 32) - 1)
        if self.queried_tick_100ns is not None:
            _integer(self.queried_tick_100ns, "queried_tick_100ns")
        if self.applied_validity is Validity.VALID:
            _integer(self.applied_flags, "applied_flags", 0, (1 << 32) - 1)
            if self.applied_rate_bp is not None:
                _integer(self.applied_rate_bp, "applied_rate_bp", 0, 10000)
            if (self.queried_tick_100ns is None or type(self.native_disabled) is not bool or
                    self.native_disabled != (self.applied_flags & 1 == 0)):
                raise ContractViolation("native_disabled: exact valid readback required")
        elif self.applied_flags is not None or self.applied_rate_bp is not None or self.native_disabled is not None:
            raise ContractViolation("applied: unknown readback cannot claim native values")
        if self.result is RestoreOutcome.RESTORED and (
                self.native_disabled is not True or self.bookkeeping_settled is not True or
                self.slot_released is not True or self.applied_validity is not Validity.VALID or
                self.win32_error is not None):
            raise ContractViolation("result: restoration requires readback and settled obligations")
        if self.barrier_cleared and (self.native_disabled is not True or
                self.bookkeeping_settled is not True or self.slot_released is not True):
            raise ContractViolation("barrier_cleared: settled restoration required")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        data["result"] = _read_enum(data["result"], RestoreOutcome, "result")
        data["applied_validity"] = _read_enum(data["applied_validity"], Validity, "applied_validity")
        if data["queried_tick_100ns"] is not None:
            data["queried_tick_100ns"] = _decimal(data["queried_tick_100ns"], "queried_tick_100ns")
        return cls(**data)
