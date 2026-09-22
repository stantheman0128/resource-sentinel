"""Closed operator messages: conservative requests and separately stated facts.

These contracts carry locators and observations, never native custody or a
permission to launch work, apply a CPU target, or repair a ledger.
"""
from dataclasses import dataclass
from enum import Enum
import re

from .contracts import (Contract, ContractViolation, SCHEMA_VERSION,
    _decimal, _enum, _identifier, _integer, _object, _read_enum, _typed, _version)
from .ipc import _uuid as _wire_uuid


MAX_OPERATOR_ITEMS = 32
MAX_OPERATOR_REQUESTS = 128


def _uuid(value, name):
    try:
        _wire_uuid(value)
    except Exception:
        raise ContractViolation(f"{name}: canonical nonzero UUID required") from None


def _code(value, name="reason"):
    if type(value) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", value) is None:
        raise ContractViolation(f"{name}: bounded stable code required")


def _bool(value, name):
    if value is not None and type(value) is not bool:
        raise ContractViolation(f"{name}: boolean or unknown required")


def _cursor(value):
    if value is not None and (type(value) is not str or
            re.fullmatch(r"[A-Za-z0-9_.:-]{1,192}", value) is None):
        raise ContractViolation("cursor: bounded opaque token required")


class OperatorOperation(str, Enum):
    DESCRIBE = "describe"
    DRAIN = "drain"
    RESTORE_ONLY = "restore_only"
    AUDIT = "audit"


class OperatorOutcome(str, Enum):
    COMPLETE = "complete"
    REFUSED = "refused"
    PENDING = "pending"
    UNAVAILABLE = "unavailable"
    UNVERIFIED = "unverified"


def _binding(value):
    _version(value.schema_version)
    for name in ("request_id", "instance_id", "policy_instance_id"):
        _uuid(getattr(value, name), name)
    _identifier(value.guardian_epoch, "guardian_epoch")
    _enum(value.operation, OperatorOperation, "operation")


@dataclass(frozen=True)
class OperatorRequest(Contract):
    request_id: str
    operation: OperatorOperation
    instance_id: str
    policy_instance_id: str
    guardian_epoch: str
    expected_registry_revision: int | None = None
    observe_request_id: str | None = None
    cursor: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        if self.expected_registry_revision is not None:
            _integer(self.expected_registry_revision, "expected_registry_revision", 0, (1 << 63) - 1)
        if self.operation is OperatorOperation.DRAIN and self.expected_registry_revision is None:
            raise ContractViolation("drain: original registry revision required")
        if self.observe_request_id is not None:
            _uuid(self.observe_request_id, "observe_request_id")
            if self.operation is not OperatorOperation.DESCRIBE:
                raise ContractViolation("observe_request_id: describe only")
        _cursor(self.cursor)
        if self.cursor is not None and (self.operation is not OperatorOperation.AUDIT or
                self.expected_registry_revision is None):
            raise ContractViolation("cursor: audit with stable revision required")

    @property
    def mutating(self):
        return self.operation in (OperatorOperation.DRAIN, OperatorOperation.RESTORE_ONLY)

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        data["operation"] = _read_enum(data["operation"], OperatorOperation, "operation")
        return cls(**data)


@dataclass(frozen=True)
class OperatorInventoryItem(Contract):
    execution_id: str
    provenance: str
    reason: str
    native_disabled: bool | None = None
    bookkeeping_settled: bool | None = None
    cleanup_complete: bool | None = None
    observed_tick_100ns: int | None = None
    applied_flags: int | None = None
    applied_rate_bp: int | None = None

    def __post_init__(self):
        _uuid(self.execution_id, "execution_id")
        if type(self.provenance) is not str or self.provenance not in {"native", "retired", "unknown"}:
            raise ContractViolation("provenance: closed evidence kind required")
        _code(self.reason)
        for name in ("native_disabled", "bookkeeping_settled", "cleanup_complete"):
            _bool(getattr(self, name), name)
        if self.observed_tick_100ns is not None:
            _integer(self.observed_tick_100ns, "observed_tick_100ns")
        if self.provenance == "native":
            _integer(self.applied_flags, "applied_flags", 0, (1 << 32) - 1)
            if (self.observed_tick_100ns is None or type(self.native_disabled) is not bool or
                    self.native_disabled != (self.applied_flags & 1 == 0)):
                raise ContractViolation("native: timestamp and matching CPU readback required")
            if self.applied_rate_bp is not None:
                _integer(self.applied_rate_bp, "applied_rate_bp", 0, 10000)
        elif any(getattr(self, name) is not None for name in (
                "native_disabled", "observed_tick_100ns", "applied_flags", "applied_rate_bp")):
            raise ContractViolation("provenance: non-native proof cannot claim native readback")
        if self.provenance == "retired" and (self.bookkeeping_settled is not True or
                self.cleanup_complete is not True):
            raise ContractViolation("retired: exact settled retirement required")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        if data["observed_tick_100ns"] is not None:
            data["observed_tick_100ns"] = _decimal(data["observed_tick_100ns"], "observed_tick_100ns")
        return cls(**data)


@dataclass(frozen=True)
class OperatorReply(Contract):
    request_id: str
    operation: OperatorOperation
    instance_id: str
    policy_instance_id: str
    guardian_epoch: str
    outcome: OperatorOutcome
    scope: str
    reason: str
    accepted: bool | None = None
    desired_mode: str | None = None
    host_state: str = "unavailable"
    inventory_complete: bool | None = None
    native_disabled: bool | None = None
    bookkeeping_settled: bool | None = None
    slot_released: bool | None = None
    barrier_cleared: bool | None = None
    cleanup_settled: bool | None = None
    remaining_executions: int | None = None
    remaining_custody: int | None = None
    registry_revision: int | None = None
    items: tuple[OperatorInventoryItem, ...] = ()
    next_cursor: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        _binding(self)
        _enum(self.outcome, OperatorOutcome, "outcome")
        if type(self.scope) is not str or self.scope not in {"instance", "guardian", "helper"}:
            raise ContractViolation("scope: exact host scope required")
        if self.desired_mode not in (None, "off"):
            raise ContractViolation("desired_mode: operator can request only off")
        _code(self.reason)
        _code(self.host_state, "host_state")
        for name in ("accepted", "inventory_complete", "native_disabled", "bookkeeping_settled",
                     "slot_released", "barrier_cleared", "cleanup_settled"):
            _bool(getattr(self, name), name)
        for name in ("remaining_executions", "remaining_custody", "registry_revision"):
            if getattr(self, name) is not None:
                _integer(getattr(self, name), name, 0, (1 << 63) - 1)
        if type(self.items) is not tuple or len(self.items) > MAX_OPERATOR_ITEMS:
            raise ContractViolation("items: bounded immutable inventory required")
        for item in self.items:
            _typed(item, OperatorInventoryItem, "items")
        if len({item.execution_id for item in self.items}) != len(self.items):
            raise ContractViolation("items: duplicate execution")
        _cursor(self.next_cursor)
        if self.next_cursor is not None and (self.operation is not OperatorOperation.AUDIT or
                self.registry_revision is None or self.inventory_complete is True):
            raise ContractViolation("next_cursor: incomplete audit with stable revision required")
        if self.outcome is OperatorOutcome.PENDING and self.accepted is False:
            raise ContractViolation("pending: cannot claim refused acceptance")
        if self.outcome is OperatorOutcome.REFUSED and self.accepted is True:
            raise ContractViolation("refused: cannot claim acceptance")

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        data["operation"] = _read_enum(data["operation"], OperatorOperation, "operation")
        data["outcome"] = _read_enum(data["outcome"], OperatorOutcome, "outcome")
        if type(data["items"]) is not list or len(data["items"]) > MAX_OPERATOR_ITEMS:
            raise ContractViolation("items: bounded list required")
        data["items"] = tuple(OperatorInventoryItem.from_dict(item) for item in data["items"])
        return cls(**data)
