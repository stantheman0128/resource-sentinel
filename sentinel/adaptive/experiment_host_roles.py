"""Fixed, private role inputs for an isolated production-host experiment plan.

These objects are DATA, not parent authentication, file identity, admission,
readiness, a release receipt, or control authority. Parsing/hashing performs no
file, IPC, or native operation. The original parent must bind each actor and its
references to declared members, and verify profile bytes against the declared
hash before dispatch. A wrapper's guardian identity/endpoints come from that
parent's retained created guardian, never from these serialized inputs.

The JSON contains private paths and potentially a raw workload command. It is
for the private original plan/bootstrap only; do not put it in telemetry. Helper
dispatch is shadow-only. This module cannot select an active controller, start a
supervisor, construct a host, or establish a Windows capability gate.
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields
import hashlib
import json
import ntpath
from typing import ClassVar

from .contracts import (
    ContractViolation, _hash, _identifier, _uuid as _contract_uuid, strict_json_loads,
)
from .launch_spec import LaunchSpec, LaunchSpecError, _absolute_windows_path


MAX_ROLE_SPEC_BYTES = 64 * 1024
MAX_WRAPPER_WAIT_SEC = 86400
MAX_HELPER_ITERATIONS = 86400
DOMAIN = "sentinel-experiment-host-role-v1"


class ExperimentRoleSpecError(ValueError):
    """Sanitized schema failure; supplied command/path values are never echoed."""

    def __init__(self, reason="invalid"):
        self.reason = "experiment_role_" + reason
        super().__init__(self.reason)


def _fail(reason="invalid"):
    raise ExperimentRoleSpecError(reason)


def _text(value, validator, name):
    if type(value) is not str:
        _fail()
    try:
        validator(value, name)
    except ContractViolation:
        _fail()


def _uuid(value, name):
    _contract_uuid(value, name)
    # Match the actual experiment ledger, native pipe and POLICY identifiers.
    if value == "00000000-0000-0000-0000-000000000000":
        raise ContractViolation("nonzero UUID required")


def _path(value):
    try:
        _absolute_windows_path(value)
    except LaunchSpecError:
        _fail()
    # Spelling validation only: no normalization changes the hashed input, and
    # no assertion is made about junctions, file identity, existence or access.
    if ntpath.normpath(value) != value:
        _fail()


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail()


def _canonical(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _fail()
    if len(raw) > MAX_ROLE_SPEC_BYTES:
        _fail("too_large")
    return raw


class _RoleSpec:
    role: ClassVar[str]

    def _validate_common(self):
        if type(self) not in (GuardianRoleSpec, WrapperRoleSpec, HelperRoleSpec):
            _fail()
        _text(self.member_id, _uuid, "member_id")
        _path(self.data_dir)

    def _wire(self):
        data = {item.name: getattr(self, item.name) for item in fields(self)}
        if type(self) is WrapperRoleSpec:
            data["launch_spec"] = self.launch_spec.to_dict()
        return {"domain": DOMAIN, "role": self.role, **data}

    def __post_init__(self):
        self._validate_common()
        self._validate()
        _canonical(self._wire())

    def to_dict(self):
        """Return private plan data; this is deliberately not host kwargs."""
        self.__post_init__()
        return self._wire()

    def to_json(self):
        return _canonical(self.to_dict()).decode("ascii")

    @property
    def sha256(self):
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()

    @classmethod
    def from_dict(cls, value):
        if cls not in (GuardianRoleSpec, WrapperRoleSpec, HelperRoleSpec):
            _fail()
        expected = {item.name for item in fields(cls)} | {"domain", "role"}
        if (type(value) is not dict or set(value) != expected or
                type(value["domain"]) is not str or value["domain"] != DOMAIN or
                type(value["role"]) is not str or value["role"] != cls.role):
            _fail()
        data = {item.name: value[item.name] for item in fields(cls)}
        if cls is WrapperRoleSpec:
            try:
                data["launch_spec"] = LaunchSpec.from_dict(data["launch_spec"])
            except (ContractViolation, LaunchSpecError):
                _fail()
        return cls(**data)

    @classmethod
    def from_json(cls, value):
        return cls.from_dict(_decode(value))


@dataclass(frozen=True)
class GuardianRoleSpec(_RoleSpec):
    member_id: str
    data_dir: str = field(repr=False)
    journal_dir: str = field(repr=False)
    profile_path: str = field(repr=False)
    profile_sha256: str
    guardian_epoch: str
    launch_instance_id: str
    query_instance_id: str
    control_instance_id: str
    instance_id: str
    operator_instance_id: str
    policy_instance_id: str
    rpc_timeout_ms: int = 100
    role: ClassVar[str] = "guardian"

    def _validate(self):
        _path(self.journal_dir)
        _path(self.profile_path)
        _text(self.profile_sha256, _hash, "profile_sha256")
        _text(self.guardian_epoch, _identifier, "guardian_epoch")
        instance_ids = (self.launch_instance_id, self.query_instance_id,
                        self.control_instance_id, self.instance_id,
                        self.operator_instance_id, self.policy_instance_id)
        for value in instance_ids:
            _text(value, _uuid, "instance_id")
        if len(set(instance_ids)) != len(instance_ids):
            _fail()
        _int(self.rpc_timeout_ms, 1, 1000)


@dataclass(frozen=True)
class WrapperRoleSpec(_RoleSpec):
    member_id: str
    data_dir: str = field(repr=False)
    launch_spec: LaunchSpec = field(repr=False)
    workload_member_id: str
    guardian_member_id: str
    rpc_timeout_ms: int = 1000
    poll_interval_ms: int = 100
    max_wait_sec: int = 3600
    role: ClassVar[str] = "wrapper"

    def _validate(self):
        if type(self.launch_spec) is not LaunchSpec:
            _fail()
        try:
            self.launch_spec.__post_init__()
        except (ContractViolation, LaunchSpecError):
            _fail()
        for value in (self.workload_member_id, self.guardian_member_id):
            _text(value, _uuid, "member_id")
        if len({self.member_id, self.workload_member_id, self.guardian_member_id}) != 3:
            _fail()
        _int(self.rpc_timeout_ms, 1, 1000)
        _int(self.poll_interval_ms, 1, 1000)
        _int(self.max_wait_sec, 1, MAX_WRAPPER_WAIT_SEC)


@dataclass(frozen=True)
class HelperRoleSpec(_RoleSpec):
    member_id: str
    data_dir: str = field(repr=False)
    profile_path: str = field(repr=False)
    profile_sha256: str
    enroll_every_ticks: int = 5
    report_every_ticks: int = 10
    iterations: int = 1
    role: ClassVar[str] = "helper"

    def _validate(self):
        _path(self.profile_path)
        _text(self.profile_sha256, _hash, "profile_sha256")
        _int(self.enroll_every_ticks, 1, 3600)
        _int(self.report_every_ticks, 1, 3600)
        _int(self.iterations, 1, MAX_HELPER_ITERATIONS)


def _decode(payload):
    if type(payload) not in (str, bytes):
        _fail()
    try:
        size = len(payload.encode("utf-8")) if type(payload) is str else len(payload)
        if size > MAX_ROLE_SPEC_BYTES:
            _fail("too_large")
        return strict_json_loads(payload)
    except (ContractViolation, UnicodeError):
        _fail()


def role_spec_from_dict(value):
    """Decode the closed three-role union; does not resolve or dispatch it."""
    if type(value) is not dict or type(value.get("role")) is not str:
        _fail()
    if value["role"] == "guardian":
        return GuardianRoleSpec.from_dict(value)
    if value["role"] == "wrapper":
        return WrapperRoleSpec.from_dict(value)
    if value["role"] == "helper":
        return HelperRoleSpec.from_dict(value)
    _fail()


def role_spec_from_json(payload):
    return role_spec_from_dict(_decode(payload))
