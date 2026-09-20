"""Bounded, in-memory transport from a thin wrapper to a local launch host.

The payload is UTF-8 JSON in one standard Base64 argument. Base64 is not
encryption: same-user process inspection can reveal the original command and
paths. Never log these objects, serialize them into telemetry, or persist them.
Validation grants no admission, native identity, launch, or control authority.
This module performs no filesystem access, process creation, or retry.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import json
import ntpath
import subprocess

from .contracts import (
    ContractViolation, MAX_MESSAGE_BYTES, Priority, ResourceDemand, Role,
    SCHEMA_VERSION, _identifier, _object, _read_enum, _version,
    strict_json_loads,
)


# CreateProcessW includes the trailing NUL in its UTF-16 command-line limit.
# https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
CREATE_PROCESS_LIMIT = 32767
# This bounds the literal cmd command line only. Environment-variable expansion
# can independently exceed cmd's limit; no environment is read or expanded here.
# https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/command-line-string-limitation
CMD_LIMIT = 8191
MAX_BASE64_CHARS = 4 * ((MAX_MESSAGE_BYTES + 2) // 3)
MAX_ADMISSION_TIMEOUT_SEC = (1 << 31) - 1


class LaunchSpecError(ValueError):
    """A sanitized transport error; never includes supplied field values."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def utf16_units(value: str) -> int:
    """Count Windows UTF-16 code units, rejecting unpaired surrogates."""
    if type(value) is not str:
        raise LaunchSpecError("launch_payload_invalid")
    try:
        return len(value.encode("utf-16-le", errors="strict")) // 2
    except UnicodeError:
        raise LaunchSpecError("launch_payload_invalid") from None


def _command(value: str) -> None:
    # Preserve shell syntax, embedded quotes, whitespace, and newlines exactly,
    # matching ManagedAdmission.current's command boundary.
    if type(value) is not str or not value or len(value) > CREATE_PROCESS_LIMIT:
        raise LaunchSpecError("launch_payload_invalid")
    if any(char == "\0" or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise LaunchSpecError("launch_payload_invalid")


def _absolute_windows_path(value: str) -> None:
    # This is spelling validation, not filesystem identity or executable proof.
    # Quotes and controls cannot be valid Windows filename characters and must
    # not enter the literal cmd.exe wrapper's quoted application name.
    if type(value) is not str or not 1 <= len(value) <= CREATE_PROCESS_LIMIT:
        raise LaunchSpecError("launch_payload_invalid")
    if any(ord(char) < 32 or char == '"' or 0xD800 <= ord(char) <= 0xDFFF
           for char in value):
        raise LaunchSpecError("launch_payload_invalid")
    drive, path = ntpath.splitdrive(value)
    if not drive or not path.startswith(("\\", "/")):
        raise LaunchSpecError("launch_payload_invalid")


@dataclass(frozen=True)
class LaunchSpec:
    """Pre-admission input only; native identity is determined by the host.

    ``admission_timeout_sec`` is the wrapper's nonnegative Int32 admission wait
    deadline, including zero for no wait. It is never a workload execution timer.
    Raw fields may be encoded only for the immediate CLI transport.
    """

    command: str = field(repr=False)
    cwd: str = field(repr=False)
    repo_identifier: str = field(repr=False)
    requested: ResourceDemand
    role: Role
    priority: Priority
    admission_timeout_sec: int = 1800
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        try:
            _version(self.schema_version)
            _command(self.command)
            _absolute_windows_path(self.cwd)
            _identifier(self.repo_identifier, "repo_identifier")
            if type(self.requested) is not ResourceDemand:
                raise LaunchSpecError("launch_payload_invalid")
            # Reuse the existing bounds, including finite CPU and exact integer
            # byte units. Revalidate before encoding even an in-memory object.
            self.requested.__post_init__()
            if type(self.role) is not Role or type(self.priority) is not Priority:
                raise LaunchSpecError("launch_payload_invalid")
            if (type(self.admission_timeout_sec) is not int
                    or not 0 <= self.admission_timeout_sec <= MAX_ADMISSION_TIMEOUT_SEC):
                raise LaunchSpecError("launch_payload_invalid")
        except ContractViolation:
            raise LaunchSpecError("launch_payload_invalid") from None

    def to_dict(self) -> dict:
        """Return sensitive transport data, never a telemetry representation."""
        self.__post_init__()
        return {
            "schema_version": self.schema_version,
            "command": self.command,
            "cwd": self.cwd,
            "repo_identifier": self.repo_identifier,
            "requested": self.requested.to_dict(),
            "role": self.role.value,
            "priority": self.priority.value,
            "admission_timeout_sec": self.admission_timeout_sec,
        }

    @classmethod
    def from_dict(cls, value: dict) -> LaunchSpec:
        try:
            data = _object(value, cls)
            data["requested"] = ResourceDemand.from_dict(data["requested"])
            data["role"] = _read_enum(data["role"], Role, "role")
            data["priority"] = _read_enum(data["priority"], Priority, "priority")
            return cls(**data)
        except ContractViolation:
            raise LaunchSpecError("launch_payload_invalid") from None


def _decode_base64(encoded: str) -> bytes:
    if type(encoded) is not str or not encoded:
        raise LaunchSpecError("launch_payload_invalid")
    if len(encoded) > MAX_BASE64_CHARS:
        raise LaunchSpecError("launch_payload_too_large")
    try:
        raw = base64.b64decode(encoded.encode("ascii", errors="strict"), validate=True)
    except (UnicodeError, binascii.Error, ValueError):
        raise LaunchSpecError("launch_payload_invalid") from None
    if len(raw) > MAX_MESSAGE_BYTES:
        raise LaunchSpecError("launch_payload_too_large")
    # validate=True still accepts nonzero unused bits and certain extra-padding
    # forms. One canonical spelling avoids transport ambiguity.
    if base64.b64encode(raw).decode("ascii") != encoded:
        raise LaunchSpecError("launch_payload_invalid")
    return raw


def encode_launch_spec(spec: LaunchSpec) -> str:
    if type(spec) is not LaunchSpec:
        raise LaunchSpecError("launch_payload_invalid")
    try:
        raw = json.dumps(spec.to_dict(), ensure_ascii=False, allow_nan=False,
                         sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (UnicodeError, ContractViolation):
        raise LaunchSpecError("launch_payload_invalid") from None
    if len(raw) > MAX_MESSAGE_BYTES:
        raise LaunchSpecError("launch_payload_too_large")
    return base64.b64encode(raw).decode("ascii")


def decode_launch_spec(encoded: str) -> LaunchSpec:
    raw = _decode_base64(encoded)
    try:
        return LaunchSpec.from_dict(strict_json_loads(raw))
    except ContractViolation:
        raise LaunchSpecError("launch_payload_invalid") from None


@dataclass(frozen=True)
class LaunchCommand:
    """Immediate CreateProcess transport; every command-bearing field is private.

    ``command_line`` is the complete line to preflight and use unchanged.
    A launcher that adds switches or a different prefix must preflight again.
    Neither this object nor successful preflight authorizes process creation.
    """

    argv: tuple[str, ...] = field(repr=False)
    command_line: str = field(repr=False)
    payload: str = field(repr=False)


def prepare_encoded_host_command(encoded: str, *, python_executable: str,
                                 host_path: str) -> LaunchCommand:
    """Preflight one bounded canonical Base64 argument, not its JSON schema.

    This lower-level transport function also serves test hosts with their own
    schemas. It performs no authentication or launch-spec validation; production
    hosts must separately call ``decode_launch_spec`` before using the payload.
    Oversized command lines fail before Base64 decoding or format validation.
    """
    if type(encoded) is not str:
        raise LaunchSpecError("launch_payload_invalid")
    if len(encoded) >= CREATE_PROCESS_LIMIT:
        raise LaunchSpecError("launch_payload_too_large")
    _absolute_windows_path(python_executable)
    _absolute_windows_path(host_path)
    argv = (python_executable, host_path, "--launch-spec-b64", encoded)
    # Only the outer fixed argv is quoted; the raw workload command is never
    # tokenized or passed through list2cmdline.
    command_line = subprocess.list2cmdline(argv)
    if utf16_units(command_line) + 1 > CREATE_PROCESS_LIMIT:
        raise LaunchSpecError("launch_payload_too_large")
    _decode_base64(encoded)
    return LaunchCommand(argv, command_line, encoded)


def prepare_host_command(spec: LaunchSpec, *, python_executable: str,
                         host_path: str) -> LaunchCommand:
    return prepare_encoded_host_command(
        encode_launch_spec(spec), python_executable=python_executable, host_path=host_path,
    )


def build_cmd_command_line(command: str, *, cmd_path: str) -> str:
    """Preserve the existing cmd.exe /d /s /c raw-command semantics verbatim.

    The caller must separately resolve and verify the executable, then use the
    same ``cmd_path`` as CreateProcessW's applicationName. Validation only bounds
    the literal line; it cannot predict cmd's later environment expansion.
    """
    try:
        _command(command)
        _absolute_windows_path(cmd_path)
        if ntpath.basename(cmd_path).lower() != "cmd.exe":
            raise LaunchSpecError("launch_payload_invalid")
        command_line = '"' + cmd_path + '" /d /s /c "' + command + '"'
        if utf16_units(command_line) > CMD_LIMIT:
            raise LaunchSpecError("launch_payload_invalid")
        return command_line
    except LaunchSpecError:
        raise LaunchSpecError("cmd_payload_too_large_or_invalid") from None
