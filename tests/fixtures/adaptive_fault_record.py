"""Section 9 fault evidence record, bounded writer and read-only ledger snapshot.

Section 9 requires every fault test to save the injection point, the state
before injection, exact execution identities, the OS readback, whether the
reservation was retained, the exemption rows and revision, each timestamp and
the final reason. "A Python exception was caught" is none of those fields, so
this record refuses to be constructed without them.

The evidence level uses the four levels of 11.1. ``native`` is derived from the
level; no caller can declare a portable record native.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from urllib.parse import quote

EVIDENCE_LEVELS = ("L1", "L2", "L3", "L4")
NATIVE_LEVELS = ("L2", "L3", "L4")
LIVE_DATA_DIRECTORY = Path.home() / ".resource-sentinel"
MAX_RECORD_BYTES = 65536
MAX_SNAPSHOT_ROWS = 256
MAX_NESTING_DEPTH = 6
_TABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_FILETIME = re.compile(r"[0-9]{1,20}")


class FaultRecordError(ValueError):
    """Strict validation failure; an incomplete record is never evidence."""


def _text(value, label):
    if type(value) is not str or not value.strip():
        raise FaultRecordError(f"{label} must be a non-empty string")
    return value


def _json_value(value, label, depth=0):
    """Accept only finite JSON scalars, sequences and string-keyed mappings."""
    if depth > MAX_NESTING_DEPTH:
        raise FaultRecordError(f"{label} nests deeper than the bounded record allows")
    if value is None or type(value) in (bool, int, str):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise FaultRecordError(f"{label} must be finite")
        return value
    if type(value) in (list, tuple):
        return tuple(_json_value(item, f"{label}[]", depth + 1) for item in value)
    if type(value) is dict:
        return MappingProxyType({
            _text(key, f"{label} key"): _json_value(item, f"{label}.{key}", depth + 1)
            for key, item in value.items()})
    raise FaultRecordError(f"{label} holds an unsupported {type(value).__name__}")


def _mapping(value, label, *, allow_empty):
    if type(value) is not dict:
        raise FaultRecordError(f"{label} must be a dictionary")
    if not value and not allow_empty:
        raise FaultRecordError(f"{label} must not be empty")
    return _json_value(value, label)


def _plain(value):
    """Convert the frozen record back into json-serializable containers."""
    if isinstance(value, MappingProxyType):
        return {key: _plain(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_plain(item) for item in value]
    return value


def _identity(value, label):
    identity = _mapping(value, label, allow_empty=False)
    pid = identity.get("pid")
    birth = identity.get("created_filetime_100ns")
    if type(pid) is not int or type(pid) is bool or pid <= 0:
        raise FaultRecordError(f"{label} needs a positive integer pid")
    if type(birth) is not str or not _FILETIME.fullmatch(birth):
        raise FaultRecordError(f"{label} needs created_filetime_100ns as a digit string")
    return identity


def _reject_live_path(path, label):
    """The live Sentinel data directory is never read or written by a test."""
    live = LIVE_DATA_DIRECTORY.resolve() if LIVE_DATA_DIRECTORY.exists() else LIVE_DATA_DIRECTORY
    if path == live or live in path.parents:
        raise FaultRecordError(f"{label} is inside the live Sentinel data directory")


@dataclass(frozen=True)
class FaultRecord:
    """One fault injection, with the whole section 9 field set or nothing."""

    injection_point: str
    evidence_level: str
    state_before: dict
    execution_identities: tuple
    os_readback: dict
    reservation_retained: bool
    exemption_rows: tuple
    exemption_revision: int
    timestamps: dict
    final_reason: str

    def __post_init__(self):
        set_field = object.__setattr__
        set_field(self, "injection_point", _text(self.injection_point, "injection_point"))
        if self.evidence_level not in EVIDENCE_LEVELS:
            raise FaultRecordError(f"evidence_level must be one of {EVIDENCE_LEVELS}")
        set_field(self, "state_before", _mapping(self.state_before, "state_before", allow_empty=False))
        identities = self.execution_identities
        if type(identities) not in (list, tuple) or not identities:
            raise FaultRecordError("execution_identities must be a non-empty sequence")
        set_field(self, "execution_identities", tuple(
            _identity(item, f"execution_identities[{index}]")
            for index, item in enumerate(identities)))
        readback = _mapping(self.os_readback, "os_readback", allow_empty=True)
        if self.native and not readback:
            raise FaultRecordError(f"{self.evidence_level} evidence requires an OS readback")
        if not self.native and readback:
            raise FaultRecordError("an L1 record cannot carry an OS readback")
        set_field(self, "os_readback", readback)
        if type(self.reservation_retained) is not bool:
            raise FaultRecordError("reservation_retained must be exactly True or False")
        rows = self.exemption_rows
        if type(rows) not in (list, tuple):
            raise FaultRecordError("exemption_rows must be a sequence")
        set_field(self, "exemption_rows", tuple(
            _mapping(row, f"exemption_rows[{index}]", allow_empty=False)
            for index, row in enumerate(rows)))
        if type(self.exemption_revision) is not int or type(self.exemption_revision) is bool \
                or self.exemption_revision < 0:
            raise FaultRecordError("exemption_revision must be a non-negative integer")
        stamps = _mapping(self.timestamps, "timestamps", allow_empty=False)
        for name, value in stamps.items():
            if type(value) not in (int, float) or type(value) is bool or not math.isfinite(value):
                raise FaultRecordError(f"timestamps.{name} must be a finite number")
        set_field(self, "timestamps", stamps)
        set_field(self, "final_reason", _text(self.final_reason, "final_reason"))

    @property
    def native(self):
        """Derived from the level; 11.1 forbids substituting one level for another."""
        return self.evidence_level in NATIVE_LEVELS

    def to_dict(self):
        return {
            "injection_point": self.injection_point,
            "evidence_level": self.evidence_level,
            "native": self.native,
            "state_before": _plain(self.state_before),
            "execution_identities": _plain(self.execution_identities),
            "os_readback": _plain(self.os_readback),
            "reservation_retained": self.reservation_retained,
            "exemption_rows": _plain(self.exemption_rows),
            "exemption_revision": self.exemption_revision,
            "timestamps": _plain(self.timestamps),
            "final_reason": self.final_reason,
        }


def write_fault_record(path, record, *, max_bytes=MAX_RECORD_BYTES):
    """Bounded atomic JSON writer; an oversized record fails instead of growing."""
    if not isinstance(record, FaultRecord):
        raise FaultRecordError("only a validated FaultRecord is written as evidence")
    if type(max_bytes) is not int or not 0 < max_bytes <= 1 << 20:
        raise FaultRecordError("max_bytes must be a positive integer up to 1 MiB")
    destination = Path(path)
    if not destination.is_absolute():
        raise FaultRecordError("fault evidence needs an absolute isolated path")
    _reject_live_path(destination.parent.resolve(), "evidence directory")
    payload = json.dumps(record.to_dict(), indent=2, sort_keys=True).encode("utf-8")
    if len(payload) > max_bytes:
        raise FaultRecordError(f"fault record is {len(payload)} bytes over the {max_bytes} byte cap")
    temporary = destination.with_suffix(".pending")
    temporary.write_bytes(payload)
    os.replace(temporary, destination)
    return len(payload)


def _cell(value):
    if type(value) in (bytes, bytearray, memoryview):
        return "hex:" + bytes(value).hex()
    if type(value) is float and not math.isfinite(value):
        raise FaultRecordError("ledger snapshot holds a non-finite value")
    if value is None or type(value) in (int, float, str):
        return value
    raise FaultRecordError(f"ledger snapshot holds an unsupported {type(value).__name__}")


def snapshot_ledger(database_path, tables, *, max_rows=MAX_SNAPSHOT_ROWS):
    """Read named tables from an isolated sqlite file, read only and bounded.

    The caller proves the ledger before and after an injection with two calls.
    The live data directory is refused before any connection is attempted.
    """
    if type(max_rows) is not int or not 0 < max_rows <= 4096:
        raise FaultRecordError("max_rows must be a positive integer up to 4096")
    source = Path(database_path)
    if not source.is_absolute():
        raise FaultRecordError("ledger snapshot needs an absolute isolated path")
    resolved = source.resolve()
    _reject_live_path(resolved, "ledger snapshot path")
    if not resolved.is_file():
        raise FaultRecordError("isolated ledger file does not exist")
    names = tuple(tables)
    if not names:
        raise FaultRecordError("name at least one table to snapshot")
    for name in names:
        if type(name) is not str or not _TABLE_NAME.fullmatch(name):
            raise FaultRecordError(f"unsupported table name: {name!r}")
    connection = sqlite3.connect("file:" + quote(resolved.as_posix()) + "?mode=ro",
                                 uri=True, timeout=2.0)
    try:
        connection.row_factory = sqlite3.Row
        snapshot = {}
        for name in names:
            present = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
            if present is None:
                raise FaultRecordError(f"table {name} is absent from the isolated ledger")
            rows = connection.execute(f'SELECT * FROM "{name}"').fetchmany(max_rows + 1)
            if len(rows) > max_rows:
                raise FaultRecordError(f"table {name} exceeds the {max_rows} row snapshot bound")
            snapshot[name] = tuple(
                MappingProxyType({key: _cell(row[key]) for key in row.keys()}) for row in rows)
        return MappingProxyType(snapshot)
    finally:
        connection.close()
