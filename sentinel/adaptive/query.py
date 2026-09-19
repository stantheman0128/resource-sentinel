"""Bounded, read-only admission/lifecycle diagnostics.

This reader deliberately does not construct LifecycleStore or Coordinator: both
own migrations. Recorded mode and lifecycle state are not OS-control evidence.
Only a later independently verified guardian can establish native readiness.
"""
from __future__ import annotations

import math
from pathlib import Path
import re
import sqlite3
import time
from typing import Any


MAX_QUERY_ROWS = 100
DEFAULT_QUERY_ROWS = 20
DEFAULT_TIMEOUT_MS = 250
_SCHEMA_VERSION = 1
_PROTOCOL_VERSION = 1
_ID = re.compile(r"[A-Za-z0-9_.:@-]{1,128}\Z")
_FILETIME = re.compile(r"[1-9][0-9]{0,19}\Z")
_STATES = frozenset({"NEW", "QUEUED", "RESERVED", "PREPARED", "LAUNCHING",
                     "RUNNING", "DRAINING", "FINISHED", "CANCELLED_BEFORE_START",
                     "START_FAILED", "START_UNKNOWN", "UNCERTAIN_HOLD"})
_TERMINAL = frozenset({"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"})
_HOLDS = frozenset({"identity_unknown", "heartbeat_lost", "reservation_expired",
                    "launch_ack_lost", "recovery_unverified", "legacy_release_attempt"})
_TABLES = {"direct": "reservations", "routed": "worker_reservations"}
_FIELDS = ("execution_id", "allocation_kind", "reservation_id", "parent_execution_id",
           "state", "state_revision", "coverage", "launch_in_flight", "launch_sealed",
           "wrapper_pid", "wrapper_created_filetime_100ns", "root_pid",
           "root_created_filetime_100ns", "floor_cpu_units", "floor_physical_bytes",
           "floor_commit_bytes", "floor_io_slots", "hold_reason")
_TEXT_FIELDS = frozenset({"execution_id", "allocation_kind", "reservation_id",
                          "parent_execution_id", "state", "coverage", "hold_reason",
                          "wrapper_created_filetime_100ns", "root_created_filetime_100ns"})
_SELECT_FIELDS = ",".join(f"substr({field},1,129) AS {field}" if field in _TEXT_FIELDS else field
                          for field in _FIELDS)


def _integer(value: Any, *, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("invalid_diagnostic_record")
    return value


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError("invalid_diagnostic_identifier")
    return value


def _identity(pid: Any, birth: Any) -> dict[str, Any]:
    if (type(pid) is not int or not 1 <= pid <= 0xFFFFFFFF or
            not isinstance(birth, str) or _FILETIME.fullmatch(birth) is None or
            int(birth) > 0xFFFFFFFFFFFFFFFF):
        raise ValueError("invalid_diagnostic_identity")
    return {"pid": pid, "created_filetime_100ns": birth}


def _base() -> dict[str, Any]:
    return {"available": False, "implementation_mode": "admission-only",
            "native_readiness": "unverified", "control_writes": False,
            "os_limit_state": "unverified", "recorded_mode": None,
            "executions": [], "truncated": False}


def _row(row: sqlite3.Row) -> dict[str, Any]:
    kind, state, coverage = row["allocation_kind"], row["state"], row["coverage"]
    if kind not in {*_TABLES, "parent"} or state not in _STATES or coverage not in {"unmanaged", "job_contained"}:
        raise ValueError("invalid_diagnostic_record")
    if (type(row["launch_in_flight"]) is not int or row["launch_in_flight"] not in (0, 1) or
            type(row["launch_sealed"]) is not int or row["launch_sealed"] not in (0, 1)):
        raise ValueError("invalid_diagnostic_record")
    cpu = row["floor_cpu_units"]
    if type(cpu) not in (int, float) or not math.isfinite(cpu) or cpu < 0:
        raise ValueError("invalid_diagnostic_record")
    reservation_id = row["reservation_id"]
    parent_id = row["parent_execution_id"]
    if kind == "parent":
        if reservation_id is not None:
            raise ValueError("invalid_diagnostic_binding")
        parent_id = _identifier(parent_id)
    else:
        if parent_id is not None:
            raise ValueError("invalid_diagnostic_binding")
        reservation_id = _identifier(reservation_id)
    root = None
    if row["root_pid"] is not None or row["root_created_filetime_100ns"] is not None:
        root = _identity(row["root_pid"], row["root_created_filetime_100ns"])
    return {
        "execution_id": _identifier(row["execution_id"]),
        "allocation": {"kind": kind, "reservation_id": reservation_id,
                       "parent_execution_id": parent_id},
        "state": state, "state_revision": _integer(row["state_revision"]),
        "coverage": coverage, "launch_in_flight": bool(row["launch_in_flight"]),
        "launch_sealed": bool(row["launch_sealed"]),
        "wrapper": _identity(row["wrapper_pid"], row["wrapper_created_filetime_100ns"]),
        "root": root,
        "floor": {"cpu_units": cpu,
                  "physical_bytes": _integer(row["floor_physical_bytes"]),
                  "commit_bytes": _integer(row["floor_commit_bytes"]),
                  "io_slots": _integer(row["floor_io_slots"])},
        "hold_reason": row["hold_reason"] if row["hold_reason"] in _HOLDS else
                       (None if row["hold_reason"] is None else "unrecognized"),
    }


def _binding(conn: sqlite3.Connection, execution: dict[str, Any], tables: set[str]) -> str:
    """Check recorded references, not process containment or native identity."""
    allocation = execution["allocation"]
    if allocation["kind"] == "parent":
        row = conn.execute("SELECT execution_id FROM managed_executions WHERE execution_id=? LIMIT 1",
                           (allocation["parent_execution_id"],)).fetchone()
        return "parent_record_present" if row else "parent_record_missing"
    table = _TABLES[allocation["kind"]]
    if table not in tables:
        return "allocation_table_missing"
    rows = conn.execute(f"SELECT execution_id,lifecycle_managed FROM {table} WHERE id=? LIMIT 2",
                        (allocation["reservation_id"],)).fetchall()
    if not rows:
        return "terminal_allocation_absent" if execution["state"] in _TERMINAL else "allocation_missing"
    if len(rows) == 1 and rows[0][0] == execution["execution_id"] and rows[0][1] == 1:
        return "recorded_binding_matches"
    return "allocation_binding_inconsistent"


def query_adaptive(db_path: str | Path, *, execution_id: str | None = None,
                   reservation_id: str | None = None, limit: int = DEFAULT_QUERY_ROWS,
                   timeout_ms: int = DEFAULT_TIMEOUT_MS) -> dict[str, Any]:
    """Return a sanitized snapshot without creating a DB or changing its schema.

    Filters use exact equality. ``timeout_ms`` bounds lock waits and SQL work;
    it cannot preempt a stalled filesystem open. Unknown schema is unavailable,
    never silently migrated. No caller-provided native evidence is accepted.
    """
    if type(limit) is not int or not 1 <= limit <= MAX_QUERY_ROWS:
        raise ValueError("invalid_query_limit")
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
        raise ValueError("invalid_query_timeout")
    for value in (execution_id, reservation_id):
        if value is not None:
            _identifier(value)
    result = _base()
    conn = None
    deadline = time.monotonic() + timeout_ms / 1000
    try:
        path = Path(db_path).absolute()
        if not path.is_file():
            return {**result, "reason": "database_missing"}
        conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                               timeout=timeout_ms / 1000, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
        conn.execute("BEGIN")
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
            "('adaptive_runtime','managed_executions','reservations','worker_reservations') LIMIT 4")}
        if "adaptive_runtime" not in tables:
            return {**result, "reason": "adaptive_schema_missing"}
        runtime = conn.execute("SELECT schema_version,protocol_version,mode,registry_revision,admission_barrier,singleton "
                               "FROM adaptive_runtime LIMIT 2").fetchall()
        if (len(runtime) != 1 or type(runtime[0][0]) is not int or
                type(runtime[0][1]) is not int or runtime[0][0] != _SCHEMA_VERSION or
                runtime[0][1] != _PROTOCOL_VERSION):
            return {**result, "reason": "unsupported_adaptive_schema"}
        current = runtime[0]
        if (current[2] not in {"off", "shadow", "canary", "limited"} or
                current[4] not in {"NONE", "CONTROLLING", "RECOVERY_HOLD"} or
                type(current[5]) is not int or current[5] != 1 or
                "managed_executions" not in tables):
            return {**result, "reason": "invalid_adaptive_schema"}
        conditions, parameters = [], []
        for key, value in (("execution_id", execution_id), ("reservation_id", reservation_id)):
            if value is not None:
                conditions.append(key + "=?")
                parameters.append(value)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        records = conn.execute("SELECT " + _SELECT_FIELDS + " FROM managed_executions" +
                               where + " ORDER BY execution_id LIMIT ?", (*parameters, limit + 1)).fetchall()
        executions = []
        for record in records[:limit]:
            if time.monotonic() >= deadline:
                return {**result, "reason": "query_timeout"}
            execution = _row(record)
            execution["allocation"]["recorded_binding"] = _binding(conn, execution, tables)
            executions.append(execution)
        if time.monotonic() >= deadline:
            return {**result, "reason": "query_timeout"}
        return {**result, "available": True, "reason": "ok", "schema_version": _SCHEMA_VERSION,
                "protocol_version": _PROTOCOL_VERSION, "recorded_mode": current[2],
                "registry_revision": _integer(current[3]), "admission_barrier": current[4],
                "executions": executions, "truncated": len(records) > limit,
                "row_limit": limit}
    except sqlite3.Error as exc:
        code = getattr(exc, "sqlite_errorcode", None)
        reason = ("query_timeout" if code == sqlite3.SQLITE_INTERRUPT else
                  "database_busy" if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else
                  "database_unavailable")
        return {**result, "reason": reason}
    except (OSError, ValueError, OverflowError):
        return {**result, "reason": "invalid_or_unavailable_diagnostics"}
    finally:
        if conn is not None:
            conn.close()
