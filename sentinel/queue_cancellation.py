"""Caller-scoped cancellation of one queued request, never a running allocation.

This is a cooperative same-user ownership check, not an OS security boundary.
Do not construct Coordinator (which owns migrations) before proving ownership.
No process names, command lines, unrelated queue rows or exemptions are read.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
import re
import sqlite3


MAX_ANCESTRY = 32
_REQUEST_KEY = re.compile(r"[a-f0-9]{64}\Z")


class CancellationRejected(ValueError):
    """A fixed, privacy-safe reason why cancellation was not performed."""


def _observe(pid: int, process_factory) -> tuple[int, float, int]:
    proc = process_factory(pid)
    started, parent = float(proc.create_time()), int(proc.ppid())
    if (int(proc.pid) != pid or not math.isfinite(started) or started <= 0
            or parent < 0 or parent == pid):
        raise CancellationRejected("owner_identity_unverified")
    return pid, started, parent


def caller_owner_started(owner_pid: int, *, process_factory=None) -> float:
    """Prove an owner is this caller or its bounded, creation-checked ancestor.

    Read each parent edge twice through fresh Process objects. A disappearing,
    inaccessible, reused or inconsistent PID rejects; a bare requested PID is
    never treated as authorization. Queries stay outside the SQLite transaction.
    """
    if type(owner_pid) is not int or not 1 <= owner_pid <= 0xFFFFFFFF:
        raise CancellationRejected("invalid_owner_pid")
    if process_factory is None:
        import psutil
        process_factory = psutil.Process
    current = os.getpid()
    chain: list[tuple[int, float, int]] = []
    seen: set[int] = set()
    try:
        for _ in range(MAX_ANCESTRY):
            if current in seen or current <= 0:
                raise CancellationRejected("owner_not_caller_ancestor")
            node = _observe(current, process_factory)
            if chain and node[1] > chain[-1][1]:
                raise CancellationRejected("owner_identity_unverified")
            chain.append(node)
            seen.add(current)
            if current == owner_pid:
                # Recheck from oldest to newest, including the exact child
                # edges, so a PID-only ancestry snapshot is not sufficient.
                for observed in reversed(chain):
                    if _observe(observed[0], process_factory) != observed:
                        raise CancellationRejected("owner_identity_unverified")
                return node[1]
            current = node[2]
        raise CancellationRejected("owner_ancestry_limit")
    except CancellationRejected:
        raise
    except Exception:
        raise CancellationRejected("owner_identity_unverified") from None


def cancel_queued_row(db_path, *, request_key: str, owner_pid: int,
                      owner_started: float) -> int:
    """Short CAS in an existing DB, without initialization or unrelated writes.

    This storage primitive expects caller authorization to have been checked.
    SQLite is authoritative; compatibility JSON is refreshed by its normal
    publisher, rather than reading unrelated allocations to rebuild it here.
    """
    if (not isinstance(request_key, str) or _REQUEST_KEY.fullmatch(request_key) is None
            or type(owner_pid) is not int or not 1 <= owner_pid <= 0xFFFFFFFF
            or type(owner_started) not in (int, float)
            or not math.isfinite(owner_started) or owner_started <= 0):
        raise CancellationRejected("invalid_queue_identity")
    conn = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=rw", uri=True,
                           timeout=.25, isolation_level=None)
    try:
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute(
            "DELETE FROM queue WHERE request_key=? AND owner_pid=? AND owner_started=?",
            (request_key, owner_pid, owner_started),
        ).rowcount
        conn.execute("COMMIT")
        return count
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def cancel_for_caller(data_dir, *, request_key: str, owner_pid: int) -> dict:
    """Validate live caller ancestry, then compare-and-delete exactly one row."""
    result = {"cancelled": 0, "request_key": request_key}
    try:
        if not isinstance(request_key, str) or _REQUEST_KEY.fullmatch(request_key) is None:
            raise CancellationRejected("invalid_request_key")
        owner_started = caller_owner_started(owner_pid)
        db_path = Path(data_dir) / "sentinel.db"
        if not db_path.is_file():
            raise CancellationRejected("queue_unavailable")
        # mode=ro neither creates a missing database nor runs migrations. The
        # primary-key lookup intentionally excludes command/repository text.
        conn = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True, timeout=.25)
        try:
            row = conn.execute(
                "SELECT owner_pid,owner_started FROM queue WHERE request_key=? LIMIT 1",
                (request_key,),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return {**result, "ok": True, "reason": "not_queued"}
        if row[0] != owner_pid:
            raise CancellationRejected("queue_owner_mismatch")
        if (type(row[1]) not in (int, float) or not math.isfinite(row[1])
                or row[1] <= 0):
            raise CancellationRejected("owner_identity_unknown")
        if row[1] != owner_started:
            raise CancellationRejected("owner_identity_mismatch")
        count = cancel_queued_row(db_path,
            owner_pid=owner_pid, owner_started=owner_started, request_key=request_key,
        )
        return {**result, "ok": True, "cancelled": count,
                "reason": "cancelled" if count else "not_queued_or_changed",
                "mirror_refresh": "deferred"}
    except CancellationRejected as exc:
        return {**result, "ok": False, "reason": str(exc)}
    except (OSError, sqlite3.Error):
        return {**result, "ok": False, "reason": "queue_unavailable"}
