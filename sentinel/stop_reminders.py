"""Atomic, bounded Stop notifications; never cancel queued work.

An episode lasts while an exact owner has at least one queued request. The
last queue deletion resets only its notification state, including deletions
performed by admission, explicit cancellation, or ordinary queue cleanup.
"""

from __future__ import annotations

import math
import sqlite3
import time


MAX_REMINDERS = 3
MAX_LEGACY_ENTRIES = 256


def _legacy_count(conn, blocks, owner_pid, owner_started, now):
    if not isinstance(blocks, dict):
        return 0
    if len(blocks) > MAX_LEGACY_ENTRIES:
        return MAX_REMINDERS  # Unknown old reminder history cannot justify more nagging.
    total = 0
    prefix = f"{owner_pid}:"
    for key, record in blocks.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            continue
        if key != str(owner_pid) and not key.startswith(prefix):
            continue
        count, stamp = record.get("n"), record.get("ts")
        if (type(count) is not int or count < 0
                or type(stamp) not in (int, float) or not math.isfinite(stamp)
                or not max(owner_started, now - 86400) <= stamp <= now):
            continue
        if key != str(owner_pid):
            request_key = key[len(prefix):]
            if len(request_key) != 64:
                continue
            found = conn.execute(
                "SELECT 1 FROM queue WHERE request_key=? AND owner_pid=? AND owner_started=?",
                (request_key, owner_pid, owner_started),
            ).fetchone()
            if found is None:
                continue
        total = min(MAX_REMINDERS, total + count)
        if total == MAX_REMINDERS:
            break
    return total


def claim_reminder(
    conn: sqlite3.Connection, *, owner_pid: int, owner_started: float,
    max_reminders: int = MAX_REMINDERS, legacy_blocks: dict | None = None,
) -> dict:
    if type(owner_pid) is not int or owner_pid <= 0:
        raise ValueError("owner_identity_unknown")
    if (type(owner_started) not in (int, float)
            or not math.isfinite(owner_started) or owner_started <= 0):
        raise ValueError("owner_identity_unknown")
    if type(max_reminders) is not int or not 1 <= max_reminders <= MAX_REMINDERS:
        raise ValueError("invalid_reminder_limit")
    if conn.in_transaction:
        raise ValueError("unexpected_transaction")
    now = time.time()
    # This connection is private to the hook call. A busy notification store
    # must not make Stop wait for a long admission/collector transaction.
    conn.execute("PRAGMA busy_timeout=250")
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stop_reminder_episodes (
                owner_pid INTEGER NOT NULL,
                owner_started REAL NOT NULL,
                reminders INTEGER NOT NULL CHECK (reminders BETWEEN 0 AND 3),
                updated_at REAL NOT NULL,
                PRIMARY KEY (owner_pid, owner_started)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_queue_stop_owner
            ON queue(owner_pid, owner_started)
        """)
        conn.execute("""
            CREATE TRIGGER IF NOT EXISTS stop_reminder_queue_empty
            AFTER DELETE ON queue
            WHEN NOT EXISTS (
                SELECT 1 FROM queue
                WHERE owner_pid=OLD.owner_pid AND owner_started=OLD.owner_started
            )
            BEGIN
                UPDATE stop_reminder_episodes SET reminders=0
                WHERE owner_pid=OLD.owner_pid AND owner_started=OLD.owner_started;
            END
        """)
        queued_count = conn.execute(
            "SELECT COUNT(*) FROM queue WHERE owner_pid=? AND owner_started=?",
            (owner_pid, owner_started),
        ).fetchone()[0]
        if not queued_count:
            conn.execute(
                "UPDATE stop_reminder_episodes SET reminders=0 WHERE owner_pid=? AND owner_started=?",
                (owner_pid, owner_started),
            )
            result = dict(queued_count=0, request_key=None, reminder_count=0, should_block=False)
        else:
            first = conn.execute(
                "SELECT request_key FROM queue WHERE owner_pid=? AND owner_started=? "
                "ORDER BY priority_rank,queued_at,request_key LIMIT 1",
                (owner_pid, owner_started),
            ).fetchone()[0]
            previous = conn.execute(
                "SELECT reminders FROM stop_reminder_episodes WHERE owner_pid=? AND owner_started=?",
                (owner_pid, owner_started),
            ).fetchone()
            count = (previous[0] if previous is not None else
                     _legacy_count(conn, legacy_blocks, owner_pid, owner_started, now))
            should_block = count < max_reminders
            count = min(max_reminders, count + int(should_block))
            conn.execute(
                "INSERT INTO stop_reminder_episodes VALUES (?,?,?,?) "
                "ON CONFLICT(owner_pid,owner_started) DO UPDATE SET "
                "reminders=excluded.reminders,updated_at=excluded.updated_at",
                (owner_pid, owner_started, count, now),
            )
            result = dict(queued_count=queued_count, request_key=first,
                          reminder_count=count, should_block=should_block)
        conn.execute("COMMIT")
        return result
    except BaseException:
        conn.execute("ROLLBACK")
        raise
