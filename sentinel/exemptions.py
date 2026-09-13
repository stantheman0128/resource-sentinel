"""User-authorized, expiring process-tree exemptions (not OS privileges).

The flag is an operator attestation, not an authentication boundary: local agents
already run as the same Windows user. Never infer authorization from load alone.
"""
from __future__ import annotations

import math
import sqlite3
import time
import uuid
from pathlib import Path


def process_chain(pid: int) -> list[tuple[int, float]]:
    """Live, creation-time-checked ancestry; inaccessible identities fail closed."""
    try:
        import psutil
        proc = psutil.Process(pid)
        chain = [(proc.pid, proc.create_time())]
        for parent in proc.parents():
            started = parent.create_time()
            if started > chain[-1][1]:
                break  # parent PID was reused
            chain.append((parent.pid, started))
        return chain
    except Exception:
        return []


class Exemptions:
    def __init__(self, data_dir, *, chain=process_chain):
        self.path = Path(data_dir) / "exemptions.sqlite3"
        self.chain = chain

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=2)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS exemptions (
                id TEXT PRIMARY KEY, root_pid INTEGER NOT NULL, root_started REAL NOT NULL,
                created_at REAL NOT NULL, expires_at REAL NOT NULL, reason TEXT NOT NULL,
                revoked_at REAL)""")
        except Exception:
            conn.close()
            raise
        return conn

    def grant(self, pid, *, minutes=60, reason, user_authorized=False, now=None):
        if not user_authorized:
            raise ValueError("explicit user authorization is required")
        if not math.isfinite(minutes) or not 1 <= minutes <= 1440:
            raise ValueError("minutes must be between 1 and 1440")
        if not reason.strip():
            raise ValueError("an authorization reason is required")
        chain = self.chain(int(pid))
        if not chain or chain[0][0] != int(pid) or chain[0][1] <= 0:
            raise ValueError("target process identity is unavailable")
        now = time.time() if now is None else now
        row = dict(id=uuid.uuid4().hex, root_pid=int(pid), root_started=chain[0][1],
                   created_at=now, expires_at=now + minutes * 60,
                   reason=reason.strip()[:500], revoked_at=None)
        conn = self._connect()
        try:
            with conn:
                conn.execute("INSERT INTO exemptions VALUES (:id,:root_pid,:root_started,:created_at,:expires_at,:reason,:revoked_at)", row)
        finally:
            conn.close()
        return row

    def rows(self, *, now=None, include_inactive=False):
        if not self.path.exists():
            return []
        now = time.time() if now is None else now
        conn = self._connect()
        try:
            query = "SELECT * FROM exemptions"
            params = ()
            if not include_inactive:
                query += " WHERE revoked_at IS NULL AND expires_at > ?"
                params = (now,)
            rows = [dict(r) for r in conn.execute(query + " ORDER BY created_at", params)]
        finally:
            conn.close()
        for row in rows:
            chain = self.chain(row["root_pid"])
            alive = bool(chain and chain[0][0] == row["root_pid"] and
                         abs(chain[0][1] - row["root_started"]) < 0.01)
            row["state"] = ("revoked" if row["revoked_at"] is not None else
                            "expired" if row["expires_at"] <= now else
                            "process_exited" if not alive else "active")
        return rows if include_inactive else [r for r in rows if r["state"] == "active"]

    def match(self, pid, started, *, now=None, rows=None):
        if not math.isfinite(started) or started <= 0:
            return None
        rows = self.rows(now=now) if rows is None else rows
        if not rows:
            return None
        chain = self.chain(int(pid))
        if not chain or chain[0][0] != int(pid) or abs(chain[0][1] - started) >= 0.01:
            return None
        for row in sorted(rows, key=lambda r: r["expires_at"], reverse=True):
            if any(p == row["root_pid"] and abs(s - row["root_started"]) < 0.01 for p, s in chain):
                return row
        return None

    def revoke(self, exemption_id, *, now=None):
        if not self.path.exists():
            return 0
        conn = self._connect()
        try:
            with conn:
                return conn.execute("UPDATE exemptions SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                                    (time.time() if now is None else now, exemption_id)).rowcount
        finally:
            conn.close()

    def resolve(self):
        """Return concrete identities for the collector; never just bare PIDs."""
        rows = self.rows()
        if not rows:
            return []
        import psutil
        # One process snapshot instead of an OS ancestry query for every PID.
        nodes = {p.pid: p.info for p in psutil.process_iter(["pid", "ppid", "create_time"])
                 if p.info.get("create_time") is not None}
        roots = {r["root_pid"]: r for r in sorted(rows, key=lambda r: r["expires_at"])}
        result = []
        for pid, node in nodes.items():
            current = node
            seen = set()
            while current and current["pid"] not in seen:
                seen.add(current["pid"])
                row = roots.get(current["pid"])
                if row and abs(current["create_time"] - row["root_started"]) < 0.01:
                    result.append(dict(pid=pid, started=node["create_time"], expires_at=row["expires_at"], id=row["id"]))
                    break
                parent = nodes.get(current["ppid"])
                if parent and parent["create_time"] > current["create_time"]:
                    break
                current = parent
        return result
