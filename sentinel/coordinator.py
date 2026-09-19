"""Atomic local admission, reservations, and telemetry.

SQLite is the authority.  The legacy queue.json and slots.json files are
best-effort read-only mirrors so the existing dashboard and integrations keep
working while callers migrate to this module.
"""

from __future__ import annotations

import ctypes
import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from sentinel.exemptions import Exemptions
from sentinel.command_classification import classify_command
from sentinel.stop_reminders import claim_reminder
from sentinel.accounting import frame_from_status, local_host_identity, shared_admission_blockers
from sentinel.adaptive.store import allocation_is_bound, check_schema_version, hold_expired_allocations, migrate_schema


PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
CLASS_DEFAULTS = {
    "LIGHT": (0.5, 0.5, 0),
    "MEDIUM": (2.0, 4.0, 0),
    "HEAVY": (4.0, 8.0, 1),
    "EXTREME": (8.0, 14.0, 1),
}


@dataclass(frozen=True)
class ResourceRequest:
    owner_pid: int
    owner_started: float
    repo: str
    command: str
    resource_class: str = "HEAVY"
    priority: str = "P2"
    tool_use_id: str = ""
    cpu_units: float | None = None
    ram_gib: float | None = None
    io_slots: int | None = None
    signature: str = ""
    commit_bytes: int | None = None

    def normalized(self) -> "ResourceRequest":
        cls = self.resource_class.upper()
        priority = self.priority.upper()
        if cls not in CLASS_DEFAULTS:
            raise ValueError(f"unknown resource class: {cls}")
        if priority not in PRIORITY_RANK:
            raise ValueError(f"unknown priority: {priority}")
        cpu, ram, io = CLASS_DEFAULTS[cls]
        normalized = ResourceRequest(
            owner_pid=int(self.owner_pid),
            owner_started=float(self.owner_started or 0),
            repo=self.repo or "unknown",
            command=self.command,
            resource_class=cls,
            priority=priority,
            tool_use_id=self.tool_use_id or "",
            cpu_units=float(cpu if self.cpu_units is None else self.cpu_units),
            ram_gib=float(ram if self.ram_gib is None else self.ram_gib),
            io_slots=int(io if self.io_slots is None else self.io_slots),
            signature=self.signature,
            commit_bytes=self.commit_bytes,
        )
        if normalized.owner_pid <= 0:
            raise ValueError("owner_pid must be positive")
        if min(normalized.cpu_units or 0, normalized.ram_gib or 0, normalized.io_slots or 0) < 0:
            raise ValueError("resource requirements cannot be negative")
        if not all(math.isfinite(v) for v in (normalized.cpu_units, normalized.ram_gib, normalized.io_slots)):
            raise ValueError("resource requirements must be finite")
        if normalized.cpu_units < .05 or normalized.ram_gib < .05:
            raise ValueError("CPU and RAM requests must each be at least 0.05")
        if normalized.commit_bytes is not None and (
            isinstance(normalized.commit_bytes, bool) or not isinstance(normalized.commit_bytes, int)
            or not 0 <= normalized.commit_bytes <= (1 << 63) - 1
        ):
            raise ValueError("commit_bytes must be a nonnegative signed 64-bit integer")
        return normalized

    @property
    def command_signature(self) -> str:
        if self.signature:
            if not re.fullmatch(r"[a-f0-9]{20}", self.signature):
                raise ValueError("invalid command signature hint")
            return self.signature
        normalized = re.sub(r"\s+", " ", self.command.strip().lower())
        normalized = re.sub(r"[a-f0-9]{7,40}", "<sha>", normalized)
        normalized = re.sub(r"\b\d{4,}\b", "<n>", normalized)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:20]

    @property
    def request_key(self) -> str:
        operation = self.tool_use_id or self.command_signature
        raw = f"{self.owner_pid}:{self.owner_started:.3f}:{self.repo}:{operation}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @property
    def spec_hash(self) -> str:
        req = self.normalized()
        values = {
            "repo": req.repo, "command_signature": req.command_signature,
            "resource_class": req.resource_class, "priority": req.priority,
            "cpu_units": req.cpu_units, "ram_gib": req.ram_gib,
            "io_slots": req.io_slots,
        }
        # Existing callers retain their exact hash and RAM-to-Commit fallback.
        if req.commit_bytes is not None:
            values["commit_bytes"] = req.commit_bytes
        raw = json.dumps(values, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def redact_command(command: str) -> str:
    """Keep queue diagnostics useful without persisting common secret forms."""
    value = command[:2000]
    value = re.sub(
        r"(?i)\b(token|password|passwd|secret|api[_-]?key)\s*=\s*(?:\"[^\"]*\"|'[^']*'|\S+)",
        lambda match: f"{match.group(1)}=<redacted>", value,
    )
    value = re.sub(r"(?i)(authorization\s*:\s*bearer\s+)\S+", r"\1<redacted>", value)
    value = re.sub(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})\b", "<redacted>", value)
    return value[:500]


def _atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=True, separators=(",", ":")), encoding="ascii")
    os.replace(tmp, path)


def _default_pid_identity(pid: int) -> tuple[bool | None, float]:
    try:
        import psutil

        process = psutil.Process(pid)
        return process.is_running(), float(process.create_time())
    except ImportError:
        return None, 0.0
    except Exception as error:
        # Permission errors and query failures do not establish process death.
        if isinstance(error, psutil.NoSuchProcess):
            return False, 0.0
        return None, 0.0


class Coordinator:
    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        db_path: str | os.PathLike[str] | None = None,
        pid_identity: Callable[[int], tuple[bool | None, float]] | None = None,
        local_host_id: str | None = None,
    ) -> None:
        self.local_host_id = local_host_identity() if local_host_id is None else local_host_id
        if not isinstance(self.local_host_id, str) or not self.local_host_id.strip():
            raise ValueError("local_host_id must be a nonempty string")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self.pid_identity = pid_identity or _default_pid_identity
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            check_schema_version(conn)
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except BaseException:
            conn.close()
            raise

    @contextmanager
    def _db(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            check_schema_version(conn)
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    id TEXT PRIMARY KEY,
                    request_key TEXT NOT NULL UNIQUE,
                    owner_pid INTEGER NOT NULL,
                    owner_started REAL NOT NULL,
                    tool_use_id TEXT,
                    repo TEXT NOT NULL,
                    command_signature TEXT NOT NULL,
                    command_text TEXT NOT NULL,
                    resource_class TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    priority_rank INTEGER NOT NULL,
                    cpu_units REAL NOT NULL,
                    ram_gib REAL NOT NULL,
                    io_slots INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                    ,spec_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS queue (
                    request_key TEXT PRIMARY KEY,
                    owner_pid INTEGER NOT NULL,
                    owner_started REAL NOT NULL,
                    tool_use_id TEXT,
                    repo TEXT NOT NULL,
                    command_signature TEXT NOT NULL,
                    command_text TEXT NOT NULL,
                    resource_class TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    priority_rank INTEGER NOT NULL,
                    cpu_units REAL NOT NULL,
                    ram_gib REAL NOT NULL,
                    io_slots INTEGER NOT NULL,
                    queued_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL
                    ,spec_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reservation_id TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    owner_pid INTEGER NOT NULL,
                    repo TEXT NOT NULL,
                    command_signature TEXT NOT NULL,
                    resource_class TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    cpu_units REAL NOT NULL,
                    ram_gib REAL NOT NULL,
                    io_slots INTEGER NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL NOT NULL,
                    outcome TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS resource_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sampled_at REAL NOT NULL,
                    light TEXT,
                    cpu_pct REAL,
                    cpu_5min_avg REAL,
                    ram_used_pct REAL,
                    ram_free_gib REAL,
                    commit_used_gib REAL,
                    commit_limit_gib REAL,
                    pagefile_used_gib REAL,
                    disk_json TEXT,
                    agent_groups_json TEXT,
                    agent_trees_json TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_samples_time ON resource_samples(sampled_at);
                CREATE INDEX IF NOT EXISTS idx_exec_signature ON executions(command_signature, ended_at);
                """
            )
            reservation_columns = {row[1] for row in conn.execute("PRAGMA table_info(reservations)")}
            if "spec_hash" not in reservation_columns:
                conn.execute("ALTER TABLE reservations ADD COLUMN spec_hash TEXT NOT NULL DEFAULT ''")
            queue_columns = {row[1] for row in conn.execute("PRAGMA table_info(queue)")}
            if "spec_hash" not in queue_columns:
                conn.execute("ALTER TABLE queue ADD COLUMN spec_hash TEXT NOT NULL DEFAULT ''")
            migrate_schema(conn)

    @staticmethod
    def _config(config: dict[str, Any] | None, *, local_host_id: str | None = None) -> dict[str, Any]:
        cfg = dict(config or {})
        # All local entry points bind to this ledger host, independently of
        # caller/worker config that may describe a different machine.
        cfg["local_host_id"] = local_host_identity() if local_host_id is None else local_host_id
        cfg.setdefault("local_allocatable_cpu", 8.0)
        cfg.setdefault("local_allocatable_ram_gib", 48.0)
        cfg.setdefault("local_commit_headroom_gib", 4.0)
        cfg.setdefault("heavy_io_slots", 1)
        cfg.setdefault("reservation_ttl_min", 120)
        cfg.setdefault("queue_ttl_min", 30)
        cfg.setdefault("reservation_grace_sec", 120)
        cfg.setdefault("admission_status_stale_sec", 300)
        cfg.setdefault("local_worker_id", "local-windows")
        return cfg

    @staticmethod
    def _observation_key(table: str, row: sqlite3.Row) -> tuple[Any, ...]:
        # A concurrent heartbeat, binding, replacement or other row change makes
        # this observation inapplicable. Such a row waits for the next cleanup.
        return (table, tuple((name, row[name]) for name in row.keys()))

    def _cleanup_observations(self) -> dict[tuple[Any, ...], tuple[bool | None, float]]:
        with self._db() as conn:
            rows = [(table, row) for table in ("reservations", "queue")
                    for row in conn.execute(f"SELECT * FROM {table}").fetchall()]
        identities: dict[int, tuple[bool | None, float]] = {}
        observations = {}
        for table, row in rows:
            pid = int(row["owner_pid"])
            if pid not in identities:
                try:
                    alive, started = self.pid_identity(pid)
                    if alive is not True and alive is not False:
                        alive, started = None, 0.0
                    elif alive and (not math.isfinite(float(started)) or float(started) <= 0):
                        alive, started = None, 0.0
                    identities[pid] = alive, float(started)
                except Exception:
                    identities[pid] = None, 0.0
            observations[self._observation_key(table, row)] = identities[pid]
        return observations

    def _cleanup_locked(
        self, conn: sqlite3.Connection, now: float, config: dict[str, Any],
        observations: dict[tuple[Any, ...], tuple[bool | None, float]],
    ) -> list[str]:
        removed: list[str] = []
        hold_expired_allocations(conn, "direct", now)
        for row in conn.execute("SELECT * FROM reservations").fetchall():
            if allocation_is_bound(conn, "direct", row["id"]):
                continue
            alive, started = observations.get(self._observation_key("reservations", row), (None, 0.0))
            if alive is None:
                continue
            identity_matches = not row["owner_started"] or abs(started - row["owner_started"]) < 2
            if not alive or not identity_matches or float(row["expires_at"]) <= now:
                self._archive_locked(conn, row, now, "stale")
                removed.append(row["id"])
        queue_cutoff = now - float(config["queue_ttl_min"]) * 60
        for row in conn.execute("SELECT * FROM queue").fetchall():
            alive, started = observations.get(self._observation_key("queue", row), (None, 0.0))
            if alive is None:
                continue
            identity_matches = not row["owner_started"] or abs(started - row["owner_started"]) < 2
            if not alive or not identity_matches or float(row["heartbeat_at"]) < queue_cutoff:
                conn.execute("DELETE FROM queue WHERE request_key=?", (row["request_key"],))
        return removed

    @staticmethod
    def _archive_locked(conn: sqlite3.Connection, row: sqlite3.Row, now: float, outcome: str) -> None:
        conn.execute(
            """INSERT INTO executions
            (reservation_id,request_key,owner_pid,repo,command_signature,resource_class,priority,
             cpu_units,ram_gib,io_slots,started_at,ended_at,outcome)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["request_key"], row["owner_pid"], row["repo"],
                row["command_signature"], row["resource_class"], row["priority"],
                row["cpu_units"], row["ram_gib"], row["io_slots"], row["created_at"], now, outcome,
            ),
        )
        conn.execute("DELETE FROM reservations WHERE id=?", (row["id"],))

    @staticmethod
    def _status_metrics(status: dict[str, Any], config: dict[str, Any], now: float) -> dict[str, float | str | bool]:
        generated = status.get("generated_at")
        fresh = False
        if generated:
            try:
                stamp = datetime.strptime(generated, "%Y-%m-%d %H:%M:%S").timestamp()
                fresh = now - stamp <= float(config["admission_status_stale_sec"])
            except (TypeError, ValueError):
                pass
        ram = status.get("ram") or {}
        total_ram = float(ram.get("total_gb") or 0)
        free_ram = float(ram.get("free_gb") or 0)
        memory = status.get("memory") or {}
        return {
            "fresh": fresh,
            "light": str(status.get("light") or "UNKNOWN"),
            "actual_cpu": float(status.get("cpu_5min_avg") or status.get("cpu_pct") or 0) / 100.0
            * (os.cpu_count() or 1),
            "actual_ram": max(0.0, total_ram - free_ram),
            "commit_used": float(memory.get("commit_used_gib") or 0),
            "commit_limit": float(memory.get("commit_limit_gib") or 0),
        }

    @staticmethod
    def _routed_local_pending(
        conn: sqlite3.Connection, config: dict[str, Any], now: float
    ) -> tuple[float, float]:
        """Return fresh Maintainer reservations for this local execution pool."""
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_reservations'"
        ).fetchone()
        if not table:
            return 0.0, 0.0
        cutoff = now - float(config["reservation_grace_sec"])
        row = conn.execute(
            """SELECT COALESCE(SUM(cpu_units),0) cpu,COALESCE(SUM(ram_gib),0) ram
               FROM worker_reservations WHERE worker_id=? AND created_at>=?""",
            (str(config["local_worker_id"]), cutoff),
        ).fetchone()
        return float(row["cpu"]), float(row["ram"])

    def admit(
        self,
        request: ResourceRequest,
        status: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        req = request.normalized()
        cfg = self._config(config, local_host_id=self.local_host_id)
        now = time.time() if now is None else now
        v2 = cfg.get("admission_policy") == "resource-v2"
        frame = frame_from_status(status, cfg, now=now, logical_processors=os.cpu_count() or 1) if v2 else None
        metrics = ({"fresh": frame["fresh"], "light": status.get("light", "UNKNOWN")}
                   if v2 else self._status_metrics(status, cfg, now))
        observations = self._cleanup_observations()
        # Process ancestry and the other SQLite store must not run while the
        # capacity writer transaction is held. P2 does not add any cap writer;
        # its later grant/control linearization belongs to the policy mutex.
        exemption = None
        try:
            exemption = Exemptions(self.data_dir).match(req.owner_pid, req.owner_started, now=now)
        except (OSError, sqlite3.Error):
            pass  # unreadable exemption state never grants a bypass
        result: dict[str, Any]
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, cfg, observations)
            existing = conn.execute("SELECT * FROM reservations WHERE request_key=?", (req.request_key,)).fetchone()
            if existing:
                if allocation_is_bound(conn, "direct", existing["id"]):
                    conn.execute("COMMIT")
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "request_key": req.request_key, "reservation_id": existing["id"]}
                if existing["spec_hash"] != req.spec_hash:
                    conn.execute("COMMIT")
                    return {
                        "allowed": False, "reason": "request_spec_mismatch",
                        "request_key": req.request_key, "reservation_id": existing["id"],
                    }
                conn.execute(
                    "UPDATE reservations SET heartbeat_at=?,expires_at=?,tool_use_id=? WHERE id=?",
                    (now, now + float(cfg["reservation_ttl_min"]) * 60, req.tool_use_id, existing["id"]),
                )
                conn.execute("COMMIT")
                self._mirror()
                return {"allowed": True, "reservation_id": existing["id"], "reused": True, "request_key": req.request_key}
            handoffs = conn.execute(
                "SELECT * FROM reservations WHERE owner_pid=? AND command_signature=? AND tool_use_id='' ORDER BY created_at",
                (req.owner_pid, req.command_signature),
            ).fetchall()
            handoff = next((row for row in handoffs
                            if not allocation_is_bound(conn, "direct", row["id"])), None)
            if handoff and handoff["spec_hash"] == req.spec_hash:
                conn.execute("UPDATE reservations SET tool_use_id=?,heartbeat_at=? WHERE id=?", (req.tool_use_id, now, handoff["id"]))
                conn.execute("COMMIT")
                self._mirror()
                return {"allowed": True, "reservation_id": handoff["id"], "reused": True, "request_key": handoff["request_key"]}

            queued_existing = conn.execute(
                "SELECT spec_hash FROM queue WHERE request_key=?", (req.request_key,)
            ).fetchone()
            if queued_existing and queued_existing["spec_hash"] != req.spec_hash:
                conn.execute("COMMIT")
                return {
                    "allowed": False, "reason": "request_spec_mismatch",
                    "request_key": req.request_key,
                }

            conn.execute(
                """INSERT INTO queue
                (request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                 resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,
                 spec_hash,commit_bytes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(request_key) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,
                  tool_use_id=excluded.tool_use_id,priority=excluded.priority,
                  priority_rank=excluded.priority_rank""",
                (
                    req.request_key, req.owner_pid, req.owner_started, req.tool_use_id, req.repo,
                    req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                    PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                    req.spec_hash, req.commit_bytes,
                ),
            )
            ordered = conn.execute("SELECT request_key FROM queue ORDER BY priority_rank,queued_at,request_key").fetchall()
            position = next(i for i, row in enumerate(ordered, 1) if row["request_key"] == req.request_key)
            reason = "capacity"
            allowed = position == 1
            if not metrics["fresh"]:
                allowed = False
                reason = "status_stale"
            elif cfg.get("admission_policy") != "resource-v2" and metrics["light"] in {"ORANGE", "RED"}:
                allowed = False
                reason = f"light_{str(metrics['light']).lower()}"
            elif position != 1:
                allowed = False
                reason = "queue_order"

            if not v2:
                active = conn.execute("SELECT * FROM reservations").fetchall()
                grace = float(cfg["reservation_grace_sec"])
                pending_cpu = sum(float(r["cpu_units"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_ram = sum(float(r["ram_gib"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_commit = sum((r["commit_bytes"] / 2**30 if r["commit_bytes"] is not None else float(r["ram_gib"]))
                                     for r in active if now - float(r["created_at"]) <= grace)
                routed_cpu, routed_ram = self._routed_local_pending(conn, cfg, now)
                pending_cpu += routed_cpu
                pending_ram += routed_ram
                pending_commit += routed_ram
                used_io = sum(int(r["io_slots"]) for r in active)
                if allowed and float(metrics["actual_cpu"]) + pending_cpu + float(req.cpu_units) > float(cfg["local_allocatable_cpu"]):
                    allowed, reason = False, "cpu_capacity"
                if allowed and float(metrics["actual_ram"]) + pending_ram + float(req.ram_gib) > float(cfg["local_allocatable_ram_gib"]):
                    allowed, reason = False, "ram_capacity"
                commit_limit = float(metrics["commit_limit"])
                requested_commit = req.commit_bytes / 2**30 if req.commit_bytes is not None else float(req.ram_gib)
                if allowed and commit_limit and float(metrics["commit_used"]) + pending_commit + requested_commit > commit_limit - float(cfg["local_commit_headroom_gib"]):
                    allowed, reason = False, "commit_capacity"
                if allowed and used_io + int(req.io_slots) > int(cfg["heavy_io_slots"]):
                    allowed, reason = False, "io_capacity"

            details = []
            if v2:
                details = shared_admission_blockers(conn, req, frame, cfg, exempt=bool(exemption))
                if details:
                    allowed, reason = False, details[0]["reason"]
                else:
                    # First feasible request wins. A blocked CPU job must not hold
                    # an unrelated IO job behind it; feasible requests retain priority/FIFO.
                    eligible = None
                    for candidate in conn.execute("SELECT * FROM queue ORDER BY priority_rank,queued_at,request_key"):
                        shape = ResourceRequest(candidate["owner_pid"], candidate["owner_started"], candidate["repo"],
                                                candidate["command_text"], candidate["resource_class"], candidate["priority"],
                                                cpu_units=candidate["cpu_units"], ram_gib=candidate["ram_gib"], io_slots=candidate["io_slots"],
                                                commit_bytes=candidate["commit_bytes"])
                        if not shared_admission_blockers(conn, shape, frame, cfg):
                            eligible = candidate["request_key"]
                            break
                    allowed = eligible == req.request_key
                    reason = "resource_capacity" if allowed else "queue_order"

            # Explicit operator exemption bypasses load/order gates, but still
            # reserves and records usage so non-exempt callers see the pressure.
            if exemption and (not v2 or not details):
                allowed = True

            if allowed:
                reservation_id = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO reservations
                    (id,request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                     resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,created_at,
                     heartbeat_at,expires_at,spec_hash,commit_bytes)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        reservation_id, req.request_key, req.owner_pid, req.owner_started, req.tool_use_id,
                        req.repo, req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                        PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                        now + float(cfg["reservation_ttl_min"]) * 60, req.spec_hash, req.commit_bytes,
                    ),
                )
                conn.execute("DELETE FROM queue WHERE request_key=?", (req.request_key,))
                result = {"allowed": True, "reservation_id": reservation_id, "reused": False, "request_key": req.request_key}
                if exemption:
                    result.update(reason="user_exemption", exemption_id=exemption["id"], exemption_expires_at=exemption["expires_at"])
            else:
                result = {"allowed": False, "reason": reason, "position": position, "request_key": req.request_key}
                if cfg.get("admission_policy") == "resource-v2":
                    result.update(policy="resource-v2", blockers=details)
            conn.execute("COMMIT")
        self._mirror()
        return result

    def retry_queued(
        self,
        request_key: str,
        status: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM queue WHERE request_key=?", (request_key,)).fetchone()
        if row is None:
            with self._db() as conn:
                conn.execute("BEGIN")
                active = conn.execute("SELECT id FROM reservations WHERE request_key=?", (request_key,)).fetchone()
                bound = bool(active and allocation_is_bound(conn, "direct", active["id"]))
                conn.execute("COMMIT")
            if active:
                if bound:
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "reservation_id": active["id"], "request_key": request_key}
                return {"allowed": True, "reservation_id": active["id"], "reused": True, "request_key": request_key}
            return {"allowed": False, "reason": "request_missing", "request_key": request_key}
        request = ResourceRequest(
            owner_pid=row["owner_pid"], owner_started=row["owner_started"], repo=row["repo"],
            command=row["command_text"], resource_class=row["resource_class"], priority=row["priority"],
            tool_use_id=row["tool_use_id"] or "", cpu_units=row["cpu_units"],
            ram_gib=row["ram_gib"], io_slots=row["io_slots"], signature=row["command_signature"],
            commit_bytes=row["commit_bytes"],
        )
        result = self.admit(request, status, config=config, now=now)
        if result.get("allowed"):
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                if allocation_is_bound(conn, "direct", result["reservation_id"]):
                    result = {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                              "reservation_id": result["reservation_id"], "request_key": request_key}
                else:
                    conn.execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (result["reservation_id"],))
                conn.execute("COMMIT")
            self._mirror()
        return result

    def release(
        self,
        *,
        owner_pid: int,
        tool_use_id: str = "",
        command: str = "",
        outcome: str = "success",
        now: float | None = None,
    ) -> int:
        """Release matching legacy allocations; return only the archived count.

        Managed allocations require exact lifecycle finalization even when the
        feature is off or a PostToolUse reports success.
        """
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows: list[sqlite3.Row]
            if tool_use_id:
                rows = conn.execute(
                    "SELECT * FROM reservations WHERE owner_pid=? AND tool_use_id=?", (owner_pid, tool_use_id)
                ).fetchall()
            elif command:
                sig = ResourceRequest(owner_pid, 0, "", command).command_signature
                rows = conn.execute(
                    "SELECT * FROM reservations WHERE owner_pid=? AND command_signature=? ORDER BY created_at LIMIT 1",
                    (owner_pid, sig),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM reservations WHERE owner_pid=?", (owner_pid,)).fetchall()
            released = 0
            for row in rows:
                if allocation_is_bound(conn, "direct", row["id"]):
                    continue
                self._archive_locked(conn, row, now, outcome)
                released += 1
            conn.execute("COMMIT")
        self._mirror()
        return released

    def cancel_queued(self, *, owner_pid: int, request_key: str = "") -> int:
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if request_key:
                cur = conn.execute("DELETE FROM queue WHERE owner_pid=? AND request_key=?", (owner_pid, request_key))
            else:
                cur = conn.execute("DELETE FROM queue WHERE owner_pid=?", (owner_pid,))
            conn.execute("COMMIT")
        self._mirror()
        return cur.rowcount

    def claim_stop_reminder(
        self, *, owner_pid: int, owner_started: float,
        max_reminders: int = 3, legacy_blocks: dict | None = None,
    ) -> dict[str, Any]:
        """Claim one session reminder, independently of queue scheduling."""
        with self._db() as conn:
            return claim_reminder(
                conn, owner_pid=owner_pid, owner_started=owner_started,
                max_reminders=max_reminders, legacy_blocks=legacy_blocks,
            )

    def queued_for_owner(self, owner_pid: int) -> list[dict[str, Any]]:
        with self._db() as conn:
            rows = conn.execute(
                "SELECT * FROM queue WHERE owner_pid=? ORDER BY priority_rank,queued_at", (owner_pid,)
            ).fetchall()
            return [dict(row) for row in rows]

    def cleanup(self, *, config: dict[str, Any] | None = None, now: float | None = None) -> list[str]:
        cfg = self._config(config, local_host_id=self.local_host_id)
        now = time.time() if now is None else now
        observations = self._cleanup_observations()
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            removed = self._cleanup_locked(conn, now, cfg, observations)
            conn.execute("COMMIT")
        self._mirror()
        return removed

    def record_sample(self, status: dict[str, Any], *, sampled_at: float | None = None) -> None:
        sampled_at = time.time() if sampled_at is None else sampled_at
        memory = _windows_memory()
        disks = _disk_io()
        ram = status.get("ram") or {}
        with self._db() as conn:
            conn.execute(
                """INSERT INTO resource_samples
                (sampled_at,light,cpu_pct,cpu_5min_avg,ram_used_pct,ram_free_gib,
                 commit_used_gib,commit_limit_gib,pagefile_used_gib,disk_json,
                 agent_groups_json,agent_trees_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sampled_at, status.get("light"), status.get("cpu_pct"), status.get("cpu_5min_avg"),
                    ram.get("used_pct"), ram.get("free_gb"), memory.get("commit_used_gib"),
                    memory.get("commit_limit_gib"), memory.get("pagefile_used_gib"),
                    json.dumps(disks, separators=(",", ":")),
                    json.dumps(status.get("agent_groups") or [], separators=(",", ":")),
                    json.dumps(status.get("agent_trees") or [], separators=(",", ":")),
                ),
            )
            conn.execute("DELETE FROM resource_samples WHERE sampled_at < ?", (sampled_at - 30 * 86400,))

    def snapshot(self) -> dict[str, Any]:
        with self._db() as conn:
            return {
                "reservations": [dict(r) for r in conn.execute("SELECT * FROM reservations ORDER BY created_at")],
                "queue": [dict(r) for r in conn.execute("SELECT * FROM queue ORDER BY priority_rank,queued_at")],
            }

    def _mirror(self) -> None:
        """Refresh compatibility JSON without changing committed DB outcomes."""
        try:
            self._mirror_impl()
        except (OSError, ValueError, TypeError):
            # SQLite is authoritative.  A locked antivirus/indexer or malformed
            # legacy mirror must never make a successful admission look failed.
            return

    def _mirror_impl(self) -> None:
        snap = self.snapshot()
        slots = {
            "slots": [
                {
                    "id": r["id"], "pid": r["owner_pid"], "repo": r["repo"],
                    "cmd": r["command_text"][:80], "ts": r["created_at"],
                    "ttl_min": max(1, round((r["expires_at"] - r["created_at"]) / 60)),
                    "priority": r["priority"], "resource_class": r["resource_class"],
                    "cpu_units": r["cpu_units"], "ram_gib": r["ram_gib"], "io_slots": r["io_slots"],
                }
                for r in snap["reservations"]
            ]
        }
        queue = {
            "q": [
                {
                    "request_key": r["request_key"], "pid": r["owner_pid"], "repo": r["repo"],
                    "ts": r["heartbeat_at"], "priority": r["priority"],
                    "resource_class": r["resource_class"],
                }
                for r in snap["queue"]
            ]
        }
        _atomic_json(self.data_dir / "slots.json", slots)
        _atomic_json(self.data_dir / "queue.json", queue)


def _windows_memory() -> dict[str, float]:
    result: dict[str, float] = {}
    if os.name == "nt":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        state = MEMORYSTATUSEX()
        state.dwLength = ctypes.sizeof(state)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(state)):
            result["commit_limit_gib"] = round(state.ullTotalPageFile / 2**30, 3)
            result["commit_used_gib"] = round((state.ullTotalPageFile - state.ullAvailPageFile) / 2**30, 3)
    try:
        import psutil

        result["pagefile_used_gib"] = round(psutil.swap_memory().used / 2**30, 3)
    except Exception:
        pass
    return result


def _disk_io() -> dict[str, Any]:
    try:
        import psutil

        return {name: value._asdict() for name, value in (psutil.disk_io_counters(perdisk=True) or {}).items()}
    except Exception:
        return {}
