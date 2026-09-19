"""Frozen SQL-bearing writer dependency closure from public commit 0b2f378.

This fixture intentionally has no imports/subclasses from current Sentinel code.
Selected old method bodies, schemas, resource normalization and capacity helpers
are verbatim, including the missing writer protocol and SELECT-only retry ACK.
They are test evidence of an older cooperating writer, never a supported runtime.

Two explicit test-only seams are NOT copied historical behavior:
* Coordinator._mirror is a no-op so admission does not write compatibility files.
* Exemptions always returns None; the tests exercise ordinary old admission only.

All source comes from public tracked Python at SOURCE_COMMIT. No local diff,
configuration, runtime database, environment or secret is included. SOURCE_NODES
records original path, inclusive line range and normalized-LF SHA256 for each
copied definition. Do not update these bodies to current helpers when tests fail.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Any, Callable
import uuid


class Exemptions:
    """Explicit fixture seam: no live or synthetic exemption can bypass gates."""
    def __init__(self, data_dir):
        self.data_dir = data_dir

    def match(self, *args, **kwargs):
        return None


SOURCE_COMMIT = '0b2f37819a2d4f68299fbec3fe619a4d05ba4749'
SOURCE_BLOBS = {'sentinel/coordinator.py': 'cce423f8eee93fed23305f6f90340f53933a3850', 'sentinel/maintainer.py': 'd6dc95b9d93263b89fa786798aee645499420819'}
SOURCE_NODES = {
    "ACTIVE_STATES": {
        "first_line": 24,
        "last_line": 24,
        "path": "sentinel/maintainer.py",
        "sha256": "3cc7d3f864755e6bb66d9435f1f1693eb51da412fa493e5efee78c8f4d585356"
    },
    "AUTOMATION_RANK": {
        "first_line": 25,
        "last_line": 25,
        "path": "sentinel/maintainer.py",
        "sha256": "4b6b5f752fafe2f7988cbfba34096276c05c7a98f224935153c54cf52b9ef980"
    },
    "CAPACITY_SCOPES": {
        "first_line": 27,
        "last_line": 27,
        "path": "sentinel/maintainer.py",
        "sha256": "b81bf79bd8e257ef620d182a40d9d0d3f0c2b1df4f64f1b5a524b78637821112"
    },
    "CLASS_DEFAULTS": {
        "first_line": 28,
        "last_line": 33,
        "path": "sentinel/coordinator.py",
        "sha256": "85fd3f5b942be8d1b52b6ecbb8d657a248123e4994a48fb2acd753463556849e"
    },
    "Coordinator.__init__": {
        "first_line": 159,
        "last_line": 170,
        "path": "sentinel/coordinator.py",
        "sha256": "0ed92565a01e222a346477214ce00adf70a24549a6e00767b1fa1ad5b95d2fb4"
    },
    "Coordinator._archive_locked": {
        "first_line": 303,
        "last_line": 316,
        "path": "sentinel/coordinator.py",
        "sha256": "19936ce905981fd193918e400e70c06f57d36a0e9cc900f5beebc1d737b6f895"
    },
    "Coordinator._cleanup_locked": {
        "first_line": 287,
        "last_line": 301,
        "path": "sentinel/coordinator.py",
        "sha256": "21d47dca525fbfd58b0ab72f35cbb20b950acfd8d93d5e70da8505972aad36b5"
    },
    "Coordinator._config": {
        "first_line": 273,
        "last_line": 285,
        "path": "sentinel/coordinator.py",
        "sha256": "35c528622c9770be585742701bbc6fb1bbd39e4e23dbaf057f0d63f718ffaf88"
    },
    "Coordinator._connect": {
        "first_line": 172,
        "last_line": 179,
        "path": "sentinel/coordinator.py",
        "sha256": "21028a4c3f4b85ce8cb830721c80522ef6d1b865fbb33537aaee0b1f83b4ce2d"
    },
    "Coordinator._db": {
        "first_line": 181,
        "last_line": 187,
        "path": "sentinel/coordinator.py",
        "sha256": "a142592b3b699035af2cfc83b668cc2c5543a5b6acf493018a1ad5b07b811679"
    },
    "Coordinator._init_db": {
        "first_line": 189,
        "last_line": 271,
        "path": "sentinel/coordinator.py",
        "sha256": "e49ae2809a1fe1be92f59a24dff3abab9245bde2d9c660616b57f07307c350b6"
    },
    "Coordinator._routed_local_pending": {
        "first_line": 342,
        "last_line": 358,
        "path": "sentinel/coordinator.py",
        "sha256": "d6539f83887f8b521321ef81e6c6c6d01aaca540212bbf4fc4a41eb6c407a442"
    },
    "Coordinator._status_metrics": {
        "first_line": 318,
        "last_line": 340,
        "path": "sentinel/coordinator.py",
        "sha256": "8223078f1532df3ede5384b487910c6873434ef82da126f23c82b35905018479"
    },
    "Coordinator.admit": {
        "first_line": 360,
        "last_line": 492,
        "path": "sentinel/coordinator.py",
        "sha256": "8dbb76a766c1b7fc405e76a722e831a60f064566f4f88784e6f02dccbb3ba758"
    },
    "Coordinator.cleanup": {
        "first_line": 572,
        "last_line": 580,
        "path": "sentinel/coordinator.py",
        "sha256": "84e625bf71e44a5f316b67d17a768e5e2e0d5edd26b39b156685ac492f622ef3"
    },
    "Coordinator.release": {
        "first_line": 523,
        "last_line": 552,
        "path": "sentinel/coordinator.py",
        "sha256": "377646a3c576cf54cfbebbeba576200929fe67742a79520294d0a302ece7015d"
    },
    "Coordinator.retry_queued": {
        "first_line": 494,
        "last_line": 521,
        "path": "sentinel/coordinator.py",
        "sha256": "a47a254dbd4111e096725a05a025542c127faca73b1b8498608b66b7f72b1729"
    },
    "Maintainer.__init__": {
        "first_line": 145,
        "last_line": 149,
        "path": "sentinel/maintainer.py",
        "sha256": "35dc0a3944fc29d5cc4a9e545c9c9523ddc80e3e1b5bdc8ffaae3024de7f425e"
    },
    "Maintainer._archive_locked": {
        "first_line": 546,
        "last_line": 560,
        "path": "sentinel/maintainer.py",
        "sha256": "22dfa78404525add8866b8c66a8cab304480466bf0d62989333742023f1b728d"
    },
    "Maintainer._cleanup_locked": {
        "first_line": 540,
        "last_line": 544,
        "path": "sentinel/maintainer.py",
        "sha256": "6558ddc4a163b714d616587aaf826e187eb1820399920b7415b20e52c17dd286"
    },
    "Maintainer._connect": {
        "first_line": 151,
        "last_line": 158,
        "path": "sentinel/maintainer.py",
        "sha256": "21028a4c3f4b85ce8cb830721c80522ef6d1b865fbb33537aaee0b1f83b4ce2d"
    },
    "Maintainer._db": {
        "first_line": 160,
        "last_line": 166,
        "path": "sentinel/maintainer.py",
        "sha256": "a142592b3b699035af2cfc83b668cc2c5543a5b6acf493018a1ad5b07b811679"
    },
    "Maintainer._decode_worker": {
        "first_line": 309,
        "last_line": 314,
        "path": "sentinel/maintainer.py",
        "sha256": "f68a0bab998d93685c50b0885ac83531e83fb06cc284904d673e288077981a1b"
    },
    "Maintainer._ensure_columns": {
        "first_line": 257,
        "last_line": 262,
        "path": "sentinel/maintainer.py",
        "sha256": "7de44983c7c4ac2b7bbc2b7391958298ae91230be3faa19c4e2a289af8c35072"
    },
    "Maintainer._fits": {
        "first_line": 335,
        "last_line": 371,
        "path": "sentinel/maintainer.py",
        "sha256": "37b17326d4fb5608b4d9338837a572b1b57b56ff34ad64c7afc3d921a56e1efb"
    },
    "Maintainer._init_db": {
        "first_line": 168,
        "last_line": 255,
        "path": "sentinel/maintainer.py",
        "sha256": "6b78a8fb0934787a5a8e8a50d38514e80eab0aeefcd9296cde0d2be056168030"
    },
    "Maintainer._pool_usage": {
        "first_line": 398,
        "last_line": 427,
        "path": "sentinel/maintainer.py",
        "sha256": "99558a33ef08652b1f800cd76341dd0b126de4c2939ca2d38b125f9a40c79f03"
    },
    "Maintainer._quota_jobs": {
        "first_line": 429,
        "last_line": 437,
        "path": "sentinel/maintainer.py",
        "sha256": "a1e30aed43b293fa61ec5942591d1198aacceb06fac4d123fc017fd9ab98cb81"
    },
    "Maintainer._safe_metadata": {
        "first_line": 378,
        "last_line": 396,
        "path": "sentinel/maintainer.py",
        "sha256": "12dadfb1ec04e56b5d075f8f0261dfb931aa208412e149a023e00e3deb1bdc5a"
    },
    "Maintainer._spec_hash": {
        "first_line": 373,
        "last_line": 376,
        "path": "sentinel/maintainer.py",
        "sha256": "703f1651f67035fc1f3a9efd3c6f262bd2fa44713ba499da301310c5cf555a30"
    },
    "Maintainer.heartbeat": {
        "first_line": 577,
        "last_line": 586,
        "path": "sentinel/maintainer.py",
        "sha256": "75433a5b35475ad5293877aaa21662e2684fcad01b4422bbd3947bc09ef64c47"
    },
    "Maintainer.release": {
        "first_line": 562,
        "last_line": 575,
        "path": "sentinel/maintainer.py",
        "sha256": "c5c907e46033d1cbdcda8628383c5e94f939ffd2734b9cfbb60eec27b983feea"
    },
    "Maintainer.route_and_reserve": {
        "first_line": 439,
        "last_line": 538,
        "path": "sentinel/maintainer.py",
        "sha256": "add809dd0b9bf9a1cb5b0ccbd2bc109cc28cf775774a5e1656459eec6826e900"
    },
    "Maintainer.upsert_worker": {
        "first_line": 264,
        "last_line": 304,
        "path": "sentinel/maintainer.py",
        "sha256": "68075bbe196f451ae8175d081e31729ee3ee7f8a3ae0dfa863e65888e5ea072d"
    },
    "PREFERENCES": {
        "first_line": 26,
        "last_line": 26,
        "path": "sentinel/maintainer.py",
        "sha256": "2c75be4b2c1d06f9c7f82c326e27992a3572d4131314f57cb6ca5086a4a9b6ae"
    },
    "PRIORITY_RANK": {
        "first_line": 27,
        "last_line": 27,
        "path": "sentinel/coordinator.py",
        "sha256": "766dab112a717b8b37deb08931629a0d75871a4044cee298832c7698d72d0c28"
    },
    "ResourceRequest": {
        "first_line": 36,
        "last_line": 106,
        "path": "sentinel/coordinator.py",
        "sha256": "a59d44762bc08594de96f6f417d1a87b1a0bbd863f72e6f28caf9fed9dc5cb8d"
    },
    "SENSITIVE_KEY": {
        "first_line": 28,
        "last_line": 28,
        "path": "sentinel/maintainer.py",
        "sha256": "7f9176d318990dfebbba09bbbd5d31cd6b04e94340dc77410439e6ff81035c2f"
    },
    "Task": {
        "first_line": 95,
        "last_line": 139,
        "path": "sentinel/maintainer.py",
        "sha256": "732d10c9cfd0074bba978de4a07b98a1ebb11e8214a2e81e5b19033837202e41"
    },
    "Worker": {
        "first_line": 31,
        "last_line": 92,
        "path": "sentinel/maintainer.py",
        "sha256": "64e47c408b96587851ede7270bb9161b3ab4a339e6e755d5b0bde271bd3dfa55"
    },
    "_default_pid_identity": {
        "first_line": 148,
        "last_line": 155,
        "path": "sentinel/coordinator.py",
        "sha256": "7c1fcf43ad61b26ff628cf4a1db3c5905ed042066aae2870c49363e7de2c67e8"
    },
    "redact_command": {
        "first_line": 129,
        "last_line": 138,
        "path": "sentinel/coordinator.py",
        "sha256": "b671c9007fa016cb93047e6bcc7c7dbc18e4d9f0e134b4e59170195ead32d7ee"
    }
}


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
        )
        if normalized.owner_pid <= 0:
            raise ValueError("owner_pid must be positive")
        if min(normalized.cpu_units or 0, normalized.ram_gib or 0, normalized.io_slots or 0) < 0:
            raise ValueError("resource requirements cannot be negative")
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
        raw = json.dumps(
            {
                "repo": req.repo, "command_signature": req.command_signature,
                "resource_class": req.resource_class, "priority": req.priority,
                "cpu_units": req.cpu_units, "ram_gib": req.ram_gib,
                "io_slots": req.io_slots,
            },
            sort_keys=True, separators=(",", ":"),
        )
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

def _default_pid_identity(pid: int) -> tuple[bool, float]:
    try:
        import psutil

        process = psutil.Process(pid)
        return process.is_running(), float(process.create_time())
    except Exception:
        return False, 0.0

class Coordinator:
    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        db_path: str | os.PathLike[str] | None = None,
        pid_identity: Callable[[int], tuple[bool, float]] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self.pid_identity = pid_identity or _default_pid_identity
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _db(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
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

    @staticmethod
    def _config(config: dict[str, Any] | None) -> dict[str, Any]:
        cfg = dict(config or {})
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

    def _cleanup_locked(self, conn: sqlite3.Connection, now: float, config: dict[str, Any]) -> list[str]:
        removed: list[str] = []
        for row in conn.execute("SELECT * FROM reservations").fetchall():
            alive, started = self.pid_identity(int(row["owner_pid"]))
            identity_matches = not row["owner_started"] or abs(started - row["owner_started"]) < 2
            if not alive or not identity_matches or float(row["expires_at"]) <= now:
                self._archive_locked(conn, row, now, "stale")
                removed.append(row["id"])
        queue_cutoff = now - float(config["queue_ttl_min"]) * 60
        for row in conn.execute("SELECT * FROM queue").fetchall():
            alive, started = self.pid_identity(int(row["owner_pid"]))
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
        cfg = self._config(config)
        now = time.time() if now is None else now
        metrics = self._status_metrics(status, cfg, now)
        result: dict[str, Any]
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now, cfg)
            existing = conn.execute("SELECT * FROM reservations WHERE request_key=?", (req.request_key,)).fetchone()
            if existing:
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
            handoff = conn.execute(
                "SELECT * FROM reservations WHERE owner_pid=? AND command_signature=? AND tool_use_id='' ORDER BY created_at LIMIT 1",
                (req.owner_pid, req.command_signature),
            ).fetchone()
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
                 spec_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(request_key) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,
                  tool_use_id=excluded.tool_use_id,priority=excluded.priority,
                  priority_rank=excluded.priority_rank""",
                (
                    req.request_key, req.owner_pid, req.owner_started, req.tool_use_id, req.repo,
                    req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                    PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                    req.spec_hash,
                ),
            )
            ordered = conn.execute("SELECT request_key FROM queue ORDER BY priority_rank,queued_at,request_key").fetchall()
            position = next(i for i, row in enumerate(ordered, 1) if row["request_key"] == req.request_key)
            reason = "capacity"
            allowed = position == 1
            if not metrics["fresh"]:
                allowed = False
                reason = "status_stale"
            elif metrics["light"] in {"ORANGE", "RED"}:
                allowed = False
                reason = f"light_{str(metrics['light']).lower()}"
            elif position != 1:
                allowed = False
                reason = "queue_order"

            active = conn.execute("SELECT * FROM reservations").fetchall()
            grace = float(cfg["reservation_grace_sec"])
            pending_cpu = sum(float(r["cpu_units"]) for r in active if now - float(r["created_at"]) <= grace)
            pending_ram = sum(float(r["ram_gib"]) for r in active if now - float(r["created_at"]) <= grace)
            routed_cpu, routed_ram = self._routed_local_pending(conn, cfg, now)
            pending_cpu += routed_cpu
            pending_ram += routed_ram
            used_io = sum(int(r["io_slots"]) for r in active)
            if allowed and float(metrics["actual_cpu"]) + pending_cpu + float(req.cpu_units) > float(cfg["local_allocatable_cpu"]):
                allowed, reason = False, "cpu_capacity"
            if allowed and float(metrics["actual_ram"]) + pending_ram + float(req.ram_gib) > float(cfg["local_allocatable_ram_gib"]):
                allowed, reason = False, "ram_capacity"
            commit_limit = float(metrics["commit_limit"])
            if allowed and commit_limit and float(metrics["commit_used"]) + pending_ram + float(req.ram_gib) > commit_limit - float(cfg["local_commit_headroom_gib"]):
                allowed, reason = False, "commit_capacity"
            if allowed and used_io + int(req.io_slots) > int(cfg["heavy_io_slots"]):
                allowed, reason = False, "io_capacity"

            # Explicit operator exemption bypasses load/order gates, but still
            # reserves and records usage so non-exempt callers see the pressure.
            exemption = None
            try:
                exemption = Exemptions(self.data_dir).match(req.owner_pid, req.owner_started, now=now)
            except (OSError, sqlite3.Error):
                pass  # unreadable exemption state never grants a bypass
            if exemption:
                allowed = True

            if allowed:
                reservation_id = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO reservations
                    (id,request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                     resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,created_at,
                     heartbeat_at,expires_at,spec_hash)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        reservation_id, req.request_key, req.owner_pid, req.owner_started, req.tool_use_id,
                        req.repo, req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                        PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                        now + float(cfg["reservation_ttl_min"]) * 60, req.spec_hash,
                    ),
                )
                conn.execute("DELETE FROM queue WHERE request_key=?", (req.request_key,))
                result = {"allowed": True, "reservation_id": reservation_id, "reused": False, "request_key": req.request_key}
                if exemption:
                    result.update(reason="user_exemption", exemption_id=exemption["id"], exemption_expires_at=exemption["expires_at"])
            else:
                result = {"allowed": False, "reason": reason, "position": position, "request_key": req.request_key}
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
                active = conn.execute("SELECT id FROM reservations WHERE request_key=?", (request_key,)).fetchone()
            if active:
                return {"allowed": True, "reservation_id": active["id"], "reused": True, "request_key": request_key}
            return {"allowed": False, "reason": "request_missing", "request_key": request_key}
        request = ResourceRequest(
            owner_pid=row["owner_pid"], owner_started=row["owner_started"], repo=row["repo"],
            command=row["command_text"], resource_class=row["resource_class"], priority=row["priority"],
            tool_use_id=row["tool_use_id"] or "", cpu_units=row["cpu_units"],
            ram_gib=row["ram_gib"], io_slots=row["io_slots"], signature=row["command_signature"],
        )
        result = self.admit(request, status, config=config, now=now)
        if result.get("allowed"):
            with self._db() as conn:
                conn.execute("UPDATE reservations SET tool_use_id='' WHERE id=?", (result["reservation_id"],))
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
            for row in rows:
                self._archive_locked(conn, row, now, outcome)
            conn.execute("COMMIT")
        self._mirror()
        return len(rows)

    def cleanup(self, *, config: dict[str, Any] | None = None, now: float | None = None) -> list[str]:
        cfg = self._config(config)
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            removed = self._cleanup_locked(conn, now, cfg)
            conn.execute("COMMIT")
        self._mirror()
        return removed

    def _mirror(self):
        """Fixture-only filesystem seam; SQL methods above are unchanged."""
        return None


ACTIVE_STATES = {"AVAILABLE", "BUSY"}

AUTOMATION_RANK = {"AUTOMATABLE": 0, "PARTIAL": 1, "MANUAL": 2, "UNKNOWN": 3}

PREFERENCES = {"LOCAL_REQUIRED", "LOCAL_PREFERRED", "CLOUD_OK", "CLOUD_PREFERRED"}

CAPACITY_SCOPES = {"SHARED_POOL", "PER_EXECUTION"}

SENSITIVE_KEY = re.compile(r"(?i)(token|password|passwd|secret|credential|api[_-]?key)")

@dataclass(frozen=True)
class Worker:
    id: str
    provider: str
    failure_domain: str
    capacity_scope: str = "SHARED_POOL"
    capacity_pool: str = ""
    max_concurrency: int = 1
    quota_domain: str = ""
    state: str = "UNKNOWN"
    automation_level: str = "UNKNOWN"
    os: str = "linux"
    capacity_ram_gib: float = 0.0
    allocatable_ram_gib: float = 0.0
    visible_cpu: float | None = None
    allocatable_cpu: float | None = None
    disk_free_gib: float | None = None
    allocatable_disk_gib: float | None = None
    capabilities: dict[str, Any] = field(default_factory=dict)
    trust_domain: str = "unknown"
    source: str = "manual"
    observed_at: float = 0.0
    probe_expires_at: float = 0.0

    def normalized(self) -> "Worker":
        state = self.state.upper()
        automation = self.automation_level.upper()
        capacity_scope = self.capacity_scope.upper()
        if automation not in AUTOMATION_RANK:
            raise ValueError(f"unknown automation level: {automation}")
        if capacity_scope not in CAPACITY_SCOPES:
            raise ValueError(f"unknown capacity scope: {capacity_scope}")
        if not self.id or not self.failure_domain:
            raise ValueError("worker id and failure_domain are required")
        if self.allocatable_ram_gib < 0 or self.capacity_ram_gib < self.allocatable_ram_gib:
            raise ValueError("allocatable RAM must be between zero and capacity RAM")
        if int(self.max_concurrency) < 1:
            raise ValueError("max_concurrency must be positive")
        capacity_pool = self.capacity_pool or self.failure_domain
        return Worker(
            id=self.id,
            provider=self.provider or self.id,
            failure_domain=self.failure_domain,
            capacity_scope=capacity_scope,
            capacity_pool=capacity_pool,
            max_concurrency=int(self.max_concurrency),
            quota_domain=self.quota_domain or capacity_pool,
            state=state,
            automation_level=automation,
            os=self.os.lower(),
            capacity_ram_gib=float(self.capacity_ram_gib),
            allocatable_ram_gib=float(self.allocatable_ram_gib),
            visible_cpu=None if self.visible_cpu is None else float(self.visible_cpu),
            allocatable_cpu=None if self.allocatable_cpu is None else float(self.allocatable_cpu),
            disk_free_gib=None if self.disk_free_gib is None else float(self.disk_free_gib),
            allocatable_disk_gib=None if self.allocatable_disk_gib is None else float(self.allocatable_disk_gib),
            capabilities=dict(self.capabilities),
            trust_domain=self.trust_domain,
            source=self.source,
            observed_at=float(self.observed_at),
            probe_expires_at=float(self.probe_expires_at),
        )

@dataclass(frozen=True)
class Task:
    id: str
    ram_gib: float
    cpu_units: float = 1.0
    disk_gib: float = 0.0
    os: str = "any"
    docker: bool = False
    browser: bool = False
    hardware: bool = False
    local_browser_state: bool = False
    local_network: bool = False
    persistent_environment: bool = False
    execution_preference: str = "CLOUD_PREFERRED"
    allowed_trust_domains: tuple[str, ...] = ()
    allowed_worker_ids: tuple[str, ...] = ()
    automated_only: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "Task":
        preference = self.execution_preference.upper()
        if preference not in PREFERENCES:
            raise ValueError(f"unknown execution preference: {preference}")
        if not self.id:
            raise ValueError("task id is required")
        if min(self.ram_gib, self.cpu_units, self.disk_gib) < 0:
            raise ValueError("task resources cannot be negative")
        return Task(
            id=self.id,
            ram_gib=float(self.ram_gib),
            cpu_units=float(self.cpu_units),
            disk_gib=float(self.disk_gib),
            os=self.os.lower(),
            docker=bool(self.docker),
            browser=bool(self.browser),
            hardware=bool(self.hardware),
            local_browser_state=bool(self.local_browser_state),
            local_network=bool(self.local_network),
            persistent_environment=bool(self.persistent_environment),
            execution_preference=preference,
            allowed_trust_domains=tuple(self.allowed_trust_domains),
            allowed_worker_ids=tuple(self.allowed_worker_ids),
            automated_only=bool(self.automated_only),
            metadata=dict(self.metadata),
        )

class Maintainer:
    def __init__(self, data_dir: str | os.PathLike[str], *, db_path: str | os.PathLike[str] | None = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextmanager
    def _db(self):
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._db() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workers (
                    id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL,
                    failure_domain TEXT NOT NULL,
                    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
                    capacity_pool TEXT NOT NULL DEFAULT '',
                    max_concurrency INTEGER NOT NULL DEFAULT 1,
                    quota_domain TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    automation_level TEXT NOT NULL,
                    os TEXT NOT NULL,
                    capacity_ram_gib REAL NOT NULL,
                    allocatable_ram_gib REAL NOT NULL,
                    visible_cpu REAL,
                    allocatable_cpu REAL,
                    disk_free_gib REAL,
                    allocatable_disk_gib REAL,
                    capabilities_json TEXT NOT NULL,
                    trust_domain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    probe_expires_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workers_domain ON workers(failure_domain);
                CREATE TABLE IF NOT EXISTS worker_reservations (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL UNIQUE,
                    worker_id TEXT NOT NULL,
                    failure_domain TEXT NOT NULL,
                    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
                    capacity_pool TEXT NOT NULL DEFAULT '',
                    spec_hash TEXT NOT NULL DEFAULT '',
                    ram_gib REAL NOT NULL,
                    cpu_units REAL NOT NULL,
                    disk_gib REAL NOT NULL,
                    created_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY(worker_id) REFERENCES workers(id)
                );
                CREATE INDEX IF NOT EXISTS idx_worker_res_domain
                    ON worker_reservations(failure_domain, expires_at);
                CREATE TABLE IF NOT EXISTS routed_executions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reservation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    failure_domain TEXT NOT NULL,
                    capacity_scope TEXT NOT NULL DEFAULT 'SHARED_POOL',
                    capacity_pool TEXT NOT NULL DEFAULT '',
                    spec_hash TEXT NOT NULL DEFAULT '',
                    ram_gib REAL NOT NULL,
                    cpu_units REAL NOT NULL,
                    disk_gib REAL NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL NOT NULL,
                    outcome TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );
                """
            )
            # Additive migrations keep existing live databases usable.
            self._ensure_columns(conn, "workers", {
                "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
                "capacity_pool": "TEXT NOT NULL DEFAULT ''",
                "max_concurrency": "INTEGER NOT NULL DEFAULT 1",
                "quota_domain": "TEXT NOT NULL DEFAULT ''",
            })
            self._ensure_columns(conn, "worker_reservations", {
                "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
                "capacity_pool": "TEXT NOT NULL DEFAULT ''",
                "spec_hash": "TEXT NOT NULL DEFAULT ''",
            })
            self._ensure_columns(conn, "routed_executions", {
                "capacity_scope": "TEXT NOT NULL DEFAULT 'SHARED_POOL'",
                "capacity_pool": "TEXT NOT NULL DEFAULT ''",
                "spec_hash": "TEXT NOT NULL DEFAULT ''",
            })
            conn.execute("UPDATE workers SET capacity_pool=failure_domain WHERE capacity_pool='' OR capacity_pool IS NULL")
            conn.execute("UPDATE workers SET quota_domain=capacity_pool WHERE quota_domain='' OR quota_domain IS NULL")
            conn.execute("UPDATE worker_reservations SET capacity_pool=failure_domain WHERE capacity_pool='' OR capacity_pool IS NULL")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_worker_res_pool ON worker_reservations(capacity_pool, expires_at)")

    @staticmethod
    def _ensure_columns(conn: sqlite3.Connection, table: str, columns: dict[str, str]) -> None:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    def upsert_worker(self, worker: Worker, *, now: float | None = None) -> dict[str, Any]:
        w = worker.normalized()
        now = time.time() if now is None else now
        observed = w.observed_at or now
        expires = w.probe_expires_at or observed + 7 * 86400
        values = asdict(w)
        values.update(observed_at=observed, probe_expires_at=expires)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO workers
                (id,provider,failure_domain,capacity_scope,capacity_pool,max_concurrency,quota_domain,
                 state,automation_level,os,capacity_ram_gib,
                 allocatable_ram_gib,visible_cpu,allocatable_cpu,disk_free_gib,
                 allocatable_disk_gib,capabilities_json,trust_domain,source,observed_at,
                 probe_expires_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  provider=excluded.provider,failure_domain=excluded.failure_domain,
                  capacity_scope=excluded.capacity_scope,capacity_pool=excluded.capacity_pool,
                  max_concurrency=excluded.max_concurrency,quota_domain=excluded.quota_domain,
                  state=excluded.state,automation_level=excluded.automation_level,os=excluded.os,
                  capacity_ram_gib=excluded.capacity_ram_gib,
                  allocatable_ram_gib=excluded.allocatable_ram_gib,
                  visible_cpu=excluded.visible_cpu,allocatable_cpu=excluded.allocatable_cpu,
                  disk_free_gib=excluded.disk_free_gib,
                  allocatable_disk_gib=excluded.allocatable_disk_gib,
                  capabilities_json=excluded.capabilities_json,trust_domain=excluded.trust_domain,
                  source=excluded.source,observed_at=excluded.observed_at,
                  probe_expires_at=excluded.probe_expires_at,updated_at=excluded.updated_at""",
                (
                    w.id, w.provider, w.failure_domain, w.capacity_scope, w.capacity_pool,
                    w.max_concurrency, w.quota_domain, w.state, w.automation_level, w.os,
                    w.capacity_ram_gib, w.allocatable_ram_gib, w.visible_cpu, w.allocatable_cpu,
                    w.disk_free_gib, w.allocatable_disk_gib,
                    json.dumps(w.capabilities, separators=(",", ":")), w.trust_domain, w.source,
                    observed, expires, now,
                ),
            )
            conn.execute("COMMIT")
        return values

    @staticmethod
    def _decode_worker(row: sqlite3.Row, now: float) -> dict[str, Any]:
        item = dict(row)
        item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
        item["probe_fresh"] = float(item["probe_expires_at"]) > now
        return item

    @staticmethod
    def _fits(task: Task, worker: dict[str, Any], now: float) -> tuple[bool, str]:
        if worker["state"] not in ACTIVE_STATES:
            return False, f"state_{worker['state'].lower()}"
        if float(worker["probe_expires_at"]) <= now:
            return False, "probe_stale"
        local = bool(worker["capabilities"].get("local"))
        if task.automated_only:
            if worker["capabilities"].get("enabled", True) is False:
                return False, "worker_disabled"
            if worker["automation_level"] != "AUTOMATABLE":
                return False, "not_automatable"
            adapter_ready = worker["capabilities"].get("adapter_ready")
            if adapter_ready is None:
                adapter_ready = local
            if not bool(adapter_ready):
                return False, "adapter_not_ready"
        if task.allowed_worker_ids and worker["id"] not in task.allowed_worker_ids:
            return False, "worker_allowlist"
        if task.execution_preference == "LOCAL_REQUIRED" and not local:
            return False, "local_required"
        if task.os != "any" and worker["os"] != task.os:
            return False, "os"
        checks = {
            "docker": task.docker,
            "browser": task.browser,
            "hardware": task.hardware,
            "local_browser_state": task.local_browser_state,
            "local_network": task.local_network,
            "persistent_environment": task.persistent_environment,
        }
        for capability, required in checks.items():
            if required and not bool(worker["capabilities"].get(capability)):
                return False, capability
        if task.allowed_trust_domains and worker["trust_domain"] not in task.allowed_trust_domains:
            return False, "trust_domain"
        return True, "fit"

    @staticmethod
    def _spec_hash(task: Task) -> str:
        payload = json.dumps(asdict(task), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_metadata(value: Any, *, depth: int = 0) -> Any:
        if depth > 4:
            return "<truncated>"
        if isinstance(value, dict):
            return {
                str(key): (
                    "<redacted>" if SENSITIVE_KEY.search(str(key))
                    else Maintainer._safe_metadata(item, depth=depth + 1)
                )
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [Maintainer._safe_metadata(item, depth=depth + 1) for item in value[:100]]
        if isinstance(value, str):
            return value[:500]
        if value is None or isinstance(value, (int, float, bool)):
            return value
        return f"<{type(value).__name__}>"

    @staticmethod
    def _pool_usage(
        conn: sqlite3.Connection, worker: dict[str, Any]
    ) -> dict[str, float | int]:
        usage = conn.execute(
            """SELECT COALESCE(SUM(ram_gib),0) ram,COALESCE(SUM(cpu_units),0) cpu,
                      COALESCE(SUM(disk_gib),0) disk,COUNT(*) jobs
               FROM worker_reservations WHERE capacity_pool=?""",
            (worker["capacity_pool"],),
        ).fetchone()
        result: dict[str, float | int] = {
            "ram": float(usage["ram"]), "cpu": float(usage["cpu"]),
            "disk": float(usage["disk"]), "jobs": int(usage["jobs"]),
        }
        # Coordinator reservations are another entry point to this same local
        # pool.  Counting them here prevents local agent commands and routed
        # executions from independently spending the same headroom.
        if bool(worker["capabilities"].get("local")):
            has_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='reservations'"
            ).fetchone()
            if has_table:
                direct = conn.execute(
                    """SELECT COALESCE(SUM(ram_gib),0) ram,COALESCE(SUM(cpu_units),0) cpu,
                              COALESCE(SUM(io_slots),0) io,COUNT(*) jobs FROM reservations"""
                ).fetchone()
                result["ram"] = float(result["ram"]) + float(direct["ram"])
                result["cpu"] = float(result["cpu"]) + float(direct["cpu"])
                result["jobs"] = int(result["jobs"]) + int(direct["jobs"])
        return result

    @staticmethod
    def _quota_jobs(conn: sqlite3.Connection, quota_domain: str) -> int:
        return int(conn.execute(
            """SELECT COUNT(*)
               FROM worker_reservations r
               JOIN workers w ON w.id=r.worker_id
               WHERE w.quota_domain=?""",
            (quota_domain,),
        ).fetchone()[0])

    def route_and_reserve(self, task: Task, *, ttl_min: int = 120, now: float | None = None) -> dict[str, Any]:
        t = task.normalized()
        spec_hash = self._spec_hash(t)
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now)
            existing = conn.execute("SELECT * FROM worker_reservations WHERE task_id=?", (t.id,)).fetchone()
            if existing:
                if existing["spec_hash"] != spec_hash:
                    conn.execute("COMMIT")
                    return {
                        "reserved": False, "reason": "task_spec_mismatch", "task_id": t.id,
                        "reservation_id": existing["id"],
                    }
                conn.execute(
                    "UPDATE worker_reservations SET heartbeat_at=?,expires_at=? WHERE id=?",
                    (now, now + ttl_min * 60, existing["id"]),
                )
                conn.execute("COMMIT")
                return {"reserved": True, "reused": True, **dict(existing)}

            workers = [self._decode_worker(row, now) for row in conn.execute("SELECT * FROM workers")]
            rejected: dict[str, str] = {}
            candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
            for worker in workers:
                fits, reason = self._fits(t, worker, now)
                if not fits:
                    rejected[worker["id"]] = reason
                    continue
                usage = self._pool_usage(conn, worker)
                if int(usage["jobs"]) >= int(worker["max_concurrency"]):
                    rejected[worker["id"]] = "concurrency_capacity"
                    continue
                quota_jobs = self._quota_jobs(conn, worker["quota_domain"])
                if quota_jobs >= int(worker["max_concurrency"]):
                    rejected[worker["id"]] = "quota_concurrency"
                    continue
                shared = worker["capacity_scope"] == "SHARED_POOL"
                accounted_ram = float(usage["ram"]) if shared else 0.0
                accounted_cpu = float(usage["cpu"]) if shared else 0.0
                accounted_disk = float(usage["disk"]) if shared else 0.0
                if accounted_ram + t.ram_gib > float(worker["allocatable_ram_gib"]):
                    rejected[worker["id"]] = "ram_capacity"
                    continue
                if worker["allocatable_cpu"] is not None and accounted_cpu + t.cpu_units > float(worker["allocatable_cpu"]):
                    rejected[worker["id"]] = "cpu_capacity"
                    continue
                if worker["allocatable_disk_gib"] is not None and accounted_disk + t.disk_gib > float(worker["allocatable_disk_gib"]):
                    rejected[worker["id"]] = "disk_capacity"
                    continue
                observed_free = worker["capabilities"].get("observed_free_ram_gib")
                if observed_free is not None:
                    headroom = float(worker["capabilities"].get("memory_headroom_gib") or 0)
                    if t.ram_gib > max(0.0, float(observed_free) - headroom - accounted_ram):
                        rejected[worker["id"]] = "observed_ram_headroom"
                        continue
                local = bool(worker["capabilities"].get("local"))
                if t.execution_preference == "LOCAL_PREFERRED":
                    preference_rank = 0 if local else 1
                elif t.execution_preference in {"CLOUD_PREFERRED", "CLOUD_OK"}:
                    preference_rank = 1 if local else 0
                else:
                    preference_rank = 0
                ram_after = float(worker["allocatable_ram_gib"]) - accounted_ram - t.ram_gib
                rank = (preference_rank, AUTOMATION_RANK[worker["automation_level"]], ram_after, worker["id"])
                candidates.append((rank, worker))

            if not candidates:
                conn.execute("COMMIT")
                return {"reserved": False, "reason": "no_compatible_worker", "rejected": rejected}

            worker = min(candidates, key=lambda item: item[0])[1]
            reservation_id = uuid.uuid4().hex
            conn.execute(
                """INSERT INTO worker_reservations
                (id,task_id,worker_id,failure_domain,capacity_scope,capacity_pool,spec_hash,
                 ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,expires_at,metadata_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    reservation_id, t.id, worker["id"], worker["failure_domain"],
                    worker["capacity_scope"], worker["capacity_pool"], spec_hash, t.ram_gib,
                    t.cpu_units, t.disk_gib, now, now, now + ttl_min * 60,
                    json.dumps(self._safe_metadata(t.metadata), separators=(",", ":")),
                ),
            )
            conn.execute("COMMIT")
        return {
            "reserved": True,
            "reused": False,
            "reservation_id": reservation_id,
            "task_id": t.id,
            "worker_id": worker["id"],
            "failure_domain": worker["failure_domain"],
            "capacity_scope": worker["capacity_scope"],
            "capacity_pool": worker["capacity_pool"],
            "ram_gib": t.ram_gib,
            "cpu_units": t.cpu_units,
            "disk_gib": t.disk_gib,
        }

    def _cleanup_locked(self, conn: sqlite3.Connection, now: float) -> int:
        rows = conn.execute("SELECT * FROM worker_reservations WHERE expires_at<=?", (now,)).fetchall()
        for row in rows:
            self._archive_locked(conn, row, now, "stale")
        return len(rows)

    @staticmethod
    def _archive_locked(conn: sqlite3.Connection, row: sqlite3.Row, now: float, outcome: str) -> None:
        conn.execute(
            """INSERT INTO routed_executions
            (reservation_id,task_id,worker_id,failure_domain,capacity_scope,capacity_pool,
             spec_hash,ram_gib,cpu_units,disk_gib,started_at,ended_at,outcome,metadata_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                row["id"], row["task_id"], row["worker_id"], row["failure_domain"],
                row["capacity_scope"], row["capacity_pool"], row["spec_hash"],
                row["ram_gib"], row["cpu_units"], row["disk_gib"], row["created_at"], now,
                outcome, row["metadata_json"],
            ),
        )
        conn.execute("DELETE FROM worker_reservations WHERE id=?", (row["id"],))

    def release(self, *, reservation_id: str = "", task_id: str = "", outcome: str = "success", now: float | None = None) -> int:
        if not reservation_id and not task_id:
            raise ValueError("reservation_id or task_id is required")
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if reservation_id:
                rows = conn.execute("SELECT * FROM worker_reservations WHERE id=?", (reservation_id,)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM worker_reservations WHERE task_id=?", (task_id,)).fetchall()
            for row in rows:
                self._archive_locked(conn, row, now, outcome)
            conn.execute("COMMIT")
        return len(rows)

    def heartbeat(self, task_id: str, *, ttl_min: int = 120, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE worker_reservations SET heartbeat_at=?,expires_at=? WHERE task_id=?",
                (now, now + ttl_min * 60, task_id),
            )
            conn.execute("COMMIT")
        return cur.rowcount > 0
