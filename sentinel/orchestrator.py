"""Persistent task orchestration across agent sessions and heterogeneous workers.

The orchestrator is deliberately a one-shot reconciler.  A scheduled `tick`
can crash or the machine can reboot; SQLite remains authoritative and the next
tick resumes polling, routing, reservations, claims, and result collection.
"""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from sentinel.maintainer import Maintainer, Task as PlacementTask


PRIORITIES = {"P0", "P1", "P2", "P3"}
DISPATCH_MODES = {"WORKER", "SESSION"}
EXECUTION_PREFERENCES = {"LOCAL_REQUIRED", "LOCAL_PREFERRED", "CLOUD_PREFERRED", "CLOUD_OK"}
TERMINAL_TASK_STATES = {"DONE", "FAILED", "CANCELLED", "BLOCKED"}
ACTIVE_JOB_STATES = {"SUBMITTING", "SUBMITTED", "QUEUED", "RUNNING"}
SUCCESS_JOB_STATES = {"SUCCEEDED", "SUCCESS", "DONE", "COMPLETED"}
FAILURE_JOB_STATES = {"FAILED", "ERROR", "TIMED_OUT", "TIMEOUT"}
CANCEL_JOB_STATES = {"CANCELLED", "CANCELED"}
TASK_STATES = {
    "QUEUED", "ROUTING", "WAITING_CAPACITY", "RESERVED", "SUBMITTED", "RUNNING",
    "AWAITING_MANUAL", "ASSIGNED", "VERIFYING", "DONE", "FAILED", "RETRYABLE", "BLOCKED", "CANCELLED",
}


def _explicit_capacity_estimates(requirements: dict[str, Any]) -> tuple[int | None, int]:
    """Preserve explicit byte/slot estimates without truthiness or coercion.

    Missing Commit retains the existing RAM-based estimate. An explicit unknown,
    Boolean, fractional value, or out-of-range SQLite integer is not that default.
    """
    if not isinstance(requirements, dict):
        raise ValueError("requirements must be an object")
    for name in ("commit_bytes", "io_slots"):
        if name in requirements and (type(requirements[name]) is not int or
                                     not 0 <= requirements[name] <= (1 << 63) - 1):
            raise ValueError(f"requirements.{name} must be a nonnegative SQLite integer")
    return requirements.get("commit_bytes"), requirements.get("io_slots", 1)


@dataclass(frozen=True)
class TaskSpec:
    id: str
    prompt: str = ""
    command: str = ""
    repo: str = ""
    base_sha: str = ""
    branch: str = ""
    path_scopes: tuple[str, ...] = ()
    priority: str = "P2"
    requirements: dict[str, Any] = field(default_factory=dict)
    execution_preference: str = "CLOUD_PREFERRED"
    allowed_trust_domains: tuple[str, ...] = ()
    allowed_worker_ids: tuple[str, ...] = ()
    dispatch_mode: str = "WORKER"
    allowed_agent_kinds: tuple[str, ...] = ()
    verification: dict[str, Any] = field(default_factory=dict)
    depends_on: tuple[str, ...] = ()
    parent_task_id: str = ""
    requested_by_session: str = ""
    max_attempts: int = 2
    metadata: dict[str, Any] = field(default_factory=dict)

    def normalized(self) -> "TaskSpec":
        if not self.id or not all(ch.isalnum() or ch in "-_.:" for ch in self.id):
            raise ValueError("task id must contain only letters, digits, '-', '_', '.', or ':'")
        if not self.prompt.strip() and not self.command.strip():
            raise ValueError("task requires prompt or command")
        priority = self.priority.upper()
        if priority not in PRIORITIES:
            raise ValueError(f"unknown priority: {priority}")
        dispatch_mode = self.dispatch_mode.upper()
        if dispatch_mode not in DISPATCH_MODES:
            raise ValueError(f"unknown dispatch mode: {dispatch_mode}")
        execution_preference = self.execution_preference.upper()
        if execution_preference not in EXECUTION_PREFERENCES:
            raise ValueError(f"unknown execution preference: {execution_preference}")
        requirements = {
            "ram_gib": 1.0,
            "cpu_units": 1.0,
            "disk_gib": 0.0,
            "os": "any",
            "docker": False,
            "browser": False,
            "hardware": False,
            "local_browser_state": False,
            "local_network": False,
            "persistent_environment": False,
            **dict(self.requirements),
        }
        for name in ("ram_gib", "cpu_units", "disk_gib"):
            try:
                requirements[name] = float(requirements[name])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"requirements.{name} must be numeric") from exc
            if not math.isfinite(requirements[name]) or requirements[name] < 0:
                raise ValueError(f"requirements.{name} must be finite and nonnegative")
        _explicit_capacity_estimates(requirements)
        normalized_scope_set = set()
        for path_scope in self.path_scopes:
            if not path_scope:
                continue
            scope = path_scope.replace("\\", "/").strip("/")
            normalized_scope_set.add(scope or ".")
        normalized_scopes = tuple(sorted(normalized_scope_set))
        metadata = dict(self.metadata)
        if self.repo and not bool(metadata.get("read_only")):
            if not self.base_sha or not normalized_scopes:
                raise ValueError(
                    "repo-writing tasks require base_sha and path_scopes; set metadata.read_only=true for read-only work"
                )
            if not re.fullmatch(r"[0-9a-fA-F]{7,64}", self.base_sha):
                raise ValueError("base_sha must be a 7-64 character hexadecimal Git object id")
        return TaskSpec(
            id=self.id,
            prompt=self.prompt.strip(),
            command=self.command.strip(),
            repo=self.repo,
            base_sha=self.base_sha,
            branch=self.branch,
            path_scopes=normalized_scopes,
            priority=priority,
            requirements=requirements,
            execution_preference=execution_preference,
            allowed_trust_domains=tuple(self.allowed_trust_domains),
            allowed_worker_ids=tuple(self.allowed_worker_ids),
            dispatch_mode=dispatch_mode,
            allowed_agent_kinds=tuple(kind.lower() for kind in self.allowed_agent_kinds),
            verification=dict(self.verification),
            depends_on=tuple(self.depends_on),
            parent_task_id=self.parent_task_id,
            requested_by_session=self.requested_by_session,
            max_attempts=max(1, int(self.max_attempts)),
            metadata=metadata,
        )


class Orchestrator:
    """Durable scheduler that reconciles tasks in bounded one-shot ticks."""

    def __init__(
        self,
        data_dir: str | os.PathLike[str],
        *,
        adapters: dict[str, Any] | None = None,
        maintainer: Maintainer | None = None,
        claims: Any | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "sentinel.db"
        self.maintainer = maintainer or Maintainer(self.data_dir)
        self.claims = claims if claims is not None else self._default_claims()
        self.adapters = adapters if adapters is not None else self._default_adapters()
        self.clock = clock or time.time
        self._init_db()

    def _default_claims(self) -> Any | None:
        try:
            from sentinel.workspace import WorkspaceClaims

            return WorkspaceClaims(self.data_dir)
        except (ImportError, AttributeError):
            return None

    def _default_adapters(self) -> dict[str, Any]:
        try:
            from sentinel.adapters import default_adapters

            return default_adapters(self.data_dir / "local-jobs")
        except (ImportError, AttributeError):
            return {}

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
                CREATE TABLE IF NOT EXISTS orchestrator_tasks (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    command_text TEXT NOT NULL,
                    repo TEXT NOT NULL,
                    base_sha TEXT NOT NULL,
                    branch TEXT NOT NULL,
                    path_scopes_json TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    requirements_json TEXT NOT NULL,
                    execution_preference TEXT NOT NULL,
                    allowed_trust_domains_json TEXT NOT NULL,
                    allowed_worker_ids_json TEXT NOT NULL,
                    dispatch_mode TEXT NOT NULL DEFAULT 'WORKER',
                    allowed_agent_kinds_json TEXT NOT NULL DEFAULT '[]',
                    verification_json TEXT NOT NULL,
                    depends_on_json TEXT NOT NULL,
                    parent_task_id TEXT NOT NULL,
                    requested_by_session TEXT NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    attempts INTEGER NOT NULL,
                    selected_worker_id TEXT NOT NULL,
                    selected_session_id TEXT NOT NULL DEFAULT '',
                    active_job_id TEXT NOT NULL,
                    last_error TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                    ,spec_hash TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_orch_tasks_state
                    ON orchestrator_tasks(state, priority, created_at);
                CREATE TABLE IF NOT EXISTS orchestrator_jobs (
                    id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    attempt INTEGER NOT NULL,
                    worker_id TEXT NOT NULL,
                    session_id TEXT NOT NULL DEFAULT '',
                    adapter_name TEXT NOT NULL,
                    reservation_id TEXT NOT NULL,
                    external_job_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    submitted_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL,
                    ended_at REAL,
                    result_json TEXT NOT NULL,
                    error_text TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES orchestrator_tasks(id)
                );
                CREATE INDEX IF NOT EXISTS idx_orch_jobs_active
                    ON orchestrator_jobs(status, heartbeat_at);
                CREATE TABLE IF NOT EXISTS orchestrator_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_orch_events_task
                    ON orchestrator_events(task_id, created_at);
                CREATE TABLE IF NOT EXISTS agent_sessions (
                    id TEXT PRIMARY KEY,
                    agent_kind TEXT NOT NULL,
                    control_adapter TEXT NOT NULL DEFAULT 'pull',
                    bound_worker_id TEXT NOT NULL DEFAULT '',
                    accepts_tasks INTEGER NOT NULL DEFAULT 0,
                    max_inflight INTEGER NOT NULL DEFAULT 1,
                    owner_pid INTEGER NOT NULL,
                    owner_started REAL NOT NULL,
                    repo TEXT NOT NULL,
                    state TEXT NOT NULL,
                    current_task_id TEXT NOT NULL,
                    capabilities_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    heartbeat_at REAL NOT NULL
                    ,expires_at REAL NOT NULL DEFAULT 0
                );
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(orchestrator_tasks)")}
            if "spec_hash" not in columns:
                conn.execute("ALTER TABLE orchestrator_tasks ADD COLUMN spec_hash TEXT NOT NULL DEFAULT ''")
            task_migrations = {
                "dispatch_mode": "TEXT NOT NULL DEFAULT 'WORKER'",
                "allowed_agent_kinds_json": "TEXT NOT NULL DEFAULT '[]'",
                "selected_session_id": "TEXT NOT NULL DEFAULT ''",
            }
            for name, declaration in task_migrations.items():
                if name not in columns:
                    conn.execute(f"ALTER TABLE orchestrator_tasks ADD COLUMN {name} {declaration}")
            job_columns = {row[1] for row in conn.execute("PRAGMA table_info(orchestrator_jobs)")}
            if "session_id" not in job_columns:
                conn.execute("ALTER TABLE orchestrator_jobs ADD COLUMN session_id TEXT NOT NULL DEFAULT ''")
            session_columns = {row[1] for row in conn.execute("PRAGMA table_info(agent_sessions)")}
            session_migrations = {
                "control_adapter": "TEXT NOT NULL DEFAULT 'pull'",
                "bound_worker_id": "TEXT NOT NULL DEFAULT ''",
                "accepts_tasks": "INTEGER NOT NULL DEFAULT 0",
                "max_inflight": "INTEGER NOT NULL DEFAULT 1",
                "expires_at": "REAL NOT NULL DEFAULT 0",
            }
            for name, declaration in session_migrations.items():
                if name not in session_columns:
                    conn.execute(f"ALTER TABLE agent_sessions ADD COLUMN {name} {declaration}")
            # Process-discovered sessions from older versions were
            # optimistically accepting. Require one explicit heartbeat with
            # handshake metadata before any session may pull work.
            conn.execute(
                """UPDATE agent_sessions SET accepts_tasks=0
                   WHERE metadata_json NOT LIKE '%\"handshake\":true%'"""
            )

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

    @classmethod
    def _task_hash(cls, task: TaskSpec) -> str:
        payload = cls._json(asdict(task))
        # Dataclass field order is stable; sort nested maps to make equivalent
        # normalized specifications idempotent as well.
        canonical = json.dumps(json.loads(payload), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _execution_signature(task: dict[str, Any]) -> str:
        """Return a stable, non-reversible profile key for similar executions."""
        metadata = dict(task.get("metadata") or {})
        hint = metadata.get("execution_signature")
        if hint:
            source = f"explicit:{hint}"
        elif metadata.get("argv"):
            source = json.dumps(metadata["argv"], ensure_ascii=False, separators=(",", ":"))
        else:
            source = str(task.get("command_text") or task.get("prompt") or "")
        normalized = re.sub(r"\s+", " ", source.strip().lower())
        normalized = re.sub(r"[a-f0-9]{7,64}", "<sha>", normalized)
        normalized = re.sub(r"\b\d{4,}\b", "<n>", normalized)
        repo = os.path.normcase(os.path.abspath(str(task.get("repo") or "")))
        canonical = f"{repo}\n{normalized}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]

    @staticmethod
    def _decode_task(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        for column, target in (
            ("path_scopes_json", "path_scopes"),
            ("requirements_json", "requirements"),
            ("allowed_trust_domains_json", "allowed_trust_domains"),
            ("allowed_worker_ids_json", "allowed_worker_ids"),
            ("allowed_agent_kinds_json", "allowed_agent_kinds"),
            ("verification_json", "verification"),
            ("depends_on_json", "depends_on"),
            ("result_json", "result"),
            ("metadata_json", "metadata"),
        ):
            item[target] = json.loads(item.pop(column) or "{}")
        return item

    @staticmethod
    def _decode_job(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["result"] = json.loads(item.pop("result_json") or "{}")
        item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
        return item

    def _decode_job_row(self, job_id: str) -> dict[str, Any]:
        with self._db() as conn:
            row = conn.execute("SELECT * FROM orchestrator_jobs WHERE id=?", (job_id,)).fetchone()
        job = self._decode_job(row)
        if job is None:
            raise RuntimeError(f"orchestrator job disappeared: {job_id}")
        return job

    def _event(self, conn: sqlite3.Connection, task_id: str, event_type: str, message: str, data: Any, now: float) -> None:
        conn.execute(
            "INSERT INTO orchestrator_events(task_id,event_type,message,data_json,created_at) VALUES (?,?,?,?,?)",
            (task_id, event_type, message, self._json(data), now),
        )

    def submit_task(self, spec: TaskSpec, *, now: float | None = None) -> dict[str, Any]:
        task = spec.normalized()
        spec_hash = self._task_hash(task)
        now = self.clock() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute("SELECT * FROM orchestrator_tasks WHERE id=?", (task.id,)).fetchone()
            if existing:
                conn.execute("COMMIT")
                if existing["spec_hash"] != spec_hash:
                    raise ValueError(f"task id {task.id!r} conflicts with a different normalized specification")
                return self._decode_task(existing) or {}
            conn.execute(
                """INSERT INTO orchestrator_tasks
                (id,state,prompt,command_text,repo,base_sha,branch,path_scopes_json,priority,
                 requirements_json,execution_preference,allowed_trust_domains_json,
                 allowed_worker_ids_json,dispatch_mode,allowed_agent_kinds_json,
                 verification_json,depends_on_json,parent_task_id,
                 requested_by_session,max_attempts,attempts,selected_worker_id,active_job_id,
                 selected_session_id,last_error,result_json,metadata_json,created_at,updated_at,spec_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    task.id, "QUEUED", task.prompt, task.command, task.repo, task.base_sha, task.branch,
                    self._json(task.path_scopes), task.priority, self._json(task.requirements),
                    task.execution_preference, self._json(task.allowed_trust_domains),
                    self._json(task.allowed_worker_ids), task.dispatch_mode,
                    self._json(task.allowed_agent_kinds), self._json(task.verification),
                    self._json(task.depends_on), task.parent_task_id, task.requested_by_session,
                    task.max_attempts, 0, "", "", "", "", "{}", self._json(task.metadata), now, now,
                    spec_hash,
                ),
            )
            self._event(
                conn, task.id, "TASK_CREATED", "Task queued",
                {"spec_hash": spec_hash, "priority": task.priority, "repo": task.repo}, now,
            )
            conn.execute("COMMIT")
        return self.get_task(task.id) or {}

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        with self._db() as conn:
            return self._decode_task(conn.execute("SELECT * FROM orchestrator_tasks WHERE id=?", (task_id,)).fetchone())

    def list_tasks(self, *, states: tuple[str, ...] = (), limit: int = 100) -> list[dict[str, Any]]:
        with self._db() as conn:
            if states:
                placeholders = ",".join("?" for _ in states)
                rows = conn.execute(
                    f"SELECT * FROM orchestrator_tasks WHERE state IN ({placeholders}) ORDER BY created_at LIMIT ?",
                    (*states, limit),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM orchestrator_tasks ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._decode_task(row) or {} for row in rows]

    def register_session(
        self,
        session_id: str,
        *,
        agent_kind: str,
        owner_pid: int,
        owner_started: float,
        repo: str = "",
        state: str = "IDLE",
        current_task_id: str = "",
        control_adapter: str = "pull",
        bound_worker_id: str = "local-windows",
        accepts_tasks: bool = True,
        max_inflight: int = 1,
        ttl_sec: int = 600,
        capabilities: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        now = self.clock() if now is None else now
        if not session_id:
            raise ValueError("session_id is required")
        if max_inflight < 1 or ttl_sec < 30:
            raise ValueError("max_inflight must be positive and ttl_sec must be at least 30")
        session_metadata = {"handshake": True, **dict(metadata or {})}
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO agent_sessions
                (id,agent_kind,control_adapter,bound_worker_id,accepts_tasks,max_inflight,
                 owner_pid,owner_started,repo,state,current_task_id,capabilities_json,
                 metadata_json,created_at,heartbeat_at,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET agent_kind=excluded.agent_kind,
                  control_adapter=excluded.control_adapter,bound_worker_id=excluded.bound_worker_id,
                  accepts_tasks=excluded.accepts_tasks,max_inflight=excluded.max_inflight,
                  owner_pid=excluded.owner_pid,owner_started=excluded.owner_started,
                  repo=excluded.repo,state=excluded.state,current_task_id=excluded.current_task_id,
                  capabilities_json=excluded.capabilities_json,metadata_json=excluded.metadata_json,
                  heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at""",
                (
                    session_id, agent_kind.lower(), control_adapter, bound_worker_id,
                    int(bool(accepts_tasks)), int(max_inflight), owner_pid, owner_started,
                    repo, state.upper(), current_task_id, self._json(capabilities or {}),
                    self._json(session_metadata), now, now, now + ttl_sec,
                ),
            )
            conn.execute("COMMIT")
        return self.sessions(session_id=session_id)[0]

    def sessions(self, *, session_id: str = "", stale_after_sec: int = 600, now: float | None = None) -> list[dict[str, Any]]:
        now = self.clock() if now is None else now
        with self._db() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_sessions WHERE id=?" if session_id else "SELECT * FROM agent_sessions ORDER BY heartbeat_at DESC",
                (session_id,) if session_id else (),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
            item["metadata"] = json.loads(item.pop("metadata_json") or "{}")
            item["accepts_tasks"] = bool(item["accepts_tasks"])
            item["fresh"] = (
                now - float(item["heartbeat_at"]) <= stale_after_sec
                and (not item["expires_at"] or float(item["expires_at"]) > now)
            )
            result.append(item)
        return result

    def heartbeat_session(
        self, session_id: str, *, state: str | None = None,
        current_task_id: str | None = None, ttl_sec: int = 600,
        now: float | None = None,
    ) -> dict[str, Any]:
        now = self.clock() if now is None else now
        updates = ["heartbeat_at=?", "expires_at=?"]
        values: list[Any] = [now, now + ttl_sec]
        if state is not None:
            updates.append("state=?")
            values.append(state.upper())
        if current_task_id is not None:
            updates.append("current_task_id=?")
            values.append(current_task_id)
        values.append(session_id)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(f"UPDATE agent_sessions SET {','.join(updates)} WHERE id=?", values)
            conn.execute("COMMIT")
        if cur.rowcount == 0:
            return {"heartbeat": False, "reason": "session_missing", "session_id": session_id}
        refreshed = self.sessions(session_id=session_id, now=now)[0]
        with self._db() as conn:
            active_tasks = [row[0] for row in conn.execute(
                "SELECT id FROM orchestrator_tasks WHERE selected_session_id=? AND state='ASSIGNED'",
                (session_id,),
            )]
        for active_task in active_tasks:
            self.maintainer.heartbeat(active_task, now=now)
            self._heartbeat_claim(active_task, now)
        return {"heartbeat": True, "session": refreshed}

    def discover_session(
        self, session_id: str, *, agent_kind: str, owner_pid: int,
        owner_started: float = 0, repo: str = "", bound_worker_id: str = "local-windows",
        capabilities: dict[str, Any] | None = None, ttl_sec: int = 180,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Refresh process-discovered identity without overwriting assignments/policy."""
        now = self.clock() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT metadata_json FROM agent_sessions WHERE id=?", (session_id,)
            ).fetchone()
            explicit_handshake = False
            if existing:
                try:
                    explicit_handshake = bool(json.loads(existing["metadata_json"] or "{}").get("handshake"))
                except (TypeError, ValueError):
                    pass
            conn.execute(
                """INSERT INTO agent_sessions
                (id,agent_kind,control_adapter,bound_worker_id,accepts_tasks,max_inflight,
                 owner_pid,owner_started,repo,state,current_task_id,capabilities_json,
                 metadata_json,created_at,heartbeat_at,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  agent_kind=excluded.agent_kind,bound_worker_id=excluded.bound_worker_id,
                  owner_pid=excluded.owner_pid,owner_started=excluded.owner_started,
                  repo=CASE WHEN excluded.repo<>'' THEN excluded.repo ELSE agent_sessions.repo END,
                  state=CASE WHEN agent_sessions.state IN ('BUSY','CLOSED','DISABLED')
                             THEN agent_sessions.state ELSE 'ONLINE' END,
                  heartbeat_at=excluded.heartbeat_at,expires_at=excluded.expires_at""",
                (
                    session_id, agent_kind.lower(), "pull", bound_worker_id, 0, 1,
                    int(owner_pid), float(owner_started), repo, "ONLINE", "",
                    self._json(capabilities or {"source": "process-tree"}), "{}",
                    now, now, now + max(30, int(ttl_sec)),
                ),
            )
            if not explicit_handshake:
                conn.execute(
                    "UPDATE agent_sessions SET accepts_tasks=0 WHERE id=?", (session_id,)
                )
            conn.execute("COMMIT")
        return self.sessions(session_id=session_id, now=now)[0]

    def discover_sessions(self, sessions: list[dict[str, Any]], *, now: float | None = None) -> list[dict[str, Any]]:
        now = self.clock() if now is None else now
        return [self.discover_session(now=now, **dict(item)) for item in sessions]

    def session_pull(self, session_id: str, *, now: float | None = None) -> dict[str, Any]:
        """Atomically assign one SESSION-mode task to a fresh polling agent."""
        now = self.clock() if now is None else now
        session_rows = self.sessions(session_id=session_id, now=now)
        if not session_rows:
            return {"assigned": False, "reason": "session_missing", "session_id": session_id}
        session = session_rows[0]
        if not session["fresh"]:
            return {"assigned": False, "reason": "session_stale", "session_id": session_id}
        if not session["accepts_tasks"] or session["state"] in {"CLOSED", "DISABLED"}:
            return {"assigned": False, "reason": "session_not_accepting", "session_id": session_id}
        with self._db() as conn:
            active = int(conn.execute(
                """SELECT COUNT(*) FROM orchestrator_tasks
                   WHERE selected_session_id=? AND state='ASSIGNED'""", (session_id,),
            ).fetchone()[0])
        if active >= int(session["max_inflight"]):
            return {"assigned": False, "reason": "session_capacity", "session_id": session_id}

        candidates = self.list_tasks(states=("QUEUED", "WAITING_CAPACITY", "RETRYABLE"), limit=200)
        priority_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        candidates.sort(key=lambda item: (priority_rank.get(item["priority"], 9), item["created_at"]))
        for task in candidates:
            if task["dispatch_mode"] != "SESSION":
                continue
            if task["allowed_agent_kinds"] and session["agent_kind"] not in task["allowed_agent_kinds"]:
                continue
            if task["repo"] and session["repo"] and Path(task["repo"]).resolve() != Path(session["repo"]).resolve():
                continue
            ready, reason = self._dependencies_ready(task)
            if not ready:
                if reason.startswith(("failed_dependency", "missing_dependency")):
                    self._set_task_state(task["id"], "BLOCKED", last_error=reason, message=reason, now=now)
                continue
            worker_id = str(session["bound_worker_id"] or "")
            if not worker_id:
                continue
            if task["allowed_worker_ids"] and worker_id not in task["allowed_worker_ids"]:
                continue
            if not self._acquire_dispatch_lease(task["id"], now=now):
                continue
            try:
                placement_task = self._placement(
                    task, allowed_worker_ids=(worker_id,), automated_only=False
                )
            except (TypeError, ValueError, OverflowError):
                self._set_task_state(task["id"], "BLOCKED", last_error="invalid_requirements",
                    message="Invalid resource estimates; no capacity reserved", now=now)
                continue
            placement = self.maintainer.route_and_reserve(placement_task, now=now)
            if not placement.get("reserved"):
                self._set_task_state(
                    task["id"], "WAITING_CAPACITY", last_error=str(placement.get("reason") or "capacity"),
                    message="Bound session worker has no compatible capacity", data=placement, now=now,
                )
                continue
            worker = self.maintainer.get_worker(worker_id, now=now)
            if not worker:
                self.maintainer.release(task_id=task["id"], outcome="worker_missing", now=now)
                self._set_task_state(
                    task["id"], "RETRYABLE", last_error="worker_missing",
                    message="Bound session worker disappeared", now=now,
                )
                continue
            claimed, claim_reason, workspace = self._claim(task, worker_id, now, owner=session_id)
            if not claimed:
                self.maintainer.release(task_id=task["id"], outcome="claim_conflict", now=now)
                self._set_task_state(
                    task["id"], "QUEUED", last_error=claim_reason,
                    message="Repository scope is already claimed", now=now,
                )
                continue
            try:
                workspace = self._prepare_workspace(task, worker, workspace)
            except Exception as exc:
                error = f"workspace_prepare_failed:{type(exc).__name__}:{exc}"
                self.maintainer.release(task_id=task["id"], outcome="workspace_prepare_failed", now=now)
                self._release_claim(task["id"], "BLOCKED", now)
                self._set_task_state(
                    task["id"], "BLOCKED", last_error=error,
                    message="Safe isolated workspace could not be prepared", now=now,
                )
                return {"assigned": False, "reason": "workspace_prepare_failed", "task_id": task["id"], "error": error}
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                active_now = int(conn.execute(
                    """SELECT COUNT(*) FROM orchestrator_tasks
                       WHERE selected_session_id=? AND state='ASSIGNED'""",
                    (session_id,),
                ).fetchone()[0])
                if active_now < int(session["max_inflight"]):
                    cur = conn.execute(
                        """UPDATE orchestrator_tasks SET state='ASSIGNED',selected_session_id=?,
                           selected_worker_id=?,attempts=attempts+1,updated_at=?,last_error=''
                           WHERE id=? AND state='ROUTING' AND dispatch_mode='SESSION'""",
                        (session_id, worker_id, now, task["id"]),
                    )
                else:
                    cur = None
                if cur is not None and cur.rowcount:
                    conn.execute(
                        "UPDATE agent_sessions SET state='BUSY',current_task_id=?,heartbeat_at=?,expires_at=? WHERE id=?",
                        (task["id"], now, now + 600, session_id),
                    )
                    self._event(
                        conn, task["id"], "STATE_ASSIGNED", f"Assigned to session {session_id}",
                        {
                            "session_id": session_id, "agent_kind": session["agent_kind"],
                            "worker_id": worker_id, "reservation_id": placement.get("reservation_id"),
                            "workspace": workspace,
                        }, now,
                    )
                conn.execute("COMMIT")
            if cur is not None and cur.rowcount:
                return {
                    "assigned": True, "session_id": session_id,
                    "reservation_id": placement.get("reservation_id"),
                    "workspace": workspace, "task": self.get_task(task["id"]),
                }
            self.maintainer.release(task_id=task["id"], outcome="assignment_race", now=now)
            self._release_claim(task["id"], "RETRYABLE", now)
        return {"assigned": False, "reason": "no_matching_task", "session_id": session_id}

    def session_complete(
        self, session_id: str, task_id: str, *, success: bool,
        result: Any = None, error: str = "", now: float | None = None,
    ) -> dict[str, Any]:
        now = self.clock() if now is None else now
        task = self.get_task(task_id)
        if not task or task["state"] != "ASSIGNED" or task["selected_session_id"] != session_id:
            return {"completed": False, "reason": "assignment_missing", "task_id": task_id}
        if success:
            next_state, claim_outcome = "DONE", "DONE"
        else:
            next_state = "RETRYABLE" if task["attempts"] < task["max_attempts"] else "FAILED"
            claim_outcome = "RETRYABLE" if next_state == "RETRYABLE" else "FAILED"
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            values: list[Any] = [
                next_state, now, "" if success else (error or "session_failure"),
                self._json(result) if success else "{}",
                task_id, session_id,
            ]
            cur = conn.execute(
                """UPDATE orchestrator_tasks SET state=?,selected_session_id='',updated_at=?,
                   last_error=?,result_json=?
                   WHERE id=? AND state='ASSIGNED' AND selected_session_id=?""",
                values,
            )
            if not cur.rowcount:
                conn.execute("COMMIT")
                return {"completed": False, "reason": "assignment_raced", "task_id": task_id}
            self._event(
                conn, task_id, f"STATE_{next_state}",
                f"Session {session_id} reported {'success' if success else 'failure'}",
                {}, now,
            )
            remaining_row = conn.execute(
                """SELECT id FROM orchestrator_tasks
                   WHERE selected_session_id=? AND state='ASSIGNED' ORDER BY updated_at LIMIT 1""",
                (session_id,),
            ).fetchone()
            remaining = bool(remaining_row)
            conn.execute(
                "UPDATE agent_sessions SET state=?,current_task_id=?,heartbeat_at=?,expires_at=? WHERE id=?",
                (
                    "BUSY" if remaining else "IDLE",
                    str(remaining_row["id"]) if remaining_row else "",
                    now, now + 600, session_id,
                ),
            )
            conn.execute("COMMIT")
        self._release_claim(task_id, claim_outcome, now)
        self.maintainer.release(
            task_id=task_id, outcome="success" if success else claim_outcome.lower(), now=now
        )
        return {"completed": True, "task_id": task_id, "state": next_state}

    def close_session(self, session_id: str, *, now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            task_ids = [row[0] for row in conn.execute(
                "SELECT id FROM orchestrator_tasks WHERE selected_session_id=? AND state='ASSIGNED'",
                (session_id,),
            )]
            conn.execute(
                """UPDATE orchestrator_tasks SET state='RETRYABLE',selected_session_id='',
                   last_error='session_closed',updated_at=?
                   WHERE selected_session_id=? AND state='ASSIGNED'""",
                (now, session_id),
            )
            cur = conn.execute(
                "UPDATE agent_sessions SET state='CLOSED',accepts_tasks=0,current_task_id='',heartbeat_at=?,expires_at=? WHERE id=?",
                (now, now, session_id),
            )
            conn.execute("COMMIT")
        for task_id in task_ids:
            self.maintainer.release(task_id=task_id, outcome="session_closed", now=now)
            self._release_claim(task_id, "RETRYABLE", now)
        return {"closed": cur.rowcount > 0, "session_id": session_id, "requeued_tasks": task_ids}

    def _set_task_state(
        self,
        task_id: str,
        state: str,
        *,
        message: str = "",
        data: Any = None,
        selected_worker_id: str | None = None,
        selected_session_id: str | None = None,
        active_job_id: str | None = None,
        last_error: str | None = None,
        result: Any | None = None,
        increment_attempts: bool = False,
        now: float | None = None,
    ) -> None:
        state = state.upper()
        if state not in TASK_STATES:
            raise ValueError(f"unknown task state: {state}")
        now = self.clock() if now is None else now
        updates = ["state=?", "updated_at=?"]
        values: list[Any] = [state, now]
        for column, value in (
            ("selected_worker_id", selected_worker_id),
            ("selected_session_id", selected_session_id),
            ("active_job_id", active_job_id),
            ("last_error", last_error),
        ):
            if value is not None:
                updates.append(f"{column}=?")
                values.append(value)
        if result is not None:
            updates.append("result_json=?")
            values.append(self._json(result))
        if increment_attempts:
            updates.append("attempts=attempts+1")
        values.append(task_id)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(f"UPDATE orchestrator_tasks SET {','.join(updates)} WHERE id=?", values)
            self._event(conn, task_id, f"STATE_{state}", message or state, data or {}, now)
            conn.execute("COMMIT")

    def _acquire_dispatch_lease(self, task_id: str, *, now: float) -> bool:
        """CAS a schedulable task into ROUTING so only one tick may dispatch it."""
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """UPDATE orchestrator_tasks SET state='ROUTING',updated_at=?,last_error=''
                   WHERE id=? AND state IN ('QUEUED','WAITING_CAPACITY','RETRYABLE')""",
                (now, task_id),
            )
            if cur.rowcount:
                self._event(
                    conn, task_id, "STATE_ROUTING", "Dispatch lease acquired",
                    {"lease_started_at": now}, now,
                )
            conn.execute("COMMIT")
        return bool(cur.rowcount)

    def _adapter_name(self, worker: dict[str, Any]) -> str:
        locality = self.maintainer.worker_locality(worker)
        if locality == "unknown":
            raise ValueError("local_scope_unknown")
        configured = str((worker.get("capabilities") or {}).get("adapter") or "")
        if configured:
            return configured
        if locality == "local":
            return "local"
        provider = str(worker.get("provider") or "").lower()
        worker_id = str(worker.get("id") or "").lower()
        if provider == "github":
            return "github_actions"
        if provider == "cursor":
            return "cursor"
        if provider == "anthropic":
            return "claude_remote"
        if provider == "openai" and "chatgpt" in worker_id:
            return "chatgpt_work"
        return "manual"

    @staticmethod
    def _placement(
        task: dict[str, Any], *, allowed_worker_ids: tuple[str, ...] | None = None,
        automated_only: bool | None = None,
    ) -> PlacementTask:
        req = task["requirements"]
        commit_bytes, io_slots = _explicit_capacity_estimates(req)
        return PlacementTask(
            id=task["id"],
            ram_gib=float(req.get("ram_gib", 1)),
            cpu_units=float(req.get("cpu_units", 1)),
            disk_gib=float(req.get("disk_gib", 0)),
            commit_bytes=commit_bytes,
            io_slots=io_slots,
            os=str(req.get("os") or "any"),
            docker=bool(req.get("docker")),
            browser=bool(req.get("browser")),
            hardware=bool(req.get("hardware")),
            local_browser_state=bool(req.get("local_browser_state")),
            local_network=bool(req.get("local_network")),
            persistent_environment=bool(req.get("persistent_environment")),
            execution_preference=task["execution_preference"],
            allowed_trust_domains=tuple(task["allowed_trust_domains"]),
            allowed_worker_ids=(
                tuple(task["allowed_worker_ids"])
                if allowed_worker_ids is None else tuple(allowed_worker_ids)
            ),
            automated_only=(
                not bool(task["metadata"].get("allow_manual_worker", False))
                if automated_only is None else bool(automated_only)
            ),
            metadata={"priority": task["priority"], "repo": task["repo"]},
        ).normalized()

    @staticmethod
    def _adapter_payload(task: dict[str, Any], job_id: str) -> dict[str, Any]:
        metadata = dict(task["metadata"])
        payload = {
            "task_id": task["id"],
            "job_id": job_id,
            "prompt": task["prompt"],
            "command": task["command_text"],
            "repo": task["repo"],
            "base_sha": task["base_sha"],
            "branch": task["branch"],
            "path_scopes": task["path_scopes"],
            "requirements": task["requirements"],
            "metadata": task["metadata"],
        }
        # Execution controls are explicit top-level adapter inputs.  Secrets
        # remain references to environment-variable names, never values.
        for name in (
            "argv", "shell", "cwd", "timeout_seconds", "env_refs", "inherit_all_env",
        ):
            if name in metadata:
                payload[name] = metadata[name]
        return payload

    def _prepare_workspace(
        self, task: dict[str, Any], worker: dict[str, Any], plan: dict[str, Any]
    ) -> dict[str, Any]:
        locality = self.maintainer.worker_locality(worker)
        if locality == "unknown":
            raise ValueError("local_scope_unknown")
        if not plan:
            return {}
        if locality == "remote":
            # Remote adapters receive the immutable base/branch/path contract
            # and are responsible for provider-side checkout isolation.
            return {**plan, "mode": "provider-managed", "ready": False}
        mode = str(task["metadata"].get("workspace_mode") or "worktree").lower()
        if mode == "claim-only":
            return {**plan, "mode": "claim-only", "ready": True}
        if mode != "worktree":
            raise ValueError(f"unknown workspace_mode: {mode}")
        from sentinel.workspace import materialize_worktree

        materialized = materialize_worktree(plan)
        return {**plan, **materialized, "mode": "worktree", "ready": True}

    def _dependencies_ready(self, task: dict[str, Any]) -> tuple[bool, str]:
        for dependency in task["depends_on"]:
            parent = self.get_task(dependency)
            if not parent:
                return False, f"missing_dependency:{dependency}"
            if parent["state"] in {"FAILED", "CANCELLED", "BLOCKED"}:
                return False, f"failed_dependency:{dependency}"
            if parent["state"] != "DONE":
                return False, "dependency_pending"
        return True, "ready"

    def _claim(
        self, task: dict[str, Any], worker_id: str, now: float, *, owner: str | None = None
    ) -> tuple[bool, str, dict[str, Any]]:
        if self.claims is None or not task["repo"] or not task["path_scopes"]:
            return True, "no_claim_required", {}
        try:
            result = self.claims.claim(
                task_id=task["id"], repo=task["repo"], base_sha=task["base_sha"],
                paths=task["path_scopes"],
                owner=owner or task["requested_by_session"] or "orchestrator",
                worker_id=worker_id, ttl_sec=7200, now=now,
            )
            allowed = bool(result.get("allowed", result.get("claimed", False)))
            return allowed, str(result.get("reason") or "claimed"), dict(result.get("plan") or {})
        except (TypeError, ValueError, OSError) as exc:
            return False, f"claim_error:{type(exc).__name__}", {}

    def _release_claim(self, task_id: str, outcome: str, now: float) -> None:
        if self.claims is None:
            return
        try:
            self.claims.release(task_id=task_id, outcome=outcome, now=now)
        except (TypeError, ValueError):
            pass

    def _heartbeat_claim(self, task_id: str, now: float) -> None:
        if self.claims is None:
            return
        try:
            self.claims.heartbeat(task_id, ttl_sec=7200, now=now)
        except (TypeError, ValueError):
            pass

    def dispatch_one(self, task_id: str, *, now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        task = self.get_task(task_id)
        if not task:
            return {"dispatched": False, "reason": "task_missing", "task_id": task_id}
        if task["state"] not in {"QUEUED", "WAITING_CAPACITY", "RETRYABLE"}:
            return {"dispatched": False, "reason": f"state_{task['state'].lower()}", "task_id": task_id}
        if task["dispatch_mode"] != "WORKER":
            return {"dispatched": False, "reason": "session_pull_required", "task_id": task_id}
        ready, reason = self._dependencies_ready(task)
        if not ready:
            if reason.startswith("failed_dependency") or reason.startswith("missing_dependency"):
                self._set_task_state(task_id, "BLOCKED", message=reason, last_error=reason, now=now)
            return {"dispatched": False, "reason": reason, "task_id": task_id}

        if not self._acquire_dispatch_lease(task_id, now=now):
            return {"dispatched": False, "reason": "dispatch_raced", "task_id": task_id}
        try:
            placement_task = self._placement(task)
        except (TypeError, ValueError, OverflowError):
            self._set_task_state(task_id, "BLOCKED", last_error="invalid_requirements",
                message="Invalid resource estimates; no capacity reserved", now=now)
            return {"dispatched": False, "reason": "invalid_requirements", "task_id": task_id}
        placement = self.maintainer.route_and_reserve(placement_task, now=now)
        if not placement.get("reserved"):
            self._set_task_state(
                task_id, "WAITING_CAPACITY", message="No worker currently fits",
                data=placement, last_error=str(placement.get("reason") or "capacity"), now=now,
            )
            return {"dispatched": False, "reason": "waiting_capacity", "placement": placement, "task_id": task_id}

        worker_id = str(placement["worker_id"])
        worker = self.maintainer.get_worker(worker_id, now=now)
        if not worker:
            self.maintainer.release(task_id=task_id, outcome="worker_missing", now=now)
            self._set_task_state(task_id, "RETRYABLE", message="Selected worker disappeared", last_error="worker_missing", now=now)
            return {"dispatched": False, "reason": "worker_missing", "task_id": task_id}

        claimed, claim_reason, workspace = self._claim(task, worker_id, now)
        if not claimed:
            self.maintainer.release(task_id=task_id, outcome="claim_conflict", now=now)
            self._set_task_state(task_id, "QUEUED", message="Repository scope is already claimed", last_error=claim_reason, now=now)
            return {"dispatched": False, "reason": "claim_conflict", "task_id": task_id}
        try:
            workspace = self._prepare_workspace(task, worker, workspace)
        except Exception as exc:
            error = f"workspace_prepare_failed:{type(exc).__name__}:{exc}"
            self.maintainer.release(task_id=task_id, outcome="workspace_prepare_failed", now=now)
            self._release_claim(task_id, "BLOCKED", now)
            self._set_task_state(
                task_id, "BLOCKED", last_error=error,
                message="Safe isolated workspace could not be prepared", now=now,
            )
            return {
                "dispatched": False, "reason": "workspace_prepare_failed",
                "task_id": task_id, "error": error,
            }

        adapter_name = self._adapter_name(worker)
        adapter = self.adapters.get(adapter_name)
        job_id = uuid.uuid4().hex
        execution_signature = self._execution_signature(task)
        if adapter is None:
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO orchestrator_jobs
                    (id,task_id,attempt,worker_id,adapter_name,reservation_id,external_job_id,status,
                     submitted_at,heartbeat_at,ended_at,result_json,error_text,metadata_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        job_id, task_id, task["attempts"] + 1, worker_id, adapter_name,
                        str(placement["reservation_id"]), "", "AWAITING_MANUAL", now, now, None,
                        "{}", "adapter_not_configured", self._json({
                            "worker": worker, "execution_signature": execution_signature,
                            "workspace": workspace,
                        }),
                    ),
                )
                conn.execute("COMMIT")
            self.maintainer.release(task_id=task_id, outcome="awaiting_manual", now=now)
            self._set_task_state(
                task_id, "AWAITING_MANUAL", selected_worker_id=worker_id, active_job_id=job_id,
                increment_attempts=True, message=f"Manual dispatch required for {worker_id}",
                data={"adapter": adapter_name}, now=now,
            )
            return {"dispatched": False, "manual": True, "worker_id": worker_id, "task_id": task_id, "job_id": job_id}

        payload = self._adapter_payload(task, job_id)
        if workspace:
            payload["workspace"] = workspace
            if workspace.get("mode") == "worktree":
                payload["cwd"] = workspace["worktree_path"]
        attempt = task["attempts"] + 1
        # Persist the attempt and dispatch key before crossing the adapter
        # boundary.  A crash can therefore be reconciled without silently
        # creating another attempt with the same task id.
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """INSERT INTO orchestrator_jobs
                (id,task_id,attempt,worker_id,session_id,adapter_name,reservation_id,external_job_id,status,
                 submitted_at,heartbeat_at,ended_at,result_json,error_text,metadata_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    job_id, task_id, attempt, worker_id, task["requested_by_session"], adapter_name,
                    str(placement["reservation_id"]), "", "SUBMITTING", now, now, None,
                    "{}", "", self._json({
                        "dispatch_key": job_id,
                        "execution_signature": execution_signature,
                        "workspace": workspace,
                    }),
                ),
            )
            conn.execute("COMMIT")
        self._set_task_state(
            task_id, "RESERVED", selected_worker_id=worker_id, active_job_id=job_id,
            increment_attempts=True, message=f"Reserved {worker_id}; dispatch starting",
            data={"adapter": adapter_name, "dispatch_key": job_id}, now=now,
        )
        try:
            submitted = adapter.submit(payload, worker)
            external_job_id = str(submitted.get("job_id") or submitted.get("external_job_id") or job_id)
            job_status = str(submitted.get("status") or "SUBMITTED").upper()
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            with self._db() as conn:
                conn.execute(
                    "UPDATE orchestrator_jobs SET status='FAILED',ended_at=?,heartbeat_at=?,error_text=? WHERE id=?",
                    (now, now, error, job_id),
                )
            self.maintainer.release(task_id=task_id, outcome="submit_failed", now=now)
            self._release_claim(task_id, "RETRYABLE", now)
            next_state = "RETRYABLE" if attempt < task["max_attempts"] else "FAILED"
            self._set_task_state(
                task_id, next_state, active_job_id="", last_error=error,
                message="Adapter submission failed", data={"adapter": adapter_name, "error": error}, now=now,
            )
            return {"dispatched": False, "reason": "submit_failed", "error": error, "task_id": task_id}

        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE orchestrator_jobs SET external_job_id=?,status=?,heartbeat_at=?,
                   metadata_json=? WHERE id=?""",
                (external_job_id, job_status, now, self._json({
                    "dispatch_key": job_id, "execution_signature": execution_signature,
                    "workspace": workspace, "submit": submitted,
                }), job_id),
            )
            conn.execute("COMMIT")

        if job_status == "AWAITING_MANUAL":
            self.maintainer.release(task_id=task_id, outcome="awaiting_manual", now=now)
            self._release_claim(task_id, "RETRYABLE", now)
            self._set_task_state(
                task_id, "AWAITING_MANUAL", message=str(submitted.get("message") or "Manual dispatch required"),
                data={"adapter": adapter_name, "external_job_id": external_job_id}, now=now,
            )
            return {
                "dispatched": False, "manual": True, "task_id": task_id, "job_id": job_id,
                "external_job_id": external_job_id, "worker_id": worker_id, "adapter": adapter_name,
            }

        current_task = self.get_task(task_id) or task
        current_job = self._decode_job_row(job_id)
        if job_status in SUCCESS_JOB_STATES:
            try:
                result = adapter.collect_result(external_job_id)
            except Exception as exc:
                error = f"result_collection_pending:{type(exc).__name__}:{exc}"
                with self._db() as conn:
                    conn.execute(
                        "UPDATE orchestrator_jobs SET status='RUNNING',heartbeat_at=?,error_text=? WHERE id=?",
                        (now, error, job_id),
                    )
                self.maintainer.heartbeat(task_id, now=now)
                self._heartbeat_claim(task_id, now)
                self._set_task_state(
                    task_id, "RUNNING", last_error=error,
                    message="Provider finished; result collection will be retried", now=now,
                )
            else:
                self._finish_success(current_task, current_job, result, now)
        elif job_status in FAILURE_JOB_STATES | CANCEL_JOB_STATES:
            self._finish_failure(
                current_task, current_job, "CANCELLED" if job_status in CANCEL_JOB_STATES else "FAILED",
                str(submitted.get("error") or submitted.get("message") or job_status), now,
            )
        else:
            task_state = "RUNNING" if job_status in {"RUNNING", "QUEUED", "SUBMITTED"} else "SUBMITTED"
            self._set_task_state(
                task_id, task_state, message=f"Submitted to {worker_id}",
                data={"adapter": adapter_name, "external_job_id": external_job_id}, now=now,
            )
        return {
            "dispatched": True, "task_id": task_id, "job_id": job_id,
            "external_job_id": external_job_id, "worker_id": worker_id, "adapter": adapter_name,
        }

    def _finish_success(self, task: dict[str, Any], job: dict[str, Any], result: Any, now: float) -> None:
        job_workspace = dict((job.get("metadata") or {}).get("workspace") or {})
        if job_workspace:
            if isinstance(result, dict):
                result = {**result, "workspace": job_workspace}
            else:
                result = {"value": result, "workspace": job_workspace}
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE orchestrator_jobs SET status='SUCCEEDED',heartbeat_at=?,ended_at=?,result_json=? WHERE id=?",
                (now, now, self._json(result), job["id"]),
            )
            conn.execute("COMMIT")
        self.maintainer.release(task_id=task["id"], outcome="success", now=now)
        self._release_claim(task["id"], "DONE", now)
        verification = task["verification"]
        if verification and not task["parent_task_id"]:
            verify_id = str(verification.get("task_id") or f"{task['id']}:verify")
            verify_command = str(verification.get("command") or "")
            verify_metadata: dict[str, Any] = {
                "parent_result": result, "verification": True,
            }
            for name in (
                "argv", "shell", "cwd", "timeout_seconds", "env_refs", "inherit_all_env",
            ):
                if name in verification:
                    verify_metadata[name] = verification[name]
            parent_worktree = str(job_workspace.get("worktree_path") or "")
            if parent_worktree and job_workspace.get("mode") == "worktree":
                verify_metadata.setdefault("cwd", parent_worktree)
                verify_metadata["workspace_mode"] = "claim-only"
            elif verify_command and "argv" not in verify_metadata:
                # A string verification command is an explicit shell request
                # from the task author, not an implicit adapter fallback.
                verify_metadata.setdefault("shell", True)
            verify_spec = TaskSpec(
                id=verify_id,
                prompt=str(verification.get("prompt") or "Verify the parent task result on the local target environment."),
                command=verify_command,
                repo=task["repo"], base_sha=task["base_sha"], branch=task["branch"],
                path_scopes=tuple(task["path_scopes"]), priority="P1",
                requirements={**task["requirements"], **dict(verification.get("requirements") or {}), "os": "windows"},
                execution_preference="LOCAL_REQUIRED",
                allowed_trust_domains=tuple(verification.get("allowed_trust_domains") or ("local-private",)),
                parent_task_id=task["id"], requested_by_session=task["requested_by_session"],
                max_attempts=int(verification.get("max_attempts") or 2),
                metadata=verify_metadata,
            )
            self.submit_task(verify_spec, now=now)
            self._set_task_state(
                task["id"], "VERIFYING", active_job_id="", result=result,
                message=f"Cloud phase done; local verification queued as {verify_id}", now=now,
            )
        else:
            self._set_task_state(task["id"], "DONE", active_job_id="", result=result, message="Task completed", now=now)
            if task["parent_task_id"]:
                self._set_task_state(
                    task["parent_task_id"], "DONE", active_job_id="",
                    result={"verification_task": task["id"], "verification_result": result},
                    message="Local verification completed", now=now,
                )

    def _finish_failure(self, task: dict[str, Any], job: dict[str, Any], status: str, error: str, now: float) -> None:
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE orchestrator_jobs SET status=?,heartbeat_at=?,ended_at=?,error_text=? WHERE id=?",
                (status, now, now, error, job["id"]),
            )
            conn.execute("COMMIT")
        self.maintainer.release(task_id=task["id"], outcome=status.lower(), now=now)
        self._release_claim(task["id"], "RETRYABLE", now)
        next_state = "RETRYABLE" if task["attempts"] < task["max_attempts"] else "FAILED"
        self._set_task_state(task["id"], next_state, active_job_id="", last_error=error, message=f"Job {status}", now=now)
        if next_state == "FAILED" and task["parent_task_id"]:
            self._set_task_state(
                task["parent_task_id"], "FAILED", last_error=f"verification_failed:{task['id']}",
                message="Local verification failed", now=now,
            )

    def reconcile_stale_routing(
        self, *, now: float | None = None, stale_after_sec: int = 120
    ) -> list[dict[str, Any]]:
        """Recover a crash between the ROUTING CAS and durable job creation."""
        now = self.clock() if now is None else now
        recovered: list[dict[str, Any]] = []
        with self._db() as conn:
            rows = conn.execute(
                """SELECT id FROM orchestrator_tasks
                   WHERE state='ROUTING' AND updated_at<=? ORDER BY updated_at""",
                (now - max(1, int(stale_after_sec)),),
            ).fetchall()
        for row in rows:
            task_id = str(row["id"])
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                job = conn.execute(
                    """SELECT 1 FROM orchestrator_jobs
                       WHERE task_id=? AND status IN ('SUBMITTING','SUBMITTED','QUEUED','RUNNING')
                       LIMIT 1""",
                    (task_id,),
                ).fetchone()
                if job:
                    conn.execute("COMMIT")
                    continue
                cur = conn.execute(
                    """UPDATE orchestrator_tasks SET state='RETRYABLE',updated_at=?,
                       last_error='stale_routing_lease'
                       WHERE id=? AND state='ROUTING' AND updated_at<=?""",
                    (now, task_id, now - max(1, int(stale_after_sec))),
                )
                if cur.rowcount:
                    self._event(
                        conn, task_id, "STATE_RETRYABLE",
                        "Recovered stale routing lease after scheduler interruption", {}, now,
                    )
                conn.execute("COMMIT")
            if cur.rowcount:
                self.maintainer.release(task_id=task_id, outcome="stale_routing", now=now)
                self._release_claim(task_id, "RETRYABLE", now)
                recovered.append({"task_id": task_id, "status": "RETRYABLE"})
        return recovered

    def reconcile_sessions(self, *, now: float | None = None) -> list[dict[str, Any]]:
        """Requeue assignments whose controlling session lease has expired."""
        now = self.clock() if now is None else now
        with self._db() as conn:
            rows = conn.execute(
                """SELECT t.id,t.attempts,t.max_attempts,t.selected_session_id
                   FROM orchestrator_tasks t
                   LEFT JOIN agent_sessions s ON s.id=t.selected_session_id
                   WHERE t.state='ASSIGNED' AND (
                     s.id IS NULL OR s.expires_at<=? OR s.state IN ('CLOSED','DISABLED')
                   )""",
                (now,),
            ).fetchall()
        updates: list[dict[str, Any]] = []
        for row in rows:
            task_id = str(row["id"])
            next_state = "RETRYABLE" if int(row["attempts"]) < int(row["max_attempts"]) else "FAILED"
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    """UPDATE orchestrator_tasks SET state=?,selected_session_id='',updated_at=?,
                       last_error='session_lease_expired'
                       WHERE id=? AND state='ASSIGNED' AND selected_session_id=?""",
                    (next_state, now, task_id, row["selected_session_id"]),
                )
                if cur.rowcount:
                    self._event(
                        conn, task_id, f"STATE_{next_state}",
                        "Controlling agent session expired", {"session_id": row["selected_session_id"]}, now,
                    )
                    conn.execute(
                        """UPDATE agent_sessions SET state='STALE',current_task_id=''
                           WHERE id=? AND expires_at<=?""",
                        (row["selected_session_id"], now),
                    )
                conn.execute("COMMIT")
            if cur.rowcount:
                outcome = "RETRYABLE" if next_state == "RETRYABLE" else "FAILED"
                self.maintainer.release(task_id=task_id, outcome="session_expired", now=now)
                self._release_claim(task_id, outcome, now)
                updates.append({"task_id": task_id, "status": next_state, "reason": "session_lease_expired"})
        return updates

    def reconcile(self, *, now: float | None = None) -> list[dict[str, Any]]:
        now = self.clock() if now is None else now
        with self._db() as conn:
            rows = conn.execute(
                "SELECT * FROM orchestrator_jobs WHERE status IN ('SUBMITTING','SUBMITTED','QUEUED','RUNNING') ORDER BY submitted_at"
            ).fetchall()
        updates: list[dict[str, Any]] = []
        for row in rows:
            job = self._decode_job(row) or {}
            task = self.get_task(job["task_id"])
            if not task or task["state"] in TERMINAL_TASK_STATES:
                continue
            adapter = self.adapters.get(job["adapter_name"])
            if job["status"] == "SUBMITTING" and not job["external_job_id"]:
                age = now - float(job["heartbeat_at"])
                dispatch_key = str(job["metadata"].get("dispatch_key") or "")
                recovered = False
                if adapter is not None and dispatch_key:
                    try:
                        capabilities = adapter.capabilities()
                    except Exception:
                        capabilities = {}
                    if capabilities.get("dispatch_key_is_job_id"):
                        try:
                            recovered_status = adapter.status(dispatch_key)
                        except Exception:
                            pass
                        else:
                            recovered_state = str(recovered_status.get("status") or "RUNNING").upper()
                            with self._db() as conn:
                                conn.execute(
                                    """UPDATE orchestrator_jobs SET external_job_id=?,status=?,
                                       heartbeat_at=?,error_text='' WHERE id=?""",
                                    (dispatch_key, recovered_state, now, job["id"]),
                                )
                            job["external_job_id"] = dispatch_key
                            job["status"] = recovered_state
                            recovered = True
                if not recovered and age >= 120:
                    self._set_task_state(
                        task["id"], "BLOCKED", last_error="dispatch_outcome_unknown",
                        message="Dispatch was interrupted before an external id was persisted; operator reconciliation required",
                        data={"job_id": job["id"], "dispatch_key": job["metadata"].get("dispatch_key")}, now=now,
                    )
                    updates.append({"task_id": task["id"], "status": "BLOCKED", "reason": "dispatch_outcome_unknown"})
                if not recovered:
                    continue
            if adapter is None:
                continue
            try:
                polled = adapter.status(job["external_job_id"])
                status = str(polled.get("status") or "RUNNING").upper()
            except Exception as exc:
                self.maintainer.heartbeat(task["id"], now=now)
                self._heartbeat_claim(task["id"], now)
                updates.append({"task_id": task["id"], "status": "POLL_ERROR", "error": str(exc)})
                continue
            if status in ACTIVE_JOB_STATES:
                self.maintainer.heartbeat(task["id"], now=now)
                self._heartbeat_claim(task["id"], now)
                with self._db() as conn:
                    conn.execute("UPDATE orchestrator_jobs SET status=?,heartbeat_at=? WHERE id=?", (status, now, job["id"]))
                if task["state"] != "RUNNING":
                    self._set_task_state(task["id"], "RUNNING", message="Worker reports running", now=now)
                updates.append({"task_id": task["id"], "status": status})
            elif status in SUCCESS_JOB_STATES:
                try:
                    result = adapter.collect_result(job["external_job_id"])
                except Exception as exc:
                    error = f"result_collection_pending:{type(exc).__name__}:{exc}"
                    with self._db() as conn:
                        conn.execute(
                            "UPDATE orchestrator_jobs SET status='RUNNING',heartbeat_at=?,error_text=? WHERE id=?",
                            (now, error, job["id"]),
                        )
                    self.maintainer.heartbeat(task["id"], now=now)
                    self._heartbeat_claim(task["id"], now)
                    if task["state"] != "RUNNING":
                        self._set_task_state(
                            task["id"], "RUNNING", last_error=error,
                            message="Provider finished; result collection will be retried", now=now,
                        )
                    updates.append({"task_id": task["id"], "status": "COLLECT_ERROR", "error": error})
                    continue
                self._finish_success(task, job, result, now)
                updates.append({"task_id": task["id"], "status": "SUCCEEDED", "result": result})
            elif status in FAILURE_JOB_STATES:
                error = str(polled.get("error") or polled.get("message") or status)
                self._finish_failure(task, job, "FAILED", error, now)
                updates.append({"task_id": task["id"], "status": "FAILED", "error": error})
            elif status in CANCEL_JOB_STATES:
                self._finish_failure(task, job, "CANCELLED", "cancelled", now)
                updates.append({"task_id": task["id"], "status": "CANCELLED"})
        return updates

    def tick(self, *, limit: int = 4, now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        recovered_routing = self.reconcile_stale_routing(now=now)
        recovered_sessions = self.reconcile_sessions(now=now)
        reconciled = self.reconcile(now=now)
        candidates = self.list_tasks(states=("QUEUED", "WAITING_CAPACITY", "RETRYABLE"), limit=max(limit * 4, limit))
        priority_rank = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        candidates.sort(key=lambda task: (priority_rank.get(task["priority"], 9), task["created_at"]))
        dispatched = []
        for task in candidates:
            if len(dispatched) >= limit:
                break
            if task["dispatch_mode"] != "WORKER":
                continue
            result = self.dispatch_one(task["id"], now=now)
            if result.get("dispatched") or result.get("manual"):
                dispatched.append(result)
        return {
            "recovered_routing": recovered_routing,
            "recovered_sessions": recovered_sessions,
            "reconciled": reconciled, "dispatched": dispatched,
            "task_counts": self.task_counts(),
        }

    def task_counts(self) -> dict[str, int]:
        with self._db() as conn:
            return {row["state"]: int(row["n"]) for row in conn.execute("SELECT state,COUNT(*) n FROM orchestrator_tasks GROUP BY state")}

    def resource_profiles(self, *, limit: int = 2000) -> dict[str, Any]:
        """Aggregate durable process-tree measurements into reusable profiles.

        Profiles are observational only: routing still honors explicit task
        requirements.  Operators can use P90/P95 values to tune those requests
        without trusting a single peak or an unmeasured provider claim.
        """
        with self._db() as conn:
            rows = conn.execute(
                """SELECT worker_id,adapter_name,result_json,metadata_json
                   FROM orchestrator_jobs
                   WHERE status='SUCCEEDED' AND result_json NOT IN ('','{}')
                   ORDER BY ended_at DESC LIMIT ?""",
                (max(1, int(limit)),),
            ).fetchall()
        metric_names = (
            "duration_seconds", "peak_working_set_gib", "peak_private_gib",
            "cpu_seconds", "average_cpu_equivalent", "peak_cpu_equivalent",
            "disk_read_bytes", "disk_write_bytes",
        )
        groups: dict[tuple[str, str, str], dict[str, list[float]]] = {}
        for row in rows:
            try:
                result = json.loads(row["result_json"] or "{}")
                metadata = json.loads(row["metadata_json"] or "{}")
            except (TypeError, ValueError):
                continue
            signature = str(metadata.get("execution_signature") or "")
            if not signature or not isinstance(result, dict) or result.get("metrics_available") is not True:
                continue
            key = (signature, str(row["worker_id"]), str(row["adapter_name"]))
            bucket = groups.setdefault(key, {name: [] for name in metric_names})
            for name in metric_names:
                value = result.get(name)
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    bucket[name].append(float(value))

        def percentile(values: list[float], fraction: float) -> float | None:
            if not values:
                return None
            ordered = sorted(values)
            position = (len(ordered) - 1) * fraction
            lower = int(position)
            upper = min(lower + 1, len(ordered) - 1)
            weight = position - lower
            return ordered[lower] * (1.0 - weight) + ordered[upper] * weight

        profiles = []
        for (signature, worker_id, adapter_name), values in sorted(groups.items()):
            sample_count = max((len(items) for items in values.values()), default=0)
            profiles.append({
                "execution_signature": signature,
                "worker_id": worker_id,
                "adapter_name": adapter_name,
                "samples": sample_count,
                "metrics": {
                    name: {
                        "p50": percentile(items, 0.50),
                        "p90": percentile(items, 0.90),
                        "p95": percentile(items, 0.95),
                    }
                    for name, items in values.items() if items
                },
            })
        return {"generated_at": self.clock(), "profiles": profiles}

    def retry(self, task_id: str, *, now: float | None = None) -> dict[str, Any]:
        """Explicitly reopen a failed/blocked task for one additional attempt."""
        now = self.clock() if now is None else now
        task = self.get_task(task_id)
        if not task:
            return {"retried": False, "reason": "task_missing", "task_id": task_id}
        if task["last_error"] == "dispatch_outcome_unknown":
            return {
                "retried": False, "reason": "dispatch_resolution_required", "task_id": task_id,
                "message": "Attach the provider job id or explicitly confirm that submission did not occur.",
            }
        if task["state"] not in {"FAILED", "BLOCKED", "CANCELLED", "RETRYABLE", "AWAITING_MANUAL"}:
            return {"retried": False, "reason": f"state_{task['state'].lower()}", "task_id": task_id}
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE orchestrator_tasks SET state='QUEUED',active_job_id='',
                   selected_worker_id='',selected_session_id='',last_error='',
                   max_attempts=CASE WHEN max_attempts<=attempts THEN attempts+1 ELSE max_attempts END,
                   updated_at=? WHERE id=?""",
                (now, task_id),
            )
            self._event(conn, task_id, "STATE_QUEUED", "Task explicitly retried", {}, now)
            conn.execute("COMMIT")
        return {"retried": True, "task": self.get_task(task_id)}

    def resolve_dispatch(
        self, task_id: str, *, external_job_id: str = "",
        confirmed_not_submitted: bool = False, now: float | None = None,
    ) -> dict[str, Any]:
        """Resolve a crash at the non-atomic provider submission boundary."""
        now = self.clock() if now is None else now
        if bool(external_job_id) == bool(confirmed_not_submitted):
            raise ValueError("provide exactly one of external_job_id or confirmed_not_submitted")
        task = self.get_task(task_id)
        if not task or task["state"] != "BLOCKED" or task["last_error"] != "dispatch_outcome_unknown":
            return {"resolved": False, "reason": "dispatch_resolution_not_required", "task_id": task_id}
        with self._db() as conn:
            job_row = conn.execute(
                """SELECT * FROM orchestrator_jobs WHERE task_id=? AND status='SUBMITTING'
                   ORDER BY submitted_at DESC LIMIT 1""",
                (task_id,),
            ).fetchone()
        job = self._decode_job(job_row)
        if not job:
            return {"resolved": False, "reason": "submitting_job_missing", "task_id": task_id}
        if confirmed_not_submitted:
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """UPDATE orchestrator_jobs SET status='FAILED',heartbeat_at=?,ended_at=?,
                       error_text='operator_confirmed_not_submitted' WHERE id=?""",
                    (now, now, job["id"]),
                )
                conn.execute("COMMIT")
            self.maintainer.release(task_id=task_id, outcome="confirmed_not_submitted", now=now)
            self._release_claim(task_id, "RETRYABLE", now)
            self._set_task_state(
                task_id, "RETRYABLE", active_job_id="", last_error="",
                message="Operator confirmed provider submission did not occur", now=now,
            )
            return {"resolved": True, "resolution": "not_submitted", "task": self.get_task(task_id)}

        # Attaching a remote id is safe only while the original capacity lease
        # is still present; otherwise accounting can no longer represent the
        # already-running provider job truthfully.
        if not self.maintainer.heartbeat(task_id, now=now):
            return {"resolved": False, "reason": "capacity_lease_missing", "task_id": task_id}
        self._heartbeat_claim(task_id, now)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """UPDATE orchestrator_jobs SET external_job_id=?,status='SUBMITTED',
                   heartbeat_at=?,error_text='' WHERE id=?""",
                (external_job_id, now, job["id"]),
            )
            conn.execute("COMMIT")
        self._set_task_state(
            task_id, "RUNNING", last_error="",
            message="Operator attached the provider job id after interrupted dispatch",
            data={"external_job_id": external_job_id}, now=now,
        )
        return {"resolved": True, "resolution": "attached", "task": self.get_task(task_id)}

    def cancel(self, task_id: str, *, now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        task = self.get_task(task_id)
        if not task:
            return {"cancelled": False, "reason": "task_missing"}
        if task["state"] == "ASSIGNED" and task["selected_session_id"]:
            session_id = task["selected_session_id"]
            self._release_claim(task_id, "CANCELLED", now)
            with self._db() as conn:
                conn.execute(
                    "UPDATE agent_sessions SET state='IDLE',current_task_id='',heartbeat_at=? WHERE id=? AND current_task_id=?",
                    (now, session_id, task_id),
                )
        job = None
        if task["active_job_id"]:
            with self._db() as conn:
                job = self._decode_job(conn.execute("SELECT * FROM orchestrator_jobs WHERE id=?", (task["active_job_id"],)).fetchone())
        if job and job["status"] in ACTIVE_JOB_STATES:
            adapter = self.adapters.get(job["adapter_name"])
            if adapter:
                try:
                    adapter.cancel(job["external_job_id"])
                except Exception:
                    pass
            with self._db() as conn:
                conn.execute("UPDATE orchestrator_jobs SET status='CANCELLED',ended_at=?,heartbeat_at=? WHERE id=?", (now, now, job["id"]))
        self.maintainer.release(task_id=task_id, outcome="cancelled", now=now)
        self._release_claim(task_id, "CANCELLED", now)
        self._set_task_state(task_id, "CANCELLED", active_job_id="", message="Task cancelled", now=now)
        return {"cancelled": True, "task_id": task_id}

    def complete_manual(self, task_id: str, *, success: bool, result: Any = None, error: str = "", now: float | None = None) -> dict[str, Any]:
        now = self.clock() if now is None else now
        task = self.get_task(task_id)
        if not task or task["state"] != "AWAITING_MANUAL":
            return {"completed": False, "reason": "not_awaiting_manual"}
        if success:
            fake_job = {"id": task["active_job_id"]}
            self._finish_success(task, fake_job, result or {}, now)
        else:
            fake_job = {"id": task["active_job_id"]}
            self._finish_failure(task, fake_job, "FAILED", error or "manual_failure", now)
        return {"completed": True, "task_id": task_id, "success": success}

    def snapshot(self, *, task_limit: int = 100) -> dict[str, Any]:
        with self._db() as conn:
            jobs = [self._decode_job(row) for row in conn.execute("SELECT * FROM orchestrator_jobs ORDER BY submitted_at DESC LIMIT ?", (task_limit,))]
            events = [dict(row) for row in conn.execute("SELECT * FROM orchestrator_events ORDER BY created_at DESC LIMIT ?", (task_limit,))]
        return {
            "task_counts": self.task_counts(),
            "tasks": self.list_tasks(limit=task_limit),
            "jobs": jobs,
            "sessions": self.sessions(),
            "events": events,
            "resource_profiles": self.resource_profiles(),
            "workers": self.maintainer.snapshot(),
        }
