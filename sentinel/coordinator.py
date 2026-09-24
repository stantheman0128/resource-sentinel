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
import threading
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
from sentinel.adaptive.store import (
    allocation_is_bound, check_schema_version, commit_managed_admission,
    hold_expired_allocations, migrate_schema, retry_managed_admission,
)
from sentinel.adaptive.capacity_schema import reservation_lease


PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
CLASS_DEFAULTS = {
    "LIGHT": (0.5, 0.5, 0),
    "MEDIUM": (2.0, 4.0, 0),
    "HEAVY": (4.0, 8.0, 1),
    "EXTREME": (8.0, 14.0, 1),
}


def legacy_lifecycle_blocker(conn: sqlite3.Connection) -> str | None:
    """Keep legacy projections away from retained managed capacity.

    This compatibility check shares the caller's writer transaction. A legacy
    caller has no trustworthy v2 frame/config for interpreting lifetime floors
    or control barriers; exemptions cannot supply that missing evidence.
    """
    if not conn.in_transaction:
        raise RuntimeError("transaction_required")
    try:
        if not check_schema_version(conn):
            return "managed_lifecycle_unavailable"
        runtime = conn.execute(
            "SELECT mode,admission_barrier FROM adaptive_runtime WHERE singleton=1"
        ).fetchone()
        if runtime is None or runtime["mode"] not in {"off", "shadow", "canary", "limited"}:
            return "managed_lifecycle_unavailable"
        if runtime["admission_barrier"] != "NONE":
            return "managed_lifecycle_requires_resource_v2"
        if conn.execute("""SELECT 1 FROM managed_executions
            WHERE state IS NULL OR state NOT IN
                ('FINISHED','CANCELLED_BEFORE_START','START_FAILED') LIMIT 1""").fetchone():
            return "managed_lifecycle_requires_resource_v2"
        for table in ("reservations", "worker_reservations"):
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                # Include orphan/terminal bindings: neither missing registry
                # evidence nor an inconsistent terminal row releases capacity.
                if conn.execute(f"""SELECT 1 FROM {table} WHERE execution_id IS NOT NULL
                    OR lifecycle_managed IS NULL OR lifecycle_managed<>0 LIMIT 1""").fetchone():
                    return "managed_lifecycle_requires_resource_v2"
    except (sqlite3.Error, RuntimeError):
        return "managed_lifecycle_unavailable"
    return None


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
        policy_provider=None,
    ) -> None:
        self.local_host_id = local_host_identity() if local_host_id is None else local_host_id
        if not isinstance(self.local_host_id, str) or not self.local_host_id.strip():
            raise ValueError("local_host_id must be a nonempty string")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self.pid_identity = pid_identity or _default_pid_identity
        self._managed_policy_provider = policy_provider
        self._managed_store = None
        self._managed_store_lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            from .adaptive.daily_generation import prepare_connection
            prepare_connection(conn, role="coordinator", db_path=self.db_path)
            check_schema_version(conn)
            conn.execute("PRAGMA busy_timeout=10000")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn
        except BaseException as primary:
            try:
                conn.close()
            except BaseException:
                primary._sentinel_connection_cleanup = conn
                primary.add_note("coordinator_connection_cleanup_failed")
            raise

    @contextmanager
    def _db(self):
        from .adaptive.daily_generation import readiness_scope
        with readiness_scope(self.db_path):
            with self._db_owned() as conn:
                yield conn

    @contextmanager
    def _db_owned(self):
        conn = self._connect()
        primary = None
        try:
            yield conn
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                conn.close()
            except BaseException as error:
                target = error if primary is None else primary
                target._sentinel_connection_cleanup = conn
                target.add_note("coordinator_connection_cleanup_failed")
                if primary is None:
                    raise

    def _managed_lifecycle_store(self):
        # Legacy admission does not initialize or acquire a native policy
        # provider. Explicit fixture injection is the only synthetic seam.
        from sentinel.adaptive.store import LifecycleStore
        with self._managed_store_lock:
            if self._managed_store is None:
                self._managed_store = LifecycleStore(
                    self.db_path, policy_provider=self._managed_policy_provider,
                    local_host_id=self.local_host_id)
            return self._managed_store

    @staticmethod
    def _commit_admission(conn, transaction):
        if transaction is not None:
            # A COMMIT error can be a lost acknowledgement. A later successful
            # rollback must never turn that uncertainty into a clean rejection.
            transaction["commit_attempted"] = True
        conn.execute("COMMIT")

    @contextmanager
    def _admission_db(self, managed, context):
        if managed is None:
            with self._admission_db_owned(managed, context) as value:
                yield value
            return
        self._settle_managed_submission(context)
        try:
            with self._admission_db_owned(managed, context) as value:
                yield value
        except BaseException as error:
            # Keep the original guard, transaction and exception owners. An
            # uncertain native release is never permission to open a fresh
            # mutex or to clear a nonce copied from the ledger.
            context._submission_policy_error = error
            raise
        else:
            context._submission_guard = None
            context._submission_policy_error = None

    def _settle_managed_submission(self, context):
        """Settle only this original context's positively released publication."""
        from sentinel.adaptive.admission import ManagedAdmissionUnavailable
        from sentinel.adaptive.windows import NativePolicyMutexError
        if context._submission_prepare_unknown:
            raise ManagedAdmissionUnavailable("managed_policy_publication_unknown")
        guard, policy = context._submission_guard, context._submission_policy
        if guard is None:
            return
        if policy is not self._managed_lifecycle_store()._policy:
            raise ManagedAdmissionUnavailable("managed_policy_owner_mismatch")
        error = context._submission_policy_error
        notes = tuple(getattr(error, "__notes__", ()))
        if (str(error) == "managed_admission_connection_cleanup_failed" or
                any(note != "policy_entry_cleanup_failed" for note in notes) or
                (not context._submission_policy_entered and error is not None and
                 not (isinstance(error, NativePolicyMutexError) and error.reason in
                      {"policy_mutex_timeout", "policy_mutex_wait_failed"})) or
                (isinstance(error, NativePolicyMutexError) and error.reason not in
                 {"policy_mutex_timeout", "policy_mutex_wait_failed"})):
            raise ManagedAdmissionUnavailable("managed_policy_cleanup_unverified")
        with policy.store._connection() as conn:
            runtime = policy._runtime(conn)
            binding = policy._binding(runtime, guard.binding.logon_id)
        if binding != guard.binding:
            raise ManagedAdmissionUnavailable("managed_policy_binding_changed")
        nonce = runtime["policy_entry_nonce"]
        if nonce is not None:
            if nonce != guard.nonce:
                raise ManagedAdmissionUnavailable("managed_policy_entry_changed")
            try:
                # This guard was retained before the original native wait.
                # hold revalidates it under the actual POLICY mutex; no new
                # admission or capacity transaction is performed by this retry.
                context._submission_policy_entered = False
                with policy.hold(guard):
                    context._submission_policy_entered = True
                    pass
            except BaseException as primary:
                context._submission_policy_error = primary
                raise
        context._submission_guard = None
        context._submission_policy_error = None

    @contextmanager
    def _admission_db_owned(self, managed, context):
        if managed is None:
            with self._db() as conn:
                conn.execute("BEGIN IMMEDIATE")
                yield conn, None, True, None
            return

        from sentinel.adaptive.policy import PolicyBusy, PolicyError
        from sentinel.adaptive.store import LifecycleError
        policy = self._managed_lifecycle_store()._policy
        logon = policy.current_logon()
        if logon != managed.wrapper_identity.logon_id:
            raise PolicyError("policy_logon_mismatch")
        deadline = time.monotonic() + 1.0
        while True:
            try:
                context._submission_prepare_unknown = True
                guard = policy.prepare(logon)
                context._submission_policy = policy
                context._submission_guard = guard
                context._submission_policy_error = None
                context._submission_policy_entered = False
                context._submission_prepare_unknown = False
                break
            except PolicyBusy as error:
                context._submission_prepare_unknown = bool(getattr(error, "__notes__", ()))
                if getattr(error, "__notes__", ()) or time.monotonic() >= deadline:
                    raise
                # No native scope or database connection survives this wait.
                time.sleep(min(.01, max(0, deadline - time.monotonic())))
            except BaseException:
                # prepare may have committed its nonce before failing. Without
                # a returned original guard its publication cannot be adopted.
                context._submission_prepare_unknown = True
                raise
        with policy.hold(guard):
            context._submission_policy_entered = True
            # Native identity and canonical ledger checks remain outside the
            # capacity transaction. Contention has not consumed first submission.
            try:
                snapshot, first_submission = context.begin_submission(db_path=self.db_path)
            except BaseException as primary:
                # No capacity transaction or publication has begun. A retained
                # context's rejection does not leave a new launch outcome.
                if not getattr(primary, "__notes__", ()):
                    guard.clean_rejection = True
                raise
            if snapshot is not managed:
                guard.clean_rejection = True
                raise LifecycleError("managed_admission_context_changed")
            transaction = {"commit_attempted": False, "rolled_back": False,
                           "first_submission": first_submission,
                           "execution_id": managed.execution_id,
                           "db_path": context._admission_db_path}
            context._submission_transaction = transaction
            try:
                conn = self._connect()
            except BaseException as primary:
                # _connect preserves the original error and flags an unverified
                # close. No capacity transaction has begun on this path.
                if not getattr(primary, "__notes__", ()):
                    guard.clean_rejection = True
                raise
            transaction["connection"] = conn
            transaction["connection_closed"] = False
            rolled_back = False
            try:
                conn.execute("BEGIN IMMEDIATE")
                policy.assert_held(guard)
                policy.revalidate(conn, guard)
                yield conn, policy, first_submission, transaction
                if conn.in_transaction:
                    raise LifecycleError("managed_admission_transaction_unfinished")
            except BaseException as primary:
                try:
                    conn.rollback()
                    rolled_back = not conn.in_transaction
                    transaction["rolled_back"] = rolled_back
                except BaseException:
                    primary.add_note("managed_admission_rollback_failed")
                try:
                    conn.close()
                    transaction["connection_closed"] = True
                except BaseException:
                    primary._sentinel_connection_cleanup = conn
                    primary.add_note("managed_admission_connection_cleanup_failed")
                if (rolled_back and not transaction["commit_attempted"] and
                        not getattr(primary, "__notes__", ())):
                    guard.clean_rejection = True
                raise
            else:
                try:
                    conn.close()
                    transaction["connection_closed"] = True
                except BaseException as primary:
                    primary._sentinel_connection_cleanup = conn
                    primary.add_note("managed_admission_connection_cleanup_failed")
                    raise

    def _init_db(self) -> None:
        with self._db() as conn:
            check_schema_version(conn)
            # Own non-capacity tables and the complete shared capacity schema
            # become visible together with their persistent writer guards.
            conn.execute("BEGIN IMMEDIATE")
            schema = """
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
                """
            for statement in schema.split(";"):
                if statement.strip():
                    conn.execute(statement)
            queue_columns = {row[1] for row in conn.execute("PRAGMA table_info(queue)")}
            if "spec_hash" not in queue_columns:
                conn.execute("ALTER TABLE queue ADD COLUMN spec_hash TEXT NOT NULL DEFAULT ''")
            migrate_schema(conn, in_transaction=True)
            conn.commit()

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
            # A managed queue intent has not reserved or launched anything.
            # Its activity TTL is independent of an uncertain legacy PID lookup;
            # expiring it never releases an execution's retained allocation.
            if row["managed_execution_id"] is not None and float(row["heartbeat_at"]) < queue_cutoff:
                conn.execute("DELETE FROM queue WHERE request_key=?", (row["request_key"],))
                continue
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
                fresh = -30 <= now - stamp <= float(config["admission_status_stale_sec"])
                if status.get("sampled_at"):
                    sample = datetime.strptime(status["sampled_at"], "%Y-%m-%d %H:%M:%S").timestamp()
                    fresh = fresh and -30 <= now - sample <= float(config["admission_status_stale_sec"])
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
    ) -> tuple[float, float, int]:
        """Return fresh Maintainer reservations for this local execution pool."""
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_reservations'"
        ).fetchone()
        if not table:
            return 0.0, 0.0, 0
        cutoff = now - float(config["reservation_grace_sec"])
        row = conn.execute(
            """SELECT COALESCE(SUM(CASE WHEN created_at>=? THEN cpu_units ELSE 0 END),0) cpu,
                      COALESCE(SUM(CASE WHEN created_at>=? THEN ram_gib ELSE 0 END),0) ram,COUNT(*) io
               FROM worker_reservations WHERE worker_id=? AND expires_at>?""",
            (cutoff, cutoff, str(config["local_worker_id"]), now),
        ).fetchone()
        return float(row["cpu"]), float(row["ram"]), int(row["io"])

    def admit(
        self, request: ResourceRequest, status: dict[str, Any], *,
        config: dict[str, Any] | None = None, now: float | None = None,
    ) -> dict[str, Any]:
        return self._admit(request, status, config=config, now=now)

    def admit_managed(
        self, context, status: dict[str, Any], *,
        config: dict[str, Any] | None = None, now: float | None = None,
    ) -> dict[str, Any]:
        """Reserve and bind a self-wrapper atomically; never authorize launch.

        The in-process context retains native self identity and its original
        launch token. JSON identity/snapshots and legacy reservations are not
        adoption authority. Native validation happens before the DB transaction.
        """
        from sentinel.adaptive.admission import ManagedAdmission
        if type(context) is not ManagedAdmission:
            raise TypeError("managed_admission_context_required")
        if getattr(context, "_experiment_demand", None) is not None:
            raise TypeError("experiment_original_admission_route_required")
        with context.submission_scope():
            snapshot = context.snapshot()
            return self._admit(snapshot.request, status, config=config, now=now,
                               managed=snapshot, managed_context=context)

    def admit_experiment(self, owner):
        """Admit one original test demand through the actual daily provider.

        This grants capacity only. The isolated native scope still needs its
        separate original creation and cleanup authority before any work.
        """
        from sentinel.adaptive.experiment_demand import DailyExperimentDemand
        from sentinel.adaptive.daily_generation import readiness_scope
        if type(owner) is not DailyExperimentDemand:
            raise TypeError("experiment_original_owner_required")
        try:
            with readiness_scope(self.db_path), owner._lock:
                context, status, config = owner._prepare_submission(self)
                with context.submission_scope():
                    snapshot = context.snapshot()
                    return self._admit(snapshot.request, status, config=config,
                        managed=snapshot, managed_context=context, experiment_context=owner)
        except BaseException as error:
            owner._retain_submission_error(error)
            raise

    def settle_experiment_admission(self, owner):
        """Settle one original sealed experiment admission without new work."""
        from sentinel.adaptive.experiment_cleanup import settle_admission
        return settle_admission(self, owner)

    def release_experiment(self, operation):
        """Release only a retained original experiment with positive cleanup.

        This route neither manufactures a managed cancellation context nor
        invokes the ordinary mirroring/readiness path during cleanup.
        """
        from sentinel.adaptive.experiment_cleanup import ExperimentReleaseOperation
        if type(operation) is not ExperimentReleaseOperation:
            raise TypeError("experiment_original_release_required")
        return operation.release(self)

    @staticmethod
    def _managed_context_snapshot(context, db_path, *, pin=False):
        from sentinel.adaptive.admission import ManagedAdmission, ManagedAdmissionUnavailable
        if type(context) is not ManagedAdmission:
            raise TypeError("managed_admission_context_required")
        snapshot = context.snapshot()
        path = context._ledger_path(db_path)
        if context._admission_db_path is not None and path != context._admission_db_path:
            raise ManagedAdmissionUnavailable("managed_admission_ledger_mismatch")
        if context._submitted and context._admission_db_path is None:
            raise ManagedAdmissionUnavailable("managed_admission_ledger_mismatch")
        if pin:
            context._admission_db_path = path
        return snapshot, path

    def _managed_reconciliation_locked(self, conn, context, snapshot):
        """Read one original binding in the caller's coherent transaction."""
        from sentinel.adaptive.admission import ManagedAdmissionUnavailable
        request = snapshot.request
        queues = conn.execute("""SELECT * FROM queue
            WHERE request_key=? OR managed_execution_id=?""",
            (request.request_key, snapshot.execution_id)).fetchall()
        if queues:
            if len(queues) != 1:
                raise ManagedAdmissionUnavailable("managed_queue_binding_ambiguous")
            context._validate_queued(queues[0], snapshot)
        allocations = conn.execute("""SELECT * FROM reservations
            WHERE request_key=? OR execution_id=?""",
            (request.request_key, snapshot.execution_id)).fetchall()
        if conn.execute("""SELECT 1 FROM worker_reservations
            WHERE execution_id=? OR task_id=? LIMIT 1""",
            (snapshot.execution_id, snapshot.task_id)).fetchone():
            raise ManagedAdmissionUnavailable("managed_abandon_routed_obligation")
        row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?",
                           (snapshot.execution_id,)).fetchone()
        result = {"execution_id": snapshot.execution_id, "request_key": request.request_key,
                  "allowed": False, "launch_authorized": False}
        if row is not None:
            if queues or len(allocations) > 1:
                raise ManagedAdmissionUnavailable("managed_admission_binding_mismatch")
            if row["state"] in {"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"} and allocations:
                raise ManagedAdmissionUnavailable("managed_abandon_allocation_unresolved")
            if allocations:
                context._validate_cancel_allocation(dict(allocations[0]), snapshot,
                                                    row["reservation_id"])
            replay = retry_managed_admission(conn, snapshot,
                local_context=self._config({"admission_policy": "resource-v2"},
                                           local_host_id=self.local_host_id))
            return result | {key: replay[key] for key in
                             ("state", "state_revision", "reservation_id")}
        if allocations or conn.execute("SELECT 1 FROM executions WHERE request_key=? LIMIT 1",
                                       (request.request_key,)).fetchone():
            raise ManagedAdmissionUnavailable("managed_abandon_allocation_unresolved")
        if queues:
            return result | {"state": "QUEUED"}
        state = "ABSENT_AFTER_SUBMISSION" if context._submitted else "NEVER_SUBMITTED"
        transaction = context._submission_transaction
        if (context._submitted and transaction is not None and
                transaction.get("execution_id") == snapshot.execution_id and
                transaction.get("db_path") == context._admission_db_path and
                transaction.get("first_submission") is True and
                transaction.get("commit_attempted") is False and
                transaction.get("rolled_back") is True and
                transaction.get("connection_closed") is True):
            # Positive evidence from this exact first transaction, combined
            # with the coherent absence check above. A later missing queue or
            # lost COMMIT reply has none of this never-committed proof.
            state = "SUBMISSION_REJECTED"
        return result | {"state": state}

    def reconcile_managed(self, context) -> dict[str, Any]:
        """Inspect the original attempt without submitting, renewing or launching.

        This is a read-only locator result, never unused-claim authority. In
        particular ABSENT_AFTER_SUBMISSION does not authorize releasing owners.
        """
        from sentinel.adaptive.admission import ManagedAdmission
        if type(context) is not ManagedAdmission:
            raise TypeError("managed_admission_context_required")
        with context._lock:
            snapshot, path = self._managed_context_snapshot(context, self.db_path)
            conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True,
                                   timeout=1, isolation_level=None)
            conn.row_factory = sqlite3.Row
            try:
                check_schema_version(conn)
                conn.execute("BEGIN")
                result = self._managed_reconciliation_locked(conn, context, snapshot)
                conn.execute("COMMIT")
            except BaseException as primary:
                try:
                    conn.close()
                except BaseException:
                    primary.add_note("managed_reconciliation_cleanup_failed")
                raise
            else:
                conn.close()
            result["submission_cleanup_pending"] = bool(
                context._submission_guard is not None or context._submission_prepare_unknown)
            return result

    def cancel_managed(self, context, *, reservation_id: str | None = None,
                       expected_revision: int | None = None,
                       now: float | None = None) -> dict[str, Any]:
        """Abandon exactly one original pre-handoff attempt, never another owner.

        Explicit RESERVED cancellation delegates to the retained unused-claim
        proof. A queued intent has no lifecycle allocation to archive; its
        transaction proves full binding and absence of direct/routed obligations
        before sealing and deleting exactly that key. Neither route uses a PID
        as authority or interprets missing acknowledgement as a rejection.
        """
        from sentinel.adaptive.admission import ManagedAdmission, ManagedAdmissionUnavailable
        if type(context) is not ManagedAdmission:
            raise TypeError("managed_admission_context_required")
        if getattr(context, "_experiment_demand", None) is not None:
            raise ManagedAdmissionUnavailable("experiment_native_cleanup_unverified")
        if (reservation_id is None) != (expected_revision is None):
            raise ManagedAdmissionUnavailable("exact_reserved_cancel_arguments_required")
        if now is not None and (type(now) not in {int, float} or not math.isfinite(now)):
            raise ValueError("invalid_time")
        with context._lock:
            snapshot, path = self._managed_context_snapshot(context, self.db_path, pin=True)
            if context._prepare_attempted:
                raise ManagedAdmissionUnavailable("prepare_already_attempted")
            if context._claim_exported:
                raise ManagedAdmissionUnavailable("launch_claim_already_exported")
            if context._abandon_error is not None:
                raise ManagedAdmissionUnavailable("managed_abandon_cleanup_unverified")
            self._settle_managed_submission(context)
            if reservation_id is not None:
                if context._abandon_target is not None:
                    raise ManagedAdmissionUnavailable("managed_abandon_target_mismatch")
                result = context.cancel_reserved(path, reservation_id=reservation_id,
                    expected_revision=expected_revision, now=now)
                # Keep the public adapter free of row internals and secrets.
                result = {key: result[key] for key in
                          ("execution_id", "reservation_id", "state", "state_revision", "cancelled")}
                result.update(request_key=snapshot.request.request_key,
                              allowed=False, launch_authorized=False)
            else:
                if context._cancel_target is not None:
                    raise ManagedAdmissionUnavailable("exact_reserved_cancel_arguments_required")
                result = self._cancel_managed_queue(context, snapshot, path)
            # Mirrors follow an acknowledged authoritative outcome. Their
            # best-effort failure cannot turn successful retirement into a
            # retry of admission, nor into apparent allocation retention.
            try:
                self._mirror()
            except (OSError, sqlite3.Error):
                result["mirror_synced"] = False
            else:
                result["mirror_synced"] = True
            return result

    def _cancel_managed_queue(self, context, snapshot, path):
        from .adaptive.daily_generation import readiness_scope
        with readiness_scope(self.db_path):
            return self._cancel_managed_queue_owned(context, snapshot, path)

    def _cancel_managed_queue_owned(self, context, snapshot, path):
        from sentinel.adaptive.admission import ManagedAdmissionUnavailable
        if context._abandon_error is not None:
            raise ManagedAdmissionUnavailable("managed_abandon_cleanup_unverified")
        transaction = {"commit_attempted": False}
        context._abandon_transaction = transaction
        try:
            conn = self._connect()
        except BaseException as primary:
            if getattr(primary, "__notes__", ()):
                context._abandon_error = primary
            raise
        transaction.update(connection=conn, connection_closed=False)
        try:
            conn.execute("BEGIN IMMEDIATE")
            observed = self._managed_reconciliation_locked(conn, context, snapshot)
            state = observed["state"]
            target = (path, snapshot.execution_id, snapshot.request.request_key)
            if context._abandon_target is not None:
                if context._abandon_target != target:
                    raise ManagedAdmissionUnavailable("managed_abandon_target_mismatch")
                kind = context._abandon_kind
                if state == "QUEUED" and kind != "QUEUED_CANCELLED":
                    raise ManagedAdmissionUnavailable("managed_abandon_target_mismatch")
                if state not in {"QUEUED", "NEVER_SUBMITTED", "ABSENT_AFTER_SUBMISSION", "SUBMISSION_REJECTED"}:
                    raise ManagedAdmissionUnavailable("managed_abandon_obligation_changed")
                if (state != "QUEUED" and kind == "QUEUED_CANCELLED" and
                        not context._abandon_commit_attempted):
                    raise ManagedAdmissionUnavailable("managed_abandon_absence_unverified")
            elif state == "QUEUED":
                kind = "QUEUED_CANCELLED"
            elif state == "NEVER_SUBMITTED":
                kind = "NOT_SUBMITTED"
            elif state == "SUBMISSION_REJECTED":
                kind = "SUBMISSION_REJECTED"
            else:
                raise ManagedAdmissionUnavailable("managed_abandon_requires_exact_evidence")
            context._seal_abandonment(path, snapshot, kind)
            result = {"cancelled": True, "state": kind, "execution_id": snapshot.execution_id,
                      "request_key": snapshot.request.request_key, "allowed": False,
                      "launch_authorized": False}
            if state == "QUEUED":
                changed = conn.execute("""DELETE FROM queue WHERE request_key=?
                    AND managed_execution_id=? AND managed_binding_hash=?
                    AND owner_pid=? AND owner_started=?""",
                    (snapshot.request.request_key, snapshot.execution_id, snapshot.binding_hash,
                     snapshot.wrapper_identity.pid, snapshot.request.owner_started)).rowcount
                if changed != 1:
                    raise ManagedAdmissionUnavailable("managed_queue_cancel_conflict")
            # Publish the exact replay target before COMMIT can have any effect.
            context._abandon_commit_attempted = True
            self._commit_admission(conn, transaction)
        except BaseException as primary:
            try:
                conn.rollback()
            except BaseException:
                primary.add_note("managed_abandon_rollback_failed")
            try:
                conn.close()
                transaction["connection_closed"] = True
            except BaseException:
                primary._sentinel_connection_cleanup = conn
                primary.add_note("managed_abandon_connection_cleanup_failed")
            if getattr(primary, "__notes__", ()):
                context._abandon_error = primary
            raise
        else:
            try:
                conn.close()
                transaction["connection_closed"] = True
            except BaseException as primary:
                context._abandon_error = primary
                primary._sentinel_connection_cleanup = conn
                primary.add_note("managed_abandon_connection_cleanup_failed")
                raise
        context._abandon_result = result.copy()
        return result

    def _admit(
        self,
        request: ResourceRequest,
        status: dict[str, Any],
        *,
        config: dict[str, Any] | None = None,
        now: float | None = None,
        managed=None,
        managed_context=None,
        experiment_context=None,
    ) -> dict[str, Any]:
        if getattr(managed_context, "_experiment_demand", None) is not experiment_context:
            raise TypeError("experiment_original_admission_route_required")
        if experiment_context is not None:
            from sentinel.adaptive.experiment_demand import DailyExperimentDemand
            if (type(experiment_context) is not DailyExperimentDemand or
                    experiment_context._admission is not managed_context or
                    experiment_context._snapshot is not managed):
                raise TypeError("experiment_original_owner_required")
        req = request.normalized()
        cfg = self._config(config, local_host_id=self.local_host_id)
        now = time.time() if now is None else now
        v2 = cfg.get("admission_policy") == "resource-v2"
        if managed is not None and (not v2 or cfg.get("local_allocatable_ram_gib") != 58 or
                cfg.get("local_physical_headroom_gib", 4) != 4 or cfg["local_commit_headroom_gib"] != 4):
            return {"allowed": False, "reason": "managed_policy_mismatch", "request_key": req.request_key}
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
        with self._admission_db(managed, managed_context) as (conn, policy, first_submission, transaction):
            from sentinel.adaptive.daily_retirement_fence import assert_new_capacity_allowed
            assert_new_capacity_allowed(conn)
            self._cleanup_locked(conn, now, cfg, observations)
            legacy_blocker = legacy_lifecycle_blocker(conn) if not v2 else None
            if managed is not None:
                replay = retry_managed_admission(conn, managed, local_context=cfg)
                if replay is not None:
                    if experiment_context is not None:
                        replay = experiment_context.publish_locked(conn, managed, policy, replay, replay=True)
                    self._commit_admission(conn, transaction)
                    return replay
            queued_existing = conn.execute("SELECT * FROM queue WHERE request_key=?", (req.request_key,)).fetchone()
            if managed is None and queued_existing and queued_existing["managed_execution_id"] is not None:
                self._commit_admission(conn, transaction)
                return {"allowed": False, "reason": "managed_request_requires_context", "request_key": req.request_key}
            existing = conn.execute("SELECT * FROM reservations WHERE request_key=?", (req.request_key,)).fetchone()
            if existing:
                if managed is not None:
                    self._commit_admission(conn, transaction)
                    return {"allowed": False, "reason": "legacy_reservation_cannot_be_adopted",
                            "request_key": req.request_key}
                if allocation_is_bound(conn, "direct", existing["id"]):
                    self._commit_admission(conn, transaction)
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "request_key": req.request_key, "reservation_id": existing["id"]}
                if legacy_blocker:
                    self._commit_admission(conn, transaction)
                    return {"allowed": False, "reason": legacy_blocker,
                            "request_key": req.request_key, "reservation_id": existing["id"]}
                if existing["spec_hash"] != req.spec_hash:
                    self._commit_admission(conn, transaction)
                    return {
                        "allowed": False, "reason": "request_spec_mismatch",
                        "request_key": req.request_key, "reservation_id": existing["id"],
                    }
                conn.execute(
                    "UPDATE reservations SET heartbeat_at=?,expires_at=?,tool_use_id=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                    (now, now + float(cfg["reservation_ttl_min"]) * 60, req.tool_use_id, existing["id"]),
                )
                self._commit_admission(conn, transaction)
                self._mirror()
                return {"allowed": True, "reservation_id": existing["id"], "reused": True, "request_key": req.request_key}
            handoffs = conn.execute(
                "SELECT * FROM reservations WHERE owner_pid=? AND command_signature=? AND tool_use_id='' ORDER BY created_at",
                (req.owner_pid, req.command_signature),
            ).fetchall()
            handoff = next((row for row in handoffs
                            if not allocation_is_bound(conn, "direct", row["id"])), None)
            if managed is None and not legacy_blocker and handoff and handoff["spec_hash"] == req.spec_hash:
                conn.execute("UPDATE reservations SET tool_use_id=?,heartbeat_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?", (req.tool_use_id, now, handoff["id"]))
                self._commit_admission(conn, transaction)
                self._mirror()
                return {"allowed": True, "reservation_id": handoff["id"], "reused": True, "request_key": handoff["request_key"]}

            queue_hash = "managed-v1:" + managed.binding_hash if managed is not None else req.spec_hash
            immutable_queue = {"owner_pid": req.owner_pid, "owner_started": req.owner_started,
                "tool_use_id": req.tool_use_id, "repo": req.repo, "command_signature": req.command_signature,
                "command_text": "", "resource_class": req.resource_class, "priority": req.priority,
                "priority_rank": PRIORITY_RANK[req.priority], "cpu_units": req.cpu_units,
                "ram_gib": req.ram_gib, "io_slots": req.io_slots, "commit_bytes": req.commit_bytes}
            if queued_existing and (queued_existing["spec_hash"] != queue_hash or
                    (managed is not None and (queued_existing["managed_execution_id"] != managed.execution_id or
                                              queued_existing["managed_binding_hash"] != managed.binding_hash or
                                              any(queued_existing[key] != value for key, value in immutable_queue.items())))):
                self._commit_admission(conn, transaction)
                return {
                    "allowed": False, "reason": "request_spec_mismatch",
                    "request_key": req.request_key,
                }
            if managed is not None and not first_submission and queued_existing is None:
                self._commit_admission(conn, transaction)
                return {"allowed": False, "reason": "managed_request_missing", "request_key": req.request_key}

            conn.execute(
                """INSERT INTO queue
                (request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                 resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,queued_at,heartbeat_at,
                 spec_hash,commit_bytes,managed_execution_id,managed_binding_hash)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(request_key) DO UPDATE SET heartbeat_at=excluded.heartbeat_at,
                  tool_use_id=excluded.tool_use_id,priority=excluded.priority,
                  priority_rank=excluded.priority_rank""",
                (
                    req.request_key, req.owner_pid, req.owner_started, req.tool_use_id, req.repo,
                    req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                    PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                    queue_hash, req.commit_bytes,
                    managed.execution_id if managed is not None else None,
                    managed.binding_hash if managed is not None else None,
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

            if legacy_blocker:
                allowed, reason = False, legacy_blocker
            elif not v2:
                active = conn.execute("SELECT * FROM reservations").fetchall()
                grace = float(cfg["reservation_grace_sec"])
                pending_cpu = sum(float(r["cpu_units"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_ram = sum(float(r["ram_gib"]) for r in active if now - float(r["created_at"]) <= grace)
                pending_commit = sum((r["commit_bytes"] / 2**30 if r["commit_bytes"] is not None else float(r["ram_gib"]))
                                     for r in active if now - float(r["created_at"]) <= grace)
                routed_cpu, routed_ram, routed_io = self._routed_local_pending(conn, cfg, now)
                pending_cpu += routed_cpu
                pending_ram += routed_ram
                pending_commit += routed_ram
                used_io = sum(int(r["io_slots"]) for r in active) + routed_io
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
            if exemption and not legacy_blocker and (not v2 or not details):
                allowed = True

            if experiment_context is not None:
                experiment_blocker = experiment_context.admission_blocker_locked(conn, managed, policy)
                if experiment_blocker is not None:
                    allowed, reason = False, experiment_blocker

            if allowed:
                lease_duration, lease_deadline = reservation_lease(cfg["reservation_ttl_min"], now)
                reservation_id = uuid.uuid4().hex
                conn.execute(
                    """INSERT INTO reservations
                    (id,request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                     resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,created_at,
                     heartbeat_at,expires_at,spec_hash,commit_bytes,execution_id,lifecycle_managed,managed_spec_hash,
                     lease_duration_sec,writer_protocol,writer_revision)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0)""",
                    (
                        reservation_id, req.request_key, req.owner_pid, req.owner_started, req.tool_use_id,
                        req.repo, req.command_signature, redact_command(req.command), req.resource_class, req.priority,
                        PRIORITY_RANK[req.priority], req.cpu_units, req.ram_gib, req.io_slots, now, now,
                        lease_deadline, req.spec_hash, req.commit_bytes,
                        managed.execution_id if managed is not None else None, 1 if managed is not None else 0,
                        managed.spec_hash if managed is not None else None,
                        lease_duration,
                    ),
                )
                conn.execute("DELETE FROM queue WHERE request_key=?", (req.request_key,))
                result = {"allowed": True, "reservation_id": reservation_id, "reused": False, "request_key": req.request_key}
                if managed is not None:
                    result = commit_managed_admission(conn, managed, reservation_id, now=now, local_context=cfg, policy_coordinator=policy)
                    if experiment_context is not None:
                        result = experiment_context.publish_locked(conn, managed, policy, result, replay=False)
                if exemption:
                    result.update(reason="user_exemption", exemption_id=exemption["id"], exemption_expires_at=exemption["expires_at"])
            else:
                result = {"allowed": False, "reason": reason, "position": position, "request_key": req.request_key}
                if cfg.get("admission_policy") == "resource-v2":
                    result.update(policy="resource-v2", blockers=details)
            self._commit_admission(conn, transaction)
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
                conn.execute("BEGIN IMMEDIATE")
                from sentinel.adaptive.daily_retirement_fence import assert_new_capacity_allowed
                assert_new_capacity_allowed(conn)
                active = conn.execute("SELECT id FROM reservations WHERE request_key=?", (request_key,)).fetchone()
                bound = bool(active and allocation_is_bound(conn, "direct", active["id"]))
                legacy_blocker = (legacy_lifecycle_blocker(conn)
                                  if (config or {}).get("admission_policy") != "resource-v2" else None)
                conn.execute("COMMIT")
            if active:
                if bound:
                    return {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                            "reservation_id": active["id"], "request_key": request_key}
                if legacy_blocker:
                    return {"allowed": False, "reason": legacy_blocker,
                            "reservation_id": active["id"], "request_key": request_key}
                return {"allowed": True, "reservation_id": active["id"], "reused": True, "request_key": request_key}
            return {"allowed": False, "reason": "request_missing", "request_key": request_key}
        if row["managed_execution_id"] is not None:
            return {"allowed": False, "reason": "managed_request_requires_context", "request_key": request_key}
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
                from sentinel.adaptive.daily_retirement_fence import assert_new_capacity_allowed
                assert_new_capacity_allowed(conn)
                legacy_blocker = (legacy_lifecycle_blocker(conn)
                                  if (config or {}).get("admission_policy") != "resource-v2" else None)
                if allocation_is_bound(conn, "direct", result["reservation_id"]):
                    result = {"allowed": False, "reason": "managed_reservation_requires_exact_claim",
                              "reservation_id": result["reservation_id"], "request_key": request_key}
                elif legacy_blocker:
                    result = {"allowed": False, "reason": legacy_blocker,
                              "reservation_id": result["reservation_id"], "request_key": request_key}
                else:
                    conn.execute("UPDATE reservations SET tool_use_id='',writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?", (result["reservation_id"],))
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
        if sampled_at is None:
            try:
                sampled_at = datetime.strptime(status['sampled_at'], '%Y-%m-%d %H:%M:%S').timestamp()
            except (KeyError, TypeError, ValueError):
                sampled_at = time.time()  # compatibility with callers predating sampled_at
        # The collector has already sampled these counters. Re-reading here would
        # associate later values with the original snapshot and add collection cost.
        memory = status.get('memory') or {}
        disks = status.get('disk_performance') or {}
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
