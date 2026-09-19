"""Provider-neutral worker registry and capacity-aware task router.

``failure_domain`` describes correlated failure only.  Capacity accounting is
kept separately: a ``SHARED_POOL`` worker consumes a common RAM/CPU/disk pool,
while a ``PER_EXECUTION`` worker represents a fresh VM/container for each job
and is limited by per-job resources plus account concurrency.
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
from typing import Any
from sentinel.accounting import (
    frame_from_status, local_host_identity, resolve_worker_locality, shared_admission_blockers,
)
from sentinel.adaptive.store import (
    allocation_is_bound, check_schema_version, hold_bound_allocation,
    hold_expired_allocations, migrate_schema,
)
from sentinel.coordinator import legacy_lifecycle_blocker
from sentinel.adaptive.writers import writer_obligations_present


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
    commit_bytes: int | None = None
    io_slots: int = 1

    def normalized(self) -> "Task":
        preference = self.execution_preference.upper()
        if preference not in PREFERENCES:
            raise ValueError(f"unknown execution preference: {preference}")
        if not self.id:
            raise ValueError("task id is required")
        if not all(math.isfinite(float(value)) for value in (self.ram_gib, self.cpu_units, self.disk_gib)):
            raise ValueError("task resources must be finite")
        if min(self.ram_gib, self.cpu_units, self.disk_gib) < 0:
            raise ValueError("task resources cannot be negative")
        if self.commit_bytes is not None and (type(self.commit_bytes) is not int or self.commit_bytes < 0):
            raise ValueError("commit_bytes must be a nonnegative integer")
        if type(self.io_slots) is not int or self.io_slots < 0:
            raise ValueError("io_slots must be a nonnegative integer")
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
            commit_bytes=self.commit_bytes,
            io_slots=self.io_slots,
        )


class Maintainer:
    """Atomic registry, router, and cross-worker resource reservations."""

    def __init__(self, data_dir: str | os.PathLike[str], *, db_path: str | os.PathLike[str] | None = None,
                 local_host_id: str | None = None):
        self.local_host_id = local_host_identity() if local_host_id is None else local_host_id
        if not isinstance(self.local_host_id, str) or not self.local_host_id.strip():
            raise ValueError("local_host_id must be a nonempty string")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else self.data_dir / "sentinel.db"
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            # An unknown adaptive schema must be rejected before legacy schema
            # initialization, cleanup or even changing its journal mode.
            check_schema_version(conn)
        except BaseException:
            conn.close()
            raise
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
            # Migration creates both existing ledgers and their guards under
            # this lock, including a peer not yet used by this entry point.
            conn.execute("BEGIN IMMEDIATE")
            migrate_schema(conn, in_transaction=True)
            # Legacy locality backfills must not reinterpret retained or corrupt
            # managed capacity. Resolve those obligations explicitly first.
            if not writer_obligations_present(conn):
                conn.execute("UPDATE workers SET capacity_pool=failure_domain,writer_protocol=1,writer_revision=writer_revision+1 WHERE capacity_pool='' OR capacity_pool IS NULL")
                conn.execute("UPDATE workers SET quota_domain=capacity_pool,writer_protocol=1,writer_revision=writer_revision+1 WHERE quota_domain='' OR quota_domain IS NULL")
                conn.execute("UPDATE worker_reservations SET capacity_pool=failure_domain,writer_protocol=1,writer_revision=writer_revision+1 WHERE capacity_pool='' OR capacity_pool IS NULL")
            conn.commit()

    def upsert_worker(self, worker: Worker, *, now: float | None = None) -> dict[str, Any]:
        w = worker.normalized()
        now = time.time() if now is None else now
        observed = w.observed_at or now
        expires = w.probe_expires_at or observed + 7 * 86400
        values = asdict(w)
        values.update(observed_at=observed, probe_expires_at=expires)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT 1 FROM worker_reservations WHERE worker_id=? LIMIT 1", (w.id,)).fetchone():
                # Locality is part of active allocation accounting. A registry
                # refresh cannot turn running local demand into a remote pool,
                # nor resolve uncertain demand by relabelling its worker. This
                # shares the writer lock with reservation creation and includes
                # expired/bound rows: only actual release unlocks a new scope.
                previous = conn.execute("SELECT capabilities_json FROM workers WHERE id=?", (w.id,)).fetchone()
                try:
                    previous_caps = json.loads(previous["capabilities_json"]) if previous else None
                except (TypeError, ValueError, RecursionError):
                    previous_caps = None
                context = {"local_host_id": self.local_host_id}
                old_scope = resolve_worker_locality(previous_caps, context)
                new_scope = resolve_worker_locality(w.capabilities, context)

                def binding(caps):
                    if not isinstance(caps, dict):
                        return None
                    return json.dumps({key: caps[key] for key in ("local", "canonical_host_id") if key in caps},
                                      sort_keys=True, separators=(",", ":"))

                if old_scope != new_scope or (old_scope == "unknown" and binding(previous_caps) != binding(w.capabilities)):
                    raise ValueError("worker_locality_change_with_active_reservations")
            columns = (
                "id", "provider", "failure_domain", "capacity_scope", "capacity_pool",
                "max_concurrency", "quota_domain", "state", "automation_level", "os",
                "capacity_ram_gib", "allocatable_ram_gib", "visible_cpu", "allocatable_cpu",
                "disk_free_gib", "allocatable_disk_gib", "capabilities_json", "trust_domain",
                "source", "observed_at", "probe_expires_at", "updated_at",
            )
            record = (
                w.id, w.provider, w.failure_domain, w.capacity_scope, w.capacity_pool,
                w.max_concurrency, w.quota_domain, w.state, w.automation_level, w.os,
                w.capacity_ram_gib, w.allocatable_ram_gib, w.visible_cpu, w.allocatable_cpu,
                w.disk_free_gib, w.allocatable_disk_gib,
                json.dumps(w.capabilities, separators=(",", ":")), w.trust_domain, w.source,
                observed, expires, now,
            )
            # The writer lock serializes this choice. A plain UPDATE avoids the
            # replacement guard on INSERT into an occupied managed worker ID.
            if conn.execute("SELECT 1 FROM workers WHERE id=?", (w.id,)).fetchone():
                conn.execute(
                    "UPDATE workers SET " + ",".join(name + "=?" for name in columns[1:])
                    + ",writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                    (*record[1:], w.id),
                )
            else:
                conn.execute(
                    "INSERT INTO workers (" + ",".join(columns)
                    + ",writer_protocol,writer_revision) VALUES ("
                    + ",".join("?" for _ in columns) + ",1,0)", record,
                )
            conn.execute("COMMIT")
        return values

    def import_workers(self, workers: list[dict[str, Any]], *, now: float | None = None) -> list[dict[str, Any]]:
        return [self.upsert_worker(Worker(**item), now=now) for item in workers]

    @staticmethod
    def _decode_worker(row: sqlite3.Row, now: float) -> dict[str, Any]:
        item = dict(row)
        item["capabilities"] = json.loads(item.pop("capabilities_json") or "{}")
        item["probe_fresh"] = float(item["probe_expires_at"]) > now
        return item

    def workers(self, *, now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        with self._db() as conn:
            return [self._decode_worker(row, now) for row in conn.execute("SELECT * FROM workers ORDER BY id")]

    def get_worker(self, worker_id: str, *, now: float | None = None) -> dict[str, Any] | None:
        now = time.time() if now is None else now
        with self._db() as conn:
            row = conn.execute("SELECT * FROM workers WHERE id=?", (worker_id,)).fetchone()
        return self._decode_worker(row, now) if row else None

    def update_worker_state(self, worker_id: str, state: str, *, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute("UPDATE workers SET state=?,updated_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?", (state.upper(), now, worker_id))
            conn.execute("COMMIT")
        return cur.rowcount > 0

    def worker_locality(self, worker: dict[str, Any]) -> str:
        """Use the ledger host's identity, never a remote worker's own config."""
        return resolve_worker_locality(worker.get("capabilities"), {"local_host_id": self.local_host_id})

    def _admission_config(self, worker: dict[str, Any]) -> dict[str, Any]:
        config = worker["capabilities"].get("admission_config") or {}
        return {**config, "local_host_id": self.local_host_id}

    def _fits(self, task: Task, worker: dict[str, Any], now: float) -> tuple[bool, str]:
        if worker["state"] not in ACTIVE_STATES:
            return False, f"state_{worker['state'].lower()}"
        if float(worker["probe_expires_at"]) <= now:
            return False, "probe_stale"
        scope = self.worker_locality(worker)
        if scope == "unknown":
            return False, "local_scope_unknown"
        local = scope == "local"
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
        spec = asdict(task)
        # Keep existing idempotency hashes for callers with the legacy shape.
        if task.commit_bytes is None:
            spec.pop("commit_bytes")
        if task.io_slots == 1:
            spec.pop("io_slots")
        payload = json.dumps(spec, sort_keys=True, separators=(",", ":"), default=str)
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

    def _pool_usage(
        self, conn: sqlite3.Connection, worker: dict[str, Any]
    ) -> dict[str, float | int]:
        config = {"local_host_id": self.local_host_id}
        local = self.worker_locality(worker) != "remote"
        usage = conn.execute(
            """SELECT COALESCE(SUM(ram_gib),0) ram,COALESCE(SUM(cpu_units),0) cpu,
                      COALESCE(SUM(disk_gib),0) disk,COUNT(*) jobs
               FROM worker_reservations WHERE capacity_pool=?""",
            (worker["capacity_pool"],),
        ).fetchone()
        result: dict[str, float | int] = {
            "ram": float(usage["ram"]), "cpu": float(usage["cpu"]),
            "disk": float(usage["disk"]), "jobs": int(usage["jobs"]), "io": int(usage["jobs"]),
        }
        if local:
            # All local aliases spend the same host, even if a legacy registry
            # gives each alias another capacity_pool. Unknown registry entries
            # cannot create capacity by being omitted.
            result = {"ram": 0.0, "cpu": 0.0, "disk": 0.0, "jobs": 0, "io": 0}
            for reservation in conn.execute(
                """SELECT r.*,w.capabilities_json FROM worker_reservations r
                   LEFT JOIN workers w ON w.id=r.worker_id"""
            ):
                try:
                    capabilities = json.loads(reservation["capabilities_json"])
                    include = resolve_worker_locality(capabilities, config) != "remote"
                except (TypeError, ValueError, RecursionError):
                    include = True
                if include:
                    result["ram"] += float(reservation["ram_gib"])
                    result["cpu"] += float(reservation["cpu_units"])
                    result["disk"] += float(reservation["disk_gib"])
                    result["jobs"] += 1
                    result["io"] += 1 if reservation["io_slots"] is None else int(reservation["io_slots"])
        # Coordinator reservations are another entry point to this same local
        # pool.  Counting them here prevents local agent commands and routed
        # executions from independently spending the same headroom.
        if local:
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
                result["io"] = int(result["io"]) + int(direct["io"])
        return result

    @staticmethod
    def _reservation_resources_match(row: sqlite3.Row, task: Task) -> bool:
        # The hash binds the requested spec, not the mutable ledger columns.
        # Null compatibility must match accounting._demand's effective values.
        if (row["cpu_units"], row["ram_gib"], row["disk_gib"]) != (task.cpu_units, task.ram_gib, task.disk_gib):
            return False
        physical = math.ceil(task.ram_gib * 2**30)
        commit = physical if task.commit_bytes is None else task.commit_bytes
        return (
            (physical if row["physical_bytes"] is None else row["physical_bytes"]) == physical
            and (physical if row["commit_bytes"] is None else row["commit_bytes"]) == commit
            and (1 if row["io_slots"] is None else row["io_slots"]) == task.io_slots
        )

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
        # Capture the machine topology and immutable telemetry before beginning
        # the capacity transaction. Revalidate the worker snapshot inside it.
        logical_processors = os.cpu_count() or 1
        local_frames = {}
        for observed_worker in self.workers(now=now):
            caps = observed_worker["capabilities"]
            if self.worker_locality(observed_worker) == "local" and caps.get("admission_policy") == "resource-v2":
                try:
                    config = self._admission_config(observed_worker)
                    snapshot = caps.get("admission_snapshot") or {}
                    frame = frame_from_status(snapshot, config, now=now, logical_processors=logical_processors)
                except (TypeError, ValueError, OverflowError):
                    continue  # malformed evidence cannot supply a replay frame
                local_frames[observed_worker["id"]] = (snapshot, config, frame)
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now)
            legacy_blocker = legacy_lifecycle_blocker(conn)
            existing = conn.execute("SELECT * FROM worker_reservations WHERE task_id=?", (t.id,)).fetchone()
            if existing:
                if allocation_is_bound(conn, "routed", existing["id"]):
                    conn.execute("COMMIT")
                    return {"reserved": False, "reason": "execution_bound", "task_id": t.id,
                            "reservation_id": existing["id"]}
                if existing["spec_hash"] != spec_hash:
                    conn.execute("COMMIT")
                    return {
                        "reserved": False, "reason": "task_spec_mismatch", "task_id": t.id,
                        "reservation_id": existing["id"],
                    }
                if legacy_blocker:
                    source = conn.execute("SELECT * FROM workers WHERE id=?", (existing["worker_id"],)).fetchone()
                    source = self._decode_worker(source, now) if source is not None else None
                    if source is None or self.worker_locality(source) == "unknown" or (self.worker_locality(source) == "local" and
                            source["capabilities"].get("admission_policy") != "resource-v2"):
                        conn.execute("COMMIT")
                        return {"reserved": False, "reason": legacy_blocker, "task_id": t.id,
                                "reservation_id": existing["id"]}
                    if self.worker_locality(source) == "local":
                        caps = source["capabilities"]
                        raw_config = caps.get("admission_config")
                        snapshot = caps.get("admission_snapshot")
                        reason = None
                        if not self._reservation_resources_match(existing, t):
                            reason = "reservation_resource_mismatch"
                        elif not isinstance(raw_config, dict) or raw_config.get("admission_policy") != "resource-v2":
                            reason = "policy_config_invalid"
                        elif not isinstance(snapshot, dict) or not snapshot:
                            reason = "policy_snapshot_unavailable"
                        else:
                            config = self._admission_config(source)
                            captured = local_frames.get(source["id"])
                            if captured is None or captured[:2] != (snapshot, config):
                                reason = "revision_conflict"
                            else:
                                reasons = shared_admission_blockers(conn, t, captured[2], config, already_reserved=True)
                                if reasons:
                                    reason = reasons[0]["reason"]
                        if reason:
                            conn.execute("COMMIT")
                            return {"reserved": False, "reason": reason, "task_id": t.id,
                                    "reservation_id": existing["id"]}
                conn.execute(
                    "UPDATE worker_reservations SET heartbeat_at=?,expires_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
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
                if (legacy_blocker and self.worker_locality(worker) == "local" and
                        worker["capabilities"].get("admission_policy") != "resource-v2"):
                    rejected[worker["id"]] = legacy_blocker
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
                caps = worker["capabilities"]
                local = self.worker_locality(worker) == "local"
                local_v2 = local and caps.get("admission_policy") == "resource-v2"
                if local_v2:
                    config = self._admission_config(worker)
                    snapshot = caps.get("admission_snapshot") or {}
                    captured = local_frames.get(worker["id"])
                    if captured is None or captured[:2] != (snapshot, config):
                        rejected[worker["id"]] = "revision_conflict"
                        continue
                    reasons = shared_admission_blockers(conn, t, captured[2], config)
                    if reasons:
                        rejected[worker["id"]] = reasons[0]["reason"]
                        continue
                if not local_v2 and accounted_ram + t.ram_gib > float(worker["allocatable_ram_gib"]):
                    rejected[worker["id"]] = "ram_capacity"
                    continue
                if not local_v2 and worker["allocatable_cpu"] is not None and accounted_cpu + t.cpu_units > float(worker["allocatable_cpu"]):
                    rejected[worker["id"]] = "cpu_capacity"
                    continue
                if worker["allocatable_disk_gib"] is not None and accounted_disk + t.disk_gib > float(worker["allocatable_disk_gib"]):
                    rejected[worker["id"]] = "disk_capacity"
                    continue
                observed_free = worker["capabilities"].get("observed_free_ram_gib")
                if observed_free is not None and not local_v2:
                    headroom = float(worker["capabilities"].get("memory_headroom_gib") or 0)
                    if t.ram_gib > max(0.0, float(observed_free) - headroom - accounted_ram):
                        rejected[worker["id"]] = "observed_ram_headroom"
                        continue
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
                 ram_gib,cpu_units,disk_gib,created_at,heartbeat_at,expires_at,metadata_json,
                 physical_bytes,commit_bytes,io_slots,writer_protocol,writer_revision)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0)""",
                (
                    reservation_id, t.id, worker["id"], worker["failure_domain"],
                    worker["capacity_scope"], worker["capacity_pool"], spec_hash, t.ram_gib,
                    t.cpu_units, t.disk_gib, now, now, now + ttl_min * 60,
                    json.dumps(self._safe_metadata(t.metadata), separators=(",", ":")),
                    math.ceil(t.ram_gib * 2**30),
                    math.ceil(t.ram_gib * 2**30) if t.commit_bytes is None else t.commit_bytes,
                    t.io_slots,
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
            "physical_bytes": math.ceil(t.ram_gib * 2**30),
            "commit_bytes": math.ceil(t.ram_gib * 2**30) if t.commit_bytes is None else t.commit_bytes,
            "io_slots": t.io_slots,
            "coverage": "unmanaged",
            "lifecycle_evidence": "limited",
        }

    def _cleanup_locked(self, conn: sqlite3.Connection, now: float) -> int:
        hold_expired_allocations(conn, "routed", now)
        rows = conn.execute("SELECT * FROM worker_reservations WHERE expires_at<=?", (now,)).fetchall()
        archived = 0
        for row in rows:
            archived += self._archive_locked(conn, row, now, "stale")
        return archived

    @staticmethod
    def _archive_locked(conn: sqlite3.Connection, row: sqlite3.Row, now: float, outcome: str) -> bool:
        if allocation_is_bound(conn, "routed", row["id"]):
            hold_bound_allocation(conn, "routed", row["id"],
                                  "reservation_expired" if outcome == "stale" else "legacy_release_attempt", now)
            return False
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
        return True

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
            released = sum(self._archive_locked(conn, row, now, outcome) for row in rows)
            conn.execute("COMMIT")
        return released

    def heartbeat(self, task_id: str, *, ttl_min: int = 120, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "UPDATE worker_reservations SET heartbeat_at=?,expires_at=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE task_id=?",
                (now, now + ttl_min * 60, task_id),
            )
            conn.execute("COMMIT")
        return cur.rowcount > 0

    def snapshot(self, *, now: float | None = None) -> dict[str, Any]:
        now = time.time() if now is None else now
        with self._db() as conn:
            conn.execute("BEGIN IMMEDIATE")
            self._cleanup_locked(conn, now)
            workers = [self._decode_worker(row, now) for row in conn.execute("SELECT * FROM workers ORDER BY id")]
            reservations = [dict(row) for row in conn.execute("SELECT * FROM worker_reservations ORDER BY created_at")]
            conn.execute("COMMIT")
        by_domain: dict[str, dict[str, float]] = {}
        by_pool: dict[str, dict[str, float]] = {}
        by_quota: dict[str, dict[str, float | int]] = {}
        for row in reservations:
            usage = by_domain.setdefault(row["failure_domain"], {"ram_gib": 0.0, "cpu_units": 0.0, "disk_gib": 0.0})
            usage["ram_gib"] += float(row["ram_gib"])
            usage["cpu_units"] += float(row["cpu_units"])
            usage["disk_gib"] += float(row["disk_gib"])
            pool = by_pool.setdefault(row["capacity_pool"], {"ram_gib": 0.0, "cpu_units": 0.0, "disk_gib": 0.0})
            pool["ram_gib"] += float(row["ram_gib"])
            pool["cpu_units"] += float(row["cpu_units"])
            pool["disk_gib"] += float(row["disk_gib"])
            worker = next((item for item in workers if item["id"] == row["worker_id"]), None)
            quota_name = str(worker["quota_domain"] if worker else row["worker_id"])
            quota = by_quota.setdefault(
                quota_name, {"jobs": 0, "ram_gib": 0.0, "cpu_units": 0.0, "disk_gib": 0.0}
            )
            quota["jobs"] = int(quota["jobs"]) + 1
            quota["ram_gib"] = float(quota["ram_gib"]) + float(row["ram_gib"])
            quota["cpu_units"] = float(quota["cpu_units"]) + float(row["cpu_units"])
            quota["disk_gib"] = float(quota["disk_gib"]) + float(row["disk_gib"])
        return {
            "workers": workers, "reservations": reservations,
            "usage_by_capacity_pool": by_pool,
            "usage_by_failure_domain": by_domain,
            "usage_by_quota_domain": by_quota,
        }
