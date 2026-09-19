"""Additive, fail-closed lifecycle ledger. No process launch or OS control.

Native evidence is deliberately unavailable by default. P2's injected verifier
is an L1 test seam, not an assertion supplied by a CLI caller. A later guardian
must implement and validate that boundary before active enrollment is possible.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Callable, Mapping, Any

from sentinel.accounting import (
    AccountingError, local_host_identity, resolve_worker_locality,
    validate_active_allocation,
)
from .contracts import ExecutionSpec, ProcessIdentity, MAX_ENROLLED_JOBS

SCHEMA_VERSION = 1
TERMINAL_STATES = frozenset({"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"})
_TABLES = {"direct": "reservations", "routed": "worker_reservations"}
_STATES = ("NEW", "QUEUED", "RESERVED", "PREPARED", "LAUNCHING", "RUNNING",
           "DRAINING", "FINISHED", "CANCELLED_BEFORE_START", "START_FAILED",
           "START_UNKNOWN", "UNCERTAIN_HOLD")


class LifecycleError(RuntimeError):
    """Stable error codes suitable for a sanitized caller response."""


class SchemaVersionError(LifecycleError):
    pass


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _columns(conn: sqlite3.Connection, name: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({name})")}


def _check_version(conn: sqlite3.Connection) -> bool:
    if not _has_table(conn, "adaptive_runtime"):
        if _has_table(conn, "managed_executions"):
            raise SchemaVersionError("orphan_adaptive_schema")
        return False
    try:
        rows = conn.execute("SELECT schema_version, protocol_version FROM adaptive_runtime").fetchall()
    except sqlite3.DatabaseError as error:
        raise SchemaVersionError("unreadable_adaptive_schema") from error
    if len(rows) != 1 or rows[0][0] != SCHEMA_VERSION or rows[0][1] != 1:
        raise SchemaVersionError("unsupported_adaptive_schema")
    return True


def check_schema_version(conn: sqlite3.Connection) -> bool:
    """Read-only preflight before an older entry point performs any DDL/DML."""
    return _check_version(conn)


def migrate_schema(conn: sqlite3.Connection) -> None:
    """Serialize the additive migration; do not implicitly commit caller work."""
    if conn.in_transaction:
        raise LifecycleError("migration_requires_own_transaction")
    conn.execute("BEGIN IMMEDIATE")
    try:
        existing = _check_version(conn)
        # No third capacity store: metadata binds the two existing ledgers.
        for table in _TABLES.values():
            if not _has_table(conn, table):
                continue
            present = _columns(conn, table)
            additions = {"execution_id": "TEXT", "lifecycle_managed": "INTEGER NOT NULL DEFAULT 0",
                         "physical_bytes": "INTEGER", "commit_bytes": "INTEGER"}
            if table == "worker_reservations":
                additions["io_slots"] = "INTEGER"
            for name, sql_type in additions.items():
                if name not in present:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
            conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_execution ON {table}(execution_id) WHERE execution_id IS NOT NULL")
        # Queue and reservation projections share the explicit Commit request.
        # Keep the column check under this same writer lock: concurrent legacy
        # constructors must not both observe a missing column before ALTER.
        if _has_table(conn, "queue") and "commit_bytes" not in _columns(conn, "queue"):
            conn.execute("ALTER TABLE queue ADD COLUMN commit_bytes INTEGER")
        if not existing:
            conn.execute("""CREATE TABLE adaptive_runtime (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                schema_version INTEGER NOT NULL, protocol_version INTEGER NOT NULL,
                mode TEXT NOT NULL DEFAULT 'off' CHECK(mode IN ('off','shadow','canary','limited')),
                registry_revision INTEGER NOT NULL DEFAULT 0 CHECK(registry_revision>=0),
                guardian_epoch TEXT NOT NULL DEFAULT '', active_logon_id TEXT NOT NULL DEFAULT '',
                admission_barrier TEXT NOT NULL DEFAULT 'NONE'
                    CHECK(admission_barrier IN ('NONE','CONTROLLING','RECOVERY_HOLD'))
            )""")
            conn.execute("INSERT INTO adaptive_runtime(singleton,schema_version,protocol_version) VALUES(1,1,1)")
        state_sql = ",".join("'" + value + "'" for value in _STATES)
        conn.execute(f"""CREATE TABLE IF NOT EXISTS managed_executions (
            execution_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, session_id TEXT NOT NULL,
            principal_id TEXT NOT NULL, logon_id TEXT NOT NULL,
            allocation_kind TEXT NOT NULL CHECK(allocation_kind IN ('direct','routed','parent')),
            reservation_id TEXT, parent_execution_id TEXT,
            spec_hash TEXT NOT NULL, wrapper_pid INTEGER NOT NULL CHECK(wrapper_pid>0),
            wrapper_created_filetime_100ns TEXT NOT NULL,
            root_pid INTEGER, root_created_filetime_100ns TEXT,
            job_name TEXT UNIQUE, role TEXT NOT NULL CHECK(role IN ('background','protected','neutral')),
            priority TEXT NOT NULL CHECK(priority IN ('P0','P1','P2','P3')),
            coverage TEXT NOT NULL DEFAULT 'unmanaged' CHECK(coverage IN ('unmanaged','job_contained')),
            state TEXT NOT NULL CHECK(state IN ({state_sql})),
            state_revision INTEGER NOT NULL DEFAULT 0 CHECK(state_revision>=0),
            guardian_epoch TEXT NOT NULL DEFAULT '',
            launch_in_flight INTEGER NOT NULL DEFAULT 0 CHECK(launch_in_flight IN (0,1)),
            launch_sealed INTEGER NOT NULL DEFAULT 0 CHECK(launch_sealed IN (0,1)),
            claim_token_hash TEXT NOT NULL, claim_consumed INTEGER NOT NULL DEFAULT 0 CHECK(claim_consumed IN (0,1)),
            root_outcome TEXT, hold_reason TEXT, created_at REAL NOT NULL, heartbeat_at REAL NOT NULL,
            finished_at REAL, cancel_requested_at REAL,
            requested_cpu_units REAL NOT NULL CHECK(typeof(requested_cpu_units) IN ('integer','real') AND requested_cpu_units>=0 AND requested_cpu_units<1e308),
            requested_physical_bytes INTEGER NOT NULL CHECK(typeof(requested_physical_bytes)='integer' AND requested_physical_bytes>=0),
            requested_commit_bytes INTEGER NOT NULL CHECK(typeof(requested_commit_bytes)='integer' AND requested_commit_bytes>=0),
            requested_io_slots INTEGER NOT NULL CHECK(typeof(requested_io_slots)='integer' AND requested_io_slots>=0),
            floor_cpu_units REAL NOT NULL CHECK(typeof(floor_cpu_units) IN ('integer','real') AND floor_cpu_units>=0 AND floor_cpu_units<1e308),
            floor_physical_bytes INTEGER NOT NULL CHECK(typeof(floor_physical_bytes)='integer' AND floor_physical_bytes>=0),
            floor_commit_bytes INTEGER NOT NULL CHECK(typeof(floor_commit_bytes)='integer' AND floor_commit_bytes>=0),
            floor_io_slots INTEGER NOT NULL CHECK(typeof(floor_io_slots)='integer' AND floor_io_slots>=0),
            CHECK((allocation_kind IN ('direct','routed') AND reservation_id IS NOT NULL AND parent_execution_id IS NULL)
               OR (allocation_kind='parent' AND reservation_id IS NULL AND parent_execution_id IS NOT NULL)),
            CHECK((root_pid IS NULL AND root_created_filetime_100ns IS NULL)
               OR (root_pid>0 AND root_created_filetime_100ns IS NOT NULL))
        )""")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_managed_allocation ON managed_executions(allocation_kind,reservation_id) WHERE allocation_kind IN ('direct','routed')")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_state_heartbeat ON managed_executions(state,heartbeat_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_principal_state ON managed_executions(principal_id,state)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_managed_parent ON managed_executions(parent_execution_id)")
        if "cancel_requested_at" not in _columns(conn, "managed_executions"):
            conn.execute("ALTER TABLE managed_executions ADD COLUMN cancel_requested_at REAL")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise


def allocation_is_bound(conn: sqlite3.Connection, kind: str, reservation_id: str) -> bool:
    """Protect even an inconsistent tagged row; absent legacy schema stays legacy."""
    if kind not in _TABLES:
        raise ValueError("invalid_allocation_kind")
    table = _TABLES[kind]
    versioned = _check_version(conn)
    if _has_table(conn, table) and {"execution_id", "lifecycle_managed"} <= _columns(conn, table):
        row = conn.execute(f"SELECT execution_id,lifecycle_managed FROM {table} WHERE id=?", (reservation_id,)).fetchone()
        if row is not None and (row[0] is not None or row[1] != 0):
            return True
    if _has_table(conn, "managed_executions"):
        if not versioned:
            raise SchemaVersionError("orphan_adaptive_schema")
        return conn.execute("SELECT 1 FROM managed_executions WHERE allocation_kind=? AND reservation_id=?", (kind, reservation_id)).fetchone() is not None
    return False


def _bump_registry(conn: sqlite3.Connection) -> None:
    if conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1").rowcount != 1:
        raise SchemaVersionError("missing_adaptive_runtime")


def hold_expired_allocations(conn: sqlite3.Connection, kind: str, now: float) -> int:
    """TTL is health evidence, never a release condition. Caller owns transaction."""
    if kind not in _TABLES:
        raise ValueError("invalid_allocation_kind")
    if not math.isfinite(now):
        raise ValueError("invalid_time")
    if not _check_version(conn) or not _has_table(conn, _TABLES[kind]):
        return 0
    if not conn.in_transaction:
        raise LifecycleError("transaction_required")
    changed = conn.execute(f"""UPDATE managed_executions
        SET state=CASE WHEN state='LAUNCHING' THEN 'START_UNKNOWN' ELSE 'UNCERTAIN_HOLD' END,
            state_revision=state_revision+1,hold_reason='reservation_expired'
        WHERE allocation_kind=? AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED','START_UNKNOWN','UNCERTAIN_HOLD')
          AND reservation_id IN (SELECT id FROM {_TABLES[kind]} WHERE expires_at<=?)""", (kind, now)).rowcount
    if changed:
        _bump_registry(conn)
    return changed


def hold_bound_allocation(conn: sqlite3.Connection, kind: str, reservation_id: str,
                          reason: str, now: float) -> int:
    """A legacy release attempt can only mark uncertainty, never release."""
    if kind not in _TABLES or reason not in {"legacy_release_attempt", "identity_unknown", "heartbeat_lost", "reservation_expired"}:
        raise ValueError("invalid_hold_request")
    if not math.isfinite(now):
        raise ValueError("invalid_time")
    if not _check_version(conn):
        return 0
    if not conn.in_transaction:
        raise LifecycleError("transaction_required")
    changed = conn.execute("""UPDATE managed_executions
        SET state=CASE WHEN launch_in_flight=1 THEN 'START_UNKNOWN' ELSE 'UNCERTAIN_HOLD' END,
            state_revision=state_revision+1,hold_reason=?
        WHERE allocation_kind=? AND reservation_id=?
          AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED','START_UNKNOWN','UNCERTAIN_HOLD')""",
        (reason, kind, reservation_id)).rowcount
    if changed:
        _bump_registry(conn)
    return changed


@dataclass(frozen=True)
class LifecycleEvidence:
    """Result of trusted bounded verification, obtained before a DB transaction.

    This class is not accepted as a public command/CLI payload. Verifier code is
    part of the trusted runtime and must hold identity/Job handles through the
    decision. A never-started proof must also fence every launcher until the
    terminal CAS commits; an empty Job or missing root alone cannot prove it.
    launch_failed/user_code_started are tri-state observations, not caller
    assertions. P2 does not supply such a production implementation.
    """
    operation: str
    execution_id: str
    state_revision: int
    observation_id: str
    caller: ProcessIdentity
    guardian_epoch: str = ""
    job_name: str | None = None
    root: ProcessIdentity | None = None
    active_process_count: int | None = None
    process_ids: tuple[int, ...] | None = None
    launch_sealed: bool = False
    original_cpu_disabled: bool = False
    durable_manifest: bool = False
    legacy_exclusion: bool = False
    root_exited: bool = False
    parent_membership: bool = False
    user_code_started: bool | None = None
    launch_failed: bool | None = None

    def __post_init__(self):
        if self.operation not in {"register", "prepare", "claim", "bind_root", "root_exited", "finalize", "cancel", "start_failed"}:
            raise ValueError("invalid_evidence_operation")
        for name in ("execution_id", "observation_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
                raise ValueError("invalid_evidence_identity")
        if type(self.state_revision) is not int or self.state_revision < 0:
            raise ValueError("invalid_evidence_revision")
        if not isinstance(self.caller, ProcessIdentity) or (self.root is not None and not isinstance(self.root, ProcessIdentity)):
            raise ValueError("invalid_evidence_process_identity")
        if not isinstance(self.guardian_epoch, str) or len(self.guardian_epoch) > 128:
            raise ValueError("invalid_evidence_epoch")
        if self.job_name is not None and (not isinstance(self.job_name, str) or not 1 <= len(self.job_name) <= 256):
            raise ValueError("invalid_evidence_job")
        if self.active_process_count is not None and (type(self.active_process_count) is not int or not 0 <= self.active_process_count < 1 << 32):
            raise ValueError("invalid_evidence_process_count")
        if self.process_ids is not None:
            if (type(self.process_ids) is not tuple or len(self.process_ids) > 4096 or
                    any(type(pid) is not int or not 0 < pid < 1 << 32 for pid in self.process_ids) or
                    len(set(self.process_ids)) != len(self.process_ids)):
                raise ValueError("invalid_evidence_process_list")
        for name in ("launch_sealed", "original_cpu_disabled", "durable_manifest", "legacy_exclusion", "root_exited", "parent_membership"):
            if type(getattr(self, name)) is not bool:
                raise ValueError("invalid_evidence_boolean")
        for name in ("user_code_started", "launch_failed"):
            if getattr(self, name) is not None and type(getattr(self, name)) is not bool:
                raise ValueError("invalid_evidence_boolean")


def _unavailable_verifier(operation: str, record: Mapping[str, Any], caller: ProcessIdentity) -> LifecycleEvidence:
    raise LifecycleError("native_lifecycle_evidence_unavailable")


class LifecycleStore:
    def __init__(self, db_path: str | Path, *, verifier: Callable[[str, Mapping[str, Any], ProcessIdentity], LifecycleEvidence] | None = None,
                 local_host_id: str | None = None):
        self.db_path = Path(db_path)
        self.verifier = verifier or _unavailable_verifier
        # Capture the actual host once before acquiring any SQLite transaction.
        # Injection is a deterministic fixture seam, not a worker-supplied claim.
        self.local_host_id = local_host_identity() if local_host_id is None else local_host_id
        if not isinstance(self.local_host_id, str) or not self.local_host_id.strip():
            raise ValueError("local_host_id must be a nonempty string")
        self._local_context = {"local_host_id": self.local_host_id}
        with self._connection() as conn:
            migrate_schema(conn)

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                _check_version(conn)
                yield conn
                conn.commit()
            except BaseException:
                conn.rollback()
                raise

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: row[key] for key in row.keys() if key != "claim_token_hash"}

    @staticmethod
    def _get(conn: sqlite3.Connection, execution_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise LifecycleError("execution_not_found")
        return row

    def query(self, execution_id: str) -> dict[str, Any]:
        with self._connection() as conn:
            _check_version(conn)
            return self._public(self._get(conn, execution_id))

    @staticmethod
    def _caller(row: Mapping[str, Any], caller: ProcessIdentity) -> None:
        if not isinstance(caller, ProcessIdentity) or (caller.pid != row["wrapper_pid"] or
                str(caller.created_filetime_100ns) != row["wrapper_created_filetime_100ns"] or caller.logon_id != row["logon_id"]):
            raise LifecycleError("caller_identity_mismatch")

    def _proof(self, operation: str, row: Mapping[str, Any], caller: ProcessIdentity) -> LifecycleEvidence:
        self._caller(row, caller)
        evidence = self.verifier(operation, self._public(row), caller)
        if (not isinstance(evidence, LifecycleEvidence) or evidence.operation != operation or
                evidence.execution_id != row["execution_id"] or evidence.state_revision != row["state_revision"] or
                evidence.caller != caller or not isinstance(evidence.observation_id, str) or not evidence.observation_id):
            raise LifecycleError("invalid_lifecycle_evidence")
        return evidence

    @staticmethod
    def _cas(conn: sqlite3.Connection, execution_id: str, revision: int, updates: Mapping[str, Any]) -> sqlite3.Row:
        assignments = ",".join(key + "=?" for key in updates)
        result = conn.execute(f"UPDATE managed_executions SET {assignments},state_revision=state_revision+1 WHERE execution_id=? AND state_revision=?",
                              (*updates.values(), execution_id, revision))
        if result.rowcount != 1:
            raise LifecycleError("revision_conflict")
        _bump_registry(conn)
        return LifecycleStore._get(conn, execution_id)

    @staticmethod
    def _require_revision(row: Mapping[str, Any], expected_revision: int) -> None:
        if type(expected_revision) is not int or row["state_revision"] != expected_revision:
            raise LifecycleError("revision_conflict")

    def _require_allocation(self, conn: sqlite3.Connection, execution_id: str) -> None:
        try:
            validate_active_allocation(conn, execution_id, local_context=self._local_context)
        except AccountingError as error:
            raise LifecycleError(str(error)) from error

    def prepare_registration(self, spec: ExecutionSpec, *, caller: ProcessIdentity, now: float | None = None) -> dict[str, Any]:
        """Bind exact existing capacity in RESERVED; this does not prepare a Job."""
        if not isinstance(spec, ExecutionSpec):
            raise ValueError("execution_spec_required")
        now = time.time() if now is None else now
        if not math.isfinite(now):
            raise ValueError("invalid_time")
        kind = spec.reservation.kind.value
        row = {"execution_id": spec.execution_id, "task_id": spec.task_id, "session_id": spec.session_id,
               "principal_id": spec.principal_id, "logon_id": spec.wrapper_identity.logon_id,
               "allocation_kind": kind, "reservation_id": spec.reservation.id if kind != "parent" else None,
               "parent_execution_id": spec.parent_execution_id, "spec_hash": spec.spec_hash,
               "wrapper_pid": spec.wrapper_identity.pid, "wrapper_created_filetime_100ns": str(spec.wrapper_identity.created_filetime_100ns),
               "role": spec.role.value, "priority": spec.priority.value, "state": "RESERVED", "state_revision": 0,
               "created_at": now, "heartbeat_at": now}
        for name, value in spec.requested.to_dict().items():
            row["requested_" + name] = value
            row["floor_" + name] = value
        # Every attempt authenticates caller, including retries; a public spec is
        # not evidence that the process/session or parent membership is real.
        proof = self._proof("register", row, caller)
        raw_token = secrets.token_urlsafe(32)
        row["claim_token_hash"] = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        with self._transaction() as conn:
            previous = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?", (spec.execution_id,)).fetchone()
            if previous is not None:
                immutable = [key for key in row if key not in {"created_at", "heartbeat_at", "state", "state_revision", "claim_token_hash"} and not key.startswith("floor_")]
                if any(previous[key] != row[key] for key in immutable):
                    raise LifecycleError("execution_spec_mismatch")
                if previous["state"] not in TERMINAL_STATES:
                    self._require_allocation(conn, spec.execution_id)
                return {**self._public(previous), "claim_token": None, "registered": False}
            if kind == "parent":
                parent = self._get(conn, spec.parent_execution_id)
                if parent["logon_id"] != row["logon_id"] or parent["state"] not in {"RUNNING", "DRAINING"} or not proof.parent_membership:
                    raise LifecycleError("parent_membership_unverified")
                ancestor = parent
                visited = {spec.execution_id}
                for _ in range(128):
                    if ancestor["execution_id"] in visited:
                        raise LifecycleError("parent_cycle")
                    visited.add(ancestor["execution_id"])
                    if ancestor["logon_id"] != row["logon_id"] or ancestor["state"] not in {"RUNNING", "DRAINING"}:
                        raise LifecycleError("parent_membership_unverified")
                    if ancestor["allocation_kind"] != "parent":
                        break
                    ancestor = self._get(conn, ancestor["parent_execution_id"])
                else:
                    raise LifecycleError("parent_depth_exceeded")
                if any(row["requested_" + resource] > parent["requested_" + resource] for resource in spec.requested.to_dict()):
                    raise LifecycleError("nested_budget_upgrade_required")
            else:
                table = _TABLES[kind]
                if not _has_table(conn, table):
                    raise LifecycleError("allocation_not_found")
                allocation = conn.execute(f"SELECT * FROM {table} WHERE id=?", (spec.reservation.id,)).fetchone()
                if allocation is None:
                    raise LifecycleError("allocation_not_found")
                if allocation_is_bound(conn, kind, spec.reservation.id):
                    raise LifecycleError("allocation_already_bound")
                if allocation["spec_hash"] != spec.spec_hash:
                    raise LifecycleError("reservation_spec_mismatch")
                if allocation["expires_at"] <= now:
                    raise LifecycleError("reservation_expired")
                physical = allocation["physical_bytes"]
                physical = int(float(allocation["ram_gib"]) * (1 << 30)) if physical is None else physical
                commit = allocation["commit_bytes"] if allocation["commit_bytes"] is not None else physical
                io = allocation["io_slots"] if allocation["io_slots"] is not None else 1
                if (allocation["cpu_units"], physical, commit, io) != (spec.requested.cpu_units, spec.requested.physical_bytes, spec.requested.commit_bytes, spec.requested.io_slots):
                    raise LifecycleError("reservation_resource_mismatch")
                if kind == "routed":
                    if allocation["task_id"] != spec.task_id:
                        raise LifecycleError("allocation_task_mismatch")
                    worker = conn.execute("SELECT capabilities_json FROM workers WHERE id=?", (allocation["worker_id"],)).fetchone()
                    try:
                        capabilities = json.loads(worker[0]) if worker is not None else None
                    except (TypeError, ValueError):
                        capabilities = None
                    if resolve_worker_locality(capabilities, self._local_context) != "local":
                        raise LifecycleError("nonlocal_allocation")
                conn.execute(f"UPDATE {table} SET execution_id=?,lifecycle_managed=1,physical_bytes=?,commit_bytes=? WHERE id=?",
                             (spec.execution_id, physical, commit, spec.reservation.id))
            names = ",".join(row)
            conn.execute(f"INSERT INTO managed_executions({names}) VALUES({','.join('?' for _ in row)})", tuple(row.values()))
            self._require_allocation(conn, spec.execution_id)
            _bump_registry(conn)
            return {**self._public(self._get(conn, spec.execution_id)), "claim_token": raw_token, "registered": True}

    def mark_prepared(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int) -> dict[str, Any]:
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        proof = self._proof("prepare", snapshot, caller)
        if (not proof.guardian_epoch or not proof.job_name or not proof.original_cpu_disabled or
                not proof.durable_manifest or not proof.legacy_exclusion or type(proof.active_process_count) is not int or
                proof.active_process_count != 0 or proof.process_ids != ()):
            raise LifecycleError("job_preparation_unverified")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            if row["state"] != "RESERVED" or row["allocation_kind"] == "parent":
                raise LifecycleError("invalid_lifecycle_transition")
            self._require_allocation(conn, execution_id)
            enrolled = conn.execute("""SELECT count(*) FROM managed_executions
                WHERE allocation_kind IN ('direct','routed') AND job_name IS NOT NULL
                  AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED')""").fetchone()[0]
            if enrolled >= MAX_ENROLLED_JOBS:
                raise LifecycleError("managed_job_limit_reached")
            runtime = conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
            if runtime["active_logon_id"] not in {"", row["logon_id"]} or runtime["guardian_epoch"] not in {"", proof.guardian_epoch}:
                raise LifecycleError("guardian_identity_mismatch")
            conn.execute("UPDATE adaptive_runtime SET active_logon_id=?,guardian_epoch=? WHERE singleton=1", (row["logon_id"], proof.guardian_epoch))
            return self._public(self._cas(conn, execution_id, expected_revision, {"state": "PREPARED", "job_name": proof.job_name,
                                "guardian_epoch": proof.guardian_epoch, "coverage": "job_contained"}))

    def claim_launch(self, execution_id: str, *, caller: ProcessIdentity, claim_token: str, spec_hash: str, guardian_epoch: str, expected_revision: int) -> dict[str, Any]:
        if not isinstance(claim_token, str) or not 32 <= len(claim_token) <= 128 or not claim_token.isascii():
            raise LifecycleError("invalid_claim_token")
        snapshot = self.query(execution_id)
        # A consumed claim is a read-only retry, never another launch authority.
        # Authenticate its immutable binding without requiring a surviving Job.
        self._caller(snapshot, caller)
        token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
        with self._connection() as conn:
            token_row = self._get(conn, execution_id)
            if not hmac.compare_digest(token_row["claim_token_hash"], token_hash) or token_row["spec_hash"] != spec_hash:
                raise LifecycleError("claim_binding_mismatch")
            if token_row["guardian_epoch"] != guardian_epoch or not guardian_epoch:
                raise LifecycleError("guardian_identity_mismatch")
            if token_row["claim_consumed"]:
                return {**self._public(token_row), "launch_authorized": False, "duplicate": True}
        self._require_revision(snapshot, expected_revision)
        proof = self._proof("claim", snapshot, caller)
        if proof.guardian_epoch != guardian_epoch or not guardian_epoch:
            raise LifecycleError("guardian_identity_mismatch")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._caller(row, caller)
            if not hmac.compare_digest(row["claim_token_hash"], token_hash) or row["spec_hash"] != spec_hash:
                raise LifecycleError("claim_binding_mismatch")
            if row["guardian_epoch"] != guardian_epoch:
                raise LifecycleError("guardian_identity_mismatch")
            if row["claim_consumed"]:
                return {**self._public(row), "launch_authorized": False, "duplicate": True}
            self._require_revision(row, expected_revision)
            if row["state"] != "PREPARED" or row["launch_sealed"]:
                raise LifecycleError("invalid_lifecycle_transition")
            runtime = conn.execute("SELECT guardian_epoch,admission_barrier FROM adaptive_runtime WHERE singleton=1").fetchone()
            if runtime[0] != guardian_epoch or runtime[1] != "NONE":
                raise LifecycleError("launch_barrier_active")
            self._require_allocation(conn, execution_id)
            updated = self._cas(conn, execution_id, expected_revision, {"state": "LAUNCHING", "claim_consumed": 1, "launch_in_flight": 1})
            return {**self._public(updated), "launch_authorized": True, "duplicate": False}

    @staticmethod
    def _require_never_started(row: Mapping[str, Any], proof: LifecycleEvidence) -> None:
        """A trusted launch fence plus positive evidence, never absence alone.

        The verifier retains the launch fence through the caller's transaction.
        CAS then invalidates the claim durably. For a subspan there is no own Job
        to empty: sealing this child's launch must not close its parent's Job.
        """
        if (proof.user_code_started is not False or not proof.launch_sealed or
                proof.root is not None or row["root_pid"] is not None or row["root_outcome"] is not None or
                proof.guardian_epoch != row["guardian_epoch"] or proof.job_name != row["job_name"]):
            raise LifecycleError("never_started_unverified")
        if row["job_name"] is not None:
            if (not row["guardian_epoch"] or type(proof.active_process_count) is not int or
                    proof.active_process_count != 0 or proof.process_ids != ()):
                raise LifecycleError("never_started_unverified")
        elif proof.active_process_count is not None or proof.process_ids is not None:
            # No Job exists for RESERVED/subspan records. Do not accept an
            # invented empty Job query or use the running parent's counts.
            raise LifecycleError("never_started_unverified")
        if row["allocation_kind"] == "parent" and not proof.parent_membership:
            raise LifecycleError("parent_membership_unverified")

    @staticmethod
    def _require_no_live_descendants(conn: sqlite3.Connection, execution_id: str) -> None:
        # A correctly registered prelaunch record cannot already have running
        # subspans. Inconsistent linkage must not silently release their source.
        live = conn.execute("""WITH RECURSIVE descendants(execution_id) AS (
            SELECT execution_id FROM managed_executions WHERE parent_execution_id=?
            UNION SELECT m.execution_id FROM managed_executions m JOIN descendants d ON m.parent_execution_id=d.execution_id)
            SELECT 1 FROM managed_executions m JOIN descendants d ON m.execution_id=d.execution_id
            WHERE m.state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED') LIMIT 1""",
            (execution_id,)).fetchone()
        if live is not None:
            raise LifecycleError("live_descendants_unreconciled")

    def _finish_before_start(self, conn: sqlite3.Connection, row: Mapping[str, Any], *,
                             expected_revision: int, state: str, now: float) -> dict[str, Any]:
        if row["job_name"] is not None:
            runtime = conn.execute("SELECT guardian_epoch,active_logon_id FROM adaptive_runtime WHERE singleton=1").fetchone()
            if runtime is None or runtime[0] != row["guardian_epoch"] or runtime[1] != row["logon_id"]:
                raise LifecycleError("guardian_identity_mismatch")
        self._require_no_live_descendants(conn, row["execution_id"])
        if row["allocation_kind"] != "parent":
            self._archive_allocation(conn, row, now, outcome="managed_" + state.lower())
        updates = {"state": state, "finished_at": now, "launch_sealed": 1,
                   "launch_in_flight": 0, "claim_consumed": 1, "claim_token_hash": "", "hold_reason": None}
        if state == "CANCELLED_BEFORE_START":
            updates["cancel_requested_at"] = now
        return self._public(self._cas(conn, row["execution_id"], expected_revision, updates))

    def cancel_before_start(self, execution_id: str, *, caller: ProcessIdentity,
                            expected_revision: int, now: float | None = None) -> dict[str, Any]:
        """Cancel one proven prelaunch execution, or durably request reconciliation.

        This does not signal, kill, release, renew, or retry launched work. A
        post-claim cancellation remains pending even if the current Job is empty.
        The caller must retry a revision conflict against freshly queried state.
        """
        now = time.time() if now is None else now
        if not math.isfinite(now):
            raise ValueError("invalid_time")
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        self._caller(snapshot, caller)
        if snapshot["state"] == "CANCELLED_BEFORE_START":
            return {**snapshot, "cancelled": True, "reason": "cancelled_before_start"}
        if snapshot["state"] in TERMINAL_STATES:
            raise LifecycleError("invalid_lifecycle_transition")
        proof = self._proof("cancel", snapshot, caller)
        prelaunch = (snapshot["state"] in {"RESERVED", "PREPARED"} and
                     not snapshot["claim_consumed"] and not snapshot["launch_in_flight"])
        if prelaunch:
            self._require_never_started(snapshot, proof)
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            self._caller(row, caller)
            if not prelaunch:
                if row["cancel_requested_at"] is None:
                    row = self._cas(conn, execution_id, expected_revision, {"cancel_requested_at": now})
                return {**self._public(row), "cancelled": False, "reason": "cancel_pending_reconciliation"}
            self._require_never_started(row, proof)
            done = self._finish_before_start(conn, row, expected_revision=expected_revision,
                                            state="CANCELLED_BEFORE_START", now=now)
            return {**done, "cancelled": True, "reason": "cancelled_before_start"}

    def mark_start_failed(self, execution_id: str, *, caller: ProcessIdentity,
                          expected_revision: int, now: float | None = None) -> dict[str, Any]:
        """Close an attempt positively proven to have failed before user code.

        An ACK loss, timeout, root exit, or absent process identity is insufficient.
        A later retry requires a new execution attempt; this claim is destroyed.
        """
        now = time.time() if now is None else now
        if not math.isfinite(now):
            raise ValueError("invalid_time")
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        self._caller(snapshot, caller)
        if snapshot["state"] == "START_FAILED":
            return snapshot
        if snapshot["state"] not in {"RESERVED", "PREPARED", "LAUNCHING", "START_UNKNOWN", "UNCERTAIN_HOLD"}:
            raise LifecycleError("invalid_lifecycle_transition")
        proof = self._proof("start_failed", snapshot, caller)
        if proof.launch_failed is not True:
            raise LifecycleError("launch_failure_unverified")
        self._require_never_started(snapshot, proof)
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            self._caller(row, caller)
            self._require_never_started(row, proof)
            return self._finish_before_start(conn, row, expected_revision=expected_revision,
                                             state="START_FAILED", now=now)

    def bind_root(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int) -> dict[str, Any]:
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        proof = self._proof("bind_root", snapshot, caller)
        if (not isinstance(proof.root, ProcessIdentity) or proof.root.logon_id != caller.logon_id or
                proof.guardian_epoch != snapshot["guardian_epoch"] or proof.job_name != snapshot["job_name"] or not proof.launch_sealed):
            raise LifecycleError("root_binding_unverified")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            if row["state"] not in {"LAUNCHING", "START_UNKNOWN"} or not row["launch_in_flight"]:
                raise LifecycleError("invalid_lifecycle_transition")
            return self._public(self._cas(conn, execution_id, expected_revision, {"state": "RUNNING", "root_pid": proof.root.pid,
                "root_created_filetime_100ns": str(proof.root.created_filetime_100ns), "launch_in_flight": 0, "launch_sealed": 1}))

    def mark_root_exited(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int, exit_code: int) -> dict[str, Any]:
        if type(exit_code) is not int or not -(1 << 31) <= exit_code < (1 << 32):
            raise ValueError("invalid_exit_code")
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        proof = self._proof("root_exited", snapshot, caller)
        if (not proof.root_exited or proof.root is None or proof.root.pid != snapshot["root_pid"] or
                str(proof.root.created_filetime_100ns) != snapshot["root_created_filetime_100ns"] or proof.root.logon_id != snapshot["logon_id"]):
            raise LifecycleError("root_exit_unverified")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            if row["state"] not in {"RUNNING", "UNCERTAIN_HOLD"}:
                raise LifecycleError("invalid_lifecycle_transition")
            return self._public(self._cas(conn, execution_id, expected_revision, {"state": "DRAINING", "root_outcome": str(exit_code)}))

    def hold(self, execution_id: str, *, expected_revision: int, reason: str) -> dict[str, Any]:
        if reason not in {"identity_unknown", "heartbeat_lost", "reservation_expired", "launch_ack_lost", "recovery_unverified"}:
            raise ValueError("invalid_hold_reason")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            if row["state"] in TERMINAL_STATES:
                raise LifecycleError("invalid_lifecycle_transition")
            state = "START_UNKNOWN" if row["launch_in_flight"] else "UNCERTAIN_HOLD"
            return self._public(self._cas(conn, execution_id, expected_revision, {"state": state, "hold_reason": reason}))

    def finalize_if_empty(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int, now: float | None = None) -> dict[str, Any]:
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        self._caller(snapshot, caller)
        if snapshot["state"] == "FINISHED":
            # Replaying an already committed result makes no OS/ledger change;
            # the original named Job may no longer exist after verified empty.
            return snapshot
        proof = self._proof("finalize", snapshot, caller)
        if (snapshot["allocation_kind"] == "parent" or not snapshot["job_name"] or proof.job_name != snapshot["job_name"] or
                proof.guardian_epoch != snapshot["guardian_epoch"] or type(proof.active_process_count) is not int or proof.active_process_count != 0 or
                proof.process_ids != () or not proof.launch_sealed):
            raise LifecycleError("job_empty_unverified")
        now = time.time() if now is None else now
        if not math.isfinite(now):
            raise ValueError("invalid_time")
        with self._transaction() as conn:
            row = self._get(conn, execution_id)
            self._require_revision(row, expected_revision)
            if row["state"] in TERMINAL_STATES:
                return self._public(row)
            if row["state"] not in {"RUNNING", "DRAINING", "START_UNKNOWN", "UNCERTAIN_HOLD"} or not proof.launch_sealed:
                raise LifecycleError("invalid_lifecycle_transition")
            # Parent positive-empty proof closes all nested subspans atomically.
            descendants = conn.execute("""WITH RECURSIVE descendants(execution_id) AS (
                SELECT execution_id FROM managed_executions WHERE parent_execution_id=?
                UNION SELECT m.execution_id FROM managed_executions m JOIN descendants d ON m.parent_execution_id=d.execution_id)
                SELECT execution_id FROM descendants""", (execution_id,)).fetchall()
            for child in descendants:
                conn.execute("UPDATE managed_executions SET state='FINISHED',state_revision=state_revision+1,finished_at=?,launch_sealed=1,launch_in_flight=0 WHERE execution_id=? AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED')", (now, child[0]))
            self._archive_allocation(conn, row, now)
            return self._public(self._cas(conn, execution_id, expected_revision, {"state": "FINISHED", "finished_at": now,
                "launch_sealed": 1, "launch_in_flight": 0}))

    @staticmethod
    def _archive_allocation(conn: sqlite3.Connection, row: Mapping[str, Any], now: float,
                            *, outcome: str = "managed_finished") -> None:
        if outcome not in {"managed_finished", "managed_cancelled_before_start", "managed_start_failed"}:
            raise LifecycleError("invalid_archive_outcome")
        table = _TABLES[row["allocation_kind"]]
        allocation = conn.execute(f"SELECT * FROM {table} WHERE id=? AND execution_id=? AND lifecycle_managed=1", (row["reservation_id"], row["execution_id"])).fetchone()
        if allocation is None:
            raise LifecycleError("allocation_binding_missing")
        if table == "reservations":
            conn.execute("""INSERT INTO executions(reservation_id,request_key,owner_pid,repo,command_signature,
                resource_class,priority,cpu_units,ram_gib,io_slots,started_at,ended_at,outcome)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (allocation["id"], allocation["request_key"], allocation["owner_pid"],
                allocation["repo"], allocation["command_signature"], allocation["resource_class"], allocation["priority"],
                allocation["cpu_units"], allocation["ram_gib"], allocation["io_slots"], allocation["created_at"], now, outcome))
        else:
            # Do not copy potentially private routed metadata to a new archive.
            conn.execute("""INSERT INTO routed_executions(reservation_id,task_id,worker_id,failure_domain,
                capacity_scope,capacity_pool,spec_hash,ram_gib,cpu_units,disk_gib,started_at,ended_at,outcome,metadata_json)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (allocation["id"], allocation["task_id"], allocation["worker_id"],
                allocation["failure_domain"], allocation["capacity_scope"], allocation["capacity_pool"], allocation["spec_hash"],
                allocation["ram_gib"], allocation["cpu_units"], allocation["disk_gib"], allocation["created_at"], now, outcome, "{}"))
        if conn.execute(f"DELETE FROM {table} WHERE id=? AND execution_id=?", (row["reservation_id"], row["execution_id"])).rowcount != 1:
            raise LifecycleError("allocation_binding_missing")
