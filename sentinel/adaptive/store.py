"""Additive, fail-closed lifecycle ledger. No process launch or OS control.

Native evidence is deliberately unavailable by default. An evidence provider
must retain its verified handles and launch fences through transaction completion.
L1 tests explicitly inject a fixture scope; no bare evidence assertion from a
CLI or verifier callback is adapted into production lifecycle authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import re
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Callable, ContextManager, Mapping, Any
from uuid import UUID

from sentinel.accounting import (
    AccountingError, local_host_identity, resolve_worker_locality,
    validate_active_allocation,
)
from .contracts import (
    AllocationKind, ContractViolation, ExecutionSpec, ProcessIdentity, RecoveryManifest,
    ReservationRef, ResourceDemand, MAX_ENROLLED_JOBS,
)
from .capacity_schema import prepare_capacity_schema
from .writers import migrate_writer_fence

SCHEMA_VERSION = 1
TERMINAL_STATES = frozenset({"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"})
_TABLES = {"direct": "reservations", "routed": "worker_reservations"}
_STATES = ("NEW", "QUEUED", "RESERVED", "PREPARED", "LAUNCHING", "RUNNING",
           "DRAINING", "FINISHED", "CANCELLED_BEFORE_START", "START_FAILED",
           "START_UNKNOWN", "UNCERTAIN_HOLD")


class LifecycleError(RuntimeError):
    """Stable error codes suitable for a sanitized caller response."""


class ControlSlotRejected(LifecycleError):
    """This slot attempt was rejected and its rollback/cleanup verified.

    This is not reconciliation of any earlier uncertain attempt using the same
    episode ID. A caller may mark never-acquired only for its initial attempt;
    it must preserve previously acquired or uncertain episode responsibility.
    """


class SchemaVersionError(LifecycleError):
    pass


def prelaunch_record_hash(row: Mapping[str, Any], *, claim_token_hash: str,
                          allocation: Mapping[str, Any]) -> str:
    """Bind a native prelaunch observation to immutable ledger contents.

    This digest is not launch authority. The evidence provider must retain the
    current native identity and irrevocably seal an unexported launch credential.
    Heartbeats and the allocation deadline may advance without changing custody.
    Everything else is rechecked under the writer transaction before release.
    """
    if (not isinstance(claim_token_hash, str) or len(claim_token_hash) != 64 or
            any(c not in "0123456789abcdef" for c in claim_token_hash)):
        raise LifecycleError("invalid_prelaunch_record")
    try:
        record = dict(row)
        source = dict(allocation)
        record.pop("heartbeat_at", None)
        # The independent IPC credential authenticates queries, not launch
        # custody. Public proof snapshots intentionally omit it. The immutable
        # admission binding remains in this digest, and admission retries still
        # compare the private key itself; do not export it to fill a proof.
        record.pop("ipc_auth_key", None)
        record["claim_token_hash"] = claim_token_hash
        source.pop("heartbeat_at", None)
        source.pop("expires_at", None)
        # SQL compatibility bookkeeping may advance independently of native
        # launch custody. Keep writer_protocol bound, but not its revision.
        source.pop("writer_revision", None)
        encoded = json.dumps({"domain": "sentinel-prelaunch-record-v1",
                              "record": record, "allocation": source},
                             sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise LifecycleError("invalid_prelaunch_record") from None
    if len(encoded) > 65536:
        raise LifecycleError("invalid_prelaunch_record")
    return hashlib.sha256(encoded).hexdigest()


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


def migrate_schema(conn: sqlite3.Connection, *, in_transaction: bool = False) -> None:
    """Serialize the additive migration without committing caller-owned work.

    Constructors use ``in_transaction=True`` to cover first table creation and
    fence installation under one writer lock. The default still owns its whole
    transaction and rejects nesting, preserving existing callers' semantics.
    """
    if in_transaction:
        if not conn.in_transaction:
            raise LifecycleError("migration_requires_transaction")
    else:
        if conn.in_transaction:
            raise LifecycleError("migration_requires_own_transaction")
        conn.execute("BEGIN IMMEDIATE")
    try:
        existing = _check_version(conn)
        # Pre-create both real ledgers before installing persistent guards. An
        # old opposite constructor must never be able to CREATE an unguarded
        # capacity table after a managed obligation has already been admitted.
        prepare_capacity_schema(conn)
        # No third capacity store: metadata binds the two existing ledgers.
        for table in _TABLES.values():
            if not _has_table(conn, table):
                continue
            present = _columns(conn, table)
            additions = {"execution_id": "TEXT", "lifecycle_managed": "INTEGER NOT NULL DEFAULT 0",
                         "physical_bytes": "INTEGER", "commit_bytes": "INTEGER"}
            if table == "reservations":
                additions["managed_spec_hash"] = "TEXT"
            if table == "worker_reservations":
                additions["io_slots"] = "INTEGER"
            for name, sql_type in additions.items():
                if name not in present:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
            conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS idx_{table}_execution ON {table}(execution_id) WHERE execution_id IS NOT NULL")
        if _has_table(conn, "reservations") and "tool_use_id" in _columns(conn, "reservations"):
            # The discriminator survives queue deletion: even an older binary
            # retrying a cancelled/expired managed intent cannot INSERT a legacy
            # allocation. Native metadata must be supplied in the same INSERT.
            for trigger, event in (("managed_direct_insert_guard", "INSERT"),
                    ("managed_direct_update_guard", "UPDATE OF tool_use_id,lifecycle_managed,execution_id,managed_spec_hash")):
                conn.execute(f"""CREATE TRIGGER IF NOT EXISTS {trigger}
                    BEFORE {event} ON reservations
                    WHEN substr(NEW.tool_use_id,1,11)='managed-v1:' AND (
                        NEW.lifecycle_managed IS NOT 1 OR NEW.execution_id IS NULL OR
                        NEW.execution_id != substr(NEW.tool_use_id,12) OR
                        length(NEW.managed_spec_hash) IS NOT 64)
                    BEGIN SELECT RAISE(ABORT,'managed_admission_context_required'); END""")
        # Queue and reservation projections share the explicit Commit request.
        # Keep the column check under this same writer lock: concurrent legacy
        # constructors must not both observe a missing column before ALTER.
        if _has_table(conn, "queue"):
            present = _columns(conn, "queue")
            for name, sql_type in {"commit_bytes": "INTEGER", "managed_execution_id": "TEXT",
                                   "managed_binding_hash": "TEXT"}.items():
                if name not in present:
                    conn.execute(f"ALTER TABLE queue ADD COLUMN {name} {sql_type}")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_queue_managed_execution ON queue(managed_execution_id) WHERE managed_execution_id IS NOT NULL")
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
        # Binding is initialized only by a verified policy operation, never by
        # an ordinary constructor. Partial/malformed existing values fail shut.
        for name in ("policy_instance_id", "policy_logon_id", "policy_entry_nonce"):
            if name not in _columns(conn, "adaptive_runtime"):
                conn.execute(f"ALTER TABLE adaptive_runtime ADD COLUMN {name} TEXT")
        if "policy_binding_initialized" not in _columns(conn, "adaptive_runtime"):
            conn.execute("ALTER TABLE adaptive_runtime ADD COLUMN policy_binding_initialized INTEGER NOT NULL DEFAULT 0 CHECK(policy_binding_initialized IN (0,1))")
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
        if "admission_binding_hash" not in _columns(conn, "managed_executions"):
            conn.execute("ALTER TABLE managed_executions ADD COLUMN admission_binding_hash TEXT")
        if "ipc_auth_key" not in _columns(conn, "managed_executions"):
            # Old rows deliberately stay NULL: constructing a store must not
            # mint a new cross-process credential for an existing execution.
            conn.execute("ALTER TABLE managed_executions ADD COLUMN ipc_auth_key BLOB")
        if "job_nonce" not in _columns(conn, "managed_executions"):
            # No nonce is manufactured for a legacy provider's existing Job.
            # New native owners must register a fresh scope before OS creation.
            conn.execute("ALTER TABLE managed_executions ADD COLUMN job_nonce TEXT")
        # Three fixed operation slots per execution, not a capacity ledger or
        # unbounded response cache. No claim secret, raw payload or handle is
        # persisted. An uncertain first insert never grants an OS side effect.
        conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_launch_requests (
            execution_id TEXT NOT NULL,
            operation TEXT NOT NULL CHECK(operation IN ('PrepareExecution','ClaimLaunch','BindRoot')),
            request_id TEXT NOT NULL UNIQUE,
            payload_hash TEXT NOT NULL,
            spec_hash TEXT NOT NULL,
            guardian_epoch TEXT NOT NULL,
            PRIMARY KEY(execution_id,operation),
            FOREIGN KEY(execution_id) REFERENCES managed_executions(execution_id)
        )""")
        from .control_slot import ControlSlotError, migrate_control_slot_schema
        try:
            migrate_control_slot_schema(conn)
        except ControlSlotError as error:
            raise SchemaVersionError(str(error)) from error
        migrate_writer_fence(conn)
        if not in_transaction:
            conn.commit()
    except BaseException:
        if not in_transaction:
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
    assertions. The current-process unexported-credential cancellation provider
    is deliberately narrower than a native Job lifecycle provider.

    job_creation_never_attempted is an in-process creation fence observation,
    never inferred from a missing object. For cancellation, that capability is
    irrevocably sealed through the terminal CAS; it cannot be reconstructed
    from a manifest or returned by any owner that has attempted native Create.

    For finalization, current_cpu_disabled is a current native Query result,
    not the original state. recovery_manifest_settled verifies the durable
    manifest for this exact execution/nonce/Job has no unresolved intent or
    active applied cap. Both require the same retained policy then Job mutation
    fences, through terminal CAS/archive commit or rollback; no writer may
    invalidate either observation while SQLite waits or the release commits.

    A heartbeat authenticates the actual retained guardian rather than claiming
    the wrapper is alive. Its provider retains policy/Job fences, durable exact
    manifest, root identity and consistent current Job count/list through the
    observation transaction. Even an empty observation grants no release.
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
    prelaunch_record_hash: str | None = None
    current_cpu_disabled: bool = False
    recovery_manifest_settled: bool = False
    job_nonce: str | None = None
    job_creation_never_attempted: bool = False

    def __post_init__(self):
        if self.operation not in {"register", "register_scope", "prepare", "claim", "bind_root", "root_exited", "finalize", "cancel", "start_failed",
                                  "control_begin", "control_restore", "heartbeat"}:
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
        if self.job_nonce is not None and (not isinstance(self.job_nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", self.job_nonce)):
            raise ValueError("invalid_evidence_job_nonce")
        if self.active_process_count is not None and (type(self.active_process_count) is not int or not 0 <= self.active_process_count < 1 << 32):
            raise ValueError("invalid_evidence_process_count")
        if self.process_ids is not None:
            if (type(self.process_ids) is not tuple or len(self.process_ids) > 4096 or
                    any(type(pid) is not int or not 0 < pid < 1 << 32 for pid in self.process_ids) or
                    len(set(self.process_ids)) != len(self.process_ids)):
                raise ValueError("invalid_evidence_process_list")
        for name in ("launch_sealed", "original_cpu_disabled", "durable_manifest", "legacy_exclusion", "root_exited", "parent_membership",
                     "current_cpu_disabled", "recovery_manifest_settled", "job_creation_never_attempted"):
            if type(getattr(self, name)) is not bool:
                raise ValueError("invalid_evidence_boolean")
        for name in ("user_code_started", "launch_failed"):
            if getattr(self, name) is not None and type(getattr(self, name)) is not bool:
                raise ValueError("invalid_evidence_boolean")
        if self.prelaunch_record_hash is not None:
            if (self.operation != "cancel" or not isinstance(self.prelaunch_record_hash, str) or
                    len(self.prelaunch_record_hash) != 64 or
                    any(c not in "0123456789abcdef" for c in self.prelaunch_record_hash)):
                raise ValueError("invalid_prelaunch_record_hash")


def _unavailable_evidence_provider(operation: str, record: Mapping[str, Any],
                                   caller: ProcessIdentity) -> ContextManager[LifecycleEvidence]:
    raise LifecycleError("native_lifecycle_evidence_unavailable")


@contextmanager
def _coverage_read_transaction(db_path):
    """One bounded read-only snapshot; never migrate or recreate a lost DB."""
    conn = None
    deadline = time.monotonic() + .25
    try:
        try:
            # The caller already pinned the absolute path before authenticating
            # the admission. Never re-resolve a relative selector after that.
            uri = Path(db_path).as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=.25, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
            conn.execute("BEGIN")
            if not _check_version(conn):
                raise LifecycleError("coverage_registry_unavailable")
            yield conn
            if time.monotonic() >= deadline:
                raise LifecycleError("coverage_read_timeout")
        except sqlite3.Error as error:
            code = getattr(error, "sqlite_errorcode", None)
            reason = ("coverage_read_timeout" if code == sqlite3.SQLITE_INTERRUPT else
                      "coverage_database_busy" if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else
                      "coverage_registry_unavailable")
            raise LifecycleError(reason) from None
        except (OSError, TypeError, ValueError, OverflowError):
            raise LifecycleError("coverage_registry_unavailable") from None
    except BaseException as primary:
        if conn is not None:
            try:
                conn.close()
            except BaseException:
                primary.add_note("coverage_reader_cleanup_failed")
        raise
    else:
        try:
            conn.close()
        except BaseException:
            raise LifecycleError("coverage_reader_cleanup_failed") from None


def _registration_row(spec: ExecutionSpec, now: float) -> dict[str, Any]:
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
    return row


def _admitted_row(admission, reservation_id: str, now: float) -> dict[str, Any]:
    # Internal transaction boundary, never a deserialized CLI authority.
    from .admission import ManagedAdmissionSnapshot
    if not isinstance(admission, ManagedAdmissionSnapshot):
        raise LifecycleError("managed_admission_context_required")
    spec = ExecutionSpec(admission.execution_id, admission.task_id, admission.session_id,
        admission.principal_id, ReservationRef(AllocationKind.DIRECT, reservation_id), None,
        admission.spec_hash, admission.role, admission.priority, admission.requested, admission.wrapper_identity)
    row = _registration_row(spec, now)
    if type(admission.ipc_auth_key) is not bytes or len(admission.ipc_auth_key) != 32:
        raise LifecycleError("managed_admission_binding_mismatch")
    row.update(admission_binding_hash=admission.binding_hash, claim_token_hash=admission.claim_token_hash,
               ipc_auth_key=admission.ipc_auth_key)
    return row


def _admission_result(row: Mapping[str, Any], request_key: str, *, reused: bool) -> dict[str, Any]:
    # Capacity approval is separate from the later one-use Job launch claim.
    allowed = row["state"] in {"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING"}
    result = dict(allowed=allowed, reservation_id=row["reservation_id"], request_key=request_key,
                  execution_id=row["execution_id"], state=row["state"], state_revision=row["state_revision"],
                  reused=reused, launch_authorized=False)
    if not allowed:
        result["reason"] = "managed_execution_terminal" if row["state"] in TERMINAL_STATES else "managed_execution_held"
    return result


def retry_managed_admission(conn: sqlite3.Connection, admission, *, local_context) -> dict[str, Any] | None:
    """Replay an exact self-owned admission; never mint a token or renew a lease."""
    if not conn.in_transaction:
        raise LifecycleError("transaction_required")
    _check_version(conn)
    row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?", (admission.execution_id,)).fetchone()
    if row is None:
        return None
    expected = _admitted_row(admission, row["reservation_id"], row["created_at"])
    mutable = {"state", "state_revision", "heartbeat_at"}
    # Verified prelaunch closure deliberately destroys the launch credential.
    # Its immutable admission digest still binds the original context/secret;
    # returning the terminal outcome must not require restoring that credential.
    if (row["state"] in {"CANCELLED_BEFORE_START", "START_FAILED"} and row["claim_token_hash"] == "" and
            row["claim_consumed"] == 1 and row["launch_sealed"] == 1 and row["launch_in_flight"] == 0):
        mutable.add("claim_token_hash")
    if any(row[key] != value for key, value in expected.items() if key not in mutable and not key.startswith("floor_")):
        raise LifecycleError("managed_admission_binding_mismatch")
    if row["state"] not in TERMINAL_STATES:
        try:
            source = validate_active_allocation(conn, row["execution_id"], local_context=local_context)
        except AccountingError as error:
            raise LifecycleError(str(error)) from error
        allocation = source["allocation"]
        if allocation["request_key"] != admission.request.request_key or allocation["spec_hash"] != admission.request.spec_hash:
            raise LifecycleError("managed_admission_binding_mismatch")
    return _admission_result(row, admission.request.request_key, reused=True)


def commit_managed_admission(conn: sqlite3.Connection, admission, reservation_id: str, *, now: float,
                             local_context, policy_coordinator=None) -> dict[str, Any]:
    """Bind a new direct reservation inside its admission transaction.

    The self-wrapper context is authenticated before acquiring the transaction.
    No native calls, migration, IPC or second connection is performed here.
    """
    if not conn.in_transaction:
        raise LifecycleError("transaction_required")
    from .policy import PolicyCoordinator, PolicyError
    if type(policy_coordinator) is not PolicyCoordinator:
        raise LifecycleError("policy_scope_not_held")
    try:
        guard = policy_coordinator.assert_held()
        if guard.binding.logon_id != admission.wrapper_identity.logon_id:
            raise PolicyError("policy_logon_mismatch")
        policy_coordinator.revalidate(conn, guard)
    except PolicyError as error:
        raise LifecycleError(str(error)) from error
    _check_version(conn)
    allocation = conn.execute("SELECT * FROM reservations WHERE id=?", (reservation_id,)).fetchone()
    if (allocation is None or allocation["execution_id"] != admission.execution_id or
            allocation["lifecycle_managed"] != 1 or allocation["managed_spec_hash"] != admission.spec_hash or
            allocation["request_key"] != admission.request.request_key or
            allocation["spec_hash"] != admission.request.spec_hash or
            allocation["owner_pid"] != admission.wrapper_identity.pid or
            allocation["owner_started"] != admission.request.owner_started):
        raise LifecycleError("managed_admission_binding_mismatch")
    row = _admitted_row(admission, reservation_id, now)
    names = ",".join(row)
    conn.execute(f"INSERT INTO managed_executions({names}) VALUES({','.join('?' for _ in row)})", tuple(row.values()))
    changed = conn.execute("""UPDATE reservations SET execution_id=?,lifecycle_managed=1,
        physical_bytes=?,commit_bytes=?,managed_spec_hash=?,writer_protocol=1,writer_revision=writer_revision+1
        WHERE id=? AND execution_id=? AND lifecycle_managed=1 AND managed_spec_hash=?""",
        (admission.execution_id, admission.requested.physical_bytes, admission.requested.commit_bytes,
         admission.spec_hash, reservation_id, admission.execution_id, admission.spec_hash)).rowcount
    if changed != 1:
        raise LifecycleError("managed_admission_binding_mismatch")
    try:
        validate_active_allocation(conn, admission.execution_id, local_context=local_context)
    except AccountingError as error:
        raise LifecycleError(str(error)) from error
    _bump_registry(conn)
    return _admission_result(row, admission.request.request_key, reused=False)


@dataclass(frozen=True)
class _IpcAuthRecord:
    """Trusted service-local authentication material, never a wire response.

    The key is an actual shared secret. Its presence proves no native peer
    identity and confers no lifecycle mutation or launch authority.
    """
    execution_id: str
    spec_hash: str
    wrapper_identity: ProcessIdentity
    allocation_kind: str
    reservation_id: str
    admission_binding_hash: str
    ipc_auth_key: bytes = field(repr=False)


def _ipc_query_arguments(execution_id, timeout_ms):
    try:
        parsed = UUID(execution_id) if isinstance(execution_id, str) else None
        valid = parsed is not None and parsed.int != 0 and str(parsed) == execution_id
    except (ValueError, AttributeError):
        valid = False
    if not valid or type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
        raise LifecycleError("invalid_ipc_query")


@contextmanager
def _ipc_read_transaction(db_path, *, timeout_ms):
    """No migration/creation; a short read snapshot with bounded SQL work.

    As with the diagnostic reader, a stalled filesystem open cannot be
    preempted by SQLite's lock/progress deadlines. Native peer handles belong
    to the service and must remain retained outside this entire scope.
    """
    conn = None
    deadline = time.monotonic() + timeout_ms / 1000
    try:
        try:
            uri = Path(db_path).absolute().as_uri() + "?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=timeout_ms / 1000, isolation_level=None)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA query_only=ON")
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 100)
            conn.execute("BEGIN")
            if not _has_table(conn, "adaptive_runtime"):
                raise LifecycleError("ipc_registry_unavailable")
            versions = conn.execute("""SELECT
                CASE WHEN typeof(schema_version)='integer' THEN schema_version END,
                CASE WHEN typeof(protocol_version)='integer' THEN protocol_version END
                FROM adaptive_runtime LIMIT 2""").fetchall()
            if len(versions) != 1 or versions[0][0] != SCHEMA_VERSION or versions[0][1] != 1:
                raise LifecycleError("ipc_registry_unavailable")
            yield conn
            if time.monotonic() >= deadline:
                raise LifecycleError("ipc_query_timeout")
        except sqlite3.Error as error:
            code = getattr(error, "sqlite_errorcode", None)
            reason = ("ipc_query_timeout" if code == sqlite3.SQLITE_INTERRUPT else
                      "ipc_database_busy" if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else
                      "ipc_registry_unavailable")
            raise LifecycleError(reason) from None
        except (OSError, TypeError, ValueError, OverflowError):
            raise LifecycleError("ipc_registry_unavailable") from None
    except BaseException as primary:
        if conn is not None:
            try:
                conn.close()
            except BaseException:
                primary.add_note("ipc_reader_cleanup_failed")
        raise
    else:
        try:
            conn.close()
        except BaseException:
            raise LifecycleError("ipc_reader_cleanup_failed") from None


def _ipc_auth_record(conn, execution_id):
    # Bound private reads as well as diagnostics: a damaged large BLOB/text
    # value must not become an unbounded service allocation or an error value.
    rows = conn.execute("""SELECT execution_id,
        substr(spec_hash,1,65) AS spec_hash,
        CASE WHEN typeof(wrapper_pid)='integer' THEN wrapper_pid END AS wrapper_pid,
        substr(wrapper_created_filetime_100ns,1,21) AS wrapper_created_filetime_100ns,
        substr(logon_id,1,129) AS logon_id,
        substr(allocation_kind,1,8) AS allocation_kind,
        substr(reservation_id,1,129) AS reservation_id,
        parent_execution_id IS NULL AS no_parent,
        substr(admission_binding_hash,1,65) AS admission_binding_hash,
        CASE WHEN typeof(ipc_auth_key)='blob' AND length(ipc_auth_key)=32
             THEN ipc_auth_key END AS ipc_auth_key
        FROM managed_executions WHERE execution_id=? LIMIT 2""", (execution_id,)).fetchall()
    if len(rows) != 1:
        raise LifecycleError("ipc_auth_unavailable")
    row = rows[0]
    try:
        from .query import _identifier
        for value in (row["spec_hash"], row["admission_binding_hash"]):
            if (not isinstance(value, str) or len(value) != 64 or
                    any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("invalid_hash")
        if (row["allocation_kind"] != "direct" or row["no_parent"] != 1 or
                type(row["ipc_auth_key"]) is not bytes or len(row["ipc_auth_key"]) != 32):
            raise ValueError("invalid_ipc_binding")
        reservation_id = _identifier(row["reservation_id"])
        identity = ProcessIdentity.from_dict({"pid": row["wrapper_pid"],
            "created_filetime_100ns": row["wrapper_created_filetime_100ns"], "logon_id": row["logon_id"]})
    except (TypeError, ValueError, OverflowError):
        raise LifecycleError("ipc_auth_unavailable") from None
    return _IpcAuthRecord(execution_id, row["spec_hash"], identity, "direct", reservation_id,
                          row["admission_binding_hash"], row["ipc_auth_key"])


def _get_ipc_auth_record(db_path, execution_id: str, *, timeout_ms: int = 250) -> _IpcAuthRecord:
    """Read the existing credential; never mint one for NULL/legacy rows.

    Only the trusted IPC service may consume this private result. It must
    authenticate a held native peer and the request MAC before final readback.
    """
    _ipc_query_arguments(execution_id, timeout_ms)
    with _ipc_read_transaction(db_path, timeout_ms=timeout_ms) as conn:
        return _ipc_auth_record(conn, execution_id)


def _revalidate_launch_auth(conn, execution_id, caller, expected_auth):
    """Bind an already authenticated native-peer request to this DB snapshot.

    This internal record is not authentication or launch authority by itself.
    The IPC service must retain its verified native peer and operation-specific
    proof; ClaimLaunch additionally requires the original separate claim token.
    """
    if (type(expected_auth) is not _IpcAuthRecord or
            expected_auth.execution_id != execution_id or
            type(caller) is not ProcessIdentity or expected_auth.wrapper_identity != caller or
            type(expected_auth.ipc_auth_key) is not bytes or len(expected_auth.ipc_auth_key) != 32):
        raise LifecycleError("ipc_auth_binding_changed")
    actual = _ipc_auth_record(conn, execution_id)
    names = ("execution_id", "spec_hash", "wrapper_identity", "allocation_kind",
             "reservation_id", "admission_binding_hash")
    if (any(getattr(actual, name) != getattr(expected_auth, name) for name in names) or
            not hmac.compare_digest(actual.ipc_auth_key, expected_auth.ipc_auth_key)):
        raise LifecycleError("ipc_auth_binding_changed")
    return actual


def authenticated_query(db_path, execution_id: str, expected_record: _IpcAuthRecord, *,
                        timeout_ms: int = 250) -> dict[str, Any]:
    """Read one sanitized execution after service-side native/MAC verification.

    ``expected_record`` is internal material, not caller authentication. The
    service retains the actual peer throughout this call. Authentication
    metadata and the result are checked in this same read transaction, so a
    changed binding between challenge and dispatch cannot expose another row.
    """
    _ipc_query_arguments(execution_id, timeout_ms)
    if (type(expected_record) is not _IpcAuthRecord or
            expected_record.execution_id != execution_id or
            type(expected_record.ipc_auth_key) is not bytes or len(expected_record.ipc_auth_key) != 32):
        raise LifecycleError("invalid_ipc_query")
    from .query import _base, _row, _integer, _FIELDS, _TEXT_FIELDS
    with _ipc_read_transaction(db_path, timeout_ms=timeout_ms) as conn:
        actual = _ipc_auth_record(conn, execution_id)
        names = ("execution_id", "spec_hash", "wrapper_identity", "allocation_kind",
                 "reservation_id", "admission_binding_hash")
        if (any(getattr(actual, name) != getattr(expected_record, name) for name in names) or
                not hmac.compare_digest(actual.ipc_auth_key, expected_record.ipc_auth_key)):
            raise LifecycleError("ipc_auth_binding_changed")
        runtime = conn.execute("""SELECT
            CASE WHEN typeof(schema_version)='integer' THEN schema_version END,
            CASE WHEN typeof(protocol_version)='integer' THEN protocol_version END,
            CASE WHEN typeof(mode)='text' THEN substr(mode,1,8) END,
            CASE WHEN typeof(registry_revision)='integer' THEN registry_revision END,
            CASE WHEN typeof(admission_barrier)='text' THEN substr(admission_barrier,1,14) END,
            CASE WHEN typeof(singleton)='integer' THEN singleton END
            FROM adaptive_runtime LIMIT 2""").fetchall()
        if len(runtime) != 1:
            raise LifecycleError("ipc_registry_unavailable")
        current = runtime[0]
        if (type(current[0]) is not int or current[0] != SCHEMA_VERSION or
                type(current[1]) is not int or current[1] != 1 or
                current[2] not in {"off", "shadow", "canary", "limited"} or
                current[4] not in {"NONE", "CONTROLLING", "RECOVERY_HOLD"} or
                type(current[5]) is not int or current[5] != 1):
            raise LifecycleError("ipc_registry_unavailable")
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('managed_executions','reservations','worker_reservations') LIMIT 3")}
        # SQLite comparison CHECKs do not guarantee a numeric storage class.
        # Guard before fetching: rejecting a huge BLOB/TEXT in Python is late.
        projections = []
        for name in _FIELDS:
            if name in _TEXT_FIELDS:
                expression = (f"CASE WHEN typeof({name})='text' THEN substr({name},1,129) "
                              f"WHEN {name} IS NULL THEN NULL ELSE '<invalid>' END")
            else:
                types = "('integer','real')" if name == "floor_cpu_units" else "('integer')"
                expression = (f"CASE WHEN typeof({name}) IN {types} THEN {name} "
                              f"WHEN {name} IS NULL THEN NULL ELSE -1 END")
            projections.append(f"{expression} AS {name}")
        record = conn.execute("SELECT " + ",".join(projections) +
            " FROM managed_executions WHERE execution_id=? LIMIT 1", (execution_id,)).fetchone()
        execution = _row(record)
        if "reservations" not in tables:
            binding = "allocation_table_missing"
        else:
            # This authenticated path only accepts direct allocations. Compute
            # the match in SQL so malformed large binding values stay private
            # and cannot become unbounded Python allocations before rejection.
            matches = conn.execute("""SELECT CASE WHEN typeof(execution_id)='text'
                AND execution_id=? AND typeof(lifecycle_managed)='integer'
                AND lifecycle_managed=1 THEN 1 ELSE 0 END
                FROM reservations WHERE id=? LIMIT 2""",
                (execution_id, actual.reservation_id)).fetchall()
            if not matches:
                binding = "terminal_allocation_absent" if execution["state"] in TERMINAL_STATES else "allocation_missing"
            else:
                binding = "recorded_binding_matches" if len(matches) == 1 and matches[0][0] == 1 else "allocation_binding_inconsistent"
        execution["allocation"]["recorded_binding"] = binding
        return {**_base(), "available": True, "reason": "ok", "schema_version": SCHEMA_VERSION,
                "protocol_version": 1, "recorded_mode": current[2],
                "registry_revision": _integer(current[3]), "admission_barrier": current[4],
                "executions": [execution], "truncated": False, "row_limit": 1}


class LifecycleStore:
    def __init__(self, db_path: str | Path, *, evidence_provider: Callable[[str, Mapping[str, Any], ProcessIdentity], ContextManager[LifecycleEvidence]] | None = None,
                 local_host_id: str | None = None, policy_provider=None, existing_path: bool = False):
        if type(existing_path) is not bool:
            raise ValueError("invalid_existing_path_mode")
        self.existing_path = existing_path
        try:
            self.db_path = Path(db_path).resolve() if existing_path else Path(db_path)
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        self._existing_ledger_path = self.db_path if existing_path else None
        self.evidence_provider = (_unavailable_evidence_provider
                                  if evidence_provider is None else evidence_provider)
        # Capture the actual host once before acquiring any SQLite transaction.
        # Injection is a deterministic fixture seam, not a worker-supplied claim.
        self.local_host_id = local_host_identity() if local_host_id is None else local_host_id
        if not isinstance(self.local_host_id, str) or not self.local_host_id.strip():
            raise ValueError("local_host_id must be a nonempty string")
        self._local_context = {"local_host_id": self.local_host_id}
        with self._connection() as conn:
            if existing_path and not _check_version(conn):
                raise LifecycleError("coverage_registry_unavailable")
            migrate_schema(conn)
        from .policy import PolicyCoordinator
        # This is an explicit fixture seam independent of lifecycle evidence.
        # Construction creates no mutex and performs no native identity query.
        self._policy = PolicyCoordinator(self, policy_provider)

    @contextmanager
    def _connection(self, *, existing_path: Path | None = None):
        # A retained guardian must not recreate a disappeared ledger, or switch
        # relative-path targets while waiting for native evidence. Ordinary
        # constructors retain their existing create/migrate behavior.
        pinned = self._existing_ledger_path if existing_path is None else existing_path
        if self._existing_ledger_path is not None and pinned != self._existing_ledger_path:
            raise LifecycleError("coverage_registry_unavailable")
        target = self.db_path if pinned is None else pinned.as_uri() + "?mode=rw"
        try:
            conn = sqlite3.connect(target, uri=pinned is not None, timeout=5, isolation_level=None)
        except sqlite3.Error:
            if pinned is not None:
                raise LifecycleError("coverage_registry_unavailable") from None
            raise
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        except BaseException as primary:
            try:
                conn.close()
            except BaseException:
                primary.add_note("lifecycle_connection_cleanup_failed")
            raise
        else:
            try:
                conn.close()
            except BaseException:
                raise LifecycleError("lifecycle_connection_cleanup_failed") from None

    @contextmanager
    def _transaction(self, *, existing_path: Path | None = None):
        connection = self._connection() if existing_path is None else self._connection(existing_path=existing_path)
        with connection as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                present = _check_version(conn)
                if (existing_path is not None or self.existing_path) and not present:
                    raise LifecycleError("coverage_registry_unavailable")
                yield conn
                conn.commit()
            except BaseException as primary:
                try:
                    conn.rollback()
                except BaseException:
                    primary.add_note("lifecycle_transaction_rollback_failed")
                raise

    @contextmanager
    def _publication_scope(self, caller):
        """Serialize first wrapper and Job metadata publication with POLICY.

        A caller already holding this exact store's current-thread scope lends
        it; this method never releases or re-enters borrowed ownership. Native
        waiting and evidence collection precede the publication transaction.
        """
        from .policy import PolicyBusy, PolicyError
        from .windows import NativePolicyMutexError
        try:
            guard = self._policy.current_guard()
            if guard is not None:
                self._policy.assert_held(guard)
                if guard.binding.logon_id != caller.logon_id:
                    raise PolicyError("policy_logon_mismatch")
                yield guard, False
                return
            logon = self._policy.current_logon()
            if logon != caller.logon_id:
                raise PolicyError("policy_logon_mismatch")
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    guard = self._policy.prepare(logon)
                    break
                except PolicyBusy as error:
                    if getattr(error, "__notes__", ()) or time.monotonic() >= deadline:
                        raise
                    time.sleep(min(.01, max(0, deadline - time.monotonic())))
            with self._policy.hold(guard):
                yield guard, True
        except (PolicyError, NativePolicyMutexError) as error:
            translated = LifecycleError(str(error))
            for note in getattr(error, "__notes__", ()):
                translated.add_note(note)
            raise translated from error

    @contextmanager
    def _publication_transaction(self, guard, owns_scope):
        # Separate from _transaction so only this publication's positively
        # rolled-back pre-commit rejection can release its durable entry nonce.
        commit_attempted = False
        rolled_back = False
        connection_entered = False
        try:
            with self._connection() as conn:
                connection_entered = True
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    _check_version(conn)
                    self._policy.assert_held(guard)
                    self._policy.revalidate(conn, guard)
                    yield conn
                    commit_attempted = True
                    conn.commit()
                except BaseException as primary:
                    try:
                        conn.rollback()
                        rolled_back = not conn.in_transaction
                    except BaseException:
                        primary.add_note("lifecycle_transaction_rollback_failed")
                    raise
        except BaseException as primary:
            if (owns_scope and (rolled_back or not connection_entered) and not commit_attempted and
                    not getattr(primary, "__notes__", ())):
                guard.clean_rejection = True
            raise

    @staticmethod
    def _public(row: Mapping[str, Any]) -> dict[str, Any]:
        return {key: row[key] for key in row.keys() if key not in {"claim_token_hash", "ipc_auth_key"}}

    @staticmethod
    def _get(conn: sqlite3.Connection, execution_id: str) -> sqlite3.Row:
        row = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?", (execution_id,)).fetchone()
        if row is None:
            raise LifecycleError("execution_not_found")
        return row

    def query(self, execution_id: str, *, existing_path: bool = False) -> dict[str, Any]:
        if type(existing_path) is not bool:
            raise ValueError("invalid_existing_path_mode")
        if existing_path or self.existing_path:
            try:
                ledger_path = self._existing_ledger_path or Path(self.db_path).resolve()
            except (OSError, TypeError, ValueError, RuntimeError):
                raise LifecycleError("coverage_registry_unavailable") from None
            with _coverage_read_transaction(ledger_path) as conn:
                return self._public(self._get(conn, execution_id))
        with self._connection() as conn:
            _check_version(conn)
            return self._public(self._get(conn, execution_id))

    def _require_authenticated_allocation(self, conn, row):
        if row["allocation_kind"] != "direct" or row["parent_execution_id"] is not None:
            raise LifecycleError("authenticated_direct_allocation_required")
        self._require_allocation(conn, row["execution_id"])
        if (conn.execute("SELECT count(*) FROM reservations WHERE execution_id=? OR id=?",
                         (row["execution_id"], row["reservation_id"])).fetchone()[0] != 1 or
                conn.execute("SELECT count(*) FROM worker_reservations WHERE execution_id=?",
                             (row["execution_id"],)).fetchone()[0] != 0 or
                conn.execute("""SELECT count(*) FROM managed_executions WHERE execution_id=? OR
                    (reservation_id=? AND (allocation_kind='direct' OR allocation_kind IS NULL OR
                                          allocation_kind NOT IN ('direct','routed')))""",
                             (row["execution_id"], row["reservation_id"])).fetchone()[0] != 1):
            raise LifecycleError("authenticated_allocation_not_unique")

    def _launch_snapshot(self, execution_id, caller, expected_auth, *, guard=None):
        if expected_auth is None:
            return self.query(execution_id)
        with self._connection() as conn:
            conn.execute("BEGIN")
            _check_version(conn)
            if guard is not None:
                self._policy.revalidate(conn, guard)
            _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
            row = self._get(conn, execution_id)
            if row["state"] not in TERMINAL_STATES:
                self._require_authenticated_allocation(conn, row)
            return self._public(row)

    @staticmethod
    def _launch_ack(row, expected_auth, *, duplicate=False):
        public = LifecycleStore._public(row)
        if expected_auth is not None:
            public.update(duplicate=duplicate, launch_authorized=False)
        return public

    def assert_authenticated_allocation(self, expected_row: Mapping[str, Any], *,
                                        caller: ProcessIdentity, expected_auth: _IpcAuthRecord) -> None:
        """Read-only pre-Job custody after service-side native/MAC verification.

        This requires no wrapper-local ManagedAdmission object or fabricated
        manifest. Authentication material, exact expected row and actual unique
        allocation are checked in one snapshot. It grants no launch permission.
        """
        if (not isinstance(expected_row, Mapping) or type(expected_row.get("state_revision")) is not int or
                type(expected_auth) is not _IpcAuthRecord or
                expected_row.get("execution_id") != expected_auth.execution_id):
            raise LifecycleError("authenticated_expected_row_invalid")
        try:
            ledger_path = self._existing_ledger_path or Path(self.db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        with _coverage_read_transaction(ledger_path) as conn:
            _revalidate_launch_auth(conn, expected_auth.execution_id, caller, expected_auth)
            row = self._get(conn, expected_auth.execution_id)
            self._require_revision(row, expected_row["state_revision"])
            public = self._public(row)
            if any(key not in expected_row or expected_row[key] != value for key, value in public.items()):
                raise LifecycleError("authenticated_expected_row_mismatch")
            self._require_authenticated_allocation(conn, row)

    def record_launch_request_locked(self, execution_id: str, operation: str, request_id: str,
                                     payload_hash: str, *, caller: ProcessIdentity,
                                     expected_auth: _IpcAuthRecord, guardian_epoch: str) -> bool:
        """Record one immutable request before OS side effects; never authorize them.

        The trusted transport hashes its complete typed request, including its
        operation, revision and binding fields. A key/digest change cannot
        overwrite an earlier attempt. True acknowledges an exact retry; neither
        result reconstructs a lost native creation/launch capability.
        """
        from .policy import PolicyError

        if (type(operation) is not str or operation not in {"PrepareExecution", "ClaimLaunch", "BindRoot"} or
                type(caller) is not ProcessIdentity or
                type(payload_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", payload_hash) or
                type(guardian_epoch) is not str or not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", guardian_epoch)):
            raise LifecycleError("invalid_launch_request")
        try:
            if type(request_id) is not str or UUID(request_id).int == 0 or str(UUID(request_id)) != request_id:
                raise ValueError
        except (ValueError, AttributeError):
            raise LifecycleError("invalid_launch_request") from None
        try:
            guard = self._policy.assert_held()
            if guard.binding.logon_id != caller.logon_id:
                raise LifecycleError("policy_logon_mismatch")
            with self._transaction() as conn:
                runtime = self._policy.revalidate(conn, guard)
                auth = _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
                row = self._get(conn, execution_id)
                if (row["guardian_epoch"] not in {"", guardian_epoch} or
                        runtime["guardian_epoch"] not in {"", guardian_epoch} or
                        (operation != "PrepareExecution" and row["guardian_epoch"] != guardian_epoch)):
                    raise LifecycleError("guardian_identity_mismatch")
                values = (execution_id, operation, request_id, payload_hash, auth.spec_hash, guardian_epoch)
                recorded = conn.execute("""SELECT execution_id,operation,request_id,payload_hash,spec_hash,guardian_epoch
                    FROM adaptive_launch_requests WHERE (execution_id=? AND operation=?) OR request_id=? LIMIT 2""",
                    (execution_id, operation, request_id)).fetchall()
                if recorded:
                    if len(recorded) != 1 or tuple(recorded[0]) != values:
                        raise LifecycleError("launch_request_mismatch")
                    if row["state"] not in TERMINAL_STATES:
                        self._require_authenticated_allocation(conn, row)
                    return True
                if (row["state"] not in {"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING",
                                          "START_UNKNOWN", "UNCERTAIN_HOLD"} or
                        (operation == "PrepareExecution" and row["state"] != "RESERVED") or
                        (operation == "ClaimLaunch" and row["state"] != "PREPARED") or
                        (operation == "BindRoot" and row["state"] not in {"LAUNCHING", "START_UNKNOWN"})):
                    raise LifecycleError("invalid_lifecycle_transition")
                self._require_authenticated_allocation(conn, row)
                conn.execute("""INSERT INTO adaptive_launch_requests
                    (execution_id,operation,request_id,payload_hash,spec_hash,guardian_epoch)
                    VALUES(?,?,?,?,?,?)""", values)
                return False
        except PolicyError as error:
            raise LifecycleError(str(error)) from error

    def assert_admission_covered(self, admission, expected_row: Mapping[str, Any]) -> None:
        """Verify one direct admission's retained ledger custody, read-only.

        This asserts neither host cohort cutover nor collector exclusion, native
        containment, exemption state or control permission. The caller retains
        its independent lifecycle/mutation fences. No terminal record, queued
        intent or returned ``allowed`` flag substitutes for the exact allocation.
        START_UNKNOWN and UNCERTAIN_HOLD still have custody to reconcile.
        """
        from .admission import ManagedAdmission

        if type(admission) is not ManagedAdmission:
            raise LifecycleError("managed_admission_context_required")
        try:
            ledger_path = Path(self.db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        snapshot = admission.snapshot_for_ledger(ledger_path)
        names = (
            "execution_id", "task_id", "session_id", "principal_id", "logon_id",
            "allocation_kind", "reservation_id", "parent_execution_id", "spec_hash",
            "admission_binding_hash", "wrapper_pid", "wrapper_created_filetime_100ns",
            "role", "priority", "state", "state_revision", "coverage", "job_name", "job_nonce",
            "guardian_epoch", "root_pid", "root_created_filetime_100ns", "root_outcome",
            "claim_consumed", "launch_in_flight", "launch_sealed", "hold_reason",
        ) + tuple(prefix + key for prefix in ("requested_", "floor_") for key in snapshot.requested.to_dict())
        if not isinstance(expected_row, Mapping) or any(name not in expected_row for name in names):
            raise LifecycleError("coverage_expected_row_invalid")
        expected = {name: expected_row[name] for name in names}
        if (expected["execution_id"] != snapshot.execution_id or
                type(expected["state_revision"]) is not int or expected["state_revision"] < 0):
            raise LifecycleError("coverage_expected_row_mismatch")

        with _coverage_read_transaction(ledger_path) as conn:
            row = self._get(conn, snapshot.execution_id)
            self._require_revision(row, expected["state_revision"])
            if any(row[name] != value for name, value in expected.items()):
                raise LifecycleError("coverage_expected_row_mismatch")
            if row["state"] in TERMINAL_STATES:
                raise LifecycleError("coverage_execution_terminal")
            if row["state"] not in {"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING",
                                    "START_UNKNOWN", "UNCERTAIN_HOLD"}:
                raise LifecycleError("coverage_execution_state_invalid")
            if row["allocation_kind"] != "direct" or row["parent_execution_id"] is not None:
                raise LifecycleError("coverage_direct_allocation_required")
            # This existing verifier checks all immutable admission metadata and
            # the original claim/IPC binding. Its allowed=False for a held
            # execution does not negate that execution's retained allocation.
            replay = retry_managed_admission(conn, snapshot, local_context=self._local_context)
            if replay is None:
                raise LifecycleError("execution_not_found")
            try:
                source = validate_active_allocation(conn, snapshot.execution_id, local_context=self._local_context)
            except AccountingError as error:
                raise LifecycleError(str(error)) from error
            reservation_id = row["reservation_id"]
            if (conn.execute("SELECT count(*) FROM reservations WHERE execution_id=? OR id=?",
                             (snapshot.execution_id, reservation_id)).fetchone()[0] != 1 or
                    conn.execute("SELECT count(*) FROM worker_reservations WHERE execution_id=?",
                                 (snapshot.execution_id,)).fetchone()[0] != 0 or
                    conn.execute("""SELECT count(*) FROM managed_executions
                        WHERE execution_id=? OR (allocation_kind='direct' AND reservation_id=?)""",
                                 (snapshot.execution_id, reservation_id)).fetchone()[0] != 1):
                raise LifecycleError("coverage_allocation_not_unique")
            request = snapshot.request
            bound = {
                "id": reservation_id, "execution_id": snapshot.execution_id, "lifecycle_managed": 1,
                "managed_spec_hash": snapshot.spec_hash, "request_key": request.request_key,
                "spec_hash": request.spec_hash, "owner_pid": request.owner_pid,
                "owner_started": request.owner_started, "tool_use_id": request.tool_use_id,
                "repo": request.repo, "command_signature": request.command_signature, "command_text": "",
                "resource_class": request.resource_class, "priority": request.priority,
                "priority_rank": int(request.priority[1:]), "cpu_units": request.cpu_units,
                "ram_gib": request.ram_gib, "io_slots": request.io_slots,
                "physical_bytes": snapshot.requested.physical_bytes, "commit_bytes": snapshot.requested.commit_bytes,
            }
            if any(source["allocation"].get(key) != value for key, value in bound.items()):
                raise LifecycleError("coverage_allocation_binding_mismatch")

    @staticmethod
    def _retained_inputs(expected_row: Mapping[str, Any], manifest: RecoveryManifest):
        """Validate retained data without treating it as native authority."""
        if type(manifest) is not RecoveryManifest:
            raise LifecycleError("retained_manifest_invalid")
        try:
            # Revalidate nested contracts and the checksum before using a
            # retained object; a manifest hash proves integrity, not custody.
            manifest = RecoveryManifest.from_dict(manifest.to_dict())
        except (ContractViolation, TypeError, ValueError, OverflowError):
            raise LifecycleError("retained_manifest_invalid") from None
        resource_keys = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")
        names = (
            "execution_id", "task_id", "session_id", "principal_id", "logon_id",
            "allocation_kind", "reservation_id", "parent_execution_id", "spec_hash",
            "admission_binding_hash", "wrapper_pid", "wrapper_created_filetime_100ns",
            "role", "priority", "state", "state_revision", "coverage", "job_name", "job_nonce",
            "guardian_epoch", "root_pid", "root_created_filetime_100ns", "root_outcome",
            "claim_consumed", "launch_in_flight", "launch_sealed", "hold_reason",
        ) + tuple(prefix + key for prefix in ("requested_", "floor_") for key in resource_keys)
        if not isinstance(expected_row, Mapping) or any(name not in expected_row for name in names):
            raise LifecycleError("retained_expected_row_invalid")
        expected = {name: expected_row[name] for name in names}
        if (type(expected["state_revision"]) is not int or expected["state_revision"] < 0 or
                any(type(expected[name]) is not int or expected[name] not in {0, 1}
                    for name in ("claim_consumed", "launch_in_flight", "launch_sealed"))):
            raise LifecycleError("retained_expected_row_invalid")
        try:
            wrapper = ProcessIdentity.from_dict({"pid": expected["wrapper_pid"],
                "created_filetime_100ns": expected["wrapper_created_filetime_100ns"],
                "logon_id": expected["logon_id"]})
            root = None
            if expected["root_pid"] is not None or expected["root_created_filetime_100ns"] is not None:
                root = ProcessIdentity.from_dict({"pid": expected["root_pid"],
                    "created_filetime_100ns": expected["root_created_filetime_100ns"],
                    "logon_id": expected["logon_id"]})
            ResourceDemand.from_dict({key: expected["requested_" + key] for key in resource_keys})
            floor = ResourceDemand.from_dict({key: expected["floor_" + key] for key in resource_keys})
        except (ContractViolation, TypeError, ValueError, OverflowError):
            raise LifecycleError("retained_expected_row_invalid") from None
        if (expected["execution_id"] != manifest.execution_id or
                expected["spec_hash"] != manifest.spec_hash or
                expected["allocation_kind"] != manifest.reservation.kind.value or
                expected["reservation_id"] != manifest.reservation.id or
                expected["parent_execution_id"] is not None or
                expected["job_name"] != manifest.job_name or expected["job_nonce"] != manifest.creation_nonce or
                expected["guardian_epoch"] != manifest.guardian_epoch or
                wrapper != manifest.wrapper_identity or root != manifest.root_identity or
                floor != manifest.allocated_floor):
            raise LifecycleError("retained_manifest_mismatch")
        return expected, manifest

    def _validate_retained_allocation(self, conn, expected, manifest):
        row = self._get(conn, manifest.execution_id)
        self._require_revision(row, expected["state_revision"])
        if any(row[name] != value for name, value in expected.items()):
            raise LifecycleError("retained_expected_row_mismatch")
        if row["state"] not in {"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING",
                                "START_UNKNOWN", "UNCERTAIN_HOLD"}:
            raise LifecycleError("retained_execution_inactive")
        if row["allocation_kind"] not in _TABLES or row["parent_execution_id"] is not None:
            raise LifecycleError("retained_top_level_required")
        runtime = conn.execute("SELECT guardian_epoch,active_logon_id FROM adaptive_runtime WHERE singleton=1").fetchone()
        if (runtime is None or runtime["guardian_epoch"] != manifest.guardian_epoch or
                runtime["active_logon_id"] != manifest.wrapper_identity.logon_id):
            raise LifecycleError("retained_guardian_epoch_mismatch")
        try:
            source = validate_active_allocation(conn, manifest.execution_id, local_context=self._local_context)
        except AccountingError as error:
            raise LifecycleError(str(error)) from error
        kind = row["allocation_kind"]
        table = _TABLES[kind]
        other = _TABLES["routed" if kind == "direct" else "direct"]
        if (source["execution_id"] != manifest.execution_id or
                conn.execute(f"SELECT count(*) FROM {table} WHERE execution_id=? OR id=?",
                    (manifest.execution_id, row["reservation_id"])).fetchone()[0] != 1 or
                conn.execute(f"SELECT count(*) FROM {other} WHERE execution_id=?",
                    (manifest.execution_id,)).fetchone()[0] != 0 or
                conn.execute("""SELECT count(*) FROM managed_executions WHERE execution_id=? OR
                    (reservation_id=? AND (allocation_kind=? OR allocation_kind IS NULL OR
                                          allocation_kind NOT IN ('direct','routed')))""",
                    (manifest.execution_id, row["reservation_id"], kind)).fetchone()[0] != 1):
            raise LifecycleError("retained_allocation_not_unique")
        return row, source

    def assert_retained_allocation(self, expected_row: Mapping[str, Any],
                                   manifest: RecoveryManifest) -> None:
        """Internal read-only ledger custody check for a retained guardian.

        No current/alive wrapper is required. The manifest must match the exact
        committed allocation, Job scope and floor in one read snapshot. This
        proves no host cohort, native liveness, containment or guardian authority;
        those remain the retained provider's independent responsibilities.
        Missing/unknown storage is never recreated, repaired or treated as free.
        """
        expected, manifest = self._retained_inputs(expected_row, manifest)
        try:
            ledger_path = self._existing_ledger_path or Path(self.db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        with _coverage_read_transaction(ledger_path) as conn:
            self._validate_retained_allocation(conn, expected, manifest)

    def assert_retained_terminal(self, expected_row: Mapping[str, Any],
                                 manifest: RecoveryManifest) -> None:
        """Reconcile a committed FINISHED result after a lost finalization ACK.

        This is a separate read-only ledger proof, never an active allocation
        fallback or another release. Native empty/disabled/settled verification
        must still be repeated under the retained guardian's own fences before
        it relinquishes custody. The direct archive has no spec hash; neither
        archive stores physical/Commit bytes. Only actually persisted fields
        are compared; the exact managed row retains immutable binding.
        """
        expected, manifest = self._retained_inputs(expected_row, manifest)
        finished = expected_row.get("finished_at")
        try:
            valid_finished = type(finished) in (int, float) and math.isfinite(finished) and finished >= 0
        except OverflowError:
            valid_finished = False
        if not valid_finished:
            raise LifecycleError("retained_terminal_unverified")
        expected["finished_at"] = finished
        try:
            ledger_path = self._existing_ledger_path or Path(self.db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        with _coverage_read_transaction(ledger_path) as conn:
            row = self._get(conn, manifest.execution_id)
            self._require_revision(row, expected["state_revision"])
            if any(row[name] != value for name, value in expected.items()):
                raise LifecycleError("retained_expected_row_mismatch")
            kind = row["allocation_kind"]
            if (row["state"] != "FINISHED" or row["launch_sealed"] != 1 or row["launch_in_flight"] != 0 or
                    kind not in _TABLES or row["parent_execution_id"] is not None):
                raise LifecycleError("retained_terminal_unverified")
            table = _TABLES[kind]
            other = _TABLES["routed" if kind == "direct" else "direct"]
            if (conn.execute(f"SELECT count(*) FROM {table} WHERE execution_id=? OR id=?",
                    (manifest.execution_id, row["reservation_id"])).fetchone()[0] != 0 or
                    conn.execute(f"SELECT count(*) FROM {other} WHERE execution_id=?",
                    (manifest.execution_id,)).fetchone()[0] != 0 or
                    conn.execute("""SELECT count(*) FROM managed_executions WHERE execution_id=? OR
                        (reservation_id=? AND (allocation_kind=? OR allocation_kind IS NULL OR
                                              allocation_kind NOT IN ('direct','routed')))""",
                        (manifest.execution_id, row["reservation_id"], kind)).fetchone()[0] != 1):
                raise LifecycleError("retained_terminal_unverified")
            archive_table = "executions" if kind == "direct" else "routed_executions"
            # LIMIT 2 bounds the proof and distinguishes exactly one archive
            # from duplicate/reused reservation history without choosing a row.
            # Do not fetch legacy command labels or private routed metadata.
            columns = "outcome,ended_at,cpu_units,started_at,ram_gib," + (
                "io_slots" if kind == "direct" else "task_id,spec_hash")
            archives = conn.execute(f"SELECT {columns} FROM {archive_table} WHERE reservation_id=? LIMIT 2",
                                    (row["reservation_id"],)).fetchall()
            if len(archives) != 1:
                raise LifecycleError("retained_terminal_unverified")
            archive = archives[0]
            if (archive["outcome"] != "managed_finished" or archive["ended_at"] != finished or
                    archive["cpu_units"] != row["requested_cpu_units"] or
                    (kind == "direct" and archive["io_slots"] != row["requested_io_slots"]) or
                    (kind == "routed" and (archive["task_id"] != row["task_id"] or
                                           archive["spec_hash"] != row["spec_hash"]))):
                raise LifecycleError("retained_terminal_unverified")
            for name in ("started_at", "ram_gib"):
                value = archive[name]
                if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                    raise LifecycleError("retained_terminal_unverified")
            if archive["started_at"] > finished:
                raise LifecycleError("retained_terminal_unverified")

    def heartbeat_retained_allocation(self, expected_row: Mapping[str, Any], manifest: RecoveryManifest,
                                      *, caller: ProcessIdentity, now: float | None = None) -> dict[str, Any]:
        """Internal guardian observation, with native fences held through commit.

        The provider must authenticate the actual guardian and retain exact Job,
        manifest and root custody under policy then Job mutation fences. Data
        supplied here is not authority; the default provider remains unavailable.
        Even positive empty membership only refreshes observation timestamps.
        Only a healthy, still-unexpired RUNNING/DRAINING allocation with a
        durably captured original lease period receives a renewed deadline.
        Unknown old periods are never inferred. Expiry records uncertainty;
        observations never clear holds, lower floors or prove work is finished.
        """
        from .policy import PolicyError

        expected, manifest = self._retained_inputs(expected_row, manifest)
        if type(caller) is not ProcessIdentity or caller != manifest.guardian_identity:
            raise LifecycleError("guardian_identity_mismatch")
        now = time.time() if now is None else now
        try:
            valid_now = type(now) in (int, float) and math.isfinite(now) and now >= 0
        except OverflowError:
            valid_now = False
        if not valid_now:
            raise ValueError("invalid_time")
        try:
            ledger_path = self._existing_ledger_path or Path(self.db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise LifecycleError("coverage_registry_unavailable") from None
        try:
            with self._evidence_scope("heartbeat", expected, caller, guardian=manifest.guardian_identity) as proof:
                if (proof.job_name != manifest.job_name or proof.job_nonce != manifest.creation_nonce or
                        proof.guardian_epoch != manifest.guardian_epoch or not proof.durable_manifest or
                        type(proof.active_process_count) is not int or proof.process_ids is None or
                        proof.active_process_count != len(proof.process_ids) or
                        proof.root != manifest.root_identity or
                        proof.launch_sealed != bool(expected["launch_sealed"]) or
                        (expected["state"] in {"RUNNING", "DRAINING"} and
                         (not proof.launch_sealed or expected["launch_in_flight"]))):
                    raise LifecycleError("heartbeat_evidence_unverified")
                guard = self._policy.assert_held()
                if guard.binding.logon_id != caller.logon_id:
                    raise LifecycleError("policy_logon_mismatch")
                with self._transaction(existing_path=ledger_path) as conn:
                    self._policy.revalidate(conn, guard)
                    row, source = self._validate_retained_allocation(conn, expected, manifest)
                    for previous in (row["heartbeat_at"], source["allocation"].get("heartbeat_at")):
                        if (type(previous) not in (int, float) or not math.isfinite(previous) or
                                previous < 0 or now < previous):
                            raise LifecycleError("heartbeat_clock_regression")
                    allocation = source["allocation"]
                    expires_at = allocation.get("expires_at")
                    duration = allocation.get("lease_duration_sec")
                    try:
                        valid_expiry = (type(expires_at) in (int, float) and math.isfinite(expires_at) and expires_at >= 0)
                        valid_duration = (duration is None or
                            (type(duration) in (int, float) and math.isfinite(duration) and duration > 0))
                    except OverflowError:
                        valid_expiry = valid_duration = False
                    if not valid_expiry or not valid_duration:
                        raise LifecycleError("allocation_lease_invalid")
                    deadline = expires_at
                    updates = {"heartbeat_at": now}
                    if expires_at <= now:
                        # Preserve the missed-health interval even when this
                        # native observation beats a legacy cleanup sweep. A
                        # single CAS records it with the heartbeat; no gap is
                        # erased by extending the elapsed deadline first.
                        if row["state"] not in {"START_UNKNOWN", "UNCERTAIN_HOLD"}:
                            updates["state"] = "START_UNKNOWN" if row["launch_in_flight"] else "UNCERTAIN_HOLD"
                            updates["hold_reason"] = row["hold_reason"] or "reservation_expired"
                    elif (duration is not None and row["state"] in {"RUNNING", "DRAINING"} and
                          row["hold_reason"] is None):
                        renewal = now + duration
                        if not math.isfinite(renewal) or renewal <= now:
                            raise LifecycleError("allocation_lease_invalid")
                        deadline = max(expires_at, renewal)
                    table = _TABLES[row["allocation_kind"]]
                    updated = conn.execute(f"""UPDATE {table} SET heartbeat_at=?,expires_at=?,
                        writer_protocol=1,writer_revision=writer_revision+1
                        WHERE id=? AND execution_id=? AND lifecycle_managed=1""",
                        (now, deadline, row["reservation_id"], row["execution_id"]))
                    if updated.rowcount != 1:
                        raise LifecycleError("allocation_binding_missing")
                    result = self._public(self._cas(conn, row["execution_id"], expected["state_revision"], updates))
            return result
        except (PolicyError, sqlite3.Error) as error:
            translated = LifecycleError(str(error) if isinstance(error, PolicyError) else "coverage_registry_unavailable")
            for note in getattr(error, "__notes__", ()):
                translated.add_note(note)
            raise translated from None

    @staticmethod
    def _caller(row: Mapping[str, Any], caller: ProcessIdentity) -> None:
        if not isinstance(caller, ProcessIdentity) or (caller.pid != row["wrapper_pid"] or
                str(caller.created_filetime_100ns) != row["wrapper_created_filetime_100ns"] or caller.logon_id != row["logon_id"]):
            raise LifecycleError("caller_identity_mismatch")

    @contextmanager
    def _evidence_scope(self, operation: str, row: Mapping[str, Any], caller: ProcessIdentity, *, publication=None,
                        guardian: ProcessIdentity | None = None):
        """Verify before SQLite; retain evidence authority through commit/rollback.

        The trusted provider acquires and validates native resources in enter,
        keeping them owned until exit. Enter must unwind partial acquisition on
        failure, as with every context manager. Returned data is not itself a
        fence. Acquire policy then Job mutation locks where required, followed
        by this scope's nested SQLite transaction. Waiting for a DB lock does
        not refresh evidence: the provider's ownership/fence must keep the
        proof valid throughout that wait and transaction. Never call this
        inside a transaction or let provider cleanup
        suppress or replace a transaction/body error. Cleanup failure after a
        successful commit is reported, but cannot undo the committed operation.
        """
        if operation == "heartbeat":
            # This private branch changes the claimed actor only. The retained
            # provider must still authenticate that guardian natively; neither
            # a serialized identity nor a manifest checksum can authorize it.
            if (type(guardian) is not ProcessIdentity or caller != guardian or
                    guardian.logon_id != row["logon_id"]):
                raise LifecycleError("guardian_identity_mismatch")
        else:
            self._caller(row, caller)
        scope = self.evidence_provider(operation, self._public(row), caller)
        enter = getattr(type(scope), "__enter__", None)
        leave = getattr(type(scope), "__exit__", None)
        if not callable(enter) or not callable(leave):
            raise LifecycleError("invalid_lifecycle_evidence_scope")
        evidence = enter(scope)
        decision_error = None
        try:
            try:
                if (not isinstance(evidence, LifecycleEvidence) or evidence.operation != operation or
                        evidence.execution_id != row["execution_id"] or evidence.state_revision != row["state_revision"] or
                        evidence.caller != caller or not isinstance(evidence.observation_id, str) or not evidence.observation_id):
                    raise LifecycleError("invalid_lifecycle_evidence")
                if "job_nonce" in row.keys() and row["job_nonce"] is not None and (
                        evidence.job_nonce != row["job_nonce"] or evidence.job_name != row["job_name"] or
                        evidence.guardian_epoch != row["guardian_epoch"]):
                    raise LifecycleError("job_scope_evidence_mismatch")
                if operation != "register_scope" and evidence.job_nonce is not None and (
                        "job_nonce" not in row.keys() or row["job_nonce"] is None):
                    # A new native provider cannot silently fall into the older
                    # nonce-less synthetic seam and skip pre-Create registration.
                    raise LifecycleError("job_scope_not_registered")
            except LifecycleError as error:
                # Only validation performed here, before yielding to the
                # publication body, proves that no publication was attempted.
                decision_error = error
                raise
            yield evidence
        except BaseException as primary:
            cleaned = False
            try:
                # Suppression cannot turn failure into success or certify a
                # clean publication rejection. Retain its uncertainty as a note.
                suppressed = leave(scope, type(primary), primary, primary.__traceback__)
                if suppressed:
                    primary.add_note("lifecycle_evidence_cleanup_unverified")
                cleaned = not suppressed and not getattr(primary, "__notes__", ())
            except BaseException:
                primary.add_note("lifecycle_evidence_cleanup_failed")
            if (publication is not None and publication[1] and
                    primary is decision_error and cleaned):
                # The retained evidence scope has positively closed; no writer
                # transaction was entered and no commit ACK can be uncertain.
                publication[0].clean_rejection = True
            raise
        else:
            try:
                leave(scope, None, None, None)
            except BaseException:
                raise LifecycleError("lifecycle_evidence_cleanup_failed") from None

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
        row = _registration_row(spec, now)
        # Every attempt authenticates caller, including retries; a public spec is
        # not evidence that the process/session or parent membership is real.
        self._caller(row, caller)
        with self._publication_scope(caller) as publication:
            with self._evidence_scope("register", row, caller, publication=publication) as proof:
                raw_token = secrets.token_urlsafe(32)
                row["claim_token_hash"] = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
                with self._publication_transaction(*publication) as conn:
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
                        conn.execute(f"UPDATE {table} SET execution_id=?,lifecycle_managed=1,physical_bytes=?,commit_bytes=?,writer_protocol=1,writer_revision=writer_revision+1 WHERE id=?",
                                     (spec.execution_id, physical, commit, spec.reservation.id))
                    names = ",".join(row)
                    conn.execute(f"INSERT INTO managed_executions({names}) VALUES({','.join('?' for _ in row)})", tuple(row.values()))
                    self._require_allocation(conn, spec.execution_id)
                    _bump_registry(conn)
                    return {**self._public(self._get(conn, spec.execution_id)), "claim_token": raw_token, "registered": True}

    def register_job_scope(self, execution_id: str, *, caller: ProcessIdentity,
                           expected_revision: int, guardian_epoch: str,
                           job_name: str, job_nonce: str,
                           expected_auth: _IpcAuthRecord | None = None) -> dict[str, Any]:
        """Persist one native creation responsibility before creating any Job.

        The trusted owner already holds this store's POLICY scope and retains
        it through manifest persistence and native creation. A successful call
        records planned identity only: it grants no launch, control, containment
        or host-admission permission. It does not write a second allocation.

        Register exactly once. A repeated/uncertain call must reconcile this
        existing attempt, never recreate an object or remint its nonce. The
        caller's per-Job mutex identity must derive from this persisted scope.
        Native owners cannot use the older synthetic-provider preparation path
        in place of this step; production evidence remains unavailable by
        default. No durable record reconstructs a lost never-created capability.
        """
        from .policy import PolicyError

        try:
            parsed_execution = UUID(execution_id) if isinstance(execution_id, str) else None
            canonical_execution = (parsed_execution is not None and parsed_execution.int != 0 and
                                   str(parsed_execution) == execution_id)
        except (ValueError, AttributeError):
            canonical_execution = False
        if not canonical_execution:
            raise LifecycleError("invalid_job_scope")
        if (not isinstance(job_nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", job_nonce) or
                not isinstance(guardian_epoch, str) or not 1 <= len(guardian_epoch) <= 128 or
                any(ord(char) < 32 for char in guardian_epoch)):
            raise LifecycleError("invalid_job_scope")
        if not isinstance(job_name, str) or job_name not in {
                f"Local\\ResourceSentinel.Job.{execution_id}.{job_nonce}",
                f"Local\\ResourceSentinel.Test.Job.{job_nonce}"}:
            raise LifecycleError("invalid_job_scope")
        try:
            guard = self._policy.assert_held()
        except PolicyError as error:
            raise LifecycleError(str(error)) from error
        if type(caller) is not ProcessIdentity or guard.binding.logon_id != caller.logon_id:
            raise LifecycleError("policy_logon_mismatch")
        snapshot = self._launch_snapshot(execution_id, caller, expected_auth, guard=guard)
        if expected_auth is not None and snapshot["job_name"] is not None:
            # Durable scope is a replay ACK, never a reconstructed capability
            # to create/recreate a named object after an uncertain outcome.
            if (snapshot["state"] in TERMINAL_STATES or snapshot["job_name"] != job_name or
                    snapshot["job_nonce"] != job_nonce or snapshot["guardian_epoch"] != guardian_epoch):
                raise LifecycleError("job_scope_already_registered")
            return self._launch_ack(snapshot, expected_auth, duplicate=True)
        self._require_revision(snapshot, expected_revision)
        self._caller(snapshot, caller)
        if guard.binding.logon_id != caller.logon_id:
            raise LifecycleError("policy_logon_mismatch")
        with self._evidence_scope("register_scope", snapshot, caller) as proof:
            if (proof.job_name != job_name or proof.job_nonce != job_nonce or
                    proof.guardian_epoch != guardian_epoch or not proof.job_creation_never_attempted or
                    proof.root is not None or proof.active_process_count is not None or proof.process_ids is not None):
                raise LifecycleError("job_scope_registration_unverified")
            # Evidence is bounded and acquired outside SQLite. Both the same
            # POLICY ownership and the native creation fence survive this CAS.
            self._policy.assert_held(guard)
            with self._transaction() as conn:
                runtime = self._policy.revalidate(conn, guard)
                if expected_auth is not None:
                    _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
                row = self._get(conn, execution_id)
                self._require_revision(row, expected_revision)
                self._caller(row, caller)
                if (row["state"] != "RESERVED" or row["allocation_kind"] == "parent" or
                        row["coverage"] != "unmanaged" or row["claim_consumed"] or row["launch_sealed"] or
                        row["launch_in_flight"] or row["root_pid"] is not None or row["root_outcome"] is not None):
                    raise LifecycleError("invalid_lifecycle_transition")
                if row["job_name"] is not None or row["job_nonce"] is not None or row["guardian_epoch"]:
                    raise LifecycleError("job_scope_already_registered")
                if runtime["admission_barrier"] != "NONE":
                    raise LifecycleError("launch_barrier_active")
                if (runtime["active_logon_id"] not in {"", row["logon_id"]} or
                        runtime["guardian_epoch"] not in {"", guardian_epoch}):
                    raise LifecycleError("guardian_identity_mismatch")
                if expected_auth is not None:
                    self._require_authenticated_allocation(conn, row)
                else:
                    self._require_allocation(conn, execution_id)
                enrolled = conn.execute("""SELECT count(*) FROM managed_executions
                    WHERE allocation_kind IN ('direct','routed') AND job_name IS NOT NULL
                      AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED')""").fetchone()[0]
                if enrolled >= MAX_ENROLLED_JOBS:
                    raise LifecycleError("managed_job_limit_reached")
                conn.execute("UPDATE adaptive_runtime SET active_logon_id=?,guardian_epoch=? WHERE singleton=1",
                             (row["logon_id"], guardian_epoch))
                return self._launch_ack(self._cas(conn, execution_id, expected_revision,
                    {"job_name": job_name, "job_nonce": job_nonce, "guardian_epoch": guardian_epoch}), expected_auth)

    def mark_prepared(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int,
                      expected_auth: _IpcAuthRecord | None = None) -> dict[str, Any]:
        snapshot = self._launch_snapshot(execution_id, caller, expected_auth)
        replay = expected_auth is not None and snapshot["state"] == "PREPARED"
        if not replay:
            self._require_revision(snapshot, expected_revision)
        self._caller(snapshot, caller)
        with self._publication_scope(caller) as publication:
            with self._evidence_scope("prepare", snapshot, caller, publication=publication) as proof:
                with self._publication_transaction(*publication) as conn:
                    if expected_auth is not None:
                        _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
                    if (not proof.guardian_epoch or not proof.job_name or not proof.original_cpu_disabled or
                            not proof.durable_manifest or not proof.legacy_exclusion or type(proof.active_process_count) is not int or
                            proof.active_process_count != 0 or proof.process_ids != () or proof.job_creation_never_attempted):
                        raise LifecycleError("job_preparation_unverified")
                    row = self._get(conn, execution_id)
                    self._require_revision(row, snapshot["state_revision"] if replay else expected_revision)
                    if expected_auth is not None:
                        self._require_authenticated_allocation(conn, row)
                    if replay:
                        if (row["state"] != "PREPARED" or row["job_name"] != proof.job_name or
                                row["job_nonce"] != proof.job_nonce or row["guardian_epoch"] != proof.guardian_epoch or
                                row["coverage"] != "job_contained"):
                            raise LifecycleError("job_scope_evidence_mismatch")
                        return self._launch_ack(row, expected_auth, duplicate=True)
                    if row["state"] != "RESERVED" or row["allocation_kind"] == "parent":
                        raise LifecycleError("invalid_lifecycle_transition")
                    self._require_allocation(conn, execution_id)
                    enrolled = conn.execute("""SELECT count(*) FROM managed_executions
                        WHERE allocation_kind IN ('direct','routed') AND job_name IS NOT NULL
                          AND execution_id!=?
                          AND state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED')""", (execution_id,)).fetchone()[0]
                    if enrolled >= MAX_ENROLLED_JOBS:
                        raise LifecycleError("managed_job_limit_reached")
                    if row["job_nonce"] is not None and (row["job_name"] != proof.job_name or
                            row["job_nonce"] != proof.job_nonce or row["guardian_epoch"] != proof.guardian_epoch):
                        raise LifecycleError("job_scope_evidence_mismatch")
                    runtime = conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
                    if runtime["active_logon_id"] not in {"", row["logon_id"]} or runtime["guardian_epoch"] not in {"", proof.guardian_epoch}:
                        raise LifecycleError("guardian_identity_mismatch")
                    conn.execute("UPDATE adaptive_runtime SET active_logon_id=?,guardian_epoch=? WHERE singleton=1", (row["logon_id"], proof.guardian_epoch))
                    return self._launch_ack(self._cas(conn, execution_id, expected_revision, {"state": "PREPARED", "job_name": proof.job_name,
                                        "guardian_epoch": proof.guardian_epoch, "coverage": "job_contained"}), expected_auth)

    @staticmethod
    def _claim_digest(claim_token):
        if type(claim_token) is not str or not 32 <= len(claim_token) <= 128 or not claim_token.isascii():
            raise LifecycleError("invalid_claim_token")
        return hashlib.sha256(claim_token.encode("ascii")).hexdigest()

    def _authenticate_claim(self, row, caller, token_hash, spec_hash, guardian_epoch):
        self._caller(row, caller)
        if (type(row["claim_token_hash"]) is not str or
                not hmac.compare_digest(row["claim_token_hash"], token_hash) or row["spec_hash"] != spec_hash):
            raise LifecycleError("claim_binding_mismatch")
        if row["guardian_epoch"] != guardian_epoch or not guardian_epoch:
            raise LifecycleError("guardian_identity_mismatch")

    def _authenticated_claim_snapshot(self, execution_id, *, caller, token_hash, spec_hash,
                                      guardian_epoch, expected_revision, expected_auth, guard=None):
        # The key, token binding, duplicate flag and allocation share one
        # snapshot. A stale credential cannot authorize even a read-only ACK.
        with self._connection() as conn:
            conn.execute("BEGIN")
            _check_version(conn)
            if guard is not None:
                self._policy.revalidate(conn, guard)
            _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
            row = self._get(conn, execution_id)
            self._authenticate_claim(row, caller, token_hash, spec_hash, guardian_epoch)
            if row["state"] not in TERMINAL_STATES:
                self._require_authenticated_allocation(conn, row)
            if row["claim_consumed"]:
                return self._public(row), True
            self._require_revision(row, expected_revision)
            if row["state"] != "PREPARED" or row["launch_sealed"]:
                raise LifecycleError("invalid_lifecycle_transition")
            runtime = conn.execute("SELECT guardian_epoch,admission_barrier FROM adaptive_runtime WHERE singleton=1").fetchone()
            if runtime is None or runtime[0] != guardian_epoch or runtime[1] != "NONE":
                raise LifecycleError("launch_barrier_active")
            return self._public(row), False

    def claim_launch_locked(self, execution_id: str, *, caller: ProcessIdentity, claim_token: str,
                            spec_hash: str, guardian_epoch: str, expected_revision: int,
                            expected_auth: _IpcAuthRecord) -> dict[str, Any]:
        """Consume the wrapper's one-use token under this store's held POLICY.

        The authenticated service retains its native peer, guardian and Job
        fence. This method neither obtains another POLICY nonce nor substitutes
        the query credential for the separate original launch token. Any lost
        commit/evidence-cleanup ACK must be reconciled as consumed, never retried
        as permission to create another root process.
        """
        from .policy import PolicyError

        token_hash = self._claim_digest(claim_token)
        try:
            guard = self._policy.assert_held()
            if type(caller) is not ProcessIdentity or guard.binding.logon_id != caller.logon_id:
                raise LifecycleError("policy_logon_mismatch")
            snapshot, duplicate = self._authenticated_claim_snapshot(execution_id,
                caller=caller, token_hash=token_hash, spec_hash=spec_hash, guardian_epoch=guardian_epoch,
                expected_revision=expected_revision, expected_auth=expected_auth, guard=guard)
            if duplicate:
                return self._launch_ack(snapshot, expected_auth, duplicate=True)
            with self._evidence_scope("claim", snapshot, caller) as proof:
                if proof.guardian_epoch != guardian_epoch:
                    raise LifecycleError("guardian_identity_mismatch")
                self._policy.assert_held(guard)
                with self._transaction() as conn:
                    runtime = self._policy.revalidate(conn, guard)
                    _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
                    row = self._get(conn, execution_id)
                    self._authenticate_claim(row, caller, token_hash, spec_hash, guardian_epoch)
                    if row["state"] not in TERMINAL_STATES:
                        self._require_authenticated_allocation(conn, row)
                    if row["claim_consumed"]:
                        result = self._launch_ack(row, expected_auth, duplicate=True)
                    else:
                        self._require_revision(row, expected_revision)
                        if row["state"] != "PREPARED" or row["launch_sealed"]:
                            raise LifecycleError("invalid_lifecycle_transition")
                        if runtime["guardian_epoch"] != guardian_epoch or runtime["admission_barrier"] != "NONE":
                            raise LifecycleError("launch_barrier_active")
                        updated = self._cas(conn, execution_id, expected_revision,
                            {"state": "LAUNCHING", "claim_consumed": 1, "launch_in_flight": 1})
                        result = {**self._public(updated), "launch_authorized": True, "duplicate": False}
            # Evidence must exit successfully before returning new authority.
            # The caller still owns POLICY and its outer per-Job/native scope.
            return result
        except PolicyError as error:
            translated = LifecycleError(str(error))
            for note in getattr(error, "__notes__", ()):
                translated.add_note(note)
            raise translated from error

    def claim_launch(self, execution_id: str, *, caller: ProcessIdentity, claim_token: str, spec_hash: str,
                     guardian_epoch: str, expected_revision: int,
                     expected_auth: _IpcAuthRecord | None = None) -> dict[str, Any]:
        if expected_auth is not None:
            token_hash = self._claim_digest(claim_token)
            snapshot, duplicate = self._authenticated_claim_snapshot(execution_id,
                caller=caller, token_hash=token_hash, spec_hash=spec_hash, guardian_epoch=guardian_epoch,
                expected_revision=expected_revision, expected_auth=expected_auth)
            if duplicate:
                return self._launch_ack(snapshot, expected_auth, duplicate=True)
            with self._publication_scope(caller):
                result = self.claim_launch_locked(execution_id, caller=caller, claim_token=claim_token,
                    spec_hash=spec_hash, guardian_epoch=guardian_epoch, expected_revision=expected_revision,
                    expected_auth=expected_auth)
            return result
        from .policy import PolicyBusy, PolicyError
        from .windows import NativePolicyMutexError

        if not isinstance(claim_token, str) or not 32 <= len(claim_token) <= 128 or not claim_token.isascii():
            raise LifecycleError("invalid_claim_token")
        token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()

        def authenticate(row):
            self._caller(row, caller)
            if not hmac.compare_digest(row["claim_token_hash"], token_hash) or row["spec_hash"] != spec_hash:
                raise LifecycleError("claim_binding_mismatch")
            if row["guardian_epoch"] != guardian_epoch or not guardian_epoch:
                raise LifecycleError("guardian_identity_mismatch")

        def inspect():
            # Duplicate delivery remains read-only, even under a barrier or
            # uncertain policy nonce. It never receives a new launch authority.
            with self._connection() as conn:
                _check_version(conn)
                row = self._get(conn, execution_id)
                authenticate(row)
                if row["claim_consumed"]:
                    return self._public(row), True
                self._require_revision(row, expected_revision)
                if row["state"] != "PREPARED" or row["launch_sealed"]:
                    raise LifecycleError("invalid_lifecycle_transition")
                runtime = conn.execute("SELECT guardian_epoch,admission_barrier FROM adaptive_runtime WHERE singleton=1").fetchone()
                if runtime is None or runtime[0] != guardian_epoch or runtime[1] != "NONE":
                    raise LifecycleError("launch_barrier_active")
                return self._public(row), False

        snapshot, duplicate = inspect()
        if duplicate:
            return {**snapshot, "launch_authorized": False, "duplicate": True}
        try:
            logon_id = self._policy.current_logon()
            if logon_id != caller.logon_id:
                raise PolicyError("policy_logon_mismatch")
            deadline = time.monotonic() + 1.0
            while True:
                try:
                    guard = self._policy.prepare(logon_id)
                    break
                except PolicyBusy:
                    snapshot, duplicate = inspect()
                    if duplicate:
                        return {**snapshot, "launch_authorized": False, "duplicate": True}
                    if time.monotonic() >= deadline:
                        raise
                    # No connection/transaction/native mutex is held here.
                    time.sleep(min(.01, max(0, deadline - time.monotonic())))
            with self._policy.hold(guard):
                # Another delivery may have committed immediately before this
                # entry acquired its nonce. Recheck before asking for native
                # lifecycle evidence, which a read-only duplicate never needs.
                with self._connection() as conn:
                    _check_version(conn)
                    completed = self._get(conn, execution_id)
                    is_duplicate = (completed["claim_consumed"] and
                        hmac.compare_digest(completed["claim_token_hash"], token_hash) and
                        completed["spec_hash"] == spec_hash and completed["guardian_epoch"] == guardian_epoch and
                        completed["wrapper_pid"] == caller.pid and
                        completed["wrapper_created_filetime_100ns"] == str(caller.created_filetime_100ns) and
                        completed["logon_id"] == caller.logon_id)
                    duplicate_result = ({**self._public(completed), "launch_authorized": False, "duplicate": True}
                                        if is_duplicate else None)
                if duplicate_result is not None:
                    return duplicate_result
                # POLICY precedes the provider, which may own a per-Job fence.
                # Both survive the claim transaction and its cleanup.
                with self._evidence_scope("claim", snapshot, caller) as proof:
                    if proof.guardian_epoch != guardian_epoch:
                        raise LifecycleError("guardian_identity_mismatch")
                    decision_error = None
                    try:
                        with self._transaction() as conn:
                            runtime = self._policy.revalidate(conn, guard)
                            row = self._get(conn, execution_id)
                            try:
                                authenticate(row)
                                if row["claim_consumed"]:
                                    result = {**self._public(row), "launch_authorized": False, "duplicate": True}
                                else:
                                    self._require_revision(row, expected_revision)
                                    if row["state"] != "PREPARED" or row["launch_sealed"]:
                                        raise LifecycleError("invalid_lifecycle_transition")
                                    if runtime["guardian_epoch"] != guardian_epoch or runtime["admission_barrier"] != "NONE":
                                        raise LifecycleError("launch_barrier_active")
                                    result = None
                            except LifecycleError as error:
                                # Mark only these checks at the actual decision
                                # point, not a provider raising a similar error.
                                decision_error = error
                                raise
                            if result is None:
                                self._require_allocation(conn, execution_id)
                                updated = self._cas(conn, execution_id, expected_revision,
                                    {"state": "LAUNCHING", "claim_consumed": 1, "launch_in_flight": 1})
                                result = {**self._public(updated), "launch_authorized": True, "duplicate": False}
                    except LifecycleError as error:
                        # Rollback and connection cleanup have now completed.
                        if error is decision_error and not getattr(error, "__notes__", ()):
                            guard.clean_rejection = True
                        raise
            # No successful authority ACK before native release + nonce clear.
            return result
        except (PolicyError, NativePolicyMutexError) as error:
            raise LifecycleError(str(error)) from error

    def query_control_slot_locked(self) -> dict[str, Any] | None:
        """Read the exact slot under borrowed POLICY; unknown is never empty."""
        from .control_slot import ControlSlotError, query_locked
        from .policy import PolicyError

        try:
            guard = self._policy.assert_held()
            try:
                ledger_path = Path(self.db_path).resolve()
            except (OSError, TypeError, ValueError, RuntimeError):
                raise LifecycleError("control_slot_registry_unavailable") from None
            with _coverage_read_transaction(ledger_path) as conn:
                runtime = self._policy.revalidate(conn, guard)
                try:
                    result = query_locked(conn, runtime, guard)
                except ControlSlotError as error:
                    # Convert this module's deliberate domain rejection before
                    # the generic reader sanitizes ValueError from decoding.
                    # Missing/unknown storage remains a rejection, never None.
                    raise LifecycleError(str(error)) from error
            self._policy.assert_held(guard)
            return result
        except (ControlSlotError, PolicyError) as error:
            raise LifecycleError(str(error)) from error

    def begin_control_slot_locked(self, execution_id: str, *, caller: ProcessIdentity,
                                  expected_revision: int, slot_id: str,
                                  exemption_revision: int) -> dict[str, Any]:
        """Reserve one control responsibility before intent or native Set.

        The trusted caller already holds POLICY, authenticates fresh exemption
        state under that lock and retains its native Job evidence fence through
        this call. exemption_revision records that external observation; this
        method does not authenticate the separate grant authority. It returns
        no Set/renewal authority, including on exact lost-ACK replay. The current
        wrapper binding plus original guardian epoch is P1 provenance, not a
        substitute for authenticating a separate production guardian process.
        """
        from .control_slot import ControlSlotError, begin_locked, require_evidence
        from .policy import PolicyError

        decision_error = None
        try:
            guard = self._policy.assert_held()
            snapshot = self.query(execution_id)
            self._require_revision(snapshot, expected_revision)
            self._caller(snapshot, caller)
            if guard.binding.logon_id != caller.logon_id:
                raise LifecycleError("policy_logon_mismatch")
            with self._evidence_scope("control_begin", snapshot, caller) as proof:
                require_evidence(snapshot, proof, restoring=False)
                self._policy.assert_held(guard)
                with self._transaction() as conn:
                    try:
                        runtime = self._policy.revalidate(conn, guard)
                        row = self._get(conn, execution_id)
                        self._require_revision(row, expected_revision)
                        self._caller(row, caller)
                        require_evidence(row, proof, restoring=False)
                        self._require_allocation(conn, execution_id)
                        result = begin_locked(conn, row, runtime, guard, proof,
                            slot_id=slot_id, exemption_revision=exemption_revision)
                    except (ControlSlotError, LifecycleError, PolicyError) as error:
                        # Mark only the exact synchronous decision exception.
                        # Commit/rollback, connection and evidence cleanup all
                        # finish before its classification below can be used.
                        decision_error = error
                        raise
            return result
        except (ControlSlotError, LifecycleError, PolicyError) as error:
            if error is decision_error and not getattr(error, "__notes__", ()):
                raise ControlSlotRejected(str(error)) from error
            if isinstance(error, LifecycleError):
                raise
            raise LifecycleError(str(error)) from error

    def release_control_slot_locked(self, execution_id: str, *, caller: ProcessIdentity,
                                    expected_revision: int, slot_id: str) -> dict[str, Any]:
        """Record verified restoration, retaining the host recovery barrier.

        Restore the owned native cap before calling this method: unreadable DB,
        changed eligibility or grant authority cannot authorize retaining that
        cap. Only the already held evidence scope's current disabled Query and
        settled exact durable manifest permit this bookkeeping transition. No
        fresh-sample counter or barrier-clear shortcut is provided here.
        """
        from .control_slot import ControlSlotError, release_locked, require_evidence
        from .policy import PolicyError

        try:
            guard = self._policy.assert_held()
            snapshot = self.query(execution_id)
            self._require_revision(snapshot, expected_revision)
            self._caller(snapshot, caller)
            if guard.binding.logon_id != caller.logon_id:
                raise LifecycleError("policy_logon_mismatch")
            with self._evidence_scope("control_restore", snapshot, caller) as proof:
                require_evidence(snapshot, proof, restoring=True)
                self._policy.assert_held(guard)
                with self._transaction() as conn:
                    runtime = self._policy.revalidate(conn, guard)
                    row = self._get(conn, execution_id)
                    self._require_revision(row, expected_revision)
                    self._caller(row, caller)
                    require_evidence(row, proof, restoring=True)
                    result = release_locked(conn, row, runtime, guard, slot_id=slot_id)
            return result
        except (ControlSlotError, PolicyError) as error:
            raise LifecycleError(str(error)) from error

    def enter_recovery_hold(self, *, expected_registry_revision: int,
                            reason: str = "recovery_unverified") -> dict[str, Any]:
        """Persist a conservative barrier under POLICY; never clear or tighten.

        This internal cooperating-writer operation grants no guardian/actuator
        authority. A repeated existing hold is a read-only acknowledgement.
        """
        from .policy import PolicyError
        from .windows import NativePolicyMutexError
        if type(expected_registry_revision) is not int or expected_registry_revision < 0:
            raise ValueError("invalid_registry_revision")
        if reason != "recovery_unverified":
            raise ValueError("invalid_recovery_reason")
        with self._connection() as conn:
            _check_version(conn)
            row = self._policy._runtime(conn)
        if row["admission_barrier"] == "RECOVERY_HOLD":
            return {"admission_barrier": "RECOVERY_HOLD", "registry_revision": row["registry_revision"]}
        if row["registry_revision"] != expected_registry_revision:
            raise LifecycleError("revision_conflict")
        try:
            logon_id = self._policy.current_logon()
            guard = self._policy.prepare(logon_id)
            with self._policy.hold(guard):
                decision_error = None
                try:
                    with self._transaction() as conn:
                        row = self._policy.revalidate(conn, guard)
                        if row["admission_barrier"] != "RECOVERY_HOLD":
                            if row["registry_revision"] != expected_registry_revision:
                                decision_error = LifecycleError("revision_conflict")
                                raise decision_error
                            conn.execute("UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD',registry_revision=registry_revision+1 WHERE singleton=1")
                        row = self._policy._runtime(conn)
                        result = {"admission_barrier": row["admission_barrier"], "registry_revision": row["registry_revision"]}
                except LifecycleError as error:
                    if error is decision_error and not getattr(error, "__notes__", ()):
                        guard.clean_rejection = True
                    raise
            return result
        except (PolicyError, NativePolicyMutexError) as error:
            raise LifecycleError(str(error)) from error

    @staticmethod
    def _require_never_started(row: Mapping[str, Any], proof: LifecycleEvidence) -> None:
        """A trusted launch fence plus positive evidence, never absence alone.

        The evidence provider retains its launch fence through the transaction.
        CAS then invalidates the claim durably. For a subspan there is no own Job
        to empty: sealing this child's launch must not close its parent's Job.
        """
        if (proof.user_code_started is not False or not proof.launch_sealed or
                proof.root is not None or row["root_pid"] is not None or row["root_outcome"] is not None or
                proof.guardian_epoch != row["guardian_epoch"] or proof.job_name != row["job_name"]):
            raise LifecycleError("never_started_unverified")
        if row["job_name"] is not None:
            if proof.job_creation_never_attempted:
                # A planned name is not an empty native Job. Only the same
                # owner, having irreversibly fenced creation before its first
                # attempt, may take this no-query path. Lost ownership, failed
                # Create or Open-not-found cannot reproduce this capability.
                if (row["job_nonce"] is None or row["state"] != "RESERVED" or
                        row["claim_consumed"] or row["launch_in_flight"] or
                        proof.active_process_count is not None or proof.process_ids is not None or
                        not proof.recovery_manifest_settled):
                    raise LifecycleError("never_started_unverified")
            elif (not row["guardian_epoch"] or type(proof.active_process_count) is not int or
                    proof.active_process_count != 0 or proof.process_ids != ()):
                raise LifecycleError("never_started_unverified")
            elif row["job_nonce"] is not None and (
                    not proof.current_cpu_disabled or not proof.recovery_manifest_settled):
                raise LifecycleError("restore_unverified")
        elif proof.active_process_count is not None or proof.process_ids is not None:
            # No Job exists for RESERVED/subspan records. Do not accept an
            # invented empty Job query or use the running parent's counts.
            raise LifecycleError("never_started_unverified")
        elif proof.job_creation_never_attempted:
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
        updates = {"state": state, "finished_at": now, "launch_sealed": 1,
                   "launch_in_flight": 0, "claim_consumed": 1, "claim_token_hash": "", "hold_reason": None}
        if state == "CANCELLED_BEFORE_START":
            updates["cancel_requested_at"] = now
        finished = self._cas(conn, row["execution_id"], expected_revision, updates)
        if row["allocation_kind"] != "parent":
            self._archive_allocation(conn, finished, now, outcome="managed_" + state.lower())
        return self._public(finished)

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
        with self._evidence_scope("cancel", snapshot, caller) as proof:
            prelaunch = (snapshot["state"] in {"RESERVED", "PREPARED"} and
                         not snapshot["claim_consumed"] and not snapshot["launch_in_flight"])
            if prelaunch:
                self._require_never_started(snapshot, proof)
            with self._transaction() as conn:
                row = self._get(conn, execution_id)
                self._require_revision(row, expected_revision)
                self._caller(row, caller)
                if proof.prelaunch_record_hash is not None:
                    try:
                        source = validate_active_allocation(
                            conn, execution_id, local_context=self._local_context)
                    except AccountingError as error:
                        raise LifecycleError(str(error)) from error
                    if source["allocation_kind"] != "direct":
                        raise LifecycleError("prelaunch_record_changed")
                    actual_hash = prelaunch_record_hash(
                        row, claim_token_hash=row["claim_token_hash"],
                        allocation=source["allocation"])
                    if not hmac.compare_digest(actual_hash, proof.prelaunch_record_hash):
                        raise LifecycleError("prelaunch_record_changed")
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
        with self._evidence_scope("start_failed", snapshot, caller) as proof:
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

    def bind_root(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int,
                  expected_auth: _IpcAuthRecord | None = None) -> dict[str, Any]:
        snapshot = self._launch_snapshot(execution_id, caller, expected_auth)
        replay = (expected_auth is not None and snapshot["state"] in {"RUNNING", "DRAINING", "UNCERTAIN_HOLD"} and
                  snapshot["root_pid"] is not None and snapshot["claim_consumed"] and
                  snapshot["launch_sealed"] and not snapshot["launch_in_flight"])
        if not replay:
            self._require_revision(snapshot, expected_revision)
        with self._evidence_scope("bind_root", snapshot, caller) as proof:
            if (not isinstance(proof.root, ProcessIdentity) or proof.root.logon_id != caller.logon_id or
                    proof.guardian_epoch != snapshot["guardian_epoch"] or proof.job_name != snapshot["job_name"] or not proof.launch_sealed):
                raise LifecycleError("root_binding_unverified")
            guard = None
            if expected_auth is not None:
                from .policy import PolicyError
                try:
                    guard = self._policy.assert_held()
                    if guard.binding.logon_id != caller.logon_id:
                        raise PolicyError("policy_logon_mismatch")
                except PolicyError as error:
                    raise LifecycleError(str(error)) from error
            with self._transaction() as conn:
                if expected_auth is not None:
                    self._policy.revalidate(conn, guard)
                    _revalidate_launch_auth(conn, execution_id, caller, expected_auth)
                row = self._get(conn, execution_id)
                self._require_revision(row, snapshot["state_revision"] if replay else expected_revision)
                if expected_auth is not None:
                    self._require_authenticated_allocation(conn, row)
                else:
                    self._require_allocation(conn, execution_id)
                if replay:
                    # The immutable request journal belongs to the service;
                    # the store additionally verifies current native root
                    # custody and the surviving allocation. An old request
                    # revision cannot regress DRAINING/HOLD or repeat a CAS.
                    if (row["root_pid"] != proof.root.pid or
                            row["root_created_filetime_100ns"] != str(proof.root.created_filetime_100ns) or
                            row["logon_id"] != proof.root.logon_id):
                        raise LifecycleError("root_binding_unverified")
                    return self._launch_ack(row, expected_auth, duplicate=True)
                if row["state"] not in {"LAUNCHING", "START_UNKNOWN"} or not row["launch_in_flight"]:
                    raise LifecycleError("invalid_lifecycle_transition")
                return self._launch_ack(self._cas(conn, execution_id, expected_revision, {"state": "RUNNING", "root_pid": proof.root.pid,
                    "root_created_filetime_100ns": str(proof.root.created_filetime_100ns), "launch_in_flight": 0, "launch_sealed": 1}), expected_auth)

    def mark_root_exited(self, execution_id: str, *, caller: ProcessIdentity, expected_revision: int, exit_code: int) -> dict[str, Any]:
        if type(exit_code) is not int or not -(1 << 31) <= exit_code < (1 << 32):
            raise ValueError("invalid_exit_code")
        snapshot = self.query(execution_id)
        self._require_revision(snapshot, expected_revision)
        with self._evidence_scope("root_exited", snapshot, caller) as proof:
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
        with self._evidence_scope("finalize", snapshot, caller) as proof:
            if (snapshot["allocation_kind"] == "parent" or not snapshot["job_name"] or proof.job_name != snapshot["job_name"] or
                    proof.guardian_epoch != snapshot["guardian_epoch"] or type(proof.active_process_count) is not int or proof.active_process_count != 0 or
                    proof.process_ids != () or not proof.launch_sealed):
                raise LifecycleError("job_empty_unverified")
            # Initial disabled state is not restoration evidence. The provider
            # must query current CPU control and settle the matching durable
            # recovery manifest (no pending intent or active applied cap), while
            # retaining policy/Job mutation fences through this transaction.
            # Empty membership alone cannot release recovery/accounting custody.
            if not proof.current_cpu_disabled or not proof.recovery_manifest_settled:
                raise LifecycleError("restore_unverified")
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
                finished = self._cas(conn, execution_id, expected_revision, {"state": "FINISHED", "finished_at": now,
                    "launch_sealed": 1, "launch_in_flight": 0})
                self._archive_allocation(conn, finished, now)
                return self._public(finished)

    @staticmethod
    def _archive_allocation(conn: sqlite3.Connection, row: Mapping[str, Any], now: float,
                            *, outcome: str = "managed_finished") -> None:
        from .control_slot import ControlSlotError, require_archive_clear

        if outcome not in {"managed_finished", "managed_cancelled_before_start", "managed_start_failed"}:
            raise LifecycleError("invalid_archive_outcome")
        try:
            require_archive_clear(conn, row)
        except ControlSlotError as error:
            raise LifecycleError(str(error)) from error
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
