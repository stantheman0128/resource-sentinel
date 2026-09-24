"""Original-parent daily admission intents; never child admission authority.

One immutable member fixes one isolated execution/reservation before that
ledger's admission transaction. A row proves only the daily intent: missing
isolated ACK, local expiry, cancellation or terminal state cannot release it.
There is no isolated connection, native getter, RPC, completion or reuse here.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import sqlite3
import threading

from sentinel import coordinator
from . import experiment_host_ledger as ledger
from .admission import ManagedAdmissionSnapshot
from .contracts import Priority, ProcessIdentity, ResourceDemand, Role


TABLE = "adaptive_experiment_host_backings"
MAX_BACKINGS = 10
_PREFIX = "experiment_partition_backing_"
_UDF = "sentinel_experiment_partition_original_insert"
_CREATE = object()
_INSERTS = {}
FIELDS = ("member_id", "scope_id", "wrapper_member_id", "wrapper_identity_json",
    "isolated_execution_id", "isolated_reservation_id", "request_key", "request_spec_hash",
    "spec_hash", "admission_binding_hash", "requested_json", "scope_binding_sha256",
    "isolated_ledger_identity_json", "schema_version", "registered_revision", "binding_sha256")
_UNIQUE = ("member_id", "wrapper_member_id", "isolated_execution_id", "isolated_reservation_id", "request_key")
_BOUNDS = {name: 128 for name in FIELDS if name not in {"schema_version", "registered_revision"}}
_BOUNDS.update(wrapper_identity_json=1024, requested_json=1024)
SCHEMA = f"""CREATE TABLE {TABLE} (
    member_id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL,
    wrapper_member_id TEXT UNIQUE NOT NULL, wrapper_identity_json TEXT NOT NULL,
    isolated_execution_id TEXT UNIQUE NOT NULL, isolated_reservation_id TEXT UNIQUE NOT NULL,
    request_key TEXT UNIQUE NOT NULL, request_spec_hash TEXT NOT NULL,
    spec_hash TEXT NOT NULL, admission_binding_hash TEXT NOT NULL, requested_json TEXT NOT NULL,
    scope_binding_sha256 TEXT NOT NULL, isolated_ledger_identity_json TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK(schema_version=1),
    registered_revision INTEGER NOT NULL CHECK(registered_revision>=0), binding_sha256 TEXT NOT NULL)"""
GUARDS = {_PREFIX + "insert": f"CREATE TRIGGER {_PREFIX}insert BEFORE INSERT ON {TABLE} "
    f"WHEN {_UDF}(" + ",".join("NEW." + key for key in FIELDS) + ") IS NOT 1 "
    "BEGIN SELECT RAISE(ABORT,'experiment_backing_original_insert_required'); END"}
for _event in ("UPDATE", "DELETE"):
    GUARDS[_PREFIX + _event.lower()] = f"CREATE TRIGGER {_PREFIX}{_event.lower()} BEFORE {_event} ON {TABLE} " \
        "BEGIN SELECT RAISE(ABORT,'experiment_backing_immutable'); END"
GUARDS[_PREFIX + "replace"] = f"CREATE TRIGGER {_PREFIX}replace BEFORE INSERT ON {TABLE} WHEN EXISTS(" \
    f"SELECT 1 FROM {TABLE} WHERE " + " OR ".join(key + "=NEW." + key for key in _UNIQUE) + \
    " OR rowid=NEW.rowid) BEGIN SELECT RAISE(ABORT,'experiment_backing_immutable'); END"


class BackingError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_backing_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise BackingError(reason)


def _hash(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _fail("hash_invalid")
    return value


@dataclass(frozen=True)
class IsolatedAdmissionBinding:
    """Safe immutable observation, with no claim token or IPC credential."""
    execution_id: str
    reservation_id: str
    request_key: str
    request_spec_hash: str
    spec_hash: str
    admission_binding_hash: str
    wrapper_identity: ProcessIdentity
    requested: ResourceDemand

    def __post_init__(self):
        ledger._uuid(self.execution_id)
        ledger._text(self.reservation_id)
        for value in (self.request_key, self.request_spec_hash, self.spec_hash, self.admission_binding_hash):
            _hash(value)
        ledger._identity(self.wrapper_identity)
        ledger._resources(self.requested)

    def to_dict(self):
        return dict(execution_id=self.execution_id, reservation_id=self.reservation_id,
            request_key=self.request_key, request_spec_hash=self.request_spec_hash, spec_hash=self.spec_hash,
            admission_binding_hash=self.admission_binding_hash, wrapper_identity=self.wrapper_identity.to_dict(),
            requested=self.requested.to_dict())


def _snapshot_binding(snapshot, reservation_id):
    # Never call ManagedAdmission.snapshot()/snapshot_for_ledger here: they
    # inspect native identity and paths. The parent receives observation only.
    if type(snapshot) is not ManagedAdmissionSnapshot:
        _fail("snapshot_required")
    if (type(snapshot.wrapper_identity) is not ProcessIdentity or type(snapshot.requested) is not ResourceDemand or
            type(snapshot.request) is not coordinator.ResourceRequest or
            type(snapshot.role) is not Role or type(snapshot.priority) is not Priority or
            snapshot.logon_id != snapshot.wrapper_identity.logon_id):
        _fail("snapshot_scope_invalid")
    # This is capacity provenance, not CPU-control eligibility. The actual
    # guardian still limits new control to explicit background P2/P3 work.
    request, identity, resources = snapshot.request, snapshot.wrapper_identity, snapshot.requested
    _hash(snapshot.spec_hash)
    _hash(snapshot.binding_hash)
    if (any(type(getattr(request, key)) is not str for key in
            ("repo", "command", "resource_class", "priority", "tool_use_id", "signature")) or
            any(type(getattr(request, key)) not in (int, float) or not math.isfinite(getattr(request, key))
                for key in ("owner_started", "cpu_units", "ram_gib")) or
            any(type(getattr(request, key)) is not int for key in ("owner_pid", "io_slots", "commit_bytes"))):
        _fail("snapshot_request_changed")
    if (request.owner_pid != identity.pid or request.owner_started !=
            (identity.created_filetime_100ns - 116444736000000000) / 10_000_000 or
            request.tool_use_id != "managed-v1:" + snapshot.execution_id or request.signature != snapshot.spec_hash[:20] or
            request.resource_class != "HEAVY" or request.priority != snapshot.priority.value or request.command != "" or
            request.cpu_units != resources.cpu_units or request.ram_gib * (1 << 30) != resources.physical_bytes or
            request.commit_bytes != resources.commit_bytes or request.io_slots != resources.io_slots):
        _fail("snapshot_request_changed")
    return IsolatedAdmissionBinding(snapshot.execution_id, reservation_id, snapshot.request.request_key,
        snapshot.request.spec_hash, snapshot.spec_hash, snapshot.binding_hash, snapshot.wrapper_identity,
        snapshot.requested)


class ParentAdmissionBacking:
    """Retained original parent publication; cannot stand in for a child owner."""
    def __init__(self, scope, member_id, wrapper_member_id, snapshot, binding, *, _token=None):
        if _token is not _CREATE:
            _fail("original_operation_required")
        self.scope, self.member_id, self.wrapper_member_id = scope, member_id, wrapper_member_id
        self.binding = binding
        self._snapshot = snapshot
        self._fixed = (scope, member_id, wrapper_member_id, snapshot, binding)
        self._payload = ledger._canonical(binding.to_dict())
        self._row = None
        self._row_payload = None

    @classmethod
    def prepare(cls, *, scope, member_id, wrapper_member_id, snapshot, reservation_id):
        if cls is not ParentAdmissionBacking or type(scope) is not ledger.RegisteredHostScope:
            _fail("original_scope_required")
        scope._original()
        ledger._uuid(member_id)
        ledger._uuid(wrapper_member_id)
        if member_id == wrapper_member_id:
            _fail("member_binding_invalid")
        binding = _snapshot_binding(snapshot, reservation_id)
        original = scope._backings.get(member_id)
        if original is not None:
            original._original()
            if (original._snapshot is not snapshot or original.wrapper_member_id != wrapper_member_id or
                    original.binding != binding):
                _fail("original_operation_changed")
            return original
        original = cls(scope, member_id, wrapper_member_id, snapshot, binding, _token=_CREATE)
        scope._backings[member_id] = original
        return original

    def _original(self):
        if (type(self) is not ParentAdmissionBacking or type(self.scope) is not ledger.RegisteredHostScope or
                self.scope._backings.get(self.member_id) is not self or self.scope is not self._fixed[0] or
                (self.member_id, self.wrapper_member_id) != self._fixed[1:3] or
                self._snapshot is not self._fixed[3] or self.binding is not self._fixed[4]):
            _fail("original_operation_required")
        scope = self.scope._original()
        if (ledger._canonical(self.binding.to_dict()) != self._payload or
                _snapshot_binding(self._snapshot, self.binding.reservation_id) != self.binding):
            _fail("original_payload_changed")
        if (self._row is None) != (self._row_payload is None) or self._row is not None and ledger._canonical(self._row) != self._row_payload:
            _fail("original_publication_changed")
        return scope


@dataclass(frozen=True)
class BackingObservation:
    scope_id: str
    member_id: str
    wrapper_member_id: str
    binding: IsolatedAdmissionBinding
    registered_revision: int
    binding_sha256: str
    daily_expires_at: float


def validate_schema_locked(conn):
    ledger._transaction(conn)
    names = (TABLE, *GUARDS)
    rows = conn.execute("SELECT name,type,CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END "
        "FROM sqlite_master WHERE name IN (" + ",".join("?" for _ in names) + ") OR name GLOB ? "
        "OR (type='trigger' AND tbl_name=?) LIMIT 17", (*names, _PREFIX + "*", TABLE)).fetchall()
    if not rows:
        return False
    expected = {TABLE: ("table", ledger._sql(SCHEMA)),
                **{key: ("trigger", ledger._sql(value)) for key, value in GUARDS.items()}}
    if len(rows) != len(expected) or {row[0]: (row[1], ledger._sql(row[2])) for row in rows} != expected:
        _fail("schema_invalid")
    if tuple(row[1] for row in conn.execute("PRAGMA table_info(" + TABLE + ")")) != FIELDS:
        _fail("schema_invalid")
    indexes = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? LIMIT 9", (TABLE,)).fetchall()
    expected_indexes = {f"sqlite_autoindex_{TABLE}_{index}": (key,) for index, key in enumerate(_UNIQUE, 1)}
    if len(indexes) != len(expected_indexes) or any(row[1] is not None for row in indexes):
        _fail("schema_invalid")
    for name, _ in indexes:
        if name not in expected_indexes or tuple(row[2] for row in conn.execute(
                "PRAGMA index_info(" + name + ")")) != expected_indexes[name]:
            _fail("schema_invalid")
    return True


def _values(scope, operation):
    binding = operation.binding
    return dict(member_id=operation.member_id, scope_id=scope["scope_id"],
        wrapper_member_id=operation.wrapper_member_id, wrapper_identity_json=ledger._canonical(binding.wrapper_identity.to_dict()),
        isolated_execution_id=binding.execution_id, isolated_reservation_id=binding.reservation_id,
        request_key=binding.request_key, request_spec_hash=binding.request_spec_hash, spec_hash=binding.spec_hash,
        admission_binding_hash=binding.admission_binding_hash, requested_json=ledger._canonical(binding.requested.to_dict()),
        scope_binding_sha256=scope["binding_sha256"], isolated_ledger_identity_json=scope["isolated_ledger_identity_json"])


def _binding(row):
    return IsolatedAdmissionBinding(row["isolated_execution_id"], row["isolated_reservation_id"], row["request_key"],
        row["request_spec_hash"], row["spec_hash"], row["admission_binding_hash"],
        ProcessIdentity.from_dict(ledger._decode(row["wrapper_identity_json"])),
        ResourceDemand.from_dict(ledger._decode(row["requested_json"])))


def _validate_relation(row, tables, revision, conn):
    matches = [scope for scope in tables[ledger.SCOPES_TABLE] if scope["scope_id"] == row["scope_id"]]
    if len(matches) != 1:
        _fail("scope_missing")
    scope = matches[0]
    binding = _binding(row)
    members = {item["member_id"]: item for item in tables[ledger.MEMBERS_TABLE]}
    actors = {item["member_id"]: item for item in tables[ledger.ACTORS_TABLE]}
    member, wrapper, actor = members.get(row["member_id"]), members.get(row["wrapper_member_id"]), actors.get(row["wrapper_member_id"])
    if (member is None or member["scope_id"] != scope["scope_id"] or member["kind"] != "workload" or
            member["role"] != "workload" or member["demand_json"] != row["requested_json"] or
            wrapper is None or wrapper["scope_id"] != scope["scope_id"] or wrapper["role"] != "wrapper" or
            actor is None or actor["identity_json"] != row["wrapper_identity_json"] or
            binding.wrapper_identity.logon_id != scope["logon_id"] or
            row["scope_binding_sha256"] != scope["binding_sha256"] or
            row["isolated_ledger_identity_json"] != scope["isolated_ledger_identity_json"] or
            binding.execution_id == scope["daily_execution_id"] or binding.reservation_id == scope["reservation_id"] or
            row["registered_revision"] > revision):
        _fail("partition_binding_changed")
    if conn.execute("SELECT 1 FROM managed_executions WHERE execution_id=? OR reservation_id=? LIMIT 1",
            (binding.execution_id, binding.reservation_id)).fetchone() or conn.execute(
            "SELECT 1 FROM reservations WHERE id=? OR execution_id=? OR request_key=? LIMIT 1",
            (binding.reservation_id, binding.execution_id, binding.request_key)).fetchone():
        _fail("daily_identity_alias")
    for job in tables[ledger.JOBS_TABLE]:
        shares_binding = (job["member_id"] == row["member_id"] or
            job["isolated_execution_id"] == binding.execution_id or
            job["isolated_reservation_id"] == binding.reservation_id or
            job["wrapper_member_id"] == row["wrapper_member_id"])
        if shares_binding and (job["kind"] != "managed" or job["member_id"] != row["member_id"] or
                job["isolated_execution_id"] != binding.execution_id or job["isolated_reservation_id"] != binding.reservation_id or
                job["wrapper_member_id"] != row["wrapper_member_id"]):
            _fail("job_binding_changed")
    allocations = conn.execute("SELECT expires_at FROM reservations WHERE id=? AND execution_id=? LIMIT 2",
        (scope["reservation_id"], scope["daily_execution_id"])).fetchall()
    if (len(allocations) != 1 or type(allocations[0][0]) not in (float, int) or
            not math.isfinite(allocations[0][0]) or allocations[0][0] <= 0):
        _fail("daily_allocation_missing")
    return BackingObservation(row["scope_id"], row["member_id"], row["wrapper_member_id"], binding,
                              row["registered_revision"], row["binding_sha256"], float(allocations[0][0]))


def read_for_inventory_locked(conn, *, tables, revision, budget):
    """Private SQL composition; the enclosing ledger owns POLICY and budget."""
    if not validate_schema_locked(conn):
        return ()
    allowance = min(MAX_BACKINGS, ledger.MAX_ROWS - budget.rows)
    valid = "_backing_position<=" + str(allowance) + " AND " + " AND ".join(
        f"typeof({name})='text' AND length(CAST({name} AS BLOB))<={bound * 4} "
        f"AND length({name})<={bound} AND instr({name},char(0))=0" for name, bound in _BOUNDS.items())
    valid += " AND typeof(schema_version)='integer' AND typeof(registered_revision)='integer'"
    projection = ",".join(f"CASE WHEN {valid} THEN {name} END" for name in FIELDS)
    result = []
    for values in conn.execute(f"SELECT {projection},CASE WHEN {valid} THEN 1 ELSE 0 END FROM "
            f"(SELECT {','.join(FIELDS)},row_number() OVER (ORDER BY rowid) AS _backing_position "
            f"FROM {TABLE} ORDER BY rowid LIMIT ?) ORDER BY _backing_position", (allowance + 1,)):
        if len(result) >= allowance:
            _fail("history_or_partition_limit")
        if values[-1] != 1:
            _fail("row_unverified")
        row = dict(zip(FIELDS, tuple(values)[:-1]))
        budget.charge(1, len(ledger._canonical(row).encode("ascii")))
        for key in ("member_id", "scope_id", "wrapper_member_id"):
            ledger._uuid(row[key])
        if (row["schema_version"] != 1 or not 0 <= row["registered_revision"] < 1 << 63 or
                row["binding_sha256"] != ledger._digest({key: value for key, value in row.items() if key != "binding_sha256"})):
            _fail("row_binding_invalid")
        result.append(_validate_relation(row, tables, revision, conn))
    return tuple(result)


def _insert(conn, operation, row, *, policy, guard):
    if id(conn) in _INSERTS:
        _fail("insert_nested")
    marker, thread, consumed = object(), threading.get_ident(), False
    expected = tuple(row[key] for key in FIELDS)
    _INSERTS[id(conn)] = marker
    def authorize(*values):
        nonlocal consumed
        try:
            if (consumed or _INSERTS.get(id(conn)) is not marker or threading.get_ident() != thread or
                    not conn.in_transaction or values != expected or operation._row is not row or
                    tuple(row[key] for key in FIELDS) != expected):
                return 0
            ledger._held(conn, policy, guard)
            scope = operation._original()
            if {key: row[key] for key in _values(scope, operation)} != _values(scope, operation):
                return 0
            consumed = True
            return 1
        except (RuntimeError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
            return 0
    try:
        conn.create_function(_UDF, -1, authorize)
        conn.execute("INSERT INTO " + TABLE + "(" + ",".join(FIELDS) + ") VALUES(" +
                     ",".join("?" for _ in FIELDS) + ")", expected)
        if not consumed:
            _fail("original_insert_required")
    finally:
        try:
            conn.create_function(_UDF, -1, None)
        finally:
            if _INSERTS.get(id(conn)) is marker:
                del _INSERTS[id(conn)]


def publish_locked(conn, *, operation, policy, guard):
    """Commit a parent intent only; caller owns commit and close reconciliation."""
    if type(operation) is not ParentAdmissionBacking:
        _fail("original_operation_required")
    operation._original()
    scope, runtime, tables, history = ledger._publication(conn, operation.scope, policy, guard)
    values = _values(scope, operation)
    if operation._row is None:
        operation._row = ledger._new_row(values, runtime["registry_revision"])
        operation._row_payload = ledger._canonical(operation._row)
    row = operation._row
    if {key: row[key] for key in values} != values:
        _fail("original_payload_changed")
    _validate_relation(row, tables, max(runtime["registry_revision"], row["registered_revision"]), conn)
    present = validate_schema_locked(conn)
    existing = conn.execute("SELECT 1 FROM " + TABLE + " WHERE member_id=?", (operation.member_id,)).fetchone() if present else None
    if existing:
        observed = validate_backing_locked(conn, scope_id=scope["scope_id"], member_id=operation.member_id,
            wrapper_member_id=operation.wrapper_member_id, binding=operation.binding, policy=policy, guard=guard)
        if observed.registered_revision != row["registered_revision"] or observed.binding_sha256 != row["binding_sha256"]:
            _fail("publication_changed")
        return observed
    if operation.scope.demand._native_preparation_sealed:
        _fail("no_new_work")
    ledger._daily_binding(conn, scope, history, guard, restrictive=True)
    if row["registered_revision"] != runtime["registry_revision"] + 1:
        _fail("publication_revision_changed")
    conn.execute("SAVEPOINT experiment_backing_publication")
    try:
        if not present:
            for statement in (SCHEMA, *GUARDS.values()):
                conn.execute(statement)
        _insert(conn, operation, row, policy=policy, guard=guard)
        if conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 "
                "WHERE singleton=1 AND registry_revision=?", (runtime["registry_revision"],)).rowcount != 1:
            _fail("revision_changed")
        observed = validate_backing_locked(conn, scope_id=scope["scope_id"], member_id=operation.member_id,
            wrapper_member_id=operation.wrapper_member_id, binding=operation.binding, policy=policy, guard=guard)
    except BaseException:
        conn.execute("ROLLBACK TO experiment_backing_publication")
        conn.execute("RELEASE experiment_backing_publication")
        raise
    conn.execute("RELEASE experiment_backing_publication")
    return observed


def _validated(conn, *, scope_id, member_id, wrapper_member_id, binding, policy, guard):
    if type(binding) is not IsolatedAdmissionBinding:
        _fail("binding_required")
    for value in (scope_id, member_id, wrapper_member_id):
        ledger._uuid(value)
    inventory, history, tables = ledger._inventory(conn, policy, guard)
    matches = [row for row in inventory.admission_backings if row.scope_id == scope_id and row.member_id == member_id]
    if len(matches) != 1 or matches[0].wrapper_member_id != wrapper_member_id or matches[0].binding != binding:
        _fail("binding_missing_or_changed")
    return matches[0], history, tables


def validate_backing_locked(conn, *, scope_id, member_id, wrapper_member_id, binding, policy, guard):
    """Exact readonly observation; expiry/HOLD never discards the intent."""
    return _validated(conn, scope_id=scope_id, member_id=member_id, wrapper_member_id=wrapper_member_id,
                      binding=binding, policy=policy, guard=guard)[0]


def validate_admission_locked(conn, *, scope_id, member_id, wrapper_member_id, binding, policy, guard):
    """Restrictive SQL observation only; exact child/native authority is separate.

    The caller must finish this daily transaction before any isolated transaction,
    native identity/readiness observation or IPC. No returned value is a permit.
    """
    observed, history, tables = _validated(conn, scope_id=scope_id, member_id=member_id,
        wrapper_member_id=wrapper_member_id, binding=binding, policy=policy, guard=guard)
    scopes = [row for row in tables[ledger.SCOPES_TABLE] if row["scope_id"] == scope_id]
    if len(scopes) != 1:
        _fail("scope_missing")
    ledger._daily_binding(conn, scopes[0], history, guard, restrictive=True)
    return observed
