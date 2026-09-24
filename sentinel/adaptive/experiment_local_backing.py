"""Immutable isolated admission provenance; never custody or daily authority.

Only the original partition adapter can publish, in the SAME isolated
transaction as its original reservation and managed execution. A preimage read
precedes those inserts, so an existing ordinary row cannot be upgraded. The
optional schema is installed by that publication, never by ordinary migration.
Rows survive local cancellation/retirement and do not return daily capacity.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import sqlite3
import threading

from . import experiment_host_ledger as ledger
from .admission import ManagedAdmission, ManagedAdmissionSnapshot
from .contracts import ProcessIdentity, ResourceDemand
from .experiment_host_backing import BackingObservation, _snapshot_binding
from .policy import PolicyCoordinator
from .store import LifecycleError, TERMINAL_STATES


TABLE = "adaptive_experiment_local_backings"
PREFIX = "experiment_local_backing_"
_UDF = "sentinel_experiment_local_original_insert"
_TOKEN = object()
_INSERTS = {}
MAX_ROWS = 128
MAX_BYTES = 16 * 1024 * 1024
FIELDS = ("execution_id", "reservation_id", "request_key", "request_spec_hash", "spec_hash",
    "admission_binding_hash", "scope_id", "member_id", "wrapper_member_id", "scope_nonce",
    "plan_sha256", "source_generation", "source_digest", "config_digest", "daily_ledger_path",
    "daily_ledger_dev", "daily_ledger_ino", "daily_policy_instance_id", "isolated_ledger_path",
    "isolated_ledger_dev", "isolated_ledger_ino", "isolated_policy_instance_id", "wrapper_pid",
    "wrapper_created_filetime_100ns", "logon_id", "cpu_units", "physical_bytes", "commit_bytes",
    "io_slots", "daily_binding_sha256", "daily_registered_revision", "daily_expires_at",
    "schema_version", "link_sha256")
_UNIQUE = ("execution_id", "reservation_id", "request_key", "member_id", "wrapper_member_id")
_INTS = frozenset(("wrapper_pid", "physical_bytes", "commit_bytes", "io_slots",
                   "daily_registered_revision", "schema_version"))
_REALS = frozenset(("cpu_units", "daily_expires_at"))
_PATHS = frozenset(("daily_ledger_path", "isolated_ledger_path"))
_TEXT = frozenset(FIELDS) - _INTS - _REALS
_BOUNDS = {field: 32768 if field in _PATHS else 128 for field in FIELDS}


def _definition(field):
    unique = " PRIMARY KEY" if field == "execution_id" else " UNIQUE" if field in _UNIQUE else ""
    if field in _INTS:
        bounds = " AND " + field + "=1" if field == "schema_version" else " AND " + field + ">=0"
        return f"{field} INTEGER NOT NULL CHECK(typeof({field})='integer'{bounds})"
    if field in _REALS:
        return (f"{field} REAL NOT NULL CHECK(typeof({field}) IN ('integer','real') "
                f"AND {field}>=0 AND {field}<1e308)")
    return (f"{field} TEXT{unique} NOT NULL CHECK(typeof({field})='text' AND "
            f"length(CAST({field} AS BLOB)) BETWEEN 1 AND {_BOUNDS[field]})")


SCHEMA = ("CREATE TABLE " + TABLE + " (" + ",".join(_definition(field) for field in FIELDS) +
    ",FOREIGN KEY(execution_id) REFERENCES managed_executions(execution_id))")
GUARDS = {PREFIX + "insert": "CREATE TRIGGER " + PREFIX + "insert BEFORE INSERT ON " + TABLE +
    " WHEN " + _UDF + "(" + ",".join("NEW." + field for field in FIELDS) + ") IS NOT 1 " +
    "BEGIN SELECT RAISE(ABORT,'experiment_local_original_insert_required'); END"}
for _event in ("UPDATE", "DELETE"):
    GUARDS[PREFIX + _event.lower()] = ("CREATE TRIGGER " + PREFIX + _event.lower() + " BEFORE " +
        _event + " ON " + TABLE + " BEGIN SELECT RAISE(ABORT,'experiment_local_backing_immutable'); END")
GUARDS[PREFIX + "replace"] = ("CREATE TRIGGER " + PREFIX + "replace BEFORE INSERT ON " + TABLE +
    " WHEN EXISTS(SELECT 1 FROM " + TABLE + " WHERE " +
    " OR ".join(field + "=NEW." + field for field in _UNIQUE) + " OR rowid=NEW.rowid) " +
    "BEGIN SELECT RAISE(ABORT,'experiment_local_backing_immutable'); END")
# This marker belongs to the established lifecycle table. Dropping only the
# optional link table removes its own triggers, but MUST NOT turn previously
# partition-backed rows into ordinary rows. The surviving marker makes that
# loss an invalid partial schema, while also protecting their execution keys.
GUARDS[PREFIX + "initialized"] = ("CREATE TRIGGER " + PREFIX + "initialized "
    "BEFORE UPDATE OF execution_id ON managed_executions WHEN OLD.execution_id IS NOT NEW.execution_id "
    "AND EXISTS(SELECT 1 FROM " + TABLE + " WHERE execution_id=OLD.execution_id) "
    "BEGIN SELECT RAISE(ABORT,'experiment_local_execution_immutable'); END")


class LocalBackingError(LifecycleError):
    def __init__(self, reason):
        self.reason = "local_backing_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise LocalBackingError(reason)


def _transaction(conn):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _fail("transaction_required")


def _digest(row):
    value = {key: row[key] for key in FIELDS if key != "link_sha256"}
    return hashlib.sha256(ledger._canonical({"domain": "sentinel-experiment-local-backing-v1",
                                           "row": value}).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class LocalBackingObservation:
    """Bounded immutable DATA, deliberately without any authority methods."""
    fields: tuple[tuple[str, object], ...]

    def to_dict(self):
        return dict(self.fields)


@dataclass(frozen=True)
class LocalBackingInventory:
    """bytes_used is the conservative preprojection charge, not JSON length."""
    rows: tuple[LocalBackingObservation, ...]
    rows_used: int
    bytes_used: int


def validate_schema_locked(conn):
    _transaction(conn)
    names = (TABLE, *GUARDS)
    found = conn.execute("SELECT name,type,CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END "
        "FROM sqlite_master WHERE name IN (" + ",".join("?" for _ in names) + ") OR name GLOB ? "
        "OR (type='trigger' AND tbl_name=?) LIMIT ?", (*names, PREFIX + "*", TABLE, len(names) + 1)).fetchall()
    if not found:
        return False
    expected = {TABLE: ("table", ledger._sql(SCHEMA)),
                **{key: ("trigger", ledger._sql(value)) for key, value in GUARDS.items()}}
    if len(found) != len(expected) or {row[0]: (row[1], ledger._sql(row[2])) for row in found} != expected:
        _fail("schema_invalid")
    if tuple(row[1] for row in conn.execute("PRAGMA table_info(" + TABLE + ")")) != FIELDS:
        _fail("schema_invalid")
    indexes = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? LIMIT ?",
                           (TABLE, len(_UNIQUE) + 1)).fetchall()
    expected_indexes = {f"sqlite_autoindex_{TABLE}_{index}": (field,)
                        for index, field in enumerate(_UNIQUE, 1)}
    if len(indexes) != len(expected_indexes) or any(row[1] is not None for row in indexes):
        _fail("schema_invalid")
    for name, _ in indexes:
        if name not in expected_indexes or tuple(row[2] for row in conn.execute(
                "PRAGMA index_info(" + name + ")")) != expected_indexes[name]:
            _fail("schema_invalid")
    return True


def _validate_row(row):
    if set(row) != set(FIELDS) or row["schema_version"] != 1:
        _fail("row_invalid")
    for field in _TEXT:
        value = row[field]
        if (type(value) is not str or not 1 <= len(value.encode("utf-8")) <= _BOUNDS[field] or
                any(ord(char) < 32 for char in value)):
            _fail("row_invalid")
    for field in _INTS:
        if type(row[field]) is not int or not 0 <= row[field] < 1 << 63:
            _fail("row_invalid")
    for field in _REALS:
        if type(row[field]) not in (int, float) or not math.isfinite(row[field]) or not 0 <= row[field] < 1e308:
            _fail("row_invalid")
    if any(not Path(row[field]).is_absolute() or ".." in Path(row[field]).parts for field in _PATHS):
        _fail("row_invalid")
    for field in ("execution_id", "scope_id", "member_id", "wrapper_member_id", "source_generation",
                  "daily_policy_instance_id", "isolated_policy_instance_id"):
        try:
            ledger._uuid(row[field])
        except (ValueError, RuntimeError):
            _fail("row_invalid")
    for field in ("request_key", "request_spec_hash", "spec_hash", "admission_binding_hash", "scope_nonce",
                  "plan_sha256", "source_digest", "config_digest", "daily_binding_sha256", "link_sha256"):
        if len(row[field]) != 64 or any(char not in "0123456789abcdef" for char in row[field]):
            _fail("row_invalid")
    for field in ("daily_ledger_dev", "daily_ledger_ino", "isolated_ledger_dev", "isolated_ledger_ino",
                  "wrapper_created_filetime_100ns"):
        value = row[field]
        if not value.isascii() or not value.isdecimal() or str(int(value)) != value or int(value) >= 1 << 128:
            _fail("row_invalid")
    if (row["wrapper_pid"] <= 0 or row["wrapper_pid"] > 0xFFFFFFFF or
            int(row["wrapper_created_filetime_100ns"]) == 0 or
            int(row["daily_ledger_ino"]) == 0 or int(row["isolated_ledger_ino"]) == 0 or
            row["daily_ledger_path"] == row["isolated_ledger_path"] or
            (row["daily_ledger_dev"], row["daily_ledger_ino"]) ==
                (row["isolated_ledger_dev"], row["isolated_ledger_ino"]) or
            row["daily_policy_instance_id"] == row["isolated_policy_instance_id"] or
            row["daily_expires_at"] <= 0 or row["link_sha256"] != _digest(row)):
        _fail("row_invalid")
    try:
        ProcessIdentity(row["wrapper_pid"], int(row["wrapper_created_filetime_100ns"]), row["logon_id"])
        ResourceDemand(row["cpu_units"], row["physical_bytes"], row["commit_bytes"], row["io_slots"])
    except (TypeError, ValueError):
        _fail("row_invalid")


def _relation(conn, row):
    expected = {"execution_id": row["execution_id"], "reservation_id": row["reservation_id"],
        "spec_hash": row["spec_hash"], "admission_binding_hash": row["admission_binding_hash"],
        "wrapper_pid": row["wrapper_pid"], "wrapper_created_filetime_100ns": row["wrapper_created_filetime_100ns"],
        "logon_id": row["logon_id"], "allocation_kind": "direct", "parent_execution_id": None,
        "requested_cpu_units": row["cpu_units"], "requested_physical_bytes": row["physical_bytes"],
        "requested_commit_bytes": row["commit_bytes"], "requested_io_slots": row["io_slots"]}
    columns = (*expected, "state")
    projection = ",".join("CASE WHEN length(CAST(" + field + " AS BLOB))<=256 THEN " + field + " END"
                          for field in columns)
    values = conn.execute("SELECT " + projection + " FROM managed_executions WHERE execution_id=? LIMIT 2",
                          (row["execution_id"],)).fetchall()
    if len(values) != 1:
        _fail("managed_binding_missing")
    live = dict(zip(columns, values[0]))
    if any(live[field] != value for field, value in expected.items()):
        _fail("managed_binding_changed")
    allocation_fields = ("execution_id", "request_key", "spec_hash", "managed_spec_hash", "lifecycle_managed")
    allocation_projection = ",".join("CASE WHEN length(CAST(" + field + " AS BLOB))<=128 THEN " + field + " END"
                                     for field in allocation_fields)
    allocation = conn.execute("SELECT " + allocation_projection + " "
        "FROM reservations WHERE id=? LIMIT 2", (row["reservation_id"],)).fetchall()
    if not allocation and live["state"] in TERMINAL_STATES:
        return
    if len(allocation) != 1 or tuple(allocation[0]) != (row["execution_id"], row["request_key"],
            row["request_spec_hash"], row["spec_hash"], 1):
        _fail("reservation_binding_changed")


def _read(conn, *, max_rows, max_bytes, execution_id=None):
    if (type(max_rows) is not int or not 0 <= max_rows <= MAX_ROWS or type(max_bytes) is not int or
            not 0 <= max_bytes <= MAX_BYTES):
        _fail("budget_invalid")
    if not validate_schema_locked(conn):
        return LocalBackingInventory((), 0, 0)
    # SQL computes a conservative ASCII-JSON upper bound before projecting
    # payload. Even the overflow sentinel carries no row/cell content. Caller
    # passes its REMAINING shared allowance; no independent inventory budget.
    overhead = len(ledger._canonical({key: "" for key in FIELDS}).encode("ascii"))
    cost = str(overhead) + "+" + "+".join("6*length(CAST(" + key + " AS BLOB))" for key in FIELDS)
    bounded = " AND ".join("length(CAST(" + key + " AS BLOB))<=" + str(_BOUNDS[key]) for key in FIELDS)
    where, parameters = (" WHERE execution_id=?", (execution_id,)) if execution_id is not None else ("", ())
    inner = ("SELECT " + ",".join(FIELDS) + ",(" + cost + ") AS _cost," +
             "row_number() OVER (ORDER BY rowid) AS _position FROM " + TABLE + where + " ORDER BY rowid LIMIT ?")
    middle = "SELECT *,sum(_cost) OVER (ORDER BY _position) AS _total FROM (" + inner + ")"
    available = "_position<=" + str(max_rows) + " AND _total<=" + str(max_bytes) + " AND " + bounded
    projection = ",".join("CASE WHEN " + available + " THEN " + key + " END" for key in FIELDS)
    cursor = conn.execute("SELECT " + projection + ",CASE WHEN " + available + " THEN _cost ELSE 0 END,CASE WHEN " + available +
        " THEN 1 ELSE 0 END FROM (" + middle + ") ORDER BY _position", (*parameters, max_rows + 1))
    rows, used = [], 0
    for values in cursor:
        if len(rows) >= max_rows:
            _fail("rows_exceeded")
        if values[-1] != 1:
            _fail("bytes_or_cell_exceeded")
        row = dict(zip(FIELDS, tuple(values)[:-2]))
        _validate_row(row)
        _relation(conn, row)
        charge = values[-2]
        if type(charge) is not int or charge < len(ledger._canonical(row).encode("ascii")):
            _fail("byte_charge_invalid")
        used += charge
        if used > max_bytes:
            _fail("bytes_exceeded")
        rows.append(LocalBackingObservation(tuple((key, row[key]) for key in FIELDS)))
    return LocalBackingInventory(tuple(rows), len(rows), used)


def read_inventory_locked(conn, *, max_rows, max_bytes):
    return _read(conn, max_rows=max_rows, max_bytes=max_bytes)


def read_link_locked(conn, execution_id, *, max_rows, max_bytes):
    ledger._uuid(execution_id)
    found = _read(conn, max_rows=max_rows, max_bytes=max_bytes, execution_id=execution_id)
    return found.rows[0] if found.rows else None


def assert_ordinary_execution(conn, execution_id):
    """Default host paths cannot consume partition rows; no bypass parameter."""
    # Ordinary lifecycle callers historically accept non-UUID execution IDs.
    # Only typed experiment readers require the experiment UUID contract.
    if type(execution_id) is not str or not execution_id:
        _fail("execution_id_invalid")
    if validate_schema_locked(conn) and conn.execute("SELECT 1 FROM " + TABLE +
            " WHERE execution_id=? LIMIT 1", (execution_id,)).fetchone():
        _fail("experiment_backed_authority_required")


class LocalBackingPublication:
    def __init__(self, *, _token=None):
        if _token is not _TOKEN:
            _fail("original_operation_required")
        self._transactions = []

    def __reduce__(self):
        raise TypeError("local_backing_publication_not_serializable")

    @classmethod
    def prepare(cls, *, adapter, context, observation):
        from .experiment_partition_admission import ExperimentPartitionCoordinator
        if (cls is not LocalBackingPublication or type(adapter) is not ExperimentPartitionCoordinator or
                type(context) is not ManagedAdmission or type(observation) is not BackingObservation or
                adapter._context is not context or type(adapter._snapshot) is not ManagedAdmissionSnapshot or
                context._snapshot is not adapter._snapshot or
                getattr(adapter, "_local_backing_observation", None) is not observation or
                adapter._backing != observation.binding):
            _fail("original_partition_required")
        manifest, binding = adapter.manifest, observation.binding
        previous_tx = context._submission_transaction
        if previous_tx is not None and previous_tx.get("connection_closed") is not True:
            _fail("prepare_outside_transaction_required")
        if (observation.scope_id != manifest.scope_id or observation.member_id != adapter.member_id or
                observation.wrapper_member_id != manifest.actor_member_id or
                binding.wrapper_identity != manifest.child_identity or
                manifest.role != "wrapper" or adapter.member_id not in manifest.permitted_member_ids or
                adapter.child_binding._manifest is not manifest):
            _fail("partition_binding_changed")
        identity, resources = binding.wrapper_identity, binding.requested
        row = dict(execution_id=binding.execution_id, reservation_id=binding.reservation_id,
            request_key=binding.request_key, request_spec_hash=binding.request_spec_hash,
            spec_hash=binding.spec_hash, admission_binding_hash=binding.admission_binding_hash,
            scope_id=manifest.scope_id, member_id=adapter.member_id, wrapper_member_id=manifest.actor_member_id,
            scope_nonce=manifest.scope_nonce, plan_sha256=manifest.plan_sha256,
            source_generation=manifest.source_generation, source_digest=manifest.source_digest,
            config_digest=manifest.config_digest, daily_ledger_path=manifest.daily_ledger_path,
            daily_ledger_dev=str(manifest.daily_ledger_identity.st_dev),
            daily_ledger_ino=str(manifest.daily_ledger_identity.st_ino), daily_policy_instance_id=manifest.daily_policy_instance_id,
            isolated_ledger_path=manifest.isolated_ledger_path,
            isolated_ledger_dev=str(manifest.isolated_ledger_identity.st_dev),
            isolated_ledger_ino=str(manifest.isolated_ledger_identity.st_ino), isolated_policy_instance_id=manifest.isolated_policy_instance_id,
            wrapper_pid=identity.pid, wrapper_created_filetime_100ns=str(identity.created_filetime_100ns),
            logon_id=identity.logon_id, cpu_units=float(resources.cpu_units), physical_bytes=resources.physical_bytes,
            commit_bytes=resources.commit_bytes, io_slots=resources.io_slots,
            daily_binding_sha256=observation.binding_sha256, daily_registered_revision=observation.registered_revision,
            daily_expires_at=float(observation.daily_expires_at), schema_version=1)
        row["link_sha256"] = _digest(row)
        _validate_row(row)
        previous = getattr(adapter, "_local_backing_publication", None)
        if previous is not None:
            if type(previous) is not cls:
                _fail("original_operation_changed")
            previous._original()
            if previous._row != row:
                _fail("original_payload_changed")
            return previous
        owner = cls(_token=_TOKEN)
        owner.adapter, owner.context, owner.snapshot = adapter, context, adapter._snapshot
        owner.manifest, owner._row = manifest, row
        owner._pins = (adapter, context, owner.snapshot, manifest, adapter.child_binding,
                       adapter._original_daily_policy, adapter._original_isolated_policy)
        owner._payload = ledger._canonical(row)
        owner._manifest_payload = ledger._canonical(manifest.to_dict())
        owner._snapshot_payload = ledger._canonical(_snapshot_binding(owner.snapshot, binding.reservation_id).to_dict())
        owner._thread = threading.current_thread()
        adapter._local_backing_publication = owner
        return owner

    def _original(self):
        adapter, context, snapshot, manifest, child, daily, isolated = self._pins
        if (type(self) is not LocalBackingPublication or self.adapter is not adapter or self.context is not context or
                self.snapshot is not snapshot or self.manifest is not manifest or
                adapter._local_backing_publication is not self or adapter._context is not context or
                adapter._snapshot is not snapshot or context._snapshot is not snapshot or
                adapter.manifest is not manifest or adapter.child_binding is not child or child._manifest is not manifest or
                adapter._original_daily_policy is not daily or adapter._original_isolated_policy is not isolated or
                self._thread is not threading.current_thread() or ledger._canonical(self._row) != self._payload or
                ledger._canonical(manifest.to_dict()) != self._manifest_payload or
                ledger._canonical(_snapshot_binding(snapshot, self._row["reservation_id"]).to_dict()) != self._snapshot_payload):
            _fail("original_operation_changed")
        return adapter


def _held(conn, operation, policy, guard):
    _transaction(conn)
    if type(operation) is not LocalBackingPublication:
        _fail("original_operation_required")
    adapter = operation._original()
    if (type(policy) is not PolicyCoordinator or policy is not adapter._original_isolated_policy or
            operation.context._submission_policy is not policy or operation.context._submission_guard is not guard):
        _fail("original_policy_required")
    policy.assert_held(guard)
    adapter._original_daily_policy.assert_held(adapter._daily_guard)
    if (adapter._daily_guard is None or
            guard.binding.instance_id != operation._row["isolated_policy_instance_id"] or
            adapter._daily_guard.binding.instance_id != operation._row["daily_policy_instance_id"] or
            guard.binding.logon_id != operation._row["logon_id"]):
        _fail("policy_binding_changed")
    policy.revalidate(conn, guard)
    tx = operation.context._submission_transaction
    if (type(tx) is not dict or tx.get("connection") is not conn or tx.get("connection_closed") is not False or
            tx.get("commit_attempted") is not False or tx.get("rolled_back") is not False or
            tx.get("execution_id") != operation._row["execution_id"] or
            str(tx.get("db_path")) != operation._row["isolated_ledger_path"]):
        _fail("original_transaction_required")
    return tx


def begin_locked(conn, *, operation, policy, guard):
    """Retain the preimage BEFORE isolated managed/reservation mutations."""
    tx = _held(conn, operation, policy, guard)
    for previous in operation._transactions:
        if previous[0] is tx:
            if previous[1] is not conn:
                _fail("original_transaction_changed")
            return
    if len(operation._transactions) >= MAX_ROWS:
        _fail("transaction_inventory_full")
    existing = read_link_locked(conn, operation._row["execution_id"], max_rows=1, max_bytes=MAX_BYTES)
    present = conn.execute("SELECT 1 FROM managed_executions WHERE execution_id=? LIMIT 1",
                           (operation._row["execution_id"],)).fetchone() is not None
    if present and existing is None:
        _fail("ordinary_execution_upgrade_forbidden")
    if existing is not None and existing.to_dict() != operation._row:
        _fail("original_link_changed")
    operation._transactions.append((tx, conn, present, existing))


def _insert(conn, operation, policy, guard):
    if id(conn) in _INSERTS:
        _fail("nested_insert")
    expected = tuple(operation._row[key] for key in FIELDS)
    marker, thread, used = object(), threading.get_ident(), False
    _INSERTS[id(conn)] = marker
    def authorize(*values):
        nonlocal used
        try:
            if used or _INSERTS.get(id(conn)) is not marker or threading.get_ident() != thread or values != expected:
                return 0
            _held(conn, operation, policy, guard)
            if tuple(operation._row[key] for key in FIELDS) != expected:
                return 0
            used = True
            return 1
        except (RuntimeError, ValueError, TypeError, KeyError, sqlite3.Error):
            return 0
    try:
        conn.create_function(_UDF, -1, authorize)
        conn.execute("INSERT INTO " + TABLE + "(" + ",".join(FIELDS) + ") VALUES(" +
                     ",".join("?" for _ in FIELDS) + ")", expected)
        if not used:
            _fail("original_insert_required")
    finally:
        try:
            conn.create_function(_UDF, -1, None)
        finally:
            if _INSERTS.get(id(conn)) is marker:
                del _INSERTS[id(conn)]


def publish_locked(conn, *, operation, policy, guard, admission_result):
    """Pure metadata/SQL; caller owns original COMMIT and cleanup outcomes."""
    tx = _held(conn, operation, policy, guard)
    attempts = [item for item in operation._transactions if item[0] is tx and item[1] is conn]
    if len(attempts) != 1:
        _fail("original_preimage_required")
    if (type(admission_result) is not dict or admission_result.get("allowed") is not True or
            admission_result.get("execution_id") != operation._row["execution_id"] or
            admission_result.get("reservation_id") != operation._row["reservation_id"] or
            admission_result.get("request_key") != operation._row["request_key"]):
        _fail("admission_result_changed")
    _relation(conn, operation._row)
    existing = read_link_locked(conn, operation._row["execution_id"], max_rows=1, max_bytes=MAX_BYTES)
    if existing is not None:
        if existing.to_dict() != operation._row:
            _fail("original_link_changed")
        return existing
    if attempts[0][2] or attempts[0][3] is not None:
        _fail("ordinary_execution_upgrade_forbidden")
    if not validate_schema_locked(conn):
        for statement in (SCHEMA, *GUARDS.values()):
            conn.execute(statement)
    if conn.execute("SELECT 1 FROM " + TABLE + " LIMIT 1 OFFSET ?", (MAX_ROWS - 1,)).fetchone():
        _fail("rows_exceeded")
    _insert(conn, operation, policy, guard)
    observed = read_link_locked(conn, operation._row["execution_id"], max_rows=1, max_bytes=MAX_BYTES)
    if observed is None or observed.to_dict() != operation._row:
        _fail("publication_unverified")
    return observed
