"""SQL-only, permanent admission freeze for an original daily retirement.

These helpers do not acquire POLICY, prove native custody, change runtime mode,
restore a cap, commit a transaction, or acknowledge retirement. Their caller is
the original retained retirement operation and must validate its exact owner and
held guard before entry. Guards supplement all existing writer/lifecycle checks.
No queue or exemption records are changed or automatically abandoned.
"""
from __future__ import annotations

import json
import re
import sqlite3
from uuid import UUID

from .contracts import ProcessIdentity
from .policy import PolicyBinding, PolicyGuard


class DailyRetirementError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


RetirementFenceError = DailyRetirementError
TABLE = "adaptive_daily_retirement"
_PREFIX = "adaptive_retirement_"
_GENERATION = "adaptive_daily_generation"
OWNER_BINDING_FIELDS = ("generation", "source_digest", "config_digest", "source_root",
                       "ledger_path", "owner_identity_json", "ledger_identity_json",
                       "readiness_instance_id")
_FIELDS = ("singleton", "schema_version", "request_id", *OWNER_BINDING_FIELDS,
           "policy_instance_id", "policy_logon_id", "freeze_policy_nonce",
           "freeze_registry_revision", "phase", "seal_digest")
_IMMUTABLE = _FIELDS[:-2]
_TERMINAL = "('FINISHED','CANCELLED_BEFORE_START','START_FAILED')"
_SCHEMA = f"""CREATE TABLE {TABLE} (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
    request_id TEXT NOT NULL,
    generation TEXT NOT NULL, source_digest TEXT NOT NULL, config_digest TEXT NOT NULL,
    source_root TEXT NOT NULL, ledger_path TEXT NOT NULL,
    owner_identity_json TEXT NOT NULL, ledger_identity_json TEXT NOT NULL,
    readiness_instance_id TEXT NOT NULL,
    policy_instance_id TEXT NOT NULL, policy_logon_id TEXT NOT NULL,
    freeze_policy_nonce TEXT NOT NULL,
    freeze_registry_revision INTEGER NOT NULL CHECK(typeof(freeze_registry_revision)='integer' AND freeze_registry_revision>=0),
    phase TEXT NOT NULL CHECK(phase IN ('FROZEN','SEALED')),
    seal_digest TEXT,
    CHECK((phase='FROZEN' AND seal_digest IS NULL) OR
          (phase='SEALED' AND typeof(seal_digest)='text' AND length(seal_digest)=64
           AND seal_digest NOT GLOB '*[^0-9a-f]*'))
)"""
_BOUNDS = {"request_id": 36, "generation": 36, "source_digest": 64, "config_digest": 64,
           "source_root": 32768, "ledger_path": 32768, "owner_identity_json": 1024,
           "ledger_identity_json": 128, "readiness_instance_id": 36,
           "policy_instance_id": 36, "policy_logon_id": 128, "freeze_policy_nonce": 36,
           "phase": 8, "seal_digest": 64}
_CORE = {
    "reservations": {"id", "request_key", "owner_pid", "owner_started", "spec_hash",
        "cpu_units", "ram_gib", "physical_bytes", "commit_bytes", "io_slots",
        "execution_id", "lifecycle_managed", "managed_spec_hash", "lease_duration_sec",
        "heartbeat_at", "expires_at", "writer_protocol", "writer_revision"},
    "worker_reservations": {"id", "task_id", "worker_id", "failure_domain", "capacity_scope",
        "capacity_pool", "spec_hash", "cpu_units", "ram_gib", "disk_gib", "physical_bytes",
        "commit_bytes", "io_slots", "execution_id", "lifecycle_managed", "lease_duration_sec",
        "heartbeat_at", "expires_at", "writer_protocol", "writer_revision"},
    "workers": {"id", "state", "capabilities_json", "capacity_pool", "quota_domain",
        "allocatable_cpu", "allocatable_ram_gib", "max_concurrency", "observed_at",
        "probe_expires_at", "updated_at", "writer_protocol", "writer_revision"},
    "managed_executions": {"execution_id", "allocation_kind", "reservation_id", "state",
        "state_revision", "job_name", "job_nonce", "guardian_epoch", "claim_consumed",
        "claim_token_hash", "launch_in_flight", "launch_sealed", "root_pid",
        "root_created_filetime_100ns", "heartbeat_at", "hold_reason", "root_outcome",
        "finished_at", "cancel_requested_at", *{prefix + resource for prefix in ("requested_", "floor_")
            for resource in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")}},
    "adaptive_runtime": {"singleton", "mode", "registry_revision", "policy_instance_id",
        "policy_logon_id", "policy_entry_nonce", "policy_binding_initialized", "active_logon_id"},
    "adaptive_control_slot": {"slot_state"},
}


def _fail(reason):
    raise DailyRetirementError(reason)


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        return parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        return False


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _transaction(conn):
    if not conn.in_transaction:
        _fail("daily_retirement_transaction_required")


def _object(conn, name):
    return conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (name,)).fetchone()


def _columns(conn, table):
    found = _object(conn, table)
    if found is None or found[0] != "table":
        _fail("daily_retirement_schema_unsupported")
    columns = tuple(row[1] for row in conn.execute(f'PRAGMA table_info("{table}")'))
    if any(type(name) is not str or not re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in columns):
        _fail("daily_retirement_schema_unsupported")
    return columns


def _generation(conn):
    found = _object(conn, _GENERATION)
    if found is None:
        return None
    if found[0] != "table":
        _fail("daily_retirement_generation_invalid")
    from .daily_generation import read_generation
    try:
        return read_generation(conn)
    except Exception:
        _fail("daily_retirement_generation_invalid")


def _validate_binding(binding):
    if type(binding) is not dict or set(binding) != set(OWNER_BINDING_FIELDS):
        _fail("daily_retirement_binding_invalid")
    for name, value in binding.items():
        if (type(value) is not str or not 0 < len(value) <= _BOUNDS[name]
                or any(ord(char) < 32 for char in value)):
            _fail("daily_retirement_binding_invalid")
    if (not _uuid(binding["generation"]) or not _uuid(binding["readiness_instance_id"])
            or not _digest(binding["source_digest"]) or not _digest(binding["config_digest"])):
        _fail("daily_retirement_binding_invalid")
    try:
        identity = ProcessIdentity.from_dict(json.loads(binding["owner_identity_json"]))
        ledger = json.loads(binding["ledger_identity_json"])
        if (type(ledger) is not list or len(ledger) != 2 or
                any(type(value) is not str or not value.isdecimal() or len(value) > 40 for value in ledger)):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        _fail("daily_retirement_binding_invalid")
    return identity


def _runtime_guard(conn, guard):
    if type(guard) is not PolicyGuard or type(guard.binding) is not PolicyBinding or not _uuid(guard.nonce):
        _fail("daily_retirement_policy_invalid")
    cursor = conn.execute("SELECT * FROM adaptive_runtime LIMIT 2")
    rows = cursor.fetchall()
    if len(rows) != 1:
        _fail("daily_retirement_policy_changed")
    row = dict(zip([item[0] for item in cursor.description], rows[0]))
    if (row.get("singleton") != 1 or row.get("schema_version") != 1
            or row.get("protocol_version") != 1 or row.get("policy_binding_initialized") != 1
            or row.get("policy_instance_id") != guard.binding.instance_id
            or row.get("policy_logon_id") != guard.binding.logon_id
            or row.get("policy_entry_nonce") != guard.nonce
            or row.get("active_logon_id") not in {"", guard.binding.logon_id}
            or type(row.get("registry_revision")) is not int or not 0 <= row["registry_revision"] < 1 << 63):
        _fail("daily_retirement_policy_changed")
    return row


def _changed(columns, mutable):
    return " OR ".join(f'NEW."{name}" IS NOT OLD."{name}"' for name in columns if name not in mutable) or "0"


def _definitions(conn):
    columns = {}
    for table, required in _CORE.items():
        columns[table] = _columns(conn, table)
        if not required <= set(columns[table]):
            _fail("daily_retirement_schema_unsupported")
    result = {}
    def guard(name, event, table, predicate="1", reason="daily_retirement_frozen"):
        name = _PREFIX + name
        result[name] = (f"CREATE TRIGGER {name} BEFORE {event} ON {table} "
                        f"WHEN {predicate} BEGIN SELECT RAISE(ABORT,'{reason}'); END")
    for table in ("reservations", "worker_reservations"):
        guard(table + "_insert", "INSERT", table)
        mutable = {"heartbeat_at", "expires_at", "writer_protocol", "writer_revision"}
        guard(table + "_update", "UPDATE", table,
              f"NEW.rowid IS NOT OLD.rowid OR ({_changed(columns[table], mutable)})")
    guard("workers_insert", "INSERT", "workers")
    worker_mutable = {"state", "observed_at", "probe_expires_at", "updated_at", "writer_protocol", "writer_revision"}
    guard("workers_update", "UPDATE", "workers",
          f"NEW.rowid IS NOT OLD.rowid OR ({_changed(columns['workers'], worker_mutable)}) OR "
          "(NEW.state IS NOT OLD.state AND (NEW.state IN ('AVAILABLE','BUSY') OR typeof(NEW.state)!='text'))")
    guard("managed_insert", "INSERT", "managed_executions")
    mutable = {"state", "state_revision", "heartbeat_at", "hold_reason", "root_outcome",
        "finished_at", "cancel_requested_at", "launch_in_flight", "launch_sealed", "claim_consumed",
        "claim_token_hash", "root_pid", "root_created_filetime_100ns",
        "floor_cpu_units", "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots"}
    terminal_seal = (f"(NEW.state IN {_TERMINAL} AND NEW.launch_sealed IS 1 "
                     "AND NEW.launch_in_flight IS 0 AND NEW.claim_consumed IS 1 AND NEW.claim_token_hash IS '')")
    bind_root = ("(OLD.state IN ('LAUNCHING','START_UNKNOWN') AND OLD.launch_in_flight IS 1 "
                 "AND OLD.claim_consumed IS 1 AND OLD.root_pid IS NULL AND OLD.root_created_filetime_100ns IS NULL "
                 "AND NEW.state IS 'RUNNING' AND NEW.launch_in_flight IS 0 AND NEW.launch_sealed IS 1 "
                 "AND typeof(NEW.root_pid)='integer' AND NEW.root_pid>0 "
                 "AND typeof(NEW.root_created_filetime_100ns)='text' AND length(NEW.root_created_filetime_100ns)>0)")
    predicates = ["NEW.rowid IS NOT OLD.rowid", _changed(columns["managed_executions"], mutable),
        "NEW.launch_in_flight IS 1 AND OLD.launch_in_flight IS NOT 1",
        "OLD.launch_sealed IS 1 AND NEW.launch_sealed IS NOT 1",
        "OLD.claim_consumed IS 1 AND NEW.claim_consumed IS NOT 1",
        f"OLD.claim_consumed IS NOT NEW.claim_consumed AND ({terminal_seal}) IS NOT 1",
        f"NEW.claim_token_hash IS NOT OLD.claim_token_hash AND ({terminal_seal}) IS NOT 1",
        "NEW.state IS NOT OLD.state AND NEW.state IN ('NEW','QUEUED','RESERVED','PREPARED','LAUNCHING')",
        f"OLD.state IN {_TERMINAL} AND NEW.state IS NOT OLD.state",
        "(NEW.root_pid IS NOT OLD.root_pid OR NEW.root_created_filetime_100ns IS NOT OLD.root_created_filetime_100ns) "
            f"AND ({bind_root}) IS NOT 1",
        "(typeof(NEW.state_revision)='integer' AND NEW.state_revision>=OLD.state_revision) IS NOT 1"]
    for name in ("floor_cpu_units", "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots"):
        kind = "typeof(NEW.floor_cpu_units) IN ('integer','real')" if name == "floor_cpu_units" else f"typeof(NEW.{name})='integer'"
        predicates.append(f"({kind} AND NEW.{name}>=OLD.{name}) IS NOT 1")
    guard("managed_update", "UPDATE", "managed_executions", " OR ".join(f"({item})" for item in predicates))
    # An explicit mode write must converge to off. Other runtime writes remain
    # possible while the original off operation has not yet changed old mode.
    guard("runtime_mode_update", "UPDATE OF mode", "adaptive_runtime", "NEW.mode IS NOT 'off'")
    guard("runtime_mode_insert", "INSERT", "adaptive_runtime", "NEW.mode IS NOT 'off'")
    guard("control_slot_insert", "INSERT", "adaptive_control_slot", "NEW.slot_state IS NOT 'RESTORED'")
    guard("control_slot_update", "UPDATE", "adaptive_control_slot", "NEW.slot_state IS NOT 'RESTORED'")
    # Audit rows report native outcomes, sometimes after uncertain ACKs. Do not
    # suppress APPLIED/RENEWED/RESTORED history here; a caller must use the
    # pre-effect helper below for every native restriction and renewal.
    guard("binding_insert", "INSERT", TABLE, f"EXISTS(SELECT 1 FROM {TABLE})", "daily_retirement_immutable")
    guard("binding_delete", "DELETE", TABLE, reason="daily_retirement_immutable")
    transition = ("((OLD.phase IS 'FROZEN' AND NEW.phase IS 'FROZEN' AND NEW.seal_digest IS NULL) OR "
        "(OLD.phase IS 'FROZEN' AND NEW.phase IS 'SEALED' AND typeof(NEW.seal_digest)='text' "
        "AND length(NEW.seal_digest)=64 AND NEW.seal_digest NOT GLOB '*[^0-9a-f]*' "
        f"AND (SELECT state FROM {_GENERATION} WHERE singleton=1) IS 'DRAINING') OR "
        "(OLD.phase IS 'SEALED' AND NEW.phase IS 'SEALED' AND NEW.seal_digest IS OLD.seal_digest))")
    guard("binding_update", "UPDATE", TABLE,
          f"NEW.rowid IS NOT OLD.rowid OR ({_changed(_FIELDS, {'phase', 'seal_digest'})}) OR ({transition}) IS NOT 1",
          "daily_retirement_immutable")
    return result


def _normalized_sql(sql):
    return " ".join(sql.split()) if isinstance(sql, str) else ""


def read_retirement(conn):
    """Bounded read of complete frozen evidence; partial schemas fail closed."""
    try:
        found = _object(conn, TABLE)
        triggers = dict(conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                                     (_PREFIX + "*",)))
        if found is None:
            if triggers:
                _fail("daily_retirement_schema_incomplete")
            return None
        if (found[0] != "table" or _normalized_sql(found[1]) != _normalized_sql(_SCHEMA)
                or _columns(conn, TABLE) != _FIELDS):
            _fail("daily_retirement_schema_unsupported")
        expected = _definitions(conn)
        if set(triggers) != set(expected) or any(_normalized_sql(triggers[key]) != _normalized_sql(sql)
                                               for key, sql in expected.items()):
            _fail("daily_retirement_guards_unverified")
        selected = []
        for field in _FIELDS:
            if field in _BOUNDS:
                selected.append(f"CASE WHEN typeof({field})='text' AND length(CAST({field} AS BLOB))<={_BOUNDS[field] * 4} THEN {field} END")
            else:
                selected.append(f"CASE WHEN typeof({field})='integer' THEN {field} END")
        rows = conn.execute(f"SELECT {','.join(selected)},typeof(seal_digest) FROM {TABLE} LIMIT 2").fetchall()
        if len(rows) != 1:
            _fail("daily_retirement_row_invalid")
        row = dict(zip(_FIELDS, rows[0][:-1]))
        identity = _validate_binding({key: row[key] for key in OWNER_BINDING_FIELDS})
        if (row["singleton"] != 1 or row["schema_version"] != 1 or not _uuid(row["request_id"])
                or not _uuid(row["policy_instance_id"]) or not _uuid(row["freeze_policy_nonce"])
                or row["policy_logon_id"] != identity.logon_id
                or type(row["freeze_registry_revision"]) is not int or not 0 <= row["freeze_registry_revision"] < 1 << 63
                or row["phase"] not in {"FROZEN", "SEALED"}
                or (row["phase"] == "FROZEN" and (row["seal_digest"] is not None or rows[0][-1] != "null"))
                or (row["phase"] == "SEALED" and not _digest(row["seal_digest"]))):
            _fail("daily_retirement_row_invalid")
        generation = _generation(conn)
        if generation is None or any(generation[key] != row[key] for key in OWNER_BINDING_FIELDS):
            _fail("daily_retirement_generation_changed")
        if row["phase"] == "SEALED" and generation["state"] != "DRAINING":
            _fail("daily_retirement_seal_generation_mismatch")
        return row
    except sqlite3.Error:
        _fail("daily_retirement_registry_unavailable")


def assert_new_capacity_allowed(conn):
    """Transaction-time refusal, including reuse; no legacy admission rewrite."""
    try:
        generation = _generation(conn)
        retirement = read_retirement(conn)
        if generation is None and retirement is None:
            return
        _transaction(conn)
        if retirement is not None:
            _fail("daily_retirement_frozen")
        if generation["state"] != "ACTIVE":
            _fail("daily_generation_draining")
    except sqlite3.Error:
        _fail("daily_retirement_registry_unavailable")


def assert_tightening_allowed(conn):
    """Use only before restrictive Set/renewal; restoration must not call it."""
    assert_new_capacity_allowed(conn)


def install_freeze_locked(conn, owner_binding, request_id, guard):
    """Install under original held POLICY/transaction; never commit or change mode."""
    _transaction(conn)
    identity = _validate_binding(owner_binding)
    if not _uuid(request_id):
        _fail("daily_retirement_request_invalid")
    try:
        runtime = _runtime_guard(conn, guard)
        if identity.logon_id != guard.binding.logon_id:
            _fail("daily_retirement_policy_changed")
        generation = _generation(conn)
        if (generation is None or generation["state"] != "ACTIVE"
                or any(generation[key] != value for key, value in owner_binding.items())):
            _fail("daily_retirement_generation_changed")
        existing = read_retirement(conn)
        if existing is not None:
            if (existing["request_id"] != request_id or existing["phase"] != "FROZEN"
                    or existing["freeze_policy_nonce"] != guard.nonce
                    or existing["policy_instance_id"] != guard.binding.instance_id
                    or existing["policy_logon_id"] != guard.binding.logon_id
                    or any(existing[key] != value for key, value in owner_binding.items())):
                _fail("daily_retirement_request_conflict")
            return existing
        definitions = _definitions(conn)
        conn.execute(_SCHEMA)
        row = {"singleton": 1, "schema_version": 1, "request_id": request_id, **owner_binding,
               "policy_instance_id": guard.binding.instance_id, "policy_logon_id": guard.binding.logon_id,
               "freeze_policy_nonce": guard.nonce, "freeze_registry_revision": runtime["registry_revision"],
               "phase": "FROZEN", "seal_digest": None}
        conn.execute(f"INSERT INTO {TABLE}({','.join(_FIELDS)}) VALUES({','.join('?' for _ in _FIELDS)})",
                     tuple(row[field] for field in _FIELDS))
        for sql in definitions.values():
            conn.execute(sql)
        return read_retirement(conn)
    except sqlite3.Error:
        _fail("daily_retirement_registry_unavailable")


def seal_freeze_locked(conn, row, seal_digest, guard):
    """Persist SQL seal after caller's complete original native settlement.

    The generation must already be DRAINING in this same transaction. Caller
    retains the original seal guard through commit, nonce cleanup and ACK.
    Neither a row nor this helper's return value is a native-cleanup receipt.
    """
    _transaction(conn)
    if (type(row) is not dict or set(row) != set(_FIELDS) or not _digest(seal_digest)
            or row.get("phase") not in {"FROZEN", "SEALED"}
            or (row.get("phase") == "FROZEN" and row.get("seal_digest") is not None)
            or (row.get("phase") == "SEALED" and not _digest(row.get("seal_digest")))):
        _fail("daily_retirement_seal_invalid")
    try:
        _runtime_guard(conn, guard)
        current = read_retirement(conn)
        if (current is None or any(current[key] != row[key] for key in _IMMUTABLE)
                or current["policy_instance_id"] != guard.binding.instance_id
                or current["policy_logon_id"] != guard.binding.logon_id
                or _generation(conn)["state"] != "DRAINING"):
            _fail("daily_retirement_seal_binding_changed")
        if current["phase"] == "SEALED":
            if current["seal_digest"] != seal_digest:
                _fail("daily_retirement_seal_conflict")
            return current
        if conn.execute(f"UPDATE {TABLE} SET phase='SEALED',seal_digest=? WHERE singleton=1 AND request_id=? AND phase='FROZEN'",
                        (seal_digest, current["request_id"])).rowcount != 1:
            _fail("daily_retirement_seal_conflict")
        return read_retirement(conn)
    except sqlite3.Error:
        _fail("daily_retirement_registry_unavailable")
