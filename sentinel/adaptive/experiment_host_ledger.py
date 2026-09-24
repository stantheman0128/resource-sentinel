"""Daily SQL partitions for one original S2/P4 experiment demand.

Rows and returned inventories are observations, never readiness, native custody,
launch permission or completion.  RegisteredHostScope retains only the original
SQL publication operation.  The future host must retain and verify its native
owners before publishing actors/Jobs and must publish before workload launch.

All *_locked functions use the caller's existing daily connection and POLICY.
They neither open another ledger nor query files, processes, IPC or native APIs.
Child claims partition the ONE actual daily allocation; they admit no capacity.
There is deliberately no child reuse, deletion, completion or release API.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import threading
from uuid import UUID

from . import daily_generation, experiment_demand, experiment_history, experiment_exclusion
from . import daily_successor_history, daily_successor_epoch
from .experiment_exclusion import _combined_jobs_locked
from .contracts import ProcessIdentity, ResourceDemand
from .daily_retirement_fence import assert_new_capacity_allowed
from .policy import PolicyCoordinator, PolicyGuard


MAX_ROWS, MAX_BYTES = 4096, 16 * 1024 * 1024
MAX_MEMBERS, MAX_ACTORS = 128, 64
MAX_MANAGED_JOBS, MAX_QUERY_JOBS = 10, 40
SCOPES_TABLE = "adaptive_experiment_host_scopes"
MEMBERS_TABLE = "adaptive_experiment_host_members"
ACTORS_TABLE = "adaptive_experiment_host_actors"
JOBS_TABLE = "adaptive_experiment_host_jobs"
TABLES = (SCOPES_TABLE, MEMBERS_TABLE, ACTORS_TABLE, JOBS_TABLE)
_PREFIX = "experiment_host_"
_CREATE = object()
_ORIGINALS = {}
_INSERT_OPERATIONS = {}
_INSERT_UDF = "sentinel_experiment_host_original_insert"
_RESOURCES = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")
_INFRA_ROLES = frozenset({"caller", "readiness_keeper", "guardian", "wrapper", "helper",
                         "supervisor", "observer", "query_owner", "runner"})
_COMMON = ("schema_version", "registered_revision", "binding_sha256")
FIELDS = {
    SCOPES_TABLE: ("scope_id", "experiment_id", "daily_execution_id", "reservation_id", "suite",
        "source_generation", "source_digest", "config_digest", "generation_binding_sha256",
        "demand_binding_sha256", "isolated_ledger_path", "isolated_ledger_identity_json",
        "isolated_policy_instance_id", "daily_policy_instance_id", "logon_id", *_COMMON),
    MEMBERS_TABLE: ("member_id", "scope_id", "kind", "role", "demand_json", *_COMMON),
    ACTORS_TABLE: ("member_id", "scope_id", "identity_json", *_COMMON),
    JOBS_TABLE: ("member_id", "scope_id", "kind", "job_name", "creation_nonce",
        "isolated_execution_id", "isolated_reservation_id", "guardian_member_id", "wrapper_member_id", *_COMMON),
}
_LIMITS = {name: 128 for fields in FIELDS.values() for name in fields if name not in _COMMON[:2]}
_LIMITS.update(isolated_ledger_path=32768, isolated_ledger_identity_json=128,
               identity_json=1024, demand_json=1024, job_name=256, logon_id=184)
_NULLABLE = frozenset({"isolated_execution_id", "isolated_reservation_id", "wrapper_member_id"})

SCHEMA = {
    SCOPES_TABLE: f"""CREATE TABLE {SCOPES_TABLE} (
        scope_id TEXT PRIMARY KEY NOT NULL, experiment_id TEXT UNIQUE NOT NULL,
        daily_execution_id TEXT UNIQUE NOT NULL, reservation_id TEXT UNIQUE NOT NULL,
        suite TEXT NOT NULL CHECK(suite IN ('S2','P4')), source_generation TEXT NOT NULL,
        source_digest TEXT NOT NULL, config_digest TEXT NOT NULL,
        generation_binding_sha256 TEXT NOT NULL, demand_binding_sha256 TEXT NOT NULL,
        isolated_ledger_path TEXT NOT NULL, isolated_ledger_identity_json TEXT NOT NULL,
        isolated_policy_instance_id TEXT NOT NULL, daily_policy_instance_id TEXT NOT NULL,
        logon_id TEXT NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
        registered_revision INTEGER NOT NULL CHECK(registered_revision>=0), binding_sha256 TEXT NOT NULL)""",
    MEMBERS_TABLE: f"""CREATE TABLE {MEMBERS_TABLE} (
        member_id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('infrastructure','workload')), role TEXT NOT NULL,
        demand_json TEXT NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
        registered_revision INTEGER NOT NULL CHECK(registered_revision>=0), binding_sha256 TEXT NOT NULL)""",
    ACTORS_TABLE: f"""CREATE TABLE {ACTORS_TABLE} (
        member_id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL, identity_json TEXT UNIQUE NOT NULL,
        schema_version INTEGER NOT NULL CHECK(schema_version=1),
        registered_revision INTEGER NOT NULL CHECK(registered_revision>=0), binding_sha256 TEXT NOT NULL)""",
    JOBS_TABLE: f"""CREATE TABLE {JOBS_TABLE} (
        member_id TEXT PRIMARY KEY NOT NULL, scope_id TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('managed','query_only')),
        job_name TEXT UNIQUE NOT NULL, creation_nonce TEXT UNIQUE NOT NULL,
        isolated_execution_id TEXT UNIQUE, isolated_reservation_id TEXT UNIQUE,
        guardian_member_id TEXT NOT NULL, wrapper_member_id TEXT UNIQUE,
        schema_version INTEGER NOT NULL CHECK(schema_version=1),
        registered_revision INTEGER NOT NULL CHECK(registered_revision>=0), binding_sha256 TEXT NOT NULL)""",
}
GUARDS = {}
_UNIQUE = {SCOPES_TABLE: ("scope_id", "experiment_id", "daily_execution_id", "reservation_id"),
           MEMBERS_TABLE: ("member_id",), ACTORS_TABLE: ("member_id", "identity_json"),
           JOBS_TABLE: ("member_id", "job_name", "creation_nonce", "isolated_execution_id",
                        "isolated_reservation_id", "wrapper_member_id")}
for _table, _key in ((SCOPES_TABLE, "scope_id"), (MEMBERS_TABLE, "member_id"),
                     (ACTORS_TABLE, "member_id"), (JOBS_TABLE, "member_id")):
    _stem = _PREFIX + _table.removeprefix("adaptive_experiment_host_")
    for _operation in ("update", "delete"):
        _name = _stem + "_" + _operation
        GUARDS[_name] = (f"CREATE TRIGGER {_name} BEFORE {_operation.upper()} ON {_table} "
            "BEGIN SELECT RAISE(ABORT,'experiment_host_history_immutable'); END")
    _name = _stem + "_replace"
    _collisions = " OR ".join(f"{key}=NEW.{key}" for key in _UNIQUE[_table])
    GUARDS[_name] = (f"CREATE TRIGGER {_name} BEFORE INSERT ON {_table} WHEN EXISTS(SELECT 1 FROM {_table} "
        f"WHERE {_collisions} OR rowid=NEW.rowid) "
        "BEGIN SELECT RAISE(ABORT,'experiment_host_history_immutable'); END")
GUARDS[_PREFIX + "scope_limit"] = f"""CREATE TRIGGER experiment_host_scope_limit
    BEFORE INSERT ON {SCOPES_TABLE} WHEN EXISTS(SELECT 1 FROM {SCOPES_TABLE})
    BEGIN SELECT RAISE(ABORT,'experiment_host_scope_occupied'); END"""
GUARDS[_PREFIX + "reservation_delete"] = f"""CREATE TRIGGER experiment_host_reservation_delete
    BEFORE DELETE ON reservations WHEN EXISTS(SELECT 1 FROM {SCOPES_TABLE}
        WHERE reservation_id=OLD.id OR daily_execution_id=OLD.execution_id)
    BEGIN SELECT RAISE(ABORT,'experiment_host_cleanup_unverified'); END"""
GUARDS[_PREFIX + "execution_terminal"] = f"""CREATE TRIGGER experiment_host_execution_terminal
    BEFORE UPDATE ON managed_executions WHEN EXISTS(SELECT 1 FROM {SCOPES_TABLE}
        WHERE daily_execution_id=OLD.execution_id OR reservation_id=OLD.reservation_id) AND
        (NEW.state NOT IN ('RESERVED','UNCERTAIN_HOLD') OR NEW.claim_consumed IS NOT 0 OR
         NEW.launch_sealed IS NOT 0 OR NEW.launch_in_flight IS NOT 0 OR
         NEW.claim_token_hash IS NOT OLD.claim_token_hash OR NEW.job_name IS NOT NULL OR NEW.root_pid IS NOT NULL)
    BEGIN SELECT RAISE(ABORT,'experiment_host_cleanup_unverified'); END"""
# Every new row also needs the original lexical publisher. Outside that scope,
# SQLite may reject the missing UDF while preparing the immutable guards.
GUARDS = {**{_PREFIX + table.removeprefix("adaptive_experiment_host_") + "_insert":
    f"CREATE TRIGGER {_PREFIX + table.removeprefix('adaptive_experiment_host_')}_insert "
    f"BEFORE INSERT ON {table} WHEN {_INSERT_UDF}('{table}'," +
    ",".join("NEW." + key for key in FIELDS[table]) + ") IS NOT 1 "
    "BEGIN SELECT RAISE(ABORT,'experiment_host_original_insert_required'); END"
    for table in TABLES}, **GUARDS}


class HostLedgerError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_host_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise HostLedgerError(reason)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail("json_invalid")


def _digest(value):
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _uuid(value):
    try:
        if type(value) is str and str(UUID(value)) == value and UUID(value).int:
            return value
    except (ValueError, TypeError, AttributeError):
        pass
    _fail("uuid_invalid")


def _text(value, limit=128):
    if type(value) is not str or not 1 <= len(value) <= limit or any(
            ord(char) < 32 or 0xD800 <= ord(char) <= 0xDFFF for char in value):
        _fail("text_invalid")
    return value


def _identity(value):
    if type(value) is not ProcessIdentity:
        _fail("identity_invalid")
    try:
        experiment_history._identity(value.to_dict())
    except (ValueError, RuntimeError):
        _fail("identity_invalid")
    return value


def _resources(value):
    if type(value) is not ResourceDemand:
        _fail("resources_invalid")
    # Actual actors/workloads need a declared envelope, not a free slot.
    if value.cpu_units <= 0 or value.physical_bytes <= 0 or value.commit_bytes <= 0:
        _fail("resources_invalid")
    return value


def _decode(value):
    try:
        return experiment_history._json(value)
    except (ValueError, RuntimeError):
        _fail("json_invalid")


def _sql(value):
    return " ".join(value.split()).rstrip(";") if type(value) is str else None


def _transaction(conn):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _fail("transaction_required")


def validate_schema_locked(conn):
    """No repair: any partial/foreign table or guard fails closed, even empty."""
    _transaction(conn)
    names = (*TABLES, *GUARDS)
    found = conn.execute("SELECT name,type,CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END "
        "FROM sqlite_master WHERE name IN (" + ",".join("?" for _ in names) + ") OR name GLOB ? "
        "OR (type='trigger' AND tbl_name IN (" + ",".join("?" for _ in TABLES) + ")) LIMIT 65",
        (*names, _PREFIX + "*", *TABLES)).fetchall()
    if not found:
        if experiment_host_backing.validate_schema_locked(conn):
            _fail("backing_without_scope")
        return False
    expected = {name: ("table", _sql(statement)) for name, statement in SCHEMA.items()}
    expected.update({name: ("trigger", _sql(statement)) for name, statement in GUARDS.items()})
    if len(found) != len(expected) or {row[0]: (row[1], _sql(row[2])) for row in found} != expected:
        _fail("schema_invalid")
    for table in TABLES:
        if tuple(row[1] for row in conn.execute("PRAGMA table_info(" + table + ")")) != FIELDS[table]:
            _fail("schema_invalid")
        # Additional UNIQUE indexes introduce alternate REPLACE conflicts that
        # immutable guards cannot safely infer. Only canonical autoindexes exist.
        indexes = conn.execute("SELECT name,sql FROM sqlite_master WHERE type='index' AND tbl_name=? LIMIT 17",
                               (table,)).fetchall()
        expected_indexes = {f"sqlite_autoindex_{table}_{index}": (key,)
                            for index, key in enumerate(_UNIQUE[table], 1)}
        if len(indexes) != len(expected_indexes) or any(row[1] is not None for row in indexes):
            _fail("schema_invalid")
        for name, _ in indexes:
            # Name is compared to fixed expected names before being SQL syntax.
            if name not in expected_indexes or tuple(row[2] for row in conn.execute(
                    "PRAGMA index_info(" + name + ")")) != expected_indexes[name]:
                _fail("schema_invalid")
    return True


def _held(conn, policy, guard):
    _transaction(conn)
    if type(policy) is not PolicyCoordinator or type(guard) is not PolicyGuard or policy.store._policy is not policy:
        _fail("policy_required")
    policy.assert_held(guard)
    runtime = policy.revalidate(conn, guard)
    files = [row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"]
    if len(files) != 1 or Path(files[0]) != Path(policy.store.db_path):
        _fail("daily_ledger_mismatch")
    return runtime


@dataclass(frozen=True)
class HostScopeSpec:
    scope_id: str
    suite: str
    isolated_ledger_path: str
    isolated_ledger_identity: tuple[int, int]
    isolated_policy_instance_id: str

    def __post_init__(self):
        _uuid(self.scope_id)
        _uuid(self.isolated_policy_instance_id)
        _text(self.isolated_ledger_path, 32768)
        path = Path(self.isolated_ledger_path)
        if self.suite not in {"S2", "P4"} or not path.is_absolute() or ".." in path.parts:
            _fail("scope_invalid")
        if (type(self.isolated_ledger_identity) is not tuple or len(self.isolated_ledger_identity) != 2 or
                any(type(value) is not int or not 0 <= value < 1 << 128 for value in self.isolated_ledger_identity) or
                self.isolated_ledger_identity[1] == 0):
            _fail("scope_invalid")


@dataclass(frozen=True)
class MemberClaim:
    member_id: str
    kind: str
    role: str
    requested: ResourceDemand

    def __post_init__(self):
        _uuid(self.member_id)
        _resources(self.requested)
        if not ((self.kind == "infrastructure" and self.role in _INFRA_ROLES) or
                (self.kind == "workload" and self.role in {"workload", "unmanaged_baseline"})):
            _fail("member_kind_invalid")


@dataclass(frozen=True)
class JobBinding:
    member_id: str
    kind: str
    job_name: str
    creation_nonce: str
    guardian_member_id: str
    wrapper_member_id: str | None = None
    isolated_execution_id: str | None = None
    isolated_reservation_id: str | None = None

    def __post_init__(self):
        _uuid(self.member_id)
        _uuid(self.guardian_member_id)
        if type(self.creation_nonce) is not str or re.fullmatch("[0-9a-f]{32}", self.creation_nonce) is None:
            _fail("job_invalid")
        if self.kind == "managed":
            _uuid(self.isolated_execution_id)
            _text(self.isolated_reservation_id)
            _uuid(self.wrapper_member_id)
            if (self.guardian_member_id == self.wrapper_member_id or self.job_name !=
                    "Local\\ResourceSentinel.Job." + self.isolated_execution_id + "." + self.creation_nonce):
                _fail("job_invalid")
        elif self.kind == "query_only":
            if (self.wrapper_member_id is not None or self.isolated_execution_id is not None or
                    self.isolated_reservation_id is not None or self.job_name !=
                    "Local\\ResourceSentinel.Test.Job." + self.creation_nonce):
                _fail("job_invalid")
        else:
            _fail("job_kind_invalid")


class RegisteredHostScope:
    """Exact original publication custody only; no native/readiness authority."""
    def __init__(self, demand, spec, row, *, preparation=None, _token=None):
        if _token is not _CREATE:
            _fail("original_scope_required")
        self.demand, self.spec = demand, spec
        self.preparation = preparation
        self._binding = _canonical(row)
        self._immutable = (demand, spec, self._binding, preparation)
        self._claims = {}
        self._actors = {}
        self._jobs = {}
        self._backings = {}

    def _original(self):
        if (type(self.demand) is not experiment_demand.DailyExperimentDemand or
                _ORIGINALS.get(self.demand.declaration.experiment_id) is not self):
            _fail("original_scope_required")
        self.demand._static_original()
        self.demand._assert_unused_claim()
        if (type(self.spec) is not HostScopeSpec or self.demand is not self._immutable[0] or
                self.spec is not self._immutable[1] or self._binding != self._immutable[2]):
            _fail("original_scope_changed")
        if self.preparation is not self._immutable[3]:
            _fail("original_preparation_changed")
        _assert_preparation(self.demand, self.spec, self.preparation, self)
        return _decode(self._binding)


def _assert_preparation(demand, spec, preparation, registered=None):
    if preparation is None:
        if demand._native_preparation is not None:
            _fail("original_preparation_changed")
        return
    kind = experiment_host_scope.ProductionExperimentScope
    if type(preparation) is not kind or demand._native_preparation is not preparation:
        _fail("original_preparation_required")
    kind._assert_ledger_original(preparation, demand, spec, registered)


@dataclass(frozen=True)
class HostExclusionInventory:
    identities: frozenset[ProcessIdentity]
    managed_job_names: tuple[str, ...]
    query_job_names: tuple[str, ...]
    rows: int
    bytes_used: int
    scope_count: int
    scopes_json: tuple[str, ...] = ()
    host_rows: int = 0
    host_bytes_used: int = 0
    prior_exclusion: experiment_exclusion.ExclusionInventory | None = None
    admission_backings: tuple[experiment_host_backing.BackingObservation, ...] = ()


class _Budget:
    def __init__(self):
        self.rows = self.bytes = 0

    def charge(self, rows, count):
        if type(rows) is not int or rows < 0 or type(count) is not int or count < 0:
            _fail("history_budget_invalid")
        self.rows += rows
        self.bytes += count
        if self.rows > MAX_ROWS or self.bytes > MAX_BYTES:
            _fail("history_exhausted")


def _history_locked(conn, budget):
    """Charge each existing history reader once, passing remaining allowances."""
    experiment_exclusion._precheck_history_locked(conn)
    history = experiment_history.verify_experiment_history_locked(conn,
        max_rows=MAX_ROWS - budget.rows, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(history.rows_used, history.bytes_used)
    previous = daily_successor_history.read_successor_history(conn,
        max_rows=MAX_ROWS - budget.rows, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(previous.rows_used, previous.bytes_used)
    epochs = daily_successor_epoch.read_successor_guardian_epochs(conn,
        max_rows=MAX_ROWS - budget.rows, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(epochs.rows_used, epochs.bytes_used)
    archived = {json.loads(entry.record)["transition_id"]: entry for entry in previous.entries}
    for audit in epochs.entries:
        row = audit.to_dict()
        entry = archived.get(row["transition_id"])
        if entry is None:
            _fail("orphan_epoch_history")
        record = json.loads(entry.record)
        if (row["succession_sha256"] != entry.sha256 or
                row["successor_generation"] != record["successor"]["generation"] or
                row["policy_instance_id"] != record["policy"]["instance_id"] or
                row["policy_logon_id"] != record["policy"]["logon_id"]):
            _fail("epoch_history_changed")
    return history


def _rows(conn, table, budget):
    fields = FIELDS[table]
    checks = []
    for name in fields:
        if name in _COMMON[:2]:
            checks.append(f"typeof({name})='integer'")
        else:
            predicate = (f"typeof({name})='text' AND length(CAST({name} AS BLOB))<={_LIMITS[name] * 4} "
                         f"AND length({name})<={_LIMITS[name]} AND instr({name},char(0))=0")
            checks.append(f"({name} IS NULL OR ({predicate}))" if name in _NULLABLE else "(" + predicate + ")")
    allowance = MAX_ROWS - budget.rows
    valid = "_host_position<=" + str(allowance) + " AND " + " AND ".join(checks)
    projection = ",".join(f"CASE WHEN {valid} THEN {name} END" for name in fields)
    result = []
    for values in conn.execute(f"SELECT {projection},CASE WHEN {valid} THEN 1 ELSE 0 END FROM "
            f"(SELECT {','.join(fields)},row_number() OVER (ORDER BY rowid) AS _host_position "
            f"FROM {table} ORDER BY rowid LIMIT ?) ORDER BY _host_position", (allowance + 1,)):
        if len(result) >= allowance:
            _fail("history_exhausted")
        if values[-1] != 1:
            _fail("row_bound_invalid")
        row = dict(zip(fields, tuple(values)[:-1]))
        budget.charge(1, len(_canonical(row).encode("ascii")))
        if (row["schema_version"] != 1 or not 0 <= row["registered_revision"] < 1 << 63 or
                row["binding_sha256"] != _digest({k: v for k, v in row.items() if k != "binding_sha256"})):
            _fail("row_binding_invalid")
        result.append(row)
    return result


def _generation_digest(generation):
    return _digest({key: value for key, value in generation.items() if key != "state"})


def _daily_binding(conn, scope, history, guard, *, restrictive=False):
    matches = [_decode(value) for value in history.active_json
               if _decode(value)["experiment_id"] == scope["experiment_id"]]
    if len(matches) != 1:
        _fail("original_demand_missing")
    metadata = matches[0]
    generation = daily_generation.read_generation(conn)
    if (generation is None or generation["state"] not in {"ACTIVE", "DRAINING"} or
            _generation_digest(generation) != scope["generation_binding_sha256"] or
            any(metadata[key] != scope[target] for key, target in (
                ("execution_id", "daily_execution_id"), ("reservation_id", "reservation_id"),
                ("suite", "suite"), ("source_generation", "source_generation"),
                ("source_digest", "source_digest"), ("config_digest", "config_digest"),
                ("binding_sha256", "demand_binding_sha256"), ("owner_logon_id", "logon_id"))) or
            scope["logon_id"] != guard.binding.logon_id or
            scope["daily_policy_instance_id"] != guard.binding.instance_id or
            scope["isolated_policy_instance_id"] == guard.binding.instance_id or
            Path(scope["isolated_ledger_path"]).parent != Path(metadata["scope_directory"]) or
            Path(scope["isolated_ledger_path"]) == Path(generation["ledger_path"]) or
            scope["isolated_ledger_identity_json"] == metadata["ledger_identity_json"]):
        _fail("daily_binding_changed")
    # The shared verifier above validates full requested/floor/allocation rows.
    execution = next((dict(zip(row.fields, row.values)) for row in history._sql_rows
                      if row.table == "managed_executions" and dict(zip(row.fields, row.values))["execution_id"] ==
                      scope["daily_execution_id"]), None)
    allocation = next((dict(zip(row.fields, row.values)) for row in history._sql_rows
                       if row.table == "reservations" and dict(zip(row.fields, row.values))["id"] ==
                       scope["reservation_id"]), None)
    if execution is None or allocation is None:
        _fail("daily_allocation_missing")
    if restrictive:
        assert_new_capacity_allowed(conn)
        runtime = PolicyCoordinator._runtime(conn)
        # SQLite samples its clock within this same SQL transaction; no injected
        # readiness Boolean, caller timestamp or Python/native query can renew it.
        now = conn.execute("SELECT (julianday('now')-2440587.5)*86400.0").fetchone()[0]
        if (generation["state"] != "ACTIVE" or runtime["mode"] != "off" or
                runtime["admission_barrier"] != "NONE" or execution["state"] != "RESERVED" or
                type(now) not in (int, float) or not math.isfinite(now) or allocation["expires_at"] <= now):
            _fail("no_new_work")
    return metadata


def _combined_jobs(conn, history, managed, query, backings=()):
    old_names = []
    for raw in history.exclusions_json:
        row = _decode(raw)
        if row["phase"] != "CLOSED":
            old_names.append(row["job_name"])
    # A pending partition already occupies an enrolled slot. These count-only
    # labels are never returned as Job names or passed to native operations.
    pending = tuple("pending-partition:" + row.binding.execution_id for row in backings
                    if not any(".Job." + row.binding.execution_id + "." in name for name in managed))
    _combined_jobs_locked(conn, tuple(old_names) + tuple(managed) + pending)
    if len(query) > MAX_QUERY_JOBS or len(set((*old_names, *managed, *query))) != len(old_names) + len(managed) + len(query):
        _fail("job_limit_or_duplicate")


def _inventory(conn, policy, guard):
    runtime = _held(conn, policy, guard)
    if not validate_schema_locked(conn):
        return HostExclusionInventory(frozenset(), (), (), 0, 0, 0), None, {}
    budget = _Budget()
    history = _history_locked(conn, budget)
    start_rows, start_bytes = budget.rows, budget.bytes
    tables = {table: _rows(conn, table, budget) for table in TABLES}
    scopes = tables[SCOPES_TABLE]
    if len(scopes) > 1 or (not scopes and any(tables[name] for name in TABLES[1:])):
        _fail("scope_orphan")
    if len(tables[MEMBERS_TABLE]) > MAX_MEMBERS or len(tables[ACTORS_TABLE]) > MAX_ACTORS:
        _fail("member_limit")
    identities, managed, query = set(), [], []
    for scope in scopes:
        for key in ("scope_id", "experiment_id", "daily_execution_id", "source_generation",
                    "isolated_policy_instance_id", "daily_policy_instance_id"):
            _uuid(scope[key])
        spec = HostScopeSpec(scope["scope_id"], scope["suite"], scope["isolated_ledger_path"],
            tuple(_decode(scope["isolated_ledger_identity_json"])), scope["isolated_policy_instance_id"])
        metadata = _daily_binding(conn, scope, history, guard)
        if scope["registered_revision"] > runtime["registry_revision"]:
            _fail("revision_changed")
        members, actors = {}, {}
        for row in tables[MEMBERS_TABLE]:
            if row["scope_id"] != spec.scope_id or row["registered_revision"] > runtime["registry_revision"]:
                _fail("member_orphan")
            claim = MemberClaim(row["member_id"], row["kind"], row["role"], ResourceDemand.from_dict(_decode(row["demand_json"])))
            members[claim.member_id] = claim
        requested = ResourceDemand.from_dict(_decode(metadata["demand_json"]))
        for key, amount in requested.to_dict().items():
            values = [claim.requested.to_dict()[key] for claim in members.values()]
            total = math.fsum(values) if key == "cpu_units" else sum(values)
            if total > amount:
                _fail("aggregate_demand_exceeded")
        for row in tables[ACTORS_TABLE]:
            member = members.get(row["member_id"])
            actor = _identity(ProcessIdentity.from_dict(_decode(row["identity_json"])))
            if (member is None or member.role == "workload" or row["scope_id"] != spec.scope_id or
                    row["registered_revision"] > runtime["registry_revision"] or
                    actor.logon_id != scope["logon_id"] or actor in identities):
                _fail("actor_orphan_or_duplicate")
            actors[member.member_id] = actor
            identities.add(actor)
        for row in tables[JOBS_TABLE]:
            job = JobBinding(**{key: row[key] for key in JobBinding.__dataclass_fields__})
            member = members.get(job.member_id)
            guardian = members.get(job.guardian_member_id)
            if (member is None or member.role != "workload" or row["scope_id"] != spec.scope_id or
                    row["registered_revision"] > runtime["registry_revision"] or guardian is None or
                    job.guardian_member_id not in actors):
                _fail("job_orphan")
            if job.kind == "managed":
                wrapper = members.get(job.wrapper_member_id)
                if (guardian.role != "guardian" or wrapper is None or wrapper.role != "wrapper" or
                        job.wrapper_member_id not in actors or actors[job.wrapper_member_id] == actors[job.guardian_member_id] or
                        job.isolated_execution_id == scope["daily_execution_id"] or
                        job.isolated_reservation_id == scope["reservation_id"]):
                    _fail("job_actor_binding_invalid")
                managed.append(job.job_name)
            else:
                if spec.suite != "P4" or guardian.role != "query_owner":
                    _fail("query_scope_invalid")
                query.append(job.job_name)
    backings = experiment_host_backing.read_for_inventory_locked(conn, tables=tables,
        revision=runtime["registry_revision"], budget=budget)
    _combined_jobs(conn, history, managed, query, backings)
    prior = experiment_exclusion._inventory_from_history_locked(conn, guard, history)
    return HostExclusionInventory(frozenset(identities), tuple(managed), tuple(query), budget.rows,
        budget.bytes, len(scopes), tuple(_canonical(row) for row in scopes),
        budget.rows - start_rows, budget.bytes - start_bytes, prior, backings), history, tables


def read_locked(conn, *, policy, guard):
    """Observation only. HOLD/expiry keeps every actor/Job and aggregate demand."""
    try:
        inventory, _, tables = _inventory(conn, policy, guard)
    except HostLedgerError:
        raise
    except (RuntimeError, ValueError, TypeError, KeyError, OverflowError, sqlite3.DatabaseError):
        # Consumer code has one refusal type; no unverified nested history can
        # escape as a seemingly successful empty exclusion inventory.
        raise HostLedgerError("inventory_unverified") from None
    if tables:
        published = {row["member_id"] for table in (ACTORS_TABLE, JOBS_TABLE) for row in tables[table]}
        if any(row["member_id"] not in published for row in tables[MEMBERS_TABLE]):
            # A durable creation obligation may already have a live, not-yet-
            # acknowledged process. Empty identities are NOT permission for
            # legacy writers to touch it. Only exact publication closes this.
            _fail("member_publication_pending")
    return inventory


def assert_release_unblocked_locked(conn, *, experiment_id, execution_id, reservation_id):
    """An unresolved host scope cannot use S1/before-native release authority."""
    if not validate_schema_locked(conn):
        return
    # Bound before materializing and reject any ambiguous partial identity match.
    budget = _Budget()
    for row in _rows(conn, SCOPES_TABLE, budget):
        if (row["experiment_id"] == experiment_id or row["daily_execution_id"] == execution_id or
                row["reservation_id"] == reservation_id):
            _fail("cleanup_unverified")


def _new_row(values, revision):
    row = dict(values, schema_version=1, registered_revision=revision + 1)
    row["binding_sha256"] = _digest(row)
    return row


def _insert(conn, table, row, runtime, *, scope, publication, policy, guard):
    """One lexical original INSERT, never a digest-based SQL capability."""
    revision = runtime["registry_revision"]
    if type(revision) is not int or not 0 <= revision < (1 << 63) - 1:
        _fail("revision_invalid")
    if id(conn) in _INSERT_OPERATIONS:
        _fail("insert_operation_in_progress")
    expected = tuple(row[key] for key in FIELDS[table])
    thread = threading.get_ident()
    operation, consumed = object(), False
    _INSERT_OPERATIONS[id(conn)] = operation

    def authorize(candidate_table, *values):
        nonlocal consumed
        try:
            if (consumed or not conn.in_transaction or threading.get_ident() != thread or
                    _INSERT_OPERATIONS.get(id(conn)) is not operation or candidate_table != table or
                    values != expected or tuple(row[key] for key in FIELDS[table]) != expected):
                return 0
            # Metadata only: no source/native/readiness observation is permitted
            # in this callback. Revalidate the actual same-transaction POLICY.
            _held(conn, policy, guard)
            original = scope._original()
            if table == SCOPES_TABLE:
                if publication is not scope or original != row:
                    return 0
            else:
                originals = {MEMBERS_TABLE: scope._claims, ACTORS_TABLE: scope._actors,
                             JOBS_TABLE: scope._jobs}[table]
                retained = originals.get(row["member_id"])
                if retained is None or retained[0] is not publication or retained[1] is not row:
                    return 0
            consumed = True
            return 1
        except (RuntimeError, ValueError, TypeError, KeyError, sqlite3.DatabaseError):
            return 0

    try:
        conn.create_function(_INSERT_UDF, -1, authorize)
        conn.execute("INSERT INTO " + table + "(" + ",".join(FIELDS[table]) + ") VALUES(" +
                     ",".join("?" for _ in FIELDS[table]) + ")", expected)
        if not consumed:
            _fail("original_insert_required")
    finally:
        try:
            conn.create_function(_INSERT_UDF, -1, None)
        finally:
            if _INSERT_OPERATIONS.get(id(conn)) is operation:
                del _INSERT_OPERATIONS[id(conn)]
    if conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 "
                    "WHERE singleton=1 AND registry_revision=?", (revision,)).rowcount != 1:
        _fail("revision_changed")


def declare_scope_locked(conn, *, demand, spec, policy, guard, preparation=None):
    """Retain one original SQL owner; caller retains it even across lost ACKs."""
    runtime = _held(conn, policy, guard)
    if type(demand) is not experiment_demand.DailyExperimentDemand or type(spec) is not HostScopeSpec:
        _fail("original_demand_required")
    demand._static_original()
    demand._assert_unused_claim()
    if (demand.declaration.suite != spec.suite or demand._policy_original != guard.binding or
            Path(policy.store.db_path) != demand.ledger_path or
            Path(spec.isolated_ledger_path).parent != demand.directory or
            spec.isolated_ledger_identity == demand.ledger_identity):
        _fail("original_demand_changed")
    _assert_preparation(demand, spec, preparation, _ORIGINALS.get(demand.declaration.experiment_id))
    present = validate_schema_locked(conn)
    history = _history_locked(conn, _Budget())
    rows = [_decode(value) for value in history.active_json]
    if len(rows) != 1 or rows[0]["experiment_id"] != demand.declaration.experiment_id:
        _fail("original_demand_missing")
    metadata = rows[0]
    if metadata != demand._binding(metadata["reservation_id"]):
        _fail("original_demand_changed")
    values = dict(scope_id=spec.scope_id, experiment_id=metadata["experiment_id"],
        daily_execution_id=metadata["execution_id"], reservation_id=metadata["reservation_id"], suite=spec.suite,
        source_generation=metadata["source_generation"], source_digest=metadata["source_digest"],
        config_digest=metadata["config_digest"], generation_binding_sha256=_generation_digest(demand._original_generation_binding()),
        demand_binding_sha256=metadata["binding_sha256"], isolated_ledger_path=spec.isolated_ledger_path,
        isolated_ledger_identity_json=_canonical(spec.isolated_ledger_identity),
        isolated_policy_instance_id=spec.isolated_policy_instance_id,
        daily_policy_instance_id=guard.binding.instance_id, logon_id=guard.binding.logon_id)
    _daily_binding(conn, values, history, guard)
    original = _ORIGINALS.get(metadata["experiment_id"])
    if original is None:
        original = RegisteredHostScope(demand, spec, _new_row(values, runtime["registry_revision"]),
                                       preparation=preparation, _token=_CREATE)
        _ORIGINALS[metadata["experiment_id"]] = original
        if preparation is not None:
            experiment_host_scope.ProductionExperimentScope._retain_ledger_scope(preparation, original)
    expected = original._original()
    if (original.demand is not demand or original.spec is not spec or original.preparation is not preparation or
            {key: expected[key] for key in values} != values):
        _fail("original_scope_changed")
    conn.execute("SAVEPOINT experiment_host_declaration")
    try:
        if not present:
            for statement in (*SCHEMA.values(), *GUARDS.values()):
                conn.execute(statement)
        _, _, tables = _inventory(conn, policy, guard)
        if tables[SCOPES_TABLE]:
            if tables[SCOPES_TABLE] != [expected]:
                _fail("scope_occupied")
        else:
            if demand._native_preparation_sealed:
                _fail("no_new_work")
            _daily_binding(conn, values, history, guard, restrictive=True)
            if expected["registered_revision"] != runtime["registry_revision"] + 1:
                _fail("publication_revision_changed")
            _insert(conn, SCOPES_TABLE, expected, runtime, scope=original, publication=original,
                    policy=policy, guard=guard)
            read_locked(conn, policy=policy, guard=guard)
    except BaseException:
        conn.execute("ROLLBACK TO experiment_host_declaration")
        conn.execute("RELEASE experiment_host_declaration")
        raise
    conn.execute("RELEASE experiment_host_declaration")
    return original


def _publication(conn, scope, policy, guard):
    if type(scope) is not RegisteredHostScope:
        _fail("original_scope_required")
    expected = scope._original()
    runtime = _held(conn, policy, guard)
    _, history, tables = _inventory(conn, policy, guard)
    if history is None or tables[SCOPES_TABLE] != [expected]:
        _fail("original_scope_changed")
    _daily_binding(conn, expected, history, guard)
    return expected, runtime, tables, history


def _publish(conn, scope, table, key, values, originals, original, policy, guard):
    expected, runtime, tables, history = _publication(conn, scope, policy, guard)
    saved = originals.get(key)
    if saved is None:
        saved = (original, _new_row(values, runtime["registry_revision"]))
        originals[key] = saved
    if saved[0] is not original or {name: saved[1][name] for name in values} != values:
        _fail("original_publication_changed")
    matches = [row for row in tables[table] if row["member_id"] == key]
    if matches:
        if matches != [saved[1]]:
            _fail("publication_changed")
        return dict(saved[1])
    # A committed exact original can reconcile after HOLD/expiry/freeze without
    # claiming fresh capacity. Only a missing publication enters the new-work
    # gate; persisted rows and original object custody were checked above.
    if scope.demand._native_preparation_sealed:
        _fail("no_new_work")
    _daily_binding(conn, expected, history, guard, restrictive=True)
    if saved[1]["registered_revision"] != runtime["registry_revision"] + 1:
        _fail("publication_revision_changed")
    # A checked SQL rejection must not leave a partially inserted row that a
    # caller could accidentally commit after catching the domain exception.
    conn.execute("SAVEPOINT experiment_host_publication")
    try:
        _insert(conn, table, saved[1], runtime, scope=scope, publication=original, policy=policy, guard=guard)
        _inventory(conn, policy, guard)
    except BaseException:
        conn.execute("ROLLBACK TO experiment_host_publication")
        conn.execute("RELEASE experiment_host_publication")
        raise
    conn.execute("RELEASE experiment_host_publication")
    return dict(saved[1])


def reserve_member_locked(conn, *, scope, claim, policy, guard):
    if type(claim) is not MemberClaim or type(scope) is not RegisteredHostScope:
        _fail("original_member_required")
    if scope.preparation is not None:
        scope._original()
        if not any(item is claim for item in scope.preparation.plan.members):
            _fail("declared_original_member_required")
    values = dict(member_id=claim.member_id, scope_id=scope.spec.scope_id, kind=claim.kind,
                  role=claim.role, demand_json=_canonical(claim.requested.to_dict()))
    return _publish(conn, scope, MEMBERS_TABLE, claim.member_id, values, scope._claims, claim, policy, guard)


@dataclass(frozen=True)
class MemberCreationObservation:
    """Same-transaction lease observation, not native custody or a permit."""
    member_id: str
    registered_revision: int
    daily_expires_at: float


def validate_member_creation_locked(conn, *, scope, claim, policy, guard):
    """Recheck new creation separately from readonly original member replay.

    The native owner must retain its own original creation operation and check
    its expiry/readiness at the final native boundary after this SQL closes.
    No claim, allocation, registry revision or publication is changed here.
    """
    if type(scope) is not RegisteredHostScope or type(claim) is not MemberClaim:
        _fail("original_member_required")
    expected, _, tables, history = _publication(conn, scope, policy, guard)
    saved = scope._claims.get(claim.member_id)
    values = dict(member_id=claim.member_id, scope_id=scope.spec.scope_id, kind=claim.kind,
                  role=claim.role, demand_json=_canonical(claim.requested.to_dict()))
    if (saved is None or saved[0] is not claim or
            any(saved[1][key] != value for key, value in values.items()) or
            [row for row in tables[MEMBERS_TABLE] if row["member_id"] == claim.member_id] != [saved[1]]):
        _fail("original_member_required")
    if scope.preparation is not None and not any(item is claim for item in scope.preparation.plan.members):
        _fail("declared_original_member_required")
    if any(row["member_id"] == claim.member_id for table in (ACTORS_TABLE, JOBS_TABLE) for row in tables[table]):
        _fail("member_already_published")
    if scope.demand._native_preparation_sealed:
        _fail("no_new_work")
    _daily_binding(conn, expected, history, guard, restrictive=True)
    allocations = conn.execute("SELECT expires_at FROM reservations WHERE id=? AND execution_id=? LIMIT 2",
        (expected["reservation_id"], expected["daily_execution_id"])).fetchall()
    if (len(allocations) != 1 or type(allocations[0][0]) not in (float, int) or
            not math.isfinite(allocations[0][0]) or allocations[0][0] <= 0):
        _fail("daily_allocation_missing")
    return MemberCreationObservation(claim.member_id, saved[1]["registered_revision"], float(allocations[0][0]))


def publish_actor_locked(conn, *, scope, member_id, actor, policy, guard):
    """Publish an observed identity; it is NOT native custody evidence."""
    if type(scope) is not RegisteredHostScope:
        _fail("original_scope_required")
    _uuid(member_id)
    _identity(actor)
    values = dict(member_id=member_id, scope_id=scope.spec.scope_id, identity_json=_canonical(actor.to_dict()))
    return _publish(conn, scope, ACTORS_TABLE, member_id, values, scope._actors, actor, policy, guard)


def publish_job_locked(conn, *, scope, binding, policy, guard):
    """Publish after retained native proof and before launch; no permit minted."""
    if type(scope) is not RegisteredHostScope or type(binding) is not JobBinding:
        _fail("original_job_required")
    if scope.preparation is not None and binding.kind == "managed":
        backing = scope._backings.get(binding.member_id)
        if type(backing) is not experiment_host_backing.ParentAdmissionBacking:
            _fail("admission_backing_required")
        backing._original()
        if (binding.wrapper_member_id != backing.wrapper_member_id or
                binding.isolated_execution_id != backing.binding.execution_id or
                binding.isolated_reservation_id != backing.binding.reservation_id):
            _fail("admission_backing_changed")
        experiment_host_backing.validate_backing_locked(conn, scope_id=scope.spec.scope_id,
            member_id=binding.member_id, wrapper_member_id=binding.wrapper_member_id,
            binding=backing.binding, policy=policy, guard=guard)
    values = {key: getattr(binding, key) for key in JobBinding.__dataclass_fields__}
    values["scope_id"] = scope.spec.scope_id
    return _publish(conn, scope, JOBS_TABLE, binding.member_id, values, scope._jobs, binding, policy, guard)


# Load fixed collaborators before any *_locked function can enter SQL. These
# modules may refer back to this module in methods, never during construction.
from . import experiment_host_scope, experiment_host_backing
