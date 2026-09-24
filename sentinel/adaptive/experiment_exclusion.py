"""Daily legacy-writer exclusions for one original, isolated S1 native scope.

These SQL primitives publish metadata, never capacity or native authority. The
original scope owner must verify and retain creation/actor/Job custody before
calling register_locked under the actual daily POLICY. Readers consume the same
daily reservation and never inspect an alternate capacity database. This slice
has no closure, deletion, retirement or launch-permit API.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from uuid import UUID

from . import daily_generation, experiment_demand
from .contracts import ProcessIdentity, ResourceDemand
from .policy import PolicyCoordinator, PolicyGuard


TABLE = "adaptive_experiment_exclusions"
_PREFIX = "experiment_exclusion_"
MAX_SCOPES = 1
MAX_JOBS = 10
_PRODUCTION_JOB = re.compile(r"Local\\ResourceSentinel\.Job\.([0-9a-f-]{36})\.([0-9a-f]{32})\Z")
_SID = re.compile(r"S-1-5-5-[0-9]+-[0-9]+\Z")
_FIELDS = ("scope_execution_id", "schema_version", "experiment_id", "daily_execution_id",
    "reservation_id", "source_generation", "isolated_ledger_path", "isolated_ledger_identity_json",
    "isolated_policy_instance_id", "job_name", "creation_nonce", "logon_id",
    "guardian_identity_json", "wrapper_identity_json", "phase", "cleanup_digest",
    "registered_revision", "binding_sha256")
_SCHEMA = """CREATE TABLE adaptive_experiment_exclusions (
    scope_execution_id TEXT PRIMARY KEY NOT NULL,
    schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
    experiment_id TEXT UNIQUE NOT NULL, daily_execution_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL, source_generation TEXT NOT NULL,
    isolated_ledger_path TEXT NOT NULL, isolated_ledger_identity_json TEXT NOT NULL,
    isolated_policy_instance_id TEXT NOT NULL, job_name TEXT UNIQUE NOT NULL,
    creation_nonce TEXT UNIQUE NOT NULL, logon_id TEXT NOT NULL,
    guardian_identity_json TEXT NOT NULL, wrapper_identity_json TEXT,
    phase TEXT NOT NULL CHECK(phase IN ('CREATED','REGISTERED','CLOSED')),
    cleanup_digest TEXT,
    registered_revision INTEGER NOT NULL CHECK(typeof(registered_revision)='integer' AND registered_revision>=0),
    binding_sha256 TEXT NOT NULL,
    CHECK((phase IN ('CREATED','REGISTERED') AND cleanup_digest IS NULL) OR
          (phase='CLOSED' AND typeof(cleanup_digest)='text' AND length(cleanup_digest)=64
           AND cleanup_digest NOT GLOB '*[^0-9a-f]*')))
"""
_GUARDS = {
    _PREFIX + "insert_guard": """CREATE TRIGGER experiment_exclusion_insert_guard
        BEFORE INSERT ON adaptive_experiment_exclusions
        WHEN EXISTS(SELECT 1 FROM adaptive_experiment_exclusions)
        BEGIN SELECT RAISE(ABORT,'experiment_exclusion_scope_occupied'); END""",
    _PREFIX + "update_guard": """CREATE TRIGGER experiment_exclusion_update_guard
        BEFORE UPDATE ON adaptive_experiment_exclusions
        BEGIN SELECT RAISE(ABORT,'experiment_exclusion_cleanup_unverified'); END""",
    _PREFIX + "delete_guard": """CREATE TRIGGER experiment_exclusion_delete_guard
        BEFORE DELETE ON adaptive_experiment_exclusions
        BEGIN SELECT RAISE(ABORT,'experiment_exclusion_cleanup_unverified'); END""",
}
_BOUNDS = {"scope_execution_id": 36, "experiment_id": 36, "daily_execution_id": 36,
    "reservation_id": 128, "source_generation": 36, "isolated_ledger_path": 32768,
    "isolated_ledger_identity_json": 128, "isolated_policy_instance_id": 36, "job_name": 256,
    "creation_nonce": 32, "logon_id": 184, "guardian_identity_json": 1024,
    "wrapper_identity_json": 1024, "phase": 16, "cleanup_digest": 64, "binding_sha256": 64}


class ExperimentExclusionError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_exclusion_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise ExperimentExclusionError(reason)


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        return parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _sql(value):
    return " ".join(value.split()).rstrip(";") if type(value) is str else None


def _transaction(conn):
    if not conn.in_transaction:
        _fail("transaction_required")


@dataclass(frozen=True)
class ExperimentExclusionBinding:
    experiment_id: str
    daily_execution_id: str
    reservation_id: str
    source_generation: str
    scope_execution_id: str
    isolated_ledger_path: str
    isolated_ledger_identity: tuple[int, int]
    isolated_policy_instance_id: str
    job_name: str
    creation_nonce: str
    logon_id: str
    guardian_identity: ProcessIdentity
    wrapper_identity: ProcessIdentity | None = None

    def __post_init__(self):
        if (any(not _uuid(value) for value in (self.experiment_id, self.daily_execution_id,
                self.source_generation, self.scope_execution_id, self.isolated_policy_instance_id)) or
                type(self.reservation_id) is not str or not 1 <= len(self.reservation_id) <= 128 or
                type(self.isolated_ledger_path) is not str or not 1 <= len(self.isolated_ledger_path) <= 32768 or
                not Path(self.isolated_ledger_path).is_absolute() or
                ".." in Path(self.isolated_ledger_path).parts or
                type(self.isolated_ledger_identity) is not tuple or len(self.isolated_ledger_identity) != 2 or
                any(type(value) is not int or not 0 <= value < 1 << 128 for value in self.isolated_ledger_identity) or
                type(self.creation_nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", self.creation_nonce) is None or
                self.job_name != "Local\\ResourceSentinel.Test.Job." + self.creation_nonce or
                type(self.logon_id) is not str or len(self.logon_id) > 184 or not _SID.fullmatch(self.logon_id) or
                type(self.guardian_identity) is not ProcessIdentity or
                self.guardian_identity.logon_id != self.logon_id or
                (self.wrapper_identity is not None and (type(self.wrapper_identity) is not ProcessIdentity or
                    self.wrapper_identity.logon_id != self.logon_id or self.wrapper_identity == self.guardian_identity))):
            _fail("binding_invalid")
        if any(ord(char) < 32 for char in self.isolated_ledger_path):
            _fail("binding_invalid")

    def _values(self):
        return dict(scope_execution_id=self.scope_execution_id, schema_version=1,
            experiment_id=self.experiment_id, daily_execution_id=self.daily_execution_id,
            reservation_id=self.reservation_id, source_generation=self.source_generation,
            isolated_ledger_path=self.isolated_ledger_path,
            isolated_ledger_identity_json=_canonical(self.isolated_ledger_identity),
            isolated_policy_instance_id=self.isolated_policy_instance_id,
            job_name=self.job_name, creation_nonce=self.creation_nonce, logon_id=self.logon_id,
            guardian_identity_json=_canonical(self.guardian_identity.to_dict()),
            wrapper_identity_json=(None if self.wrapper_identity is None else
                                   _canonical(self.wrapper_identity.to_dict())))


@dataclass(frozen=True)
class ExclusionInventory:
    bindings: tuple[ExperimentExclusionBinding, ...]
    identities: frozenset[ProcessIdentity]
    job_names: tuple[str, ...]


def validate_schema_locked(conn):
    """Strict SQL schema read for the legacy consumer and retirement inventory.

    False means no table or guard exists, not an empty or repaired partial schema.
    Reserved future phases do not become supported by this schema inspection.
    """
    _transaction(conn)
    found = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()
    guards = dict(conn.execute("SELECT name,sql FROM sqlite_master WHERE name GLOB ?", (_PREFIX + "*",)))
    if found is None:
        if guards:
            _fail("schema_partial")
        return False
    if (found[0] != "table" or _sql(found[1]) != _sql(_SCHEMA) or
            tuple(row[1] for row in conn.execute("PRAGMA table_info(" + TABLE + ")")) != _FIELDS or
            set(guards) != set(_GUARDS) or
            any(_sql(guards[name]) != _sql(statement) for name, statement in _GUARDS.items())):
        _fail("schema_invalid")
    return True


def _held(conn, policy, guard):
    _transaction(conn)
    if type(policy) is not PolicyCoordinator or type(guard) is not PolicyGuard:
        _fail("policy_required")
    policy.assert_held(guard)
    runtime = policy.revalidate(conn, guard)
    databases = [row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"]
    if len(databases) != 1 or Path(databases[0]) != Path(policy.store.db_path):
        _fail("ledger_mismatch")
    return runtime


def _bounded_row(conn, table, where, params, bounds, *, fields=None):
    """Validate every projected value before materializing editable SQL data.

    SQLite TEXT length stops at NUL. Check byte length and NUL independently,
    and reject TEXT/BLOB in numeric fields despite SQLite's permissive affinity.
    Nullable values remain subject to the exact binding checks after this bound.
    """
    if fields is None:
        if table == TABLE:
            fields = _FIELDS
        elif table == experiment_demand.TABLE:
            fields = experiment_demand._FIELDS
        else:
            _fail("row_projection_invalid")
    checks = []
    for name in fields:
        if name in bounds:
            limit = bounds[name]
            checks.append("CASE WHEN typeof(" + name + ")='null' THEN 1 WHEN typeof(" + name +
                ")='text' THEN (length(CAST(" + name + " AS BLOB))<=" + str(4 * limit) +
                " AND length(" + name + ")<=" + str(limit) + " AND instr(" + name +
                ",char(0))=0) ELSE 0 END")
        else:
            checks.append("typeof(" + name + ") IN ('null','integer','real')")
    inspected = conn.execute("SELECT " + ",".join(checks) + " FROM " + table +
                             " WHERE " + where + " LIMIT 2", params).fetchall()
    if len(inspected) != 1 or any(type(value) is not int or value != 1 for value in inspected[0]):
        _fail("row_unverified")
    cursor = conn.execute("SELECT " + ",".join(fields) +
                         " FROM " + table + " WHERE " + where + " LIMIT 2", params)
    rows = cursor.fetchall()
    if len(rows) != 1:
        _fail("row_unverified")
    return dict(zip((item[0] for item in cursor.description), rows[0]))


def _binding_from_row(row):
    try:
        if (row["schema_version"] != 1 or row["phase"] != "REGISTERED" or row["cleanup_digest"] is not None or
                type(row["registered_revision"]) is not int or not 0 <= row["registered_revision"] < 1 << 63):
            _fail("phase_unverified")
        identity = json.loads(row["isolated_ledger_identity_json"])
        if type(identity) is not list:
            _fail("binding_invalid")
        value = ExperimentExclusionBinding(
            row["experiment_id"], row["daily_execution_id"], row["reservation_id"], row["source_generation"],
            row["scope_execution_id"], row["isolated_ledger_path"], tuple(identity),
            row["isolated_policy_instance_id"], row["job_name"], row["creation_nonce"], row["logon_id"],
            ProcessIdentity.from_dict(json.loads(row["guardian_identity_json"])),
            None if row["wrapper_identity_json"] is None else ProcessIdentity.from_dict(json.loads(row["wrapper_identity_json"])))
        expected = value._values()
        if any(row[key] != item for key, item in expected.items()) or row["binding_sha256"] != _digest(expected):
            _fail("binding_digest_invalid")
        return value
    except (ValueError, TypeError, KeyError, AttributeError):
        _fail("binding_invalid")


def _demand_locked(conn, binding, guard):
    experiment_demand._schema(conn)
    bounds = {name: (32768 if name in {"scope_directory"} else 2048)
              for name in experiment_demand._FIELDS if name not in {"schema_version", "revision", "owner_pid"}}
    metadata = _bounded_row(conn, experiment_demand.TABLE, "experiment_id=?",
                            (binding.experiment_id,), bounds)
    generation = daily_generation.read_generation(conn)
    if (generation is None or generation["state"] not in {"ACTIVE", "DRAINING"} or
            generation["generation"] != binding.source_generation or
            metadata["source_generation"] != binding.source_generation or
            metadata["source_digest"] != generation["source_digest"] or
            metadata["config_digest"] != generation["config_digest"] or
            metadata["execution_id"] != binding.daily_execution_id or
            metadata["reservation_id"] != binding.reservation_id or metadata["suite"] != "S1" or
            metadata["owner_logon_id"] != binding.logon_id or binding.logon_id != guard.binding.logon_id or
            Path(binding.isolated_ledger_path).parent != Path(metadata["scope_directory"]) or
            binding.isolated_policy_instance_id == guard.binding.instance_id):
        _fail("daily_binding_mismatch")
    main = [row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"]
    try:
        ledger_identity = json.loads(metadata["ledger_identity_json"])
        generation_identity = json.loads(generation["ledger_identity_json"])
        if (len(main) != 1 or Path(main[0]) != Path(generation["ledger_path"]) or
                Path(binding.isolated_ledger_path) == Path(main[0]) or
                type(ledger_identity) is not list or len(ledger_identity) != 2 or
                any(type(value) is not int or value < 0 for value in ledger_identity) or
                generation_identity != [str(value) for value in ledger_identity] or
                binding.isolated_ledger_identity == tuple(ledger_identity)):
            _fail("daily_binding_mismatch")
    except (ValueError, TypeError, KeyError):
        _fail("daily_binding_mismatch")
    expected_metadata = {key: value for key, value in metadata.items() if key != "binding_sha256"}
    if metadata["binding_sha256"] != _digest(expected_metadata):
        _fail("daily_binding_mismatch")
    try:
        declared = ResourceDemand.from_dict(json.loads(metadata["demand_json"]))
        caller = ProcessIdentity.from_dict(dict(pid=metadata["owner_pid"],
            created_filetime_100ns=metadata["owner_birth"], logon_id=metadata["owner_logon_id"]))
    except (ValueError, TypeError, KeyError):
        _fail("daily_demand_invalid")
    resources = tuple(declared.to_dict())
    execution_fields = ("state", "reservation_id", "allocation_kind", "parent_execution_id", "job_name",
        "job_nonce", "root_pid", "root_created_filetime_100ns", "guardian_epoch",
        "claim_consumed", "launch_in_flight", "launch_sealed", "coverage", "wrapper_pid",
        "wrapper_created_filetime_100ns", "logon_id", "spec_hash", "admission_binding_hash",
        *("floor_" + key for key in resources), *("requested_" + key for key in resources))
    execution = _bounded_row(conn, "managed_executions", "execution_id=?", (binding.daily_execution_id,),
        {"execution_id": 36, "reservation_id": 128, "spec_hash": 128, "admission_binding_hash": 128,
         "wrapper_created_filetime_100ns": 20, "logon_id": 184, "state": 32,
         "allocation_kind": 16, "parent_execution_id": 36, "job_name": 256, "coverage": 32,
         "job_nonce": 32, "root_created_filetime_100ns": 20, "guardian_epoch": 128},
        fields=execution_fields)
    reservation = _bounded_row(conn, "reservations", "id=? OR execution_id=?",
        (binding.reservation_id, binding.daily_execution_id),
        {"id": 128, "execution_id": 36, "request_key": 128, "managed_spec_hash": 128},
        fields=("id", "execution_id", "lifecycle_managed", "request_key", "managed_spec_hash", "owner_pid", *resources))
    if (execution["state"] not in {"RESERVED", "UNCERTAIN_HOLD"} or
            execution["reservation_id"] != binding.reservation_id or execution["allocation_kind"] != "direct" or
            execution["parent_execution_id"] is not None or execution["job_name"] is not None or
            execution["job_nonce"] is not None or execution["root_pid"] is not None or
            execution["root_created_filetime_100ns"] is not None or execution["guardian_epoch"] != "" or
            execution["claim_consumed"] != 0 or execution["launch_in_flight"] != 0 or
            execution["launch_sealed"] != 0 or execution["coverage"] != "unmanaged" or
            execution["wrapper_pid"] != caller.pid or
            execution["wrapper_created_filetime_100ns"] != str(caller.created_filetime_100ns) or
            execution["logon_id"] != caller.logon_id or
            execution["spec_hash"] != metadata["spec_hash"] or
            execution["admission_binding_hash"] != metadata["admission_binding_hash"] or
            reservation["id"] != binding.reservation_id or reservation["execution_id"] != binding.daily_execution_id or
            reservation["lifecycle_managed"] != 1 or reservation["request_key"] != metadata["request_key"] or
            reservation["managed_spec_hash"] != metadata["spec_hash"] or reservation["owner_pid"] != caller.pid):
        _fail("daily_allocation_mismatch")
    try:
        floor = ResourceDemand.from_dict({key: execution["floor_" + key] for key in declared.to_dict()})
        requested = ResourceDemand.from_dict({key: execution["requested_" + key] for key in declared.to_dict()})
        allocation = ResourceDemand.from_dict({key: reservation[key] for key in declared.to_dict()})
    except (ValueError, TypeError, KeyError):
        _fail("daily_demand_invalid")
    if (requested != declared or allocation != declared or
            any(floor.to_dict()[key] < amount for key, amount in declared.to_dict().items())):
        _fail("daily_demand_invalid")
    return caller


def _combined_jobs_locked(conn, names):
    rows = conn.execute("""SELECT substr(execution_id,1,37),substr(job_name,1,257),substr(job_nonce,1,33) FROM managed_executions
        WHERE job_name IS NOT NULL AND (typeof(state)='text' AND
            state IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED') AND
            launch_sealed IS 1 AND launch_in_flight IS 0 AND
            ((allocation_kind IN ('direct','routed') AND typeof(reservation_id)='text' AND
              length(reservation_id)>0 AND parent_execution_id IS NULL) OR
             (allocation_kind IS 'parent' AND reservation_id IS NULL AND
              typeof(parent_execution_id)='text' AND length(parent_execution_id)>0))) IS NOT 1 LIMIT 11""").fetchall()
    if len(rows) + len(names) > MAX_JOBS:
        _fail("job_limit")
    jobs = list(names)
    for execution, name, nonce in rows:
        match = _PRODUCTION_JOB.fullmatch(name) if type(name) is str else None
        if match is None or not _uuid(execution) or match.groups() != (execution, nonce):
            _fail("production_scope_invalid")
        jobs.append(name)
    if len(set(jobs)) != len(jobs):
        _fail("job_duplicate")


def read_locked(conn, *, policy, guard):
    """Strict bounded SQL read; expiry/HOLD never drops actors or a Job."""
    _held(conn, policy, guard)
    if not validate_schema_locked(conn):
        return ExclusionInventory((), frozenset(), ())
    ids = conn.execute("SELECT substr(scope_execution_id,1,37) FROM " + TABLE + " LIMIT 2").fetchall()
    if len(ids) > MAX_SCOPES:
        _fail("scope_limit")
    bindings, identities, jobs = [], set(), []
    for (execution,) in ids:
        row = _bounded_row(conn, TABLE, "scope_execution_id=?", (execution,), _BOUNDS)
        binding = _binding_from_row(row)
        identities.add(_demand_locked(conn, binding, guard))
        identities.add(binding.guardian_identity)
        if binding.wrapper_identity is not None:
            identities.add(binding.wrapper_identity)
        bindings.append(binding)
        jobs.append(binding.job_name)
    _combined_jobs_locked(conn, jobs)
    return ExclusionInventory(tuple(bindings), frozenset(identities), tuple(jobs))


def assert_available_locked(conn, *, policy, guard):
    """Read-only precreation bound; not native creation or launch authority.

    The original scope owner must retain this same daily POLICY through native
    creation and registration. Publication repeats every allocation/count check.
    """
    runtime = _held(conn, policy, guard)
    if runtime["mode"] != "off":
        _fail("daily_mode_required")
    if read_locked(conn, policy=policy, guard=guard).bindings:
        _fail("scope_occupied")
    _combined_jobs_locked(conn, ("<pending-experiment-scope>",))


def register_locked(conn, binding, *, policy, guard):
    """Publish after original native creation proof, without granting a permit.

    Caller owns the transaction/commit and retains its original publication
    operation across lost ACKs. This function never closes a native owner.
    """
    if type(binding) is not ExperimentExclusionBinding:
        _fail("binding_required")
    runtime = _held(conn, policy, guard)
    if runtime["mode"] != "off":
        _fail("daily_mode_required")
    _demand_locked(conn, binding, guard)
    if not validate_schema_locked(conn):
        conn.execute(_SCHEMA)
        for statement in _GUARDS.values():
            conn.execute(statement)
    current = read_locked(conn, policy=policy, guard=guard)
    if current.bindings:
        if current.bindings != (binding,):
            _fail("scope_occupied")
        return _bounded_row(conn, TABLE, "scope_execution_id=?", (binding.scope_execution_id,), _BOUNDS)
    _combined_jobs_locked(conn, (binding.job_name,))
    revision = runtime["registry_revision"]
    if type(revision) is not int or not 0 <= revision < (1 << 63) - 1:
        _fail("revision_invalid")
    values = binding._values()
    row = values | dict(phase="REGISTERED", cleanup_digest=None,
                        registered_revision=revision + 1, binding_sha256=_digest(values))
    conn.execute("INSERT INTO " + TABLE + "(" + ",".join(_FIELDS) + ") VALUES(" +
        ",".join("?" for _ in _FIELDS) + ")", tuple(row[name] for name in _FIELDS))
    if conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1 "
            "AND registry_revision=?", (revision,)).rowcount != 1:
        _fail("revision_changed")
    return row
