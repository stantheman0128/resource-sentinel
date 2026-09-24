"""One original successor guardian epoch; this module never creates a process.

The audit reader returns bounded data, not native or registration authority.
Publication additionally needs the exact retained successor, fresh held startup,
complete startup inventory and positively settled original POLICY/SQL owners.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from uuid import UUID, uuid4
import weakref

from . import daily_generation as generation
from . import daily_successor_history as succession
from .daily_activation_host import _ConnectionCustody
from .daily_retirement_fence import read_retirement
from .policy import PolicyBinding, PolicyCoordinator, _cleanup_outcome_unverified
from .store import LifecycleError
from .supervisor_reconcile import ReconcileResult, RetainedPolicyOperation
from .supervisor_startup import SupervisorStartup, supervisor_instance_binding


TABLE = "adaptive_successor_guardian_epochs"
MAX_ROWS, MAX_BYTES = 4096, 16 * 1024 * 1024
_FIELDS = ("schema_version", "attempt_id", "transition_id", "successor_generation",
    "succession_sha256", "old_epoch", "new_epoch", "supervisor_pid",
    "supervisor_created_filetime_100ns", "supervisor_logon_id", "supervisor_instance_id",
    "policy_instance_id", "policy_logon_id", "previous_revision", "registry_revision", "inventory_digest")
_TEXT_BOUNDS = {name: 36 for name in ("attempt_id", "transition_id", "successor_generation",
    "supervisor_instance_id", "policy_instance_id")}
_TEXT_BOUNDS.update(succession_sha256=64, old_epoch=128, new_epoch=128,
    supervisor_created_filetime_100ns=20, supervisor_logon_id=128, policy_logon_id=128,
    inventory_digest=64)
_SCHEMA = f"""CREATE TABLE {TABLE} (
    schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
    attempt_id TEXT PRIMARY KEY NOT NULL,
    transition_id TEXT NOT NULL UNIQUE, successor_generation TEXT NOT NULL UNIQUE,
    succession_sha256 TEXT NOT NULL, old_epoch TEXT NOT NULL, new_epoch TEXT NOT NULL UNIQUE,
    supervisor_pid INTEGER NOT NULL, supervisor_created_filetime_100ns TEXT NOT NULL,
    supervisor_logon_id TEXT NOT NULL, supervisor_instance_id TEXT NOT NULL,
    policy_instance_id TEXT NOT NULL, policy_logon_id TEXT NOT NULL,
    previous_revision INTEGER NOT NULL, registry_revision INTEGER NOT NULL UNIQUE,
    inventory_digest TEXT NOT NULL
)"""
_TRIGGERS = {
    TABLE + "_update": f"""CREATE TRIGGER {TABLE}_update BEFORE UPDATE ON {TABLE}
        BEGIN SELECT RAISE(ABORT,'successor_epoch_immutable'); END""",
    TABLE + "_delete": f"""CREATE TRIGGER {TABLE}_delete BEFORE DELETE ON {TABLE}
        BEGIN SELECT RAISE(ABORT,'successor_epoch_immutable'); END""",
    TABLE + "_replace": f"""CREATE TRIGGER {TABLE}_replace BEFORE INSERT ON {TABLE}
        WHEN EXISTS(SELECT 1 FROM {TABLE} WHERE attempt_id=NEW.attempt_id OR
            transition_id=NEW.transition_id OR successor_generation=NEW.successor_generation OR
            new_epoch=NEW.new_epoch OR registry_revision=NEW.registry_revision OR rowid=NEW.rowid)
        BEGIN SELECT RAISE(ABORT,'successor_epoch_immutable'); END""",
}
_ORIGINALS = weakref.WeakSet()
_CURRENT = threading.local()


def _fail(reason):
    raise LifecycleError("daily_successor_epoch_" + reason)


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, AttributeError):
        return False


def _epoch(value, *, empty=False):
    return type(value) is str and (empty and value == "" or
        re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", value) is not None)


def _transaction(conn):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _fail("transaction_required")


def _schema(conn):
    rows = conn.execute("""SELECT type,
        CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,
        CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name END,
        CASE WHEN sql IS NULL OR length(CAST(sql AS BLOB))<=65536 THEN sql END
        FROM sqlite_master WHERE name=? OR tbl_name=? OR name GLOB ? LIMIT 11""",
        (TABLE, TABLE, TABLE + "_*")).fetchall()
    if not rows:
        return False
    normalize = lambda sql: " ".join(sql.split()).rstrip(";")
    expected = {TABLE: ("table", TABLE, normalize(_SCHEMA))}
    expected.update({name: ("trigger", TABLE, normalize(sql)) for name, sql in _TRIGGERS.items()})
    expected.update({f"sqlite_autoindex_{TABLE}_{index}": ("index", TABLE, None) for index in range(1, 6)})
    if (len(rows) != len(expected) or any(name is None or table is None for _, name, table, _ in rows) or
            {name: (kind, table, None if sql is None else normalize(sql))
             for kind, name, table, sql in rows} != expected or
            tuple(row[1] for row in conn.execute(f"PRAGMA main.table_info({TABLE})")) != _FIELDS):
        _fail("schema_unverified")
    return True


def _validate(row):
    from .contracts import ProcessIdentity
    if type(row) is not dict or set(row) != set(_FIELDS):
        _fail("row_invalid")
    if (type(row["schema_version"]) is not int or row["schema_version"] != 1 or
            any(type(row[name]) is not str or len(row[name]) > bound
                for name, bound in _TEXT_BOUNDS.items()) or
            any(not _uuid(row[name]) for name in ("attempt_id", "transition_id", "successor_generation",
                "supervisor_instance_id", "policy_instance_id")) or
            any(re.fullmatch(r"[0-9a-f]{64}", row[name]) is None
                for name in ("succession_sha256", "inventory_digest")) or
            not _epoch(row["old_epoch"], empty=True) or not _epoch(row["new_epoch"]) or
            row["old_epoch"] == row["new_epoch"] or
            type(row["previous_revision"]) is not int or not 0 <= row["previous_revision"] < (1 << 63) - 1 or
            type(row["registry_revision"]) is not int or row["registry_revision"] != row["previous_revision"] + 1):
        _fail("row_invalid")
    try:
        identity = ProcessIdentity.from_dict(dict(pid=row["supervisor_pid"],
            created_filetime_100ns=row["supervisor_created_filetime_100ns"], logon_id=row["supervisor_logon_id"]))
        binding = PolicyBinding(row["policy_instance_id"], row["policy_logon_id"])
    except (TypeError, ValueError, RuntimeError):
        _fail("row_invalid")
    if (str(identity.created_filetime_100ns) != row["supervisor_created_filetime_100ns"] or
            identity.logon_id != binding.logon_id or
            supervisor_instance_binding(binding).instance_id != row["supervisor_instance_id"]):
        _fail("row_invalid")


@dataclass(frozen=True)
class SuccessorEpochAudit:
    values: tuple

    def to_dict(self):
        return dict(zip(_FIELDS, self.values))


@dataclass(frozen=True)
class SuccessorEpochHistory:
    entries: tuple[SuccessorEpochAudit, ...]
    bytes_used: int

    @property
    def rows_used(self):
        return len(self.entries)


def read_successor_guardian_epochs(conn, *, max_rows=MAX_ROWS, max_bytes=MAX_BYTES):
    """Read complete canonical immutable audit data, with no write authority."""
    _transaction(conn)
    if (type(max_rows) is not int or not 0 <= max_rows <= MAX_ROWS or
            type(max_bytes) is not int or not 0 <= max_bytes <= MAX_BYTES):
        _fail("budget_invalid")
    if not _schema(conn):
        return SuccessorEpochHistory((), 0)
    # Classify SQLite cell types/sizes before fetching any text payload.
    valid = "_epoch_position<=" + str(max_rows) + " AND " + " AND ".join(f"typeof({name})='text' AND length(CAST({name} AS BLOB))<={bound}"
                         for name, bound in _TEXT_BOUNDS.items())
    valid += " AND " + " AND ".join(f"typeof({name})='integer'" for name in
        ("schema_version", "supervisor_pid", "previous_revision", "registry_revision"))
    projection = ",".join(f"CASE WHEN {valid} THEN {name} END" for name in _FIELDS)
    entries, total, transitions, epochs, revisions, generations = [], 0, set(), set(), set(), set()
    # The overflow sentinel carries no payload into Python, even when the
    # containing inventory has no rows remaining in its shared allowance.
    for row in conn.execute(f"SELECT {projection},CASE WHEN {valid} THEN 1 ELSE 0 END "
            f"FROM (SELECT {','.join(_FIELDS)},row_number() OVER (ORDER BY registry_revision) AS _epoch_position "
            f"FROM {TABLE} ORDER BY registry_revision LIMIT ?) ORDER BY _epoch_position", (max_rows + 1,)):
        if len(entries) >= max_rows:
            _fail("rows_exceeded")
        if row[-1] != 1:
            _fail("row_invalid")
        values = tuple(row[:-1])
        value = dict(zip(_FIELDS, values))
        _validate(value)
        total += len(_encoded(value))
        if total > max_bytes:
            _fail("bytes_exceeded")
        if (value["transition_id"] in transitions or value["successor_generation"] in generations or
                value["new_epoch"] in epochs or value["registry_revision"] in revisions):
            _fail("row_invalid")
        transitions.add(value["transition_id"])
        generations.add(value["successor_generation"])
        epochs.add(value["new_epoch"])
        revisions.add(value["registry_revision"])
        entries.append(SuccessorEpochAudit(values))
    return SuccessorEpochHistory(tuple(entries), total)


def _ordinary_route(conn, epoch):
    from .supervisor_epoch import SettledEpochRollover
    if not SettledEpochRollover._audit_schema(conn):
        return False
    return conn.execute("SELECT 1 FROM adaptive_epoch_rollovers WHERE old_epoch=? OR new_epoch=? LIMIT 1",
                        (epoch, epoch)).fetchone() is not None


def validate_successor_guardian_epoch(conn, *, guardian_epoch, logon_id, policy_instance_id):
    """Data-only registration check; caller retains its own live self/proofs."""
    audits = read_successor_guardian_epochs(conn)
    matches = [entry.to_dict() for entry in audits.entries if entry.to_dict()["new_epoch"] == guardian_epoch]
    if not matches:
        return None
    if len(matches) != 1 or _ordinary_route(conn, guardian_epoch):
        _fail("ambiguous_audit_route")
    row = matches[0]
    current = generation.read_generation(conn)
    runtime = PolicyCoordinator._runtime(conn)
    archives = succession.read_successor_history(conn, max_rows=MAX_ROWS - audits.rows_used,
        max_bytes=MAX_BYTES - audits.bytes_used)
    if not archives.entries:
        _fail("succession_unverified")
    archived = archives.entries[-1]
    record = json.loads(archived.record)
    if (current != record["successor"] or current["state"] != "ACTIVE" or read_retirement(conn) is not None or
            row["transition_id"] != record["transition_id"] or row["succession_sha256"] != archived.sha256 or
            row["successor_generation"] != current["generation"] or
            row["policy_instance_id"] != policy_instance_id or row["policy_logon_id"] != logon_id or
            record["policy"]["instance_id"] != policy_instance_id or record["policy"]["logon_id"] != logon_id or
            runtime["policy_instance_id"] != policy_instance_id or runtime["policy_logon_id"] != logon_id or
            runtime["guardian_epoch"] != guardian_epoch or runtime["active_logon_id"] != logon_id or
            runtime["registry_revision"] != row["registry_revision"] or runtime["mode"] != "off" or
            runtime["admission_barrier"] != "NONE"):
        _fail("binding_changed")
    return row


def current_sql_owner(db_path=None):
    """Tracking-only lexical owner; never a generation/connection authority."""
    owner = getattr(_CURRENT, "operation", None)
    if owner is None:
        return None
    if type(owner) is not SuccessorGuardianEpoch:
        _fail("original_operation_required")
    owner._original()
    if db_path is not None and Path(db_path).resolve() != owner.store.db_path.resolve():
        _fail("ledger_changed")
    return owner


class SuccessorGuardianEpoch:
    def __init__(self, operation, fresh_supervisor):
        from .daily_successor import DailySuccessorOperation
        from .supervisor_host import SupervisorHost, mint_guardian_epoch
        if type(operation) is not DailySuccessorOperation or type(fresh_supervisor) is not SupervisorHost:
            _fail("original_owner_required")
        operation.assert_supervisor(fresh_supervisor)
        startup = fresh_supervisor.startup
        if type(startup) is not SupervisorStartup:
            _fail("startup_required")
        startup.assert_held()
        if getattr(operation, "_guardian_epoch_operation", None) is not None:
            _fail("original_attempt_already_present")
        self.operation, self.supervisor, self.startup = operation, fresh_supervisor, startup
        self.store, self.policy = fresh_supervisor.store, fresh_supervisor.store._policy
        self.identity, self.binding = startup._current.identity, startup.binding
        self.attempt_id, self.new_epoch = str(uuid4()), mint_guardian_epoch()
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._policy_operation = RetainedPolicyOperation(self.store)
        self._policy_original = self._policy_operation
        self._pins = (operation, fresh_supervisor, startup, startup._current, startup._mutex,
            startup._scope, startup._lease, self.store, self.policy, self.binding,
            startup.instance_binding, self.attempt_id, self.new_epoch, self.identity)
        self._guard = self._snapshot = self._candidate = self._result = None
        self._guard_pin = self._snapshot_pin = self._candidate_pin = None
        self._connections, self._connection_pins = [], {}
        self._quarantine = self._error = None
        self._complete = False
        _ORIGINALS.add(self)
        operation._guardian_epoch_operation = self

    def _original(self):
        if (type(self) is not SuccessorGuardianEpoch or self not in _ORIGINALS or
                threading.current_thread() is not self._thread or os.getpid() != self._pid):
            _fail("original_operation_required")
        current = (self.operation, self.supervisor, self.startup, self.startup._current, self.startup._mutex,
            self.startup._scope, self.startup._lease, self.store, self.store._policy, self.startup.binding,
            self.startup.instance_binding, self.attempt_id, self.new_epoch, self.startup._current.identity)
        if (any(left is not right for left, right in zip(current[:11], self._pins[:11])) or
                current[11:] != self._pins[11:] or self.operation._guardian_epoch_operation is not self or
                self._policy_operation is not self._policy_original or self.policy is not self.store._policy or
                self.binding is not self.startup.binding or self.identity != self._pins[-1] or
                len(self._connections) != len(self._connection_pins) or
                any(self._connection_pins.get(id(item)) != (item, item.connection) for item in self._connections)):
            _fail("original_binding_changed")
        if (self._guard_pin is not None and (self._guard is not self._guard_pin[0] or
                self._guard.binding is not self._guard_pin[1] or self._guard.nonce != self._guard_pin[2]) or
                self._snapshot_pin is not None and self._snapshot is not self._snapshot_pin or
                self._candidate_pin is not None and self._candidate is not self._candidate_pin):
            _fail("original_evidence_changed")
        if self._quarantine is not None:
            _fail("custody_unsettled")

    def _authority(self):
        self._original()
        self.operation.assert_supervisor(self.supervisor)
        self.startup.assert_held()

    @contextmanager
    def _scope(self):
        self._authority()
        prior = getattr(_CURRENT, "operation", None)
        if prior is not None and prior is not self:
            _fail("foreign_scope")
        _CURRENT.operation = self
        try:
            yield
        finally:
            _CURRENT.operation = prior

    def begin_sql_acquisition(self):
        self._original()
        owner = _ConnectionCustody(None)
        self._connections.append(owner)
        self._connection_pins[id(owner)] = (owner, None)
        return owner

    def sql_acquired(self, owner, conn):
        if (self._connection_pins.get(id(owner)) != (owner, None) or owner.connection is not None or
                not isinstance(conn, sqlite3.Connection)):
            _fail("sql_acquisition_changed")
        owner.connection = conn
        self._connection_pins[id(owner)] = (owner, conn)

    def sql_acquisition_failed(self, owner, error):
        self._quarantine, self._error = "sql_acquisition_unknown", error
        error._daily_successor_epoch = self
        error.add_note("daily_successor_epoch_sql_acquisition_unknown")

    def connection_closed(self, conn):
        found = [owner for owner in self._connections if owner.connection is conn]
        if len(found) != 1 or found[0].closed or found[0].close_unknown:
            _fail("sql_close_unowned")
        found[0].closed = True

    def _settled_connections(self):
        if any(not owner.closed or owner.close_unknown or owner.connection is None for owner in self._connections):
            _fail("sql_custody_unsettled")

    def _readback(self, *, require_clear=False):
        self._authority()
        with self.store._connection() as conn:
            conn.execute("BEGIN")
            row = validate_successor_guardian_epoch(conn, guardian_epoch=self.new_epoch,
                logon_id=self.identity.logon_id, policy_instance_id=self.binding.instance_id)
            if row is None:
                return False
            if self._candidate is None or tuple(row[name] for name in _FIELDS) != self._candidate:
                _fail("replay_changed")
            if require_clear and self.policy._runtime(conn)["policy_entry_nonce"] is not None:
                _fail("nonce_unsettled")
        return True

    def _authorizer(self, conn, guard):
        def authorize(action, table, column, database, source):
            if (getattr(_CURRENT, "operation", None) is not self or
                    self.policy.current_guard() is not guard or self._quarantine is not None):
                return sqlite3.SQLITE_DENY
            if action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION,
                          sqlite3.SQLITE_TRANSACTION}:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and table in {
                    "table_info", "table_xinfo", "database_list", "index_list", "index_info", "foreign_key_list"}:
                return sqlite3.SQLITE_OK
            if database != "main":
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and column in {
                    "guardian_epoch", "active_logon_id", "registry_revision"}:
                return sqlite3.SQLITE_OK
            if action in {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_INSERT} and table == TABLE:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_CREATE_TRIGGER and table in _TRIGGERS and column == TABLE:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_CREATE_INDEX and column == TABLE and table.startswith("sqlite_autoindex_"):
                return sqlite3.SQLITE_OK
            if action in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE} and table == "sqlite_master":
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(authorize)

    def _write(self):
        self._authority()
        guard = self.policy.assert_held()
        if (guard is self.operation.guard or guard is self.operation.retirement._seal_guard or
                guard is self.operation.retirement._freeze_guard or guard.binding != self.binding):
            _fail("distinct_policy_required")
        if self._guard is None:
            self._guard = guard
            self._guard_pin = (guard, guard.binding, guard.nonce)
        elif self._guard is not guard:
            _fail("original_policy_changed")
        if self._readback():
            return True
        self._snapshot = self.operation.capture_startup_inventory(self.supervisor, guard)
        self._snapshot_pin = self._snapshot
        with self.store._transaction() as conn:
            self.operation.revalidate_startup_inventory(conn, self.supervisor, guard, self._snapshot)
            runtime = self.policy.revalidate(conn, guard)
            if runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE":
                _fail("runtime_unsettled")
            audits = read_successor_guardian_epochs(conn)
            if (self.new_epoch == runtime["guardian_epoch"] or _ordinary_route(conn, self.new_epoch) or
                    any(self.new_epoch in (entry.to_dict()["old_epoch"], entry.to_dict()["new_epoch"])
                        for entry in audits.entries) or conn.execute(
                        "SELECT 1 FROM managed_executions WHERE guardian_epoch=? LIMIT 1", (self.new_epoch,)).fetchone()):
                _fail("epoch_reused")
            value = dict(schema_version=1, attempt_id=self.attempt_id,
                transition_id=self.operation.transition_id, successor_generation=self.operation.owner.generation,
                succession_sha256=self.operation._archive.sha256, old_epoch=runtime["guardian_epoch"],
                new_epoch=self.new_epoch, supervisor_pid=self.identity.pid,
                supervisor_created_filetime_100ns=str(self.identity.created_filetime_100ns),
                supervisor_logon_id=self.identity.logon_id, supervisor_instance_id=self.startup.instance_binding.instance_id,
                policy_instance_id=self.binding.instance_id, policy_logon_id=self.binding.logon_id,
                previous_revision=runtime["registry_revision"], registry_revision=runtime["registry_revision"] + 1,
                inventory_digest=self._snapshot.digest)
            _validate(value)
            candidate = tuple(value[name] for name in _FIELDS)
            if self._candidate is None:
                self._candidate = candidate
                self._candidate_pin = candidate
            elif self._candidate != candidate:
                _fail("candidate_changed")
            budget = self._snapshot.budget
            if budget.remaining_history_rows < 1:
                _fail("history_budget_exceeded")
            existing = _schema(conn)
            self._authorizer(conn, guard)
            if not existing:
                conn.execute(_SCHEMA)
                for sql in _TRIGGERS.values():
                    conn.execute(sql)
            # Charge the complete newly serialized metadata, including actual
            # autoindexes and column declarations, inside this rollback scope.
            # No removed predecessor bytes are credited to the shared budget.
            extra = len(_encoded({TABLE: [value]}))
            if not existing:
                _schema(conn)
                extra += len(_encoded([tuple(row) for row in conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name=? OR tbl_name=? ORDER BY name",
                    (TABLE, TABLE))]))
                extra += len(_encoded([tuple(row) for row in conn.execute(f"PRAGMA table_xinfo({TABLE})")]))
            if extra > budget.remaining_bytes:
                _fail("history_budget_exceeded")
            conn.execute(f"INSERT INTO {TABLE} VALUES({','.join('?' for _ in _FIELDS)})", candidate)
            if conn.execute("""UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?,
                registry_revision=registry_revision+1 WHERE singleton=1 AND guardian_epoch=?
                AND active_logon_id=? AND registry_revision=? AND policy_instance_id=?
                AND policy_logon_id=? AND policy_entry_nonce=? AND mode='off' AND admission_barrier='NONE'""",
                (self.new_epoch, self.identity.logon_id, runtime["guardian_epoch"], runtime["active_logon_id"],
                 runtime["registry_revision"], self.binding.instance_id, self.binding.logon_id, guard.nonce)).rowcount != 1:
                _fail("revision_changed")
        return True

    def tick(self):
        """At most one retained POLICY attempt; never a guardian Create permit."""
        self._authority()
        if self._complete:
            return self._result
        try:
            with self._scope():
                result = self._policy_operation._run(self.identity.logon_id, self._write, self._readback)
                error = self._policy_operation._error
                if error is not None and _cleanup_outcome_unverified(error):
                    self._error, self._quarantine = error, "policy_cleanup_unknown"
                    return ReconcileResult(False, True, True, "daily_successor_epoch_custody_unsettled")
                if not result.complete:
                    return result
                self._settled_connections()
                if (self._guard is None or self._guard._native_exit_confirmed is not True or
                        self._guard._nonce_clear_attempted is not True or
                        self.policy.current_guard() is not None or self.policy.current_cleanup_guard() is not None or
                        not self._readback(require_clear=True)):
                    _fail("ack_unsettled")
                self._settled_connections()
                self._complete, self._result = True, result
                return result
        except BaseException as error:
            self._error = error
            if _cleanup_outcome_unverified(error):
                self._quarantine = "cleanup_unknown"
            raise

    def assert_retained_publication(self):
        """Original settled ownership only; never a new Create permission."""
        self._authority()
        if (not self._complete or self._policy_operation.pending or not self._policy_operation._complete or
                self._candidate is None or self._snapshot is None or self._guard is None or
                self._guard._native_exit_confirmed is not True or self._guard._nonce_clear_attempted is not True or
                self._result is None or not self._result.complete):
            _fail("publication_unsettled")
        self._settled_connections()

    def assert_complete(self):
        self.assert_retained_publication()
        with self._scope():
            if not self._readback(require_clear=True):
                _fail("audit_missing")
            self._settled_connections()
        return None
