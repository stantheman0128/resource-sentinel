"""Actual exemption writes and POLICY synchronization, without OS actuation.

The public functions are the legacy library's mutation facade. Bound mode is a
record-only fallback: no healthy-guardian mutation RPC or recovery worker is
invented here. A committed grant remains recorded/restore_pending until a real
owner verifies restoration. No environment switch or serialized receipt can
provide mutex ownership. All database paths are caller-owned configuration.

A sticky intent in sentinel.db binds the original exemption store ID before
coordination is armed. Loss/replacement of the grants DB cannot reopen legacy
mode. The stores commit separately; an interrupted bind remains non-controlling
and only an explicit bind retry against the original store may finish it.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
from pathlib import Path
import sqlite3
from types import MappingProxyType
from typing import Mapping
from uuid import UUID, uuid4

from .policy import PolicyBinding, PolicyBusy, PolicyCoordinator, PolicyError
from .store import LifecycleStore, _check_version
from .windows import NativePolicyMutexError


MAX_CONCURRENT_EXEMPTIONS = 3
_MAX_REVISION = (1 << 63) - 1
_MAX_ROWS = 4096
_FIELDS = ("id", "root_pid", "root_started", "created_at", "expires_at", "reason", "revoked_at", "owner_metadata")
_WRITER = "writer_protocol"
_REV = "writer_revision"


class ExemptionSyncError(ValueError):
    """Stable sanitized reason; never contains grant text or metadata."""
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class _GrantRejected(ExemptionSyncError):
    """An unchanged transaction's own expected business rejection only."""


@dataclass(frozen=True)
class ExemptionBinding:
    instance_id: str
    logon_id: str

    def __post_init__(self):
        try:
            PolicyBinding(self.instance_id, self.logon_id)
        except (PolicyError, TypeError, ValueError):
            raise ExemptionSyncError("exemption_policy_binding_invalid") from None


@dataclass(frozen=True)
class ExemptionSnapshot:
    binding: ExemptionBinding
    revision: int
    leases: tuple[Mapping, ...]


@dataclass(frozen=True)
class MutationNotice:
    operation: str
    exemption_id: str
    revision: int
    changed: bool


@dataclass(frozen=True)
class _BindingIntent:
    binding: ExemptionBinding
    store_id: str


def _store_id(value):
    try:
        parsed = UUID(value) if isinstance(value, str) else None
        if parsed is None or not parsed.int or str(parsed) != value:
            raise ValueError
    except (TypeError, ValueError, AttributeError):
        raise ExemptionSyncError("exemption_store_identity_invalid") from None
    return value


def _path(value):
    try:
        path = Path(getattr(value, "path", value)).resolve()
        if path.name != "exemptions.sqlite3":
            raise ValueError
        return path
    except (OSError, TypeError, ValueError, RuntimeError):
        raise ExemptionSyncError("exemption_path_invalid") from None


def _now(value):
    try:
        valid = (not isinstance(value, bool) and isinstance(value, (int, float)) and
                 math.isfinite(value) and value >= 0)
    except (OverflowError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ExemptionSyncError("exemption_time_invalid")
    return value


def _connect(path, *, create=False, readonly=False):
    """Open exactly the captured absolute path; never create a bound ledger."""
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
    mode = "ro" if readonly else "rwc" if create else "rw"
    conn = sqlite3.connect(path.as_uri() + "?mode=" + mode, uri=True, timeout=.25, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        if readonly:
            conn.execute("PRAGMA query_only=ON")
        return conn
    except BaseException:
        conn.close()
        raise


@contextmanager
def _transaction(path, *, create=False, write=True):
    conn = None
    try:
        try:
            conn = _connect(path, create=create, readonly=not write)
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield conn
            if write:
                conn.commit()
        except sqlite3.Error as error:
            reason = ("exemption_database_busy" if getattr(error, "sqlite_errorcode", None) in
                      {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else "exemption_database_unavailable")
            raise ExemptionSyncError(reason) from None
        except OSError:
            raise ExemptionSyncError("exemption_database_unavailable") from None
    except BaseException as primary:
        if conn is not None:
            try:
                conn.rollback()
            except BaseException:
                primary.add_note("exemption_rollback_failed")
            try:
                conn.close()
            except BaseException:
                primary.add_note("exemption_connection_cleanup_failed")
        raise
    else:
        try:
            conn.close()
        except BaseException:
            raise ExemptionSyncError("exemption_connection_cleanup_failed") from None


def _exists(conn, name):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None


def _meta(conn):
    if not _exists(conn, "exemption_sync"):
        # Additive migration is transactional. Existing protocol artifacts with
        # missing metadata therefore mean damaged state, never a fresh legacy
        # ledger that the public facade may silently reopen as unbound.
        columns = ({row[1] for row in conn.execute("PRAGMA table_info(exemptions)")}
                   if _exists(conn, "exemptions") else set())
        artifacts = conn.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND name GLOB 'adaptive_exemption_*' LIMIT 1").fetchone()
        if {_WRITER, _REV} & columns or artifacts is not None:
            raise ExemptionSyncError("exemption_sync_missing")
        return None
    rows = conn.execute("SELECT * FROM exemption_sync LIMIT 2").fetchall()
    if len(rows) != 1:
        raise ExemptionSyncError("exemption_sync_invalid")
    row = dict(rows[0])
    if (row.get("singleton") != 1 or type(row.get("singleton")) is not int or
            row.get("schema_version") != 1 or type(row.get("schema_version")) is not int or
            type(row.get("revision")) is not int or not 0 <= row["revision"] <= _MAX_REVISION or
            type(row.get("coordination_required")) is not int or row["coordination_required"] not in {0, 1}):
        raise ExemptionSyncError("exemption_sync_invalid")
    _store_id(row.get("store_id"))
    if row["coordination_required"]:
        ExemptionBinding(row.get("policy_instance_id"), row.get("policy_logon_id"))
    elif row.get("policy_instance_id") is not None or row.get("policy_logon_id") is not None:
        raise ExemptionSyncError("exemption_sync_invalid")
    return row


def _binding(row):
    if row is None or not row["coordination_required"]:
        raise ExemptionSyncError("exemption_sync_unbound")
    return ExemptionBinding(row["policy_instance_id"], row["policy_logon_id"])


def _trigger_sql():
    # Protocol/revision marks audited cooperative writers, not hostile same-SID
    # code. Persistent triggers also apply to connections opened before bind.
    bound = "(SELECT coordination_required FROM exemption_sync WHERE singleton=1) IS 1"
    new_insert = "(typeof(NEW.writer_protocol)='integer' AND NEW.writer_protocol IS 1 AND typeof(NEW.writer_revision)='integer' AND NEW.writer_revision IS 0)"
    new_update = ("(typeof(NEW.writer_protocol)='integer' AND NEW.writer_protocol IS 1 "
                  "AND typeof(OLD.writer_revision)='integer' AND OLD.writer_revision>=0 "
                  f"AND OLD.writer_revision<{_MAX_REVISION} AND typeof(NEW.writer_revision)='integer' "
                  "AND NEW.writer_revision IS OLD.writer_revision+1)")
    specs = {
        "adaptive_exemption_insert": ("BEFORE INSERT", f"{bound} AND NOT {new_insert}",
                                      "SELECT RAISE(ABORT,'exemption_writer_protocol_required');"),
        "adaptive_exemption_update": ("BEFORE UPDATE", f"{bound} AND NOT {new_update}",
                                      "SELECT RAISE(ABORT,'exemption_writer_protocol_required');"),
        "adaptive_exemption_delete": ("BEFORE DELETE", bound,
                                      "SELECT RAISE(ABORT,'exemption_delete_forbidden');"),
        # REPLACE's implicit deletion may bypass DELETE triggers. Fence the
        # conflicting INSERT itself, including explicit rowid collisions.
        "adaptive_exemption_replace": ("BEFORE INSERT", f"{bound} AND EXISTS(SELECT 1 FROM exemptions e WHERE e.id=NEW.id OR e.rowid=NEW.rowid)",
                                       "SELECT RAISE(ABORT,'exemption_replace_forbidden');"),
    }
    changed = " OR ".join("OLD." + name + " IS NOT NEW." + name for name in _FIELDS)
    for operation, condition in (("insert", "1"), ("update", "(" + changed + ")"), ("delete", "1")):
        specs["adaptive_exemption_revision_" + operation] = (
            "AFTER " + operation.upper(), condition,
            "UPDATE exemption_sync SET revision=revision+1 WHERE singleton=1;")
    sql = {name: f"CREATE TRIGGER {name} {event} ON exemptions WHEN {condition} BEGIN {body} END"
           for name, (event, condition, body) in specs.items()}
    # Once bound, ordinary SQL cannot revert to the uncoordinated facade or
    # silently give the same store a different mutex identity. This is not a
    # defense against code authorized to drop the schema itself.
    sql.update({
        "adaptive_exemption_binding_update": "CREATE TRIGGER adaptive_exemption_binding_update BEFORE UPDATE ON exemption_sync "
        "WHEN OLD.coordination_required IS 1 AND (NEW.coordination_required IS NOT 1 OR "
        "NEW.singleton IS NOT OLD.singleton OR NEW.schema_version IS NOT OLD.schema_version OR "
        "NEW.policy_instance_id IS NOT OLD.policy_instance_id OR NEW.policy_logon_id IS NOT OLD.policy_logon_id OR "
        "NEW.store_id IS NOT OLD.store_id) "
        "BEGIN SELECT RAISE(ABORT,'exemption_binding_immutable'); END",
        "adaptive_exemption_binding_delete": "CREATE TRIGGER adaptive_exemption_binding_delete BEFORE DELETE ON exemption_sync "
        "WHEN OLD.coordination_required IS 1 BEGIN SELECT RAISE(ABORT,'exemption_binding_immutable'); END",
        "adaptive_exemption_binding_replace": "CREATE TRIGGER adaptive_exemption_binding_replace BEFORE INSERT ON exemption_sync "
        "WHEN EXISTS(SELECT 1 FROM exemption_sync WHERE coordination_required IS 1) "
        "BEGIN SELECT RAISE(ABORT,'exemption_binding_immutable'); END",
    })
    return sql


def _install_fences(conn):
    for name, sql in _trigger_sql().items():
        conn.execute("DROP TRIGGER IF EXISTS " + name)
        conn.execute(sql)


def _require_fences(conn):
    for name, sql in _trigger_sql().items():
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if row is None or row[0] != sql:
            raise ExemptionSyncError("exemption_writer_fence_unavailable")


def _bootstrap(conn, candidate_store_id):
    """Only while unbound, under this exemption DB's existing writer lock."""
    meta = _meta(conn)
    if meta is not None and meta["coordination_required"]:
        _require_fences(conn)
        return meta
    if meta is not None and not _exists(conn, "exemptions"):
        raise ExemptionSyncError("exemption_schema_invalid")
    conn.execute("""CREATE TABLE IF NOT EXISTS exemptions (
        id TEXT PRIMARY KEY, root_pid INTEGER NOT NULL, root_started REAL NOT NULL,
        created_at REAL NOT NULL, expires_at REAL NOT NULL, reason TEXT NOT NULL, revoked_at REAL)""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(exemptions)")}
    if not set(_FIELDS[:-1]) <= columns:
        raise ExemptionSyncError("exemption_schema_invalid")
    additions = {"owner_metadata": "TEXT NOT NULL DEFAULT '{}'",
                 _WRITER: "INTEGER NOT NULL DEFAULT 0 CHECK(typeof(writer_protocol)='integer' AND writer_protocol>=0)",
                 _REV: f"INTEGER NOT NULL DEFAULT 0 CHECK(typeof(writer_revision)='integer' AND writer_revision BETWEEN 0 AND {_MAX_REVISION})"}
    for name, declaration in additions.items():
        if name not in columns:
            conn.execute(f"ALTER TABLE exemptions ADD COLUMN {name} {declaration}")
    conn.execute(f"""CREATE TABLE IF NOT EXISTS exemption_sync (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL,
        revision INTEGER NOT NULL CHECK(typeof(revision)='integer' AND revision BETWEEN 0 AND {_MAX_REVISION}),
        coordination_required INTEGER NOT NULL CHECK(coordination_required IN (0,1)),
        policy_instance_id TEXT, policy_logon_id TEXT, store_id TEXT NOT NULL)""")
    if meta is None:
        conn.execute("INSERT INTO exemption_sync VALUES(1,1,0,0,NULL,NULL,?)", (_store_id(candidate_store_id),))
    _install_fences(conn)
    return _meta(conn)


def _record(record):
    required = set(_FIELDS[:-1])
    if type(record) is not dict or not required <= record.keys() or set(record) - set(_FIELDS):
        raise ExemptionSyncError("exemption_record_invalid")
    row = dict(record)
    if (not isinstance(row["id"], str) or not 1 <= len(row["id"]) <= 128 or
            any(ord(c) < 32 for c in row["id"]) or type(row["root_pid"]) is not int or
            not 0 < row["root_pid"] < (1 << 32) or row["revoked_at"] is not None or
            not isinstance(row["reason"], str) or not row["reason"].strip() or len(row["reason"]) > 500):
        raise ExemptionSyncError("exemption_record_invalid")
    for name in ("root_started", "created_at", "expires_at"):
        _now(row[name])
    if row["root_started"] <= 0 or not 60 <= row["expires_at"] - row["created_at"] <= 86400:
        raise ExemptionSyncError("exemption_record_invalid")
    metadata = row.setdefault("owner_metadata", "{}")
    try:
        if not isinstance(metadata, str) or len(metadata.encode("utf-8")) > 65536 or not isinstance(json.loads(metadata), dict):
            raise ValueError
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ExemptionSyncError("exemption_metadata_invalid") from None
    return row


def _active(conn, now):
    # Include malformed expiry/revocation even when SQL comparisons would hide
    # it. A corrupt authority must not turn an unknown grant into eligibility.
    rows = conn.execute("""SELECT * FROM exemptions WHERE
        (revoked_at IS NOT NULL AND (typeof(revoked_at) NOT IN ('integer','real') OR
            revoked_at<0 OR revoked_at>1.7976931348623157e308)) OR
        (revoked_at IS NULL AND (typeof(expires_at) NOT IN ('integer','real') OR expires_at<0 OR
            expires_at>1.7976931348623157e308 OR expires_at>?))
        ORDER BY created_at,id LIMIT ?""", (now, _MAX_ROWS + 1)).fetchall()
    if len(rows) > _MAX_ROWS:
        raise ExemptionSyncError("exemption_snapshot_too_large")
    for row in rows:
        try:
            _record({name: row[name] for name in _FIELDS})
            if (type(row[_WRITER]) is not int or row[_WRITER] < 0 or
                    type(row[_REV]) is not int or not 0 <= row[_REV] <= _MAX_REVISION):
                raise ValueError
        except (KeyError, IndexError, TypeError, ValueError, OverflowError):
            raise ExemptionSyncError("exemption_snapshot_invalid") from None
    return rows


def _grant(conn, row, now):
    live = _active(conn, now)
    for existing in live:
        if existing["root_pid"] == row["root_pid"] and abs(existing["root_started"] - row["root_started"]) < .01:
            return dict(existing), False
    if len(live) >= MAX_CONCURRENT_EXEMPTIONS:
        raise _GrantRejected("exemption_limit_reached")
    if row["expires_at"] <= now:
        raise _GrantRejected("exemption_record_expired")
    columns = ",".join(_FIELDS)
    conn.execute(f"INSERT INTO exemptions({columns},writer_protocol,writer_revision) VALUES({','.join('?' for _ in _FIELDS)},1,0)",
                 tuple(row[name] for name in _FIELDS))
    return dict(conn.execute("SELECT * FROM exemptions WHERE id=?", (row["id"],)).fetchone()), True


def _revoke(conn, exemption_id, now):
    return conn.execute("""UPDATE exemptions SET revoked_at=?,writer_protocol=1,writer_revision=writer_revision+1
        WHERE id=? AND revoked_at IS NULL""", (now, exemption_id)).rowcount


def _grant_result(row, revision, *, bound, changed):
    result = {name: row[name] for name in _FIELDS}
    result.update(exemption_revision=revision, grant_state="recorded" if bound else "active",
                  enforcement_state="restore_pending" if bound else "not_applicable",
                  recovery_request_state="not_requested", changed=changed)
    return result


def _sentinel_path(path):
    return path.parent / "sentinel.db"


def _runtime_binding(conn):
    if not _check_version(conn):
        raise ExemptionSyncError("exemption_policy_unavailable")
    row = PolicyCoordinator._runtime(conn)
    if row.get("policy_binding_initialized") != 1:
        raise ExemptionSyncError("exemption_policy_binding_invalid")
    binding = ExemptionBinding(row.get("policy_instance_id"), row.get("policy_logon_id"))
    if row.get("active_logon_id") not in {"", binding.logon_id}:
        raise ExemptionSyncError("exemption_policy_binding_invalid")
    return binding


def _intent_fences():
    return {
        "adaptive_exemption_intent_update": "CREATE TRIGGER adaptive_exemption_intent_update BEFORE UPDATE ON adaptive_exemption_binding "
        "BEGIN SELECT RAISE(ABORT,'exemption_binding_intent_immutable'); END",
        "adaptive_exemption_intent_delete": "CREATE TRIGGER adaptive_exemption_intent_delete BEFORE DELETE ON adaptive_exemption_binding "
        "BEGIN SELECT RAISE(ABORT,'exemption_binding_intent_immutable'); END",
        "adaptive_exemption_intent_replace": "CREATE TRIGGER adaptive_exemption_intent_replace BEFORE INSERT ON adaptive_exemption_binding "
        "WHEN EXISTS(SELECT 1 FROM adaptive_exemption_binding) "
        "BEGIN SELECT RAISE(ABORT,'exemption_binding_intent_immutable'); END",
    }


def _intent(conn):
    if not _exists(conn, "adaptive_exemption_binding"):
        return None
    rows = conn.execute("SELECT * FROM adaptive_exemption_binding LIMIT 2").fetchall()
    if len(rows) != 1:
        raise ExemptionSyncError("exemption_binding_intent_invalid")
    row = dict(rows[0])
    if type(row.get("singleton")) is not int or row["singleton"] != 1 or type(row.get("schema_version")) is not int or row["schema_version"] != 1:
        raise ExemptionSyncError("exemption_binding_intent_invalid")
    intent = _BindingIntent(ExemptionBinding(row.get("policy_instance_id"), row.get("policy_logon_id")),
                            _store_id(row.get("store_id")))
    if _runtime_binding(conn) != intent.binding:
        raise ExemptionSyncError("exemption_policy_binding_mismatch")
    for name, sql in _intent_fences().items():
        present = conn.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
        if present is None or present[0] != sql:
            raise ExemptionSyncError("exemption_binding_intent_invalid")
    return intent


def _read_intent(path):
    """Preflight the surviving ledger, without creating or migrating it."""
    sentinel_path = _sentinel_path(path)
    if not sentinel_path.exists():
        return None
    with _transaction(sentinel_path, write=False) as conn:
        return _intent(conn)


def _persist_intent(lifecycle_store, binding, store_id):
    guard = lifecycle_store._policy.assert_held()
    intended = _BindingIntent(binding, store_id)
    with lifecycle_store._transaction() as conn:
        lifecycle_store._policy.revalidate(conn, guard)
        if _runtime_binding(conn) != binding:
            raise ExemptionSyncError("exemption_policy_binding_mismatch")
        current = _intent(conn)
        if current is not None:
            if current != intended:
                raise ExemptionSyncError("exemption_store_identity_mismatch")
            return current
        conn.execute("""CREATE TABLE adaptive_exemption_binding (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL CHECK(schema_version=1),
            policy_instance_id TEXT NOT NULL, policy_logon_id TEXT NOT NULL, store_id TEXT NOT NULL)""")
        conn.execute("INSERT INTO adaptive_exemption_binding VALUES(1,1,?,?,?)",
                     (binding.instance_id, binding.logon_id, _store_id(store_id)))
        for sql in _intent_fences().values():
            conn.execute(sql)
        return _intent(conn)


class ExistingPolicyStore:
    """Minimal existing-ledger adapter for the real PolicyCoordinator.

    Construction and connections never migrate/create sentinel.db. The pinned
    binding is revalidated inside every policy writer transaction. Explicit
    synthetic providers are an in-process test seam, never CLI/environment data.
    """
    def __init__(self, db_path, *, expected_binding=None, policy_provider=None):
        try:
            self.db_path = Path(db_path).resolve()
        except (OSError, TypeError, ValueError, RuntimeError):
            raise ExemptionSyncError("exemption_policy_unavailable") from None
        with self._connection() as conn:
            actual = _runtime_binding(conn)
        if expected_binding is not None and actual != expected_binding:
            raise ExemptionSyncError("exemption_policy_binding_mismatch")
        self._expected_binding = actual
        self._policy = PolicyCoordinator(self, policy_provider)

    @contextmanager
    def _connection(self):
        conn = None
        try:
            conn = _connect(self.db_path)
            yield conn
        except BaseException as primary:
            if conn is not None:
                try:
                    conn.close()
                except BaseException:
                    primary.add_note("exemption_policy_cleanup_failed")
            if isinstance(primary, (sqlite3.Error, OSError)):
                raise ExemptionSyncError("exemption_policy_unavailable") from None
            raise
        else:
            try:
                conn.close()
            except BaseException:
                raise ExemptionSyncError("exemption_policy_cleanup_failed") from None

    @contextmanager
    def _transaction(self):
        with self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if _runtime_binding(conn) != self._expected_binding:
                    raise ExemptionSyncError("exemption_policy_binding_mismatch")
                yield conn
                conn.commit()
            except BaseException as primary:
                try:
                    conn.rollback()
                except BaseException:
                    primary.add_note("exemption_policy_rollback_failed")
                raise


def _locked_path(exemptions, lifecycle_store, *, require_intent=True):
    path = _path(exemptions)
    if not isinstance(lifecycle_store, (LifecycleStore, ExistingPolicyStore)):
        raise ExemptionSyncError("exemption_policy_store_required")
    if Path(lifecycle_store.db_path).resolve() != _sentinel_path(path):
        raise ExemptionSyncError("exemption_policy_ledger_mismatch")
    guard = lifecycle_store._policy.assert_held()
    # Close this short sentinel read before opening an exemption transaction.
    with lifecycle_store._connection() as conn:
        conn.execute("BEGIN")
        runtime = _runtime_binding(conn)
        lifecycle_store._policy.revalidate(conn, guard)
        if runtime != ExemptionBinding(guard.binding.instance_id, guard.binding.logon_id):
            raise ExemptionSyncError("exemption_policy_binding_mismatch")
        intent = _intent(conn)
        if require_intent and intent is None:
            raise ExemptionSyncError("exemption_binding_intent_missing")
    return path, runtime, intent


def _bound_meta(conn, binding, intent):
    meta = _meta(conn)
    if _binding(meta) != binding:
        raise ExemptionSyncError("exemption_policy_binding_mismatch")
    if intent is None or intent.binding != binding or meta["store_id"] != intent.store_id:
        raise ExemptionSyncError("exemption_store_identity_mismatch")
    _require_fences(conn)
    return meta


def _commit_binding(conn, binding, store_id):
    meta = _meta(conn)
    if meta is None or meta["store_id"] != store_id:
        raise ExemptionSyncError("exemption_store_identity_mismatch")
    _require_fences(conn)
    if not meta["coordination_required"]:
        conn.execute("""UPDATE exemption_sync SET coordination_required=1,
            policy_instance_id=?,policy_logon_id=? WHERE singleton=1 AND coordination_required=0 AND store_id=?""",
                     (binding.instance_id, binding.logon_id, store_id))
    _bound_meta(conn, binding, _BindingIntent(binding, store_id))


def bind_policy_locked(exemptions, lifecycle_store):
    """Arm actual persistent fences while already owning this host's POLICY.

    Import/construction/feature-off never does this automatically. A pre-bind
    legacy-compatible transaction finishes before this writer lock, or sees the
    bound marker and exits before acquiring native POLICY. Prepare a store ID,
    persist its sticky intent in sentinel.db, then arm that same exemption DB;
    each transaction closes before the next begins. The intentional crash gap
    denies public mutations/control, while explicit retry can finish binding
    the original store. Missing or replaced grants are never reconstructed.
    """
    candidate_store_id = str(uuid4())
    path, binding, intent = _locked_path(exemptions, lifecycle_store, require_intent=False)
    with _transaction(path, create=intent is None) as conn:
        if intent is None:
            meta = _bootstrap(conn, candidate_store_id)
        else:
            meta = _meta(conn)
            if meta is None or meta["store_id"] != intent.store_id:
                raise ExemptionSyncError("exemption_store_identity_mismatch")
            _require_fences(conn)
        store_id = meta["store_id"]
    _persist_intent(lifecycle_store, binding, store_id)
    with _transaction(path) as conn:
        _commit_binding(conn, binding, store_id)
    return binding


def commit_grant_locked(exemptions, record, *, lifecycle_store, now):
    row, now = _record(record), _now(now)
    path, binding, intent = _locked_path(exemptions, lifecycle_store)
    with _transaction(path) as conn:
        _bound_meta(conn, binding, intent)
        grant, changed = _grant(conn, row, now)
        result = _grant_result(grant, _meta(conn)["revision"], bound=True, changed=changed)
    return result


def commit_revoke_locked(exemptions, exemption_id, *, lifecycle_store, now):
    if not isinstance(exemption_id, str) or not 1 <= len(exemption_id) <= 128:
        raise ExemptionSyncError("exemption_id_invalid")
    now = _now(now)
    path, binding, intent = _locked_path(exemptions, lifecycle_store)
    with _transaction(path) as conn:
        _bound_meta(conn, binding, intent)
        count = _revoke(conn, exemption_id, now)
        result = {"revoked": count, "exemption_revision": _meta(conn)["revision"]}
    return result


def snapshot_locked(exemptions, *, lifecycle_store, now):
    now = _now(now)
    path, binding, intent = _locked_path(exemptions, lifecycle_store)
    with _transaction(path, write=False) as conn:
        meta = _bound_meta(conn, binding, intent)
        leases = tuple(MappingProxyType(dict(row)) for row in _active(conn, now))
        return ExemptionSnapshot(binding, meta["revision"], leases)


def _public_store(path, binding, policy_factory):
    sentinel_path = _sentinel_path(path)
    store = (ExistingPolicyStore(sentinel_path, expected_binding=binding) if policy_factory is None
             else policy_factory(sentinel_path))
    if not isinstance(store, (LifecycleStore, ExistingPolicyStore)):
        raise ExemptionSyncError("exemption_policy_store_required")
    if Path(store.db_path).resolve() != sentinel_path:
        raise ExemptionSyncError("exemption_policy_ledger_mismatch")
    if store._policy.current_guard() is not None:
        raise ExemptionSyncError("exemption_facade_requires_unlocked_policy")
    with store._connection() as conn:
        conn.execute("BEGIN")
        if _runtime_binding(conn) != binding:
            raise ExemptionSyncError("exemption_policy_binding_mismatch")
    return store


def _request_recovery(after_unlock, notice):
    if after_unlock is None:
        return "not_requested"
    try:
        after_unlock(notice)
    except Exception:
        return "failed"
    return "requested"


def _facade_binding(conn, intent):
    meta = _meta(conn)
    if intent is not None:
        _bound_meta(conn, intent.binding, intent)
        return intent.binding
    if meta is not None and meta["coordination_required"]:
        raise ExemptionSyncError("exemption_binding_intent_missing")
    return None


def grant_record(exemptions, record, *, now, policy_factory=None, after_unlock=None):
    """Legacy-consumed facade; bound mode only records a restore-pending grant.

    ``after_unlock`` receives MutationNotice after confirmed native release and
    nonce cleanup. A callback is a recovery request, never an OS restore ACK.
    It is optional and no recovery dispatch is claimed when absent or failed.
    """
    path, row, now = _path(exemptions), _record(record), _now(now)
    candidate_store_id = str(uuid4())
    intent = _read_intent(path)
    with _transaction(path, create=intent is None) as conn:
        binding = _facade_binding(conn, intent)
        if binding is None:
            _bootstrap(conn, candidate_store_id)
            grant, changed = _grant(conn, row, now)
            result = _grant_result(grant, _meta(conn)["revision"], bound=False, changed=changed)
    if binding is None:
        return result
    # No exemption transaction remains while acquiring identity/native POLICY.
    try:
        store = _public_store(path, binding, policy_factory)
        logon = store._policy.current_logon()
        if logon != binding.logon_id:
            raise ExemptionSyncError("exemption_policy_logon_mismatch")
        guard = store._policy.prepare(logon)
        rejection = None
        with store._policy.hold(guard):
            try:
                result = commit_grant_locked(path, row, lifecycle_store=store, now=now)
            except _GrantRejected as error:
                # The private exception originates only before any grant DML.
                # Reaching here confirms its transaction rolled back/closed;
                # cleanup notes keep an uncertain operation failure-closed.
                if getattr(error, "__notes__", ()):
                    raise
                rejection = error
        if rejection is not None:
            raise rejection
    except PolicyBusy:
        raise ExemptionSyncError("exemption_policy_busy") from None
    except (PolicyError, NativePolicyMutexError):
        raise ExemptionSyncError("exemption_policy_unavailable") from None
    notice = MutationNotice("grant", result["id"], result["exemption_revision"], result["changed"])
    result["recovery_request_state"] = _request_recovery(after_unlock, notice)
    return result


def revoke_record(exemptions, exemption_id, *, now, policy_factory=None, after_unlock=None):
    """Return the legacy changed-row count; revocation never reapplies a cap."""
    if not isinstance(exemption_id, str) or not 1 <= len(exemption_id) <= 128:
        raise ExemptionSyncError("exemption_id_invalid")
    path, now = _path(exemptions), _now(now)
    candidate_store_id = str(uuid4())
    intent = _read_intent(path)
    if intent is None and not path.exists():
        return 0
    with _transaction(path) as conn:
        binding = _facade_binding(conn, intent)
        if binding is None:
            _bootstrap(conn, candidate_store_id)
            count = _revoke(conn, exemption_id, now)
    if binding is None:
        return count
    try:
        store = _public_store(path, binding, policy_factory)
        logon = store._policy.current_logon()
        if logon != binding.logon_id:
            raise ExemptionSyncError("exemption_policy_logon_mismatch")
        guard = store._policy.prepare(logon)
        with store._policy.hold(guard):
            result = commit_revoke_locked(path, exemption_id, lifecycle_store=store, now=now)
    except PolicyBusy:
        raise ExemptionSyncError("exemption_policy_busy") from None
    except (PolicyError, NativePolicyMutexError):
        raise ExemptionSyncError("exemption_policy_unavailable") from None
    notice = MutationNotice("revoke", exemption_id, result["exemption_revision"], bool(result["revoked"]))
    if _request_recovery(after_unlock, notice) == "failed":
        error = ExemptionSyncError("exemption_recovery_request_failed")
        error.committed_count = result["revoked"]
        raise error
    return result["revoked"]
