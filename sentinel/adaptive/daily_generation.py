"""Unactivated daily source/cohort handoff primitives.

Nothing imports Coordinator, creates a ledger, deploys files, or installs a task.
Only an original in-process owner may install the generation under an existing
POLICY scope after positive old-cohort retirement. A manifest is data, never
native admission authority. Production consumers must call prepare_connection
before their transaction; an absent generation preserves existing behavior.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextlib import contextmanager, ExitStack
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import struct
import sys
import threading
import types
import uuid

from .contracts import IdentityStatus, ProcessIdentity
from .identity import VerifiedProcess


MAX_SOURCE_FILES = 1024
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024
ROLES = frozenset({"coordinator", "maintainer", "lifecycle", "legacy_writer"})
CAPACITY_TABLES = ("reservations", "worker_reservations", "workers", "queue")
REQUIRED_PATHS = frozenset({
    "sentinel_daily_bootstrap.py", "sentinel/__init__.py",
    "sentinel/coordinator.py", "sentinel/maintainer.py", "sentinel/accounting.py",
    "sentinel/orchestrator.py", "sentinel/adaptive/store.py",
    "sentinel/adaptive/writers.py", "sentinel/adaptive/legacy_writer.py",
    "sentinel/adaptive/daily_generation.py", "scripts/sentinelctl.py",
    "sentinel/adaptive/daily_readiness_transport.py", "sentinel/adaptive/policy.py",
    "sentinel/adaptive/windows.py",
    "scripts/maintainerctl.py", "scripts/invoke-sentinel.ps1",
    "scripts/collect.ps1", "scripts/collect-scheduled.ps1",
    "scripts/legacy-mutation.py", "hooks/sentinel-gate.py",
    "hooks/sentinel-stop.py", "docs/agent-policy.md",
})
_TABLE = "adaptive_daily_generation"
_GENERATION_FIELDS = frozenset({"singleton", "schema_version", "generation", "state",
    "source_digest", "config_digest", "source_manifest_json", "source_root", "ledger_path",
    "owner_identity_json", "ledger_identity_json", "readiness_instance_id"})
_TOKEN = object()
_LOCAL_GENERATIONS = {}
_READINESS_LOCAL = threading.local()
_READINESS_SCOPES = {}
_ABSENCE_SCOPES = {}
_READINESS_SCOPES_LOCK = threading.Lock()
MAX_READINESS_SCOPES = 8
MAX_ABSENCE_SCOPES = 8


def _readiness_cleanup_unknown(error):
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        notes = tuple(getattr(current, "__notes__", ()))
        if notes:
            from .policy import _cleanup_outcome_unverified
            # A retained clear ACK failure with positively completed SQL close
            # is not an outstanding readiness resource. Never infer this from
            # the note alone, or hide any nested original cleanup obligation.
            benign_clear_ack = (all(note == "policy_entry_cleanup_failed" for note in notes) and
                isinstance(getattr(current, "_policy_entry_cleanup_error", None), BaseException) and
                not _cleanup_outcome_unverified(current))
            if not benign_clear_ack:
                return True
        if (len(seen) > 32 or
                getattr(current, "_daily_readiness_cleanup_pending", False) or
                getattr(current, "_sentinel_connection_cleanup", None) is not None or
                getattr(current, "_identity_handle_cleanup", ()) or
                getattr(current, "_policy_mutex_cleanup", ()) or
                getattr(current, "experiment_scope_sql_owner", None) is not None or
                getattr(current, "experiment_connection_owner", None) is not None or
                getattr(current, "_native_duplicate_outcome_unknown", False) or
                getattr(current, "_native_close_outcome_unknown", False) or
                getattr(current, "io_pending", False)):
            return True
        pending.extend((getattr(current, "_daily_readiness_cause", None),
                        getattr(current, "__cause__", None), getattr(current, "__context__", None),
                        getattr(current, "_policy_entry_cleanup_error", None)))
    return False


class _ReadinessScope:
    """Lexical custody, retained permanently when nested cleanup is unknown."""
    def __init__(self, path, *, absence_only=False):
        self.path = path
        self.absence_only = absence_only
        self.pool = _ABSENCE_SCOPES if absence_only else _READINESS_SCOPES
        self.thread = threading.current_thread()
        self.row = self.authority = self.reader = self.error = None
        self.local_owner = None
        self.ledger_identity = None
        self.closed = False
        self.cleanup = None

    def poison(self, error):
        if self.error is None:
            self.error = error
        error.daily_readiness_scope = self
        originals = getattr(error, "_daily_readiness_scopes", ())
        if not any(value is self for value in originals):
            error._daily_readiness_scopes = (*originals, self)
        with _READINESS_SCOPES_LOCK:
            self.pool[id(self)] = self

    def assert_current(self):
        if (self.closed or self.error is not None or self.thread is not threading.current_thread()
                or getattr(_READINESS_LOCAL, "scope", None) is not self):
            _reject("daily_readiness_scope_unavailable")

    def read(self):
        # No generation is created by observing a not-yet-existing ledger.
        if not self.path.exists():
            return
        self.ledger_identity = _ledger_identity(self.path)
        self.reader = _ReadinessReader()
        self.reader.open_attempted = True
        primary = None
        try:
            self.reader.connection = sqlite3.connect(self.path.as_uri() + "?mode=ro",
                uri=True, timeout=.25, isolation_level=None)
            self.reader.connection.execute("PRAGMA query_only=ON")
            self.row = read_generation(self.reader.connection)
            if (not _ledger_matches(self.reader.connection, self.path) or
                    _ledger_identity(self.path) != self.ledger_identity):
                _reject("daily_ledger_identity_changed")
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                self.reader.close()
            except BaseException as cleanup:
                target = primary or cleanup
                self.poison(target)
                target.add_note("daily_readiness_scope_reader_cleanup_unknown")
                if primary is None:
                    raise

    def close(self):
        if self.error is not None:
            failure = DailyGenerationUnavailable("daily_readiness_scope_cleanup_pending")
            failure.daily_readiness_scope = self
            raise failure from self.error
        if self.closed:
            return
        if self.authority is not None:
            try:
                self.authority.close()
            except BaseException as error:
                self.poison(error)
                error.add_note("daily_readiness_scope_cleanup_unknown")
                raise
        self.closed = True


@contextmanager
def readiness_scope(db_path):
    """Acquire before any lock; nested exact-ledger users borrow, never refresh."""
    from .experiment_cleanup import current_operation
    operation = current_operation(db_path)
    if operation is not None:
        with operation.connection_scope(db_path) as original:
            yield original
        return
    path = Path(db_path).resolve()
    borrowed = getattr(_READINESS_LOCAL, "scope", None)
    group = getattr(_READINESS_LOCAL, "group", None)
    if group is not None:
        selected = group.get(path)
        if selected is None:
            _reject("daily_readiness_scope_ledger_changed")
        previous = borrowed
        _READINESS_LOCAL.scope = selected
        try:
            selected.assert_current()
            try:
                yield selected
            except BaseException as error:
                if _readiness_cleanup_unknown(error):
                    selected.poison(error)
                raise
        finally:
            _READINESS_LOCAL.scope = previous
        return
    if borrowed is not None:
        borrowed.assert_current()
        if borrowed.path != path:
            _reject("daily_readiness_scope_ledger_changed")
        try:
            yield borrowed
        except BaseException as error:
            if borrowed.row is not None and _readiness_cleanup_unknown(error):
                borrowed.poison(error)
            raise
        return
    with _owned_readiness_scope(path, absence_only=False) as original:
        yield original


@contextmanager
def _owned_readiness_scope(path, *, absence_only):
    if (getattr(_READINESS_LOCAL, "scope", None) is not None or
            getattr(_READINESS_LOCAL, "group", None) is not None):
        _reject("daily_readiness_group_invalid")
    from .windows import current_thread_holds_mutex
    if current_thread_holds_mutex():
        _reject("daily_readiness_lock_held")
    scope = _ReadinessScope(path, absence_only=absence_only)
    pool = scope.pool
    limit = MAX_ABSENCE_SCOPES if absence_only else MAX_READINESS_SCOPES
    with _READINESS_SCOPES_LOCK:
        if any(value.path == path and value.error is not None
               for registry in (_READINESS_SCOPES, _ABSENCE_SCOPES) for value in registry.values()):
            _reject("daily_readiness_scope_cleanup_pending")
        if len(pool) >= limit:
            _reject("daily_readiness_scopes_pending")
        pool[id(scope)] = scope
    _READINESS_LOCAL.scope = scope
    primary = None
    try:
        scope.read()
        if scope.row is not None:
            if absence_only:
                _reject("daily_readiness_absence_required")
            _assert_daily_locations(scope.row["source_root"], path)
            if (scope.row["ledger_path"] != str(path) or
                    scope.ledger_identity != tuple(int(v) for v in json.loads(scope.row["ledger_identity_json"]))):
                _reject("daily_ledger_mismatch")
            if _fixed_policy_digest(path) != scope.row["config_digest"]:
                _reject("daily_config_changed")
            local = _LOCAL_GENERATIONS.get(scope.row["generation"])
            # Original install/retirement cleanup has its own nonce-only gate.
            cleanup = local is not None and (not local._activated or scope.row["state"] == "DRAINING")
            if not cleanup:
                scope.authority = _prove_retained_owner_ready(scope.row, local_owner=local)
                # Pin the exact object used by the pre-lock proof, including
                # the remote None branch. Never adopt a later registry lookup.
                scope.local_owner = local
        elif not absence_only:
            # A known absent generation retains no native readiness resource.
            # Do not impose the daily native-custody limit on legacy callers.
            with _READINESS_SCOPES_LOCK:
                pool.pop(id(scope), None)
        yield scope
    except BaseException as error:
        primary = error
        if (absence_only or scope.row is not None) and _readiness_cleanup_unknown(error):
            scope.poison(error)
        raise
    finally:
        _READINESS_LOCAL.scope = None
        try:
            scope.close()
        except BaseException as cleanup:
            if primary is None:
                raise
            primary.daily_readiness_scope = scope
            primary.add_note("daily_readiness_scope_cleanup_unknown")
        else:
            with _READINESS_SCOPES_LOCK:
                pool.pop(id(scope), None)


@contextmanager
def readiness_scopes(db_paths, *, absent_paths=()):
    """Pre-acquire at most two distinct existing ledgers before native/SQL locks.

    Callers own the SQL lock ordering; arbitrary sqlite connections cannot be
    introspected here. A group or lexical scope already in progress refuses.
    """
    from .windows import current_thread_holds_mutex
    paths = tuple(Path(path).resolve() for path in db_paths)
    absent = tuple(Path(path).resolve() for path in absent_paths)
    if (not 1 <= len(paths) <= 2 or len(set(paths)) != len(paths) or
            len(set(absent)) != len(absent) or not set(absent) <= set(paths) or
            getattr(_READINESS_LOCAL, "scope", None) is not None or
            getattr(_READINESS_LOCAL, "group", None) is not None):
        _reject("daily_readiness_group_invalid")
    if current_thread_holds_mutex():
        _reject("daily_readiness_lock_held")
    with ExitStack() as owners:
        prepared = {}
        for path in paths:
            if not path.is_file():
                _reject("daily_readiness_group_existing_ledger_required")
            original = owners.enter_context(_owned_readiness_scope(path, absence_only=path in absent))
            _READINESS_LOCAL.scope = None
            if original.ledger_identity is None:
                _reject("daily_ledger_identity_unavailable")
            prepared[path] = original
        _READINESS_LOCAL.group = prepared
        try:
            yield
        except BaseException as error:
            if _readiness_cleanup_unknown(error):
                for original in prepared.values():
                    original.poison(error)
            raise
        finally:
            _READINESS_LOCAL.group = None
            _READINESS_LOCAL.scope = None


def revalidate_scoped_readiness(db_path, *, expected_generation):
    """Validate an existing lexical original; return only its timing bound.

    No SQL, RPC, new process handle or acquisition fallback is allowed here.
    The caller separately proves the actual row on its consumer connection.
    A returned NativeDeadline is the remote authority's same original object,
    not readiness/capacity authority that can survive this lexical scope.
    """
    path = Path(db_path).resolve()
    previous = getattr(_READINESS_LOCAL, "scope", None)
    group = getattr(_READINESS_LOCAL, "group", None)
    scope = group.get(path) if group is not None else previous
    if type(scope) is not _ReadinessScope or scope.path != path:
        _reject("daily_readiness_scope_required")
    _READINESS_LOCAL.scope = scope
    try:
        scope.assert_current()
        with _READINESS_SCOPES_LOCK:
            if scope.pool is not _READINESS_SCOPES or _READINESS_SCOPES.get(id(scope)) is not scope:
                _reject("daily_readiness_original_scope_required")
        if scope.absence_only or scope.cleanup is not None:
            _reject("daily_readiness_capacity_scope_required")
        row = expected_generation
        for candidate in (row, scope.row):
            if (type(candidate) is not dict or set(candidate) != _GENERATION_FIELDS or
                    any(type(candidate[key]) is not int or candidate[key] != 1
                        for key in ("singleton", "schema_version")) or
                    any(type(candidate[key]) is not str
                        for key in _GENERATION_FIELDS - {"singleton", "schema_version"}) or
                    candidate["state"] != "ACTIVE"):
                _reject("daily_readiness_scope_binding_changed")
        if scope.row != row:
            _reject("daily_readiness_scope_binding_changed")
        local = scope.local_owner
        if local is None:
            _revalidate_remote(scope, row)
            from .pipe_windows import NativeDeadline
            if type(scope.authority._deadline) is not NativeDeadline:
                _reject("daily_readiness_original_deadline_required")
        else:
            _revalidate_local_scope(scope, row, path)
            _revalidate_local(local, row)
        _assert_daily_locations(row["source_root"], path)
        if (row["ledger_path"] != str(path) or
                scope.ledger_identity != tuple(int(value) for value in json.loads(row["ledger_identity_json"])) or
                _ledger_identity(path) != scope.ledger_identity):
            _reject("daily_ledger_identity_changed")
        if _fixed_policy_digest(path) != row["config_digest"]:
            _reject("daily_config_changed")
        manifest = SourceManifest.from_dict(json.loads(row["source_manifest_json"]))
        if manifest.digest != row["source_digest"]:
            _reject("daily_source_digest_changed")
        verify_import_provenance(manifest, row["source_root"])
        # Source/config validation consumes the original deadline. Its cost is
        # never excused by a successful earlier observation.
        if local is None:
            _revalidate_remote(scope, row)
            return scope.authority._deadline
        _revalidate_local_scope(scope, row, path)
        _revalidate_local(local, row)
        return None
    finally:
        _READINESS_LOCAL.scope = previous


def _revalidate_absent(conn, scope, db_path):
    if scope is None:
        return
    scope.assert_current()
    if scope.row is not None:
        _reject("daily_generation_changed")
    if scope.path != Path(db_path).resolve() or not _ledger_matches(conn, scope.path):
        _reject("daily_ledger_mismatch")
    if scope.ledger_identity is not None and _ledger_identity(scope.path) != scope.ledger_identity:
        _reject("daily_ledger_identity_changed")


@contextmanager
def readiness_nonce_cleanup(policy, guard):
    """Only _clear after positive original native release may enter this seam."""
    from .experiment_cleanup import current_operation
    operation = current_operation()
    if operation is not None:
        current_operation(policy.store.db_path)
        with operation.nonce_cleanup(policy, guard):
            yield
        return
    scope = getattr(_READINESS_LOCAL, "scope", None)
    if scope is None:
        yield
        return
    scope.assert_current()
    if scope.cleanup is not None or Path(policy.store.db_path).resolve() != scope.path:
        _reject("daily_readiness_cleanup_scope_invalid")
    scope.cleanup = policy, guard
    try:
        yield
    finally:
        scope.cleanup = None


def _nonce_only(conn, *, scope=None, policy=None, guard=None, row=None):
    if scope is not None:
        def owned():
            if (getattr(_READINESS_LOCAL, "scope", None) is not scope or scope.closed or
                    scope.error is not None or scope.thread is not threading.current_thread() or
                    scope.cleanup is None or scope.cleanup[0] is not policy or scope.cleanup[1] is not guard or
                    policy.current_cleanup_guard() is not guard or policy.current_guard() is not None):
                return 0
            if read_generation(conn) != row or not _ledger_matches(conn, scope.path):
                return 0
            if (_ledger_identity(scope.path) != tuple(int(v) for v in json.loads(row["ledger_identity_json"])) or
                    _fixed_policy_digest(scope.path) != row["config_digest"]):
                return 0
            verify_import_provenance(SourceManifest.from_dict(json.loads(row["source_manifest_json"])),
                                     row["source_root"])
            return 1
        conn.create_function("sentinel_daily_nonce_clear", 0, owned)
        conn.execute("""CREATE TEMP TRIGGER daily_readiness_nonce_guard
            BEFORE UPDATE OF policy_entry_nonce ON main.adaptive_runtime
            WHEN sentinel_daily_nonce_clear() IS NOT 1 OR NEW.policy_entry_nonce IS NOT NULL
                 OR OLD.policy_entry_nonce IS NOT '""" + guard.nonce.replace("'", "''") + "' "
            "BEGIN SELECT RAISE(ABORT,'daily_readiness_cleanup_not_owned'); END")
    allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
               sqlite3.SQLITE_FUNCTION}
    def authorize(action, table, column, database, source):
        if action in allowed:
            return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_PRAGMA:
            if scope is None or (
                    table in {"table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list"} or
                    table == "database_list" and column is None or
                    table == "foreign_keys" and (column is None or str(column).lower() in {"on", "1"}) or
                    table == "busy_timeout" and (column is None or str(column).isdigit() and int(column) <= 250)):
                return sqlite3.SQLITE_OK
        if action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and column == "policy_entry_nonce":
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    conn.set_authorizer(authorize)


class _ReadinessReader:
    """One original read connection; an uncertain close is never retried."""
    def __init__(self):
        self.connection = None
        self.open_attempted = False
        self.closed = self.close_unknown = False

    def close(self):
        if self.closed:
            return
        if self.close_unknown:
            _reject("daily_generation_readiness_cleanup_unknown")
        if self.connection is None:
            _reject("daily_generation_readiness_acquisition_unknown")
        self.close_unknown = True
        self.connection.close()
        self.closed, self.close_unknown = True, False


def _ledger_identity(path):
    try:
        path = Path(path).absolute()
        for component in (path, *path.parents):
            value = component.lstat()
            if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
                _reject("daily_ledger_reparse_unsupported")
        before = path.stat()
        if (not stat.S_ISREG(before.st_mode) or not 0 <= before.st_dev < 1 << 128 or
                not 0 < before.st_ino < 1 << 128):
            _reject("daily_ledger_identity_unavailable")
        identity = int(before.st_dev), int(before.st_ino)
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != identity:
                _reject("daily_ledger_identity_changed")
        after = path.stat()
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != identity:
            _reject("daily_ledger_identity_changed")
        return identity
    except OSError:
        _reject("daily_ledger_identity_unavailable")


def daily_locations():
    home = Path.home().resolve()
    return home / "Projects" / "resource-sentinel", home / ".resource-sentinel"


def _assert_daily_locations(source_root, ledger_path):
    expected_root, expected_data = daily_locations()
    if (Path(source_root).resolve() != expected_root.resolve() or
            Path(ledger_path).resolve() != (expected_data / "sentinel.db").resolve()):
        _reject("daily_location_mismatch")


def _fixed_policy_digest(ledger_path):
    try:
        with Path(ledger_path).with_name("config.json").open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError
        config = json.loads(data.decode("utf-8-sig"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if (type(config) is not dict or config.get("admission_policy") != "resource-v2" or
                config.get("local_allocatable_ram_gib") != 58 or
                config.get("local_physical_headroom_gib", 4) != 4 or
                config.get("local_commit_headroom_gib", 4) != 4):
            _reject("daily_fixed_policy_mismatch")
        return _hash(data)
    except (OSError, ValueError, UnicodeError):
        _reject("daily_config_unavailable")


class DailyGenerationUnavailable(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _reject(reason):
    raise DailyGenerationUnavailable(reason)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _existing_root(root):
    root = Path(root).absolute()
    try:
        for path in (root, *root.parents):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _reject("daily_source_reparse_unsupported")
        if not root.is_dir():
            _reject("daily_source_unavailable")
        return root.resolve(strict=True)
    except OSError:
        _reject("daily_source_unavailable")


def _source_paths(root, *, require_complete=True):
    found = set()
    for folder in ("sentinel", "scripts", "hooks"):
        directory = root / folder
        if not directory.is_dir():
            _reject("daily_source_closure_incomplete")
        for path in directory.rglob("*"):
            # Do not traverse or quietly skip a redirected executable subtree.
            try:
                info = path.lstat()
            except OSError:
                _reject("daily_source_unavailable")
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _reject("daily_source_reparse_unsupported")
            if path.is_file() and path.suffix.casefold() in {".py", ".ps1"}:
                found.add(path.relative_to(root).as_posix())
                if len(found) > MAX_SOURCE_FILES:
                    _reject("daily_source_bound_exceeded")
    found.add("docs/agent-policy.md")
    if (root / "sentinel_daily_bootstrap.py").is_file():
        found.add("sentinel_daily_bootstrap.py")
    if require_complete and not REQUIRED_PATHS <= found:
        _reject("daily_source_closure_incomplete")
    return tuple(sorted(found))


def _read_source(root, relative):
    part = PurePosixPath(relative)
    if (part.is_absolute() or ".." in part.parts or "\\" in relative or
            str(part) != relative or ":" in relative):
        _reject("daily_source_path_invalid")
    path = root.joinpath(*part.parts)
    try:
        for component in (path, *tuple(path.parents)[:len(part.parts) - 1]):
            item = component.lstat()
            if stat.S_ISLNK(item.st_mode) or getattr(item, "st_file_attributes", 0) & 0x400:
                _reject("daily_source_reparse_unsupported")
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
            _reject("daily_source_bound_exceeded")
        with path.open("rb") as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        after = path.stat()
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
        if len(data) != before.st_size or any(getattr(before, f) != getattr(after, f) for f in fields):
            _reject("daily_source_changed")
        return data
    except OSError:
        _reject("daily_source_unavailable")


@dataclass(frozen=True)
class SourceEntry:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class SourceManifest:
    entries: tuple[SourceEntry, ...]

    def __post_init__(self):
        if (type(self.entries) is not tuple or not 0 < len(self.entries) <= MAX_SOURCE_FILES or
                any(type(e) is not SourceEntry or type(e.path) is not str or not 0 < len(e.path) <= 512 or
                    not _digest(e.sha256) or type(e.size) is not int or
                    not 0 <= e.size <= MAX_FILE_BYTES for e in self.entries)):
            _reject("daily_manifest_invalid")
        paths = tuple(e.path for e in self.entries)
        for path in paths:
            part = PurePosixPath(path)
            if (part.is_absolute() or ".." in part.parts or "\\" in path or
                    str(part) != path or ":" in path):
                _reject("daily_source_path_invalid")
        if paths != tuple(sorted(set(paths))) or not REQUIRED_PATHS <= set(paths):
            _reject("daily_manifest_incomplete")
        if sum(e.size for e in self.entries) > MAX_SOURCE_BYTES:
            _reject("daily_source_bound_exceeded")

    @property
    def digest(self):
        return _hash(_canonical(self.to_dict()))

    def to_dict(self):
        return {"schema_version": 1, "files": [
            {"path": e.path, "sha256": e.sha256, "size": e.size} for e in self.entries]}

    @classmethod
    def from_dict(cls, value):
        if (type(value) is not dict or set(value) != {"schema_version", "files"} or
                type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                type(value["files"]) is not list or len(value["files"]) > MAX_SOURCE_FILES):
            _reject("daily_manifest_invalid")
        entries = []
        for row in value["files"]:
            if type(row) is not dict or set(row) != {"path", "sha256", "size"}:
                _reject("daily_manifest_invalid")
            entries.append(SourceEntry(**row))
        return cls(tuple(entries))

    @classmethod
    def capture(cls, root):
        root = _existing_root(root)
        entries = []
        for relative in _source_paths(root):
            data = _read_source(root, relative)
            entries.append(SourceEntry(relative, _hash(data), len(data)))
            if sum(e.size for e in entries) > MAX_SOURCE_BYTES:
                _reject("daily_source_bound_exceeded")
        return cls(tuple(entries))

    def verify(self, root):
        root = _existing_root(root)
        if _source_paths(root) != tuple(e.path for e in self.entries):
            _reject("daily_source_closure_changed")
        for entry in self.entries:
            data = _read_source(root, entry.path)
            if len(data) != entry.size or _hash(data) != entry.sha256:
                _reject("daily_source_generation_mismatch")
        return root


_CODE_ATTRIBUTES = frozenset({
    "co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
    "co_stacksize", "co_flags", "co_code", "co_consts", "co_names", "co_varnames",
    "co_freevars", "co_cellvars", "co_name", "co_qualname", "co_filename",
    "co_firstlineno", "co_linetable", "co_exceptiontable",
    # Derived views: represented already by the persisted fields above.
    "co_lines", "co_positions", "co_lnotab",
})
_CODE_LAYOUT_VERIFIED = False


def _constant_key(value):
    """Typed immutable compiler constants, preserving IEEE sign/payload bits."""
    kind = type(value)
    if value is None:
        return ("none",)
    if value is Ellipsis:
        return ("ellipsis",)
    if kind is bool:
        return ("bool", value)
    if kind is int:
        return ("int", value)
    if kind is str:
        return ("str", value)
    if kind is bytes:
        return ("bytes", value)
    if kind is float:
        return ("float", struct.pack(">d", value))
    if kind is complex:
        return ("complex", struct.pack(">d", value.real), struct.pack(">d", value.imag))
    if kind is tuple:
        return ("tuple", tuple(_constant_key(item) for item in value))
    if kind is frozenset:
        counts = {}
        for item in value:
            key = _constant_key(item)
            counts[key] = counts.get(key, 0) + 1
        return ("frozenset", frozenset(counts.items()))
    if kind is types.CodeType:
        return _code_key(value)
    _reject("daily_loaded_code_unverified")


def _code_key(code):
    # Bare CodeType equality omits stacksize/qualname; marshal additionally
    # encodes reference sharing. Preserve every persisted structural field,
    # excluding only filename (the loaded function's exact origin is checked
    # separately). Nested code/constants receive the same complete comparison.
    global _CODE_LAYOUT_VERIFIED
    if type(code) is not types.CodeType:
        _reject("daily_loaded_code_unverified")
    if not _CODE_LAYOUT_VERIFIED:
        if frozenset(name for name in dir(types.CodeType) if name.startswith("co_")) != _CODE_ATTRIBUTES:
            _reject("daily_loaded_code_unverified")
        _CODE_LAYOUT_VERIFIED = True
    return ("code", code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
            code.co_nlocals, code.co_stacksize, code.co_flags, code.co_code,
            code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
            code.co_name, code.co_qualname, code.co_firstlineno, code.co_linetable,
            code.co_exceptiontable, tuple(_constant_key(value) for value in code.co_consts))


def _compiled_code_keys(code):
    result = {_code_key(code)}
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            result.update(_compiled_code_keys(value))
    return result


def _functions(value, module_name):
    if inspect.isfunction(value) and value.__module__ == module_name:
        yield inspect.unwrap(value)
    elif inspect.isclass(value) and value.__module__ == module_name:
        for child in vars(value).values():
            if isinstance(child, (staticmethod, classmethod)):
                child = child.__func__
            if isinstance(child, property):
                for accessor in (child.fget, child.fset, child.fdel):
                    if accessor is not None:
                        yield inspect.unwrap(accessor)
            elif inspect.isfunction(child) and child.__module__ == module_name:
                yield inspect.unwrap(child)


def verify_loaded_source(manifest, root, *, modules=None):
    """Diagnostic drift check only; complete import provenance is required below."""
    root = manifest.verify(root)
    expected = {e.path: e for e in manifest.entries}
    for name, module in tuple((sys.modules if modules is None else modules).items()):
        if not (name == "sentinel" or name.startswith("sentinel.")) or module is None:
            continue
        filename = getattr(module, "__file__", None)
        try:
            path = Path(filename).resolve(strict=True)
            relative = path.relative_to(root).as_posix()
        except (TypeError, ValueError, OSError):
            _reject("daily_loaded_source_origin_mismatch")
        if relative not in expected or path.suffix != ".py":
            _reject("daily_loaded_source_unreviewed")
        try:
            compiled = compile(_read_source(root, relative), str(path), "exec", dont_inherit=True)
            codes = _compiled_code_keys(compiled)
            for value in tuple(vars(module).values()):
                # Dataclasses/Enum generate methods whose filename is <string>
                # or the stdlib definition. Their Python source is pinned; the
                # check here concerns source-defined loaded functions, not a
                # claim that all mutable Python object state is attested.
                for function in _functions(value, name):
                    origin = function.__code__.co_filename
                    if origin.startswith("<"):
                        continue
                    if origin != str(path) or _code_key(function.__code__) not in codes:
                        _reject("daily_loaded_code_generation_mismatch")
        except (SyntaxError, ValueError, TypeError):
            _reject("daily_loaded_code_unverified")
    return root


def _manifest_bound_sources(manifest, root, paths):
    expected = {entry.path: entry for entry in manifest.entries}
    if not set(paths) <= expected.keys():
        _reject("daily_loaded_source_unreviewed")
    sources = {}
    for path in paths:
        data = _read_source(root, path)
        entry = expected[path]
        if len(data) != entry.size or _hash(data) != entry.sha256:
            _reject("daily_source_generation_mismatch")
        sources[path] = data
    return sources


def verify_import_provenance(manifest, root):
    """Require actual complete module execution, including global initializers."""
    from sentinel_daily_bootstrap import assert_import_provenance, ImportProvenanceUnavailable
    root = manifest.verify(root)
    paths = {"sentinel_daily_bootstrap.py"}
    modules = tuple((name, module) for name, module in tuple(sys.modules.items())
                    if (name == "sentinel" or name.startswith("sentinel.")) and module is not None)
    for name, module in modules:
        try:
            paths.add(Path(module.__file__).resolve(strict=True).relative_to(root).as_posix())
        except (TypeError, ValueError, AttributeError, OSError):
            _reject("daily_loaded_source_origin_mismatch")
    sources = _manifest_bound_sources(manifest, root, paths)
    try:
        assert_import_provenance(root, sources)
    except (ImportProvenanceUnavailable, SyntaxError, ValueError, TypeError) as error:
        _reject(str(error) if isinstance(error, ImportProvenanceUnavailable) else "daily_import_provenance_unavailable")
    after = tuple((name, module) for name, module in tuple(sys.modules.items())
                  if (name == "sentinel" or name.startswith("sentinel.")) and module is not None)
    if modules != after:
        _reject("daily_import_inventory_changed")
    return root


def read_generation(conn):
    present = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)).fetchone()
    if present is None:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' "
                        "AND name GLOB 'adaptive_daily_*' LIMIT 1").fetchone() is not None:
            _reject("daily_generation_guards_unverified")
        return None
    validate_triggers(conn)
    bounds = {"generation": 36, "state": 16, "source_digest": 64, "config_digest": 64,
              "source_manifest_json": 1024 * 1024, "source_root": 32768,
              "ledger_path": 32768, "owner_identity_json": 1024,
              "ledger_identity_json": 128, "readiness_instance_id": 36}
    lengths = conn.execute("SELECT " + ",".join(f"length({key})" for key in bounds) +
                           f" FROM {_TABLE} LIMIT 2").fetchall()
    if len(lengths) != 1 or any(type(value) is not int or value > bound or value < 1
                               for value, bound in zip(lengths[0], bounds.values())):
        _reject("daily_generation_invalid")
    rows = conn.execute(f"SELECT * FROM {_TABLE} LIMIT 2").fetchall()
    if len(rows) != 1:
        _reject("daily_generation_invalid")
    names = [r[1] for r in conn.execute(f"PRAGMA table_info({_TABLE})")]
    row = dict(zip(names, rows[0])) if not hasattr(rows[0], "keys") else dict(rows[0])
    try:
        if (row["singleton"] != 1 or row["schema_version"] != 1 or
                row["state"] not in {"ACTIVE", "DRAINING"} or
                str(uuid.UUID(row["generation"])) != row["generation"] or
                not _digest(row["source_digest"]) or not _digest(row["config_digest"])):
            raise ValueError
        manifest = SourceManifest.from_dict(json.loads(row["source_manifest_json"]))
        if manifest.digest != row["source_digest"]:
            raise ValueError
        ProcessIdentity.from_dict(json.loads(row["owner_identity_json"]))
        if str(uuid.UUID(row["readiness_instance_id"])) != row["readiness_instance_id"]:
            raise ValueError
        identity = json.loads(row["ledger_identity_json"])
        if (type(identity) is not list or len(identity) != 2 or
                any(type(v) is not str or not v.isdecimal() or len(v) > 40 for v in identity)):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        _reject("daily_generation_invalid")
    return row


def _ledger_matches(conn, db_path):
    rows = conn.execute("PRAGMA database_list").fetchall()
    files = [r[2] for r in rows if r[1] == "main"]
    try:
        return len(files) == 1 and Path(files[0]).resolve(strict=True) == Path(db_path).resolve(strict=True)
    except OSError:
        return False


def prepare_connection(conn, *, role, db_path):
    """Validate outside BEGIN and bind this connection, without installing schema."""
    if role not in ROLES or conn.in_transaction:
        _reject("daily_connection_scope_invalid")
    from .experiment_cleanup import current_operation
    operation = current_operation(db_path)
    if operation is not None:
        operation.bind_connection(conn, role=role, db_path=db_path)
        return None
    # Persistent experiment guards reference this fixed function even on their
    # ordinary HOLD branch. Name resolution is not release authority.
    conn.create_function("sentinel_experiment_release_mutation", 4, lambda *_: 0)
    row = read_generation(conn)
    if row is None:
        scope = getattr(_READINESS_LOCAL, "scope", None)
        _revalidate_absent(conn, scope, db_path)
        return None
    scope = getattr(_READINESS_LOCAL, "scope", None)
    if scope is not None and scope.absence_only:
        _reject("daily_readiness_absence_required")
    local = _LOCAL_GENERATIONS.get(row["generation"])
    retirement = getattr(local, "_retirement_operation", None)
    retirement_cleanup = row["state"] == "DRAINING" and role == "lifecycle" and retirement is not None
    if row["state"] != "ACTIVE" and not retirement_cleanup:
        _reject("daily_generation_draining")
    _assert_daily_locations(row["source_root"], db_path)
    if not _ledger_matches(conn, db_path) or Path(db_path).resolve() != Path(row["ledger_path"]):
        _reject("daily_ledger_mismatch")
    if _ledger_identity(db_path) != tuple(int(v) for v in json.loads(row["ledger_identity_json"])):
        _reject("daily_ledger_identity_changed")
    manifest = SourceManifest.from_dict(json.loads(row["source_manifest_json"]))
    if _fixed_policy_digest(db_path) != row["config_digest"]:
        _reject("daily_config_changed")
    verify_import_provenance(manifest, row["source_root"])
    if retirement_cleanup:
        from .daily_retirement import DailyRetirementOperation
        if type(retirement) is not DailyRetirementOperation or retirement.owner is not local:
            _reject("daily_retirement_cleanup_not_owned")
        retirement.authorize_nonce_cleanup(conn, row)
        return None
    if (local is not None and role == "lifecycle" and not local._activated and
            getattr(local, "_install_attempted", False)):
        local._assert_owner()
        if (local.ledger_path != Path(db_path).resolve() or
                local.process.identity.to_dict() != json.loads(row["owner_identity_json"])):
            _reject("daily_install_cleanup_binding_mismatch")
        # The original install POLICY must clear its nonce before readiness
        # can be ACKed. This connection gets NO capacity-generation function.
        # Permit only that metadata cleanup, never a reservation or DDL write.
        _nonce_only(conn)
        return None
    scope = getattr(_READINESS_LOCAL, "scope", None)
    if scope is not None and scope.cleanup is not None and role == "lifecycle":
        scope.assert_current()
        policy, guard = scope.cleanup
        if (scope.row != row or scope.path != Path(db_path).resolve() or
                policy.current_cleanup_guard() is not guard):
            _reject("daily_readiness_cleanup_binding_changed")
        policy.revalidate(conn, guard)
        _nonce_only(conn, scope=scope, policy=policy, guard=guard, row=row)
        return None
    if scope is not None:
        # Capacity always uses the same branch proved before locks. A new
        # registry entry cannot replace an authenticated remote original.
        scope.assert_current()
        if scope.row != row or scope.path != Path(db_path).resolve():
            _reject("daily_readiness_scope_binding_changed")
        local = scope.local_owner
    if local is None:
        if scope is None or scope.row != row or scope.path != Path(db_path).resolve():
            _reject("daily_readiness_scope_required")
        scope.assert_current()
        _revalidate_remote(scope, row)
    else:
        if scope is None:
            # Existing original local owner path; this does not open a peer.
            local.assert_ready()
        else:
            _revalidate_local_scope(scope, row, db_path)
        _revalidate_local(local, row)
    def current_generation():
        # SQLite invokes this within the actual writer transaction. Re-read
        # that same connection, never a side database or readiness RPC.
        if read_generation(conn) != row:
            _reject("daily_generation_changed")
        if (_ledger_identity(db_path) != tuple(int(v) for v in json.loads(row["ledger_identity_json"]))
                or not _ledger_matches(conn, db_path)):
            _reject("daily_ledger_identity_changed")
        if _fixed_policy_digest(db_path) != row["config_digest"]:
            _reject("daily_config_changed")
        verify_import_provenance(manifest, row["source_root"])
        if local is None:
            scope.assert_current()
            _revalidate_remote(scope, row)
        else:
            if scope is not None:
                _revalidate_local_scope(scope, row, db_path)
            _revalidate_local(local, row)
        return row["generation"]
    conn.create_function("sentinel_daily_generation", 0, current_generation)
    def delete_authority(table, key):
        if table not in {"reservations", "queue"} or type(key) is not str or not key:
            _reject("daily_delete_scope_invalid")
        generation = current_generation()
        if row["state"] != "ACTIVE" or generation != row["generation"]:
            _reject("daily_generation_draining")
        return 1
    conn.create_function("sentinel_daily_delete_authority", 2, delete_authority)
    return row["generation"]


def _revalidate_local_scope(scope, row, db_path):
    scope.assert_current()
    if scope.row != row or scope.path != Path(db_path).resolve():
        _reject("daily_readiness_scope_binding_changed")
    if (type(scope.local_owner) is not DailyGenerationOwner or
            _LOCAL_GENERATIONS.get(row["generation"]) is not scope.local_owner):
        _reject("daily_readiness_local_owner_changed")


def _revalidate_local(local, row):
    if not local._activated or not local._matches_generation(row):
        _reject("daily_generation_owner_mismatch")
    local._assert_owner()
    local.cohort.assert_retained_retired()


def revalidate_transaction(conn, *, db_path):
    """Recheck on the actual acquired SQL snapshot, without acquiring authority."""
    if not conn.in_transaction:
        _reject("daily_connection_scope_invalid")
    from .experiment_cleanup import current_operation
    operation = current_operation(db_path)
    if operation is not None:
        operation.revalidate_connection(conn, db_path=db_path)
        return
    row = read_generation(conn)
    scope = getattr(_READINESS_LOCAL, "scope", None)
    if row is None:
        _revalidate_absent(conn, scope, db_path)
        return
    if scope is not None and scope.absence_only:
        _reject("daily_readiness_absence_required")
    local = _LOCAL_GENERATIONS.get(row["generation"])
    # These already installed restrictive connection authorizers; asking for
    # the capacity UDF would turn nonce cleanup into capacity authorization.
    if ((scope is not None and scope.cleanup is not None) or
            (local is not None and (not local._activated or row["state"] == "DRAINING"))):
        if scope is not None and scope.cleanup is not None and local is None and scope.row != row:
            _reject("daily_readiness_cleanup_binding_changed")
        return
    if not _ledger_matches(conn, db_path):
        _reject("daily_ledger_mismatch")
    conn.execute("SELECT sentinel_daily_generation()").fetchone()


def _revalidate_remote(scope, row):
    from .daily_readiness_transport import DailyReadinessAuthority, LedgerFileIdentity, _binding
    from .pipe_windows import NativePipeEndpoint
    if type(scope.authority) is not DailyReadinessAuthority:
        _reject("daily_readiness_original_authority_required")
    identity = ProcessIdentity.from_dict(json.loads(row["owner_identity_json"]))
    endpoint = NativePipeEndpoint(identity.logon_id, row["readiness_instance_id"], identity)
    binding = _binding(row["generation"], row["source_digest"], row["config_digest"],
        LedgerFileIdentity(*(int(v) for v in json.loads(row["ledger_identity_json"]))))
    scope.authority.revalidate(endpoint, binding)


def _prove_retained_owner_ready(row, *, local_owner=_TOKEN):
    local = _LOCAL_GENERATIONS.get(row["generation"]) if local_owner is _TOKEN else local_owner
    if local is not None:
        if (type(local) is not DailyGenerationOwner or
                local.process.identity.to_dict() != json.loads(row["owner_identity_json"]) or
                local.manifest.digest != row["source_digest"]):
            _reject("daily_generation_owner_mismatch")
        local.assert_ready()
        return
    from .daily_readiness_transport import DailyReadinessClient, LedgerFileIdentity
    from .pipe_windows import NativePipeEndpoint
    # Lazy imports are also consumers: attest their executed module code before
    # using the transport, rather than only attesting the earlier module set.
    verify_import_provenance(SourceManifest.from_dict(json.loads(row["source_manifest_json"])),
                             row["source_root"])
    identity = ProcessIdentity.from_dict(json.loads(row["owner_identity_json"]))
    endpoint = NativePipeEndpoint(identity.logon_id, row["readiness_instance_id"], identity)
    caller = VerifiedProcess.current()
    primary = None
    authority = None
    try:
        authority = DailyReadinessClient(endpoint, caller).acquire_ready(
            row["generation"], row["source_digest"], row["config_digest"],
            LedgerFileIdentity(*(int(v) for v in json.loads(row["ledger_identity_json"]))),
            timeout_ms=1000)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            caller.close()
        except BaseException as error:
            target = error if primary is None else primary
            target.daily_readiness_current_process = caller
            target._daily_readiness_authority = authority
            target.add_note("daily_readiness_caller_cleanup_unverified")
            if primary is None:
                raise
    return authority


def _trigger_definitions():
    result = {}
    for table in CAPACITY_TABLES:
        for event in ("INSERT", "UPDATE", "DELETE"):
            name = f"adaptive_daily_{table}_{event.lower()}"
            if event == "DELETE" and table in {"reservations", "queue"}:
                key = "id" if table == "reservations" else "request_key"
                predicate = f"sentinel_daily_delete_authority('{table}',OLD.{key}) IS NOT 1"
            else:
                predicate = (f"(SELECT state FROM {_TABLE} WHERE singleton=1) IS NOT 'ACTIVE' OR "
                    f"sentinel_daily_generation() IS NOT (SELECT generation FROM {_TABLE} WHERE singleton=1)")
            result[name] = (f"CREATE TRIGGER {name} BEFORE {event} ON {table} WHEN {predicate} "
                "BEGIN SELECT RAISE(ABORT,'daily_generation_required'); END")
    return result


def validate_triggers(conn):
    """Require the complete canonical generation guards without repairing them."""
    expected = _trigger_definitions()
    rows = conn.execute("""SELECT
        CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,
        CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END
        FROM sqlite_master WHERE type='trigger' AND name GLOB 'adaptive_daily_*'
        LIMIT ?""", (len(expected) + 1,)).fetchall()
    if len(rows) != len(expected) or any(name is None or sql is None for name, sql in rows):
        _reject("daily_generation_guards_unverified")
    actual = dict(rows)
    normalize = lambda sql: " ".join(sql.split()).rstrip(";")
    if set(actual) != set(expected) or any(normalize(actual[name]) != normalize(sql)
                                          for name, sql in expected.items()):
        _reject("daily_generation_guards_unverified")


def _install_triggers(conn):
    for statement in _trigger_definitions().values():
        conn.execute(statement)


class DailyGenerationOwner:
    """Retained activation custody; constructor is not a serialized receipt API."""
    def __init__(self, *, _token=None, process=None, cohort=None, manifest=None,
                 source_root=None, ledger_path=None):
        if _token is not _TOKEN:
            raise TypeError("use_daily_generation_capture")
        self.process, self.cohort, self.manifest = process, cohort, manifest
        self.source_root, self.ledger_path = source_root, ledger_path
        self.ledger_identity = _ledger_identity(ledger_path)
        self.generation = str(uuid.uuid4())
        from .pipe_windows import NativePipeEndpoint
        self.readiness_endpoint = NativePipeEndpoint(process.identity.logon_id, str(uuid.uuid4()), process.identity)
        self._activated = False
        self._closed = False
        self._install_policy = self._install_guard = None
        self._readiness_reader_lock = threading.Lock()
        self._readiness_readers = {}
        self._readiness_cleanup_error = None

    @classmethod
    def capture(cls, *, manifest, source_root, ledger_path):
        from .daily_cohort import RetainedCohort
        if type(manifest) is not SourceManifest:
            _reject("daily_manifest_required")
        _assert_daily_locations(source_root, ledger_path)
        root = verify_import_provenance(manifest, source_root)
        ledger = Path(ledger_path).resolve(strict=True)
        if not ledger.is_file():
            _reject("daily_ledger_missing")
        process = VerifiedProcess.current()
        owner = None
        try:
            owner = cls(_token=_TOKEN, process=process, manifest=manifest,
                        source_root=root, ledger_path=ledger)
            owner.cohort = RetainedCohort.capture_current()
            return owner
        except BaseException as error:
            # An incomplete native capture may still own handles.
            if owner is not None:
                owner.cohort = getattr(error, "cohort", None)
                error.daily_generation_owner = owner
            error.daily_generation_process = process
            raise

    def _assert_owner(self):
        if self._closed:
            _reject("daily_generation_owner_closed")
        if self._readiness_cleanup_error is not None:
            _reject("daily_generation_readiness_cleanup_unknown")
        observation = self.process.observe()
        if observation.status is not IdentityStatus.ALIVE or observation.identity != self.process.identity:
            _reject("daily_generation_owner_unavailable")

    def _matches_generation(self, row):
        return (row is not None and row["state"] == "ACTIVE" and
                row["generation"] == self.generation and
                row["source_digest"] == self.manifest.digest and
                row["config_digest"] == self._config_digest and
                row["source_root"] == str(self.source_root) and
                row["ledger_path"] == str(self.ledger_path) and
                json.loads(row["owner_identity_json"]) == self.process.identity.to_dict() and
                tuple(int(value) for value in json.loads(row["ledger_identity_json"])) == self.ledger_identity and
                row["readiness_instance_id"] == self.readiness_endpoint.instance_id)

    def install_locked(self, conn, *, policy, guard):
        """Only called by the authorized owner inside its existing POLICY/SQL scope.

        Source and cohort checks belong before BEGIN; the caller must use
        prepare_install immediately before entering this exact retained scope.
        No retry reconstruction, owner adoption or generic bool is accepted.
        """
        prepared = getattr(self, "_prepared_install", None)
        self._prepared_install = None
        if prepared is None or prepared[0] is not policy or prepared[1] is not guard:
            _reject("daily_install_not_prepared")
        policy.assert_held(guard)
        if not conn.in_transaction or not _ledger_matches(conn, self.ledger_path):
            _reject("daily_install_transaction_invalid")
        policy.revalidate(conn, guard)
        self._install_policy, self._install_guard = policy, guard
        if read_generation(conn) is not None:
            _reject("daily_generation_already_present")
        runtime = dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())
        if runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE":
            _reject("daily_activation_requires_off")
        for table in ("reservations", "worker_reservations", "queue"):
            if conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None:
                _reject("daily_activation_allocations_not_empty")
        if conn.execute("SELECT 1 FROM managed_executions LIMIT 1").fetchone() is not None:
            # Cold terminal-history adoption has no native custody proof here.
            _reject("daily_activation_lifecycle_history_unverified")
        # Retain custody before the first possible mutation, including an
        # interruption in CREATE/INSERT or a connection whose outcome is lost.
        self._install_attempted = True
        _LOCAL_GENERATIONS[self.generation] = self
        self._install_connection = conn
        self._install_connection_closed = False
        self._install_close_unknown = False
        conn.execute(f"""CREATE TABLE {_TABLE} (
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            schema_version INTEGER NOT NULL CHECK(schema_version=1),
            generation TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('ACTIVE','DRAINING')),
            source_digest TEXT NOT NULL, config_digest TEXT NOT NULL, source_manifest_json TEXT NOT NULL,
            source_root TEXT NOT NULL, ledger_path TEXT NOT NULL,
            owner_identity_json TEXT NOT NULL, ledger_identity_json TEXT NOT NULL,
            readiness_instance_id TEXT NOT NULL)""")
        conn.execute(f"INSERT INTO {_TABLE} VALUES(1,1,?,'ACTIVE',?,?,?,?,?,?,?,?)", (
            self.generation, self.manifest.digest, self._config_digest, _canonical(self.manifest.to_dict()).decode(),
            str(self.source_root), str(self.ledger_path),
            _canonical(self.process.identity.to_dict()).decode(),
            _canonical([str(value) for value in self.ledger_identity]).decode(),
            self.readiness_endpoint.instance_id))
        _install_triggers(conn)
        conn.create_function("sentinel_daily_generation", 0, lambda: self.generation)
        # The owner is not ACTIVE until its caller acknowledges commit AND
        # original POLICY/connection cleanup, retaining this owner on ambiguity.

    def prepare_install(self, *, policy, guard):
        self._prepared_install = None
        policy.assert_held(guard)
        self._assert_owner()
        _assert_daily_locations(self.source_root, self.ledger_path)
        if _ledger_identity(self.ledger_path) != self.ledger_identity:
            _reject("daily_ledger_identity_changed")
        self._config_digest = _fixed_policy_digest(self.ledger_path)
        verify_import_provenance(self.manifest, self.source_root)
        self.cohort.assert_retired()
        self._prepared_install = (policy, guard)

    def acknowledge_install(self, *, conn):
        if (conn.in_transaction or not getattr(self, "_install_attempted", False) or
                not getattr(self, "_install_connection_closed", False) or
                conn is getattr(self, "_install_connection", None)):
            _reject("daily_install_unsettled")
        self._assert_owner()
        if not _ledger_matches(conn, self.ledger_path):
            _reject("daily_ledger_mismatch")
        if self._install_policy.current_guard() is not None:
            _reject("daily_install_policy_unsettled")
        runtime = conn.execute("SELECT policy_entry_nonce,policy_instance_id,policy_logon_id "
                               "FROM adaptive_runtime WHERE singleton=1").fetchone()
        if (runtime is None or runtime[0] is not None or
                runtime[1] != self._install_guard.binding.instance_id or
                runtime[2] != self._install_guard.binding.logon_id):
            _reject("daily_install_policy_unsettled")
        row = read_generation(conn)
        if not self._matches_generation(row):
            _reject("daily_install_unsettled")
        self._activated = True

    def settle_install_connection(self):
        """Own the original connection's final close before installation ACK.

        sqlite3 exposes no reliable failed-close/unknown distinction. Any close
        exception is quarantined; never assume a second call proves the first.
        """
        if not getattr(self, "_install_attempted", False):
            _reject("daily_install_unsettled")
        if self._install_connection_closed:
            return
        if self._install_close_unknown:
            _reject("daily_install_connection_close_unknown")
        if self._install_policy.current_guard() is not None:
            _reject("daily_install_policy_unsettled")
        connection = self._install_connection
        try:
            active = connection.in_transaction
        except sqlite3.ProgrammingError:
            # The transaction context may have closed it already. Ownership
            # still lives on this exact Connection object; close is idempotent.
            active = False
        if active:
            _reject("daily_install_transaction_unsettled")
        self._install_close_unknown = True
        connection.close()
        self._install_connection_closed = True
        self._install_close_unknown = False

    def assert_ready(self):
        if not self._activated:
            _reject("daily_generation_not_activated")
        self._assert_owner()
        _assert_daily_locations(self.source_root, self.ledger_path)
        if _ledger_identity(self.ledger_path) != self.ledger_identity:
            _reject("daily_ledger_identity_changed")
        if _fixed_policy_digest(self.ledger_path) != self._config_digest:
            _reject("daily_config_changed")
        verify_import_provenance(self.manifest, self.source_root)
        self.cohort.assert_retained_retired()
        # Retain before SQL use. Readiness can be queried by the resident
        # service and original keeper concurrently, so registry changes share
        # a bounded in-process lock; this lock grants no POLICY authority.
        with self._readiness_reader_lock:
            if self._readiness_cleanup_error is not None:
                _reject("daily_generation_readiness_cleanup_unknown")
            if len(self._readiness_readers) >= 4:
                _reject("daily_generation_readiness_readers_pending")
            reader = None
            try:
                # Publish a pending original owner before acquiring SQL. If
                # connect is interrupted before returning a connection, the
                # attempt itself remains retained and blocks final retirement.
                reader = _ReadinessReader()
                self._readiness_readers[id(reader)] = reader
                reader.open_attempted = True
                reader.connection = sqlite3.connect(
                    self.ledger_path.as_uri() + "?mode=ro", uri=True, timeout=.25)
            except BaseException as error:
                # A failed registry update happens before connect. An unknown
                # connect result cannot certify that no SQL owner existed.
                self._readiness_cleanup_error = error
                error.daily_generation_readiness_reader = reader
                error.add_note("daily_generation_readiness_cleanup_unknown")
                raise
        primary = None
        try:
            row = read_generation(reader.connection)
            if not self._matches_generation(row):
                _reject("daily_generation_changed")
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                reader.close()
            except BaseException as cleanup:
                # Keep both original connection and first close failure. A
                # successful future read can never settle this custody.
                with self._readiness_reader_lock:
                    if self._readiness_cleanup_error is None:
                        self._readiness_cleanup_error = cleanup
                target = primary if primary is not None else cleanup
                target.daily_generation_readiness_reader = reader
                target.add_note("daily_generation_readiness_cleanup_unknown")
                if primary is None:
                    raise
            else:
                with self._readiness_reader_lock:
                    self._readiness_readers.pop(id(reader))
        return None

    def assert_readiness_readers_settled(self):
        """Retirement checks actual readers after joining the original service."""
        with self._readiness_reader_lock:
            if self._readiness_cleanup_error is not None:
                _reject("daily_generation_readiness_cleanup_unknown")
            if self._readiness_readers:
                _reject("daily_generation_readiness_readers_pending")

    def close_unactivated(self):
        if self._activated or getattr(self, "_install_attempted", False):
            _reject("daily_generation_custody_required")
        self.assert_readiness_readers_settled()
        if self.cohort is not None:
            self.cohort.close()
        self.process.close()
        self._closed = True
