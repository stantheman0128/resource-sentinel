"""Unactivated daily source/cohort handoff primitives.

Nothing imports Coordinator, creates a ledger, deploys files, or installs a task.
Only an original in-process owner may install the generation under an existing
POLICY scope after positive old-cohort retirement. A manifest is data, never
native admission authority. Production consumers must call prepare_connection
before their transaction; an absent generation preserves existing behavior.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
import json
import marshal
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
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
    "scripts/maintainerctl.py", "scripts/invoke-sentinel.ps1",
    "scripts/collect.ps1", "scripts/collect-scheduled.ps1",
    "scripts/legacy-mutation.py", "hooks/sentinel-gate.py",
    "hooks/sentinel-stop.py", "docs/agent-policy.md",
})
_TABLE = "adaptive_daily_generation"
_TOKEN = object()
_LOCAL_GENERATIONS = {}


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


def _code_hash(code):
    # Paths differ in staged copies. The bytecode/constants/name/line structure
    # still has to match; no symbol-name-only or file-hash-only loaded check.
    constants = tuple(_normalize_code(c) if isinstance(c, types.CodeType) else c
                      for c in code.co_consts)
    return _hash(marshal.dumps(code.replace(co_filename="<daily-source>", co_consts=constants)))


def _normalize_code(code):
    return code.replace(co_filename="<daily-source>", co_consts=tuple(
        _normalize_code(c) if isinstance(c, types.CodeType) else c for c in code.co_consts))


def _compiled_hashes(code):
    result = {_code_hash(code)}
    for value in code.co_consts:
        if isinstance(value, types.CodeType):
            result.update(_compiled_hashes(value))
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
            hashes = _compiled_hashes(compiled)
            for value in tuple(vars(module).values()):
                # Dataclasses/Enum generate methods whose filename is <string>
                # or the stdlib definition. Their Python source is pinned; the
                # check here concerns source-defined loaded functions, not a
                # claim that all mutable Python object state is attested.
                for function in _functions(value, name):
                    origin = function.__code__.co_filename
                    if origin.startswith("<"):
                        continue
                    if origin != str(path) or _code_hash(function.__code__) not in hashes:
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
        return None
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
    row = read_generation(conn)
    if row is None:
        return None
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
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                   sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_PRAGMA}
        def cleanup_only(action, table, column, database, source):
            if action in allowed:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and column == "policy_entry_nonce":
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(cleanup_only)
        return None
    _prove_retained_owner_ready(row)
    # Constant local generation only; SQL compares against the row again.
    conn.create_function("sentinel_daily_generation", 0, lambda: row["generation"])
    return row["generation"]


def _prove_retained_owner_ready(row):
    local = _LOCAL_GENERATIONS.get(row["generation"])
    if local is not None:
        if (local.process.identity.to_dict() != json.loads(row["owner_identity_json"]) or
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
    try:
        DailyReadinessClient(endpoint, caller).assert_ready(
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
            if primary is None:
                raise
            primary.add_note("daily_readiness_caller_cleanup_unverified")


def _install_triggers(conn):
    for table in CAPACITY_TABLES:
        for event in ("INSERT", "UPDATE", "DELETE"):
            name = f"adaptive_daily_{table}_{event.lower()}"
            conn.execute(f"CREATE TRIGGER {name} BEFORE {event} ON {table} WHEN "
                f"(SELECT state FROM {_TABLE} WHERE singleton=1) IS NOT 'ACTIVE' OR "
                f"sentinel_daily_generation() IS NOT (SELECT generation FROM {_TABLE} WHERE singleton=1) "
                "BEGIN SELECT RAISE(ABORT,'daily_generation_required'); END")


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
