"""Original daily admission custody for isolated native verification.

This first slice reserves real daily capacity and atomically marks its separate
experiment obligation. It does not authorize native creation/control or supply
a daily release capability. Native preparation and positive cleanup remain
owned by this original demand; admitted-demand release is still unavailable.
Ordinary managed
launch/cancellation cannot consume the private, experiment-bound credential.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from uuid import UUID

from .admission import ManagedAdmission
from .contracts import Priority, ResourceDemand, Role
from . import daily_generation


TABLE = "adaptive_experiment_demands"
_CREATE = object()
_BEFORE_NATIVE = object()
_RETAINED = {}
_GENERATION_FIELDS = frozenset({"singleton", "schema_version", "generation", "state",
    "source_digest", "config_digest", "source_manifest_json", "source_root", "ledger_path",
    "owner_identity_json", "ledger_identity_json", "readiness_instance_id"})
_FIELDS = ("experiment_id", "schema_version", "execution_id", "reservation_id",
    "request_key", "suite", "scope_sha256", "scope_directory", "scope_identity_json",
    "source_generation", "source_digest", "config_digest", "ledger_identity_json",
    "owner_pid", "owner_birth", "owner_logon_id", "spec_hash", "admission_binding_hash",
    "demand_json", "state", "revision", "binding_sha256")
_TABLE_SQL = """CREATE TABLE adaptive_experiment_demands (
    experiment_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL CHECK(schema_version=1),
    execution_id TEXT UNIQUE NOT NULL, reservation_id TEXT UNIQUE NOT NULL,
    request_key TEXT UNIQUE NOT NULL, suite TEXT NOT NULL, scope_sha256 TEXT NOT NULL,
    scope_directory TEXT NOT NULL, scope_identity_json TEXT NOT NULL,
    source_generation TEXT NOT NULL, source_digest TEXT NOT NULL, config_digest TEXT NOT NULL,
    ledger_identity_json TEXT NOT NULL, owner_pid INTEGER NOT NULL, owner_birth TEXT NOT NULL,
    owner_logon_id TEXT NOT NULL, spec_hash TEXT NOT NULL, admission_binding_hash TEXT NOT NULL,
    demand_json TEXT NOT NULL, state TEXT NOT NULL CHECK(state='ADMITTED'),
    revision INTEGER NOT NULL CHECK(revision=0), binding_sha256 TEXT NOT NULL)"""
_MANAGED_IMMUTABLE = (
    "execution_id", "task_id", "session_id", "principal_id", "logon_id",
    "allocation_kind", "reservation_id", "parent_execution_id", "spec_hash",
    "wrapper_pid", "wrapper_created_filetime_100ns", "root_pid", "root_created_filetime_100ns",
    "job_name", "job_nonce", "role", "priority", "coverage", "guardian_epoch",
    "launch_in_flight", "launch_sealed", "claim_token_hash", "claim_consumed",
    "root_outcome", "created_at", "finished_at", "admission_binding_hash", "ipc_auth_key",
) + tuple(prefix + name for prefix in ("requested_", "floor_")
          for name in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots"))
_TRIGGER_SQL = {
    "experiment_reservation_delete_guard": """CREATE TRIGGER experiment_reservation_delete_guard
        BEFORE DELETE ON reservations WHEN EXISTS(SELECT 1 FROM adaptive_experiment_demands
            WHERE reservation_id=OLD.id OR execution_id=OLD.execution_id)
        BEGIN SELECT RAISE(ABORT,'experiment_native_cleanup_unverified'); END""",
    "experiment_reservation_update_guard": """CREATE TRIGGER experiment_reservation_update_guard
        BEFORE UPDATE ON reservations WHEN EXISTS(SELECT 1 FROM adaptive_experiment_demands
            WHERE reservation_id=OLD.id OR execution_id=OLD.execution_id)
        BEGIN SELECT RAISE(ABORT,'experiment_demand_immutable'); END""",
    "experiment_execution_update_guard": """CREATE TRIGGER experiment_execution_update_guard
        BEFORE UPDATE ON managed_executions WHEN
            EXISTS(SELECT 1 FROM adaptive_experiment_demands WHERE execution_id=OLD.execution_id) AND (
            NOT(NEW.state IS OLD.state OR (OLD.state='RESERVED' AND NEW.state='UNCERTAIN_HOLD')) OR """ +
        " OR ".join("NEW." + key + " IS NOT OLD." + key for key in _MANAGED_IMMUTABLE) + """ )
        BEGIN SELECT RAISE(ABORT,'experiment_native_cleanup_unverified'); END""",
    "experiment_execution_delete_guard": """CREATE TRIGGER experiment_execution_delete_guard
        BEFORE DELETE ON managed_executions WHEN EXISTS(SELECT 1 FROM adaptive_experiment_demands
            WHERE execution_id=OLD.execution_id)
        BEGIN SELECT RAISE(ABORT,'experiment_native_cleanup_unverified'); END""",
    "experiment_metadata_update_guard": """CREATE TRIGGER experiment_metadata_update_guard
        BEFORE UPDATE ON adaptive_experiment_demands
        BEGIN SELECT RAISE(ABORT,'experiment_native_cleanup_unverified'); END""",
    "experiment_metadata_delete_guard": """CREATE TRIGGER experiment_metadata_delete_guard
        BEFORE DELETE ON adaptive_experiment_demands
        BEGIN SELECT RAISE(ABORT,'experiment_native_cleanup_unverified'); END""",
}


class ExperimentDemandError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = reason, owner
        super().__init__(reason)


def _deny(reason, owner=None):
    raise ExperimentDemandError("experiment_" + reason, owner)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identity(path):
    value = Path(path).stat()
    return (int(value.st_dev), int(value.st_ino))


def _sql(value):
    return " ".join(value.split()).rstrip(";") if type(value) is str else None


def _read_json(path, *, limit):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        _deny("publication_oversized")
    value = json.loads(data.decode("utf-8-sig"),
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))
    if type(value) is not dict:
        _deny("publication_invalid")
    return value, hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class ExperimentDeclaration:
    experiment_id: str
    suite: str
    scope_sha256: str
    requested: ResourceDemand

    def __post_init__(self):
        try:
            valid_id = str(UUID(self.experiment_id)) == self.experiment_id and UUID(self.experiment_id).int != 0
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        if (not valid_id or self.suite not in {"S1", "S2", "S3", "P4", "P5", "P6"} or
                type(self.scope_sha256) is not str or not re.fullmatch("[0-9a-f]{64}", self.scope_sha256) or
                type(self.requested) is not ResourceDemand or self.requested.cpu_units > 64 or
                self.requested.physical_bytes > 58 * (1 << 30)):
            _deny("declaration_invalid")


def _schema(conn, *, create=False):
    if not conn.in_transaction:
        _deny("transaction_required")
    present = conn.execute("SELECT type,sql FROM sqlite_master WHERE name=?", (TABLE,)).fetchone()
    if present is None:
        if not create:
            _deny("metadata_missing")
        conn.execute(_TABLE_SQL)
        # These persist across older connections and owner death. The first
        # slice provides no native retirement authority, so all release routes
        # remain fenced, including direct store finalization and legacy DELETE.
        for statement in _TRIGGER_SQL.values():
            conn.execute(statement)
    elif present[0] != "table" or _sql(present[1]) != _sql(_TABLE_SQL):
        _deny("metadata_schema_unknown")
    if tuple(row[1] for row in conn.execute("PRAGMA table_info(" + TABLE + ")")) != _FIELDS:
        _deny("metadata_schema_unknown")
    actual = {row[0]: row[1] for row in conn.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'")}
    if any(_sql(actual.get(name)) != _sql(statement) for name, statement in _TRIGGER_SQL.items()):
        _deny("metadata_guards_unknown")
    if conn.execute("SELECT 1 FROM " + TABLE +
            " WHERE schema_version IS NOT 1 OR state IS NOT 'ADMITTED' OR revision IS NOT 0 LIMIT 1").fetchone():
        _deny("metadata_version_unknown")
    if len(conn.execute("SELECT experiment_id FROM " + TABLE + " LIMIT 2").fetchall()) > 1:
        _deny("metadata_scope_count_invalid")


@dataclass(frozen=True, init=False)
class BeforeNativeCompletion:
    """Positive original never-entered preparation, not capacity release."""
    owner: object
    digest: str

    def __init__(self, owner, digest, *, _token=None):
        if _token is not _BEFORE_NATIVE or type(owner) is not DailyExperimentDemand:
            _deny("original_completion_required")
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "digest", digest)

    def assert_original(self):
        owner = self.owner
        if (type(owner) is not DailyExperimentDemand or owner._before_native_completion is not self or
                not owner._native_preparation_sealed or owner._native_preparation is not None or
                owner._before_native_digest != self.digest):
            _deny("original_completion_changed", owner)
        owner._static_original()
        owner._assert_unused_claim()
        if (owner._before_native_binding != _canonical(owner._completion_binding()) or
                owner._before_native_digest != owner._before_native_hash() or
                owner._seal_connection is not None or owner._seal_connection_unknown):
            _deny("original_completion_changed", owner)

    def snapshot(self):
        """Fresh data only; callers must retain this exact capability as authority."""
        self.assert_original()
        return json.loads(self.owner._before_native_record)


class DailyExperimentDemand:
    """One original native caller, immutable declaration, and daily request.

    Construct only with capture(). Neither declarations nor observations are
    native authority. The inner unused launch capability is never exported.
    """
    def __init__(self, *, _token=None):
        if _token is not _CREATE:
            _deny("original_owner_required")
        self._lock = threading.RLock()
        self._admission = self._prepared = None
        self._generation_original = None
        self._original_admission = None
        self._errors = []
        self._quarantine = None
        self._closed = False
        self._native_preparation = None
        self._native_preparation_binding = None
        self._native_preparation_admission = None
        self._native_preparation_sealed = False
        self._before_native_completion = self._before_native_digest = None
        self._before_native_record = self._before_native_binding = None
        self._seal_connection = None
        self._seal_connection_unknown = False

    @classmethod
    def capture(cls, declaration, isolated_directory):
        if type(declaration) is not ExperimentDeclaration:
            _deny("declaration_required")
        source, data_directory = daily_generation.daily_locations()
        ledger = Path(data_directory) / "sentinel.db"
        daily_generation._assert_daily_locations(source, ledger)
        ledger = Path(ledger).resolve(strict=True)
        directory = Path(isolated_directory)
        if not directory.is_absolute() or directory.is_symlink():
            _deny("isolated_directory_required")
        for component in (directory, *directory.parents):
            info = component.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                _deny("isolated_directory_required")
        directory = directory.resolve(strict=True)
        if (not directory.is_dir() or directory == ledger.parent or ledger.parent in directory.parents or
                getattr(directory.stat(), "st_file_attributes", 0) & 0x400):
            _deny("isolated_directory_required")
        owner = cls(_token=_CREATE)
        owner.declaration, owner.directory, owner.ledger_path = declaration, directory, ledger
        owner.directory_identity, owner.ledger_identity = _identity(directory), _identity(ledger)
        owner._source_root = Path(source).resolve(strict=True)
        owner._immutable = (declaration, directory, ledger, owner.directory_identity,
                            owner.ledger_identity, owner._source_root)
        # Own the object before acquiring the native caller capability.
        if declaration.experiment_id in _RETAINED:
            _deny("original_owner_already_exists")
        _RETAINED[declaration.experiment_id] = owner
        try:
            owner._admission = ManagedAdmission.current(
                command="sentinel-native-experiment:" + declaration.suite + ":" +
                    declaration.experiment_id + ":" + declaration.scope_sha256,
                cwd=str(directory), repo_identifier="resource-sentinel-native-verification",
                requested=declaration.requested, role=Role.BACKGROUND, priority=Priority.P2)
            owner._original_admission = owner._admission
            owner._admission._experiment_demand = owner
            owner._snapshot = owner._admission.snapshot()
            return owner
        except BaseException as error:
            owner._errors.append(error)
            error.experiment_demand_owner = owner
            raise

    def _original(self):
        self._static_original()
        if (self._admission.snapshot() is not self._snapshot or
                _identity(self.ledger_path) != self.ledger_identity or
                _identity(self.directory) != self.directory_identity):
            _deny("original_binding_changed", self)

    def _completion_binding(self):
        """Original immutable data shared by either completion disposition."""
        snap = self._snapshot
        return dict(experiment_id=self.declaration.experiment_id, suite=self.declaration.suite,
            scope_sha256=self.declaration.scope_sha256, requested=self.declaration.requested.to_dict(),
            execution_id=snap.execution_id, request_key=snap.request.request_key,
            admission_binding_hash=snap.binding_hash, spec_hash=snap.spec_hash,
            caller_identity=snap.wrapper_identity.to_dict(), ledger_path=str(self.ledger_path),
            ledger_identity=list(self.ledger_identity), scope_directory=str(self.directory),
            scope_directory_identity=list(self.directory_identity), source_root=str(self._source_root),
            generation=None if self._prepared is None else dict(self._prepared[0]),
            generation_binding=self._original_generation_binding())

    def _original_generation_binding(self):
        """Return copied data from the original admission pin, never a fresh row."""
        original = getattr(self, "_generation_original", None)
        if type(original) is not str:
            _deny("original_generation_required", self)
        try:
            row = json.loads(original)
        except (ValueError, TypeError):
            _deny("original_generation_required", self)
        if (type(row) is not dict or set(row) != _GENERATION_FIELDS or
                row["state"] != "ACTIVE" or _canonical(row) != original):
            _deny("original_generation_required", self)
        return row

    def _generation_row(self, conn):
        """Read and bind the same SQL snapshot already checked by daily readiness."""
        if not conn.in_transaction:
            _deny("generation_transaction_required", self)
        row = daily_generation.read_generation(conn)
        if (type(row) is not dict or set(row) != _GENERATION_FIELDS or
                any(type(row[key]) is not int or row[key] != 1 for key in ("singleton", "schema_version")) or
                any(type(row[key]) is not str for key in _GENERATION_FIELDS - {"singleton", "schema_version"}) or
                row["state"] != "ACTIVE"):
            _deny("daily_generation_unverified", self)
        main = [value[2] for value in conn.execute("PRAGMA database_list") if value[1] == "main"]
        if (len(main) != 1 or Path(main[0]).resolve(strict=True) != self.ledger_path or
                _identity(self.ledger_path) != self.ledger_identity or
                row["ledger_path"] != str(self.ledger_path) or
                row["source_root"] != str(self._source_root) or
                row["ledger_identity_json"] != _canonical([str(value) for value in self.ledger_identity])):
            _deny("daily_generation_binding_changed", self)
        return row

    def _register_native_preparation(self, scope):
        """Called only by the concrete scope factory, before its first acquisition."""
        from .experiment_scope import ExperimentNativeScope, _OWNERS
        with self._lock:
            self._static_original()  # Pure original-object checks; no native query.
            if (type(scope) is not ExperimentNativeScope or scope.demand is not self or
                    _OWNERS.get(scope.scope_id) is not scope):
                _deny("original_native_preparation_required", self)
            if self._native_preparation_sealed or self._native_preparation is not None:
                _deny("native_preparation_already_registered", self)
            self._native_preparation_binding = _canonical(self._completion_binding())
            self._native_preparation_admission = self._admission
            self._native_preparation = scope

    def _assert_native_preparation(self, scope):
        from .experiment_scope import ExperimentNativeScope, _OWNERS
        if (type(scope) is not ExperimentNativeScope or self._native_preparation is not scope or
                _RETAINED.get(self.declaration.experiment_id) is not self or
                _OWNERS.get(scope.scope_id) is not scope or scope.demand is not self or
                self._admission is not self._native_preparation_admission or
                getattr(self._admission, "_experiment_demand", None) is not self or
                self._native_preparation_binding != _canonical(self._completion_binding())):
            _deny("original_native_preparation_changed", self)

    def _seal_native_preparation(self, scope):
        with self._lock:
            self._assert_native_preparation(scope)
            self._native_preparation_sealed = True

    def _assert_unused_claim(self):
        inner = self._admission
        inner._require_settled_submission()
        if (not inner._submitted or inner._claim_exported or inner._prepare_attempted or
                inner._submission_policy is None or inner._abandon_target is not None or
                inner._submission_transaction is None or
                inner._submission_transaction.get("connection_closed") is not True):
            _deny("unused_daily_claim_required", self)

    def _before_native_hash(self):
        return hashlib.sha256(("experiment-before-native-v1\n" + self._before_native_record).encode()).hexdigest()

    def _validate_completion_connection(self, conn):
        """Bind this read transaction to the original ledger, without readiness."""
        if conn is not self._seal_connection or not conn.in_transaction:
            _deny("completion_connection_changed", self)
        main = [row[2] for row in conn.execute("PRAGMA database_list") if row[1] == "main"]
        if (len(main) != 1 or Path(main[0]).resolve(strict=True) != self.ledger_path or
                _identity(self.ledger_path) != self.ledger_identity):
            _deny("completion_ledger_changed", self)

    def seal_without_native(self):
        """Seal forever; mint only after original unused admitted custody settles.

        This read-only proof cannot cancel a reservation. An uncertain read or
        close retains the original operation; it never opens a replacement.
        """
        with self._lock:
            self._native_preparation_sealed = True
            self._static_original()
            if self._native_preparation is not None:
                _deny("native_preparation_entered", self)
            if self._before_native_completion is not None:
                self._before_native_completion.assert_original()
                return self._before_native_completion
            inner = self._admission
            with inner._lock:
                self._assert_unused_claim()
                if (inner._cancel_sealed or inner._claim_token is None or
                        hashlib.sha256(inner._claim_token.encode("ascii")).hexdigest() != self._snapshot.claim_token_hash or
                        inner.snapshot() is not self._snapshot or
                        _identity(self.ledger_path) != self.ledger_identity or
                        _identity(self.directory) != self.directory_identity):
                    _deny("unused_daily_claim_required", self)
                if self._seal_connection_unknown or self._seal_connection is not None:
                    _deny("completion_read_unsettled", self)
                primary = None
                self._seal_connection_unknown = True
                try:
                    self._seal_connection = sqlite3.connect(self.ledger_path.as_uri() + "?mode=ro",
                        uri=True, timeout=.25, isolation_level=None)
                    self._seal_connection_unknown = False
                    conn = self._seal_connection
                    conn.row_factory = sqlite3.Row
                    conn.execute("BEGIN")
                    self._validate_completion_connection(conn)
                    _schema(conn)
                    row = conn.execute("SELECT * FROM " + TABLE + " WHERE experiment_id=?",
                        (self.declaration.experiment_id,)).fetchone()
                    if row is None or dict(row) != self._binding(row["reservation_id"]):
                        _deny("admitted_demand_required", self)
                    execution = conn.execute("SELECT * FROM managed_executions WHERE execution_id=?",
                        (self._snapshot.execution_id,)).fetchone()
                    unused = dict(claim_consumed=0, launch_sealed=0, launch_in_flight=0,
                        claim_token_hash=self._snapshot.claim_token_hash, job_name=None, job_nonce=None,
                        root_pid=None, root_created_filetime_100ns=None, root_outcome=None, guardian_epoch="")
                    if (execution is None or execution["state"] not in {"RESERVED", "UNCERTAIN_HOLD"} or
                            any(execution[key] != value for key, value in unused.items())):
                        _deny("unused_daily_claim_required", self)
                    self._validate_completion_connection(conn)
                    binding = self._completion_binding()
                    record = dict(schema_version=1, disposition="BEFORE_NATIVE", demand=binding,
                        reservation_id=row["reservation_id"], daily_binding_sha256=row["binding_sha256"],
                        native_preparation=None)
                    conn.rollback()
                except BaseException as error:
                    primary = error
                    self._retain_submission_error(error)
                    raise
                finally:
                    if self._seal_connection is not None:
                        self._seal_connection_unknown = True
                        try:
                            self._seal_connection.close()
                        except BaseException as error:
                            self._quarantine = (self._seal_connection, error)
                            error.experiment_connection_owner = self._seal_connection
                            self._retain_submission_error(error)
                            if primary is None:
                                raise
                            primary.add_note("experiment_completion_connection_cleanup_unverified")
                        else:
                            self._seal_connection = None
                            self._seal_connection_unknown = False
                self._before_native_binding = _canonical(binding)
                self._before_native_record = _canonical(record)
                self._before_native_digest = self._before_native_hash()
                self._before_native_completion = BeforeNativeCompletion(self, self._before_native_digest,
                    _token=_BEFORE_NATIVE)
                return self._before_native_completion

    def _retain_submission_error(self, error):
        """Keep failures from every downstream daily readiness connection.

        A plain COMMIT acknowledgement loss remains reconcilable by the inner
        original POLICY owner. Attached native/connection obligations cannot
        be discarded by starting another preparation operation.
        """
        self._errors.append(error)
        error.experiment_demand_owner = self
        pending, seen = [error], set()
        custody_attributes = ("daily_readiness_current_process", "_identity_handle_cleanup",
            "_policy_mutex_cleanup", "_daily_readiness_connection", "_daily_readiness_owner",
            "daily_readiness_scope", "_daily_readiness_authority",
            "_sentinel_connection_cleanup", "_native_close_outcome_unknown",
            "_native_duplicate_outcome_unknown", "io_pending")
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            if len(seen) > 32 or any(getattr(current, key, None) for key in custody_attributes):
                if self._quarantine is None:
                    self._quarantine = (self._admission, error)
                return
            pending.extend(cause for cause in (getattr(current, "__cause__", None),
                getattr(current, "__context__", None), getattr(current, "_daily_readiness_cause", None))
                if isinstance(cause, BaseException))

    def _static_original(self):
        if (self._closed or self._quarantine is not None or
                self.declaration is not self._immutable[0] or
                (self.declaration, self.directory, self.ledger_path, self.directory_identity,
                 self.ledger_identity, self._source_root) != self._immutable or
                _RETAINED.get(self.declaration.experiment_id) is not self or
                type(self._admission) is not ManagedAdmission or
                self._admission is not self._original_admission or
                getattr(self._admission, "_experiment_demand", None) is not self or
                self._snapshot.requested != self.declaration.requested):
            _deny("original_binding_changed", self)

    def _prepare_submission(self, coordinator):
        """Fresh native generation proof outside the capacity transaction."""
        from sentinel.coordinator import Coordinator
        with self._lock:
            self._original()
            if self._native_preparation_sealed:
                _deny("preparation_sealed", self)
            if self._generation_original is None:
                if self._prepared is not None or self._admission._submitted:
                    _deny("original_generation_required", self)
            else:
                self._original_generation_binding()
            if type(coordinator) is not Coordinator or Path(coordinator.db_path).resolve(strict=True) != self.ledger_path:
                _deny("daily_coordinator_required", self)
            conn = sqlite3.connect(self.ledger_path.as_uri() + "?mode=ro", uri=True,
                                   timeout=.25, isolation_level=None)
            conn.row_factory = sqlite3.Row
            primary = None
            try:
                try:
                    generation = daily_generation.prepare_connection(conn, role="coordinator", db_path=self.ledger_path)
                except BaseException as error:
                    # A readiness attempt can retain caller/transport/handle
                    # custody on its exception. None is permission to open a
                    # replacement operation. Conservatively retain every failed
                    # readiness attempt until that original is reconciled.
                    self._quarantine = (conn, error)
                    raise
                if generation is None:
                    _deny("daily_generation_unverified", self)
                # Bind the captured row to the original authenticated authority
                # on this same read snapshot. A row read after prepare_connection
                # without BEGIN could otherwise change before it becomes origin.
                conn.execute("BEGIN")
                daily_generation.revalidate_transaction(conn, db_path=self.ledger_path)
                row = self._generation_row(conn)
                if row["generation"] != generation:
                    _deny("daily_generation_unverified", self)
                original = _canonical(row)
                if self._generation_original is not None and self._generation_original != original:
                    _deny("daily_generation_changed", self)
                pin = {key: row[key] for key in ("generation", "source_digest", "config_digest")}
                if self._prepared is not None and self._prepared[0] != pin:
                    _deny("daily_generation_changed", self)
                config, digest = _read_json(self.ledger_path.with_name("config.json"), limit=1024 * 1024)
                if digest != pin["config_digest"]:
                    _deny("daily_config_changed", self)
                status, _ = _read_json(self.ledger_path.with_name("status.json"), limit=4 * 1024 * 1024)
                if _canonical(self._generation_row(conn)) != original:
                    _deny("daily_generation_changed", self)
                prepared_until = time.monotonic() + 2
                conn.rollback()
            except BaseException as error:
                primary = error
                self._errors.append(error)
                error.experiment_demand_owner = self
                raise
            finally:
                try:
                    conn.close()
                except BaseException as error:
                    # Preserve the original SQL object; no implicit retry of
                    # a close whose completion may be unknown.
                    self._errors.append(error)
                    self._quarantine = (conn, error)
                    error.experiment_connection_owner = conn
                    error.experiment_demand_owner = self
                    error.add_note("experiment_read_connection_cleanup_unverified")
                    if primary is None:
                        raise
                    primary.add_note("experiment_read_connection_cleanup_unverified")
            # Only the same reader's positive close publishes the first pin.
            # A failed close keeps quarantine and cannot establish an origin.
            if self._generation_original is None:
                self._generation_original = original
            self._prepared = (pin, prepared_until)
            return self._admission, status, config

    def _locked(self, conn, snapshot, policy):
        self._static_original()
        if self._native_preparation_sealed:
            _deny("preparation_sealed", self)
        if (self._prepared is None or time.monotonic() >= self._prepared[1] or
                snapshot is not self._snapshot or getattr(self._admission, "_experiment_demand", None) is not self):
            _deny("prepared_original_required", self)
        guard = policy.assert_held()
        runtime = policy.revalidate(conn, guard)
        if runtime["mode"] != "off" or guard.binding.logon_id != snapshot.logon_id:
            _deny("daily_off_required", self)
        self._original_generation_binding()
        row = self._generation_row(conn)
        if (_canonical(row) != self._generation_original or
                any(row[key] != value for key, value in self._prepared[0].items())):
            _deny("daily_generation_changed", self)
        main = [r[2] for r in conn.execute("PRAGMA database_list") if r[1] == "main"]
        if len(main) != 1 or Path(main[0]).resolve() != self.ledger_path:
            _deny("daily_ledger_required", self)
        _schema(conn, create=True)

    def admission_blocker_locked(self, conn, snapshot, policy):
        self._locked(conn, snapshot, policy)
        # This serial test-run guard is separate from production Job and user
        # exemption limits. It never grants or changes either policy.
        row = conn.execute("SELECT experiment_id FROM " + TABLE + " LIMIT 1").fetchone()
        return None if row is None or row[0] == self.declaration.experiment_id else "experiment_scope_occupied"

    def _binding(self, reservation_id):
        spec, snap = self.declaration, self._snapshot
        values = dict(experiment_id=spec.experiment_id, schema_version=1,
            execution_id=snap.execution_id, reservation_id=reservation_id, request_key=snap.request.request_key,
            suite=spec.suite, scope_sha256=spec.scope_sha256, scope_directory=str(self.directory),
            scope_identity_json=_canonical(self.directory_identity), source_generation=self._prepared[0]["generation"],
            source_digest=self._prepared[0]["source_digest"], config_digest=self._prepared[0]["config_digest"],
            ledger_identity_json=_canonical(self.ledger_identity), owner_pid=snap.wrapper_identity.pid,
            owner_birth=str(snap.wrapper_identity.created_filetime_100ns), owner_logon_id=snap.logon_id,
            spec_hash=snap.spec_hash, admission_binding_hash=snap.binding_hash,
            demand_json=_canonical(spec.requested.to_dict()), state="ADMITTED", revision=0)
        values["binding_sha256"] = hashlib.sha256(_canonical(values).encode()).hexdigest()
        return values

    def publish_locked(self, conn, snapshot, policy, result, *, replay):
        self._locked(conn, snapshot, policy)
        expected = self._binding(result["reservation_id"])
        rows = conn.execute("SELECT * FROM " + TABLE + " WHERE experiment_id=? OR execution_id=? OR reservation_id=?",
            (self.declaration.experiment_id, snapshot.execution_id, result["reservation_id"])).fetchall()
        if replay:
            if len(rows) != 1 or dict(rows[0]) != expected:
                _deny("replay_metadata_unverified", self)
        else:
            if rows:
                _deny("metadata_already_exists", self)
            conn.execute("INSERT INTO " + TABLE + "(" + ",".join(_FIELDS) + ") VALUES(" +
                ",".join("?" for _ in _FIELDS) + ")", tuple(expected[k] for k in _FIELDS))
        return result | {"experiment_id": self.declaration.experiment_id,
                         "native_scope_authorized": False}

    def require_native_scope(self):
        _deny("scope_binding_unavailable", self)

    def close_unsubmitted(self):
        """Close only an original context that never submitted any demand."""
        with self._lock:
            self._original()
            inner = self._admission
            with inner._lock:
                if inner._submitted:
                    _deny("native_cleanup_unverified", self)
                inner._require_settled_submission()
                try:
                    inner._process.close()
                except BaseException as error:
                    self._errors.append(error)
                    self._quarantine = (inner._process, error)
                    error.experiment_demand_owner = self
                    raise
                inner._closed = self._closed = True
                inner._claim_token = inner._key = inner._snapshot = self._snapshot = None
                _RETAINED.pop(self.declaration.experiment_id, None)
