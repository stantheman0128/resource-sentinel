"""One S1-only, distinct wrapper launch with original native custody.

This is a mechanism for ExperimentNativeScope, not admission/control authority.
prepare() runs outside POLICY/Job locks; create_inert() only creates the inert
wrapper; launch_once() obtains the original scope's authorization before IPC.
No timeout, wire record or process exit is a native-cleanup capability.
"""
from __future__ import annotations

from dataclasses import dataclass
import ctypes as C
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from uuid import UUID, uuid4


_OWNERS = {}
_NEW = object()
_MAX_SOURCE = 1024 * 1024
_SCHEMA = 1


class ScopeLaunchError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = reason, owner
        self.scope_launch_owner = owner
        super().__init__(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _absolute(value):
    if type(value) is not str or not value or "\x00" in value or not Path(value).is_absolute():
        raise ScopeLaunchError("scope_path_invalid")
    return value


def _regular(path):
    path = Path(_absolute(str(path)))
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ScopeLaunchError("scope_source_redirected")
    if not path.is_file():
        raise ScopeLaunchError("scope_source_not_file")
    return path


@dataclass(frozen=True)
class FixtureSource:
    path: str
    sha256: str
    size: int
    file_identity: tuple[int, int]

    def __post_init__(self):
        _absolute(self.path)
        if (type(self.sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None or
                type(self.size) is not int or not 0 < self.size <= _MAX_SOURCE or
                type(self.file_identity) is not tuple or len(self.file_identity) != 2 or
                any(type(v) is not int or v < 0 for v in self.file_identity)):
            raise ScopeLaunchError("scope_source_invalid")

    @classmethod
    def capture(cls, path):
        path = _regular(path)
        before = path.stat()
        with path.open("rb") as stream:
            data = stream.read(_MAX_SOURCE + 1)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ScopeLaunchError("scope_source_changed")
        return cls(str(path.resolve(strict=True)), hashlib.sha256(data).hexdigest(),
                   len(data), (int(after.st_dev), int(after.st_ino)))

    def verify(self):
        if FixtureSource.capture(self.path) != self:
            raise ScopeLaunchError("scope_source_changed")

    def to_dict(self):
        return dict(path=self.path, sha256=self.sha256, size=self.size,
                    file_identity=list(self.file_identity))

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"path", "sha256", "size", "file_identity"}:
            raise ScopeLaunchError("scope_source_invalid")
        if type(value["file_identity"]) is not list:
            raise ScopeLaunchError("scope_source_invalid")
        return cls(value["path"], value["sha256"], value["size"], tuple(value["file_identity"]))


@dataclass(frozen=True)
class ScopeCommand:
    application: str
    arguments: tuple[str, ...]
    cwd: str
    fixture_sources: tuple[FixtureSource, ...]

    def __post_init__(self):
        _absolute(self.application)
        _absolute(self.cwd)
        if (type(self.arguments) is not tuple or not 1 <= len(self.arguments) <= 128 or
                any(type(v) is not str or "\x00" in v or len(v) > 32767 or
                    any(0xD800 <= ord(c) <= 0xDFFF for c in v) for v in self.arguments) or
                type(self.fixture_sources) is not tuple or not 1 <= len(self.fixture_sources) <= 8 or
                any(type(v) is not FixtureSource for v in self.fixture_sources) or
                len({v.path for v in self.fixture_sources}) != len(self.fixture_sources) or
                len(self.arguments) < 2 or self.arguments[0] != "-I" or
                self.arguments[1] not in {v.path for v in self.fixture_sources}):
            raise ScopeLaunchError("scope_command_invalid")
        if len(self.command_line.encode("utf-16-le")) // 2 + 1 > 32767:
            raise ScopeLaunchError("scope_command_too_long")

    @classmethod
    def capture(cls, *, application, arguments, cwd, fixture_paths):
        return cls(str(Path(application).resolve(strict=True)), tuple(arguments),
                   str(Path(cwd).resolve(strict=True)),
                   tuple(FixtureSource.capture(path) for path in fixture_paths))

    @property
    def command_line(self):
        return subprocess.list2cmdline((self.application, *self.arguments))

    @property
    def sha256(self):
        return digest(self.to_dict())

    def verify(self):
        for source in self.fixture_sources:
            source.verify()
        if not Path(self.cwd).is_dir():
            raise ScopeLaunchError("scope_directory_changed")

    def to_dict(self):
        return dict(application=self.application, arguments=list(self.arguments), cwd=self.cwd,
                    fixture_sources=[source.to_dict() for source in self.fixture_sources])

    @classmethod
    def from_dict(cls, value):
        if (type(value) is not dict or
                set(value) != {"application", "arguments", "cwd", "fixture_sources"} or
                type(value["arguments"]) is not list or type(value["fixture_sources"]) is not list):
            raise ScopeLaunchError("scope_command_invalid")
        return cls(value["application"], tuple(value["arguments"]), value["cwd"],
                   tuple(FixtureSource.from_dict(row) for row in value["fixture_sources"]))


class OnceLaunchState:
    """Process-local at-most-once state; wire payloads cannot recreate it."""
    def __init__(self, command_sha256):
        self.command_sha256 = command_sha256
        self.attempted = self.sealed = False
        self.request_id = None
        self._bounds = None

    def begin(self, request_id, command_sha256, *, launch_bounds=None):
        if not _uuid(request_id) or command_sha256 != self.command_sha256:
            raise ScopeLaunchError("scope_request_changed")
        bounds = None if launch_bounds is None else canonical(validate_launch_bounds(launch_bounds))
        if self.attempted:
            if request_id != self.request_id or bounds != self._bounds:
                raise ScopeLaunchError("scope_second_launch_refused")
            return False
        if self.sealed:
            raise ScopeLaunchError("scope_launch_sealed")
        # Retain the attempt BEFORE any open/lock/Create side effect.
        self.request_id, self.attempted = request_id, True
        self._bounds = bounds
        return True

    def seal(self):
        self.sealed = True


def validate_launch_bounds(value):
    if (type(value) is not dict or set(value) != {
            "reservation_id", "binding_sha256", "expires_at", "lease_deadline_monotonic_ns"} or
            type(value["reservation_id"]) is not str or not 1 <= len(value["reservation_id"]) <= 128 or
            "\x00" in value["reservation_id"] or type(value["binding_sha256"]) is not str or
            re.fullmatch(r"[0-9a-f]{64}", value["binding_sha256"]) is None or
            type(value["expires_at"]) not in (int, float) or not math.isfinite(value["expires_at"]) or
            value["expires_at"] <= 0 or type(value["lease_deadline_monotonic_ns"]) is not int or
            value["lease_deadline_monotonic_ns"] <= 0):
        raise ScopeLaunchError("scope_launch_bounds_invalid")
    return dict(value)


def validate_generation(value):
    from sentinel.adaptive.daily_generation import _GENERATION_FIELDS
    if (type(value) is not dict or set(value) != _GENERATION_FIELDS or
            any(type(value[key]) is not int or value[key] != 1 for key in ("singleton", "schema_version")) or
            any(type(value[key]) is not str for key in _GENERATION_FIELDS - {"singleton", "schema_version"}) or
            value["state"] != "ACTIVE" or not _uuid(value["generation"]) or
            not _uuid(value["readiness_instance_id"]) or
            any(re.fullmatch(r"[0-9a-f]{64}", value[key]) is None for key in ("source_digest", "config_digest"))):
        raise ScopeLaunchError("scope_source_generation_changed")
    _absolute(value["source_root"])
    _absolute(value["ledger_path"])
    return dict(value)


def request(operation, scope_id, request_id, command_sha256, *, launch_bounds=None):
    if operation not in {"launch", "observe", "seal", "drain"} or not _uuid(scope_id) or not _uuid(request_id):
        raise ScopeLaunchError("scope_request_invalid")
    if type(command_sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", command_sha256) is None:
        raise ScopeLaunchError("scope_request_invalid")
    value = dict(schema_version=2 if operation == "launch" else _SCHEMA,
        kind="S1ScopeRequest", operation=operation, scope_id=scope_id,
        request_id=request_id, command_sha256=command_sha256)
    if operation == "launch":
        value["launch_bounds"] = validate_launch_bounds(launch_bounds)
    elif launch_bounds is not None:
        raise ScopeLaunchError("scope_launch_bounds_invalid")
    return value


def validate_request(value, scope_id, command_sha256):
    if type(value) is not dict:
        raise ScopeLaunchError("scope_request_invalid")
    fields = {"schema_version", "kind", "operation", "scope_id", "request_id", "command_sha256"}
    if set(value) != fields | ({"launch_bounds"} if value.get("operation") == "launch" else set()):
        raise ScopeLaunchError("scope_request_invalid")
    if type(value["schema_version"]) is not int:
        raise ScopeLaunchError("scope_request_invalid")
    expected = request(value["operation"], scope_id, value["request_id"], command_sha256,
        launch_bounds=value.get("launch_bounds"))
    if value != expected:
        raise ScopeLaunchError("scope_request_changed")
    return value


def receipt(value):
    return dict(schema_version=_SCHEMA, kind="S1ScopeReceipt", scope_id=value["scope_id"],
                request_id=value["request_id"], result_sha256=digest(value))


def receipt_confirmation(value):
    # The client sends the final frame. A server disconnect must not discard
    # a receipt that the client has not yet read and validated.
    return receipt(value) | {"kind": "S1ScopeReceiptConfirmed"}


@dataclass(frozen=True)
class ScopeDrainStatus:
    """Drain readiness only; ScopeLaunch.close still owns parent native handles."""
    scope_id: str
    launch_sealed: bool
    root_dead: bool
    job_empty: bool
    cpu_disabled: bool
    wrapper_local_closed: bool
    wrapper_exited: bool
    transport_closed: bool
    complete: bool


def _retain(error, owner):
    owner.errors.append(error)
    error.scope_launch_owner = owner
    return error


class ScopeLaunch:
    """Retain the original wrapper/root/transport through positive cleanup.

    root_witness and wrapper_witness are BORROWED observations; the original
    scope must not close them. This owner closes them only at final close().
    """
    def __init__(self, *, _token=None):
        if _token is not _NEW:
            raise ScopeLaunchError("scope_original_factory_required")
        self._lock = threading.RLock()
        self.errors = []
        self.process = self.wrapper_witness = self.root_witness = None
        self.listener = self.connection = self.registry = None
        self.job = None
        self._created = self._launch_attempted = self._authorized = False
        self._wrapper_create_entered = self._command_dispatched = False
        self._transfer_attempted = self._sealed = self._closed = False
        self._transport_unknown = self._wrapper_local_closed = False
        self._drain_receipt_sent = self._transport_closed = False
        self._close_started = False
        self._source_connection = None
        self._source_close_unknown = False
        self._last_result = None
        self._root_offer = None
        self._root_membership_verified = False
        self._root_membership_binding = None
        self._launch_bounds = self._original_launch_bounds = None
        self._request_marker = None
        self._request_ids = {name: str(uuid4()) for name in ("launch", "observe", "seal", "drain")}

    @classmethod
    def prepare(cls, demand, command, scope_id, job_nonce, deadline):
        """Before native Create, outside POLICY/Job locks; retain every owner."""
        from sentinel.adaptive.experiment_demand import DailyExperimentDemand
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeListener, NativePipeRegistry
        from sentinel.adaptive.daily_generation import read_generation, SourceManifest, verify_import_provenance
        if (type(demand) is not DailyExperimentDemand or type(command) is not ScopeCommand or
                not _uuid(scope_id) or type(job_nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", job_nonce) is None or
                type(deadline) not in (int, float) or not math.isfinite(deadline) or
                not 0 < deadline - time.monotonic() <= 120):
            raise ScopeLaunchError("scope_prepare_invalid")
        demand._original()
        base = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
        if Path(sys.executable).resolve(strict=True) != base or Path(command.application).resolve(strict=True) != base:
            raise ScopeLaunchError("scope_base_python_required")
        if scope_id in _OWNERS:
            raise ScopeLaunchError("scope_original_exists")
        owner = cls(_token=_NEW)
        owner.demand, owner.command, owner.scope_id, owner.job_nonce, owner.deadline = (
            demand, command, scope_id, job_nonce, deadline)
        owner.guardian = demand._admission._process
        if type(owner.guardian) is not VerifiedProcess:
            raise ScopeLaunchError("scope_original_guardian_required")
        owner.guardian_identity = owner.guardian.identity
        owner.job_name = "Local\\ResourceSentinel.Test.Job." + job_nonce
        _OWNERS[scope_id] = owner
        try:
            command.verify()
            # The explicit fixture closure is finite; never install/copy tests.
            owner.fixture_sources = tuple(FixtureSource.capture(path) for path in (
                Path(__file__).resolve(), Path(__file__).with_name("adaptive_scope_wrapper.py").resolve()))
            connection = owner._source_connection = sqlite3.connect(demand.ledger_path.as_uri() + "?mode=ro",
                uri=True, timeout=.25, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN")
            generation = read_generation(connection)
            original_generation = validate_generation(demand._original_generation_binding())
            metadata = connection.execute("SELECT * FROM adaptive_experiment_demands WHERE experiment_id=?",
                (demand.declaration.experiment_id,)).fetchone()
            if (generation != original_generation or metadata is None or
                    dict(metadata) != demand._binding(metadata["reservation_id"])):
                raise ScopeLaunchError("scope_source_generation_changed")
            owner.reservation_id, owner.binding_sha256 = metadata["reservation_id"], metadata["binding_sha256"]
            connection.rollback()
            owner._source_close_unknown = True
            connection.close()
            owner._source_connection = None
            owner._source_close_unknown = False
            manifest = SourceManifest.from_dict(json.loads(generation["source_manifest_json"]))
            verify_import_provenance(manifest, demand._source_root)
            owner.endpoint = NativePipeEndpoint(owner.guardian_identity.logon_id, str(uuid4()), owner.guardian_identity)
            owner.registry = NativePipeRegistry(max_resources=4)
            owner.listener = NativePipeListener(owner.endpoint, registry=owner.registry)
            payload = dict(schema_version=2, scope_id=scope_id, job_nonce=job_nonce,
                job_name=owner.job_name, guardian_identity=owner.guardian_identity.to_dict(),
                endpoint_instance=owner.endpoint.instance_id, deadline_monotonic=deadline,
                command=command.to_dict(), command_sha256=command.sha256,
                canonical_source=str(demand._source_root), generation=original_generation,
                reservation_id=owner.reservation_id, binding_sha256=owner.binding_sha256,
                request_marker=str(demand.directory / ("scope-request-" + scope_id + ".json")),
                fixture_sources=[source.to_dict() for source in owner.fixture_sources],
                python_sha256=hashlib.sha256(base.read_bytes()).hexdigest())
            owner.bootstrap_path = demand.directory / ("scope-wrapper-" + scope_id + ".json")
            data = canonical(payload)
            if len(data) > 2 * _MAX_SOURCE:
                raise ScopeLaunchError("scope_bootstrap_too_large")
            with owner.bootstrap_path.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            owner.bootstrap_sha256 = hashlib.sha256(data).hexdigest()
            owner._request_marker = Path(payload["request_marker"])
            owner.wrapper_command_line = subprocess.list2cmdline((str(base), "-I",
                owner.fixture_sources[1].path, "--bootstrap", str(owner.bootstrap_path),
                "--bootstrap-sha256", owner.bootstrap_sha256))
            return owner
        except BaseException as error:
            raise _retain(error, owner)

    def create_inert(self, *, native_deadline=None):
        """Native creation only; no pipe/readiness RPC under parent locks."""
        from sentinel.adaptive import native_launcher as native
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.pipe_windows import NativeDeadline
        if native_deadline is not None and type(native_deadline) is not NativeDeadline:
            raise ValueError("scope_wrapper_deadline_invalid")
        with self._lock:
            if self._created or self._closed or self._sealed:
                raise ScopeLaunchError("scope_wrapper_creation_repeated", self)
            self._created = True
            owner = self.process = native.CreatedProcess(native._WindowsBackend(), self.guardian_identity.logon_id)
            startup = native._StartupInfoEx()
            startup.StartupInfo.cb = C.sizeof(native._StartupInfo)
            info = owner._unverified_process_info
            try:
                if time.monotonic() >= self.deadline:
                    raise ScopeLaunchError("scope_deadline_expired")
                for source in self.fixture_sources:
                    source.verify()
                command_buffer = C.create_unicode_buffer(self.wrapper_command_line)
                if time.monotonic() >= self.deadline:
                    raise ScopeLaunchError("scope_deadline_expired")
                if native_deadline is not None:
                    native_deadline.require()
                owner._creation_outcome = "unknown"
                self._wrapper_create_entered = True
                created = owner._backend.kernel.CreateProcessW(self.command.application,
                    command_buffer, None, None, False,
                    0x08000000, None, self.command.cwd, C.byref(startup), C.byref(info))
                owner._creation_outcome = "created" if created else "not_created"
                if created:
                    owner.handle, owner.pid, owner._thread = info.hProcess, int(info.dwProcessId), info.hThread
                owner._backend.check(created, "scope_wrapper_create_failed")
                native._handle(owner.handle)
                native._handle(owner._thread)
                with owner._lock:
                    self.wrapper_witness = VerifiedProcess.duplicate_from_handle(owner._live_handle(),
                        expected_pid=owner.pid, expected_logon_id=self.guardian_identity.logon_id)
                if self.wrapper_witness.identity == self.guardian_identity or self.wrapper_witness.is_in_job(None) is not False:
                    raise ScopeLaunchError("scope_wrapper_foreign_job")
                owner._cleanup_transient()
                return self.wrapper_witness
            except BaseException as error:
                raise _retain(error, self)

    def _job(self, job):
        from sentinel.adaptive.native_job import NativeJob
        if (type(job) is not NativeJob or job.name != self.job_name or job.nonce != self.job_nonce or
                job.logon_sid != self.guardian_identity.logon_id or self.job not in (None, job)):
            raise ScopeLaunchError("scope_job_changed", self)
        self.job = job

    def launch_once(self, job, registration):
        from sentinel.adaptive.experiment_scope import ExperimentNativeScope
        with self._lock:
            self._job(job)
            if type(registration) is not ExperimentNativeScope or self._launch_attempted or self._sealed:
                raise ScopeLaunchError("scope_launch_authority_required", self)
            self._launch_attempted = True
            try:
                self._launch_bounds = validate_launch_bounds(registration._authorize_launch(self, job))
                if (self._launch_bounds["reservation_id"] != self.reservation_id or
                        self._launch_bounds["binding_sha256"] != self.binding_sha256):
                    raise ScopeLaunchError("scope_launch_binding_changed")
                self._original_launch_bounds = canonical(self._launch_bounds)
                self._authorized = True
                result = self._exchange("launch")
                if self.root_witness is None:
                    raise ScopeLaunchError("scope_root_unverified")
                self._require_launch_success(result)
                return self.root_witness
            except BaseException as error:
                raise _retain(error, self)

    @staticmethod
    def _require_launch_success(result):
        if (result["attempted"] is not True or result["sealed"] is not False or
                result["creation_outcome"] != "created" or
                result["reason"] != "scope_observed" or result["local_closed"] is not False):
            raise ScopeLaunchError("scope_launch_unverified")

    def reconcile_launch(self):
        """Borrow recovery custody; never retry or turn an earlier error into success."""
        with self._lock:
            if not self._authorized:
                raise ScopeLaunchError("scope_launch_authorization_unverified", self)
            self._exchange("observe")
            return self.root_witness

    def observe_root(self):
        if self.root_witness is None:
            raise ScopeLaunchError("scope_root_unavailable", self)
        return self.root_witness.observe()

    @property
    def root_job_bound(self):
        """Original transfer/query provenance, including a subsequently exited root.

        This is not wire membership or liveness. The parent must retain this
        same original launcher, Job and witness to use the historical fact.
        """
        bound = self._root_membership_binding
        return (_OWNERS.get(self.scope_id) is self and self._root_membership_verified and bound is not None and
                bound[0] is self.root_witness and bound[1] is self.job and
                self.root_witness is not None and bound[2] == self.root_witness.identity)

    def _exchange(self, operation):
        from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
        from sentinel.adaptive.pipe_windows import NativeDeadline
        from sentinel.adaptive.ipc import read_frame, write_frame
        if self._transport_unknown or self._transport_closed or self.wrapper_witness is None:
            raise ScopeLaunchError("scope_transport_unavailable", self)
        if self.wrapper_witness.observe().status is not IdentityStatus.ALIVE:
            raise ScopeLaunchError("scope_wrapper_not_alive", self)
        if operation == "launch" and time.monotonic() >= self.deadline:
            raise ScopeLaunchError("scope_deadline_expired", self)
        deadline = NativeDeadline.after_ms(5000)
        connection = None
        try:
            # Wakeup only. The wrapper cannot act on this untrusted file: the
            # request still arrives over its verified native guardian pipe.
            marker = dict(scope_id=self.scope_id, nonce=str(uuid4()))
            temporary = self._request_marker.with_suffix(".pending")
            with temporary.open("xb") as stream:
                stream.write(canonical(marker))
                stream.flush()
            os.replace(temporary, self._request_marker)
            connection = self.connection = self.listener.accept(deadline)
            with connection.verified_peer(self.wrapper_witness.identity) as peer:
                hello = read_frame(connection, deadline)
                expected = dict(schema_version=1, kind="S1ScopeHello", scope_id=self.scope_id,
                    wrapper_identity=self.wrapper_witness.identity.to_dict(), command_sha256=self.command.sha256)
                if hello != expected or peer.identity != self.wrapper_witness.identity:
                    raise ScopeLaunchError("scope_wrapper_auth_failed")
                bounds = None
                if operation == "launch":
                    bounds = validate_launch_bounds(self._launch_bounds)
                    if canonical(bounds) != self._original_launch_bounds:
                        raise ScopeLaunchError("scope_launch_binding_changed")
                outgoing = request(operation, self.scope_id, self._request_ids[operation], self.command.sha256,
                    launch_bounds=bounds)
                if operation == "launch":
                    self._command_dispatched = True  # unknown delivery still forbids another attempt
                write_frame(connection, outgoing, deadline)
                result = read_frame(connection, deadline)
                self._validate_result(result, outgoing)
                offered = result["root"]
                if offered is not None:
                    identity = ProcessIdentity.from_dict(offered["identity"])
                    if identity in {self.guardian_identity, self.wrapper_witness.identity}:
                        raise ScopeLaunchError("scope_distinct_identity_required")
                    if self.root_witness is None:
                        if self._transfer_attempted:
                            raise ScopeLaunchError("scope_root_transfer_unverified")
                        self._transfer_attempted = True
                        self.root_witness = peer.duplicate_remote_handle(offered["handle_locator"], expected=identity)
                        self._root_offer = dict(offered)
                        if self.job is None or self.root_witness.query_owned_job_membership(self.job.handle) is not True:
                            raise ScopeLaunchError("scope_root_membership_unverified")
                        self._root_membership_binding = (self.root_witness, self.job, identity)
                        self._root_membership_verified = True
                    elif self.root_witness.identity != identity or self._root_offer != offered:
                        raise ScopeLaunchError("scope_root_changed")
                self._last_result = result
                self._wrapper_local_closed = result["local_closed"] is True
                write_frame(connection, receipt(result), deadline)
                if read_frame(connection, deadline) != receipt_confirmation(result):
                    raise ScopeLaunchError("scope_receipt_confirmation_invalid")
                if operation == "drain" and self._wrapper_local_closed:
                    self._drain_receipt_sent = True
            connection.close()
            self.connection = None
            return result
        except BaseException as error:
            # The present pipe mechanism has no general ambiguous-close
            # tombstone. Never blindly reap/reclose numeric handles after an
            # uncertain transport boundary. Retain this original registry.
            self._transport_unknown = True
            raise _retain(error, self)

    def _validate_result(self, value, outgoing):
        fields = {"schema_version", "kind", "scope_id", "request_id", "command_sha256",
                  "attempted", "sealed", "creation_outcome", "root", "local_closed", "reason", "launch_provenance"}
        if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1 or
                value["kind"] != "S1ScopeResult" or value["scope_id"] != self.scope_id or
                value["request_id"] != outgoing["request_id"] or value["command_sha256"] != self.command.sha256 or
                any(type(value[key]) is not bool for key in ("attempted", "sealed", "local_closed")) or
                value["creation_outcome"] not in {"not_attempted", "not_created", "created", "unknown"} or
                type(value["reason"]) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value["reason"]) is None):
            raise ScopeLaunchError("scope_result_invalid")
        root = value["root"]
        if root is not None and (type(root) is not dict or set(root) != {"identity", "handle_locator"} or
                type(root["handle_locator"]) is not int or not 0 < root["handle_locator"] < 1 << 63):
            raise ScopeLaunchError("scope_root_offer_invalid")
        if value["local_closed"] and (not value["sealed"] or root is not None):
            raise ScopeLaunchError("scope_cleanup_record_invalid")
        # During drain the wrapper may have closed its local root duplicate
        # before another owner close fails. The guardian's original duplicate
        # must already exist; this is not evidence that all cleanup succeeded.
        draining_existing_root = (value["sealed"] and outgoing["operation"] == "drain" and
                                  self.root_witness is not None)
        if (root is not None and (not value["attempted"] or value["creation_outcome"] not in {"created", "unknown"}) or
                value["creation_outcome"] == "created" and root is None and
                not value["local_closed"] and not draining_existing_root or
                not value["attempted"] and value["creation_outcome"] != "not_attempted" or
                value["local_closed"] and value["creation_outcome"] == "unknown"):
            raise ScopeLaunchError("scope_creation_record_invalid")

    def seal(self):
        with self._lock:
            self._sealed = True
            if not self._wrapper_local_closed:
                return self._exchange("seal")
            return self._last_result

    def drain_once(self, job):
        """One bounded observation; guardian supplies its same retained Job."""
        from sentinel.adaptive.contracts import IdentityStatus
        with self._lock:
            self._job(job)
            if not self._sealed:
                raise ScopeLaunchError("scope_launch_not_sealed", self)
            accounting = job.accounting()
            # Missing custody is never absence proof. A rootless attempt needs
            # the same authenticated, sealed wrapper's positive disposition,
            # together with this original Job's lifetime never-used counter.
            result = self._last_result
            root_dead = (self.root_witness is None and not self._transport_unknown and
                result is not None and result["sealed"] is True and
                result["creation_outcome"] in {"not_attempted", "not_created"} and
                result["root"] is None and accounting.total_processes == 0)
            if self.root_witness is not None:
                root_dead = self.root_witness.observe().status is IdentityStatus.DEAD
            empty = accounting.active_processes == 0 and job.active_pids() == ()
            disabled = not job.query_cpu().flags & 1
            if not self._wrapper_local_closed and root_dead and empty and disabled:
                self._exchange("drain")
            exited = (self._drain_receipt_sent and self.process.wait(0) and self.process.exit_code() == 0)
            if exited and not self._transport_closed:
                if self._transport_unknown or self.connection is not None:
                    raise ScopeLaunchError("scope_transport_cleanup_unverified", self)
                self._transport_unknown = True  # clear only after positive close
                try:
                    self.listener.close()
                    status = self.registry.status()
                    if status.resources or status.pending or status.quarantined:
                        raise ScopeLaunchError("scope_transport_cleanup_unverified", self)
                    self._transport_closed = True
                    self._transport_unknown = False
                except BaseException as error:
                    raise _retain(error, self)
            complete = bool(root_dead and empty and disabled and self._wrapper_local_closed and
                            exited and self._transport_closed)
            return ScopeDrainStatus(self.scope_id, self._sealed, bool(root_dead), bool(empty), bool(disabled),
                self._wrapper_local_closed, bool(exited), self._transport_closed, complete)

    def close(self):
        """Only after observed native drain; no capacity release or Job close."""
        with self._lock:
            if self._closed:
                return
            if (not self._command_dispatched and self.wrapper_witness is None and self.root_witness is None and
                    (not self._wrapper_create_entered or
                     self.process is not None and self.process.creation_definitely_absent)):
                self._close_before_wrapper()
                return
            if not self._close_started and (self.job is None or not self.drain_once(self.job).complete):
                raise ScopeLaunchError("scope_custody_unsettled", self)
            self._close_started = True
            try:
                for owner in (self.root_witness, self.wrapper_witness, self.process):
                    if owner is not None:
                        owner.close()
                self._closed = True
                _OWNERS.pop(self.scope_id, None)
            except BaseException as error:
                raise _retain(error, self)

    def _close_before_wrapper(self):
        """Positive never-created cleanup; no absent witness is used as proof."""
        self._sealed = True
        try:
            if self._source_close_unknown or self._transport_unknown or self.connection is not None:
                raise ScopeLaunchError("scope_preparation_custody_unsettled")
            if self._source_connection is not None:
                self._source_close_unknown = True
                self._source_connection.close()
                self._source_connection = None
                self._source_close_unknown = False
            if not self._transport_closed:
                if self.listener is not None:
                    self._transport_unknown = True
                    self.listener.close()
                    self._transport_unknown = False
                if self.registry is not None:
                    status = self.registry.status()
                    if status.resources or status.pending or status.quarantined:
                        raise ScopeLaunchError("scope_preparation_transport_unsettled")
                self._transport_closed = True
            if self.process is not None:
                self.process.close()
            self._closed = True
            _OWNERS.pop(self.scope_id, None)
        except BaseException as error:
            raise _retain(error, self)
