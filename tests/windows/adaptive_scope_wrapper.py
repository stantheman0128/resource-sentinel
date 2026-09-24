"""Pinned S1 fixture wrapper; no admission, CPU Set, kill or PID-based custody.

Executed only by ScopeLaunch's retained CreateProcessW owner using base Python
-I. The bootstrap is source/payload binding, not launch authority: the exact
guardian must independently authenticate on the native pipe for every command.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import sys
import tempfile
import time


_RETAINED = []


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("scope_duplicate_json_key")
        result[key] = value
    return result


def _read(path, limit):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("scope_bootstrap_path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("scope_bootstrap_redirected")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("scope_bootstrap_oversized")
    return data


def load_bootstrap(path, sha256):
    """Pin the two reviewed fixture files before importing either one."""
    if any(name == "sentinel" or name.startswith("sentinel.") or name == "sentinel_daily_bootstrap"
           for name in sys.modules):
        raise ValueError("scope_sentinel_preloaded")
    data = _read(path, 2 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("scope_bootstrap_changed")
    payload = json.loads(data, object_pairs_hook=_unique_object,
        parse_constant=lambda unused: (_ for _ in ()).throw(ValueError("nonfinite")))
    fields = {"schema_version", "scope_id", "job_nonce", "job_name", "guardian_identity",
              "endpoint_instance", "deadline_monotonic", "command", "command_sha256",
              "canonical_source", "generation", "reservation_id", "binding_sha256",
              "fixture_sources", "python_sha256", "request_marker"}
    if (type(payload) is not dict or set(payload) != fields or
            type(payload["schema_version"]) is not int or payload["schema_version"] != 2):
        raise ValueError("scope_bootstrap_invalid")
    sources = payload["fixture_sources"]
    paths = {str(Path(__file__).resolve()), str(Path(__file__).with_name("adaptive_scope_launch.py").resolve())}
    if (type(sources) is not list or len(sources) != 2 or
            any(type(row) is not dict or set(row) != {"path", "sha256", "size", "file_identity"} for row in sources) or
            {row["path"] for row in sources} != paths):
        raise ValueError("scope_fixture_closure_invalid")
    verified_sources = {}
    for row in sources:
        actual = _read(row["path"], 1024 * 1024)
        info = Path(row["path"]).stat()
        if (len(actual) != row["size"] or hashlib.sha256(actual).hexdigest() != row["sha256"] or
                [int(info.st_dev), int(info.st_ino)] != row["file_identity"]):
            raise ValueError("scope_fixture_changed")
        verified_sources[row["path"]] = actual
    canonical = Path(payload["canonical_source"])
    expected = Path.home() / "Projects" / "resource-sentinel"
    if canonical.resolve(strict=True) != expected.resolve(strict=True):
        raise ValueError("scope_canonical_source_required")
    base = Path(getattr(sys, "_base_executable", sys.executable)).resolve(strict=True)
    if (not sys.flags.isolated or Path(sys.executable).resolve(strict=True) != base or
            hashlib.sha256(base.read_bytes()).hexdigest() != payload["python_sha256"]):
        raise ValueError("scope_base_python_required")
    # Match the workload bootstrap: a fresh isolated interpreter must import
    # sentinel/__init__.py first so its original execution audit is installed.
    # Refuse an ambient provider instead of relying on import-path precedence.
    for entry in sys.path:
        if entry and ((Path(entry) / "sentinel").exists() or
                      (Path(entry) / "sentinel_daily_bootstrap.py").exists()):
            raise ValueError("scope_ambient_sentinel_path")
    sys.path.insert(0, str(canonical))
    source = Path(__file__).with_name("adaptive_scope_launch.py").resolve()
    spec = importlib.util.spec_from_file_location("_sentinel_s1_scope_launch", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    # The loader would be allowed to reuse a timestamp-valid stale .pyc. Compile
    # the exact bytes checked above, including every module initializer.
    exec(compile(verified_sources[str(source)], str(source), "exec", dont_inherit=True), module.__dict__)
    generation = importlib.import_module("sentinel.adaptive.daily_generation")
    # These are all of initialize()'s production imports. Attest their actual
    # completed execution before it acquires the first native self handle.
    for name in ("sentinel.adaptive.contracts", "sentinel.adaptive.identity", "sentinel.adaptive.pipe_windows"):
        importlib.import_module(name)
    row = module.validate_generation(payload["generation"])
    manifest = generation.SourceManifest.from_dict(json.loads(row["source_manifest_json"],
        object_pairs_hook=_unique_object))
    if manifest.digest != row["source_digest"] or row["source_root"] != str(canonical):
        raise ValueError("scope_source_digest_changed")
    module.validate_launch_bounds(dict(reservation_id=payload["reservation_id"],
        binding_sha256=payload["binding_sha256"], expires_at=1, lease_deadline_monotonic_ns=1))
    generation.verify_import_provenance(manifest, canonical)
    command = module.ScopeCommand.from_dict(payload["command"])
    command.verify()
    if command.sha256 != payload["command_sha256"] or Path(command.application).resolve() != base:
        raise ValueError("scope_command_changed")
    if (not module._uuid(payload["scope_id"]) or
            payload["job_name"] != "Local\\ResourceSentinel.Test.Job." + payload["job_nonce"] or
            type(payload["deadline_monotonic"]) not in (int, float) or
            not math.isfinite(payload["deadline_monotonic"]) or
            payload["deadline_monotonic"] - time.monotonic() > 120):
        raise ValueError("scope_bootstrap_binding_invalid")
    marker = Path(payload["request_marker"])
    if (not marker.is_absolute() or marker.parent.resolve() != Path(path).parent.resolve() or
            marker.name != "scope-request-" + payload["scope_id"] + ".json"):
        raise ValueError("scope_request_marker_invalid")
    return payload, module, command, manifest


def timing_record(command, payload):
    """Only independently pinned argv fields, never a self-referential hash."""
    arguments = command.arguments[2:]
    if (arguments.count("--scope-bound-stdin") != 1 or "--leaf" in arguments or
            "--deadline-monotonic-ns" in arguments):
        raise ValueError("scope_timing_command_invalid")
    def argument(flag):
        if arguments.count(flag) != 1:
            raise ValueError("scope_timing_command_invalid")
        index = arguments.index(flag) + 1
        if index >= len(arguments):
            raise ValueError("scope_timing_command_invalid")
        return arguments[index]
    fixture = next(source for source in command.fixture_sources if source.path == command.arguments[1])
    expected = {"--scope-id": payload["scope_id"], "--nonce": payload["job_nonce"],
        "--job-name": payload["job_name"], "--canonical-root": payload["canonical_source"],
        "--source-generation": payload["generation"]["generation"],
        "--source-digest": payload["generation"]["source_digest"], "--fixture-sha256": fixture.sha256,
        "--directory": str(Path(payload["request_marker"]).parent)}
    if any(argument(key) != value for key, value in expected.items()):
        raise ValueError("scope_timing_binding_changed")
    deadline = payload["deadline_monotonic"]
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or deadline <= 0:
        raise ValueError("scope_timing_deadline_invalid")
    value = dict(schema_version=1, kind="S1ScopeTiming", scope_id=payload["scope_id"],
        job_nonce=payload["job_nonce"], source_generation=payload["generation"]["generation"],
        source_digest=payload["generation"]["source_digest"], fixture_sha256=fixture.sha256,
        scope_deadline_monotonic_ns=math.floor(deadline * 1_000_000_000))
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= 4096:
        raise ValueError("scope_timing_oversized")
    return raw


class WrapperOwner:
    """No public success branch until local and transport custody both close."""
    def __init__(self, payload, module, command, manifest):
        self.payload, self.api, self.command, self.manifest = payload, module, command, manifest
        self.errors = []
        self.process = self.job = self.mutex = self.current = None
        self.connection = self.registry = None
        self.files = []
        self._close_unknown = False
        self._acquisition_pending = False
        self._local_closed = self._closing = False
        self._creation_outcome = "not_attempted"
        self._launch_failed = False
        self._provenance = None
        self._marker_nonce = None
        self._readiness_context = self._readiness_scope = self._readiness_error = None
        self._readiness_pending = False
        self.state = module.OnceLaunchState(command.sha256)
        _RETAINED.append(self)  # Own partial native constructors before calls.

    def initialize(self):
        from sentinel.adaptive.contracts import ProcessIdentity
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.pipe_windows import NativePipeEndpoint, NativePipeRegistry
        self.guardian = ProcessIdentity.from_dict(self.payload["guardian_identity"])
        self.current = VerifiedProcess.current()
        if self.current.identity == self.guardian or self.current.identity.logon_id != self.guardian.logon_id:
            raise self.api.ScopeLaunchError("scope_wrapper_identity_invalid")
        if self.current.is_in_job(None) is not False:
            raise self.api.ScopeLaunchError("scope_wrapper_foreign_job")
        self.endpoint = NativePipeEndpoint(self.guardian.logon_id, self.payload["endpoint_instance"], self.guardian)
        self.registry = NativePipeRegistry(max_resources=4)

    def _result(self, incoming, reason="scope_observed"):
        if incoming.get("operation") in {"launch", "observe"} and self._launch_failed:
            reason = "scope_launch_unverified"
        root = None
        if (self.process is not None and not self._closing and
                self._creation_outcome in {"created", "unknown"}):
            with self.process._lock:
                # A documented Create FALSE still retains an ancillary cleanup
                # owner. It has no root handle to offer or reopen by PID.
                if self.process.handle is not None:
                    root = dict(identity=self.process.full_identity(expected_logon_id=self.guardian.logon_id).to_dict(),
                                handle_locator=self.process._live_handle())
        return dict(schema_version=1, kind="S1ScopeResult", scope_id=self.payload["scope_id"],
            request_id=incoming["request_id"], command_sha256=self.command.sha256,
            attempted=self.state.attempted, sealed=self.state.sealed,
            creation_outcome=self._creation_outcome, root=root,
            local_closed=self._local_closed, reason=reason, launch_provenance=self._provenance)

    def _launch(self, incoming, deadline):
        from sentinel.adaptive import native_launcher
        from sentinel.adaptive import daily_generation
        from sentinel.adaptive.native_job import NativeJob, JobAccess
        from sentinel.adaptive.pipe_windows import NativeDeadline
        from sentinel.adaptive.windows import NativePolicyMutex
        from sentinel.adaptive.guardian_lifecycle import job_mutex_instance
        import msvcrt
        bounds = self.api.validate_launch_bounds(incoming.get("launch_bounds"))
        if not self.state.begin(incoming["request_id"], incoming["command_sha256"], launch_bounds=bounds):
            return
        if (bounds["reservation_id"] != self.payload["reservation_id"] or
                bounds["binding_sha256"] != self.payload["binding_sha256"] or
                bounds["lease_deadline_monotonic_ns"] > math.floor(self.payload["deadline_monotonic"] * 1e9)):
            raise self.api.ScopeLaunchError("scope_launch_binding_changed")
        if (time.monotonic() >= self.payload["deadline_monotonic"] or
                time.monotonic_ns() >= bounds["lease_deadline_monotonic_ns"] or
                time.time() >= bounds["expires_at"]):
            raise self.api.ScopeLaunchError("scope_deadline_expired")
        deadline.require()
        self.command.verify()
        daily_generation.verify_import_provenance(self.manifest, self.payload["canonical_source"])
        timing = timing_record(self.command, self.payload)
        self._acquisition_pending = True
        self.job = NativeJob.open(self.payload["job_name"], self.payload["job_nonce"],
                                  self.guardian.logon_id, access=JobAccess.LAUNCH)
        self._acquisition_pending = False
        self._acquisition_pending = True
        self.mutex = NativePolicyMutex(self.guardian.logon_id,
            job_mutex_instance(self.payload["scope_id"], self.payload["job_nonce"]))
        self._acquisition_pending = False
        # These handles are genuinely owned by THIS wrapper. Parent handle
        # numbers are never accepted or reinterpreted in this process.
        self._acquisition_pending = True
        self.files.append(tempfile.TemporaryFile(mode="w+b", dir=Path(self.payload["request_marker"]).parent))
        self._acquisition_pending = False
        if self.files[0].write(timing) != len(timing):
            raise self.api.ScopeLaunchError("scope_timing_write_incomplete")
        self.files[0].flush()
        self.files[0].seek(0)
        for mode in ("wb", "wb"):
            self._acquisition_pending = True
            self.files.append(open(os.devnull, mode))
            self._acquisition_pending = False
        failure = None
        self._readiness_pending = True
        try:
            self._readiness_context = daily_generation.readiness_scope(self.payload["generation"]["ledger_path"])
            with self._readiness_context as original:
                self._readiness_scope = original
                with self.mutex.acquire(timeout_ms=250) as lease:
                    if lease.abandoned or self.state.sealed or time.monotonic() >= self.payload["deadline_monotonic"]:
                        raise self.api.ScopeLaunchError("scope_launch_fence_unavailable")
                    ready_deadline = daily_generation.revalidate_scoped_readiness(
                        self.payload["generation"]["ledger_path"], expected_generation=self.payload["generation"])
                    if type(ready_deadline) is not NativeDeadline:
                        raise self.api.ScopeLaunchError("scope_remote_readiness_required")
                    if self.job.accounting().total_processes != 0 or self.job.active_pids() != ():
                        raise self.api.ScopeLaunchError("scope_job_previously_used")
                    deadline.require()
                    self._creation_outcome = "unknown"
                    try:
                        self.process = native_launcher.launch_in_job(self.job, self.command.application,
                            self.command.command_line, cwd=self.command.cwd,
                            stdin_handle=msvcrt.get_osfhandle(self.files[0].fileno()),
                            stdout_handle=msvcrt.get_osfhandle(self.files[1].fileno()),
                            stderr_handle=msvcrt.get_osfhandle(self.files[2].fileno()), native_deadline=deadline,
                            readiness_deadline=ready_deadline, scope_deadline_monotonic=self.payload["deadline_monotonic"],
                            lease_deadline_monotonic_ns=bounds["lease_deadline_monotonic_ns"],
                            lease_expires_at=bounds["expires_at"])
                    except BaseException as error:
                        failure = error
                        self.errors.append(error)
                        retained = getattr(error, "native_launch_owner", None)
                        if type(retained) is native_launcher.CreatedProcess:
                            self.process = retained
                    if self.process is not None:
                        self._creation_outcome = self.process._creation_outcome
                        if self.process.launch_provenance is not None:
                            self._provenance = self.process.launch_provenance.to_dict()
        except BaseException as error:
            self._readiness_error = error
            # Every actual owner/error stays retained. Clear only the acquisition
            # marker when the readiness API positively settled its own resources.
            self._readiness_pending = False
            if self._readiness_unsettled():
                self._readiness_pending = True
            raise
        self._readiness_pending = False
        if failure is not None:
            raise failure

    def _readiness_unsettled(self):
        from sentinel.adaptive.daily_generation import _readiness_cleanup_unknown
        if self._readiness_pending or (self._readiness_scope is not None and
                self._readiness_scope.closed is not True):
            return True
        if self._readiness_error is None:
            return False
        if _readiness_cleanup_unknown(self._readiness_error):
            return True
        pending, seen = [self._readiness_error], set()
        while pending:
            error = pending.pop()
            if id(error) in seen:
                continue
            seen.add(id(error))
            if len(seen) > 32:
                return True
            scopes = (*getattr(error, "_daily_readiness_scopes", ()), getattr(error, "daily_readiness_scope", None))
            if any(value is not None and getattr(value, "closed", None) is not True for value in scopes):
                return True
            pending.extend(value for value in (getattr(error, "__cause__", None),
                getattr(error, "__context__", None), getattr(error, "_daily_readiness_cause", None),
                getattr(error, "_daily_readiness_authority_cleanup", None)) if isinstance(value, BaseException))
        return False

    def _drain(self):
        if not self.state.sealed:
            raise self.api.ScopeLaunchError("scope_launch_not_sealed")
        if self._local_closed:
            return
        # Diagnostics are not custody. Pure source/deadline refusals may drain;
        # interrupted constructors and ambiguous closes retain their originals.
        if self._close_unknown or self._acquisition_pending or self._readiness_unsettled():
            raise self.api.ScopeLaunchError("scope_wrapper_custody_quarantined")
        if not self._closing:
            if (self.process is not None and not self.process.creation_definitely_absent and
                    not self.process.wait(0)):
                return
            if self._creation_outcome == "unknown":
                raise self.api.ScopeLaunchError("scope_creation_unverified")
            if self.job is not None:
                # The guardian remains the only actuator; this wrapper only
                # observes restored state and zero children before closure.
                with self.mutex.acquire(timeout_ms=250) as lease:
                    if (lease.abandoned or self.job.accounting().active_processes != 0 or
                            self.job.active_pids() != () or self.job.query_cpu().flags & 1):
                        return
            self._closing = True
        # Native owners have their own unknown-close quarantine. Mark file
        # and mutex close ambiguity before calls: no blanket retry/finalizer.
        if self.process is not None:
            self.process.close()
        if self.job is not None:
            self.job.close()
        if self.mutex is not None:
            self._close_unknown = True
            self.mutex.close()
            self.mutex = None
            self._close_unknown = False
        while self.files:
            self._close_unknown = True
            self.files[-1].close()
            self.files.pop()
            self._close_unknown = False
        self._local_closed = True

    def serve_once(self):
        from sentinel.adaptive.pipe_windows import NativeDeadline, NativePipeConnection
        from sentinel.adaptive.ipc import read_frame, write_frame
        deadline = NativeDeadline.after_ms(5000)
        connection = self.connection = NativePipeConnection.connect(self.endpoint, deadline, registry=self.registry)
        should_exit = False
        with connection.verified_peer(self.guardian) as peer:
            if peer.identity != self.guardian:
                raise self.api.ScopeLaunchError("scope_guardian_changed")
            hello = dict(schema_version=1, kind="S1ScopeHello", scope_id=self.payload["scope_id"],
                wrapper_identity=self.current.identity.to_dict(), command_sha256=self.command.sha256)
            write_frame(connection, hello, deadline)
            incoming = self.api.validate_request(read_frame(connection, deadline),
                self.payload["scope_id"], self.command.sha256)
            operation = incoming["operation"]
            reason = "scope_observed"
            try:
                if operation == "launch":
                    self._launch(incoming, deadline)
                elif operation == "seal":
                    self.state.seal()
                elif operation == "drain":
                    self._drain()
            except BaseException as error:
                self.errors.append(error)
                if operation == "launch":
                    self._launch_failed = True
                if not isinstance(error, Exception):
                    raise
                reason = "scope_operation_unverified"
            result = self._result(incoming, reason)
            write_frame(connection, result, deadline)
            if read_frame(connection, deadline) != self.api.receipt(result):
                raise self.api.ScopeLaunchError("scope_receipt_invalid")
            write_frame(connection, self.api.receipt_confirmation(result), deadline)
            should_exit = operation == "drain" and self._local_closed
        # The preceding message deliberately does NOT claim transport closure.
        self._close_unknown = True
        connection.close()
        self.connection = None
        self._close_unknown = False
        if should_exit:
            status = self.registry.status()
            if status.resources or status.pending or status.quarantined:
                raise self.api.ScopeLaunchError("scope_wrapper_transport_unsettled")
            self.current.close()
            self.current = None
            _RETAINED.remove(self)
            return True
        return False

    def notification_pending(self):
        """A bounded wakeup, never launch/cleanup authority or a heartbeat."""
        try:
            data = _read(self.payload["request_marker"], 4096)
        except FileNotFoundError:
            return False
        value = json.loads(data)
        if (type(value) is not dict or set(value) != {"scope_id", "nonce"} or
                value["scope_id"] != self.payload["scope_id"] or not self.api._uuid(value["nonce"])):
            raise self.api.ScopeLaunchError("scope_request_marker_invalid")
        if value["nonce"] == self._marker_nonce:
            return False
        self._marker_nonce = value["nonce"]
        return True


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--bootstrap-sha256", required=True)
    args = parser.parse_args(argv)
    owner = None
    try:
        payload, module, command, manifest = load_bootstrap(args.bootstrap, args.bootstrap_sha256)
        owner = WrapperOwner(payload, module, command, manifest)
        owner.initialize()
        while True:
            if owner.notification_pending() and owner.serve_once():
                return 0
            time.sleep(.025)
    except BaseException as error:
        if owner is None:
            # Bootstrap failed before native owner acquisition or user work.
            return 124
        owner.errors.append(error)
        owner.state.seal()
        # No normal exit drops unknown ownership. The guardian retains its
        # exact creation handle and reports this custody as unresolved. This
        # quarantine does not count as a successful 120-second observation.
        while True:
            try:
                time.sleep(.25)
            except BaseException as interruption:
                owner.errors.append(interruption)


if __name__ == "__main__":
    raise SystemExit(main())
