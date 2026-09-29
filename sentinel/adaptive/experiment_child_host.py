"""Fixed authenticated aggregate child dispatch and original cleanup custody.

Registration files contain credentials, never release/admission authority. No
host, sampler or ledger is constructed before the real parent role exchange.
Errors retain the original owner; process exit is not substituted for cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time
from uuid import uuid4

from .contracts import ProcessIdentity, strict_json_loads
from .experiment_host_roles import GuardianRoleSpec, HelperRoleSpec, WrapperRoleSpec, role_spec_from_dict
from .experiment_host_transport import (ExperimentChildBinding, ExperimentChildClient,
    ExperimentChildManifest, ExperimentChildRegistration)
from .host_discovery import _WindowsProtection
from .identity import VerifiedProcess
from .pipe_windows import NativePipeEndpoint
from .windows import retained_owners, settle_retained


MAX_REGISTRATION_BYTES = 256 * 1024
MAX_PROFILE_BYTES = 1024 * 1024
_FILE = re.compile(r"\.experiment-child-([0-9a-f-]{36})\.json")
_HOST = None
_PUBLICATIONS = {}


class ExperimentChildHostError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_child_host_" + reason
        super().__init__(self.reason)


def _fail(reason):
    raise ExperimentChildHostError(reason)


def _safe(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path.resolve(strict=True) != path:
        _fail("path_invalid")
    for component in (path, *path.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            _fail("path_redirected")
    return path


def _read(path, limit):
    path = _safe(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or not before.st_ino or not 0 < before.st_size <= limit:
        _fail("file_invalid")
    shared = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_birthtime_ns")
    def signature(info, names=shared):
        return tuple(getattr(info, name, None) for name in names)
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(limit + 1)
        closed = os.fstat(stream.fileno())
    after = path.stat()
    full = (*shared, "st_ctime_ns")
    if (len(raw) != before.st_size or signature(before) != signature(opened) or
            signature(before, full) != signature(after, full) or
            signature(opened, full) != signature(closed, full)):
        _fail("file_changed")
    return raw, (signature(before, full), signature(opened, full))


def registration_bytes(registration):
    if type(registration) is not ExperimentChildRegistration or registration.role_spec is None:
        _fail("registration_required")
    registration.__post_init__()
    value = dict(version=1, kind="ExperimentChildRegistration",
        manifest=registration.manifest.to_dict(), auth_key=registration.auth_key.hex(),
        role_spec=registration.role_spec.to_dict())
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                     allow_nan=False).encode("ascii")
    if len(raw) > MAX_REGISTRATION_BYTES:
        _fail("registration_oversized")
    return raw


def parse_registration(raw):
    if type(raw) is not bytes or len(raw) > MAX_REGISTRATION_BYTES:
        _fail("registration_invalid")
    value = strict_json_loads(raw)
    if (type(value) is not dict or set(value) != {"version", "kind", "manifest", "auth_key", "role_spec"}
            or type(value["version"]) is not int or value["version"] != 1
            or value["kind"] != "ExperimentChildRegistration" or type(value["auth_key"]) is not str
            or re.fullmatch("[0-9a-f]{64}", value["auth_key"]) is None):
        _fail("registration_invalid")
    return ExperimentChildRegistration(ExperimentChildManifest.from_dict(value["manifest"]),
        bytes.fromhex(value["auth_key"]), role_spec=role_spec_from_dict(value["role_spec"]))


class ChildRegistrationPublication:
    """One private atomic file publication; its return is not child release."""
    @classmethod
    def prepare(cls, registration, directory):
        if cls is not ChildRegistrationPublication:
            _fail("original_publication_required")
        raw = registration_bytes(registration)
        directory = _safe(directory)
        if not directory.is_dir():
            _fail("directory_invalid")
        key = (os.getpid(), registration.manifest.request_id)
        previous = _PUBLICATIONS.get(key)
        if previous is not None:
            if previous.registration is not registration or previous.directory != directory:
                _fail("original_publication_changed")
            return previous
        owner = cls.__new__(cls)
        owner.registration, owner.directory, owner.raw = registration, directory, raw
        owner.target = directory / (".experiment-child-" + registration.manifest.actor_member_id + ".json")
        owner.staging = directory / (".experiment-registration-" + str(uuid4()) + ".tmp")
        owner.protection = owner.stream = owner.failure = owner.identity = None
        owner.started = owner.published = False
        owner._stream_entered = owner._stream_close_entered = owner._stream_closed = False
        owner._stream_original = owner._protection_original = None
        owner._protection_entered = owner._protection_close_entered = owner._protection_closed = False
        owner._closed = False
        owner._thread, owner._pid = threading.get_ident(), os.getpid()
        owner._key = key
        owner._fixed = (registration, directory, raw, owner.target, owner.staging)
        _PUBLICATIONS[key] = owner
        return owner

    def publish(self):
        self._assert_original()
        if self._closed:
            _fail("publication_closed")
        if self.published:
            if _read(self.target, MAX_REGISTRATION_BYTES) != (self.raw, self.identity):
                _fail("publication_changed")
            self.protection.verify(self.target, directory=False)
            return self.target
        if self.started:
            _fail("publication_outcome_unknown")
        self.started = True
        try:
            self._protection_entered = True
            self.protection = _WindowsProtection(self.registration.manifest.child_identity.logon_id)
            self._protection_original = self.protection
            # Empty file first: credential bytes are written only AFTER ACL
            # application and native readback have both completed.
            self._stream_entered = True
            self.stream = self.staging.open("xb")
            self._stream_original = self.stream
            self.protection.protect_file(self.staging)
            self.protection.verify(self.staging, directory=False)
            self.stream.write(self.raw)
            self.stream.flush()
            os.fsync(self.stream.fileno())
            self._stream_close_entered = True
            self.stream.close()
            self._stream_closed = True
            self.stream = None
            if self.target.exists():
                _fail("registration_already_exists")
            # Windows rename refuses an existing destination. Do not replace a
            # foreign/original publication even if it races the prior check.
            if os.name != "nt":
                _fail("windows_publication_required")
            self.staging.rename(self.target)
            self.protection.verify(self.target, directory=False)
            observed, self.identity = _read(self.target, MAX_REGISTRATION_BYTES)
            if observed != self.raw:
                _fail("publication_changed")
            self.published = True
            return self.target
        except BaseException as error:
            self.failure = error
            error.experiment_registration_publication = self
            raise

    def _assert_original(self):
        if (type(self) is not ChildRegistrationPublication or _PUBLICATIONS.get(self._key) is not self or
                (self.registration, self.directory, self.raw, self.target, self.staging) != self._fixed or
                (threading.get_ident(), os.getpid()) != (self._thread, self._pid) or
                self.protection is not self._protection_original or
                self.stream is not (None if self._stream_closed else self._stream_original)):
            _fail("original_publication_changed")

    def close(self):
        """Close original owners only; publication/actor outcome stays separate."""
        self._assert_original()
        if self._closed:
            return self.assert_closed()
        if self._stream_entered and self._stream_original is None:
            _fail("file_creation_outcome_unknown")
        if self._protection_entered and self._protection_original is None:
            _fail("protection_construction_unknown")
        if self._stream_original is not None and not self._stream_closed:
            if self._stream_close_entered:
                _fail("file_close_outcome_unknown")
            self._stream_close_entered = True
            self.stream.close()
            self._stream_closed = True
            self.stream = None
        if self.failure is not None and not settle_retained(self.failure):
            _fail("publication_native_cleanup_pending")
        if self.protection is not None and not self._protection_closed:
            if self._protection_close_entered:
                _fail("protection_close_outcome_unknown")
            self._protection_close_entered = True
            self.protection.close()
            self._protection_closed = True
        self._closed = True
        self.assert_closed()

    def assert_closed(self):
        """Pure retained-owner checks; safe inside the final SQL publication."""
        self._assert_original()
        if (not self._closed or self.stream is not None or
                self._stream_entered and (self._stream_original is None or not self._stream_closed) or
                self._protection_entered and (self.protection is None or not self._protection_closed) or
                self.failure is not None and retained_owners(self.failure)):
            _fail("publication_cleanup_pending")


class ExperimentChildHost:
    """Exactly one process's bootstrap, concrete host, and terminal publisher."""
    def __init__(self, registration_path):
        path = Path(registration_path)
        if not path.is_absolute() or ".." in path.parts or _FILE.fullmatch(path.name) is None:
            _fail("registration_path_invalid")
        self.path = path
        self.process = self.protection = self.registration = self.client = self.binding = None
        self.host = self.daily_store = self.isolated_store = self.coordinator = None
        self.partition = self.publication = self.context = self.terminal = None
        self.file_pin = self.profile_pin = self.role = None
        self.errors, self.constructing = [], {}
        self.authenticated = self.dispatched = self.host_closed = self.closed = False
        self._terminal_settled = self._binding_closed = self._protection_closed = self._process_closed = False
        self._thread, self._pid = threading.get_ident(), os.getpid()

    def _retain(self, error):
        if len(self.errors) < 32 and not any(item is error for item in self.errors):
            self.errors.append(error)
        error.experiment_child_host = self

    def authenticate(self):
        if self.authenticated or self.client is not None:
            _fail("authentication_already_entered")
        if self.process is None:
            self.process = VerifiedProcess.current()
        if self.protection is None:
            self.protection = _WindowsProtection(self.process.identity.logon_id)
        raw, self.file_pin = _read(self.path, MAX_REGISTRATION_BYTES)
        self.protection.verify(self.path, directory=False)
        registration = parse_registration(raw)
        if (self.path.name != ".experiment-child-" + registration.manifest.actor_member_id + ".json" or
                registration.manifest.child_identity != self.process.identity):
            _fail("registration_identity_mismatch")
        self.registration = registration
        self.client = ExperimentChildClient(registration, self.process)
        self.binding = self.client.bind()
        if getattr(self.binding, "_experiment_bootstrap_owner", None) is not None:
            _fail("original_bootstrap_already_retained")
        self.binding._experiment_bootstrap_owner = self
        self.role = self.binding.released_role
        self.binding.require_role_release(self.role)
        if self.role is not registration.role_spec:
            _fail("original_role_required")
        if _read(self.path, MAX_REGISTRATION_BYTES) != (raw, self.file_pin):
            _fail("registration_changed")
        self.authenticated = True

    def _construct(self, name, cls, **kwargs):
        if name in self.constructing:
            _fail("construction_already_entered")
        owner = cls.__new__(cls)
        self.constructing[name] = owner
        setattr(self, name, owner)
        cls.__init__(owner, **kwargs)
        return owner

    def _profile(self):
        raw, pin = _read(Path(self.role.profile_path), MAX_PROFILE_BYTES)
        if hashlib.sha256(raw).hexdigest() != self.role.profile_sha256:
            _fail("profile_changed")
        self.profile_pin = (raw, pin)
        return raw

    def dispatch(self):
        if (not self.authenticated or type(self.binding) is not ExperimentChildBinding or self.dispatched or
                self.binding._experiment_bootstrap_owner is not self or
                (threading.get_ident(), os.getpid()) != (self._thread, self._pid)):
            _fail("authenticated_original_dispatch_required")
        self.binding.require_role_release(self.role)
        context = self.binding.role_release_context(self.role)
        if type(context) is not dict:
            _fail("role_context_invalid")
        self.dispatched = True  # no replacement construction after any failure
        from .store import LifecycleStore
        from .guardian_host import GuardianHost
        from .wrapper_host import WrapperHost
        from .helper_control_host import OperationalHelperHost
        manifest, role = self.registration.manifest, self.role
        if type(role) is GuardianRoleSpec:
            if context:
                _fail("guardian_context_invalid")
            self._profile()
            self._construct("daily_store", LifecycleStore, db_path=manifest.daily_ledger_path, existing_path=True)
            self._construct("isolated_store", LifecycleStore, db_path=manifest.isolated_ledger_path, existing_path=True)
            self.host = GuardianHost.for_experiment(role, child_binding=self.binding,
                isolated_store=self.isolated_store, daily_store=self.daily_store)
        elif type(role) is WrapperRoleSpec:
            if (set(context) != {"endpoint", "guardian_epoch", "reservation_id", "backing_request_id"} or
                    type(context["endpoint"]) is not NativePipeEndpoint or role.max_wait_sec > 120):
                _fail("wrapper_context_invalid")
            from sentinel.coordinator import Coordinator
            from .admission import ManagedAdmission
            from .experiment_partition_admission import ExperimentPartitionCoordinator
            from .experiment_backing_transport import ExperimentBackingPublication
            self._construct("daily_store", LifecycleStore, db_path=manifest.daily_ledger_path, existing_path=True)
            self._construct("coordinator", Coordinator, data_dir=role.data_dir,
                            db_path=manifest.isolated_ledger_path)
            self._construct("partition", ExperimentPartitionCoordinator, coordinator=self.coordinator,
                child_binding=self.binding, member_id=role.workload_member_id,
                reservation_id=context["reservation_id"], daily_store=self.daily_store)
            spec = role.launch_spec
            self.context = ManagedAdmission.current(command=spec.command, cwd=spec.cwd,
                repo_identifier=spec.repo_identifier, requested=spec.requested, role=spec.role, priority=spec.priority)
            self.publication = ExperimentBackingPublication.prepare(self.binding, self.context,
                member_id=role.workload_member_id, reservation_id=context["reservation_id"],
                request_id=context["backing_request_id"])
            self.host = WrapperHost.for_experiment(spec, partition=self.partition, publication=self.publication,
                endpoint=context["endpoint"], guardian_epoch=context["guardian_epoch"],
                max_wait_sec=role.max_wait_sec, rpc_timeout_ms=role.rpc_timeout_ms,
                poll_interval_ms=role.poll_interval_ms)
        elif type(role) is HelperRoleSpec:
            expected = {"instance_id", "operator_instance_id", "parent_instance_id", "policy_instance_id",
                        "guardian_epoch", "parent_identity", "guardian_endpoint"}
            if (set(context) != expected or type(context["parent_identity"]) is not ProcessIdentity or
                    type(context["guardian_endpoint"]) is not NativePipeEndpoint):
                _fail("helper_context_invalid")
            from .decision import Mode, parse_policy_profile
            if parse_policy_profile(self._profile()).mode is not Mode.SHADOW:
                _fail("helper_shadow_required")
            self._construct("host", OperationalHelperHost, **context, data_dir=role.data_dir,
                profile_path=role.profile_path, enroll_every_ticks=role.enroll_every_ticks,
                report_every_ticks=role.report_every_ticks)
            self.host._experiment_child_binding = self.binding
            self.host._experiment_role_spec = role
        else:
            _fail("role_unsupported")
        return self.host

    def run_host(self):
        from .guardian_host import GuardianHost
        from .wrapper_host import WrapperHost
        from .helper_control_host import OperationalHelperHost
        host = self.host
        if type(host) is GuardianHost:
            host.start()
            host.serve_until_stopped()
            host.begin_drain()
            host.drain_until_settled()
            host.close()
        elif type(host) is WrapperHost:
            try:
                host.run()
            except BaseException as error:
                self._retain(error)
                host.settle_release()
            else:
                host.settle_release()
        elif type(host) is OperationalHelperHost:
            try:
                host.start()
            finally:
                # OperationalHelperHost clears closed fields. Keep the actual
                # originals BEFORE close, including partial startup ownership.
                # The retirement inspector decides whether they prove closure.
                host._experiment_retirement_owners = (host.process, host.parent_process,
                    host.operator_listener, host._pipe_registry, host.jobs, host.telemetry)
                host._experiment_retirement_fields = (host.data_dir, host.profile_path,
                    host.enroll_every_ticks, host.report_every_ticks, host.instance_id,
                    host.operator_instance_id, host.parent_instance_id, host.policy_instance_id,
                    host.guardian_epoch, host.parent_identity, host.guardian_endpoint)
            if _read(Path(self.role.profile_path), MAX_PROFILE_BYTES) != self.profile_pin:
                _fail("profile_changed")
            host.run_bounded(self.role.iterations)
            host.request_drain("bounded_run_complete")
            host.serve_until_stopped()
        else:
            _fail("original_host_required")
        self.host_closed = True

    def finish(self):
        if not self.host_closed:
            _fail("host_cleanup_pending")
        from .experiment_host_retirement_transport import publish_host_closed
        if not self._terminal_settled:
            try:
                if self.terminal is None:
                    self.terminal = publish_host_closed(self.host, self.binding, self.process)
                else:
                    self.terminal.publish(timeout_ms=1000)
                self.terminal.assert_settled()
                self._terminal_settled = True
            except BaseException as error:
                retained = getattr(error, "experiment_host_retirement_publication", None)
                if retained is not None and self.terminal is None:
                    self.terminal = retained
                raise
        if not self._binding_closed:
            self.binding.close()
            self._binding_closed = True
        if not self._protection_closed:
            self.protection.close()
            self._protection_closed = True
        if not self._process_closed:
            self.process.close()
            self._process_closed = True
        self.closed = True


def main(argv=None):
    global _HOST
    parser = argparse.ArgumentParser()
    parser.add_argument("--registration", required=True)
    options = parser.parse_args(argv)
    if _HOST is not None:
        _fail("original_owner_already_retained")
    _HOST = ExperimentChildHost(options.registration)
    owner = _HOST
    # Creation precedes publication. A missing file means inert wait, never
    # permission to start a host, read machine samples or create another actor.
    while owner.registration is None:
        try:
            owner.authenticate()
        except FileNotFoundError:
            time.sleep(.1)
            continue
        except BaseException as error:
            owner._retain(error)
            break
    if not owner.errors:
        try:
            owner.dispatch()
            owner.run_host()
            owner.finish()
        except BaseException as error:
            owner._retain(error)
    # No parent death/timeout/exception is an exit or capacity release proof.
    # Original host methods own safe recovery; never construct a replacement.
    while not owner.closed:
        try:
            if owner.host_closed:
                owner.finish()
            elif owner.host is not None and owner.dispatched:
                from .guardian_host import GuardianHost
                from .wrapper_host import WrapperHost
                from .helper_control_host import OperationalHelperHost
                if type(owner.host) is GuardianHost:
                    owner.host.begin_drain()
                    if owner.host._started:
                        owner.host.drain_until_settled()
                    owner.host.close()
                    owner.host_closed = True
                elif type(owner.host) is WrapperHost:
                    owner.host.settle_release()
                    owner.host_closed = True
                elif type(owner.host) is OperationalHelperHost:
                    owner.host.request_drain("experiment_child_failure")
                    if owner.host._started:
                        owner.host.serve_until_stopped()
                    else:
                        owner.host.close()
                    owner.host_closed = True
            if not owner.closed:
                time.sleep(1)
        except BaseException as error:
            owner._retain(error)
            try:
                time.sleep(1)
            except BaseException as interruption:
                owner._retain(interruption)
    return 0 if not owner.errors else 3
