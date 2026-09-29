"""Authenticated closure of one original experimental host, never actor exit.

The child inspects its actual supported host and retained cleanup owners before
publishing. The parent retains a typed receipt tied to the accepted child and
the original CreationAttempt. Wire data and snapshots are audit evidence only;
aggregate retirement must separately prove actor exit and native handle closure.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import threading
from uuid import uuid4

from . import experiment_host_transport as child
from .contracts import ProcessIdentity, strict_json_loads
from .identity import VerifiedProcess
from .ipc import _canonical, _hex, _identity, _live, _remaining, _shape, _uuid
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeRegistry


DOMAIN = "ResourceSentinel/experiment-host-closed/v1"
MAX_ATTEMPTS = 8
MAX_CLOSURE_BYTES = 32768
_CREATE = object()
_PUBLICATIONS = {}
_PUBLICATIONS_LOCK = threading.Lock()


class ExperimentHostRetirementError(child.ExperimentChildError):
    pass


def _fail(reason):
    raise ExperimentHostRetirementError("experiment_host_retirement_" + reason)


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text(value, limit=1024):
    if (type(value) is not str or not 1 <= len(value) <= limit or
            any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        _fail("closure_invalid")


def _closure(value, role):
    """A bounded closed schema. This validates DATA, not cleanup authority."""
    if type(value) is not dict or value.get("kind") != role:
        _fail("closure_invalid")
    if role == "wrapper":
        if set(value) != {"kind", "execution_id", "native_owners_closed", "publication_request_id",
                          "publication_sha256", "launcher_phase"} or value["launcher_phase"] != "CLOSED":
            _fail("closure_invalid")
        _uuid(value["execution_id"])
        _uuid(value["publication_request_id"])
        _hex(value["publication_sha256"])
        if type(value["native_owners_closed"]) is not int or not 0 <= value["native_owners_closed"] <= 128:
            _fail("closure_invalid")
    elif role == "helper":
        if set(value) != {"kind", "instance_id", "operator_instance_id", "iterations", "mode"}:
            _fail("closure_invalid")
        _uuid(value["instance_id"])
        _uuid(value["operator_instance_id"])
        if value["mode"] != "shadow" or type(value["iterations"]) is not int or value["iterations"] < 0:
            _fail("closure_invalid")
    elif role == "guardian":
        if set(value) != {"kind", "jobs"} or type(value["jobs"]) is not list or len(value["jobs"]) > 10:
            _fail("closure_invalid")
        ids = []
        for job in value["jobs"]:
            if type(job) is not dict or set(job) != {"execution_id", "evidence_kind", "job_name",
                    "job_nonce", "manifest_hash", "receipt_sha256"}:
                _fail("closure_invalid")
            _uuid(job["execution_id"])
            _hex(job["manifest_hash"])
            _hex(job["receipt_sha256"])
            _text(job["job_name"])
            if (type(job["job_nonce"]) is not str or len(job["job_nonce"]) != 32 or
                    any(c not in "0123456789abcdef" for c in job["job_nonce"]) or
                    job["evidence_kind"] not in {"guardian_terminal_custody_closed",
                                                  "guardian_prelaunch_custody_closed"}):
                _fail("closure_invalid")
            ids.append(job["execution_id"])
        if ids != sorted(set(ids)):
            _fail("closure_invalid")
    else:
        _fail("closure_invalid")
    wire = _canonical(value)
    if len(wire) > MAX_CLOSURE_BYTES:
        _fail("closure_too_large")
    return wire


def _registry_closed(registry):
    if type(registry) is not NativePipeRegistry:
        _fail("original_registry_required")
    status = NativePipeRegistry.status(registry)
    if status.resources or status.pending or status.quarantined:
        _fail("pipe_cleanup_pending")


def _telemetry_closed(telemetry):
    from .telemetry import ResidentTelemetry, SharedTelemetryStore
    if (type(telemetry) is not ResidentTelemetry or type(telemetry.store) is not SharedTelemetryStore or
            telemetry._thread is None or telemetry._thread.is_alive() or
            telemetry._stop is not True or telemetry._done is not True or telemetry._error is not None or
            telemetry.store.retained_files or telemetry.store._quarantined or
            telemetry.store._quarantine_error is not None):
        _fail("telemetry_cleanup_pending")


def _listener_closed(listener):
    from .pipe_windows import NativePipeListener
    if type(listener) is not NativePipeListener:
        _fail("original_listener_required")
    owner = listener._owner
    if (owner._handle is not None or owner._operation is not None or owner._active is not None or
            owner._accept_operation is not None or owner._accept_connection is not None or
            owner._handle_close_unknown or owner._poisoned or owner._server_process is not None or
            owner._self_process is not None or owner._peer_process is not None):
        _fail("listener_cleanup_pending")


def _closed_process(process):
    if (type(process) is not VerifiedProcess or process._handle is not None or
            process._close_outcome_unknown is not False):
        _fail("native_cleanup_pending")


def _wrapper_closed(host, binding, spec):
    from .wrapper_host import WrapperHost
    from .launcher import ManagedLauncher, _ExperimentWrapperBinding
    WrapperHost._assert_experiment_host(host)
    original, launcher = host._experiment, host.launcher
    if (type(original) is not _ExperimentWrapperBinding or type(launcher) is not ManagedLauncher or
            original.authority.child_binding is not binding or original.spec is not spec.launch_spec or
            host._construction_unknown is not None):
        _fail("original_wrapper_required")
    _ExperimentWrapperBinding.assert_original(original, launcher)
    _ExperimentWrapperBinding.assert_publication_settled(original)
    original.authority._cleanup_observed()
    if (launcher._closed is not True or launcher.phase != "CLOSED" or launcher._admission_closed is not True or
            launcher._admission_close_unknown or launcher._transport_cleanup_unknown or
            launcher._mutex_construction_unknown):
        _fail("wrapper_cleanup_pending")
    owners = tuple(owner for owner in (launcher.process, launcher.job, launcher._launch_mutex,
                   *launcher._extra_cleanup_owners) if owner is not None)
    for owner in owners:
        record = launcher._cleanup_records.get(id(owner))
        if type(record) is not dict or record.get("owner") is not owner or record.get("state") != "closed":
            _fail("wrapper_cleanup_pending")
    if any(record.get("state") != "closed" for record in launcher._cleanup_records.values()):
        _fail("wrapper_cleanup_pending")
    request = original.publication.request
    return (dict(kind="wrapper", execution_id=original.snapshot.execution_id,
                 native_owners_closed=len({id(owner) for owner in owners}),
                 publication_request_id=request.request_id, publication_sha256=request.payload_sha256,
                 launcher_phase="CLOSED"), (original, launcher, *owners))


def _helper_closed(host, binding, spec):
    from .helper_host import JobHandleSource
    from .helper_control_host import OperationalHelperHost
    from .contracts import Mode
    if (type(host) is not OperationalHelperHost or host._experiment_child_binding is not binding or
            host._experiment_role_spec is not spec or host._closed is not True or host._started is not False or
            host._operator_ready is not True or host._cleanup_started is not True or
            host._drain_requested is not True or host._startup_error is not None or
            host._cleanup_error is not None or host._operator_error is not None or
            host.process is not None or host.parent_process is not None or host.operator_listener is not None or
            host._listener_factory is not None or host._observer_factory is not None or host._parent_opener is not None):
        _fail("helper_cleanup_pending")
    fields = (host.data_dir, host.profile_path, host.enroll_every_ticks, host.report_every_ticks,
              host.instance_id, host.operator_instance_id, host.parent_instance_id, host.policy_instance_id,
              host.guardian_epoch, host.parent_identity, host.guardian_endpoint)
    if (type(host._experiment_retirement_fields) is not tuple or fields != host._experiment_retirement_fields or
            fields[:4] != (Path(spec.data_dir), Path(spec.profile_path), spec.enroll_every_ticks,
                           spec.report_every_ticks) or host.profile.mode is not Mode.SHADOW):
        _fail("original_helper_changed")
    context = binding.role_release_context(spec)
    if any(getattr(host, name) != value for name, value in context.items()):
        _fail("original_helper_changed")
    owners = host._experiment_retirement_owners
    if type(owners) is not tuple or len(owners) != 6:
        _fail("original_helper_owners_required")
    process, parent, listener, registry, jobs, telemetry = owners
    if (process.identity != binding._manifest.child_identity or parent.identity != host.parent_identity or
            registry is not host._pipe_registry or jobs is not host.jobs or telemetry is not host.telemetry or
            type(jobs) is not JobHandleSource or jobs.enrolled or jobs.retained_uncertain):
        _fail("original_helper_owners_changed")
    _closed_process(process)
    _closed_process(parent)
    _listener_closed(listener)
    _registry_closed(registry)
    _telemetry_closed(telemetry)
    operation = host._registration_operation
    if operation is None or operation.pending or operation._quarantine:
        _fail("helper_registration_unsettled")
    return (dict(kind="helper", instance_id=host.instance_id, operator_instance_id=host.operator_instance_id,
                 iterations=host._iterations, mode="shadow"), owners)


def _guardian_closed(host, binding, spec):
    from .guardian_host import GuardianHost
    from .terminal_custody import TerminalCustody
    from .prelaunch_receipt import PrelaunchReceiptOperation
    GuardianHost._assert_experiment_host(host)
    if host._experiment_binding is not binding or host._experiment_original[0] is not spec:
        _fail("original_guardian_required")
    retained = GuardianHost.closed_experiment_custody(host)
    if type(retained) is not tuple or len(retained) > 10:
        _fail("guardian_custody_required")
    jobs = []
    for item in retained:
        if type(item) is not tuple or len(item) != 3:
            _fail("guardian_custody_required")
        kind, entry, custody = item
        if kind == "terminal" and type(custody) is TerminalCustody:
            operation = custody.receipt_operation
            if (entry.terminal_cleanup is not custody or entry.closed is not True or
                    custody.native_complete is not True or custody.quarantined or custody.proof_published is not True):
                _fail("guardian_custody_unsettled")
        elif kind == "prelaunch" and type(custody) is PrelaunchReceiptOperation:
            operation = custody
            if entry.retirement_receipt_operation is not custody:
                _fail("guardian_custody_unsettled")
        else:
            _fail("guardian_custody_required")
        if (operation is None or operation._candidate is None or operation._operation._changed is not True or
                operation._operation.pending or operation._operation._quarantine):
            _fail("guardian_receipt_unsettled")
        body = operation._candidate
        if (body["execution_id"] != entry.execution_id or
                body["guardian_identity"] != binding._manifest.child_identity.to_dict()):
            _fail("guardian_receipt_changed")
        jobs.append(dict(execution_id=body["execution_id"], evidence_kind=body["evidence_kind"],
            job_name=body["job_name"], job_nonce=body["job_nonce"], manifest_hash=body["manifest_hash"],
            receipt_sha256=_digest(body)))
    _telemetry_closed(host.telemetry)
    return dict(kind="guardian", jobs=sorted(jobs, key=lambda value: value["execution_id"])), retained


def _closed_host(host, binding, process):
    """Fixed class dispatch; no caller-provided bool, snapshot or callback."""
    from .guardian_host import GuardianHost
    from .wrapper_host import WrapperHost
    from .helper_control_host import OperationalHelperHost
    from .experiment_host_roles import GuardianRoleSpec, WrapperRoleSpec, HelperRoleSpec
    if type(binding) is not child.ExperimentChildBinding or type(process) is not VerifiedProcess:
        _fail("original_child_required")
    manifest = binding.manifest
    if binding._process is not process:
        _fail("original_process_required")
    child._current(process, manifest.child_identity)
    spec = binding.released_role
    supported = {GuardianHost: ("guardian", GuardianRoleSpec, _guardian_closed),
                 WrapperHost: ("wrapper", WrapperRoleSpec, _wrapper_closed),
                 OperationalHelperHost: ("helper", HelperRoleSpec, _helper_closed)}
    if type(host) not in supported:
        _fail("supported_original_host_required")
    role, role_type, inspect = supported[type(host)]
    if manifest.role != role or type(spec) is not role_type or spec.member_id != manifest.actor_member_id:
        _fail("original_role_required")
    data, owners = inspect(host, binding, spec)
    return _closure(data, role), owners


@dataclass(frozen=True)
class PublishHostClosedRequest:
    manifest: child.ExperimentChildManifest
    request_id: str
    closure_json: bytes

    def __post_init__(self):
        if type(self.manifest) is not child.ExperimentChildManifest or type(self.closure_json) is not bytes:
            _fail("request_invalid")
        _uuid(self.request_id)
        if (self.request_id == self.manifest.request_id or
                _closure(strict_json_loads(self.closure_json), self.manifest.role) != self.closure_json):
            _fail("request_invalid")

    @property
    def closure(self):
        return strict_json_loads(self.closure_json)

    @property
    def payload_sha256(self):
        return _digest(dict(domain=DOMAIN, manifest=self.manifest.to_dict(), request_id=self.request_id,
                            closure=self.closure))

    def to_dict(self):
        return dict(version=1, kind="PublishExperimentHostClosed", manifest=self.manifest.to_dict(),
                    request_id=self.request_id, closure=self.closure, payload_sha256=self.payload_sha256)

    @classmethod
    def from_dict(cls, value):
        _shape(value, "PublishExperimentHostClosed", {"manifest", "closure", "payload_sha256"})
        _hex(value["payload_sha256"])
        manifest = child.ExperimentChildManifest.from_dict(value["manifest"])
        result = cls(manifest, value["request_id"], _closure(value["closure"], manifest.role))
        if not hmac.compare_digest(result.payload_sha256, value["payload_sha256"]):
            _fail("payload_digest_mismatch")
        return result


def _challenge(request):
    value = child._challenge(request)
    value.update(kind="ExperimentHostRetirementChallenge", payload_sha256=request.payload_sha256)
    return value


def _check_challenge(value, request):
    _shape(value, "ExperimentHostRetirementChallenge", {"nonce", "endpoint_id", "server", "client", "payload_sha256"})
    _hex(value["nonce"])
    if (value["request_id"] != request.request_id or value["payload_sha256"] != request.payload_sha256 or
            value["endpoint_id"] != request.manifest.endpoint.instance_id or
            _identity(value["server"]) != request.manifest.endpoint.server_identity or
            _identity(value["client"]) != request.manifest.child_identity):
        _fail("challenge_mismatch")


def _mac(key, purpose, request, challenge, result=None):
    if purpose not in {"proof", "result", "receipt"}:
        _fail("domain_invalid")
    transcript = dict(domain="ResourceSentinel/experiment-host-retirement-ipc/v1/" + purpose,
                      request=request.to_dict(), challenge=challenge)
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, _canonical(transcript), hashlib.sha256).hexdigest()


def _result(request):
    return dict(actor_member_id=request.manifest.actor_member_id, payload_sha256=request.payload_sha256)


def _failure(error, owner, attempt):
    attempt.fail(error)
    failure = ExperimentHostRetirementError("experiment_host_retirement_rpc_failed")
    failure.original_error, failure.transport_owner, failure.attempt = error, owner, attempt
    failure.experiment_host_retirement_publication = owner
    return failure


class AcceptedHostRetirement:
    """Exact parent service receipt; a copied audit dictionary has no authority."""
    def __init__(self, service, registration, request, actor, *, _token=None):
        if _token is not _CREATE:
            _fail("original_receipt_required")
        self.service, self.registration, self.request, self.actor = service, registration, request, actor
        self._wire = _canonical(request.to_dict())
        self._fixed = (service, registration, request, actor, self._wire)
        self._attempts = []

    def __reduce__(self):
        raise TypeError("original_host_retirement_not_serializable")

    def assert_original(self, scope):
        from .experiment_host_creation import CreationAttempt
        if type(self) is not AcceptedHostRetirement:
            _fail("original_receipt_required")
        service, registration, request, actor, wire = self._fixed
        if (self.service is not service or self.registration is not registration or self.request is not request or
                self.actor is not actor or self._wire != wire or _canonical(request.to_dict()) != wire or
                service.owner is not scope or service._receipts.get(request.manifest.actor_member_id) is not self):
            _fail("original_receipt_changed")
        ExperimentHostRetirementService._retained_original(service, scope)
        if (scope._accepted_children.get(request.manifest.request_id) is not registration or
                scope._child_registrations.get(request.manifest.actor_member_id) != (actor[0], registration) or
                scope._published_actors.get(request.manifest.actor_member_id) is not actor or
                actor[1] != request.manifest.child_identity or type(actor[0]) is not CreationAttempt):
            _fail("original_registration_changed")
        CreationAttempt.assert_original(actor[0], scope)
        if (not self._attempts or any(not any(item is original for original in service._attempts)
                                    for item in self._attempts) or
                not any(item.exchange_complete is True and not item.cleanup_pending for item in self._attempts)):
            _fail("retirement_exchange_unsettled")
        return self

    def snapshot(self):
        self.assert_original(self.service.owner)
        request = self.request
        return dict(version=1, domain=DOMAIN, actor_member_id=request.manifest.actor_member_id,
                    role=request.manifest.role, child_identity=request.manifest.child_identity.to_dict(),
                    manifest_sha256=_digest(request.manifest.to_dict()), request_id=request.request_id,
                    payload_sha256=request.payload_sha256, closure=request.closure)


class ExperimentHostRetirementService:
    def __init__(self, endpoint, owner):
        from .experiment_host_scope import ProductionExperimentScope
        if type(endpoint) is not NativePipeEndpoint or type(owner) is not ProductionExperimentScope:
            _fail("original_scope_required")
        self.endpoint, self.owner = endpoint, owner
        self._process = ProductionExperimentScope._assert_transport_original(owner, endpoint)
        child._current(self._process, endpoint.server_identity)
        self._native_pin = child._NativePin(self._process)
        self._attempts, self._receipts = [], {}
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._fixed = (endpoint, owner, self._process, self._native_pin, self._attempts, self._receipts,
                       self._thread, self._pid)
        ProductionExperimentScope._retain_retirement_transport(owner, self)

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _retained_original(self, scope):
        from .experiment_host_scope import ProductionExperimentScope
        if type(self) is not ExperimentHostRetirementService or type(scope) is not ProductionExperimentScope:
            _fail("original_service_required")
        values = (self.endpoint, self.owner, self._process, self._native_pin, self._attempts, self._receipts,
                  self._thread, self._pid)
        if (any(a is not b for a, b in zip(values, self._fixed)) or self.owner is not scope or
                scope._retirement_service is not self or self._thread is not threading.current_thread() or
                self._pid != os.getpid()):
            _fail("original_service_changed")
        self._native_pin.check()
        if any(attempt.cleanup_pending for attempt in self._attempts):
            _fail("service_cleanup_pending")

    def _original(self):
        from .experiment_host_scope import ProductionExperimentScope
        # A currently serving attempt is intentionally not yet channel-settled.
        endpoint, owner, process, pin, attempts, receipts, thread, pid = self._fixed
        if (self.endpoint is not endpoint or self.owner is not owner or self._process is not process or
                self._native_pin is not pin or self._attempts is not attempts or self._receipts is not receipts or
                self._thread is not thread or thread is not threading.current_thread() or self._pid != pid or
                os.getpid() != pid or owner._retirement_service is not self or
                ProductionExperimentScope._assert_transport_original(owner, endpoint) is not process):
            _fail("original_service_changed")
        pin.check()
        child._current(process, endpoint.server_identity)

    def serve_once(self, listener, *, timeout_ms=1000):
        child._no_mutex()
        child._timeout(timeout_ms)
        self._original()
        if listener.endpoint != self.endpoint or len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
            _fail("listener_or_limit_invalid")
        attempt = child._Attempt()
        self._attempts.append(attempt)
        deadline = NativeDeadline.after_ms(timeout_ms)
        try:
            attempt.channel_origin, attempt.channel_started = listener, True
            with child._settled_scope(listener.accept(deadline), attempt, "channel") as connection:
                self._serve_connection(connection, deadline, attempt)
            _remaining(deadline)
            self._original()
            attempt.seal()
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_host_retirement_service = self
            raise

    def _serve_connection(self, connection, deadline, attempt, *, hello=None):
        from .experiment_host_scope import ProductionExperimentScope
        from .experiment_host_creation import CreationAttempt
        self._original()
        if type(attempt) is not child._Attempt:
            _fail("original_attempt_required")
        if not any(attempt is original for original in self._attempts):
            if len(self._attempts) >= child.MAX_SERVER_ATTEMPTS:
                _fail("attempt_limit")
            self._attempts.append(attempt)
        if hello is None:
            hello = child._read(connection, deadline, limit=child.MAX_HELLO_BYTES)
        _shape(hello, "ExperimentHostRetirementHello", {"caller"})
        caller = _identity(hello["caller"])
        if caller.logon_id != self.endpoint.logon_id:
            _fail("peer_logon_mismatch")
        with child._settled_scope(connection.verified_peer(caller), attempt, "peer") as peer:
            if type(peer) is not VerifiedProcess:
                _fail("original_peer_required")
            _live(connection, peer, caller)
            request = PublishHostClosedRequest.from_dict(child._read(connection, deadline))
            if (request.request_id != hello["request_id"] or request.manifest.child_identity != caller or
                    request.manifest.endpoint != self.endpoint):
                _fail("request_binding_mismatch")
            registration = ProductionExperimentScope._transport_child_registration(self.owner,
                child.BindExperimentChildRequest(request.manifest), peer)
            actor = self.owner._published_actors.get(request.manifest.actor_member_id)
            if (type(registration) is not child.ExperimentChildRegistration or registration.manifest != request.manifest or
                    self.owner._accepted_children.get(request.manifest.request_id) is not registration or
                    type(actor) is not tuple or len(actor) != 2 or type(actor[0]) is not CreationAttempt or
                    actor[1] != caller):
                _fail("original_registration_required")
            CreationAttempt.assert_original(actor[0], self.owner)
            self._original()
            challenge = _challenge(request)
            child._write(connection, challenge, deadline)
            proof = child._read(connection, deadline)
            child._correlated(proof, "ExperimentHostRetirementProof", request, challenge)
            if not hmac.compare_digest(proof["mac"], _mac(registration.auth_key, "proof", request, challenge)):
                _fail("authentication_failed")
            _live(connection, peer, caller)
            _remaining(deadline)
            receipt_owner = self._receipts.get(request.manifest.actor_member_id)
            if receipt_owner is None:
                receipt_owner = AcceptedHostRetirement(self, registration, request, actor, _token=_CREATE)
                self._receipts[request.manifest.actor_member_id] = receipt_owner
            elif (receipt_owner.registration is not registration or receipt_owner.actor is not actor or
                    receipt_owner._wire != _canonical(request.to_dict())):
                _fail("original_retirement_changed")
            receipt_owner._attempts.append(attempt)
            attempt.accepted = True
            payload = _result(request)
            response = child._envelope("ExperimentHostRetirementResult", request, challenge,
                                      _mac(registration.auth_key, "result", request, challenge, payload))
            response["result"] = payload
            child._write(connection, response, deadline)
            receipt = child._read(connection, deadline)
            child._correlated(receipt, "ExperimentHostRetirementReceipt", request, challenge)
            if not hmac.compare_digest(receipt["mac"], _mac(registration.auth_key, "receipt", request, challenge, payload)):
                _fail("receipt_invalid")
            _live(connection, peer, caller)
            _remaining(deadline)
            attempt.exchange_complete = True


class ExperimentHostRetirementPublication:
    def __init__(self, *, _token=None):
        if _token is not _CREATE:
            _fail("original_factory_required")

    def __reduce__(self):
        raise TypeError("original_host_retirement_publication_not_serializable")

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _retained_original(self):
        values = (self.host, self.child_binding, self.process, self.request, self._wire,
                  self._registry, self._owners, self._attempts, self._thread, self._pid, self._key)
        if (type(self) is not ExperimentHostRetirementPublication or
                any(a is not b for a, b in zip(values, self._fixed)) or
                threading.current_thread() is not self._thread or os.getpid() != self._pid or
                _PUBLICATIONS.get(self._key) is not self or _canonical(self.request.to_dict()) != self._wire):
            _fail("original_publication_changed")
        self.child_binding._check_original()

    def _original(self):
        self._retained_original()
        wire, owners = _closed_host(self.host, self.child_binding, self.process)
        if (wire != self.request.closure_json or len(owners) != len(self._owners) or
                any(a is not b for a, b in zip(owners, self._owners))):
            _fail("original_closure_changed")

    @property
    def custody_pending(self):
        self._retained_original()
        status = self._registry.status()
        return (self._result is None or any(attempt.cleanup_pending for attempt in self._attempts) or
                bool(status.resources or status.pending or status.quarantined))

    def assert_settled(self):
        self._original()
        if (self.custody_pending or self._result != _result(self.request) or
                not any(attempt.exchange_complete is True for attempt in self._attempts)):
            _fail("publication_unsettled")

    def publish(self, *, timeout_ms=1000):
        child._no_mutex()
        child._timeout(timeout_ms)
        self._original()
        if any(attempt.cleanup_pending for attempt in self._attempts):
            _fail("original_cleanup_pending")
        _registry_closed(self._registry)
        if self._result is not None:
            self.assert_settled()
            return self._result.copy()
        if len(self._attempts) >= MAX_ATTEMPTS:
            _fail("attempt_limit")
        attempt = child._Attempt()
        self._attempts.append(attempt)
        request, endpoint = self.request, self.request.manifest.endpoint
        deadline = NativeDeadline.after_ms(timeout_ms)
        try:
            attempt.channel_origin, attempt.channel_started = self._registry, True
            with child._settled_scope(NativePipeConnection.connect(endpoint, deadline, registry=self._registry),
                                      attempt, "channel") as connection:
                with child._settled_scope(connection.verified_peer(endpoint.server_identity), attempt, "peer") as peer:
                    if type(peer) is not VerifiedProcess:
                        _fail("original_peer_required")
                    _live(connection, peer, endpoint.server_identity)
                    self._original()
                    child._write(connection, dict(version=1, kind="ExperimentHostRetirementHello",
                        request_id=request.request_id, caller=request.manifest.child_identity.to_dict()), deadline,
                        limit=child.MAX_HELLO_BYTES)
                    child._write(connection, request.to_dict(), deadline)
                    challenge = child._read(connection, deadline)
                    _check_challenge(challenge, request)
                    _live(connection, peer, endpoint.server_identity)
                    key = self.child_binding._client.registration.auth_key
                    attempt.accepted = True
                    child._write(connection, child._envelope("ExperimentHostRetirementProof", request, challenge,
                        _mac(key, "proof", request, challenge)), deadline)
                    response = child._read(connection, deadline)
                    child._correlated(response, "ExperimentHostRetirementResult", request, challenge, result=True)
                    payload = response["result"]
                    if (payload != _result(request) or not hmac.compare_digest(response["mac"],
                            _mac(key, "result", request, challenge, payload))):
                        _fail("result_authentication_failed")
                    _live(connection, peer, endpoint.server_identity)
                    self._original()
                    child._write(connection, child._envelope("ExperimentHostRetirementReceipt", request, challenge,
                        _mac(key, "receipt", request, challenge, payload)), deadline)
                    attempt.exchange_complete = True
            _remaining(deadline)
            self._original()
            self._result = payload.copy()
            attempt.seal()
            return payload.copy()
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_host_retirement_publication = self
            raise


def publish_host_closed(host, child_binding, current_process):
    child._no_mutex()
    if type(child_binding) is not child.ExperimentChildBinding or type(current_process) is not VerifiedProcess:
        _fail("original_child_required")
    manifest = child_binding.manifest
    key = (os.getpid(), manifest.child_identity, manifest.scope_id, manifest.actor_member_id)
    with _PUBLICATIONS_LOCK:
        owner = _PUBLICATIONS.get(key)
        if owner is None:
            wire, owners = _closed_host(host, child_binding, current_process)
            owner = ExperimentHostRetirementPublication(_token=_CREATE)
            owner.host, owner.child_binding, owner.process = host, child_binding, current_process
            owner.request = PublishHostClosedRequest(manifest, str(uuid4()), wire)
            owner._wire, owner._owners = _canonical(owner.request.to_dict()), owners
            owner._registry, owner._attempts = NativePipeRegistry(max_resources=1), []
            owner._thread, owner._pid, owner._key = threading.current_thread(), os.getpid(), key
            owner._fixed = (host, child_binding, current_process, owner.request, owner._wire,
                owner._registry, owners, owner._attempts, owner._thread, owner._pid, key)
            owner._result = None
            _PUBLICATIONS[key] = owner
        elif owner.host is not host or owner.child_binding is not child_binding or owner.process is not current_process:
            _fail("original_publication_retained")
    try:
        owner.publish()
    except BaseException as error:
        error.experiment_host_retirement_publication = owner
        raise
    return owner


def retained_retirements(scope):
    """Metadata-only retained receipts; caller separately closes actor/listener owners."""
    from .experiment_host_scope import ProductionExperimentScope
    if type(scope) is not ProductionExperimentScope:
        _fail("original_scope_required")
    service = scope._retirement_service
    if type(service) is not ExperimentHostRetirementService:
        _fail("original_service_required")
    ExperimentHostRetirementService._retained_original(service, scope)
    receipts = tuple(service._receipts[key] for key in sorted(service._receipts))
    for receipt in receipts:
        AcceptedHostRetirement.assert_original(receipt, scope)
    return receipts
