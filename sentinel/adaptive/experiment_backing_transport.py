"""Publish an existing aggregate partition's backing through its original parent.

The child retains its real ManagedAdmission and authenticated child binding.
Wire observations intentionally omit credentials, raw commands and attribution.
The parent retains ONE redacted snapshot only as ParentAdmissionBacking DATA;
it cannot reconstruct ManagedAdmission, verify its secret binding hash, launch,
renew a lease or release capacity. The fixed parent method owns publication and
must finish all local SQL/POLICY scopes before any response I/O.

This phased service shares the existing pinned parent endpoint. It supplies no
general dispatcher or host startup. An actual provider must choose this fixed
phase after accepting the original wrapper child binding.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import os
import threading

from sentinel.coordinator import ResourceRequest
from .admission import ManagedAdmission, ManagedAdmissionSnapshot
from .contracts import Priority, ProcessIdentity, ResourceDemand, Role
from . import experiment_host_backing as backing
from . import experiment_host_transport as child
from .identity import VerifiedProcess
from .ipc import _canonical, _hex, _identity, _live, _remaining, _shape, _uuid
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeRegistry


MAX_SNAPSHOT_BYTES = 8192
MAX_ATTEMPTS = 8
_CREATE = object()
_PUBLICATIONS = {}
_PUBLICATIONS_LOCK = threading.Lock()


class ExperimentBackingTransportError(child.ExperimentChildError):
    pass


def _fail(reason):
    raise ExperimentBackingTransportError("experiment_backing_transport_" + reason)


@dataclass(frozen=True)
class AdmissionSnapshotObservation:
    """Credential-free metadata. Never a complete original admission snapshot."""
    execution_id: str
    wrapper_identity: ProcessIdentity
    requested: ResourceDemand
    role: Role
    priority: Priority
    repo_identifier: str
    spec_hash: str
    binding_hash: str
    parent_snapshot: ManagedAdmissionSnapshot = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        _uuid(self.execution_id)
        _hex(self.spec_hash)
        _hex(self.binding_hash)
        if (type(self.wrapper_identity) is not ProcessIdentity or type(self.requested) is not ResourceDemand or
                type(self.role) is not Role or type(self.priority) is not Priority or
                type(self.repo_identifier) is not str or not 1 <= len(self.repo_identifier) <= 1024 or
                any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in self.repo_identifier)):
            _fail("observation_invalid")
        identity, demand = self.wrapper_identity, self.requested
        request = ResourceRequest(owner_pid=identity.pid,
            owner_started=(identity.created_filetime_100ns - 116444736000000000) / 10_000_000,
            repo=self.repo_identifier, command="", resource_class="HEAVY", priority=self.priority.value,
            tool_use_id="managed-v1:" + self.execution_id, cpu_units=float(demand.cpu_units),
            ram_gib=demand.physical_bytes / (1 << 30), io_slots=demand.io_slots,
            signature=self.spec_hash[:20], commit_bytes=demand.commit_bytes).normalized()
        if (request.cpu_units != demand.cpu_units or request.ram_gib * (1 << 30) != demand.physical_bytes):
            _fail("resource_conversion_inexact")
        # Empty unused fields are deliberate: this is observation-only input to
        # _snapshot_binding, never a valid launch/admission credential bundle.
        snapshot = ManagedAdmissionSnapshot(self.execution_id, "", "", "", identity.logon_id,
            identity, self.spec_hash, self.binding_hash, "", b"", demand, self.role, self.priority, request)
        object.__setattr__(self, "parent_snapshot", snapshot)
        if len(_canonical(self.to_dict())) > MAX_SNAPSHOT_BYTES:
            _fail("observation_too_large")

    def to_dict(self):
        return dict(execution_id=self.execution_id, wrapper_identity=self.wrapper_identity.to_dict(),
            requested=self.requested.to_dict(), role=self.role.value, priority=self.priority.value,
            repo_identifier=self.repo_identifier, spec_hash=self.spec_hash, binding_hash=self.binding_hash)

    @classmethod
    def from_snapshot(cls, snapshot):
        if type(snapshot) is not ManagedAdmissionSnapshot:
            _fail("original_snapshot_required")
        if type(snapshot.request) is not ResourceRequest:
            _fail("original_request_required")
        value = cls(snapshot.execution_id, snapshot.wrapper_identity, snapshot.requested, snapshot.role,
                    snapshot.priority, snapshot.request.repo, snapshot.spec_hash, snapshot.binding_hash)
        if snapshot.request != value.parent_snapshot.request or snapshot.logon_id != snapshot.wrapper_identity.logon_id:
            _fail("original_request_changed")
        return value

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"execution_id", "wrapper_identity", "requested", "role",
                "priority", "repo_identifier", "spec_hash", "binding_hash"}:
            _fail("observation_invalid")
        if len(_canonical(value)) > MAX_SNAPSHOT_BYTES:
            _fail("observation_too_large")
        return cls(value["execution_id"], _identity(value["wrapper_identity"]),
            ResourceDemand.from_dict(value["requested"]), Role(value["role"]), Priority(value["priority"]),
            value["repo_identifier"], value["spec_hash"], value["binding_hash"])


@dataclass(frozen=True)
class PublishExperimentBackingRequest:
    manifest: child.ExperimentChildManifest
    request_id: str
    member_id: str
    reservation_id: str
    observation: AdmissionSnapshotObservation

    def __post_init__(self):
        if type(self.manifest) is not child.ExperimentChildManifest or type(self.observation) is not AdmissionSnapshotObservation:
            _fail("request_invalid")
        _uuid(self.request_id)
        _uuid(self.member_id)
        backing.ledger._text(self.reservation_id)
        if (self.request_id == self.manifest.request_id or self.manifest.role != "wrapper" or
                self.member_id == self.manifest.actor_member_id or
                self.member_id not in self.manifest.permitted_member_ids or
                self.observation.wrapper_identity != self.manifest.child_identity):
            _fail("request_binding_mismatch")
        self.binding
        _canonical(self.to_dict())

    @property
    def binding(self):
        return backing._snapshot_binding(self.observation.parent_snapshot, self.reservation_id)

    def _payload(self):
        return dict(domain="ResourceSentinel/experiment-backing-publication/v1",
            manifest=self.manifest.to_dict(), request_id=self.request_id, member_id=self.member_id,
            reservation_id=self.reservation_id, observation=self.observation.to_dict())

    @property
    def payload_sha256(self):
        return hashlib.sha256(_canonical(self._payload())).hexdigest()

    def to_dict(self):
        return dict(version=1, kind="PublishExperimentBacking", request_id=self.request_id,
            manifest=self.manifest.to_dict(), member_id=self.member_id, reservation_id=self.reservation_id,
            observation=self.observation.to_dict(), payload_sha256=self.payload_sha256)

    @classmethod
    def from_dict(cls, value):
        _shape(value, "PublishExperimentBacking", {"manifest", "member_id", "reservation_id",
                                                   "observation", "payload_sha256"})
        _hex(value["payload_sha256"])
        result = cls(child.ExperimentChildManifest.from_dict(value["manifest"]), value["request_id"],
            value["member_id"], value["reservation_id"], AdmissionSnapshotObservation.from_dict(value["observation"]))
        if not hmac.compare_digest(result.payload_sha256, value["payload_sha256"]):
            _fail("payload_digest_mismatch")
        return result


def _result(value, request):
    if (type(value) is not backing.BackingObservation or type(value.binding) is not backing.IsolatedAdmissionBinding or
            value.scope_id != request.manifest.scope_id or value.member_id != request.member_id or
            value.wrapper_member_id != request.manifest.actor_member_id or value.binding != request.binding or
            type(value.registered_revision) is not int or value.registered_revision < 1 or
            type(value.daily_expires_at) not in (int, float) or not math.isfinite(value.daily_expires_at) or
            value.daily_expires_at <= 0):
        _fail("result_invalid")
    _hex(value.binding_sha256)
    return dict(scope_id=value.scope_id, member_id=value.member_id, wrapper_member_id=value.wrapper_member_id,
        binding=value.binding.to_dict(), registered_revision=value.registered_revision,
        binding_sha256=value.binding_sha256, daily_expires_at=value.daily_expires_at)


def _decode_result(value, request):
    if type(value) is not dict or set(value) != {"scope_id", "member_id", "wrapper_member_id", "binding",
            "registered_revision", "binding_sha256", "daily_expires_at"}:
        _fail("result_invalid")
    if value["binding"] != request.binding.to_dict():
        _fail("result_binding_mismatch")
    result = backing.BackingObservation(value["scope_id"], value["member_id"], value["wrapper_member_id"],
        request.binding, value["registered_revision"], value["binding_sha256"], value["daily_expires_at"])
    _result(result, request)
    return result


def _challenge(request):
    value = child._challenge(request)
    value["kind"] = "ExperimentBackingChallenge"
    value["payload_sha256"] = request.payload_sha256
    return value


def _check_challenge(value, request):
    _shape(value, "ExperimentBackingChallenge", {"nonce", "endpoint_id", "server", "client", "payload_sha256"})
    _hex(value["nonce"])
    if (value["request_id"] != request.request_id or value["payload_sha256"] != request.payload_sha256 or
            value["endpoint_id"] != request.manifest.endpoint.instance_id or
            _identity(value["server"]) != request.manifest.endpoint.server_identity or
            _identity(value["client"]) != request.manifest.child_identity):
        _fail("challenge_mismatch")


def _mac(key, purpose, request, challenge, result=None):
    if purpose not in {"proof", "result", "receipt"}:
        _fail("domain_invalid")
    transcript = dict(domain="ResourceSentinel/experiment-backing-ipc/v1/" + purpose,
                      request=request.to_dict(), challenge=challenge)
    if purpose != "proof":
        transcript["result"] = result
    return hmac.new(key, _canonical(transcript), hashlib.sha256).hexdigest()


def _failure(error, owner, attempt):
    attempt.fail(error)
    failure = ExperimentBackingTransportError("experiment_backing_transport_rpc_failed")
    failure.original_error, failure.transport_owner, failure.attempt = error, owner, attempt
    return failure


def _before_submission(context):
    """This intent precedes isolated admission; it cannot backfill ordinary work."""
    context._require_unsealed()
    context._require_settled_submission()
    if (context._submitted is not False or context._admission_db_path is not None or
            context._submission_transaction is not None or context._claim_exported is not False or
            context._prepare_attempted is not False):
        _fail("admission_or_launch_already_started")


class ExperimentBackingService:
    """Only the exact original parent can authorize and publish backing."""
    def __init__(self, endpoint, owner):
        from .experiment_host_scope import ProductionExperimentScope
        if type(endpoint) is not NativePipeEndpoint or type(owner) is not ProductionExperimentScope:
            _fail("original_scope_required")
        self.endpoint, self.owner = endpoint, owner
        self._process = ProductionExperimentScope._assert_transport_original(owner, endpoint)
        child._current(self._process, endpoint.server_identity)
        self._native_pin = child._NativePin(self._process)
        self._fixed = (endpoint, owner, self._process, self._native_pin)
        self._attempts = []
        ProductionExperimentScope._retain_backing_transport(owner, self)

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _original(self):
        from .experiment_host_scope import ProductionExperimentScope
        endpoint, owner, process, pin = self._fixed
        if (self.endpoint is not endpoint or self.owner is not owner or self._process is not process or
                self._native_pin is not pin or
                ProductionExperimentScope._assert_transport_original(owner, endpoint) is not process):
            _fail("original_scope_changed")
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
            error.experiment_backing_service, error.experiment_backing_attempt = self, attempt
            raise

    def _serve_connection(self, connection, deadline, attempt):
        from .experiment_host_scope import ProductionExperimentScope
        hello = child._read(connection, deadline, limit=child.MAX_HELLO_BYTES)
        _shape(hello, "ExperimentBackingHello", {"caller"})
        caller = _identity(hello["caller"])
        if caller.logon_id != self.endpoint.logon_id:
            _fail("peer_logon_mismatch")
        with child._settled_scope(connection.verified_peer(caller), attempt, "peer") as peer:
            if type(peer) is not VerifiedProcess:
                _fail("original_peer_required")
            _live(connection, peer, caller)
            request = PublishExperimentBackingRequest.from_dict(child._read(connection, deadline))
            if (request.request_id != hello["request_id"] or request.manifest.child_identity != caller or
                    request.manifest.endpoint != self.endpoint):
                _fail("request_binding_mismatch")
            registration = ProductionExperimentScope._transport_backing_registration(self.owner, request, peer)
            if type(registration) is not child.ExperimentChildRegistration or registration.manifest != request.manifest:
                _fail("original_registration_required")
            self._original()
            child._no_mutex()
            _live(connection, peer, caller)
            challenge = _challenge(request)
            child._write(connection, challenge, deadline)
            proof = child._read(connection, deadline)
            child._correlated(proof, "ExperimentBackingProof", request, challenge)
            if not hmac.compare_digest(proof["mac"], _mac(registration.auth_key, "proof", request, challenge)):
                _fail("authentication_failed")
            _live(connection, peer, caller)
            _remaining(deadline)
            # The parent may commit even if its return/response is lost. Its
            # original operation must already be retained before its first SQL.
            attempt.accepted = True
            observed = ProductionExperimentScope._publish_transport_backing(self.owner, request, peer, registration)
            child._no_mutex()
            self._original()
            _live(connection, peer, caller)
            payload = _result(observed, request)
            response = child._envelope("ExperimentBackingResult", request, challenge,
                                       _mac(registration.auth_key, "result", request, challenge, payload))
            response["result"] = payload
            child._write(connection, response, deadline)
            receipt = child._read(connection, deadline)
            child._correlated(receipt, "ExperimentBackingReceipt", request, challenge)
            if not hmac.compare_digest(receipt["mac"], _mac(registration.auth_key, "receipt", request, challenge, payload)):
                _fail("receipt_invalid")
            _live(connection, peer, caller)
            _remaining(deadline)
            attempt.exchange_complete = True


class ExperimentBackingPublication:
    """One original child's publication; retries retain the same request/data."""
    def __init__(self, *, _token=None):
        if _token is not _CREATE:
            _fail("original_factory_required")

    def __reduce__(self):
        raise TypeError("experiment_backing_publication_not_serializable")

    @classmethod
    def prepare(cls, child_binding, context, *, member_id, reservation_id, request_id):
        child._no_mutex()
        if (cls is not ExperimentBackingPublication or type(child_binding) is not child.ExperimentChildBinding or
                type(context) is not ManagedAdmission or getattr(context, "_experiment_demand", None) is not None):
            _fail("original_child_context_required")
        manifest = child_binding.manifest
        child_binding.revalidate(manifest, role="wrapper", member_id=member_id)
        snapshot = context.snapshot()
        _before_submission(context)
        request = PublishExperimentBackingRequest(manifest, request_id, member_id, reservation_id,
                                                  AdmissionSnapshotObservation.from_snapshot(snapshot))
        owner = cls(_token=_CREATE)
        owner.child_binding, owner.context, owner.request = child_binding, context, request
        owner._snapshot, owner._wire = snapshot, _canonical(request.to_dict())
        owner._registry = NativePipeRegistry(max_resources=1)
        owner._attempts = []
        owner._thread, owner._pid = threading.current_thread(), os.getpid()
        owner._fixed = (child_binding, context, request, snapshot, owner._wire, owner._registry,
                        owner._thread, owner._pid)
        owner._result = None
        owner._key = (os.getpid(), manifest.child_identity, manifest.scope_id, member_id)
        with _PUBLICATIONS_LOCK:
            if owner._key in _PUBLICATIONS:
                _fail("original_publication_retained")
            _PUBLICATIONS[owner._key] = owner
        return owner

    @property
    def attempts(self):
        return tuple(self._attempts)

    def _original(self):
        binding, context, request, snapshot, wire, registry, thread, pid = self._fixed
        if (self.child_binding is not binding or self.context is not context or self.request is not request or
                self._snapshot is not snapshot or self._wire != wire or self._registry is not registry or
                self._thread is not thread or self._pid != pid or threading.current_thread() is not thread or
                os.getpid() != pid or _PUBLICATIONS.get(self._key) is not self or
                _canonical(request.to_dict()) != wire or context.snapshot() is not snapshot or
                AdmissionSnapshotObservation.from_snapshot(snapshot) != request.observation):
            _fail("original_publication_changed")
        _before_submission(context)
        binding.revalidate(request.manifest, role="wrapper", member_id=request.member_id)

    def publish(self, *, timeout_ms=1000):
        child._no_mutex()
        child._timeout(timeout_ms)
        self._original()
        if any(attempt.cleanup_pending for attempt in self._attempts) or self._registry.status().resources:
            _fail("original_cleanup_pending")
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
                    child._write(connection, dict(version=1, kind="ExperimentBackingHello", request_id=request.request_id,
                        caller=request.manifest.child_identity.to_dict()), deadline, limit=child.MAX_HELLO_BYTES)
                    child._write(connection, request.to_dict(), deadline)
                    challenge = child._read(connection, deadline)
                    _check_challenge(challenge, request)
                    _live(connection, peer, endpoint.server_identity)
                    # Key access occurs only after original binding and native
                    # server verification. No credential is serialized.
                    key = self.child_binding._client.registration.auth_key
                    attempt.accepted = True  # a partial proof write may reach parent
                    child._write(connection, child._envelope("ExperimentBackingProof", request, challenge,
                        _mac(key, "proof", request, challenge)), deadline)
                    response = child._read(connection, deadline)
                    child._correlated(response, "ExperimentBackingResult", request, challenge, result=True)
                    payload = response["result"]
                    if not hmac.compare_digest(response["mac"], _mac(key, "result", request, challenge, payload)):
                        _fail("result_authentication_failed")
                    observed = _decode_result(payload, request)
                    _live(connection, peer, endpoint.server_identity)
                    self._original()
                    child._write(connection, child._envelope("ExperimentBackingReceipt", request, challenge,
                        _mac(key, "receipt", request, challenge, payload)), deadline)
                    attempt.exchange_complete = True
            _remaining(deadline)
            self._original()
            if self._result is not None and self._result != observed:
                _fail("original_result_changed")
            self._result = observed
            attempt.seal()
            return observed
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_backing_publication, error.experiment_backing_attempt = self, attempt
            raise
