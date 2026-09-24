"""Authenticate one original aggregate child; never grant or release capacity.

The manifest and bootstrap key are data. Only the original parent scope can
accept its registered, created child. The child keeps its own parent duplicate
after both borrowed peer and channel have positively closed. Transport failure
keeps the original attempt, exception and partial native owners, including an
interrupted DuplicateHandle output. No JSON receipt is a cleanup authority.

There is deliberately no SQL here. Each fixed parent method must return outside
SQL and POLICY scopes; both endpoints reject a held native mutex before RPC.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field, fields
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import struct
import threading

from .contracts import IdentityStatus, ProcessIdentity, strict_json_loads
from .daily_readiness_transport import LedgerFileIdentity
from .identity import VerifiedProcess
from .ipc import IpcError, _canonical, _hex, _identity, _live, _remaining, _shape, _uuid
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeRegistry


MAX_MESSAGE_BYTES = 256 * 1024
MAX_HELLO_BYTES = 2048
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PERMITTED_MEMBERS = 128
MAX_SERVER_ATTEMPTS = 512
ROLES = frozenset({"caller", "readiness_keeper", "guardian", "wrapper", "helper",
                   "supervisor", "observer", "query_owner", "runner"})
_BINDING_KEY = object()
_ORIGINAL_CLIENTS = {}
_CLIENTS_LOCK = threading.Lock()


class ExperimentChildError(IpcError):
    pass


def _fail(reason):
    raise ExperimentChildError("experiment_child_" + reason)


def _path(value):
    if (type(value) is not str or not 1 <= len(value) <= 32768 or
            any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in value)):
        _fail("ledger_path_invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        _fail("ledger_path_invalid")


@dataclass(frozen=True)
class ExperimentChildManifest:
    """Bounded immutable bootstrap data, not creation or admission evidence."""
    endpoint: NativePipeEndpoint
    child_identity: ProcessIdentity
    scope_id: str
    scope_nonce: str
    plan_sha256: str
    source_generation: str
    source_digest: str
    config_digest: str
    daily_ledger_path: str
    daily_ledger_identity: LedgerFileIdentity
    daily_policy_instance_id: str
    isolated_ledger_path: str
    isolated_ledger_identity: LedgerFileIdentity
    isolated_policy_instance_id: str
    actor_member_id: str
    role: str
    permitted_member_ids: tuple[str, ...]
    request_id: str

    def __post_init__(self):
        if (type(self.endpoint) is not NativePipeEndpoint or
                type(self.endpoint.server_identity) is not ProcessIdentity or
                type(self.child_identity) is not ProcessIdentity or
                self.child_identity.logon_id != self.endpoint.logon_id or
                self.child_identity == self.endpoint.server_identity):
            _fail("identity_invalid")
        for value in (self.scope_id, self.source_generation, self.daily_policy_instance_id,
                      self.isolated_policy_instance_id, self.actor_member_id, self.request_id):
            _uuid(value)
        for value in (self.scope_nonce, self.plan_sha256, self.source_digest, self.config_digest):
            _hex(value)
        for path in (self.daily_ledger_path, self.isolated_ledger_path):
            _path(path)
        if (type(self.daily_ledger_identity) is not LedgerFileIdentity or
                type(self.isolated_ledger_identity) is not LedgerFileIdentity or
                self.daily_ledger_identity == self.isolated_ledger_identity or
                self.daily_ledger_path == self.isolated_ledger_path or
                self.daily_policy_instance_id == self.isolated_policy_instance_id):
            _fail("ledger_binding_invalid")
        if type(self.role) is not str or self.role not in ROLES:
            _fail("role_invalid")
        members = self.permitted_member_ids
        if type(members) is not tuple or len(members) > MAX_PERMITTED_MEMBERS:
            _fail("members_invalid")
        for member in members:
            _uuid(member)
        if members != tuple(sorted(set(members))):
            _fail("members_invalid")
        if len(_canonical(self.to_dict())) > MAX_MANIFEST_BYTES:
            _fail("manifest_size_invalid")

    def to_dict(self):
        result = {item.name: getattr(self, item.name) for item in fields(self)}
        result["endpoint"] = {"logon_id": self.endpoint.logon_id,
                              "instance_id": self.endpoint.instance_id,
                              "server_identity": self.endpoint.server_identity.to_dict()}
        result["child_identity"] = self.child_identity.to_dict()
        result["daily_ledger_identity"] = self.daily_ledger_identity.to_dict()
        result["isolated_ledger_identity"] = self.isolated_ledger_identity.to_dict()
        result["permitted_member_ids"] = list(self.permitted_member_ids)
        return result

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {item.name for item in fields(cls)}:
            _fail("manifest_invalid")
        endpoint = value["endpoint"]
        if (type(endpoint) is not dict or
                set(endpoint) != {"logon_id", "instance_id", "server_identity"} or
                type(value["permitted_member_ids"]) is not list):
            _fail("manifest_invalid")
        return cls(**(value | {
            "endpoint": NativePipeEndpoint(endpoint["logon_id"], endpoint["instance_id"],
                                           _identity(endpoint["server_identity"])),
            "child_identity": _identity(value["child_identity"]),
            "daily_ledger_identity": LedgerFileIdentity.from_dict(value["daily_ledger_identity"]),
            "isolated_ledger_identity": LedgerFileIdentity.from_dict(value["isolated_ledger_identity"]),
            "permitted_member_ids": tuple(value["permitted_member_ids"])}))


@dataclass(frozen=True)
class BindExperimentChildRequest:
    manifest: ExperimentChildManifest

    def __post_init__(self):
        if type(self.manifest) is not ExperimentChildManifest:
            _fail("manifest_required")

    @property
    def request_id(self):
        return self.manifest.request_id

    def to_dict(self):
        return {"version": 1, "kind": "BindExperimentChild", "request_id": self.request_id,
                "manifest": self.manifest.to_dict()}

    @classmethod
    def from_dict(cls, value):
        _shape(value, "BindExperimentChild", {"manifest"})
        result = cls(ExperimentChildManifest.from_dict(value["manifest"]))
        if result.request_id != value["request_id"]:
            _fail("request_mismatch")
        return result


@dataclass(frozen=True)
class ExperimentChildRegistration:
    manifest: ExperimentChildManifest
    auth_key: bytes = field(repr=False)

    def __post_init__(self):
        if type(self.manifest) is not ExperimentChildManifest:
            _fail("manifest_required")
        if type(self.auth_key) is not bytes or len(self.auth_key) != 32:
            _fail("credential_invalid")


def _read(connection, deadline, *, limit=MAX_MESSAGE_BYTES):
    _no_mutex()
    _remaining(deadline)
    prefix = connection.read_exact(4, deadline)
    if type(prefix) is not bytes or len(prefix) != 4:
        _fail("frame_truncated")
    size = struct.unpack("<I", prefix)[0]
    if not 1 <= size <= limit:
        _fail("frame_size_invalid")
    _remaining(deadline)
    body = connection.read_exact(size, deadline)
    _remaining(deadline)
    if type(body) is not bytes or len(body) != size:
        _fail("frame_truncated")
    return strict_json_loads(body)


def _write(connection, value, deadline, *, limit=MAX_MESSAGE_BYTES):
    body = _canonical(value)
    if len(body) > limit:
        _fail("frame_size_invalid")
    _no_mutex()
    _remaining(deadline)
    connection.write_all(struct.pack("<I", len(body)) + body, deadline)
    _remaining(deadline)


def _no_mutex():
    from .windows import current_thread_holds_mutex
    if current_thread_holds_mutex():
        _fail("lock_held")


def _timeout(value):
    if type(value) is not int or not 1 <= value <= 1000:
        _fail("deadline_invalid")


def _current(process, expected):
    if (type(process) is not VerifiedProcess or process.identity != expected or
            expected.pid != os.getpid()):
        _fail("current_process_required")
    observed = process.observe()
    if observed.identity != expected or observed.status is not IdentityStatus.ALIVE:
        _fail("current_process_unavailable")


class _NativePin:
    """Pin the original Python owner and native value, not just equal identity."""
    def __init__(self, owner):
        self.owner = owner
        self.original = (owner, owner._backend, owner._lock, owner._handle, owner.identity)

    def check(self, *, closed=False):
        owner, backend, lock, handle, identity = self.original
        if (self.owner is not owner or type(owner) is not VerifiedProcess or
                owner._backend is not backend or owner._lock is not lock or
                owner.identity is not identity or
                owner._handle != (None if closed else handle) or
                owner._close_outcome_unknown is not False):
            _fail("original_native_custody_changed")
        return owner


class _Attempt:
    """Registered before acquisition; holds every uncertain original object."""
    def __init__(self):
        self.connection = None
        self.channel_started = False
        self.channel_origin = None
        self.peer = None
        self.error = None
        self.error_owners = ()
        self.exchange_complete = False
        self.peer_settled = False
        self.channel_settled = False
        self.accepted = False
        self._failure_pin = None
        self._partial_pins = ()
        self._error_snapshots = ()
        self._terminal = None

    def seal(self):
        self._terminal = (self.connection, self.peer, self.exchange_complete, self.peer_settled,
                          self.channel_settled, self.accepted, self.channel_started, self.channel_origin)

    def fail(self, error):
        # Preserve the original before reading optional diagnostic properties.
        self.error = error
        errors = (error, *getattr(error, "_experiment_transport_cleanup", ()))
        self._error_snapshots = tuple((item, tuple(getattr(item, "_identity_handle_cleanup", ())))
                                     for item in errors)
        owners = []
        for _item, retained in self._error_snapshots:
            for owner in retained:
                if not any(owner is prior for prior in owners):
                    owners.append(owner)
        self.error_owners = tuple(owners)
        self._partial_pins = tuple(_PartialPin(owner) for owner in self.error_owners)
        self._failure_pin = (error, self.error_owners, self.connection, self.peer,
                             self._partial_pins, self._error_snapshots, errors)
        self.seal()

    @property
    def cleanup_pending(self):
        if self._terminal is not None:
            connection, peer, exchanged, peer_settled, channel_settled, accepted, started, origin = self._terminal
            if (self.connection is not connection or self.peer is not peer or
                    self.exchange_complete is not exchanged or self.peer_settled is not peer_settled or
                    self.channel_settled is not channel_settled or self.accepted is not accepted or
                    self.channel_started is not started or self.channel_origin is not origin):
                _fail("original_outcome_changed")
        if self._failure_pin is not None:
            error, owners, connection, peer, pins, snapshots, errors = self._failure_pin
            if (self.error is not error or self.connection is not connection or self.peer is not peer or
                    self.error_owners is not owners or self._partial_pins is not pins or
                    self._error_snapshots is not snapshots or
                    (error, *getattr(error, "_experiment_transport_cleanup", ())) != errors):
                _fail("original_outcome_changed")
            for item, retained in snapshots:
                current = tuple(getattr(item, "_identity_handle_cleanup", ()))
                if len(current) != len(retained) or any(a is not b for a, b in zip(current, retained)):
                    _fail("original_outcome_changed")
            for pin in self._partial_pins:
                pin.check()
        return (bool(self.error_owners) or
                (self.channel_started is True and self.channel_settled is not True) or
                (self.peer is not None and self.peer_settled is not True))


class _PartialPin:
    """Quarantined duplicate output cells remain owned even without a handle."""
    def __init__(self, owner):
        self.owner = owner
        self.values = tuple(getattr(owner, name, None) for name in
            ("_backend", "_lock", "_handle", "_output", "_duplicate_outcome_unknown",
             "_close_outcome_unknown"))
        self.output_value = getattr(self.values[3], "value", None)

    def check(self):
        current = tuple(getattr(self.owner, name, None) for name in
            ("_backend", "_lock", "_handle", "_output", "_duplicate_outcome_unknown",
             "_close_outcome_unknown"))
        if (any(current[index] is not self.values[index] for index in (0, 1, 3, 4, 5)) or
                current[2] != self.values[2] or getattr(current[3], "value", None) != self.output_value):
            _fail("original_native_custody_changed")


@contextmanager
def _settled_scope(manager, attempt, kind):
    """Preserve body failure and independently require a positive native exit.

    Delivering a body error to a context manager can obscure whether cleanup
    succeeded. Keep it locally, let the original native context exit normally,
    then propagate it. A second cleanup error is retained on that original;
    neither context is retried and a failed exit never sets its settled flag.
    """
    primary = None
    try:
        with manager as value:
            if kind == "peer":
                attempt.peer = value
            else:
                attempt.connection = value
            try:
                yield value
            except BaseException as error:
                primary = error
        if kind == "peer":
            attempt.peer_settled = True
        else:
            attempt.channel_settled = True
    except BaseException as cleanup:
        if primary is not None and cleanup is not primary:
            pending = getattr(primary, "_experiment_transport_cleanup", ())
            primary._experiment_transport_cleanup = (*pending, cleanup)
            raise primary from None
        raise
    if primary is not None:
        raise primary


class ExperimentChildBinding:
    """Child-local authentication witness; no admission/readiness/release API."""
    def __init__(self, client, *, _key=None):
        if _key is not _BINDING_KEY:
            _fail("original_binding_required")
        self._client = client
        self._manifest = client.registration.manifest
        self._manifest_wire = _canonical(self._manifest.to_dict())
        self._process = client.current_process
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._attempt = _Attempt()
        self._registry = NativePipeRegistry(max_resources=1)
        self._peer = self._peer_pin = None
        self._native_original = None
        self._issued = self._closed = self._close_attempted = False
        self._close_error = None
        self._original = (client, self._manifest, self._process, self._attempt,
                          self._manifest_wire, self._thread, self._pid, self._registry)

    def __reduce__(self):
        raise TypeError("experiment_child_binding_not_serializable")

    @property
    def manifest(self):
        self._check_original()
        return self._manifest

    def _check_original(self):
        client, manifest, process, attempt, wire, thread, pid, registry = self._original
        if (self._client is not client or self._manifest is not manifest or
                self._process is not process or self._attempt is not attempt or
                self._manifest_wire != wire or _canonical(manifest.to_dict()) != wire or
                self._thread is not thread or self._pid != pid or
                threading.current_thread() is not thread or os.getpid() != pid or
                client._binding is not self or self._registry is not registry):
            _fail("original_binding_changed")
        client._check_original()
        if self._peer_pin is not None and self._peer is not self._peer_pin.owner:
            _fail("original_native_custody_changed")
        if self._native_original is not None:
            peer, pin = self._native_original
            if self._peer is not peer or self._peer_pin is not pin:
                _fail("original_native_custody_changed")
        self._attempt.cleanup_pending

    @property
    def custody_pending(self):
        self._check_original()
        if self._peer_pin is not None and self._close_attempted is False:
            self._peer_pin.check()
        if self._closed is True:
            if self._peer_pin is not None:
                self._peer_pin.check(closed=True)
            return self._attempt.cleanup_pending or self._registry.status().resources != 0
        return self._peer is not None or self._attempt.cleanup_pending or self._registry.status().resources != 0

    def revalidate(self, expected_manifest, *, role, member_id=None):
        self._check_original()
        if (type(expected_manifest) is not ExperimentChildManifest or
                _canonical(expected_manifest.to_dict()) != self._manifest_wire or
                role != self._manifest.role or self._issued is not True or
                self._closed is not False or self._close_attempted is not False or
                self._peer_pin is None or self._attempt.exchange_complete is not True or
                self._attempt.peer_settled is not True or self._attempt.channel_settled is not True):
            _fail("binding_unavailable")
        if member_id is not None:
            _uuid(member_id)
            if member_id not in self._manifest.permitted_member_ids:
                _fail("member_not_permitted")
        _current(self._process, self._manifest.child_identity)
        peer = self._peer_pin.check()
        observed = peer.observe()
        if (observed.identity != self._manifest.endpoint.server_identity or
                observed.status is not IdentityStatus.ALIVE):
            _fail("parent_unavailable")
        return None

    def close(self):
        self._check_original()
        if self._closed is True:
            if self._peer_pin is not None:
                self._peer_pin.check(closed=True)
            if self._attempt.cleanup_pending or self._registry.status().resources != 0:
                _fail("cleanup_pending")
            return
        if self._close_attempted is not False:
            _fail("cleanup_pending")
        # Partial duplicate/channel ownership is never speculatively reclosed.
        if (self._attempt.cleanup_pending or self._registry.status().resources != 0 or
                (self._peer is not None and self._peer_pin is None)):
            _fail("cleanup_pending")
        self._issued = False
        if self._peer_pin is not None:
            peer = self._peer_pin.check()
            self._close_attempted = True
            try:
                peer.close()
                self._peer_pin.check(closed=True)
            except BaseException as error:
                self._close_error = error
                error.experiment_child_binding = self
                raise
        self._closed = True


def _challenge(request):
    manifest = request.manifest
    return {"version": 1, "kind": "ExperimentChildChallenge", "request_id": request.request_id,
            "nonce": secrets.token_hex(32), "endpoint_id": manifest.endpoint.instance_id,
            "server": manifest.endpoint.server_identity.to_dict(),
            "client": manifest.child_identity.to_dict()}


def _check_challenge(value, request):
    _shape(value, "ExperimentChildChallenge", {"nonce", "endpoint_id", "server", "client"})
    _hex(value["nonce"])
    manifest = request.manifest
    if (value["request_id"] != request.request_id or
            value["endpoint_id"] != manifest.endpoint.instance_id or
            _identity(value["server"]) != manifest.endpoint.server_identity or
            _identity(value["client"]) != manifest.child_identity):
        _fail("challenge_mismatch")


def _transcript(purpose, request, challenge, result=None):
    if purpose not in {"proof", "result", "receipt"}:
        _fail("domain_invalid")
    value = {"domain": "ResourceSentinel/experiment-child-ipc/v1/" + purpose,
             "request": request.to_dict(), "challenge": challenge}
    if purpose != "proof":
        value["result"] = result
    return _canonical(value)


def _mac(key, purpose, request, challenge, result=None):
    return hmac.new(key, _transcript(purpose, request, challenge, result), hashlib.sha256).hexdigest()


def _envelope(kind, request, challenge, mac):
    return {"version": 1, "kind": kind, "request_id": request.request_id,
            "nonce": challenge["nonce"], "mac": mac}


def _correlated(value, kind, request, challenge, *, result=False):
    _shape(value, kind, {"nonce", "mac", *({"result"} if result else set())})
    _hex(value["mac"])
    if value["request_id"] != request.request_id or value["nonce"] != challenge["nonce"]:
        _fail("response_mismatch")


def _failure(error, owner, attempt, *, binding=None):
    if binding is not None:
        binding._issued = False
    attempt.fail(error)
    failure = ExperimentChildError("experiment_child_rpc_failed")
    failure.original_error = error
    failure.transport_owner = owner
    failure.attempt = attempt
    failure.binding = binding
    return failure


class ExperimentChildService:
    """Fixed original ProductionExperimentScope service, without callbacks."""
    def __init__(self, endpoint, owner):
        from .experiment_host_scope import ProductionExperimentScope
        if type(owner) is not ProductionExperimentScope or type(endpoint) is not NativePipeEndpoint:
            _fail("original_scope_required")
        self.endpoint, self.owner = endpoint, owner
        self._process = ProductionExperimentScope._assert_transport_original(owner, endpoint)
        _current(self._process, endpoint.server_identity)
        self._process_pin = _NativePin(self._process)
        self._original = (endpoint, owner, self._process, self._process_pin)
        self._attempts = []
        ProductionExperimentScope._retain_child_transport(owner, self)

    def _check_original(self):
        from .experiment_host_scope import ProductionExperimentScope
        endpoint, owner, process, pin = self._original
        if (self.endpoint is not endpoint or self.owner is not owner or
                self._process is not process or self._process_pin is not pin or
                ProductionExperimentScope._assert_transport_original(owner, endpoint) is not process):
            _fail("original_scope_changed")
        pin.check()
        _current(process, endpoint.server_identity)

    @property
    def attempts(self):
        return tuple(self._attempts)

    def serve_once(self, listener, *, timeout_ms=1000):
        _no_mutex()
        _timeout(timeout_ms)
        self._check_original()
        if listener.endpoint != self.endpoint:
            _fail("endpoint_mismatch")
        if len(self._attempts) >= MAX_SERVER_ATTEMPTS:
            _fail("attempt_limit")
        deadline = NativeDeadline.after_ms(timeout_ms)
        attempt = _Attempt()
        self._attempts.append(attempt)
        try:
            attempt.channel_origin = listener
            attempt.channel_started = True
            with _settled_scope(listener.accept(deadline), attempt, "channel") as connection:
                self._serve_connection(connection, deadline, attempt)
            attempt.channel_settled = True
            _remaining(deadline)
            self._check_original()
            attempt.seal()
            # A settled RPC is audit data only; it is not child retirement.
            return None
        except Exception as error:
            raise _failure(error, self, attempt) from None
        except BaseException as error:
            attempt.fail(error)
            error.experiment_child_transport = self
            error.experiment_child_attempt = attempt
            raise

    def _serve_connection(self, connection, deadline, attempt):
        from .experiment_host_scope import ProductionExperimentScope
        hello = _read(connection, deadline, limit=MAX_HELLO_BYTES)
        _shape(hello, "ExperimentChildHello", {"caller"})
        caller = _identity(hello["caller"])
        if caller.logon_id != self.endpoint.logon_id:
            _fail("peer_logon_mismatch")
        with _settled_scope(connection.verified_peer(caller), attempt, "peer") as peer:
            if type(peer) is not VerifiedProcess:
                _fail("original_peer_required")
            _live(connection, peer, caller)
            request = BindExperimentChildRequest.from_dict(_read(connection, deadline))
            if (request.request_id != hello["request_id"] or request.manifest.endpoint != self.endpoint or
                    request.manifest.child_identity != caller):
                _fail("request_mismatch")
            registration = ProductionExperimentScope._transport_child_registration(self.owner, request, peer)
            if type(registration) is not ExperimentChildRegistration or registration.manifest != request.manifest:
                _fail("registration_mismatch")
            self._check_original()
            _no_mutex()
            _live(connection, peer, caller)
            challenge = _challenge(request)
            _write(connection, challenge, deadline)
            proof = _read(connection, deadline)
            _correlated(proof, "ExperimentChildProof", request, challenge)
            if not hmac.compare_digest(proof["mac"], _mac(registration.auth_key, "proof", request, challenge)):
                _fail("authentication_failed")
            _live(connection, peer, caller)
            _remaining(deadline)
            # Lost/partial return is retained as potentially accepted.
            attempt.accepted = True
            ProductionExperimentScope._accept_transport_child(self.owner, request, peer, registration)
            _no_mutex()
            self._check_original()
            _live(connection, peer, caller)
            result = {"bound_manifest": registration.manifest.to_dict()}
            response = _envelope("ExperimentChildResult", request, challenge,
                                 _mac(registration.auth_key, "result", request, challenge, result))
            response["result"] = result
            _write(connection, response, deadline)
            receipt = _read(connection, deadline)
            _correlated(receipt, "ExperimentChildReceipt", request, challenge)
            if not hmac.compare_digest(receipt["mac"],
                                       _mac(registration.auth_key, "receipt", request, challenge, result)):
                _fail("receipt_invalid")
            _live(connection, peer, caller)
            _remaining(deadline)
            attempt.exchange_complete = True
        attempt.peer_settled = True


class ExperimentChildClient:
    """One original binding attempt; uncertain acquisition cannot be replaced."""
    def __init__(self, registration, current_process):
        if type(registration) is not ExperimentChildRegistration:
            _fail("registration_required")
        _current(current_process, registration.manifest.child_identity)
        self.registration, self.current_process = registration, current_process
        self._process_pin = _NativePin(current_process)
        self._original = (registration, current_process, self._process_pin,
                          _canonical(registration.manifest.to_dict()), registration.auth_key)
        self._binding = None
        self._request_key = (os.getpid(), registration.manifest.child_identity,
                             registration.manifest.request_id)

    def _check_original(self):
        registration, process, pin, wire, key = self._original
        if (self.registration is not registration or self.current_process is not process or
                self._process_pin is not pin or _canonical(registration.manifest.to_dict()) != wire or
                registration.auth_key != key):
            _fail("original_client_changed")
        pin.check()
        _current(process, registration.manifest.child_identity)
        if self._binding is not None and _ORIGINAL_CLIENTS.get(self._request_key) is not self:
            _fail("original_client_changed")

    def bind(self, *, timeout_ms=1000):
        _no_mutex()
        _timeout(timeout_ms)
        self._check_original()
        if self._binding is not None:
            _fail("original_attempt_retained")
        request = BindExperimentChildRequest(self.registration.manifest)
        manifest = request.manifest
        key = self._request_key
        with _CLIENTS_LOCK:
            if key in _ORIGINAL_CLIENTS:
                _fail("original_attempt_retained")
            _ORIGINAL_CLIENTS[key] = self
        # Publish the owner before connect/duplicate; interruption preserves it.
        binding = ExperimentChildBinding(self, _key=_BINDING_KEY)
        self._binding = binding
        attempt = binding._attempt
        deadline = NativeDeadline.after_ms(timeout_ms)
        try:
            attempt.channel_origin = binding._registry
            attempt.channel_started = True
            with _settled_scope(NativePipeConnection.connect(manifest.endpoint, deadline,
                                                            registry=binding._registry),
                                attempt, "channel") as connection:
                with _settled_scope(connection.verified_peer(manifest.endpoint.server_identity),
                                    attempt, "peer") as peer:
                    if type(peer) is not VerifiedProcess:
                        _fail("original_peer_required")
                    _live(connection, peer, manifest.endpoint.server_identity)
                    _write(connection, {"version": 1, "kind": "ExperimentChildHello",
                        "request_id": request.request_id, "caller": manifest.child_identity.to_dict()},
                        deadline, limit=MAX_HELLO_BYTES)
                    _write(connection, request.to_dict(), deadline)
                    challenge = _read(connection, deadline)
                    _check_challenge(challenge, request)
                    _live(connection, peer, manifest.endpoint.server_identity)
                    _write(connection, _envelope("ExperimentChildProof", request, challenge,
                        _mac(self.registration.auth_key, "proof", request, challenge)), deadline)
                    response = _read(connection, deadline)
                    _correlated(response, "ExperimentChildResult", request, challenge, result=True)
                    result = response["result"]
                    if (result != {"bound_manifest": manifest.to_dict()} or
                            not hmac.compare_digest(response["mac"],
                                _mac(self.registration.auth_key, "result", request, challenge, result))):
                        _fail("result_invalid")
                    _live(connection, peer, manifest.endpoint.server_identity)
                    self._check_original()
                    binding._peer = peer.duplicate()
                    binding._peer_pin = _NativePin(binding._peer)
                    binding._native_original = (binding._peer, binding._peer_pin)
                    binding._peer_pin.check()
                    _live(connection, peer, manifest.endpoint.server_identity)
                    _write(connection, _envelope("ExperimentChildReceipt", request, challenge,
                        _mac(self.registration.auth_key, "receipt", request, challenge, result)), deadline)
                    attempt.exchange_complete = True
                attempt.peer_settled = True
            attempt.channel_settled = True
            _remaining(deadline)
            attempt.seal()
            binding._issued = True
            binding.revalidate(manifest, role=manifest.role)
            return binding
        except Exception as error:
            raise _failure(error, self, attempt, binding=binding) from None
        except BaseException as error:
            binding._issued = False
            attempt.fail(error)
            error.experiment_child_client = self
            error.experiment_child_binding = binding
            error.experiment_child_attempt = attempt
            raise
