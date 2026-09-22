"""One bounded authenticated operator RPC, separate from helper control.

The only pre-authentication input is a small claimed caller identity. Its native
process object must match the actual pipe peer before the request is read or an
owner callback runs. Both peer handles remain retained across the operation.
The callback owns monotonic drain/recovery and its retained pending work; this
module performs no DB writes, admission, launch, control Set or cold adoption.

Mutation bindings are retained before dispatch, including an interrupted or
failed callback. An exact replay calls that same owner for progress, never
fabricates a cached completion. The transport performs no automatic retry.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import struct
import threading

from .contracts import ContractViolation, ProcessIdentity, _identifier, strict_json_loads
from .ipc import (IpcError, PROTOCOL_MAJOR, _hex, _identity, _live, _remaining,
                  _shape, _uuid, read_frame, write_frame)
from .operator_messages import (MAX_OPERATOR_REQUESTS, OperatorOperation,
                                OperatorReply, OperatorRequest)
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint, NativePipeError


MAX_HELLO_BYTES = 2048
MAX_READ_BINDINGS = 64
_REASON = re.compile(r"[a-z][a-z0-9_]{0,127}")
_SCOPES = frozenset({"instance", "guardian", "helper"})


class OperatorTransportError(IpcError):
    def __init__(self, reason, *, outcome_unknown=False):
        self.outcome_unknown = outcome_unknown
        super().__init__(reason)


def _digest(request):
    return hashlib.sha256(request.to_json().encode("utf-8")).hexdigest()


def _target(instance_id, policy_instance_id, guardian_epoch, scope):
    _uuid(instance_id)
    _uuid(policy_instance_id)
    try:
        _identifier(guardian_epoch, "guardian_epoch")
    except ContractViolation:
        raise OperatorTransportError("operator_target_invalid") from None
    if type(scope) is not str or scope not in _SCOPES:
        raise OperatorTransportError("operator_target_invalid")


def _check_target(request, instance_id, policy_instance_id, guardian_epoch, scope):
    if (request.instance_id != instance_id or request.policy_instance_id != policy_instance_id or
            request.guardian_epoch != guardian_epoch):
        raise OperatorTransportError("operator_target_binding_mismatch")
    if scope == "helper" and request.operation not in (OperatorOperation.DESCRIBE, OperatorOperation.DRAIN):
        raise OperatorTransportError("operator_scope_unsupported")


def hello_envelope(request, caller):
    return {"version": PROTOCOL_MAJOR, "kind": "OperatorHello", "request_id": request.request_id,
            "caller": caller.to_dict()}


def _read_hello(connection, deadline):
    # Refuse an oversized claim before allocating/reading its body. No field in
    # this envelope can authorize an operation without verified_peer below.
    _remaining(deadline)
    prefix = connection.read_exact(4, deadline)
    if type(prefix) is not bytes or len(prefix) != 4:
        raise IpcError("ipc_truncated_frame")
    size = struct.unpack("<I", prefix)[0]
    if not 1 <= size <= MAX_HELLO_BYTES:
        raise OperatorTransportError("operator_hello_too_large")
    _remaining(deadline)
    payload = connection.read_exact(size, deadline)
    _remaining(deadline)
    if type(payload) is not bytes or len(payload) != size:
        raise IpcError("ipc_truncated_frame")
    try:
        value = strict_json_loads(payload)
    except (ContractViolation, ValueError, TypeError, RecursionError):
        raise IpcError("ipc_invalid_json") from None
    _shape(value, "OperatorHello", {"caller"})
    return value["request_id"], _identity(value["caller"])


def request_envelope(request):
    if type(request) is not OperatorRequest:
        raise OperatorTransportError("operator_request_required")
    return {"version": PROTOCOL_MAJOR, "kind": "OperatorRequest", "request_id": request.request_id,
            "request": request.to_dict()}


def decode_request(value):
    _shape(value, "OperatorRequest", {"request"})
    try:
        request = OperatorRequest.from_dict(value["request"])
    except (ContractViolation, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise OperatorTransportError("operator_invalid_request") from None
    if request.request_id != value["request_id"]:
        raise OperatorTransportError("operator_request_binding_mismatch")
    return request


def _challenge(request, endpoint, caller, scope):
    return {"version": PROTOCOL_MAJOR, "kind": "OperatorChallenge", "request_id": request.request_id,
        "nonce": secrets.token_hex(32), "endpoint_id": endpoint.instance_id,
        "instance_id": request.instance_id, "policy_instance_id": request.policy_instance_id,
        "guardian_epoch": request.guardian_epoch, "operation": request.operation.value,
        "scope": scope, "payload_hash": _digest(request),
        "server": endpoint.server_identity.to_dict(), "client": caller.to_dict()}


def _check_challenge(value, request, endpoint, caller, scope):
    _shape(value, "OperatorChallenge", {"nonce", "endpoint_id", "instance_id", "policy_instance_id",
        "guardian_epoch", "operation", "scope", "payload_hash", "server", "client"})
    _hex(value["nonce"])
    _hex(value["payload_hash"])
    _uuid(value["endpoint_id"])
    if (value["request_id"] != request.request_id or value["endpoint_id"] != endpoint.instance_id or
            value["instance_id"] != request.instance_id or value["policy_instance_id"] != request.policy_instance_id or
            value["guardian_epoch"] != request.guardian_epoch or value["operation"] != request.operation.value or
            value["scope"] != scope or value["payload_hash"] != _digest(request) or
            _identity(value["server"]) != endpoint.server_identity or _identity(value["client"]) != caller):
        raise OperatorTransportError("operator_challenge_binding_mismatch")


def _check_reply(reply, request, scope):
    if type(reply) is not OperatorReply:
        raise OperatorTransportError("operator_invalid_reply")
    try:
        OperatorReply.from_dict(reply.to_dict())
    except (ContractViolation, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise OperatorTransportError("operator_invalid_reply") from None
    if (any(getattr(reply, key) != getattr(request, key) for key in (
            "request_id", "operation", "instance_id", "policy_instance_id", "guardian_epoch")) or
            reply.scope != scope):
        raise OperatorTransportError("operator_reply_binding_mismatch")
    return reply


def _reply_envelope(reply, request, challenge, endpoint):
    return {"version": PROTOCOL_MAJOR, "kind": "OperatorReply", "request_id": request.request_id,
        "nonce": challenge["nonce"], "endpoint_id": endpoint.instance_id,
        "payload_hash": _digest(request), "reply": reply.to_dict()}


def decode_reply(value, request, challenge, endpoint, scope):
    _shape(value, "OperatorReply", {"nonce", "endpoint_id", "payload_hash", "reply"})
    _hex(value["nonce"])
    _hex(value["payload_hash"])
    if (value["request_id"] != request.request_id or value["nonce"] != challenge["nonce"] or
            value["endpoint_id"] != endpoint.instance_id or value["payload_hash"] != _digest(request)):
        raise OperatorTransportError("operator_response_binding_mismatch")
    try:
        reply = OperatorReply.from_dict(value["reply"])
    except (ContractViolation, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise OperatorTransportError("operator_invalid_reply") from None
    return _check_reply(reply, request, scope)


class OperatorService:
    """One live host binding and a closed callback, without a helper privilege."""

    def __init__(self, endpoint, *, instance_id, policy_instance_id, guardian_epoch, handler, scope="instance"):
        if type(endpoint) is not NativePipeEndpoint or not callable(handler):
            raise OperatorTransportError("operator_service_invalid")
        _target(instance_id, policy_instance_id, guardian_epoch, scope)
        self.endpoint, self.instance_id, self.policy_instance_id = endpoint, instance_id, policy_instance_id
        self.guardian_epoch, self.handler, self.scope = guardian_epoch, handler, scope
        self._mutations, self._reads = {}, {}
        self._lock = threading.RLock()

    def _bind_request(self, request, caller):
        binding = (caller, _digest(request))
        with self._lock:
            prior = self._mutations.get(request.request_id, self._reads.get(request.request_id))
            if prior is not None:
                if prior != binding:
                    raise OperatorTransportError("operator_request_payload_changed")
                return
            if request.mutating:
                if len(self._mutations) >= MAX_OPERATOR_REQUESTS:
                    raise OperatorTransportError("operator_request_capacity")
                # Never evict mutation tombstones: an old uncertainty must not
                # be reinterpreted as a newly authorized operation.
                self._mutations[request.request_id] = binding
            else:
                self._reads[request.request_id] = binding
                if len(self._reads) > MAX_READ_BINDINGS:
                    del self._reads[next(iter(self._reads))]

    def serve_once(self, listener, *, timeout_ms=1000):
        if listener.endpoint != self.endpoint:
            raise OperatorTransportError("operator_endpoint_mismatch")
        deadline = NativeDeadline.after_ms(timeout_ms)
        with listener.accept(deadline) as connection:
            reply = self._serve_connection(connection, deadline)
        _remaining(deadline)
        return reply

    def poll_once(self, listener, *, timeout_ms=50):
        """Observe one retained accept without spending a request deadline idle.

        A ready borrower enters the same authenticated protocol as serve_once.
        Its one connected-request deadline begins only after that exact
        connection is owned by the context, including deadline-factory failure.
        """
        if listener.endpoint != self.endpoint:
            raise OperatorTransportError("operator_endpoint_mismatch")
        # Match NativeDeadline's input bound without creating a deadline or
        # touching its native clock for a listener that may simply be idle.
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 5000:
            raise NativePipeError("pipe_deadline_invalid")
        connection = listener.poll_accept()
        if connection is None:
            return None
        with connection:
            deadline = NativeDeadline.after_ms(timeout_ms)
            reply = self._serve_connection(connection, deadline)
        _remaining(deadline)
        return reply

    def _serve_connection(self, connection, deadline):
        request_id, caller = _read_hello(connection, deadline)
        if caller.logon_id != self.endpoint.logon_id:
            raise OperatorTransportError("operator_logon_mismatch")
        with connection.verified_peer(caller) as peer:
            _live(connection, peer, caller)
            request = decode_request(read_frame(connection, deadline))
            if request.request_id != request_id:
                raise OperatorTransportError("operator_request_binding_mismatch")
            _check_target(request, self.instance_id, self.policy_instance_id, self.guardian_epoch, self.scope)
            _live(connection, peer, caller)
            self._bind_request(request, peer.identity)
            challenge = _challenge(request, self.endpoint, peer.identity, self.scope)
            write_frame(connection, challenge, deadline)
            _live(connection, peer, caller)
            _remaining(deadline)
            reply = self.handler(request, caller_identity=peer.identity)
            _remaining(deadline)
            _live(connection, peer, caller)
            _check_reply(reply, request, self.scope)
            write_frame(connection, _reply_envelope(reply, request, challenge, self.endpoint), deadline)
            _remaining(deadline)
            return reply


class OperatorClient:
    """Pin the complete server/target binding; one RPC attempt, no retries."""

    def __init__(self, endpoint, *, caller_process_or_identity, instance_id,
                 policy_instance_id, guardian_epoch, scope="instance"):
        caller = getattr(caller_process_or_identity, "identity", caller_process_or_identity)
        if type(endpoint) is not NativePipeEndpoint or type(caller) is not ProcessIdentity:
            raise OperatorTransportError("operator_identity_required")
        _target(instance_id, policy_instance_id, guardian_epoch, scope)
        if caller.logon_id != endpoint.logon_id:
            raise OperatorTransportError("operator_logon_mismatch")
        self.endpoint, self.caller = endpoint, caller
        self.instance_id, self.policy_instance_id = instance_id, policy_instance_id
        self.guardian_epoch, self.scope = guardian_epoch, scope

    def request(self, request, *, timeout_ms=1000):
        unknown = False
        try:
            if type(request) is not OperatorRequest:
                raise OperatorTransportError("operator_request_required")
            _check_target(request, self.instance_id, self.policy_instance_id, self.guardian_epoch, self.scope)
            deadline = NativeDeadline.after_ms(timeout_ms)
            message = request_envelope(request)
            with NativePipeConnection.connect(self.endpoint, deadline) as connection:
                with connection.verified_peer(self.endpoint.server_identity) as peer:
                    _live(connection, peer, self.endpoint.server_identity)
                    write_frame(connection, hello_envelope(request, self.caller), deadline)
                    # A hello contains no operation. After the request write is
                    # entered, a lost observation or mutation result is unknown
                    # (operational exit 5), never a clean pre-delivery absence.
                    unknown = True
                    write_frame(connection, message, deadline)
                    challenge = read_frame(connection, deadline)
                    _check_challenge(challenge, request, self.endpoint, self.caller, self.scope)
                    _live(connection, peer, self.endpoint.server_identity)
                    reply = decode_reply(read_frame(connection, deadline), request, challenge, self.endpoint, self.scope)
                    _live(connection, peer, self.endpoint.server_identity)
                    _remaining(deadline)
            _remaining(deadline)
            return reply
        except Exception as error:
            reason = getattr(error, "reason", "operator_rpc_failed")
            if type(reason) is not str or _REASON.fullmatch(reason) is None:
                reason = "operator_rpc_failed"
            failure = OperatorTransportError(reason, outcome_unknown=unknown)
            # Sanitized public text must not discard private retained native
            # cleanup witnesses attached to the underlying failure.
            failure._operator_cause = error
            raise failure from None
        except BaseException as error:
            error.operator_outcome_unknown = unknown
            raise
