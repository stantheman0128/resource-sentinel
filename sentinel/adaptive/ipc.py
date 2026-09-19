"""Bounded, authenticated local queries for an admitted wrapper execution.

This early P3 dependency implements actual Named Pipe transport, not launch or
control readiness. The caller supplies an endpoint whose exact server identity
was obtained through a trusted bootstrap. A hello from that same endpoint can
never establish its own authority. Only QueryExecution and GetReadiness exist;
there is no generic handler registry, mutation route, or launch-ACK cache.

Every connection uses one deadline and a fresh one-use server challenge. A
separate query credential preserves the wrapper's unexported launch capability.
Authentication covers the operation, execution/spec, both native identities and
endpoint instance. The service keeps the verified native peer handle through
the read transaction and response receipt. Same-logon hostile process isolation
and a production guardian rendezvous are outside this interface's guarantees.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import secrets
import struct
from uuid import UUID, uuid4

from .contracts import ContractViolation, IdentityStatus, MAX_MESSAGE_BYTES, ProcessIdentity, strict_json_loads
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint
from .store import _get_ipc_auth_record, authenticated_query


PROTOCOL_MAJOR = 1
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_OPERATIONS = frozenset({"QueryExecution", "GetReadiness"})


class IpcError(RuntimeError):
    """Stable errors contain no request payload, credentials or raw exceptions."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        if parsed is not None and parsed.int and str(parsed) == value:
            return value
    except ValueError:
        pass
    raise IpcError("ipc_invalid_identifier")


def _hex(value):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise IpcError("ipc_invalid_digest")
    return value


def _shape(value, kind, fields):
    if type(value) is not dict or set(value) != {"version", "kind", "request_id", *fields}:
        raise IpcError("ipc_invalid_envelope")
    if type(value["version"]) is not int or value["version"] != PROTOCOL_MAJOR:
        raise IpcError("ipc_protocol_mismatch")
    if value["kind"] != kind:
        raise IpcError("ipc_unexpected_message")
    _uuid(value["request_id"])


def _canonical(value):
    try:
        result = json.dumps(value, ensure_ascii=True, sort_keys=True,
                            separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise IpcError("ipc_invalid_json") from None
    if not 1 <= len(result) <= MAX_MESSAGE_BYTES:
        raise IpcError("ipc_message_too_large")
    return result


def encode_frame(value: dict) -> bytes:
    payload = _canonical(value)
    return struct.pack("<I", len(payload)) + payload


def _remaining(deadline):
    remaining = deadline.remaining_ms()
    if remaining <= 0:
        raise IpcError("ipc_deadline_exceeded")
    return remaining


def read_frame(connection, deadline) -> dict:
    """Validate the length before requesting or allocating the body."""
    _remaining(deadline)
    prefix = connection.read_exact(4, deadline)
    if type(prefix) is not bytes or len(prefix) != 4:
        raise IpcError("ipc_truncated_frame")
    size = struct.unpack("<I", prefix)[0]
    if not 1 <= size <= MAX_MESSAGE_BYTES:
        raise IpcError("ipc_invalid_frame_length")
    _remaining(deadline)
    payload = connection.read_exact(size, deadline)
    _remaining(deadline)
    if type(payload) is not bytes or len(payload) != size:
        raise IpcError("ipc_truncated_frame")
    try:
        return strict_json_loads(payload)
    except (ContractViolation, ValueError, TypeError, RecursionError):
        raise IpcError("ipc_invalid_json") from None


def write_frame(connection, value, deadline):
    _remaining(deadline)
    connection.write_all(encode_frame(value), deadline)
    _remaining(deadline)


@dataclass(frozen=True)
class QueryRequest:
    request_id: str
    operation: str
    execution_id: str
    spec_hash: str

    def __post_init__(self):
        _uuid(self.request_id)
        _uuid(self.execution_id)
        _hex(self.spec_hash)
        if type(self.operation) is not str or self.operation not in _OPERATIONS:
            raise IpcError("ipc_unsupported_operation")

    def to_dict(self):
        return {"version": PROTOCOL_MAJOR, "kind": "Request", "request_id": self.request_id,
                "operation": self.operation, "execution_id": self.execution_id, "spec_hash": self.spec_hash}

    @classmethod
    def from_dict(cls, value):
        _shape(value, "Request", {"operation", "execution_id", "spec_hash"})
        return cls(value["request_id"], value["operation"], value["execution_id"], value["spec_hash"])


def _identity(value):
    try:
        return ProcessIdentity.from_dict(value)
    except (ValueError, TypeError, OverflowError):
        raise IpcError("ipc_invalid_identity") from None


def _challenge(request, endpoint, caller):
    return {"version": PROTOCOL_MAJOR, "kind": "Challenge", "request_id": request.request_id,
            "nonce": secrets.token_hex(32), "endpoint_id": endpoint.instance_id,
            "server": endpoint.server_identity.to_dict(), "client": caller.to_dict()}


def _check_challenge(value, request, endpoint, caller):
    _shape(value, "Challenge", {"nonce", "endpoint_id", "server", "client"})
    _hex(value["nonce"])
    _uuid(value["endpoint_id"])
    if (value["request_id"] != request.request_id or value["endpoint_id"] != endpoint.instance_id or
            _identity(value["server"]) != endpoint.server_identity or _identity(value["client"]) != caller):
        raise IpcError("ipc_challenge_binding_mismatch")


def _transcript(purpose, request, challenge, result=None):
    # Fixed domains cannot be chosen from wire data. Full canonical envelopes
    # bind every phase; a response MAC cannot authenticate a proof or receipt.
    if purpose not in {"proof", "result", "receipt"}:
        raise IpcError("ipc_invalid_domain")
    value = {"domain": "ResourceSentinel/query-ipc/v1/" + purpose,
             "request": request.to_dict(), "challenge": challenge}
    if purpose != "proof":
        value["result"] = result
    return _canonical(value)


def _mac(key, transcript):
    return hmac.new(key, transcript, hashlib.sha256).hexdigest()


def _proof_envelope(kind, request, challenge, mac):
    return {"version": PROTOCOL_MAJOR, "kind": kind, "request_id": request.request_id,
            "nonce": challenge["nonce"], "mac": mac}


def _check_correlated(value, kind, request, challenge, *, result=False):
    _shape(value, kind, {"nonce", "mac", *({"result"} if result else set())})
    _hex(value["nonce"])
    _hex(value["mac"])
    if value["request_id"] != request.request_id or value["nonce"] != challenge["nonce"]:
        raise IpcError("ipc_response_binding_mismatch")


def _live(connection, retained, expected):
    observation = retained.observe()
    if (connection.peer_pid() != expected.pid or retained.identity != expected or
            observation.identity != expected or observation.status is not IdentityStatus.ALIVE):
        raise IpcError("ipc_peer_unverified")


_READINESS_FIELDS = frozenset({"execution_id", "implementation_mode", "native_readiness",
    "control_writes", "os_limit_state", "recorded_mode", "admission_barrier", "registry_revision", "reason"})
_QUERY_FIELDS = frozenset({"available", "implementation_mode", "native_readiness", "control_writes",
    "os_limit_state", "recorded_mode", "executions", "truncated", "reason", "schema_version",
    "protocol_version", "registry_revision", "admission_barrier", "row_limit"})


def _result_for(request, query):
    if request.operation == "QueryExecution":
        return query
    return {key: (request.execution_id if key == "execution_id" else query[key])
            for key in _READINESS_FIELDS}


def _validate_result(request, result):
    fields = _QUERY_FIELDS if request.operation == "QueryExecution" else _READINESS_FIELDS
    if type(result) is not dict or set(result) != fields:
        raise IpcError("ipc_invalid_result")
    # This implementation has no native control evidence. Recorded mode must
    # never be promoted into an assertion of readiness or restored OS limits.
    if (result["implementation_mode"] != "admission-only" or result["native_readiness"] != "unverified" or
            result["control_writes"] is not False or result["os_limit_state"] != "unverified" or
            result["reason"] != "ok" or type(result["recorded_mode"]) is not str or
            result["recorded_mode"] not in {"off", "shadow", "canary", "limited"} or
            type(result["admission_barrier"]) is not str or
            result["admission_barrier"] not in {"NONE", "CONTROLLING", "RECOVERY_HOLD"} or
            type(result["registry_revision"]) is not int or not 0 <= result["registry_revision"] < (1 << 63)):
        raise IpcError("ipc_invalid_result")
    if request.operation == "GetReadiness":
        if result["execution_id"] != request.execution_id:
            raise IpcError("ipc_invalid_result")
        return
    if (result["available"] is not True or result["truncated"] is not False or
            any(type(result[field]) is not int or result[field] != 1 for field in
                ("schema_version", "protocol_version", "row_limit")) or
            type(result["executions"]) is not list or len(result["executions"]) != 1):
        raise IpcError("ipc_invalid_result")
    execution = result["executions"][0]
    # Exact allowlist prevents accidentally exporting new private DB columns.
    if (type(execution) is not dict or set(execution) != {"execution_id", "allocation", "state",
            "state_revision", "coverage", "launch_in_flight", "launch_sealed", "wrapper", "root", "floor", "hold_reason"}
            or execution["execution_id"] != request.execution_id):
        raise IpcError("ipc_invalid_result")
    for field, expected in (("allocation", {"kind", "reservation_id", "parent_execution_id", "recorded_binding"}),
                            ("wrapper", {"pid", "created_filetime_100ns"}),
                            ("floor", {"cpu_units", "physical_bytes", "commit_bytes", "io_slots"})):
        if type(execution[field]) is not dict or set(execution[field]) != expected:
            raise IpcError("ipc_invalid_result")
    if execution["root"] is not None and (type(execution["root"]) is not dict or
            set(execution["root"]) != {"pid", "created_filetime_100ns"}):
        raise IpcError("ipc_invalid_result")
    # Reuse the diagnostic contract's scalar checks, without opening a DB.
    # Comparing the normalized row also rejects truthy ints masquerading as
    # flags or arbitrary nested values in otherwise allowlisted fields.
    from .query import _row
    allocation, wrapper, root, floor = (execution[name] for name in ("allocation", "wrapper", "root", "floor"))
    binding = allocation["recorded_binding"]
    if (type(binding) is not str or binding not in {"recorded_binding_matches", "allocation_missing",
            "allocation_table_missing", "allocation_binding_inconsistent", "terminal_allocation_absent"} or
            allocation["kind"] != "direct" or type(execution["launch_in_flight"]) is not bool or
            type(execution["launch_sealed"]) is not bool):
        raise IpcError("ipc_invalid_result")
    flat = {**execution, "allocation_kind": allocation["kind"], "reservation_id": allocation["reservation_id"],
            "parent_execution_id": allocation["parent_execution_id"], "wrapper_pid": wrapper["pid"],
            "wrapper_created_filetime_100ns": wrapper["created_filetime_100ns"],
            "root_pid": None if root is None else root["pid"],
            "root_created_filetime_100ns": None if root is None else root["created_filetime_100ns"],
            "launch_in_flight": int(execution["launch_in_flight"]), "launch_sealed": int(execution["launch_sealed"]),
            **{"floor_" + name: value for name, value in floor.items()}}
    try:
        normalized = _row(flat)
        normalized["allocation"]["recorded_binding"] = binding
        if normalized != execution:
            raise ValueError()
    except (TypeError, ValueError, OverflowError):
        raise IpcError("ipc_invalid_result") from None


def _check_result_owner(request, result, caller):
    if request.operation == "QueryExecution" and result["executions"][0]["wrapper"] != {
            "pid": caller.pid, "created_filetime_100ns": str(caller.created_filetime_100ns)}:
        raise IpcError("ipc_result_owner_mismatch")


class LifecycleQueryService:
    """Serialized service entrypoint; does not start threads or a resident daemon.

    A NativePipeListener owns one instance for its entire lifetime. Its shared
    registry counts listeners, clients and uncertain pending resources against
    the native global bound. There is no application-side waiting request list.
    """

    def __init__(self, db_path, endpoint: NativePipeEndpoint):
        self.db_path = db_path
        self.endpoint = endpoint

    def serve_once(self, listener, *, timeout_ms=1000):
        if listener.endpoint != self.endpoint:
            raise IpcError("ipc_endpoint_mismatch")
        deadline = NativeDeadline.after_ms(timeout_ms)
        with listener.accept(deadline) as connection:
            return self._serve_connection(connection, deadline)

    def _serve_connection(self, connection, deadline):
        request = QueryRequest.from_dict(read_frame(connection, deadline))
        record = _get_ipc_auth_record(self.db_path, request.execution_id,
                                      timeout_ms=min(250, _remaining(deadline)))
        if record.spec_hash != request.spec_hash or record.wrapper_identity.logon_id != self.endpoint.logon_id:
            raise IpcError("ipc_binding_mismatch")
        with connection.verified_peer(record.wrapper_identity) as retained:
            _live(connection, retained, record.wrapper_identity)
            challenge = _challenge(request, self.endpoint, record.wrapper_identity)
            write_frame(connection, challenge, deadline)
            proof = read_frame(connection, deadline)
            _check_correlated(proof, "Proof", request, challenge)
            # Exactly one proof is read and compared. Any error unwinds the
            # connection: this nonce has no reusable object/cache/DB session.
            expected = _mac(record.ipc_auth_key, _transcript("proof", request, challenge))
            if not hmac.compare_digest(proof["mac"], expected):
                raise IpcError("ipc_authentication_failed")
            _live(connection, retained, record.wrapper_identity)
            query = authenticated_query(self.db_path, request.execution_id, record,
                                        timeout_ms=min(250, _remaining(deadline)))
            _remaining(deadline)
            _live(connection, retained, record.wrapper_identity)
            result = _result_for(request, query)
            _validate_result(request, result)
            _check_result_owner(request, result, record.wrapper_identity)
            response = {**_proof_envelope("Result", request, challenge,
                _mac(record.ipc_auth_key, _transcript("result", request, challenge, result))), "result": result}
            write_frame(connection, response, deadline)
            # DisconnectNamedPipe may discard unread output. A receipt proves
            # consumption without unbounded FlushFileBuffers waiting on a peer.
            receipt = read_frame(connection, deadline)
            _check_correlated(receipt, "Receipt", request, challenge)
            expected = _mac(record.ipc_auth_key, _transcript("receipt", request, challenge, result))
            if not hmac.compare_digest(receipt["mac"], expected):
                raise IpcError("ipc_authentication_failed")
            # Receipt is the read-only completion point. The peer may close its
            # pipe or exit immediately after sending it; a fresh PID/liveness
            # query here would spuriously undo an already authenticated read.
            # Keep the original exact process handle retained until scope exit.
            _remaining(deadline)
            return {"request_id": request.request_id, "execution_id": request.execution_id,
                    "operation": request.operation, "receipt_verified": True, "control_writes": False}


class ManagedExecutionClient:
    """Query only this live ManagedAdmission; never exports its launch token."""

    def __init__(self, context, endpoint: NativePipeEndpoint):
        self.context = context
        self.endpoint = endpoint

    def query_execution(self, *, request_id=None, timeout_ms=1000):
        return self._request("QueryExecution", request_id=request_id, timeout_ms=timeout_ms)

    def get_readiness(self, *, request_id=None, timeout_ms=1000):
        return self._request("GetReadiness", request_id=request_id, timeout_ms=timeout_ms)

    def _request(self, operation, *, request_id, timeout_ms):
        deadline = NativeDeadline.after_ms(timeout_ms)
        snapshot = self.context.snapshot()
        request = QueryRequest(str(uuid4()) if request_id is None else request_id, operation,
                               snapshot.execution_id, snapshot.spec_hash)
        if snapshot.logon_id != self.endpoint.logon_id:
            raise IpcError("ipc_binding_mismatch")
        with NativePipeConnection.connect(self.endpoint, deadline) as connection:
            # Verify native server identity before sending even an execution
            # selector. No identity claimed in the challenge establishes trust.
            with connection.verified_peer(self.endpoint.server_identity) as retained:
                return self._exchange(connection, retained, request, snapshot.wrapper_identity, deadline)

    def _exchange(self, connection, retained, request, caller, deadline):
        def sign(purpose, challenge, result=None):
            return self.context._ipc_mac(_transcript(purpose, request, challenge, result),
                execution_id=request.execution_id, spec_hash=request.spec_hash, caller=caller)

        _live(connection, retained, self.endpoint.server_identity)
        write_frame(connection, request.to_dict(), deadline)
        challenge = read_frame(connection, deadline)
        _check_challenge(challenge, request, self.endpoint, caller)
        _live(connection, retained, self.endpoint.server_identity)
        write_frame(connection, _proof_envelope("Proof", request, challenge, sign("proof", challenge)), deadline)
        response = read_frame(connection, deadline)
        _check_correlated(response, "Result", request, challenge, result=True)
        _live(connection, retained, self.endpoint.server_identity)
        result = response["result"]
        if not hmac.compare_digest(response["mac"], sign("result", challenge, result)):
            raise IpcError("ipc_authentication_failed")
        _validate_result(request, result)
        _check_result_owner(request, result, caller)
        write_frame(connection, _proof_envelope("Receipt", request, challenge, sign("receipt", challenge, result)), deadline)
        _remaining(deadline)
        return result
