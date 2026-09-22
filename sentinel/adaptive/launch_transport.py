"""Authenticated, bounded wrapper-to-guardian launch messages.

These three RPCs contain immutable identifiers, not a command, cwd or environment.
The endpoint and guardian epoch come from trusted bootstrap; the wire cannot
establish either authority. The wrapper pins the actual native server before
exporting its claim or writing any request. The service keeps the verified peer
borrowed through the owner call. An owner retaining it must duplicate custody.

Durable authentication, intent replay, native evidence and mutation belong to
the fixed launch owner and store. A response receipt only drains the pipe; it
does not commit a mutation. No request is automatically retried. After sending
proof begins, any client error is an uncertain mutation outcome. Native timeout
and cancellation semantics remain those of pipe_windows, including quarantine.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import re
import secrets
import struct
from typing import ClassVar

from .contracts import LifecycleState, ProcessIdentity
from .ipc import IpcError, _canonical, _hex, _identity, _live, _remaining, _shape, _uuid, read_frame, write_frame
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint
from .store import _get_ipc_auth_record


_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:@-]{1,128}\Z")
_NONCE = re.compile(r"[0-9a-f]{32}\Z")
_CLAIM = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")
_STATES = frozenset(item.value for item in LifecycleState)
_RESULT_FIELDS = frozenset({"execution_id", "spec_hash", "guardian_epoch", "state", "state_revision",
                            "job_name", "job_nonce", "launch_authorized", "duplicate"})
_COMMON = frozenset({"operation", "execution_id", "spec_hash", "guardian_epoch", "expected_revision"})


class LaunchTransportError(IpcError):
    """A sanitized failure; uncertain outcomes never grant launch authority."""

    def __init__(self, reason, *, launch_outcome_unknown=False, cleanup_error=None):
        self.launch_outcome_unknown = launch_outcome_unknown
        # Native scope errors may carry exact retained cleanup owners. Keep
        # their custody without putting raw details/handles in diagnostics.
        self._transport_cleanup_error = cleanup_error
        super().__init__(reason)


def _epoch(value):
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise IpcError("launch_invalid_guardian_epoch")


def _revision(value):
    if type(value) is not int or not 0 <= value < (1 << 63):
        raise IpcError("launch_invalid_revision")


def _nonce(value):
    if type(value) is not str or _NONCE.fullmatch(value) is None:
        raise IpcError("launch_invalid_job_nonce")


def _locator(value):
    # A locator has meaning only in the authenticated peer's handle table. It
    # is never authority to reopen a root by PID, nor a current-process handle.
    if type(value) is not int or not 0 < value < (1 << (8 * struct.calcsize("P") - 1)):
        raise IpcError("launch_invalid_root_locator")
    return value


def _read_locator(value):
    if type(value) is not str or _DECIMAL.fullmatch(value) is None:
        raise IpcError("launch_invalid_root_locator")
    return _locator(int(value))


@dataclass(frozen=True)
class PrepareExecutionRequest:
    request_id: str
    execution_id: str
    spec_hash: str
    guardian_epoch: str
    expected_revision: int
    operation: ClassVar[str] = "PrepareExecution"

    def __post_init__(self):
        _uuid(self.request_id)
        _uuid(self.execution_id)
        _hex(self.spec_hash)
        _epoch(self.guardian_epoch)
        _revision(self.expected_revision)

    def to_dict(self):
        return {"version": 1, "kind": "LaunchRequest", "request_id": self.request_id,
                "operation": self.operation, "execution_id": self.execution_id, "spec_hash": self.spec_hash,
                "guardian_epoch": self.guardian_epoch, "expected_revision": self.expected_revision}

    def payload_hash(self):
        """Canonical whole-request digest; durable storage must not retain the payload."""
        return hashlib.sha256(_canonical(self.to_dict())).hexdigest()

    @classmethod
    def from_dict(cls, value):
        result = decode_request(value)
        if type(result) is not cls:
            raise IpcError("launch_unexpected_operation")
        return result


@dataclass(frozen=True)
class ClaimLaunchRequest(PrepareExecutionRequest):
    job_nonce: str
    claim_token: str = field(repr=False)
    launch_fence_version: int = 1
    operation: ClassVar[str] = "ClaimLaunch"

    def __post_init__(self):
        super().__post_init__()
        _nonce(self.job_nonce)
        if type(self.launch_fence_version) is not int or self.launch_fence_version != 1:
            raise IpcError("launch_fence_version_unsupported")
        if type(self.claim_token) is not str or _CLAIM.fullmatch(self.claim_token) is None:
            raise IpcError("launch_invalid_claim_token")

    def to_dict(self):
        return {**super().to_dict(), "job_nonce": self.job_nonce, "claim_token": self.claim_token,
                "launch_fence_version": self.launch_fence_version}


@dataclass(frozen=True)
class CancelBeforeStartRequest(PrepareExecutionRequest):
    job_nonce: str
    operation: ClassVar[str] = "CancelBeforeStart"

    def __post_init__(self):
        super().__post_init__()
        _nonce(self.job_nonce)

    def to_dict(self):
        return {**super().to_dict(), "job_nonce": self.job_nonce}


@dataclass(frozen=True)
class StartFailedRequest(CancelBeforeStartRequest):
    operation: ClassVar[str] = "StartFailed"


@dataclass(frozen=True)
class BindRootRequest(PrepareExecutionRequest):
    job_nonce: str
    root_identity: ProcessIdentity
    root_handle_locator: int = field(repr=False)
    operation: ClassVar[str] = "BindRoot"

    def __post_init__(self):
        super().__post_init__()
        _nonce(self.job_nonce)
        if type(self.root_identity) is not ProcessIdentity:
            raise IpcError("launch_invalid_root_identity")
        _locator(self.root_handle_locator)

    def to_dict(self):
        return {**super().to_dict(), "job_nonce": self.job_nonce,
                "root_identity": self.root_identity.to_dict(),
                "root_handle_locator": str(self.root_handle_locator)}


def decode_request(value):
    if type(value) is not dict or type(value.get("operation")) is not str:
        raise IpcError("launch_invalid_request")
    operation = value["operation"]
    extra = {"PrepareExecution": set(), "ClaimLaunch": {"job_nonce", "claim_token", "launch_fence_version"},
             "BindRoot": {"job_nonce", "root_identity", "root_handle_locator"},
             "CancelBeforeStart": {"job_nonce"}, "StartFailed": {"job_nonce"}}.get(operation)
    if extra is None:
        raise IpcError("launch_unsupported_operation")
    _shape(value, "LaunchRequest", _COMMON | extra)
    common = {name: value[name] for name in
              ("request_id", "execution_id", "spec_hash", "guardian_epoch", "expected_revision")}
    if operation == "PrepareExecution":
        return PrepareExecutionRequest(**common)
    if operation == "ClaimLaunch":
        return ClaimLaunchRequest(**common, job_nonce=value["job_nonce"], claim_token=value["claim_token"],
                                  launch_fence_version=value["launch_fence_version"])
    if operation in {"CancelBeforeStart", "StartFailed"}:
        cls = CancelBeforeStartRequest if operation == "CancelBeforeStart" else StartFailedRequest
        return cls(**common, job_nonce=value["job_nonce"])
    return BindRootRequest(**common, job_nonce=value["job_nonce"], root_identity=_identity(value["root_identity"]),
                           root_handle_locator=_read_locator(value["root_handle_locator"]))


@dataclass(frozen=True)
class LaunchResult:
    execution_id: str
    spec_hash: str
    guardian_epoch: str
    state: str
    state_revision: int
    job_name: str
    job_nonce: str
    launch_authorized: bool
    duplicate: bool

    def __post_init__(self):
        _uuid(self.execution_id)
        _hex(self.spec_hash)
        _epoch(self.guardian_epoch)
        _revision(self.state_revision)
        _nonce(self.job_nonce)
        if (type(self.state) is not str or self.state not in _STATES or
                type(self.job_name) is not str or
                self.job_name != f"Local\\ResourceSentinel.Job.{self.execution_id}.{self.job_nonce}" or
                type(self.launch_authorized) is not bool or type(self.duplicate) is not bool or
                (self.launch_authorized and (self.state != "LAUNCHING" or self.duplicate))):
            raise IpcError("launch_invalid_result")

    def to_dict(self):
        return {name: getattr(self, name) for name in _RESULT_FIELDS}

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != _RESULT_FIELDS:
            raise IpcError("launch_invalid_result")
        return cls(**value)


def _check_result(request, result):
    if type(result) is not LaunchResult:
        raise IpcError("launch_invalid_result")
    if (result.execution_id != request.execution_id or result.spec_hash != request.spec_hash or
            result.guardian_epoch != request.guardian_epoch or result.state_revision < request.expected_revision or
            (type(request) is not PrepareExecutionRequest and result.job_nonce != request.job_nonce)):
        raise IpcError("launch_result_binding_mismatch")
    if request.operation == "PrepareExecution":
        valid = result.state == "PREPARED" and not result.launch_authorized
    elif request.operation == "ClaimLaunch":
        valid = result.launch_authorized or result.duplicate
    elif request.operation == "CancelBeforeStart":
        valid = result.state in {"CANCELLED_BEFORE_START", "LAUNCHING", "START_UNKNOWN", "RUNNING",
                                 "DRAINING", "UNCERTAIN_HOLD", "FINISHED"} and not result.launch_authorized
    elif request.operation == "StartFailed":
        valid = result.state == "START_FAILED" and not result.launch_authorized
    else:
        valid = result.state in {"RUNNING", "DRAINING", "FINISHED"} and not result.launch_authorized
    if not valid:
        raise IpcError("launch_invalid_result")


def _challenge(request, endpoint, caller):
    return {"version": 1, "kind": "LaunchChallenge", "request_id": request.request_id,
            "nonce": secrets.token_hex(32), "endpoint_id": endpoint.instance_id,
            "guardian_epoch": request.guardian_epoch,
            "server": endpoint.server_identity.to_dict(), "client": caller.to_dict()}


def _check_challenge(value, request, endpoint, caller):
    _shape(value, "LaunchChallenge", {"nonce", "endpoint_id", "guardian_epoch", "server", "client"})
    _hex(value["nonce"])
    _uuid(value["endpoint_id"])
    _epoch(value["guardian_epoch"])
    if (value["request_id"] != request.request_id or value["endpoint_id"] != endpoint.instance_id or
            value["guardian_epoch"] != request.guardian_epoch or _identity(value["server"]) != endpoint.server_identity or
            _identity(value["client"]) != caller):
        raise IpcError("launch_challenge_binding_mismatch")


def _transcript(purpose, request, challenge, result=None):
    if purpose not in {"proof", "result", "receipt"}:
        raise IpcError("launch_invalid_domain")
    value = {"domain": "ResourceSentinel/launch-ipc/v1/" + purpose,
             "request": request.to_dict(), "challenge": challenge}
    if purpose != "proof":
        value["result"] = result
    return _canonical(value)


def _mac(key, payload):
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _envelope(kind, request, challenge, mac):
    return {"version": 1, "kind": kind, "request_id": request.request_id,
            "nonce": challenge["nonce"], "mac": mac}


def _check_correlated(value, kind, request, challenge, *, result=False):
    _shape(value, kind, {"nonce", "mac", *({"result"} if result else set())})
    _hex(value["nonce"])
    _hex(value["mac"])
    if value["request_id"] != request.request_id or value["nonce"] != challenge["nonce"]:
        raise IpcError("launch_response_binding_mismatch")


class LaunchService:
    """One authenticated RPC delegated to a fixed native launch owner.

    The owner must revalidate ``auth_record`` in its mutation transactions,
    consume durable per-operation request slots, and hold native evidence.
    Receiving a typed request here confers none of that authority by itself.
    ``peer`` is borrowed and remains open through the call and response.
    """

    def __init__(self, db_path, endpoint: NativePipeEndpoint, owner):
        self.db_path, self.endpoint, self.owner = db_path, endpoint, owner

    def serve_once(self, listener, *, timeout_ms=1000):
        if listener.endpoint != self.endpoint:
            raise IpcError("launch_endpoint_mismatch")
        deadline = NativeDeadline.after_ms(timeout_ms)
        with listener.accept(deadline) as connection:
            result = self._serve_connection(connection, deadline)
        _remaining(deadline)
        return result

    def _serve_connection(self, connection, deadline):
        request = decode_request(read_frame(connection, deadline))
        record = _get_ipc_auth_record(self.db_path, request.execution_id,
                                      timeout_ms=min(250, _remaining(deadline)))
        if record.spec_hash != request.spec_hash or record.wrapper_identity.logon_id != self.endpoint.logon_id:
            raise IpcError("launch_auth_binding_mismatch")
        if type(request) is BindRootRequest and request.root_identity.logon_id != record.wrapper_identity.logon_id:
            raise IpcError("launch_root_logon_mismatch")
        with connection.verified_peer(record.wrapper_identity) as peer:
            _live(connection, peer, record.wrapper_identity)
            challenge = _challenge(request, self.endpoint, record.wrapper_identity)
            write_frame(connection, challenge, deadline)
            proof = read_frame(connection, deadline)
            _check_correlated(proof, "LaunchProof", request, challenge)
            if not hmac.compare_digest(proof["mac"], _mac(record.ipc_auth_key, _transcript("proof", request, challenge))):
                raise IpcError("launch_auth_failed")
            _remaining(deadline)
            _live(connection, peer, record.wrapper_identity)
            if type(request) is PrepareExecutionRequest:
                result = self.owner.prepare_execution(request, peer, auth_record=record, deadline=deadline)
            elif type(request) is ClaimLaunchRequest:
                result = self.owner.claim_launch(request, peer, auth_record=record, deadline=deadline)
            elif type(request) in {CancelBeforeStartRequest, StartFailedRequest}:
                result = self.owner.retire_before_start(request, peer, auth_record=record, deadline=deadline)
            else:
                result = self.owner.bind_root(request, peer, auth_record=record, deadline=deadline)
            _remaining(deadline)
            _live(connection, peer, record.wrapper_identity)
            _check_result(request, result)
            payload = result.to_dict()
            response = _envelope("LaunchResult", request, challenge,
                                 _mac(record.ipc_auth_key, _transcript("result", request, challenge, payload)))
            response["result"] = payload
            write_frame(connection, response, deadline)
            receipt = read_frame(connection, deadline)
            _check_correlated(receipt, "LaunchReceipt", request, challenge)
            if not hmac.compare_digest(receipt["mac"],
                    _mac(record.ipc_auth_key, _transcript("receipt", request, challenge, payload))):
                raise IpcError("launch_receipt_invalid")
            _remaining(deadline)
            return {"request_id": request.request_id, "execution_id": request.execution_id,
                    "operation": request.operation, "receipt_verified": True}


class ManagedLaunchClient:
    """Use one retained ManagedAdmission; never relaunch after an uncertain RPC.

    All RPCs return only after result validation, a response receipt, and native
    scope cleanup. A caller must keep the original root/Job/context until the
    guardian has positively accepted custody. The receipt is not that proof.
    """

    def __init__(self, context, endpoint: NativePipeEndpoint, *, guardian_epoch):
        _epoch(guardian_epoch)
        self.context, self.endpoint, self.guardian_epoch = context, endpoint, guardian_epoch

    def prepare_execution(self, *, expected_revision, request_id, timeout_ms=1000):
        return self._request("PrepareExecution", expected_revision=expected_revision,
                             request_id=request_id, timeout_ms=timeout_ms)

    def claim_launch(self, *, expected_revision, job_nonce, request_id, timeout_ms=1000, launch_fence_version=1):
        return self._request("ClaimLaunch", expected_revision=expected_revision, job_nonce=job_nonce,
                             request_id=request_id, timeout_ms=timeout_ms, launch_fence_version=launch_fence_version)

    def bind_root(self, *, expected_revision, job_nonce, root_identity, root_handle_locator,
                  request_id, timeout_ms=1000):
        return self._request("BindRoot", expected_revision=expected_revision, job_nonce=job_nonce,
                             root_identity=root_identity, root_handle_locator=root_handle_locator,
                             request_id=request_id, timeout_ms=timeout_ms)

    def cancel_before_start(self, *, expected_revision, job_nonce, request_id, timeout_ms=1000):
        return self._request("CancelBeforeStart", expected_revision=expected_revision, job_nonce=job_nonce,
                             request_id=request_id, timeout_ms=timeout_ms)

    def start_failed(self, *, expected_revision, job_nonce, request_id, timeout_ms=1000):
        return self._request("StartFailed", expected_revision=expected_revision, job_nonce=job_nonce,
                             request_id=request_id, timeout_ms=timeout_ms)

    def _request(self, operation, *, expected_revision, request_id, timeout_ms, **fields):
        mutation_possible = False
        try:
            deadline = NativeDeadline.after_ms(timeout_ms)
            snapshot = self.context.snapshot()
            caller = snapshot.wrapper_identity
            common = dict(request_id=request_id,
                          execution_id=snapshot.execution_id, spec_hash=snapshot.spec_hash,
                          guardian_epoch=self.guardian_epoch, expected_revision=expected_revision)
            # Validate selectors before transport but never export the one-use
            # credential until inside the positively verified server scope.
            PrepareExecutionRequest(**common)
            if caller.logon_id != self.endpoint.logon_id:
                raise IpcError("launch_client_logon_mismatch")
            with NativePipeConnection.connect(self.endpoint, deadline) as connection:
                with connection.verified_peer(self.endpoint.server_identity) as peer:
                    _live(connection, peer, self.endpoint.server_identity)
                    if operation == "ClaimLaunch":
                        request = ClaimLaunchRequest(**common, **fields, claim_token=self.context.launch_claim_token())
                    elif operation == "BindRoot":
                        request = BindRootRequest(**common, **fields)
                        if request.root_identity.logon_id != caller.logon_id:
                            raise IpcError("launch_root_logon_mismatch")
                    elif operation in {"CancelBeforeStart", "StartFailed"}:
                        cls = CancelBeforeStartRequest if operation == "CancelBeforeStart" else StartFailedRequest
                        request = cls(**common, **fields)
                    else:
                        request = PrepareExecutionRequest(**common)
                    _live(connection, peer, self.endpoint.server_identity)
                    write_frame(connection, request.to_dict(), deadline)
                    challenge = read_frame(connection, deadline)
                    _check_challenge(challenge, request, self.endpoint, caller)
                    _live(connection, peer, self.endpoint.server_identity)
                    def sign(purpose, payload=None):
                        return self.context._ipc_mac(_transcript(purpose, request, challenge, payload),
                            execution_id=request.execution_id, spec_hash=request.spec_hash, caller=caller)
                    proof = _envelope("LaunchProof", request, challenge, sign("proof"))
                    mutation_possible = True  # A partial/failed write may have completed remotely.
                    write_frame(connection, proof, deadline)
                    response = read_frame(connection, deadline)
                    _check_correlated(response, "LaunchResult", request, challenge, result=True)
                    _live(connection, peer, self.endpoint.server_identity)
                    if not hmac.compare_digest(response["mac"], sign("result", response["result"])):
                        raise IpcError("launch_result_auth_failed")
                    result = LaunchResult.from_dict(response["result"])
                    _check_result(request, result)
                    write_frame(connection, _envelope("LaunchReceipt", request, challenge,
                                                      sign("receipt", response["result"])), deadline)
                    _remaining(deadline)
            _remaining(deadline)
            return result
        except Exception as error:
            reason = getattr(error, "reason", "launch_rpc_failed")
            if type(reason) is not str or re.fullmatch(r"[a-z][a-z0-9_]{0,127}", reason) is None:
                reason = "launch_rpc_failed"
            raise LaunchTransportError(reason, launch_outcome_unknown=mutation_possible,
                                       cleanup_error=error) from None
        except BaseException as error:
            # Preserve interrupts, but let the owning wrapper retain custody
            # rather than infer that an interrupted call never committed.
            error.launch_outcome_unknown = mutation_possible
            raise
