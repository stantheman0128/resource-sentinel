"""Authenticated, bounded helper-to-guardian control transport.

The closed union carries proposals, at-most-ten Job aggregates or exact scoped
restore requests. It accepts no arbitrary PID, command or SetInformation class.

The service grants no authority. It decodes one frame, authenticates the caller
against the infrastructure registry, hands the typed proposal to GuardianControl
and returns the acknowledgement that came back. Mode, scope, exemption reread,
freshness, lease and the single active cap all stay where they already live. The
service never reads the ledger mode, never short circuits an apply and keeps no
acknowledgement of its own. A retried request id is answered by GuardianControl
with the original acknowledgement, which is the only correct cache for it.

Authentication is the OS verified peer plus a per request nonce. The caller must
be the process registered with role helper for this endpoint's logon in
``adaptive_infrastructure``, proven through the native peer handle rather than
through anything in the message. A PID reported inside JSON is never trusted.
Unlike the wrapper RPCs there is no shared secret, because the helper owns no
``ipc_auth_key`` and the registry schema is fixed. See the plan clarification in
docs/planning/adaptive-scheduler/P3-CONTROL-TRANSPORT.md.

The client verifies the exact server process before writing anything, checks the
challenge binding before accepting a response and checks that the returned
acknowledgement is bound to the proposal it sent. Once the proposal frame may
have reached the guardian, any later failure is an uncertain outcome. The client
never retries by itself, and it never invents a new request id or sequence.

Every request, challenge and response binds operation kind and policy epoch.
Mixed old/new endpoints lacking these fields fail closed; there is no legacy
wire fallback. Transport success proves no Windows control capability or gate.
"""
from __future__ import annotations

import re
import secrets

from .contracts import (ApplyAck, ContractViolation, ControlProposal, MAX_MESSAGE_BYTES,
                        ProcessIdentity)
from .control_messages import (ControlFrameAck, ControlFrameRequest, ControlRestoreRequest, RestoreAck)
from .ipc import (IpcError, PROTOCOL_MAJOR, _hex, _identity, _live, _remaining, _shape, _uuid,
                  read_frame, write_frame)
from .legacy_writer import MAX_INFRASTRUCTURE, _INFRA_COLUMNS
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint
from .store import _ipc_read_transaction


# One short registry snapshot per request, the same bound the other services use
# for their authentication read.
REGISTRY_TIMEOUT_MS = 250
HELPER_ROLE = "helper"
# The plan's 256 KiB cap, reused rather than restated. read_frame rejects a
# length prefix above it before any body is requested, and the canonical
# encoder refuses to emit a larger frame.
MAX_FRAME_BYTES = MAX_MESSAGE_BYTES
_REASON = re.compile(r"[a-z][a-z0-9_]{0,127}")


class ControlTransportError(IpcError):
    """A sanitized failure. An uncertain outcome never becomes a result."""

    def __init__(self, reason, *, outcome_unknown=False):
        self.outcome_unknown = outcome_unknown
        super().__init__(reason)


# --- caller authentication ----------------------------------------------------


def registered_helper(db_path, endpoint: NativePipeEndpoint, *,
                      timeout_ms: int = REGISTRY_TIMEOUT_MS) -> ProcessIdentity:
    """Resolve the one process registered as helper for this endpoint's logon.

    ``adaptive_infrastructure`` is the only authority on who the helper is. The
    read is a short bounded snapshot that ends before the native peer is opened,
    so no transaction is held across a native call or across the owner call. An
    unreadable or malformed registry is a refusal, and so is a registry holding
    no helper row or more than one for this logon: the MVP supports a single
    resident helper per logon session, and choosing between candidates would put
    a selection rule where an authority record belongs.
    """
    with _ipc_read_transaction(db_path, timeout_ms=timeout_ms) as conn:
        found = conn.execute(
            "SELECT type FROM sqlite_master WHERE name='adaptive_infrastructure'").fetchone()
        if found is None or found[0] != "table":
            raise ControlTransportError("control_registry_unavailable")
        if {row[1] for row in conn.execute("PRAGMA table_info(adaptive_infrastructure)")} != _INFRA_COLUMNS:
            raise ControlTransportError("control_registry_invalid")
        # Bound every column before it becomes a Python value, as the other
        # private readers do, so a damaged large row cannot be allocated here.
        rows = conn.execute("""SELECT
            CASE WHEN typeof(pid)='integer' THEN pid END AS pid,
            substr(created_filetime_100ns,1,21) AS created_filetime_100ns,
            substr(logon_id,1,129) AS logon_id,
            CASE WHEN typeof(schema_version)='integer' THEN schema_version END AS schema_version
            FROM adaptive_infrastructure
            WHERE typeof(role)='text' AND role=?
              AND typeof(logon_id)='text' AND logon_id=?
            LIMIT ?""", (HELPER_ROLE, endpoint.logon_id, MAX_INFRASTRUCTURE + 1)).fetchall()
    if not rows:
        raise ControlTransportError("control_helper_unregistered")
    if len(rows) > 1:
        raise ControlTransportError("control_helper_ambiguous")
    row = rows[0]
    if row["schema_version"] != 1:
        raise ControlTransportError("control_registry_invalid")
    try:
        identity = ProcessIdentity.from_dict({"pid": row["pid"],
                                              "created_filetime_100ns": row["created_filetime_100ns"],
                                              "logon_id": row["logon_id"]})
    except (ContractViolation, ValueError, TypeError, OverflowError):
        raise ControlTransportError("control_registry_invalid") from None
    if identity == endpoint.server_identity:
        # The guardian is the server here. A registry row naming it as the
        # helper is a broken record, not a caller this service will accept.
        raise ControlTransportError("control_helper_identity_invalid")
    return identity


# --- wire format --------------------------------------------------------------


_REQUEST_KINDS = {ControlProposal: "ControlProposalRequest", ControlFrameRequest: "ControlFrameRequest",
                  ControlRestoreRequest: "ControlRestoreRequest"}
_ACK_TYPES = {ControlProposal: ApplyAck, ControlFrameRequest: ControlFrameAck, ControlRestoreRequest: RestoreAck}


def _request_kind(request):
    try:
        return _REQUEST_KINDS[type(request)]
    except KeyError:
        raise ControlTransportError("control_invalid_request") from None


def request_envelope(request) -> dict:
    """Closed operation union; old envelopes lacking binding fail closed."""
    kind = _request_kind(request)
    message = {"version": PROTOCOL_MAJOR, "kind": kind, "request_id": request.request_id,
               "guardian_epoch": request.guardian_epoch, "policy_epoch": request.policy_epoch}
    if type(request) is ControlProposal:
        message["proposal"] = request.to_dict()
    elif type(request) is ControlFrameRequest:
        message["frame"] = request.frame.to_dict()
    else:
        message.update(execution_id=request.execution_id, reason=request.reason)
    return message


def decode_proposal(value) -> ControlProposal:
    """Validate one wire message into the typed contract, or refuse it."""
    _shape(value, "ControlProposalRequest", {"proposal", "guardian_epoch", "policy_epoch"})
    payload = value["proposal"]
    if type(payload) is not dict:
        raise ControlTransportError("control_invalid_proposal")
    try:
        proposal = ControlProposal.from_dict(payload)
    except (ContractViolation, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ControlTransportError("control_invalid_proposal") from None
    if any(getattr(proposal, name) != value[name] for name in ("request_id", "guardian_epoch", "policy_epoch")):
        raise ControlTransportError("control_request_binding_mismatch")
    return proposal


def decode_request(value):
    if type(value) is not dict:
        raise ControlTransportError("control_invalid_request")
    kind = value.get("kind")
    if kind == "ControlProposalRequest":
        return decode_proposal(value)
    if type(kind) is not str or kind not in {"ControlFrameRequest", "ControlRestoreRequest"}:
        raise IpcError("ipc_unexpected_message")
    payload_fields = {"frame"} if kind == "ControlFrameRequest" else {"execution_id", "reason"}
    _shape(value, kind, {"guardian_epoch", "policy_epoch", *payload_fields})
    data = {name: value[name] for name in ("request_id", "guardian_epoch", "policy_epoch", *payload_fields)}
    data["schema_version"] = PROTOCOL_MAJOR
    cls = ControlFrameRequest if kind == "ControlFrameRequest" else ControlRestoreRequest
    try:
        return cls.from_dict(data)
    except (ContractViolation, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ControlTransportError("control_invalid_request") from None


def _challenge(proposal, endpoint, caller):
    """A one use server nonce bound to this request and both identities.

    It is not a secret and it proves no shared key. It exists so an answer
    cannot be correlated to another request, another endpoint instance, another
    guardian epoch or another pair of processes.
    """
    return {"version": PROTOCOL_MAJOR, "kind": "ControlChallenge",
            "request_id": proposal.request_id, "nonce": secrets.token_hex(32),
            "endpoint_id": endpoint.instance_id, "guardian_epoch": proposal.guardian_epoch,
            "policy_epoch": proposal.policy_epoch, "operation": _request_kind(proposal),
            "server": endpoint.server_identity.to_dict(), "client": caller.to_dict()}


def _check_challenge(value, proposal, endpoint, caller):
    _shape(value, "ControlChallenge", {"nonce", "endpoint_id", "guardian_epoch", "policy_epoch", "operation", "server", "client"})
    _hex(value["nonce"])
    _uuid(value["endpoint_id"])
    if (value["request_id"] != proposal.request_id or
            value["endpoint_id"] != endpoint.instance_id or
            value["guardian_epoch"] != proposal.guardian_epoch or
            value["policy_epoch"] != proposal.policy_epoch or value["operation"] != _request_kind(proposal) or
            _identity(value["server"]) != endpoint.server_identity or
            _identity(value["client"]) != caller):
        raise ControlTransportError("control_challenge_binding_mismatch")


def _ack_envelope(proposal, challenge, ack):
    return {"version": PROTOCOL_MAJOR, "kind": "ControlAck", "request_id": proposal.request_id,
            "guardian_epoch": proposal.guardian_epoch, "policy_epoch": proposal.policy_epoch,
            "operation": _request_kind(proposal), "nonce": challenge["nonce"], "ack": ack.to_dict()}


def _check_ack(proposal, ack):
    """The acknowledgement must belong to the proposal that was sent.

    A guardian that refuses a stale guardian epoch answers with its own epoch,
    so such a rejection fails this check on both sides and never reaches the
    caller as a parsed acknowledgement. That is the conservative direction: the
    proposer has to resynchronize rather than read a refusal it cannot bind.
    """
    cls = _ACK_TYPES.get(type(proposal))
    if cls is None or type(ack) is not cls:
        raise ControlTransportError("control_invalid_ack")
    try:
        # Validate trusted-owner output too, before publishing it. The wire
        # decoder repeats this independently on the receiving helper.
        cls.from_dict(ack.to_dict())
    except (ContractViolation, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ControlTransportError("control_invalid_ack") from None
    if (ack.request_id != proposal.request_id or
            ack.guardian_epoch != proposal.guardian_epoch or
            ack.policy_epoch != proposal.policy_epoch):
        raise ControlTransportError("control_ack_binding_mismatch")
    if type(proposal) is ControlProposal:
        if ack.execution_id != proposal.execution_id or ack.decision_seq != proposal.decision_seq:
            raise ControlTransportError("control_ack_binding_mismatch")
    elif type(proposal) is ControlFrameRequest:
        frame = proposal.frame
        if (ack.sampler_epoch != frame.sampler_epoch or ack.clock_epoch != frame.clock_epoch or
                ack.sample_seq != frame.sample_seq or
                not {item.execution_id for item in ack.results} <= {job.execution_id for job in frame.jobs}):
            raise ControlTransportError("control_ack_binding_mismatch")
    elif ack.execution_id != proposal.execution_id:
        raise ControlTransportError("control_ack_binding_mismatch")
    return ack


def decode_ack(value, proposal, challenge) -> ApplyAck | ControlFrameAck | RestoreAck:
    _shape(value, "ControlAck", {"nonce", "ack", "operation", "guardian_epoch", "policy_epoch"})
    _hex(value["nonce"])
    if (value["request_id"] != proposal.request_id or value["nonce"] != challenge["nonce"] or
            value["operation"] != _request_kind(proposal) or value["guardian_epoch"] != proposal.guardian_epoch or
            value["policy_epoch"] != proposal.policy_epoch):
        raise ControlTransportError("control_response_binding_mismatch")
    payload = value["ack"]
    if type(payload) is not dict:
        raise ControlTransportError("control_invalid_ack")
    try:
        ack = _ACK_TYPES[type(proposal)].from_dict(payload)
    except (ContractViolation, ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise ControlTransportError("control_invalid_ack") from None
    return _check_ack(proposal, ack)


# --- service ------------------------------------------------------------------


class ControlProposalService:
    """One proposal, one acknowledgement, one connection, one deadline.

    ``db_path_or_store`` is the lifecycle ledger path, or a store exposing it.
    The database is read for the infrastructure registry only. ``control`` is
    the GuardianControl that owns every safety decision; this class adds none
    and removes none. It starts no thread and holds no resident daemon: a host
    calls serve_once for each accepted connection.
    """

    def __init__(self, db_path_or_store, endpoint: NativePipeEndpoint, control):
        self.db_path = getattr(db_path_or_store, "db_path", db_path_or_store)
        self.endpoint = endpoint
        self.control = control

    def serve_once(self, listener, *, timeout_ms=1000) -> ApplyAck | ControlFrameAck | RestoreAck:
        """Serve one authenticated closed operation and its typed response."""
        if listener.endpoint != self.endpoint:
            raise ControlTransportError("control_endpoint_mismatch")
        deadline = NativeDeadline.after_ms(timeout_ms)
        with listener.accept(deadline) as connection:
            ack = self._serve_connection(connection, deadline)
        _remaining(deadline)
        return ack

    def _serve_connection(self, connection, deadline):
        # The helper's identity does not depend on the request, so the caller is
        # authenticated before a single request byte is read or parsed.
        caller = registered_helper(self.db_path, self.endpoint,
                                   timeout_ms=min(REGISTRY_TIMEOUT_MS, _remaining(deadline)))
        # The peer handle is opened against the registered identity and stays
        # retained through the apply and the response. A liveness recheck sits
        # before and after the owner call, as in the other two services.
        with connection.verified_peer(caller) as peer:
            _live(connection, peer, caller)
            proposal = decode_request(read_frame(connection, deadline))
            _live(connection, peer, caller)
            challenge = _challenge(proposal, self.endpoint, caller)
            write_frame(connection, challenge, deadline)
            _live(connection, peer, caller)
            # Native peer observation may itself consume the remaining budget.
            # Do not start an owner operation after the total RPC deadline.
            _remaining(deadline)
            if type(proposal) is ControlProposal:
                ack = self.control.apply(proposal, helper_identity=peer.identity)
            elif type(proposal) is ControlFrameRequest:
                ack = self.control.observe_control_frame(proposal, helper_identity=peer.identity)
            else:
                ack = self.control.restore_control_request(proposal, helper_identity=peer.identity)
            _remaining(deadline)
            _live(connection, peer, caller)
            _check_ack(proposal, ack)
            write_frame(connection, _ack_envelope(proposal, challenge, ack), deadline)
            _remaining(deadline)
            return ack


# --- client -------------------------------------------------------------------


class ControlProposalClient:
    """Send one proposal to the pinned guardian and read its acknowledgement.

    ``caller_process_or_identity`` is the helper's own retained process or its
    exact identity. It is used to check the challenge binding, so the caller
    learns that the guardian authenticated the process it believes it is.
    """

    def __init__(self, endpoint: NativePipeEndpoint, *, caller_process_or_identity):
        identity = getattr(caller_process_or_identity, "identity", caller_process_or_identity)
        if not isinstance(identity, ProcessIdentity):
            raise ControlTransportError("control_caller_identity_required")
        if identity.logon_id != endpoint.logon_id:
            raise ControlTransportError("control_client_logon_mismatch")
        self.endpoint = endpoint
        self.caller = identity

    def propose(self, proposal, *, timeout_ms=1000) -> ApplyAck:
        """One attempt. A failure after the write is an unknown outcome.

        There is no automatic retry here. Retrying is the proposer's decision,
        and a retry must reuse the same request id and the same decision
        sequence so the guardian can answer with the original acknowledgement.
        """
        if type(proposal) is not ControlProposal:
            raise ControlTransportError("control_proposal_required")
        return self._send(proposal, timeout_ms=timeout_ms)

    def observe_uncapped(self, frame, *, request_id, guardian_epoch, policy_epoch, timeout_ms=1000) -> ControlFrameAck:
        try:
            request = ControlFrameRequest(request_id, guardian_epoch, policy_epoch, frame)
        except (ContractViolation, ValueError, TypeError):
            raise ControlTransportError("control_invalid_frame_request") from None
        return self._send(request, timeout_ms=timeout_ms)

    def request_restore(self, execution_id, *, request_id, guardian_epoch, policy_epoch,
                        reason, timeout_ms=1000) -> RestoreAck:
        try:
            request = ControlRestoreRequest(request_id, guardian_epoch, policy_epoch, execution_id, reason)
        except (ContractViolation, ValueError, TypeError):
            raise ControlTransportError("control_invalid_restore_request") from None
        return self._send(request, timeout_ms=timeout_ms)

    def _send(self, proposal, *, timeout_ms=1000):
        outcome_unknown = False
        try:
            _request_kind(proposal)
            deadline = NativeDeadline.after_ms(timeout_ms)
            message = request_envelope(proposal)
            with NativePipeConnection.connect(self.endpoint, deadline) as connection:
                # Pin the actual server process before a single byte is written.
                # No identity claimed on the wire can establish this.
                with connection.verified_peer(self.endpoint.server_identity) as peer:
                    _live(connection, peer, self.endpoint.server_identity)
                    outcome_unknown = True  # A partial write may still arrive.
                    write_frame(connection, message, deadline)
                    challenge = read_frame(connection, deadline)
                    _check_challenge(challenge, proposal, self.endpoint, self.caller)
                    _live(connection, peer, self.endpoint.server_identity)
                    ack = decode_ack(read_frame(connection, deadline), proposal, challenge)
                    _live(connection, peer, self.endpoint.server_identity)
                    _remaining(deadline)
            _remaining(deadline)
            return ack
        except Exception as error:
            reason = getattr(error, "reason", "control_rpc_failed")
            if type(reason) is not str or _REASON.fullmatch(reason) is None:
                reason = "control_rpc_failed"
            raise ControlTransportError(reason, outcome_unknown=outcome_unknown) from None
        except BaseException as error:
            # Keep interrupts, and keep the uncertainty with them rather than
            # letting a caller infer that an interrupted call never arrived.
            error.control_outcome_unknown = outcome_unknown
            raise
