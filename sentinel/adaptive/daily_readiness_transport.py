"""Read-only readiness from the original daily generation's retained owner.

The endpoint is a locator, not an admission receipt. Only the original native
server can answer, and it calls its own DailyGenerationOwner.assert_ready after
authenticating the caller. This protocol neither allocates capacity nor adopts
a generation, enters POLICY, installs a trigger, or starts a keeper.

Success has no serializable receipt: the client returns None only after exact
peer verification, a fully bound reply and positive channel/peer cleanup. The
caller must perform this check before entering its own SQL transaction. Native
I/O shares one deadline; synchronous readiness verification can exceed that
deadline, in which case its result is rejected rather than accepted late.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
from uuid import uuid4

from .contracts import ContractViolation, IdentityStatus, ProcessIdentity, strict_json_loads
from .identity import VerifiedProcess
from .ipc import IpcError, PROTOCOL_MAJOR, _hex, _identity, _live, _remaining, _shape, _uuid
from .pipe_windows import NativeDeadline, NativePipeConnection, NativePipeEndpoint


MAX_HELLO_BYTES = 2048
MAX_MESSAGE_BYTES = 4096
_REASON = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,38})\Z")
_BINDING_FIELDS = frozenset({"generation", "source_digest", "config_digest", "ledger_identity"})


class DailyReadinessError(IpcError):
    """A failed observation; never proof of generation or capacity readiness."""


@dataclass(frozen=True)
class LedgerFileIdentity:
    """Stable file-object binding; SQLite's mutable size/mtime are excluded."""

    st_dev: int
    st_ino: int

    def __post_init__(self):
        if (type(self.st_dev) is not int or not 0 <= self.st_dev < 1 << 128 or
                type(self.st_ino) is not int or not 0 < self.st_ino < 1 << 128):
            raise DailyReadinessError("daily_ledger_identity_invalid")

    def to_dict(self):
        return {"st_dev": str(self.st_dev), "st_ino": str(self.st_ino)}

    @classmethod
    def from_dict(cls, value):
        if (type(value) is not dict or set(value) != {"st_dev", "st_ino"} or
                any(type(item) is not str or _DECIMAL.fullmatch(item) is None
                    for item in value.values())):
            raise DailyReadinessError("daily_ledger_identity_invalid")
        return cls(int(value["st_dev"]), int(value["st_ino"]))

    @classmethod
    def capture(cls, path):
        """Read an existing non-reparse ledger; creates and writes nothing."""
        path = Path(path).absolute()
        try:
            for component in (path, *path.parents):
                item = component.lstat()
                if stat.S_ISLNK(item.st_mode) or getattr(item, "st_file_attributes", 0) & 0x400:
                    raise DailyReadinessError("daily_ledger_reparse_unsupported")
            before = path.stat()
            if not stat.S_ISREG(before.st_mode):
                raise DailyReadinessError("daily_ledger_identity_invalid")
            expected = cls(before.st_dev, before.st_ino)
            with path.open("rb") as stream:
                opened = os.fstat(stream.fileno())
                if not stat.S_ISREG(opened.st_mode) or cls(opened.st_dev, opened.st_ino) != expected:
                    raise DailyReadinessError("daily_ledger_identity_changed")
            after = path.stat()
            if not stat.S_ISREG(after.st_mode) or cls(after.st_dev, after.st_ino) != expected:
                raise DailyReadinessError("daily_ledger_identity_changed")
            return expected
        except OSError:
            raise DailyReadinessError("daily_ledger_identity_unavailable") from None


def _binding(generation, source_digest, config_digest, ledger_identity):
    _uuid(generation)
    _hex(source_digest)
    _hex(config_digest)
    if type(ledger_identity) is not LedgerFileIdentity:
        raise DailyReadinessError("daily_ledger_identity_required")
    return {"generation": generation, "source_digest": source_digest,
            "config_digest": config_digest, "ledger_identity": ledger_identity.to_dict()}


def _validate_binding(value):
    return _binding(value["generation"], value["source_digest"], value["config_digest"],
                    LedgerFileIdentity.from_dict(value["ledger_identity"]))


def _read(connection, deadline, *, limit=MAX_MESSAGE_BYTES):
    _remaining(deadline)
    prefix = connection.read_exact(4, deadline)
    if type(prefix) is not bytes or len(prefix) != 4:
        raise DailyReadinessError("daily_readiness_truncated_frame")
    size = struct.unpack("<I", prefix)[0]
    if not 1 <= size <= limit:
        raise DailyReadinessError("daily_readiness_frame_too_large")
    _remaining(deadline)
    payload = connection.read_exact(size, deadline)
    _remaining(deadline)
    if type(payload) is not bytes or len(payload) != size:
        raise DailyReadinessError("daily_readiness_truncated_frame")
    try:
        return strict_json_loads(payload)
    except (ContractViolation, ValueError, TypeError, RecursionError):
        raise DailyReadinessError("daily_readiness_invalid_json") from None


def _write(connection, value, deadline, *, limit=MAX_MESSAGE_BYTES):
    try:
        payload = json.dumps(value, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError):
        raise DailyReadinessError("daily_readiness_invalid_json") from None
    if not 1 <= len(payload) <= limit:
        raise DailyReadinessError("daily_readiness_frame_too_large")
    _remaining(deadline)
    connection.write_all(struct.pack("<I", len(payload)) + payload, deadline)
    _remaining(deadline)


def _current_process(process, endpoint, *, server=False):
    if type(process) is not VerifiedProcess or process.identity.pid != os.getpid():
        raise DailyReadinessError("daily_readiness_current_process_required")
    if (process.identity.logon_id != endpoint.logon_id or
            (server and process.identity != endpoint.server_identity)):
        raise DailyReadinessError("daily_readiness_identity_mismatch")
    observed = process.observe()
    if observed.status is not IdentityStatus.ALIVE or observed.identity != process.identity:
        raise DailyReadinessError("daily_readiness_process_unavailable")
    return process.identity


def _failure(error, *, connection, owner):
    reason = getattr(error, "reason", "daily_readiness_rpc_failed")
    if type(reason) is not str or _REASON.fullmatch(reason) is None:
        reason = "daily_readiness_rpc_failed"
    failure = DailyReadinessError(reason)
    # Native transport also retains unknown completions in its bounded registry.
    # Keep every original witness/cause here: sanitization must not lose custody.
    failure._daily_readiness_cause = error
    failure._daily_readiness_connection = connection
    failure._daily_readiness_owner = owner
    return failure


class DailyReadinessService:
    """A fixed original owner, with no generic handler or caller-supplied proof."""

    def __init__(self, endpoint, owner):
        from .daily_generation import DailyGenerationOwner
        if type(endpoint) is not NativePipeEndpoint or type(owner) is not DailyGenerationOwner:
            raise DailyReadinessError("daily_readiness_original_owner_required")
        if endpoint != getattr(owner, "readiness_endpoint", None):
            raise DailyReadinessError("daily_readiness_endpoint_mismatch")
        _current_process(owner.process, endpoint, server=True)
        self.endpoint, self.owner = endpoint, owner
        self._process = owner.process

    def serve_once(self, listener, *, timeout_ms=100):
        if listener.endpoint != self.endpoint:
            raise DailyReadinessError("daily_readiness_endpoint_mismatch")
        if self.owner.process is not self._process:
            raise DailyReadinessError("daily_readiness_original_owner_required")
        _current_process(self.owner.process, self.endpoint, server=True)
        deadline = NativeDeadline.after_ms(timeout_ms)
        connection = None
        try:
            with listener.accept(deadline) as connection:
                self._serve_connection(connection, deadline)
            _remaining(deadline)
        except Exception as error:
            raise _failure(error, connection=connection, owner=self) from None
        except BaseException as error:
            error._daily_readiness_connection = connection
            error._daily_readiness_owner = self
            raise

    def _serve_connection(self, connection, deadline):
        hello = _read(connection, deadline, limit=MAX_HELLO_BYTES)
        _shape(hello, "DailyReadinessHello", {"caller"})
        caller = _identity(hello["caller"])
        if caller.logon_id != self.endpoint.logon_id:
            raise DailyReadinessError("daily_readiness_logon_mismatch")
        with connection.verified_peer(caller) as peer:
            _live(connection, peer, caller)
            request = _read(connection, deadline)
            _shape(request, "DailyReadinessAssert", _BINDING_FIELDS)
            requested = _validate_binding(request)
            if request["request_id"] != hello["request_id"]:
                raise DailyReadinessError("daily_readiness_request_mismatch")
            _current_process(self.owner.process, self.endpoint, server=True)
            _live(connection, peer, caller)
            _remaining(deadline)
            # Only this exact retained owner can establish readiness. In
            # particular its activation ACK is not inferred from a DB row.
            self.owner.assert_ready()
            _remaining(deadline)
            ledger_identity = self.owner.ledger_identity
            if type(ledger_identity) is not tuple or len(ledger_identity) != 2:
                raise DailyReadinessError("daily_ledger_identity_invalid")
            actual = _binding(self.owner.generation, self.owner.manifest.digest,
                              self.owner._config_digest, LedgerFileIdentity(*ledger_identity))
            if actual != requested:
                raise DailyReadinessError("daily_readiness_binding_mismatch")
            _current_process(self.owner.process, self.endpoint, server=True)
            _live(connection, peer, caller)
            reply = {"version": PROTOCOL_MAJOR, "kind": "DailyReadinessReady",
                     "request_id": request["request_id"], "endpoint_id": self.endpoint.instance_id,
                     "server": self.endpoint.server_identity.to_dict(), "client": caller.to_dict(),
                     "nonce": secrets.token_hex(32), **actual}
            _write(connection, reply, deadline)
            _live(connection, peer, caller)
            _remaining(deadline)


class DailyReadinessClient:
    """One authenticated observation before caller SQL BEGIN; never retries."""

    def __init__(self, endpoint, caller_process):
        if type(endpoint) is not NativePipeEndpoint:
            raise DailyReadinessError("daily_readiness_endpoint_required")
        _current_process(caller_process, endpoint)
        self.endpoint, self.caller_process = endpoint, caller_process

    def assert_ready(self, generation, source_digest, config_digest, ledger_identity, *, timeout_ms=1000):
        expected = _binding(generation, source_digest, config_digest, ledger_identity)
        caller = _current_process(self.caller_process, self.endpoint)
        request_id = str(uuid4())
        request = {"version": PROTOCOL_MAJOR, "kind": "DailyReadinessAssert",
                   "request_id": request_id, **expected}
        hello = {"version": PROTOCOL_MAJOR, "kind": "DailyReadinessHello",
                 "request_id": request_id, "caller": caller.to_dict()}
        deadline = NativeDeadline.after_ms(timeout_ms)
        connection = None
        try:
            with NativePipeConnection.connect(self.endpoint, deadline) as connection:
                with connection.verified_peer(self.endpoint.server_identity) as peer:
                    _live(connection, peer, self.endpoint.server_identity)
                    _write(connection, hello, deadline, limit=MAX_HELLO_BYTES)
                    _write(connection, request, deadline)
                    reply = _read(connection, deadline)
                    _shape(reply, "DailyReadinessReady", _BINDING_FIELDS | {
                        "endpoint_id", "server", "client", "nonce"})
                    _hex(reply["nonce"])
                    _uuid(reply["endpoint_id"])
                    if (reply["request_id"] != request_id or
                            reply["endpoint_id"] != self.endpoint.instance_id or
                            _identity(reply["server"]) != self.endpoint.server_identity or
                            _identity(reply["client"]) != caller or
                            _validate_binding(reply) != expected):
                        raise DailyReadinessError("daily_readiness_reply_mismatch")
                    _live(connection, peer, self.endpoint.server_identity)
                    _current_process(self.caller_process, self.endpoint)
                    _remaining(deadline)
            # Both native context managers must return positively. No JSON,
            # callback result, or reply observed before cleanup is returned.
            _remaining(deadline)
            return None
        except Exception as error:
            raise _failure(error, connection=connection, owner=self) from None
        except BaseException as error:
            error._daily_readiness_connection = connection
            error._daily_readiness_owner = self
            raise
