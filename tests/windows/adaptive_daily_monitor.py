"""Authenticated daily-owner cost witness for the still incomplete P4 bridge.

This owns only duplicated query handles. It grants no capacity, readiness,
launch, control or retirement authority. A successful short readiness RPC is
not extended: its separate long-lived duplicate identifies the process whose
cost must be charged. All later admission checks remain the provider's job.
"""
from __future__ import annotations

import json
import os
import threading
import weakref
from dataclasses import dataclass

from sentinel.adaptive import daily_generation as generation
from sentinel.adaptive.daily_readiness_transport import (
    DailyReadinessAuthority, DailyReadinessClient, LedgerFileIdentity, _binding,
)
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.experiment_demand import DailyExperimentDemand
from sentinel.adaptive.identity import (
    VerifiedProcess, _DuplicateCleanup, _TransferDuplicate, _known_close_failure,
)
from sentinel.adaptive.pipe_windows import NativePipeConnection, NativePipeEndpoint
from sentinel.adaptive.windows import current_thread_holds_mutex


_KEY = object()
_CLOSED = object()
_ORIGINALS = weakref.WeakKeyDictionary()
_OUTCOMES = weakref.WeakKeyDictionary()
_SETTLED = weakref.WeakSet()
_NATIVE_STATES = weakref.WeakKeyDictionary()
_CAPTURED = weakref.WeakKeyDictionary()
_PENDING = {}


class DailyMonitorError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = "p4_daily_monitor_" + reason, owner
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise DailyMonitorError(reason, owner)


def _graph(error):
    pending, seen, result = [error], set(), []
    while pending:
        value = pending.pop()
        if value is None or id(value) in seen:
            continue
        if not isinstance(value, BaseException) or len(seen) >= 32:
            _fail("error_graph_unverified")
        seen.add(id(value))
        result.append(value)
        # Only the fixed client's explicit ownership links authorize cleanup.
        # Python exception context/cause can belong to an unrelated outer
        # operation; it remains reachable on the error but is never acted on.
        pending.extend(getattr(value, name, None) for name in (
            "_daily_readiness_cause", "_daily_readiness_authority_cleanup"))
    return tuple(result)


def _closed_process(owner):
    return (type(owner) in {VerifiedProcess, _DuplicateCleanup, _TransferDuplicate} and
            owner._handle is None and owner._close_outcome_unknown is False and
            getattr(owner, "_duplicate_outcome_unknown", False) is False)


@dataclass(frozen=True, eq=False)
class _NativePin:
    owner: object
    backend: object
    lock: object
    handle: object
    identity: object
    output: object
    output_value: object


@dataclass(frozen=True, eq=False)
class _CaptureOutcome:
    client: object
    authority: object
    authority_pin: object
    witness: object
    error: object
    connection: object
    connection_owner: object
    error_owners: tuple
    flags: tuple
    retention_error: object
    native_pins: tuple


def _record_outcome(owner):
    """Only the original factory publishes acquisition results, never a retry."""
    pins, states, seen = [], {}, set()
    originals = [owner._witness, None if owner._authority is None else owner._authority._peer]
    originals.extend(item for unused, values in owner._error_owners for item in values)
    for original in originals:
        if original is None or id(original) in seen:
            continue
        if type(original) not in {VerifiedProcess, _DuplicateCleanup, _TransferDuplicate}:
            _fail("native_custody_unverified", owner)
        seen.add(id(original))
        output = getattr(original, "_output", None)
        pins.append(_NativePin(original, original._backend, original._lock, original._handle,
            getattr(original, "_identity", None), output, None if output is None else output.value))
        states[id(original)] = ("closed" if _closed_process(original) else "unknown"
            if original._close_outcome_unknown or getattr(original, "_duplicate_outcome_unknown", False)
            else "retained")
    _OUTCOMES[owner] = _CaptureOutcome(owner._client, owner._authority, owner._authority_pin,
        owner._witness, owner._error, owner._error_connection, owner._error_connection_owner,
        owner._error_owners, (owner._rpc_started, owner._rpc_returned, owner._duplicate_started,
            owner._duplicate_returned, owner._duplicate_known_failure, owner._duplicate_cleanup_observed),
        owner._retention_error, tuple(pins))
    _NATIVE_STATES[owner] = states


class DailyMonitorWitness:
    def __init__(self, demand, row, *, _key=None):
        if _key is not _KEY:
            _fail("capture_required")
        self.demand, self._generation = demand, demand._generation_original
        self._caller = demand._admission._process
        identity = ProcessIdentity.from_dict(json.loads(row["owner_identity_json"]))
        self.endpoint = NativePipeEndpoint(identity.logon_id, row["readiness_instance_id"], identity)
        self._binding = _binding(row["generation"], row["source_digest"], row["config_digest"],
            LedgerFileIdentity(*(int(value) for value in json.loads(row["ledger_identity_json"]))))
        self._binding_json = json.dumps(self._binding, sort_keys=True, separators=(",", ":"))
        self.identity = identity
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._authority = self._authority_pin = self._witness = self._witness_pin = None
        self._client = self._client_pin = None
        self._rpc_started = self._rpc_returned = False
        self._duplicate_started = self._duplicate_returned = False
        self._issued = self._stopping = self._closed = False
        self._error = self._cleanup_error = None
        self._error_owners = ()
        self._error_connection = self._error_connection_owner = None
        self._retention_error = None
        self._duplicate_known_failure = False
        self._duplicate_cleanup_observed = False
        _ORIGINALS[self] = (demand, demand._admission, demand._snapshot, self._caller,
            self.endpoint, self._generation, self._binding_json, identity, self._thread, self._pid)

    @classmethod
    def capture(cls, demand):
        if cls is not DailyMonitorWitness or type(demand) is not DailyExperimentDemand:
            _fail("original_demand_required")
        demand._original()
        demand._assert_unused_claim()
        if (demand._policy_original is None or demand._native_preparation is not None or
                demand._native_preparation_sealed or demand.declaration.suite not in {"S2", "P4"}):
            _fail("before_fixture_capture_required")
        if demand in _CAPTURED:
            _fail("original_capture_already_exists", _PENDING.get(id(demand)))
        if current_thread_holds_mutex():
            _fail("lock_held")
        row = demand._original_generation_binding()
        generation.verify_import_provenance(
            generation.SourceManifest.from_dict(json.loads(row["source_manifest_json"])), row["source_root"])
        if type(demand._admission._process) is not VerifiedProcess:
            _fail("original_caller_required")
        owner = cls(demand, row, _key=_KEY)
        # Retain before the first RPC/duplicate acquisition. Errors always point
        # back to this original; a second capture is never a cleanup operation.
        _CAPTURED[demand], _PENDING[id(demand)] = weakref.ref(owner), owner
        try:
            owner._client = DailyReadinessClient(owner.endpoint, owner._caller)
            owner._client_pin = owner._client
            owner._rpc_started = True
            owner._authority = owner._client.acquire_ready(row["generation"], row["source_digest"],
                row["config_digest"], LedgerFileIdentity(*(int(value) for value in
                    json.loads(row["ledger_identity_json"]))), timeout_ms=1000)
            owner._rpc_returned = True
            owner._pin_authority()
            owner._authority.revalidate(owner.endpoint, owner._binding)
            owner._duplicate_started = True
            owner._witness = owner._authority._peer.duplicate()
            owner._witness_pin = owner._witness
            owner._duplicate_returned = True
            owner._authority.revalidate(owner.endpoint, owner._binding)
            owner._authority.close()
            if owner._authority._closed is not True or owner._authority._close_unknown:
                _fail("authority_cleanup_unverified", owner)
            owner._issued = True
            _record_outcome(owner)
            owner.assert_original()
            return owner
        except BaseException as error:
            owner._error = error
            error.daily_monitor_owner = owner
            try:
                if owner._authority is None:
                    partial = getattr(error, "_daily_readiness_authority", None)
                    if type(partial) is DailyReadinessAuthority:
                        owner._authority = partial
                        owner._pin_authority()
                owner._error_connection = getattr(error, "_daily_readiness_connection", None)
                owner._error_connection_owner = getattr(owner._error_connection, "_owner", None)
                nodes = _graph(error)
                entries = []
                for value in nodes:
                    originals = getattr(value, "_identity_handle_cleanup", ())
                    if (type(originals) is not tuple or any(type(item) not in
                            {VerifiedProcess, _DuplicateCleanup, _TransferDuplicate} for item in originals)):
                        _fail("cleanup_owner_changed", owner)
                    # Keep the owners independently of mutable exception attrs.
                    entries.append((value, originals))
                owner._error_owners = tuple(entries)
                owner._duplicate_cleanup_observed = any(originals for unused, originals in entries)
                owner._duplicate_known_failure = (
                    getattr(error, "_native_duplicate_failed", False) is True and
                    getattr(error, "_native_duplicate_outcome_unknown", False) is not True)
            except BaseException as retention_error:
                # Neither a malformed graph nor interrupted bookkeeping may
                # replace the original acquisition error or authorize release.
                owner._retention_error = retention_error
            try:
                _record_outcome(owner)
            except BaseException as retention_error:
                owner._retention_error = retention_error
            raise

    def __reduce__(self):
        raise TypeError("p4_daily_monitor_not_serializable")

    def _pin_authority(self):
        value = self._authority
        if (type(value) is not DailyReadinessAuthority or value._endpoint != self.endpoint or
                value._binding != self._binding or value._thread is not self._thread or value._pid != self._pid):
            _fail("original_authority_required", self)
        self._authority_pin = (value, value._peer, value._deadline)

    def _original(self):
        pinned = _ORIGINALS.get(self) if type(self) is DailyMonitorWitness else None
        if pinned is None:
            _fail("original_owner_required", self)
        marker = _CAPTURED.get(self.demand)
        original_marker = isinstance(marker, weakref.ReferenceType) and marker() is self
        settled = self in _SETTLED
        if ((settled and (marker is not _CLOSED and not original_marker or
                _PENDING.get(id(self.demand)) not in (None, self))) or
                (not settled and (self._closed or not original_marker or
                    _PENDING.get(id(self.demand)) is not self))):
            _fail("original_capture_changed", self)
        current = (self.demand, self.demand._admission, self.demand._snapshot, self._caller,
            self.endpoint, self._generation, self._binding_json, self.identity, self._thread, self._pid)
        if (any(a is not b for a, b in zip(current[:5], pinned[:5])) or current[5:] != pinned[5:] or
                threading.current_thread() is not self._thread or os.getpid() != self._pid or
                self.demand._generation_original != self._generation or
                self.demand._admission._process is not self._caller or
                json.dumps(self._binding, sort_keys=True, separators=(",", ":")) != self._binding_json or
                self._client is not self._client_pin or self._witness is not self._witness_pin):
            _fail("original_binding_changed", self)
        if self._authority_pin is not None and (
                self._authority is not self._authority_pin[0] or
                self._authority._peer is not self._authority_pin[1] or
                self._authority._deadline is not self._authority_pin[2]):
            _fail("original_authority_changed", self)
        outcome = _OUTCOMES.get(self)
        if outcome is None:
            _fail("capture_outcome_unverified", self)
        if (self._client is not outcome.client or self._authority is not outcome.authority or
                self._authority_pin is not outcome.authority_pin or self._witness is not outcome.witness or
                self._error is not outcome.error or self._error_connection is not outcome.connection or
                self._error_connection_owner is not outcome.connection_owner or
                self._error_owners is not outcome.error_owners or self._retention_error is not outcome.retention_error or
                any(type(value) is not bool for value in outcome.flags) or
                any(type(value) is not bool for value in (self._rpc_started, self._rpc_returned,
                    self._duplicate_started, self._duplicate_returned, self._duplicate_known_failure,
                    self._duplicate_cleanup_observed, self._issued, self._stopping, self._closed)) or
                (self._rpc_started, self._rpc_returned, self._duplicate_started, self._duplicate_returned,
                    self._duplicate_known_failure, self._duplicate_cleanup_observed) != outcome.flags):
            _fail("original_outcome_changed", self)
        if outcome.error is not None and {id(value) for value in _graph(outcome.error)} != {
                id(value) for value, unused in outcome.error_owners}:
            _fail("original_error_graph_changed", self)
        for error, originals in outcome.error_owners:
            current = getattr(error, "_identity_handle_cleanup", ())
            if (type(current) is not tuple or
                    any(not any(value is original for original in originals) for value in current) or
                    any(not any(value is original for value in current) and not _closed_process(original)
                        for original in originals)):
                _fail("cleanup_owner_changed", self)
        if self not in _NATIVE_STATES:
            _fail("native_custody_unverified", self)
        for pin in outcome.native_pins:
            self._verify_native(pin)
        if settled:
            self._assert_handles_closed(outcome)
        return outcome

    def _verify_native(self, pin):
        original = pin.owner
        if (original._backend is not pin.backend or original._lock is not pin.lock or
                getattr(original, "_identity", None) is not pin.identity or
                getattr(original, "_output", None) is not pin.output or
                pin.output is not None and pin.output.value != pin.output_value):
            _fail("original_native_custody_changed", self)
        state = _NATIVE_STATES[self][id(original)]
        if state == "closed":
            if not _closed_process(original):
                _fail("original_native_custody_changed", self)
        elif original._handle != pin.handle or type(original._handle) is not type(pin.handle):
            _fail("original_native_custody_changed", self)
        elif state == "unknown" and not (original._close_outcome_unknown or
                getattr(original, "_duplicate_outcome_unknown", False)):
            _fail("native_cleanup_unverified", self)
        elif state not in {"retained", "unknown"}:
            _fail("native_cleanup_unverified", self)
        return state

    def _close_native(self, pin, *, authority=False):
        state = self._verify_native(pin)
        if state == "closed" and not authority:
            return
        _NATIVE_STATES[self][id(pin.owner)] = "closing"
        try:
            if authority:
                self._authority.close()
            else:
                pin.owner.close()
        except BaseException as error:
            if _closed_process(pin.owner):
                # The original native owner's positive close survived an
                # interruption in subsequent local acknowledgement code.
                _NATIVE_STATES[self][id(pin.owner)] = "closed"
            elif (_known_close_failure(error) and pin.owner._handle == pin.handle and
                    pin.owner._close_outcome_unknown is False and
                    not getattr(pin.owner, "_duplicate_outcome_unknown", False)):
                _NATIVE_STATES[self][id(pin.owner)] = "retained"
            else:
                _NATIVE_STATES[self][id(pin.owner)] = "unknown"
            raise
        if not _closed_process(pin.owner):
            _NATIVE_STATES[self][id(pin.owner)] = "unknown"
            _fail("native_cleanup_unverified", self)
        _NATIVE_STATES[self][id(pin.owner)] = "closed"

    def _assert_handles_closed(self, outcome):
        for pin in outcome.native_pins:
            self._verify_native(pin)
        if outcome.witness is not None and not _closed_process(outcome.witness):
            _fail("witness_cleanup_unverified", self)
        if outcome.authority is not None and (
                outcome.authority._closed is not True or outcome.authority._close_unknown is not False or
                outcome.authority._peer is not None and not _closed_process(outcome.authority._peer)):
            _fail("authority_cleanup_unverified", self)
        if any(not _closed_process(original) for unused, originals in outcome.error_owners for original in originals):
            _fail("cleanup_owner_unsettled", self)
        self._assert_rpc_closed()

    def _assert_rpc_closed(self):
        if not self._rpc_started or self._rpc_returned:
            return
        # A thrown call is not an absence receipt. Only the originally retained
        # actual native client can acknowledge this failed acquisition boundary.
        connection = self._error_connection
        if (getattr(self._error, "_daily_readiness_connection", None) is not connection or
                type(connection) is not NativePipeConnection or
                connection._owner is not self._error_connection_owner or connection._closed is not True or
                connection._owner._handle is not None or connection._owner._handle_close_unknown or
                connection._owner._proofs or connection._owner._busy or
                any(getattr(connection._owner, name, None) is not None for name in
                    ("_operation", "_active", "_server_process", "_self_process", "_peer_process",
                     "_accept_connection", "_accept_operation"))):
            _fail("rpc_custody_unsettled", self)

    def _close_original_rpc(self):
        if not self._rpc_started or self._rpc_returned:
            return
        connection = self._error_connection
        if (getattr(self._error, "_daily_readiness_connection", None) is not connection or
                type(connection) is not NativePipeConnection or
                connection._owner is not self._error_connection_owner):
            _fail("rpc_custody_unsettled", self)
        # The transport's own original close enforces pending-I/O and unknown
        # native-close fences. A known FALSE may retry; connect is never called.
        connection.close()
        self._assert_rpc_closed()

    def _finish_local(self):
        # _SETTLED was recorded only after every original handle closed
        # positively. An interrupted local update retries no native operation.
        self._closed = True
        _CAPTURED[self.demand] = _CLOSED
        _PENDING.pop(id(self.demand), None)

    def assert_original(self):
        """Return only the original live COST witness; no readiness renewal."""
        self._original()
        if (not self._issued or self._error is not None or self._stopping or self._closed or
                not self._rpc_returned or not self._duplicate_returned or
                type(self._witness) is not VerifiedProcess or self._authority is None or
                self._authority._closed is not True or self._authority._close_unknown):
            _fail("witness_unavailable", self)
        self.demand._original()
        observed = self._witness.observe()
        if observed.identity != self.identity or observed.status is not IdentityStatus.ALIVE:
            _fail("identity_unverified", self)
        return self._witness

    @property
    def custody_pending(self):
        self._original()
        return not (self in _SETTLED and self._closed and _CAPTURED.get(self.demand) is _CLOSED and
                    _PENDING.get(id(self.demand)) is None)

    def close(self):
        """Settle these exact originals; never release demand or reacquire RPC."""
        outcome = self._original()
        if self in _SETTLED:
            self._finish_local()
            return
        self._stopping, self._issued = True, False
        try:
            if self._retention_error is not None:
                _fail("failure_custody_unverified", self)
            pins = {id(pin.owner): pin for pin in outcome.native_pins}
            if self._witness is not None:
                self._close_native(pins[id(self._witness)])
            if self._authority is not None:
                if self._authority._peer is None:
                    self._authority.close()
                else:
                    self._close_native(pins[id(self._authority._peer)], authority=True)
            settled = set()
            for unused_error, originals in outcome.error_owners:
                for original in originals:
                    if id(original) not in settled:
                        # Error attributes cannot replace or erase this owner.
                        # Native unknown flags remain sticky on its own close.
                        self._close_native(pins[id(original)])
                        if not _closed_process(original):
                            _fail("cleanup_owner_unsettled", self)
                        settled.add(id(original))
            self._close_original_rpc()
            if (self._duplicate_started and not self._duplicate_returned and
                    not self._duplicate_known_failure and not self._duplicate_cleanup_observed):
                _fail("duplicate_custody_unsettled", self)
            self._assert_handles_closed(outcome)
            _SETTLED.add(self)
            self._finish_local()
        except BaseException as error:
            if self._cleanup_error is None:
                self._cleanup_error = error
            error.daily_monitor_owner = self
            raise
