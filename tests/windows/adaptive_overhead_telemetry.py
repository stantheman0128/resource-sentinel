"""Original sink observations for P4; observations grant no native authority.

The aggregate provider must transport remote observations over its original
authenticated guardian/supervisor peers. This module does not implement that
missing bridge, reconstruct owners, or accept an imported observation file.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import time

from sentinel.adaptive import telemetry as log
from sentinel.adaptive.capability_evidence import _P4_MAX_BYTES
from sentinel.adaptive.contracts import ProcessIdentity
from sentinel.adaptive.machine_sampler import _WindowsBackend


class TelemetryEvidenceError(RuntimeError):
    pass


@dataclass(frozen=True)
class NativeTelemetryObservation:
    role: str
    identity: ProcessIdentity
    instance_id: str
    scope_nonce: str
    sequence: int
    observed_tick: int
    status: dict
    offers: tuple
    writes: tuple


class NativeTelemetryProbe:
    """Runs in the original resident process and borrows its actual sink.

    No supplied serializer, clock, backend or callback can stand in for the
    production worker. Probe/ring/serialization CPU and memory are charged to
    the resident process, and bridge/reducer work is charged to the helper.
    """
    def __init__(self, host, *, scope_nonce, log_directory):
        from sentinel.adaptive.helper_control_host import OperationalHelperHost
        from sentinel.adaptive.helper_host import HelperHost
        from sentinel.adaptive.guardian_host import GuardianHost
        from sentinel.adaptive.supervisor_host import SupervisorHost
        hosts = {OperationalHelperHost: ("helper", HelperHost.emit),
                 GuardianHost: ("guardian", GuardianHost.emit),
                 SupervisorHost: ("supervisor", SupervisorHost.emit)}
        if (os.name != "nt" or type(scope_nonce) is not str
                or re.fullmatch(r"[0-9a-f]{32}", scope_nonce) is None or type(host) not in hosts or
                getattr(host.emit, "__func__", None) is not hosts[type(host)][1]):
            raise TelemetryEvidenceError("p4_original_resident_telemetry_required")
        self.host, self.sink = host, getattr(host, "telemetry", None)
        self.role, self._emit = hosts[type(host)]
        self.scope_nonce, self.sequence = scope_nonce, 0
        self.directory = Path(log_directory)
        self._clock = _WindowsBackend().tick
        self.verify()

    def verify(self):
        sink = self.sink
        native = (getattr(self.host, "process", None) if self.role == "helper" else
                  getattr(self.host, "guardian", None) if self.role == "guardian" else
                  getattr(getattr(self.host, "startup", None), "_current", None))
        instance = getattr(self.host, "_instance_id" if self.role == "supervisor" else "instance_id", None)
        if (type(sink) is not log.ResidentTelemetry or self.host.telemetry is not sink
                or getattr(self.host.emit, "__func__", None) is not self._emit
                or type(sink.store) is not log.SharedTelemetryStore
                or sink.role != self.role or sink.identity.pid != os.getpid()
                or sink.identity != getattr(native, "identity", None) or sink.instance_id != instance
                or getattr(self.host, "_telemetry_factory", None) is not None
                or sink.store.directory != self.directory
                or sink.store.policy != log._StoragePolicy()
                or sink._clock is not time.monotonic or sink.store._utc_ns is not time.time_ns
                or sink._thread is None or not sink._thread.is_alive()
                or getattr(getattr(sink._thread, "_target", None), "__self__", None) is not sink
                or getattr(getattr(sink._thread, "_target", None), "__func__", None) is not log.ResidentTelemetry._run):
            raise TelemetryEvidenceError("p4_original_resident_telemetry_required")
        for obj, cls, names in ((sink, log.ResidentTelemetry,
                ("offer", "observe", "snapshot", "_run", "_batch", "_kind", "_offer_receipt")),
                (sink.store, log.SharedTelemetryStore,
                 ("append", "inventory_observation", "_inventory", "_open", "_close"))):
            if any(getattr(getattr(obj, name), "__func__", None) is not getattr(cls, name) for name in names):
                raise TelemetryEvidenceError("p4_telemetry_source_changed")

    def read(self):
        self.verify()
        status, offers, writes = self.sink.observe()
        self.sequence += 1
        return NativeTelemetryObservation(self.role, self.sink.identity, self.sink.instance_id,
            self.scope_nonce, self.sequence, self._clock(), status, offers, writes)

    def inventory(self):
        self.verify()
        return self.sink.store.inventory_observation()


def _chunk(value):
    if (type(value) is not log.ChunkObservation or type(value.name) is not str
            or re.fullmatch(r"(aggregate|event)-[0-9]{20}-[0-9a-f]{32}\.jsonl", value.name) is None
            or value.kind not in ("aggregate", "event")):
        raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")
    _uint(value.size, minimum=1, maximum=log.MAX_CHUNK_BYTES)
    _uint(value.created_utc_ns)
    _file_identity(value.identity)
    return [value.name, value.size, value.created_utc_ns, value.kind, list(value.identity)]


def _uint(value, *, minimum=0, maximum=(1 << 63) - 1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")


def _file_identity(value):
    if type(value) is not tuple or len(value) != 2:
        raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")
    _uint(value[0], minimum=1, maximum=(1 << 64) - 1)
    _uint(value[1], minimum=1, maximum=(1 << 128) - 1)


def _encoded_size(value):
    return len(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8"))


def _failure_label(error):
    # Diagnostic recorder owns no native cleanup obligation. Never retain an
    # exception/cause/traceback: its frames can retain the rejected observation
    # and defeat the very byte bound that refused it. Caller receives the
    # original raised exception; sticky state keeps bounded primitive labels.
    if (type(error) is TelemetryEvidenceError and len(error.args) == 1
            and type(error.args[0]) is str and len(error.args[0]) <= 128
            and re.fullmatch(r"[a-z0-9_]+", error.args[0])):
        return ("TelemetryEvidenceError", error.args[0])
    return ("exception", "p4_telemetry_observation_rejected")


def _wire_offer(value):
    _uint(value.sequence, minimum=1)
    _uint(value.serialized_bytes, minimum=1, maximum=log.MAX_RECORD_BYTES)
    if (value.accepted is not True or value.outcome != "telemetry_queued"
            or value.kind not in ("aggregate", "event")):
        raise TelemetryEvidenceError("p4_telemetry_required_record_dropped")
    if value.superseded is not None:
        _uint(value.superseded, minimum=1)
    return [value.sequence, value.serialized_bytes, value.kind, value.superseded]


def _wire_write(value):
    for name in ("sequence", "first_offer", "last_offer", "utc_ns"):
        _uint(getattr(value, name), minimum=0 if name == "utc_ns" else 1)
    _uint(value.records, minimum=1, maximum=log.MAX_PENDING)
    _uint(value.written_bytes, minimum=1, maximum=log.MAX_BATCH_BYTES)
    for name in ("deleted_bytes", "before_bytes", "after_bytes"):
        _uint(getattr(value, name), maximum=log.MAX_BYTES)
    _file_identity(value.lock_identity)
    if (type(value.offers) is not tuple or not 1 <= len(value.offers) <= log.MAX_PENDING
            or value.kind not in ("aggregate", "event")
            or any(type(items) is not tuple or len(items) > 63
                   for items in (value.before_inventory, value.inventory, value.deleted))):
        raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")
    for pair in value.offers:
        if type(pair) is not tuple or len(pair) != 2:
            raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")
        _uint(pair[0], minimum=1)
        _uint(pair[1], minimum=1, maximum=log.MAX_RECORD_BYTES)
    return dict(sequence=value.sequence, offers=[list(item) for item in value.offers],
        before=[_chunk(item) for item in value.before_inventory],
        after=[_chunk(item) for item in value.inventory],
        deleted=[_chunk(item) for item in value.deleted], utc_ns=value.utc_ns,
        lock_identity=list(value.lock_identity), kind=value.kind)


_STATUS_FIELDS = frozenset(("role", "instance_id", "offered", "accepted", "persisted", "dropped",
    "coalesced", "pending_records", "written_bytes", "deleted_bytes", "inventory_bytes", "rotations",
    "error", "stopping", "stopped", "retained_files", "max_bytes", "max_age_ns"))


class CohortTelemetryTrace:
    """Bounded recorder of original receipts; gaps/refusals are failures.

    Retain startup records as well as the measured interval. The isolated
    directory must start empty; prefilled/old logging artifacts are rejected.
    Guardian/supervisor observations must be supplied by the missing aggregate
    bridge's authenticated original peers, never inferred from a PID or flag.
    """
    MAX_OFFERS = 16000
    MAX_WRITES = 2048
    MAX_TRACE_BYTES = _P4_MAX_BYTES
    # Covers three closed identities/status objects, syntax and <=63 native
    # file records at their full unsigned identity widths. Checked at finish.
    FRAME_RESERVE_BYTES = 64 * 1024

    def __init__(self, *, scope_nonce, identities):
        self.scope_nonce, self.identities = scope_nonce, dict(identities)
        if (set(self.identities) != {"helper", "guardian", "supervisor"}
                or any(type(value) is not ProcessIdentity for value in self.identities.values())
                or type(scope_nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", scope_nonce) is None):
            raise TelemetryEvidenceError("p4_telemetry_roles_incomplete")
        self.rows = {}
        self._charged_bytes = self.FRAME_RESERVE_BYTES
        self._failure = None

    def add(self, value):
        if self._failure is not None:
            raise TelemetryEvidenceError("p4_telemetry_trace_unresolved")
        try:
            self._add(value)
        except BaseException as error:
            # A partial observation is never silently dropped and later sold
            # as a complete trace, including on interruption or a byte refusal.
            self._failure = _failure_label(error)
            raise

    def _add(self, value):
        if (type(value) is not NativeTelemetryObservation or value.role not in self.identities
                or value.identity != self.identities[value.role] or value.scope_nonce != self.scope_nonce):
            raise TelemetryEvidenceError("p4_telemetry_peer_binding_invalid")
        status = value.status
        if (type(status) is not dict or set(status) != _STATUS_FIELDS or status.get("role") != value.role
                or status.get("instance_id") != value.instance_id
                or type(value.instance_id) is not str or re.fullmatch(
                    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value.instance_id) is None
                or status.get("max_bytes") != log.MAX_BYTES or status.get("max_age_ns") != log.MAX_AGE_NS
                or status.get("dropped") != 0 or status.get("error") is not None
                or type(status.get("retained_files")) is not int or not 0 <= status["retained_files"] <= 2
                or status.get("stopping") is not False
                or status.get("stopped") is not False):
            raise TelemetryEvidenceError("p4_telemetry_degraded")
        for key in _STATUS_FIELDS - {"role", "instance_id", "error", "stopping", "stopped"}:
            _uint(status[key])
        row = self.rows.get(value.role)
        if row is None:
            row = dict(instance_id=value.instance_id, identity=value.identity.to_dict(),
                       sequence=0, observed_tick=-1, offers={}, writes={})
            self.rows[value.role] = row
        if (row["instance_id"] != value.instance_id or type(value.sequence) is not int
                or value.sequence <= row["sequence"] or type(value.observed_tick) is not int
                or value.observed_tick <= row["observed_tick"]):
            raise TelemetryEvidenceError("p4_telemetry_observation_replayed")
        for records, kind, cls, maximum in ((value.offers, "offers", log.EmitReceipt, self.MAX_OFFERS),
                (value.writes, "writes", log.WriteReceipt, self.MAX_WRITES)):
            if type(records) is not tuple or len(records) > 128:
                raise TelemetryEvidenceError("p4_telemetry_ring_invalid")
            known = row[kind]
            for record in records:
                if type(record) is not cls or type(record.sequence) is not int:
                    raise TelemetryEvidenceError("p4_telemetry_ring_invalid")
                if kind == "offers" and record.instance_id != value.instance_id:
                    raise TelemetryEvidenceError("p4_telemetry_peer_binding_invalid")
                if record.sequence in known:
                    if known[record.sequence] != record:
                        raise TelemetryEvidenceError("p4_telemetry_receipt_changed")
                elif record.sequence != len(known) + 1 or len(known) >= maximum:
                    raise TelemetryEvidenceError("p4_telemetry_ring_coverage_lost")
                else:
                    # Serialize only a genuinely new bounded receipt. Existing
                    # ring entries neither rescan history nor consume new bytes.
                    wire = _wire_offer(record) if kind == "offers" else _wire_write(record)
                    charge = _encoded_size(wire) + 1  # conservative list delimiter
                    if self._charged_bytes + charge > self.MAX_TRACE_BYTES:
                        raise TelemetryEvidenceError("p4_telemetry_trace_byte_bound")
                    self._charged_bytes += charge
                    known[record.sequence] = record
        if len(row["offers"]) != status.get("offered"):
            raise TelemetryEvidenceError("p4_telemetry_ring_coverage_lost")
        row.update(sequence=value.sequence, observed_tick=value.observed_tick, status=dict(status))

    def finish(self, lock_identity, inventory):
        if self._failure is not None:
            raise TelemetryEvidenceError("p4_telemetry_trace_unresolved")
        try:
            return self._finish(lock_identity, inventory)
        except BaseException as error:
            self._failure = _failure_label(error)
            raise

    def _finish(self, lock_identity, inventory):
        _file_identity(lock_identity)
        if type(inventory) is not tuple or len(inventory) > 63:
            raise TelemetryEvidenceError("p4_telemetry_receipt_invalid")
        if set(self.rows) != set(self.identities):
            raise TelemetryEvidenceError("p4_telemetry_roles_incomplete")
        sinks = []
        for role in sorted(self.rows):
            row = self.rows[role]
            offers = []
            for value in row["offers"].values():
                if not value.accepted or value.instance_id != row["instance_id"]:
                    raise TelemetryEvidenceError("p4_telemetry_required_record_dropped")
                offers.append(_wire_offer(value))
            writes = [_wire_write(value) for value in row["writes"].values()]
            sinks.append(dict(role=role, identity=row["identity"], instance_id=row["instance_id"],
                status=row["status"], offers=offers, writes=writes))
        result = dict(schema_version=1, scope_nonce=self.scope_nonce, max_bytes=log.MAX_BYTES,
            max_age_ns=log.MAX_AGE_NS, lock_identity=list(lock_identity),
            final_inventory=[_chunk(item) for item in inventory], sinks=sinks)
        framing = {**result, "sinks": [{**sink, "offers": [], "writes": []} for sink in sinks]}
        if (_encoded_size(framing) > self.FRAME_RESERVE_BYTES
                or _encoded_size(result) > self._charged_bytes):
            raise TelemetryEvidenceError("p4_telemetry_trace_byte_bound")
        return result
