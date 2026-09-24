"""Shared bounded resident diagnostics, independent of control/audit durability.

Only this fixed directory's closed-schema chunks are rotated. Recovery manifests,
SQLite/WAL, workload stdio and producer evidence are never visited. File I/O runs
on a bounded per-host worker; a stalled/full diagnostic disk cannot block restore.
No diagnostic receipt supplies launch, mutation, accounting or durability rights.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum
import errno
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
from uuid import UUID, uuid4

from .contracts import ProcessIdentity

MAX_BYTES = 20 * 1024 * 1024
MAX_AGE_NS = 7 * 24 * 60 * 60 * 1_000_000_000
MAX_RECORD_BYTES = 16 * 1024
MAX_PENDING = 128
MAX_CHUNK_BYTES = 512 * 1024
MAX_FILES = 64
MAX_BATCH_BYTES = 64 * 1024
AGGREGATE_SECONDS = 30
_CHUNK = re.compile(r"(aggregate|event)-([0-9]{20})-([0-9a-f]{32})\.jsonl\Z")
_ROLES = {"helper", "guardian", "supervisor"}
_ITERATIONS = {"guardian_host_iteration", "supervisor_host_iteration"}


def _bounded_record(record):
    """Bound traversal/serialization before allocating a potentially large JSON."""
    pending, visited, characters = [(record, 0)], 0, 0
    while pending:
        value, depth = pending.pop()
        visited += 1
        if visited > 2048 or depth > 12:
            return False
        if type(value) is str:
            characters += len(value)
            if len(value) > MAX_RECORD_BYTES or characters > MAX_RECORD_BYTES:
                return False
        elif type(value) is dict:
            if len(value) > 128 or any(type(key) is not str or len(key) > 128 for key in value):
                return False
            pending.extend((item, depth + 1) for pair in value.items() for item in pair)
        elif type(value) in (list, tuple):
            if len(value) > 256:
                return False
            pending.extend((item, depth + 1) for item in value)
        elif value is not None and type(value) not in (bool, int, float):
            return False
        elif type(value) is int and value.bit_length() > 128:
            return False
    return True


class TelemetryError(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class TelemetryBusy(TelemetryError):
    pass


class TelemetryKind(str, Enum):
    AGGREGATE = "aggregate"
    EVENT = "event"


@dataclass(frozen=True)
class _StoragePolicy:
    """Smaller explicit filesystem fixtures are allowed; production uses default.

    This private in-process seam cannot increase the formal byte/age bounds.
    No CLI/config/environment setting selects it.
    """
    max_bytes: int = MAX_BYTES
    max_age_ns: int = MAX_AGE_NS
    chunk_bytes: int = MAX_CHUNK_BYTES
    max_files: int = MAX_FILES

    def __post_init__(self):
        for value, lower, upper in ((self.max_bytes, 64, MAX_BYTES),
                (self.max_age_ns, 1, MAX_AGE_NS), (self.chunk_bytes, 32, MAX_CHUNK_BYTES),
                (self.max_files, 2, MAX_FILES)):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError("telemetry_policy_invalid")


@dataclass(frozen=True)
class EmitReceipt:
    instance_id: str
    sequence: int
    accepted: bool
    serialized_bytes: int
    outcome: str


@dataclass(frozen=True)
class ChunkObservation:
    name: str
    size: int
    created_utc_ns: int
    kind: str
    identity: tuple


@dataclass(frozen=True)
class WriteReceipt:
    sequence: int
    first_offer: int
    last_offer: int
    records: int
    written_bytes: int
    deleted_bytes: int
    before_bytes: int
    after_bytes: int
    deleted: tuple[ChunkObservation, ...]
    inventory: tuple[ChunkObservation, ...]
    utc_ns: int


class _FileOwner:
    """One ordinary noninheritable fd; ambiguous close is never repeated."""
    def __init__(self):
        self.fd = None
        self.acquire_uncertain = False
        self.acquire_error = None
        self.close_uncertain = False

    def acquire(self, path, flags):
        if self.fd is not None or self.acquire_uncertain or self.close_uncertain:
            raise TelemetryError("telemetry_file_acquisition_unresolved")
        self.acquire_uncertain = True
        try:
            self.fd = os.open(path, flags | getattr(os, "O_BINARY", 0) |
                              getattr(os, "O_NOFOLLOW", 0), 0o600)
        except OSError:
            self.acquire_uncertain = False  # a known syscall failure acquired no fd
            raise
        except BaseException as error:
            self.acquire_error = error
            raise
        self.acquire_uncertain = False
        os.set_inheritable(self.fd, False)

    def close(self):
        if self.close_uncertain or self.acquire_uncertain:
            raise TelemetryError("telemetry_file_cleanup_unknown")
        if self.fd is None:
            return
        self.close_uncertain = True
        os.close(self.fd)
        self.fd = None
        self.close_uncertain = False


def _safe_info(path, *, directory=False):
    value = os.lstat(path)
    if (stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400 or
            (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode)) or
            (not directory and value.st_nlink != 1)):
        raise TelemetryError("telemetry_path_unsafe")
    return value


def _identity(value):
    return value.st_dev, value.st_ino


class SharedTelemetryStore:
    """One shared quota, serialized by a nonblocking lock file per directory."""
    def __init__(self, data_dir, *, excluded_paths=(), policy=None, utc_ns=time.time_ns):
        self.data_dir = Path(data_dir)
        if (not self.data_dir.is_absolute() or ".." in self.data_dir.parts or
                len(self.data_dir.parts) > 128 or len(str(self.data_dir)) > 32000):
            raise TelemetryError("telemetry_directory_invalid")
        self.directory = self.data_dir / "adaptive-telemetry"
        self.excluded_paths = tuple(Path(item) for item in excluded_paths)
        self.policy = _StoragePolicy() if policy is None else policy
        if type(self.policy) is not _StoragePolicy:
            raise TelemetryError("telemetry_policy_invalid")
        self._utc_ns = utc_ns
        self._paths = tuple(reversed(self.directory.parents)) + (self.directory,)
        self._directory_ids = None
        self._owners = []
        self._quarantined = False
        self._quarantine_error = None
        self._last_utc = None
        self._write_sequence = 0

    @property
    def retained_files(self):
        return len(self._owners)

    def _check_directories(self):
        observed = tuple(_identity(_safe_info(path, directory=True)) for path in self._paths)
        if self._directory_ids is not None and observed != self._directory_ids:
            raise TelemetryError("telemetry_directory_changed")
        return observed

    def start(self):
        # Inspect ancestors before mkdir, never resolve through a reparse point.
        for path in self._paths[:-1]:
            _safe_info(path, directory=True)
        for excluded in self.excluded_paths:
            if not excluded.is_absolute() or (excluded == self.directory or
                    self.directory in excluded.parents or excluded in self.directory.parents):
                raise TelemetryError("telemetry_recovery_directory_overlap")
        try:
            self.directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        self._directory_ids = self._check_directories()

    def _verify_open(self, owner, path, expected=None):
        self._check_directories()
        opened = os.fstat(owner.fd)
        current = _safe_info(path)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                getattr(opened, "st_file_attributes", 0) & 0x400 or
                (_identity(opened), opened.st_size) != (_identity(current), current.st_size) or
                expected is not None and (_identity(current), current.st_size) !=
                    (_identity(expected), expected.st_size)):
            raise TelemetryError("telemetry_file_changed")
        return current

    def _open(self, path, flags, expected=None):
        owner = _FileOwner()
        self._owners.append(owner)  # retained before opening the descriptor
        try:
            owner.acquire(path, flags)
            self._verify_open(owner, path, expected)
        except BaseException as error:
            if owner.acquire_uncertain:
                self._quarantined = True
                self._quarantine_error = error
            elif owner.fd is None:
                self._owners.remove(owner)
            else:
                # The fd is ours even if its path was replaced. Closing that
                # exact fd once is safe; never write through an unverified leaf.
                self._close(owner)
            raise
        return owner

    def _close(self, owner):
        try:
            owner.close()
        except BaseException as error:
            self._quarantined = True
            self._quarantine_error = error
            raise
        else:
            self._owners.remove(owner)

    @staticmethod
    def _lock(fd, acquire):
        os.lseek(fd, 0, os.SEEK_SET)
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK if acquire else msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, (fcntl.LOCK_EX | fcntl.LOCK_NB) if acquire else fcntl.LOCK_UN)

    def _acquire_lock(self):
        if self._quarantined:
            raise TelemetryError("telemetry_file_cleanup_unknown")
        self._check_directories()
        path = self.directory / "telemetry.lock"
        try:
            owner = self._open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)
        except FileExistsError:
            value = _safe_info(path)
            if value.st_size == 0:
                raise TelemetryBusy("telemetry_lock_initializing")
            if value.st_size != 1:
                raise TelemetryError("telemetry_lock_invalid")
            owner = self._open(path, os.O_RDWR, value)
        else:
            try:
                if os.write(owner.fd, b"\0") != 1:
                    raise TelemetryError("telemetry_lock_write_incomplete")
            except BaseException:
                self._close(owner)
                raise
        try:
            self._lock(owner.fd, True)
        except OSError as error:
            self._close(owner)
            if error.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise TelemetryBusy("telemetry_store_busy") from None
            raise
        except BaseException as error:
            self._quarantined = True
            self._quarantine_error = error
            # The original descriptor may hold the lock. Do not re-acquire,
            # unlock or close after an unknown acquisition outcome.
            raise
        try:
            self._verify_open(owner, path)
        except BaseException:
            self._unlock_close(owner)
            raise
        return owner

    def _inventory(self):
        self._check_directories()
        chunks = []
        count = 0
        with os.scandir(self.directory) as entries:
            for entry in entries:
                count += 1
                if count > self.policy.max_files:
                    raise TelemetryError("telemetry_inventory_bound")
                value = _safe_info(Path(entry.path))
                if entry.name == "telemetry.lock":
                    if value.st_size != 1:
                        raise TelemetryError("telemetry_lock_invalid")
                    continue
                match = _CHUNK.fullmatch(entry.name)
                if match is None or not 0 < value.st_size <= self.policy.chunk_bytes:
                    raise TelemetryError("telemetry_inventory_unknown")
                owner = self._open(Path(entry.path), os.O_RDONLY, value)
                try:
                    os.lseek(owner.fd, -1, os.SEEK_END)
                    if os.read(owner.fd, 1) != b"\n":
                        raise TelemetryError("telemetry_partial_record")
                finally:
                    self._close(owner)
                if _identity(_safe_info(Path(entry.path))) != _identity(value):
                    raise TelemetryError("telemetry_file_changed")
                chunks.append(ChunkObservation(entry.name, value.st_size,
                    int(match[2]), match[1], _identity(value)))
        return tuple(chunks)

    def inventory(self):
        lock = self._acquire_lock()
        try:
            return self._inventory()
        finally:
            self._unlock_close(lock)

    def _unlock_close(self, lock):
        try:
            self._lock(lock.fd, False)
        except BaseException as error:
            self._quarantined = True
            self._quarantine_error = error
            # Retain the fd/possibly-held lock; never infer unlock completion.
            raise
        self._close(lock)

    def append(self, kind, records):
        """records contains (offer sequence, complete UTF-8 JSON line) pairs."""
        if type(kind) is not TelemetryKind or not records or len(records) > MAX_PENDING:
            raise TelemetryError("telemetry_batch_invalid")
        if any(type(seq) is not int or seq <= 0 or type(line) is not bytes or
               not line.endswith(b"\n") or len(line) > MAX_RECORD_BYTES for seq, line in records):
            raise TelemetryError("telemetry_batch_invalid")
        payload = b"".join(line for _, line in records)
        if len(payload) > min(MAX_BATCH_BYTES, self.policy.chunk_bytes, self.policy.max_bytes - 1):
            raise TelemetryError("telemetry_batch_too_large")
        lock = self._acquire_lock()
        try:
            now = self._utc_ns()
            if type(now) is not int or not 0 <= now < 10 ** 20:
                raise TelemetryError("telemetry_utc_unknown")
            if self._last_utc is not None and now < self._last_utc:
                raise TelemetryError("telemetry_utc_regressed")
            self._last_utc = now
            chunks = list(self._inventory())
            if any(item.created_utc_ns > now for item in chunks):
                raise TelemetryError("telemetry_utc_regressed")
            before = 1 + sum(item.size for item in chunks)
            if before > self.policy.max_bytes:
                # Reconcile only recognized prior telemetry, never append over
                # quota or pretend an externally oversized state was compliant.
                raise TelemetryError("telemetry_existing_quota_exceeded")
            deleted = []
            expired = sorted((item for item in chunks if item.created_utc_ns < now - self.policy.max_age_ns),
                             key=lambda item: (item.created_utc_ns, item.name))
            def remove(item):
                self._check_directories()
                path = self.directory / item.name
                current = _safe_info(path)
                if _identity(current) != item.identity or current.st_size != item.size:
                    raise TelemetryError("telemetry_file_changed")
                os.unlink(path)  # one exact validated telemetry chunk only
                chunks.remove(item)
                deleted.append(item)
            for item in expired:
                remove(item)
            def target():
                eligible = [item for item in chunks if item.kind == kind.value and
                            item.size + len(payload) <= self.policy.chunk_bytes]
                return max(eligible, key=lambda item: (item.created_utc_ns, item.name), default=None)
            while (1 + sum(item.size for item in chunks) + len(payload) > self.policy.max_bytes or
                   target() is None and len(chunks) + 2 > self.policy.max_files):
                if not chunks:
                    raise TelemetryError("telemetry_quota_unavailable")
                remove(min(chunks, key=lambda item: (item.kind != "aggregate", item.created_utc_ns, item.name)))
            chosen = target()
            path = self.directory / (chosen.name if chosen else
                f"{kind.value}-{now:020d}-{uuid4().hex}.jsonl")
            self._check_directories()
            flags = os.O_WRONLY | (os.O_APPEND if chosen else os.O_CREAT | os.O_EXCL)
            if chosen is not None:
                info = _safe_info(path)
                if _identity(info) != chosen.identity or info.st_size != chosen.size:
                    raise TelemetryError("telemetry_file_changed")
            owner = self._open(path, flags, info if chosen is not None else None)
            try:
                self._verify_open(owner, path, info if chosen is not None else None)
                # A short write is failure. Never append a guessed remainder or
                # truncate history to conceal an uncertain record boundary.
                if os.write(owner.fd, payload) != len(payload):
                    raise TelemetryError("telemetry_write_incomplete")
            finally:
                self._close(owner)
            after_inventory = self._inventory()
            after = 1 + sum(item.size for item in after_inventory)
            removed = sum(item.size for item in deleted)
            if after != before + len(payload) - removed or after > self.policy.max_bytes:
                raise TelemetryError("telemetry_byte_conservation_failed")
            self._write_sequence += 1
            return WriteReceipt(self._write_sequence, records[0][0], records[-1][0], len(records),
                len(payload), removed, before, after, tuple(deleted), after_inventory, now)
        finally:
            self._unlock_close(lock)


class ResidentTelemetry:
    """One exact host's bounded asynchronous producer and retained file worker."""
    def __init__(self, *, data_dir, role, identity, instance_id, excluded_paths=(),
                 store_factory=SharedTelemetryStore, monotonic=time.monotonic):
        if role not in _ROLES or type(identity) is not ProcessIdentity:
            raise TelemetryError("telemetry_host_identity_invalid")
        if str(UUID(instance_id)) != instance_id:
            raise TelemetryError("telemetry_instance_invalid")
        self.role, self.identity, self.instance_id = role, identity, instance_id
        self.store = store_factory(data_dir, excluded_paths=excluded_paths)
        self._clock = monotonic
        self._condition = threading.Condition()
        self._events = deque()
        self._aggregate = None
        self._thread = None
        self._stop = self._done = False
        self._sequence = self._accepted = self._persisted = self._dropped = self._coalesced = 0
        self._written = self._deleted = self._rotations = self._inventory_bytes = 0
        self._error = None
        self._last_flush = self._clock()
        self._receipts = deque(maxlen=128)
        self._active_batch = None
        self._last_iteration_state = None
        self._last_rpc_states = {}

    def start(self):
        with self._condition:
            if self._thread is not None:
                raise TelemetryError("telemetry_already_started")
            self._thread = threading.Thread(target=self._run,
                name="sentinel-telemetry-" + self.role, daemon=True)
            try:
                self._thread.start()
            except BaseException as error:
                self._error = error
                self._stop = True
                raise
        return self

    def _kind(self, record):
        event = record.get("event")
        if event == "helper_host_metrics":
            return TelemetryKind.AGGREGATE
        if event not in _ITERATIONS:
            return TelemetryKind.EVENT
        # Snapshot only stable observation fields. Do not keep a caller's
        # mutable dict, or treat advancing sample_seq as a lifecycle transition.
        state = {key: record.get(key) for key in (
            "event", "state", "reason", "guardian_epoch", "guardian_status", "guardian_observed",
            "guardian_created", "guardian_pid", "attached", "draining", "inventory_verified",
            "known_executions", "unresolved_executions", "drain_unresolved_executions",
            "inventory_error", "discovery_reason", "helper", "replacement", "barrier")}
        state["reconciled"] = [(item.get("execution_id"), item.get("state"), item.get("terminal"))
                               for item in record.get("reconciled", ()) if type(item) is dict]
        signature = json.dumps(state, sort_keys=True, separators=(",", ":"))
        changed = signature != self._last_iteration_state
        self._last_iteration_state = signature
        action = any(record.get(key) for key in (
            "restored", "reconcile_errors", "barrier_clears", "barrier_clear_errors",
            "terminal_retirements", "prelaunch_retirements", "restored_executions",
            "slot_released_executions", "finalized_executions", "errors", "cleanup_errors",
            "unverified", "cold_recovery_reason"))
        for key, field in (("helper", "started"), ("replacement", "started"), ("barrier", "changed")):
            item = record.get(key)
            action = action or type(item) is dict and item.get(field) is True
        for key in ("launch_rpc", "query_rpc", "control_rpc", "operator_rpc"):
            rpc = record.get(key)
            if rpc is None:
                continue
            if type(rpc) is not dict:
                action = True
                continue
            if rpc.get("served") is False and rpc.get("reason") == "pipe_timeout":
                continue  # ordinary no-caller idle result; not an action
            result = rpc.get("result")
            rpc_state = ("error", rpc.get("reason"))
            if rpc.get("served") is True and type(result) is dict:
                if key == "launch_rpc" or key == "control_rpc" and "sample_seq" not in result:
                    action = True  # launch / Apply / Renew / Restore acknowledgements
                elif key == "control_rpc":
                    observations = result.get("results", ())
                    rpc_state = ("frame", [(item.get("execution_id"), item.get("observation"),
                        item.get("reason")) for item in observations if type(item) is dict])
                    action = action or any(type(item) is dict and item.get("barrier_cleared") is True
                                           for item in observations)
                elif key == "operator_rpc":
                    action = action or result.get("operation") not in ("describe", "audit")
                    rpc_state = ("operator", result.get("operation"), result.get("outcome"),
                                 result.get("host_state"))
                else:
                    rpc_state = ("query", result.get("operation"), result.get("receipt_verified"),
                                 result.get("control_writes"))
            elif rpc.get("served") is False:
                # Each refused/malformed request is a separate failed service
                # attempt, even when its reason repeats across idle polls. Only
                # the explicit no-attempt custody-full state is coalescible.
                action = action or rpc.get("reason") != "guardian_host_rpc_custody_full"
            else:
                action = True  # an unknown result shape is never quietly coalesced
            rpc_signature = json.dumps(rpc_state, sort_keys=True, separators=(",", ":"))
            changed = changed or self._last_rpc_states.get(key) != rpc_signature
            self._last_rpc_states[key] = rpc_signature
        return TelemetryKind.EVENT if action or changed else TelemetryKind.AGGREGATE

    def offer(self, record, *, kind=None):
        with self._condition:
            self._sequence += 1
            seq = self._sequence
            if self._stop or self._error is not None:
                self._dropped += 1
                return EmitReceipt(self.instance_id, seq, False, 0, "telemetry_unavailable")
            try:
                if type(record) is not dict or not _bounded_record(record):
                    raise ValueError("record")
                selected = self._kind(record) if kind is None else kind
                if type(selected) is not TelemetryKind:
                    raise ValueError("kind")
                envelope = {"schema_version": 1, "role": self.role, "instance_id": self.instance_id,
                    "identity": self.identity.to_dict(), "sequence": seq, "record": record}
                payload = (json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                           allow_nan=False) + "\n").encode("utf-8")
                if len(payload) > MAX_RECORD_BYTES:
                    raise ValueError("size")
            except (TypeError, ValueError, OverflowError):
                self._dropped += 1
                return EmitReceipt(self.instance_id, seq, False, 0, "telemetry_record_invalid")
            queued = len(self._events) + (self._aggregate is not None) + (
                0 if self._active_batch is None else len(self._active_batch[1]))
            if selected is TelemetryKind.AGGREGATE and self._aggregate is not None:
                self._coalesced += 1
            elif queued >= MAX_PENDING:
                self._dropped += 1
                return EmitReceipt(self.instance_id, seq, False, len(payload), "telemetry_queue_full")
            if selected is TelemetryKind.AGGREGATE:
                self._aggregate = (seq, payload)
            else:
                self._events.append((seq, payload))
            self._accepted += 1
            self._condition.notify()
            return EmitReceipt(self.instance_id, seq, True, len(payload), "telemetry_queued")

    def request_stop(self):
        with self._condition:
            self._stop = True
            self._condition.notify()

    def finish(self, timeout=.05):
        if type(timeout) not in (float, int) or not 0 <= timeout <= .05:
            raise ValueError("telemetry_shutdown_budget_invalid")
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout)
        return self.snapshot()

    def snapshot(self):
        with self._condition:
            return {"role": self.role, "instance_id": self.instance_id,
                "offered": self._sequence, "accepted": self._accepted, "persisted": self._persisted,
                "dropped": self._dropped, "coalesced": self._coalesced,
                "pending_records": len(self._events) + (self._aggregate is not None) +
                    (0 if self._active_batch is None else len(self._active_batch[1])),
                "written_bytes": self._written, "deleted_bytes": self._deleted,
                "inventory_bytes": self._inventory_bytes, "rotations": self._rotations,
                "error": None if self._error is None else getattr(self._error, "reason", type(self._error).__name__),
                "stopping": self._stop, "stopped": self._done,
                "retained_files": self.store.retained_files,
                "max_bytes": self.store.policy.max_bytes, "max_age_ns": self.store.policy.max_age_ns}

    def receipts(self):
        with self._condition:
            return tuple(self._receipts)

    def _batch(self):
        # A continuously replenished event queue must not starve an aggregate
        # whose 30-second deadline is already due.
        if self._aggregate is not None and (self._stop or self._clock() - self._last_flush >= AGGREGATE_SECONDS):
            record, self._aggregate = self._aggregate, None
            return TelemetryKind.AGGREGATE, (record,)
        if self._events:
            records, size = [], 0
            while self._events and size + len(self._events[0][1]) <= MAX_BATCH_BYTES:
                record = self._events.popleft()
                records.append(record)
                size += len(record[1])
            return TelemetryKind.EVENT, tuple(records)
        return None

    def _run(self):
        try:
            self.store.start()
            while True:
                with self._condition:
                    if self._active_batch is None:
                        self._active_batch = self._batch()
                    if self._active_batch is None:
                        if self._stop:
                            return
                        self._condition.wait(timeout=1)
                        continue
                    kind, records = self._active_batch
                try:
                    receipt = self.store.append(kind, records)
                except TelemetryBusy:
                    with self._condition:
                        if self._stop:
                            return  # pending batch remains visible; no false flush ACK
                        self._condition.wait(timeout=.1)
                    continue
                with self._condition:
                    self._receipts.append(receipt)
                    self._persisted += receipt.records
                    self._written += receipt.written_bytes
                    self._deleted += receipt.deleted_bytes
                    self._inventory_bytes = receipt.after_bytes
                    self._rotations += len(receipt.deleted)
                    self._active_batch = None
                    if kind is TelemetryKind.AGGREGATE:
                        self._last_flush = self._clock()
        except BaseException as error:
            with self._condition:
                self._error = error  # original exception/uncertain file custody retained
        finally:
            with self._condition:
                self._done = True


class _UnavailableTelemetry:
    def __init__(self, error):
        self.error = error
    def offer(self, record, **kwargs):
        return None
    def snapshot(self):
        return {"error": getattr(self.error, "reason", type(self.error).__name__),
                "stopped": True, "pending_records": 0}
    def request_stop(self):
        pass
    def finish(self, timeout=.05):
        return self.snapshot()


def start_resident_telemetry(host, *, role, identity, instance_id, data_dir, excluded_paths=()):
    """Retain exact original sink before start; never install a module global."""
    existing = getattr(host, "telemetry", None)
    if existing is not None:
        return existing
    factory = getattr(host, "_telemetry_factory", None) or ResidentTelemetry
    try:
        host.telemetry = factory(data_dir=data_dir, role=role, identity=identity,
                                 instance_id=instance_id, excluded_paths=tuple(excluded_paths))
        host.telemetry.start()
    except Exception as error:
        host._telemetry_start_error = error
        if getattr(host, "telemetry", None) is None:
            host.telemetry = _UnavailableTelemetry(error)
    return host.telemetry


def emit_resident(host, record, stream=None):
    if stream is not None or getattr(host, "telemetry", None) is None:
        import sys
        try:
            print(json.dumps(record, sort_keys=True, default=str),
                  file=sys.stderr if stream is None else stream, flush=True)
        except Exception:
            return False
        return True
    try:
        return host.telemetry.offer(record)
    except Exception as error:
        host._telemetry_emit_error = error
        return False


def stop_resident_telemetry(host, final_record):
    sink = getattr(host, "telemetry", None)
    if sink is None:
        return None
    try:
        sink.offer(final_record, kind=TelemetryKind.EVENT)
        sink.request_stop()
        return sink.finish(timeout=.05)
    except Exception as error:
        host._telemetry_stop_error = error
        return {"error": getattr(error, "reason", type(error).__name__), "stopped": False}
