"""Bounded S1 recovery journal consumed by the isolated native case owner.

The caller retains a trusted, thread-bound exclusive mutation scope throughout
each write. This module neither acquires native authority nor enrolls work.
CPU intent transitions require that scope's current native Job Query. Records
are explicitly test-only and cannot deserialize as production RecoveryManifest.

Files are staged exclusively in the same directory and fsynced before atomic
namespace publication. This is not a power-loss durability guarantee for the
later directory-entry change. The directory and ancestors must be protected
from noncooperating replacement: reparse/fingerprint checks detect known unsafe
paths, but pathname operations are not hostile same-user race containment.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4

from sentinel.adaptive.contracts import (
    Contract, ContractViolation, CpuControl, CpuControlMode, MAX_MESSAGE_BYTES,
    PendingIntent, ProcessIdentity, ResourceDemand, UINT64_MAX,
)


class TestJournalError(RuntimeError):
    """Sanitized storage failure; uncertainty never authorizes launch or Set."""

    def __init__(self, reason, *, publication_may_have_occurred=False):
        self.reason = reason
        self.publication_may_have_occurred = publication_may_have_occurred
        super().__init__(reason)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class TestRecoveryRecord(Contract):
    """Checksummed fixture evidence, never production authority or liveness."""

    execution_id: str
    job_name: str
    creation_nonce: str
    wrapper_identity: ProcessIdentity
    root_identity: ProcessIdentity | None
    guardian_identity: ProcessIdentity
    guardian_epoch: str
    original: CpuControl
    last_applied: CpuControl | None
    pending_intent: PendingIntent | None
    allocated_floor: ResourceDemand
    manifest_seq: int
    manifest_hash: str
    fixture_schema_version: int = 1
    test_only: bool = True

    def __post_init__(self):
        _execution(self.execution_id)
        _nonce(self.creation_nonce)
        if (type(self.fixture_schema_version) is not int or self.fixture_schema_version != 1 or
                self.test_only is not True or
                self.job_name != "Local\\ResourceSentinel.Test.Job." + self.creation_nonce):
            raise TestJournalError("manifest_fixture_binding_invalid")
        if (type(self.guardian_epoch) is not str or
                not re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", self.guardian_epoch) or
                type(self.manifest_seq) is not int or not 0 <= self.manifest_seq <= UINT64_MAX):
            raise TestJournalError("manifest_invalid")
        values = ((self.wrapper_identity, ProcessIdentity), (self.guardian_identity, ProcessIdentity),
                  (self.original, CpuControl), (self.allocated_floor, ResourceDemand))
        if self.root_identity is not None:
            values += ((self.root_identity, ProcessIdentity),)
        if self.last_applied is not None:
            values += ((self.last_applied, CpuControl),)
        if self.pending_intent is not None:
            values += ((self.pending_intent, PendingIntent),)
        try:
            for value, kind in values:
                if type(value) is not kind or kind.from_dict(value.to_dict()) != value:
                    raise TestJournalError("manifest_invalid")
        except (ContractViolation, TypeError, ValueError):
            raise TestJournalError("manifest_invalid") from None
        identities = (self.wrapper_identity, self.guardian_identity) + (
            () if self.root_identity is None else (self.root_identity,))
        if (len({identity.logon_id for identity in identities}) != 1 or
                self.original.mode is not CpuControlMode.DISABLED or
                (self.pending_intent is not None and
                 self.pending_intent.old != (self.last_applied or self.original))):
            raise TestJournalError("manifest_invalid")
        if (type(self.manifest_hash) is not str or
                not re.fullmatch(r"[0-9a-f]{64}", self.manifest_hash) or
                not hmac.compare_digest(self.manifest_hash, self.content_hash())):
            raise TestJournalError("manifest_hash_invalid")

    def content_hash(self):
        value = self.to_dict()
        value.pop("manifest_hash")
        return hashlib.sha256(_canonical(value)).hexdigest()

    @classmethod
    def create(cls, **values):
        if "manifest_hash" in values:
            raise TestJournalError("manifest_hash_computed")
        values.setdefault("fixture_schema_version", 1)
        values.setdefault("test_only", True)
        if set(values) != {field.name for field in fields(cls)} - {"manifest_hash"}:
            raise TestJournalError("manifest_invalid")
        payload = {name: value.to_dict() if isinstance(value, Contract) else value
                   for name, value in values.items()}
        try:
            values["manifest_hash"] = hashlib.sha256(_canonical(payload)).hexdigest()
            return cls(**values)
        except (ContractViolation, TypeError, ValueError):
            raise TestJournalError("manifest_invalid") from None

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {field.name for field in fields(cls)}:
            raise TestJournalError("manifest_invalid")
        data = dict(value)
        try:
            for name in ("wrapper_identity", "guardian_identity", "root_identity"):
                if data[name] is not None:
                    data[name] = ProcessIdentity.from_dict(data[name])
            for name in ("original", "last_applied"):
                if data[name] is not None:
                    data[name] = CpuControl.from_dict(data[name])
            if data["pending_intent"] is not None:
                data["pending_intent"] = PendingIntent.from_dict(data["pending_intent"])
            data["allocated_floor"] = ResourceDemand.from_dict(data["allocated_floor"])
            return cls(**data)
        except (ContractViolation, TypeError, ValueError):
            raise TestJournalError("manifest_invalid") from None


def _execution(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        valid = parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise TestJournalError("manifest_binding_invalid")


def _nonce(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise TestJournalError("manifest_binding_invalid")


def _safe_stat(value, *, directory=False):
    if (stat.S_ISLNK(value.st_mode) or
            getattr(value, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400) or
            not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)) or
            value.st_ino == 0):
        raise TestJournalError("manifest_path_unsafe")
    return value.st_dev, value.st_ino


def _record(value):
    if type(value) is not TestRecoveryRecord:
        raise TestJournalError("manifest_invalid")
    try:
        encoded = value.to_json().encode("utf-8")
        checked = TestRecoveryRecord.from_json(encoded)
    except (ContractViolation, TypeError, ValueError):
        raise TestJournalError("manifest_invalid") from None
    if len(encoded) > MAX_MESSAGE_BYTES or checked != value:
        raise TestJournalError("manifest_invalid")
    _execution(value.execution_id)
    return encoded


@contextmanager
def _binary_file(path, flags, mode):
    """Keep raw descriptor ownership separate from stream construction."""
    descriptor = os.open(path, flags, 0o600)
    stream = None

    def close_owned():
        if stream is not None:
            try:
                stream.close()
            except BaseException as cleanup:
                # Do not invalidate an fd while an unclosed stream might still
                # use it. Retain both owners; no automatic close retry occurs.
                cleanup._journal_cleanup_owner = (stream, descriptor)
                raise
        try:
            os.close(descriptor)
        except BaseException as cleanup:
            cleanup._journal_cleanup_owner = descriptor
            raise

    try:
        # fdopen(closefd=True) may close its input before failing while building
        # a wrapper. Keep sole fd ownership here to prevent a double close of a
        # reused integer. No buffering is needed before the explicit fsync.
        stream = os.fdopen(descriptor, mode, buffering=0, closefd=False)
        yield stream
    except BaseException as primary:
        try:
            close_owned()
        except BaseException as cleanup:
            # Keep the owner privately reachable for diagnosis; do not mask a
            # write/verification failure with a second cleanup exception.
            primary._journal_cleanup_owner = cleanup._journal_cleanup_owner
            primary.add_note("manifest_stream_cleanup_unverified")
        raise
    else:
        close_owned()


class TestRecoveryJournal:
    """One canonical file per execution; never delete or rotate live evidence.

    ``writer_scope`` is a trusted in-process owner, not caller-supplied JSON. It
    exposes execution_id, creation_nonce, assert_held() (None on success), and
    query_cpu_control() returning a CpuControl from the actual held native Job.
    assert_held must verify policy and per-Job exclusive mutation mutex ownership
    on this thread; merely retaining a live handle is insufficient. The caller
    keeps that scope acquired until this entire call returns or raises. Initial
    create precedes Job creation, so its disabled original is a required baseline,
    not proof that a native Job exists or has been queried. Guardian identity and
    epoch remain immutable creation provenance; they do not assert current life.
    """

    def __init__(self, directory):
        try:
            path = Path(directory)
        except (TypeError, ValueError):
            raise TestJournalError("manifest_directory_invalid") from None
        if (not path.is_absolute() or len(path.parts) > 128 or
                len(str(path)) > 32760 or "\x00" in str(path) or
                any(part in {".", ".."} for part in path.parts) or
                (os.name == "nt" and (len(path.drive) != 2 or path.drive[1] != ":"))):
            raise TestJournalError("manifest_directory_invalid")
        # Do not resolve() through a junction/symlink before checking it.
        self._directory = path
        self._ancestors = tuple(reversed(path.parents)) + (path,)
        self._directory_ids = self._inspect_directories()

    def _inspect_directories(self):
        try:
            return tuple(_safe_stat(os.lstat(path), directory=True) for path in self._ancestors)
        except OSError:
            raise TestJournalError("manifest_directory_unavailable") from None

    def _check_directory(self):
        if self._inspect_directories() != self._directory_ids:
            raise TestJournalError("manifest_directory_changed")

    def _path(self, execution_id):
        _execution(execution_id)
        return self._directory / (execution_id + ".json")

    @staticmethod
    def _scope(scope, record):
        if (getattr(scope, "execution_id", None) != record.execution_id or
                getattr(scope, "creation_nonce", None) != record.creation_nonce or
                not callable(getattr(scope, "assert_held", None)) or
                not callable(getattr(scope, "query_cpu_control", None))):
            raise TestJournalError("manifest_writer_scope_invalid")
        try:
            held = scope.assert_held()
        except Exception:
            raise TestJournalError("manifest_writer_scope_invalid") from None
        if held is not None:
            raise TestJournalError("manifest_writer_scope_invalid")

    def read(self, execution_id, *, creation_nonce):
        """Return validated evidence; no owner liveness or native state inferred."""
        path = self._path(execution_id)
        _nonce(creation_nonce)
        self._check_directory()
        try:
            before = os.lstat(path)
            expected = _safe_stat(before)
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            with _binary_file(path, flags, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if _safe_stat(opened) != expected or opened.st_size > MAX_MESSAGE_BYTES:
                    raise TestJournalError("manifest_invalid")
                payload = stream.read(MAX_MESSAGE_BYTES + 1)
                after = os.fstat(stream.fileno())
                if (len(payload) > MAX_MESSAGE_BYTES or len(payload) != opened.st_size or
                        _safe_stat(after) != expected or
                        (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                    raise TestJournalError("manifest_invalid")
            self._check_directory()
            if _safe_stat(os.lstat(path)) != expected:
                raise TestJournalError("manifest_path_changed")
            record = TestRecoveryRecord.from_json(payload)
        except FileNotFoundError:
            raise TestJournalError("manifest_not_found") from None
        except OSError:
            raise TestJournalError("manifest_read_unavailable") from None
        except (ContractViolation, TypeError, ValueError):
            raise TestJournalError("manifest_invalid") from None
        if record.execution_id != execution_id or record.creation_nonce != creation_nonce:
            raise TestJournalError("manifest_binding_mismatch")
        return record

    def _control_transition(self, old, new, scope):
        self._scope(scope, new)
        try:
            observed = scope.query_cpu_control()
        except Exception:
            raise TestJournalError("manifest_cpu_query_unavailable") from None
        if type(observed) is not CpuControl:
            raise TestJournalError("manifest_cpu_query_invalid")
        try:
            if CpuControl.from_dict(observed.to_dict()) != observed:
                raise TestJournalError("manifest_cpu_query_invalid")
        except (ContractViolation, TypeError, ValueError):
            raise TestJournalError("manifest_cpu_query_invalid") from None
        self._scope(scope, new)
        effective = old.last_applied or old.original
        pending = old.pending_intent
        if pending is not None:
            # A pending old/new pair remains recovery evidence until a current
            # Query resolves it. Never overwrite it with a different action.
            if observed not in (pending.old, pending.new, old.original):
                raise TestJournalError("manifest_external_control_conflict")
            if new.pending_intent == pending and new.last_applied == old.last_applied:
                return
            if new.pending_intent is None and new.last_applied == observed:
                return
            raise TestJournalError("manifest_control_transition_invalid")
        if new.pending_intent is not None:
            if (observed != effective or new.last_applied != old.last_applied or
                    new.pending_intent.old != effective or new.pending_intent.new == effective):
                raise TestJournalError("manifest_control_transition_invalid")
            return
        if new.last_applied == old.last_applied:
            if observed != effective:
                raise TestJournalError("manifest_external_control_conflict")
            return
        # Safety restoration need not wait for a new durable restrictive intent.
        # Record that disabled result only after the actual Query confirms it.
        if new.last_applied != old.original or observed != old.original:
            raise TestJournalError("manifest_control_transition_invalid")

    def create(self, record, *, writer_scope):
        encoded = _record(record)
        if (record.manifest_seq != 0 or record.root_identity is not None or
                record.last_applied is not None or record.pending_intent is not None):
            raise TestJournalError("manifest_initial_state_invalid")
        self._scope(writer_scope, record)
        self._check_directory()
        try:
            os.lstat(self._path(record.execution_id))
        except FileNotFoundError:
            pass
        except OSError:
            raise TestJournalError("manifest_read_unavailable") from None
        else:
            raise TestJournalError("manifest_already_exists")
        return self._publish(record, encoded, writer_scope, previous=None)

    def publish(self, record, *, expected_seq, expected_hash, writer_scope):
        encoded = _record(record)
        if (type(expected_seq) is not int or not 0 <= expected_seq < UINT64_MAX or
                type(expected_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or
                record.manifest_seq != expected_seq + 1):
            raise TestJournalError("manifest_sequence_conflict")
        self._scope(writer_scope, record)
        old = self.read(record.execution_id, creation_nonce=record.creation_nonce)
        if (old.manifest_seq, old.manifest_hash) != (expected_seq, expected_hash):
            raise TestJournalError("manifest_sequence_conflict")
        for field in ("execution_id", "creation_nonce", "job_name", "wrapper_identity",
                      "guardian_identity", "guardian_epoch", "original", "fixture_schema_version", "test_only"):
            if getattr(old, field) != getattr(record, field):
                raise TestJournalError("manifest_immutable_changed")
        if old.root_identity is not None and old.root_identity != record.root_identity:
            raise TestJournalError("manifest_root_changed")
        if any(getattr(record.allocated_floor, field) < getattr(old.allocated_floor, field)
               for field in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")):
            raise TestJournalError("manifest_floor_decreased")
        self._control_transition(old, record, writer_scope)
        return self._publish(record, encoded, writer_scope, previous=old)

    @staticmethod
    def _cleanup_temp(path, expected):
        try:
            current = os.lstat(path)
        except FileNotFoundError:
            return
        if _safe_stat(current) != expected:
            raise TestJournalError("manifest_temporary_changed")
        os.unlink(path)

    def _publish(self, record, encoded, scope, *, previous):
        target = self._path(record.execution_id)
        temporary = self._directory / ("." + record.execution_id + "." + uuid4().hex + ".tmp")
        temporary_id = None
        primary = None
        publishing = published = False
        try:
            self._check_directory()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
            with _binary_file(temporary, flags, "wb") as stream:
                temporary_id = _safe_stat(os.fstat(stream.fileno()))
                if stream.write(encoded) != len(encoded):
                    raise TestJournalError("manifest_write_incomplete")
                stream.flush()
                os.fsync(stream.fileno())
            self._check_directory()
            self._scope(scope, record)
            if _safe_stat(os.lstat(temporary)) != temporary_id:
                raise TestJournalError("manifest_temporary_changed")
            if previous is not None:
                current = self.read(record.execution_id, creation_nonce=record.creation_nonce)
                if current != previous:
                    raise TestJournalError("manifest_sequence_conflict")
                # Fsync may have blocked. Confirm the same retained Job state
                # again under the owner fences before publishing a new intent
                # or retiring the previous one. No control is written here.
                self._control_transition(previous, record, scope)
            self._scope(scope, record)
            self._check_directory()
            publishing = True
            if previous is not None:
                os.replace(temporary, target)
            elif os.name == "nt":
                os.rename(temporary, target)  # Windows rename never replaces dst.
            else:
                # POSIX rename replaces dst; a hard link instead publishes the
                # fully closed staging inode without overwriting a collision.
                os.link(temporary, target, follow_symlinks=False)
            published = True
            return record
        except FileExistsError:
            if publishing and previous is not None:
                primary = TestJournalError("manifest_publication_unverified",
                                           publication_may_have_occurred=True)
            else:
                # Exclusive first publication positively refused the existing
                # destination. Its staging file can be cleaned without touching
                # that destination; this is not an uncertain replacement.
                publishing = False
                primary = TestJournalError("manifest_already_exists")
            raise primary from None
        except TestJournalError as error:
            primary = error
            if publishing:
                error.publication_may_have_occurred = True
            raise
        except OSError:
            primary = TestJournalError("manifest_publication_unverified" if publishing else
                                    "manifest_write_unavailable",
                                    publication_may_have_occurred=publishing)
            raise primary from None
        except BaseException as error:
            primary = error
            if publishing:
                error.publication_may_have_occurred = True
            raise
        finally:
            # Keep staging evidence after an ambiguous publication failure.
            # Never revert the canonical file, delete unknown temporary files,
            # or reinterpret a cleanup failure as permission to launch again.
            if temporary_id is not None and (not publishing or published):
                try:
                    self._check_directory()
                    self._cleanup_temp(temporary, temporary_id)
                except BaseException:
                    if primary is not None:
                        primary.add_note("manifest_temporary_cleanup_unverified")
                    else:
                        raise TestJournalError("manifest_temporary_cleanup_unverified",
                                            publication_may_have_occurred=published) from None
