"""Production recovery evidence under the retained POLICY and Job writer scope.

This module consumes only the formal RecoveryManifest contract. It never opens
Jobs, grants authority, writes controls, or imports test-only records. Successful
intent publication must precede a consumer's Set; a publication exception must
never be treated as permission to Set, even if readback finds the new record.
A recovered pending intent is possible-effect evidence, never a desired replay.

Each file is bounded and staged exclusively beside its canonical execution UUID
path, fsynced before namespace publication. Windows publication requests native
MoveFileExW WRITE_THROUGH without cross-volume copy fallback; successful return
and canonical readback precede a consumer's Set. Neither that request nor this
journal promises crash-consistent hardware writes under sudden power loss.
The caller provisions an
ACL-protected local directory and retains those protections on every ancestor;
reparse/fingerprint checks detect unsafe paths but do not isolate a hostile
same-logon actor capable of replacing paths. This journal makes no whole-machine
power-loss recovery guarantee and cannot make an unavailable volume durable.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from functools import lru_cache
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4

from .contracts import (
    ContractViolation, CpuControl, MAX_MESSAGE_BYTES, RecoveryManifest, UINT64_MAX,
)


class RecoveryJournalError(RuntimeError):
    """Sanitized failure; ambiguous publication is not permission for native Set."""
    def __init__(self, reason, *, publication_may_have_occurred=False):
        self.reason = reason
        self.publication_may_have_occurred = publication_may_have_occurred
        super().__init__(reason)


def _storage_failure(reason, source, *, publication_may_have_occurred=False):
    """Sanitize OS details while keeping uncertain stream/fd custody explicit."""
    failure = RecoveryJournalError(reason, publication_may_have_occurred=publication_may_have_occurred)
    if hasattr(source, "_journal_cleanup_owner"):
        failure._journal_cleanup_owner = source._journal_cleanup_owner
    if "manifest_stream_cleanup_unverified" in getattr(source, "__notes__", ()):
        failure.add_note("manifest_stream_cleanup_unverified")
    return failure


@lru_cache(maxsize=1)
def _move_file():
    # Microsoft documents MOVEFILE_WRITE_THROUGH, while ReplaceFileW's similarly
    # named flag is unsupported. No COPY_ALLOWED: staging must remain on-volume.
    # https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
    function = C.WinDLL("kernel32", use_last_error=True).MoveFileExW
    function.restype = C.c_int32
    function.argtypes = (C.c_wchar_p, C.c_wchar_p, C.c_uint32)
    return function


def _publish_namespace(temporary, target, *, replace):
    """Request durable namespace publication; never fall back after failure."""
    if os.name != "nt":
        raise RecoveryJournalError("manifest_native_publication_unavailable")
    result = _move_file()(str(temporary), str(target), 0x8 | (0x1 if replace else 0))
    if type(result) is not int or not -(1 << 31) <= result < (1 << 31):
        raise RecoveryJournalError("manifest_publication_unverified", publication_may_have_occurred=True)
    if result == 0:
        error = C.get_last_error()
        kind = FileExistsError if error in {80, 183} else OSError
        failure = kind(error, "manifest_namespace_publication_failed")
        if kind is FileExistsError and not replace:
            failure._journal_exclusive_collision = True
        raise failure


def _execution(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        valid = parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise RecoveryJournalError("manifest_binding_invalid")


def _nonce(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise RecoveryJournalError("manifest_binding_invalid")


def _safe_stat(value, *, directory=False):
    if (stat.S_ISLNK(value.st_mode) or
            getattr(value, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400) or
            not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode)) or
            value.st_ino == 0):
        raise RecoveryJournalError("manifest_path_unsafe")
    return value.st_dev, value.st_ino


def _record(value):
    if type(value) is not RecoveryManifest:
        raise RecoveryJournalError("manifest_invalid")
    try:
        encoded = value.to_json().encode("utf-8")
        checked = RecoveryManifest.from_json(encoded)
    except (ContractViolation, TypeError, ValueError):
        raise RecoveryJournalError("manifest_invalid") from None
    if len(encoded) > MAX_MESSAGE_BYTES or checked != value:
        raise RecoveryJournalError("manifest_invalid")
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


class RecoveryJournal:
    """One canonical file per execution; never delete or rotate live evidence.

    ``writer_scope`` is a trusted in-process owner, not caller-supplied JSON. It
    exposes exact execution_id, creation_nonce, job_name, reservation, spec_hash,
    assert_held() (None on success), and query_cpu_control() returning a CpuControl
    from the actual held native Job.
    assert_held must verify policy and per-Job exclusive mutation mutex ownership
    on this thread; merely retaining a live handle is insufficient. The caller
    keeps that scope acquired until this entire call returns or raises. Initial
    create precedes Job creation, so its disabled original is a required baseline,
    not proof that a native Job exists or has been queried. Guardian identity and
    epoch remain immutable creation provenance; they do not assert current life.
    """

    def __init__(self, directory, *, publisher=None):
        try:
            path = Path(directory)
        except (TypeError, ValueError):
            raise RecoveryJournalError("manifest_directory_invalid") from None
        if (not path.is_absolute() or len(path.parts) > 128 or
                len(str(path)) > 32760 or "\x00" in str(path) or
                any(part in {".", ".."} for part in path.parts) or
                (os.name == "nt" and (len(path.drive) != 2 or path.drive[1] != ":"))):
            raise RecoveryJournalError("manifest_directory_invalid")
        # Do not resolve() through a junction/symlink before checking it.
        self._directory = path
        self._ancestors = tuple(reversed(path.parents)) + (path,)
        self._directory_ids = self._inspect_directories()
        # Explicit in-process fixture seam only. Default production publication
        # is native Windows write-through; no environment/serialized opt-in.
        if publisher is not None and not callable(publisher):
            raise RecoveryJournalError("manifest_publisher_invalid")
        self._publisher = _publish_namespace if publisher is None else publisher

    def _inspect_directories(self):
        try:
            return tuple(_safe_stat(os.lstat(path), directory=True) for path in self._ancestors)
        except OSError:
            raise RecoveryJournalError("manifest_directory_unavailable") from None

    def _check_directory(self):
        if self._inspect_directories() != self._directory_ids:
            raise RecoveryJournalError("manifest_directory_changed")

    def _path(self, execution_id):
        _execution(execution_id)
        return self._directory / (execution_id + ".json")

    @staticmethod
    def _scope(scope, record):
        if (getattr(scope, "execution_id", None) != record.execution_id or
                getattr(scope, "creation_nonce", None) != record.creation_nonce or
                getattr(scope, "job_name", None) != record.job_name or
                getattr(scope, "reservation", None) != record.reservation or
                getattr(scope, "spec_hash", None) != record.spec_hash or
                not callable(getattr(scope, "assert_held", None)) or
                not callable(getattr(scope, "query_cpu_control", None))):
            raise RecoveryJournalError("manifest_writer_scope_invalid")
        try:
            held = scope.assert_held()
        except Exception:
            raise RecoveryJournalError("manifest_writer_scope_invalid") from None
        if held is not None:
            raise RecoveryJournalError("manifest_writer_scope_invalid")

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
                    raise RecoveryJournalError("manifest_invalid")
                payload = stream.read(MAX_MESSAGE_BYTES + 1)
                after = os.fstat(stream.fileno())
                if (len(payload) > MAX_MESSAGE_BYTES or len(payload) != opened.st_size or
                        _safe_stat(after) != expected or
                        (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                    raise RecoveryJournalError("manifest_invalid")
            self._check_directory()
            if _safe_stat(os.lstat(path)) != expected:
                raise RecoveryJournalError("manifest_path_changed")
            record = RecoveryManifest.from_json(payload)
        except FileNotFoundError as error:
            raise _storage_failure("manifest_not_found", error) from None
        except OSError as error:
            raise _storage_failure("manifest_read_unavailable", error) from None
        except (ContractViolation, TypeError, ValueError):
            raise RecoveryJournalError("manifest_invalid") from None
        if record.execution_id != execution_id or record.creation_nonce != creation_nonce:
            raise RecoveryJournalError("manifest_binding_mismatch")
        return record

    def _control_transition(self, old, new, scope):
        self._scope(scope, new)
        try:
            observed = scope.query_cpu_control()
        except Exception:
            raise RecoveryJournalError("manifest_cpu_query_unavailable") from None
        if type(observed) is not CpuControl:
            raise RecoveryJournalError("manifest_cpu_query_invalid")
        try:
            if CpuControl.from_dict(observed.to_dict()) != observed:
                raise RecoveryJournalError("manifest_cpu_query_invalid")
        except (ContractViolation, TypeError, ValueError):
            raise RecoveryJournalError("manifest_cpu_query_invalid") from None
        self._scope(scope, new)
        effective = old.last_applied or old.original
        pending = old.pending_intent
        if pending is not None:
            # A pending old/new pair remains recovery evidence until a current
            # Query resolves it. Never overwrite it with a different action.
            if observed not in (pending.old, pending.new, old.original):
                raise RecoveryJournalError("manifest_external_control_conflict")
            if new.pending_intent == pending and new.last_applied == old.last_applied:
                return
            if new.pending_intent is None and new.last_applied == observed:
                return
            raise RecoveryJournalError("manifest_control_transition_invalid")
        if new.pending_intent is not None:
            if (observed != effective or new.last_applied != old.last_applied or
                    new.pending_intent.old != effective or new.pending_intent.new == effective):
                raise RecoveryJournalError("manifest_control_transition_invalid")
            return
        if new.last_applied == old.last_applied:
            if observed != effective:
                raise RecoveryJournalError("manifest_external_control_conflict")
            return
        # Safety restoration need not wait for a new durable restrictive intent.
        # Record that disabled result only after the actual Query confirms it.
        if new.last_applied != old.original or observed != old.original:
            raise RecoveryJournalError("manifest_control_transition_invalid")

    def create(self, record, *, writer_scope):
        encoded = _record(record)
        if (record.manifest_seq != 0 or record.root_identity is not None or
                record.last_applied is not None or record.pending_intent is not None):
            raise RecoveryJournalError("manifest_initial_state_invalid")
        self._scope(writer_scope, record)
        self._check_directory()
        try:
            os.lstat(self._path(record.execution_id))
        except FileNotFoundError:
            pass
        except OSError:
            raise RecoveryJournalError("manifest_read_unavailable") from None
        else:
            raise RecoveryJournalError("manifest_already_exists")
        return self._publish(record, encoded, writer_scope, previous=None)

    def publish(self, record, *, expected_seq, expected_hash, writer_scope):
        encoded = _record(record)
        if (type(expected_seq) is not int or not 0 <= expected_seq < UINT64_MAX or
                type(expected_hash) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or
                record.manifest_seq != expected_seq + 1):
            raise RecoveryJournalError("manifest_sequence_conflict")
        self._scope(writer_scope, record)
        old = self.read(record.execution_id, creation_nonce=record.creation_nonce)
        if (old.manifest_seq, old.manifest_hash) != (expected_seq, expected_hash):
            raise RecoveryJournalError("manifest_sequence_conflict")
        for field in ("execution_id", "creation_nonce", "job_name", "wrapper_identity",
                      "guardian_identity", "guardian_epoch", "original", "schema_version",
                      "reservation", "spec_hash"):
            if getattr(old, field) != getattr(record, field):
                raise RecoveryJournalError("manifest_immutable_changed")
        if old.root_identity is not None and old.root_identity != record.root_identity:
            raise RecoveryJournalError("manifest_root_changed")
        if any(getattr(record.allocated_floor, field) < getattr(old.allocated_floor, field)
               for field in ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")):
            raise RecoveryJournalError("manifest_floor_decreased")
        self._control_transition(old, record, writer_scope)
        return self._publish(record, encoded, writer_scope, previous=old)

    @staticmethod
    def _cleanup_temp(path, expected):
        try:
            current = os.lstat(path)
        except FileNotFoundError:
            return
        if _safe_stat(current) != expected:
            raise RecoveryJournalError("manifest_temporary_changed")
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
                    raise RecoveryJournalError("manifest_write_incomplete")
                stream.flush()
                os.fsync(stream.fileno())
            self._check_directory()
            self._scope(scope, record)
            if _safe_stat(os.lstat(temporary)) != temporary_id:
                raise RecoveryJournalError("manifest_temporary_changed")
            if previous is not None:
                current = self.read(record.execution_id, creation_nonce=record.creation_nonce)
                if current != previous:
                    raise RecoveryJournalError("manifest_sequence_conflict")
                # Fsync may have blocked. Confirm the same retained Job state
                # again under the owner fences before publishing a new intent
                # or retiring the previous one. No control is written here.
                self._control_transition(previous, record, scope)
            self._scope(scope, record)
            self._check_directory()
            publishing = True
            if self._publisher(temporary, target, replace=previous is not None) is not None:
                raise RecoveryJournalError("manifest_publication_unverified")
            published = True
            self._scope(scope, record)
            if self.read(record.execution_id, creation_nonce=record.creation_nonce) != record:
                raise RecoveryJournalError("manifest_publication_unverified")
            return record
        except FileExistsError as error:
            if publishing and (previous is not None or
                               getattr(error, "_journal_exclusive_collision", False) is not True):
                primary = _storage_failure("manifest_publication_unverified", error,
                                           publication_may_have_occurred=True)
            else:
                # Exclusive first publication positively refused the existing
                # destination. Its staging file can be cleaned without touching
                # that destination; this is not an uncertain replacement.
                publishing = False
                primary = _storage_failure("manifest_already_exists", error)
            raise primary from None
        except RecoveryJournalError as error:
            primary = error
            if publishing:
                error.publication_may_have_occurred = True
            raise
        except OSError as error:
            primary = _storage_failure("manifest_publication_unverified" if publishing else
                                    "manifest_write_unavailable", error,
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
                        raise RecoveryJournalError("manifest_temporary_cleanup_unverified",
                                            publication_may_have_occurred=published) from None
