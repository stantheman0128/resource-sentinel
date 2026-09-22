"""Retained Windows source-file custody for an explicitly authorized installer.

Standard library only: safe to import before any Sentinel package is loaded.
Importing this module does not open files, load native libraries or write data.
Existing files are opened with GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
OPEN_EXISTING and OPEN_REPARSE_POINT. New files use CREATE_NEW and also request
DELETE solely for same-handle rollback. Parent directory handles deny writes
and deletion, preventing ancestor rename or reparse mutation during custody.
An existing directory write handle can therefore refuse this strict acquisition.

This is an in-place writer, not a transaction or deployment authorization.
All original bytes and native identities remain in memory. A mutation with an
uncertain outcome is quarantined and cannot be retried or automatically rolled
back. Closing a handle never establishes that a write or deletion succeeded.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import hashlib
import ntpath
import os
import re
import threading


MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_PARENT_HANDLES = 128


class SourceFileError(RuntimeError):
    """Stable reason plus retained custody; never embeds file contents."""

    def __init__(self, reason, *, retained=None, known_failed=False, win32_error=None):
        self.reason, self.retained = reason, retained
        self.retained_file = retained
        self.known_failed = known_failed
        self.win32_error = win32_error
        super().__init__(reason)


@dataclass(frozen=True)
class NativeFileIdentity:
    """Raw Win32 values, deliberately NOT aliases for Python st_dev/st_ino.

    First two fields come from BY_HANDLE_FILE_INFORMATION. The last two come
    from FILE_ID_INFO; file_id_128 is the 16 opaque bytes in native byte order,
    hex encoded. No conversion to a Python stat inode is asserted. Compare a
    separately captured baseline only when it used this exact representation.
    """

    volume_serial_number32: int
    file_index64: int
    volume_serial_number64: int
    file_id_128: str


@dataclass(frozen=True)
class FileSnapshot:
    identity: NativeFileIdentity
    normalized_path: str
    size: int
    attributes: int
    links: int
    delete_pending: bool


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _expected_hash(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("invalid_expected_source_hash")
    return value


def _path(value):
    value = os.fspath(value)
    if not isinstance(value, str):
        raise ValueError("source_path_must_be_text")
    value = value.replace("/", "\\")
    if (len(value) > 32760 or re.match(r"^[A-Za-z]:\\", value) is None
            or any(ord(char) < 32 for char in value)
            or any(char in value[2:] for char in ':*?"<>|')):
        raise ValueError("unsupported_source_path")
    parts = value[3:].split("\\")
    if not parts or any(not part or part in {".", ".."} or part[-1:] in {" ", "."}
                        or re.fullmatch(r"(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", part)
                        for part in parts):
        raise ValueError("unsupported_source_path")
    if len(parts) > MAX_PARENT_HANDLES:
        raise ValueError("source_parent_bound_exceeded")
    return value[0].upper() + value[1:]


def _parents(path):
    drive, tail = ntpath.splitdrive(path)
    parts = tail.lstrip("\\").split("\\")[:-1]
    result = [drive + "\\"]
    for part in parts:
        result.append(ntpath.join(result[-1], part))
    return result


class _Handle:
    def __init__(self, backend, path, *, directory, new=False):
        self.backend, self.path, self.directory, self.new = backend, path, directory, new
        self.value = None
        self.identity = None
        self.open_unknown = False
        self.close_unknown = False

    def open(self):
        self.open_unknown = True
        try:
            handle = self.backend.open(self.path, directory=self.directory, new=self.new)
        except SourceFileError as error:
            if error.known_failed is True:
                self.open_unknown = False
            raise
        if type(handle) is not int or not 0 < handle < 1 << (C.sizeof(C.c_void_p) * 8 - 1):
            raise SourceFileError("source_open_outcome_unknown")
        self.value = handle
        self.open_unknown = False

    def close(self):
        if self.open_unknown or self.close_unknown:
            raise SourceFileError("source_handle_outcome_unknown")
        if self.value is None:
            return
        self.close_unknown = True
        try:
            self.backend.close(self.value)
        except SourceFileError as error:
            if error.reason == "source_close_failed" and error.known_failed is True:
                self.close_unknown = False
            raise
        self.value = None
        self.close_unknown = False


def _snapshot_held(backend, held, *, allow_delete=False):
    if held.value is None or held.open_unknown or held.close_unknown:
        raise SourceFileError("source_handle_unavailable")
    record = backend.snapshot(held.value)
    if (not isinstance(record, FileSnapshot) or not isinstance(record.identity, NativeFileIdentity)
            or type(record.attributes) is not int or type(record.size) is not int
            or record.size < 0 or type(record.links) is not int
            or type(record.delete_pending) is not bool
            or record.normalized_path.casefold() != held.path.casefold()
            or record.attributes & 0x400
            or bool(record.attributes & 0x10) is not held.directory
            or (not held.directory and record.links != 1)
            or (record.delete_pending and not allow_delete)):
        raise SourceFileError("source_path_or_metadata_unverified")
    if held.identity is not None and record.identity != held.identity:
        raise SourceFileError("source_retained_identity_changed")
    return record


class RetainedParentDirectories:
    """Bounded ancestor custody; created directories are never auto-deleted."""

    def __init__(self, backend, file_path):
        self._backend, self.file_path = backend, file_path
        self._parents, self._created = [], []
        self._creation_unknown = False
        self._quarantined = self._closing = self._closed = False
        self._lock = threading.RLock()

    @property
    def created_directories(self):
        return tuple(self._created)

    @property
    def quarantined(self):
        return self._quarantined

    @property
    def closed(self):
        return self._closed

    def _prepare(self):
        for index, path in enumerate(_parents(self.file_path)):
            for ancestor in self._parents:
                _snapshot_held(self._backend, ancestor)
            held = _Handle(self._backend, path, directory=True)
            self._parents.append(held)
            try:
                held.open()
            except SourceFileError as error:
                # Only an explicit missing-directory result permits creation.
                # The drive root must already exist; never try to manufacture it.
                if (index == 0 or error.known_failed is not True
                        or error.win32_error not in {2, 3}
                        or held.open_unknown or held.value is not None):
                    raise
                for ancestor in self._parents[:-1]:
                    _snapshot_held(self._backend, ancestor)
                self._creation_unknown = True
                try:
                    created = self._backend.create_directory(path)
                except SourceFileError as failure:
                    if failure.known_failed is True:
                        self._creation_unknown = False
                    raise
                if type(created) is not bool:
                    raise SourceFileError("source_directory_create_unverified")
                if created:
                    self._created.append(path)
                self._creation_unknown = False
                # A concurrent existing directory is verified too; a junction,
                # file or inaccessible object cannot become the next ancestor.
                held.open()
            held.identity = _snapshot_held(self._backend, held).identity

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closing = True
            try:
                if self._creation_unknown:
                    raise SourceFileError("source_directory_create_outcome_unknown")
                for held in reversed(self._parents):
                    held.close()
                self._closed = True
            except BaseException as error:
                self._quarantined = True
                reason = error.reason if isinstance(error, SourceFileError) else "source_close_outcome_unknown"
                raise SourceFileError(reason, retained=self) from None


class NativeSourceFiles:
    """Factory retaining failed acquisitions, with an explicit synthetic seam."""

    def __init__(self, *, backend=None, max_bytes=MAX_SOURCE_BYTES):
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
            raise ValueError("invalid_source_byte_bound")
        self._backend = backend
        self.max_bytes = max_bytes
        self._owned = []

    def _open(self, path, *, new, expected_sha256=None, expected_identity=None):
        path = _path(path)
        if expected_sha256 is not None:
            _expected_hash(expected_sha256)
        if expected_identity is not None and not isinstance(expected_identity, NativeFileIdentity):
            raise TypeError("exact_native_file_identity_required")
        if self._backend is None:
            self._backend = _WindowsBackend()
        owner = RetainedSourceFile(self._backend, path, new=new, max_bytes=self.max_bytes)
        self._owned.append(owner)
        try:
            owner._acquire()
            if expected_identity is not None and owner.native_identity != expected_identity:
                raise SourceFileError("source_baseline_identity_changed")
            if expected_sha256 is not None and owner.sha256 != expected_sha256:
                raise SourceFileError("source_baseline_hash_changed")
            return owner
        except BaseException as error:
            owner._quarantined = True
            reason = error.reason if isinstance(error, SourceFileError) else "source_acquisition_unverified"
            raise SourceFileError(reason, retained=owner) from None

    def open_existing(self, path, *, expected_sha256=None, expected_identity=None):
        return self._open(path, new=False, expected_sha256=expected_sha256,
                          expected_identity=expected_identity)

    def create_new(self, path):
        """Explicit CREATE_NEW action. Never replaces or truncates an entry."""
        return self._open(path, new=True)

    def prepare_parent_directories(self, file_path):
        """Explicit bounded parent creation under retained ancestor handles.

        Existing directories are untouched. Created directories remain present
        on every failure/rollback path; there is no recursive cleanup operation.
        Keep the returned owner alive through CREATE_NEW and source verification.
        """
        file_path = _path(file_path)
        if self._backend is None:
            self._backend = _WindowsBackend()
        owner = RetainedParentDirectories(self._backend, file_path)
        self._owned.append(owner)
        try:
            owner._prepare()
            return owner
        except BaseException as error:
            owner._quarantined = True
            reason = error.reason if isinstance(error, SourceFileError) else "source_directory_preparation_unverified"
            failure = SourceFileError(reason, retained=owner)
            failure.retained_directories = owner
            raise failure from None


class RetainedSourceFile:
    def __init__(self, backend, path, *, new, max_bytes):
        self._backend, self.normalized_path = backend, path
        self.owned_new, self._max_bytes = new, max_bytes
        self._parents = []
        self._file = None
        self._native_identity = None
        self._stat_identity = None
        self._auxiliary = []
        self._backup_bytes = None
        self._sha256 = None
        self._quarantined = self._closing = self._closed = self._delete_pending = False
        self._lock = threading.RLock()

    @property
    def native_identity(self):
        return self._native_identity

    @property
    def identity(self):
        return self._native_identity

    @property
    def backup_bytes(self):
        return self._backup_bytes

    @property
    def stat_identity(self):
        """Acquisition os.fstat values from a separately duplicated handle.

        The original native handle never transfers to a CRT file descriptor.
        Return a copy so caller edits cannot rewrite this baseline.
        """
        return None if self._stat_identity is None else dict(self._stat_identity)

    @property
    def sha256(self):
        """Hash of the last verified readback, never of an uncertain mutation."""
        return self._sha256

    @property
    def quarantined(self):
        return self._quarantined

    @property
    def delete_pending(self):
        return self._delete_pending

    @property
    def closed(self):
        return self._closed

    def _snapshot(self, held, *, allow_delete=False):
        return _snapshot_held(self._backend, held, allow_delete=allow_delete)

    def _acquire(self):
        for path in _parents(self.normalized_path):
            held = _Handle(self._backend, path, directory=True)
            self._parents.append(held)
            held.open()
            held.identity = self._snapshot(held).identity
        self._file = _Handle(self._backend, self.normalized_path, directory=False, new=self.owned_new)
        self._file.open()
        record = self._snapshot(self._file)
        self._file.identity = self._native_identity = record.identity
        if self.owned_new and record.size != 0:
            raise SourceFileError("source_new_file_not_empty")
        data = self._read()
        try:
            stat_identity = self._backend.stat_identity(self._file.value)
        except BaseException as error:
            self._auxiliary.extend(getattr(error, "_source_stat_custody", ()))
            raise
        if (not isinstance(stat_identity, dict)
                or set(stat_identity) != {"device", "file_id", "size", "mtime_ns"}
                or any(type(value) is not int or value < 0 for value in stat_identity.values())
                or stat_identity["size"] != len(data)):
            raise SourceFileError("source_stat_identity_unverified")
        self._snapshot(self._file)
        self._stat_identity = dict(stat_identity)
        self._backup_bytes, self._sha256 = data, _hash(data)

    def _check_open(self):
        if self._closed or self._closing:
            raise SourceFileError("source_closed_or_closing", retained=self)
        if self._quarantined:
            raise SourceFileError("source_mutation_quarantined", retained=self)
        if self._delete_pending:
            raise SourceFileError("source_deletion_pending", retained=self)

    def _read(self):
        for held in self._parents:
            self._snapshot(held)
        before = self._snapshot(self._file)
        if before.size > self._max_bytes:
            raise SourceFileError("source_byte_bound_exceeded")
        data = self._backend.read(self._file.value, self._max_bytes)
        if not isinstance(data, bytes) or len(data) != before.size or len(data) > self._max_bytes:
            raise SourceFileError("source_read_incomplete")
        after = self._snapshot(self._file)
        if after != before:
            raise SourceFileError("source_changed_during_read")
        return data

    def read_bytes(self):
        with self._lock:
            self._check_open()
            try:
                return self._read()
            except BaseException as error:
                reason = error.reason if isinstance(error, SourceFileError) else "source_read_unverified"
                raise SourceFileError(reason, retained=self) from None

    def overwrite(self, data, *, expected_sha256):
        """Explicit same-handle write/truncate/flush/readback; no path reopen."""
        _expected_hash(expected_sha256)
        if not isinstance(data, bytes) or len(data) > self._max_bytes:
            raise ValueError("invalid_source_bytes")
        with self._lock:
            self._check_open()
            before = self.read_bytes()
            if _hash(before) != expected_sha256:
                raise SourceFileError("source_expected_hash_mismatch", retained=self)
            # Publish quarantine BEFORE any mutating API. Nothing clears it
            # until all bytes, final length, durable flush and readback agree.
            self._quarantined = True
            try:
                self._backend.write(self._file.value, data)
                self._backend.truncate(self._file.value, len(data))
                self._backend.flush(self._file.value)
                observed = self._read()
                if observed != data:
                    raise SourceFileError("source_write_readback_mismatch")
                self._sha256 = _hash(observed)
                self._quarantined = False
            except BaseException as error:
                reason = error.reason if isinstance(error, SourceFileError) else "source_write_outcome_unknown"
                raise SourceFileError(reason, retained=self) from None

    def delete_new(self, *, expected_sha256):
        """Request deletion of only this CREATE_NEW object after exact hash.

        Success proves native deletion-pending, not directory-entry removal.
        Other readers may defer removal even after our handle closes.
        """
        _expected_hash(expected_sha256)
        with self._lock:
            self._check_open()
            if not self.owned_new:
                raise SourceFileError("source_existing_delete_forbidden", retained=self)
            if _hash(self.read_bytes()) != expected_sha256:
                raise SourceFileError("source_expected_hash_mismatch", retained=self)
            self._quarantined = True
            try:
                self._backend.delete(self._file.value)
                if not self._snapshot(self._file, allow_delete=True).delete_pending:
                    raise SourceFileError("source_delete_readback_unverified")
                self._delete_pending = True
                self._quarantined = False
            except BaseException as error:
                reason = error.reason if isinstance(error, SourceFileError) else "source_delete_outcome_unknown"
                raise SourceFileError(reason, retained=self) from None

    def close(self):
        """Close leaf before parents; unknown close keeps ancestor custody."""
        with self._lock:
            if self._closed:
                return
            self._closing = True
            try:
                for custody in self._auxiliary:
                    custody.close()
                if self._file is not None:
                    self._file.close()
                for held in reversed(self._parents):
                    held.close()
                self._closed = True
            except BaseException as error:
                self._quarantined = True
                reason = error.reason if isinstance(error, SourceFileError) else "source_close_outcome_unknown"
                raise SourceFileError(reason, retained=self) from None


class _FileTime(C.Structure):
    _fields_ = [("low", C.c_uint32), ("high", C.c_uint32)]


class _ByHandleInfo(C.Structure):
    _fields_ = [("attributes", C.c_uint32), ("creation", _FileTime),
                ("access", _FileTime), ("write", _FileTime),
                ("volume", C.c_uint32), ("size_high", C.c_uint32),
                ("size_low", C.c_uint32), ("links", C.c_uint32),
                ("index_high", C.c_uint32), ("index_low", C.c_uint32)]


class _FileIdInfo(C.Structure):
    _fields_ = [("volume", C.c_uint64), ("file_id", C.c_ubyte * 16)]


class _StandardInfo(C.Structure):
    _fields_ = [("allocation_size", C.c_int64), ("end_of_file", C.c_int64),
                ("links", C.c_uint32), ("delete_pending", C.c_ubyte),
                ("directory", C.c_ubyte)]


class _StatDuplicate:
    """Own a duplicate across CRT transfer; never transfer the original handle."""

    def __init__(self, backend):
        self.backend = backend
        self.handle = self.fd = None
        self.output = C.c_void_p()
        self.duplicate_unknown = self.transfer_unknown = self.close_unknown = False

    def acquire(self, original):
        self.duplicate_unknown = True
        current = self.backend.k.GetCurrentProcess()
        result = self.backend.k.DuplicateHandle(current, original, current,
                                                C.byref(self.output), 0, False, 2)
        if not result:
            if self.output.value is None:
                self.duplicate_unknown = False
            raise SourceFileError("source_stat_duplicate_failed")
        if type(self.output.value) is not int or not 0 < self.output.value < 1 << 63:
            raise SourceFileError("source_stat_duplicate_unverified")
        self.handle, self.duplicate_unknown = self.output.value, False

    def as_fd(self):
        import msvcrt
        self.transfer_unknown = True
        fd = msvcrt.open_osfhandle(self.handle, os.O_RDONLY | getattr(os, "O_BINARY", 0))
        if type(fd) is not int or fd < 0:
            raise SourceFileError("source_stat_transfer_unverified")
        self.fd, self.handle = fd, None
        self.transfer_unknown = False
        return fd

    def close(self):
        if self.duplicate_unknown or self.transfer_unknown or self.close_unknown:
            raise SourceFileError("source_stat_custody_unknown")
        if self.fd is not None:
            self.close_unknown = True
            os.close(self.fd)
            self.fd, self.close_unknown = None, False
        if self.handle is not None:
            self.close_unknown = True
            try:
                self.backend.close(self.handle)
            except SourceFileError as error:
                if error.reason == "source_close_failed" and error.known_failed is True:
                    self.close_unknown = False
                raise
            self.handle, self.close_unknown = None, False


def _bind(dll, name, result, *args):
    function = getattr(dll, name)
    function.restype, function.argtypes = result, args


def _check(result, reason):
    if not result:
        raise SourceFileError(reason, known_failed=True)


class _WindowsBackend:
    def __init__(self):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise SourceFileError("source_platform_unsupported")
        self.k = k = C.WinDLL("kernel32", use_last_error=True)
        ptr, dword, boolean = C.c_void_p, C.c_uint32, C.c_int32
        _bind(k, "CreateFileW", ptr, C.c_wchar_p, dword, dword, ptr, dword, dword, ptr)
        _bind(k, "CreateDirectoryW", boolean, C.c_wchar_p, ptr)
        _bind(k, "CloseHandle", boolean, ptr)
        _bind(k, "GetCurrentProcess", ptr)
        _bind(k, "DuplicateHandle", boolean, ptr, ptr, ptr, C.POINTER(ptr), dword, boolean, dword)
        _bind(k, "GetFileInformationByHandle", boolean, ptr, C.POINTER(_ByHandleInfo))
        _bind(k, "GetFileInformationByHandleEx", boolean, ptr, C.c_int, ptr, dword)
        _bind(k, "GetFinalPathNameByHandleW", dword, ptr, C.c_wchar_p, dword, dword)
        _bind(k, "SetFilePointerEx", boolean, ptr, C.c_int64, C.POINTER(C.c_int64), dword)
        _bind(k, "ReadFile", boolean, ptr, ptr, dword, C.POINTER(dword), ptr)
        _bind(k, "WriteFile", boolean, ptr, ptr, dword, C.POINTER(dword), ptr)
        _bind(k, "SetEndOfFile", boolean, ptr)
        _bind(k, "FlushFileBuffers", boolean, ptr)
        _bind(k, "SetFileInformationByHandle", boolean, ptr, C.c_int, ptr, dword)

    def open(self, path, *, directory, new):
        if directory and new:
            raise SourceFileError("source_directory_creation_forbidden", known_failed=True)
        access = 0x00100080 if directory else 0xC0000000 | (0x00010000 if new else 0)
        share = 1
        flags = 0x00200000 | (0x02000000 if directory else 0)
        handle = self.k.CreateFileW("\\\\?\\" + path, access, share, None,
                                    1 if new else 3, flags, None)
        if handle in {None, C.c_void_p(-1).value}:
            raise SourceFileError("source_open_failed", known_failed=True,
                                  win32_error=C.get_last_error())
        return handle

    def create_directory(self, path):
        if self.k.CreateDirectoryW("\\\\?\\" + path, None):
            return True
        error = C.get_last_error()
        if error == 183:  # ERROR_ALREADY_EXISTS, still requires handle validation.
            return False
        raise SourceFileError("source_directory_create_failed", known_failed=True,
                              win32_error=error)

    def close(self, handle):
        _check(self.k.CloseHandle(handle), "source_close_failed")

    def snapshot(self, handle):
        info, file_id, standard = _ByHandleInfo(), _FileIdInfo(), _StandardInfo()
        _check(self.k.GetFileInformationByHandle(handle, C.byref(info)), "source_info_unavailable")
        _check(self.k.GetFileInformationByHandleEx(handle, 18, C.byref(file_id), C.sizeof(file_id)),
               "source_file_id_unavailable")
        _check(self.k.GetFileInformationByHandleEx(handle, 1, C.byref(standard), C.sizeof(standard)),
               "source_standard_info_unavailable")
        buffer = C.create_unicode_buffer(32768)
        length = self.k.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not 0 < length < len(buffer) or not buffer.value.startswith("\\\\?\\"):
            raise SourceFileError("source_final_path_unavailable")
        size = (int(info.size_high) << 32) | int(info.size_low)
        if (size != standard.end_of_file or info.links != standard.links
                or bool(info.attributes & 0x10) != bool(standard.directory)):
            raise SourceFileError("source_native_metadata_disagrees")
        identity = NativeFileIdentity(int(info.volume),
            (int(info.index_high) << 32) | int(info.index_low),
            int(file_id.volume), bytes(file_id.file_id).hex())
        return FileSnapshot(identity, buffer.value[4:], size, int(info.attributes),
                            int(info.links), bool(standard.delete_pending))

    def stat_identity(self, handle):
        owner = _StatDuplicate(self)
        try:
            owner.acquire(handle)
            stat = os.fstat(owner.as_fd())
            result = {"device": stat.st_dev, "file_id": stat.st_ino,
                      "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
            owner.close()
            return result
        except BaseException as error:
            try:
                owner.close()
            except BaseException:
                error._source_stat_custody = (owner,)
            raise

    def _seek(self, handle, offset):
        actual = C.c_int64()
        _check(self.k.SetFilePointerEx(handle, offset, C.byref(actual), 0), "source_seek_failed")
        if actual.value != offset:
            raise SourceFileError("source_seek_unverified")

    def read(self, handle, max_bytes):
        self._seek(handle, 0)
        result = bytearray()
        while len(result) <= max_bytes:
            size = min(65536, max_bytes + 1 - len(result))
            buffer, read = C.create_string_buffer(size), C.c_uint32()
            _check(self.k.ReadFile(handle, buffer, size, C.byref(read), None), "source_read_failed")
            if read.value > size:
                raise SourceFileError("source_read_count_invalid")
            if read.value == 0:
                return bytes(result)
            result.extend(buffer.raw[:read.value])
        raise SourceFileError("source_byte_bound_exceeded")

    def write(self, handle, data):
        self._seek(handle, 0)
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 65536]
            buffer, written = C.create_string_buffer(chunk), C.c_uint32()
            _check(self.k.WriteFile(handle, buffer, len(chunk), C.byref(written), None),
                   "source_write_failed")
            if not 0 < written.value <= len(chunk):
                raise SourceFileError("source_write_count_invalid")
            offset += written.value

    def truncate(self, handle, size):
        self._seek(handle, size)
        _check(self.k.SetEndOfFile(handle), "source_truncate_failed")

    def flush(self, handle):
        _check(self.k.FlushFileBuffers(handle), "source_flush_failed")

    def delete(self, handle):
        disposition = C.c_ubyte(1)
        _check(self.k.SetFileInformationByHandle(handle, 4, C.byref(disposition), C.sizeof(disposition)),
               "source_delete_failed")
