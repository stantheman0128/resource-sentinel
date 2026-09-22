"""Original-wrapper native launch observations, not serialized permission.

Capture uses the exact duplicated standard handles passed to CreateProcess.
The peer-authenticated BindRoot path retains this record with the original
wrapper/root objects. Same-SID cooperative processes can forge their own data;
this is scope consistency, not a hostile-process security boundary.

GetConsoleWindow also exists under ConPTY. Its raw window class/visibility is
recorded without claiming that an HWND proves a classic or visible console.
CHAR without GetConsoleMode is called character, never assumed to be NUL.
No command text, environment, paths, title, or handle locator is serialized.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re

from .contracts import IdentityStatus, ProcessIdentity
from .identity import VerifiedProcess, _known_close_failure, retry_identity_cleanup
from .store import LifecycleError


def _fail(reason="launch_topology_unverified"):
    raise LifecycleError(reason)


def _digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True)
class LaunchTopology:
    schema_version: int
    shell_kind: str
    shell_image_sha256: str
    python_image_sha256: str
    command_host_image_sha256: str
    stdio_types: tuple[str, str, str]
    stdio_console_modes: tuple[int | None, int | None, int | None]
    console_attached: bool
    console_window_class: str
    console_window_visible: bool
    console_input_cp: int | None
    console_output_cp: int | None
    creation_flags: int
    startup_flags: int
    inheritance: str

    def __post_init__(self):
        if (type(self.schema_version) is not int or self.schema_version != 1 or
                type(self.shell_kind) is not str or self.shell_kind not in {"powershell51", "pwsh", "other"} or
                not all(_digest(value) for value in (self.shell_image_sha256,
                    self.python_image_sha256, self.command_host_image_sha256)) or
                type(self.stdio_types) is not tuple or len(self.stdio_types) != 3 or
                any(type(value) is not str or value not in {"pipe", "disk", "console", "character"} for value in self.stdio_types) or
                type(self.stdio_console_modes) is not tuple or len(self.stdio_console_modes) != 3 or
                any((kind == "console" and (type(mode) is not int or not 0 <= mode <= 0xFFFFFFFF)) or
                    (kind != "console" and mode is not None)
                    for kind, mode in zip(self.stdio_types, self.stdio_console_modes)) or
                type(self.console_attached) is not bool or type(self.console_window_visible) is not bool or
                type(self.console_window_class) is not str or len(self.console_window_class) > 128 or
                any(ord(char) < 32 for char in self.console_window_class) or
                (not self.console_attached and (self.console_window_class or self.console_window_visible)) or
                (self.console_attached and not self.console_window_class) or
                any((self.console_attached and (type(cp) is not int or not 0 < cp <= 65535)) or
                    (not self.console_attached and cp is not None)
                    for cp in (self.console_input_cp, self.console_output_cp)) or
                type(self.creation_flags) is not int or self.creation_flags != 0x80000 or
                type(self.startup_flags) is not int or self.startup_flags != 0x100 or
                self.inheritance != "job_list_handle_list"):
            _fail("launch_topology_invalid")

    def to_dict(self):
        result = asdict(self)
        result["stdio_types"] = list(self.stdio_types)
        result["stdio_console_modes"] = list(self.stdio_console_modes)
        return result

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            _fail("launch_topology_invalid")
        if type(value["stdio_types"]) is not list or type(value["stdio_console_modes"]) is not list:
            _fail("launch_topology_invalid")
        return cls(**(value | {name: tuple(value[name]) for name in ("stdio_types", "stdio_console_modes")}))

    @property
    def sha256(self):
        return hashlib.sha256(json.dumps(self.to_dict(), sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class OriginalLaunchProvenance:
    wrapper_identity: ProcessIdentity
    parent_identity: ProcessIdentity
    root_identity: ProcessIdentity
    topology: LaunchTopology

    def __post_init__(self):
        if (type(self.wrapper_identity) is not ProcessIdentity or
                type(self.parent_identity) is not ProcessIdentity or
                type(self.root_identity) is not ProcessIdentity or
                type(self.topology) is not LaunchTopology or
                self.wrapper_identity == self.parent_identity or
                self.root_identity in {self.wrapper_identity, self.parent_identity} or
                self.wrapper_identity.logon_id != self.parent_identity.logon_id or
                self.wrapper_identity.logon_id != self.root_identity.logon_id or
                self.root_identity.created_filetime_100ns < self.wrapper_identity.created_filetime_100ns or
                self.parent_identity.created_filetime_100ns > self.wrapper_identity.created_filetime_100ns):
            _fail("launch_provenance_invalid")

    def to_dict(self):
        return dict(wrapper_identity=self.wrapper_identity.to_dict(),
            parent_identity=self.parent_identity.to_dict(), root_identity=self.root_identity.to_dict(),
            topology=self.topology.to_dict())

    @classmethod
    def from_dict(cls, value):
        if type(value) is not dict or set(value) != {"wrapper_identity", "parent_identity", "root_identity", "topology"}:
            _fail("launch_provenance_invalid")
        return cls(ProcessIdentity.from_dict(value["wrapper_identity"]),
            ProcessIdentity.from_dict(value["parent_identity"]), ProcessIdentity.from_dict(value["root_identity"]),
            LaunchTopology.from_dict(value["topology"]))


def _image_digest(path):
    """Bounded actual image bytes, rejecting changes during the read."""
    path = Path(path)
    before = path.stat()
    if not path.is_absolute() or not 0 < before.st_size <= 64 * 1024 * 1024:
        _fail("launch_image_unverified")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns"):
            if getattr(before, name) != getattr(opened, name):
                _fail("launch_image_changed")
        remaining = before.st_size
        while remaining:
            block = stream.read(min(remaining, 1024 * 1024))
            if not block:
                _fail("launch_image_changed")
            remaining -= len(block)
            digest.update(block)
        if stream.read(1):
            _fail("launch_image_changed")
    after = path.stat()
    if any(getattr(before, name) != getattr(after, name)
           for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")):
        _fail("launch_image_changed")
    return digest.hexdigest()


class NativeLaunchCapture:
    """Single-use observation owner. Caller retains it before capture().

    Identity handles are query-only. Any failed/ambiguous native cleanup stays
    reachable on this object and the original error; capture is never retried.
    No destructor or best-effort blind close can discard uncertain ownership.
    """
    def __init__(self, *, backend=None, current=None, parent=None, image_digest=None):
        self._backend = backend
        self._current = current or VerifiedProcess.current
        self._parent = parent or (lambda: VerifiedProcess._open(os.getppid()))
        self._hash = image_digest or _image_digest
        self._owners = []
        self._close_errors = {}
        self._attempted = False
        self.failure = None
        self.provenance = None
        self._prepared = None
        self._prepared_images = ()
        self._stdio_handles = ()
        self._finalize_attempted = False

    @property
    def cleanup_pending(self):
        return bool(self._owners or getattr(self.failure, "_identity_handle_cleanup", ()))

    def capture(self, *, application, stdio_handles, creation_flags, startup_flags):
        if self._attempted:
            _fail("launch_capture_already_attempted")
        self._attempted = True
        primary = None
        result = None
        try:
            if type(stdio_handles) not in {tuple, list} or len(stdio_handles) != 3:
                _fail("launch_stdio_unverified")
            backend = self._backend = self._backend or _WindowsTopologyBackend()
            current = self._current()
            self._owners.append(current)
            parent = self._parent()
            self._owners.append(parent)
            if (current.observe().status is not IdentityStatus.ALIVE or
                    parent.observe().status is not IdentityStatus.ALIVE or
                    backend.in_parent_job(current) is not False):
                _fail()
            python_path, shell_path = backend.image_path(current), backend.image_path(parent)
            kind = {"powershell.exe": "powershell51", "pwsh.exe": "pwsh"}.get(
                Path(shell_path).name.lower(), "other")
            console = backend.console_scope()
            stdio = tuple(backend.stdio_observation(value) for value in stdio_handles)
            topology = LaunchTopology(
                1, kind, self._hash(shell_path), self._hash(python_path), self._hash(application),
                tuple(value[0] for value in stdio), tuple(value[1] for value in stdio),
                *console, creation_flags, startup_flags, "job_list_handle_list")
            if (current.identity == parent.identity or current.identity.logon_id != parent.identity.logon_id or
                    parent.identity.created_filetime_100ns > current.identity.created_filetime_100ns):
                _fail("launch_parent_unverified")
            result = (current.identity, parent.identity, topology)
            self._stdio_handles = tuple(stdio_handles)
            self._prepared_images = ((python_path, topology.python_image_sha256),
                (shell_path, topology.shell_image_sha256), (application, topology.command_host_image_sha256))
            if current.observe().status is not IdentityStatus.ALIVE or parent.observe().status is not IdentityStatus.ALIVE:
                _fail()
        except BaseException as error:
            primary = error
        for owner in tuple(reversed(self._owners)):
            try:
                owner.close()
            except BaseException as error:
                self._close_errors[id(owner)] = error
                if primary is None:
                    primary = error
            else:
                self._owners.remove(owner)
        if primary is not None:
            self.failure = primary
            primary._launch_capture_owner = self
            raise primary
        self._prepared = result
        return result

    def confirm_launch(self):
        """Cheap same-handle recheck adjacent to Create; never hash/open here."""
        if self._prepared is None or self.failure is not None:
            _fail("launch_capture_unprepared")
        topology = self._prepared[2]
        stdio = tuple(self._backend.stdio_observation(handle) for handle in self._stdio_handles)
        observed = (tuple(value[0] for value in stdio), tuple(value[1] for value in stdio),
                    *self._backend.console_scope())
        expected = (topology.stdio_types, topology.stdio_console_modes, topology.console_attached,
                    topology.console_window_class, topology.console_window_visible,
                    topology.console_input_cp, topology.console_output_cp)
        if observed != expected:
            _fail("launch_topology_changed")

    def retry_cleanup(self):
        """Retry only positively failed closes; ambiguous outcomes stay held."""
        for owner in tuple(self._owners):
            previous = self._close_errors.get(id(owner))
            if previous is None or not _known_close_failure(previous):
                continue
            try:
                owner.close()
            except BaseException as error:
                self._close_errors[id(owner)] = error
            else:
                self._owners.remove(owner)
                self._close_errors.pop(id(owner), None)
        # A constructor can fail before returning an owner; its existing exact
        # identity cleanup contract owns those handles and guards unknown closes.
        if self.failure is not None and getattr(self.failure, "_identity_handle_cleanup", ()):
            retry_identity_cleanup(self.failure)
        if self.cleanup_pending:
            error = LifecycleError("launch_capture_cleanup_unverified")
            error._launch_capture_owner = self
            raise error

    def bind_created(self, process):
        """Called once on the original CreateProcess result, including fast exit."""
        if self._prepared is None or self.failure is not None or self._finalize_attempted:
            _fail("launch_capture_finalize_unavailable")
        self._finalize_attempted = True
        try:
            wrapper, parent, topology = self._prepared
            root = process.full_identity(expected_logon_id=wrapper.logon_id)
            if self._hash(self._backend.created_image_path(process)) != topology.command_host_image_sha256:
                _fail("launch_created_image_mismatch")
            if any(self._hash(path) != digest for path, digest in self._prepared_images):
                _fail("launch_image_changed")
            self.confirm_launch()
            self.provenance = OriginalLaunchProvenance(wrapper, parent, root, topology)
            return self.provenance
        except BaseException as error:
            self.failure = error
            error._launch_capture_owner = self
            raise


class _WindowsTopologyBackend:
    def __init__(self):
        if os.name != "nt":
            _fail("launch_topology_windows_required")
        self.kernel = C.WinDLL("kernel32", use_last_error=True)
        self.user = C.WinDLL("user32", use_last_error=True)
        signatures = ((self.kernel, "QueryFullProcessImageNameW", C.c_int, (C.c_void_p, C.c_uint32, C.c_wchar_p, C.POINTER(C.c_uint32))),
            (self.kernel, "GetFileType", C.c_uint32, (C.c_void_p,)),
            (self.kernel, "GetConsoleMode", C.c_int, (C.c_void_p, C.POINTER(C.c_uint32))),
            (self.kernel, "GetConsoleWindow", C.c_void_p, ()),
            (self.kernel, "GetConsoleCP", C.c_uint32, ()),
            (self.kernel, "GetConsoleOutputCP", C.c_uint32, ()),
            (self.user, "GetClassNameW", C.c_int, (C.c_void_p, C.c_wchar_p, C.c_int)),
            (self.user, "IsWindowVisible", C.c_int, (C.c_void_p,)),
            (self.kernel, "IsProcessInJob", C.c_int, (C.c_void_p, C.c_void_p, C.POINTER(C.c_int))))
        for library, name, result, arguments in signatures:
            function = getattr(library, name)
            function.restype, function.argtypes = result, arguments

    def image_path(self, process):
        with process._lock:
            if process._handle is None or process._close_outcome_unknown:
                _fail()
            return self._image_path(process._handle)

    def created_image_path(self, process):
        with process._lock:
            return self._image_path(process._live_handle())

    def _image_path(self, handle):
        if type(handle) is not int or handle <= 0:
            _fail("launch_image_unverified")
        buffer, size = C.create_unicode_buffer(32768), C.c_uint32(32768)
        if not self.kernel.QueryFullProcessImageNameW(handle, 0, buffer, C.byref(size)) or not 0 < size.value < 32768:
            _fail("launch_image_unverified")
        return buffer.value

    def in_parent_job(self, process):
        with process._lock:
            member = C.c_int()
            if not self.kernel.IsProcessInJob(process._handle, None, C.byref(member)):
                _fail()
            return bool(member.value)

    def stdio_observation(self, handle):
        if type(handle) is not int or handle <= 0:
            _fail("launch_stdio_unverified")
        C.set_last_error(0)
        kind = self.kernel.GetFileType(handle)
        if kind == 1:
            return "disk", None
        if kind == 3:
            return "pipe", None
        if kind == 2:
            mode = C.c_uint32()
            if self.kernel.GetConsoleMode(handle, C.byref(mode)):
                return "console", mode.value
            if C.get_last_error() == 6:  # documented non-console INVALID_HANDLE
                return "character", None
            _fail("launch_console_mode_unverified")
        _fail("launch_stdio_query_failed" if C.get_last_error() else "launch_stdio_type_unknown")

    def console_scope(self):
        window = self.kernel.GetConsoleWindow()
        if not window:
            return False, "", False, None, None
        name = C.create_unicode_buffer(129)
        length = self.user.GetClassNameW(window, name, len(name))
        if not 0 < length < 128:
            _fail("launch_console_unverified")
        return (True, name.value, bool(self.user.IsWindowVisible(window)),
                int(self.kernel.GetConsoleCP()), int(self.kernel.GetConsoleOutputCP()))
