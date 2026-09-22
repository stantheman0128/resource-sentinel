"""Bounded protected host locators; no admission, recovery or launch authority.

Only a supervisor publishes the canonical instance. A guardian publishes its
own child metadata, cross-bound to the original supervisor process/instance.
Consumers must still authenticate every pipe peer and live response. Neither a
descriptor, its state nor its existence supplies a native custody witness.

Readers never create directories, repair ACLs, or construct ledger services.
Writers serialize compare-and-publication under a separate namespace mutex and
use the recovery journal's protected staging/write-through primitives. This is
the cooperative same-logon model, not isolation from a hostile same-SID actor.
"""
from __future__ import annotations

from contextlib import contextmanager
import ctypes as C
from dataclasses import dataclass
import os
from pathlib import Path
from uuid import UUID, uuid4, uuid5, NAMESPACE_URL

from .contracts import (
    Contract, ContractViolation, IdentityStatus, ProcessIdentity, _identifier,
    _integer, _object, _version, strict_json_loads,
)
from .identity import VerifiedProcess
from .pipe_windows import NativePipeEndpoint, NativePipeError
from .recovery_journal import (
    RecoveryJournalError, _binary_file, _publish_namespace, _safe_stat,
)
from . import windows as _security


MAX_DESCRIPTOR_BYTES = 32 * 1024
_ROLES = frozenset({"operator", "launch", "query", "control"})
_STATES = frozenset({"starting", "ready", "draining", "unavailable"})
_FILE_ACCESS = 0x001F01FF


@contextmanager
def _native_resource(value, release, reason):
    """Retain native owners even when the only error is scope cleanup."""
    try:
        yield value
    except BaseException as primary:
        try:
            release(value)
        except BaseException as cleanup:
            _security._retain_native(primary, release, value, reason, cleanup)
        raise
    else:
        try:
            release(value)
        except BaseException as cleanup:
            _security._retain_native(cleanup, release, value, reason, cleanup)
            raise


class DiscoveryError(RuntimeError):
    """Stable sanitized reason; a failed publication may already be visible."""
    def __init__(self, reason, *, publication_may_have_occurred=False):
        self.reason = reason
        self.publication_may_have_occurred = publication_may_have_occurred
        super().__init__(reason)


def _uuid(value, name):
    try:
        parsed = UUID(value) if type(value) is str else None
        valid = parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        valid = False
    if not valid:
        raise ContractViolation(name + ": canonical nonzero UUID required")


def _logon(value):
    match = _security._LOGON_SID.fullmatch(value) if type(value) is str else None
    if match is None or any(int(item) > 0xFFFFFFFF for item in match.groups()):
        raise ContractViolation("logon_id: logon SID required")


@dataclass(frozen=True)
class EndpointLocator(Contract):
    role: str
    endpoint: NativePipeEndpoint

    def __post_init__(self):
        if type(self.role) is not str or self.role not in _ROLES:
            raise ContractViolation("role: unknown endpoint role")
        if type(self.endpoint) is not NativePipeEndpoint:
            raise ContractViolation("endpoint: native endpoint required")
        # Revalidate the complete nested identity, even for in-process values.
        ProcessIdentity.from_dict(self.endpoint.server_identity.to_dict())
        NativePipeEndpoint(self.endpoint.logon_id, self.endpoint.instance_id,
                           self.endpoint.server_identity)

    def to_dict(self):
        return {"role": self.role, "endpoint": {
            "logon_id": self.endpoint.logon_id,
            "instance_id": self.endpoint.instance_id,
            "server_identity": self.endpoint.server_identity.to_dict()}}

    @classmethod
    def from_dict(cls, value):
        data = _object(value, cls)
        nested = data["endpoint"]
        if type(nested) is not dict or set(nested) != {"logon_id", "instance_id", "server_identity"}:
            raise ContractViolation("endpoint: missing or unknown fields")
        try:
            data["endpoint"] = NativePipeEndpoint(nested["logon_id"], nested["instance_id"],
                                                 ProcessIdentity.from_dict(nested["server_identity"]))
        except NativePipeError:
            raise ContractViolation("endpoint: invalid binding") from None
        return cls(**data)


@dataclass(frozen=True)
class HostDescriptor(Contract):
    instance_id: str
    policy_instance_id: str
    logon_id: str
    guardian_epoch: str
    host_role: str
    host_identity: ProcessIdentity
    endpoints: tuple[EndpointLocator, ...]
    state: str
    revision: int
    parent_identity: ProcessIdentity | None = None
    parent_instance_id: str | None = None
    schema_version: int = 1
    guardian: HostDescriptor | None = None
    tool: str = "resource-sentinel"
    protocol_version: int = 1

    def __post_init__(self):
        _version(self.schema_version)
        _version(self.protocol_version)
        if type(self.tool) is not str or self.tool != "resource-sentinel":
            raise ContractViolation("tool: unsupported implementation")
        _uuid(self.instance_id, "instance_id")
        _uuid(self.policy_instance_id, "policy_instance_id")
        _logon(self.logon_id)
        _identifier(self.guardian_epoch, "guardian_epoch")
        _integer(self.revision, "revision", 1)
        if type(self.host_identity) is not ProcessIdentity or self.host_identity.logon_id != self.logon_id:
            raise ContractViolation("host_identity: logon binding required")
        if type(self.host_role) is not str or self.host_role not in {"supervisor", "guardian"}:
            raise ContractViolation("host_role: unknown host role")
        if type(self.state) is not str or self.state not in _STATES:
            raise ContractViolation("state: unknown state")
        if type(self.endpoints) is not tuple or not 1 <= len(self.endpoints) <= len(_ROLES):
            raise ContractViolation("endpoints: bounded tuple required")
        roles, instances = set(), set()
        for locator in self.endpoints:
            if type(locator) is not EndpointLocator:
                raise ContractViolation("endpoints: typed locator required")
            if (locator.role in roles or locator.endpoint.instance_id in instances or
                    locator.endpoint.server_identity != self.host_identity or
                    locator.endpoint.logon_id != self.logon_id):
                raise ContractViolation("endpoints: duplicate or mismatched binding")
            roles.add(locator.role)
            instances.add(locator.endpoint.instance_id)
        if "operator" not in roles:
            raise ContractViolation("endpoints: operator endpoint required")
        if self.host_role == "guardian":
            if (type(self.parent_identity) is not ProcessIdentity or
                    self.parent_identity.logon_id != self.logon_id or
                    self.parent_identity == self.host_identity or self.guardian is not None):
                raise ContractViolation("parent_identity: exact supervisor binding required")
            _uuid(self.parent_instance_id, "parent_instance_id")
            if self.parent_instance_id == self.instance_id:
                raise ContractViolation("parent_instance_id: distinct instance required")
            if self.state == "ready" and not {"launch", "query", "control"} <= roles:
                raise ContractViolation("endpoints: ready guardian listeners required")
        else:
            if self.parent_identity is not None or self.parent_instance_id is not None or roles != {"operator"}:
                raise ContractViolation("supervisor: unexpected parent or endpoint")
            if self.guardian is not None:
                self._check_child(self.guardian)
                if self.guardian.endpoints and instances.intersection(
                        item.endpoint.instance_id for item in self.guardian.endpoints):
                    raise ContractViolation("endpoints: duplicate instance")
            if self.state == "ready" and (self.guardian is None or self.guardian.state != "ready"):
                raise ContractViolation("guardian: ready child required")

    def _check_child(self, child):
        if (type(child) is not HostDescriptor or child.host_role != "guardian" or
                child.parent_identity != self.host_identity or child.parent_instance_id != self.instance_id or
                child.policy_instance_id != self.policy_instance_id or child.logon_id != self.logon_id or
                child.guardian_epoch != self.guardian_epoch):
            raise ContractViolation("guardian: child binding mismatch")

    def to_dict(self):
        result = {name: getattr(self, name) for name in self.__dataclass_fields__}
        result["host_identity"] = self.host_identity.to_dict()
        result["parent_identity"] = None if self.parent_identity is None else self.parent_identity.to_dict()
        result["endpoints"] = [item.to_dict() for item in self.endpoints]
        result["guardian"] = None if self.guardian is None else self.guardian.to_dict()
        return result

    @classmethod
    def from_dict(cls, value):
        return cls._decode(value, child=False)

    @classmethod
    def _decode(cls, value, *, child):
        data = _object(value, cls)
        data["host_identity"] = ProcessIdentity.from_dict(data["host_identity"])
        if data["parent_identity"] is not None:
            data["parent_identity"] = ProcessIdentity.from_dict(data["parent_identity"])
        if type(data["endpoints"]) is not list or not 1 <= len(data["endpoints"]) <= 4:
            raise ContractViolation("endpoints: bounded array required")
        data["endpoints"] = tuple(EndpointLocator.from_dict(item) for item in data["endpoints"])
        if data["guardian"] is not None:
            if child:
                raise ContractViolation("guardian: nested topology forbidden")
            data["guardian"] = cls._decode(data["guardian"], child=True)
        return cls(**data)


class _WindowsProtection:
    """Explicit logon-only protected file ACLs, verified using native readback."""
    def __init__(self, logon_id):
        self.logon_id = logon_id
        self.api = _security._WindowsMutexBackend()
        self.owner_sid = self.api.current_owner_sid()
        k, a = self.api.kernel, self.api.security
        ptr, dword = C.c_void_p, C.c_uint32
        _security._bind(k, "CreateDirectoryW", C.c_int32, C.c_wchar_p,
                        C.POINTER(_security._SecurityAttributes))
        _security._bind(k, "CreateFileW", ptr, C.c_wchar_p, dword, dword, ptr, dword, dword, ptr)
        _security._bind(a, "GetSecurityDescriptorDacl", C.c_int32, ptr,
                        C.POINTER(C.c_int32), C.POINTER(ptr), C.POINTER(C.c_int32))
        _security._bind(a, "SetNamedSecurityInfoW", dword, C.c_wchar_p, C.c_int, dword,
                        ptr, ptr, ptr, ptr)
        self.mutex = None

    @contextmanager
    def _descriptor(self):
        pointer = C.c_void_p()
        text = f"O:{self.owner_sid}D:P(A;;0x{_FILE_ACCESS:08x};;;{self.logon_id})"
        _security._check(self.api.security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text, 1, C.byref(pointer), None), "discovery_security_build_failed")
        with _native_resource(pointer, self.api.free, "discovery_security_free_failed"):
            yield pointer

    def create_directory(self, path):
        with self._descriptor() as descriptor:
            attributes = _security._SecurityAttributes(C.sizeof(_security._SecurityAttributes), descriptor, False)
            if not self.api.kernel.CreateDirectoryW(str(path), C.byref(attributes)):
                if C.get_last_error() != 183:
                    raise DiscoveryError("discovery_directory_create_failed")
        self.verify(path, directory=True)

    def protect_file(self, path):
        with self._descriptor() as descriptor:
            # Only our exclusively created empty staging file; do not request
            # owner takeover or assume WRITE_OWNER. Its original owner is still
            # required by verify(). No fallback widens this protected DACL.
            # https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow
            present, defaulted, dacl = C.c_int32(), C.c_int32(), C.c_void_p()
            _security._check(self.api.security.GetSecurityDescriptorDacl(
                descriptor, C.byref(present), C.byref(dacl), C.byref(defaulted)),
                "discovery_security_invalid")
            if not present.value or defaulted.value or not dacl.value:
                raise DiscoveryError("discovery_security_invalid")
            code = self.api.security.SetNamedSecurityInfoW(str(path), 1, 0x80000004,
                                                          None, None, dacl, None)
            if code:
                raise DiscoveryError("discovery_security_write_failed")
        self.verify(path, directory=False)

    def verify(self, path, *, directory):
        handle = self.api.kernel.CreateFileW(str(path), 0x00020000, 3, None, 3,
                                             0x02200000, None)
        if handle in (None, C.c_void_p(-1).value):
            raise DiscoveryError("discovery_security_open_failed")
        with _native_resource(handle, self.api.close, "discovery_security_handle_close_failed"):
            owner, dacl, descriptor = (C.c_void_p() for _ in range(3))
            # SE_FILE_OBJECT, never the kernel-object type used by the mutex.
            code = self.api.security.GetSecurityInfo(handle, 1, 5, C.byref(owner), None,
                                                     C.byref(dacl), None, C.byref(descriptor))
            if code:
                raise DiscoveryError("discovery_security_unavailable")
            with _native_resource(descriptor, self.api.free, "discovery_security_free_failed"):
                size = int(self.api.security.GetSecurityDescriptorLength(descriptor)) if descriptor.value else 0
                if not 20 <= size <= 65536:
                    raise DiscoveryError("discovery_security_invalid")
                start, end = descriptor.value, descriptor.value + size
                if self.api._sid_text(owner.value, start, end)[0] != self.owner_sid:
                    raise DiscoveryError("discovery_security_owner_mismatch")
                control, revision = C.c_uint16(), C.c_uint32()
                _security._check(self.api.security.GetSecurityDescriptorControl(
                    descriptor, C.byref(control), C.byref(revision)), "discovery_security_unavailable")
                if (control.value & 0x1004 != 0x1004 or control.value & 0x0009 or
                        not dacl.value or not start <= dacl.value <= end - C.sizeof(_security._Acl)):
                    raise DiscoveryError("discovery_security_dacl_mismatch")
                acl = _security._Acl.from_address(dacl.value)
                if (acl.revision != 2 or acl.reserved or acl.reserved2 or acl.ace_count != 1 or
                        acl.size < C.sizeof(_security._Acl) + C.sizeof(_security._AceHeader) + 8 or
                        dacl.value + acl.size > end):
                    raise DiscoveryError("discovery_security_dacl_mismatch")
                ace_pointer = dacl.value + C.sizeof(_security._Acl)
                ace = _security._AceHeader.from_address(ace_pointer)
                if (ace.kind != 0 or ace.flags != 0 or ace.mask != _FILE_ACCESS or
                        ace.size != acl.size - C.sizeof(_security._Acl)):
                    raise DiscoveryError("discovery_security_dacl_mismatch")
                sid, sid_size = self.api._sid_text(ace_pointer + C.sizeof(_security._AceHeader),
                    ace_pointer + C.sizeof(_security._AceHeader), ace_pointer + ace.size)
                if sid != self.logon_id or ace.size != C.sizeof(_security._AceHeader) + sid_size:
                    raise DiscoveryError("discovery_security_dacl_mismatch")

    @contextmanager
    def write_scope(self, directory):
        # Stable per namespace, separate from any actual POLICY binding. Keep
        # the original mutex after errors; unknown cleanup cannot be retried by
        # creating another owner. The enclosing discovery object quarantines it.
        if self.mutex is None:
            key = str(uuid5(NAMESPACE_URL, "resource-sentinel:discovery:" + os.path.normcase(str(directory))))
            self.mutex = _security.NativePolicyMutex(self.logon_id, key)
        with self.mutex.acquire(timeout_ms=250):
            yield

    def close(self):
        if self.mutex is not None:
            self.mutex.close()


def _failure(reason, error, *, uncertain=False):
    result = DiscoveryError(reason, publication_may_have_occurred=uncertain)
    # Preserve cleanup witnesses without exposing their native values or text.
    result._discovery_source_error = error
    return result


class HostDiscovery:
    """Read-only construction; only explicit publication provisions storage.

    ``protection``/``publisher`` are trusted in-process native fixture seams,
    never configuration/IPC fields. Protection implements create_directory,
    protect_file, verify(path, directory=...), write_scope(directory), close.
    Production defaults always require native Windows ACLs and publication.
    """
    def __init__(self, data_dir, *, logon_id, protection=None, publisher=None):
        try:
            _logon(logon_id)
            path = Path(data_dir)
            if (not path.is_absolute() or len(path.parts) > 128 or len(str(path)) > 32000 or
                    "\x00" in str(path) or ".." in path.parts or
                    (os.name == "nt" and (len(path.drive) != 2 or path.drive[1] != ":"))):
                raise ValueError
        except (ContractViolation, TypeError, ValueError):
            raise DiscoveryError("discovery_directory_invalid") from None
        if publisher is not None and not callable(publisher):
            raise DiscoveryError("discovery_publisher_invalid")
        if protection is not None and any(not callable(getattr(protection, method, None)) for method in
                ("create_directory", "protect_file", "verify", "write_scope", "close")):
            raise DiscoveryError("discovery_protection_invalid")
        self.data_dir, self.directory, self.logon_id = path, path / "adaptive-host", logon_id
        self._protection = protection
        self._publisher = _publish_namespace if publisher is None else publisher
        self._ancestors = tuple(reversed(self.directory.parents)) + (self.directory,)
        self._directory_ids = None
        self._quarantined = False
        self._retained_error = None

    def _protect(self):
        if self._protection is None:
            self._protection = _WindowsProtection(self.logon_id)
        return self._protection

    def _inspect(self, *, include_namespace=True):
        paths = self._ancestors if include_namespace else self._ancestors[:-1]
        return tuple(_safe_stat(os.lstat(path), directory=True) for path in paths)

    def _check(self):
        observed = self._inspect()
        if self._directory_ids is None:
            self._directory_ids = observed
        elif self._directory_ids != observed:
            raise DiscoveryError("discovery_directory_changed")
        if self._protect().verify(self.directory, directory=True) is not None:
            raise DiscoveryError("discovery_security_unverified")
        if self._inspect() != observed:
            raise DiscoveryError("discovery_directory_changed")

    def _provision(self):
        before = self._inspect(include_namespace=False)
        try:
            os.lstat(self.directory)
        except FileNotFoundError:
            if self._protect().create_directory(self.directory) is not None:
                raise DiscoveryError("discovery_security_unverified")
        if self._inspect(include_namespace=False) != before:
            raise DiscoveryError("discovery_directory_changed")
        self._check()

    @staticmethod
    def _owner(process, identity):
        if not isinstance(process, VerifiedProcess) or process.identity != identity:
            raise DiscoveryError("discovery_owner_mismatch")
        try:
            observed = process.observe()
        except Exception as error:
            raise _failure("discovery_owner_unverified", error) from None
        if observed.identity != identity or observed.status is not IdentityStatus.ALIVE:
            raise DiscoveryError("discovery_owner_unverified")

    def _record(self, value):
        try:
            if type(value) is not HostDescriptor:
                raise ContractViolation("descriptor required")
            encoded = value.to_json().encode("utf-8")
            if len(encoded) > MAX_DESCRIPTOR_BYTES or HostDescriptor.from_json(encoded) != value:
                raise ContractViolation("descriptor invalid")
        except (ContractViolation, TypeError, ValueError, NativePipeError):
            raise DiscoveryError("discovery_invalid") from None
        if value.logon_id != self.logon_id:
            raise DiscoveryError("discovery_logon_mismatch")
        return encoded

    def _read(self, path):
        try:
            self._check()
            before = os.lstat(path)
            fingerprint = _safe_stat(before)
            if before.st_size > MAX_DESCRIPTOR_BYTES:
                raise DiscoveryError("discovery_invalid")
            if self._protect().verify(path, directory=False) is not None:
                raise DiscoveryError("discovery_security_unverified")
            with _binary_file(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if _safe_stat(opened) != fingerprint or opened.st_size > MAX_DESCRIPTOR_BYTES:
                    raise DiscoveryError("discovery_path_changed")
                payload = stream.read(MAX_DESCRIPTOR_BYTES + 1)
                after = os.fstat(stream.fileno())
                if (len(payload) > MAX_DESCRIPTOR_BYTES or len(payload) != opened.st_size or
                        _safe_stat(after) != fingerprint or
                        (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
                    raise DiscoveryError("discovery_invalid")
            self._check()
            if _safe_stat(os.lstat(path)) != fingerprint:
                raise DiscoveryError("discovery_path_changed")
            result = HostDescriptor.from_dict(strict_json_loads(payload))
            self._record(result)
            return result
        except FileNotFoundError:
            raise DiscoveryError("discovery_not_found") from None
        except DiscoveryError:
            raise
        except RecoveryJournalError as error:
            raise _failure("discovery_path_unsafe", error) from None
        except (ContractViolation, TypeError, ValueError, NativePipeError):
            raise DiscoveryError("discovery_invalid") from None
        except Exception as error:
            raise _failure("discovery_read_unavailable", error) from None

    def read_instance(self):
        record = self._read(self.directory / "instance.json")
        if record.host_role != "supervisor":
            raise DiscoveryError("discovery_topology_invalid")
        if record.guardian is not None:
            child = record.guardian
            observed = self.read_guardian(parent_identity=record.host_identity,
                parent_instance_id=record.instance_id, child_identity=child.host_identity,
                instance_id=child.instance_id, policy_instance_id=record.policy_instance_id,
                guardian_epoch=record.guardian_epoch)
            if observed != child:
                raise DiscoveryError("discovery_child_changed")
        return record

    def _guardian_path(self, instance_id):
        try:
            _uuid(instance_id, "instance_id")
        except ContractViolation:
            raise DiscoveryError("discovery_binding_invalid") from None
        return self.directory / ("guardian-" + instance_id + ".json")

    def read_guardian(self, *, parent_identity, parent_instance_id, child_identity,
                      instance_id, policy_instance_id, guardian_epoch):
        record = self._read(self._guardian_path(instance_id))
        if (record.host_role != "guardian" or record.instance_id != instance_id or
                record.parent_identity != parent_identity or record.parent_instance_id != parent_instance_id or
                record.host_identity != child_identity or record.policy_instance_id != policy_instance_id or
                record.guardian_epoch != guardian_epoch):
            raise DiscoveryError("discovery_child_mismatch")
        return record

    def publish_instance(self, record, *, expected, owner_process, child_process=None):
        self._record(record)
        if record.host_role != "supervisor":
            raise DiscoveryError("discovery_canonical_supervisor_required")

        def verify():
            self._owner(owner_process, record.host_identity)
            if record.guardian is not None:
                child = record.guardian
                self._owner(child_process, child.host_identity)
                if self.read_guardian(parent_identity=record.host_identity,
                        parent_instance_id=record.instance_id, child_identity=child.host_identity,
                        instance_id=child.instance_id, policy_instance_id=record.policy_instance_id,
                        guardian_epoch=record.guardian_epoch) != child:
                    raise DiscoveryError("discovery_child_changed")

        return self._publish(record, self.directory / "instance.json", expected, verify)

    def publish_guardian(self, record, *, expected, owner_process, parent_process):
        self._record(record)
        if record.host_role != "guardian":
            raise DiscoveryError("discovery_guardian_required")

        def verify():
            self._owner(owner_process, record.host_identity)
            self._owner(parent_process, record.parent_identity)

        return self._publish(record, self._guardian_path(record.instance_id), expected, verify)

    def _compare(self, path, expected):
        try:
            actual = self._read(path)
        except DiscoveryError as error:
            if error.reason == "discovery_not_found" and expected is None:
                return
            raise
        if expected is None or actual != expected:
            raise DiscoveryError("discovery_revision_conflict")

    def _transition(self, record, expected):
        if expected is None:
            if record.revision != 1:
                raise DiscoveryError("discovery_revision_conflict")
            return
        self._record(expected)
        if expected.instance_id != record.instance_id:
            if record.revision != 1:
                raise DiscoveryError("discovery_revision_conflict")
            return
        if record.revision != expected.revision + 1:
            raise DiscoveryError("discovery_revision_conflict")
        for field in ("policy_instance_id", "logon_id", "guardian_epoch", "host_role", "host_identity",
                      "parent_identity", "parent_instance_id"):
            if getattr(record, field) != getattr(expected, field):
                raise DiscoveryError("discovery_binding_changed")
        current = {item.role: item.endpoint for item in record.endpoints}
        if any(current.get(item.role) != item.endpoint for item in expected.endpoints):
            raise DiscoveryError("discovery_binding_changed")

    @contextmanager
    def _write_scope(self):
        if self._quarantined:
            raise DiscoveryError("discovery_cleanup_quarantined")
        scope = None
        try:
            scope = self._protect().write_scope(self.directory)
            scope.__enter__()
        except BaseException as error:
            self._quarantined = True
            self._retained_error = (error, scope)
            raise
        try:
            yield
        except BaseException as primary:
            notes = tuple(getattr(primary, "__notes__", ()))
            try:
                suppressed = scope.__exit__(type(primary), primary, primary.__traceback__)
                if suppressed or tuple(getattr(primary, "__notes__", ())) != notes:
                    self._quarantined = True
                    self._retained_error = (primary, scope)
            except BaseException as cleanup:
                self._quarantined = True
                self._retained_error = (primary, cleanup, scope)
                primary._discovery_cleanup_error = cleanup
            if not isinstance(primary, Exception):
                self._quarantined = True
                self._retained_error = (primary, scope)
            raise
        else:
            try:
                if scope.__exit__(None, None, None):
                    raise DiscoveryError("discovery_cleanup_unverified")
            except BaseException as cleanup:
                self._quarantined = True
                self._retained_error = (cleanup, scope)
                raise

    def _publish(self, record, path, expected, verify):
        encoded = self._record(record)
        self._transition(record, expected)
        verify()
        publishing = published = False
        temporary = self.directory / ("." + path.name + "." + uuid4().hex + ".tmp")
        temporary_id = None
        primary = None
        try:
            with self._write_scope():
                self._provision()
                self._compare(path, expected)
                verify()
                with _binary_file(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), "wb") as stream:
                    temporary_id = _safe_stat(os.fstat(stream.fileno()))
                    if self._protect().protect_file(temporary) is not None:
                        raise DiscoveryError("discovery_security_unverified")
                    if _safe_stat(os.lstat(temporary)) != temporary_id:
                        raise DiscoveryError("discovery_path_changed")
                    if stream.write(encoded) != len(encoded):
                        raise DiscoveryError("discovery_write_incomplete")
                    stream.flush()
                    os.fsync(stream.fileno())
                self._check()
                self._compare(path, expected)
                verify()
                if _safe_stat(os.lstat(temporary)) != temporary_id:
                    raise DiscoveryError("discovery_path_changed")
                publishing = True
                if self._publisher(temporary, path, replace=expected is not None) is not None:
                    raise DiscoveryError("discovery_publication_unverified")
                published = True
                self._check()
                verify()
                if self._read(path) != record:
                    raise DiscoveryError("discovery_publication_unverified")
            return record
        except BaseException as error:
            primary = error
            if not isinstance(error, Exception):
                error.publication_may_have_occurred = publishing
                raise
            if isinstance(error, DiscoveryError):
                error.publication_may_have_occurred |= publishing
                raise
            raise _failure("discovery_publication_unverified" if publishing else
                           "discovery_write_unavailable", error, uncertain=publishing) from None
        finally:
            if temporary_id is not None and (not publishing or published):
                try:
                    self._check()
                    try:
                        observed = _safe_stat(os.lstat(temporary))
                    except FileNotFoundError:
                        observed = None
                    if observed is not None:
                        if observed != temporary_id:
                            raise DiscoveryError("discovery_temporary_changed")
                        os.unlink(temporary)
                except BaseException as cleanup:
                    self._quarantined = True
                    self._retained_error = cleanup
                    if primary is not None:
                        primary._discovery_cleanup_error = cleanup
                    else:
                        raise _failure("discovery_temporary_cleanup_unverified", cleanup,
                                       uncertain=published) from None

    def remove_instance(self, expected, *, owner_process):
        self._record(expected)
        if expected.host_role != "supervisor":
            raise DiscoveryError("discovery_canonical_supervisor_required")
        return self._remove(self.directory / "instance.json", expected, owner_process)

    def remove_guardian(self, expected, *, owner_process):
        self._record(expected)
        if expected.host_role != "guardian":
            raise DiscoveryError("discovery_guardian_required")
        return self._remove(self._guardian_path(expected.instance_id), expected, owner_process)

    def _remove(self, path, expected, owner_process):
        self._owner(owner_process, expected.host_identity)
        attempted = False
        try:
            with self._write_scope():
                self._check()
                try:
                    actual = self._read(path)
                except DiscoveryError as error:
                    if error.reason == "discovery_not_found":
                        return False
                    raise
                if actual != expected:
                    raise DiscoveryError("discovery_revision_conflict")
                fingerprint = _safe_stat(os.lstat(path))
                self._owner(owner_process, expected.host_identity)
                self._check()
                if self._read(path) != expected or _safe_stat(os.lstat(path)) != fingerprint:
                    raise DiscoveryError("discovery_revision_conflict")
                attempted = True
                os.unlink(path)
                self._check()
                self._owner(owner_process, expected.host_identity)
                if path.exists():
                    raise DiscoveryError("discovery_removal_unverified")
            return True
        except BaseException as error:
            if not isinstance(error, Exception):
                error.publication_may_have_occurred = attempted
                raise
            if isinstance(error, DiscoveryError):
                error.publication_may_have_occurred |= attempted
                raise
            raise _failure("discovery_removal_unverified", error, uncertain=attempted) from None

    def close(self):
        """Close only the optional namespace mutex; never remove descriptors."""
        if self._quarantined:
            raise DiscoveryError("discovery_cleanup_quarantined")
        if self._protection is not None:
            try:
                self._protection.close()
            except BaseException as error:
                self._quarantined = True
                self._retained_error = error
                raise
