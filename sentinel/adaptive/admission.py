"""Trusted, in-process metadata for one wrapper's direct admission attempt.

This context is created by the wrapper itself, retaining its exact native
process handle. It is neither an IPC authentication scheme nor an enrollment
gate. The Coordinator must obtain ``snapshot()`` before its SQLite transaction;
the returned immutable data cannot replace the live context on future retries.
Raw command, cwd, and environment are not retained here. The HMAC key and
one-use launch claim remain private in memory until close; neither is part of
a snapshot or diagnostic representation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
import secrets
import threading
from typing import TYPE_CHECKING
import uuid

from .contracts import (
    ContractViolation, IdentityStatus, Priority, ProcessIdentity, ResourceDemand,
    Role, make_spec_hash,
)
from .identity import VerifiedProcess

if TYPE_CHECKING:
    from sentinel.coordinator import ResourceRequest


_CONSTRUCTION_TOKEN = object()
_GIB = 1 << 30
_FILETIME_UNIX_EPOCH = 116444736000000000


class ManagedAdmissionUnavailable(RuntimeError):
    """Sanitized failure; values from the launch payload are never included."""


@dataclass(frozen=True)
class ManagedAdmissionSnapshot:
    execution_id: str
    task_id: str
    session_id: str
    principal_id: str
    logon_id: str
    wrapper_identity: ProcessIdentity
    spec_hash: str
    binding_hash: str
    claim_token_hash: str
    requested: ResourceDemand
    role: Role
    priority: Priority
    request: ResourceRequest


class ManagedAdmission:
    """Retain current-wrapper identity and immutable metadata across retries.

    Create only with ``current`` and keep the context open through admission.
    A fallback session denotes this exact local wrapper identity; all wrappers
    without trusted upstream attribution share their logon's principal. Neither
    session nor principal can be supplied by arbitrary request JSON.

    Python objects are not a boundary against hostile code in the same process.
    This API is for trusted wrapper code; receiving a serialized snapshot from
    another process must never confer the authority of a current context.
    """

    def __init__(self, *, _token=None, _process=None, _snapshot=None,
                 _claim_token=None, _key=None):
        if _token is not _CONSTRUCTION_TOKEN:
            raise TypeError("use_managed_admission_current")
        self._process = _process
        self._snapshot = _snapshot
        self._claim_token = _claim_token
        self._key = _key
        self._lock = threading.RLock()
        self._closed = False
        self._submitted = False

    @classmethod
    def current(cls, *, command: str, cwd: str, repo_identifier: str,
                requested: ResourceDemand, role: Role,
                priority: Priority) -> ManagedAdmission:
        # Retain the exact typed values rather than a mutable/custom input
        # object's view. The public contract's validation also bounds integers.
        if type(requested) is not ResourceDemand:
            raise TypeError("resource_demand_required")
        process = VerifiedProcess.current()
        try:
            identity = process.identity
            cls._validate_current(process, identity)
            key = secrets.token_bytes(32)
            managed_hash = make_spec_hash(
                key=key, command=command, cwd=cwd, repo_identifier=repo_identifier,
                requested=requested, role=role, priority=priority,
                parent_execution_id=None, caller=identity,
            )
            execution_id = str(uuid.uuid4())
            task_id = str(uuid.uuid4())
            session_id = (f"local:{identity.pid}:"
                          f"{identity.created_filetime_100ns}:{identity.logon_id}")
            principal_id = f"unattributed:{identity.logon_id}"
            claim_token = secrets.token_urlsafe(32)
            claim_token_hash = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
            # Existing ResourceRequest uses GiB. Refuse values that cannot make
            # the boundary conversion exactly; never silently shrink a demand.
            ram_gib = requested.physical_bytes / _GIB
            cpu_units = float(requested.cpu_units)
            if (int(ram_gib * _GIB) != requested.physical_bytes or
                    cpu_units != requested.cpu_units):
                raise ManagedAdmissionUnavailable("resource_conversion_inexact")
            # Lazy import avoids Coordinator -> admission -> Coordinator cycles.
            from sentinel.coordinator import ResourceRequest
            request = ResourceRequest(
                owner_pid=identity.pid,
                # Legacy diagnostic field only; native lifecycle uses FILETIME.
                owner_started=(identity.created_filetime_100ns -
                               _FILETIME_UNIX_EPOCH) / 10_000_000,
                repo=repo_identifier, command="", resource_class="HEAVY",
                priority=priority.value, tool_use_id=f"managed-v1:{execution_id}",
                cpu_units=cpu_units, ram_gib=ram_gib,
                io_slots=requested.io_slots, signature=managed_hash[:20],
                commit_bytes=requested.commit_bytes,
            ).normalized()
            binding = {
                "domain": "sentinel.managed-admission", "schema_version": 1,
                "spec_hash": managed_hash, "execution_id": execution_id,
                "task_id": task_id, "session_id": session_id,
                "principal_id": principal_id,
                "claim_token_hash": claim_token_hash,
                "wrapper_identity": identity.to_dict(),
                "requested": requested.to_dict(),
                "role": role.value, "priority": priority.value,
            }
            digest = hmac.new(
                key, json.dumps(binding, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True).encode("utf-8"), hashlib.sha256,
            ).hexdigest()
            snapshot = ManagedAdmissionSnapshot(
                execution_id, task_id, session_id, principal_id, identity.logon_id,
                identity, managed_hash, digest, claim_token_hash,
                requested, role, priority, request,
            )
            return cls(_token=_CONSTRUCTION_TOKEN, _process=process,
                       _snapshot=snapshot, _claim_token=claim_token, _key=key)
        except BaseException:
            process.close()
            raise

    @staticmethod
    def _validate_current(process, identity):
        if os.getpid() != identity.pid:
            raise ManagedAdmissionUnavailable("wrapper_is_not_current_process")
        observed = process.observe()
        if observed.identity != identity:
            raise ManagedAdmissionUnavailable("wrapper_identity_mismatch")
        if observed.status is not IdentityStatus.ALIVE:
            raise ManagedAdmissionUnavailable("wrapper_identity_not_alive")

    def snapshot(self) -> ManagedAdmissionSnapshot:
        """Revalidate the retained current process before opening a transaction."""
        with self._lock:
            if self._closed:
                raise ManagedAdmissionUnavailable("managed_admission_closed")
            self._validate_current(self._process, self._snapshot.wrapper_identity)
            return self._snapshot

    def begin_submission(self) -> tuple[ManagedAdmissionSnapshot, bool]:
        """Mark first submission before its transaction, never remint on retry.

        A repeat without a matching queue or execution must not insert work.
        This deliberately requires reconciliation after an uncertain outcome;
        reading ``snapshot`` alone does not consume the first submission.
        """
        with self._lock:
            snapshot = self.snapshot()
            first_submission = not self._submitted
            self._submitted = True
            return snapshot, first_submission

    def launch_claim_token(self) -> str:
        """Read the same private one-use claim after checking current identity.

        The trusted wrapper passes this only to its launch-claim operation;
        it must never be logged or exported with admission diagnostics.
        """
        with self._lock:
            self.snapshot()
            return self._claim_token

    def verify_launch_payload(self, *, command: str, cwd: str) -> None:
        """Bind the actual launch payload to the immutable admitted request.

        The launcher calls this outside SQLite immediately before claiming and
        launching. Successful comparison is not a launch fence or proof of
        admission; lifecycle state and ownership still require their own checks.
        Raw payload text remains a call-local value and is never saved here.
        """
        with self._lock:
            snapshot = self.snapshot()
            try:
                actual_hash = make_spec_hash(
                    key=self._key, command=command, cwd=cwd,
                    repo_identifier=snapshot.request.repo,
                    requested=snapshot.requested, role=snapshot.role,
                    priority=snapshot.priority, parent_execution_id=None,
                    caller=snapshot.wrapper_identity,
                )
            except ContractViolation:
                raise ManagedAdmissionUnavailable("launch_payload_mismatch") from None
            if not hmac.compare_digest(actual_hash, snapshot.spec_hash):
                raise ManagedAdmissionUnavailable("launch_payload_mismatch")

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._claim_token = None
                self._key = None
                self._process.close()

    def __enter__(self):
        try:
            self.snapshot()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *_):
        self.close()
