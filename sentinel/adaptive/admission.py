"""Trusted, in-process metadata for one wrapper's direct admission attempt.

This context is created by the wrapper itself, retaining its exact native
process handle. It is not an enrollment gate. The Coordinator must obtain
``snapshot()`` before its SQLite transaction;
the returned immutable data cannot replace the live context on future retries.
Raw command, cwd, and environment are not retained here. The HMAC key and
one-use launch claim remain private in memory until close. A separate query-only
IPC key is carried by the trusted admission snapshot and persisted atomically;
that snapshot must never be exported as diagnostics or generic JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading
from typing import TYPE_CHECKING
import uuid

from .contracts import (
    ContractViolation, IdentityStatus, Priority, ProcessIdentity, ResourceDemand,
    Role, make_spec_hash, MAX_MESSAGE_BYTES,
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
    ipc_auth_key: bytes = field(repr=False)
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
        self._admission_db_path = None
        self._claim_exported = False
        self._cancel_sealed = False
        self._cancel_target = None
        self._cancel_revision = None

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
            # The digest is a usable shared secret, not a public verifier. It
            # never reuses or exports the one-use launch claim credential.
            ipc_auth_key = hashlib.sha256(secrets.token_bytes(32)).digest()
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
                "ipc_auth_key": ipc_auth_key.hex(),
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
                identity, managed_hash, digest, claim_token_hash, ipc_auth_key,
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

    @staticmethod
    def _ledger_path(db_path):
        try:
            path = Path(db_path).resolve()
            if path.is_file():
                return path
        except (OSError, TypeError, ValueError, RuntimeError):
            pass
        raise ManagedAdmissionUnavailable("managed_admission_ledger_unavailable")

    def begin_submission(self, *, db_path) -> tuple[ManagedAdmissionSnapshot, bool]:
        """Mark first submission before its transaction, never remint on retry.

        A repeat without a matching queue or execution must not insert work.
        This deliberately requires reconciliation after an uncertain outcome;
        reading ``snapshot`` alone does not consume the first submission.
        Canonical ledger identity is pinned before submission can have any
        outcome, including an uncertain ACK. It is trusted configuration, not
        protection against hostile replacement of the file at that path.
        """
        with self._lock:
            snapshot = self.snapshot()
            self._require_unsealed()
            path = self._ledger_path(db_path)
            if self._admission_db_path is not None and path != self._admission_db_path:
                raise ManagedAdmissionUnavailable("managed_admission_ledger_mismatch")
            self._admission_db_path = path
            first_submission = not self._submitted
            self._submitted = True
            return snapshot, first_submission

    def launch_claim_token(self) -> str:
        """Read the same private one-use claim after checking current identity.

        The trusted wrapper passes this only to its launch-claim operation;
        it must never be logged or exported with admission diagnostics.
        Returning it permanently ends this context's unused-claim cancellation
        authority, even if the receiving component does not actually launch.
        """
        with self._lock:
            self.snapshot()
            self._require_unsealed()
            # Once another trusted component can know the token, this context
            # cannot prove exclusive control of every possible launch path.
            self._claim_exported = True
            return self._claim_token

    def _ipc_mac(self, transcript: bytes, *, execution_id: str,
                 spec_hash: str, caller: ProcessIdentity) -> str:
        """Authenticate the trusted IPC factory's canonical query transcript.

        The sibling IPC implementation owns domain/envelope validation and
        native server authentication. This internal helper checks the current
        wrapper binding and bounds input; it does not turn arbitrary bytes into
        a valid RPC. Query authentication neither exports the launch token nor
        consumes cancellation authority, so terminal readback remains possible.
        """
        with self._lock:
            snapshot = self.snapshot()
            if type(transcript) is not bytes or not 1 <= len(transcript) <= MAX_MESSAGE_BYTES:
                raise ManagedAdmissionUnavailable("invalid_ipc_transcript")
            if (execution_id != snapshot.execution_id or spec_hash != snapshot.spec_hash or
                    type(caller) is not ProcessIdentity or caller != snapshot.wrapper_identity):
                raise ManagedAdmissionUnavailable("ipc_binding_mismatch")
            return hmac.new(snapshot.ipc_auth_key, transcript, hashlib.sha256).hexdigest()

    def verify_launch_payload(self, *, command: str, cwd: str) -> None:
        """Bind the actual launch payload to the immutable admitted request.

        The launcher calls this outside SQLite immediately before claiming and
        launching. Successful comparison is not a launch fence or proof of
        admission; lifecycle state and ownership still require their own checks.
        Raw payload text remains a call-local value and is never saved here.
        """
        with self._lock:
            snapshot = self.snapshot()
            self._require_unsealed()
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

    def _require_unsealed(self):
        if self._cancel_sealed:
            raise ManagedAdmissionUnavailable("managed_admission_sealed")

    @staticmethod
    def _validate_cancel_row(row, snapshot, reservation_id, *, terminal=False):
        expected = {
            "execution_id": snapshot.execution_id, "task_id": snapshot.task_id,
            "session_id": snapshot.session_id, "principal_id": snapshot.principal_id,
            "logon_id": snapshot.logon_id, "allocation_kind": "direct",
            "reservation_id": reservation_id, "parent_execution_id": None,
            "spec_hash": snapshot.spec_hash, "admission_binding_hash": snapshot.binding_hash,
            "wrapper_pid": snapshot.wrapper_identity.pid,
            "wrapper_created_filetime_100ns": str(snapshot.wrapper_identity.created_filetime_100ns),
            "role": snapshot.role.value, "priority": snapshot.priority.value,
            "coverage": "unmanaged", "job_name": None, "guardian_epoch": "",
            "root_pid": None, "root_created_filetime_100ns": None, "root_outcome": None,
            "launch_in_flight": 0, "hold_reason": None,
            "state": "CANCELLED_BEFORE_START" if terminal else "RESERVED",
            "claim_consumed": 1 if terminal else 0,
            "launch_sealed": 1 if terminal else 0,
        }
        expected.update({"requested_" + key: value for key, value in snapshot.requested.to_dict().items()})
        if not terminal:
            expected.update(finished_at=None, cancel_requested_at=None)
        if any(row.get(key) != value for key, value in expected.items()):
            raise ManagedAdmissionUnavailable("reserved_cancel_binding_mismatch")

    @staticmethod
    def _validate_cancel_allocation(allocation, snapshot, reservation_id):
        request = snapshot.request
        expected = {
            "id": reservation_id, "execution_id": snapshot.execution_id,
            "lifecycle_managed": 1, "managed_spec_hash": snapshot.spec_hash,
            "request_key": request.request_key, "spec_hash": request.spec_hash,
            "owner_pid": request.owner_pid, "owner_started": request.owner_started,
            "tool_use_id": request.tool_use_id, "repo": request.repo,
            "command_signature": request.command_signature, "command_text": "",
            "resource_class": request.resource_class, "priority": request.priority,
            "priority_rank": int(request.priority[1:]), "cpu_units": request.cpu_units,
            "ram_gib": request.ram_gib, "io_slots": request.io_slots,
            "physical_bytes": snapshot.requested.physical_bytes,
            "commit_bytes": snapshot.requested.commit_bytes,
        }
        if allocation is None or any(allocation.get(key) != value for key, value in expected.items()):
            raise ManagedAdmissionUnavailable("reserved_cancel_allocation_mismatch")

    def cancel_reserved(self, db_path, *, reservation_id: str, expected_revision: int,
                        now: float | None = None) -> dict:
        """Cancel this context's direct allocation before any claim handoff.

        Authority is the retained native self handle plus exclusive ownership of
        an unexported launch credential. The lock only serializes access to that
        capability; it is not a kernel launch fence. No Job, guardian, workload
        or cross-process handoff may exist on this deliberately narrow path.

        Before yielding native evidence, seal future submission, payload checks
        and token handoff irreversibly. A failed transaction or lost ACK retains
        the seal; only this exact cancellation can be retried. Closing/restarting
        the context cannot recreate that capability. No OS query runs under a
        SQLite writer lock, and all DB binding is rechecked by the store there.
        """
        from .store import LifecycleEvidence, LifecycleStore, prelaunch_record_hash

        if (not isinstance(reservation_id, str) or not 1 <= len(reservation_id) <= 128 or
                type(expected_revision) is not int or expected_revision < 0):
            raise ManagedAdmissionUnavailable("invalid_reserved_cancel_request")
        with self._lock:
            snapshot = self.snapshot()
            if self._claim_exported:
                raise ManagedAdmissionUnavailable("launch_claim_already_exported")
            path = self._ledger_path(db_path)
            if self._admission_db_path is None or path != self._admission_db_path:
                raise ManagedAdmissionUnavailable("managed_admission_ledger_mismatch")
            target = (path, reservation_id)
            if self._cancel_target is not None and target != self._cancel_target:
                raise ManagedAdmissionUnavailable("reserved_cancel_target_mismatch")

            @contextmanager
            def unused_claim_scope(operation, row, caller):
                # The outer lock remains held through this scope and SQLite
                # completion. Native checks are before the store's transaction.
                current = self.snapshot()
                if operation != "cancel" or caller != current.wrapper_identity or self._claim_exported:
                    raise ManagedAdmissionUnavailable("reserved_cancel_authority_unavailable")
                self._validate_cancel_row(row, current, reservation_id)
                with store._connection() as conn:
                    allocation = conn.execute("SELECT * FROM reservations WHERE id=?", (reservation_id,)).fetchone()
                    allocation = None if allocation is None else dict(allocation)
                self._validate_cancel_allocation(allocation, current, reservation_id)
                self.snapshot()
                digest = prelaunch_record_hash(row, claim_token_hash=current.claim_token_hash,
                                               allocation=allocation)
                self._cancel_sealed = True
                self._cancel_target = target
                # A failed attempt may be followed by a legitimate floor CAS.
                # Remember the latest proof-backed attempt so its lost ACK can
                # be replayed exactly; the target and launch seal never change.
                self._cancel_revision = expected_revision
                self._claim_token = None
                self._key = None
                yield LifecycleEvidence(
                    "cancel", current.execution_id, row["state_revision"],
                    "native-unused-wrapper-claim", current.wrapper_identity,
                    launch_sealed=True, user_code_started=False,
                    prelaunch_record_hash=digest,
                )

            store = LifecycleStore(path, evidence_provider=unused_claim_scope)
            row = store.query(snapshot.execution_id)
            if row["state"] == "CANCELLED_BEFORE_START":
                if not self._cancel_sealed or self._cancel_target != target:
                    raise ManagedAdmissionUnavailable("reserved_cancel_replay_unverified")
                self._validate_cancel_row(row, snapshot, reservation_id, terminal=True)
                if expected_revision not in {self._cancel_revision, row["state_revision"]}:
                    raise ManagedAdmissionUnavailable("reserved_cancel_revision_mismatch")
                with store._connection() as conn:
                    actual = conn.execute("SELECT claim_token_hash FROM managed_executions WHERE execution_id=?",
                                          (snapshot.execution_id,)).fetchone()
                    remaining = conn.execute("SELECT 1 FROM reservations WHERE id=?", (reservation_id,)).fetchone()
                    archived = conn.execute("SELECT count(*) FROM executions WHERE reservation_id=? AND outcome=?",
                                            (reservation_id, "managed_cancelled_before_start")).fetchone()[0]
                if actual is None or actual[0] != "" or remaining is not None or archived != 1:
                    raise ManagedAdmissionUnavailable("reserved_cancel_replay_unverified")
                return store.cancel_before_start(snapshot.execution_id, caller=snapshot.wrapper_identity,
                                                 expected_revision=row["state_revision"], now=now)
            self._validate_cancel_row(row, snapshot, reservation_id)
            return store.cancel_before_start(snapshot.execution_id, caller=snapshot.wrapper_identity,
                                             expected_revision=expected_revision, now=now)

    def close(self):
        with self._lock:
            if not self._closed:
                self._closed = True
                self._claim_token = None
                self._key = None
                # Drop this context's reference to the IPC key as well. Python
                # immutable bytes do not provide guaranteed physical erasure.
                self._snapshot = None
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
