"""Restore-only takeover from a previously captured, exact guardian witness.

Capture runs while that guardian is alive and the existing ledger is readable.
It pins the real POLICY namespace and duplicates the retained guardian handle.
Later restoration needs neither SQLite nor a live wrapper/root. A completely
cold process with no captured binding/death witness is deliberately unsupported;
missing PIDs, epochs and lease expiry are never proof of guardian death.

No allocation, exclusion, slot or admission barrier is released here. Manifest
creator identity remains immutable. A successful result proves only this Job's
native withdrawal and durable journal settlement, not complete host recovery.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import os
import threading
from uuid import UUID, uuid5

from .contracts import CpuControl, CpuControlMode, IdentityStatus, RecoveryManifest
from .guardian_lifecycle import job_mutex_instance
from .identity import VerifiedProcess
from .native_job import JobAccess, NativeJob
from .policy import PolicyBinding
from .recovery_journal import RecoveryJournalError
from .store import LifecycleError
from .windows import (NativePolicyMutex, NativePolicyMutexError, PolicyMutexLease,
                      replacement_allowed, retained_owners, settle_retained, unresolved_construction)


_CAPTURE = object()
_INSTANCE_NAMESPACE = UUID("b6fb6083-6db5-41c9-a54a-39cb9000df21")
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_IMMUTABLE = ("execution_id", "reservation", "spec_hash", "job_name", "creation_nonce",
              "wrapper_identity", "root_identity", "guardian_identity", "guardian_epoch", "original")
_UNAVAILABLE = {"manifest_read_unavailable", "manifest_directory_unavailable", "manifest_not_found",
                "manifest_write_unavailable", "manifest_write_incomplete", "manifest_publication_unverified"}


@dataclass(frozen=True)
class RecoveryResult:
    execution_id: str
    native_disabled: bool
    journal_settled: bool


class _Entry:
    def __init__(self, execution_id, nonce):
        self.execution_id, self.nonce = execution_id, nonce
        self.mutex = self.job = self.record = None
        self.mutex_error = None
        self.open_error = self.integrity_error = self.journal_error = None
        self.previous = self.candidate = None
        self.native_disabled = self.settled = self.cleanup_started = False


class RecoveryOwner:
    """One bounded restore owner; constructor authority is created by capture.

    Explicit current/mutex/job seams are in-process test fixtures only. Public
    callers supply no POLICY binding, native death flag or serialized handles.
    Exceptions keep ``_recovery_owner`` reachable until custody is reconciled.
    """
    def __init__(self, token):
        if token is not _CAPTURE:
            raise LifecycleError("recovery_capture_required")
        self._lock = threading.RLock()
        self._entries = {}
        self._binding = self._guardian = self._current = None
        self._policy_mutex = self._instance_mutex = None
        self._fence_error = self._capture_error = None
        self._captured = self._closed = False
        self._held_entry = self._held_thread = None

    @classmethod
    def capture(cls, store, journal, *, guardian, guardian_epoch,
                current=None, mutex_factory=None, job_opener=None):
        owner = cls(_CAPTURE)
        owner.journal = journal
        owner._mutex_factory = mutex_factory or NativePolicyMutex
        owner._job_opener = job_opener or NativeJob.open
        owner._guardian_epoch = guardian_epoch
        try:
            if getattr(store, "existing_path", False) is not True or not isinstance(guardian, VerifiedProcess):
                raise LifecycleError("recovery_capture_unverified")
            if type(guardian_epoch) is not str or not guardian_epoch:
                raise LifecycleError("recovery_epoch_invalid")
            owner._current = VerifiedProcess.current() if current is None else current.duplicate()
            owner._validate_current()
            if guardian.identity.logon_id != owner._current.identity.logon_id or guardian.identity == owner._current.identity:
                raise LifecycleError("recovery_guardian_binding_invalid")
            if guardian.observe().status is not IdentityStatus.ALIVE:
                raise LifecycleError("recovery_capture_guardian_not_alive")
            owner._guardian = guardian.duplicate()
            def read_binding():
                with store._connection() as conn:
                    runtime = store._policy._runtime(conn)
                    binding = store._policy._binding(runtime, owner._current.identity.logon_id)
                if (type(binding) is not PolicyBinding or runtime["guardian_epoch"] != guardian_epoch or
                        runtime["active_logon_id"] != binding.logon_id):
                    raise LifecycleError("recovery_capture_binding_unverified")
                return binding
            owner._binding = read_binding()
            owner._instance_binding = PolicyBinding(str(uuid5(_INSTANCE_NAMESPACE, owner.binding.instance_id)),
                                                     owner.binding.logon_id)
            owner._instance_mutex = owner._mutex_factory(owner.binding.logon_id, owner._instance_binding.instance_id)
            owner._policy_mutex = owner._mutex_factory(owner.binding.logon_id, owner.binding.instance_id)
            with owner._mutex(owner._instance_mutex, owner._instance_binding):
                with owner._mutex(owner._policy_mutex, owner.binding):
                    # No transaction spans a native wait. The second read is
                    # under the actual mutex, never a fabricated DB PolicyGuard.
                    if read_binding() != owner.binding:
                        raise LifecycleError("recovery_capture_binding_changed")
                    if owner.observe_guardian().status is not IdentityStatus.ALIVE:
                        raise LifecycleError("recovery_capture_guardian_not_alive")
            owner._captured = True
            return owner
        except BaseException as error:
            owner._capture_error = error
            error._recovery_owner = owner
            raise

    @property
    def binding(self):
        return self._binding

    @property
    def guardian_identity(self):
        return self._guardian.identity

    @property
    def guardian_epoch(self):
        return self._guardian_epoch

    @property
    def retained_execution_ids(self):
        with self._lock:
            return tuple(self._entries)

    def _validate_current(self):
        if self._closed or not isinstance(self._current, VerifiedProcess):
            raise LifecycleError("recovery_current_unverified")
        observation = self._current.observe()
        if (self._current.identity.pid != os.getpid() or observation.identity != self._current.identity or
                observation.status is not IdentityStatus.ALIVE):
            raise LifecycleError("recovery_current_unverified")

    def observe_guardian(self):
        with self._lock:
            self._validate_current()
            return self._guardian.observe()

    def _dead(self):
        observed = self.observe_guardian()
        if observed.identity != self.guardian_identity or observed.status is not IdentityStatus.DEAD:
            raise LifecycleError("recovery_guardian_death_unverified")

    @contextmanager
    def _mutex(self, mutex, expected):
        if self._fence_error is not None:
            raise LifecycleError("recovery_fence_uncertain")
        scope = mutex.acquire(timeout_ms=250)
        try:
            lease = scope.__enter__()
        except BaseException as error:
            if (not isinstance(error, NativePolicyMutexError) or error.reason not in
                    {"policy_mutex_timeout", "policy_mutex_wait_failed"} or getattr(error, "__notes__", ())):
                self._fence_error = error
            raise
        primary = None
        try:
            if (type(lease) is not PolicyMutexLease or lease.name != expected.name or
                    lease.logon_id != expected.logon_id or lease.instance_id != expected.instance_id or
                    type(lease.abandoned) is not bool):
                raise LifecycleError("recovery_mutex_binding_unverified")
            # Abandonment authorizes no new policy. Only positively dead-owner
            # recovery below can perform a compare-and-disable operation.
            yield
        except BaseException as error:
            primary = error
            raise
        finally:
            notes = tuple(getattr(primary, "__notes__", ()))
            try:
                suppressed = scope.__exit__(None if primary is None else type(primary), primary,
                    None if primary is None else primary.__traceback__)
                if suppressed or tuple(getattr(primary, "__notes__", ())) != notes:
                    self._fence_error = primary or LifecycleError("recovery_fence_cleanup_unverified")
                    if primary is None:
                        raise self._fence_error
                    primary.add_note("recovery_fence_cleanup_unverified")
            except BaseException as cleanup:
                self._fence_error = cleanup
                if primary is None:
                    raise
                primary.add_note("recovery_fence_cleanup_unverified")

    @contextmanager
    def _scope(self, entry, *, policy_scope=None):
        if not self._captured or self._capture_error is not None or self._closed:
            raise LifecycleError("recovery_capture_unverified")
        self._dead()
        with self._mutex(self._instance_mutex, self._instance_binding):
            # A cooperating writer that needs the store's own PolicyGuard takes
            # the POLICY level itself and passes the factory in. One name cannot
            # be held twice on one thread: NativePolicyMutex refuses that with
            # policy_mutex_recursive_entry, so this owner must not also hold its
            # handle while that guard is live. The order is unchanged.
            with (self._mutex(self._policy_mutex, self.binding) if policy_scope is None
                  else policy_scope()):
                self._dead()
                job_binding = PolicyBinding(job_mutex_instance(entry.execution_id, entry.nonce), self.binding.logon_id)
                if entry.mutex is None:
                    entry.mutex = self._job_mutex(entry, job_binding)
                with self._mutex(entry.mutex, job_binding):
                    self._held_entry, self._held_thread = entry, threading.get_ident()
                    try:
                        self._dead()
                        yield
                    finally:
                        self._held_entry = self._held_thread = None

    def _job_mutex(self, entry, binding):
        failed = entry.mutex_error
        if failed is not None:
            # A partial constructor may still own a native handle. Build a
            # replacement only after every owner it retained closed positively;
            # a failure that retained nothing verifiable stays sticky.
            if not replacement_allowed(failed):
                raise LifecycleError("recovery_job_mutex_unverified")
            entry.mutex_error = None
        try:
            return self._mutex_factory(binding.logon_id, binding.instance_id)
        except BaseException as error:
            # Only a sanitized native failure without cleanup notes or owners
            # is a positive nothing-allocated result that may simply be retried.
            if unresolved_construction(error):
                entry.mutex_error = error
            raise

    def _assert_held(self, entry):
        if (self._held_entry is not entry or self._held_thread != threading.get_ident() or
                self._fence_error is not None):
            raise LifecycleError("recovery_scope_required")
        self._dead()

    def _read(self, entry):
        self._assert_held(entry)
        if entry.integrity_error is not None:
            raise LifecycleError("recovery_manifest_integrity_unresolved")
        if entry.journal_error is not None:
            raise LifecycleError("recovery_journal_cleanup_unverified")
        try:
            record = self.journal.read(entry.execution_id, creation_nonce=entry.nonce)
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_error = error
            if type(error) is RecoveryJournalError and error.reason not in _UNAVAILABLE:
                entry.integrity_error = error
            raise
        if (type(record) is not RecoveryManifest or record.guardian_identity != self.guardian_identity or
                record.guardian_epoch != self.guardian_epoch or record.original != _DISABLED or
                record.wrapper_identity.logon_id != self.binding.logon_id):
            entry.integrity_error = LifecycleError("recovery_manifest_binding_changed")
            raise entry.integrity_error
        prior = entry.record
        if prior is not None and (any(getattr(record, key) != getattr(prior, key) for key in _IMMUTABLE) or
                record.manifest_seq < prior.manifest_seq or
                (record.manifest_seq == prior.manifest_seq and record != prior) or
                any(getattr(record.allocated_floor, key) < getattr(prior.allocated_floor, key)
                    for key in prior.allocated_floor.to_dict())):
            entry.integrity_error = LifecycleError("recovery_manifest_changed")
            raise entry.integrity_error
        if entry.candidate is not None and record not in (entry.previous, entry.candidate):
            entry.integrity_error = LifecycleError("recovery_manifest_changed")
            raise entry.integrity_error
        return record

    def _control(self, entry):
        self._assert_held(entry)
        raw = entry.job.query_cpu()
        if type(raw.flags) is not int or not 0 <= raw.flags < 1 << 32:
            raise LifecycleError("recovery_control_unverified")
        if not raw.flags & 1:
            return _DISABLED
        if raw.flags != 5:
            raise LifecycleError("external_control_conflict")
        return CpuControl(CpuControlMode.HARD_CAP, raw.rate_bp)

    def restore(self, execution_id, *, creation_nonce):
        with self._lock:
            entry = self._entries.get(execution_id)
            if entry is None:
                # The real journal validates UUID/nonce before any object name
                # is constructed; this first read is repeated under the fences.
                self.journal._path(execution_id)
                from .recovery_journal import _nonce
                _nonce(creation_nonce)
                if len(self._entries) >= 10:
                    raise LifecycleError("managed_job_limit_reached")
                entry = self._entries[execution_id] = _Entry(execution_id, creation_nonce)
            if entry.nonce != creation_nonce or entry.cleanup_started:
                raise LifecycleError("recovery_custody_conflict")
            entry.native_disabled = entry.settled = False
            try:
                with self._scope(entry):
                    record = self._read(entry)
                    if entry.job is None:
                        if entry.open_error is not None:
                            raise LifecycleError("recovery_job_open_unverified")
                        try:
                            entry.job = self._job_opener(record.job_name, record.creation_nonce,
                                self.binding.logon_id, access=JobAccess.CONTROL)
                        except BaseException as error:
                            entry.open_error = error
                            raise
                    if (entry.job.name != record.job_name or entry.job.nonce != record.creation_nonce or
                            entry.job.logon_sid != self.binding.logon_id or
                            self._current.is_in_job(entry.job.handle) is not False):
                        raise LifecycleError("recovery_job_binding_unverified")
                    entry.record = record
                    current = self._control(entry)
                    candidates = {record.original, record.last_applied or record.original}
                    if record.pending_intent is not None:
                        candidates.update((record.pending_intent.old, record.pending_intent.new))
                    if current not in candidates:
                        raise LifecycleError("external_control_conflict")
                    if current != _DISABLED:
                        self._assert_held(entry)
                        entry.job.disable()
                    if self._control(entry) != _DISABLED:
                        raise LifecycleError("restore_unverified")
                    entry.native_disabled = True
                    if record.pending_intent is not None or record.last_applied not in (None, _DISABLED) or entry.candidate is not None:
                        values = {item.name: getattr(record, item.name) for item in fields(record) if item.name != "manifest_hash"}
                        values.update(manifest_seq=record.manifest_seq + 1, last_applied=_DISABLED, pending_intent=None)
                        following = RecoveryManifest.create(**values)
                        entry.previous, entry.candidate = record, following
                        try:
                            self.journal.publish(following, expected_seq=record.manifest_seq,
                                expected_hash=record.manifest_hash, writer_scope=_JournalScope(self, entry, record))
                        except BaseException as error:
                            if hasattr(error, "_journal_cleanup_owner"):
                                entry.journal_error = error
                            raise
                        entry.record = following
                        entry.previous = entry.candidate = None
                    entry.settled = True
                return RecoveryResult(execution_id, True, True)
            except BaseException as error:
                error._recovery_owner = self
                error.recovery_result = RecoveryResult(execution_id, entry.native_disabled, False)
                raise

    def close_verified(self, execution_id):
        with self._lock:
            entry = self._entries[execution_id]
            if self._fence_error is not None or entry.integrity_error is not None or entry.journal_error is not None:
                raise LifecycleError("recovery_custody_unsettled")
            try:
                if not entry.cleanup_started:
                    self.restore(execution_id, creation_nonce=entry.nonce)
                    # Completed disable+settlement, positive fence release and
                    # dead original writer precede cleanup. Close itself is not
                    # evidence of restoration, Job emptiness or released floor.
                    entry.cleanup_started = True
                # A retry closes only what is still open. Only a positive close
                # drops an owner reference here.
                if entry.job is not None:
                    entry.job.close()
                    entry.job = None
                if entry.mutex is not None:
                    entry.mutex.close()
                    entry.mutex = None
                del self._entries[execution_id]
            except BaseException as error:
                error._recovery_owner = self
                raise

    def close(self):
        with self._lock:
            if self._closed:
                return
            if self._entries or self._fence_error is not None:
                raise LifecycleError("recovery_custody_unsettled")
            try:
                # A failed capture may hold partial duplicate/mutex owners only
                # on its exception. Closing the fields below cannot reach them.
                error = self._capture_error
                if error is not None:
                    # A cleanup note is the only evidence left by a failure that
                    # retained no owner; nothing here can ever account for it.
                    accounted = bool(retained_owners(error))
                    if not settle_retained(error) or (getattr(error, "__notes__", ()) and not accounted):
                        raise LifecycleError("recovery_custody_unsettled")
                for value in (self._policy_mutex, self._instance_mutex, self._guardian, self._current):
                    if value is not None:
                        value.close()
                self._closed = True
            except BaseException as error:
                error._recovery_owner = self
                raise


class _JournalScope:
    def __init__(self, owner, entry, record):
        self.owner, self.entry = owner, entry
        self.execution_id, self.creation_nonce, self.job_name = record.execution_id, record.creation_nonce, record.job_name
        self.reservation, self.spec_hash = record.reservation, record.spec_hash

    def assert_held(self):
        self.owner._assert_held(self.entry)

    def query_cpu_control(self):
        self.assert_held()
        return self.owner._control(self.entry)
