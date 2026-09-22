"""Restore only the exact Jobs already retained by this guardian.

No caller supplies a mutex binding, native handle, control target or readiness
flag. Successful lifecycle adoption pins the existing POLICY identity and a
second handle to that same kernel mutex. Its emergency path acquires POLICY
then the retained Job mutex without constructing a DB PolicyGuard. It can only
Query/disable; normal held evidence is still required for journal/DB settlement.
This is not cold-start takeover, a supervisor, or permission to enable caps.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, fields
import threading

from .contracts import CpuControl, CpuControlMode, RecoveryManifest
from .policy import PolicyBinding
from .recovery_journal import RecoveryJournalError
from .store import LifecycleError
from .windows import NativePolicyMutexError, PolicyMutexLease


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_IMMUTABLE = ("execution_id", "reservation", "spec_hash", "job_name", "creation_nonce",
              "wrapper_identity", "root_identity", "guardian_identity", "guardian_epoch", "original")
_UNAVAILABLE = {"manifest_read_unavailable", "manifest_directory_unavailable", "manifest_not_found"}
_CLEANUP_UNAVAILABLE = _UNAVAILABLE | {"manifest_write_unavailable", "manifest_write_incomplete",
                                     "manifest_publication_unverified", "manifest_temporary_cleanup_unverified"}
_INTEGRITY_ERRORS = {"guardian_restore_manifest_unverified", "guardian_restore_manifest_changed",
                     "guardian_restore_custody_changed", "guardian_custody_binding_mismatch",
                     "guardian_manifest_changed", "guardian_inside_workload_or_unknown"}


@dataclass(frozen=True)
class RestoreResult:
    execution_id: str
    native_disabled: bool
    bookkeeping_settled: bool
    slot_released: bool


class RestoreBatchError(LifecycleError):
    def __init__(self, results, errors):
        self.restore_results, self.restore_errors = tuple(results), tuple(errors)
        super().__init__("guardian_restore_batch_unresolved")


class GuardianRestorer:
    """Internal consumer; every retained reference belongs to one lifecycle."""
    def __init__(self, lifecycle):
        self.owner = lifecycle
        self.binding = self.policy_mutex = None
        self.fence_error = None
        self.closed = False
        self._emergency_entry = self._emergency_thread = None

    def poison(self, error):
        if self.fence_error is None:
            self.fence_error = error

    def check_fence(self):
        if self.closed:
            raise LifecycleError("guardian_restore_fence_closed")
        if self.fence_error is not None:
            raise LifecycleError("guardian_restore_fence_uncertain")

    def close(self):
        """Retire the original global recovery fence after all custody settles."""
        with self.owner._lock:
            if self.closed:
                return
            self.check_fence()
            if (self.owner.retained_execution_ids or self.owner._pending_policy is not None or
                    self.owner._scope_entry is not None or self._emergency_entry is not None):
                raise LifecycleError("guardian_restore_fence_still_owned")
            if self.policy_mutex is not None:
                try:
                    self.policy_mutex.close()
                except BaseException as error:
                    self.poison(error)
                    raise
            self.closed = True

    def note_fence_failure(self, error):
        notes = getattr(error, "__notes__", ())
        if (any(note.startswith(("policy_scope_cleanup_failed", "policy_scope_cleanup_unverified",
                                 "policy_mutex_release_failed", "policy_mutex_wait_outcome_unknown"))
                for note in notes) or
                (isinstance(error, NativePolicyMutexError) and error.reason not in
                 {"policy_mutex_timeout", "policy_mutex_wait_failed"})):
            self.poison(error)

    def pin(self, entry):
        """Only a successful adoption inside the existing normal fences pins."""
        self.check_fence()
        guard = self.owner.store._policy.assert_held()
        self._normal(entry)
        if type(guard.binding) is not PolicyBinding or not entry.validated or entry.manifest is None:
            raise LifecycleError("guardian_restore_binding_unverified")
        if self.binding is not None:
            if guard.binding != self.binding:
                raise LifecycleError("guardian_restore_binding_changed")
            return
        self.binding = guard.binding
        try:
            # Construct/open the same mutex while normal ownership is held;
            # this does not recursively Wait or create a new policy namespace.
            self.policy_mutex = self.owner._mutex_factory(self.binding.logon_id, self.binding.instance_id)
        except BaseException as error:
            self.poison(error)
            raise

    def _normal(self, entry):
        self.owner._queryable(entry)
        guard = self.owner.store._policy.assert_held()
        if (self.owner._scope_entry is not entry or
                self.owner._scope_thread != threading.get_ident() or
                (self.binding is not None and guard.binding != self.binding)):
            raise LifecycleError("guardian_restore_scope_required")

    def _held(self, entry):
        if self._emergency_entry is entry and self._emergency_thread == threading.get_ident():
            self.check_fence()
            return
        self._normal(entry)

    def _record(self, entry, *, allow_cached=False):
        """Unavailable I/O may narrow recovery to previously verified values.

        A readable but invalid/changed record is never treated as unavailable.
        Pending publication candidates remain uncertain until a new successful
        publication; a successful read alone does not settle an ACK loss.
        """
        self._held(entry)
        if entry.restore_integrity_error is not None:
            raise LifecycleError("guardian_restore_integrity_unresolved")
        prior = entry.manifest
        if type(prior) is not RecoveryManifest:
            raise LifecycleError("guardian_restore_manifest_unverified")
        if entry.journal_cleanup_error is not None:
            # Keep the first unclosed file owner; another read must not open a
            # second owner over uncertain cleanup. Only native withdrawal can
            # use the already verified, narrower cached candidates.
            retained = entry.journal_cleanup_error
            unavailable = (isinstance(retained, OSError) or
                           type(retained) is RecoveryJournalError and retained.reason in _CLEANUP_UNAVAILABLE)
            if not allow_cached or not unavailable:
                raise LifecycleError("guardian_journal_cleanup_unverified")
            record = prior
        else:
            try:
                record = self.owner.journal.read(entry.execution_id, creation_nonce=prior.creation_nonce)
            except BaseException as error:
                entry.restore_error = error
                if hasattr(error, "_journal_cleanup_owner"):
                    entry.journal_cleanup_error = error
                unavailable = (isinstance(error, OSError) or
                               type(error) is RecoveryJournalError and error.reason in _UNAVAILABLE)
                if not allow_cached or not unavailable:
                    raise
                record = prior
        if (type(record) is not RecoveryManifest or record.original != DISABLED or
                any(getattr(record, name) != getattr(prior, name) for name in _IMMUTABLE) or
                record.manifest_seq < prior.manifest_seq or
                (record.manifest_seq == prior.manifest_seq and record != prior) or
                any(getattr(record.allocated_floor, key) < getattr(prior.allocated_floor, key)
                    for key in prior.allocated_floor.to_dict())):
            raise LifecycleError("guardian_restore_manifest_changed")
        self.owner._validate_guardian()
        if (record.guardian_identity != self.owner.guardian.identity or record.execution_id != entry.execution_id or
                record.job_name != entry.job.name or record.creation_nonce != entry.job.nonce or
                record.wrapper_identity != entry.wrapper.identity or record.root_identity != entry.root.identity or
                record.wrapper_identity.logon_id != entry.job.logon_sid or
                self.owner.guardian.is_in_job(entry.job.handle) is not False):
            raise LifecycleError("guardian_restore_custody_changed")
        return record

    def _native(self, entry, record):
        self._held(entry)
        entry.restore_attempts += 1
        entry.restore_native_disabled = False
        current = self.owner._control(entry)
        candidates = {record.original, record.last_applied or record.original}
        if record.pending_intent is not None:
            candidates.update((record.pending_intent.old, record.pending_intent.new))
        if current not in candidates:
            raise LifecycleError("external_control_conflict")
        if current != DISABLED:
            entry.job.disable()
        # NativeJob.disable has its own readback; this independent read also
        # covers the no-Set branch and refuses a changed value before an ACK.
        if self.owner._control(entry) != DISABLED:
            raise LifecycleError("restore_unverified")
        entry.restore_native_disabled = True

    @contextmanager
    def _mutex(self, mutex, *, policy=False):
        scope = mutex.acquire(timeout_ms=250)
        try:
            lease = scope.__enter__()
        except BaseException as error:
            if (not isinstance(error, NativePolicyMutexError) or error.reason not in
                    {"policy_mutex_timeout", "policy_mutex_wait_failed"} or getattr(error, "__notes__", ())):
                self.poison(error)
            raise
        primary = None
        try:
            if (type(lease.abandoned) is not bool or
                    (policy and (type(lease) is not PolicyMutexLease or lease.name != self.binding.name or
                                 lease.instance_id != self.binding.instance_id or lease.logon_id != self.binding.logon_id))):
                raise LifecycleError("guardian_restore_lease_unverified")
            # Abandonment permits only this fenced compare-and-restore, never
            # normal mutation or barrier clearing. Bookkeeping remains pending.
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
                    failure = LifecycleError("guardian_restore_fence_cleanup_unverified")
                    self.poison(primary or failure)
                    if primary is None:
                        raise failure
                    primary.add_note("guardian_restore_fence_cleanup_unverified")
            except BaseException as cleanup:
                self.poison(cleanup)
                if primary is not None:
                    primary.add_note("guardian_restore_fence_cleanup_unverified")
                else:
                    raise

    def emergency(self, entry):
        """Native-only recovery, including when no DB connection can be made."""
        with self.owner._lock:
            self.owner._queryable(entry)
            self.check_fence()
            if (not entry.validated or self.binding is None or self.policy_mutex is None or
                    entry.mutex is None or self.owner._scope_entry is not None or
                    self.owner.store._policy.current_guard() is not None):
                raise LifecycleError("guardian_restore_binding_unavailable")
            entry.restore_pending = True
            with self._mutex(self.policy_mutex, policy=True):
                with self._mutex(entry.mutex):
                    self._emergency_entry, self._emergency_thread = entry, threading.get_ident()
                    try:
                        record = self._record(entry, allow_cached=True)
                        self._native(entry, record)
                    finally:
                        self._emergency_entry = self._emergency_thread = None
            return RestoreResult(entry.execution_id, True, False, False)

    @staticmethod
    def _retain_integrity(entry, error):
        if ((type(error) is RecoveryJournalError and error.reason not in _CLEANUP_UNAVAILABLE) or
                (isinstance(error, LifecycleError) and str(error) in _INTEGRITY_ERRORS)):
            # An observed contradiction cannot be erased by a second read
            # becoming unavailable, including on a later explicit retry. Keep
            # this Job's evidence without poisoning unrelated native scopes.
            if entry.restore_integrity_error is None:
                entry.restore_integrity_error = error

    def retain_failure(self, entry, error, *, fallback):
        """Keep the primary outcome and report any completed native withdrawal."""
        entry.restore_pending = True
        error.guardian_restore_owner = self.owner
        self._retain_integrity(entry, error)
        if entry.restore_integrity_error is not None:
            fallback = False
        if str(error) in {"guardian_restore_binding_changed", "guardian_policy_changed",
                          "policy_binding_invalid", "policy_logon_mismatch"}:
            fallback = False
        if fallback:
            try:
                error.guardian_restore_result = self.emergency(entry)
            except BaseException as restore_error:
                self._retain_integrity(entry, restore_error)
                error.guardian_restore_error = restore_error
        entry.restore_error = error
        if entry.restore_native_disabled:
            error.guardian_restore_result = RestoreResult(entry.execution_id, True, False, False)
            error.add_note("guardian_native_disabled_bookkeeping_unresolved")

    def locked(self, entry, row):
        """Normal held scope: native restore first, then durable settlement."""
        self.check_fence()
        self._normal(entry)
        if not entry.validated:
            raise LifecycleError("guardian_custody_unverified")
        entry.restore_pending = True
        try:
            record = self._record(entry)
            self._native(entry, record)
            guard = self.owner.store._policy.assert_held()
            self.owner.store._policy.record_recovery_hold(guard)
            if entry.journal_cleanup_error is not None:
                raise LifecycleError("guardian_journal_cleanup_unverified")
            uncertain = entry.restore_candidate
            if uncertain is not None and record not in (entry.restore_previous, uncertain):
                raise LifecycleError("guardian_restore_manifest_changed")
            needs_slot = (entry.restore_slot_id is not None or record.pending_intent is not None or
                          record.last_applied is not None or uncertain is not None)
            if record.pending_intent is not None or record.last_applied not in (None, DISABLED) or uncertain is not None:
                values = {item.name: getattr(record, item.name) for item in fields(record) if item.name != "manifest_hash"}
                values.update(manifest_seq=record.manifest_seq + 1, pending_intent=None, last_applied=DISABLED)
                following = RecoveryManifest.create(**values)
                entry.restore_previous, entry.restore_candidate = record, following
                try:
                    self.owner.journal.publish(following, expected_seq=record.manifest_seq,
                        expected_hash=record.manifest_hash, writer_scope=_JournalScope(self, entry, record))
                except BaseException as error:
                    if hasattr(error, "_journal_cleanup_owner"):
                        entry.journal_cleanup_error = error
                    raise
                # Only positive publication ACK settles this candidate. An ACK
                # loss is reaffirmed at a new sequence on an explicit retry.
                entry.manifest = record = following
                entry.restore_previous = entry.restore_candidate = None
            # Withdrawal must remain possible while accounting publication is
            # unavailable. Settle a retained floor only after native disable,
            # and before acknowledging bookkeeping or releasing the slot.
            if getattr(self.owner, "_floor_publisher", None) is not None and row["state"] != "FINISHED":
                fresh = self.owner.store.query(entry.execution_id, existing_path=True)
                record = self.owner._manifest(entry, fresh)
            slot = self.owner.store.query_control_slot_locked()
            if slot is None or slot["execution_id"] != entry.execution_id:
                if needs_slot:
                    raise LifecycleError("guardian_restore_slot_unresolved")
                released = False
            else:
                if entry.restore_slot_id is not None and entry.restore_slot_id != slot["slot_id"]:
                    raise LifecycleError("guardian_restore_slot_changed")
                entry.restore_slot_id = slot["slot_id"]
                fresh = self.owner.store.query(entry.execution_id, existing_path=True)
                self.owner.store.release_control_slot_locked(entry.execution_id,
                    caller=record.wrapper_identity, expected_revision=fresh["state_revision"], slot_id=slot["slot_id"])
                released = True
            entry.restore_pending = False
            entry.restore_error = None
            return RestoreResult(entry.execution_id, True, True, released)
        except BaseException as error:
            try:
                self.owner.store._policy.record_recovery_hold(self.owner.store._policy.assert_held())
            except BaseException as hold_error:
                error.guardian_restore_hold_error = hold_error
                error.add_note("guardian_restore_hold_unverified")
            self.retain_failure(entry, error, fallback=False)
            raise


class _JournalScope:
    def __init__(self, restorer, entry, record):
        self._restorer, self._entry = restorer, entry
        self.execution_id, self.creation_nonce, self.job_name = record.execution_id, record.creation_nonce, record.job_name
        self.reservation, self.spec_hash = record.reservation, record.spec_hash

    def assert_held(self):
        self._restorer._normal(self._entry)

    def query_cpu_control(self):
        self.assert_held()
        return self._restorer.owner._control(self._entry)
