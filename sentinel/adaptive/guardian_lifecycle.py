"""Guardian custody after the wrapper has published a verified, sealed launch.

This is the actual lifecycle consumer, not a service entry point or enrollment
permit. The trusted guardian server transfers its retained Job, wrapper and root
handles here only after authenticated launch reconciliation. No raw command,
ManagedAdmission object, serialized handle or caller-provided liveness is used.
The module performs no launch, tightening, workload termination or runtime setup.
Its retained restore-only consumer may disable a positively owned CPU cap.

Custody survives wrapper/root exit and query/DB failures. POLICY and the same
per-execution mutex span observation through the store transaction. A terminal
archive, verified disabled control and settled manifest precede handle cleanup.
The future service/supervisor must still provide authenticated launch transfer,
restore handling and cross-guardian recovery; construction proves none of those.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
import threading
from uuid import UUID, uuid4, uuid5

from .contracts import CpuControl, CpuControlMode, IdentityStatus, RecoveryManifest
from .identity import VerifiedProcess
from .guardian_restore import GuardianRestorer
from .store import LifecycleError, LifecycleEvidence
from .windows import NativePolicyMutex


_JOB_MUTEX_NAMESPACE = UUID("a649f2ae-1ed5-49b3-a0a5-2b85d18bbd7c")
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_STARTED = frozenset({"RUNNING", "DRAINING", "START_UNKNOWN", "UNCERTAIN_HOLD"})


def job_mutex_instance(execution_id, creation_nonce):
    """Shared by cooperating guardian/wrapper restore writers for this scope."""
    return str(uuid5(_JOB_MUTEX_NAMESPACE, execution_id + ":" + creation_nonce))


@dataclass(frozen=True)
class ReconcileResult:
    execution_id: str
    state: str
    root_exit_code: int | None
    active_processes: int
    restore_required: bool
    terminal: bool


class _Custody:
    def __init__(self, execution_id, job, wrapper, root):
        self.execution_id = execution_id
        self.job, self.wrapper, self.root = job, wrapper, root
        self.manifest = self.mutex = None
        self.validated = self.terminal = self.closed = False
        self.completed = None
        self.journal_cleanup_error = None
        self.restore_pending = self.restore_native_disabled = False
        self.restore_attempts = 0
        self.restore_previous = self.restore_candidate = None
        self.restore_slot_id = self.restore_error = None
        self.restore_integrity_error = None


class GuardianLifecycle:
    """One dispatcher for at most ten retained executions in one guardian.

    ``adopt_started`` transfers all three handle owners once an entry is inserted;
    subsequent validation failure retains that entry. A rejected duplicate/full
    registry transfers nothing. Callers must not close or concurrently use the
    transferred handles. No destructor silently drops unsettled custody.

    ``guardian`` and ``mutex_factory`` are explicit in-process fixture seams.
    Normal construction uses the actual current process and native ACL mutexes.
    They are not wire/config inputs or substitutes for native acceptance gates.
    """

    def __init__(self, store, journal, *, guardian=None, mutex_factory=None,
                 install_evidence_provider=True):
        if getattr(store, "existing_path", False) is not True:
            raise LifecycleError("guardian_existing_registry_required")
        self.store, self.journal = store, journal
        self.guardian = VerifiedProcess.current() if guardian is None else guardian
        self._mutex_factory = mutex_factory or NativePolicyMutex
        self._entries = {}
        self._lock = threading.RLock()
        self._scope_entry = self._scope_thread = None
        self._pending_policy = None
        self._restorer = GuardianRestorer(self)
        try:
            self._validate_guardian()
        except BaseException as primary:
            if guardian is None:
                try:
                    self.guardian.close()
                except BaseException:
                    primary._guardian_cleanup_owner = self.guardian
                    primary.add_note("guardian_identity_cleanup_unverified")
            raise
        # One provider dispatches by immutable execution ID. Individual owners
        # must never overwrite a shared store's provider with their own method.
        if install_evidence_provider:
            self.store.evidence_provider = self.evidence_scope

    @property
    def retained_execution_ids(self):
        with self._lock:
            return tuple(self._entries)

    def _validate_guardian(self):
        if not isinstance(self.guardian, VerifiedProcess):
            raise LifecycleError("guardian_identity_required")
        identity = self.guardian.identity
        observed = self.guardian.observe()
        if (identity.pid != os.getpid() or observed.identity != identity or
                observed.status is not IdentityStatus.ALIVE):
            raise LifecycleError("guardian_identity_unverified")

    def _entry(self, execution_id):
        entry = self._entries.get(execution_id)
        if entry is None or entry.closed:
            raise LifecycleError("guardian_custody_missing")
        return entry

    def _manifest(self, entry, row, *, terminal=False):
        if entry.restore_integrity_error is not None:
            raise LifecycleError("guardian_restore_integrity_unresolved")
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("guardian_journal_cleanup_unverified")
        try:
            record = self.journal.read(entry.execution_id, creation_nonce=row["job_nonce"])
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise
        if (type(record) is not RecoveryManifest or record.guardian_identity != self.guardian.identity or
                record.job_name != entry.job.name or record.creation_nonce != entry.job.nonce or
                record.wrapper_identity != entry.wrapper.identity or record.root_identity != entry.root.identity or
                record.wrapper_identity.logon_id != entry.job.logon_sid or
                len({record.guardian_identity, record.wrapper_identity, record.root_identity}) != 3):
            raise LifecycleError("guardian_custody_binding_mismatch")
        if self.guardian.is_in_job(entry.job.handle) is not False:
            raise LifecycleError("guardian_inside_workload_or_unknown")
        if entry.manifest is not None:
            prior = entry.manifest
            immutable = ("execution_id", "reservation", "spec_hash", "job_name", "creation_nonce",
                         "wrapper_identity", "root_identity", "guardian_identity", "guardian_epoch", "original")
            if (any(getattr(prior, name) != getattr(record, name) for name in immutable) or
                    record.manifest_seq < prior.manifest_seq or
                    (record.manifest_seq == prior.manifest_seq and record.manifest_hash != prior.manifest_hash) or
                    any(getattr(record.allocated_floor, key) < getattr(prior.allocated_floor, key)
                        for key in prior.allocated_floor.to_dict())):
                raise LifecycleError("guardian_manifest_changed")
        if terminal:
            self.store.assert_retained_terminal(row, record)
        else:
            self.store.assert_retained_allocation(row, record)
        entry.manifest = record
        return record

    def _policy_guard(self):
        policy = self.store._policy
        pending = self._pending_policy
        if pending is not None:
            with self.store._connection() as conn:
                runtime = policy._runtime(conn)
                binding = policy._binding(runtime, pending.binding.logon_id)
            if binding != pending.binding:
                raise LifecycleError("guardian_policy_changed")
            if runtime["policy_entry_nonce"] == pending.nonce:
                return pending
            if runtime["policy_entry_nonce"] is not None:
                raise LifecycleError("guardian_policy_changed")
            self._pending_policy = None
        return policy.prepare(self.guardian.identity.logon_id)

    @contextmanager
    def _job_scope(self, entry):
        if entry.mutex is None:
            entry.mutex = self._mutex_factory(self.guardian.identity.logon_id,
                job_mutex_instance(entry.execution_id,
                    entry.creation_nonce if hasattr(entry, "creation_nonce") else entry.job.nonce))
        entered, primary, notes = False, None, ()
        try:
            with entry.mutex.acquire(timeout_ms=250) as lease:
                entered = True
                try:
                    if lease.abandoned:
                        raise LifecycleError("guardian_job_mutex_abandoned")
                    self._scope_entry, self._scope_thread = entry, threading.get_ident()
                    yield
                except BaseException as error:
                    primary, notes = error, tuple(getattr(error, "__notes__", ()))
                    raise
                finally:
                    self._scope_entry = self._scope_thread = None
        except BaseException as error:
            if entered and (error is not primary or tuple(getattr(error, "__notes__", ())) != notes):
                self._restorer.poison(error)
            raise

    @contextmanager
    def _scope(self, entry):
        self._restorer.check_fence()
        try:
            with self._normal_scope(entry):
                yield
        except BaseException as error:
            self._restorer.note_fence_failure(error)
            raise

    @contextmanager
    def _normal_scope(self, entry):
        # This lock also prevents close/reuse of any retained native handle
        # while an evidence provider's nested SQLite transaction is in flight.
        with self._lock:
            self._validate_guardian()
            if self._scope_entry is not None:
                if self._scope_entry is not entry or self._scope_thread != threading.get_ident():
                    raise LifecycleError("guardian_scope_conflict")
                self.store._policy.assert_held()
                yield
                return
            current = self.store._policy.current_guard()
            if current is not None:
                self.store._policy.assert_held(current)
                if current.binding.logon_id != self.guardian.identity.logon_id:
                    raise LifecycleError("guardian_logon_mismatch")
                if self._restorer.binding is not None and current.binding != self._restorer.binding:
                    raise LifecycleError("guardian_restore_binding_changed")
                with self._job_scope(entry):
                    yield
                return
            guard = self._policy_guard()
            if self._restorer.binding is not None and guard.binding != self._restorer.binding:
                raise LifecycleError("guardian_restore_binding_changed")
            self._pending_policy = guard
            with self.store._policy.hold(guard):
                with self.store._connection() as conn:
                    self.store._policy.revalidate(conn, guard)
                with self._job_scope(entry):
                    yield
            self._pending_policy = None

    def adopt_started(self, execution_id, *, job, wrapper, root, mutex=None):
        with self._lock:
            if execution_id in self._entries:
                raise LifecycleError("guardian_custody_already_owned")
            if len(self._entries) >= 10:
                raise LifecycleError("managed_job_limit_reached")
            if not isinstance(wrapper, VerifiedProcess) or not isinstance(root, VerifiedProcess):
                raise LifecycleError("guardian_retained_identity_required")
            entry = _Custody(execution_id, job, wrapper, root)
            entry.mutex = mutex
            self._entries[execution_id] = entry
            self.retry_adoption(execution_id)

    def retry_adoption(self, execution_id):
        """Retry observation on the same owners; never replace a retained handle."""
        entry = self._entry(execution_id)
        with self._scope(entry):
            if entry.validated:
                self._restorer.pin(entry)
                return
            row = self.store.query(execution_id, existing_path=True)
            if (row["state"] not in _STARTED or not row["launch_sealed"] or row["launch_in_flight"] or
                    not row["claim_consumed"] or row["root_pid"] is None):
                raise LifecycleError("guardian_launch_not_reconciled")
            self._manifest(entry, row)
            wrapper_state = entry.wrapper.observe()
            if (wrapper_state.identity != entry.wrapper.identity or
                    wrapper_state.status not in {IdentityStatus.ALIVE, IdentityStatus.DEAD}):
                raise LifecycleError("guardian_wrapper_unverified")
            root_state = entry.root.observe()
            if root_state.status is IdentityStatus.UNKNOWN or root_state.identity != entry.root.identity:
                raise LifecycleError("guardian_root_unverified")
            # For an already exited exact retained root, the authenticated
            # launch binder established membership before publishing this
            # sealed row and manifest. Do not invent a positive membership
            # answer from IsProcessInJob on a terminated process.
            if root_state.status is IdentityStatus.ALIVE and entry.root.is_in_job(entry.job.handle) is not True:
                raise LifecycleError("guardian_root_membership_unverified")
            entry.validated = True
            self._restorer.pin(entry)

    @staticmethod
    def _control(entry):
        raw = entry.job.query_cpu()
        flags, rate = raw.flags, raw.rate_bp
        if type(flags) is not int or not 0 <= flags < 1 << 32:
            raise LifecycleError("guardian_control_unverified")
        if not flags & 1:
            return _DISABLED
        if flags != 5:
            raise LifecycleError("external_control_conflict")
        return CpuControl(CpuControlMode.HARD_CAP, rate)

    @staticmethod
    def _members(entry):
        count = entry.job.accounting().active_processes
        members = tuple(entry.job.active_pids())
        if (type(count) is not int or not 0 <= count <= 4096 or count != len(members) or
                len(set(members)) != len(members) or
                any(type(pid) is not int or not 0 < pid < 1 << 32 for pid in members)):
            raise LifecycleError("guardian_membership_unverified")
        return count, members

    @contextmanager
    def evidence_scope(self, operation, row, caller):
        if operation not in {"root_exited", "finalize", "heartbeat", "control_restore"}:
            raise LifecycleError("guardian_evidence_operation_unsupported")
        entry = self._entry(row["execution_id"])
        with self._scope(entry):
            if not entry.validated:
                raise LifecycleError("guardian_custody_unverified")
            if operation == "control_restore":
                # Withdrawal needs neither a live root nor active allocation,
                # but still proves the exact guardian/Job and actual Query.
                manifest = self._restorer._record(entry)
                expected = {
                    "execution_id": manifest.execution_id, "spec_hash": manifest.spec_hash,
                    "allocation_kind": manifest.reservation.kind.value, "reservation_id": manifest.reservation.id,
                    "job_name": manifest.job_name, "job_nonce": manifest.creation_nonce,
                    "guardian_epoch": manifest.guardian_epoch, "logon_id": manifest.wrapper_identity.logon_id,
                    "wrapper_pid": manifest.wrapper_identity.pid,
                    "wrapper_created_filetime_100ns": str(manifest.wrapper_identity.created_filetime_100ns),
                    "root_pid": manifest.root_identity.pid,
                    "root_created_filetime_100ns": str(manifest.root_identity.created_filetime_100ns),
                }
                if caller != manifest.wrapper_identity or any(row[key] != value for key, value in expected.items()):
                    raise LifecycleError("guardian_restore_row_changed")
                yield LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex, caller,
                    guardian_epoch=manifest.guardian_epoch, job_name=manifest.job_name,
                    job_nonce=manifest.creation_nonce, root=manifest.root_identity,
                    durable_manifest=True, current_cpu_disabled=self._control(entry) == _DISABLED,
                    recovery_manifest_settled=(entry.restore_candidate is None and entry.journal_cleanup_error is None and
                        manifest.pending_intent is None and manifest.last_applied in (None, _DISABLED)))
                return
            manifest = self._manifest(entry, row)
            expected = manifest.guardian_identity if operation == "heartbeat" else manifest.wrapper_identity
            if caller != expected:
                raise LifecycleError("guardian_evidence_caller_mismatch")
            count, members = self._members(entry)
            control = self._control(entry)
            observed = entry.root.observe()
            if observed.identity != manifest.root_identity or observed.status is IdentityStatus.UNKNOWN:
                raise LifecycleError("guardian_root_unverified")
            if observed.status is IdentityStatus.ALIVE and entry.root.is_in_job(entry.job.handle) is not True:
                raise LifecycleError("guardian_root_membership_unverified")
            settled = manifest.pending_intent is None and manifest.last_applied in (None, _DISABLED)
            yield LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex, caller,
                guardian_epoch=manifest.guardian_epoch, job_name=manifest.job_name,
                job_nonce=manifest.creation_nonce, root=manifest.root_identity,
                active_process_count=count, process_ids=members, launch_sealed=bool(row["launch_sealed"]),
                durable_manifest=True, root_exited=observed.status is IdentityStatus.DEAD,
                current_cpu_disabled=control == _DISABLED, recovery_manifest_settled=settled)

    def reconcile(self, execution_id, *, now=None):
        with self._lock:
            entry = self._entry(execution_id)
            entry.restore_native_disabled = False
            attempts = entry.restore_attempts
            try:
                return self._reconcile(execution_id, now=now)
            except BaseException as error:
                if entry.validated:
                    self._restorer.retain_failure(entry, error,
                        fallback=entry.restore_attempts == attempts)
                raise

    def restore_owned_cap(self, execution_id):
        """Restore adopted custody; DB failure still attempts native withdrawal.

        An exception reports native-disabled separately and never becomes a
        successful manifest/slot result or permission to release allocation.
        """
        with self._lock:
            entry = self._entry(execution_id)
            entry.restore_native_disabled = False
            attempts = entry.restore_attempts
            try:
                with self._scope(entry):
                    row = self.store.query(execution_id, existing_path=True)
                    return self._restorer.locked(entry, row)
            except BaseException as error:
                if entry.validated:
                    self._restorer.retain_failure(entry, error,
                        fallback=entry.restore_attempts == attempts)
                raise

    def _reconcile(self, execution_id, *, now=None):
        entry = self._entry(execution_id)
        with self._scope(entry):
            if not entry.validated:
                raise LifecycleError("guardian_custody_unverified")
            row = self.store.query(execution_id, existing_path=True)
            manifest = self._manifest(entry, row, terminal=row["state"] == "FINISHED")
            if entry.restore_pending:
                self._restorer.locked(entry, row)
                manifest = self._restorer._record(entry)
            if row["state"] == "FINISHED":
                # A prior archive may have committed without a successful ACK.
                # Revalidate the exact archive and native state; never release
                # again or mistake a missing allocation alone for completion.
                count, _ = self._members(entry)
                if (count != 0 or self._control(entry) != _DISABLED or
                        manifest.pending_intent is not None or manifest.last_applied not in (None, _DISABLED) or
                        entry.restore_candidate is not None):
                    raise LifecycleError("guardian_terminal_unverified")
                exit_code = entry.root.exit_code()
                if row["root_outcome"] != str(exit_code):
                    raise LifecycleError("guardian_root_outcome_mismatch")
                result = ReconcileResult(execution_id, "FINISHED", exit_code, 0, False, True)
                entry.completed, entry.terminal = result, True
                # A lost archive/cleanup ACK is resolved only by this fresh
                # exact archive, retained-empty Job and settled disabled proof.
                entry.restore_pending, entry.restore_error = False, None
                return result
            wrapper_state, root_state = entry.wrapper.observe(), entry.root.observe()
            if wrapper_state.identity != manifest.wrapper_identity or root_state.identity != manifest.root_identity:
                raise LifecycleError("guardian_identity_changed")
            if root_state.status is IdentityStatus.UNKNOWN:
                if row["state"] not in {"START_UNKNOWN", "UNCERTAIN_HOLD"}:
                    self.store.hold(execution_id, expected_revision=row["state_revision"], reason="identity_unknown")
                raise LifecycleError("guardian_root_unverified")
            if (wrapper_state.status is not IdentityStatus.ALIVE and row["state"] not in {"START_UNKNOWN", "UNCERTAIN_HOLD"}
                    and row.get("hold_reason") != "heartbeat_lost"):
                row = self.store.hold(execution_id, expected_revision=row["state_revision"], reason="heartbeat_lost")
            exit_code = None
            if root_state.status is IdentityStatus.DEAD:
                exit_code = entry.root.exit_code()
                if row["root_outcome"] is not None and row["root_outcome"] != str(exit_code):
                    raise LifecycleError("guardian_root_outcome_mismatch")
                if row["state"] in {"RUNNING", "UNCERTAIN_HOLD"}:
                    row = self.store.mark_root_exited(execution_id, caller=manifest.wrapper_identity,
                        expected_revision=row["state_revision"], exit_code=exit_code)
            count, _ = self._members(entry)
            current = self._control(entry)
            settled = current == _DISABLED and manifest.pending_intent is None and manifest.last_applied in (None, _DISABLED)
            restore = (manifest.pending_intent is not None or current != (manifest.last_applied or manifest.original) or
                (not settled and (wrapper_state.status is not IdentityStatus.ALIVE or root_state.status is IdentityStatus.DEAD)))
            if restore:
                self._restorer.locked(entry, row)
                manifest = self._restorer._record(entry)
                settled, restore = True, False
            if count == 0 and root_state.status is IdentityStatus.DEAD and settled:
                row = self.store.finalize_if_empty(execution_id, caller=manifest.wrapper_identity,
                    expected_revision=row["state_revision"], now=now)
            else:
                row = self.store.heartbeat_retained_allocation(row, manifest,
                    caller=self.guardian.identity, now=now)
            result = ReconcileResult(execution_id, row["state"], exit_code, count, restore, row["state"] == "FINISHED")
            if result.terminal:
                entry.completed = result
                entry.terminal = True
            return result

    def close_terminal(self, execution_id):
        with self._lock:
            entry = self._entry(execution_id)
            if (not entry.terminal or self._scope_entry is not None or self._pending_policy is not None or
                    entry.journal_cleanup_error is not None or entry.restore_pending or
                    self._restorer.fence_error is not None):
                raise LifecycleError("guardian_custody_unsettled")
            # Each object retains its own known-failure/unknown-close custody;
            # exceptions leave all references here rather than dropping them.
            entry.root.close()
            entry.wrapper.close()
            entry.job.close()
            if entry.mutex is not None:
                entry.mutex.close()
            del self._entries[execution_id]
            entry.closed = True
