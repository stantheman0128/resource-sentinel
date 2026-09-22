"""Restore-only drain of an orphaned Job through the formal lifecycle store.

The original guardian is verifiably dead and its identity can never return.
This owner runs in the supervisor process and creates nothing of its own. It
borrows the RecoveryOwner's already verified custody, the open Job handle, the
settled manifest and the immutable creator epoch, and presents them as
``control_restore`` and ``finalize`` evidence to the existing store operations.

It is not a guardian. There is no begin, tighten, heartbeat, launch, adopt or
epoch rewrite here, and the manifest creator identity and epoch are never
written, so a replacement guardian identity stays refused by the existing
custody binding check. A native empty Job is the only gate on release: a root
exit, a lease expiry, a closed handle or a withdrawn cap is never that proof.

The POLICY level comes from the store's own PolicyCoordinator, not from the
recovery owner's handle. ``NativePolicyMutex`` refuses a second same-thread
acquisition of one name with ``policy_mutex_recursive_entry``, so the two
cannot both hold it; the store needs its guard, and the recovery owner accepts
a delegated POLICY scope for exactly this reason. Lock order stays
recovery-instance, POLICY, per-Job, then one short DB transaction.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import threading
from uuid import uuid4

from .contracts import CpuControl, CpuControlMode
from .policy import PolicyBusy, PolicyError
from .recovery_owner import RecoveryOwner
from .store import LifecycleError, LifecycleEvidence
from .supervisor_reconcile import RetainedPolicyOperation
from .windows import NativePolicyMutexError


_DISABLED = CpuControl(CpuControlMode.DISABLED, None)


@dataclass(frozen=True)
class DrainResult:
    execution_id: str
    state: str
    active_processes: int
    slot_released: bool
    finalized: bool
    # Clarification C3. False with no reason means the pass never asked: the
    # slot, the barrier or the state said this is not ours to clear.
    barrier_cleared: bool = False
    barrier_reason: str | None = None


class OrphanDrainOwner:
    """Finish the ledger side of one dead guardian's Jobs, nothing else.

    Construction needs the actual ``RecoveryOwner`` that captured the exact
    guardian handle. No other object can prove death, retain the Job or hold
    the settled manifest, so no other object may drain. The evidence provider
    installed here answers only the two operations below and only inside this
    owner's own fenced scope.
    """

    def __init__(self, store, recovery, *, install_evidence_provider=True):
        if getattr(store, "existing_path", False) is not True:
            raise LifecycleError("orphan_existing_registry_required")
        if not isinstance(recovery, RecoveryOwner):
            raise LifecycleError("orphan_recovery_owner_required")
        self.store, self.recovery = store, recovery
        self._lock = threading.RLock()
        self._scope_entry = self._scope_thread = None
        self._ledger_touched = False
        self._policy_operation = RetainedPolicyOperation(store)
        self._policy_execution_id = None
        if install_evidence_provider:
            self.store.evidence_provider = self.evidence_scope

    @property
    def retained_execution_ids(self):
        return self.recovery.retained_execution_ids

    @staticmethod
    def _members(entry):
        count = entry.job.accounting().active_processes
        members = tuple(entry.job.active_pids())
        if (type(count) is not int or not 0 <= count <= 4096 or count != len(members) or
                len(set(members)) != len(members) or
                any(type(pid) is not int or not 0 < pid < 1 << 32 for pid in members)):
            raise LifecycleError("orphan_membership_unverified")
        return count, members

    def _entry(self, execution_id, creation_nonce):
        entry = self.recovery._entries.get(execution_id)
        if entry is None or entry.nonce != creation_nonce or entry.cleanup_started:
            raise LifecycleError("orphan_custody_missing")
        if (entry.job is None or entry.record is None or not entry.native_disabled or
                not entry.settled):
            # Only a completed restore, with the owned cap withdrawn and the
            # manifest settled, may be drained. A partial pass keeps its hold.
            raise LifecycleError("orphan_restore_unsettled")
        return entry

    @contextmanager
    def _policy(self, execution_id=None):
        """Retain the same POLICY guard across a known interrupted drain.

        The guard returned by prepare is the only nonce authority. Unknown
        prepare/native cleanup is quarantined; a later read never reconstructs
        custody from an existing nonce. A pending drain cannot lend its guard
        to a different execution and accidentally clear that obligation.
        """
        operation = self._policy_operation
        if operation._quarantine:
            raise LifecycleError("orphan_policy_cleanup_unverified")
        if operation.guard is not None and execution_id != self._policy_execution_id:
            raise LifecycleError("orphan_policy_operation_pending")
        binding = self.recovery.binding
        with self.store._connection() as conn:
            runtime = self.store._policy._runtime(conn)
            current = self.store._policy._binding(runtime, binding.logon_id)
        if current != binding:
            # Read before prepare: a changed namespace must not leave a
            # committed entry nonce behind for a scope that cannot run.
            raise LifecycleError("orphan_policy_binding_changed")
        if operation.guard is not None:
            try:
                nonce = operation._guard_nonce()
                if nonce is None:
                    # The preceding hold or clear committed and released its
                    # own durable nonce. Retire only this retained authority;
                    # never adopt a different nonce observed in the ledger.
                    operation._guard = None
                    self._policy_execution_id = None
                elif nonce != operation.guard.nonce:
                    operation._quarantine = "policy_entry_changed"
                    raise PolicyError("policy_entry_changed")
            except BaseException as error:
                operation._failure(error)
                raise
        if operation.guard is None:
            try:
                operation._guard = self.store._policy.prepare(binding.logon_id)
                self._policy_execution_id = execution_id
            except PolicyBusy:
                raise
            except BaseException as error:
                # prepare may have committed without returning the guard.
                operation._error = error
                operation._quarantine = "policy_prepare_ownership_unknown"
                raise
        guard = operation.guard
        guard.clean_rejection = False
        entered = False
        try:
            with self.store._policy.hold(guard) as held:
                entered = True
                operation._attempted = True
                self._ledger_touched = False
                if held.binding != binding:
                    raise LifecycleError("orphan_policy_binding_changed")
                try:
                    yield held
                except LifecycleError:
                    # A read-only refusal can release its own entry. Any
                    # started journal/ledger mutation keeps the retained guard.
                    if not self._ledger_touched:
                        guard.clean_rejection = True
                    raise
        except BaseException as error:
            if not entered and not (isinstance(error, NativePolicyMutexError) and
                    getattr(error, "reason", None) == "policy_mutex_timeout"):
                operation._error = error
                operation._quarantine = "orphan_policy_acquisition_unverified"
            else:
                operation._failure(error)
            raise
        else:
            operation._guard = operation._error = None
            self._policy_execution_id = None

    def _clear_barrier(self, record, row):
        """Ask the store to clear a finished Job's barrier, or leave it held.

        Clarification C3 of plan section 7.4. The read-only proof runs first, so
        a refusal decided here exits the borrowed scope normally and leaves no
        POLICY entry nonce behind for a pass that never wrote. Only the write
        call below marks the ledger as touched, and a failure past that line
        keeps the nonce like every other borrowed scope.
        """
        execution_id = row["execution_id"]
        try:
            slot = self.store.query_control_slot_locked()
            guard = self.store._policy.assert_held()
            with self.store._connection() as conn:
                runtime = self.store._policy.revalidate(conn, guard)
            if (slot is None or slot["execution_id"] != execution_id or
                    slot["slot_state"] != "RESTORED" or
                    runtime["admission_barrier"] != "RECOVERY_HOLD"):
                # Another owner's slot, no slot at all, or a barrier this scope
                # never placed. Nothing was asked and nothing is reported.
                return False, None
            self.store.assert_finished_barrier_clearable(execution_id,
                caller=record.wrapper_identity, expected_revision=row["state_revision"],
                manifest=record)
        except (LifecycleError, PolicyError) as error:
            return False, str(error)
        self._ledger_touched = True
        self.store.clear_recovery_hold_finished_locked(execution_id,
            caller=record.wrapper_identity, expected_revision=row["state_revision"],
            expected_registry_revision=runtime["registry_revision"],
            slot_id=slot["slot_id"], manifest=record)
        return True, None

    def drain(self, execution_id, *, creation_nonce, now=None):
        """One bounded pass: release the slot, then finish a natively empty Job.

        Every precondition is read again inside the fences. A Job that still
        contains a process returns without touching the ledger, so no slot,
        allocation or barrier moves while work may still be running.
        """
        with self._lock:
            entry = self._entry(execution_id, creation_nonce)
            with self.recovery._scope(entry, policy_scope=lambda: self._policy(execution_id)):
                record = self.recovery._read(entry)
                if record.pending_intent is not None or record.last_applied not in (None, _DISABLED):
                    raise LifecycleError("orphan_restore_unsettled")
                if self.recovery._control(entry) != _DISABLED:
                    raise LifecycleError("restore_unverified")
                count, _ = self._members(entry)
                row = self.store.query(execution_id)
                if row["state"] == "FINISHED":
                    # Committed by this or an earlier pass. Nothing is released
                    # again; the caller may still settle its native custody. The
                    # barrier an earlier pass left behind is still offered here,
                    # so a clear that could not run then can run now. The owner's
                    # rule asks for a Job this pass read as empty, so a member
                    # seen now contradicts the terminal row and keeps the hold.
                    if count != 0:
                        return DrainResult(execution_id, "FINISHED", count, False, True,
                                           False, "finished_job_not_empty")
                    cleared, reason = self._clear_barrier(record, row)
                    return DrainResult(execution_id, "FINISHED", count, False, True, cleared, reason)
                if count != 0:
                    return DrainResult(execution_id, row["state"], count, False, False)
                from .guardian_floor import reconcile_orphan_floor_locked
                # The DB may have acknowledged an increased demand floor just
                # before guardian death. Repair only that monotone publication
                # cut, after native withdrawal/empty proof, before finalization.
                self._ledger_touched = True
                record = reconcile_orphan_floor_locked(self.store, self.recovery, entry, row, record)
                caller = record.wrapper_identity
                # From here the ledger is asked to change. A failure past this
                # line keeps the POLICY entry nonce, like any borrowed scope.
                self._ledger_touched = True
                self._scope_entry, self._scope_thread = entry, threading.get_ident()
                try:
                    slot = self.store.query_control_slot_locked()
                    released = (slot is not None and slot["execution_id"] == execution_id and
                                slot["slot_state"] == "HELD")
                    if released:
                        # The terminal archive refuses an unrestored slot, so
                        # the bookkeeping transition has to commit first.
                        self.store.release_control_slot_locked(execution_id, caller=caller,
                            expected_revision=row["state_revision"], slot_id=slot["slot_id"])
                        row = self.store.query(execution_id)
                    row = self.store.finalize_if_empty(execution_id, caller=caller,
                        expected_revision=row["state_revision"], now=now)
                finally:
                    self._scope_entry = self._scope_thread = None
                finalized = row["state"] == "FINISHED"
                cleared, reason = self._clear_barrier(record, row) if finalized else (False, None)
                return DrainResult(execution_id, row["state"], 0, released, finalized, cleared, reason)

    @contextmanager
    def evidence_scope(self, operation, row, caller):
        """Native evidence for the only two operations this owner may request.

        Every field below is a native read taken here or a value carried by the
        durable manifest. The root exit code is unknown to this owner and no
        substitute is invented, so ``root_exited`` stays false and nothing here
        asks for the transitions that would need it.
        """
        if operation not in {"control_restore", "finalize"}:
            raise LifecycleError("orphan_evidence_operation_unsupported")
        with self._lock:
            entry = self._scope_entry
            if entry is None or self._scope_thread != threading.get_ident():
                raise LifecycleError("orphan_scope_required")
            if row["execution_id"] != entry.execution_id:
                raise LifecycleError("orphan_custody_missing")
            # Re-verifies guardian death and that all three fences are retained.
            self.recovery._assert_held(entry)
            record = self.recovery._read(entry)
            expected = {
                "execution_id": record.execution_id, "spec_hash": record.spec_hash,
                "allocation_kind": record.reservation.kind.value, "reservation_id": record.reservation.id,
                "job_name": record.job_name, "job_nonce": record.creation_nonce,
                "guardian_epoch": record.guardian_epoch, "logon_id": record.wrapper_identity.logon_id,
                "wrapper_pid": record.wrapper_identity.pid,
                "wrapper_created_filetime_100ns": str(record.wrapper_identity.created_filetime_100ns),
                "root_pid": record.root_identity.pid,
                "root_created_filetime_100ns": str(record.root_identity.created_filetime_100ns),
            }
            if caller != record.wrapper_identity or any(row[key] != value for key, value in expected.items()):
                raise LifecycleError("orphan_row_changed")
            if (entry.job.name != record.job_name or entry.job.nonce != record.creation_nonce or
                    entry.job.logon_sid != record.wrapper_identity.logon_id):
                raise LifecycleError("orphan_job_binding_unverified")
            count, members = self._members(entry)
            yield LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex, caller,
                guardian_epoch=record.guardian_epoch, job_name=record.job_name,
                job_nonce=record.creation_nonce, root=record.root_identity,
                active_process_count=count, process_ids=members,
                launch_sealed=bool(row["launch_sealed"]), durable_manifest=True,
                current_cpu_disabled=self.recovery._control(entry) == _DISABLED,
                recovery_manifest_settled=(record.pending_intent is None and
                                           record.last_applied in (None, _DISABLED)))
