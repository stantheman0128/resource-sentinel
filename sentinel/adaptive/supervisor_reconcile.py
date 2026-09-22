"""Bounded supervisor ledger reconciliation with retained POLICY ownership.

No process is opened, closed, started or controlled here. Original native
witnesses belong to the host. A failed ledger operation keeps its same-process
guard; an unknown native cleanup or unowned durable nonce never creates one.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3

from .contracts import CpuControl, CpuControlMode, IdentityStatus, ProcessIdentity, RecoveryManifest
from .control_slot import read_slot
from .identity import VerifiedProcess
from .legacy_writer import _infra_schema, unregister_dead_infrastructure_locked
from .policy import PolicyBusy, PolicyError
from .store import LifecycleError
from .windows import NativePolicyMutexError


@dataclass(frozen=True)
class ReconcileResult:
    complete: bool
    pending: bool
    quarantined: bool
    reason: str | None
    changed: bool = False


def _reason(error):
    value = getattr(error, "reason", str(error))
    return value if type(value) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value) else type(error).__name__


class _PendingPolicyOperation:
    def __init__(self, store):
        self.store = store
        self._guard = None
        self._error = None
        self._quarantine = None
        self._attempted = False
        self._changed = False
        self._complete = False

    @property
    def guard(self):
        return self._guard

    @property
    def pending(self):
        # Includes interrupts, which retain custody but return no result.
        return bool(self._guard is not None or self._quarantine or
                    (self._attempted and not self._complete))

    def reset_completed(self):
        """Start a later logical operation only after verified prior cleanup."""
        if not self._complete or self._guard is not None or self._quarantine:
            raise LifecycleError("policy_operation_unsettled")
        self._complete = self._attempted = self._changed = False
        self._error = None

    def _pending(self, reason, *, quarantine=False):
        if quarantine:
            self._quarantine = reason
        return ReconcileResult(False, True, quarantine, reason, self._changed)

    def _failure(self, error):
        # Retain exceptions carrying journal/native cleanup owners. Dropping
        # an exception would discard the only reachable cleanup obligation.
        self._error = error
        notes = set(getattr(error, "__notes__", ()))
        # User/process interrupts still propagate, but the same host must not
        # forget an interrupted ownership boundary and later retry it as safe.
        unsafe = not isinstance(error, Exception) or bool(
            notes & {"policy_scope_cleanup_failed", "policy_scope_cleanup_unverified"})
        unsafe = unsafe or hasattr(error, "_journal_cleanup_owner") or bool(
            getattr(error, "_native_close_outcome_unknown", False))
        unsafe = unsafe or (isinstance(error, NativePolicyMutexError) and
            getattr(error, "reason", None) != "policy_mutex_timeout")
        unsafe = unsafe or _reason(error) in {"policy_entry_changed", "policy_binding_invalid", "policy_logon_mismatch"}
        result = self._pending(_reason(error), quarantine=unsafe)
        if not isinstance(error, Exception):
            raise error
        return result

    def _guard_nonce(self):
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self.store._policy._runtime(conn)
            binding = self.store._policy._binding(runtime, self._guard.binding.logon_id)
            if binding != self._guard.binding or runtime["active_logon_id"] not in {"", binding.logon_id}:
                raise PolicyError("policy_entry_changed")
            return runtime["policy_entry_nonce"]

    def _run(self, logon, operation, reconciled):
        """At most one POLICY attempt per call, retaining uncertain SQL work."""
        if self._quarantine:
            return self._pending(self._quarantine, quarantine=True)
        if self._complete:
            return ReconcileResult(True, False, False, None, self._changed)
        if self._guard is not None:
            try:
                nonce = self._guard_nonce()
                if nonce is None:
                    if self._attempted and reconciled():
                        self._guard = None
                        self._complete = True
                        return ReconcileResult(True, False, False, None, self._changed)
                    # A known timeout/clean refusal cleared its own nonce. Do
                    # not repeatedly reacquire within the same host tick.
                    self._guard = None
                    self._attempted = False
                    return self._pending("policy_attempt_released_retry")
                if nonce != self._guard.nonce:
                    return self._pending("policy_entry_changed", quarantine=True)
            except BaseException as error:
                return self._failure(error)
        else:
            try:
                self._guard = self.store._policy.prepare(logon)
            except PolicyBusy as error:
                return self._pending(_reason(error))
            except BaseException as error:
                # prepare returns ownership only after commit AND cleanup.
                # It may have committed a nonce without returning the guard.
                self._error = error
                result = self._pending("policy_prepare_ownership_unknown", quarantine=True)
                if not isinstance(error, Exception):
                    raise
                return result
        entered = False
        try:
            # A prior pre-transaction identity refusal may set this flag. It
            # cannot authorize clearing after a later failed SQL attempt.
            self._guard.clean_rejection = False
            with self.store._policy.hold(self._guard):
                entered = True
                self._attempted = True
                self._changed = bool(operation()) or self._changed
            self._guard = None
            self._complete = True
            self._error = None
            return ReconcileResult(True, False, False, None, self._changed)
        except BaseException as error:
            if not entered and not (isinstance(error, NativePolicyMutexError) and
                    getattr(error, "reason", None) == "policy_mutex_timeout"):
                # hold() cannot attest to a provider invocation that raised
                # before yielding. Never assume a generic acquisition failure
                # implies no native ownership, even if it carries no notes.
                self._error = error
                result = self._pending(_reason(error), quarantine=True)
                if not isinstance(error, Exception):
                    raise
                return result
            return self._failure(error)


RetainedPolicyOperation = _PendingPolicyOperation


class PendingInfrastructureRetirement(_PendingPolicyOperation):
    """Retry one exact dead infrastructure row independently of replacement."""

    def __init__(self, store, *, role, witness):
        super().__init__(store)
        if role not in {"guardian", "helper", "supervisor"} or not isinstance(witness, VerifiedProcess):
            raise ValueError("infrastructure_retirement_identity_required")
        self.role, self.witness, self.identity = role, witness, witness.identity

    def _dead(self):
        observed = self.witness.observe()
        if self.witness.identity != self.identity or observed.identity != self.identity:
            raise LifecycleError("infrastructure_retirement_identity_changed")
        return observed.status is IdentityStatus.DEAD

    def _absent(self):
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            _infra_schema(conn)
            identity = self.identity
            return conn.execute("""SELECT 1 FROM adaptive_infrastructure
                WHERE role=? AND pid=? AND created_filetime_100ns=? AND logon_id=? LIMIT 1""",
                (self.role, identity.pid, str(identity.created_filetime_100ns), identity.logon_id)).fetchone() is None

    def tick(self):
        if self._quarantine:
            return self._pending(self._quarantine, quarantine=True)
        if self._complete:
            return ReconcileResult(True, False, False, None, self._changed)
        try:
            if not self._dead():
                return self._pending("infrastructure_retirement_death_unverified")
        except BaseException as error:
            return self._failure(error)
        return self._run(self.identity.logon_id,
            lambda: unregister_dead_infrastructure_locked(self.store, self.role, self.witness), self._absent)


class FinishedBarrierJanitor(_PendingPolicyOperation):
    """Retry only original C3 ledger proof; never open a Job or infer death."""

    def __init__(self, store, journal):
        super().__init__(store)
        self.journal = journal
        self._candidate = None

    def _snapshot(self):
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self.store._policy._runtime(conn)
            slot = read_slot(conn)
            return runtime, slot

    def _candidate_proof(self, runtime, slot):
        if (runtime["admission_barrier"] != "RECOVERY_HOLD" or slot is None or
                slot["slot_state"] != "RESTORED" or slot["guardian_epoch"] != runtime["guardian_epoch"] or
                slot["logon_id"] != runtime["active_logon_id"]):
            raise LifecycleError("finished_barrier_prerequisite_unverified")
        row = self.store.query(slot["execution_id"], existing_path=True)
        if row["state"] != "FINISHED":
            raise LifecycleError("finished_barrier_execution_unfinished")
        manifest = self.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        disabled = CpuControl(CpuControlMode.DISABLED, None)
        if (type(manifest) is not RecoveryManifest or manifest.original != disabled or
                manifest.pending_intent is not None or manifest.last_applied not in (None, disabled)):
            raise LifecycleError("restore_unverified")
        self.store.assert_retained_terminal(row, manifest)
        return row, manifest

    def _audit_reconciled(self):
        if self._candidate is None:
            return False
        prior_runtime, prior_slot, row, manifest = self._candidate
        # Reconcile only the exact attempted clear, including its one audit;
        # a different writer making some barrier NONE is not our lost ACK.
        self.store.assert_retained_terminal(row, manifest)
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self.store._policy._runtime(conn)
            slot = read_slot(conn)
            if runtime["admission_barrier"] != "NONE":
                return False
            if (slot != prior_slot or runtime["guardian_epoch"] != prior_runtime["guardian_epoch"] or
                    runtime["policy_instance_id"] != prior_runtime["policy_instance_id"] or
                    runtime["policy_logon_id"] != prior_runtime["policy_logon_id"]):
                raise LifecycleError("finished_barrier_replay_binding_changed")
            records = conn.execute("""SELECT registry_revision,execution_id,slot_id,slot_revision,
                guardian_epoch,reason,finished_at FROM adaptive_barrier_clears
                WHERE registry_revision=? OR (execution_id=? AND slot_id=? AND slot_revision=?) LIMIT 2""",
                (prior_runtime["registry_revision"] + 1, row["execution_id"], prior_slot["slot_id"],
                 prior_slot["slot_revision"])).fetchall()
            expected = (prior_runtime["registry_revision"] + 1, row["execution_id"], prior_slot["slot_id"],
                prior_slot["slot_revision"], prior_slot["guardian_epoch"], "finished_job", float(row["finished_at"]))
            if len(records) != 1 or tuple(records[0]) != expected:
                raise LifecycleError("finished_barrier_audit_unverified")
        self._changed = True
        return True

    def tick(self, *, now=None):
        if self._quarantine:
            return self._pending(self._quarantine, quarantine=True)
        if self._complete:
            # The long-lived janitor must service a later independent episode.
            self.reset_completed()
            self._candidate = None
        try:
            runtime, slot = self._snapshot()
            if runtime["admission_barrier"] == "NONE" and self._guard is None:
                return ReconcileResult(True, False, False, None, False)
            if self._candidate is None or runtime["admission_barrier"] == "RECOVERY_HOLD":
                row, manifest = self._candidate_proof(runtime, slot)
                self._candidate = (runtime, slot, row, manifest)
            if self._candidate is None:
                return self._pending("finished_barrier_prerequisite_unverified")
        except BaseException as error:
            return self._failure(error)
        prior_runtime, prior_slot, row, manifest = self._candidate

        def clear():
            if self._audit_reconciled():
                return True
            self.store.assert_finished_barrier_clearable(row["execution_id"], caller=manifest.wrapper_identity,
                expected_revision=row["state_revision"], manifest=manifest)
            self.store.clear_recovery_hold_finished_locked(row["execution_id"], caller=manifest.wrapper_identity,
                expected_revision=row["state_revision"], expected_registry_revision=prior_runtime["registry_revision"],
                slot_id=prior_slot["slot_id"], manifest=manifest, now=now)
            return True

        return self._run(manifest.wrapper_identity.logon_id, clear, self._audit_reconciled)
