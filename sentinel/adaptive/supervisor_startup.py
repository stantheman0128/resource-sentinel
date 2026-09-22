"""Bounded cold-start inspection and a retained supervisor-instance mutex.

This owner establishes only cooperating-supervisor exclusion. It never opens an
old PID, adopts a guardian, infers death, clears a row, or writes a Job control.
Fresh means positively empty: even terminal history is an old-state refusal,
not a partial history scan presented as recovery. Existing deployments without
this singleton protocol are excluded by the separate complete empty-state check.
"""
from __future__ import annotations

import os
import re
import threading
import time
from uuid import UUID, uuid5

from .contracts import IdentityStatus, ProcessIdentity
from .control_slot import _FIELDS, _ACTION_FIELDS, _BARRIER_CLEAR_FIELDS
from .identity import VerifiedProcess
from .legacy_writer import MAX_INFRASTRUCTURE, _infra_schema, initialize_registry_locked
from .policy import PolicyBinding, PolicyError
from .recovery_journal import RecoveryJournal
from .store import LifecycleError, _FENCE_FIELDS, _RETIREMENT_FIELDS
from .supervisor_reconcile import RetainedPolicyOperation
from .windows import NativePolicyMutex, NativePolicyMutexError, PolicyMutexLease


_INSTANCE_NAMESPACE = UUID("d84073a2-b0be-5bf9-9d7a-d1c05c1f1f45")
_DIRECTORY_LIMIT = 128
_JOURNAL_NAME = re.compile(r"(?:[0-9a-f-]{36}\.json|\.[0-9a-f-]{36}\.[0-9a-f]{32}\.tmp)", re.I)
_REQUEST_FIELDS = {"execution_id", "operation", "request_id", "payload_hash", "spec_hash", "guardian_epoch"}
_EMPTY_TABLES = {
    "managed_executions": {"execution_id", "state", "state_revision", "guardian_epoch", "logon_id",
        "job_name", "job_nonce", "launch_in_flight", "launch_sealed", "claim_consumed", "coverage",
        "allocation_kind", "reservation_id", "parent_execution_id", "root_pid", "root_created_filetime_100ns",
        "wrapper_pid", "wrapper_created_filetime_100ns", "hold_reason", "finished_at"},
    "adaptive_control_slot": set(_FIELDS),
    "adaptive_launch_requests": _REQUEST_FIELDS,
    "adaptive_launch_fences": set(_FENCE_FIELDS),
    "adaptive_retirement_requests": _REQUEST_FIELDS,
    "adaptive_prelaunch_retirements": set(_RETIREMENT_FIELDS),
    "adaptive_actions": set(_ACTION_FIELDS),
    # This audit table is created only at the first successful barrier clear.
    "adaptive_barrier_clears": set(_BARRIER_CLEAR_FIELDS),
}


class _ColdHold(LifecycleError):
    """A completed read found no new-start authority; not an uncertain write."""


def supervisor_instance_binding(binding):
    """A separate, deterministic namespace for this exact POLICY and logon."""
    if type(binding) is not PolicyBinding:
        raise LifecycleError("supervisor_startup_binding_invalid")
    identifier = str(uuid5(_INSTANCE_NAMESPACE, binding.logon_id + ":" + binding.instance_id))
    return PolicyBinding(identifier, binding.logon_id)


class SupervisorStartup:
    """Lifetime owner; exceptions retain this object as ``_supervisor_startup``.

    ``current`` and ``mutex_factory`` are trusted in-process native test seams.
    Acquire once on the host thread, then keep this object through every child
    creation and close on that same thread. ``assert_fresh`` is for initial
    creation only; replacement additionally needs the separate epoch protocol.
    """

    def __init__(self, store, journal, *, current=None, mutex_factory=None):
        self.store, self.journal = store, journal
        self._current_source = current
        self._mutex_factory = NativePolicyMutex if mutex_factory is None else mutex_factory
        self._current = self._mutex = self._scope = self._lease = None
        self.binding = self.instance_binding = None
        self._thread = self._native_thread = self._pid = None
        self._attempted = self._acquired = self._closing = self._closed = False
        self._entry_unknown = self._release_unknown = self._close_unknown = False
        self._construction_error = None
        self._acquire_error = None
        self._acquire_stage = None
        self._binding_operation = RetainedPolicyOperation(store)
        self._fresh_operation = RetainedPolicyOperation(store)
        self._binding_result = self._fresh_result = None
        self._bootstrap_binding = None
        self._fresh_snapshot = self._fresh_refusal = None

    @property
    def policy_result(self):
        """Latest bounded POLICY attempt; None means none was needed yet."""
        return self._fresh_result if self._fresh_result is not None else self._binding_result

    @property
    def policy_guard(self):
        """The exact retained in-process guard, never reconstructed from SQL."""
        return self._fresh_operation.guard or self._binding_operation.guard

    @property
    def policy_pending(self):
        return (self._binding_operation.pending or self._fresh_operation.pending or
                (self.policy_result is not None and self.policy_result.pending))

    @property
    def policy_quarantined(self):
        return bool(self._fresh_operation._quarantine or self._binding_operation._quarantine)

    @property
    def acquired(self):
        return (self._acquired and self._acquire_stage == "held" and self._acquire_error is None and
                not self._closing and not self._closed and not self._entry_unknown and
                not self._release_unknown and not self._close_unknown)

    @property
    def can_retry_acquire(self):
        """Only pre-mutex binding work can resume through retry_acquire()."""
        return (self._attempted and self._acquire_stage == "binding" and
                self._acquire_error is not None and not self.policy_quarantined and
                not self._closed and not self._closing and self._mutex is None and
                not self._entry_unknown and not self._release_unknown and not self._close_unknown)

    def _policy_failure(self, operation, result):
        # Preserve the original exception and all attached cleanup owners.
        # A status result without a native/SQL exception still has a stable
        # reason and cannot be confused with completed startup inspection.
        original = operation._error
        previous_reason = getattr(original, "reason", str(original))
        if not isinstance(previous_reason, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", previous_reason):
            previous_reason = type(original).__name__
        error = (original if original is not None and result.reason == previous_reason else
                 self._error(result.reason or "supervisor_startup_policy_pending"))
        error._supervisor_startup = self
        error._supervisor_startup_policy_result = result
        if error is not original:
            raise error from original
        raise error

    def _error(self, reason):
        error = LifecycleError(reason)
        error._supervisor_startup = self
        return error

    def _refusal(self, reason):
        error = _ColdHold(reason)
        error._supervisor_startup = self
        return error

    def _validate_current(self):
        if not isinstance(self._current, VerifiedProcess):
            raise self._error("supervisor_startup_current_unverified")
        observed = self._current.observe()
        if (self._current.identity.pid != os.getpid() or
                observed.identity != self._current.identity or observed.status is not IdentityStatus.ALIVE):
            raise self._error("supervisor_startup_current_unverified")

    @staticmethod
    def _bound_read(conn):
        conn.execute("PRAGMA busy_timeout=250")
        deadline = time.monotonic() + .250
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        conn.execute("BEGIN")

    def _read_binding(self):
        with self.store._connection() as conn:
            self._bound_read(conn)
            runtime = self.store._policy._runtime(conn)
            binding = self.store._policy._binding(runtime, self._current.identity.logon_id)
            if runtime["active_logon_id"] not in {"", self._current.identity.logon_id}:
                raise self._error("supervisor_startup_binding_invalid")
            return binding

    def _acquire_binding(self):
        if self._binding_result is None:
            binding = self._read_binding()
            if binding is not None:
                return binding
        # Bootstrap only the missing namespace through normal POLICY. Persist
        # the operation before prepare: an exception after commit must keep
        # its owner, and an unreturned guard is quarantined, never fabricated.
        def bind():
            self._bootstrap_binding = self.store._policy.assert_held().binding
            return False

        def reconciled():
            return self._bootstrap_binding is not None and self._read_binding() == self._bootstrap_binding

        self._binding_result = self._binding_operation._run(self._current.identity.logon_id, bind, reconciled)
        if not self._binding_result.complete:
            self._policy_failure(self._binding_operation, self._binding_result)
        if type(self._bootstrap_binding) is not PolicyBinding:
            raise self._error("supervisor_startup_binding_unverified")
        return self._bootstrap_binding

    def _finish_acquire(self):
        self.binding = self._acquire_binding()
        self.instance_binding = supervisor_instance_binding(self.binding)
        self._acquire_stage = "mutex"
        try:
            try:
                self._mutex = self._mutex_factory(self.instance_binding.logon_id, self.instance_binding.instance_id)
            except BaseException as error:
                self._construction_error = error
                raise
            self._scope = self._mutex.acquire(timeout_ms=250)
            self._entry_unknown = True
            try:
                self._lease = self._scope.__enter__()
            except NativePolicyMutexError as error:
                if error.reason in {"policy_mutex_timeout", "policy_mutex_wait_failed"} and not getattr(error, "__notes__", ()):
                    self._entry_unknown = False
                    self._scope = None
                raise
            self._entry_unknown = False
            self._acquired = True
            lease = self._lease
            if (type(lease) is not PolicyMutexLease or lease.name != self.instance_binding.name or
                    lease.instance_id != self.instance_binding.instance_id or
                    lease.logon_id != self.instance_binding.logon_id or type(lease.abandoned) is not bool):
                raise self._error("supervisor_startup_mutex_binding_invalid")
            if self._read_binding() != self.binding:
                raise self._error("supervisor_startup_binding_changed")
            self._acquire_stage = "held"
            return self
        except BaseException as error:
            self._acquire_error = error
            error._supervisor_startup = self
            raise

    def acquire(self):
        if self._attempted or self._closed:
            raise self._error("supervisor_startup_acquire_repeated")
        self._attempted = True
        self._thread, self._native_thread, self._pid = threading.current_thread(), threading.get_native_id(), os.getpid()
        try:
            self._acquire_stage = "identity"
            if getattr(self.store, "existing_path", False) is not True or not isinstance(self.journal, RecoveryJournal):
                raise self._error("supervisor_startup_existing_ledger_required")
            self._current = (VerifiedProcess.current() if self._current_source is None
                             else self._current_source.duplicate())
            self._validate_current()
            self._acquire_stage = "binding"
            return self._finish_acquire()
        except BaseException as error:
            self._acquire_error = error
            error._supervisor_startup = self
            raise

    def retry_acquire(self):
        """Resume only a retained pre-mutex POLICY attempt, once this tick."""
        if not self.can_retry_acquire:
            raise self._error("supervisor_startup_acquire_retry_unavailable")
        if (self._thread is not threading.current_thread() or self._native_thread != threading.get_native_id() or
                self._pid != os.getpid()):
            raise self._error("supervisor_startup_foreign_owner")
        try:
            self._validate_current()
            self._acquire_error = None
            return self._finish_acquire()
        except BaseException as error:
            self._acquire_error = error
            error._supervisor_startup = self
            raise

    def _held(self, *, inspection=False):
        if (self._closed or self._closing or not self._acquired or self._acquire_error is not None or
                self._entry_unknown or self._release_unknown or self._close_unknown):
            raise self._error("supervisor_startup_mutex_unverified")
        if (self._thread is not threading.current_thread() or self._native_thread != threading.get_native_id() or
                self._pid != os.getpid()):
            raise self._error("supervisor_startup_foreign_owner")
        self._validate_current()
        if self._lease.abandoned and not inspection:
            raise self._error("supervisor_startup_mutex_abandoned")

    def assert_held(self):
        self._held()

    def _journal_empty(self):
        # Canonical manifests or unfinished publication files are obligations,
        # including files whose ledger row disappeared. Do not parse/recover or
        # erase them. Unrelated daily data files are not manifest candidates.
        self.journal._check_directory()
        with os.scandir(self.journal._directory) as entries:
            for count, entry in enumerate(entries, 1):
                if count > _DIRECTORY_LIMIT:
                    raise self._refusal("supervisor_startup_inventory_incomplete")
                if _JOURNAL_NAME.fullmatch(entry.name):
                    raise self._refusal("supervisor_startup_old_manifest")
        self.journal._check_directory()

    def assert_fresh_locked(self):
        """Inspect under the caller's actual POLICY lease; never reacquire it."""
        self._held(inspection=True)
        guard = self.store._policy.assert_held()
        if guard.binding != self.binding:
            raise self._error("supervisor_startup_binding_changed")
        initialize_registry_locked(self.store)
        with self.store._connection() as conn:
            self._bound_read(conn)
            runtime = self.store._policy.revalidate(conn, guard)
            if self.store._policy._binding(runtime, self.binding.logon_id) != self.binding:
                raise self._error("supervisor_startup_binding_changed")
            _infra_schema(conn)
            infrastructure = conn.execute("""SELECT
                CASE WHEN typeof(role)='text' AND length(role)<=10 THEN role END AS role,
                CASE WHEN typeof(pid)='integer' THEN pid END AS pid,
                CASE WHEN typeof(created_filetime_100ns)='text' AND length(created_filetime_100ns)<=20
                    THEN created_filetime_100ns END AS created_filetime_100ns,
                CASE WHEN typeof(logon_id)='text' AND length(logon_id)<=184 THEN logon_id END AS logon_id,
                CASE WHEN typeof(schema_version)='integer' THEN schema_version END AS schema_version
                FROM adaptive_infrastructure LIMIT ?""", (MAX_INFRASTRUCTURE + 1,)).fetchall()
            if len(infrastructure) > MAX_INFRASTRUCTURE:
                raise self._refusal("supervisor_startup_inventory_incomplete")
            for row in infrastructure:
                if (row["role"] not in {"guardian", "helper", "supervisor"} or row["schema_version"] != 1 or
                        row["logon_id"] != self.binding.logon_id):
                    raise self._refusal("supervisor_startup_infrastructure_invalid")
                try:
                    ProcessIdentity.from_dict({"pid": row["pid"], "created_filetime_100ns": row["created_filetime_100ns"],
                                               "logon_id": row["logon_id"]})
                except (ValueError, TypeError):
                    raise self._refusal("supervisor_startup_infrastructure_invalid") from None
            if infrastructure:
                raise self._refusal("supervisor_startup_cold_adoption_unsupported")
            if (runtime["guardian_epoch"] != "" or runtime["active_logon_id"] not in {"", self.binding.logon_id}):
                raise self._refusal("supervisor_startup_old_guardian_binding")
            if runtime["admission_barrier"] != "NONE":
                raise self._refusal("supervisor_startup_unresolved_barrier")
            # An EXISTS probe is complete when empty and bounded when nonempty.
            # It rejects terminal history rather than granting authority after
            # examining only the first page of permanent historical rows.
            for table, fields in _EMPTY_TABLES.items():
                found = conn.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
                if found is None and table == "adaptive_barrier_clears":
                    continue
                if found is None or found[0] != "table":
                    raise self._refusal("supervisor_startup_inventory_unavailable")
                if not fields.issubset({row[1] for row in conn.execute("PRAGMA table_info(" + table + ")")}):
                    raise self._refusal("supervisor_startup_inventory_invalid")
                if conn.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone() is not None:
                    raise self._refusal("supervisor_startup_old_scope_or_launch")
            for table in ("reservations", "worker_reservations"):
                # A published managed reservation can precede its execution
                # row. Absence of that row does not prove no launch obligation.
                if conn.execute("SELECT 1 FROM " + table + " WHERE execution_id IS NOT NULL OR lifecycle_managed IS NOT 0 LIMIT 1").fetchone():
                    raise self._refusal("supervisor_startup_old_allocation")
        self._journal_empty()
        if self._lease.abandoned:
            raise self._refusal("supervisor_startup_mutex_abandoned")
        self._held()
        return runtime

    def assert_fresh(self):
        """One bounded attempt, resuming its exact guard after SQL failure.

        No old empty snapshot is a launch permit. After lost cleanup ACK with
        a now-clear nonce, spend this tick retiring bookkeeping and require a
        later complete fenced inspection before returning a fresh snapshot.
        """
        self._held(inspection=True)
        if self._fresh_operation._complete:
            self._fresh_operation.reset_completed()
        self._fresh_snapshot = self._fresh_refusal = None

        def inspect():
            if self.store._policy.assert_held().binding != self.binding:
                raise PolicyError("policy_entry_changed")
            try:
                self._fresh_snapshot = self.assert_fresh_locked()
            except _ColdHold as failure:
                # Inventory refusal is read-only (apart from idempotent registry
                # initialization). Let known POLICY cleanup finish normally; do
                # not strand an entry nonce merely because old state was found.
                if getattr(failure, "__notes__", ()):
                    raise
                self._fresh_refusal = failure
            return False

        self._fresh_result = self._fresh_operation._run(self.binding.logon_id, inspect, lambda: False)
        if not self._fresh_result.complete:
            self._policy_failure(self._fresh_operation, self._fresh_result)
        if self._fresh_refusal is not None:
            raise self._fresh_refusal
        if self._fresh_snapshot is None:
            raise self._error("supervisor_startup_fresh_inspection_required")
        return self._fresh_snapshot

    def close(self):
        """Release once and close known owners; ambiguous native results hold."""
        if self._closed:
            return
        if self._attempted and (self._thread is not threading.current_thread() or
                               self._native_thread != threading.get_native_id() or self._pid != os.getpid()):
            raise self._error("supervisor_startup_foreign_owner")
        if self.policy_pending:
            raise self._error("supervisor_startup_policy_unsettled")
        self._closing = True
        if self._entry_unknown or self._release_unknown or self._close_unknown:
            raise self._error("supervisor_startup_native_cleanup_unknown")
        if self._construction_error is not None and (
                not isinstance(self._construction_error, NativePolicyMutexError) or
                getattr(self._construction_error, "_policy_mutex_cleanup", ()) or
                getattr(self._construction_error, "_identity_handle_cleanup", ()) or
                getattr(self._construction_error, "__notes__", ())):
            raise self._error("supervisor_startup_construction_cleanup_unknown")
        if self._acquire_error is not None and getattr(self._acquire_error, "_identity_handle_cleanup", ()):
            raise self._error("supervisor_startup_construction_cleanup_unknown")
        if self._acquired:
            self._release_unknown = True
            try:
                suppressed = self._scope.__exit__(None, None, None)
                if suppressed:
                    raise self._error("supervisor_startup_native_cleanup_unknown")
            except BaseException as error:
                error._supervisor_startup = self
                raise
            self._acquired = False
            self._scope = self._lease = None
            self._release_unknown = False
        if self._mutex is not None:
            self._close_unknown = True
            try:
                self._mutex.close()
            except BaseException as error:
                if (isinstance(error, NativePolicyMutexError) and
                        error.reason == "policy_mutex_handle_close_failed" and not getattr(error, "__notes__", ())):
                    self._close_unknown = False
                error._supervisor_startup = self
                raise
            self._mutex = None
            self._close_unknown = False
        if self._current is not None:
            self._current.close()
            self._current = None
        self._closed = True
