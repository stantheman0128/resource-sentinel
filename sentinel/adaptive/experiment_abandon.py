"""Original queued/rejected experiment cleanup, never admitted release authority."""
from __future__ import annotations

import json
import os
from pathlib import Path
import threading
from uuid import uuid4

from . import daily_generation as generation
from .experiment_cleanup import _NEW, _OPERATIONS, _OriginalCleanupAccess, _canonical, _fail
from .policy import PolicyBinding, PolicyCoordinator, PolicyGuard


class ExperimentUnadmittedCleanup(_OriginalCleanupAccess):
    _phases = frozenset({"READ", "ABANDON"})
    _owner_attribute = "experiment_unadmitted_owner"
    _owner_slot = "_unadmitted_cleanup"

    def __init__(self, coordinator, demand, *, _token=None):
        from .experiment_demand import DailyExperimentDemand
        if _token is not _NEW or type(demand) is not DailyExperimentDemand:
            _fail("original_unadmitted_required")
        self.coordinator, self.demand = coordinator, demand
        self.operation_id = str(uuid4())
        self.thread, self.pid = threading.current_thread(), os.getpid()
        self.ledger_path, self.ledger_identity = demand.ledger_path, demand.ledger_identity
        self.inner, self.snapshot = demand._admission, demand._snapshot
        self._process = self.inner._process
        self._submission = demand._submission_original
        if type(self._submission) is not tuple or len(self._submission) != 5:
            _fail("original_submission_guard_required", self)
        self.policy, self.store, self._guard, self._policy_binding, self._nonce = self._submission
        self._generation = demand._generation_original
        self._transaction = self.inner._submission_transaction
        self._transaction_items = tuple(self._transaction.items()) if type(self._transaction) is dict else None
        self._immutable_demand = demand._immutable
        self._retained = (coordinator, demand, self.inner, self.snapshot, self._process, self._submission,
            self._transaction, self.thread)
        self._fixed = (self.pid, self.operation_id, self.ledger_path, self.ledger_identity, self._generation)
        self._connections = {}
        self._error = self._quarantine = None
        self._candidate = self._writer = self._kind = None
        self._commit_attempted = self._committed = self._postread = False
        self._rollback_confirmed = False
        self._close_attempted = self._close_positive = self._completed = False
        self._close_error = self._local_error = None
        self._result_json = None
        _OPERATIONS[self.operation_id] = self

    def _original(self):
        from sentinel.coordinator import Coordinator
        from .experiment_demand import _RETAINED, _identity
        from .identity import VerifiedProcess
        actual = (self.coordinator, self.demand, self.inner, self.snapshot, self._process,
            self._submission, self._transaction, self.thread)
        if (type(self) is not ExperimentUnadmittedCleanup or
                any(left is not right for left, right in zip(actual, self._retained)) or
                (self.pid, self.operation_id, self.ledger_path, self.ledger_identity, self._generation) != self._fixed or
                _OPERATIONS.get(self.operation_id) is not self or self.demand._unadmitted_cleanup is not self or
                self.thread is not threading.current_thread() or self.pid != os.getpid() or
                self._quarantine is not None or type(self.coordinator) is not Coordinator or
                Path(self.coordinator.db_path).resolve() != self.ledger_path or
                getattr(self.coordinator, "_managed_store", None) is not self.store):
            _fail("original_unadmitted_changed", self)
        if (self.demand._submission_original is not self._submission or
                any(value is not self._submission[index] for index, value in
                    enumerate((self.policy, self.store, self._guard, self._policy_binding))) or
                self._nonce != self._submission[4] or type(self.policy) is not PolicyCoordinator or
                self.policy.store is not self.store or self.store._policy is not self.policy or
                Path(self.store.db_path).resolve() != self.ledger_path or
                type(self._guard) is not PolicyGuard or type(self._policy_binding) is not PolicyBinding or
                self._guard.binding != self._policy_binding or self._guard.nonce != self._nonce or
                self._policy_binding.logon_id != self.snapshot.logon_id):
            _fail("original_submission_changed", self)
        facts = (self._guard._native_exit_confirmed, self._guard._native_no_entry_confirmed)
        if (not all(type(value) is bool for value in facts) or facts not in {(True, False), (False, True)} or
                self._guard._nonce_clear_confirmed is not True or self._guard._nonce_clear_attempted is not True or
                self.inner._submission_guard is not None or self.inner._submission_policy_error is not None or
                self.inner._submission_prepare_unknown or self.inner._submission_policy is not self.policy):
            _fail("original_submission_cleanup_unverified", self)
        if (self.inner._submission_transaction is not self._transaction or
                self._transaction is not None and (type(self._transaction) is not dict or
                    tuple(self._transaction.items()) != self._transaction_items or
                    self._transaction.get("connection_closed") is not True or
                    self._transaction.get("connection") is None or
                    self._transaction.get("execution_id") != self.snapshot.execution_id or
                    self._transaction.get("db_path") != self.ledger_path) or
                self.inner._submitted and (self._transaction is None or self.inner._admission_db_path != self.ledger_path)):
            _fail("original_transaction_changed", self)
        if (self.demand._admission is not self.inner or self.demand._snapshot is not self.snapshot or
                self.demand._original_admission is not self.inner or self.inner._experiment_demand is not self.demand or
                self.demand._immutable is not self._immutable_demand or
                (self.demand.declaration, self.demand.directory, self.demand.ledger_path,
                 self.demand.directory_identity, self.demand.ledger_identity, self.demand._source_root) != self._immutable_demand or
                _RETAINED.get(self.demand.declaration.experiment_id) is not self.demand or
                self.demand._generation_original != self._generation or self.demand._quarantine is not None or
                not self.demand._native_preparation_sealed or self.demand._native_preparation is not None or
                self.demand._before_native_completion is not None or self.demand._release_operation is not None or
                self.inner._process is not self._process or type(self._process) is not VerifiedProcess or
                self._process.identity != self.snapshot.wrapper_identity or self.inner._claim_exported or
                self.inner._prepare_attempted or self.inner._cancel_sealed or self.inner._abandon_target is not None or
                _identity(self.demand.directory) != self.demand.directory_identity):
            _fail("original_demand_changed", self)
        self.demand._original_generation_binding()
        positive = self._close_positive or (self._close_attempted and self._close_error is None and
            self._process._handle is None and not self._process._close_outcome_unknown)
        if positive:
            if (not self._postread or not self._committed or self._result_json is None or
                    self._process._handle is not None or self._process._close_outcome_unknown or
                    self.inner._snapshot is not None and self.inner._snapshot is not self.snapshot):
                _fail("completed_owner_changed", self)
            if self._completed and (not self.inner._closed or not self.demand._closed or
                    self.inner._claim_token is not None or self.inner._key is not None or self.inner._snapshot is not None):
                _fail("completed_owner_changed", self)
            self._close_positive = True
        elif self.inner._closed or self.demand._closed or self.inner._snapshot is not self.snapshot:
            _fail("original_demand_closed", self)

    def prepare_policy(self, policy, logon):
        _fail("unadmitted_cleanup_no_new_policy", self)

    def _observe(self, conn):
        from . import experiment_history as history
        from .store import _check_version
        generation.revalidate_transaction(conn, db_path=self.ledger_path)
        if not _check_version(conn):
            _fail("lifecycle_schema_missing", self)
        observed = history.verify_experiment_history_locked(conn)
        experiment_id = self.demand.declaration.experiment_id
        if (experiment_id in observed.active_experiment_ids or
                self.snapshot.execution_id in observed.completed_execution_ids or
                any(json.loads(value)["experiment_id"] == experiment_id for value in
                    observed.receipts_json + observed.exclusions_json)):
            _fail("unadmitted_obligation_changed", self)
        budget = history._Budget(history.MAX_BYTES - observed.bytes_used)
        queued = history._rows(conn, "queue", history.QUEUE_FIELDS, budget,
            where="request_key=? OR managed_execution_id=?",
            parameters=(self.snapshot.request.request_key, self.snapshot.execution_id), limit=1)
        for table, condition, values in (
                ("managed_executions", "execution_id=? OR parent_execution_id=?",
                    (self.snapshot.execution_id, self.snapshot.execution_id)),
                ("reservations", "execution_id=? OR request_key=?",
                    (self.snapshot.execution_id, self.snapshot.request.request_key)),
                ("worker_reservations", "execution_id=? OR task_id=?",
                    (self.snapshot.execution_id, self.snapshot.task_id)),
                ("executions", "request_key=?", (self.snapshot.request.request_key,))):
            if conn.execute("SELECT 1 FROM " + table + " WHERE " + condition + " LIMIT 1", values).fetchone():
                _fail("unadmitted_obligation_changed", self)
        if self.policy._runtime(conn)["policy_entry_nonce"] == self._nonce:
            _fail("original_nonce_returned", self)
        if queued:
            self.inner._validate_queued(queued[0], self.snapshot)
            return queued[0]
        return None

    def _read(self):
        with self._scope("READ"), self.store._connection() as conn:
            conn.execute("BEGIN")
            queued = self._observe(conn)
            conn.rollback()
        return queued

    def _install_abandon_functions(self, conn, frame):
        def exact():
            self._validate(conn, frame)
            if (frame[1] != "ABANDON" or self._writer is not conn or not conn.in_transaction or
                    self._candidate is None or self._committed or self._close_attempted):
                _fail("original_queue_delete_required", self)

        def delete_authority(table, key):
            exact()
            return int(table == "queue" and key == self.snapshot.request.request_key)

        def row_owned(value):
            exact()
            return int(_canonical(json.loads(value)) == self._candidate)

        from .experiment_history import QUEUE_FIELDS
        conn.create_function("sentinel_daily_delete_authority", 2, delete_authority)
        conn.create_function("sentinel_experiment_queue_owned", 1, row_owned)
        projection = "json_object(" + ",".join("'" + key + "',OLD." + key for key in QUEUE_FIELDS) + ")"
        conn.execute("CREATE TEMP TRIGGER experiment_unadmitted_queue_guard BEFORE DELETE ON main.queue "
            "WHEN sentinel_experiment_queue_owned(" + projection + ") IS NOT 1 "
            "BEGIN SELECT RAISE(ABORT,'experiment_original_queue_required'); END")

    def _classify(self, queued, *, freeze=True):
        if self._kind is not None:
            if queued is not None:
                if self._kind != "QUEUED_CANCELLED" or _canonical(queued) != self._candidate or self._committed:
                    _fail("original_queue_changed", self)
            elif self._kind == "QUEUED_CANCELLED" and not self._commit_attempted:
                _fail("original_delete_absence_unverified", self)
            return
        if queued is not None:
            # A reader cannot freeze the writer's preimage: connect/BEGIN can
            # still fail cleanly while the original queue heartbeat advances.
            if freeze:
                self._candidate, self._kind = _canonical(queued), "QUEUED_CANCELLED"
        elif not self.inner._submitted:
            self._kind = "NOT_SUBMITTED"
        elif (self._transaction is not None and self._transaction.get("first_submission") is True and
                self._transaction.get("commit_attempted") is False and self._transaction.get("rolled_back") is True):
            self._kind = "SUBMISSION_REJECTED"
        else:
            _fail("unadmitted_absence_unverified", self)

    def _publication_transaction(self):
        with self._scope("ABANDON"), self.store._connection() as conn:
            self._writer = conn
            self._rollback_confirmed = False
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    queued = self._observe(conn)
                    self._classify(queued)
                    if queued is not None:
                        changed = conn.execute("DELETE FROM queue WHERE request_key=? AND managed_execution_id=?",
                            (self.snapshot.request.request_key, self.snapshot.execution_id)).rowcount
                        if changed != 1:
                            _fail("original_queue_delete_conflict", self)
                        self._commit_attempted = True
                        conn.commit()
                    else:
                        conn.rollback()
                    self._committed = True
                except BaseException as primary:
                    try:
                        conn.rollback()
                        self._rollback_confirmed = not conn.in_transaction
                    except BaseException as error:
                        primary._experiment_abandon_rollback_owner = conn
                        primary._experiment_abandon_rollback_error = error
                        primary.add_note("experiment_abandon_rollback_unverified")
                    raise
            finally:
                self._writer = None

    def _finish_self(self):
        from .identity import _known_close_failure
        if (not self._postread or not self._committed or self._connections or
                self.policy.current_guard() is not None or self.policy.current_cleanup_guard() is not None):
            _fail("unadmitted_cleanup_unsettled", self)
        if self._close_attempted and not self._close_positive:
            if self._close_error is None and self._process._handle is None and not self._process._close_outcome_unknown:
                self._close_positive = True
            elif (self._close_error is None or not _known_close_failure(self._close_error) or
                    self._process._close_outcome_unknown or self._process._handle is None):
                _fail("self_close_unverified", self)
        self._close_attempted = True
        try:
            if not self._close_positive:
                self._close_error = None
                self._process.close()
        except BaseException as error:
            self._close_error = error
            setattr(error, self._owner_attribute, self)
            if (not _known_close_failure(error) or self._process._close_outcome_unknown or
                    self._process._handle is None or tuple(getattr(error, "_identity_handle_cleanup", ())) != (self._process,) or
                    getattr(error, "__cause__", None) is not None or getattr(error, "__context__", None) is not None):
                self._quarantine = error
            raise
        self._close_positive = True
        try:
            self.inner._claim_token = self.inner._key = self.inner._snapshot = None
            self.inner._closed = self.demand._closed = True
            self._completed = True
        except BaseException as error:
            self._local_error = error
            setattr(error, self._owner_attribute, self)
            raise

    def abandon(self):
        self._original()
        if not self._close_attempted and self.inner.snapshot() is not self.snapshot:
            _fail("original_caller_changed", self)
        if (self._rollback_confirmed and not self._commit_attempted and not self._committed and
                not self._connections and self._writer is None):
            # Only this original positively closed, never-COMMIT-attempted
            # writer can discard a preimage. A lost COMMIT ACK remains sticky.
            self._candidate = self._kind = None
            self._rollback_confirmed = False
        queued = self._read()
        self._classify(queued, freeze=False)
        if not self._committed:
            if queued is None:
                self._committed = True
            else:
                self._publication_transaction()
        if self._read() is not None:
            _fail("original_queue_not_removed", self)
        self._postread = True
        self._result_json = _canonical(dict(cancelled=True, state=self._kind,
            execution_id=self.snapshot.execution_id, request_key=self.snapshot.request.request_key,
            reservation_id=None, launch_authorized=False))
        if not self._completed:
            self._finish_self()
        return json.loads(self._result_json)


def abandon(coordinator, demand):
    from sentinel.coordinator import Coordinator
    from .experiment_demand import DailyExperimentDemand
    if type(coordinator) is not Coordinator or type(demand) is not DailyExperimentDemand:
        _fail("original_unadmitted_required")
    with demand._lock, demand._admission._lock:
        operation = demand._unadmitted_cleanup
        if operation is None:
            demand._static_original()
            original = demand._submission_original
            if (Path(coordinator.db_path).resolve() != demand.ledger_path or
                    type(original) is not tuple or len(original) != 5 or
                    getattr(coordinator, "_managed_store", None) is not original[1]):
                _fail("actual_daily_coordinator_required")
            demand._native_preparation_sealed = True
            operation = ExperimentUnadmittedCleanup(coordinator, demand, _token=_NEW)
            demand._unadmitted_cleanup = operation
        elif (type(operation) is not ExperimentUnadmittedCleanup or operation.coordinator is not coordinator or
                operation.demand is not demand):
            _fail("original_unadmitted_changed", operation)
        try:
            return operation.abandon()
        except BaseException as error:
            from .policy import _cleanup_outcome_unverified
            if error is operation._close_error:
                # _finish_self already distinguished exact known FALSE from
                # unknown native close, preserving the same original handle.
                operation._error = error
            elif (error is operation._local_error and operation._close_positive and
                    operation._quarantine is None and not operation._connections and
                    not _cleanup_outcome_unverified(error, local_only=True)):
                operation._error = error
            else:
                operation._retain(error)
            raise
