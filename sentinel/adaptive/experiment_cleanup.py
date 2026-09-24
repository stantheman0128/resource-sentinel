"""Original experiment cleanup custody and narrowly scoped ledger access.

No serialized completion, current generation observation or caller callback can
construct this operation. Its read/nonce phases grant no capacity authority.
Only the original PUBLISH phase can commit the complete receipt/release tuple;
retaining an operation does not itself release capacity or close the final self
witness. Successful replay verifies that tuple through bounded reads only.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import hashlib
import hmac
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import uuid4

from . import daily_generation as generation
from .policy import PolicyBinding, PolicyBusy, PolicyCoordinator, PolicyGuard


_NEW = object()
_LOCAL = threading.local()
_OPERATIONS = {}
_PHASES = frozenset({"READ", "HOLD", "NONCE", "CLEAR", "PUBLISH"})


class ExperimentReleaseError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = "experiment_release_" + reason, owner
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise ExperimentReleaseError(reason, owner)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def current_operation(db_path=None):
    """Return only the current lexical original, never a cached authority."""
    frame = getattr(_LOCAL, "frame", None)
    if frame is None:
        return None
    operation = frame[0]
    from .experiment_abandon import ExperimentUnadmittedCleanup
    if type(operation) not in (ExperimentReleaseOperation, ExperimentAdmissionSettlement, ExperimentUnadmittedCleanup):
        _fail("original_operation_required")
    operation._current(frame)
    if db_path is not None and Path(db_path).resolve() != operation.ledger_path:
        _fail("ledger_changed", operation)
    return operation


class _OriginalCleanupAccess:
    """Shared SQL custody; only closed concrete owners supply authority."""
    _phases = _PHASES
    _owner_attribute = "experiment_release_owner"
    _owner_slot = "_release_operation"

    def _retain(self, error):
        setattr(error, self._owner_attribute, self)
        # Preserve the first unknown owner's entire exception graph. A later
        # retry must not overwrite the sole reachable native cleanup witness.
        if self._quarantine is not None:
            return
        self._error = error
        from .policy import _cleanup_outcome_unverified
        if _cleanup_outcome_unverified(error):
            self._quarantine = error
            return
        from .windows import NativePolicyMutexError
        pending, seen = [error], set()
        while pending:
            current = pending.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            notes = tuple(getattr(current, "__notes__", ()))
            if (len(seen) > 32 or not isinstance(current, Exception) or self._connections or
                    any(note != "policy_entry_cleanup_failed" for note in notes) or
                    any(getattr(current, key, None) for key in (
                        "_identity_handle_cleanup", "_policy_mutex_cleanup", "_sentinel_connection_cleanup",
                        "_native_close_outcome_unknown", "_native_duplicate_outcome_unknown", "io_pending")) or
                    isinstance(current, NativePolicyMutexError) and
                    current.reason not in {"policy_mutex_timeout", "policy_mutex_wait_failed"}):
                self._quarantine = error
                return
            pending.extend(value for value in (getattr(current, "__cause__", None),
                getattr(current, "__context__", None), getattr(current, "_daily_readiness_cause", None),
                getattr(current, "_policy_entry_cleanup_error", None))
                if isinstance(value, BaseException))

    def _current(self, frame):
        self._original()
        if getattr(_LOCAL, "frame", None) is not frame or frame[0] is not self:
            _fail("lexical_scope_changed", self)

    @contextmanager
    def _scope(self, phase):
        self._original()
        previous = getattr(_LOCAL, "frame", None)
        if phase not in self._phases or previous is not None and previous[0] is not self:
            _fail("phase_invalid", self)
        if self._close_positive and phase != "READ":
            _fail("completed_operation_read_only", self)
        frame = (self, phase, object())
        _LOCAL.frame = frame
        try:
            yield self
        except BaseException as error:
            self._retain(error)
            raise
        finally:
            # A connection retained beyond its own lexical operation is an
            # unresolved original obligation, never reusable ambient authority.
            if any(bound is frame for _, bound in self._connections.values()):
                self._quarantine = self._error or ExperimentReleaseError("connection_unsettled", self)
            _LOCAL.frame = previous

    @contextmanager
    def connection_scope(self, db_path):
        frame = getattr(_LOCAL, "frame", None)
        self._current(frame)
        if Path(db_path).resolve() != self.ledger_path:
            _fail("ledger_changed", self)
        yield self

    def _validate(self, conn, frame):
        self._current(frame)
        if self._connections.get(id(conn)) != (conn, frame):
            _fail("connection_changed", self)
        original = self.demand._original_generation_binding()
        actual = generation.read_generation(conn)
        if actual is None or actual["state"] not in {"ACTIVE", "DRAINING"}:
            _fail("generation_changed", self)
        if actual != dict(original, state=actual["state"]):
            _fail("generation_changed", self)
        from .daily_retirement_fence import read_retirement
        retirement = read_retirement(conn)
        if retirement is not None and retirement["phase"] == "SEALED" and frame[1] in {"PUBLISH", "ABANDON"}:
            _fail("generation_sealed", self)
        generation._assert_daily_locations(original["source_root"], self.ledger_path)
        if (not generation._ledger_matches(conn, self.ledger_path) or
                generation._ledger_identity(self.ledger_path) != self.ledger_identity or
                generation._fixed_policy_digest(self.ledger_path) != original["config_digest"]):
            _fail("ledger_or_config_changed", self)
        generation.verify_import_provenance(
            generation.SourceManifest.from_dict(json.loads(original["source_manifest_json"])),
            original["source_root"])
        runtime = self.policy._runtime(conn)
        binding = self.policy._binding(runtime, self._policy_binding.logon_id)
        if (binding != self._policy_binding or runtime["mode"] != "off" or
                runtime["active_logon_id"] not in {"", binding.logon_id}):
            _fail("policy_binding_changed", self)
        return runtime

    def bind_connection(self, conn, *, role, db_path):
        frame = getattr(_LOCAL, "frame", None)
        self._current(frame)
        if (role != "lifecycle" or conn.in_transaction or
                Path(db_path).resolve() != self.ledger_path or id(conn) in self._connections or
                len(self._connections) >= 8):
            _fail("connection_scope_invalid", self)
        self._connections[id(conn)] = conn, frame
        conn.execute("PRAGMA busy_timeout=250")
        self._validate(conn, frame)
        phase = frame[1]
        # Never register sentinel_daily_generation. Publication alone receives
        # exact receipt-bound mutation authority, separate from read/nonce.
        def nonce_owned(old, new):
            runtime = self._validate(conn, frame)
            if self._guard is None or self._guard.binding != self._policy_binding:
                return 0
            if phase == "NONCE":
                return int(self._nonce_attempted and old is None and new == self._guard.nonce and
                    runtime["policy_entry_nonce"] is None and self.policy.current_guard() is None)
            if phase == "CLEAR":
                return int(old == self._guard.nonce and new is None and
                    self.policy.current_cleanup_guard() is self._guard and self.policy.current_guard() is None)
            return 0
        conn.create_function("sentinel_experiment_nonce_owned", 2, nonce_owned)
        conn.execute("""CREATE TEMP TRIGGER experiment_release_nonce_guard
            BEFORE UPDATE OF policy_entry_nonce ON main.adaptive_runtime
            WHEN sentinel_experiment_nonce_owned(OLD.policy_entry_nonce,NEW.policy_entry_nonce) IS NOT 1
            BEGIN SELECT RAISE(ABORT,'experiment_release_nonce_not_owned'); END""")
        if phase == "PUBLISH":
            self._install_publication_functions(conn, frame)
        elif phase == "ABANDON":
            self._install_abandon_functions(conn, frame)
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                   sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
        def authorize(action, table, column, database, source):
            # SQLite may cache statements, so write-time triggers above also
            # validate the same original lexical frame and actual SQL snapshot.
            if (getattr(_LOCAL, "frame", None) is not frame or frame[0] is not self or
                    _OPERATIONS.get(self.operation_id) is not self or getattr(self.demand, self._owner_slot) is not self or
                    threading.current_thread() is not self.thread or os.getpid() != self.pid or
                    self._quarantine is not None or self._close_positive and phase != "READ" or
                    self._connections.get(id(conn)) != (conn, frame)):
                return sqlite3.SQLITE_DENY
            if action in allowed:
                if action == sqlite3.SQLITE_FUNCTION and column == "load_extension":
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and (
                    table in {"table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list"} or
                    table == "database_list" and column is None or
                    table == "foreign_keys" and (column is None or str(column).lower() in {"on", "1"}) or
                    table == "busy_timeout" and (column is None or str(column).isdigit() and int(column) <= 250)):
                return sqlite3.SQLITE_OK
            if (phase in {"NONCE", "CLEAR"} and action == sqlite3.SQLITE_UPDATE and
                    database == "main" and table == "adaptive_runtime" and column == "policy_entry_nonce"):
                return sqlite3.SQLITE_OK
            if phase == "ABANDON" and action == sqlite3.SQLITE_DELETE and database == "main" and table == "queue":
                return sqlite3.SQLITE_OK
            if phase == "PUBLISH" and database == "main":
                if (action == sqlite3.SQLITE_INSERT and table in {"adaptive_experiment_cleanup_receipts", "executions"} or
                        action == sqlite3.SQLITE_DELETE and table in {"reservations", "queue"} or
                        action == sqlite3.SQLITE_UPDATE and table == "managed_executions" and column in {
                            "state", "state_revision", "finished_at", "cancel_requested_at", "launch_sealed",
                            "launch_in_flight", "claim_consumed", "claim_token_hash", "hold_reason"} or
                        action == sqlite3.SQLITE_UPDATE and table == "adaptive_experiment_exclusions" and
                            column in {"phase", "cleanup_digest"} or
                        action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and column == "registry_revision"):
                    return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(authorize)

    def revalidate_connection(self, conn, *, db_path):
        frame = getattr(_LOCAL, "frame", None)
        if Path(db_path).resolve() != self.ledger_path or not conn.in_transaction:
            _fail("transaction_scope_invalid", self)
        self._validate(conn, frame)

    def connection_closed(self, conn):
        """Called only after the original LifecycleStore conn.close succeeds."""
        bound = self._connections.get(id(conn))
        if bound is not None:
            if bound[0] is not conn:
                _fail("connection_changed", self)
            self._connections.pop(id(conn))

    @contextmanager
    def nonce_cleanup(self, policy, guard):
        self._original()
        if (policy is not self.policy or guard is not self._guard or
                policy.current_guard() is not None or guard.binding != self._policy_binding):
            _fail("nonce_cleanup_not_owned", self)
        with self._scope("CLEAR"):
            yield


class ExperimentReleaseOperation(_OriginalCleanupAccess):
    """Retained before release-side SQL; owned by one original demand/thread."""

    def __init__(self, demand, completion, *, _token=None):
        from .experiment_demand import DailyExperimentDemand
        if _token is not _NEW or type(demand) is not DailyExperimentDemand:
            _fail("original_operation_required")
        self.demand, self.completion = demand, completion
        self.operation_id, self.receipt_id = str(uuid4()), str(uuid4())
        self.thread, self.pid = threading.current_thread(), os.getpid()
        self.ledger_path, self.ledger_identity = demand.ledger_path, demand.ledger_identity
        self.inner, self.snapshot = demand._admission, demand._snapshot
        self.policy = self.inner._submission_policy
        self.store = None if self.policy is None else self.policy.store
        self._generation = demand._generation_original
        self._policy_binding = demand._policy_original
        self._completion_json = self._completion_digest = None
        self._initialized = False
        self._guard = None
        self._guard_original = None
        self._connections = {}
        self._error = self._quarantine = None
        self._nonce_attempted = False
        self._candidate = self._candidate_sha = self._raw_preimage = None
        self._writer = None
        self._committed = self._policy_settled = self._postread = False
        self._commit_attempted = False
        self._rollback_confirmed = False
        self._close_attempted = self._close_positive = self._completed = False
        self._close_error = self._result_json = None
        self._process = self.inner._process
        self._retained = (demand, completion, self.inner, self.snapshot, self.policy, self.store,
            self.operation_id, self.receipt_id, self.thread, self.pid,
            self.ledger_path, self.ledger_identity, self._generation, self._policy_binding, self._process)
        _OPERATIONS[self.operation_id] = self

    def _initialize(self):
        from .experiment_demand import BeforeNativeCompletion
        from .experiment_scope import NativeScopeCompletion
        self._original(initializing=True)
        if type(self.completion) is BeforeNativeCompletion:
            if self.completion.owner is not self.demand:
                _fail("completion_owner_changed", self)
        elif type(self.completion) is NativeScopeCompletion:
            if self.completion.owner is not self.demand._native_preparation:
                _fail("completion_owner_changed", self)
        else:
            _fail("original_completion_required", self)
        self.completion.assert_original()
        self.demand._assert_unused_claim()
        if (type(self._policy_binding) is not PolicyBinding or self.policy is None or
                self.policy.store is not self.store or self.store._policy is not self.policy or
                Path(self.store.db_path).resolve() != self.ledger_path):
            _fail("original_policy_required", self)
        self.demand._original_generation_binding()
        record = self.completion.snapshot()
        if record["demand"] != self.demand._completion_binding():
            _fail("completion_binding_changed", self)
        self._completion_json = _canonical(record)
        self._completion_digest = self.completion.digest
        # Preserve the private credential until the receipt transaction destroys
        # it, but permanently forbid any ordinary admission/launch operation.
        self.inner._cancel_sealed = True
        self._initialized = True

    def _original(self, *, initializing=False):
        if (type(self) is not ExperimentReleaseOperation or
                _OPERATIONS.get(self.operation_id) is not self or
                self.demand._release_operation is not self or
                self.inner._process is not self._process or
                (self.demand, self.completion, self.inner, self.snapshot, self.policy, self.store,
                 self.operation_id, self.receipt_id, self.thread, self.pid,
                 self.ledger_path, self.ledger_identity, self._generation, self._policy_binding, self._process) != self._retained or
                self.thread is not threading.current_thread() or self.pid != os.getpid()):
            _fail("original_operation_changed", self)
        if self._guard is not None and (self._guard_original is None or
                self._guard is not self._guard_original[0] or
                (self._guard.binding, self._guard.nonce) != self._guard_original[1:]):
            _fail("original_guard_changed", self)
        positive_self = self._close_positive or (self._close_attempted and self._close_error is None and
            self._process._handle is None and not self._process._close_outcome_unknown)
        if positive_self:
            frame = getattr(_LOCAL, "frame", None)
            active_read = frame is not None and frame[0] is self and frame[1] == "READ"
            if (not self._postread or not self._policy_settled or
                    not self._committed or any(not active_read or bound is not frame
                        for _, bound in self._connections.values()) or self._quarantine is not None or
                    self.inner._process is not self._process or
                    self._process._handle is not None or self._process._close_outcome_unknown or
                    self.inner._snapshot is not None and self.inner._snapshot is not self.snapshot or self._result_json is None or
                    self.demand._release_operation is not self or self.demand._admission is not self.inner or
                    self.demand._snapshot is not self.snapshot or self.demand._generation_original != self._generation or
                    self.demand._policy_original is not self._policy_binding or self.completion.digest != self._completion_digest or
                    self._process.identity != self.snapshot.wrapper_identity):
                _fail("completed_owner_changed", self)
            if self._completed and (not self.demand._closed or not self.inner._closed or
                    self.inner._claim_token is not None or self.inner._key is not None or self.inner._snapshot is not None):
                _fail("completed_owner_changed", self)
            # Local bookkeeping may have been interrupted after the original
            # close returned. This branch confers only READ and finish-local.
            self._close_positive = True
            return
        self.demand._static_original()
        if (not self.demand._native_preparation_sealed or self.inner is not self.demand._admission or
                self.snapshot is not self.demand._snapshot or
                self._generation != self.demand._generation_original or
                self._policy_binding is not self.demand._policy_original):
            _fail("original_binding_changed", self)
        if self._quarantine is not None:
            _fail("cleanup_unverified", self)
        if not initializing:
            if not self._initialized or not self.inner._cancel_sealed:
                _fail("initialization_unsettled", self)
            self.completion.assert_original()
            if (self.completion.digest != self._completion_digest or
                    _canonical(self.completion.snapshot()) != self._completion_json):
                _fail("completion_binding_changed", self)









    def prepare_policy(self, policy, logon):
        self._original()
        if policy is not self.policy or logon != self._policy_binding.logon_id:
            _fail("policy_binding_changed", self)
        if self._guard is None:
            self._guard = PolicyGuard(self._policy_binding, str(uuid4()))
            self._guard_original = (self._guard, self._guard.binding, self._guard.nonce)
        # Original guard/candidate exists before even opening the SQL writer.
        # A lost COMMIT acknowledgement keeps this object, never adopts a nonce.
        self._nonce_attempted = True
        with self._scope("NONCE"):
            with self.store._transaction() as conn:
                runtime = self._validate(conn, getattr(_LOCAL, "frame"))
                if runtime["policy_entry_nonce"] is not None:
                    if runtime["policy_entry_nonce"] != self._guard.nonce:
                        raise PolicyBusy("policy_scope_busy")
                    policy.revalidate(conn, self._guard)
                elif conn.execute("""UPDATE adaptive_runtime SET policy_entry_nonce=?
                        WHERE singleton=1 AND policy_entry_nonce IS NULL AND policy_binding_initialized=1
                        AND policy_instance_id=? AND policy_logon_id=?""",
                        (self._guard.nonce, self._policy_binding.instance_id, logon)).rowcount != 1:
                    _fail("nonce_conflict", self)
        return self._guard

    @contextmanager
    def hold_policy(self):
        """Keep unknown pre-yield native outcomes on this exact operation."""
        from .windows import NativePolicyMutexError
        self._original()
        if self._guard is None:
            _fail("original_guard_required", self)
        entered = False
        with self._scope("HOLD"):
            try:
                with self.policy.hold(self._guard) as guard:
                    entered = True
                    yield guard
            except BaseException as error:
                timeout_cleanup = (isinstance(error, NativePolicyMutexError) and error.reason == "policy_mutex_timeout" and
                    self._guard._native_no_entry_confirmed and
                    all(note == "policy_entry_cleanup_failed" for note in getattr(error, "__notes__", ())))
                if self._quarantine is None and not entered and not (isinstance(error, NativePolicyMutexError) and
                        error.reason in {"policy_mutex_timeout", "policy_mutex_wait_failed"} and
                        not getattr(error, "__notes__", ())) and not timeout_cleanup:
                    self._quarantine = self._error = error
                self._retain(error)
                raise


    @staticmethod
    def _wire(row):
        value = dict(row)
        if "ipc_auth_key" in value:
            key = value["ipc_auth_key"]
            if type(key) is not bytes or len(key) != 32:
                _fail("credential_binding_changed")
            value["ipc_auth_key"] = key.hex()
            value["ipc_auth_key_sqlite_type"] = "blob"
        return value

    def _record(self):
        from . import experiment_history as history
        if self._candidate is None:
            _fail("publication_not_prepared", self)
        record = json.loads(self._candidate)
        encoded, digest = history.canonical_receipt(record)
        if (encoded != self._candidate or digest != self._candidate_sha or
                record["operation_id"] != self.operation_id or record["receipt_id"] != self.receipt_id or
                record["completion_digest"] != self._completion_digest or
                _canonical(record["completion"]) != self._completion_json):
            _fail("publication_candidate_changed", self)
        return record

    def _receipt_columns(self):
        from . import experiment_history as history
        record = self._record()
        result = {key: record[key] for key in history.FIELDS if key not in {"receipt_json", "receipt_sha256"}}
        return result | dict(receipt_json=self._candidate, receipt_sha256=self._candidate_sha)

    def _publication(self, conn, frame, *, receipt=True):
        self._validate(conn, frame)
        if frame[1] != "PUBLISH" or conn is not self._writer or not conn.in_transaction:
            _fail("publication_scope_changed", self)
        self.policy.assert_held(self._guard)
        self.policy.revalidate(conn, self._guard)
        record = self._record()
        if receipt:
            from . import experiment_history as history
            actual = history._one(conn, history.TABLE, history.FIELDS, history._Budget(history.MAX_BYTES),
                "receipt_id=? OR operation_id=?", (self.receipt_id, self.operation_id))
            if _canonical(actual) != _canonical(self._receipt_columns()):
                _fail("publication_receipt_changed", self)
        return record

    def _install_publication_functions(self, conn, frame):
        from . import experiment_history as history

        def receipt_owned(receipt_id, digest):
            self._publication(conn, frame, receipt=False)
            return int(receipt_id == self.receipt_id and digest == self._candidate_sha)

        def receipt_row_owned(value):
            self._publication(conn, frame, receipt=False)
            return int(_canonical(json.loads(value)) == _canonical(self._receipt_columns()))

        def mutation(table, key, old_json, new_json):
            record = self._publication(conn, frame)
            pre = json.loads(self._raw_preimage)
            if table == "managed_executions" and key == self.snapshot.execution_id:
                old = pre["managed"]
                post = record["postimage"]["managed"]
                new = old | {name: value for name, value in post.items()
                    if name not in {"ipc_auth_key_sha256", "claim_token_hash_sha256"}}
                new["claim_token_hash"] = ""
            elif table == "reservations" and key == record["reservation_id"]:
                old, new = pre["allocation"], None
            elif table == "adaptive_experiment_exclusions" and pre["exclusion"] is not None and key == pre["exclusion"]["scope_execution_id"]:
                old, new = pre["exclusion"], record["postimage"]["exclusion"]
            else:
                return 0
            try:
                return int(_canonical(json.loads(old_json)) == _canonical(old) and
                    (new_json is None if new is None else _canonical(json.loads(new_json)) == _canonical(new)))
            except (ValueError, TypeError, RecursionError):
                return 0

        def delete_authority(table, key):
            record = self._publication(conn, frame)
            pre = json.loads(self._raw_preimage)
            if table == "reservations" and key == record["reservation_id"]:
                row = history._one(conn, table, history.ALLOCATION_FIELDS, history._Budget(history.MAX_BYTES), "id=?", (key,))
                expected = pre["allocation"]
            elif table == "queue" and key == record["request_key"] and pre["queue"] is not None:
                row = history._one(conn, table, history.QUEUE_FIELDS, history._Budget(history.MAX_BYTES), "request_key=?", (key,))
                expected = pre["queue"]
            else:
                return 0
            return int(_canonical(row) == _canonical(expected))

        def archive_owned(value):
            record = self._publication(conn, frame)
            return int(_canonical(json.loads(value)) == _canonical(record["postimage"]["archive"]))

        def revision_owned(singleton, old, new):
            record = self._publication(conn, frame)
            return int(type(singleton) is int and singleton == 1 and type(old) is int and type(new) is int and
                old == record["preimage"]["registry_revision"] and new == record["postimage"]["registry_revision"])

        conn.create_function("sentinel_experiment_receipt_owned", 2, receipt_owned)
        conn.create_function("sentinel_experiment_receipt_row_owned", 1, receipt_row_owned)
        conn.create_function("sentinel_experiment_release_mutation", 4, mutation)
        conn.create_function("sentinel_daily_delete_authority", 2, delete_authority)
        conn.create_function("sentinel_experiment_archive_owned", 1, archive_owned)
        conn.create_function("sentinel_experiment_revision_owned", 3, revision_owned)
        receipt_projection = "json_object(" + ",".join("'" + key + "',NEW." + key for key in history.FIELDS) + ")"
        conn.execute("CREATE TEMP TRIGGER experiment_release_receipt_row_guard BEFORE INSERT ON main." + history.TABLE +
            " WHEN sentinel_experiment_receipt_row_owned(" + receipt_projection + ") IS NOT 1 "
            "BEGIN SELECT RAISE(ABORT,'experiment_release_receipt_not_owned'); END")
        projection = "json_object(" + ",".join("'" + key + "',NEW." + key for key in history.ARCHIVE_FIELDS) + ")"
        conn.execute("CREATE TEMP TRIGGER experiment_release_archive_guard BEFORE INSERT ON main.executions "
            "WHEN sentinel_experiment_archive_owned(" + projection + ") IS NOT 1 "
            "BEGIN SELECT RAISE(ABORT,'experiment_release_archive_not_owned'); END")
        conn.execute("""CREATE TEMP TRIGGER experiment_release_revision_guard
            BEFORE UPDATE OF registry_revision ON main.adaptive_runtime
            WHEN sentinel_experiment_revision_owned(OLD.singleton,OLD.registry_revision,NEW.registry_revision) IS NOT 1
            BEGIN SELECT RAISE(ABORT,'experiment_release_revision_not_owned'); END""")

    def _prepare_publication(self, conn):
        from . import experiment_history as history
        from . import experiment_demand, experiment_exclusion
        from .experiment_host_ledger import HostLedgerError, assert_release_unblocked_locked
        observed = history.verify_experiment_history_locked(conn)
        if self.snapshot.execution_id in observed.completed_execution_ids:
            self._verify_committed(conn)
            return False
        if observed.active_experiment_ids != frozenset({self.demand.declaration.experiment_id}):
            _fail("original_admission_missing", self)
        if not history.schema_locked(conn):
            _fail("receipt_schema_missing", self)
        budget = history._Budget(history.MAX_BYTES)
        metadata = history._one(conn, experiment_demand.TABLE, experiment_demand._FIELDS, budget,
            "experiment_id=? OR execution_id=? OR request_key=?", (self.demand.declaration.experiment_id,
                self.snapshot.execution_id, self.snapshot.request.request_key))
        reservation_id = metadata["reservation_id"]
        if metadata != self.demand._binding(reservation_id):
            _fail("admission_binding_changed", self)
        # S1/before-native completion cannot retire a separately registered
        # production-host cohort. Its distinct original completion and full
        # aggregate publication must exist before that release path can open.
        try:
            assert_release_unblocked_locked(conn,
                experiment_id=self.demand.declaration.experiment_id,
                execution_id=self.snapshot.execution_id, reservation_id=reservation_id)
        except HostLedgerError as error:
            raise ExperimentReleaseError("host_scope_cleanup_unverified", self) from error
        managed = history._one(conn, "managed_executions", history.MANAGED_FIELDS, budget,
            "execution_id=? OR reservation_id=?", (self.snapshot.execution_id, reservation_id))
        self.inner._validate_cancel_allocation(history._one(conn, "reservations", history.ALLOCATION_FIELDS,
            budget, "id=? OR execution_id=? OR request_key=?", (reservation_id, self.snapshot.execution_id,
                self.snapshot.request.request_key)), self.snapshot, reservation_id)
        allocation = history._one(conn, "reservations", history.ALLOCATION_FIELDS, budget,
            "id=?", (reservation_id,))
        if (managed["claim_token_hash"] != self.snapshot.claim_token_hash or
                type(managed["ipc_auth_key"]) is not bytes or
                not hmac.compare_digest(managed["ipc_auth_key"], self.snapshot.ipc_auth_key) or
                self.inner._claim_token is None or
                hashlib.sha256(self.inner._claim_token.encode("ascii")).hexdigest() != self.snapshot.claim_token_hash or
                managed["task_id"] != self.snapshot.task_id or managed["session_id"] != self.snapshot.session_id or
                managed["principal_id"] != self.snapshot.principal_id):
            _fail("unused_claim_changed", self)
        queued = history._rows(conn, "queue", history.QUEUE_FIELDS, budget,
            where="request_key=? OR managed_execution_id=?", parameters=(metadata["request_key"], metadata["execution_id"]), limit=1)
        excluded = (history._rows(conn, experiment_exclusion.TABLE, experiment_exclusion._FIELDS, budget,
            where="experiment_id=? OR daily_execution_id=? OR reservation_id=?", parameters=(metadata["experiment_id"],
                metadata["execution_id"], reservation_id), limit=1)
            if experiment_exclusion.validate_schema_locked(conn) else [])
        pre = dict(managed=history.managed_image(managed), allocation=allocation, queue=queued[0] if queued else None,
            exclusion=excluded[0] if excluded else None, registry_revision=self.policy.revalidate(conn, self._guard)["registry_revision"])
        raw = _canonical(pre | {"managed": self._wire(managed)})
        if self._candidate is not None:
            record = self._record()
            if _canonical(record["preimage"]) != _canonical(pre) or raw != self._raw_preimage:
                _fail("publication_preimage_changed", self)
            return True
        now = float(time.time())
        completion = json.loads(self._completion_json)
        digest = history.cleanup_digest(receipt_id=self.receipt_id, operation_id=self.operation_id,
            reservation_id=reservation_id, demand_binding_sha256=metadata["binding_sha256"],
            completion_digest=self._completion_digest, demand=completion["demand"])
        post = dict(managed=history.cancellation_image(pre["managed"], now), archive=history.archive_image(allocation, now),
            exclusion=None if pre["exclusion"] is None else pre["exclusion"] | dict(phase="CLOSED", cleanup_digest=digest),
            registry_revision=pre["registry_revision"] + 1)
        record = dict(schema_version=1, receipt_id=self.receipt_id, operation_id=self.operation_id,
            experiment_id=metadata["experiment_id"], execution_id=metadata["execution_id"], reservation_id=reservation_id,
            request_key=metadata["request_key"], suite=metadata["suite"], disposition=completion["disposition"],
            demand_binding_sha256=metadata["binding_sha256"], completion_digest=self._completion_digest,
            cleanup_digest=digest, completion=completion,
            policy=dict(instance_id=self._policy_binding.instance_id, logon_id=self._policy_binding.logon_id),
            transaction_time=now, preimage=pre, postimage=post,
            preimage_sha256=history.image_digest("preimage", pre), postimage_sha256=history.image_digest("postimage", post))
        candidate, receipt_sha = history.canonical_receipt(record)
        self._raw_preimage = raw
        self._candidate, self._candidate_sha = candidate, receipt_sha
        return True

    def _verify_committed(self, conn):
        from . import experiment_history as history
        record = self._record()
        result = history.verify_experiment_history_locked(conn)
        if (record["execution_id"] not in result.completed_execution_ids or
                self._candidate not in result.receipts_json):
            _fail("committed_tuple_unverified", self)
        actual = history._one(conn, history.TABLE, history.FIELDS, history._Budget(history.MAX_BYTES),
            "receipt_id=? OR operation_id=?", (self.receipt_id, self.operation_id))
        if _canonical(actual) != _canonical(self._receipt_columns()):
            _fail("committed_receipt_changed", self)
        return record

    def _result(self, record):
        result = _canonical(dict(released=True, execution_id=record["execution_id"],
            reservation_id=record["reservation_id"], receipt_id=self.receipt_id,
            cleanup_digest=record["cleanup_digest"], disposition=record["disposition"],
            state="CANCELLED_BEFORE_START"))
        if self._result_json is not None and self._result_json != result:
            _fail("result_binding_changed", self)
        return result

    def _publish_locked(self, conn):
        from . import experiment_history as history
        fresh = self._prepare_publication(conn)
        if not fresh:
            return
        record = self._record()
        receipt = self._receipt_columns()
        conn.execute("INSERT INTO " + history.TABLE + "(" + ",".join(receipt) + ") VALUES(" +
            ",".join("?" for _ in receipt) + ")", tuple(receipt.values()))
        post = record["postimage"]["managed"]
        fields = ("state", "state_revision", "finished_at", "cancel_requested_at", "launch_sealed",
            "launch_in_flight", "claim_consumed", "hold_reason")
        changed = conn.execute("UPDATE managed_executions SET " + ",".join(key + "=?" for key in fields) +
            ",claim_token_hash='' WHERE execution_id=? AND state_revision=?",
            (*[post[key] for key in fields], record["execution_id"], record["preimage"]["managed"]["state_revision"]))
        if changed.rowcount != 1:
            _fail("cancellation_conflict", self)
        archive = record["postimage"]["archive"]
        conn.execute("INSERT INTO executions(" + ",".join(archive) + ") VALUES(" +
            ",".join("?" for _ in archive) + ")", tuple(archive.values()))
        if conn.execute("DELETE FROM reservations WHERE id=?", (record["reservation_id"],)).rowcount != 1:
            _fail("allocation_delete_conflict", self)
        if record["preimage"]["queue"] is not None:
            if conn.execute("DELETE FROM queue WHERE request_key=?", (record["request_key"],)).rowcount != 1:
                _fail("queue_delete_conflict", self)
        excluded = record["postimage"]["exclusion"]
        if excluded is not None:
            if conn.execute("UPDATE adaptive_experiment_exclusions SET phase='CLOSED',cleanup_digest=? "
                    "WHERE scope_execution_id=? AND phase='REGISTERED'", (record["cleanup_digest"], excluded["scope_execution_id"])).rowcount != 1:
                _fail("exclusion_close_conflict", self)
        if conn.execute("UPDATE adaptive_runtime SET registry_revision=? WHERE singleton=1 AND registry_revision=?",
                (record["postimage"]["registry_revision"], record["preimage"]["registry_revision"])).rowcount != 1:
            _fail("registry_revision_conflict", self)
        self._verify_committed(conn)

    def _read_committed(self):
        with self._scope("READ"), self.store._connection() as conn:
            conn.execute("BEGIN")
            generation.revalidate_transaction(conn, db_path=self.ledger_path)
            record = self._verify_committed(conn)
            if self.policy._runtime(conn)["policy_entry_nonce"] == self._guard.nonce:
                _fail("original_nonce_unsettled", self)
            conn.rollback()
        return record

    def _settle_previous(self):
        """Reconcile the prior original SQL attempt, then its exact nonce.

        Positive provider exit permits clearing this guard only. A null nonce
        after a lost clear ACK is accepted only after our own clear attempt;
        it never causes prepare() to publish a new nonce for a committed result.
        """
        from . import experiment_history as history
        guard = self._guard
        if guard is None or not (guard._native_exit_confirmed or guard._native_no_entry_confirmed):
            return
        with self._scope("READ"), self.store._connection() as conn:
            conn.execute("BEGIN")
            generation.revalidate_transaction(conn, db_path=self.ledger_path)
            observed = history.verify_experiment_history_locked(conn)
            if self.snapshot.execution_id in observed.completed_execution_ids:
                self._verify_committed(conn)
                self._committed = True
            elif self._committed or self.demand.declaration.experiment_id not in observed.active_experiment_ids:
                _fail("publication_outcome_changed", self)
            nonce = self.policy._runtime(conn)["policy_entry_nonce"]
            if nonce not in (None, guard.nonce):
                _fail("nonce_conflict", self)
            if nonce is None and not guard._nonce_clear_attempted:
                _fail("original_nonce_unsettled", self)
            conn.rollback()
        if nonce == guard.nonce:
            # No new native wait, readiness RPC, guard or candidate.
            with self._scope("CLEAR"):
                self.policy._clear(guard)
        elif not guard._nonce_clear_confirmed:
            # This positively closed original read established the prior clear
            # outcome; keep that original attempt, rather than re-publishing it.
            guard._nonce_clear_confirmed = True
        self._policy_settled = True
        if (not self._committed and not self._commit_attempted and self._rollback_confirmed and
                not self._connections and guard._nonce_clear_confirmed):
            # A positively rolled-back, never-COMMIT-attempted candidate was
            # never published. After all original cleanup settles, a new writer
            # may freeze the current admissible preimage (for example expiry to
            # HOLD or an unrelated registry revision). Keep the same operation,
            # completion and original guard; never rebase a lost COMMIT ACK.
            self._candidate = self._candidate_sha = self._raw_preimage = None
            self._rollback_confirmed = False

    def _publication_transaction(self):
        """Retain commit attempt separately from rollback/acknowledgement."""
        from .store import _check_version
        with self._scope("PUBLISH"), self.store._connection() as conn:
            self._writer = conn
            self._rollback_confirmed = False
            try:
                conn.execute("BEGIN IMMEDIATE")
                try:
                    generation.revalidate_transaction(conn, db_path=self.ledger_path)
                    if not _check_version(conn):
                        _fail("lifecycle_schema_missing", self)
                    self._publish_locked(conn)
                    self._commit_attempted = True
                    conn.commit()
                    self._committed = True
                except BaseException as primary:
                    try:
                        conn.rollback()
                        self._rollback_confirmed = not conn.in_transaction
                    except BaseException as error:
                        primary._experiment_release_rollback_owner = conn
                        primary._experiment_release_rollback_error = error
                        primary.add_note("experiment_release_rollback_unverified")
                    raise
            finally:
                self._writer = None

    def _finish_self(self):
        from .identity import _known_close_failure
        if (not self._postread or not self._policy_settled or not self._committed or self._connections or
                self.policy.current_guard() is not None or self.policy.current_cleanup_guard() is not None):
            _fail("release_cleanup_unsettled", self)
        if self._close_attempted and not self._close_positive:
            if self._close_error is None and self._process._handle is None and not self._process._close_outcome_unknown:
                # Only the already retained VerifiedProcess.close can positively
                # retire this handle; resume bookkeeping without another call.
                self._close_positive = True
            if (self._close_error is None or not _known_close_failure(self._close_error) or
                    self._process._close_outcome_unknown or self._process._handle is None) and not self._close_positive:
                _fail("self_close_unverified", self)
        self._close_attempted = True
        try:
            if not self._close_positive:
                self._close_error = None
                self._process.close()
        except BaseException as error:
            self._close_error = error
            error.experiment_release_owner = self
            owners = getattr(error, "_identity_handle_cleanup", ())
            if (not _known_close_failure(error) or self._process._close_outcome_unknown or
                    self._process._handle is None or tuple(owners) != (self._process,) or
                    getattr(error, "__cause__", None) is not None or getattr(error, "__context__", None) is not None):
                self._quarantine = error
            raise
        self._close_positive = True
        try:
            self.inner._claim_token = self.inner._key = self.inner._snapshot = None
            self.inner._closed = self.demand._closed = True
            self._completed = True
        except BaseException as error:
            self._error = error
            error.experiment_release_owner = self
            raise

    def release(self, coordinator):
        """Original-only atomic publication, positive settlement and exact replay."""
        from sentinel.coordinator import Coordinator
        if type(coordinator) is not Coordinator or Path(coordinator.db_path).resolve() != self.ledger_path:
            _fail("actual_daily_coordinator_required", self)
        with self.demand._lock, self.inner._lock:
            self._original()
            if self._completed:
                return json.loads(self._result(self._read_committed()))
            # A known final CloseHandle FALSE retries only that retained owner,
            # after data readback. It cannot reacquire POLICY or republish SQL.
            if self._close_attempted:
                self._result(self._read_committed())
                self._finish_self()
                return json.loads(self._result_json)
            if (self.inner._process is not self._process or self.inner.snapshot() is not self.snapshot):
                _fail("original_caller_changed", self)
            self.demand._assert_unused_claim()
            self._settle_previous()
            if not self._committed:
                self._policy_settled = False
                if self._guard is not None:
                    self._guard._nonce_clear_attempted = self._guard._nonce_clear_confirmed = False
                    self._guard._native_exit_confirmed = self._guard._native_no_entry_confirmed = False
                self.prepare_policy(self.policy, self._policy_binding.logon_id)
                with self.hold_policy():
                    self._publication_transaction()
                self._policy_settled = True
            record = self._read_committed()
            self._postread = True
            self._result_json = self._result(record)
            self._finish_self()
            return json.loads(self._result_json)


class ExperimentAdmissionSettlement(_OriginalCleanupAccess):
    """Original returned admission guard; no completion or capacity authority."""
    _phases = frozenset({"READ", "CLEAR"})
    _owner_attribute = "experiment_admission_settlement_owner"
    _owner_slot = "_admission_settlement"

    def __init__(self, coordinator, demand, *, _token=None):
        from .experiment_demand import DailyExperimentDemand
        if _token is not _NEW or type(demand) is not DailyExperimentDemand:
            _fail("original_demand_required")
        self.coordinator, self.demand = coordinator, demand
        self.operation_id = str(uuid4())
        self.thread, self.pid = threading.current_thread(), os.getpid()
        self.ledger_path, self.ledger_identity = demand.ledger_path, demand.ledger_identity
        self.inner, self.snapshot = demand._admission, demand._snapshot
        self._process = self.inner._process
        self.policy = self.inner._submission_policy
        self.store = None if self.policy is None else self.policy.store
        self._guard = self.inner._submission_guard
        # A successful public admission can lose its caller-side reply after
        # clearing the inner pending slot. Only its already-retained tuple can
        # supply that original guard; no current ledger observation can do so.
        self._completed_return = self._guard is None
        self._submission_original = demand._submission_original if self._completed_return else None
        if self._completed_return:
            self._phases = frozenset({"READ"})
            original = self._submission_original
            if type(original) is tuple and len(original) == 5:
                self._guard = original[2]
        self._policy_binding = self._guard.binding if type(self._guard) is PolicyGuard else None
        self._nonce = self._guard.nonce if type(self._guard) is PolicyGuard else None
        self._generation = demand._generation_original
        self._transaction = self.inner._submission_transaction
        self._transaction_items = tuple(self._transaction.items()) if type(self._transaction) is dict else None
        self._prior_error = self.inner._submission_policy_error
        self._native_facts = None if type(self._guard) is not PolicyGuard else (
            self._guard._native_exit_confirmed, self._guard._native_no_entry_confirmed)
        self._connections = {}
        self._error = self._quarantine = None
        self._close_positive = self._cleared = self._settled = False
        self._observed_admission = None
        self._local_error = None
        self._retained = (coordinator, demand, self.inner, self.snapshot, self._process, self.policy,
            self.store, self._guard, self._policy_binding, self._nonce, self._generation,
            self._transaction, self._prior_error, self.thread, self.pid, self.operation_id,
            self.ledger_path, self.ledger_identity, self._completed_return, self._submission_original)
        _OPERATIONS[self.operation_id] = self

    def _original(self):
        from sentinel.coordinator import Coordinator
        from .identity import VerifiedProcess
        if (type(self) is not ExperimentAdmissionSettlement or
                _OPERATIONS.get(self.operation_id) is not self or
                self.demand._admission_settlement is not self or
                (self.coordinator, self.demand, self.inner, self.snapshot, self._process, self.policy,
                 self.store, self._guard, self._policy_binding, self._nonce, self._generation,
                 self._transaction, self._prior_error, self.thread, self.pid, self.operation_id,
                 self.ledger_path, self.ledger_identity, self._completed_return, self._submission_original) != self._retained or
                type(self._completed_return) is not bool or
                self.thread is not threading.current_thread() or self.pid != os.getpid()):
            _fail("original_settlement_changed", self)
        exact = (self.coordinator, self.demand, self.inner, self.snapshot, self._process,
            self.policy, self.store, self._guard)
        if (any(value is not self._retained[index] for index, value in enumerate(exact)) or
                self._transaction is not self._retained[11] or self._prior_error is not self._retained[12] or
                self._submission_original is not self._retained[19]):
            _fail("original_settlement_changed", self)
        self.demand._static_original()
        if (self._quarantine is not None or type(self.coordinator) is not Coordinator or
                Path(self.coordinator.db_path).resolve() != self.ledger_path or
                getattr(self.coordinator, "_managed_store", None) is not self.store or
                not self.demand._native_preparation_sealed or self.demand._native_preparation is not None or
                self.demand._release_operation is not None or
                self.demand._admission is not self.inner or self.inner._snapshot is not self.snapshot or
                self.demand._snapshot is not self.snapshot or self.inner._process is not self._process or
                type(self._process) is not VerifiedProcess or self._process.identity != self.snapshot.wrapper_identity or
                self.inner._claim_exported or self.inner._prepare_attempted or self.inner._cancel_sealed or
                self.inner._abandon_target is not None or self.inner._submission_prepare_unknown or
                self.inner._submission_policy is not self.policy or type(self.policy) is not PolicyCoordinator or
                self.policy.store is not self.store or self.store._policy is not self.policy or
                Path(self.store.db_path).resolve() != self.ledger_path or
                type(self._guard) is not PolicyGuard or type(self._policy_binding) is not PolicyBinding or
                self._guard.binding != self._policy_binding or
                self._guard.nonce != self._nonce or self.demand._generation_original != self._generation):
            _fail("admission_cleanup_unverified", self)
        self.demand._original_generation_binding()
        if (self.demand._policy_original is not None and self.demand._policy_original != self._policy_binding or
                self._guard.binding.logon_id != self.snapshot.logon_id or
                not all(type(value) is bool for value in self._native_facts) or
                not all(type(value) is bool for value in (
                    self._guard._native_exit_confirmed, self._guard._native_no_entry_confirmed)) or
                self._native_facts not in {(True, False), (False, True)} or
                (self._guard._native_exit_confirmed, self._guard._native_no_entry_confirmed) != self._native_facts):
            _fail("original_native_cleanup_unverified", self)
        if (self.inner._submission_transaction is not self._transaction or
                self._transaction is not None and (type(self._transaction) is not dict or
                    tuple(self._transaction.items()) != self._transaction_items)):
            _fail("original_transaction_changed", self)
        if self._transaction is not None:
            if (self._transaction.get("connection_closed") is not True or
                    self._transaction.get("execution_id") != self.snapshot.execution_id or
                    self._transaction.get("db_path") != self.ledger_path or
                    self.inner._admission_db_path != self.ledger_path or
                    self._transaction.get("connection") is None):
                _fail("original_sql_cleanup_unverified", self)
        elif self.inner._submitted:
            _fail("original_transaction_required", self)
        pending_guard, pending_error = self.inner._submission_guard, self.inner._submission_policy_error
        if self._completed_return:
            original = self._submission_original
            if (type(original) is not tuple or len(original) != 5 or
                    self.demand._submission_original is not original or
                    any(value is not original[index] for index, value in
                        enumerate((self.policy, self.store, self._guard, self._policy_binding))) or
                    self._guard.binding is not self._policy_binding or self._nonce != original[4] or
                    self._phases != frozenset({"READ"}) or
                    pending_guard is not None or pending_error is not None or self._prior_error is not None):
                _fail("original_completed_submission_changed", self)
            if (self._guard._nonce_clear_attempted is not True or self._guard._nonce_clear_confirmed is not True or
                    self._native_facts != (True, False) or self.inner._submission_policy_entered is not True or
                    self.inner._submitted is not True or type(self._transaction) is not dict or
                    self._transaction.get("commit_attempted") is not True or
                    self._transaction.get("rolled_back") is not False or
                    type(self._transaction.get("first_submission")) is not bool):
                _fail("original_completed_submission_unverified", self)
        elif (pending_guard is not self._guard and not (self._cleared and pending_guard is None) or
                pending_error is not self._prior_error and not (self._cleared and pending_error is None) or
                self._settled and (pending_guard is not None or pending_error is not None)):
            _fail("original_submission_changed", self)
        if any(note != "policy_entry_cleanup_failed" for note in getattr(self._prior_error, "__notes__", ())):
            _fail("original_cleanup_unverified", self)

    def prepare_policy(self, policy, logon):
        _fail("settlement_read_clear_only", self)

    def _read(self):
        from . import experiment_history as history
        from .store import _check_version
        metadata_binding = None
        with self._scope("READ"), self.store._connection() as conn:
            conn.execute("BEGIN")
            generation.revalidate_transaction(conn, db_path=self.ledger_path)
            if not _check_version(conn):
                _fail("lifecycle_schema_missing", self)
            observed = history.verify_experiment_history_locked(conn)
            if self.snapshot.execution_id in observed.completed_execution_ids:
                _fail("admission_already_released", self)
            budget = history._Budget(history.MAX_BYTES - observed.bytes_used)
            metadata = [row for value in observed.active_json if
                (row := json.loads(value))["experiment_id"] == self.demand.declaration.experiment_id]
            queues = history._rows(conn, "queue", history.QUEUE_FIELDS, budget,
                where="request_key=? OR managed_execution_id=?",
                parameters=(self.snapshot.request.request_key, self.snapshot.execution_id), limit=1)
            managed = history._rows(conn, "managed_executions", history.MANAGED_FIELDS, budget,
                where="execution_id=?", parameters=(self.snapshot.execution_id,), limit=1)
            allocations = history._rows(conn, "reservations", history.ALLOCATION_FIELDS, budget,
                where="execution_id=? OR request_key=?",
                parameters=(self.snapshot.execution_id, self.snapshot.request.request_key), limit=1)
            if (conn.execute("SELECT 1 FROM worker_reservations WHERE execution_id=? OR task_id=? LIMIT 1",
                    (self.snapshot.execution_id, self.snapshot.task_id)).fetchone() or
                    conn.execute("SELECT 1 FROM managed_executions WHERE parent_execution_id=? LIMIT 1",
                        (self.snapshot.execution_id,)).fetchone() or
                    conn.execute("SELECT 1 FROM executions WHERE request_key=? LIMIT 1",
                        (self.snapshot.request.request_key,)).fetchone()):
                _fail("admission_obligation_changed", self)
            if metadata:
                row = metadata[0]
                if (len(metadata) != 1 or self.demand._policy_original != self._policy_binding or
                        self._transaction is None or row != self.demand._binding(row["reservation_id"]) or
                        len(managed) != 1 or len(allocations) != 1 or queues):
                    _fail("admission_binding_changed", self)
                current = managed[0]
                if (type(current["ipc_auth_key"]) is not bytes or
                        not hmac.compare_digest(current["ipc_auth_key"], self.snapshot.ipc_auth_key) or
                        current["claim_token_hash"] != self.snapshot.claim_token_hash or
                        type(self.inner._claim_token) is not str or
                        hashlib.sha256(self.inner._claim_token.encode("ascii")).hexdigest() != self.snapshot.claim_token_hash or
                        any(current[key] != getattr(self.snapshot, key) for key in ("task_id", "session_id", "principal_id"))):
                    _fail("admission_credential_changed", self)
                self.inner._validate_cancel_allocation(allocations[0], self.snapshot, row["reservation_id"])
                metadata_binding = _canonical(row)
                result = dict(state=current["state"], reservation_id=row["reservation_id"])
            else:
                if managed or allocations:
                    _fail("admission_metadata_missing", self)
                if queues:
                    self.inner._validate_queued(queues[0], self.snapshot)
                    result = dict(state="QUEUED", reservation_id=None)
                else:
                    transaction = self._transaction
                    rejected = (transaction is not None and transaction.get("first_submission") is True and
                        transaction.get("commit_attempted") is False and transaction.get("rolled_back") is True)
                    state = "NEVER_SUBMITTED" if not self.inner._submitted else (
                        "SUBMISSION_REJECTED" if rejected else "ABSENT_AFTER_SUBMISSION")
                    result = dict(state=state, reservation_id=None)
            if any(json.loads(value)["experiment_id"] == self.demand.declaration.experiment_id
                    for value in observed.exclusions_json):
                _fail("native_preparation_already_registered", self)
            nonce = self.policy._runtime(conn)["policy_entry_nonce"]
            conn.rollback()
        if self._observed_admission is not None and metadata_binding != self._observed_admission:
            _fail("observed_admission_changed", self)
        if metadata_binding is not None:
            self._observed_admission = metadata_binding
        return result, nonce

    def settle(self):
        with self.demand._lock, self.inner._lock:
            self._original()
            if self.inner.snapshot() is not self.snapshot:
                _fail("original_caller_changed", self)
            if self._prior_error is not None:
                self._retain(self._prior_error)
                self._original()
            _, nonce = self._read()
            if self._completed_return or self._cleared:
                if nonce == self._nonce:
                    _fail("original_nonce_returned", self)
            elif nonce == self._nonce:
                with self._scope("CLEAR"):
                    self.policy._clear(self._guard)
            elif nonce is not None or not self._guard._nonce_clear_attempted:
                _fail("original_nonce_unsettled", self)
            else:
                self._guard._nonce_clear_confirmed = True
            result, nonce = self._read()
            if nonce == self._nonce or not self._guard._nonce_clear_confirmed:
                _fail("original_nonce_unsettled", self)
            # Publish local settlement last. A partial local assignment can only
            # resume through the same original read/clear owner and full checks.
            self._cleared = True
            try:
                if not self._completed_return:
                    self.inner._submission_guard = None
                    self.inner._submission_policy_error = None
                self._settled = True
            except BaseException as error:
                self._local_error = error
                raise
            return result | dict(settled=True, execution_id=self.snapshot.execution_id,
                request_key=self.snapshot.request.request_key, launch_authorized=False)


def settle_admission(coordinator, demand):
    from sentinel.coordinator import Coordinator
    from .experiment_demand import DailyExperimentDemand
    if type(coordinator) is not Coordinator or type(demand) is not DailyExperimentDemand:
        _fail("original_settlement_required")
    with demand._lock, demand._admission._lock:
        demand._static_original()
        if Path(coordinator.db_path).resolve() != demand.ledger_path:
            _fail("actual_daily_coordinator_required")
        demand._native_preparation_sealed = True
        operation = demand._admission_settlement
        if operation is None:
            operation = ExperimentAdmissionSettlement(coordinator, demand, _token=_NEW)
            demand._admission_settlement = operation
        elif (type(operation) is not ExperimentAdmissionSettlement or operation.coordinator is not coordinator or
                operation.demand is not demand):
            _fail("original_settlement_changed", operation)
        try:
            return operation.settle()
        except BaseException as error:
            from .policy import _cleanup_outcome_unverified
            if (operation._local_error is error and operation._cleared and
                    operation._quarantine is None and not operation._connections and
                    operation._guard._nonce_clear_confirmed and
                    not _cleanup_outcome_unverified(error, local_only=True)):
                operation._error = error
                error.experiment_admission_settlement_owner = operation
            else:
                operation._retain(error)
            raise


def prepare_release(demand, completion):
    """Called only by the original demand API; no native/SQL acquisition here."""
    from .experiment_demand import DailyExperimentDemand
    if type(demand) is not DailyExperimentDemand:
        _fail("original_demand_required")
    with demand._lock, demand._admission._lock:
        demand._native_preparation_sealed = True
        existing = demand._release_operation
        if existing is not None:
            if type(existing) is not ExperimentReleaseOperation or existing.completion is not completion:
                _fail("completion_changed", existing)
            existing._original()
            return existing
        operation = ExperimentReleaseOperation(demand, completion, _token=_NEW)
        demand._release_operation = operation
        try:
            operation._initialize()
        except BaseException as error:
            operation._retain(error)
            raise
        return operation
