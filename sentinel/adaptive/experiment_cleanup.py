"""Original experiment cleanup custody and narrowly scoped ledger access.

No serialized completion, current generation observation or caller callback can
construct this operation. Its read/nonce phases grant no capacity authority.
The atomic receipt publication is integrated separately; retaining an operation
does not itself release a reservation or close the demand's final self witness.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import threading
from uuid import uuid4

from . import daily_generation as generation
from .policy import PolicyBinding, PolicyBusy, PolicyGuard


_NEW = object()
_LOCAL = threading.local()
_OPERATIONS = {}
_PHASES = frozenset({"READ", "HOLD", "NONCE", "CLEAR"})


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
    if type(operation) is not ExperimentReleaseOperation:
        _fail("original_operation_required")
    operation._current(frame)
    if db_path is not None and Path(db_path).resolve() != operation.ledger_path:
        _fail("ledger_changed", operation)
    return operation


class ExperimentReleaseOperation:
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
        self._connections = {}
        self._error = self._quarantine = None
        self._nonce_attempted = False
        self._retained = (demand, completion, self.inner, self.snapshot, self.policy, self.store,
            self.operation_id, self.receipt_id, self.thread, self.pid,
            self.ledger_path, self.ledger_identity, self._generation, self._policy_binding)
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
                (self.demand, self.completion, self.inner, self.snapshot, self.policy, self.store,
                 self.operation_id, self.receipt_id, self.thread, self.pid,
                 self.ledger_path, self.ledger_identity, self._generation, self._policy_binding) != self._retained or
                self.thread is not threading.current_thread() or self.pid != os.getpid()):
            _fail("original_operation_changed", self)
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

    def _retain(self, error):
        error.experiment_release_owner = self
        # Preserve the first unknown owner's entire exception graph. A later
        # retry must not overwrite the sole reachable native cleanup witness.
        if self._quarantine is not None:
            return
        self._error = error
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
                getattr(current, "__context__", None), getattr(current, "_daily_readiness_cause", None))
                if isinstance(value, BaseException))

    def _current(self, frame):
        self._original()
        if getattr(_LOCAL, "frame", None) is not frame or frame[0] is not self:
            _fail("lexical_scope_changed", self)

    @contextmanager
    def _scope(self, phase):
        self._original()
        previous = getattr(_LOCAL, "frame", None)
        if phase not in _PHASES or previous is not None and previous[0] is not self:
            _fail("phase_invalid", self)
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
        self._validate(conn, frame)
        phase = frame[1]
        # This function never registers sentinel_daily_generation or any
        # capacity/delete authority. Its only writes are exact original nonces.
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
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                   sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
        def authorize(action, table, column, database, source):
            # SQLite may cache statements, so write-time triggers above also
            # validate the same original lexical frame and actual SQL snapshot.
            try:
                self._current(frame)
            except BaseException:
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

    def prepare_policy(self, policy, logon):
        self._original()
        if policy is not self.policy or logon != self._policy_binding.logon_id:
            _fail("policy_binding_changed", self)
        if self._guard is None:
            self._guard = PolicyGuard(self._policy_binding, str(uuid4()))
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
                if self._quarantine is None and not entered and not (isinstance(error, NativePolicyMutexError) and
                        error.reason in {"policy_mutex_timeout", "policy_mutex_wait_failed"} and
                        not getattr(error, "__notes__", ())):
                    self._quarantine = self._error = error
                self._retain(error)
                raise

    @contextmanager
    def nonce_cleanup(self, policy, guard):
        self._original()
        if (policy is not self.policy or guard is not self._guard or
                policy.current_guard() is not None or guard.binding != self._policy_binding):
            _fail("nonce_cleanup_not_owned", self)
        with self._scope("CLEAR"):
            yield


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
