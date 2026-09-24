"""Original-owner atomic generation transfer, never cold adoption.

The operation retains every original owner across prepare/commit/cleanup ACK
loss. Only metadata connections enter its thread-local scope. This module does
not start a readiness listener or supervisor, enable control, or modify ordinary
queue/allocation/exemption rows. A caller must retain it through host startup.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import uuid4
import weakref

from . import daily_generation as generation
from . import daily_retirement_fence as fence
from .daily_activation_host import _ConnectionCustody
from .daily_retirement import DailyRetirementOperation
from .daily_successor_scope import CURRENT as _CURRENT, SQL_CURRENT as _SQL_CURRENT, current_operation
from .policy import PolicyGuard, _cleanup_outcome_unverified


_ORIGINALS = weakref.WeakSet()
_NONCE_TRIGGER_SQL = """CREATE TEMP TRIGGER sentinel_successor_nonce_guard
    BEFORE UPDATE OF policy_entry_nonce ON main.adaptive_runtime
    WHEN sentinel_successor_nonce(OLD.policy_entry_nonce,NEW.policy_entry_nonce) IS NOT 1
    BEGIN SELECT RAISE(ABORT,'daily_successor_nonce_not_owned'); END"""


class DailySuccessorError(RuntimeError):
    def __init__(self, reason, operation=None):
        self.reason = "daily_successor_" + reason
        self.operation = operation
        super().__init__(self.reason)


class DailySuccessorOperation:
    """One same-process successor, retained before the first native capture."""

    def __init__(self, retirement):
        if type(retirement) is not DailyRetirementOperation:
            raise DailySuccessorError("original_retirement_required")
        retirement.assert_successor_predecessor()
        if getattr(retirement, "_successor_operation", None) is not None:
            raise DailySuccessorError("original_successor_already_present")
        self.retirement = retirement
        self.store, self.policy = retirement.store, retirement.policy
        self.ledger_path = retirement.owner.ledger_path
        self.transition_id = str(uuid4())
        self.guard = PolicyGuard(retirement._seal_guard.binding, str(uuid4()))
        self.owner = None
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._pins = (retirement, self.store, self.policy, self.guard, self.guard.binding,
                      self.guard.nonce, self.transition_id, self.ledger_path)
        self._connections = []
        self._connection_pins = {}
        self._bound_connections = {}
        self._owner_pins = None
        self._owner_prepared = False
        self._readiness_host = None
        self._host_pins = self._readiness_pins = self._supervisor_pins = None
        self._guardian_epoch_operation = None
        self._pending_supervisor = None
        self._capture_attempted = self._transition_attempted = False
        self._complete = False
        self._quarantine = self._error = None
        self._nonce_mode = None
        self._transition_connection = self._transition_stage = None
        self._inventory = self._archive = self._successor_row = None
        self._predecessor_row = dict(retirement._generation_row, state="DRAINING")
        self._seal_row = dict(retirement._seal_row)
        self.phase = "successor_capture_pending"
        _ORIGINALS.add(self)
        retirement._successor_operation = self

    def _fail(self, reason):
        raise DailySuccessorError(reason, self)

    def _original(self):
        if (type(self) is not DailySuccessorOperation or self not in _ORIGINALS or
                threading.current_thread() is not self._thread or os.getpid() != self._pid):
            self._fail("original_operation_required")
        current = (self.retirement, self.store, self.policy, self.guard, self.guard.binding)
        if (any(left is not right for left, right in zip(current, self._pins[:5])) or
                (self.guard.nonce, self.transition_id, self.ledger_path) != self._pins[5:] or
                self.retirement._successor_operation is not self or self.store._policy is not self.policy):
            self._fail("original_binding_changed")
        self.retirement.assert_successor_predecessor()
        if (len(self._connections) != len(self._connection_pins) or any(
                self._connection_pins.get(id(item)) != (item, item.connection)
                for item in self._connections)):
            self._fail("original_sql_owner_changed")
        if self._owner_pins is not None:
            self._assert_owner_binding()
        if self._host_pins is not None:
            self._assert_host_binding()
        if self._quarantine is not None or any(item.close_unknown for item in self._connections):
            self._fail("custody_unsettled")

    def _source(self):
        self._original()
        old = self.retirement.owner
        generation._assert_daily_locations(old.source_root, self.ledger_path)
        if generation._ledger_identity(self.ledger_path) != old.ledger_identity:
            self._fail("ledger_identity_changed")
        if generation._fixed_policy_digest(self.ledger_path) != old._config_digest:
            self._fail("config_changed")
        generation.verify_import_provenance(old.manifest, old.source_root)

    @contextmanager
    def scope(self):
        """Original invocation only; it exposes no capacity-generation function."""
        self._source()
        previous = getattr(_CURRENT, "operation", None)
        if previous is not None and previous is not self:
            self._fail("nested_operation")
        from .experiment_cleanup import current_operation as experiment_operation
        if (experiment_operation() is not None or
                getattr(generation._READINESS_LOCAL, "scope", None) is not None or
                getattr(generation._READINESS_LOCAL, "group", None) is not None):
            self._fail("foreign_scope")
        _CURRENT.operation = self
        try:
            yield self
        finally:
            _CURRENT.operation = previous

    @contextmanager
    def connection_scope(self, db_path):
        if current_operation(db_path) is not self:
            self._fail("scope_required")
        yield self

    def _retain_error(self, error):
        self._error = error
        if (_cleanup_outcome_unverified(error) or
                any(item.close_unknown for item in self._connections)):
            self._quarantine = "cleanup_unknown"
        self.phase = "successor_custody_pending"

    def _close(self, custody):
        if custody.closed:
            return
        if custody.close_unknown:
            self._fail("sql_close_unknown")
        try:
            if custody.connection.in_transaction:
                custody.connection.rollback()
            custody.close()
        except BaseException as error:
            self._quarantine = "sql_cleanup_unknown"
            self._error = error
            raise

    def begin_sql_acquisition(self):
        self._source()
        custody = _ConnectionCustody(None)
        self._connections.append(custody)
        self._connection_pins[id(custody)] = (custody, None)
        return custody

    def sql_acquired(self, custody, conn):
        if (self._connection_pins.get(id(custody)) != (custody, None) or
                custody.connection is not None or not isinstance(conn, sqlite3.Connection)):
            self._fail("original_sql_acquisition_required")
        custody.connection = conn
        self._connection_pins[id(custody)] = (custody, conn)

    def sql_acquisition_failed(self, custody, error):
        self._quarantine = "sql_acquisition_unknown"
        self._error = error
        error._daily_successor_operation = self
        error.add_note("daily_successor_sql_acquisition_unknown")

    @contextmanager
    def _connection(self, *, transition=False, readonly=False, observation=False):
        self._source()
        target = self.ledger_path.as_uri() + ("?mode=ro" if readonly else "?mode=rw")
        # Retain the original acquisition attempt before connect can acquire
        # anything. An exception before returning a handle is not proof that
        # there was no SQL owner and cannot authorize a replacement attempt.
        custody = self.begin_sql_acquisition()
        try:
            conn = sqlite3.connect(target, uri=True, timeout=.25, isolation_level=None)
            self.sql_acquired(custody, conn)
        except BaseException as error:
            self.sql_acquisition_failed(custody, error)
            raise
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("PRAGMA foreign_keys=ON")
            if not generation._ledger_matches(conn, self.ledger_path):
                self._fail("ledger_changed")
            if observation:
                if not readonly or transition:
                    self._fail("inventory_reader_invalid")
                from .daily_retirement_inventory import _connection_path, _READ_SECONDS
                conn.execute("PRAGMA query_only=ON")
                conn.execute("PRAGMA trusted_schema=OFF")
                _connection_path(conn, self.ledger_path)
                deadline = time.monotonic() + _READ_SECONDS
                conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            self._authorize(conn, transition=transition, nonce_guard=not observation)
            if observation:
                conn.execute("BEGIN")
            yield conn
        finally:
            if self._transition_connection is conn:
                self._transition_connection = self._transition_stage = None
            self._close(custody)

    @contextmanager
    def inventory_reader(self, retirement, guard):
        self._source()
        if retirement is not self.retirement or guard is not self.guard or current_operation() is not self:
            self._fail("original_inventory_reader_required")
        self.policy.assert_held(guard)
        with self._connection(readonly=True, observation=True) as conn:
            yield conn

    def _authorize(self, conn, *, transition=False, nonce_guard=True):
        from . import daily_successor_history as history
        # These are validated canonical names from the actual predecessor
        # schema. A separate operation may never supply a SQL identifier.
        removable = frozenset(fence._definitions(conn)) if transition else frozenset()
        allowed_read = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                        sqlite3.SQLITE_FUNCTION}

        def nonce_allowed(old, new):
            if (getattr(_CURRENT, "operation", None) is not self or self._quarantine is not None or
                    threading.current_thread() is not self._thread or os.getpid() != self._pid):
                return 0
            if self._nonce_mode == "prepare":
                return int(old is None and new == self.guard.nonce and self.policy.current_guard() is None)
            if self._nonce_mode == "clear":
                return int(old == self.guard.nonce and new is None and
                    self.policy.current_guard() is None and self.policy.current_cleanup_guard() is self.guard and
                    (self.guard._native_exit_confirmed is True or self.guard._native_no_entry_confirmed is True))
            return 0

        if nonce_guard:
            conn.create_function("sentinel_successor_nonce", 2, nonce_allowed)
            conn.execute(_NONCE_TRIGGER_SQL)

        def authorize(action, table, column, database, source):
            original_scope = getattr(_CURRENT, "operation", None) is self
            if not nonce_guard:
                from .daily_successor_epoch import current_sql_owner
                epoch = current_sql_owner()
                original_scope = original_scope or getattr(_SQL_CURRENT, "operation", None) is self or (
                    epoch is not None and epoch.operation is self)
            if not original_scope or self._quarantine is not None:
                return sqlite3.SQLITE_DENY
            if action in allowed_read:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and (table in {
                    "table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list"}
                    and (column is None or type(column) is str and 0 < len(column) <= 256) or
                    table == "database_list" and column is None or
                    table == "foreign_keys" and str(column).lower() in {"on", "1"} or
                    table == "busy_timeout" and str(column).isdigit() and int(column) <= 250):
                return sqlite3.SQLITE_OK
            if database != "main":
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and column == "policy_entry_nonce":
                return sqlite3.SQLITE_OK
            if (not transition or self.policy.current_guard() is not self.guard or
                    self._transition_connection is not conn or not conn.in_transaction or
                    self._transition_stage not in {"archive", "fence", "generation"}):
                return sqlite3.SQLITE_DENY
            if (self._transition_stage == "generation" and action == sqlite3.SQLITE_UPDATE and
                    table == generation._TABLE and column in generation._GENERATION_FIELDS):
                return sqlite3.SQLITE_OK
            if self._transition_stage == "archive" and action == sqlite3.SQLITE_INSERT and table == history.TABLE:
                return sqlite3.SQLITE_OK
            if self._transition_stage == "archive" and action == sqlite3.SQLITE_CREATE_TABLE and table == history.TABLE:
                return sqlite3.SQLITE_OK
            if (self._transition_stage == "archive" and action == sqlite3.SQLITE_CREATE_TRIGGER and
                    table in history._TRIGGERS and column == history.TABLE):
                return sqlite3.SQLITE_OK
            if (self._transition_stage == "archive" and action == sqlite3.SQLITE_CREATE_INDEX and
                    column == history.TABLE and table.startswith("sqlite_autoindex_")):
                return sqlite3.SQLITE_OK
            if self._transition_stage == "fence" and action == sqlite3.SQLITE_DROP_TRIGGER and table in removable:
                return sqlite3.SQLITE_OK
            if self._transition_stage == "fence" and action == sqlite3.SQLITE_DROP_TABLE and table == fence.TABLE:
                return sqlite3.SQLITE_OK
            if self._transition_stage == "fence" and action == sqlite3.SQLITE_DELETE and table == fence.TABLE:
                return sqlite3.SQLITE_OK
            # SQLite performs catalog writes for the narrowly permitted DDL
            # above. writable_schema, arbitrary DDL and ordinary writes remain
            # denied; no general capacity UDF is installed by this scope.
            if action in {sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE} and table == "sqlite_master":
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY

        conn.set_authorizer(authorize)

    def bind_connection(self, conn, *, role, db_path):
        if current_operation(db_path) is not self or role != "lifecycle" or conn.in_transaction:
            self._fail("metadata_connection_required")
        if id(conn) in self._bound_connections:
            self._fail("connection_rebound")
        # The store reports positive close on this same original object. An
        # error before that report leaves the connection retained here.
        self._bound_connections[id(conn)] = (conn, False)
        self._source()
        if not generation._ledger_matches(conn, self.ledger_path):
            self._fail("ledger_changed")
        self._authorize(conn)
        self._read_state(conn, archive=False)

    @contextmanager
    def nonce_cleanup(self, policy, guard):
        if (current_operation(policy.store.db_path) is not self or policy is not self.policy or
                guard is not self.guard or self._nonce_mode is not None or
                not (guard._native_exit_confirmed is True or guard._native_no_entry_confirmed is True)):
            self._fail("nonce_cleanup_unowned")
        self._nonce_mode = "clear"
        try:
            yield
        finally:
            self._nonce_mode = None

    def connection_closed(self, conn):
        for custody in self._connections:
            if custody.connection is conn:
                if custody.closed or custody.close_unknown:
                    self._fail("connection_close_unowned")
                custody.closed = True
                break
        retained = self._bound_connections.get(id(conn))
        # A readiness refusal can precede bind_connection. The store alone
        # reports a positive close here; absence grants no registration or ACK.
        if retained is None:
            return
        if retained[0] is not conn or retained[1]:
            self._fail("connection_close_unowned")
        self._bound_connections[id(conn)] = (conn, True)

    def assert_inventory_connection(self, conn, retirement, guard):
        self._original()
        bound = self._bound_connections.get(id(conn))
        own = any(item.connection is conn and not item.closed and not item.close_unknown
                  for item in self._connections)
        if (current_operation(self.ledger_path) is not self or retirement is not self.retirement or
                guard is not self.guard or not isinstance(conn, sqlite3.Connection) or
                not conn.in_transaction or not (own or bound is not None and
                    bound[0] is conn and bound[1] is False)):
            self._fail("original_inventory_connection_required")
        self.policy.assert_held(guard)

    def revalidate_connection(self, conn, *, db_path):
        self._source()
        retained = self._bound_connections.get(id(conn))
        if (current_operation(db_path) is not self or not conn.in_transaction or
                retained is None or retained[0] is not conn or retained[1]):
            self._fail("original_connection_required")
        self._read_state(conn)

    def _read_state(self, conn, *, archive=True):
        row = generation.read_generation(conn)
        sealed = fence.read_retirement(conn)
        before = row == self._predecessor_row and sealed == self._seal_row
        after = self._successor_row is not None and row == self._successor_row and sealed is None
        if not (before or after):
            self._fail("generation_changed")
        runtime = self.policy._runtime(conn)
        if (self.policy._binding(runtime, self.guard.binding.logon_id) != self.guard.binding or
                runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE" or
                runtime["policy_entry_nonce"] not in {None, self.guard.nonce}):
            self._fail("policy_changed")
        if after and archive:
            from .daily_successor_history import read_successor_history
            entries = read_successor_history(conn).entries
            if self._archive is None or not entries or entries[-1] != self._archive:
                self._fail("archive_changed")
        return before, runtime

    def _capture_owner(self):
        if self.owner is None:
            if self._capture_attempted:
                self._fail("capture_custody_unsettled")
            self._capture_attempted = True
            old = self.retirement.owner
            try:
                self.owner = generation.DailyGenerationOwner.capture(manifest=old.manifest,
                    source_root=old.source_root, ledger_path=self.ledger_path)
            except BaseException as error:
                self.owner = getattr(error, "daily_generation_owner", None)
                self._quarantine = "capture_unknown"
                self._error = error
                raise
            self.owner._config_digest = old._config_digest
            self.owner._successor_operation = self
            self._successor_row = dict(self.retirement._generation_row, generation=self.owner.generation,
                readiness_instance_id=self.owner.readiness_endpoint.instance_id)
            self._owner_pins = (self.owner, self.owner.process, self.owner.cohort, self.owner.manifest,
                self.owner.readiness_endpoint, self.owner.generation, self.owner.process.identity,
                self.owner.source_root, self.owner.ledger_path, self.owner.ledger_identity,
                self.owner._config_digest, self._successor_row, tuple(sorted(self._successor_row.items())))
        self._assert_owner_binding()
        self.owner._assert_owner()
        if self.owner.process.identity != self.retirement.owner.process.identity:
            self._fail("process_changed")
        if self._owner_prepared:
            self.owner.cohort.assert_retained_retired()

    def _assert_owner_binding(self):
        pins = self._owner_pins
        if pins is None or self.owner is not pins[0]:
            self._fail("original_owner_changed")
        owner = self.owner
        if (any(left is not right for left, right in zip(
                (owner.process, owner.cohort, owner.manifest, owner.readiness_endpoint), pins[1:5])) or
                (owner.generation, owner.process.identity, owner.source_root, owner.ledger_path,
                 owner.ledger_identity, owner._config_digest) != pins[5:11] or
                self._successor_row is not pins[11] or tuple(sorted(self._successor_row.items())) != pins[12] or
                owner._successor_operation is not self):
            self._fail("original_owner_changed")

    def _assert_host_binding(self):
        from .daily_activation_host import DailyActivationHost
        host, pins = self._readiness_host, self._host_pins
        if (pins is None or type(host) is not DailyActivationHost or host is not pins[0] or
                host.owner is not self.owner or host.store is not self.store or host.guard is not self.guard or
                host._successor_operation is not self or host._generation_settled is not True or
                any(left is not right for left, right in zip((host._listener_ready,
                    host._thread_stopped, host._readiness_stop, host._connections), pins[1:]))):
            self._fail("original_host_changed")

    def bind_readiness_host(self, host):
        from .daily_activation_host import DailyActivationHost
        self._source()
        if (not self._complete or type(host) is not DailyActivationHost or
                host is self.retirement.host or host.owner is not self.owner or
                host.store is not self.store or host.guard is not self.guard or
                host._successor_operation is not self or not host._generation_settled):
            self._fail("original_host_required")
        if self._readiness_host is not None:
            if self._readiness_host is not host:
                self._fail("original_host_changed")
            self._assert_host_binding()
            return
        if (host._readiness_start_attempted or host._listener_ready.is_set() or
                host._thread is not None or host._listener is not None or host._service is not None or
                host._registry is not None or host.supervisor is not None or host._connections):
            self._fail("fresh_host_required")
        self._readiness_host = host
        self._host_pins = (host, host._listener_ready, host._thread_stopped,
                           host._readiness_stop, host._connections)

    def assert_listener_start(self, host):
        self._source()
        self._assert_host_binding()
        if (host is not self._readiness_host or not self._complete or host._readiness_start_attempted or
                host._readiness_failure is not None or self._readiness_pins is not None):
            self._fail("listener_start_unowned")
        self.owner._assert_owner()
        self.owner.cohort.assert_retained_retired()

    def publish_readiness_listener(self, host):
        from .daily_readiness_transport import DailyReadinessService
        from .pipe_windows import NativePipeListener, NativePipeRegistry
        self._assert_owner_binding()
        self._assert_host_binding()
        if (host is not self._readiness_host or self._readiness_pins is not None or
                not self._complete or self._quarantine is not None or os.getpid() != self._pid or
                threading.current_thread() is not host._thread or
                host._thread is not host._readiness_original_thread or
                type(host._listener) is not NativePipeListener or
                type(host._registry) is not NativePipeRegistry or type(host._service) is not DailyReadinessService or
                host._listener is not host._readiness_original_listener or
                host._registry is not host._readiness_original_registry or
                host._listener.endpoint != self.owner.readiness_endpoint or host._service.owner is not self.owner or
                host._readiness_start_attempted is not True or host._readiness_stop.is_set() or
                host._readiness_failure is not None or host._thread_stopped.is_set()):
            self._fail("listener_publication_unowned")
        status = host._registry.status()
        if status.resources != 1 or status.pending or status.quarantined:
            self._fail("listener_publication_unsettled")
        self._readiness_pins = (host._thread, host._listener, host._service, host._registry)

    def assert_readiness_published(self, owner):
        # Called by both the original keeper and its retained readiness thread.
        # It only checks already published original objects, never mints scope
        # or invokes the original-thread SQL/POLICY transition from the reader.
        self._assert_owner_binding()
        host = self._readiness_host
        if (owner is not self.owner or not self._complete or self._quarantine is not None or
                host is None or self._readiness_pins is None or host.owner is not owner or not host._generation_settled or
                not host._listener_ready.is_set() or host._thread_stopped.is_set() or
                host._readiness_failure is not None or host._readiness_stop.is_set() or
                host._listener is not host._readiness_original_listener or
                host._registry is not host._readiness_original_registry or
                host._thread is not host._readiness_original_thread):
            self._fail("readiness_not_published")
        self._assert_host_binding()
        if any(left is not right for left, right in zip(
                (host._thread, host._listener, host._service, host._registry), self._readiness_pins)):
            self._fail("original_readiness_changed")
        status = host._registry.status()
        if status.quarantined or status.resources != 1:
            self._fail("readiness_cleanup_unsettled")

    def assert_supervisor(self, supervisor):
        from .supervisor_host import SupervisorHost
        from .supervisor_startup import SupervisorStartup
        self._source()
        self.assert_readiness_published(self.owner)
        if (type(supervisor) is not SupervisorHost or self._pending_supervisor is not supervisor or
                self._readiness_host.supervisor is not supervisor or
                supervisor._daily_successor_operation is not self or supervisor.store is not self.store or
                supervisor.journal is not self.retirement.journal or
                type(supervisor.startup) is not SupervisorStartup or
                supervisor.startup.store is not self.store or supervisor.startup.journal is not supervisor.journal):
            self._fail("original_supervisor_required")
        startup = supervisor.startup
        startup.assert_held()
        if startup.binding != self.guard.binding:
            self._fail("supervisor_binding_changed")
        current = (supervisor, startup, startup._current, startup._mutex, startup._scope, startup._lease)
        if self._supervisor_pins is None:
            self._supervisor_pins = current
        elif any(left is not right for left, right in zip(current, self._supervisor_pins)):
            self._fail("original_supervisor_changed")

    def bind_supervisor(self, supervisor):
        from .supervisor_host import SupervisorHost
        self._source()
        self.assert_readiness_published(self.owner)
        if (type(supervisor) is not SupervisorHost or self._readiness_host.supervisor is not supervisor or
                supervisor._daily_successor_operation is not self or supervisor.startup is not None or
                supervisor.store is not None or supervisor.journal is not None or
                supervisor.data_dir.resolve() != self.ledger_path.parent or
                supervisor.journal_dir.resolve() != self.retirement.journal._directory or
                supervisor.child_cwd.resolve() != self.owner.source_root or
                supervisor.helper_profile_path is not None or supervisor.max_guardians != 1):
            self._fail("fresh_supervisor_required")
        if self._pending_supervisor is not None:
            self._fail("original_supervisor_already_present")
        self._pending_supervisor = supervisor

    def inspect_startup_locked(self, supervisor, guard):
        self.assert_supervisor(supervisor)
        self.policy.assert_held(guard)
        with self.startup_sql_scope(supervisor):
            snapshot = self.capture_startup_inventory(supervisor, guard)
            with self.store._connection() as conn:
                supervisor.startup._bound_read(conn)
                self.revalidate_startup_inventory(conn, supervisor, guard, snapshot)
                return self.policy.revalidate(conn, guard)

    def capture_startup_inventory(self, supervisor, guard):
        from .daily_successor_startup_inventory import capture_startup_inventory
        return capture_startup_inventory(self, supervisor, guard)

    def revalidate_startup_inventory(self, conn, supervisor, guard, snapshot):
        from .daily_successor_startup_inventory import revalidate_startup_inventory
        return revalidate_startup_inventory(conn, self, supervisor, guard, snapshot)

    @contextmanager
    def startup_sql_scope(self, supervisor):
        from .daily_successor_epoch import current_sql_owner
        self.assert_supervisor(supervisor)
        previous = getattr(_SQL_CURRENT, "operation", None)
        if (current_operation() is not None or current_sql_owner() is not None or
                previous is not None and previous is not self):
            self._fail("foreign_startup_sql_scope")
        _SQL_CURRENT.operation = self
        try:
            yield
        finally:
            _SQL_CURRENT.operation = previous

    @contextmanager
    def startup_inventory_reader(self, supervisor, guard):
        from .daily_successor_epoch import current_sql_owner
        self.assert_supervisor(supervisor)
        self.policy.assert_held(guard)
        epoch = current_sql_owner()
        if epoch is not None:
            if epoch is not self._guardian_epoch_operation or epoch.supervisor is not supervisor:
                self._fail("foreign_startup_sql_scope")
            with self._connection(readonly=True, observation=True) as conn:
                yield conn
        else:
            with self.startup_sql_scope(supervisor):
                with self._connection(readonly=True, observation=True) as conn:
                    yield conn

    def assert_startup_inventory_connection(self, conn, supervisor, guard):
        from .daily_successor_epoch import current_sql_owner
        self.assert_supervisor(supervisor)
        self.policy.assert_held(guard)
        if (not isinstance(conn, sqlite3.Connection) or not conn.in_transaction or
                guard in (self.guard, self.retirement._freeze_guard, self.retirement._seal_guard)):
            self._fail("original_startup_connection_required")
        epoch = current_sql_owner()
        if epoch is not None:
            if epoch is not self._guardian_epoch_operation or epoch.supervisor is not supervisor:
                self._fail("foreign_startup_sql_scope")
            owners = (*self._connections, *epoch._connections)
        elif getattr(_SQL_CURRENT, "operation", None) is self:
            owners = self._connections
        else:
            self._fail("original_startup_connection_required")
        if not any(item.connection is conn and not item.closed and not item.close_unknown for item in owners):
            self._fail("original_startup_connection_required")

    def published_epoch(self, supervisor):
        self.assert_supervisor(supervisor)
        epoch = self._guardian_epoch_operation
        if epoch is None:
            return None
        epoch._authority()
        if epoch.operation is not self or epoch.supervisor is not supervisor:
            self._fail("original_epoch_changed")
        if not epoch._complete:
            return None
        from .daily_successor_epoch import _FIELDS
        if epoch._candidate is None:
            self._fail("epoch_unsettled")
        return dict(zip(_FIELDS, epoch._candidate))

    def _prepare_guard(self):
        if self._nonce_mode is not None:
            self._fail("nonce_scope_nested")
        self._nonce_mode = "prepare"
        try:
            with self._connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                before, runtime = self._read_state(conn)
                if not before:
                    conn.rollback()
                    return
                if runtime["policy_entry_nonce"] is None:
                    if conn.execute("UPDATE adaptive_runtime SET policy_entry_nonce=? WHERE singleton=1 "
                            "AND policy_entry_nonce IS NULL", (self.guard.nonce,)).rowcount != 1:
                        self._fail("nonce_conflict")
                conn.commit()
        finally:
            self._nonce_mode = None

    def _transfer(self):
        from .daily_successor_inventory import capture_successor_inventory, revalidate_successor_inventory
        from . import daily_successor_history as history
        from . import daily_retirement_inventory as inventory
        if not self._owner_prepared:
            self.owner.prepare_install(policy=self.policy, guard=self.guard)
            self._owner_prepared = True
        else:
            self._assert_owner_binding()
            self.owner._assert_owner()
            self.owner.cohort.assert_retained_retired()
        self._inventory = capture_successor_inventory(self.retirement, self.guard)
        with self._connection(transition=True) as conn:
            conn.execute("BEGIN IMMEDIATE")
            before, _ = self._read_state(conn)
            if not before:
                self._fail("transfer_already_applied")
            revalidate_successor_inventory(conn, self.retirement, self.guard, self._inventory)
            self._transition_connection = conn
            self._transition_stage = "archive"
            self._transition_attempted = True
            self.owner._successor_operation = self
            generation._LOCAL_GENERATIONS[self.owner.generation] = self.owner
            budget = self._inventory.budget
            existed = history._schema(conn)
            if budget.remaining_history_rows < 1:
                self._fail("history_budget_exceeded")
            self._archive = history.append_successor_history_locked(conn, retirement=self.retirement,
                successor_row=self._successor_row, guard=self.guard, transition_id=self.transition_id,
                max_bytes=budget.history_bytes + budget.remaining_bytes, max_rows=history.MAX_ROWS)
            # The archive reader charges raw record bytes. Its embedding in a
            # complete serialized ledger additionally escapes JSON strings.
            # Charge that exact new subtree and new schema/column metadata
            # before the mutation can commit; never credit removed old fences.
            extra = len(inventory._encoded({history.TABLE: [dict(zip(history._FIELDS, self._archive._row))]}))
            if not existed:
                schema, _ = inventory._schema(conn, inventory._Budget())
                extra += len(inventory._encoded([row for row in schema if row[1] == history.TABLE or row[2] == history.TABLE]))
                extra += len(inventory._encoded([tuple(row) for row in conn.execute("PRAGMA table_xinfo(" + history.TABLE + ")")]))
            if budget.bytes_used + extra > inventory.MAX_BYTES:
                self._fail("history_budget_exceeded")
            self._transition_stage = "fence"
            for name in fence._definitions(conn):
                conn.execute('DROP TRIGGER "' + name + '"')
            conn.execute("DROP TABLE " + fence.TABLE)
            columns = sorted(generation._GENERATION_FIELDS - {"singleton"})
            self._transition_stage = "generation"
            changed = conn.execute("UPDATE " + generation._TABLE + " SET " +
                ",".join(name + "=?" for name in columns) + " WHERE singleton=1 AND generation=? AND state='DRAINING'",
                (*(self._successor_row[name] for name in columns), self._predecessor_row["generation"])).rowcount
            if changed != 1:
                self._fail("generation_changed")
            conn.commit()

    def _acknowledge(self):
        if (self.policy.current_guard() is not None or self.policy.current_cleanup_guard() is not None or
                self.guard._native_exit_confirmed is not True or
                any(not closed for _, closed in self._bound_connections.values()) or
                any(not item.closed or item.close_unknown for item in self._connections)):
            self._fail("ack_custody_unsettled")
        with self._connection(readonly=True) as conn:
            conn.execute("BEGIN")
            before, runtime = self._read_state(conn)
            if before or runtime["policy_entry_nonce"] is not None or not self.owner._matches_generation(self._successor_row):
                self._fail("ack_unsettled")
        self.owner._assert_owner()
        self.owner.cohort.assert_retained_retired()
        self.owner._activated = True
        self._complete = True
        self.phase = "successor_generation_acknowledged"

    def tick(self):
        """One original prepare/transfer/settlement; failures retain this owner."""
        self._source()
        if self._complete:
            return True
        try:
            with self.scope():
                self._capture_owner()
                with self._connection(readonly=True) as conn:
                    conn.execute("BEGIN")
                    before, runtime = self._read_state(conn)
                if before:
                    self._prepare_guard()
                    entered = False
                    try:
                        with self.policy.hold(self.guard):
                            entered = True
                            self._transfer()
                    except BaseException:
                        if not entered and self.guard._native_no_entry_confirmed is not True:
                            self._quarantine = "policy_entry_unverified"
                        raise
                elif runtime["policy_entry_nonce"] is not None:
                    if self.guard._native_exit_confirmed is not True:
                        self._fail("native_exit_unverified")
                    self.policy._clear(self.guard)
                self._acknowledge()
                return True
        except BaseException as error:
            self._retain_error(error)
            raise
