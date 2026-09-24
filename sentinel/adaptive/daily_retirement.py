"""Original-owner retirement of a daily accounting generation.

The durable freeze is evidence, never a capability to adopt an active keeper.
Only the original host operation can seal its generation and close its owners.
Retirement leaves admission permanently fenced; this is not legacy fallback.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import weakref
from uuid import uuid4

from . import daily_generation as generation
from .daily_retirement_fence import (
    DailyRetirementError, install_freeze_locked, read_retirement, seal_freeze_locked,
)
from .daily_retirement_inventory import (
    capture_retirement_inventory, retirement_inventory_digest, revalidate_retirement_inventory,
)
from .recovery_journal import RecoveryJournal, RecoveryJournalError
from .store import LifecycleError, LifecycleStore
from .supervisor_host import SupervisorHost
from .supervisor_reconcile import RetainedPolicyOperation


_BINDINGS = ("generation", "source_digest", "config_digest", "source_root", "ledger_path",
             "owner_identity_json", "ledger_identity_json", "readiness_instance_id")
_ORIGINAL_OPERATIONS = weakref.WeakSet()
_MISSING = object()
_SUPERVISOR_CUSTODY = ("guardian", "helper", "supervisor", "retired", "retired_helpers",
    "unverified", "unsettled_captures", "_creation_records", "_creation_unknown", "_unknown_handles",
    "_closed_handles", "_drain_closed_children", "_operator_cleanup_errors", "_registry_retirements",
    "_registry_results", "_initial_start_operation", "_empty_check", "janitor", "_rollover",
    "_operational_current", "operator_listener", "discovery", "operations", "_operator_closed",
    "_discovery_closed", "_guardian_settled", "startup")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _custody_pin(value, *, depth=0, budget=None):
    """Bounded in-memory object/container binding; never serialized authority."""
    from .identity import VerifiedProcess
    from .recovery_owner import RetainedGuardianCreation
    from .supervisor_host import _Guardian, _Helper
    from .supervisor_startup import SupervisorStartup
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > 16384 or depth > 12:
        _reject("daily_retirement_custody_unbounded")
    if type(value) in (str, bytes, int, bool, float, type(None)):
        return type(value), value
    if type(value) in (tuple, list, set, frozenset):
        parts = [_custody_pin(item, depth=depth + 1, budget=budget) for item in value]
        return type(value), frozenset(parts) if type(value) in (set, frozenset) else tuple(parts)
    if type(value) is dict:
        return dict, tuple((_custody_pin(key, depth=depth + 1, budget=budget),
            _custody_pin(item, depth=depth + 1, budget=budget)) for key, item in value.items())
    # Only actual native owner types expose fixed custody fields. In particular,
    # an unchanged child wrapper cannot conceal a replaced process witness.
    fields = {
        VerifiedProcess: ("_identity", "_handle", "_close_outcome_unknown"),
        RetainedGuardianCreation: ("_process", "_closed", "_construction_error", "_creator_pid", "_guardian_epoch"),
        _Guardian: ("epoch", "pid", "creation_handle", "process", "creation_witness"),
        _Helper: ("pid", "creation_handle", "process"),
        SupervisorStartup: ("store", "journal", "_current", "_mutex", "_scope", "_lease", "_closed",
            "_acquired", "_entry_unknown", "_release_unknown", "_close_unknown", "_construction_error",
            "_acquire_error", "_binding_operation", "_fresh_operation", "_thread", "_native_thread", "_pid"),
    }.get(type(value))
    if fields is not None:
        return (type(value), id(value), value, tuple(_custody_pin(getattr(value, name, _MISSING),
            depth=depth + 1, budget=budget) for name in fields))
    return type(value), id(value), value


def _reject(reason):
    raise DailyRetirementError(reason)


class DailyRetirementOperation:
    """One in-process request with two retained original POLICY operations."""

    def __init__(self, host):
        from .daily_activation_host import DailyActivationHost
        if (type(host) is not DailyActivationHost or
                type(host.owner) is not generation.DailyGenerationOwner or
                type(host.store) is not LifecycleStore or
                type(host.supervisor) is not SupervisorHost or
                not host._generation_settled or host.owner._closed or
                getattr(host, "_retirement", None) is not None or
                getattr(host.owner, "_retirement_operation", None) is not None):
            _reject("daily_retirement_original_owner_required")
        self.host, self.owner, self.store = host, host.owner, host.store
        self.supervisor, self.policy = host.supervisor, host.store._policy
        self.request_id = str(uuid4())
        self._freeze = RetainedPolicyOperation(self.store)
        self._seal = RetainedPolicyOperation(self.store)
        self._freeze_row = self._seal_row = self._generation_row = None
        self._freeze_guard = self._seal_guard = None
        self._freeze_guard_pin = self._seal_guard_pin = None
        self._freeze_readback = self._seal_readback = None
        self._generation_pin = self._freeze_row_pin = self._seal_row_pin = None
        self._seal_inventory = self._seal_inventory_digest = self._seal_inventory_pin = None
        self._supervisor_custody_pin = self._closed_custody_pin = None
        self._supervisor_startup = getattr(self.supervisor, "startup", _MISSING)
        self._thread_id = threading.get_ident()
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._seal_resume_active = False
        self._seal_attempted = False
        self._sealed = self._freeze_acknowledged = self._complete = False
        self._close_unknown = self._cohort_closed = self._process_closed = False
        self._quarantine = self._error = None
        self.phase = "freeze_pending"
        self.reason = None
        self.journal = RecoveryJournal(host.journal_dir)
        self._original_objects = (self.host, self.owner, self.store, self.supervisor, self.policy,
            self._freeze, self._seal, self.journal, self.owner.process, self.owner.cohort)
        self._readiness_objects = tuple(getattr(host, name, _MISSING) for name in
            ("_thread", "_listener", "_registry", "_service", "_thread_stopped", "_readiness_stop"))
        self._readiness_native_owner = getattr(self._readiness_objects[1], "_owner", _MISSING)
        self._owner_source_pin = tuple(getattr(self.owner, name, _MISSING) for name in
            ("manifest", "source_root", "ledger_path", "ledger_identity", "generation", "readiness_endpoint"))
        self._original_request = self.request_id
        _ORIGINAL_OPERATIONS.add(self)
        # Retain the operation before any possible SQL or native side effect.
        self.owner._retirement_operation = self

    @property
    def freeze_acknowledged(self):
        return self._freeze_acknowledged

    @property
    def sealed(self):
        return self._sealed

    @property
    def complete(self):
        return self._complete

    def _original(self):
        if (self.host._retirement is not self or self.host.owner is not self.owner or
                self.host.store is not self.store or self.host.supervisor is not self.supervisor or
                self.store._policy is not self.policy or
                self.owner._retirement_operation is not self):
            _reject("daily_retirement_original_owner_changed")
        if any(item.close_unknown for item in self.host._connections):
            self._quarantine = "daily_retirement_sql_cleanup_unknown"
        if not self._complete:
            self.owner._assert_owner()
        if self._quarantine:
            _reject(self._quarantine)

    def _retain_policy_cleanup(self, operation):
        error = operation._error
        if error is None:
            return
        notes = set(getattr(error, "__notes__", ()))
        if (hasattr(error, "_daily_retirement_inventory_connection") or
                hasattr(error, "_daily_retirement_inventory_directory_reader") or
                any("cleanup" in note or "rollback_failed" in note for note in notes) or
                getattr(error, "reason", str(error)) in {
                    "lifecycle_connection_cleanup_failed", "coverage_reader_cleanup_failed"}):
            self._error = error
            self._quarantine = "daily_retirement_cleanup_unknown"
            self.reason = self._quarantine

    def _connections_settled(self):
        if any(not item.closed or item.close_unknown for item in self.host._connections):
            _reject("daily_retirement_sql_custody_unsettled")

    def _read(self):
        generation._assert_daily_locations(self.owner.source_root, self.owner.ledger_path)
        if generation._ledger_identity(self.owner.ledger_path) != self.owner.ledger_identity:
            _reject("daily_retirement_ledger_changed")
        if generation._fixed_policy_digest(self.owner.ledger_path) != self.owner._config_digest:
            _reject("daily_retirement_config_changed")
        generation.verify_import_provenance(self.owner.manifest, self.owner.source_root)
        custody = self.host._open(readonly=True)
        try:
            row = generation.read_generation(custody.connection)
            frozen = read_retirement(custody.connection)
            runtime = dict(custody.connection.execute(
                "SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())
            return row, frozen, runtime
        finally:
            custody.close()

    def _close_write(self, custody):
        # A failed rollback/close is retained on its exact owner. A later open
        # connection cannot certify that a previous close succeeded.
        if custody.closed and not custody.close_unknown:
            return
        if custody.close_unknown:
            self._quarantine = "daily_retirement_sql_cleanup_unknown"
            _reject(self._quarantine)
        try:
            if custody.connection.in_transaction:
                custody.connection.rollback()
            custody.close()
        except BaseException as error:
            self._quarantine = "daily_retirement_sql_cleanup_unknown"
            self._error = error
            raise

    def _binding(self, row, *, state):
        if row is None or row["state"] != state:
            _reject("daily_retirement_generation_changed")
        if self._generation_row is None:
            if not self.owner._matches_generation(row):
                _reject("daily_retirement_generation_changed")
            self._generation_row = dict(row)
            self._generation_pin = self._generation_row, _canonical(self._generation_row)
        expected = dict(self._generation_row, state=state)
        if row != expected:
            _reject("daily_retirement_generation_changed")

    def _freeze_write(self):
        self._original()
        self.owner.assert_ready()
        guard = self._freeze.guard
        self.policy.assert_held(guard)
        custody = self.host._open()
        try:
            conn = custody.connection
            conn.execute("BEGIN IMMEDIATE")
            self.policy.revalidate(conn, guard)
            row = generation.read_generation(conn)
            self._binding(row, state="ACTIVE")
            frozen = read_retirement(conn)
            if frozen is None:
                self._freeze_guard = guard
                self._freeze_guard_pin = guard, guard.binding, guard.nonce
                self._freeze_row = install_freeze_locked(conn,
                    owner_binding={name: row[name] for name in _BINDINGS},
                    request_id=self.request_id, guard=guard)
                self._freeze_row_pin = self._freeze_row, _canonical(self._freeze_row)
                conn.commit()
            else:
                if self._freeze_row is None or frozen != self._freeze_row:
                    _reject("daily_retirement_request_changed")
                conn.rollback()
        finally:
            self._close_write(custody)
        return True

    def _freeze_reconciled(self):
        self._original()
        self._connections_settled()
        row, frozen, runtime = self._read()
        self._binding(row, state="ACTIVE")
        if self._freeze_row is None:
            return False
        if frozen != self._freeze_row or runtime["policy_entry_nonce"] is not None:
            _reject("daily_retirement_freeze_unsettled")
        if (self._freeze_guard is not None and
                runtime["policy_instance_id"] == self._freeze_guard.binding.instance_id and
                runtime["policy_logon_id"] == self._freeze_guard.binding.logon_id):
            # _read returned only after closing its original SQL owner. This
            # also retains positive clear readback after a lost clear ACK.
            self._freeze_readback = self._freeze_guard, self._freeze_guard.nonce
        return True

    def _supervisor_settled(self):
        # This is the retained actual object, not an operator JSON receipt.
        snapshot = self.supervisor._custody_snapshot()
        guard = self.policy.current_guard()
        # The final original operation legitimately owns the current nonce.
        # Outside it require the supervisor's complete settled predicate; inside
        # it recheck the same native custody and let inventory validate nonce.
        positive = (snapshot.get("settled") is True if guard is None else
            self.supervisor._drain_children_settled() and
            snapshot.get("remaining_custody") == 0 and snapshot.get("mode_off") is True and
            snapshot.get("barrier_cleared") is True and self.supervisor._operational_error is None)
        if (not self.host._supervisor_closed or not self.supervisor.draining or
                not self.supervisor._closed or not positive):
            _reject("daily_retirement_supervisor_unsettled")
        self._supervisor_custody_pin = self._supervisor_custody()

    def _supervisor_custody(self):
        return _custody_pin(tuple(getattr(self.supervisor, name, _MISSING) for name in _SUPERVISOR_CUSTODY))

    def _seal_write(self):
        self._original()
        self.policy.assert_held(self._seal.guard)
        if self._seal_attempted:
            # Reacquisition uses the same original guard after a lost ACK.
            # No native inventory, source owner or SQL mutation is reconstructed.
            row, frozen, unused_runtime = self._read()
            if row is not None and row["state"] == "DRAINING":
                self._binding(row, state="DRAINING")
                if self._seal_row is None or frozen != self._seal_row:
                    _reject("daily_retirement_seal_unsettled")
                return True
            self._connections_settled()
            self._binding(row, state="ACTIVE")
            if frozen != self._freeze_row:
                _reject("daily_retirement_seal_unsettled")
            # The exact previous connection has closed positively, and this
            # same held guard observes the original atomic preimage. Retain
            # the request/guard and retry its SQL publication, never its owner.
            self._seal_attempted = False
            self._seal_row = None
        try:
            self.owner.assert_ready()
            self._supervisor_settled()
            self._connections_settled()
            snapshot = capture_retirement_inventory(self.store, self.journal)
        except (DailyRetirementError, LifecycleError, RecoveryJournalError) as error:
            # A positively completed read-only refusal must leave ordinary
            # cleanup able to obtain POLICY. Unknown reader/native cleanup is
            # retained instead, and never called a harmless validation refusal.
            if not getattr(error, "__notes__", ()) and not hasattr(error, "_journal_cleanup_owner"):
                self._seal.guard.clean_rejection = True
            raise
        custody = self.host._open()
        try:
            conn = custody.connection
            conn.execute("BEGIN IMMEDIATE")
            self.policy.revalidate(conn, self._seal.guard)
            self._binding(generation.read_generation(conn), state="ACTIVE")
            if read_retirement(conn) != self._freeze_row:
                _reject("daily_retirement_request_changed")
            revalidate_retirement_inventory(conn, self.store, snapshot)
            # Retain exact original operation/guard before the first seal write.
            self._seal_guard = self._seal.guard
            self._seal_guard_pin = self._seal_guard, self._seal_guard.binding, self._seal_guard.nonce
            from . import daily_retirement_inventory as inventory
            self._seal_inventory = snapshot
            self._seal_inventory_digest = retirement_inventory_digest(self.store, snapshot)
            self._seal_inventory_pin = (snapshot, inventory._SNAPSHOTS[snapshot], self._seal_inventory_digest)
            digest = hashlib.sha256(json.dumps({"request_id": self.request_id,
                "generation": self.owner.generation, "freeze": self._freeze_row,
                "inventory_digest": self._seal_inventory_digest,
                "seal_nonce": self._seal_guard.nonce}, sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            self._seal_attempted = True
            changed = conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING' "
                "WHERE singleton=1 AND generation=? AND state='ACTIVE'",
                (self.owner.generation,)).rowcount
            if changed != 1:
                _reject("daily_retirement_generation_changed")
            self._seal_row = seal_freeze_locked(conn, self._freeze_row, digest, self._seal_guard)
            self._seal_row_pin = self._seal_row, _canonical(self._seal_row)
            conn.commit()
        except (DailyRetirementError, LifecycleError) as error:
            self._close_write(custody)
            if (not self._seal_attempted and not getattr(error, "__notes__", ()) and
                    not hasattr(error, "_journal_cleanup_owner")):
                self._seal.guard.clean_rejection = True
            raise
        finally:
            self._close_write(custody)
        return True

    def _seal_reconciled(self):
        self._original()
        self._connections_settled()
        row, frozen, runtime = self._read()
        if not self._seal_attempted and row is not None and row["state"] == "ACTIVE":
            self._binding(row, state="ACTIVE")
            if frozen != self._freeze_row:
                _reject("daily_retirement_request_changed")
            return False
        self._binding(row, state="DRAINING")
        if (not self._seal_attempted or self._seal_row is None or frozen != self._seal_row or
                runtime["policy_entry_nonce"] is not None or
                runtime["policy_instance_id"] != self._seal_guard.binding.instance_id or
                runtime["policy_logon_id"] != self._seal_guard.binding.logon_id):
            _reject("daily_retirement_seal_unsettled")
        self._seal_readback = self._seal_guard, self._seal_guard.nonce
        return True

    def authorize_nonce_cleanup(self, conn, row):
        """Original seal readback or exact _clear; no capacity-generation UDF."""
        self._original()
        if (not self._seal_attempted or self._sealed or self._seal_guard is None or
                threading.get_ident() != self._thread_id or not self._seal_resume_active or
                self._seal._quarantine or
                self._seal.guard is not self._seal_guard):
            _reject("daily_retirement_cleanup_not_owned")
        held = self.policy.current_guard()
        if held is not None and held is not self._seal_guard:
            _reject("daily_retirement_cleanup_not_owned")
        self._binding(row, state="DRAINING")
        if self._seal_row is None or read_retirement(conn) != self._seal_row:
            _reject("daily_retirement_seal_unsettled")
        runtime = conn.execute("SELECT policy_instance_id,policy_logon_id,policy_entry_nonce "
                               "FROM adaptive_runtime WHERE singleton=1").fetchone()
        if (runtime is None or runtime[0] != self._seal_guard.binding.instance_id or
                runtime[1] != self._seal_guard.binding.logon_id or
                runtime[2] not in {self._seal_guard.nonce, None}):
            _reject("daily_retirement_cleanup_not_owned")
        cleanup = self.policy.current_cleanup_guard() is self._seal_guard and held is None
        def clear_owned():
            return int(self.policy.current_cleanup_guard() is self._seal_guard and
                self.policy.current_guard() is None and threading.get_ident() == self._thread_id and
                self._seal_resume_active and not self._sealed and not self._quarantine and
                not self._seal._quarantine and self.host._retirement is self and
                self._seal.guard is self._seal_guard)
        if cleanup:
            # Enforce the value at execution time as well as the column at
            # prepare time. A cached statement or retained connection cannot
            # use an expired cleanup scope to replace a nonce or clear another.
            conn.create_function("sentinel_daily_retirement_clear", 0, clear_owned)
            conn.execute("""CREATE TEMP TRIGGER daily_retirement_nonce_guard
                BEFORE UPDATE OF policy_entry_nonce ON main.adaptive_runtime
                WHEN sentinel_daily_retirement_clear() IS NOT 1 OR
                     NEW.policy_entry_nonce IS NOT NULL OR OLD.policy_entry_nonce IS NOT '""" +
                self._seal_guard.nonce.replace("'", "''") + "' "
                "BEGIN SELECT RAISE(ABORT,'daily_retirement_cleanup_not_owned'); END")
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_TRANSACTION,
                   sqlite3.SQLITE_FUNCTION}
        def cleanup_only(action, table, column, database, source):
            if action in allowed:
                return sqlite3.SQLITE_OK
            if action == sqlite3.SQLITE_PRAGMA and (
                    table in {"table_info", "table_xinfo", "index_list", "index_info", "foreign_key_list"} or
                    table == "database_list" and column is None or
                    table == "foreign_keys" and (column is None or str(column).lower() in {"on", "1"}) or
                    table == "busy_timeout" and (column is None or str(column).isdigit() and int(column) <= 250)):
                return sqlite3.SQLITE_OK
            if (cleanup and action == sqlite3.SQLITE_UPDATE and table == "adaptive_runtime" and
                    column == "policy_entry_nonce" and clear_owned() == 1):
                return sqlite3.SQLITE_OK
            return sqlite3.SQLITE_DENY
        conn.set_authorizer(cleanup_only)

    def tick(self):
        self._original()
        if self._complete or self._sealed:
            return
        try:
            if not self._freeze_acknowledged:
                result = self._freeze._run(self.owner.process.identity.logon_id,
                    self._freeze_write, self._freeze_reconciled)
                self.reason = result.reason
                self._retain_policy_cleanup(self._freeze)
                if self._quarantine:
                    return
                if result.complete and self._freeze_reconciled():
                    self._freeze_acknowledged = True
                    self.phase = "draining"
                return
            if not self.host._supervisor_closed:
                return
            self.phase = "seal_pending"
            if threading.get_ident() != self._thread_id:
                _reject("daily_retirement_thread_changed")
            self._seal_resume_active = True
            try:
                result = self._seal._run(self.owner.process.identity.logon_id,
                    self._seal_write, self._seal_reconciled)
            finally:
                self._seal_resume_active = False
            self.reason = result.reason
            self._retain_policy_cleanup(self._seal)
            if self._quarantine:
                return
            if result.complete and self._seal_reconciled():
                self._sealed = True
                self.phase = "keeper_cleanup_pending"
        except BaseException as error:
            self._error = error
            if (not isinstance(error, Exception) or self._close_unknown or
                    any(item.close_unknown for item in self.host._connections)):
                self._quarantine = "daily_retirement_cleanup_unknown"
            raise

    def close_owner(self):
        self._original()
        if self._complete:
            return
        if (not self._sealed or not self.host._readiness_cleanup_complete or
                not self.host._readiness_joined or not self.host._readiness_listener_closed or
                self.host._readiness_close_unknown or self._close_unknown):
            _reject("daily_retirement_keeper_cleanup_unsettled")
        self._connections_settled()
        self.owner.assert_readiness_readers_settled()
        if (self.policy.current_guard() is not None or self.policy.current_cleanup_guard() is not None or
                self._freeze.pending or self._seal.pending):
            _reject("daily_retirement_policy_unsettled")
        self.owner.cohort.assert_retained_retired()
        # Pin these original owners before the first native close. This never
        # discovers a new process or adopts a previously missing acquisition.
        if self._closed_custody_pin is None:
            self._closed_custody_pin = (self.owner.process, self.owner.cohort,
                getattr(self.owner.cohort, "_current", _MISSING),
                tuple(getattr(self.owner.cohort, "_processes", ())),
                tuple((item, item.connection) for item in self.host._connections))
        self._close_unknown = True
        try:
            if not self._cohort_closed:
                self.owner.cohort.close()
                self._cohort_closed = True
            if not self._process_closed:
                self.owner.process.close()
                self._process_closed = True
        except BaseException as error:
            self._error = error
            self._quarantine = "daily_retirement_owner_close_unknown"
            raise
        self._close_unknown = False
        self.owner._closed = True
        self._complete = True
        self.phase = "retired_admission_fenced"

    def assert_successor_predecessor(self):
        """Validate retained positive retirement without native or ledger I/O.

        A distinct new POLICY guard is permitted. Old guards are inspected only
        as completed original custody, never reused as a held capability.
        """
        from .daily_activation_host import DailyActivationHost, _ConnectionCustody
        from .daily_cohort import RetainedCohort
        from .identity import VerifiedProcess
        from .pipe_windows import NativePipeListener, NativePipeRegistry
        from .policy import PolicyCoordinator, PolicyGuard, _cleanup_outcome_unverified
        from .supervisor_startup import SupervisorStartup
        from . import daily_retirement_inventory as inventory
        if (type(self) is not DailyRetirementOperation or self not in _ORIGINAL_OPERATIONS or
                threading.current_thread() is not self._thread or threading.get_ident() != self._thread_id or
                os.getpid() != self._pid or self.request_id != self._original_request):
            _reject("daily_successor_original_retirement_required")
        current = (self.host, self.owner, self.store, self.supervisor, self.policy,
            self._freeze, self._seal, self.journal, self.owner.process, self.owner.cohort)
        if (any(left is not right for left, right in zip(current, self._original_objects)) or
                type(self.host) is not DailyActivationHost or type(self.policy) is not PolicyCoordinator or
                self.host._retirement is not self or self.owner._retirement_operation is not self or
                self.host.owner is not self.owner or self.host.store is not self.store or
                self.host.supervisor is not self.supervisor or self.store._policy is not self.policy or
                self.policy.store is not self.store or
                self.store.db_path != self.owner.ledger_path or self.host.ledger_path != self.owner.ledger_path or
                self.host.journal_dir != self.journal._directory):
            _reject("daily_successor_predecessor_binding_changed")
        if (tuple(getattr(self.owner, name, _MISSING) for name in
                ("manifest", "source_root", "ledger_path", "ledger_identity", "generation", "readiness_endpoint")) !=
                self._owner_source_pin or self.owner.manifest is not self._owner_source_pin[0] or
                self.owner.readiness_endpoint is not self._owner_source_pin[5] or
                not self.owner._matches_generation(self._generation_row)):
            _reject("daily_successor_predecessor_binding_changed")
        if (any(value is not True for value in (self._complete, self._sealed, self._freeze_acknowledged,
                self._cohort_closed, self._process_closed, self.owner._closed, self.host._generation_settled,
                self.host._supervisor_closed, self.supervisor._closed, self.supervisor.draining,
                self.host._readiness_cleanup_complete, self.host._readiness_joined,
                self.host._readiness_listener_closed)) or self._close_unknown is not False or
                self.host._readiness_close_unknown is not False or self._seal_resume_active is not False or
                self._quarantine is not None or self.supervisor._operational_error is not None or
                self.phase != "retired_admission_fenced"):
            _reject("daily_successor_predecessor_cleanup_unsettled")
        for operation, guard, pin, readback in ((self._freeze, self._freeze_guard, self._freeze_guard_pin,
                self._freeze_readback), (self._seal, self._seal_guard, self._seal_guard_pin, self._seal_readback)):
            if (type(operation) is not RetainedPolicyOperation or operation.store is not self.store or
                    operation._complete is not True or operation.pending or operation._quarantine is not None or
                    type(guard) is not PolicyGuard or pin is None or guard is not pin[0] or
                    guard.binding is not pin[1] or guard.nonce != pin[2] or readback is None or
                    readback[0] is not guard or readback[1] != guard.nonce or
                    guard._native_exit_confirmed is not True or guard._native_no_entry_confirmed is not False or
                    guard._nonce_clear_attempted is not True or
                    self.policy.current_guard() is guard or self.policy.current_cleanup_guard() is guard):
                _reject("daily_successor_predecessor_policy_unsettled")
        for error in (self._error, self._freeze._error, self._seal._error,
                getattr(self.host, "_retirement_cleanup_error", None), getattr(self.host, "_readiness_failure", None)):
            if error is not None and _cleanup_outcome_unverified(error):
                _reject("daily_successor_predecessor_cleanup_unsettled")
        readiness = tuple(getattr(self.host, name, _MISSING) for name in
            ("_thread", "_listener", "_registry", "_service", "_thread_stopped", "_readiness_stop"))
        if (any(left is not right or left is _MISSING for left, right in zip(readiness, self._readiness_objects)) or
                type(readiness[0]) is not threading.Thread or type(readiness[1]) is not NativePipeListener or
                type(readiness[2]) is not NativePipeRegistry or
                self.host._thread is not self.host._readiness_original_thread or
                self.host._listener is not self.host._readiness_original_listener or
                self.host._registry is not self.host._readiness_original_registry or
                not self.host._thread_stopped.is_set() or not self.host._readiness_stop.is_set() or
                self.host._thread.is_alive() is not False):
            _reject("daily_successor_predecessor_readiness_changed")
        status = self.host._registry.status()
        if (any(type(value) is not int or value != 0 for value in
                (status.resources, status.pending, status.quarantined)) or
                self.owner._readiness_cleanup_error is not None or self.owner._readiness_readers):
            _reject("daily_successor_predecessor_readiness_unsettled")
        native = self._readiness_native_owner
        if (native is _MISSING or self.host._listener._owner is not native or
                getattr(native, "_registry", None) is not self.host._registry or
                any(getattr(native, name, _MISSING) is not None for name in
                    ("_handle", "_operation", "_active", "_server_process", "_self_process", "_peer_process",
                     "_accept_operation", "_accept_connection")) or
                getattr(native, "_handle_close_unknown", None) is not False or
                getattr(native, "_busy", None) is not False or getattr(native, "_proofs", None) != 0):
            _reject("daily_successor_predecessor_readiness_unsettled")
        pin = self._closed_custody_pin
        if (pin is None or self.owner.process is not pin[0] or self.owner.cohort is not pin[1] or
                type(self.owner.cohort) is not RetainedCohort or self.owner.cohort._current is not pin[2] or
                len(self.owner.cohort._processes) != len(pin[3]) or
                any(left is not right for left, right in zip(self.owner.cohort._processes, pin[3])) or
                self.owner.cohort._closed is not True or self.owner.cohort._unresolved is not None or
                len(self.host._connections) != len(pin[4]) or
                any(left is not right[0] for left, right in zip(self.host._connections, pin[4])) or
                self._supervisor_custody_pin is None or self._supervisor_custody() != self._supervisor_custody_pin):
            _reject("daily_successor_predecessor_custody_changed")
        startup = getattr(self.supervisor, "startup", _MISSING)
        if startup is not self._supervisor_startup or startup is _MISSING:
            _reject("daily_successor_predecessor_custody_changed")
        if startup is not None and (type(startup) is not SupervisorStartup or startup._closed is not True or
                startup._acquired is not False or startup._entry_unknown is not False or
                startup._release_unknown is not False or startup._close_unknown is not False or
                any(value is not None for value in (startup._current, startup._mutex, startup._scope, startup._lease)) or
                startup.policy_pending or startup.policy_quarantined):
            _reject("daily_successor_predecessor_startup_unsettled")
        for process in (pin[0], pin[2], *pin[3]):
            if (type(process) is not VerifiedProcess or process._handle is not None or
                    process._close_outcome_unknown is not False):
                _reject("daily_successor_predecessor_process_unsettled")
        for connection, original in pin[4]:
            if (type(connection) is not _ConnectionCustody or connection.connection is not original or
                    connection.closed is not True or connection.close_unknown is not False):
                _reject("daily_successor_predecessor_sql_unsettled")
        for row, pin in ((self._generation_row, self._generation_pin),
                (self._freeze_row, self._freeze_row_pin), (self._seal_row, self._seal_row_pin)):
            if pin is None or row is not pin[0] or _canonical(row) != pin[1]:
                _reject("daily_successor_predecessor_preimage_changed")
        inventory._retired_inventory_parts(self)
        expected = hashlib.sha256(_canonical(dict(request_id=self.request_id,
            generation=self.owner.generation, freeze=self._freeze_row,
            inventory_digest=self._seal_inventory_digest, seal_nonce=self._seal_guard.nonce))).hexdigest()
        if self._seal_row != dict(self._freeze_row, phase="SEALED", seal_digest=expected):
            _reject("daily_successor_predecessor_seal_changed")
