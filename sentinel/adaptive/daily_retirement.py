"""Original-owner retirement of a daily accounting generation.

The durable freeze is evidence, never a capability to adopt an active keeper.
Only the original host operation can seal its generation and close its owners.
Retirement leaves admission permanently fenced; this is not legacy fallback.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
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
        self._seal_guard = None
        self._thread_id = threading.get_ident()
        self._seal_resume_active = False
        self._seal_attempted = False
        self._sealed = self._freeze_acknowledged = self._complete = False
        self._close_unknown = self._cohort_closed = self._process_closed = False
        self._quarantine = self._error = None
        self.phase = "freeze_pending"
        self.reason = None
        self.journal = RecoveryJournal(host.journal_dir)
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
                self._freeze_row = install_freeze_locked(conn,
                    owner_binding={name: row[name] for name in _BINDINGS},
                    request_id=self.request_id, guard=guard)
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
            digest = hashlib.sha256(json.dumps({"request_id": self.request_id,
                "generation": self.owner.generation, "freeze": self._freeze_row,
                "inventory_digest": retirement_inventory_digest(self.store, snapshot),
                "seal_nonce": self._seal_guard.nonce}, sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode()).hexdigest()
            self._seal_attempted = True
            changed = conn.execute("UPDATE adaptive_daily_generation SET state='DRAINING' "
                "WHERE singleton=1 AND generation=? AND state='ACTIVE'",
                (self.owner.generation,)).rowcount
            if changed != 1:
                _reject("daily_retirement_generation_changed")
            self._seal_row = seal_freeze_locked(conn, self._freeze_row, digest, self._seal_guard)
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
