"""Atomic startup publication by an original retained guardian under POLICY.

This adapter adds no recovery, cold adoption or native control authority. The
caller retains the original guardian and this operation before its first tick.
Fresh publication binds its infrastructure identity and runtime epoch/logon in
one transaction. A replacement consumes only the already validated, unchanged
SettledEpochRollover generation; it never manufactures a successor epoch.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
from uuid import UUID
import weakref

from .contracts import IdentityStatus, ProcessIdentity
from .identity import VerifiedProcess
from . import legacy_writer
from .legacy_writer import MAX_INFRASTRUCTURE, _infra_schema
from .recovery_journal import RecoveryJournal
from .store import LifecycleError
from .supervisor_epoch import SettledEpochRollover, _epoch
from .supervisor_reconcile import RetainedPolicyOperation
from .supervisor_startup import _DIRECTORY_LIMIT, _EMPTY_TABLES, _JOURNAL_NAME
from .policy import _cleanup_outcome_unverified


_ORIGINALS = weakref.WeakSet()
_SQL_CURRENT = threading.local()


def current_sql_owner(db_path=None):
    owner = getattr(_SQL_CURRENT, "operation", None)
    if owner is None:
        return None
    owner._original()
    if db_path is not None and Path(db_path).resolve() != owner._ledger_path:
        raise LifecycleError("guardian_registration_ledger_changed")
    return owner


@dataclass(frozen=True)
class RegistrationResult:
    complete: bool
    pending: bool
    refused: bool
    quarantined: bool
    reason: str
    registry_revision: int | None = None


class _Refused(LifecycleError):
    pass


class GuardianRegistration:
    def __init__(self, store, journal, *, guardian, guardian_epoch):
        if (not isinstance(guardian, VerifiedProcess) or type(guardian.identity) is not ProcessIdentity or
                not _epoch(guardian_epoch) or not isinstance(journal, RecoveryJournal)):
            raise LifecycleError("guardian_registration_owner_required")
        self.store, self.journal = store, journal
        self.guardian, self.identity, self.epoch = guardian, guardian.identity, guardian_epoch
        self._policy_operation = RetainedPolicyOperation(store)
        self.before = self.after = None
        self.refusal = None
        self._error = None
        self._result = RegistrationResult(False, False, False, False, "guardian_registration_not_started")
        from .daily_generation import _ledger_identity
        self._thread, self._pid = threading.current_thread(), os.getpid()
        self._ledger_path = Path(store.db_path).resolve()
        self._ledger_identity = _ledger_identity(self._ledger_path)
        self._original_pins = (store, store._policy, journal, guardian, guardian._backend,
            guardian._handle, self.identity, guardian_epoch, self._policy_operation,
            store.db_path, journal._directory, self._ledger_path, self._ledger_identity)
        self._connections, self._connection_pins = [], {}
        self._quarantine = None
        self._successor_history_snapshot = self._successor_history_guard = None
        self._publication_pins = None
        self._successor_nonce_candidate = self._successor_nonce_confirmation = None
        _ORIGINALS.add(self)

    def _original(self, *, allow_quarantine=False):
        if (type(self) is not GuardianRegistration or self not in _ORIGINALS or
                threading.current_thread() is not self._thread or os.getpid() != self._pid):
            raise LifecycleError("guardian_registration_original_owner_required")
        pins = self._original_pins
        if (any(left is not right for left, right in zip(
                (self.store, self.store._policy, self.journal, self.guardian, self.guardian._backend), pins[:5])) or
                (self.guardian._handle, self.guardian.identity, self.epoch) != pins[5:8] or
                self.identity is not pins[6] or self._policy_operation is not pins[8] or
                (self.store.db_path, self.journal._directory, self._ledger_path, self._ledger_identity) != pins[9:] or
                len(self._connections) != len(self._connection_pins) or any(
                    self._connection_pins.get(id(item), ())[:2] != (item, item.connection)
                    for item in self._connections)):
            raise LifecycleError("guardian_registration_original_owner_changed")
        if self._publication_pins is not None:
            before, after, before_values, after_values = self._publication_pins
            if (self.before is not before or self.after is not after or
                    tuple(sorted(before.items())) != before_values or tuple(sorted(after.items())) != after_values):
                raise LifecycleError("guardian_registration_original_postimage_changed")
        if not allow_quarantine and (self._quarantine is not None or any(item.close_unknown for item in self._connections)):
            raise LifecycleError("guardian_registration_custody_unsettled")

    @contextmanager
    def _sql_scope(self):
        self._original()
        previous = getattr(_SQL_CURRENT, "operation", None)
        if previous is not None and previous is not self:
            raise LifecycleError("guardian_registration_foreign_sql_scope")
        _SQL_CURRENT.operation = self
        try:
            yield
        except BaseException as error:
            self._error = error
            if _cleanup_outcome_unverified(error):
                self._quarantine = "sql_cleanup_unknown"
            raise
        finally:
            _SQL_CURRENT.operation = previous

    def begin_sql_acquisition(self):
        from .daily_activation_host import _ConnectionCustody
        self._original()
        owner = _ConnectionCustody(None)
        self._connections.append(owner)
        self._connection_pins[id(owner)] = (owner, None, None)
        return owner

    def sql_acquired(self, owner, conn):
        from .daily_generation import _ledger_identity
        if (self._connection_pins.get(id(owner)) != (owner, None, None) or
                owner.connection is not None or not isinstance(conn, sqlite3.Connection) or conn.in_transaction):
            raise LifecycleError("guardian_registration_original_sql_acquisition_required")
        owner.connection = conn
        self._connection_pins[id(owner)] = (owner, conn, None)
        identity = _ledger_identity(self._ledger_path)
        self._connection_pins[id(owner)] = (owner, conn, identity)
        if identity != self._ledger_identity:
            raise LifecycleError("guardian_registration_ledger_changed")

    def sql_acquisition_failed(self, owner, error):
        self._quarantine, self._error = "sql_acquisition_unknown", error
        error._guardian_registration = self
        error.add_note("guardian_registration_sql_acquisition_unknown")

    def connection_closed(self, conn):
        owners = [item for item in self._connections if item.connection is conn]
        if len(owners) != 1 or owners[0].closed or owners[0].close_unknown:
            raise LifecycleError("guardian_registration_original_sql_close_required")
        owners[0].closed = True

    def _assert_owned_transaction(self, conn):
        self._original()
        if (getattr(_SQL_CURRENT, "operation", None) is not self or
                not isinstance(conn, sqlite3.Connection) or not conn.in_transaction):
            raise LifecycleError("guardian_registration_original_sql_transaction_required")
        matches = [item for item in self._connections if item.connection is conn and
                   not item.closed and not item.close_unknown]
        if len(matches) != 1 or self._connection_pins[id(matches[0])][2] != self._ledger_identity:
            raise LifecycleError("guardian_registration_original_sql_transaction_required")
        # File identity was positively read before BEGIN on this tracked
        # connection. Final validation performs SQL metadata reads only.
        rows = conn.execute("PRAGMA database_list").fetchmany(2)
        if len(rows) != 1 or rows[0][1] != "main" or os.path.normcase(rows[0][2]) != os.path.normcase(str(self._ledger_path)):
            raise LifecycleError("guardian_registration_ledger_changed")

    def _assert_successor_history_owner(self, guard):
        self._original()
        self.store._policy.assert_held(guard)
        if guard is not self.guard:
            raise LifecycleError("guardian_registration_original_policy_required")
        if self._successor_history_guard is None:
            self._successor_history_guard = guard
        elif guard is not self._successor_history_guard:
            raise LifecycleError("guardian_registration_original_policy_changed")

    def assert_successor_history_connection(self, conn, guard):
        self._assert_successor_history_owner(guard)
        self._assert_owned_transaction(conn)

    def _assert_successor_postimage_owner(self, snapshot):
        self._original()
        if (self._successor_history_snapshot is not snapshot or self._successor_history_guard is None or
                self.before is None or self.after is None):
            raise LifecycleError("guardian_registration_original_postimage_required")
        guard = self._successor_history_guard
        if (self.store._policy.current_guard() is not guard and
                (guard._native_exit_confirmed is not True or guard._nonce_clear_attempted is not True)):
            raise LifecycleError("guardian_registration_original_policy_unsettled")

    def assert_successor_postimage_connection(self, conn, snapshot):
        self._assert_successor_postimage_owner(snapshot)
        self._assert_owned_transaction(conn)

    def _assert_successor_nonce_cleanup(self, snapshot):
        self._assert_successor_postimage_owner(snapshot)
        guard, operation = self._successor_history_guard, self._policy_operation
        if (operation.guard is not guard or not operation.pending or operation._complete or
                operation._quarantine is not None or guard._native_exit_confirmed is not True or
                guard._nonce_clear_attempted is not True or
                self.store._policy.current_guard() is not None or
                self.store._policy.current_cleanup_guard() is not None):
            raise LifecycleError("guardian_registration_original_cleanup_required")
        return guard

    def observe_successor_nonce_clear(self, conn, snapshot):
        """Retain a NULL observation; completion still requires positive close."""
        guard = self._assert_successor_nonce_cleanup(snapshot)
        self._assert_owned_transaction(conn)
        runtime = self.store._policy._runtime(conn)
        binding = self.store._policy._binding(runtime, self.identity.logon_id)
        if (runtime["policy_entry_nonce"] is not None or binding != guard.binding or
                self._image(runtime) != self.after or any(
                    item.connection is not conn and (not item.closed or item.close_unknown)
                    for item in self._connections)):
            raise LifecycleError("guardian_registration_cleanup_observation_unverified")
        self._successor_nonce_candidate = (snapshot, guard, conn, self._publication_pins)

    def _confirm_successor_nonce_clear(self, snapshot):
        """Called only after the complete Store/readiness context has exited."""
        guard = self._assert_successor_nonce_cleanup(snapshot)
        candidate = self._successor_nonce_candidate
        if (candidate is None or candidate[0] is not snapshot or candidate[1] is not guard or
                candidate[3] is not self._publication_pins or
                not any(item.connection is candidate[2] for item in self._connections) or
                any(not item.closed or item.close_unknown for item in self._connections)):
            raise LifecycleError("guardian_registration_cleanup_close_unverified")
        # Preserve the original failed ACK. This separate reconciliation proof
        # must never stamp the original guard's _nonce_clear_confirmed field.
        self._successor_nonce_confirmation = candidate

    @contextmanager
    def successor_history_reader(self, guard):
        self._assert_successor_history_owner(guard)
        with self._sql_scope():
            owner = self.begin_sql_acquisition()
            try:
                conn = sqlite3.connect(self._ledger_path.as_uri() + "?mode=ro", uri=True,
                                       isolation_level=None, timeout=.25)
            except BaseException as error:
                self.sql_acquisition_failed(owner, error)
                raise
            try:
                self.sql_acquired(owner, conn)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA busy_timeout=250")
                conn.execute("PRAGMA query_only=ON")
                conn.execute("PRAGMA trusted_schema=OFF")
                deadline = time.monotonic() + .250
                conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                conn.execute("BEGIN")
                self._assert_owned_transaction(conn)
                yield conn
            finally:
                try:
                    owner.close()
                except BaseException as error:
                    self._quarantine, self._error = "sql_close_unknown", error
                    error._guardian_registration = self
                    error.add_note("guardian_registration_sql_close_unknown")
                    raise

    @property
    def guard(self):
        return self._policy_operation.guard

    @property
    def pending(self):
        # A busy predecessor may still own POLICY even before this operation
        # receives a guard. Keep that ordinary startup retry resident too.
        return self._policy_operation.pending or self._result.pending

    @property
    def quarantined(self):
        # Interrupts propagate before a RegistrationResult can be returned.
        return self._quarantine is not None or self._policy_operation._quarantine is not None

    @property
    def result(self):
        return self._result

    @staticmethod
    def _image(row):
        return {key: value for key, value in dict(row).items() if key != "policy_entry_nonce"}

    def _live(self):
        observed = self.guardian.observe()
        if (self.guardian.identity != self.identity or observed.identity != self.identity or
                observed.status is not IdentityStatus.ALIVE):
            raise LifecycleError("guardian_registration_identity_unverified")

    def _key(self):
        return ("guardian", self.identity.pid, str(self.identity.created_filetime_100ns), self.identity.logon_id)

    def _rows(self, conn):
        _infra_schema(conn)
        rows = conn.execute("""SELECT
            CASE WHEN typeof(role)='text' AND length(role)<=10 THEN role END AS role,
            CASE WHEN typeof(pid)='integer' THEN pid END AS pid,
            CASE WHEN typeof(created_filetime_100ns)='text' AND length(created_filetime_100ns)<=20
                THEN created_filetime_100ns END AS created_filetime_100ns,
            CASE WHEN typeof(logon_id)='text' AND length(logon_id)<=184 THEN logon_id END AS logon_id,
            CASE WHEN typeof(schema_version)='integer' THEN schema_version END AS schema_version
            FROM adaptive_infrastructure LIMIT ?""", (MAX_INFRASTRUCTURE + 1,)).fetchall()
        if len(rows) > MAX_INFRASTRUCTURE:
            raise _Refused("guardian_host_registry_full")
        guardians = [tuple(row[:4]) for row in rows if row[0] == "guardian"]
        if len(guardians) > 1 or any(row != self._key() for row in guardians):
            raise _Refused("guardian_host_registry_occupied")
        for row in rows:
            try:
                identity = ProcessIdentity.from_dict({"pid": row[1], "created_filetime_100ns": row[2], "logon_id": row[3]})
            except (ValueError, TypeError):
                raise _Refused("guardian_host_registry_invalid") from None
            if row[0] not in {"guardian", "helper", "supervisor"} or row[4] != 1 or identity.logon_id != self.identity.logon_id:
                raise _Refused("guardian_host_registry_invalid")
        return rows, bool(guardians)

    def _fresh_ledger(self, conn, runtime, rows):
        if runtime["admission_barrier"] != "NONE":
            raise _Refused("guardian_registration_barrier_unsettled")
        if any(row[0] != "guardian" for row in rows):
            raise _Refused("guardian_registration_old_infrastructure")
        # Reuse the supervisor's complete bounded fresh-schema requirements.
        # Terminal history is history; an empty first page is not fresh proof.
        for table, fields in _EMPTY_TABLES.items():
            found = conn.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
            if found is None and table == "adaptive_barrier_clears":
                continue
            if found is None or found[0] != "table":
                raise _Refused("guardian_registration_inventory_unavailable")
            if not fields.issubset({row[1] for row in conn.execute("PRAGMA table_info(" + table + ")")}):
                raise _Refused("guardian_registration_inventory_invalid")
            if conn.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone():
                raise _Refused("guardian_registration_old_scope_or_launch")
        for table in ("reservations", "worker_reservations"):
            if conn.execute("SELECT 1 FROM " + table + " WHERE execution_id IS NOT NULL "
                    "OR lifecycle_managed IS NOT 0 LIMIT 1").fetchone():
                raise _Refused("guardian_registration_old_allocation")
        for table in ("adaptive_epoch_rollovers", "adaptive_off_holds"):
            found = conn.execute("SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
            if found is not None and (found[0] != "table" or conn.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone()):
                raise _Refused("guardian_registration_old_history")

    def _fresh_journal(self):
        self.journal._check_directory()
        with os.scandir(self.journal._directory) as entries:
            for count, entry in enumerate(entries, 1):
                if count > _DIRECTORY_LIMIT:
                    raise _Refused("guardian_registration_inventory_incomplete")
                if _JOURNAL_NAME.fullmatch(entry.name):
                    raise _Refused("guardian_registration_old_manifest")
        self.journal._check_directory()

    def _rollover(self, conn, runtime):
        if runtime["admission_barrier"] != "NONE" or not SettledEpochRollover._audit_schema(conn):
            raise _Refused("guardian_registration_rollover_unverified")
        row = conn.execute("SELECT * FROM adaptive_epoch_rollovers WHERE new_epoch=? LIMIT 2", (self.epoch,)).fetchall()
        if len(row) != 1:
            raise _Refused("guardian_registration_rollover_unverified")
        row = dict(row[0])
        try:
            valid_id = str(UUID(row["attempt_id"])) == row["attempt_id"] and UUID(row["attempt_id"]).int != 0
            ProcessIdentity.from_dict({"pid": row["guardian_pid"],
                "created_filetime_100ns": row["guardian_created_filetime_100ns"], "logon_id": row["guardian_logon_id"]})
        except (ValueError, TypeError, AttributeError):
            raise _Refused("guardian_registration_rollover_unverified") from None
        if (not valid_id or not _epoch(row["old_epoch"]) or row["old_epoch"] == self.epoch or
                row["policy_instance_id"] != runtime["policy_instance_id"] or
                row["policy_logon_id"] != self.identity.logon_id or row["guardian_logon_id"] != self.identity.logon_id or
                type(row["previous_revision"]) is not int or row["previous_revision"] < 0 or
                row["registry_revision"] != row["previous_revision"] + 1 or
                row["registry_revision"] != runtime["registry_revision"] or
                type(row["scope_count"]) is not int or row["scope_count"] < 0 or
                type(row["inventory_digest"]) is not str or re.fullmatch(r"[0-9a-f]{64}", row["inventory_digest"]) is None):
            raise _Refused("guardian_registration_rollover_unverified")
        if conn.execute("SELECT 1 FROM managed_executions WHERE guardian_epoch=? OR "
                "state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED') OR launch_in_flight IS NOT 0 LIMIT 1",
                (self.epoch,)).fetchone():
            raise _Refused("guardian_registration_old_scope_or_launch")
        for table in ("reservations", "worker_reservations"):
            if conn.execute("SELECT 1 FROM " + table + " WHERE execution_id IS NOT NULL "
                    "OR lifecycle_managed IS NOT 0 LIMIT 1").fetchone():
                raise _Refused("guardian_registration_old_allocation")

    def _validate(self, conn, runtime):
        if runtime["active_logon_id"] not in {"", self.identity.logon_id}:
            raise _Refused("guardian_host_logon_occupied")
        if runtime["guardian_epoch"] not in {"", self.epoch}:
            raise _Refused("guardian_host_epoch_occupied")
        rows, registered = self._rows(conn)
        if runtime["guardian_epoch"] == "":
            self._fresh_ledger(conn, runtime, rows)
        else:
            if runtime["active_logon_id"] != self.identity.logon_id:
                raise _Refused("guardian_registration_partial_binding")
            if not registered:
                if self._successor_history_snapshot is None:
                    self._rollover(conn, runtime)
                else:
                    from .daily_successor_registration_inventory import revalidate_registration_history
                    revalidate_registration_history(conn, self, self.guard, self._successor_history_snapshot)
        if not registered and len(rows) >= MAX_INFRASTRUCTURE:
            raise _Refused("guardian_host_registry_full")
        return registered

    def _publish(self):
        policy, guard = self.store._policy, self.guard
        # This native check is first, before this scope touches the ledger.
        legacy_writer.verify_infrastructure_candidate_locked(self.store, "guardian", self.guardian)
        legacy_writer.initialize_registry_locked(self.store)
        try:
            successor = False
            with self.store._connection() as conn:
                conn.execute("BEGIN")
                runtime = policy.revalidate(conn, guard)
                fresh = runtime["guardian_epoch"] == ""
                if not fresh and (self.after is None or self._image(runtime) != self.after):
                    from .daily_successor_epoch import validate_successor_guardian_epoch
                    successor = validate_successor_guardian_epoch(conn, guardian_epoch=self.epoch,
                        logon_id=self.identity.logon_id, policy_instance_id=guard.binding.instance_id) is not None
            if fresh:
                self._fresh_journal()
            if successor and self._successor_history_snapshot is None:
                from .daily_successor_registration_inventory import capture_registration_history
                self._live()
                snapshot = capture_registration_history(self, guard)
                self._successor_history_snapshot = snapshot
            self._live()
            with self.store._transaction() as conn:
                deadline = time.monotonic() + .250
                conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                runtime = policy.revalidate(conn, guard)
                image = self._image(runtime)
                if self.after is not None and image == self.after:
                    _, registered = self._rows(conn)
                    if not registered:
                        raise LifecycleError("guardian_registration_replay_unverified")
                    if self._successor_history_snapshot is not None:
                        from .daily_successor_registration_inventory import revalidate_registration_postimage
                        revalidate_registration_postimage(conn, self, self._successor_history_snapshot)
                    return False
                if self.before is not None and image != self.before:
                    raise LifecycleError("guardian_registration_replay_unverified")
                registered = self._validate(conn, runtime)
                changed = not registered or runtime["guardian_epoch"] != self.epoch or runtime["active_logon_id"] != self.identity.logon_id
                after = dict(image, guardian_epoch=self.epoch, active_logon_id=self.identity.logon_id,
                                  registry_revision=image["registry_revision"] + int(changed))
                if self._publication_pins is None:
                    self.before, self.after = image, after
                    self._publication_pins = (image, after, tuple(sorted(image.items())), tuple(sorted(after.items())))
                elif self.before != image or self.after != after:
                    raise LifecycleError("guardian_registration_replay_unverified")
                if not registered:
                    conn.execute("INSERT INTO adaptive_infrastructure(role,pid,created_filetime_100ns,logon_id,schema_version) "
                                 "VALUES(?,?,?,?,1)", self._key())
                if changed and conn.execute("UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?,"
                        "registry_revision=registry_revision+1 WHERE singleton=1 AND guardian_epoch=? AND active_logon_id=? "
                        "AND registry_revision=? AND policy_instance_id=? AND policy_logon_id=? AND policy_entry_nonce=?",
                        (self.epoch, self.identity.logon_id, image["guardian_epoch"], image["active_logon_id"],
                         image["registry_revision"], guard.binding.instance_id, guard.binding.logon_id, guard.nonce)).rowcount != 1:
                    raise LifecycleError("guardian_registration_revision_changed")
                if self._successor_history_snapshot is not None:
                    from .daily_successor_registration_inventory import revalidate_registration_postimage
                    revalidate_registration_postimage(conn, self, self._successor_history_snapshot)
            return changed
        except _Refused as refusal:
            # A known read-only refusal still completes the original POLICY
            # cleanup. It is not a reason to leave a durable nonce occupied.
            self.refusal = str(refusal)
            return False

    def _reconciled(self):
        if self.after is None:
            return False
        self._live()
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            deadline = time.monotonic() + .250
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            conn.execute("BEGIN")
            runtime = self.store._policy._runtime(conn)
            self.store._policy._binding(runtime, self.identity.logon_id)
            _, registered = self._rows(conn)
            if self._image(runtime) != self.after or not registered:
                return False
            if self._successor_history_snapshot is not None:
                from .daily_successor_registration_inventory import revalidate_registration_postimage
                revalidate_registration_postimage(conn, self, self._successor_history_snapshot)
        if self._successor_nonce_candidate is not None:
            self._confirm_successor_nonce_clear(self._successor_history_snapshot)
        return True

    def tick(self):
        self._original(allow_quarantine=True)
        if self._quarantine is not None:
            self._result = RegistrationResult(False, True, False, True, "guardian_registration_custody_unsettled")
            return self._result
        if self._result.complete or self._result.refused:
            return self._result
        try:
            with self._sql_scope():
                state = self._policy_operation._run(self.identity.logon_id, self._publish, self._reconciled)
                failure = self._policy_operation._error
                if failure is not None and _cleanup_outcome_unverified(failure):
                    self._error, self._quarantine = failure, "sql_cleanup_unknown"
                if self._quarantine is not None:
                    self._result = RegistrationResult(False, True, False, True, "guardian_registration_custody_unsettled")
                    return self._result
                if state.complete and any(not owner.closed or owner.close_unknown for owner in self._connections):
                    raise LifecycleError("guardian_registration_sql_custody_unsettled")
        except BaseException as error:
            self._error = error
            raise
        complete = state.complete and self.refusal is None and self.after is not None
        refused = state.complete and self.refusal is not None
        self._result = RegistrationResult(complete, state.pending, refused, state.quarantined,
            "guardian_registration_complete" if complete else self.refusal if refused else
            (state.reason or "guardian_registration_pending"),
            self.after["registry_revision"] if complete else None)
        return self._result
