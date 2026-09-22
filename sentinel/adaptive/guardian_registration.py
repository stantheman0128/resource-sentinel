"""Atomic startup publication by an original retained guardian under POLICY.

This adapter adds no recovery, cold adoption or native control authority. The
caller retains the original guardian and this operation before its first tick.
Fresh publication binds its infrastructure identity and runtime epoch/logon in
one transaction. A replacement consumes only the already validated, unchanged
SettledEpochRollover generation; it never manufactures a successor epoch.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
import time
from uuid import UUID

from .contracts import IdentityStatus, ProcessIdentity
from .identity import VerifiedProcess
from . import legacy_writer
from .legacy_writer import MAX_INFRASTRUCTURE, _infra_schema
from .recovery_journal import RecoveryJournal
from .store import LifecycleError, _ipc_read_transaction
from .supervisor_epoch import SettledEpochRollover, _epoch
from .supervisor_reconcile import RetainedPolicyOperation
from .supervisor_startup import _DIRECTORY_LIMIT, _EMPTY_TABLES, _JOURNAL_NAME


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
        return self._policy_operation._quarantine is not None

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
                self._rollover(conn, runtime)
        if not registered and len(rows) >= MAX_INFRASTRUCTURE:
            raise _Refused("guardian_host_registry_full")
        return registered

    def _publish(self):
        policy, guard = self.store._policy, self.guard
        # This native check is first, before this scope touches the ledger.
        legacy_writer.verify_infrastructure_candidate_locked(self.store, "guardian", self.guardian)
        legacy_writer.initialize_registry_locked(self.store)
        try:
            with self.store._connection() as conn:
                runtime = policy.revalidate(conn, guard)
                if runtime["guardian_epoch"] == "":
                    self._fresh_journal()
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
                    return False
                if self.before is not None and image != self.before:
                    raise LifecycleError("guardian_registration_replay_unverified")
                registered = self._validate(conn, runtime)
                self.before = image
                changed = not registered or runtime["guardian_epoch"] != self.epoch or runtime["active_logon_id"] != self.identity.logon_id
                self.after = dict(image, guardian_epoch=self.epoch, active_logon_id=self.identity.logon_id,
                                  registry_revision=image["registry_revision"] + int(changed))
                if not registered:
                    conn.execute("INSERT INTO adaptive_infrastructure(role,pid,created_filetime_100ns,logon_id,schema_version) "
                                 "VALUES(?,?,?,?,1)", self._key())
                if changed and conn.execute("UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?,"
                        "registry_revision=registry_revision+1 WHERE singleton=1 AND guardian_epoch=? AND active_logon_id=? "
                        "AND registry_revision=? AND policy_instance_id=? AND policy_logon_id=? AND policy_entry_nonce=?",
                        (self.epoch, self.identity.logon_id, image["guardian_epoch"], image["active_logon_id"],
                         image["registry_revision"], guard.binding.instance_id, guard.binding.logon_id, guard.nonce)).rowcount != 1:
                    raise LifecycleError("guardian_registration_revision_changed")
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
        with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
            runtime = self.store._policy._runtime(conn)
            self.store._policy._binding(runtime, self.identity.logon_id)
            _, registered = self._rows(conn)
            return self._image(runtime) == self.after and registered

    def tick(self):
        if self._result.complete or self._result.refused:
            return self._result
        try:
            state = self._policy_operation._run(self.identity.logon_id, self._publish, self._reconciled)
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
