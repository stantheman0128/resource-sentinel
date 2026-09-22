"""Bounded, retained-witness epoch settlement. This module starts no process.

Terminal history is paged under a stable registry revision. The dead writer
and the supervisor instance fence prevent a settled manifest being rewritten
by a cooperating owner while that inventory is built. Any ledger revision
change invalidates the complete scan. Historical provenance is never edited.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
import threading
import time
from uuid import UUID, uuid4

from .contracts import (CpuControl, CpuControlMode, IdentityObservation,
                        IdentityStatus, ProcessIdentity, RecoveryManifest)
from .control_slot import read_slot
from .identity import VerifiedProcess
from .legacy_writer import MAX_INFRASTRUCTURE, _infra_schema
from .policy import PolicyBinding
from .store import LifecycleError
from .supervisor_reconcile import RetainedPolicyOperation


_TERMINAL = ("FINISHED", "CANCELLED_BEFORE_START", "START_FAILED")
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_PAGE = 16
_COLUMNS = ("attempt_id", "old_epoch", "new_epoch", "guardian_pid",
            "guardian_created_filetime_100ns", "guardian_logon_id",
            "policy_instance_id", "policy_logon_id", "previous_revision",
            "registry_revision", "scope_count", "inventory_digest")


@dataclass(frozen=True)
class EpochRolloverResult:
    complete: bool
    pending: bool
    reason: str
    old_epoch: str
    new_epoch: str
    registry_revision: int | None = None


def _epoch(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:@-]{1,128}", value) is not None


class SettledEpochRollover:
    """Retain one rollover attempt and its same-process POLICY ownership.

    ``witness`` must be the host's retained creation VerifiedProcess. The host
    additionally owns the supervisor-instance mutex and all native cleanup:
    its required ``assert_settled_for_rollover`` method must raise until those
    obligations are settled. Neither callable is exposed through a CLI payload.
    Callers retain this object after any failure, including a lost commit ACK.
    """

    def __init__(self, store, journal, *, old_epoch, witness, instance_owner):
        if (getattr(store, "existing_path", False) is not True or not _epoch(old_epoch)
                or not isinstance(witness, VerifiedProcess)
                or type(witness.identity) is not ProcessIdentity
                or not callable(getattr(instance_owner, "assert_held", None))
                or not callable(getattr(instance_owner, "assert_settled_for_rollover", None))):
            raise LifecycleError("epoch_rollover_authority_required")
        self.store, self.journal = store, journal
        self.old_epoch, self.witness, self.instance_owner = old_epoch, witness, instance_owner
        self.identity = witness.identity
        self.binding = instance_owner.binding
        if type(self.binding) is not PolicyBinding or self.binding.logon_id != self.identity.logon_id:
            raise LifecycleError("epoch_rollover_binding_invalid")
        self.attempt_id = str(uuid4())
        self.new_epoch = None
        self._policy_operation = RetainedPolicyOperation(store)
        self._quarantined = None
        self._error = None
        self._result = None
        self._lock = threading.Lock()
        self._reset_scan()

    @property
    def guard(self):
        return self._policy_operation.guard

    def _reset_scan(self):
        import hashlib
        self._revision = None
        self._runtime_epoch = None
        self._cursor = 0
        self._count = 0
        self._digest = hashlib.sha256()

    def _authority(self):
        self.instance_owner.assert_held()
        if self.instance_owner.binding != self.binding or self.witness.identity != self.identity:
            raise LifecycleError("epoch_rollover_binding_changed")
        try:
            observation = self.witness.observe()
        except Exception as error:
            # An unavailable/malformed observation is not ledger failure and
            # never becomes positive death. Preserve its cleanup ownership.
            raise LifecycleError("epoch_rollover_death_unverified") from error
        if (type(observation) is not IdentityObservation or observation.identity != self.identity
                or observation.status is not IdentityStatus.DEAD):
            raise LifecycleError("epoch_rollover_death_unverified")

    @staticmethod
    def _audit_schema(conn, *, create=False):
        found = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_epoch_rollovers'").fetchone()
        if found is None and not create:
            return False
        if found is not None and found[0] != "table":
            raise LifecycleError("epoch_rollover_audit_invalid")
        if create:
            conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_epoch_rollovers (
                attempt_id TEXT PRIMARY KEY, old_epoch TEXT NOT NULL,
                new_epoch TEXT NOT NULL UNIQUE, guardian_pid INTEGER NOT NULL,
                guardian_created_filetime_100ns TEXT NOT NULL, guardian_logon_id TEXT NOT NULL,
                policy_instance_id TEXT NOT NULL, policy_logon_id TEXT NOT NULL,
                previous_revision INTEGER NOT NULL, registry_revision INTEGER NOT NULL UNIQUE,
                scope_count INTEGER NOT NULL, inventory_digest TEXT NOT NULL)""")
        if tuple(row[1] for row in conn.execute("PRAGMA table_info(adaptive_epoch_rollovers)")) != _COLUMNS:
            raise LifecycleError("epoch_rollover_audit_invalid")
        return True

    def _runtime(self, conn, guard=None):
        runtime = (self.store._policy._runtime(conn) if guard is None else
                   self.store._policy.revalidate(conn, guard))
        if (self.store._policy._binding(runtime, self.identity.logon_id) != self.binding
                or runtime["active_logon_id"] not in {"", self.identity.logon_id}):
            raise LifecycleError("epoch_rollover_binding_changed")
        return runtime

    def _infrastructure(self, conn):
        _infra_schema(conn)
        rows = conn.execute("SELECT * FROM adaptive_infrastructure LIMIT ?",
                            (MAX_INFRASTRUCTURE + 1,)).fetchall()
        if len(rows) > MAX_INFRASTRUCTURE:
            raise LifecycleError("epoch_rollover_infrastructure_bound")
        for row in rows:
            try:
                identity = ProcessIdentity.from_dict({"pid": row["pid"],
                    "created_filetime_100ns": row["created_filetime_100ns"], "logon_id": row["logon_id"]})
            except (ValueError, TypeError):
                raise LifecycleError("epoch_rollover_infrastructure_invalid") from None
            if (row["schema_version"] != 1 or row["role"] not in {"guardian", "helper", "supervisor"}
                    or identity.logon_id != self.identity.logon_id):
                raise LifecycleError("epoch_rollover_infrastructure_invalid")
            if row["role"] == "guardian" and identity != self.identity:
                raise LifecycleError("epoch_rollover_competing_guardian")

    def _obligations(self, conn, runtime):
        if runtime["admission_barrier"] != "NONE":
            raise LifecycleError("epoch_rollover_barrier_unsettled")
        self._infrastructure(conn)
        live = conn.execute("""SELECT execution_id FROM managed_executions
            WHERE state NOT IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED')
               OR launch_in_flight IS NOT 0 LIMIT 11""").fetchall()
        if len(live) > 10:
            raise LifecycleError("epoch_rollover_live_bound")
        if live:
            raise LifecycleError("epoch_rollover_unretired_scope")
        # A malformed allocation must not disappear merely because its managed
        # row was marked terminal or its counterpart table was used instead.
        for table in ("reservations", "worker_reservations"):
            if conn.execute(f"SELECT 1 FROM {table} WHERE execution_id IS NOT NULL LIMIT 1").fetchone():
                raise LifecycleError("epoch_rollover_live_allocation")
        if conn.execute("""SELECT 1 FROM managed_executions WHERE guardian_epoch=?
                AND (job_name IS NULL OR job_nonce IS NULL) LIMIT 1""", (self.old_epoch,)).fetchone():
            raise LifecycleError("epoch_rollover_scope_binding_invalid")
        if runtime["guardian_epoch"] == "" and conn.execute(
                "SELECT 1 FROM managed_executions WHERE job_name IS NOT NULL LIMIT 1").fetchone():
            raise LifecycleError("epoch_rollover_blank_epoch_has_scope")
        slot = read_slot(conn)
        if slot is not None:
            if slot["slot_state"] != "RESTORED":
                raise LifecycleError("epoch_rollover_slot_unsettled")
            row = self.store._get(conn, slot["execution_id"])
            if (row["state"] != "FINISHED" or row["job_name"] != slot["job_name"]
                    or row["job_nonce"] != slot["job_nonce"] or row["guardian_epoch"] != slot["guardian_epoch"]
                    or slot["policy_instance_id"] != self.binding.instance_id
                    or slot["policy_logon_id"] != self.binding.logon_id):
                raise LifecycleError("epoch_rollover_slot_unsettled")
            return dict(row), slot
        return None

    def _prove(self, row):
        execution, nonce = row["execution_id"], row["job_nonce"]
        try:
            valid_id = str(UUID(execution)) == execution and UUID(execution).int != 0
        except (ValueError, TypeError, AttributeError):
            valid_id = False
        if (not valid_id or type(nonce) is not str or re.fullmatch(r"[0-9a-f]{32}", nonce) is None
                or row["job_name"] != f"Local\\ResourceSentinel.Job.{execution}.{nonce}"
                or row["state"] not in _TERMINAL or row["logon_id"] != self.identity.logon_id):
            raise LifecycleError("epoch_rollover_scope_binding_invalid")
        manifest = self.journal.read(execution, creation_nonce=nonce)
        if (type(manifest) is not RecoveryManifest or manifest.guardian_epoch != row["guardian_epoch"]
                or (row["guardian_epoch"] == self.old_epoch and manifest.guardian_identity != self.identity)
                or manifest.original != _DISABLED or manifest.pending_intent is not None
                or manifest.last_applied not in (None, _DISABLED)):
            raise LifecycleError("epoch_rollover_manifest_unsettled")
        self.store.assert_retained_terminal(row, manifest)
        return manifest

    def _prove_slot(self, slot_proof):
        if slot_proof is not None:
            row, slot = slot_proof
            manifest = self._prove(row)
            if (slot["owner_pid"] != manifest.wrapper_identity.pid
                    or slot["owner_created_filetime_100ns"] != str(manifest.wrapper_identity.created_filetime_100ns)
                    or slot["logon_id"] != manifest.wrapper_identity.logon_id):
                raise LifecycleError("epoch_rollover_slot_unsettled")

    def _read(self):
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            deadline = time.monotonic() + .250
            conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            conn.execute("BEGIN")
            runtime = self._runtime(conn)
            if runtime["guardian_epoch"] not in {"", self.old_epoch}:
                raise LifecycleError("epoch_rollover_epoch_changed")
            if self._revision != runtime["registry_revision"]:
                self._reset_scan()
                self._revision = runtime["registry_revision"]
                self._runtime_epoch = runtime["guardian_epoch"]
            elif self._runtime_epoch != runtime["guardian_epoch"]:
                raise LifecycleError("epoch_rollover_epoch_changed")
            slot = self._obligations(conn, runtime)
            # Earlier epochs remain immutable history, but a terminal label
            # in that history is not independently sufficient settlement.
            # Include every named scope so a caller cannot hide an unresolved
            # historical receipt merely by changing the current runtime epoch.
            page = [dict(row) for row in conn.execute("""SELECT rowid AS position,* FROM managed_executions
                WHERE job_name IS NOT NULL AND rowid>?
                ORDER BY rowid LIMIT ?""", (self._cursor, _PAGE + 1))]
            return runtime, page, slot

    def _fresh_epoch(self, conn):
        if self.new_epoch == self.old_epoch or conn.execute(
                "SELECT 1 FROM managed_executions WHERE guardian_epoch=? LIMIT 1", (self.new_epoch,)).fetchone():
            raise LifecycleError("epoch_rollover_epoch_reused")
        if self._audit_schema(conn) and conn.execute("""SELECT 1 FROM adaptive_epoch_rollovers
                WHERE old_epoch=? OR new_epoch=? LIMIT 1""", (self.new_epoch, self.new_epoch)).fetchone():
            raise LifecycleError("epoch_rollover_epoch_reused")

    def _values(self):
        return (self.attempt_id, self.old_epoch, self.new_epoch, self.identity.pid,
                str(self.identity.created_filetime_100ns), self.identity.logon_id,
                self.binding.instance_id, self.binding.logon_id, self._revision,
                self._revision + 1, self._count, self._digest.hexdigest())

    def _audit_reconciled(self):
        self._authority()
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self._runtime(conn)
            if not self._audit_schema(conn):
                return False
            row = conn.execute("SELECT * FROM adaptive_epoch_rollovers WHERE attempt_id=?",
                               (self.attempt_id,)).fetchone()
            if row is None:
                return False
            if (tuple(row) != self._values() or runtime["guardian_epoch"] != self.new_epoch
                    or runtime["registry_revision"] != self._revision + 1):
                raise LifecycleError("epoch_rollover_attempt_changed")
            return True

    def _commit(self, guard):
        self._authority()
        if self.instance_owner.assert_settled_for_rollover() is not None:
            raise LifecycleError("epoch_rollover_cleanup_unsettled")
        # Recheck the bounded current obligations under POLICY. The paged
        # terminal proofs are valid only if the complete ledger revision stays
        # fixed; the dead original writer cannot append a native intent.
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self._runtime(conn, guard)
            slot = self._obligations(conn, runtime)
        self._prove_slot(slot)
        self._authority()
        with self.store._transaction() as conn:
            runtime = self._runtime(conn, guard)
            if self._audit_schema(conn):
                recorded = conn.execute("SELECT * FROM adaptive_epoch_rollovers WHERE attempt_id=?",
                                        (self.attempt_id,)).fetchone()
                if recorded is not None:
                    if tuple(recorded) != self._values() or runtime["guardian_epoch"] != self.new_epoch:
                        raise LifecycleError("epoch_rollover_attempt_changed")
                    return runtime["registry_revision"]
            if runtime["guardian_epoch"] != self._runtime_epoch or runtime["registry_revision"] != self._revision:
                raise LifecycleError("epoch_rollover_revision_changed")
            self._obligations(conn, runtime)
            self._fresh_epoch(conn)
            self._audit_schema(conn, create=True)
            conn.execute("INSERT INTO adaptive_epoch_rollovers VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", self._values())
            if conn.execute("""UPDATE adaptive_runtime SET guardian_epoch=?,active_logon_id=?,
                    registry_revision=registry_revision+1 WHERE singleton=1 AND guardian_epoch=?
                    AND registry_revision=? AND policy_instance_id=? AND policy_logon_id=? AND policy_entry_nonce=?""",
                    (self.new_epoch, self.identity.logon_id, self._runtime_epoch, self._revision,
                     self.binding.instance_id, self.binding.logon_id, guard.nonce)).rowcount != 1:
                raise LifecycleError("epoch_rollover_revision_changed")
        return self._revision + 1

    def tick(self, new_epoch):
        """Prove at most sixteen historical scopes and attempt one atomic CAS."""
        with self._lock:
            if not _epoch(new_epoch):
                return EpochRolloverResult(False, True, "epoch_rollover_new_epoch_invalid", self.old_epoch, str(new_epoch))
            if self.new_epoch is None:
                self.new_epoch = new_epoch
            elif new_epoch != self.new_epoch:
                return EpochRolloverResult(False, True, "epoch_rollover_attempt_changed", self.old_epoch, new_epoch)
            if self._quarantined:
                return self._pending(self._quarantined)
            try:
                self._authority()
                if self._result is not None:
                    return self._result
                if self.guard is None:
                    runtime, page, slot = self._read()
                    self._prove_slot(slot)
                    for row in page[:_PAGE]:
                        manifest = self._prove(row)
                        self._digest.update((row["execution_id"] + ":" + str(row["state_revision"])
                            + ":" + manifest.creation_nonce + ":" + manifest.manifest_hash + "\n").encode("ascii"))
                        self._count += 1
                        self._cursor = row["position"]
                    if len(page) > _PAGE:
                        return self._pending("epoch_rollover_inventory_incomplete")
                rescan = False

                def commit():
                    nonlocal rescan
                    if self._audit_reconciled():
                        return True
                    with self.store._connection() as conn:
                        conn.execute("PRAGMA busy_timeout=250")
                        runtime = self._runtime(conn, self.guard)
                    if (runtime["registry_revision"] != self._revision or
                            runtime["guardian_epoch"] != self._runtime_epoch):
                        # A known no-write refusal releases this attempt's
                        # nonce normally before the next bounded inventory.
                        rescan = True
                        return False
                    self._commit(self.guard)
                    return True

                result = self._policy_operation._run(self.identity.logon_id, commit, self._audit_reconciled)
                if not result.complete:
                    if result.quarantined:
                        self._quarantined = result.reason
                    return self._pending(result.reason)
                if rescan:
                    self._policy_operation.reset_completed()
                    self._reset_scan()
                    return self._pending("epoch_rollover_revision_changed")
                self._result = EpochRolloverResult(True, False, "epoch_rollover_complete", self.old_epoch,
                                                   self.new_epoch, self._revision + 1)
                return self._result
            except Exception as error:
                # Keep journal cleanup owners reachable even on a failed
                # read during a historical page, before POLICY is acquired.
                self._error = error
                reason = getattr(error, "reason", str(error))
                if hasattr(error, "_journal_cleanup_owner"):
                    self._quarantined = "epoch_rollover_journal_cleanup_unknown"
                if not isinstance(reason, str) or re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason) is None:
                    reason = "epoch_rollover_ledger_unavailable"
                return self._pending(self._quarantined or reason)

    def _pending(self, reason):
        return EpochRolloverResult(False, True, reason, self.old_epoch, self.new_epoch, self._revision)
