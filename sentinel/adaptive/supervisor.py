"""Resident guardian observation and bounded restore-only dispatch.

Attach while the original guardian is alive, retaining its actual process
object and the existing POLICY binding through RecoveryOwner. No PID/name
polling, workload restart, termination, epoch replacement or admission release
occurs here. A failed/partial inventory is never an all-caps proof. This is the
resident consumer; installing a Scheduled Task or supplying the independent
service host is a separate operational step.
"""
from __future__ import annotations

from dataclasses import dataclass
import sqlite3
import threading
from uuid import UUID

from .contracts import CpuControl, CpuControlMode, IdentityObservation, IdentityStatus, RecoveryManifest
from .orphan_lifecycle import OrphanDrainOwner
from .policy import PolicyBinding
from .recovery_journal import RecoveryJournalError
from .recovery_owner import RecoveryOwner
from .store import LifecycleError


_LIMIT = 10
# Terminal retirement proofs per tick. Each is one ledger read transaction and
# one manifest read, so a long history is paged instead of scanned at once.
_RETIRE_BATCH = 16
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
# Primary SQLite result codes that say the ledger could not be read right now.
# SQLITE_ERROR (missing table/column) is a readable contradiction instead.
_SQLITE_UNAVAILABLE = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_NOMEM,
    sqlite3.SQLITE_INTERRUPT, sqlite3.SQLITE_IOERR, sqlite3.SQLITE_FULL, sqlite3.SQLITE_CANTOPEN,
    sqlite3.SQLITE_PROTOCOL})
_JOURNAL_UNAVAILABLE = frozenset({"manifest_read_unavailable", "manifest_directory_unavailable"})
# The store's read transaction reports a real BUSY, LOCKED or INTERRUPT under
# its own sanitized reasons, so the raw SQLite code never reaches this module.
_LEDGER_UNAVAILABLE = frozenset({"coverage_registry_unavailable", "coverage_database_busy",
    "coverage_read_timeout", "supervisor_inventory_bound_exceeded",
    "supervisor_inventory_scan_incomplete"})


def _unavailable(error):
    if isinstance(error, sqlite3.OperationalError):
        code = getattr(error, "sqlite_errorcode", None)
        return type(code) is int and code & 0xFF in _SQLITE_UNAVAILABLE
    if type(error) is RecoveryJournalError:
        return error.reason in _JOURNAL_UNAVAILABLE
    if isinstance(error, LifecycleError):
        return str(error) in _LEDGER_UNAVAILABLE
    return isinstance(error, OSError)


@dataclass(frozen=True)
class SupervisionResult:
    guardian_status: IdentityStatus
    inventory_verified: bool
    known_executions: tuple[str, ...]
    restored_executions: tuple[str, ...]
    unresolved_executions: tuple[str, ...]
    inventory_error: str | None
    # Drain outcomes for a dead guardian's Jobs. Slot release and finalization
    # are separate facts and neither implies the other. A drain that finishes a
    # Job may also clear that Job's own RECOVERY_HOLD under clarification C3;
    # the per execution outcome of that attempt stays on DrainResult.
    slot_released_executions: tuple[str, ...] = ()
    finalized_executions: tuple[str, ...] = ()
    drain_unresolved_executions: tuple[str, ...] = ()


class GuardianSupervisor:
    """Keep one original guardian witness and at most ten unretired Job scopes.

    The bound is concurrent: a scope leaves it only through the formal
    finalization evidence checked by ``_prove_retired``. A terminal row whose
    proof is missing or contradictory stays an obligation and keeps its slot.

    Restore results describe native disable plus journal settlement only. The
    separate drain pass may then release this execution's control slot and
    finish a natively empty Job through the formal store operations, and clear
    the barrier that finished Job placed. No result asserts that normal mode can
    restart: legacy exclusion is untouched, a barrier another scope holds stays
    held, and a Job that still holds a process keeps its allocation. All error
    owners are retained.
    """

    def __init__(self, store, recovery, *, journal=None):
        if getattr(store, "existing_path", False) is not True:
            raise LifecycleError("supervisor_existing_registry_required")
        self.store, self.recovery = store, recovery
        self.journal = recovery.journal if journal is None else journal
        self._lock = threading.RLock()
        self._known = {}
        # Unretired terminal obligations inside _known, and the rowid below
        # which every FINISHED scope is either proven retired or held there.
        self._terminal = set()
        self._cursor = 0
        self._inventory_error = None
        self._integrity_error = None
        self._errors = {}
        self._drain = None
        self._drain_errors = {}
        self._closed = False

    @classmethod
    def attach(cls, store, journal, *, guardian, guardian_epoch, **fixtures):
        """Capture native custody before any observation loop starts.

        Extra arguments are trusted in-process native fixture seams accepted
        by RecoveryOwner, never CLI/config/wire authority.
        """
        recovery = RecoveryOwner.capture(store, journal, guardian=guardian,
                                        guardian_epoch=guardian_epoch, **fixtures)
        owner = cls(store, recovery)
        try:
            owner._refresh_inventory()
        except BaseException as error:
            # Capture may already own native resources. The caller must retain
            # this same supervisor and retry; no second attach/implicit cleanup.
            error.supervisor_owner = owner
            raise
        return owner

    @property
    def retained_execution_ids(self):
        with self._lock:
            return tuple(self._known)

    @property
    def errors(self):
        with self._lock:
            return tuple(self._errors.items())

    @property
    def drain_errors(self):
        with self._lock:
            return tuple(self._drain_errors.items())

    def _drain_owner(self):
        """Build the restore-only drain owner once, for a real recovery owner.

        Any other recovery object has no exact death witness, no retained Job
        handle and no settled manifest, so no drain is attempted through it.
        """
        if self._drain is None and isinstance(self.recovery, RecoveryOwner):
            self._drain = OrphanDrainOwner(self.store, self.recovery)
        return self._drain

    def _require_open(self):
        if self._closed:
            raise LifecycleError("supervisor_closed")

    @staticmethod
    def _scope(row):
        execution, nonce = row["execution_id"], row["job_nonce"]
        try:
            parsed = UUID(execution)
        except (ValueError, TypeError, AttributeError):
            raise LifecycleError("supervisor_inventory_invalid") from None
        if (str(parsed) != execution or parsed.int == 0 or type(nonce) is not str or
                len(nonce) != 32 or any(char not in "0123456789abcdef" for char in nonce) or
                row["job_name"] != f"Local\\ResourceSentinel.Job.{execution}.{nonce}"):
            raise LifecycleError("supervisor_inventory_invalid")
        return execution, nonce

    def _read_inventory(self):
        with self.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime = self.store._policy._runtime(conn)
            binding = self.store._policy._binding(runtime, self.recovery.guardian_identity.logon_id)
            if (type(binding) is not PolicyBinding or binding != self.recovery.binding or
                    runtime["guardian_epoch"] != self.recovery.guardian_epoch or
                    runtime["active_logon_id"] != self.recovery.guardian_identity.logon_id):
                raise LifecycleError("supervisor_inventory_binding_changed")
            columns = """
                CASE WHEN typeof(execution_id)='text' AND length(execution_id)=36 THEN execution_id END AS execution_id,
                CASE WHEN typeof(job_name)='text' AND length(job_name)<=128 THEN job_name END AS job_name,
                CASE WHEN typeof(job_nonce)='text' AND length(job_nonce)=32 THEN job_nonce END AS job_nonce,
                CASE WHEN typeof(guardian_epoch)='text' AND length(guardian_epoch)<=128 THEN guardian_epoch END AS guardian_epoch,
                CASE WHEN typeof(logon_id)='text' AND length(logon_id)<=184 THEN logon_id END AS logon_id
                FROM managed_executions WHERE job_name IS NOT NULL AND """
            # Every named scope that is not FINISHED is live, including other
            # terminal states: only finalization carries native proof.
            rows = conn.execute("SELECT" + columns + """(typeof(state)!='text' OR state!='FINISHED')
                ORDER BY execution_id LIMIT ?""", (_LIMIT + 1,)).fetchall()
            if len(rows) > _LIMIT:
                raise LifecycleError("supervisor_inventory_bound_exceeded")
            live = {}
            for row in rows:
                if (row["guardian_epoch"] != self.recovery.guardian_epoch or
                        row["logon_id"] != self.recovery.guardian_identity.logon_id):
                    raise LifecycleError("supervisor_inventory_binding_changed")
                execution, nonce = self._scope(row)
                live[execution] = nonce
            # FINISHED is permanent, so history is paged once in rowid order.
            # The SQL state only nominates a scope for _prove_retired.
            page = [(row["position"], *self._scope(row)) for row in conn.execute(
                "SELECT rowid AS position," + columns + """typeof(state)='text' AND state='FINISHED'
                AND rowid>? ORDER BY rowid LIMIT ?""", (self._cursor, _RETIRE_BATCH + 1)).fetchall()]
            slot = conn.execute("""SELECT CASE WHEN typeof(execution_id)='text'
                AND length(execution_id)=36 THEN execution_id END AS execution_id,
                CASE WHEN typeof(slot_state)='text' THEN slot_state END AS slot_state
                FROM adaptive_control_slot LIMIT 2""").fetchall()
            if len(slot) > 1:
                raise LifecycleError("supervisor_inventory_slot_unknown")
            if slot and slot[0]["execution_id"] not in live:
                # The ledger keeps a RESTORED slot row as a durable boundary
                # after its scope finishes, so that row owes no cap and may name
                # a FINISHED execution. A HELD, malformed or unknown slot
                # outside the live set is still a cap nobody here can restore.
                if slot[0]["slot_state"] != "RESTORED" or conn.execute(
                        """SELECT 1 FROM managed_executions WHERE execution_id=?
                        AND typeof(state)='text' AND state='FINISHED'""",
                        (slot[0]["execution_id"],)).fetchone() is None:
                    raise LifecycleError("supervisor_inventory_slot_unknown")
            return live, page

    def _prove_retired(self, execution, nonce):
        """True only for formal finalization evidence; False keeps the obligation.

        FINISHED is committed solely by finalize_if_empty, under the guardian's
        POLICY and Job fences, with a native empty, sealed, CPU-disabled and
        settled-manifest proof held through that commit. The ledger half here
        is the existing retained-terminal reconciliation, and the journal half
        is the settled manifest that commit required. SQL state alone, an
        absent allocation or a missing native Job name is never accepted.
        """
        try:
            row = self.store.query(execution)
        except LifecycleError as error:
            if _unavailable(error):
                raise
            raise LifecycleError("supervisor_inventory_scope_changed") from None
        if (row.get("state") != "FINISHED" or row.get("job_nonce") != nonce or
                row.get("job_name") != f"Local\\ResourceSentinel.Job.{execution}.{nonce}"):
            raise LifecycleError("supervisor_inventory_scope_changed")
        try:
            manifest = self.journal.read(execution, creation_nonce=nonce)
            if (type(manifest) is not RecoveryManifest or manifest.original != _DISABLED or
                    manifest.pending_intent is not None or manifest.last_applied not in (None, _DISABLED)):
                return False
            self.store.assert_retained_terminal(row, manifest)
        except (LifecycleError, RecoveryJournalError) as error:
            # An unreadable source is retried. A cleanup owner must stay
            # reachable. Any other refusal simply leaves the scope unretired.
            if _unavailable(error) or hasattr(error, "_journal_cleanup_owner"):
                raise
            return False
        return True

    def _refresh_inventory(self):
        self._require_open()
        if self._integrity_error is not None:
            raise LifecycleError("supervisor_inventory_integrity_unresolved")
        try:
            live, page = self._read_inventory()
            # Never erase earlier recovery obligations because SQL vanished or
            # was replaced, even if that replacement is internally consistent.
            if any(key in live if key in self._terminal else live.get(key, nonce) != nonce
                   for key, nonce in self._known.items()):
                raise LifecycleError("supervisor_inventory_scope_changed")
            if len({*self._known, *live}) > _LIMIT:
                raise LifecycleError("supervisor_inventory_bound_exceeded")
            self._known.update(live)
            held = getattr(self.recovery, "retained_execution_ids", ())
            for key, nonce in tuple(self._known.items()):
                if key in live:
                    continue
                # A scope outside the live set. Only formal finalization
                # evidence retires it; restore custody in flight keeps it. A
                # held obligation is asked again on every pass, at most ten
                # proofs, so evidence that completes later still frees its slot.
                if self._prove_retired(key, nonce) and key not in self._errors and key not in held:
                    del self._known[key]
                    self._terminal.discard(key)
                else:
                    self._terminal.add(key)
            for position, key, nonce in page[:_RETIRE_BATCH]:
                if key not in self._known and not self._prove_retired(key, nonce):
                    if len(self._known) >= _LIMIT:
                        raise LifecycleError("supervisor_inventory_bound_exceeded")
                    self._known[key] = nonce
                    self._terminal.add(key)
                self._cursor = position
            if len(page) > _RETIRE_BATCH:
                # Known scopes stay restorable, but an unread remainder of the
                # history may still hold an unretired obligation.
                raise LifecycleError("supervisor_inventory_scan_incomplete")
            self._inventory_error = None
        except BaseException as error:
            self._inventory_error = error
            if not _unavailable(error) or hasattr(error, "_journal_cleanup_owner"):
                self._integrity_error = error
            raise

    def tick(self, *, now=None):
        """One bounded pass; invoke repeatedly from the independent host.

        ``now`` only stamps the ledger rows a drain closes: finished_at on the
        execution and its descendants, and ended_at on the archive row. It is
        never evidence of liveness, emptiness or death.

        Unavailable DB may still allow withdrawal for previously observed
        scopes, while inventory_verified stays false. A readable contradiction
        is sticky and supplies no fallback authority. No retries or sleeps hide
        inside a tick; no second process is started on an observation timeout.
        """
        with self._lock:
            self._require_open()
            verified = True
            try:
                self._refresh_inventory()
            except Exception:
                verified = False
            observation = self.recovery.observe_guardian()
            if (type(observation) is not IdentityObservation or
                    observation.identity != self.recovery.guardian_identity):
                raise LifecycleError("supervisor_guardian_observation_invalid")
            restored, unresolved = [], []
            released, finalized, undrained = [], [], []
            if observation.status is IdentityStatus.DEAD and self._integrity_error is None:
                for execution, nonce in self._known.items():
                    try:
                        result = self.recovery.restore(execution, creation_nonce=nonce)
                        if (result.execution_id != execution or result.native_disabled is not True or
                                result.journal_settled is not True):
                            raise LifecycleError("supervisor_restore_unverified")
                        restored.append(execution)
                        self._errors.pop(execution, None)
                    except Exception as error:
                        self._errors[execution] = error
                        unresolved.append(execution)
                self._drain_scopes(restored, released, finalized, undrained, now)
            elif observation.status is not IdentityStatus.ALIVE or not verified:
                unresolved.extend(self._known)
            return SupervisionResult(observation.status, verified, tuple(self._known),
                tuple(restored), tuple(unresolved), None if verified else
                "supervisor_inventory_unverified", tuple(released), tuple(finalized),
                tuple(undrained))

    def _drain_scopes(self, restored, released, finalized, undrained, now):
        """Finish the ledger side of each scope whose restore just settled.

        A non-empty Job is not a failure here: the drain simply reports that it
        released nothing. Native custody is given up only after the formal
        FINISHED commit archived the allocation, and never on a refusal.
        """
        drain = self._drain_owner()
        if drain is None:
            return
        for execution in restored:
            try:
                result = drain.drain(execution, creation_nonce=self._known[execution], now=now)
                if result.slot_released:
                    released.append(execution)
                if result.finalized:
                    self.recovery.close_verified(execution)
                    finalized.append(execution)
                self._drain_errors.pop(execution, None)
            except Exception as error:
                self._drain_errors[execution] = error
                undrained.append(execution)

    def close(self):
        """Stop only a supervisor with no enrolled recovery obligations.

        No automatic close after a successful tick: living children and held
        accounting still require the service's lifecycle takeover. The caller
        cannot make a live obligation disappear by shutting down this consumer.
        """
        with self._lock:
            if self._closed:
                return
            if (self._known or self._errors or self._drain_errors or
                    self._inventory_error is not None):
                raise LifecycleError("supervisor_custody_unsettled")
            self.recovery.close()
            self._closed = True
