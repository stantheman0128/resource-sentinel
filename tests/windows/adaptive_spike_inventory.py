"""Bounded recovery inventory on the original S1 runtime's shared ledger.

History is neither native custody nor an enrollment. Foreign FINISHED rows are
accepted only with the production manifest and the original guardian's positive
terminal-custody receipt. Original S1 rows still need that runtime's native or
same-object settled-owner proof. This scanner never manufactures such proof.

The old TestRecoveryRecord namespace is deliberately unsupported here. A real
consumer must first integrate canonical RecoveryManifest/RecoveryJournal and
preserve its original handles through canonical terminal retirement. No file,
callback boolean, alternate database or row count turns that prerequisite on.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

from sentinel.adaptive.contracts import CpuControl, CpuControlMode, RecoveryManifest
from sentinel.adaptive.control_slot import query_locked
from sentinel.adaptive.operational_policy import active_off_hold
from sentinel.adaptive.recovery_journal import RecoveryJournal
from sentinel.adaptive.store import LifecycleError, LifecycleStore, TERMINAL_STATES
from sentinel.adaptive.terminal_receipt import assert_terminal_custody_receipt


PAGE_SIZE = 32
MAX_ACTIVE_JOBS = 10
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_RUNTIME_FIELDS = ("registry_revision", "mode", "guardian_epoch", "active_logon_id",
                   "admission_barrier", "policy_instance_id", "policy_logon_id")


def _fail(reason):
    raise LifecycleError("spike_inventory_" + reason)


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_encoded(value)).hexdigest()


@dataclass(frozen=True)
class InventoryProgress:
    complete: bool
    scanned_rows: int
    retired_foreign_rows: int
    active_jobs: int
    next_execution_id: str | None


@dataclass(frozen=True)
class InventorySnapshot:
    """An observation tied to this scanner; it grants no native authority."""
    registry_revision: int
    runtime_signature: str
    inventory_sha256: str
    scanned_rows: int
    retired_foreign_rows: int
    active_jobs: int
    owned_rows: tuple


class SpikeRecoveryInventory:
    def __init__(self, runtime, canonical_journal):
        from tests.windows.adaptive_execution import S1Runtime, S1ExecutionOwner

        if type(runtime) is not S1Runtime or type(canonical_journal) is not RecoveryJournal:
            _fail("original_runtime_and_canonical_journal_required")
        if runtime.pending_admissions:
            _fail("admission_unsettled")
        self.runtime, self.journal = runtime, canonical_journal
        self._owners = tuple(runtime.owners)
        if any(not isinstance(owner, S1ExecutionOwner) for owner in self._owners):
            _fail("original_owner_required")
        self._by_id = {owner.execution_id: owner for owner in self._owners}
        if len(self._by_id) != len(self._owners):
            _fail("owner_identity_ambiguous")
        self._ledger = Path(runtime.coordinator.db_path).resolve(strict=True)
        for owner in self._owners:
            if (owner._runtime is not runtime or type(owner.store) is not LifecycleStore or
                    Path(owner.store.db_path).resolve(strict=True) != self._ledger):
                _fail("ledger_or_owner_changed")
            previous = getattr(owner, "_spike_inventory_failure", None)
            if previous is not None:
                # In particular, don't overwrite an error holding an unknown
                # journal stream/descriptor owner with a new scan attempt.
                _fail("original_scan_failure_unsettled")
        self._signature = None
        self._revision = None
        self._cursor = None
        self._digest = hashlib.sha256()
        self._rows = {}
        self._scanned = self._foreign = self._active = 0
        self._snapshot = None
        self._failure = None

    @property
    def snapshot(self):
        if self._snapshot is None or self._failure is not None:
            _fail("incomplete")
        return self._snapshot

    def _ownership(self, owner=None):
        if (self.runtime.pending_admissions or
                len(self.runtime.owners) != len(self._owners) or
                any(a is not b for a, b in zip(self.runtime.owners, self._owners))):
            _fail("owner_inventory_changed")
        if owner is not None and self._by_id.get(owner.execution_id) is not owner:
            _fail("original_owner_required")
        if owner is not None and any(original is not owner and not original._closed
                                     for original in self._owners):
            # The S1 runtime is serial. We may borrow this owner's Job fence,
            # never query another live Job under the wrong per-Job mutex.
            _fail("other_owner_unsettled")
        if Path(self.runtime.coordinator.db_path).resolve(strict=True) != self._ledger:
            _fail("ledger_or_owner_changed")
        for original in self._owners:
            if (original._runtime is not self.runtime or
                    Path(original.store.db_path).resolve(strict=True) != self._ledger):
                _fail("ledger_or_owner_changed")

    @staticmethod
    def _pin(store, conn, guard):
        store._policy.assert_held(guard)
        runtime = store._policy.revalidate(conn, guard)
        slot = query_locked(conn, runtime, guard)
        image = {"runtime": {key: runtime[key] for key in _RUNTIME_FIELDS},
                 "slot": slot, "off_hold": active_off_hold(conn)}
        return runtime, slot, image["off_hold"], _digest(image)

    def _check_pin(self, store, conn, guard):
        main = [entry[2] for entry in conn.execute("PRAGMA database_list") if entry[1] == "main"]
        if len(main) != 1 or not main[0] or Path(main[0]).resolve(strict=True) != self._ledger:
            _fail("ledger_or_owner_changed")
        runtime, slot, off_hold, signature = self._pin(store, conn, guard)
        if self._signature is not None and signature != self._signature:
            _fail("registry_or_hold_changed")
        return runtime, slot, off_hold, signature

    def _row_evidence(self, store, row):
        original = self._by_id.get(row["execution_id"])
        if original is None:
            # A terminal label, missing allocation or generic terminal-state
            # set is insufficient. This API only proves FINISHED retirement.
            if row["state"] != "FINISHED":
                _fail("foreign_execution_unverified")
            receipt = assert_terminal_custody_receipt(store, self.journal, row)
            return None, {"row": row, "terminal_receipt": receipt}, 1
        if not original._closed:
            original._assert_row(row)
        if type(original.journal) is not RecoveryJournal:
            _fail("canonical_owner_journal_required")
        if row["job_name"] is None:
            # An unregistered original owner can be reconciled separately by
            # the existing never-created/prelaunch custody path. It cannot be
            # accepted as named Job evidence or used for the C3 clear below.
            if original._create_attempted or original.job is not None:
                _fail("named_job_missing")
            manifest_hash = None
        else:
            manifest = original.journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
            if type(manifest) is not RecoveryManifest:
                _fail("canonical_owner_manifest_required")
            store._retained_inputs(row, manifest)
            manifest_hash = manifest.manifest_hash
        self._prove_original(original, row)
        return original, {"row": row, "manifest_hash": manifest_hash}, 0

    def _prove_original(self, original, row):
        """Consume the real retained S1 proof, not a caller's boolean."""
        from tests.windows.adaptive_recovery import S1Recovery

        recovery = self.runtime._recovery
        if (not isinstance(recovery, S1Recovery) or recovery.runtime is not self.runtime or
                self._by_id.get(original.execution_id) is not original):
            _fail("original_recovery_owner_required")
        # Calling the canonical implementation avoids an injected proof callback.
        # Closed predecessors need its same-object _SettledOwner witness. The
        # current owner is queried only under its original POLICY/Job fences.
        return S1Recovery._prove_owner(recovery, original, row)

    def _scan_locked(self, owner, conn):
        self._ownership(owner)
        store = owner.store
        guard = store._policy.assert_held()
        runtime, _, _, signature = self._check_pin(store, conn, guard)
        if self._cursor is None:
            # No lower-bound sentinel: even a corrupt empty/null key must be
            # observed and rejected, not silently fall before the first page.
            page = conn.execute("SELECT * FROM managed_executions ORDER BY execution_id LIMIT ?",
                                (PAGE_SIZE + 1,)).fetchall()
        else:
            page = conn.execute("""SELECT * FROM managed_executions
                WHERE execution_id > ? ORDER BY execution_id LIMIT ?""",
                (self._cursor, PAGE_SIZE + 1)).fetchall()
        following = self._digest.copy()
        owned, retired, active = {}, 0, 0
        for raw in page[:PAGE_SIZE]:
            row = store._public(raw)
            if type(row["execution_id"]) is not str or not row["execution_id"]:
                _fail("execution_identity_invalid")
            original, evidence, foreign = self._row_evidence(store, row)
            following.update(_encoded(evidence) + b"\n")
            retired += foreign
            if original is not None:
                owned[row["execution_id"]] = row
            active += int(row["job_name"] is not None and row["state"] not in TERMINAL_STATES)
        if self._check_pin(store, conn, guard)[3] != signature:
            _fail("registry_or_hold_changed")
        if self._active + active > MAX_ACTIVE_JOBS:
            _fail("active_job_limit")
        complete = len(page) <= PAGE_SIZE
        if complete and set(self._rows) | set(owned) != set(self._by_id):
            _fail("original_owner_row_missing")
        # Publish progress only after the whole bounded page and pin checks.
        self._signature, self._revision = signature, runtime["registry_revision"]
        self._digest = following
        self._rows.update(owned)
        self._scanned += min(PAGE_SIZE, len(page))
        self._foreign += retired
        self._active += active
        if page:
            self._cursor = page[min(PAGE_SIZE, len(page)) - 1]["execution_id"]
        if complete:
            self._snapshot = InventorySnapshot(self._revision, self._signature,
                self._digest.hexdigest(), self._scanned, self._foreign, self._active,
                tuple(MappingProxyType(dict(row)) for _, row in sorted(self._rows.items())))
        return InventoryProgress(complete, self._scanned, self._foreign, self._active,
                                 None if complete else self._cursor)

    def scan_next(self, owner):
        """Read at most 32 rows using this exact original owner's fences.

        No new admission or native mutation is performed. A refused observation
        exits the known read-only scope cleanly before raising, so it does not
        keep a POLICY nonce that would prevent an operational off owner from
        completing its own recovery. Native scope-exit uncertainty still uses
        the original owner's existing custody path.
        """
        self._ownership(owner)
        if self._failure is not None:
            raise self._failure
        if self._snapshot is not None:
            _fail("already_complete")
        failure = result = None
        try:
            with owner.mutation_scope():
                try:
                    with owner.store._connection() as conn:
                        conn.execute("BEGIN")
                        result = self._scan_locked(owner, conn)
                except BaseException as error:
                    failure = error
            if failure is not None:
                raise failure
            return result
        except BaseException as error:
            self._failure = error
            # Retain the scanner, including exception-attached journal file
            # custody. A string reason is not a replacement for that owner.
            owner._spike_inventory_failure = (self, error)
            owner._retain()
            raise

    def assert_current_locked(self, owner, conn, snapshot):
        self._ownership(owner)
        if self._failure is not None or snapshot is not self._snapshot or snapshot is None:
            _fail("complete_original_snapshot_required")
        return self._check_pin(owner.store, conn, owner.store._policy.assert_held())[:3]

    @staticmethod
    def _c3_unsafe(error, owner):
        """A database acknowledgement cannot settle unknown native/file cleanup."""
        from sentinel.adaptive.windows import NativePolicyMutexError

        if not isinstance(error, Exception) or getattr(owner, "_release_uncertain_thread", None) is not None:
            return True
        seen, current = set(), error
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if (hasattr(current, "_journal_cleanup_owner") or
                    getattr(current, "_native_close_outcome_unknown", False) or
                    set(getattr(current, "__notes__", ())) & {
                        "policy_scope_cleanup_failed", "policy_scope_cleanup_unverified",
                        "case_mutex_release_unverified", "guardian_restore_fence_cleanup_unverified"} or
                    isinstance(current, NativePolicyMutexError) and
                    current.reason != "policy_mutex_timeout"):
                return True
            current = current.__cause__ or current.__context__
        return False

    def _c3_retain_error(self, owner, error, *, quarantine=False):
        # Initialize lazily: this operation is independent of scanner progress.
        # Retain primary and cleanup failures even when scope exit replaces the
        # exception that originally carried an open stream or native owner.
        errors = getattr(self, "_c3_errors", None)
        if errors is None:
            self._c3_errors = errors = []
        if not any(previous is error for previous in errors):
            errors.append(error)
        if quarantine or self._c3_unsafe(error, owner) or len(errors) >= 8:
            owner._spike_c3_quarantine = (self, tuple(errors))
        owner._spike_inventory_clear = (self, errors)
        owner._retain()

    @staticmethod
    def _c3_result(attempt, *, duplicate):
        slot = attempt["slot"]
        return {key: slot[key] for key in (
            "slot_id", "slot_revision", "slot_state", "execution_id", "job_name", "job_nonce",
            "guardian_epoch", "exemption_revision")} | {
                "admission_barrier": "NONE",
                "registry_revision": attempt["runtime"]["registry_revision"] + 1,
                "duplicate": duplicate, "control_authorized": False}

    def _c3_reconcile(self, owner, attempt):
        """Read the exact attempted C3 audit without constructing any guard.

        This also runs before entering mutation_scope: a positively cleared
        original nonce needs no new POLICY/native ownership just to acknowledge
        its old commit. An extant original nonce is released only by that same
        owner's ordinary mutation_scope, after this proof succeeds there.
        """
        from sentinel.adaptive.control_slot import read_slot

        self._ownership(owner)
        if attempt["owner"] is not owner or attempt["snapshot"] is not self._snapshot:
            _fail("c3_original_attempt_required")
        manifest = owner.journal.read(owner.execution_id, creation_nonce=owner.creation_nonce)
        if manifest != attempt["manifest"]:
            _fail("c3_manifest_changed")
        owner.store.assert_retained_terminal(attempt["row"], manifest)
        with owner.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            main = [entry[2] for entry in conn.execute("PRAGMA database_list") if entry[1] == "main"]
            if len(main) != 1 or not main[0] or Path(main[0]).resolve(strict=True) != self._ledger:
                _fail("ledger_or_owner_changed")
            runtime = owner.store._policy._runtime(conn)
            guard = attempt["guard"]
            binding = owner.store._policy._binding(runtime, guard.binding.logon_id)
            if binding != guard.binding or runtime["policy_entry_nonce"] not in (None, guard.nonce):
                _fail("c3_policy_entry_changed")
            slot = read_slot(conn)
            if (slot != attempt["slot"] or active_off_hold(conn) != attempt["off_hold"] or
                    owner.store._public(owner.store._get(conn, owner.execution_id)) != attempt["row"] or
                    any(runtime[key] != attempt["runtime"][key] for key in _RUNTIME_FIELDS
                        if key not in {"registry_revision", "admission_barrier"})):
                _fail("c3_replay_binding_changed")
            expected = (attempt["runtime"]["registry_revision"] + 1, owner.execution_id,
                slot["slot_id"], slot["slot_revision"], slot["guardian_epoch"], "finished_job",
                float(attempt["row"]["finished_at"]), attempt["cleared_at"])
            present = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_barrier_clears'").fetchone()
            records = [] if present is None else conn.execute("""SELECT registry_revision,execution_id,
                slot_id,slot_revision,guardian_epoch,reason,finished_at,cleared_at
                FROM adaptive_barrier_clears WHERE registry_revision=? OR
                (execution_id=? AND slot_id=? AND slot_revision=?) LIMIT 2""", expected[:4]).fetchall()
            nonce = runtime["policy_entry_nonce"]
            if (runtime["admission_barrier"] == "NONE" and
                    runtime["registry_revision"] == expected[0] and
                    len(records) == 1 and tuple(records[0]) == expected):
                return True, nonce
            if (runtime["admission_barrier"] == "RECOVERY_HOLD" and
                    runtime["registry_revision"] == attempt["runtime"]["registry_revision"] and not records):
                return False, nonce
            _fail("c3_audit_unverified")

    def _c3_prepare_locked(self, owner, snapshot, *, now):
        """Read-only preflight; callers raise refusals after clean scope exit."""
        import math
        import time

        with owner.store._connection() as conn:
            conn.execute("PRAGMA busy_timeout=250")
            conn.execute("BEGIN")
            runtime, slot, off_hold = self.assert_current_locked(owner, conn, snapshot)
            row = owner.store._public(owner.store._get(conn, owner.execution_id))
        if off_hold is not None:
            raise LifecycleError("off_inventory_recovery_pending")
        if (slot is None or slot["execution_id"] != owner.execution_id or
                slot["slot_state"] != "RESTORED" or runtime["admission_barrier"] != "RECOVERY_HOLD"):
            _fail("applicable_finished_slot_required")
        if (owner._closed or owner._cleanup_started or not owner._terminal or
                not owner._sealed or owner._control_pending or row != self._rows[owner.execution_id] or
                row["state"] != "FINISHED" or owner.job is None or type(owner.journal) is not RecoveryJournal):
            _fail("original_terminal_custody_required")
        for original in self._owners:
            self._prove_original(original, self._rows[original.execution_id])
        owner._assert_row(row)
        manifest = owner.journal.read(owner.execution_id, creation_nonce=owner.creation_nonce)
        owner.store._retained_inputs(row, manifest)
        if (owner.job.name != manifest.job_name or owner.job.nonce != manifest.creation_nonce or
                owner.job.logon_sid != owner.caller.logon_id or owner.query_cpu_control() != _DISABLED or
                owner.job.accounting()["active_processes"] != 0 or owner.job.active_pids() or
                owner.process is None or owner._root is None or
                owner.process.full_identity(expected_logon_id=owner.caller.logon_id) != owner._root or
                owner.process.wait(0) is not True):
            _fail("native_terminal_unverified")
        owner.store.assert_finished_barrier_clearable(owner.execution_id, caller=owner.caller,
            expected_revision=row["state_revision"], manifest=manifest)
        cleared_at = time.time() if now is None else now
        if type(cleared_at) not in (int, float) or not math.isfinite(cleared_at) or cleared_at < 0:
            _fail("c3_clear_time_invalid")
        return dict(owner=owner, snapshot=snapshot, guard=owner.store._policy.assert_held(),
            runtime={key: runtime[key] for key in _RUNTIME_FIELDS}, slot=dict(slot), off_hold=off_hold,
            row=dict(row), manifest=manifest, cleared_at=float(cleared_at), complete=False)

    def clear_finished(self, owner, snapshot, *, now=None):
        """C3 with original native proof and an exact retained acknowledgement.

        No no-slot/off HOLD is cleared. Cleanup uncertainty is quarantined, not
        discharged by an audit row. This never closes native owners or publishes
        a terminal custody receipt, and the test-only S1 journal stays refused.
        """
        from sentinel.adaptive.policy import PolicyBusy
        from sentinel.adaptive.windows import NativePolicyMutexError

        self._ownership(owner)
        if snapshot is None or snapshot is not self._snapshot or self._failure is not None:
            _fail("complete_original_snapshot_required")
        if getattr(owner, "_spike_c3_quarantine", None) is not None:
            _fail("c3_cleanup_quarantined")
        prior_owner = getattr(owner, "_spike_c3_attempt_owner", None)
        if prior_owner is not None and prior_owner is not self:
            _fail("c3_original_attempt_required")
        attempt = getattr(self, "_c3_attempt", None)
        entered = False
        scope_attempted = False
        refusal = None
        result = None
        try:
            if attempt is not None:
                # Reconcile before the old scan pin. In particular, do not ask
                # mutation_scope to mint a new nonce after the old clear's ACK
                # was lost while its final nonce cleanup actually committed.
                committed, nonce = self._c3_reconcile(owner, attempt)
                if nonce is None:
                    if not committed:
                        _fail("c3_released_without_clear")
                    attempt["complete"] = True
                    return self._c3_result(attempt, duplicate=True)
            scope_attempted = True
            with owner.mutation_scope():
                entered = True
                if attempt is not None:
                    if owner.store._policy.assert_held() is not attempt["guard"]:
                        _fail("c3_original_guard_required")
                    committed, _ = self._c3_reconcile(owner, attempt)
                    if committed:
                        result = self._c3_result(attempt, duplicate=True)
                if result is None:
                    try:
                        candidate = self._c3_prepare_locked(owner, snapshot,
                            now=now if attempt is None else attempt["cleared_at"])
                        if attempt is not None and any(candidate[key] != attempt[key] for key in
                                ("runtime", "slot", "off_hold", "row", "manifest", "cleared_at")):
                            _fail("c3_replay_binding_changed")
                    except BaseException as error:
                        # Preserve attached custody before scope cleanup could
                        # raise a different exception. Only ordinary read-only
                        # refusals take the clean exit path.
                        self._c3_retain_error(owner, error)
                        if self._c3_unsafe(error, owner):
                            raise
                        refusal = error
                    if refusal is None:
                        if attempt is None:
                            self._c3_attempt = attempt = candidate
                            owner._spike_c3_attempt_owner = self
                        owner.store.clear_recovery_hold_finished_locked(owner.execution_id,
                            caller=owner.caller, expected_revision=attempt["row"]["state_revision"],
                            expected_registry_revision=attempt["runtime"]["registry_revision"],
                            slot_id=attempt["slot"]["slot_id"], manifest=attempt["manifest"],
                            now=attempt["cleared_at"])
                        committed, _ = self._c3_reconcile(owner, attempt)
                        if not committed:
                            _fail("c3_audit_unverified")
                        result = self._c3_result(attempt, duplicate=False)
            if refusal is None:
                attempt["complete"] = True
                return result
        except BaseException as error:
            positive_no_entry = (isinstance(error, PolicyBusy) or
                isinstance(error, NativePolicyMutexError) and error.reason == "policy_mutex_timeout")
            binding_unknown = str(error) in {
                "spike_inventory_c3_policy_entry_changed", "spike_inventory_c3_original_guard_required",
                "spike_inventory_c3_replay_binding_changed", "policy_binding_invalid", "policy_logon_mismatch"}
            self._c3_retain_error(owner, error, quarantine=binding_unknown or
                scope_attempted and not entered and not positive_no_entry)
            raise
        raise refusal
