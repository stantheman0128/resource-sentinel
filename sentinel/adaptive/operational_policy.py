"""Retained, conservative off transaction; never a native recovery authority."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from .policy import PolicyBusy
from .store import LifecycleError
from .windows import NativePolicyMutexError


def active_off_hold(conn):
    """Optional additive table: old readers do not create it."""
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='adaptive_off_holds'").fetchone() is None:
        return None
    rows = conn.execute("SELECT * FROM adaptive_off_holds WHERE cleared_revision IS NULL LIMIT 2").fetchall()
    if len(rows) > 1:
        raise LifecycleError("off_hold_generation_invalid")
    return None if not rows else dict(rows[0])


def assert_terminal_retirement_allowed_locked(store, execution_id):
    guard = store._policy.assert_held()
    with store._connection() as conn:
        store._policy.revalidate(conn, guard)
        if active_off_hold(conn) is not None:
            raise LifecycleError("off_inventory_recovery_pending")


@dataclass(frozen=True)
class OffResult:
    committed: bool | None
    settled: bool
    registry_revision: int | None
    reason: str


class FencedOffOperation:
    """One request, one original guard, one conditional runtime mutation.

    The host must retain this object *before* calling step. Callbacks are local
    owner methods, never evidence supplied by the operator. The recovery probe
    runs under POLICY but outside the SQL write transaction. Unknown means hold.
    """

    def __init__(self, store, request, *, logon_id, assert_owner, begin_drain,
                 recovery_settled, clock=None):
        self.store, self.request, self.logon_id = store, request, logon_id
        self.assert_owner, self.begin_drain = assert_owner, begin_drain
        self.recovery_settled = recovery_settled
        self.clock = clock
        self.guard = self.before = self.after = None
        self.hold_record = None
        self.operation_record = None
        self.boundary_tick = None
        self.error = None
        self.quarantined = False
        self.result = OffResult(None, False, None, "off_pending")

    def _binding(self, row):
        request = self.request
        if (row["policy_instance_id"] != request.policy_instance_id or
                row["policy_logon_id"] != self.logon_id or
                row["active_logon_id"] != self.logon_id or
                row["guardian_epoch"] != request.guardian_epoch):
            raise LifecycleError("off_binding_changed")

    @staticmethod
    def _image(row):
        return {key: value for key, value in dict(row).items() if key != "policy_entry_nonce"}

    def _receipt_matches(self, conn):
        if self.operation_record is None:
            return False
        if conn.execute("SELECT 1 FROM sqlite_master WHERE name='adaptive_off_operations' AND type='table'").fetchone() is None:
            return False
        row = conn.execute("SELECT request_id,instance_id,policy_instance_id,guardian_epoch,original_nonce,"
            "expected_revision,result_revision,preimage_hash,postimage_hash FROM adaptive_off_operations "
            "WHERE request_id=?", (self.request.request_id,)).fetchone()
        if row is None or tuple(row) != self.operation_record:
            return False
        if self.hold_record is not None:
            hold = active_off_hold(conn)
            return hold is not None and tuple(hold[key] for key in ("request_id", "policy_instance_id",
                "guardian_epoch", "created_revision", "boundary_tick", "prior_barrier", "prior_slot_id")) == self.hold_record
        return True

    def _record_receipt(self, conn):
        digest = lambda image: hashlib.sha256(json.dumps(image, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if self.operation_record is None:
            self.operation_record = (self.request.request_id, self.request.instance_id,
                self.request.policy_instance_id, self.request.guardian_epoch, self.guard.nonce,
                self.request.expected_registry_revision, self.after["registry_revision"],
                digest(self.before), digest(self.after))
        conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_off_operations (
            request_id TEXT PRIMARY KEY, instance_id TEXT NOT NULL, policy_instance_id TEXT NOT NULL,
            guardian_epoch TEXT NOT NULL, original_nonce TEXT NOT NULL, expected_revision INTEGER NOT NULL,
            result_revision INTEGER NOT NULL, preimage_hash TEXT NOT NULL, postimage_hash TEXT NOT NULL)""")
        conn.execute("INSERT INTO adaptive_off_operations VALUES(?,?,?,?,?,?,?,?,?)", self.operation_record)

    def _mutate(self, settled):
        policy = self.store._policy
        with self.store._transaction() as conn:
            row = policy.revalidate(conn, self.guard)
            self._binding(row)
            image = self._image(row)
            if self.after is not None:
                if image == self.after and self._receipt_matches(conn):
                    return self.after["registry_revision"]
                if image != self.before:
                    raise LifecycleError("off_replay_unverified")
            else:
                if row["registry_revision"] != self.request.expected_registry_revision:
                    raise LifecycleError("off_revision_stale")
                self.before = image
                existing = active_off_hold(conn)
                if existing is not None and existing["request_id"] != self.request.request_id:
                    raise LifecycleError("off_inventory_recovery_pending")
                barrier = row["admission_barrier"]
                slot = conn.execute("SELECT slot_state,slot_id FROM adaptive_control_slot WHERE singleton=1").fetchone()
                if settled is not True or slot is not None and slot[0] == "HELD":
                    barrier = "RECOVERY_HOLD"
                self.after = dict(image, mode="off", admission_barrier=barrier)
                if self.after != image:
                    self.after["registry_revision"] += 1
                if barrier == "RECOVERY_HOLD" and (settled is not True or slot is not None and slot[0] == "HELD"):
                    # The generation is committed in the same transaction as
                    # mode/HOLD. Old per-slot janitors must not consume it.
                    self.hold_record = (self.request.request_id, self.request.policy_instance_id,
                         self.request.guardian_epoch, self.after["registry_revision"], self.boundary_tick,
                         row["admission_barrier"], None if slot is None else slot[1])
            if self.hold_record is not None:
                    conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_off_holds (
                        request_id TEXT PRIMARY KEY, policy_instance_id TEXT NOT NULL,
                        guardian_epoch TEXT NOT NULL, created_revision INTEGER NOT NULL,
                        boundary_tick INTEGER, prior_barrier TEXT NOT NULL, prior_slot_id TEXT,
                        cleared_revision INTEGER)""")
                    conn.execute("INSERT INTO adaptive_off_holds VALUES(?,?,?,?,?,?,?,NULL)",
                        self.hold_record)
            if self.after == self.before:
                self._record_receipt(conn)
                return self.after["registry_revision"]
            changed = conn.execute("""UPDATE adaptive_runtime SET mode='off',
                admission_barrier=?, registry_revision=registry_revision+1
                WHERE singleton=1 AND policy_instance_id=? AND policy_logon_id=?
                AND active_logon_id=? AND guardian_epoch=? AND registry_revision=?
                AND policy_entry_nonce=? AND mode=? AND admission_barrier=?""",
                (self.after["admission_barrier"], self.request.policy_instance_id,
                 self.logon_id, self.logon_id, self.request.guardian_epoch,
                 self.before["registry_revision"], self.guard.nonce,
                 self.before["mode"], self.before["admission_barrier"])).rowcount
            if changed != 1:
                raise LifecycleError("off_conditional_update_failed")
            self._record_receipt(conn)
        return self.after["registry_revision"]

    def step(self):
        if self.result.settled or self.quarantined:
            return self.result
        policy = self.store._policy
        try:
            self.assert_owner(self.request)
            self.begin_drain()
            if self.guard is None:
                with self.store._connection() as conn:
                    runtime = policy._runtime(conn)
                    self._binding(runtime)
                    if runtime["registry_revision"] != self.request.expected_registry_revision:
                        raise LifecycleError("off_revision_stale")
                    existing = active_off_hold(conn)
                    if existing is not None and existing["request_id"] != self.request.request_id:
                        raise LifecycleError("off_inventory_recovery_pending")
            if self.guard is not None:
                with self.store._connection() as conn:
                    runtime = policy._runtime(conn)
                    self._binding(runtime)
                    if runtime["policy_entry_nonce"] is None:
                        # A lost final nonce-clear ACK is recoverable only with
                        # this operation's original postimage and known release.
                        if (self.after is not None and self._image(runtime) == self.after and
                                self._receipt_matches(conn)):
                            self.result = OffResult(True, True, runtime["registry_revision"], "off_committed")
                            return self.result
                        if self.before is not None:
                            raise LifecycleError("off_replay_unverified")
                        self.guard = None  # positive native timeout cleared it
                    elif runtime["policy_entry_nonce"] != self.guard.nonce:
                        raise LifecycleError("off_guard_changed")
            if self.guard is None:
                self.guard = policy.prepare(self.logon_id)
            with policy.hold(self.guard):
                self.assert_owner(self.request)
                settled = self.recovery_settled()
                if self.boundary_tick is None and self.clock is not None:
                    self.boundary_tick = self.clock()
                revision = self._mutate(settled)
            self.result = OffResult(True, True, revision, "off_committed")
        except BaseException as error:
            self.error = error  # keep original cleanup/native owners reachable
            notes = tuple(getattr(error, "__notes__", ()))
            uncertain = any(note.startswith(("policy_scope_cleanup", "policy_mutex_release",
                "policy_mutex_wait_outcome_unknown", "lifecycle_connection_cleanup",
                "lifecycle_transaction_rollback")) for note in notes)
            uncertain |= (str(error) == "lifecycle_connection_cleanup_failed" or
                          not isinstance(error, Exception))
            if isinstance(error, NativePolicyMutexError) and error.reason not in {
                    "policy_mutex_timeout", "policy_mutex_wait_failed"}:
                uncertain = True
            reason = str(error) if isinstance(error, LifecycleError) else "off_pending"
            if reason in {"off_binding_changed", "off_guard_changed", "off_replay_unverified", "off_revision_stale"}:
                self.quarantined = True
            if uncertain:
                self.quarantined = True
                reason = "off_scope_cleanup_unverified"
            self.result = OffResult(None, False, None, reason)
            if not isinstance(error, Exception):
                raise
        return self.result
