"""Bounded operator adapters over a guardian's original retained owners.

Read operations use existing read-only SQLite snapshots, never initialize the
registry and never borrow a mutating POLICY scope. Historical proof is paged;
an absent live handle or a terminal label is not a native retirement receipt.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from contextlib import contextmanager
import base64
import hashlib
import hmac
import secrets
import struct
from uuid import UUID

from .contracts import IdentityStatus, ProcessIdentity
from .guardian_restore import DISABLED
from .operational_policy import FencedOffOperation, active_off_hold
from .operator_messages import (OperatorRequest, OperatorReply, OperatorInventoryItem,
    OperatorOperation as Op, OperatorOutcome as Outcome, MAX_OPERATOR_REQUESTS)
from .store import LifecycleError, TERMINAL_STATES, _ipc_read_transaction


@dataclass
class _Audit:
    revision: int
    caller: ProcessIdentity
    after: str = ""
    native: bool = True
    bookkeeping: bool = True
    cleanup: bool = True
    live: int = 0


class GuardianHostOperations:
    """One guardian scope, even when its supervisor has instance-wide discovery.

    Supervisor aggregation must not relabel this adapter's scope as instance.
    ``terminal_proof`` is a local readonly verifier supplied by the terminal
    custody module, not a caller-provided flag or serialized native authority.
    """

    def __init__(self, owner, control, *, instance_id, policy_instance_id,
                 begin_drain=None, assert_owner=None, terminal_proof=None):
        self.owner, self.control, self.store = owner, control, owner.store
        self.instance_id, self.policy_instance_id = instance_id, policy_instance_id
        self.epoch, self.logon_id = owner.guardian_epoch, owner.guardian.identity.logon_id
        self._drain_callback, self._owner_callback = begin_drain, assert_owner
        self._terminal_proof = terminal_proof
        self.draining = False
        self.operations = {}
        self._cursor_key = secrets.token_bytes(32)
        self._operation_audits = {}
        self._operation_results = {}
        self._restore_boundaries = {}
        self._tick_index = 0
        self.last_error = None
        self._hold_guard = None
        self._hold_cursor = None
        self._hold_request = None
        self._hold_quarantined = False
        self._hold_cleared_revision = None
        if self._terminal_proof is None:
            from .terminal_receipt import assert_terminal_custody_receipt
            self._terminal_proof = assert_terminal_custody_receipt

    def _assert_owner(self, request):
        if (request.instance_id != self.instance_id or
                request.policy_instance_id != self.policy_instance_id or
                request.guardian_epoch != self.epoch):
            raise LifecycleError("operator_target_changed")
        self.owner.lifecycle._validate_guardian()
        if self._owner_callback is not None:
            self._owner_callback(request)

    def begin_drain(self):
        self.draining = True  # publish intent before a potentially interrupted callback
        self.control.begin_drain()
        if self._drain_callback is not None:
            self._drain_callback()

    def _runtime(self):
        with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
            runtime = dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())
            slot = conn.execute("SELECT slot_state FROM adaptive_control_slot WHERE singleton=1").fetchone()
        if (runtime["policy_instance_id"] != self.policy_instance_id or
                runtime["policy_logon_id"] != self.logon_id or
                runtime["active_logon_id"] != self.logon_id or
                runtime["guardian_epoch"] != self.epoch):
            raise LifecycleError("operator_ledger_binding_changed")
        return runtime, None if slot is None else slot[0]

    def recovery_settled(self):
        # Empty live custody alone cannot certify historical control. This
        # bounded first page is complete only if there is no further history.
        result = self._audit_page(None, self.owner.guardian.identity)
        return (result["inventory_complete"] is True and result["native_disabled"] is True
                and result["bookkeeping_settled"] is True and result["slot_released"] is True
                and result["cleanup_settled"] is True)

    def _item(self, row):
        execution = row["execution_id"]
        lifecycle = self.owner.lifecycle
        try:
            if execution not in lifecycle.retained_execution_ids:
                if row["state"] not in TERMINAL_STATES or self._terminal_proof is None:
                    raise LifecycleError("operator_original_owner_unavailable")
                self._terminal_proof(self.store, self.owner.journal, row)
                return OperatorInventoryItem(execution, "retired", "terminal_custody_verified",
                    bookkeeping_settled=True, cleanup_complete=True)
            cleanup_started = getattr(lifecycle, "terminal_cleanup_started", lambda unused: False)
            if cleanup_started(execution):
                raise LifecycleError("operator_cleanup_pending")
            entry = lifecycle._entry(execution)
            with self._read_scope(entry):
                item = self._native_item(row, entry)
            return item  # only after positive native fence cleanup
        except Exception as error:
            self.last_error = error  # private custody, never raw error text on wire
            return OperatorInventoryItem(execution, "unknown", "operator_scope_unverified")

    @contextmanager
    def _read_scope(self, entry):
        lifecycle = self.owner.lifecycle
        restorer = lifecycle._restorer
        with self.owner._lock:
            lifecycle._queryable(entry)
            lifecycle._validate_guardian()
            restorer.check_fence()
            if (not entry.validated or entry.mutex is None or restorer.binding is None or
                    restorer.policy_mutex is None or entry.mutex_error is not None):
                raise LifecycleError("operator_read_fence_unavailable")
            try:
                guard = self.store._policy.current_guard()
                if guard is not None:
                    self.store._policy.assert_held(guard)
                    if guard.binding != restorer.binding:
                        raise LifecycleError("operator_read_binding_changed")
                    with lifecycle._job_scope(entry):
                        yield
                else:
                    # Borrow original pinned native owners; never prepare a
                    # durable POLICY nonce or create a mutex for a readonly RPC.
                    with restorer._mutex(restorer.policy_mutex, policy=True):
                        with restorer._mutex(entry.mutex):
                            yield
            except BaseException as error:
                restorer.note_fence_failure(error)
                if not isinstance(error, Exception):
                    restorer.poison(error)
                raise

    def _native_item(self, row, entry):
        execution, lifecycle = row["execution_id"], self.owner.lifecycle
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("operator_journal_cleanup_unverified")
        try:
            record = self.owner.journal.read(execution, creation_nonce=row["job_nonce"])
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise
        if (not entry.validated or record.guardian_identity != self.owner.guardian.identity or
                record.guardian_epoch != self.epoch or record.execution_id != execution or
                record.job_name != entry.job.name or record.creation_nonce != entry.job.nonce or
                record.wrapper_identity != entry.wrapper.identity or record.root_identity != entry.root.identity or
                self.owner.guardian.is_in_job(entry.job.handle) is not False):
            raise LifecycleError("operator_native_binding_unverified")
        if row["state"] in TERMINAL_STATES:
            self.store.assert_retained_terminal(row, record)
            count, members = lifecycle._members(entry)
            if count != 0 or members:
                raise LifecycleError("operator_terminal_job_nonempty")
        else:
            self.store.assert_retained_allocation(row, record)
        raw = entry.job.query_cpu()
        if type(raw.flags) is not int or not 0 <= raw.flags < (1 << 32):
            raise LifecycleError("operator_native_unknown")
        native = not raw.flags & 1
        bookkeeping = (record.original == DISABLED and record.pending_intent is None
            and record.last_applied in (None, DISABLED) and entry.restore_candidate is None
            and entry.journal_cleanup_error is None and not entry.restore_pending)
        cleanup = (entry.mutex_error is None and entry.restore_integrity_error is None
            and lifecycle._restorer.fence_error is None and lifecycle._pending_policy is None)
        return OperatorInventoryItem(execution, "native", "native_scope_observed",
            native_disabled=native, bookkeeping_settled=bookkeeping,
            cleanup_complete=cleanup, observed_tick_100ns=self.control.clock(),
            applied_flags=raw.flags, applied_rate_bp=raw.rate_bp)

    def _audit_page(self, request, caller):
        runtime, slot = self._runtime()
        revision = runtime["registry_revision"]
        token = request.cursor if request is not None else None
        if request is not None and request.expected_registry_revision not in (None, revision):
            raise LifecycleError("operator_audit_revision_changed")
        if token is None:
            state = _Audit(revision, caller)
        else:
            state = self._decode_cursor(token, caller)
            if state.revision != revision:
                raise LifecycleError("operator_audit_cursor_changed")
        with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
            # IDs only; query(row) and the native/journal proof happen after this
            # bounded read transaction. No command/secret columns reach replies.
            ids = conn.execute("SELECT execution_id FROM managed_executions WHERE execution_id>? "
                "ORDER BY execution_id LIMIT 33", (state.after,)).fetchall()
        items = []
        with self.owner._lock:
            self.owner.lifecycle._validate_guardian()
            retained = tuple(self.owner.retained_execution_ids)
            if len(retained) > 10 or len(set(retained)) != len(retained):
                raise LifecycleError("operator_inventory_unbounded")
            for item_id in ids[:32]:
                row = self.store.query(item_id[0], existing_path=True)
                item = self._item(row)
                items.append(item)
                state.native &= item.provenance == "retired" or item.native_disabled is True
                state.bookkeeping &= item.bookkeeping_settled is True
                state.cleanup &= item.cleanup_complete is True
                state.live += row["state"] not in TERMINAL_STATES
                state.after = item.execution_id
            # Final pages refresh every current live handle, so earlier pages
            # cannot turn old native observations into a complete present audit.
            if len(ids) <= 32:
                for execution in retained:
                    row = self.store.query(execution, existing_path=True)
                    item = self._item(row)
                    state.native &= item.provenance == "retired" or item.native_disabled is True
                    state.bookkeeping &= item.bookkeeping_settled is True
                    state.cleanup &= item.cleanup_complete is True
        after, slot_after = self._runtime()
        if after != runtime or slot != slot_after:
            raise LifecycleError("operator_audit_revision_changed")
        next_cursor = None
        complete = len(ids) <= 32
        if not complete and request is not None:
            next_cursor = self._encode_cursor(state)
        all_good = state.native and state.bookkeeping and state.cleanup
        return dict(inventory_complete=complete, native_disabled=state.native if complete else None,
            bookkeeping_settled=state.bookkeeping if complete else None,
            cleanup_settled=state.cleanup if complete else None,
            slot_released=slot in (None, "RESTORED"), barrier_cleared=runtime["admission_barrier"] == "NONE",
            remaining_executions=state.live if complete else None, remaining_custody=len(retained),
            registry_revision=revision, items=tuple(items), next_cursor=next_cursor,
            desired_mode="off" if runtime["mode"] == "off" else None, outcome=Outcome.COMPLETE if complete and all_good and
            slot in (None, "RESTORED") else Outcome.PENDING if not complete else Outcome.UNVERIFIED,
            reason="operator_audit_complete" if complete and all_good else "operator_audit_partial")

    def _encode_cursor(self, state):
        flags = int(state.native) | int(state.bookkeeping) << 1 | int(state.cleanup) << 2
        caller = hashlib.sha256(state.caller.to_json().encode()).digest()[:16]
        payload = struct.pack("!Q16sBQ16s", state.revision, UUID(state.after).bytes, flags, state.live, caller)
        tag = hmac.new(self._cursor_key, payload, hashlib.sha256).digest()[:16]
        return "a1." + base64.urlsafe_b64encode(payload + tag).decode().rstrip("=")

    def _decode_cursor(self, token, caller):
        try:
            if type(token) is not str or not token.startswith("a1.") or len(token) > 100:
                raise ValueError()
            encoded = token[3:]
            raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            if len(raw) != 65 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
                raise ValueError()
            payload, tag = raw[:-16], raw[-16:]
            if not hmac.compare_digest(tag, hmac.new(self._cursor_key, payload, hashlib.sha256).digest()[:16]):
                raise ValueError()
            revision, after, flags, live, bound = struct.unpack("!Q16sBQ16s", payload)
            if flags > 7 or not hmac.compare_digest(bound, hashlib.sha256(caller.to_json().encode()).digest()[:16]):
                raise ValueError()
            return _Audit(revision, caller, str(UUID(bytes=after)), bool(flags & 1), bool(flags & 2), bool(flags & 4), live)
        except (ValueError, TypeError, struct.error):
            raise LifecycleError("operator_audit_cursor_changed") from None

    def _recover_hold(self, request):
        """Original owner clears only its exact durable off generation.

        History is processed 32 rows per tick. A changed registry restarts that
        proof; the last page repeats live readback and five post-boundary frames.
        No new API allows a CLI to manufacture these facts.
        """
        if self._hold_quarantined:
            return
        policy = self.store._policy
        try:
            with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
                hold = active_off_hold(conn)
            if hold is None:
                if self._hold_guard is not None:
                    with self.store._connection() as conn:
                        runtime = policy._runtime(conn)
                        receipt = conn.execute("SELECT cleared_revision FROM adaptive_off_holds WHERE request_id=?",
                            (request.request_id,)).fetchone()
                    if (receipt is None or receipt[0] != self._hold_cleared_revision or
                            runtime["registry_revision"] != self._hold_cleared_revision or
                            runtime["admission_barrier"] != "NONE"):
                        raise LifecycleError("off_recovery_replay_unverified")
                    if runtime["policy_entry_nonce"] == self._hold_guard.nonce:
                        with policy.hold(self._hold_guard):
                            self._assert_owner(request)
                    elif runtime["policy_entry_nonce"] is not None:
                        raise LifecycleError("off_recovery_replay_unverified")
                    self._hold_guard = None
                return
            if (hold["request_id"] != request.request_id or hold["policy_instance_id"] != self.policy_instance_id
                    or hold["guardian_epoch"] != self.epoch):
                raise LifecycleError("off_hold_owner_changed")
            if hold["prior_barrier"] == "RECOVERY_HOLD" and hold["prior_slot_id"] is None:
                raise LifecycleError("off_preexisting_hold_authority_unavailable")
            if self._hold_request is None or self._hold_request.request_id != request.request_id:
                self._hold_cursor = None
            self._hold_request = request
            audit_request = replace(request, operation=Op.AUDIT, cursor=self._hold_cursor,
                expected_registry_revision=None if self._hold_cursor is None else
                self._decode_cursor(self._hold_cursor, self.owner.guardian.identity).revision)
            audit = self._audit_page(audit_request, self.owner.guardian.identity)
            self._hold_cursor = audit["next_cursor"]
            if not audit["inventory_complete"]:
                return
            if not all(audit[key] is True for key in ("native_disabled", "bookkeeping_settled",
                    "slot_released", "cleanup_settled")):
                raise LifecycleError("off_inventory_recovery_pending")
            revision = audit["registry_revision"]
            self._validate_live_frames(hold)
            # Custody prevents handle replacement; POLICY prevents any normal
            # competing writer between the final native proof and short CAS.
            with self.owner._lock:
                if self._hold_guard is not None:
                    with self.store._connection() as conn:
                        pending = policy._runtime(conn)
                    if pending["policy_entry_nonce"] is None:
                        self._hold_guard = None
                    elif pending["policy_entry_nonce"] != self._hold_guard.nonce:
                        raise LifecycleError("off_recovery_guard_changed")
                if self._hold_guard is None:
                    self._hold_guard = policy.prepare(self.logon_id)
                with policy.hold(self._hold_guard):
                    self._assert_owner(request)
                    for execution in self.owner.lifecycle.retained_execution_ids:
                        row = self.store.query(execution, existing_path=True)
                        item = self._item(row)
                        if not (item.native_disabled is True and item.bookkeeping_settled is True):
                            raise LifecycleError("off_inventory_recovery_pending")
                    self._validate_live_frames(hold)
                    with self.store._transaction() as conn:
                        runtime = policy.revalidate(conn, self._hold_guard)
                        current = active_off_hold(conn)
                        if (current != hold or runtime["registry_revision"] != revision or
                                runtime["mode"] != "off" or runtime["admission_barrier"] != "RECOVERY_HOLD"):
                            raise LifecycleError("off_recovery_revision_changed")
                        slot = conn.execute("SELECT slot_state FROM adaptive_control_slot WHERE singleton=1").fetchone()
                        if slot is not None and slot[0] != "RESTORED":
                            raise LifecycleError("off_inventory_recovery_pending")
                        if conn.execute("UPDATE adaptive_runtime SET admission_barrier='NONE',"
                                "registry_revision=registry_revision+1 WHERE singleton=1 AND registry_revision=? "
                                "AND policy_entry_nonce=?", (revision, self._hold_guard.nonce)).rowcount != 1:
                            raise LifecycleError("off_recovery_revision_changed")
                        conn.execute("UPDATE adaptive_off_holds SET cleared_revision=? WHERE request_id=? "
                            "AND cleared_revision IS NULL", (revision + 1, request.request_id))
                        self._hold_cleared_revision = revision + 1
                self._hold_guard = None
                self._hold_cursor = None
        except BaseException as error:
            self.last_error = error
            # A stale paged snapshot is restarted, never promoted to complete.
            if str(error) in {"operator_audit_revision_changed", "operator_audit_cursor_changed"}:
                self._hold_cursor = None
            notes = getattr(error, "__notes__", ())
            from .windows import NativePolicyMutexError
            if (any(note.startswith(("policy_scope_cleanup", "policy_mutex_release",
                    "policy_mutex_wait_outcome_unknown", "lifecycle_connection_cleanup")) for note in notes)
                    or str(error) == "lifecycle_connection_cleanup_failed"
                    or not isinstance(error, Exception)
                    or isinstance(error, NativePolicyMutexError) and error.reason not in {
                        "policy_mutex_timeout", "policy_mutex_wait_failed"}):
                self._hold_quarantined = True
            # Only a known business-proof rejection before any clear commit
            # can finish the retained nonce. SQL/cleanup uncertainty retains it.
            elif self._hold_guard is not None and self._hold_cleared_revision is None and not notes:
                from .control_slot import ControlSlotError
                if isinstance(error, (LifecycleError, ControlSlotError)) and str(error) in {
                        "off_inventory_recovery_pending", "off_recovery_revision_changed",
                        "uncapped_samples_insufficient", "uncapped_samples_stale",
                        "uncapped_samples_precede_restore"}:
                    try:
                        with policy.hold(self._hold_guard):
                            self._assert_owner(request)
                        self._hold_guard = None
                    except BaseException as cleanup:
                        self.last_error = cleanup
                        if getattr(cleanup, "__notes__", ()) or not isinstance(cleanup, Exception):
                            self._hold_quarantined = True
                        if not isinstance(cleanup, Exception):
                            raise
            if not isinstance(error, Exception):
                raise

    def _validate_live_frames(self, hold):
        from .control_slot import _uncapped_samples
        for execution in self.owner.lifecycle.retained_execution_ids:
            row = self.store.query(execution, existing_path=True)
            if row["state"] in TERMINAL_STATES:
                continue
            if type(hold["boundary_tick"]) is not int or hold["boundary_tick"] <= 0:
                raise LifecycleError("off_restore_boundary_unavailable")
            boundary = max(hold["boundary_tick"], self._restore_boundaries.get(execution, 0))
            samples = tuple(sample for sample in self.control._samples.get(execution, ())
                            if sample.window_start_tick_100ns >= boundary)
            _uncapped_samples(row, samples,
                boundary=boundary, now_tick_100ns=self.control.clock(),
                required=self.control.profile.admission_release_uncapped_samples,
                max_age_ms=self.control.profile.sample_max_age_ms)

    def _restore_inventory(self):
        """Do not turn an already pristine Job into a new no-slot HOLD."""
        with self.owner._lock:
            ids = tuple(self.owner.lifecycle.retained_execution_ids)
            self._restore_boundaries = {key: value for key, value in self._restore_boundaries.items() if key in ids}
            if len(ids) > 10:
                raise LifecycleError("operator_inventory_unbounded")
            for execution in ids:
                if self.owner.lifecycle.terminal_cleanup_started(execution):
                    # First-close proof already belongs to the terminal owner.
                    # Never query/acquire its partially closed native objects.
                    continue
                try:
                    # The control owner supplies action audit and resets the
                    # capped observation baseline for an actual live episode.
                    self.control.request_restore(execution, reason="operator_restore")
                    row = self.store.query(execution, existing_path=True)
                    item = self._item(row)
                    with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
                        slot = conn.execute("SELECT execution_id,slot_state FROM adaptive_control_slot WHERE singleton=1").fetchone()
                    held = slot is not None and slot[0] == execution and slot[1] == "HELD"
                    if item.native_disabled is True and item.bookkeeping_settled is True and not held:
                        self._restore_boundaries.setdefault(execution, self.control.clock())
                        continue
                except Exception as error:
                    self.last_error = error
                try:
                    # This path keeps the existing emergency restore authority
                    # even when current DB or journal observation is unavailable.
                    result = self.owner.lifecycle.restore_owned_cap(execution)
                    if result.native_disabled and result.bookkeeping_settled:
                        self._restore_boundaries.setdefault(execution, self.control.clock())
                except Exception as error:
                    self.last_error = error
                    self._restore_boundaries.pop(execution, None)

    def _reply(self, request, **values):
        return OperatorReply(request.request_id, request.operation, self.instance_id,
            self.policy_instance_id, self.epoch, scope="guardian",
            host_state="draining" if self.draining else "running", **values)

    def _advance(self, record):
        request, caller, off = record
        if off is not None:
            off.step()
        # Restore authority is the original owner and must work even if the off
        # transaction, current ledger, helper or capability receipt is unavailable.
        try:
            self._restore_inventory()
        except Exception as error:
            self.last_error = error
        if off is not None and off.result.settled:
            self._recover_hold(request)
        try:
            cursor = self._operation_audits.get(request.request_id)
            audit_request = replace(request, operation=Op.AUDIT, cursor=cursor,
                expected_registry_revision=None if cursor is None else self._decode_cursor(cursor, caller).revision)
            values = self._audit_page(audit_request, caller)
            self._operation_audits[request.request_id] = values["next_cursor"]
            values["next_cursor"] = None  # paging is owned by the accepted mutation
        except Exception as error:
            self.last_error = error
            if str(error) in {"operator_audit_revision_changed", "operator_audit_cursor_changed"}:
                self._operation_audits[request.request_id] = None
            values = dict(outcome=Outcome.UNVERIFIED, reason="operator_recovery_unverified")
        values["accepted"] = True
        if off is not None:
            values["desired_mode"] = "off"
            if not off.result.settled:
                values.update(outcome=Outcome.UNVERIFIED, reason=off.result.reason)
            elif values.get("remaining_custody") or values.get("remaining_executions"):
                values.update(outcome=Outcome.PENDING, reason="operator_drain_pending")
            elif values.get("barrier_cleared") is not True:
                values.update(outcome=Outcome.PENDING, reason="operator_recovery_hold")
        self._operation_results[request.request_id] = dict(values)
        return values

    def _observe_operation(self, record, caller):
        request, _, off = record
        saved = self._operation_results.get(request.request_id)
        runtime, slot = self._runtime()
        if (saved is not None and saved.get("inventory_complete") is True and
                saved.get("registry_revision") == runtime["registry_revision"]):
            values = dict(saved)
            with self.owner._lock:
                # Complete immutable history at this revision is retained, but
                # live native proof is always refreshed for the observer.
                for execution in self.owner.retained_execution_ids:
                    row = self.store.query(execution, existing_path=True)
                    item = self._item(row)
                    if not (item.provenance == "retired" or item.native_disabled is True):
                        values["native_disabled"] = False
                    if item.bookkeeping_settled is not True:
                        values["bookkeeping_settled"] = False
                    if item.cleanup_complete is not True:
                        values["cleanup_settled"] = False
            after, current_slot = self._runtime()
            if after != runtime or current_slot != slot:
                raise LifecycleError("operator_audit_revision_changed")
            if not all(values.get(key) is True for key in ("native_disabled", "bookkeeping_settled",
                    "cleanup_settled", "slot_released")):
                values.update(outcome=Outcome.UNVERIFIED, reason="operator_recovery_unverified")
            return values
        values = self._audit_page(None, caller)
        values["accepted"] = True
        if off is not None and (not off.result.settled or values.get("remaining_custody") or
                values.get("remaining_executions") or values.get("barrier_cleared") is not True):
            values.update(outcome=Outcome.PENDING, reason="operator_drain_pending", desired_mode="off")
        return values

    def tick(self):
        # At most one policy attempt and one bounded restore sweep per tick.
        if self.operations:
            chosen = self._tick_index % len(self.operations)
            self._tick_index += 1
            for index, record in enumerate(self.operations.values()):
                if index != chosen:
                    continue
                return self._advance(record)
        return None

    @property
    def settled(self):
        """Readonly shutdown predicate over *all* accepted owner operations.

        A completed restore response can coexist with live work; host shutdown
        cannot. Receipts must describe the current exact registry revision and
        every retained guard/hold/native custody obligation must be settled.
        This observation neither advances a mutation nor constructs authority.
        """
        try:
            with self.owner._lock:
                if (self.owner.retained_execution_ids or self._hold_guard is not None or
                        self._hold_quarantined):
                    return False
                self.owner.lifecycle._validate_guardian()
                if not self.operations:
                    return True  # no operational obligation was ever accepted
                if not self.draining:
                    return False
                runtime, slot = self._runtime()
                if (runtime["policy_entry_nonce"] is not None or
                        runtime["admission_barrier"] != "NONE" or slot not in (None, "RESTORED")):
                    return False
                with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
                    if active_off_hold(conn) is not None:
                        return False
                for request, caller, off in self.operations.values():
                    self._assert_owner(request)
                    saved = self._operation_results.get(request.request_id)
                    if (saved is None or saved.get("outcome") is not Outcome.COMPLETE or
                            saved.get("registry_revision") != runtime["registry_revision"] or
                            any(saved.get(key) is not True for key in ("accepted", "inventory_complete",
                                "native_disabled", "bookkeeping_settled", "slot_released",
                                "barrier_cleared", "cleanup_settled")) or
                            any(type(saved.get(key)) is not int or saved[key] != 0
                                for key in ("remaining_executions", "remaining_custody"))):
                        return False
                    if off is not None and (not off.result.settled or off.result.committed is not True or
                            off.quarantined or runtime["mode"] != "off"):
                        return False
                after, after_slot = self._runtime()
                return after == runtime and after_slot == slot
        except Exception as error:
            self.last_error = error
            return False

    def __call__(self, request, *, caller_identity):
        if type(request) is not OperatorRequest or type(caller_identity) is not ProcessIdentity:
            raise LifecycleError("operator_request_invalid")
        self._assert_owner(request)
        if caller_identity.logon_id != self.logon_id:
            raise LifecycleError("operator_logon_mismatch")
        if request.mutating:
            record = self.operations.get(request.request_id)
            if record is not None and record[:2] != (request, caller_identity):
                raise LifecycleError("operator_request_payload_changed")
            if record is None:
                if len(self.operations) >= MAX_OPERATOR_REQUESTS:
                    raise LifecycleError("operator_request_capacity")
                off = None
                if request.operation is Op.DRAIN:
                    off = FencedOffOperation(self.store, request, logon_id=self.logon_id,
                        assert_owner=self._assert_owner, begin_drain=self.begin_drain,
                        recovery_settled=self.recovery_settled, clock=self.control.clock)
                record = (request, caller_identity, off)
                self.operations[request.request_id] = record
                self.begin_drain()
            return self._reply(request, **self._advance(record))
        if request.observe_request_id is not None:
            record = self.operations.get(request.observe_request_id)
            if record is None:
                return self._reply(request, outcome=Outcome.UNAVAILABLE, reason="operator_request_unknown")
            # Observation does not drive the operation or issue native writes.
            return self._reply(request, **self._observe_operation(record, caller_identity))
        return self._reply(request, **self._audit_page(request if request.operation is Op.AUDIT else None,
                                                     caller_identity))
