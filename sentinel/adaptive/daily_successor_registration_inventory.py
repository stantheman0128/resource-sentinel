"""Current historical proof owned by one original successor guardian child.

This is a data-only reader. The child retains its own live self handle and POLICY;
neither an epoch audit nor this opaque observation reconstructs retired custody.
Journal I/O occurs only during capture. Final SQL checks use those exact bytes,
and ACK reconciliation permits only the original registration's fixed postimage.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
import re
import sqlite3
import threading
import weakref

from . import control_slot
from . import daily_generation as generation
from . import daily_retirement_fence as fence
from . import daily_retirement_inventory as prior
from . import daily_successor_epoch as epochs
from . import daily_successor_history as succession
from . import daily_successor_inventory as transfer
from . import experiment_history
from .contracts import ProcessIdentity, RecoveryManifest
from .identity import VerifiedProcess
from .policy import PolicyGuard
from .recovery_journal import RecoveryJournal
from .store import LifecycleError, LifecycleStore, TERMINAL_STATES
from .writers import writer_obligations_present


MAX_HISTORY, MAX_BYTES = prior.MAX_HISTORY, prior.MAX_BYTES
_MINT = object()
_SNAPSHOTS = weakref.WeakKeyDictionary()
_DOMAIN = b"resource-sentinel.successor-registration-inventory.v1\x00"


def _refuse(reason):
    raise LifecycleError("successor_registration_inventory_" + reason)


class RegistrationHistorySnapshot:
    __slots__ = ("__weakref__",)

    def __init__(self, *, _token=None):
        if _token is not _MINT:
            _refuse("original_snapshot_required")

    @property
    def budget(self):
        return _snapshot(self).budget

    @property
    def digest(self):
        return _snapshot(self).digest


@dataclass(frozen=True, repr=False)
class _Captured:
    registration: object
    store: object
    policy: object
    policy_operation: object
    guardian: object
    backend: object
    handle: object
    identity: object
    epoch: str
    guard: object
    binding: object
    nonce: str
    journal: object
    directory: object
    directory_ids: object
    path: object
    pid: int
    thread: object
    thread_id: int
    readers: tuple
    ledger: bytes
    receipts: bytes
    journals: tuple
    budget: transfer.SuccessorInventoryBudget
    digest: str


def _snapshot(snapshot):
    captured = _SNAPSHOTS.get(snapshot) if type(snapshot) is RegistrationHistorySnapshot else None
    if type(captured) is not _Captured:
        _refuse("original_snapshot_required")
    return captured


def _owner(registration, guard):
    from .guardian_registration import GuardianRegistration
    if (type(registration) is not GuardianRegistration or type(registration.store) is not LifecycleStore or
            type(registration.guardian) is not VerifiedProcess or type(registration.identity) is not ProcessIdentity or
            type(registration.journal) is not RecoveryJournal or type(guard) is not PolicyGuard):
        _refuse("original_owner_required")
    registration._assert_successor_history_owner(guard)
    if (registration.guardian.identity is not registration.identity or registration.identity.pid != os.getpid() or
            registration.guardian._handle is None or registration.guardian._close_outcome_unknown or
            registration.identity.logon_id != guard.binding.logon_id):
        _refuse("original_self_required")


def _same_owner(registration, snapshot):
    captured = _snapshot(snapshot)
    if (registration is not captured.registration or registration.store is not captured.store or
            registration.store._policy is not captured.policy or
            registration._policy_operation is not captured.policy_operation or
            registration.guardian is not captured.guardian or registration.guardian._backend is not captured.backend or
            registration.guardian._handle is not captured.handle or registration.guardian._close_outcome_unknown or
            registration.identity is not captured.identity or registration.guardian.identity is not captured.identity or
            registration.epoch != captured.epoch or registration.journal is not captured.journal or
            registration.store.db_path != captured.path or captured.guard.binding is not captured.binding or
            captured.guard.nonce != captured.nonce or captured.journal._directory != captured.directory or
            captured.journal._directory_ids != captured.directory_ids or os.getpid() != captured.pid or
            threading.current_thread() is not captured.thread or threading.get_ident() != captured.thread_id or
            registration._successor_history_snapshot is not snapshot or
            registration._successor_history_guard is not captured.guard):
        _refuse("snapshot_scope_changed")
    return captured


def _connection(conn, registration):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _refuse("transaction_required")
    # The registration checks its retained acquisition's original file identity.
    # No stat/resolve/native query is performed in this transaction.
    rows = conn.execute("PRAGMA database_list").fetchmany(3)
    if (len(rows) != 1 or rows[0][1] != "main" or type(rows[0][2]) is not str or
            os.path.normcase(os.path.abspath(rows[0][2])) !=
            os.path.normcase(os.path.abspath(registration.store.db_path))):
        _refuse("ledger_changed")


def _route(conn, registration, guard, runtime, archives, audits, *, published):
    matches = [entry.to_dict() for entry in audits.entries if entry.to_dict()["new_epoch"] == registration.epoch]
    if len(matches) != 1 or not archives.entries or epochs._ordinary_route(conn, registration.epoch):
        _refuse("epoch_route_unverified")
    audit = matches[0]
    archived = archives.entries[-1]
    record = json.loads(archived.record)
    current = generation.read_generation(conn)
    if (prior._encoded(current) != prior._encoded(record["successor"]) or current["state"] != "ACTIVE" or
            fence.read_retirement(conn) is not None or audit["transition_id"] != record["transition_id"] or
            audit["succession_sha256"] != archived.sha256 or audit["successor_generation"] != current["generation"] or
            audit["policy_instance_id"] != guard.binding.instance_id or audit["policy_logon_id"] != guard.binding.logon_id or
            runtime["policy_instance_id"] != guard.binding.instance_id or runtime["policy_logon_id"] != guard.binding.logon_id or
            runtime["guardian_epoch"] != registration.epoch or runtime["active_logon_id"] != registration.identity.logon_id or
            runtime["registry_revision"] != audit["registry_revision"] + int(published) or
            runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE"):
        _refuse("epoch_binding_changed")


def _closed_history(conn, registration, guard, runtime, values, completed):
    managed = values["managed_executions"]
    if any(row["state"] not in TERMINAL_STATES or row["guardian_epoch"] == registration.epoch for row in managed):
        _refuse("scope_unretired")
    if any(row["parent_execution_id"] is not None or row["allocation_kind"] not in {"direct", "routed"}
           or row["job_name"] is None or row["job_nonce"] is None for row in managed
           if row["execution_id"] not in completed):
        _refuse("scope_proof_unsupported")
    by_id = {row["execution_id"]: row for row in managed}
    if len(by_id) != len(managed):
        _refuse("scope_duplicate")
    if (writer_obligations_present(conn) or conn.execute("SELECT 1 FROM queue WHERE managed_execution_id IS NOT NULL "
            "OR substr(tool_use_id,1,11) IS 'managed-v1:' LIMIT 1").fetchone() is not None):
        _refuse("managed_obligation_remaining")
    for name, rows in values.items():
        if not name.startswith("adaptive_") or name in prior._EXPERIMENT_TABLES:
            continue
        for row in rows:
            if "execution_id" in row:
                target = by_id.get(row["execution_id"])
                if (target is None or row["execution_id"] in completed or
                        "guardian_epoch" in row and row["guardian_epoch"] != target["guardian_epoch"] or
                        "spec_hash" in row and row["spec_hash"] != target["spec_hash"]):
                    _refuse("orphan_scope_record")
    for hold in values.get("adaptive_off_holds", ()):
        if type(hold["cleared_revision"]) is not int or not 0 <= hold["cleared_revision"] <= runtime["registry_revision"]:
            _refuse("off_hold_unsettled")
    slot = control_slot.query_locked(conn, runtime, guard)
    if slot is not None:
        target = by_id[slot["execution_id"]]
        binding = control_slot._binding(registration.store._public(target), guard)
        if (slot["slot_state"] != "RESTORED" or target["state"] != "FINISHED" or
                any(slot[key] != value for key, value in binding.items())):
            _refuse("slot_unsettled")
    tails, seen = {}, set()
    for action in values["adaptive_actions"]:
        if (action["action_state"] not in control_slot._ACTION_STATES or
                not control_slot._integer(action["decision_seq"]) or not control_slot._integer(action["sample_seq"]) or
                not control_slot._uuid(action["action_id"]) or action["desired_mode"] not in {"disabled", "hard_cap"} or
                not control_slot._text(action["reason"], 128) or re.fullmatch(r"[A-Za-z0-9_.:@-]+", action["reason"]) is None):
            _refuse("action_invalid")
        key = (action["guardian_epoch"], action["execution_id"], action["decision_seq"])
        if key in seen:
            _refuse("action_duplicate")
        seen.add(key)
        for name, minimum, maximum in (("desired_rate_bp", 1, 10000), ("applied_flags", 0, (1 << 32) - 1),
                ("applied_rate_bp", 0, 10000), ("applied_tick_100ns", 1, (1 << 63) - 1),
                ("lease_deadline_tick_100ns", 1, (1 << 63) - 1),
                ("intervention_deadline_tick_100ns", 1, (1 << 63) - 1), ("win32_error", 0, (1 << 32) - 1)):
            value = action[name]
            if value is not None and not (control_slot._integer(value, minimum=minimum) and value <= maximum):
                _refuse("action_invalid")
        if action["action_state"] in {"APPLIED", "RENEWED"} and (
                action["applied_flags"] != 5 or not control_slot._integer(action["applied_rate_bp"], minimum=1) or
                not control_slot._integer(action["applied_tick_100ns"], minimum=1) or
                not control_slot._integer(action["lease_deadline_tick_100ns"], minimum=1) or
                not control_slot._integer(action["intervention_deadline_tick_100ns"], minimum=1) or
                action["lease_deadline_tick_100ns"] > action["intervention_deadline_tick_100ns"]):
            _refuse("action_invalid")
        key = action["execution_id"]
        if key not in tails or action["decision_seq"] > tails[key]["decision_seq"]:
            tails[key] = action
    for action in tails.values():
        if (action["action_state"] != "RESTORED" or action["desired_mode"] != "disabled" or
                type(action["applied_flags"]) is not int or action["applied_flags"] < 0 or action["applied_flags"] & 1 or
                not control_slot._integer(action["applied_tick_100ns"], minimum=1) or action["lease_deadline_tick_100ns"] is not None):
            _refuse("action_tail_unsettled")


def _read(conn, registration, guard, budget, *, captured=None):
    _connection(conn, registration)
    schema, columns = prior._schema(conn, budget)
    history = experiment_history.verify_experiment_history_locked(conn, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(history.bytes_used)
    archives, audits = prior._read_successor_histories(conn, budget, experiment_rows=history.rows_used)
    if history.active_experiment_ids:
        _refuse("experiment_obligation_remaining")
    charged = {}
    for row in history._sql_rows:
        charged.setdefault(row.table, Counter())[prior._encoded(dict(zip(row.fields, row.values)))] += 1
    for entry in archives.entries:
        charged.setdefault(succession.TABLE, Counter())[prior._encoded(dict(zip(succession._FIELDS, entry._row)))] += 1
    for entry in audits.entries:
        charged.setdefault(epochs.TABLE, Counter())[prior._encoded(entry.to_dict())] += 1
    values = {}
    for kind, name, unused_table, unused_sql in schema:
        if kind == "table":
            fields = transfer._columns(conn, name, budget)
            values[name] = transfer._rows(conn, name, fields, budget, charged.get(name, Counter()))
    # Bound all actual payloads before the legacy semantic validators fetch them.
    prior._validate_schemas(conn, columns)
    runtime = dict(registration.store._policy._runtime(conn) if captured is not None else
                   registration.store._policy.revalidate(conn, guard))
    _route(conn, registration, guard, runtime, archives, audits, published=captured is not None)
    expected_infrastructure = [] if captured is None else [_guardian_row(captured)]
    if prior._encoded(values["adaptive_infrastructure"]) != prior._encoded(expected_infrastructure):
        _refuse("infrastructure_changed")
    _closed_history(conn, registration, guard, runtime, values, history.completed_execution_ids)
    ledger = dict(schema=schema, tables=values, experiment_execution_ids=sorted(history.completed_execution_ids))
    rows = history.rows_used + archives.rows_used + audits.rows_used
    return ledger, (rows, archives.bytes_used + audits.bytes_used)


def _guardian_row(captured):
    identity = captured.identity
    return dict(role="guardian", pid=identity.pid, created_filetime_100ns=str(identity.created_filetime_100ns),
                logon_id=identity.logon_id, schema_version=1)


def _records(captured):
    return {key: RecoveryManifest.from_json(value.decode("utf-8")) for key, value in captured.journals}


def _digest(ledger, receipts, journals):
    digest = hashlib.sha256(_DOMAIN)
    for value in (ledger, receipts, *(value for unused_key, value in journals)):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _account(budget, rows, ledger, receipts, journals):
    size = len(ledger) + len(receipts) + sum(len(value) for unused_key, value in journals)
    budget.charge(max(0, size - budget.bytes))
    return transfer.SuccessorInventoryBudget(budget.bytes, rows[0], rows[1])


def capture_registration_history(registration, guard):
    _owner(registration, guard)
    journal = registration.journal
    directory, directory_ids = journal._directory, journal._directory_ids
    with registration.successor_history_reader(guard) as first:
        registration.assert_successor_history_connection(first, guard)
        initial, unused_rows = _read(first, registration, guard, prior._Budget())
    budget = prior._Budget()
    production = [row for row in initial["tables"]["managed_executions"]
                  if row["execution_id"] not in initial["experiment_execution_ids"]]
    records = prior._journal_inventory(journal, production, budget)
    journals = tuple((key, records[key].to_json().encode("utf-8")) for key in sorted(records))
    with registration.successor_history_reader(guard) as second:
        registration.assert_successor_history_connection(second, guard)
        current, rows = _read(second, registration, guard, budget)
        if prior._encoded(current) != prior._encoded(initial):
            _refuse("capture_changed")
        receipts = prior._encoded(prior._receipts(second, registration.store, current, records, budget))
    _owner(registration, guard)
    journal._check_directory()
    if journal._directory != directory or journal._directory_ids != directory_ids:
        _refuse("journal_changed")
    ledger = prior._encoded(current)
    accounting = _account(budget, rows, ledger, receipts, journals)
    snapshot = RegistrationHistorySnapshot(_token=_MINT)
    _SNAPSHOTS[snapshot] = _Captured(registration, registration.store, registration.store._policy,
        registration._policy_operation, registration.guardian, registration.guardian._backend,
        registration.guardian._handle, registration.identity, registration.epoch, guard, guard.binding, guard.nonce,
        journal, directory, directory_ids, registration.store.db_path, os.getpid(), threading.current_thread(),
        threading.get_ident(), (first, second), ledger, receipts, journals, accounting, _digest(ledger, receipts, journals))
    return snapshot


def _observe(conn, registration, guard, captured, *, postimage):
    records = _records(captured)
    budget = prior._Budget()
    for record in records.values():
        budget.add(record.to_dict())
    ledger, rows = _read(conn, registration, guard, budget, captured=captured if postimage else None)
    receipts = prior._encoded(prior._receipts(conn, registration.store, ledger, records, budget))
    accounting = _account(budget, rows, prior._encoded(ledger), receipts, captured.journals)
    if receipts != captured.receipts:
        _refuse("receipts_changed")
    return ledger, accounting


def revalidate_registration_history(conn, registration, guard, snapshot):
    captured = _same_owner(registration, snapshot)
    if guard is not captured.guard:
        _refuse("snapshot_scope_changed")
    _owner(registration, guard)
    registration.assert_successor_history_connection(conn, guard)
    ledger, accounting = _observe(conn, registration, guard, captured, postimage=False)
    encoded = prior._encoded(ledger)
    if (encoded != captured.ledger or accounting != captured.budget or
            _digest(encoded, captured.receipts, captured.journals) != captured.digest):
        _refuse("ledger_changed")


def revalidate_registration_postimage(conn, registration, snapshot):
    captured = _same_owner(registration, snapshot)
    registration._assert_successor_postimage_owner(snapshot)
    registration.assert_successor_postimage_connection(conn, snapshot)
    ledger, unused_accounting = _observe(conn, registration, captured.guard, captured, postimage=True)
    expected = json.loads(captured.ledger)
    runtime = expected["tables"]["adaptive_runtime"][0]
    before = {key: value for key, value in runtime.items() if key != "policy_entry_nonce"}
    after = dict(before, registry_revision=before["registry_revision"] + 1)
    if (prior._encoded(registration.before) != prior._encoded(before) or
            prior._encoded(registration.after) != prior._encoded(after)):
        _refuse("publication_images_changed")
    actual_nonce = ledger["tables"]["adaptive_runtime"][0]["policy_entry_nonce"]
    if actual_nonce == captured.nonce:
        pass
    elif actual_nonce is None:
        if captured.guard._nonce_clear_confirmed is not True:
            # The original registration retains the exact read connection as
            # a candidate only. It confirms reconciliation after that reader
            # and its readiness scope have both closed positively; this data
            # function does not mark a guard, SQL owner or operation complete.
            registration.observe_successor_nonce_clear(conn, snapshot)
    else:
        _refuse("nonce_unsettled")
    runtime.update(registry_revision=after["registry_revision"], policy_entry_nonce=actual_nonce)
    expected["tables"]["adaptive_infrastructure"] = [_guardian_row(captured)]
    # Ordinary tables can advance after commit. Their full current rows have
    # already passed the common budget and managed-alias checks. Adaptive data,
    # original managed rows and their receipt/archive proofs stay exact.
    immutable = lambda value: dict(schema=value["schema"], experiment_execution_ids=value["experiment_execution_ids"],
        tables={name: rows for name, rows in value["tables"].items()
                if name.startswith("adaptive_") or name == "managed_executions"})
    if prior._encoded(immutable(ledger)) != prior._encoded(immutable(expected)):
        _refuse("postimage_changed")
