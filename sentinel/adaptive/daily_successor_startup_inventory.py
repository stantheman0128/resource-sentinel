"""Complete bounded startup observations for an original acknowledged successor.

Only the original successor, published host and held fresh startup may capture
these data. Retired adaptive rows remain exact; ordinary rows are observed now,
then compared again in the same original POLICY scope. Neither the opaque token
nor its digest grants publication, admission or a guardian Create capability.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
import sqlite3
import threading
import weakref

from . import daily_generation as generation
from . import daily_retirement_fence as fence
from . import daily_retirement_inventory as prior
from . import daily_successor_history as succession
from . import daily_successor_inventory as transfer
from . import daily_successor_epoch as epochs
from . import experiment_history
from .daily_successor import DailySuccessorOperation
from .policy import PolicyGuard
from .store import LifecycleError
from .writers import writer_obligations_present


MAX_HISTORY, MAX_BYTES = prior.MAX_HISTORY, prior.MAX_BYTES
_MINT = object()
_SNAPSHOTS = weakref.WeakKeyDictionary()
_DOMAIN = b"resource-sentinel.daily-successor-startup-inventory.v1\x00"


def _refuse(reason):
    raise LifecycleError("daily_successor_startup_inventory_" + reason)


class StartupInventorySnapshot:
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
    operation: object
    supervisor: object
    startup: object
    retirement: object
    owner: object
    store: object
    journal: object
    guard: object
    binding: object
    nonce: str
    pid: int
    thread: object
    thread_id: int
    path: object
    ledger_identity: tuple
    directory: object
    directory_ids: object
    archive: object
    epoch_pin: tuple
    readers: tuple
    preimage: tuple
    full_ledger: bytes
    budget: transfer.SuccessorInventoryBudget
    digest: str


def _snapshot(snapshot):
    value = _SNAPSHOTS.get(snapshot) if type(snapshot) is StartupInventorySnapshot else None
    if type(value) is not _Captured:
        _refuse("original_snapshot_required")
    return value


def _original(operation, supervisor, guard):
    if type(operation) is not DailySuccessorOperation:
        _refuse("original_operation_required")
    operation.assert_supervisor(supervisor)
    retirement = operation.retirement
    old_guards = (operation.guard, retirement._freeze_guard, retirement._seal_guard)
    if (type(guard) is not PolicyGuard or any(guard is old for old in old_guards) or
            guard.nonce in {old.nonce for old in old_guards} or
            guard.binding != operation.guard.binding):
        _refuse("distinct_policy_required")
    operation.policy.assert_held(guard)
    if operation.policy.current_guard() is not guard:
        _refuse("original_policy_required")
    preimage = prior.retired_inventory_preimage(retirement)
    published = operation.published_epoch(supervisor)
    epoch = operation._guardian_epoch_operation
    pin = (epoch, None, None, False)
    if published is not None:
        if type(epoch) is not epochs.SuccessorGuardianEpoch:
            _refuse("original_epoch_required")
        epoch._original()
        captured = _snapshot(epoch._snapshot)
        if (epoch.operation is not operation or epoch.supervisor is not supervisor or
                epoch._complete is not True or epoch._policy_operation._complete is not True or
                epoch._policy_operation.pending or captured.operation is not operation or
                captured.supervisor is not supervisor or captured.guard is not epoch._guard or
                published != dict(zip(epochs._FIELDS, epoch._candidate)) or
                published["inventory_digest"] != captured.digest):
            _refuse("original_epoch_changed")
        pin = (epoch, epoch._candidate, epoch._snapshot, True)
    elif epoch is not None:
        if type(epoch) is not epochs.SuccessorGuardianEpoch:
            _refuse("original_epoch_required")
        epoch._original()
        if epoch.operation is not operation or epoch.supervisor is not supervisor:
            _refuse("original_epoch_changed")
        # The original publisher retains this returned snapshot before its
        # transaction. That handoff is not an epoch publication. Its own
        # _original() pins any candidate/snapshot already retained; only the
        # completed route below freezes those objects into a later observation.
        pin = (epoch, None, None, False)
    return preimage, published, pin


def _same_epoch(left, right):
    return len(left) == len(right) == 4 and all(a is b for a, b in zip(left, right))


def _path(conn, operation):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _refuse("transaction_required")
    rows = conn.execute("PRAGMA database_list").fetchmany(2)
    if (len(rows) != 1 or rows[0][1] != "main" or type(rows[0][2]) is not str or
            os.path.normcase(os.path.abspath(rows[0][2])) != os.path.normcase(str(operation.ledger_path)) or
            generation._ledger_identity(operation.ledger_path) != operation.owner.ledger_identity):
        _refuse("ledger_changed")


def _schema(conn, expected, budget):
    rows = conn.execute("""SELECT type,
        CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,
        CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name END,
        CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END,
        CASE WHEN sql IS NULL OR length(CAST(sql AS BLOB))<=65536 THEN 1 ELSE 0 END
        FROM main.sqlite_master ORDER BY type,name LIMIT ?""", (prior._SCHEMA_LIMIT + 1,)).fetchall()
    if (len(rows) > prior._SCHEMA_LIMIT or any(row[4] != 1 or row[1] is None or row[2] is None for row in rows)):
        _refuse("schema_bound")
    schema = [tuple(row[:4]) for row in rows]
    budget.add(schema)
    removed = set(fence._definitions(conn)) | {fence.TABLE}
    evolving = {succession.TABLE, epochs.TABLE}
    original = [row for row in expected["schema"] if row[1] not in removed and row[2] not in evolving]
    current = [row for row in schema if row[2] not in evolving]
    if prior._encoded(original) != prior._encoded(current):
        _refuse("schema_changed")
    return schema


def _read(conn, operation, supervisor, guard, preimage, published, records, budget):
    _path(conn, operation)
    operation.assert_startup_inventory_connection(conn, supervisor, guard)
    runtime = dict(operation.policy.revalidate(conn, guard))
    expected = json.loads(preimage[0])
    schema = _schema(conn, expected, budget)
    history = experiment_history.verify_experiment_history_locked(conn, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(history.bytes_used)
    if history.active_experiment_ids:
        _refuse("experiment_obligation_remaining")
    if history.rows_used > MAX_HISTORY:
        _refuse("history_exceeded")
    archives = succession.read_successor_history(conn, max_rows=MAX_HISTORY - history.rows_used,
        max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(archives.bytes_used)
    audit = epochs.read_successor_guardian_epochs(conn,
        max_rows=MAX_HISTORY - history.rows_used - archives.rows_used, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(audit.bytes_used)
    charged = {}
    for row in history._sql_rows:
        charged.setdefault(row.table, Counter())[prior._encoded(dict(zip(row.fields, row.values)))] += 1
    for entry in archives.entries:
        charged.setdefault(succession.TABLE, Counter())[prior._encoded(dict(zip(succession._FIELDS, entry._row)))] += 1
    for entry in audit.entries:
        charged.setdefault(epochs.TABLE, Counter())[prior._encoded(entry.to_dict())] += 1
    full = {}
    for kind, name, unused_table, unused_sql in schema:
        if kind == "table":
            columns = transfer._columns(conn, name, budget)
            full[name] = transfer._rows(conn, name, columns, budget, charged.get(name, Counter()))
    if (generation.read_generation(conn) != operation._successor_row or
            fence.read_retirement(conn) is not None or not archives.entries or
            archives.entries[-1] != operation._archive):
        _refuse("successor_changed")
    # These rows came from the original completed retirement. Only the exact
    # generation transfer and original published epoch may change their image.
    tables = expected["tables"]
    old_runtime = dict(tables["adaptive_runtime"][0], policy_entry_nonce=guard.nonce)
    if published is not None:
        if (published["old_epoch"] != old_runtime["guardian_epoch"] or
                published["previous_revision"] != old_runtime["registry_revision"] or
                published["transition_id"] != operation.transition_id or
                published["successor_generation"] != operation.owner.generation or
                published["succession_sha256"] != operation._archive.sha256):
            _refuse("epoch_changed")
        old_runtime.update(guardian_epoch=published["new_epoch"],
            active_logon_id=published["supervisor_logon_id"], registry_revision=published["registry_revision"])
    if prior._encoded(runtime) != prior._encoded(old_runtime) or runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE":
        _refuse("runtime_changed")
    special = {fence.TABLE, generation._TABLE, "adaptive_runtime", succession.TABLE, epochs.TABLE}
    for name, original in tables.items():
        if name in special:
            continue
        actual = full.get(name)
        if name == "managed_executions" and actual is not None:
            actual = sorted(actual, key=lambda row: row["execution_id"])
        if prior._encoded(actual) != prior._encoded(original):
            _refuse("retired_history_changed")
    expected_archives = list(tables.get(succession.TABLE, ())) + [dict(zip(succession._FIELDS, operation._archive._row))]
    if prior._encoded(full.get(succession.TABLE)) != prior._encoded(expected_archives):
        _refuse("succession_history_changed")
    expected_audits = list(tables.get(epochs.TABLE, ())) + ([] if published is None else [published])
    if prior._encoded([entry.to_dict() for entry in audit.entries]) != prior._encoded(expected_audits):
        _refuse("epoch_history_changed")
    if epochs.TABLE in full and epochs.TABLE not in tables and published is None:
        _refuse("epoch_history_changed")
    experiment_archives = [dict(zip(row.fields, row.values)) for row in history._sql_rows if row.table == "executions"]
    if (sorted(history.completed_execution_ids) != expected["experiment_execution_ids"] or
            prior._encoded(experiment_archives) != prior._encoded(expected["experiment_archives"])):
        _refuse("experiment_history_changed")
    if (full.get("adaptive_infrastructure") or writer_obligations_present(conn) or
            conn.execute("SELECT 1 FROM queue WHERE managed_execution_id IS NOT NULL OR "
                         "substr(tool_use_id,1,11) IS 'managed-v1:' LIMIT 1").fetchone() is not None):
        _refuse("managed_obligation_remaining")
    observed = dict(schema=schema, tables=full, experiment_execution_ids=expected["experiment_execution_ids"])
    receipts = prior._receipts(conn, operation.store, observed, records, budget)
    if prior._encoded(receipts) != preimage[1]:
        _refuse("receipts_changed")
    encoded = prior._encoded(dict(schema=schema, tables=full))
    size = len(encoded) + len(preimage[1]) + sum(len(value) for unused_key, value in preimage[2])
    budget.charge(max(0, size - budget.bytes))
    rows = history.rows_used + archives.rows_used + audit.rows_used
    return encoded, transfer.SuccessorInventoryBudget(budget.bytes, rows, archives.bytes_used + audit.bytes_used)


def _digest(ledger, preimage):
    digest = hashlib.sha256(_DOMAIN)
    for value in (ledger, preimage[1], *(value for unused_key, value in preimage[2])):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def capture_startup_inventory(operation, supervisor, guard):
    preimage, published, epoch_pin = _original(operation, supervisor, guard)
    records = transfer._records(preimage)
    with operation.startup_inventory_reader(supervisor, guard) as first:
        before, unused_budget = _read(first, operation, supervisor, guard, preimage, published, records, prior._Budget())
    budget = prior._Budget()
    retired = json.loads(preimage[0])
    production = [row for row in retired["tables"]["managed_executions"]
                  if row["execution_id"] not in retired["experiment_execution_ids"]]
    actual = prior._journal_inventory(operation.retirement.journal, production, budget)
    if tuple((key, actual[key].to_json().encode("utf-8")) for key in sorted(actual)) != preimage[2]:
        _refuse("journals_changed")
    with operation.startup_inventory_reader(supervisor, guard) as second:
        after, accounting = _read(second, operation, supervisor, guard, preimage, published, actual, budget)
    current_preimage, current_published, current_epoch = _original(operation, supervisor, guard)
    if (before != after or preimage != current_preimage or published != current_published or
            not _same_epoch(epoch_pin, current_epoch)):
        _refuse("capture_changed")
    journal = operation.retirement.journal
    snapshot = StartupInventorySnapshot(_token=_MINT)
    _SNAPSHOTS[snapshot] = _Captured(operation, supervisor, supervisor.startup, operation.retirement,
        operation.owner, operation.store, journal, guard, guard.binding, guard.nonce, os.getpid(),
        threading.current_thread(), threading.get_ident(), operation.ledger_path, operation.owner.ledger_identity,
        journal._directory, journal._directory_ids, operation._archive, epoch_pin, (first, second), preimage,
        after, accounting, _digest(after, preimage))
    return snapshot


def revalidate_startup_inventory(conn, operation, supervisor, guard, snapshot):
    captured = _snapshot(snapshot)
    if (operation is not captured.operation or supervisor is not captured.supervisor or
            supervisor.startup is not captured.startup or operation.retirement is not captured.retirement or
            operation.owner is not captured.owner or operation.store is not captured.store or
            operation.retirement.journal is not captured.journal or guard is not captured.guard or
            guard.binding is not captured.binding or guard.nonce != captured.nonce or
            os.getpid() != captured.pid or threading.current_thread() is not captured.thread or
            threading.get_ident() != captured.thread_id or operation.ledger_path != captured.path or
            operation.owner.ledger_identity != captured.ledger_identity or
            captured.journal._directory != captured.directory or captured.journal._directory_ids != captured.directory_ids or
            operation._archive is not captured.archive):
        _refuse("snapshot_scope_changed")
    preimage, published, epoch_pin = _original(operation, supervisor, guard)
    if preimage != captured.preimage or not _same_epoch(epoch_pin, captured.epoch_pin):
        _refuse("original_preimage_changed")
    records = transfer._records(preimage)
    budget = prior._Budget()
    for record in records.values():
        budget.add(record.to_dict())
    observed, accounting = _read(conn, operation, supervisor, guard, preimage, published, records, budget)
    if observed != captured.full_ledger or accounting != captured.budget or _digest(observed, preimage) != captured.digest:
        _refuse("ledger_changed")
    return None
