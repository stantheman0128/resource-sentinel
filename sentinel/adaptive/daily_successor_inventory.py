"""Bounded pre-transition observations for an original completed retirement.

The original FROZEN inventory keeps its same-guard contract. This separate
reader accepts only its exact completed owner and one distinct, already held
POLICY guard. It compares the original evidence after three fixed seal changes,
and captures every ordinary table that the earlier inventory did not retain.
Those ordinary rows are preserved from this capture onward, not retroactively
claimed to have been observed at retirement. No function grants write authority.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
import re
import sqlite3
import threading
import weakref

from . import daily_generation as generation
from . import daily_retirement_inventory as prior
from . import daily_successor_history as succession
from . import experiment_history
from .contracts import RecoveryManifest
from .daily_retirement import DailyRetirementOperation
from .daily_retirement_fence import read_retirement
from .policy import PolicyGuard
from .store import LifecycleError


MAX_HISTORY, MAX_BYTES = prior.MAX_HISTORY, prior.MAX_BYTES
_MINT = object()
_SNAPSHOTS = weakref.WeakKeyDictionary()
_IDENTIFIER = re.compile(r"[a-z_][a-z0-9_]*")


def _refuse(reason):
    raise LifecycleError("daily_successor_inventory_" + reason)


@dataclass(frozen=True)
class SuccessorInventoryBudget:
    """Accounting observation only; the original scope still owns all writes."""
    bytes_used: int
    history_rows: int
    history_bytes: int

    @property
    def remaining_bytes(self):
        return MAX_BYTES - self.bytes_used

    @property
    def remaining_history_rows(self):
        return MAX_HISTORY - self.history_rows


class SuccessorInventorySnapshot:
    """Opaque, process-local observation; copying it cannot copy registration."""
    __slots__ = ("__weakref__",)

    def __init__(self, *, _token=None):
        if _token is not _MINT:
            _refuse("original_snapshot_required")

    @property
    def budget(self):
        return _snapshot(self).budget


@dataclass(frozen=True)
class _Captured:
    retirement: object
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
    readers: tuple
    preimage: tuple
    full_ledger: bytes
    budget: SuccessorInventoryBudget


def _snapshot(snapshot):
    captured = _SNAPSHOTS.get(snapshot) if type(snapshot) is SuccessorInventorySnapshot else None
    if type(captured) is not _Captured:
        _refuse("original_snapshot_required")
    return captured


def _original(retirement, guard):
    if type(retirement) is not DailyRetirementOperation:
        _refuse("original_retirement_required")
    retirement.assert_successor_predecessor()
    if (type(guard) is not PolicyGuard or guard is retirement._freeze_guard or
            guard is retirement._seal_guard or guard.binding != retirement._seal_guard.binding or
            guard.nonce in {retirement._freeze_guard.nonce, retirement._seal_guard.nonce}):
        _refuse("distinct_policy_required")
    retirement.policy.assert_held(guard)
    if retirement.policy.current_guard() is not guard:
        _refuse("original_policy_required")
    return prior.retired_inventory_preimage(retirement)


def _identity(retirement):
    path = retirement.owner.ledger_path
    if generation._ledger_identity(path) != retirement.owner.ledger_identity:
        _refuse("ledger_changed")
    return path


def _nonce_guard():
    from .daily_successor import _NONCE_TRIGGER_SQL
    # SQLite persists TEMP triggers without the TEMP keyword. Everything else
    # must be the original operation's exact fixed definition, apart from space.
    definition = " ".join(_NONCE_TRIGGER_SQL.split())
    if not definition.startswith("CREATE TEMP TRIGGER ") or len(definition) > 4096:
        _refuse("temporary_schema_changed")
    return ("trigger", "sentinel_successor_nonce_guard", "adaptive_runtime",
            definition.replace("CREATE TEMP TRIGGER ", "CREATE TRIGGER ", 1))


def _original_connection(conn, retirement, guard):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _refuse("transaction_required")
    from .daily_successor_scope import current_operation
    operation = current_operation(retirement.owner.ledger_path)
    if operation is None:
        _refuse("original_connection_required")
    operation.assert_inventory_connection(conn, retirement, guard)


def _connection_path(conn, retirement, guard):
    databases = conn.execute("PRAGMA database_list").fetchmany(3)
    main = [row for row in databases if row[1] == "main"]
    if (len(main) != 1 or type(main[0][2]) is not str or
            os.path.normcase(os.path.abspath(main[0][2])) !=
            os.path.normcase(str(retirement.owner.ledger_path))):
        _refuse("ledger_changed")
    if len(databases) == 1:
        # Capture's own read-only SQL owners remain strictly main-only.
        return False
    if (len(databases) != 2 or any(row[1] not in {"main", "temp"} for row in databases) or
            sum(row[1] == "temp" and row[2] == "" for row in databases) != 1):
        _refuse("ledger_changed")
    _original_connection(conn, retirement, guard)
    rows = conn.execute("""SELECT type,
        CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,
        CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name END,
        CASE WHEN length(CAST(sql AS BLOB))<=4096 THEN sql END
        FROM temp.sqlite_master ORDER BY type,name LIMIT 2""").fetchall()
    if (len(rows) != 1 or any(type(value) is not str for value in rows[0]) or
            tuple(rows[0][:3]) + (" ".join(rows[0][3].split()),) != _nonce_guard()):
        _refuse("temporary_schema_changed")
    return True


def _expected(retirement, guard, preimage):
    # These bytes were validated, bounded and retained by the original seal.
    # No caller JSON or current database row supplies their origin.
    ledger = json.loads(preimage[0])
    tables = ledger["tables"]
    if (tables.get("adaptive_daily_generation") != [retirement._generation_row] or
            tables.get("adaptive_daily_retirement") != [retirement._freeze_row]):
        _refuse("original_preimage_changed")
    runtime = tables.get("adaptive_runtime")
    if (type(runtime) is not list or len(runtime) != 1 or
            runtime[0]["policy_entry_nonce"] != retirement._seal_guard.nonce or
            runtime[0]["policy_instance_id"] != guard.binding.instance_id or
            runtime[0]["policy_logon_id"] != guard.binding.logon_id or
            runtime[0]["mode"] != "off" or runtime[0]["admission_barrier"] != "NONE"):
        _refuse("original_preimage_changed")
    tables["adaptive_daily_generation"] = [dict(retirement._generation_row, state="DRAINING")]
    tables["adaptive_daily_retirement"] = [dict(retirement._seal_row)]
    runtime[0]["policy_entry_nonce"] = guard.nonce
    return ledger


def _columns(conn, table, budget):
    if type(table) is not str or _IDENTIFIER.fullmatch(table) is None:
        _refuse("schema_unknown")
    rows = []
    for row in conn.execute('PRAGMA table_xinfo("' + table + '")'):
        if len(rows) >= 128:
            _refuse("schema_unknown")
        if (len(row) != 7 or type(row[1]) is not str or
                _IDENTIFIER.fullmatch(row[1]) is None or row[6] != 0):
            _refuse("schema_unknown")
        rows.append(tuple(row))
    names = tuple(row[1] for row in rows)
    if not names or len(set(names)) != len(names):
        _refuse("schema_unknown")
    budget.add(rows)
    return names


def _rows(conn, table, columns, budget, already_charged):
    # Identifiers have passed the fixed grammar above. Bound every cell before
    # SQLite hands its payload to Python, including complete ordinary history.
    quoted = ['"' + name + '"' for name in columns]
    limits = []
    for name, sql in zip(columns, quoted):
        limit = prior._CELL_BYTES
        if table == experiment_history.TABLE and name == "receipt_json":
            limit = experiment_history.MAX_RECEIPT_BYTES
        elif table == succession.TABLE and name == "record_json":
            limit = succession.MAX_RECORD_BYTES
        limits.append(f"({sql} IS NULL OR length(CAST({sql} AS BLOB))<={limit})")
    valid = " AND ".join(limits)
    projection = ",".join(f"CASE WHEN {valid} THEN {name} END" for name in quoted)
    values = []
    for row in conn.execute(f'SELECT {projection},CASE WHEN {valid} THEN 1 ELSE 0 END '
            f'FROM "{table}" ORDER BY rowid LIMIT ?', (MAX_HISTORY + 1,)):
        if len(values) >= MAX_HISTORY:
            _refuse("history_exceeded")
        if row[-1] != 1:
            _refuse("cell_exceeded")
        value = dict(zip(columns, tuple(row)[:-1]))
        encoded = prior._encoded(value)
        if already_charged[encoded]:
            already_charged[encoded] -= 1
        else:
            budget.charge(len(encoded))
        values.append(value)
    return values


def _read(conn, retirement, guard, expected, preimage, records, budget):
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _refuse("transaction_required")
    _connection_path(conn, retirement, guard)
    # Reserve the same fixed TEMP metadata on capture's main-only readers and
    # the eventual owned transaction. It shares the whole inventory allowance.
    budget.add(_nonce_guard())
    retirement.policy.revalidate(conn, guard)
    schema, unused_columns = prior._schema(conn, budget)
    if prior._encoded(schema) != prior._encoded(expected["schema"]):
        _refuse("schema_changed")
    history = experiment_history.verify_experiment_history_locked(conn,
        max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(history.bytes_used)
    if history.active_experiment_ids:
        _refuse("experiment_obligation_remaining")
    previous = succession.read_successor_history(conn, max_rows=MAX_HISTORY,
        max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(previous.bytes_used)
    charged = {}
    for row in history._sql_rows:
        charged.setdefault(row.table, Counter())[prior._encoded(dict(zip(row.fields, row.values)))] += 1
    for entry in previous.entries:
        charged.setdefault(succession.TABLE, Counter())[prior._encoded(dict(zip(succession._FIELDS, entry._row)))] += 1
    full = {}
    for kind, name, unused_table, unused_sql in schema:
        if kind == "table":
            fields = _columns(conn, name, budget)
            full[name] = _rows(conn, name, fields, budget, charged.get(name, Counter()))
    if (generation.read_generation(conn) != dict(retirement._generation_row, state="DRAINING") or
            read_retirement(conn) != retirement._seal_row):
        _refuse("seal_changed")
    if any(full.get(name) for name in ("reservations", "worker_reservations", "adaptive_infrastructure")):
        _refuse("allocation_remaining")
    observed = dict(schema=schema, tables={},
        experiment_execution_ids=sorted(history.completed_execution_ids),
        experiment_archives=[dict(zip(row.fields, row.values)) for row in history._sql_rows
                             if row.table == "executions"])
    for name in expected["tables"]:
        if name not in full:
            _refuse("schema_changed")
        values = full[name]
        if name == "managed_executions":
            values = sorted(values, key=lambda row: row["execution_id"])
        observed["tables"][name] = values
    if prior._encoded(observed) != prior._encoded(expected):
        _refuse("predecessor_changed")
    receipts = prior._receipts(conn, retirement.store, observed, records, budget)
    if prior._encoded(receipts) != preimage[1]:
        _refuse("receipts_changed")
    encoded = prior._encoded(dict(schema=schema, tables=full))
    retained_bytes = len(encoded) + len(preimage[1]) + sum(len(value) for _, value in preimage[2])
    budget.charge(max(0, retained_bytes - budget.bytes))
    return encoded, SuccessorInventoryBudget(budget.bytes, previous.rows_used, previous.bytes_used)


def _records(preimage):
    # Decode fresh immutable contract objects; they are data, not adopted native
    # witnesses. Their exact bytes are compared with freshly read actual files.
    return {execution_id: RecoveryManifest.from_json(value.decode("utf-8"))
            for execution_id, value in preimage[2]}


def capture_successor_inventory(retirement, guard):
    """Capture outside final SQL; return only after both original readers close."""
    preimage = _original(retirement, guard)
    path = _identity(retirement)
    from .daily_successor_scope import current_operation
    operation = current_operation(path)
    if operation is None:
        _refuse("original_operation_required")
    expected = _expected(retirement, guard, preimage)
    records = _records(preimage)
    with operation.inventory_reader(retirement, guard) as first:
        before, unused_budget = _read(first, retirement, guard, expected, preimage, records, prior._Budget())
    budget = prior._Budget()
    production = [row for row in expected["tables"]["managed_executions"]
                  if row["execution_id"] not in expected["experiment_execution_ids"]]
    actual = prior._journal_inventory(retirement.journal, production, budget)
    journal_bytes = tuple((key, actual[key].to_json().encode("utf-8")) for key in sorted(actual))
    if journal_bytes != preimage[2]:
        _refuse("journals_changed")
    with operation.inventory_reader(retirement, guard) as second:
        after, accounting = _read(second, retirement, guard, expected, preimage, actual, budget)
    if before != after or _original(retirement, guard) != preimage:
        _refuse("capture_changed")
    _identity(retirement)
    snapshot = SuccessorInventorySnapshot(_token=_MINT)
    _SNAPSHOTS[snapshot] = _Captured(retirement, retirement.store, retirement.journal,
        guard, guard.binding, guard.nonce, os.getpid(), threading.current_thread(), threading.get_ident(),
        path, retirement.owner.ledger_identity, retirement.journal._directory,
        retirement.journal._directory_ids, (first, second), preimage, after, accounting)
    return snapshot


def revalidate_successor_inventory(conn, retirement, guard, snapshot):
    """Recheck complete original rows inside this distinct guard's transaction.

    Journal reads belong to capture, before BEGIN. The retained completed host,
    exact SEALED fence and held POLICY exclude cooperating journal publishers.
    """
    captured = _snapshot(snapshot)
    if (retirement is not captured.retirement or guard is not captured.guard or
            retirement.store is not captured.store or retirement.journal is not captured.journal or
            guard.binding is not captured.binding or guard.nonce != captured.nonce or
            os.getpid() != captured.pid or threading.current_thread() is not captured.thread or
            threading.get_ident() != captured.thread_id or retirement.owner.ledger_path != captured.path or
            retirement.owner.ledger_identity != captured.ledger_identity or
            retirement.journal._directory != captured.directory or
            retirement.journal._directory_ids != captured.directory_ids):
        _refuse("snapshot_scope_changed")
    if _original(retirement, guard) != captured.preimage:
        _refuse("original_preimage_changed")
    _identity(retirement)
    if not isinstance(conn, sqlite3.Connection) or not conn.in_transaction:
        _refuse("transaction_required")
    if not _connection_path(conn, retirement, guard):
        _original_connection(conn, retirement, guard)
        _refuse("temporary_schema_changed")
    expected = _expected(retirement, guard, captured.preimage)
    records = _records(captured.preimage)
    budget = prior._Budget()
    for record in records.values():
        budget.add(record.to_dict())
    current, accounting = _read(conn, retirement, guard, expected, captured.preimage, records, budget)
    if current != captured.full_ledger or accounting != captured.budget:
        _refuse("ledger_changed")
    return None
