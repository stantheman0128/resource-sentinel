"""Bounded positive historical proof for an original daily retirement.

This reader grants no native authority and performs no cleanup. The original
host separately proves its supervisor and native owners closed. Capture runs
under that host's retained POLICY guard, outside its final writer transaction;
only the same guard may use the opaque snapshot in the final transaction.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time
import weakref

from . import control_slot, prelaunch_receipt, terminal_receipt
from .contracts import CpuControl, CpuControlMode, RecoveryManifest
from .legacy_writer import _infra_schema
from .policy import PolicyGuard
from .recovery_journal import RecoveryJournal, _safe_stat
from .store import (LifecycleError, LifecycleStore, TERMINAL_STATES,
                    _FENCE_FIELDS, _RETIREMENT_FIELDS, check_schema_version)
from .writers import writer_obligations_present


MAX_HISTORY = 4096
MAX_BYTES = 16 * 1024 * 1024
_CELL_BYTES = 65536
_SCHEMA_LIMIT = 256
_READ_SECONDS = 5
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_MINT = object()
_SNAPSHOTS = weakref.WeakKeyDictionary()
_REQUEST_FIELDS = ("execution_id", "operation", "request_id", "payload_hash", "spec_hash", "guardian_epoch")
_LAYOUTS = {
    "adaptive_runtime": ("singleton", "schema_version", "protocol_version", "mode", "registry_revision",
        "guardian_epoch", "active_logon_id", "admission_barrier", "policy_instance_id", "policy_logon_id",
        "policy_entry_nonce", "policy_binding_initialized"),
    "managed_executions": ("execution_id", "task_id", "session_id", "principal_id", "logon_id", "allocation_kind",
        "reservation_id", "parent_execution_id", "spec_hash", "wrapper_pid", "wrapper_created_filetime_100ns",
        "root_pid", "root_created_filetime_100ns", "job_name", "role", "priority", "coverage", "state",
        "state_revision", "guardian_epoch", "launch_in_flight", "launch_sealed", "claim_token_hash",
        "claim_consumed", "root_outcome", "hold_reason", "created_at", "heartbeat_at", "finished_at",
        "cancel_requested_at", "requested_cpu_units", "requested_physical_bytes", "requested_commit_bytes",
        "requested_io_slots", "floor_cpu_units", "floor_physical_bytes", "floor_commit_bytes", "floor_io_slots",
        "admission_binding_hash", "ipc_auth_key", "job_nonce"),
    "adaptive_control_slot": control_slot._FIELDS,
    "adaptive_actions": control_slot._ACTION_FIELDS,
    "adaptive_launch_requests": _REQUEST_FIELDS,
    "adaptive_launch_fences": _FENCE_FIELDS,
    "adaptive_retirement_requests": _REQUEST_FIELDS,
    "adaptive_prelaunch_retirements": _RETIREMENT_FIELDS,
    "adaptive_infrastructure": ("role", "pid", "created_filetime_100ns", "logon_id", "schema_version"),
    "adaptive_terminal_custody_receipts": terminal_receipt._COLUMNS,
    "adaptive_prelaunch_custody_receipts": terminal_receipt._COLUMNS,
    "adaptive_barrier_clears": control_slot._BARRIER_CLEAR_FIELDS,
    "adaptive_off_holds": ("request_id", "policy_instance_id", "guardian_epoch", "created_revision",
        "boundary_tick", "prior_barrier", "prior_slot_id", "cleared_revision"),
    "adaptive_off_operations": ("request_id", "instance_id", "policy_instance_id", "guardian_epoch",
        "original_nonce", "expected_revision", "result_revision", "preimage_hash", "postimage_hash"),
    "adaptive_epoch_rollovers": ("attempt_id", "old_epoch", "new_epoch", "guardian_pid",
        "guardian_created_filetime_100ns", "guardian_logon_id", "policy_instance_id", "policy_logon_id",
        "previous_revision", "registry_revision", "scope_count", "inventory_digest"),
    "adaptive_exemption_binding": ("singleton", "schema_version", "policy_instance_id", "policy_logon_id", "store_id"),
}
_REQUIRED = frozenset({"adaptive_runtime", "managed_executions", "adaptive_control_slot", "adaptive_actions",
    "adaptive_launch_requests", "adaptive_launch_fences", "adaptive_retirement_requests",
    "adaptive_prelaunch_retirements", "adaptive_infrastructure", "queue"})
_SPECIAL = frozenset({"adaptive_daily_generation", "adaptive_daily_retirement", "adaptive_experiment_demands",
    "adaptive_experiment_exclusions", "adaptive_experiment_cleanup_receipts", "adaptive_generation_successions"})
_EXPERIMENT_TABLES = frozenset({"adaptive_experiment_demands", "adaptive_experiment_exclusions",
    "adaptive_experiment_cleanup_receipts"})


def _refuse(reason):
    raise LifecycleError("daily_retirement_inventory_" + reason)


def _encoded(value):
    def convert(item):
        if type(item) is bytes:
            return {"sqlite_blob_hex": item.hex()}
        if isinstance(item, dict):
            return {key: convert(val) for key, val in item.items()}
        if isinstance(item, (tuple, list)):
            return [convert(val) for val in item]
        return item
    try:
        return json.dumps(convert(value), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError, OverflowError):
        _refuse("value_invalid")


class _Budget:
    def __init__(self):
        self.bytes = 0

    def add(self, value):
        self.charge(len(_encoded(value)))

    def charge(self, count):
        self.bytes += count
        if self.bytes > MAX_BYTES:
            _refuse("bytes_exceeded")


class RetirementInventorySnapshot:
    """Opaque observation, usable only by its original store and held guard."""
    __slots__ = ("__weakref__",)

    def __init__(self, *, _token=None):
        if _token is not _MINT:
            _refuse("original_snapshot_required")


def _guard(store):
    if type(store) is not LifecycleStore:
        _refuse("store_required")
    guard = store._policy.current_guard()
    if type(guard) is not PolicyGuard:
        _refuse("original_policy_required")
    store._policy.assert_held(guard)
    return guard


def _connection_path(conn, path):
    rows = conn.execute("PRAGMA database_list").fetchall()
    if (len(rows) != 1 or rows[0][1] != "main" or
            os.path.normcase(os.path.abspath(rows[0][2])) != os.path.normcase(str(path))):
        _refuse("ledger_changed")


@contextmanager
def _reader(path):
    """Keep the actual reader reachable if its close outcome is uncertain."""
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=.25, isolation_level=None)
    primary = None
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA trusted_schema=OFF")
        deadline = time.monotonic() + _READ_SECONDS
        conn.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        _connection_path(conn, path)
        conn.execute("BEGIN")
        yield conn
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            conn.close()
        except BaseException as error:
            if primary is not None:
                primary._daily_retirement_inventory_connection = conn
                primary._daily_retirement_inventory_cleanup_error = error
                primary.add_note("daily_retirement_inventory_reader_cleanup_unverified")
            else:
                error._daily_retirement_inventory_connection = conn
                error.add_note("daily_retirement_inventory_reader_cleanup_unverified")
                raise


def _rows(conn, table, columns, budget, *, limit=MAX_HISTORY, where=None, parameters=(), exclude_execution_ids=()):
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", table) or not columns or len(columns) > 128:
        _refuse("schema_unknown")
    if any(not re.fullmatch(r"[a-z_][a-z0-9_]*", name) for name in columns):
        _refuse("schema_unknown")
    from .experiment_history import MAX_RECEIPT_BYTES, TABLE as receipt_table
    valid = " AND ".join(f"({name} IS NULL OR length(CAST({name} AS BLOB))<=" +
        str(MAX_RECEIPT_BYTES if table == receipt_table and name == "receipt_json" else _CELL_BYTES) + ")"
        for name in columns)
    projection = ",".join(f"CASE WHEN {valid} THEN {name} END AS {name}" for name in columns)
    # The only filtered reader below supplies this fixed archive predicate.
    if where not in (None, "reservation_id=?"):
        _refuse("reader_scope_invalid")
    predicate = "" if where is None else " WHERE " + where
    if exclude_execution_ids:
        if table != "managed_executions" or where is not None or len(exclude_execution_ids) > MAX_HISTORY:
            _refuse("reader_scope_invalid")
        predicate = " WHERE execution_id NOT IN (" + ",".join("?" for _ in exclude_execution_ids) + ")"
        parameters = tuple(exclude_execution_ids)
    cursor = conn.execute(f"SELECT {projection},CASE WHEN {valid} THEN 1 ELSE 0 END AS bounded "
                          f"FROM {table}{predicate} ORDER BY rowid LIMIT ?", (*parameters, limit + 1))
    values = []
    for row in cursor:
        if len(values) >= limit:
            _refuse("history_exceeded")
        if row[-1] != 1:
            _refuse("cell_exceeded")
        value = dict(zip(columns, tuple(row)[:-1]))
        budget.add(value)
        values.append(value)
    return values


def _schema(conn, budget):
    # Do not fetch an arbitrarily large sqlite_master SQL string before bounding it.
    rows = conn.execute("""SELECT type,
        CASE WHEN length(CAST(name AS BLOB))<=256 THEN name END,
        CASE WHEN length(CAST(tbl_name AS BLOB))<=256 THEN tbl_name END,
        CASE WHEN length(CAST(sql AS BLOB))<=65536 THEN sql END AS sql,
        CASE WHEN sql IS NULL OR length(CAST(sql AS BLOB))<=65536 THEN 1 ELSE 0 END AS bounded
        FROM sqlite_master ORDER BY type,name LIMIT ?""", (_SCHEMA_LIMIT + 1,)).fetchall()
    if len(rows) > _SCHEMA_LIMIT or any(row[4] != 1 or row[1] is None or row[2] is None for row in rows):
        _refuse("schema_bound")
    schema = [tuple(row)[:4] for row in rows]
    budget.add(schema)
    tables = {row[1] for row in schema if row[0] == "table"}
    named = {row[1]: row[0] for row in schema}
    if not _REQUIRED <= tables:
        _refuse("schema_missing")
    if not {"request_key", "managed_execution_id"} <= {
            row[1] for row in conn.execute("PRAGMA table_info(queue)")}:
        _refuse("queue_schema_unknown")
    if any(row[0] in {"table", "view"} and row[1].startswith("adaptive_") and
           row[1] not in _LAYOUTS and row[1] not in _SPECIAL for row in schema):
        _refuse("schema_unknown")
    columns = {}
    for name in sorted((_LAYOUTS.keys() | _SPECIAL) & named.keys()):
        if named[name] != "table":
            _refuse("schema_unknown")
        actual = tuple(row[1] for row in conn.execute("PRAGMA table_info(" + name + ")"))
        if name in _LAYOUTS and set(actual) != set(_LAYOUTS[name]):
            _refuse("schema_unknown")
        columns[name] = actual
    return schema, columns


def _validate_schemas(conn, columns):
    # Legacy validators may fetch rows; first bound every relevant payload via
    # _rows, so damaged archive/metadata text cannot evade the aggregate limit.
    if not check_schema_version(conn):
        _refuse("schema_missing")
    for receipt in (terminal_receipt, prelaunch_receipt):
        if receipt._TABLE in columns:
            receipt._schema(conn)
    if "adaptive_experiment_demands" in columns:
        from .experiment_demand import _schema as experiment_schema
        experiment_schema(conn, create=False)
    if "adaptive_daily_generation" in columns:
        from .daily_generation import read_generation
        if read_generation(conn) is None:
            _refuse("generation_missing")
    if "adaptive_daily_retirement" in columns:
        from .daily_retirement_fence import read_retirement
        retirement = read_retirement(conn)
        if retirement is None or retirement["phase"] != "FROZEN":
            _refuse("freeze_unverified")
    if "adaptive_exemption_binding" in columns:
        from .exemption_sync import _intent
        _intent(conn)
    _infra_schema(conn)


def _read_ledger(conn, store, guard, budget):
    from . import experiment_history
    from . import daily_successor_history as successions
    store._policy.assert_held(guard)
    schema, columns = _schema(conn, budget)
    try:
        history = experiment_history.verify_experiment_history_locked(conn, max_bytes=MAX_BYTES - budget.bytes)
    except experiment_history.ExperimentHistoryError as error:
        if error.reason == "experiment_history_schema_invalid":
            raise LifecycleError("daily_retirement_inventory_schema_unknown") from None
        raise LifecycleError("daily_retirement_inventory_experiment_history_unverified") from None
    budget.charge(history.bytes_used)
    previous = successions.read_successor_history(conn, max_bytes=MAX_BYTES - budget.bytes)
    budget.charge(previous.bytes_used)
    if history.active_experiment_ids:
        _refuse("experiment_obligation_remaining")
    # Consume the original bounded SQL rows from the verifier, including actual
    # archive IDs and credential bytes. Receipt postimages are never substituted
    # for the ledger. The verifier's charges enter this shared budget once.
    observed = {}
    for row in history._sql_rows:
        observed.setdefault(row.table, []).append(dict(zip(row.fields, row.values)))
    observed[successions.TABLE] = [dict(zip(successions._FIELDS, entry._row)) for entry in previous.entries]
    completed = history.completed_execution_ids
    values = {}
    for name, fields in columns.items():
        if name in _EXPERIMENT_TABLES or name == successions.TABLE:
            values[name] = observed.get(name, [])
        elif name == "managed_executions":
            historical = observed.get(name, [])
            production = _rows(conn, name, fields, budget, limit=MAX_HISTORY - len(historical),
                               exclude_execution_ids=tuple(sorted(completed)))
            values[name] = sorted(historical + production, key=lambda row: row["execution_id"])
        else:
            values[name] = _rows(conn, name, fields, budget)
    experiment_archives = observed.get("executions", [])
    _validate_schemas(conn, columns)
    runtime = dict(store._policy.revalidate(conn, guard))
    if runtime["mode"] != "off" or runtime["admission_barrier"] != "NONE":
        _refuse("runtime_unsettled")
    for table in ("reservations", "worker_reservations", "adaptive_infrastructure"):
        if conn.execute("SELECT 1 FROM " + table + " LIMIT 1").fetchone() is not None:
            _refuse("allocation_remaining" if table != "adaptive_infrastructure" else "infrastructure_remaining")
    managed = values["managed_executions"]
    if any(row["state"] not in TERMINAL_STATES for row in managed):
        _refuse("scope_unretired")
    if any(row["parent_execution_id"] is not None or row["allocation_kind"] not in {"direct", "routed"}
           or row["job_name"] is None or row["job_nonce"] is None
           for row in managed if row["execution_id"] not in completed):
        _refuse("scope_proof_unsupported")
    by_id = {row["execution_id"]: row for row in managed}
    if len(by_id) != len(managed):
        _refuse("scope_duplicate")
    # Unrelated queued work remains parked behind the permanent admission
    # freeze. A queued request for a supposedly retired scope is conflicting
    # lifecycle evidence, including FINISHED receipts whose old reader did not
    # inspect queue. Repeat this predicate in final SQL revalidation as well.
    if conn.execute("""SELECT 1 FROM queue q JOIN managed_executions m
            ON q.managed_execution_id=m.execution_id LIMIT 1""").fetchone() is not None:
        _refuse("retired_scope_queued")
    # Every execution-associated side record belongs to one positively closed
    # scope. These permanent records are not deleted to produce an empty ledger.
    for name, rows in values.items():
        if name == "managed_executions" or name in _EXPERIMENT_TABLES:
            continue
        for row in rows:
            if "execution_id" in row:
                target = by_id.get(row["execution_id"])
                if target is None or ("guardian_epoch" in row and row["guardian_epoch"] != target["guardian_epoch"]):
                    _refuse("orphan_scope_record")
                if "spec_hash" in row and row["spec_hash"] != target["spec_hash"]:
                    _refuse("scope_record_changed")
    for hold in values.get("adaptive_off_holds", ()):
        if type(hold["cleared_revision"]) is not int or not 0 <= hold["cleared_revision"] <= runtime["registry_revision"]:
            _refuse("off_hold_unsettled")
    slot = control_slot.query_locked(conn, runtime, guard)
    if slot is not None and (slot["slot_state"] != "RESTORED" or by_id[slot["execution_id"]]["state"] != "FINISHED"):
        _refuse("slot_unsettled")
    actions = values["adaptive_actions"]
    tails = {}
    seen_actions = set()
    for action in actions:
        if (action["action_state"] not in control_slot._ACTION_STATES or
                not control_slot._integer(action["decision_seq"]) or
                not control_slot._integer(action["sample_seq"]) or
                not control_slot._uuid(action["action_id"]) or
                action["desired_mode"] not in {"disabled", "hard_cap"} or
                not control_slot._text(action["reason"], 128) or
                re.fullmatch(r"[A-Za-z0-9_.:@-]+", action["reason"]) is None):
            _refuse("action_invalid")
        identity = (action["guardian_epoch"], action["execution_id"], action["decision_seq"])
        if identity in seen_actions:
            _refuse("action_duplicate")
        seen_actions.add(identity)
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
                not control_slot._integer(action["applied_tick_100ns"], minimum=1) or
                action["lease_deadline_tick_100ns"] is not None):
            _refuse("action_tail_unsettled")
    if writer_obligations_present(conn):
        _refuse("writer_obligation_remaining")
    return {"schema": schema, "tables": values, "experiment_execution_ids": sorted(completed),
            "experiment_archives": experiment_archives}


def _journal_names(journal, expected):
    journal._check_directory()
    found = set()
    entries = os.scandir(journal._directory)
    primary = None
    try:
        for entry in entries:
            if len(found) >= MAX_HISTORY:
                _refuse("history_exceeded")
            # Windows DirEntry.stat reports zero file identity fields in
            # Python 3.13. Query the exact path without following reparses;
            # keep the same strict identity/type checks used by journal.read.
            _safe_stat(os.stat(journal._directory / entry.name, follow_symlinks=False))
            if entry.name not in expected or entry.name in found:
                _refuse("journal_extra_entry")
            found.add(entry.name)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            entries.close()
        except BaseException as error:
            target = primary if primary is not None else error
            target._daily_retirement_inventory_directory_reader = entries
            target._daily_retirement_inventory_cleanup_error = error
            target.add_note("daily_retirement_inventory_directory_cleanup_unverified")
            if primary is None:
                raise
    if found != set(expected):
        _refuse("journal_scope_missing")
    journal._check_directory()
    return found


def _journal_inventory(journal, rows, budget):
    if type(journal) is not RecoveryJournal:
        _refuse("journal_required")
    expected = {row["execution_id"] + ".json": row for row in rows}
    found = _journal_names(journal, expected)
    records = {}
    for name in sorted(found):
        row = expected[name]
        record = journal.read(row["execution_id"], creation_nonce=row["job_nonce"])
        if (type(record) is not RecoveryManifest or record.original != _DISABLED or
                record.pending_intent is not None or record.last_applied not in (None, _DISABLED)):
            _refuse("manifest_unsettled")
        budget.add(record.to_dict())
        records[row["execution_id"]] = record
    # Include entries created during the bounded read, rather than certifying
    # only the earlier directory page. POLICY excludes cooperating publishers.
    _journal_names(journal, expected)
    return records


def _receipts(conn, store, ledger, records, budget):
    result = {}
    for raw in ledger["tables"]["managed_executions"]:
        if raw["execution_id"] in ledger["experiment_execution_ids"]:
            # Complete original SQL receipt/archive rows are already in ledger.
            continue
        row = store._public(raw)
        record = records[row["execution_id"]]
        archive_table = "executions" if row["allocation_kind"] == "direct" else "routed_executions"
        if not any(kind == "table" and name == archive_table for kind, name, _, _ in ledger["schema"]):
            _refuse("archive_schema_unknown")
        archive_columns = tuple(item[1] for item in conn.execute("PRAGMA table_info(" + archive_table + ")"))
        archives = _rows(conn, archive_table, archive_columns, budget, limit=2,
                         where="reservation_id=?", parameters=(row["reservation_id"],))
        if row["allocation_kind"] == "direct":
            for archive in archives:
                request_key = archive.get("request_key")
                if type(request_key) is not str or not request_key:
                    _refuse("archive_request_key_invalid")
                if conn.execute("SELECT 1 FROM queue WHERE request_key=? LIMIT 1",
                                (request_key,)).fetchone() is not None:
                    _refuse("retired_scope_queued")
        module = terminal_receipt if row["state"] == "FINISHED" else prelaunch_receipt
        receipt = module._verified_record(conn, store, row, record)
        budget.add(receipt)
        result[row["execution_id"]] = {"receipt": receipt, "archives": archives}
    return result


def _serialized_bound(ledger, receipts, records):
    # Also cover list/dict framing and original BLOB encoding, beyond the row
    # charges shared with the history verifier. Every retained snapshot payload
    # belongs to this one aggregate allowance.
    size = len(_encoded(ledger)) + len(_encoded(receipts))
    size += sum(len(records[key].to_json().encode("utf-8")) for key in records)
    if size > MAX_BYTES:
        _refuse("bytes_exceeded")


def capture_retirement_inventory(store, journal):
    """Capture exact closed history while the caller retains original POLICY.

    All journal I/O precedes the final short SQL validation. No terminal state,
    hash, or caller-provided boolean substitutes for the original custody receipt.
    """
    guard = _guard(store)
    if type(journal) is not RecoveryJournal:
        _refuse("journal_required")
    path = terminal_receipt._ledger_path(store)
    budget = _Budget()
    with _reader(path) as conn:
        ledger = _read_ledger(conn, store, guard, budget)
    production = [row for row in ledger["tables"]["managed_executions"]
                  if row["execution_id"] not in ledger["experiment_execution_ids"]]
    records = _journal_inventory(journal, production, budget)
    with _reader(path) as conn:
        current = _read_ledger(conn, store, guard, _Budget())
        if current != ledger:
            _refuse("ledger_changed")
        receipts = _receipts(conn, store, current, records, budget)
    _serialized_bound(ledger, receipts, records)
    store._policy.assert_held(guard)
    snapshot = RetirementInventorySnapshot(_token=_MINT)
    _SNAPSHOTS[snapshot] = (store, journal, guard, path, os.getpid(), threading.get_ident(),
                            _encoded(ledger), _encoded(receipts), records,
                            journal._directory, journal._directory_ids)
    return snapshot


def revalidate_retirement_inventory(conn, store, snapshot):
    """Recheck the exact snapshot under its same original POLICY transaction.

    No filesystem/native queries occur in this transaction. The held POLICY,
    durable admission freeze, exact closed-custody receipts and original host's
    separately verified supervisor closure exclude cooperating journal writers.
    """
    captured = _SNAPSHOTS.get(snapshot) if type(snapshot) is RetirementInventorySnapshot else None
    if captured is None:
        _refuse("original_snapshot_required")
    owner, journal, guard, path, pid, thread, ledger_bytes, receipt_bytes, records, directory, directory_ids = captured
    if (store is not owner or _guard(store) is not guard or os.getpid() != pid or
            threading.get_ident() != thread or not conn.in_transaction or
            journal._directory != directory or journal._directory_ids != directory_ids):
        _refuse("snapshot_scope_changed")
    _connection_path(conn, path)
    budget = _Budget()
    current = _read_ledger(conn, store, guard, budget)
    if _encoded(current) != ledger_bytes:
        _refuse("ledger_changed")
    receipts = _receipts(conn, store, current, records, budget)
    _serialized_bound(current, receipts, records)
    if _encoded(receipts) != receipt_bytes:
        _refuse("receipt_changed")
    return None


def retirement_inventory_digest(store, snapshot):
    """Digest this original guarded observation; never mint adoption authority."""
    captured = _SNAPSHOTS.get(snapshot) if type(snapshot) is RetirementInventorySnapshot else None
    if captured is None:
        _refuse("original_snapshot_required")
    owner, journal, guard, path, pid, thread, ledger_bytes, receipt_bytes, records, directory, directory_ids = captured
    if (store is not owner or _guard(store) is not guard or os.getpid() != pid or
            threading.get_ident() != thread or journal._directory != directory or
            journal._directory_ids != directory_ids):
        _refuse("snapshot_scope_changed")
    digest = hashlib.sha256(b"resource-sentinel.daily-retirement-inventory.v1\x00")
    for value in (ledger_bytes, receipt_bytes,
                  *(records[key].to_json().encode("utf-8") for key in sorted(records))):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _retired_inventory_parts(operation):
    """Recheck the original registered capture, without borrowing its old guard.

    Internal to the completed-owner assertion; the public reader first calls
    that assertion. Returned bytes are observations, never a POLICY capability.
    """
    from .daily_retirement import DailyRetirementOperation
    if type(operation) is not DailyRetirementOperation:
        _refuse("completed_retirement_required")
    snapshot, pin = operation._seal_inventory, operation._seal_inventory_pin
    captured = _SNAPSHOTS.get(snapshot) if type(snapshot) is RetirementInventorySnapshot else None
    if (captured is None or type(pin) is not tuple or len(pin) != 3 or snapshot is not pin[0] or
            captured is not pin[1] or operation._seal_inventory_digest != pin[2]):
        _refuse("original_snapshot_required")
    owner, journal, guard, path, pid, thread, ledger_bytes, receipt_bytes, records, directory, directory_ids = captured
    if (owner is not operation.store or journal is not operation.journal or guard is not operation._seal_guard or
            path != operation.owner.ledger_path or os.getpid() != pid or threading.get_ident() != thread or
            journal._directory != directory or journal._directory_ids != directory_ids or
            type(ledger_bytes) is not bytes or type(receipt_bytes) is not bytes or type(records) is not dict or
            len(records) > MAX_HISTORY or any(type(key) is not str or type(record) is not RecoveryManifest or
                key != record.execution_id
                for key, record in records.items())):
        _refuse("snapshot_scope_changed")
    journals = tuple((key, records[key].to_json().encode("utf-8")) for key in sorted(records))
    parts = (ledger_bytes, receipt_bytes, *(value for _, value in journals))
    if sum(len(value) for value in parts) > MAX_BYTES:
        _refuse("bytes_exceeded")
    digest = hashlib.sha256(b"resource-sentinel.daily-retirement-inventory.v1\x00")
    for value in parts:
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    if digest.hexdigest() != pin[2]:
        _refuse("snapshot_digest_changed")
    return ledger_bytes, receipt_bytes, journals


def retired_inventory_preimage(operation):
    """Immutable source evidence from the exact positively retired original.

    Returns ``(ledger_bytes, receipt_bytes, ((execution_id, manifest_bytes),
    ...))`` in execution-ID order. No DB, journal, native handle or held guard
    is consulted, and no mutation or authority is granted by these bytes.
    """
    from .daily_retirement import DailyRetirementOperation
    if type(operation) is not DailyRetirementOperation:
        _refuse("completed_retirement_required")
    operation.assert_successor_predecessor()
    return _retired_inventory_parts(operation)
