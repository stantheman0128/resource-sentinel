"""Bounded isolated S1 bookkeeping, never admission or native cleanup proof.

The original native scope supplies observations while holding its exact Job
mutex and isolated POLICY. This module verifies POLICY and SQLite ownership;
it does not acquire a Job, authorize Set, adopt processes, or release capacity.
No production lifecycle, control-slot, or C2 record is changed here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
from uuid import UUID

from .contracts import ProcessIdentity
from .native_job import CpuState, ENABLE, HARD_CAP
from .store import LifecycleStore


TABLE = "adaptive_experiment_scope_journal"
DISABLED = CpuState(0, 0)
S1_CAP = CpuState(ENABLE | HARD_CAP, 2500)
_BINDING = frozenset(("schema_version", "experiment_id", "scope_id",
    "daily_execution_id", "reservation_id", "isolated_ledger_identity",
    "job_name", "creation_nonce", "guardian_identity", "wrapper_identity",
    "command_sha256", "source_generation", "source_digest", "config_digest",
    "deadline_monotonic_ns"))
_TABLE_SQL = """CREATE TABLE adaptive_experiment_scope_journal (
    scope_id TEXT PRIMARY KEY, binding_json TEXT NOT NULL, binding_sha256 TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PREPARED','LAUNCH_INTENT','LAUNCH_UNKNOWN',
        'RUNNING','SEALED_UNCREATED','NEVER_LAUNCHED','FINISHED')),
    revision INTEGER NOT NULL CHECK(revision>=0),
    launch_sealed INTEGER NOT NULL CHECK(launch_sealed IN (0,1)),
    root_json TEXT, last_applied_json TEXT, pending_target_json TEXT,
    root_exit_code INTEGER, total_processes INTEGER)"""
_TRIGGERS = {
    "experiment_scope_journal_delete_guard": """CREATE TRIGGER experiment_scope_journal_delete_guard
        BEFORE DELETE ON adaptive_experiment_scope_journal
        BEGIN SELECT RAISE(ABORT,'experiment_scope_history_immutable'); END""",
    "experiment_scope_journal_update_guard": """CREATE TRIGGER experiment_scope_journal_update_guard
        BEFORE UPDATE ON adaptive_experiment_scope_journal WHEN
            NEW.scope_id IS NOT OLD.scope_id OR NEW.binding_json IS NOT OLD.binding_json OR
            NEW.binding_sha256 IS NOT OLD.binding_sha256 OR NEW.revision!=OLD.revision+1 OR
            NEW.launch_sealed<OLD.launch_sealed OR OLD.state IN ('NEVER_LAUNCHED','FINISHED')
        BEGIN SELECT RAISE(ABORT,'experiment_scope_transition_invalid'); END""",
}


class ScopeJournalError(RuntimeError):
    pass


def _deny(reason):
    raise ScopeJournalError("experiment_scope_journal_" + reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _sql(value):
    return " ".join(value.split()).rstrip(";") if type(value) is str else None


def _uuid(value):
    try:
        return type(value) is str and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _identity(path):
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            _deny("ledger_reparse_point")
    info = path.stat()
    return (int(info.st_dev), int(info.st_ino))


def _cpu(value):
    if type(value) is not CpuState or type(value.flags) is not int or type(value.rate_bp) is not int:
        _deny("cpu_state_invalid")
    # Disabled unions are unspecified native readback; canonicalize only when
    # ENABLE is clear. Unknown enabled modes/rates never become S1 authority.
    if value.flags < 0 or value.flags > 0xFFFFFFFF or value.rate_bp < 0 or value.rate_bp > 0xFFFFFFFF:
        _deny("cpu_state_invalid")
    result = DISABLED if not value.flags & ENABLE else value
    if result not in (DISABLED, S1_CAP):
        _deny("cpu_state_external")
    return {"flags": result.flags, "rate_bp": result.rate_bp}


def _process(value):
    try:
        result = ProcessIdentity.from_dict(value)
    except (TypeError, ValueError, KeyError):
        _deny("identity_invalid")
    if (result.to_dict() != value or not re.fullmatch(r"S-1-5-5-[0-9]{1,10}-[0-9]{1,10}", result.logon_id) or
            any(int(part) > 0xFFFFFFFF for part in result.logon_id.split("-")[-2:])):
        _deny("identity_invalid")
    return result


def _binding(value):
    if type(value) is not dict or value.keys() != _BINDING:
        _deny("binding_invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _deny("binding_invalid")
    for key in ("experiment_id", "scope_id", "daily_execution_id", "source_generation"):
        if not _uuid(value[key]):
            _deny("binding_invalid")
    reservation = value["reservation_id"]
    if type(reservation) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", reservation):
        _deny("binding_invalid")
    for key in ("command_sha256", "source_digest", "config_digest"):
        if type(value[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value[key]):
            _deny("binding_invalid")
    nonce = value["creation_nonce"]
    if (type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{32}", nonce) or
            value["job_name"] != "Local\\ResourceSentinel.Test.Job." + nonce):
        _deny("binding_invalid")
    identity = value["isolated_ledger_identity"]
    if (type(identity) is not list or len(identity) != 2 or
            any(type(part) is not int or part < 0 for part in identity) or identity[1] == 0 or
            type(value["deadline_monotonic_ns"]) is not int or not 0 < value["deadline_monotonic_ns"] < 1 << 63):
        _deny("binding_invalid")
    guardian, wrapper = (_process(value[key]) for key in ("guardian_identity", "wrapper_identity"))
    if guardian.logon_id != wrapper.logon_id or guardian == wrapper or guardian.pid == wrapper.pid:
        _deny("actors_invalid")
    return json.loads(_canonical(value))


class ScopeJournal:
    def __init__(self, store, scope_id):
        if type(store) is not LifecycleStore:
            # The original native owner retains uncertain connection cleanup in
            # this one concrete subclass; arbitrary store substitutes are not
            # ledger or POLICY authority.
            from .experiment_scope import _IsolatedStore
            if type(store) is not _IsolatedStore:
                _deny("owner_invalid")
        if not _uuid(scope_id):
            _deny("owner_invalid")
        self.store, self.scope_id = store, scope_id
        self._path = Path(store.db_path).absolute()
        self._ledger_identity = _identity(self._path)

    def _locked(self, conn, *, create=False):
        if not conn.in_transaction:
            _deny("transaction_required")
        if Path(self.store.db_path).absolute() != self._path or _identity(self._path) != self._ledger_identity:
            _deny("ledger_changed")
        databases = conn.execute("PRAGMA database_list").fetchall()
        if len(databases) != 1 or databases[0][1] != "main" or Path(databases[0][2]).absolute() != self._path:
            _deny("ledger_changed")
        policy = self.store._policy
        guard = policy.assert_held()
        policy.revalidate(conn, guard)
        rows = conn.execute("""SELECT name,type,sql FROM sqlite_master WHERE name=?
            OR name LIKE 'experiment_scope_journal_%' OR (type='trigger' AND tbl_name=?)""",
            (TABLE, TABLE)).fetchall()
        actual = {row[0]: (row[1], _sql(row[2])) for row in rows}
        expected = {TABLE: ("table", _sql(_TABLE_SQL)),
                    **{name: ("trigger", _sql(sql)) for name, sql in _TRIGGERS.items()}}
        if not actual and create:
            conn.execute(_TABLE_SQL)
            for sql in _TRIGGERS.values():
                conn.execute(sql)
        elif actual != expected:
            _deny("schema_unknown")
        if conn.execute("SELECT count(*) FROM " + TABLE).fetchone()[0] > 1:
            _deny("inventory_unbounded")
        return guard

    def initialize_locked(self, conn, binding):
        guard = self._locked(conn, create=True)
        binding = _binding(binding)
        if (binding["scope_id"] != self.scope_id or
                tuple(binding["isolated_ledger_identity"]) != self._ledger_identity or
                binding["guardian_identity"]["logon_id"] != guard.binding.logon_id):
            _deny("binding_mismatch")
        old = conn.execute("SELECT scope_id FROM " + TABLE).fetchone()
        if old is not None:
            row = self.read_locked(conn)
            if any(row[key] != value for key, value in binding.items()):
                _deny("binding_mismatch")
            return row
        encoded = _canonical(binding)
        conn.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,'PREPARED',0,0,NULL,NULL,NULL,NULL,NULL)",
            (self.scope_id, encoded, hashlib.sha256(encoded.encode()).hexdigest()))
        return self.read_locked(conn)

    def read_locked(self, conn):
        guard = self._locked(conn)
        value = conn.execute("SELECT * FROM " + TABLE + " WHERE scope_id=?", (self.scope_id,)).fetchone()
        if value is None:
            _deny("missing")
        row = dict(value)
        try:
            binding = _binding(json.loads(row["binding_json"]))
            if (row["binding_json"] != _canonical(binding) or
                    row["binding_sha256"] != hashlib.sha256(row["binding_json"].encode()).hexdigest() or
                    binding["scope_id"] != self.scope_id or
                    tuple(binding["isolated_ledger_identity"]) != self._ledger_identity or
                    binding["guardian_identity"]["logon_id"] != guard.binding.logon_id):
                _deny("binding_mismatch")
            for key in ("root", "last_applied", "pending_target"):
                raw = row.pop(key + "_json")
                row[key if key == "root" else key + "_cpu"] = None if raw is None else json.loads(raw)
                if raw is not None and raw != _canonical(json.loads(raw)):
                    _deny("row_invalid")
            if row["root"] is not None:
                root = _process(row["root"])
                if root.logon_id != guard.binding.logon_id or root.pid in (
                        binding["guardian_identity"]["pid"], binding["wrapper_identity"]["pid"]):
                    _deny("row_invalid")
            for key in ("last_applied_cpu", "pending_target_cpu"):
                state = row[key]
                if state is not None and (type(state) is not dict or state.keys() != {"flags", "rate_bp"} or
                        _cpu(CpuState(**state)) != state):
                    _deny("row_invalid")
            self._validate_row(row)
        except (TypeError, ValueError, KeyError):
            _deny("row_invalid")
        del row["binding_json"]
        row.update(binding)
        row["original_cpu"] = _cpu(DISABLED)
        return row

    @staticmethod
    def _validate_row(row):
        state = row["state"]
        terminal = state in {"NEVER_LAUNCHED", "FINISHED"}
        has_root = state in {"RUNNING", "FINISHED"}
        if (type(row["revision"]) is not int or row["revision"] < 0 or
                type(row["launch_sealed"]) is not int or row["launch_sealed"] not in (0, 1) or
                state not in {"PREPARED", "LAUNCH_INTENT", "LAUNCH_UNKNOWN", "RUNNING", "SEALED_UNCREATED", "NEVER_LAUNCHED", "FINISHED"} or
                has_root != (row["root"] is not None) or
                state in {"LAUNCH_INTENT", "LAUNCH_UNKNOWN"} and row["launch_sealed"] or
                state == "SEALED_UNCREATED" and not row["launch_sealed"] or
                not terminal and (row["total_processes"] is not None or row["root_exit_code"] is not None)):
            _deny("row_invalid")
        if terminal and (not row["launch_sealed"] or row["pending_target_cpu"] is not None or
                row["last_applied_cpu"] not in (None, _cpu(DISABLED))):
            _deny("terminal_unsettled")
        if state == "NEVER_LAUNCHED" and (row["total_processes"] != 0 or row["root_exit_code"] is not None):
            _deny("row_invalid")
        if state == "FINISHED" and (type(row["total_processes"]) is not int or row["total_processes"] < 1 or
                type(row["root_exit_code"]) is not int or not 0 <= row["root_exit_code"] <= 0xFFFFFFFF):
            _deny("row_invalid")

    def _current(self, conn, expected_revision):
        row = self.read_locked(conn)
        if expected_revision is not None and (type(expected_revision) is not int or expected_revision != row["revision"]):
            _deny("revision_conflict")
        return row

    def _update(self, conn, row, **changes):
        if row["state"] in {"NEVER_LAUNCHED", "FINISHED"}:
            _deny("terminal_immutable")
        assignments = ",".join(key + "=?" for key in changes)
        count = conn.execute("UPDATE " + TABLE + " SET " + assignments +
            ",revision=revision+1 WHERE scope_id=? AND revision=?",
            (*changes.values(), self.scope_id, row["revision"])).rowcount
        if count != 1:
            _deny("revision_conflict")
        return self.read_locked(conn)

    def begin_launch_locked(self, conn, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        if row["state"] != "PREPARED" or row["launch_sealed"] or row["pending_target_cpu"] is not None:
            _deny("launch_unavailable")
        return self._update(conn, row, state="LAUNCH_INTENT")

    def acknowledge_launch_locked(self, conn, root, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        if type(root) is not ProcessIdentity or row["state"] not in {"LAUNCH_INTENT", "LAUNCH_UNKNOWN"}:
            _deny("launch_unavailable")
        if root.logon_id != row["guardian_identity"]["logon_id"] or root.pid in (
                row["guardian_identity"]["pid"], row["wrapper_identity"]["pid"]):
            _deny("identity_invalid")
        return self._update(conn, row, state="RUNNING", root_json=_canonical(root.to_dict()))

    def mark_launch_unknown_locked(self, conn, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        if row["state"] == "LAUNCH_UNKNOWN":
            return row
        if row["state"] != "LAUNCH_INTENT":
            _deny("launch_unavailable")
        return self._update(conn, row, state="LAUNCH_UNKNOWN")

    def seal_launch_locked(self, conn, outcome, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        if (outcome == "never_launched" and row["state"] in {"SEALED_UNCREATED", "NEVER_LAUNCHED"} or
                outcome == "started" and row["state"] == "FINISHED"):
            return row
        if {"never_launched": "PREPARED", "started": "RUNNING"}.get(outcome) != row["state"]:
            _deny("seal_unavailable")
        return row if row["launch_sealed"] else self._update(conn, row, launch_sealed=1)

    def seal_uncreated_locked(self, conn, *, expected_revision=None):
        """Record the original owner's positively verified no-creation seal.

        The caller must retain original launcher custody, its authenticated
        no-dispatch/not-created outcome and original Job total-process count
        zero. Missing root, deadline or this journal row proves none of those.
        This is bookkeeping only: no native proof is accepted as a boolean,
        launch is never reset, and daily demand remains retained.
        """
        row = self._current(conn, expected_revision)
        if row["state"] in {"SEALED_UNCREATED", "NEVER_LAUNCHED"}:
            return row
        if (row["state"] not in {"PREPARED", "LAUNCH_INTENT", "LAUNCH_UNKNOWN"} or
                row["root"] is not None or row["pending_target_cpu"] is not None):
            _deny("uncreated_seal_unavailable")
        return self._update(conn, row, state="SEALED_UNCREATED", launch_sealed=1)

    def begin_control_locked(self, conn, target, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        target = _cpu(target)
        if row["state"] not in {"PREPARED", "RUNNING"}:
            _deny("control_unavailable")
        if row["pending_target_cpu"] is not None:
            if row["pending_target_cpu"] != target:
                _deny("intent_pending")
            return row
        return self._update(conn, row, pending_target_json=_canonical(target))

    def begin_restore_locked(self, conn, observed, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        observed = _cpu(observed)
        if observed not in (row["original_cpu"], row["last_applied_cpu"], row["pending_target_cpu"]):
            _deny("restore_conflict")
        if row["state"] in {"NEVER_LAUNCHED", "FINISHED"} and observed == _cpu(DISABLED):
            return row
        if row["pending_target_cpu"] == _cpu(DISABLED):
            return row
        # The exact query also settles a lost acknowledgement of the previous
        # Set. Preserve that observed cap before replacing its pending intent;
        # a crash before Disable must still permit the same original restore.
        return self._update(conn, row, last_applied_json=_canonical(observed),
                            pending_target_json=_canonical(_cpu(DISABLED)))

    def acknowledge_control_locked(self, conn, observed, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        observed = _cpu(observed)
        if row["state"] in {"NEVER_LAUNCHED", "FINISHED"} and observed == _cpu(DISABLED):
            return row
        if row["pending_target_cpu"] is None and row["last_applied_cpu"] == observed:
            return row
        if row["pending_target_cpu"] != observed:
            _deny("control_ack_mismatch")
        return self._update(conn, row, last_applied_json=_canonical(observed), pending_target_json=None)

    def finish_locked(self, conn, root_exit_code, total_processes, *, expected_revision=None):
        row = self._current(conn, expected_revision)
        if (type(total_processes) is not int or total_processes < 0 or not row["launch_sealed"] or
                row["pending_target_cpu"] is not None or row["last_applied_cpu"] not in (None, _cpu(DISABLED))):
            _deny("finish_unsettled")
        if row["state"] in {"NEVER_LAUNCHED", "FINISHED"}:
            if (type(root_exit_code) is type(row["root_exit_code"]) and
                    root_exit_code == row["root_exit_code"] and total_processes == row["total_processes"]):
                return row
            _deny("finish_invalid")
        if row["state"] in {"PREPARED", "SEALED_UNCREATED"} and total_processes == 0 and root_exit_code is None:
            state = "NEVER_LAUNCHED"
        elif (row["state"] == "RUNNING" and total_processes >= 1 and type(root_exit_code) is int and
                0 <= root_exit_code <= 0xFFFFFFFF):
            state = "FINISHED"
        else:
            _deny("finish_invalid")
        return self._update(conn, row, state=state, root_exit_code=root_exit_code, total_processes=total_processes)
