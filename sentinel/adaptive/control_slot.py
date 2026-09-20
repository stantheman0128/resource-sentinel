"""One conservative control-responsibility slot, never a capacity ledger.

HELD covers intent, an uncertain Set and an applied cap alike. SQLite records
neither native control authority nor a lease renewal. The lifecycle store owns
POLICY and native evidence scopes; these helpers perform only bounded SQL and
pure validation inside its existing short transaction.
"""
from __future__ import annotations

import re
import sqlite3
from uuid import UUID

from .contracts import ProcessIdentity


class ControlSlotError(ValueError):
    pass


_MAX_INT = (1 << 63) - 1
_TERMINAL = {"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"}
_FIELDS = (
    "singleton", "schema_version", "slot_id", "slot_revision", "slot_state",
    "execution_id", "job_name", "job_nonce", "guardian_epoch", "logon_id",
    "owner_pid", "owner_created_filetime_100ns", "policy_instance_id",
    "policy_logon_id", "exemption_revision",
)
_BINDINGS = (
    "execution_id", "job_name", "job_nonce", "guardian_epoch", "logon_id",
    "owner_pid", "owner_created_filetime_100ns", "policy_instance_id", "policy_logon_id",
)


def _integer(value, *, minimum=0):
    return type(value) is int and minimum <= value <= _MAX_INT


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        return parsed is not None and parsed.int != 0 and str(parsed) == value
    except (ValueError, AttributeError):
        return False


def _text(value, bound):
    return type(value) is str and 1 <= len(value) <= bound and all(ord(c) >= 32 for c in value)


def _transaction(conn):
    if not conn.in_transaction:
        raise ControlSlotError("control_slot_transaction_required")


def migrate_control_slot_schema(conn):
    """Add one empty slot table inside the caller-owned schema transaction."""
    _transaction(conn)
    found = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_control_slot'").fetchone()
    if found is not None and found[0] != "table":
        raise ControlSlotError("control_slot_schema_unsupported")
    conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_control_slot (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        schema_version INTEGER NOT NULL CHECK(typeof(schema_version)='integer' AND schema_version=1),
        slot_id TEXT NOT NULL,
        slot_revision INTEGER NOT NULL CHECK(typeof(slot_revision)='integer' AND slot_revision>=1),
        slot_state TEXT NOT NULL CHECK(slot_state IN ('HELD','RESTORED')),
        execution_id TEXT NOT NULL, job_name TEXT NOT NULL, job_nonce TEXT NOT NULL,
        guardian_epoch TEXT NOT NULL, logon_id TEXT NOT NULL,
        owner_pid INTEGER NOT NULL CHECK(typeof(owner_pid)='integer' AND owner_pid>0),
        owner_created_filetime_100ns TEXT NOT NULL,
        policy_instance_id TEXT NOT NULL, policy_logon_id TEXT NOT NULL,
        exemption_revision INTEGER NOT NULL CHECK(typeof(exemption_revision)='integer' AND exemption_revision>=0)
    )""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(adaptive_control_slot)")}
    if columns != set(_FIELDS):
        raise ControlSlotError("control_slot_schema_unsupported")


def read_slot(conn):
    """Unknown, malformed and oversized persisted bindings are never free."""
    _transaction(conn)
    try:
        # Bound strings in SQL before fetching them, including damaged records.
        columns = []
        for name in _FIELDS:
            if name in {"singleton", "schema_version", "slot_revision", "owner_pid", "exemption_revision"}:
                columns.append(f"CASE WHEN typeof({name})='integer' THEN {name} END AS {name}")
            else:
                bound = 256 if name == "job_name" else 128
                # length(TEXT) stops at NUL. Bound UTF-8 bytes before fetching
                # damaged strings; the Python validators then enforce syntax.
                columns.append(f"CASE WHEN typeof({name})='text' AND length(CAST({name} AS BLOB))<={bound * 4} THEN {name} END AS {name}")
        cursor = conn.execute("SELECT " + ",".join(columns) + " FROM adaptive_control_slot LIMIT 2")
        rows = cursor.fetchall()
    except sqlite3.Error:
        raise ControlSlotError("control_slot_registry_unavailable") from None
    if not rows:
        return None
    if len(rows) != 1:
        raise ControlSlotError("control_slot_invalid")
    row = dict(zip(_FIELDS, rows[0]))
    if (row["singleton"] != 1 or row["schema_version"] != 1 or
            not _uuid(row["slot_id"]) or not _uuid(row["execution_id"]) or
            not _integer(row["slot_revision"], minimum=1) or
            row["slot_state"] not in {"HELD", "RESTORED"} or
            not _integer(row["exemption_revision"]) or
            not _text(row["guardian_epoch"], 128) or
            not _uuid(row["policy_instance_id"]) or
            not _text(row["logon_id"], 128) or row["policy_logon_id"] != row["logon_id"] or
            not _text(row["job_nonce"], 32) or not re.fullmatch(r"[0-9a-f]{32}", row["job_nonce"]) or
            row["job_name"] not in {
                f"Local\\ResourceSentinel.Job.{row['execution_id']}.{row['job_nonce']}",
                f"Local\\ResourceSentinel.Test.Job.{row['job_nonce']}"}):
        raise ControlSlotError("control_slot_invalid")
    try:
        ProcessIdentity.from_dict({"pid": row["owner_pid"],
            "created_filetime_100ns": row["owner_created_filetime_100ns"], "logon_id": row["logon_id"]})
    except (ValueError, TypeError):
        raise ControlSlotError("control_slot_invalid") from None
    try:
        matches = conn.execute("""SELECT count(*) FROM managed_executions
            WHERE execution_id=? AND job_name IS ? AND job_nonce IS ? AND guardian_epoch IS ?
              AND logon_id IS ? AND wrapper_pid IS ? AND wrapper_created_filetime_100ns IS ?""",
            (row["execution_id"], row["job_name"], row["job_nonce"], row["guardian_epoch"],
             row["logon_id"], row["owner_pid"], row["owner_created_filetime_100ns"])).fetchone()[0]
    except sqlite3.Error:
        raise ControlSlotError("control_slot_registry_unavailable") from None
    if matches != 1:
        # A valid-looking different UUID is not proof that another execution
        # owns this responsibility, especially in the independent test namespace.
        raise ControlSlotError("control_slot_binding_mismatch")
    return row


def _binding(row, guard):
    value = {
        "execution_id": row["execution_id"], "job_name": row["job_name"],
        "job_nonce": row["job_nonce"], "guardian_epoch": row["guardian_epoch"],
        "logon_id": row["logon_id"], "owner_pid": row["wrapper_pid"],
        "owner_created_filetime_100ns": row["wrapper_created_filetime_100ns"],
        "policy_instance_id": guard.binding.instance_id, "policy_logon_id": guard.binding.logon_id,
    }
    if (not _uuid(value["execution_id"]) or not _text(value["guardian_epoch"], 128) or
            not _text(value["job_nonce"], 32) or not re.fullmatch(r"[0-9a-f]{32}", value["job_nonce"]) or
            value["job_name"] not in {
                f"Local\\ResourceSentinel.Job.{value['execution_id']}.{value['job_nonce']}",
                f"Local\\ResourceSentinel.Test.Job.{value['job_nonce']}"} or
            value["logon_id"] != guard.binding.logon_id):
        raise ControlSlotError("control_slot_binding_mismatch")
    return value


def require_evidence(row, proof, *, restoring):
    """Interpret only an already entered, retained native evidence scope."""
    if (row["allocation_kind"] not in {"direct", "routed"} or row["parent_execution_id"] is not None or
            not row["job_name"] or not row["job_nonce"] or not row["guardian_epoch"] or
            proof.job_name != row["job_name"] or proof.job_nonce != row["job_nonce"] or
            proof.guardian_epoch != row["guardian_epoch"] or proof.job_creation_never_attempted or
            not proof.durable_manifest):
        raise ControlSlotError("control_slot_evidence_unverified")
    if restoring:
        if not proof.current_cpu_disabled or not proof.recovery_manifest_settled:
            raise ControlSlotError("restore_unverified")
    else:
        if (type(proof.active_process_count) is not int or type(proof.process_ids) is not tuple or
                proof.active_process_count != len(proof.process_ids)):
            raise ControlSlotError("control_slot_evidence_unverified")
        if row["root_pid"] is not None and (proof.root is None or
                proof.root.pid != row["root_pid"] or
                str(proof.root.created_filetime_100ns) != row["root_created_filetime_100ns"] or
                proof.root.logon_id != row["logon_id"]):
            raise ControlSlotError("control_slot_evidence_unverified")
        if proof.root is not None and proof.root.logon_id != row["logon_id"]:
            raise ControlSlotError("control_slot_evidence_unverified")
        if not proof.legacy_exclusion:
            raise ControlSlotError("legacy_exclusion_unverified")


def _result(slot, runtime, *, duplicate):
    return {key: slot[key] for key in (
        "slot_id", "slot_revision", "slot_state", "execution_id", "job_name", "job_nonce",
        "guardian_epoch", "exemption_revision")} | {
        "admission_barrier": runtime["admission_barrier"],
        "registry_revision": runtime["registry_revision"],
        "duplicate": duplicate, "control_authorized": False,
    }


def _barrier_consistent(slot, runtime):
    barrier = runtime["admission_barrier"]
    if (barrier not in {"NONE", "CONTROLLING", "RECOVERY_HOLD"} or
            (slot is None and barrier == "CONTROLLING") or
            (slot is not None and slot["slot_state"] == "HELD" and barrier not in {"CONTROLLING", "RECOVERY_HOLD"}) or
            (slot is not None and slot["slot_state"] == "RESTORED" and barrier == "CONTROLLING")):
        raise ControlSlotError("control_slot_barrier_mismatch")


def query_locked(conn, runtime, guard):
    slot = read_slot(conn)
    _barrier_consistent(slot, runtime)
    if slot is not None and (slot["policy_instance_id"] != guard.binding.instance_id or
                             slot["policy_logon_id"] != guard.binding.logon_id):
        raise ControlSlotError("control_slot_binding_mismatch")
    return slot


def begin_locked(conn, row, runtime, guard, proof, *, slot_id, exemption_revision):
    _transaction(conn)
    if not _uuid(slot_id) or not _integer(exemption_revision):
        raise ControlSlotError("invalid_control_slot_request")
    binding = _binding(row, guard)
    slot = query_locked(conn, runtime, guard)
    if slot is not None and slot["slot_id"] == slot_id:
        if any(slot[key] != value for key, value in binding.items()) or slot["exemption_revision"] != exemption_revision:
            raise ControlSlotError("control_slot_binding_mismatch")
        return _result(slot, runtime, duplicate=True)
    if slot is not None and slot["slot_state"] == "HELD":
        raise ControlSlotError("control_slot_occupied")
    if runtime["mode"] not in {"canary", "limited"}:
        raise ControlSlotError("control_mode_unavailable")
    if runtime["admission_barrier"] != "NONE":
        raise ControlSlotError("control_barrier_active")
    if (runtime["guardian_epoch"] != row["guardian_epoch"] or runtime["active_logon_id"] != row["logon_id"]):
        raise ControlSlotError("guardian_identity_mismatch")
    if (row["role"] != "background" or row["priority"] not in {"P2", "P3"} or
            row["state"] not in {"PREPARED", "RUNNING", "DRAINING"} or
            (row["state"] in {"RUNNING", "DRAINING"} and row["coverage"] != "job_contained")):
        raise ControlSlotError("control_execution_ineligible")
    if row["state"] == "PREPARED" and (proof.active_process_count != 0 or proof.process_ids != () or
            proof.root is not None or row["root_pid"] is not None or row["claim_consumed"] or row["launch_in_flight"]):
        raise ControlSlotError("control_empty_probe_unverified")
    # Inconsistent state/flag combinations are also unresolved. No inferred
    # exemption exception is accepted: the caller's grant checks cannot make
    # another execution's missing classification safe.
    blocked = conn.execute("""SELECT 1 FROM managed_executions
        WHERE state IS NULL OR state NOT IN
            ('NEW','QUEUED','RESERVED','PREPARED','LAUNCHING','RUNNING','DRAINING',
             'FINISHED','CANCELLED_BEFORE_START','START_FAILED','START_UNKNOWN','UNCERTAIN_HOLD')
          OR typeof(launch_in_flight)!='integer' OR launch_in_flight NOT IN (0,1)
          OR launch_in_flight=1 OR state IN ('LAUNCHING','START_UNKNOWN') LIMIT 1""").fetchone()
    if blocked is not None:
        raise ControlSlotError("control_launch_in_flight")
    revision = 1 if slot is None else slot["slot_revision"] + 1
    if revision > _MAX_INT or runtime["registry_revision"] >= _MAX_INT:
        raise ControlSlotError("control_slot_revision_exhausted")
    values = dict(singleton=1, schema_version=1, slot_id=slot_id, slot_revision=revision,
                  slot_state="HELD", **binding, exemption_revision=exemption_revision)
    if slot is None:
        conn.execute("INSERT INTO adaptive_control_slot(" + ",".join(_FIELDS) + ") VALUES(" +
                     ",".join("?" for _ in _FIELDS) + ")", tuple(values[key] for key in _FIELDS))
    else:
        changed = conn.execute("UPDATE adaptive_control_slot SET " + ",".join(key + "=?" for key in _FIELDS if key != "singleton") +
            " WHERE singleton=1 AND slot_id=? AND slot_revision=? AND slot_state='RESTORED'",
            tuple(values[key] for key in _FIELDS if key != "singleton") + (slot["slot_id"], slot["slot_revision"])).rowcount
        if changed != 1:
            raise ControlSlotError("control_slot_revision_conflict")
    if conn.execute("""UPDATE adaptive_runtime SET admission_barrier='CONTROLLING',registry_revision=registry_revision+1
        WHERE singleton=1 AND admission_barrier='NONE' AND registry_revision=?""", (runtime["registry_revision"],)).rowcount != 1:
        raise ControlSlotError("control_slot_revision_conflict")
    return _result(values, dict(runtime) | {"admission_barrier": "CONTROLLING", "registry_revision": runtime["registry_revision"] + 1}, duplicate=False)


def release_locked(conn, row, runtime, guard, *, slot_id):
    _transaction(conn)
    if not _uuid(slot_id):
        raise ControlSlotError("invalid_control_slot_request")
    slot = query_locked(conn, runtime, guard)
    if slot is None:
        raise ControlSlotError("control_slot_missing")
    binding = _binding(row, guard)
    if slot["slot_id"] != slot_id or any(slot[key] != value for key, value in binding.items()):
        raise ControlSlotError("control_slot_binding_mismatch")
    if slot["slot_state"] == "RESTORED":
        return _result(slot, runtime, duplicate=True)
    if slot["slot_revision"] >= _MAX_INT or runtime["registry_revision"] >= _MAX_INT:
        raise ControlSlotError("control_slot_revision_exhausted")
    if conn.execute("""UPDATE adaptive_control_slot SET slot_state='RESTORED',slot_revision=slot_revision+1
        WHERE singleton=1 AND slot_id=? AND slot_revision=? AND slot_state='HELD'""",
        (slot_id, slot["slot_revision"])).rowcount != 1:
        raise ControlSlotError("control_slot_revision_conflict")
    if conn.execute("""UPDATE adaptive_runtime SET admission_barrier='RECOVERY_HOLD',registry_revision=registry_revision+1
        WHERE singleton=1 AND registry_revision=? AND admission_barrier IN ('CONTROLLING','RECOVERY_HOLD')""",
        (runtime["registry_revision"],)).rowcount != 1:
        raise ControlSlotError("control_slot_revision_conflict")
    return _result(slot | {"slot_state": "RESTORED", "slot_revision": slot["slot_revision"] + 1},
        dict(runtime) | {"admission_barrier": "RECOVERY_HOLD", "registry_revision": runtime["registry_revision"] + 1}, duplicate=False)


def require_archive_clear(conn, row):
    """A terminal CAS cannot discard an unresolved control responsibility."""
    slot = read_slot(conn)
    runtime_rows = conn.execute("SELECT admission_barrier,policy_instance_id,policy_logon_id FROM adaptive_runtime LIMIT 2").fetchall()
    if len(runtime_rows) != 1:
        raise ControlSlotError("control_slot_registry_unavailable")
    runtime = dict(zip(("admission_barrier", "policy_instance_id", "policy_logon_id"), runtime_rows[0]))
    _barrier_consistent(slot, runtime)
    if slot is None:
        return
    if (slot["policy_instance_id"] != runtime["policy_instance_id"] or
            slot["policy_logon_id"] != runtime["policy_logon_id"]):
        raise ControlSlotError("control_slot_binding_mismatch")
    # A damaged source selector cannot safely be treated as another execution.
    if slot["execution_id"] != row["execution_id"]:
        return
    if slot["slot_state"] != "RESTORED":
        raise ControlSlotError("control_slot_unrestored")
    expected = {"job_name": row["job_name"], "job_nonce": row["job_nonce"],
                "guardian_epoch": row["guardian_epoch"], "logon_id": row["logon_id"],
                "owner_pid": row["wrapper_pid"], "owner_created_filetime_100ns": row["wrapper_created_filetime_100ns"]}
    if any(slot[key] != value for key, value in expected.items()):
        raise ControlSlotError("control_slot_binding_mismatch")
