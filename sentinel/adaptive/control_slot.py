"""One conservative control-responsibility slot, never a capacity ledger.

HELD covers intent, an uncertain Set and an applied cap alike. SQLite records
neither native control authority nor a lease renewal. The lifecycle store owns
POLICY and native evidence scopes; these helpers perform only bounded SQL and
pure validation inside its existing short transaction.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
from uuid import UUID

from .contracts import ProcessIdentity


class ControlSlotError(ValueError):
    pass


_MAX_INT = (1 << 63) - 1
_TICKS_PER_MS = 10_000
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
_ACTION_FIELDS = (
    "guardian_epoch", "execution_id", "decision_seq", "action_id", "sample_seq",
    "action_state", "desired_mode", "desired_rate_bp", "applied_flags", "applied_rate_bp",
    "applied_tick_100ns", "lease_deadline_tick_100ns", "intervention_deadline_tick_100ns",
    "reason", "win32_error",
)
_ACTION_STATES = ("INTENDED", "APPLIED", "RENEWED", "RESTORED", "UNVERIFIED", "FAILED", "CONFLICT")


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


def migrate_control_actions_schema(conn):
    """Add the bounded control audit ledger inside the caller-owned transaction.

    Plan section 7.6 keeps one row per decision, so a retry at the same sequence
    cannot append a second action. Nothing here records capacity: a capped Job's
    reduced CPU is never written as released admission.
    """
    _transaction(conn)
    found = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_actions'").fetchone()
    if found is not None and found[0] != "table":
        raise ControlSlotError("control_actions_schema_unsupported")
    conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_actions (
        guardian_epoch TEXT NOT NULL,
        execution_id TEXT NOT NULL,
        decision_seq INTEGER NOT NULL CHECK(typeof(decision_seq)='integer' AND decision_seq>=0),
        action_id TEXT NOT NULL,
        sample_seq INTEGER NOT NULL CHECK(typeof(sample_seq)='integer' AND sample_seq>=0),
        action_state TEXT NOT NULL CHECK(action_state IN
            ('INTENDED','APPLIED','RENEWED','RESTORED','UNVERIFIED','FAILED','CONFLICT')),
        desired_mode TEXT NOT NULL CHECK(desired_mode IN ('disabled','hard_cap')),
        desired_rate_bp INTEGER,
        applied_flags INTEGER,
        applied_rate_bp INTEGER,
        applied_tick_100ns INTEGER,
        lease_deadline_tick_100ns INTEGER,
        intervention_deadline_tick_100ns INTEGER,
        reason TEXT NOT NULL,
        win32_error INTEGER,
        PRIMARY KEY(guardian_epoch,execution_id,decision_seq),
        CHECK(action_state NOT IN ('APPLIED','RENEWED') OR (applied_flags=5 AND applied_rate_bp>=1
            AND applied_tick_100ns>=1 AND lease_deadline_tick_100ns>=1
            AND lease_deadline_tick_100ns<=intervention_deadline_tick_100ns)),
        CHECK(action_state!='RESTORED' OR (applied_flags IS NOT NULL AND applied_flags%2=0
            AND applied_tick_100ns>=1 AND lease_deadline_tick_100ns IS NULL)),
        FOREIGN KEY(execution_id) REFERENCES managed_executions(execution_id)
    )""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(adaptive_actions)")}
    if columns != set(_ACTION_FIELDS):
        raise ControlSlotError("control_actions_schema_unsupported")


@dataclass(frozen=True)
class ControlAction:
    """One decision's audit row, written after its acknowledgement."""

    guardian_epoch: str
    execution_id: str
    decision_seq: int
    action_id: str
    sample_seq: int
    action_state: str
    desired_mode: str
    desired_rate_bp: int | None
    applied_flags: int | None
    applied_rate_bp: int | None
    applied_tick_100ns: int | None
    lease_deadline_tick_100ns: int | None
    intervention_deadline_tick_100ns: int | None
    reason: str
    win32_error: int | None


@dataclass(frozen=True)
class UncappedSample:
    """One frame the guardian itself observed while its own Job carried no cap.

    A JobFrame has no capped flag, so uncapped is the controller's knowledge and
    not a wire field. observed_tick_100ns is the guardian's own native Query for
    this frame; cpu_units is carried for the record and is never, on its own,
    evidence that a restriction was removed.
    """

    execution_id: str
    sampler_epoch: str
    clock_epoch: str
    sample_seq: int
    window_start_tick_100ns: int
    window_end_tick_100ns: int
    observed_tick_100ns: int
    cpu_units: float


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


def record_actions_locked(conn, row, actions):
    """Append the batched audit rows for one execution; never a capacity write.

    A RESTORED row is the durable boundary a later barrier clear measures its
    fresh samples against, so it is accepted only while this execution's slot is
    already RESTORED. A repeated sequence is a primary key conflict, not a
    second action.
    """
    _transaction(conn)
    if type(actions) is not tuple or not 1 <= len(actions) <= 64:
        raise ControlSlotError("invalid_control_action")
    slot = None
    for action in actions:
        if type(action) is not ControlAction:
            raise ControlSlotError("invalid_control_action")
        if (action.execution_id != row["execution_id"] or action.guardian_epoch != row["guardian_epoch"] or
                not _uuid(action.action_id) or not _integer(action.decision_seq) or
                not _integer(action.sample_seq) or action.action_state not in _ACTION_STATES or
                action.desired_mode not in {"disabled", "hard_cap"} or
                not _text(action.reason, 128) or
                not re.fullmatch(r"[A-Za-z0-9_.:@-]+", action.reason)):
            raise ControlSlotError("invalid_control_action")
        for name, minimum, maximum in (("desired_rate_bp", 1, 10000), ("applied_flags", 0, (1 << 32) - 1),
                                       ("applied_rate_bp", 0, 10000), ("applied_tick_100ns", 1, _MAX_INT),
                                       ("lease_deadline_tick_100ns", 1, _MAX_INT),
                                       ("intervention_deadline_tick_100ns", 1, _MAX_INT),
                                       ("win32_error", 0, (1 << 32) - 1)):
            value = getattr(action, name)
            if value is not None and not (_integer(value, minimum=minimum) and value <= maximum):
                raise ControlSlotError("invalid_control_action")
        if action.action_state == "RESTORED":
            slot = read_slot(conn) if slot is None else slot
            if (slot is None or slot["execution_id"] != row["execution_id"] or
                    slot["slot_state"] != "RESTORED"):
                raise ControlSlotError("control_slot_unrestored")
        try:
            conn.execute("INSERT INTO adaptive_actions(" + ",".join(_ACTION_FIELDS) + ") VALUES(" +
                         ",".join("?" for _ in _ACTION_FIELDS) + ")",
                         tuple(getattr(action, name) for name in _ACTION_FIELDS))
        except sqlite3.IntegrityError:
            raise ControlSlotError("control_action_replayed") from None
        except sqlite3.Error:
            raise ControlSlotError("control_actions_unavailable") from None


def _restore_boundary(conn, row):
    """The durable tick of this execution's own completed restore Query."""
    try:
        found = conn.execute("""SELECT action_state,applied_tick_100ns FROM adaptive_actions
            WHERE guardian_epoch=? AND execution_id=? ORDER BY decision_seq DESC LIMIT 1""",
            (row["guardian_epoch"], row["execution_id"])).fetchone()
    except sqlite3.Error:
        raise ControlSlotError("control_actions_unavailable") from None
    if found is None or found[0] != "RESTORED" or not _integer(found[1], minimum=1):
        # A later intent, applied cap or unresolved fault is never a boundary.
        raise ControlSlotError("control_restore_boundary_missing")
    return found[1]


def _uncapped_samples(row, samples, *, boundary, now_tick_100ns, required, max_age_ms):
    """Count only distinct, in-order, post-restore observations that are fresh.

    Freshness is judged when each frame was observed, because five samples one
    interval apart cannot all sit inside one freshness window at clear time. The
    newest sample must still be fresh now, so a stalled sampler cannot release
    admission with an old set. A usage drop alone counts for nothing here.
    """
    if type(samples) is not tuple or len(samples) < required:
        raise ControlSlotError("uncapped_samples_insufficient")
    age = max_age_ms * _TICKS_PER_MS
    previous = None
    for sample in samples:
        if type(sample) is not UncappedSample:
            raise ControlSlotError("uncapped_samples_invalid")
        if (sample.execution_id != row["execution_id"] or not _integer(sample.sample_seq) or
                not _integer(sample.window_start_tick_100ns, minimum=1) or
                not _integer(sample.window_end_tick_100ns, minimum=1) or
                not _integer(sample.observed_tick_100ns, minimum=1) or
                type(sample.cpu_units) not in (int, float) or not 0 <= sample.cpu_units <= 4096 or
                not _text(sample.sampler_epoch, 128) or not _text(sample.clock_epoch, 128)):
            raise ControlSlotError("uncapped_samples_invalid")
        if not (sample.window_start_tick_100ns < sample.window_end_tick_100ns <=
                sample.observed_tick_100ns <= now_tick_100ns):
            raise ControlSlotError("uncapped_samples_invalid")
        if previous is not None and (sample.sample_seq <= previous.sample_seq or
                sample.window_end_tick_100ns <= previous.window_end_tick_100ns or
                sample.sampler_epoch != previous.sampler_epoch or
                sample.clock_epoch != previous.clock_epoch):
            raise ControlSlotError("uncapped_samples_invalid")
        if sample.window_start_tick_100ns < boundary:
            raise ControlSlotError("uncapped_samples_precede_restore")
        if sample.observed_tick_100ns - sample.window_end_tick_100ns > age:
            raise ControlSlotError("uncapped_samples_stale")
        previous = sample
    if now_tick_100ns - previous.window_end_tick_100ns > age:
        raise ControlSlotError("uncapped_samples_stale")


def clear_locked(conn, row, runtime, guard, *, samples, now_tick_100ns,
                 required_samples, sample_max_age_ms):
    """Clear RECOVERY_HOLD by compare-and-swap, or keep it (plan section 7.4).

    Every condition is evidence: the slot is RESTORED for this exact execution,
    the caller's retained scope already proved a disabled Query and a settled
    manifest, the store already revalidated this execution's allocation, the
    durable audit ledger holds the restore boundary, and the required count of
    fresh uncapped samples was observed after it. There is no TTL, force flag or
    operator bypass; anything missing raises and the barrier stays.
    """
    _transaction(conn)
    if (not _integer(now_tick_100ns, minimum=1) or type(required_samples) is not int or
            not 1 <= required_samples <= 64 or type(sample_max_age_ms) is not int or
            not 1 <= sample_max_age_ms <= 60_000):
        raise ControlSlotError("invalid_control_slot_request")
    slot = query_locked(conn, runtime, guard)
    if slot is None:
        raise ControlSlotError("control_slot_missing")
    binding = _binding(row, guard)
    if any(slot[key] != value for key, value in binding.items()):
        raise ControlSlotError("control_slot_binding_mismatch")
    if slot["slot_state"] != "RESTORED":
        raise ControlSlotError("control_slot_unrestored")
    if runtime["admission_barrier"] != "RECOVERY_HOLD":
        raise ControlSlotError("control_barrier_not_held")
    _uncapped_samples(row, samples, boundary=_restore_boundary(conn, row),
                      now_tick_100ns=now_tick_100ns, required=required_samples,
                      max_age_ms=sample_max_age_ms)
    if runtime["registry_revision"] >= _MAX_INT:
        raise ControlSlotError("control_slot_revision_exhausted")
    if conn.execute("""UPDATE adaptive_runtime SET admission_barrier='NONE',registry_revision=registry_revision+1
        WHERE singleton=1 AND registry_revision=? AND admission_barrier='RECOVERY_HOLD'""",
        (runtime["registry_revision"],)).rowcount != 1:
        raise ControlSlotError("control_slot_revision_conflict")
    return _result(slot, dict(runtime) | {"admission_barrier": "NONE",
        "registry_revision": runtime["registry_revision"] + 1}, duplicate=False)


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
