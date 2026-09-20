"""Legacy setters executed inside shared POLICY, never an out-of-lock permit.

The collector supplies exact candidate identities, not mutation authority. This
module rereads the real registry and grants, retains native handles, and owns
POLICY through the setters and their cleanup. A missing registry stops writes.
It neither enables adaptive control nor migrates a daily data directory.
"""
from __future__ import annotations

from contextlib import ExitStack
from dataclasses import dataclass
import re
import time
from uuid import UUID

from .contracts import IdentityStatus, ProcessIdentity
from .exemption_sync import snapshot_locked
from .identity import VerifiedProcess


MAX_CANDIDATES = 256
MAX_INFRASTRUCTURE = 32
BATCH_SECONDS = .250
PRIORITIES = frozenset({"Idle", "BelowNormal", "Normal", "AboveNormal", "High", "RealTime"})
_ACTIVE = frozenset({"RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING",
                     "START_UNKNOWN", "UNCERTAIN_HOLD"})
_INFRA_COLUMNS = {"role", "pid", "created_filetime_100ns", "logon_id", "schema_version"}


class LegacyMutationError(ValueError):
    pass


@dataclass(frozen=True)
class Candidate:
    identity: ProcessIdentity
    priority_action: str = "none"
    restore_priority: str = "Normal"
    io_priority: int | None = None
    trim: bool = False

    def __post_init__(self):
        if (not isinstance(self.identity, ProcessIdentity) or
                self.priority_action not in {"none", "demote", "restore"} or
                self.restore_priority not in PRIORITIES or type(self.trim) is not bool or
                (self.io_priority is not None and
                 (type(self.io_priority) is not int or self.io_priority not in {1, 2}))):
            raise LegacyMutationError("legacy_candidate_invalid")

    @classmethod
    def from_dict(cls, value, logon_id):
        if (type(value) is not dict or set(value) != {
                "pid", "created_filetime_100ns", "priority_action", "restore_priority", "io_priority", "trim"}):
            raise LegacyMutationError("legacy_candidate_invalid")
        try:
            identity = ProcessIdentity.from_dict({"pid": value["pid"],
                "created_filetime_100ns": value["created_filetime_100ns"], "logon_id": logon_id})
            return cls(identity, value["priority_action"], value["restore_priority"], value["io_priority"], value["trim"])
        except (ValueError, TypeError, KeyError):
            raise LegacyMutationError("legacy_candidate_invalid") from None


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        return parsed is not None and parsed.int != 0 and str(parsed) == value
    except (TypeError, ValueError, AttributeError):
        return False


def _infra_schema(conn):
    found = conn.execute("SELECT type FROM sqlite_master WHERE name='adaptive_infrastructure'").fetchone()
    if found is None or found[0] != "table":
        raise LegacyMutationError("legacy_infrastructure_registry_unavailable")
    if {row[1] for row in conn.execute("PRAGMA table_info(adaptive_infrastructure)")} != _INFRA_COLUMNS:
        raise LegacyMutationError("legacy_infrastructure_registry_invalid")


def initialize_registry_locked(store):
    """Explicit supervisor setup under POLICY; never called by the collector."""
    guard = store._policy.assert_held()
    with store._transaction() as conn:
        store._policy.revalidate(conn, guard)
        conn.execute("""CREATE TABLE IF NOT EXISTS adaptive_infrastructure (
            role TEXT NOT NULL CHECK(role IN ('guardian','helper','supervisor')),
            pid INTEGER NOT NULL CHECK(pid>0), created_filetime_100ns TEXT NOT NULL,
            logon_id TEXT NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
            PRIMARY KEY(role,pid,created_filetime_100ns,logon_id))""")
        _infra_schema(conn)


def register_infrastructure_locked(store, role, process):
    """Register a retained, live VerifiedProcess before publishing infrastructure.

    The launch owner keeps POLICY from this call through publication. A PID or
    serialized liveness claim cannot substitute for the retained process.
    """
    guard = store._policy.assert_held()
    if role not in {"guardian", "helper", "supervisor"} or not isinstance(process, VerifiedProcess):
        raise LegacyMutationError("legacy_infrastructure_identity_required")
    observed = process.observe()
    identity = process.identity
    if (observed.status is not IdentityStatus.ALIVE or observed.identity != identity or
            identity.logon_id != guard.binding.logon_id):
        raise LegacyMutationError("legacy_infrastructure_identity_unverified")
    key = (role, identity.pid, str(identity.created_filetime_100ns), identity.logon_id)
    with store._transaction() as conn:
        store._policy.revalidate(conn, guard)
        _infra_schema(conn)
        if conn.execute("SELECT 1 FROM adaptive_infrastructure WHERE role=? AND pid=? AND created_filetime_100ns=? AND logon_id=?", key).fetchone():
            return False
        if conn.execute("SELECT count(*) FROM adaptive_infrastructure").fetchone()[0] >= MAX_INFRASTRUCTURE:
            raise LegacyMutationError("legacy_infrastructure_registry_full")
        conn.execute("INSERT INTO adaptive_infrastructure(role,pid,created_filetime_100ns,logon_id,schema_version) VALUES(?,?,?,?,1)", key)
        conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1")
    return True


def unregister_dead_infrastructure_locked(store, role, process):
    """Positive death on the retained identity, never heartbeat/TTL/PID cleanup.

    Both refusals below are decided before the transaction opens, and neither
    assert_held nor observe reads or writes the ledger, so the scope is a clean
    rejection and POLICY may release its durable entry nonce. The ordering is
    defined here, so the flag is set here; a caller cannot tell from the raised
    code which refusals reached the ledger. This assumes the refusal leaves the
    POLICY scope, which it does when the caller lets it propagate.

    Everything from the transaction onward keeps the opposite treatment. A
    rollback, a failed DELETE, an uncertain commit or a failed connection
    cleanup leaves the entry nonce in place, because the ledger outcome is then
    not known. store._transaction never sets this flag.
    """
    guard = store._policy.assert_held()
    if role not in {"guardian", "helper", "supervisor"} or not isinstance(process, VerifiedProcess):
        guard.clean_rejection = True
        raise LegacyMutationError("legacy_infrastructure_identity_required")
    observed = process.observe()
    identity = process.identity
    if (observed.status is not IdentityStatus.DEAD or observed.identity != identity or
            identity.logon_id != guard.binding.logon_id):
        guard.clean_rejection = True
        raise LegacyMutationError("legacy_infrastructure_death_unverified")
    with store._transaction() as conn:
        store._policy.revalidate(conn, guard)
        _infra_schema(conn)
        changed = conn.execute("DELETE FROM adaptive_infrastructure WHERE role=? AND pid=? AND created_filetime_100ns=? AND logon_id=?",
            (role, identity.pid, str(identity.created_filetime_100ns), identity.logon_id)).rowcount
        if changed:
            conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1")
    return bool(changed)


def _registry_locked(store, guard, deadline, clock):
    # No native query, second database or wait while this read transaction lives.
    with store._connection() as conn:
        conn.execute("PRAGMA busy_timeout=25")
        conn.set_progress_handler(lambda: int(clock() >= deadline), 1000)
        conn.execute("BEGIN")
        runtime = store._policy.revalidate(conn, guard)
        _infra_schema(conn)
        rows = conn.execute("""SELECT substr(execution_id,1,37) AS execution_id,
            wrapper_pid,substr(wrapper_created_filetime_100ns,1,21) AS birth,
            substr(logon_id,1,129) AS logon_id,substr(state,1,32) AS state,
            substr(job_name,1,257) AS job_name,substr(job_nonce,1,37) AS job_nonce,
            launch_in_flight,claim_consumed,root_pid,coverage,guardian_epoch
            FROM managed_executions WHERE (typeof(state)='text' AND
                state IN ('FINISHED','CANCELLED_BEFORE_START','START_FAILED') AND
                launch_sealed IS 1 AND launch_in_flight IS 0 AND
                ((allocation_kind IN ('direct','routed') AND typeof(reservation_id)='text' AND
                  length(reservation_id)>0 AND parent_execution_id IS NULL) OR
                 (allocation_kind IS 'parent' AND reservation_id IS NULL AND
                  typeof(parent_execution_id)='text' AND length(parent_execution_id)>0))) IS NOT 1
            LIMIT ?""", (MAX_CANDIDATES + 1,)).fetchall()
        infrastructure = conn.execute("""SELECT role,pid,substr(created_filetime_100ns,1,21) AS birth,
            substr(logon_id,1,129) AS logon_id,schema_version
            FROM adaptive_infrastructure LIMIT ?""", (MAX_INFRASTRUCTURE + 1,)).fetchall()
    if len(rows) > MAX_CANDIDATES or len(infrastructure) > MAX_INFRASTRUCTURE:
        raise LegacyMutationError("legacy_registry_too_large")
    identities, jobs = set(), []
    for row in rows:
        if (row["state"] not in _ACTIVE or not _uuid(row["execution_id"]) or
                row["logon_id"] != guard.binding.logon_id):
            raise LegacyMutationError("legacy_registry_invalid")
        identities.add(ProcessIdentity.from_dict({"pid": row["wrapper_pid"],
            "created_filetime_100ns": row["birth"], "logon_id": row["logon_id"]}))
        if row["job_name"] is None:
            if (row["job_nonce"] is not None or row["state"] not in {"RESERVED", "UNCERTAIN_HOLD"} or
                    row["launch_in_flight"] != 0 or row["claim_consumed"] != 0 or row["root_pid"] is not None or
                    row["coverage"] != "unmanaged" or row["guardian_epoch"] != ""):
                raise LegacyMutationError("legacy_job_scope_unknown")
            continue
        if (type(row["job_nonce"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", row["job_nonce"]) or
                row["job_name"] != f"Local\\ResourceSentinel.Job.{row['execution_id']}.{row['job_nonce']}"):
            raise LegacyMutationError("legacy_job_scope_unknown")
        jobs.append(row["job_name"])
    if len(jobs) > 10 or len(set(jobs)) != len(jobs):
        raise LegacyMutationError("legacy_job_scope_unknown")
    for row in infrastructure:
        if row["schema_version"] != 1 or row["role"] not in {"guardian", "helper", "supervisor"} or row["logon_id"] != guard.binding.logon_id:
            raise LegacyMutationError("legacy_infrastructure_registry_invalid")
        identities.add(ProcessIdentity.from_dict({"pid": row["pid"],
            "created_filetime_100ns": row["birth"], "logon_id": row["logon_id"]}))
    return runtime["registry_revision"], identities, jobs


def _result(candidate, reason="not_attempted"):
    return {"pid": candidate.identity.pid, "created_filetime_100ns": str(candidate.identity.created_filetime_100ns),
        "status": "skipped", "reason": reason, "priority_before": None, "priority_after": None,
        "io_applied": None, "trim_applied": False}


def execute_batch(store, exemptions, candidates, *, process_factory=None, job_factory=None,
                  clock=time.monotonic, wall_clock=time.time):
    """Run one <=250ms mutation budget with the actual shared POLICY owner.

    Injected factories/clocks are explicit in-process unit-test seams only.
    There is no JSON/environment/native bypass. A delayed native call can run
    beyond the budget; every following setter is skipped. Readback and cleanup
    still finish after an attempted write. A successful setter is
    acknowledged only after POLICY release and retained-handle cleanup.

    Legacy grants lack exact native ancestry. While any such grant is active,
    constraining actions are conservatively skipped; verified unmanaged restore
    actions remain possible. This is not proof of full exemption integration.
    """
    if (type(candidates) not in {list, tuple} or len(candidates) > MAX_CANDIDATES or
            any(not isinstance(item, Candidate) for item in candidates) or
            len({item.identity.pid for item in candidates}) != len(candidates)):
        raise LegacyMutationError("legacy_batch_invalid")
    if process_factory is None or job_factory is None:
        from .legacy_native import NativeLegacyJob, NativeLegacyProcess
        process_factory = NativeLegacyProcess.open if process_factory is None else process_factory
        job_factory = NativeLegacyJob.open if job_factory is None else job_factory
    output = {"protocol_version": 1, "available": False, "reason": "legacy_batch_unavailable",
              "results": [_result(item) for item in candidates]}
    if not candidates:
        output.update(available=True, reason="no_candidates")
        return output
    # Open targets before POLICY. The same handles survive every subsequent
    # identity/membership check and Set. Unknown targets are per-candidate skips.
    with ExitStack() as processes:
        targets = []
        for candidate, result in zip(candidates, output["results"]):
            try:
                operations = set()
                if candidate.priority_action != "none":
                    operations.add("priority")
                if candidate.io_priority is not None:
                    operations.add("io_priority")
                if candidate.trim:
                    operations.add("trim")
                target = process_factory(candidate.identity, operations=frozenset(operations))
                processes.callback(target.close)
                if target.identity != candidate.identity:
                    raise LegacyMutationError("legacy_identity_changed")
                targets.append(target)
            except Exception as error:
                # Cleanup uncertainty must propagate, never become a safe skip.
                if getattr(error, "__notes__", ()):
                    raise
                result["reason"] = "legacy_identity_unavailable"
                targets.append(None)
        logon = store._policy.current_logon()
        if any(item.identity.logon_id != logon for item in candidates):
            output["reason"] = "legacy_logon_mismatch"
            return output
        guard = store._policy.prepare(logon)
        # Re-entering ExitStack preserves its callbacks. Close them before
        # leaving POLICY; the outer scope still covers pre-acquisition failures.
        with store._policy.hold(guard), processes:
            deadline = clock() + BATCH_SECONDS
            with ExitStack() as jobs:
                try:
                    revision, protected, job_names = _registry_locked(store, guard, deadline, clock)
                    grants = snapshot_locked(exemptions, lifecycle_store=store, now=wall_clock(),
                                             deadline=deadline, clock=clock)
                    handles = []
                    for name in job_names:
                        if clock() >= deadline:
                            raise LegacyMutationError("legacy_batch_budget_exhausted")
                        job = job_factory(name, logon)
                        jobs.callback(job.close)
                        handles.append(job)
                except Exception as error:
                    if getattr(error, "__notes__", ()):
                        raise
                    output["reason"] = "legacy_registry_or_grants_unavailable"
                else:
                    output.update(available=True, reason="ok")
                    for candidate, target, result in zip(candidates, targets, output["results"]):
                        if target is None:
                            continue
                        if clock() >= deadline:
                            result["reason"] = "legacy_batch_budget_exhausted"
                            continue
                        if candidate.identity in protected:
                            result["reason"] = "legacy_managed_scope"
                            continue
                        try:
                            if target.alive() is not True:
                                result["reason"] = "legacy_identity_unavailable"
                                continue
                            memberships = []
                            for job in handles:
                                if clock() >= deadline:
                                    break
                                memberships.append(target.is_in_job(job))
                            if len(memberships) != len(handles):
                                result["reason"] = "legacy_batch_budget_exhausted"
                                continue
                            if any(value is True for value in memberships):
                                result["reason"] = "legacy_managed_scope"
                                continue
                            if any(value is not False for value in memberships):
                                result["reason"] = "legacy_membership_unknown"
                                continue
                            unresolved_grant = bool(grants.leases)
                            constraining_priority = (candidate.priority_action == "demote" or
                                (candidate.priority_action == "restore" and candidate.restore_priority == "Idle"))
                            attempted = False
                            readiness_reason = None
                            def ready():
                                nonlocal readiness_reason
                                if clock() >= deadline:
                                    readiness_reason = "legacy_batch_budget_exhausted"
                                    return False
                                alive = target.alive()
                                if alive is not True:
                                    readiness_reason = "legacy_identity_unavailable"
                                    return False
                                if clock() >= deadline:
                                    readiness_reason = "legacy_batch_budget_exhausted"
                                    return False
                                return True
                            if candidate.priority_action != "none" and ready():
                                before = target.priority()
                                if before not in PRIORITIES:
                                    raise LegacyMutationError("legacy_priority_unknown")
                                result["priority_before"] = before
                                desired = None
                                if candidate.priority_action == "demote" and not unresolved_grant and before in {"Normal", "AboveNormal", "High"}:
                                    desired = "BelowNormal"
                                elif (candidate.priority_action == "restore" and before == "BelowNormal" and
                                      not (unresolved_grant and constraining_priority)):
                                    desired = candidate.restore_priority
                                if desired is not None and ready():
                                    attempted = True
                                    target.set_priority(desired)
                                    # A successful readback is needed for map changes.
                                    if target.priority() != desired:
                                        raise LegacyMutationError("legacy_priority_readback_mismatch")
                                    result["priority_after"] = desired
                            if candidate.io_priority is not None and not (unresolved_grant and candidate.io_priority == 1) and ready():
                                attempted = True
                                target.set_io_priority(candidate.io_priority)
                                result["io_applied"] = candidate.io_priority
                            if candidate.trim and not unresolved_grant and ready():
                                attempted = True
                                target.trim()
                                result["trim_applied"] = True
                            result["status"] = ("partial" if readiness_reason else "applied") if attempted else "skipped"
                            result["reason"] = readiness_reason or ("legacy_batch_budget_exhausted" if clock() >= deadline else
                                "exemption_scope_unresolved" if unresolved_grant and
                                (constraining_priority or candidate.io_priority == 1 or candidate.trim) else "ok")
                        except Exception as error:
                            if getattr(error, "__notes__", ()):
                                raise
                            result.update(status="partial", reason="legacy_mutation_unverified")
    return output
