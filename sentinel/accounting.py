"""One conservative local-capacity projection for direct and routed admission.

All inputs are already collected snapshots.  These functions perform bounded
SQLite reads/updates on the caller's transaction; none query processes, invoke
IPC, read files, commit, or acquire a second lock.  Missing attribution adds the
entire allocation to machine usage.  It never creates capacity.
"""
from __future__ import annotations

import json
import math
import sqlite3
from collections.abc import Mapping
from datetime import datetime
from typing import Any

GIB = 1 << 30
MAX_ROWS = 10000
MAX_METADATA_BYTES = 65536
MAX_MEMBERS = 256
RESOURCE_KEYS = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")
TERMINAL_STATES = frozenset({"CANCELLED_BEFORE_START", "START_FAILED", "FINISHED"})
ACTIVE_STATES = frozenset({"NEW", "QUEUED", "RESERVED", "PREPARED", "LAUNCHING", "RUNNING", "DRAINING", "START_UNKNOWN", "UNCERTAIN_HOLD"})


class AccountingError(ValueError):
    """A ledger invariant failed; admission must hold."""


def _mapping(value):
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict"):
        return value.to_dict()
    raise AccountingError("frame_invalid")


def _number(value, *, integer=False, positive=False):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    try:
        finite = math.isfinite(value)
    except OverflowError:
        return None
    if not finite or value < 0 or (positive and value <= 0):
        return None
    if integer and (not isinstance(value, int) or value > (1 << 63) - 1):
        return None
    return value


def _gib(value):
    number = _number(value)
    return None if number is None or number > ((1 << 63) - 1) / GIB else math.ceil(number * GIB)


def _error(resource, reason, **extra):
    return dict(resource=resource, reason=reason, required=None, available=None, **extra)


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def frame_from_status(status, config, *, now, logical_processors):
    """Convert a legacy collector snapshot without querying OS/time ourselves.

    A collector frame never claims private Job attribution.  This explicit
    admission-only source must not be substituted for an unavailable fast frame
    while the controller is active.  Disk freshness has its independent 90s cap.
    """
    status = _mapping(status)
    errors = []
    now = _number(now)
    age_limit = _number(config.get("admission_status_stale_sec", 300))
    generated = _timestamp(status.get("generated_at"))
    sampled = _timestamp(status.get("sampled_at", status.get("generated_at")))
    fresh = now is not None and age_limit is not None and all(
        stamp is not None and -30 <= now - stamp <= age_limit
        for stamp in (generated, sampled))
    if not fresh:
        errors.append(_error("telemetry", "status_stale"))
    policy = status.get("resource_policy")
    if not isinstance(policy, Mapping) or policy.get("mode") != "resource-v2":
        errors.append(_error("policy", "policy_snapshot_unavailable"))
    ram = status.get("ram") if isinstance(status.get("ram"), Mapping) else {}
    memory = status.get("memory") if isinstance(status.get("memory"), Mapping) else {}
    cpu_pct = _number(status.get("cpu_5min_avg", status.get("cpu_pct")))
    count = _number(logical_processors, integer=True, positive=True)
    machine = dict(
        logical_processors=count,
        processor_groups=1,
        cpu_busy_units=(cpu_pct * count / 100 if cpu_pct is not None and count and cpu_pct <= 100 else None),
        physical_total_bytes=_gib(ram.get("total_gb")),
        physical_available_bytes=_gib(ram.get("free_gb")),
        commit_used_bytes=_gib(memory.get("commit_used_gib")),
        commit_limit_bytes=_gib(memory.get("commit_limit_gib")),
    )
    disks = status.get("disks") or []
    if isinstance(disks, dict):
        disks = [disks]
    if not isinstance(disks, list):
        disks = []
    drive = str(config.get("system_drive", "C:")).upper()
    disk = next((d for d in disks[:128] if isinstance(d, dict) and str(d.get("drive", "")).upper() == drive), {})
    io = status.get("disk_performance") if isinstance(status.get("disk_performance"), Mapping) else {}
    latencies = [_number(io.get(k)) for k in ("read_latency_ms", "write_latency_ms")]
    disk_stamp = _timestamp(io.get("sampled_at", status.get("sampled_at", status.get("generated_at"))))
    disk_fresh = now is not None and age_limit is not None and disk_stamp is not None and -30 <= now - disk_stamp <= min(age_limit, 90)
    return dict(source="collector-admission-only", fresh=fresh, validity="valid" if fresh else "invalid",
                machine=machine, jobs=[], registry_revision=None, errors=errors,
                disk=dict(fresh=disk_fresh, free_gib=_number(disk.get("free_gb")),
                          queue_length=_number(io.get("queue_length")),
                          latency_ms=max(latencies) if all(v is not None for v in latencies) else None))


legacy_frame_from_status = frame_from_status


def frame_from_fast_frame(frame, *, now_tick_100ns, clock_epoch, attribution=None, disk=None):
    """Attach locally verified clock/registry proofs to public FastFrame data.

    The internal attribution map comes from the sampler's exact membership
    registry, never an unverified remote client's aggregate claim.
    """
    result = _mapping(frame)
    result.update(source="fast", attribution=attribution or {}, disk=disk or {},
                  now_tick_100ns=now_tick_100ns, expected_clock_epoch=clock_epoch)
    result["fresh"] = _fast_fresh(result)
    return result


def _fast_fresh(frame):
    def tick(value):
        if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 20:
            value = int(value)
        return _number(value, integer=True)
    start, end, published, now = [tick(frame.get(key)) for key in (
        "window_start_tick_100ns", "window_end_tick_100ns", "published_tick_100ns", "now_tick_100ns")]
    return (all(v is not None for v in (start, end, published, now))
            and 5_000_000 <= end - start <= 15_000_000
            and end <= published <= now and 0 <= now - end <= 30_000_000
            and bool(frame.get("clock_epoch"))
            and frame.get("clock_epoch") == frame.get("expected_clock_epoch"))


def _rows(conn, table):
    # Names are constants at call sites, never caller-supplied SQL identifiers.
    if not conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
        return []
    cursor = conn.execute(f'SELECT * FROM "{table}" LIMIT ?', (MAX_ROWS + 1,))
    names = [d[0] for d in cursor.description]
    rows = [dict(zip(names, row)) for row in cursor.fetchall()]
    if len(rows) > MAX_ROWS:
        raise AccountingError("ledger_bound_exceeded")
    return rows


def _transaction(conn):
    if not conn.in_transaction:
        raise AccountingError("transaction_required")


def _supported_runtime(conn, *, required=True):
    """Read-only version gate before interpreting or changing managed rows."""
    try:
        rows = _rows(conn, "adaptive_runtime")
    except sqlite3.DatabaseError as error:
        raise AccountingError("registry_unavailable") from error
    if not rows and not required:
        return None
    if len(rows) != 1 or rows[0].get("singleton") != 1:
        raise AccountingError("registry_unavailable")
    runtime = rows[0]
    if runtime.get("schema_version") != 1 or runtime.get("protocol_version") != 1:
        raise AccountingError("schema_version_unsupported")
    if _number(runtime.get("registry_revision"), integer=True) is None:
        raise AccountingError("registry_unavailable")
    return runtime


def _worker_scope(worker, config):
    if worker is None:
        return "unknown"
    raw = worker.get("capabilities_json")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_METADATA_BYTES:
        return "unknown"
    try:
        caps = json.loads(raw)
    except (ValueError, RecursionError):
        return "unknown"
    if not isinstance(caps, dict):
        return "unknown"
    local, host = caps.get("local"), caps.get("canonical_host_id")
    expected = config.get("local_host_id", config.get("canonical_host_id"))
    if local is True:
        return "unknown" if expected and host and expected != host else "local"
    if local is False:
        return "unknown" if host and expected and host == expected else "remote"
    if host and expected:
        return "local" if host == expected else "remote"
    # A missing locality assertion is not evidence of a remote allocation.
    return "unknown"


def _demand(row, *, routed=False):
    values = dict(cpu_units=_number(row.get("cpu_units")),
                  physical_bytes=(_number(row["physical_bytes"], integer=True) if row.get("physical_bytes") is not None else _gib(row.get("ram_gib"))),
                  commit_bytes=(_number(row["commit_bytes"], integer=True) if row.get("commit_bytes") is not None else _gib(row.get("ram_gib"))),
                  io_slots=_number(row.get("io_slots") if row.get("io_slots") is not None else (1 if routed else None), integer=True))
    if any(v is None for v in values.values()):
        raise AccountingError("allocation_resources_invalid")
    return values


def _managed_floor(row, allocation):
    result = {}
    for key in RESOURCE_KEYS:
        integer = key != "cpu_units"
        requested = _number(row.get("requested_" + key), integer=integer)
        floor = _number(row.get("floor_" + key), integer=integer)
        if requested is None or floor is None or floor < requested:
            raise AccountingError("demand_floor_invalid")
        if requested != allocation[key]:
            raise AccountingError("allocation_binding_mismatch")
        result[key] = max(allocation[key], floor)
    return result


def resolve_allocation_source(conn, execution_id):
    """Resolve a subspan to its one top-level allocation, validating every hop."""
    _transaction(conn)
    _supported_runtime(conn)
    managed = {r["execution_id"]: r for r in _rows(conn, "managed_executions")}
    seen, initial_logon = set(), None
    for _ in range(128):
        if execution_id in seen or execution_id not in managed:
            raise AccountingError("allocation_parent_invalid")
        seen.add(execution_id)
        row = managed[execution_id]
        if initial_logon is None:
            initial_logon = row.get("logon_id")
        if not initial_logon or row.get("logon_id") != initial_logon:
            raise AccountingError("allocation_parent_logon_mismatch")
        kind = row.get("allocation_kind")
        if kind == "parent":
            if row.get("reservation_id") or row.get("job_name"):
                raise AccountingError("allocation_parent_invalid")
            execution_id = row.get("parent_execution_id")
            continue
        if kind not in ("direct", "routed") or row.get("parent_execution_id") or not row.get("reservation_id"):
            raise AccountingError("allocation_binding_invalid")
        table = "reservations" if kind == "direct" else "worker_reservations"
        matches = [r for r in _rows(conn, table) if r.get("id") == row["reservation_id"]]
        if len(matches) != 1:
            raise AccountingError("allocation_missing")
        allocation = matches[0]
        if allocation.get("execution_id") != row["execution_id"] or allocation.get("lifecycle_managed") != 1:
            raise AccountingError("allocation_binding_mismatch")
        return dict(allocation_kind=kind, reservation_id=row["reservation_id"],
                    execution_id=row["execution_id"], allocation=allocation, execution=row)
    raise AccountingError("allocation_parent_depth_exceeded")


def update_demand_floor(conn, execution_id, observed, *, expected_revision,
                        valid=True, uncapped=False):
    """Raise a top-level floor with a validated observation; never shrink it.

    The caller owns measurement/provenance validation and the transaction.
    Capped CPU usage cannot lower or raise the uncapped CPU high-water.  Memory
    observations may raise their own separate floors while a CPU cap is active.
    """
    _transaction(conn)
    source = resolve_allocation_source(conn, execution_id)
    row = source["execution"]
    if source["execution_id"] != execution_id:
        raise AccountingError("parent_has_no_independent_floor")
    if row.get("state") in TERMINAL_STATES:
        raise AccountingError("execution_terminal")
    if row.get("state_revision") != expected_revision:
        raise AccountingError("revision_conflict")
    current = _managed_floor(row, _demand(source["allocation"], routed=source["allocation_kind"] == "routed"))
    if valid is not True:
        return current
    measurement = _mapping(observed)
    for key in RESOURCE_KEYS:
        if key == "cpu_units" and not uncapped:
            continue
        if key not in measurement or measurement[key] is None:
            continue
        value = _number(measurement[key], integer=key != "cpu_units")
        if value is None:
            raise AccountingError("measurement_invalid")
        current[key] = max(current[key], value)
    changed = any(current[k] != row["floor_" + k] for k in RESOURCE_KEYS)
    if changed:
        changed_rows = conn.execute(
            "UPDATE managed_executions SET floor_cpu_units=?,floor_physical_bytes=?,floor_commit_bytes=?,floor_io_slots=?,state_revision=state_revision+1 WHERE execution_id=? AND state_revision=?",
            tuple(current[k] for k in RESOURCE_KEYS) + (execution_id, expected_revision)).rowcount
        if changed_rows != 1:
            raise AccountingError("revision_conflict")
        if conn.execute("UPDATE adaptive_runtime SET registry_revision=registry_revision+1 WHERE singleton=1").rowcount != 1:
            raise AccountingError("registry_unavailable")
    return current


def _machine(frame):
    machine = _mapping(frame.get("machine", {}))
    count = _number(machine.get("logical_processors"), integer=True, positive=True)
    cpu = _number(machine.get("cpu_busy_units"))
    total = _number(machine.get("physical_total_bytes"), integer=True, positive=True)
    available = _number(machine.get("physical_available_bytes"), integer=True)
    commit = _number(machine.get("commit_used_bytes"), integer=True)
    limit = _number(machine.get("commit_limit_bytes"), integer=True, positive=True)
    values = dict(cpu_units=cpu if count and cpu is not None and cpu <= count else None,
                  physical_bytes=total - available if total and available is not None and available <= total else None,
                  commit_bytes=commit if limit and commit is not None and commit <= limit else None,
                  io_slots=0)
    return machine, values


def _budgets(config, machine):
    cpu = _number(config.get("local_allocatable_cpu", 8), positive=True)
    ram = _gib(config.get("local_allocatable_ram_gib", 58))
    physical_reserve = _gib(config.get("local_physical_headroom_gib", 4))
    commit_reserve = _gib(config.get("local_commit_headroom_gib", 4))
    io = _number(config.get("heavy_io_slots", 1), integer=True)
    if cpu is None or not ram or physical_reserve is None or commit_reserve is None or io is None:
        raise AccountingError("policy_config_invalid")
    # Lower configured budgets remain legal; these fixed minima/maxima cannot
    # be relaxed by a stale config or a caller-supplied capacity estimate.
    physical_reserve = max(4 * GIB, physical_reserve)
    commit_reserve = max(4 * GIB, commit_reserve)
    total = _number(machine.get("physical_total_bytes"), integer=True, positive=True)
    limit = _number(machine.get("commit_limit_bytes"), integer=True, positive=True)
    return dict(cpu_units=cpu, physical_bytes=min(58 * GIB, ram, max(0, total - physical_reserve)) if total else None,
                commit_bytes=max(0, limit - commit_reserve) if limit else None, io_slots=io)


def _attribution(frame, allocations, managed, revision, measured):
    """Validate the whole subtraction set before subtracting any resource.

    FastFrame's public aggregates intentionally omit process identities.  The
    sampler must additionally supply an internal ``attribution`` map containing
    exact member identities, counter epoch and state revision.  Without that
    proof even a nominally valid aggregate gets subtraction zero.
    """
    result = {a["key"]: dict.fromkeys(RESOURCE_KEYS, 0) for a in allocations}
    reasons = []
    if frame.get("source") == "collector-admission-only":
        return result, ["collector_has_no_job_attribution"]
    if frame.get("validity") != "valid" or not frame.get("fresh"):
        return result, ["telemetry_stale_or_invalid"]
    if frame.get("registry_revision") != revision:
        return result, ["registry_revision_mismatch"]
    skew = _number(frame.get("collection_skew_ms"))
    if skew is None or skew > 100:
        return result, ["collection_skew"]
    jobs = frame.get("jobs", [])
    proof = frame.get("attribution", {})
    if not isinstance(jobs, list) or len(jobs) > 10 or not isinstance(proof, Mapping):
        return result, ["attribution_invalid"]
    by_execution = {}
    for item in jobs:
        item = _mapping(item)
        key = item.get("execution_id")
        if key in by_execution:
            return result, ["duplicate_job_attribution"]
        by_execution[key] = item
    members_seen = set()
    candidates = []
    for allocation in allocations:
        execution_id = allocation.get("execution_id")
        row, job = managed.get(execution_id), by_execution.get(execution_id)
        p = proof.get(execution_id)
        if not row or row.get("state") not in {"RUNNING", "DRAINING"} or row.get("coverage") != "job_contained" or not job or not isinstance(p, Mapping):
            continue
        members = p.get("members")
        if (job.get("membership_complete") is not True or p.get("state_revision") != row.get("state_revision")
                or not job.get("counter_epoch") or p.get("counter_epoch") != job.get("counter_epoch")
                or p.get("window_start_tick_100ns") != frame.get("window_start_tick_100ns")
                or p.get("window_end_tick_100ns") != frame.get("window_end_tick_100ns")
                or not isinstance(members, list) or not 1 <= len(members) <= MAX_MEMBERS
                or job.get("active_processes") != len(members)):
            reasons.append("membership_unknown")
            continue
        identities = set()
        for member in members:
            if not isinstance(member, Mapping):
                break
            pid, birth = member.get("pid"), member.get("created_filetime_100ns")
            if _number(pid, integer=True, positive=True) is None or not isinstance(birth, str) or len(birth) > 20 or not birth.isascii() or not birth.isdigit() or not 0 < int(birth) <= (1 << 64) - 1:
                break
            identities.add((pid, birth))
        else:
            if len(identities) != len(members) or identities & members_seen:
                return result, ["overlapping_membership"]
            members_seen |= identities
            high_water = _number(job.get("cpu_uncapped_high_water_units"))
            logical = _number(frame.get("machine", {}).get("logical_processors"), integer=True, positive=True)
            if high_water is not None and logical and high_water <= logical:
                allocation["demand"]["cpu_units"] = max(allocation["demand"]["cpu_units"], high_water)
            candidates.append((allocation, job))
            continue
        reasons.append("identity_unknown")
    field_map = dict(cpu_units="cpu_units", physical_bytes="private_working_set_bytes", commit_bytes="private_commit_bytes")
    for resource, field in field_map.items():
        proposed = {}
        for allocation, job in candidates:
            if resource != "cpu_units" and job.get("memory_validity") != "valid":
                continue
            amount = _number(job.get(field), integer=resource != "cpu_units")
            if amount is not None:
                proposed[allocation["key"]] = amount
        if measured[resource] is None or sum(proposed.values()) > measured[resource]:
            reasons.append(resource + "_aggregate_inconsistent")
            continue
        for key, amount in proposed.items():
            result[key][resource] = amount
            if resource != "cpu_units":
                allocation = next(a for a in allocations if a["key"] == key)
                allocation["demand"][resource] = max(allocation["demand"][resource], amount)
    return result, reasons


def project_local_capacity(conn, frame, config):
    """Project every local allocation from this exact SQLite transaction.

    Return bytes for both memory resources, CPU units, and integer IO slots.
    ``errors`` must deny admission. ``attribution_reasons`` are conservative
    subtraction fallbacks and do not independently make healthy capacity unknown.
    """
    _transaction(conn)
    frame = _mapping(frame)
    if frame.get("source") != "collector-admission-only":
        frame["fresh"] = _fast_fresh(frame)
    result = dict(projected={}, budgets={}, errors=[], allocations=[], barrier="NONE",
                  registry_revision=None, source=frame.get("source", "fast"), attribution_reasons=[])
    try:
        machine, measured = _machine(frame)
        result["budgets"] = _budgets(config, machine)
        frame_errors = frame.get("errors", [])
        if not isinstance(frame_errors, (list, tuple)) or len(frame_errors) > 128:
            raise AccountingError("frame_invalid")
        if frame.get("source") == "collector-admission-only":
            result["errors"].extend(frame_errors)
        elif frame.get("validity") != "valid":
            result["errors"].append(_error("telemetry", "frame_invalid"))
        if frame.get("source") != "collector-admission-only" and not frame.get("fresh"):
            result["errors"].append(_error("telemetry", "telemetry_stale"))
        direct, routed, workers = (_rows(conn, table) for table in ("reservations", "worker_reservations", "workers"))
        managed_rows = _rows(conn, "managed_executions")
        managed = {r["execution_id"]: r for r in managed_rows}
        has_managed_table = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='managed_executions'").fetchone() is not None
        runtime = _supported_runtime(conn, required=has_managed_table)
        if runtime:
            result["registry_revision"] = runtime.get("registry_revision")
            result["barrier"] = runtime.get("admission_barrier", "UNKNOWN")
            if frame.get("source") == "collector-admission-only" and runtime.get("mode") not in {"off", "admission-only"}:
                # Continue ledger validation even when an explicit grant can
                # bypass this telemetry requirement.  Early return here would
                # let a grant hide a corrupt/missing allocation binding.
                result["errors"].append(_error("telemetry", "fast_frame_required"))
        by_worker = {w["id"]: w for w in workers}
        seen_bindings, seen_executions = set(), set()
        for kind, rows in (("direct", direct), ("routed", routed)):
            for row in rows:
                if kind == "routed":
                    scope = _worker_scope(by_worker.get(row.get("worker_id")), config)
                    if scope == "remote":
                        continue
                    if scope != "local":
                        result["errors"].append(_error("ledger", "local_scope_unknown"))
                demand = _demand(row, routed=kind == "routed")
                execution_id = row.get("execution_id")
                if row.get("lifecycle_managed") == 1 or execution_id:
                    execution = managed.get(execution_id)
                    binding = (kind, row["id"])
                    if (not execution or execution.get("allocation_kind") != kind
                            or execution.get("reservation_id") != row["id"]
                            or row.get("lifecycle_managed") != 1
                            or execution_id in seen_executions or binding in seen_bindings):
                        raise AccountingError("allocation_binding_mismatch")
                    if execution.get("state") in TERMINAL_STATES:
                        raise AccountingError("terminal_allocation_not_released")
                    if execution.get("state") not in ACTIVE_STATES:
                        raise AccountingError("execution_state_unknown")
                    demand = _managed_floor(execution, demand)
                    seen_bindings.add(binding)
                    seen_executions.add(execution_id)
                result["allocations"].append(dict(key=f"{kind}:{row['id']}", allocation_kind=kind,
                                                  reservation_id=row["id"], execution_id=execution_id,
                                                  demand=demand))
        for row in managed_rows:
            if row.get("state") in TERMINAL_STATES:
                continue
            if row.get("allocation_kind") == "parent":
                resolve_allocation_source(conn, row["execution_id"])
            elif row["execution_id"] not in seen_executions:
                # Remote managed allocations must not enter this local registry.
                raise AccountingError("allocation_missing")
        deductions, reasons = _attribution(frame, result["allocations"], managed, result["registry_revision"], measured)
        result["attribution_reasons"] = reasons
        for resource in RESOURCE_KEYS:
            result["projected"][resource] = (None if measured[resource] is None else measured[resource] + sum(
                max(0, allocation["demand"][resource] - deductions[allocation["key"]][resource])
                for allocation in result["allocations"]))
    except (AccountingError, KeyError, TypeError, ValueError) as error:
        reason = str(error) if isinstance(error, AccountingError) else "ledger_invalid"
        result["errors"].append(_error("policy" if reason == "policy_config_invalid" else "ledger", reason))
    return result


def _request_demand(request):
    if isinstance(request, Mapping):
        values = dict(request)
    elif hasattr(request, "to_dict"):
        values = request.to_dict()
    else:
        values = {key: getattr(request, key, None) for key in (*RESOURCE_KEYS, "ram_gib")}
    return _demand(values)


def shared_admission_blockers(conn, request, frame, config, *, exempt=False):
    """The common non-exempt resource gates, retaining legacy diagnostic names.

    ``exempt`` is an already verified authority result, never a request field.
    It bypasses load, telemetry availability and barrier checks only; invalid
    requests, schema, locality and allocation bindings stay closed.  A bypass
    does not change projection's unknown measurements into free capacity.
    """
    projection = project_local_capacity(conn, frame, config)
    result = list(projection["errors"])
    try:
        demand = _request_demand(request)
    except AccountingError:
        return result + [_error("request", "request_resources_invalid")]
    if exempt is True:
        bypassable = {
            ("telemetry", "status_stale"),
            ("policy", "policy_snapshot_unavailable"),
            ("telemetry", "telemetry_stale"),
            ("telemetry", "frame_invalid"),
            ("telemetry", "fast_frame_required"),
        }
        result = [error for error in result
                  if not isinstance(error, Mapping) or (error.get("resource"), error.get("reason")) not in bypassable]
    if result:
        return result
    if exempt is True:
        return []
    if projection["barrier"] != "NONE":
        return [_error("policy", "admission_barrier", barrier=projection["barrier"])]
    names = dict(cpu_units="cpu", physical_bytes="ram", commit_bytes="commit", io_slots="io")
    for resource in RESOURCE_KEYS:
        key = names[resource]
        projected = projection["projected"].get(resource)
        budget = projection["budgets"].get(resource)
        if projected is None or budget is None:
            result.append(_error(key, key + "_unknown"))
            continue
        available = max(0, budget - projected)
        if demand[resource] > available:
            scale = GIB if resource in {"physical_bytes", "commit_bytes"} else 1
            result.append(dict(resource=key, reason=key + "_capacity", required=round(demand[resource] / scale, 6),
                               available=round(available / scale, 6),
                               request_exceeds_host_budget=demand[resource] > budget))
    disk = _mapping(frame).get("disk") or {}
    if not disk.get("fresh"):
        result.append(_error("disk_space", "disk_telemetry_stale"))
        return result
    disk_free = _number(disk.get("free_gib"))
    floor = _number(config.get("disk_red_gb", 20) if demand["io_slots"] else config.get("disk_critical_gb", 5))
    if floor is None:
        return result + [_error("policy", "policy_config_invalid")]
    if disk_free is None:
        result.append(_error("disk_space", "disk_space_unknown"))
    elif disk_free <= floor:
        result.append(dict(resource="disk_space", reason="disk_space_capacity", required=floor, available=disk_free))
    if demand["io_slots"]:
        for field, key, setting, default in (("queue_length", "disk_queue", "disk_queue_red", 8),
                                              ("latency_ms", "disk_latency", "disk_latency_red_ms", 100)):
            observed, limit = _number(disk.get(field)), _number(config.get(setting, default))
            if limit is None:
                result.append(_error("policy", "policy_config_invalid"))
            elif observed is None:
                result.append(_error(key, key + "_unknown"))
            elif observed >= limit:
                result.append(dict(resource=key, reason="io_pressure", observed=observed, limit=limit))
    return result
