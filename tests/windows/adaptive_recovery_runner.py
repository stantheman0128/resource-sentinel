"""S3 native recovery observations for real isolated production hosts.

The producer consumes actual Job readback, the production SQLite ledger and
retained native process identities. A JSON rendezvous is a locator/event log;
it is never admission, launch authority or a replacement for an original owner.
Every case has the fixed external 120-second observation bound. Cleanup cannot
restart that clock, turn workload death into restoration, or erase a failure.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from uuid import UUID

from sentinel.adaptive.capability_evidence import S3_CASES
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, strict_json_loads


TICKS_PER_SECOND = 10_000_000
OBSERVATION_SECONDS = 120
MAX_RAW_BYTES = 512 * 1024
MAX_EVENTS = 4096


class RecoveryRunUnavailable(RuntimeError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _require(condition, reason):
    if not condition:
        raise RecoveryRunUnavailable(reason)


def _integer(value, *, minimum=0):
    _require(type(value) is int and minimum <= value < 1 << 64, "s3_integer_evidence_invalid")
    return value


def _uuid(value):
    try:
        parsed = UUID(value) if type(value) is str else None
        _require(parsed is not None and parsed.int and str(parsed) == value, "s3_run_identity_invalid")
    except (ValueError, TypeError, AttributeError):
        raise RecoveryRunUnavailable("s3_run_identity_invalid") from None
    return value


def _tick():
    from tests.windows.adaptive_win32 import interrupt_time_100ns
    return interrupt_time_100ns()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def write_new(path, value):
    raw = canonical(value)
    _require(len(raw) <= MAX_RAW_BYTES, "s3_evidence_size_limit")
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CaseSpec:
    run_id: str
    case: str
    iteration: int
    scope_nonce: str
    started_tick: int

    def __post_init__(self):
        _uuid(self.run_id)
        _require(self.case in S3_CASES, "s3_fault_case_unknown")
        _require(type(self.iteration) is int and 1 <= self.iteration <= S3_CASES[self.case],
                 "s3_iteration_invalid")
        _require(type(self.scope_nonce) is str and re.fullmatch(r"[0-9a-f]{32}", self.scope_nonce),
                 "s3_scope_nonce_invalid")
        _integer(self.started_tick, minimum=1)

    @property
    def deadline_tick(self):
        return self.started_tick + OBSERVATION_SECONDS * TICKS_PER_SECOND

    def check_time(self, now):
        _require(self.started_tick <= _integer(now) <= self.deadline_tick, "s3_observation_deadline")


class RawEvents:
    """Bounded local records, never interpreted as permission to act."""
    def __init__(self, spec, path):
        self.spec, self.path = spec, Path(path)
        self.records, self.bytes = [], 0
        _require(not self.path.exists(), "s3_raw_log_already_exists")

    def append(self, event, **values):
        _require(type(event) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", event),
                 "s3_event_invalid")
        record = dict(run_id=self.spec.run_id, case=self.spec.case, iteration=self.spec.iteration,
                      scope_nonce=self.spec.scope_nonce, event=event, **values)
        raw = canonical(record) + b"\n"
        _require(len(self.records) < MAX_EVENTS and self.bytes + len(raw) <= MAX_RAW_BYTES,
                 "s3_raw_log_limit")
        with self.path.open("ab") as stream:
            stream.write(raw)
            stream.flush()
        self.records.append(record)
        self.bytes += len(raw)
        return record


def read_actor_events(path, spec):
    path = Path(path)
    _require(path.stat().st_size <= MAX_RAW_BYTES, "s3_actor_log_limit")
    raw = path.read_bytes()
    _require(len(raw) <= MAX_RAW_BYTES, "s3_actor_log_limit")
    lines = raw.splitlines()
    _require(0 < len(lines) <= MAX_EVENTS and raw.endswith(b"\n"), "s3_actor_log_incomplete")
    records = []
    for line in lines:
        row = strict_json_loads(line)
        _require(type(row) is dict and all(row.get(key) == getattr(spec, key)
                 for key in ("run_id", "case", "iteration", "scope_nonce")), "s3_actor_binding_changed")
        tick = _integer(row.get("tick"), minimum=spec.started_tick)
        _require(tick <= spec.deadline_tick, "s3_actor_event_after_deadline")
        records.append(row)
    return records


def collect_actor_events(paths, spec):
    """Combine real actor logs; readiness requires both native writer hooks."""
    records = [item for path in paths for item in read_actor_events(path, spec)]
    ready = [item for item in records if item.get("event") == "writer_instrumentation_ready" and
             item.get("boundary") == "NativeJob._set"]
    _require({item.get("role") for item in ready} == {"guardian", "supervisor"},
             "s3_writer_instrumentation_missing")
    # This is derived evidence, not a caller boolean or permission to actuate.
    # All original readiness records remain beside it for independent review.
    record = dict(ready[0], event="instrumentation_ready", tick=max(item["tick"] for item in ready),
                  native_writers=["guardian", "retained_supervisor"])
    record.pop("role", None)
    records.append(record)
    return sorted(records, key=lambda item: item["tick"])


def _read_ledger(path, execution_id):
    # URI read-only prevents an observation from creating/migrating a ledger.
    connection = sqlite3.connect(Path(path).resolve(strict=True).as_uri() + "?mode=ro",
                                 uri=True, timeout=.25, isolation_level=None)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        row = connection.execute("SELECT * FROM managed_executions WHERE execution_id=?",
                                 (execution_id,)).fetchone()
        _require(row is not None, "s3_execution_missing")
        direct = connection.execute("SELECT id FROM reservations WHERE execution_id=? OR id=?",
                                     (execution_id, row["reservation_id"])).fetchall()
        routed = connection.execute("SELECT id FROM worker_reservations WHERE execution_id=?",
                                     (execution_id,)).fetchall()
        archive = connection.execute("SELECT outcome FROM executions WHERE reservation_id=?",
                                      (row["reservation_id"],)).fetchall()
        slot = connection.execute("SELECT * FROM adaptive_control_slot WHERE singleton=1").fetchone()
        runtime = connection.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
        connection.execute("COMMIT")
        return dict(row), dict(direct_allocations=len(direct), routed_allocations=len(routed),
            archive_outcomes=[entry[0] for entry in archive], slot=None if slot is None else dict(slot),
            runtime=None if runtime is None else dict(runtime))
    finally:
        connection.close()


class NativeCaseObserver:
    """Retain a QUERY-only Job while the exact original wrapper is alive.

    Construct only after the real wrapper's BindRoot acknowledgement. The
    supplied wrapper is the original retained process witness captured by the
    fixture launcher. An ID in case.json cannot construct that authority.
    """
    def __init__(self, *, data_directory, execution_id, wrapper, spec, raw_events):
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.native_job import NativeJob, JobAccess
        _require(type(wrapper) is VerifiedProcess, "s3_original_wrapper_required")
        _uuid(execution_id)
        self.spec, self.raw = spec, raw_events
        self.directory = Path(data_directory).resolve(strict=True)
        daily = (Path.home() / ".resource-sentinel").resolve()
        _require(self.directory != daily and daily not in self.directory.parents,
                 "s3_daily_runtime_forbidden")
        self.execution_id, self.wrapper = execution_id, wrapper
        self.job, self.closed, self.close_started = None, False, False
        self.observations = []
        self._row, ledger = _read_ledger(self.directory / "sentinel.db", execution_id)
        self._binding = {name: self._row[name] for name in (
            "execution_id", "spec_hash", "reservation_id", "guardian_epoch", "job_name", "job_nonce",
            "wrapper_pid", "wrapper_created_filetime_100ns", "root_pid", "root_created_filetime_100ns", "logon_id")}
        observed = wrapper.observe()
        _require(observed.status is IdentityStatus.ALIVE and observed.identity == wrapper.identity,
                 "s3_wrapper_initial_witness_unverified")
        _require((self._row["wrapper_pid"], self._row["wrapper_created_filetime_100ns"], self._row["logon_id"]) ==
                 (wrapper.identity.pid, str(wrapper.identity.created_filetime_100ns), wrapper.identity.logon_id),
                 "s3_wrapper_binding_mismatch")
        _require(self._row["state"] == "RUNNING" and self._row["coverage"] == "job_contained" and
                 self._row["launch_sealed"] == 1 and self._row["launch_in_flight"] == 0 and
                 ledger["direct_allocations"] == 1 and ledger["routed_allocations"] == 0,
                 "s3_real_bound_allocation_required")
        self.job = NativeJob.open(self._row["job_name"], self._row["job_nonce"],
                                  self._row["logon_id"], access=JobAccess.QUERY)
        try:
            _require(wrapper.is_in_job(self.job.handle) is False, "s3_wrapper_in_work_job")
            _require(self.job.query_limits().limit_flags == 0 and
                     self.job.query_limits().ui_restrictions == 0, "s3_unsafe_job_limits")
            self.observe()
        except BaseException as error:
            error.recovery_case_observer = self
            raise

    def observe(self):
        _require(not self.closed and not self.close_started, "s3_query_owner_closed")
        before = _tick()
        cpu = self.job.query_cpu()
        accounting = self.job.accounting()
        members = self.job.active_pids()
        row, ledger = _read_ledger(self.directory / "sentinel.db", self.execution_id)
        _require(all(row[key] == value for key, value in self._binding.items()), "s3_scope_binding_changed")
        after = _tick()
        _require(accounting.active_processes == len(members), "s3_membership_observation_unstable")
        snapshot = self.raw.append("native_query", tick=after, before_tick=before,
            execution_id=self.execution_id, job_nonce=self.job.nonce,
            cpu_flags=cpu.flags, cpu_rate_bp=cpu.rate_bp,
            active_processes=accounting.active_processes, total_processes=accounting.total_processes,
            user_100ns=accounting.user_100ns, kernel_100ns=accounting.kernel_100ns,
            lifecycle_state=row["state"], state_revision=row["state_revision"], **ledger)
        self.observations.append(snapshot)
        return snapshot

    def finish(self, journal_directory, *, actor_custody):
        """Verify restoration, real final accounting, then close this handle."""
        from sentinel.adaptive.recovery_journal import RecoveryJournal
        if self.closed:
            return dict(self._cleanup)
        _require(not self.close_started, "s3_cleanup_outcome_unknown")
        final = self.observe()
        _require(final["cpu_flags"] == 0 and final["active_processes"] == 0,
                 "s3_native_cleanup_not_empty_disabled")
        _require(final["lifecycle_state"] == "FINISHED" and final["archive_outcomes"] == ["managed_finished"] and
                 final["direct_allocations"] == final["routed_allocations"] == 0,
                 "s3_final_accounting_unverified")
        journal = RecoveryJournal(journal_directory)
        manifest = journal.read(self.execution_id, creation_nonce=self.job.nonce)
        _require(manifest.pending_intent is None and manifest.original.mode.value == "disabled" and
                 (manifest.last_applied is None or manifest.last_applied.mode.value == "disabled"),
                 "s3_manifest_not_settled")
        slot = final["slot"]
        _require(slot is None or slot["slot_state"] == "RESTORED", "s3_control_slot_not_settled")
        _require(final["runtime"] is not None and final["runtime"]["policy_entry_nonce"] is None,
                 "s3_policy_guard_unsettled")
        # Query flags/empty/archive do not prove other native owners closed.
        # Only this original parent's retained creation witnesses certify its
        # fixture actors have really exited and every local close succeeded.
        _require(type(actor_custody) is ActorCustody and actor_custody.settled,
                 "s3_actor_custody_unsettled")
        self.close_started = True
        self.job.close()
        self.closed = True
        self._cleanup = dict(cpu_flags=0, active_processes=0, pending_intents=0,
                             unsettled_handles=0, live_allocations=0)
        return dict(self._cleanup)


class ActorCustody:
    """Original subprocess/identity owners; never reconstruct them from PIDs.

    Construction is not closure evidence. A case runner adds each actual
    Popen's retained creation witness before observing or faulting the actor.
    Unknown native close stays quarantined, including on subsequent calls.
    No method terminates a process, cancels admission or releases capacity.
    """
    def __init__(self):
        self._actors, self._closed, self._unknown = [], set(), {}

    def retain(self, role, process, witness):
        from sentinel.adaptive.identity import VerifiedProcess
        import subprocess
        _require(role in {"supervisor", "shell", "wrapper", "guardian", "helper"},
                 "s3_actor_role_invalid")
        _require(type(process) is subprocess.Popen and type(witness) is VerifiedProcess,
                 "s3_actor_original_creation_required")
        _require(not self._closed and not self._unknown and
                 all(item[1] is not process and item[2] is not witness for item in self._actors),
                 "s3_actor_custody_changed")
        _require(process.pid == witness.identity.pid, "s3_actor_identity_mismatch")
        self._actors.append((role, process, witness))

    @property
    def settled(self):
        return bool(self._actors) and not self._unknown and len(self._closed) == len(self._actors)

    def settle_exited(self):
        for index, (_, process, witness) in enumerate(self._actors):
            if index in self._closed:
                continue
            if index in self._unknown:
                return False
            observation = witness.observe()
            if (observation.identity != witness.identity or observation.status is not IdentityStatus.DEAD or
                    process.poll() is None):
                return False
            # The witness owns a duplicate; Python retains the original Popen
            # handle too. Close both actual owners, tombstone each success.
            record = self._unknown[index] = {"witness_closed": False, "process_closed": False}
            try:
                witness.close()
                record["witness_closed"] = True
                original = getattr(process, "_handle", None)
                _require(original is not None, "s3_actor_creation_handle_missing")
                original.Close()
                record["process_closed"] = True
            except BaseException as error:
                record["error"] = error
                raise
            self._closed.add(index)
            del self._unknown[index]
        return self.settled


def reduce_case(spec, *, observations, events, cleanup, ended_tick):
    """Reduce original measurements; missing observations never become zeros."""
    spec.check_time(ended_tick)
    _require(observations and events, "s3_evidence_incomplete")
    for item in (*observations, *events):
        _require(type(item) is dict and all(item.get(key) == getattr(spec, key)
                 for key in ("run_id", "case", "iteration", "scope_nonce")), "s3_actor_binding_changed")
        _require(spec.started_tick <= _integer(item.get("tick")) <= ended_tick,
                 "s3_event_outside_observation")
    expected = (observations[0].get("execution_id"), observations[0].get("job_nonce"))
    _uuid(expected[0])
    _require(type(expected[1]) is str and re.fullmatch(r"[0-9a-f]{32}", expected[1]), "s3_job_nonce_invalid")
    _require(all((item.get("execution_id"), item.get("job_nonce")) == expected for item in observations),
             "s3_scope_binding_changed")
    _require(all(first["tick"] <= second["tick"] for first, second in zip(observations, observations[1:])),
             "s3_observation_order_invalid")
    faults = [item for item in events if item.get("event") == "fault_injected"]
    _require(len(faults) == 1 and faults[0].get("point") == spec.case, "s3_fault_not_observed")
    _require((faults[0].get("execution_id"), faults[0].get("job_nonce")) == expected,
             "s3_fault_scope_mismatch")
    fault_tick = _integer(faults[0].get("tick"), minimum=spec.started_tick + 1)
    observed = [item for item in events if item.get("event") == "fault_observed"]
    _require(observed, "s3_fault_effect_unverified")
    observed_tick = min(_integer(item.get("tick"), minimum=fault_tick) for item in observed)
    disabled = [item for item in observations if item["tick"] > observed_tick and
                item["cpu_flags"] == 0 and item["active_processes"] > 0]
    _require(disabled, "s3_restore_query_missing")
    restored = min(disabled, key=lambda item: item["tick"])
    # Simultaneous owner loss has only eventual recovery, never the 8s claim.
    if spec.case != "independent_supervisor_recovery":
        _require(restored["tick"] - fault_tick <= 8 * TICKS_PER_SECOND, "s3_single_fault_restore_too_slow")
    _require(any(item.get("event") == "instrumentation_ready" and
                 item.get("native_writers") == ["guardian", "retained_supervisor"] for item in events),
             "s3_writer_instrumentation_missing")
    writes = [item for item in events if item.get("event") == "cpu_write"]
    attempts = [item for item in events if item.get("event") == "cpu_write_attempt"]
    _require(not any(item.get("event") == "cpu_write_unknown" for item in events),
             "s3_writer_instrumentation_unverified")
    attempt_ids = [item.get("attempt_id") for item in attempts]
    _require(all(type(value) is str for value in attempt_ids) and len(set(attempt_ids)) == len(attempts) and
             len(writes) == len(attempts), "s3_writer_instrumentation_unverified")
    completions = set()
    for item in writes:
        _require(item.get("attempt_id") not in completions, "s3_writer_instrumentation_unverified")
        matching = [start for start in attempts if start.get("attempt_id") == item.get("attempt_id")]
        _require(len(matching) == 1 and all(matching[0].get(key) == item.get(key) for key in
                 ("before_tick", "execution_id", "job_nonce", "desired_flags", "desired_rate_bp")),
                 "s3_writer_instrumentation_unverified")
        completions.add(item["attempt_id"])
    if spec.case not in {"intent_before", "intent_after_set_before", "grant_before_cap"}:
        _require(any((item.get("execution_id"), item.get("job_nonce")) == expected and
                     type(item.get("desired_flags")) is int and item["desired_flags"] == 5 and
                     spec.started_tick < item["tick"] <= fault_tick for item in writes),
                 "s3_initial_native_set_unverified")
    if spec.case in {"grant_before_cap", "grant_commit_restore_before"}:
        grants = [item for item in events if item.get("event") == "exemption_commit_observed" and
                  (item.get("execution_id"), item.get("job_nonce")) == expected and item["tick"] <= fault_tick]
        _require(len(grants) == 1, "s3_grant_commit_unverified")
        _require(not any(item.get("desired_flags") == 5 and item["tick"] >= grants[0]["tick"] for item in writes),
                 "s3_restriction_after_exemption")
    wrong = sum(1 for item in writes if item.get("execution_id") != restored["execution_id"] or
                item.get("job_nonce") != restored["job_nonce"])
    kills = [item for item in events if item.get("event") == "process_fault_termination"]
    workload_kills = sum(1 for item in kills if item.get("role") not in {"guardian", "helper", "wrapper"} or
                         item.get("original_creation_handle_verified") is not True)
    premature = sum(1 for item in observations if item["active_processes"] > 0 and
                    (item["direct_allocations"] != 1 or item["routed_allocations"] != 0 or
                     item["archive_outcomes"]))
    intervals = sorted((_integer(item.get("before_tick")), _integer(item.get("tick"))) for item in writes)
    _require(all(spec.started_tick <= start <= end <= ended_tick for start, end in intervals),
             "s3_writer_interval_invalid")
    overlap = sum(1 for first, second in zip(intervals, intervals[1:]) if second[0] < first[1])
    owners = []
    for item in observations:
        slot = item["slot"]
        owners.append(0 if slot is None or slot["slot_state"] == "RESTORED" else 1)
        _require(slot is None or slot["execution_id"] == item["execution_id"], "s3_foreign_control_slot")
    _require(wrong == workload_kills == premature == overlap == 0, "s3_safety_invariant_failed")
    _require(type(cleanup) is dict and set(cleanup) == {"cpu_flags", "active_processes", "pending_intents",
                                                     "unsettled_handles", "live_allocations"} and
             all(type(value) is int and value == 0 for value in cleanup.values()), "s3_cleanup_unverified")
    return dict(case=spec.case, iteration=spec.iteration, observations=dict(
        started_tick=spec.started_tick, ended_tick=ended_tick, wrong_pid_mutations=wrong,
        workload_kills=workload_kills, premature_releases=premature, fault_tick=fault_tick,
        fault_observed_tick=observed_tick, disabled_query_tick=restored["tick"], disabled_flags=0,
        remaining_members_before_stop=restored["active_processes"], writer_overlap_count=overlap,
        slot_owner_count=max(owners), fault_observations=len(observed), scope_nonce=spec.scope_nonce),
        cleanup=dict(cleanup))
