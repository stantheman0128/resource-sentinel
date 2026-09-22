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
import threading
from uuid import UUID, uuid4

from sentinel.adaptive.capability_evidence import S3_CASES
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity, strict_json_loads


TICKS_PER_SECOND = 10_000_000
OBSERVATION_SECONDS = 120
MAX_RAW_BYTES = 512 * 1024
MAX_EVENTS = 4096
MAX_ACTOR_LOGS = 16
MAX_TOTAL_EVENTS = 8192
MAX_TOTAL_RAW_BYTES = 2 * 1024 * 1024


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
        self._lock = threading.RLock()
        _require(not self.path.exists(), "s3_raw_log_already_exists")

    def append(self, event, **values):
        with self._lock:
            return self._append(event, **values)

    def _append(self, event, **values):
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
    records, total_bytes, count = [], 0, 0
    for path in paths:
        count += 1
        _require(count <= MAX_ACTOR_LOGS, "s3_actor_log_count_limit")
        size = Path(path).stat().st_size
        _require(total_bytes + size <= MAX_TOTAL_RAW_BYTES, "s3_actor_total_log_limit")
        following = read_actor_events(path, spec)
        _require(len(records) + len(following) <= MAX_TOTAL_EVENTS, "s3_actor_total_event_limit")
        # Append-only producers use canonical lines. Count actual decoded
        # bytes too, rather than trusting a pre-read file-size observation.
        total_bytes += max(size, sum(len(canonical(item)) + 1 for item in following))
        _require(total_bytes <= MAX_TOTAL_RAW_BYTES, "s3_actor_total_log_limit")
        records.extend(following)
    ready = [item for item in records if item.get("event") == "writer_instrumentation_ready" and
             item.get("boundary") == "NativeJob._set"]
    _require({item.get("role") for item in ready} == {"guardian", "supervisor"},
             "s3_writer_instrumentation_missing")
    # This is derived evidence, not a caller boolean or permission to actuate.
    # All original readiness records remain beside it for independent review.
    initial = [min((item["tick"] for item in ready if item["role"] == role))
               for role in ("guardian", "supervisor")]
    record = dict(ready[0], event="instrumentation_ready", tick=max(initial),
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


class RecoveryMatrix:
    """Fixed sequential 14 x 10 accounting, not a host/admission factory.

    The external original experiment owner creates the real hosts. This owner
    records only a finished NativeCaseObserver; it cannot accept a caller's
    summary, cleanup boolean or replacement callback. Missing native bootstrap
    still blocks execution before begin_case is useful.
    """
    schedule = tuple((case, iteration) for case, count in S3_CASES.items()
                     for iteration in range(1, count + 1))

    def __init__(self, directory, run_id):
        from sentinel.adaptive.capability_evidence import _safe_directory
        self.directory = Path(directory)
        _require(self.directory.is_absolute(), "s3_matrix_absolute_directory_required")
        _safe_directory(self.directory)
        self.directory = self.directory.resolve(strict=True)
        daily = (Path.home() / ".resource-sentinel").resolve()
        _require(self.directory != daily and daily not in self.directory.parents and
                 self.directory not in daily.parents, "s3_daily_runtime_forbidden")
        self.run_id = _uuid(run_id)
        self._pending = None
        self._pending_observer = None
        self._cases, self._nonces, self._observers = [], set(), []

    def begin_case(self, started_tick):
        _require(self._pending is None and len(self._cases) < len(self.schedule),
                 "s3_matrix_case_unsettled")
        case, iteration = self.schedule[len(self._cases)]
        scope_nonce = uuid4().hex
        _require(scope_nonce not in self._nonces, "s3_matrix_scope_reused")
        self._pending = CaseSpec(self.run_id, case, iteration, scope_nonce, started_tick)
        return self._pending

    def record_completed(self, observer, *, actor_paths, ended_tick):
        _require(type(observer) is NativeCaseObserver and observer.spec is self._pending and
                 observer.closed and observer.close_started and
                 not any(previous is observer for previous in self._observers),
                 "s3_matrix_original_completed_observer_required")
        spec = self._pending
        if self._pending_observer is None:
            self._pending_observer = observer
        _require(self._pending_observer is observer, "s3_matrix_original_completed_observer_required")
        _require(spec is not None and self.directory in observer.raw.path.resolve(strict=True).parents,
                 "s3_matrix_raw_scope_invalid")
        paths = []
        for path in actor_paths:
            _require(len(paths) < MAX_ACTOR_LOGS, "s3_actor_log_count_limit")
            paths.append(Path(path).resolve(strict=True))
        paths = tuple(paths)
        _require(paths and len(set(paths)) == len(paths) and
                 all(self.directory in path.parents for path in paths), "s3_matrix_raw_scope_invalid")
        events = collect_actor_events(paths, spec)
        result = reduce_case(spec, observations=observer.observations, events=events,
                             cleanup=observer._cleanup, ended_tick=ended_tick)
        # Write-once raw references precede advancement. A disk failure keeps
        # this exact completed observer reachable; no next case may begin.
        raw_paths = (observer.raw.path.resolve(strict=True), *paths)
        references = []
        for path in raw_paths:
            _require(path.stat().st_size <= MAX_RAW_BYTES, "s3_raw_log_limit")
            payload = path.read_bytes()
            _require(len(payload) <= MAX_RAW_BYTES, "s3_raw_log_limit")
            references.append(dict(path=str(path.relative_to(self.directory)),
                                   sha256=hashlib.sha256(payload).hexdigest()))
        write_new(self.directory / f"case-{len(self._cases) + 1:03d}.json",
                  dict(schema_version=1, purpose="recovery_spike", run_id=self.run_id,
                       scope_nonce=spec.scope_nonce, case=result, raw=references))
        self._cases.append(result)
        self._nonces.add(spec.scope_nonce)
        self._observers.append(observer)
        self._pending = None
        self._pending_observer = None
        return result

    def data(self):
        from sentinel.adaptive.capability_evidence import _cases
        _require(self._pending is None and len(self._cases) == len(self.schedule) and
                 len(self._nonces) == len(self.schedule), "s3_matrix_incomplete")
        data = dict(cases=strict_json_loads(canonical(self._cases)))
        _cases(data, S3_CASES, recovery=True)
        # Returning schema data is not publication or promotion. The existing
        # NativeEvidenceRun must still verify the unchanged host/build/profile.
        return data


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


def _case_events(events, name, spec, expected):
    records = [item for item in events if item.get("event") == name]
    _require(all(item.get("point") == spec.case and
                 (item.get("execution_id"), item.get("job_nonce")) == expected
                 for item in records), "s3_fault_effect_scope_mismatch")
    return records


def _event_identity(item, field):
    try:
        return ProcessIdentity.from_dict(item.get(field))
    except (TypeError, ValueError, KeyError, AttributeError):
        raise RecoveryRunUnavailable("s3_fault_identity_unverified") from None


def _single_case_event(events, name, spec, expected):
    records = _case_events(events, name, spec, expected)
    _require(len(records) == 1, "s3_" + name + "_unverified")
    return records[0]


def _case_fault_effect(spec, events, expected, fault, observed, restored):
    """Check actual case effects, not merely a label on a generic death log.

    Records are measurements from retained native owners. These checks grant no
    execution/recovery authority, and a producer missing an effect cannot fill
    it with an assumed value or borrow a different case's observation.
    """
    import math
    special = {"grant_before_cap", "audit_unavailable", "guardian_hang"}
    role = "wrapper" if spec.case == "wrapper_loss" else "guardian"
    _require(fault.get("role") == observed.get("role") == role,
             "s3_fault_actor_role_mismatch")
    original = _event_identity(fault, "actor_identity")
    _require(_event_identity(observed, "observed_identity") == original,
             "s3_fault_actor_identity_mismatch")
    if spec.case not in special:
        source = "retained_wrapper_witness" if spec.case == "wrapper_loss" else "retained_creation_witness"
        _require(observed.get("source") == source, "s3_fault_death_witness_unverified")
    if spec.case == "root_exit_after":
        root = _single_case_event(events, "root_exit_observed", spec, expected)
        _require(root.get("source") == "retained_root_witness" and
                 _event_identity(root, "observed_identity") != original and
                 _event_identity(root, "observed_identity") == _event_identity(fault, "root_identity") and
                 type(root.get("exit_code")) is int and 0 <= root["exit_code"] <= 0xFFFFFFFF and
                 _integer(root.get("active_processes"), minimum=1) >= 1 and
                 root["tick"] <= fault["tick"], "s3_root_child_survival_unverified")
    if spec.case == "guardian_hang":
        _require(observed.get("effect") == "hung_alive" and
                 observed.get("source") == "retained_creation_witness",
                 "s3_guardian_hang_unverified")
        fenced = _single_case_event(events, "guardian_fenced", spec, expected)
        _require(fenced.get("source") == "retained_creation_witness" and
                 _event_identity(fenced, "observed_identity") == original and
                 observed["tick"] < fenced["tick"] < restored["tick"],
                 "s3_guardian_fence_unverified")
    if spec.case == "audit_unavailable":
        _require(observed.get("effect") == "audit_write_failed" and
                 observed.get("source") == "audit_write_exception" and
                 type(observed.get("sqlite_errorcode")) is int and
                 observed["sqlite_errorcode"] & 0xff in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED},
                 "s3_audit_failure_unverified")
        acquired = _single_case_event(events, "audit_lock_acquired", spec, expected)
        released = _single_case_event(events, "audit_lock_released", spec, expected)
        _require(acquired.get("source") == released.get("source") == "sqlite_transaction" and
                 acquired["tick"] <= fault["tick"] <= observed["tick"] < restored["tick"] < released["tick"],
                 "s3_restore_during_audit_failure_unverified")
    if spec.case in {"grant_before_cap", "grant_commit_restore_before"}:
        committed = _single_case_event(events, "exemption_commit_observed", spec, expected)
        final = _single_case_event(events, "exemption_final_observed", spec, expected)
        lease = committed.get("exemption_id")
        _require(type(lease) is str and 1 <= len(lease) <= 128 and
                 final.get("exemption_id") == lease and
                 _event_identity(committed, "root_identity") == _event_identity(final, "root_identity") and
                 _integer(final.get("revision"), minimum=1) >= _integer(committed.get("revision"), minimum=1) and
                 committed["tick"] <= fault["tick"] and final["tick"] >= restored["tick"],
                 "s3_grant_commit_unverified")
        for field in ("created_at", "expires_at"):
            value = committed.get(field)
            _require(type(value) in (int, float) and math.isfinite(value) and value >= 0 and
                     final.get(field) == value, "s3_grant_deadline_changed")
        _require(committed["expires_at"] > committed["created_at"] and
                 all("revoked_at" in item and item["revoked_at"] is None and
                     type(item.get("active_count")) is int and 1 <= item["active_count"] <= 3
                     for item in (committed, final)), "s3_grant_not_preserved")
        if spec.case == "grant_before_cap":
            _require(observed.get("effect") == "restriction_rejected" and
                     observed.get("source") == "guardian_control_rejection",
                     "s3_grant_rejection_unverified")
    if spec.case == "guardian_takeover":
        from sentinel.adaptive.guardian_lifecycle import job_mutex_instance
        from sentinel.adaptive.policy import PolicyBinding
        fence_name = PolicyBinding(job_mutex_instance(*expected), original.logon_id).name
        lost = _single_case_event(events, "takeover_owner_lost", spec, expected)
        fence = _single_case_event(events, "recovery_fence_acquired", spec, expected)
        _require(lost.get("source") == "retained_creation_witness" and
                 _event_identity(lost, "observed_identity") not in
                     {original, _event_identity(fence, "actor_identity")} and
                 fence.get("source") == "native_mutex_wait" and
                 lost.get("fence_name") == fence.get("fence_name") == fence_name and
                 fence.get("abandoned") is True and type(fence.get("wait_result")) is int and
                 fence["wait_result"] == 128 and
                 observed["tick"] <= lost["tick"] < fence["tick"] < restored["tick"],
                 "s3_takeover_owner_death_unverified")
    if spec.case == "recovery_owner_race":
        from sentinel.adaptive.guardian_lifecycle import job_mutex_instance
        from sentinel.adaptive.policy import PolicyBinding
        fence_name = PolicyBinding(job_mutex_instance(*expected), original.logon_id).name
        ready = _case_events(events, "recovery_contender_ready", spec, expected)
        identities = [_event_identity(item, "actor_identity") for item in ready]
        _require(len(ready) >= 2 and len(set(identities)) == len(ready) and
                 original not in identities and all(item.get("source") == "retained_creation_witness" and
                 item["tick"] <= fault["tick"] for item in ready), "s3_recovery_race_not_exercised")
        acquired = _single_case_event(events, "recovery_fence_acquired", spec, expected)
        contended = _single_case_event(events, "recovery_fence_contended", spec, expected)
        winner, loser = (_event_identity(item, "actor_identity") for item in (acquired, contended))
        _require(winner != loser and winner in identities and loser in identities and
                 acquired.get("source") == contended.get("source") == "native_mutex_wait" and
                 acquired.get("fence_name") == contended.get("fence_name") == fence_name and
                 type(acquired.get("wait_result")) is int and acquired["wait_result"] in {0, 128} and
                 type(contended.get("wait_result")) is int and contended["wait_result"] == 258 and
                 observed["tick"] <= acquired["tick"] <= contended["tick"] < restored["tick"],
                 "s3_recovery_race_fence_unverified")
    if spec.case == "independent_supervisor_recovery":
        ready = _single_case_event(events, "independent_recovery_ready", spec, expected)
        alive = _single_case_event(events, "independent_recovery_alive", spec, expected)
        supervisor = _event_identity(ready, "actor_identity")
        actors = {role: _event_identity(ready, role + "_identity") for role in ("guardian", "helper", "wrapper")}
        _require(actors["guardian"] == original and len(set(actors.values()) | {supervisor}) == 4 and
                 _event_identity(alive, "observed_identity") == supervisor and
                 ready.get("source") == alive.get("source") == "retained_creation_witness" and
                 ready["tick"] <= fault["tick"], "s3_independent_original_owner_unverified")
        deaths = _case_events(events, "actor_death_observed", spec, expected)
        _require(len(deaths) == 2 and {item.get("role") for item in deaths} == {"helper", "wrapper"},
                 "s3_common_failure_not_exercised")
        for item in deaths:
            _require(item.get("source") == "retained_creation_witness" and
                     _event_identity(item, "observed_identity") == actors[item["role"]] and
                     fault["tick"] <= item["tick"] <= alive["tick"], "s3_common_failure_not_exercised")
        _require(observed["tick"] <= alive["tick"] < restored["tick"],
                 "s3_independent_recovery_unverified")


def _control_cutpoint(spec, events, expected, fault, writes, attempts):
    """Validate the captured original control boundary, never a case label alone."""
    cases = {"intent_before", "intent_after_set_before", "set_after_query_before",
             "query_after_audit_before", "lease_renewal", "guardian_hang"}
    if spec.case not in cases:
        return
    from dataclasses import fields
    from sentinel.adaptive.contracts import ControlProposal, CpuControl, CpuControlMode, RecoveryManifest
    from sentinel.adaptive.control_slot import ControlAction
    cut = _single_case_event(events, "control_cutpoint", spec, expected)
    _require(all(key in cut for key in ("boundary", "actor_identity", "manifest", "proposal", "action_id",
                 "desired", "action", "native_set_attempt_id", "previous_lease_deadline_tick_100ns")),
             "s3_control_cutpoint_fields_missing")
    try:
        manifest = RecoveryManifest.from_dict(cut.get("manifest"))
        proposal = ControlProposal.from_dict(cut.get("proposal"))
        desired = CpuControl.from_dict(cut.get("desired"))
    except (TypeError, ValueError, KeyError, AttributeError):
        raise RecoveryRunUnavailable("s3_control_cutpoint_contract_invalid") from None
    action_id = cut.get("action_id")
    _uuid(action_id)
    boundary = "set_after_query_before" if spec.case == "guardian_hang" else spec.case
    _require(cut.get("boundary") == boundary and cut["tick"] <= fault["tick"] and
             _event_identity(cut, "actor_identity") == _event_identity(fault, "actor_identity") ==
                 manifest.guardian_identity and
             (manifest.execution_id, manifest.creation_nonce) == expected and
             manifest.root_identity is not None and
             proposal.execution_id == manifest.execution_id and
             proposal.guardian_epoch == manifest.guardian_epoch and
             proposal.decision_seq > 0 and proposal.sample_seq > 0 and
             spec.started_tick <= proposal.decision_tick_100ns <= cut["tick"] and
             desired.mode is proposal.target.mode is CpuControlMode.HARD_CAP and
             desired.cpu_rate_bp == proposal.target.cpu_rate_bp,
             "s3_control_cutpoint_binding_unverified")
    # Before the first intent there is no cap or pending transition. An ACKed
    # intent binds this action exactly, but is not evidence that Set ran.
    disabled = CpuControl(CpuControlMode.DISABLED, None)
    effective = manifest.last_applied or manifest.original
    if boundary == "intent_before":
        _require(manifest.pending_intent is None and effective == disabled,
                 "s3_control_intent_preimage_unverified")
    elif boundary in {"intent_after_set_before", "set_after_query_before"}:
        pending = manifest.pending_intent
        _require(manifest.manifest_seq >= 1 and effective == disabled and pending is not None and
                 pending.action_id == action_id and pending.old == disabled and pending.new == desired,
                 "s3_control_published_intent_unverified")
    else:
        _require(manifest.manifest_seq >= 2 and manifest.pending_intent is None and
                 manifest.last_applied == desired, "s3_control_settled_manifest_unverified")
    before_cut = [item for item in writes if item["tick"] <= cut["tick"]]
    if boundary in {"intent_before", "intent_after_set_before"}:
        _require(not any(item.get("desired_flags") == 5 and item["tick"] <= fault["tick"]
                         for item in (*writes, *attempts)), "s3_control_set_before_intent_fault")
    if boundary == "set_after_query_before":
        matching = [item for item in before_cut if item.get("attempt_id") == cut.get("native_set_attempt_id")]
        _require(len(matching) == 1 and matching[0] is max(before_cut, key=lambda item: item["tick"]) and
                 matching[0].get("role") == "guardian" and
                 matching[0].get("desired_flags") == 5 and
                 type(matching[0].get("desired_rate_bp")) is int and
                 matching[0].get("desired_rate_bp") == desired.cpu_rate_bp and
                 proposal.decision_tick_100ns <= matching[0]["before_tick"] and
                 not any(item["tick"] > matching[0]["tick"] and item["tick"] <= fault["tick"]
                         for item in attempts), "s3_control_native_set_unverified")
    else:
        _require(cut.get("native_set_attempt_id") is None, "s3_control_native_set_unexpected")
    action = cut.get("action")
    previous = cut.get("previous_lease_deadline_tick_100ns")
    if boundary not in {"query_after_audit_before", "lease_renewal"}:
        _require(action is None and previous is None, "s3_control_audit_boundary_unverified")
        return
    _require(type(action) is dict and set(action) == {field.name for field in fields(ControlAction)},
             "s3_control_action_unverified")
    state = "RENEWED" if boundary == "lease_renewal" else "APPLIED"
    _require(action["execution_id"] == expected[0] and action["guardian_epoch"] == manifest.guardian_epoch and
             action["action_id"] == action_id and type(action["decision_seq"]) is int and
             action["decision_seq"] == proposal.decision_seq and type(action["sample_seq"]) is int and
             action["sample_seq"] == proposal.sample_seq and action["action_state"] == state and
             action["desired_mode"] == "hard_cap" and type(action["desired_rate_bp"]) is int and
             action["desired_rate_bp"] == desired.cpu_rate_bp and type(action["applied_flags"]) is int and
             action["applied_flags"] == 5 and type(action["applied_rate_bp"]) is int and
             action["applied_rate_bp"] == desired.cpu_rate_bp and action["reason"] == proposal.reason and
             action["win32_error"] is None, "s3_control_action_unverified")
    queried = _integer(action["applied_tick_100ns"])
    lease = _integer(action["lease_deadline_tick_100ns"])
    intervention = _integer(action["intervention_deadline_tick_100ns"])
    _require(proposal.decision_tick_100ns <= queried <= cut["tick"] < lease <= intervention and
             lease <= proposal.sample_window_end_tick_100ns + 6 * TICKS_PER_SECOND and
             intervention <= proposal.decision_tick_100ns + 60 * TICKS_PER_SECOND,
             "s3_control_query_lease_unverified")
    _require(before_cut, "s3_control_query_native_set_unverified")
    latest = max(before_cut, key=lambda item: item["tick"])
    _require(latest.get("role") == "guardian" and latest.get("desired_flags") == 5 and
             type(latest.get("desired_rate_bp")) is int and
             latest.get("desired_rate_bp") == desired.cpu_rate_bp and latest["tick"] <= queried and
             not any(queried < item["tick"] <= fault["tick"] for item in attempts),
             "s3_control_query_native_set_unverified")
    if boundary == "lease_renewal":
        _require(type(previous) is int and queried < previous < lease and
                 not any(proposal.decision_tick_100ns <= item["tick"] <= fault["tick"] for item in attempts),
                 "s3_control_lease_renewal_unverified")
    else:
        _require(previous is None and proposal.decision_tick_100ns <= latest["before_tick"],
                 "s3_control_apply_boundary_unverified")


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
    observed = _case_events(events, "fault_observed", spec, expected)
    _require(len(observed) == 1, "s3_fault_effect_unverified")
    observed_tick = min(_integer(item.get("tick"), minimum=fault_tick) for item in observed)
    disabled = [item for item in observations if item["tick"] > observed_tick and
                item["cpu_flags"] == 0 and item["active_processes"] > 0]
    _require(disabled, "s3_restore_query_missing")
    restored = min(disabled, key=lambda item: item["tick"])
    _case_fault_effect(spec, events, expected, faults[0], observed[0], restored)
    # Simultaneous owner loss has only eventual recovery, never the 8s claim.
    if spec.case != "independent_supervisor_recovery":
        _require(restored["tick"] - fault_tick <= 8 * TICKS_PER_SECOND, "s3_single_fault_restore_too_slow")
    ready = [item for item in events if item.get("event") == "instrumentation_ready" and
             item.get("native_writers") == ["guardian", "retained_supervisor"]]
    _require(ready,
             "s3_writer_instrumentation_missing")
    writes = [item for item in events if item.get("event") == "cpu_write"]
    attempts = [item for item in events if item.get("event") == "cpu_write_attempt"]
    _require(all(item.get("role") in {"guardian", "retained_supervisor"} for item in (*attempts, *writes)) and
             (not attempts or min(item["tick"] for item in ready) <= min(item["tick"] for item in attempts)),
             "s3_writer_instrumentation_unverified")
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
                 ("before_tick", "execution_id", "job_nonce", "desired_flags", "desired_rate_bp", "role")),
                 "s3_writer_instrumentation_unverified")
        completions.add(item["attempt_id"])
    if spec.case not in {"intent_before", "intent_after_set_before", "grant_before_cap"}:
        before_fault = [item for item in writes if item["tick"] <= fault_tick]
        _require(before_fault and all(type(item.get("desired_flags")) is int for item in before_fault) and
                 max(before_fault, key=lambda item: item["tick"])["desired_flags"] == 5 and
                 any((item.get("execution_id"), item.get("job_nonce")) == expected and
                     type(item.get("desired_flags")) is int and item["desired_flags"] == 5 and
                     spec.started_tick < item["tick"] <= fault_tick for item in writes),
                 "s3_initial_native_set_unverified")
    _require(not any(item.get("desired_flags") == 5 and item["tick"] >= restored["tick"]
                     for item in (*writes, *attempts)), "s3_restriction_after_restore")
    if spec.case in {"grant_before_cap", "grant_commit_restore_before"}:
        grants = [item for item in events if item.get("event") == "exemption_commit_observed" and
                  (item.get("execution_id"), item.get("job_nonce")) == expected and item["tick"] <= fault_tick]
        _require(len(grants) == 1, "s3_grant_commit_unverified")
        _require(not any(item.get("desired_flags") == 5 and
                     (spec.case == "grant_before_cap" or item["tick"] >= grants[0]["tick"])
                     for item in (*writes, *attempts)),
                 "s3_restriction_after_exemption")
    wrong = sum(1 for item in writes if item.get("execution_id") != restored["execution_id"] or
                item.get("job_nonce") != restored["job_nonce"])
    kills = [item for item in events if item.get("event") == "process_fault_termination"]
    targets = {(faults[0]["role"], _event_identity(faults[0], "actor_identity"))}
    if spec.case == "guardian_takeover":
        lost = _single_case_event(events, "takeover_owner_lost", spec, expected)
        targets.add(("retained_supervisor", _event_identity(lost, "observed_identity")))
    if spec.case == "independent_supervisor_recovery":
        ready = _single_case_event(events, "independent_recovery_ready", spec, expected)
        targets.update((role, _event_identity(ready, role + "_identity")) for role in ("helper", "wrapper"))
    workload_kills = 0
    for item in kills:
        if (item.get("role") not in {role for role, _ in targets} or
                item.get("original_creation_handle_verified") is not True):
            workload_kills += 1
            continue
        if ((item["role"], _event_identity(item, "actor_identity")) not in targets or
                item.get("point") != spec.case or
                (item.get("execution_id"), item.get("job_nonce")) != expected):
            workload_kills += 1
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
    _control_cutpoint(spec, events, expected, faults[0], writes, attempts)
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
