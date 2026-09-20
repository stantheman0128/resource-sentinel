"""Runnable shadow helper process host: py -m sentinel.adaptive.helper_host.

This wires the existing observation libraries into one resident process. It owns
no policy of its own. The profile parser, the frame sampler, the shadow helper
and the machine sampler are the production modules, and the host capability
preflight is the live one in host_authority.py.

One iteration is an optional enrollment refresh, exactly one ShadowHelper.tick()
and one paced wait. A late tick runs once. The helper already counts the ticks
it missed, so this loop never replays them.

Shadow is the only mode that runs here. The profile file is the only way to
reach it: this host never passes the in-process shadow flag to ShadowHelper, and
decision.validate_policy_profile already refuses enforce from a configuration
file. A profile in mode off refuses at startup.

What this host never does: it never creates a Job, never asks for control or
owner rights on one, never sets or withdraws a CPU rate, never terminates,
suspends or trims a process, never builds a ControlProposal and never writes a
ledger mode. The only thing it writes to the ledger is its own row in
adaptive_infrastructure. Everything else it does with the ledger is a bounded
read-only snapshot.

Startup refuses before it opens anything when the host capability preflight
refuses. On a machine whose processes run inside a parent Job the refusal is
host_foreign_parent_job, and that is the expected result there.

Registration is fail closed. A helper row for this logon that is not this exact
process blocks startup, because control_transport.registered_helper refuses a
logon with more than one helper row and a second row would create exactly that
state. There is no live deregistration function in this repository, so the row
this host writes stays after a clean exit. See
docs/planning/adaptive-scheduler/P4-HELPER-HOST.md for the restart gap that
follows from it.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import time
from uuid import UUID, uuid4

from .contracts import (
    Coverage, FrameError, MAX_ENROLLED_JOBS, Priority, RetryClass, Role, TICKS_PER_SECOND,
    UINT64_MAX, Validity,
)
from .host_authority import HostCapabilityUnsupported, read_host_capability
from .sampler import JobReading, JobSamplingError, MachineObservation, MAX_FRAME_ERRORS
from .store import LifecycleError


EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_FAILED = 5
DEFAULT_PROFILE = Path(__file__).resolve().parents[2] / "config" / "adaptive.example.json"
DEFAULT_ENROLL_EVERY = 5
DEFAULT_REPORT_EVERY = 10
# The same bounded read the other private readers use for an authentication or
# registry snapshot.
LEDGER_TIMEOUT_MS = 250
MAX_LEDGER_ROWS = 256
TICKS_PER_MS = TICKS_PER_SECOND // 1000
# Breakaway limit flags from winnt.h. A Job that lets a process leave it cannot
# prove that its accounting covers the whole execution.
JOB_LIMIT_BREAKAWAY_OK = 0x00000800
JOB_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
# A stable code is a lowercase identifier. Anything else is free text.
_STABLE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_NONCE = re.compile(r"[0-9a-f]{32}")


class HelperHostRefused(RuntimeError):
    """Startup, an iteration or shutdown refused with a stable reason."""

    def __init__(self, reason, detail=None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


def emit(record, stream=None):
    """One JSON record per line on stderr, so stdout stays free for a workload."""
    print(json.dumps(record, sort_keys=True, default=str),
          file=sys.stderr if stream is None else stream, flush=True)


def _reason(error):
    """The stable code an error carries, never free text.

    Errors raised in this package either expose a reason attribute or, for
    LifecycleError, carry the stable code as the message itself. Anything else
    reports only its type, so no path or command text reaches a record.
    """
    value = getattr(error, "reason", None)
    if type(value) is str and value:
        return value
    if isinstance(error, LifecycleError) and _STABLE_CODE.fullmatch(str(error)):
        return str(error)
    return type(error).__name__


def _uint(value):
    return type(value) is int and 0 <= value <= UINT64_MAX


def _win32(error):
    value = getattr(error, "win32_error", None)
    return value if type(value) is int and 0 <= value <= 0xFFFFFFFF else None


def _canonical_uuid(value):
    try:
        parsed = UUID(value) if isinstance(value, str) else None
    except (ValueError, AttributeError, TypeError):
        return False
    return parsed is not None and parsed.int != 0 and str(parsed) == value


def _frame_error(code, stage, execution_id, *, retry=RetryClass.NEW_ATTEMPT, api_error_code=None):
    return FrameError(code, stage, retry, execution_id=execution_id, api_error_code=api_error_code)


# --- the two adapters ---------------------------------------------------------


@dataclass
class _Handle:
    """One retained QUERY handle and the facts the host proved about it."""

    job: object
    counter_epoch: str
    membership_provable: bool
    unreadable: bool = False
    cleanup_unverified: bool = False


class JobHandleSource:
    """Per-Job accounting over QUERY handles the host already opened.

    The sampler contract forbids a backend from opening, scanning or
    enumerating on the sampler's behalf, so read() performs exactly one bounded
    accounting query on a handle that the host's enrollment step opened. A read
    that fails raises JobSamplingError with a sanitized FrameError; it never
    reports an unknown value as a zero.

    counter_epoch identifies the retained handle, not the Job name. While this
    object holds the handle the kernel keeps that exact Job alive, so its
    cumulative user and kernel times stay relatable. Releasing and reopening the
    same name mints a new epoch, which invalidates the delta rather than
    bridging two readings that may not belong together.

    membership_provable comes from the enrollment step, which reads the Job's
    limit flags once. A Job that permits breakaway cannot prove that its
    accounting covers the whole execution, and neither can a Job whose limits
    could not be read, so both are reported as incomplete membership.

    Memory stays unknown. No per-Job private working set or private commit query
    exists in this repository, and an absent query is never answered with a zero.
    """

    def __init__(self):
        self._entries: dict[str, _Handle] = {}
        # A handle whose close outcome is unknown is retained here and never
        # read again, so cleanup custody is not dropped on the floor.
        self._retained: list[_Handle] = []

    @property
    def enrolled(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))

    @property
    def retained_uncertain(self) -> int:
        return len(self._retained)

    def unreadable(self) -> tuple[str, ...]:
        return tuple(sorted(key for key, entry in self._entries.items() if entry.unreadable))

    def add(self, execution_id: str, job, *, membership_provable: bool) -> None:
        if execution_id in self._entries:
            raise ValueError("helper_host_handle_already_enrolled")
        self._entries[execution_id] = _Handle(job, "handle-" + uuid4().hex,
                                              bool(membership_provable))

    def counter_epoch(self, execution_id: str) -> str | None:
        entry = self._entries.get(execution_id)
        return None if entry is None else entry.counter_epoch

    def release(self, execution_id: str) -> str | None:
        """Close one handle. Returns a stable reason when the outcome is unknown."""
        entry = self._entries.pop(execution_id, None)
        if entry is None:
            return None
        try:
            entry.job.close()
        except BaseException as error:
            entry.cleanup_unverified = True
            self._retained.append(entry)
            return _reason(error)
        return None

    def read(self, execution_id: str) -> JobReading:
        entry = self._entries.get(execution_id)
        if entry is None:
            raise JobSamplingError(_frame_error("registry_unavailable", "helper_job_handle",
                                                execution_id,
                                                retry=RetryClass.AFTER_RECONCILIATION))
        try:
            accounting = entry.job.accounting()
        except Exception as error:
            entry.unreadable = True
            raise JobSamplingError(_frame_error("telemetry_stale", "helper_job_accounting",
                                                execution_id,
                                                api_error_code=_win32(error))) from None
        cpu = getattr(accounting, "cpu_100ns", None)
        active = getattr(accounting, "active_processes", None)
        if not _uint(cpu) or not _uint(active):
            entry.unreadable = True
            raise JobSamplingError(_frame_error("measurement_inconsistent",
                                                "helper_job_accounting", execution_id))
        return JobReading(cpu_100ns=cpu,
                          active_processes=active if entry.membership_provable else None,
                          membership_complete=entry.membership_provable,
                          counter_epoch=entry.counter_epoch,
                          private_working_set_bytes=None, private_commit_bytes=None)


class MachineObservationSource:
    """Copy one MachineSample into the MachineObservation the sampler consumes.

    The field names already match, so this is a field copy and nothing else. It
    adds no freshness judgement, no validity of its own and no substitute value.
    """

    def __init__(self, sampler):
        self._sampler = sampler

    def __call__(self) -> MachineObservation:
        from .machine_sampler import MachineSamplingError

        try:
            sample = self._sampler.sample()
        except MachineSamplingError as error:
            return MachineObservation(None, self._sampler.clock_epoch, None, None,
                                      Validity.UNKNOWN, (error.error,), True)
        return MachineObservation(sample.machine, sample.clock_epoch,
                                  sample.window_start_tick_100ns, sample.window_end_tick_100ns,
                                  sample.validity, tuple(sample.errors)[:MAX_FRAME_ERRORS],
                                  sample.reset_required)


# --- enrollment candidates ----------------------------------------------------


@dataclass(frozen=True)
class LedgerJob:
    """One enrollable execution, built from ledger facts only."""

    execution_id: str
    principal_id: str
    logon_id: str
    job_name: str
    job_nonce: str
    role: Role
    priority: Priority
    coverage: Coverage


@dataclass(frozen=True)
class TickOutcome:
    """What one iteration did. Counts and stable reasons only."""

    reason: str
    would_apply: bool
    refreshed: bool
    released: int
    slept_seconds: float


class HelperHost:
    """One shadow helper process. Construct, start, run iterations, then close."""

    def __init__(self, *, data_dir, profile_path=None,
                 enroll_every_ticks=DEFAULT_ENROLL_EVERY, report_every_ticks=DEFAULT_REPORT_EVERY,
                 sleep=time.sleep, clock=None, machine_source=None, open_job=None):
        self.data_dir = Path(data_dir)
        self.profile_path = Path(DEFAULT_PROFILE if profile_path is None else profile_path)
        self.enroll_every_ticks = enroll_every_ticks
        self.report_every_ticks = report_every_ticks
        # Paces the loop only. It is a test seam, never a timing claim.
        self._sleep = sleep
        # clock and machine_source are one pair: both come from the same
        # interrupt-time source, or both are supplied by an in-process fixture.
        self._clock = clock
        self._machine_source = machine_source
        self._opener = self._open_job if open_job is None else open_job
        self.capability = None
        self.profile = None
        self.store = self.process = self.sampler = self.shadow = None
        self.jobs = JobHandleSource()
        self.registered = False
        self._started = False
        self._iterations = 0
        self._would_apply = 0
        self._left_out = 0
        self._dropped = 0
        self._skipped_boundaries = 0
        self._last_reason = None
        self._deadline_100ns = None

    # --- startup ----------------------------------------------------------

    def start(self):
        """Refuse before touching the ledger when the host cannot support this."""
        from .decision import Mode, parse_policy_profile
        from .helper import ShadowHelper
        from .identity import VerifiedProcess
        from .sampler import FrameSampler
        from .store import LifecycleStore

        self.capability = self._capability()
        self.profile = self._profile(parse_policy_profile, Mode)
        try:
            self.store = LifecycleStore(self.data_dir / "sentinel.db", existing_path=True)
        except Exception as error:
            raise HelperHostRefused("helper_host_ledger_unavailable", _reason(error)) from None
        try:
            self.process = VerifiedProcess.current()
        except Exception as error:
            raise HelperHostRefused("helper_host_identity_unavailable", _reason(error)) from None
        # The sampler is built before the registry row exists, because a row
        # written and then abandoned would block the next helper start.
        self._sources()
        try:
            self.sampler = FrameSampler(profile=self.profile, backend=self.jobs,
                                        machine_source=self._machine_source, clock=self._clock)
            # No shadow flag is passed. The profile is the only way to shadow.
            self.shadow = ShadowHelper(profile=self.profile, sampler=self.sampler,
                                       clock=self._clock)
        except Exception as error:
            raise HelperHostRefused("helper_host_sampler_unavailable", _reason(error)) from None
        self._register()
        self._started = True
        enrollment = self.refresh_enrollment()
        return {"event": "helper_host_started", "pid": self.capability.pid,
                "mode": self.shadow.mode.value, "config_revision": self.sampler.config_revision,
                "sample_interval_ms": self.profile.sample_interval_ms,
                "max_enrolled_jobs": min(self.profile.max_enrolled_jobs, MAX_ENROLLED_JOBS),
                "enrolled": enrollment["enrolled"], "left_out": enrollment["left_out"],
                "registry_row_retained_after_exit": True,
                "capability": self.capability.to_dict()}

    @staticmethod
    def _capability():
        try:
            return read_host_capability()
        except HostCapabilityUnsupported as error:
            raise HelperHostRefused(error.reason, error.win32_error) from None

    def _profile(self, parse, mode_type):
        try:
            profile = parse(self.profile_path.read_bytes())
        except Exception as error:
            raise HelperHostRefused("helper_host_profile_unavailable", _reason(error)) from None
        if profile.mode is mode_type.SHADOW:
            return profile
        if profile.mode is mode_type.OFF:
            raise HelperHostRefused("helper_host_mode_off")
        # Unreachable through the parser, which accepts off and shadow only.
        raise HelperHostRefused("helper_host_mode_unsupported")

    def _register(self):
        """Publish this helper in the infrastructure registry under POLICY.

        The registration itself is the guardian's: the same two functions, the
        same mutex, the same identity rules. The extra step here is the refusal
        below, because a second helper row for one logon is the state that makes
        control_transport.registered_helper ambiguous.

        It writes to whatever sentinel.db --data-dir names. Pointing this host at
        the daily data directory therefore writes into the daily ledger.

        The occupied refusal is raised after the POLICY scope has ended normally.
        An exception that leaves policy.hold keeps the durable entry nonce, and
        prepare answers a leftover nonce with policy_scope_busy for every later
        caller, the guardian included. A stale helper row is the expected state
        on a restart, so that refusal must not cost the ledger its POLICY entry.
        """
        from .legacy_writer import initialize_registry_locked, register_infrastructure_locked

        policy = self.store._policy
        try:
            guard = policy.prepare(policy.current_logon())
            with policy.hold(guard):
                initialize_registry_locked(self.store)
                occupied = self._other_helpers(guard)
                if not occupied:
                    register_infrastructure_locked(self.store, "helper", self.process)
        except Exception as error:
            raise HelperHostRefused("helper_host_registry_unavailable", _reason(error)) from None
        if occupied:
            raise HelperHostRefused("helper_host_registry_occupied", str(occupied))
        self.registered = True

    def _other_helpers(self, guard):
        """Count helper rows for this logon that are not this process.

        Any such row fails the start closed. A row can only be removed through
        unregister_dead_infrastructure_locked, which requires a retained handle
        that observed the death of that exact identity. A process starting now
        cannot obtain one for a process that already exited, and an unknown
        status, a missing PID or a failed open is never death. So the caller
        refuses instead of clearing the row.
        """
        from .legacy_writer import MAX_INFRASTRUCTURE

        identity = self.process.identity
        mine = (identity.pid, str(identity.created_filetime_100ns))
        with self.store._transaction() as conn:
            self.store._policy.revalidate(conn, guard)
            # Bound every column before it becomes a Python value, as the other
            # private readers do, so a damaged large row cannot be allocated.
            rows = conn.execute("""SELECT
                CASE WHEN typeof(pid)='integer' THEN pid END AS pid,
                substr(created_filetime_100ns,1,21) AS created_filetime_100ns
                FROM adaptive_infrastructure
                WHERE typeof(role)='text' AND role='helper'
                  AND typeof(logon_id)='text' AND logon_id=?
                LIMIT ?""", (identity.logon_id, MAX_INFRASTRUCTURE + 1)).fetchall()
        found = {(row["pid"], row["created_filetime_100ns"]) for row in rows}
        return len(found - {mine})

    def _sources(self):
        """Bind the tick clock and the machine endpoint to one tick domain.

        machine_sampler reads QueryInterruptTimePrecise for every timestamp it
        publishes, so the frame skew check in FrameSampler is only meaningful
        when the helper's tick clock reads the same counter. One backend serves
        both, and a partially supplied pair is refused rather than mixed.
        """
        supplied = (self._clock is None, self._machine_source is None)
        if supplied == (False, False):
            return
        if supplied != (True, True):
            raise HelperHostRefused("helper_host_clock_domain_unshared")
        from .machine_sampler import MachineSampler

        try:
            from .machine_sampler import _WindowsBackend

            backend = _WindowsBackend()
        except Exception as error:
            raise HelperHostRefused("helper_host_sampler_unavailable", _reason(error)) from None
        self._clock = backend.tick
        self._machine_source = MachineObservationSource(MachineSampler(backend=backend))

    @staticmethod
    def _open_job(name, nonce, logon_id):
        """Open one existing Job with query rights and nothing else."""
        from .native_job import JobAccess, NativeJob

        return NativeJob.open(name, nonce, logon_id, access=JobAccess.QUERY)

    # --- enrollment -------------------------------------------------------

    def refresh_enrollment(self):
        """Re-read the live set, release what left it, fill the free capacity.

        The ledger read is a short bounded read-only snapshot. No transaction is
        held across a native call: the snapshot is released before any Job is
        opened or closed.
        """
        if not self._started:
            raise HelperHostRefused("helper_host_not_started")
        try:
            candidates, truncated, invalid = self._ledger_candidates()
        except LifecycleError as error:
            # A ledger that cannot be read now says nothing about which
            # executions ended, so nothing is released on this refresh.
            return self._enrollment_record(0, 0, 0, (), 0, False, _reason(error))
        live = {candidate.execution_id for candidate in candidates}
        unreadable = set(self.jobs.unreadable())
        released, cleanup = 0, []
        for execution_id in self.jobs.enrolled:
            if execution_id in live and execution_id not in unreadable:
                continue
            reason = self._release(execution_id)
            released += 1
            if reason is not None:
                cleanup.append(reason)
        limit = min(self.profile.max_enrolled_jobs, MAX_ENROLLED_JOBS)
        opened = failed = 0
        enrolled = set(self.jobs.enrolled)
        for candidate in candidates:
            if len(enrolled) >= limit:
                break
            if candidate.execution_id in enrolled:
                continue
            if self._enroll(candidate) is None:
                enrolled.add(candidate.execution_id)
                opened += 1
            else:
                failed += 1
        self._left_out = max(0, len(candidates) - len(self.jobs.enrolled))
        return self._enrollment_record(opened, released, failed, cleanup, invalid, truncated, None)

    def _enrollment_record(self, opened, released, failed, cleanup, invalid, truncated, ledger):
        return {"event": "helper_host_enrollment", "enrolled": len(self.jobs.enrolled),
                "opened": opened, "released": released, "open_failed": failed,
                "left_out": self._left_out, "ledger_rows_rejected": invalid,
                "ledger_truncated": truncated, "ledger": ledger,
                "cleanup_unverified": sorted(set(cleanup))}

    def _ledger_candidates(self):
        """Live, Job contained executions of this logon, in execution id order."""
        from .legacy_writer import _ACTIVE
        from .store import _ipc_read_transaction

        states = sorted(_ACTIVE)
        placeholders = ",".join("?" * len(states))
        logon = self.process.identity.logon_id
        with _ipc_read_transaction(self.store.db_path, timeout_ms=LEDGER_TIMEOUT_MS) as conn:
            rows = conn.execute(f"""SELECT
                substr(execution_id,1,37) AS execution_id,
                substr(principal_id,1,129) AS principal_id,
                substr(logon_id,1,129) AS logon_id,
                substr(job_name,1,257) AS job_name,
                substr(job_nonce,1,33) AS job_nonce,
                substr(role,1,33) AS role,
                substr(priority,1,9) AS priority,
                substr(coverage,1,33) AS coverage
                FROM managed_executions
                WHERE typeof(state)='text' AND state IN ({placeholders})
                  AND typeof(coverage)='text' AND coverage='job_contained'
                  AND typeof(job_name)='text' AND typeof(job_nonce)='text'
                  AND typeof(principal_id)='text'
                  AND typeof(logon_id)='text' AND logon_id=?
                ORDER BY execution_id
                LIMIT ?""", (*states, logon, MAX_LEDGER_ROWS + 1)).fetchall()
        truncated = len(rows) > MAX_LEDGER_ROWS
        candidates, invalid = [], 0
        for row in rows[:MAX_LEDGER_ROWS]:
            candidate = self._candidate(row)
            if candidate is None:
                invalid += 1
            else:
                candidates.append(candidate)
        return candidates, truncated, invalid

    @staticmethod
    def _candidate(row):
        """One ledger row, or None when the row cannot be trusted as it stands."""
        execution_id, nonce = row["execution_id"], row["job_nonce"]
        if not _canonical_uuid(execution_id) or _NONCE.fullmatch(nonce or "") is None:
            return None
        if row["job_name"] != f"Local\\ResourceSentinel.Job.{execution_id}.{nonce}":
            return None
        principal = row["principal_id"]
        if not isinstance(principal, str) or not 1 <= len(principal) <= 128:
            return None
        try:
            role, priority = Role(row["role"]), Priority(row["priority"])
            coverage = Coverage(row["coverage"])
        except (ValueError, TypeError):
            return None
        if coverage is not Coverage.JOB_CONTAINED:
            return None
        return LedgerJob(execution_id, principal, row["logon_id"], row["job_name"], nonce,
                         role, priority, coverage)

    def _enroll(self, candidate):
        """Open one Job and enroll it. Returns a stable reason on failure."""
        from .helper import Enrollment

        try:
            # capability_verified is False because no ledger fact proves the
            # host capability for an execution: read_host_capability produces a
            # record that is never persisted. foreground is False because the
            # ledger carries no foreground fact at all.
            enrollment = Enrollment(candidate.execution_id, candidate.principal_id,
                                    candidate.role, candidate.priority, candidate.coverage,
                                    False, False)
        except Exception as error:
            return _reason(error)
        try:
            job = self._opener(candidate.job_name, candidate.job_nonce, candidate.logon_id)
        except Exception as error:
            return _reason(error)
        try:
            provable = self._membership_provable(job)
            self.jobs.add(candidate.execution_id, job, membership_provable=provable)
        except Exception as error:
            reason = _reason(error)
            self._discard(job)
            return reason
        try:
            self.shadow.enroll(enrollment)
        except Exception as error:
            reason = _reason(error)
            self.jobs.release(candidate.execution_id)
            return reason
        return None

    @staticmethod
    def _membership_provable(job):
        """A Job that permits breakaway cannot prove its own membership.

        Limits are read once, here, because only an owner handle can change them
        and this host holds none. A limit query that fails leaves membership
        unproven, which the sampler reports as unknown rather than as complete.
        """
        try:
            flags = job.query_limits().limit_flags
        except Exception:
            return False
        if type(flags) is not int:
            return False
        return not flags & (JOB_LIMIT_BREAKAWAY_OK | JOB_LIMIT_SILENT_BREAKAWAY_OK)

    @staticmethod
    def _discard(job):
        try:
            job.close()
        except BaseException as error:
            return _reason(error)
        return None

    def _release(self, execution_id):
        if self.shadow is not None:
            self.shadow.release(execution_id)
        return self.jobs.release(execution_id)

    # --- one bounded iteration --------------------------------------------

    def run_once(self) -> TickOutcome:
        """Refresh on cadence, take exactly one tick, then pace to the boundary."""
        if not self._started:
            raise HelperHostRefused("helper_host_not_started")
        self._iterations += 1
        refreshed = False
        if self._iterations > 1 and (self._iterations - 1) % self.enroll_every_ticks == 0:
            self.refresh_enrollment()
            refreshed = True
        result = self.shadow.tick()
        would_apply = result.decision is not None and result.decision.would_apply
        if would_apply:
            self._would_apply += 1
        self._last_reason = result.reason
        released = 0
        for execution_id in self.jobs.unreadable():
            # A Job that cannot be read is released here, outside the sampler.
            # The next refresh reopens it when the ledger still shows it live.
            self._release(execution_id)
            released += 1
        self._dropped += released
        return TickOutcome(result.reason, would_apply, refreshed, released, self._pace())

    def _pace(self):
        """Wait for the next interval boundary. A late tick never bursts.

        The boundary is an interval on the same tick domain the sampler reads.
        It bounds how often this loop runs, and it is not a measured reaction
        time for anything.
        """
        interval = self.profile.sample_interval_ms * TICKS_PER_MS
        now = self._clock()
        if self._deadline_100ns is None:
            self._deadline_100ns = now + interval
        else:
            self._deadline_100ns += interval
            if self._deadline_100ns <= now:
                behind = (now - self._deadline_100ns) // interval + 1
                self._deadline_100ns += behind * interval
                self._skipped_boundaries += behind
        seconds = max(0, self._deadline_100ns - now) / TICKS_PER_SECOND
        self._sleep(seconds)
        return seconds

    def metrics_record(self):
        """Counts, stable reasons and the loop's own cost. No identifiers.

        These numbers are the helper's measured cost only when the clock and the
        backends behind them are real. They are never admission or capacity.
        """
        metrics = self.shadow.metrics
        return {"event": "helper_host_metrics", "mode": self.shadow.mode.value,
                "iterations": self._iterations, "ticks": metrics.ticks,
                "frames": metrics.frames, "frame_gaps": metrics.frame_gaps,
                "late_ticks": metrics.late_ticks, "missed_ticks": metrics.missed_ticks,
                "decisions": metrics.decisions, "last_tick_ms": metrics.last_tick_ms,
                "max_tick_ms": metrics.max_tick_ms, "total_tick_ms": metrics.total_tick_ms,
                "enrolled": len(self.jobs.enrolled), "left_out": self._left_out,
                "dropped_unreadable": self._dropped,
                "would_apply": self._would_apply, "last_reason": self._last_reason,
                "skipped_boundaries": self._skipped_boundaries,
                "sample_interval_ms": self.profile.sample_interval_ms,
                "handles_retained_uncertain": self.jobs.retained_uncertain}

    def run_bounded(self, iterations):
        """The explicit bounded mode for tests and diagnostics."""
        for _ in range(iterations):
            self.run_once()
            self._report()
        return {"event": "helper_host_finished", "iterations": self._iterations}

    def _report(self):
        """A record every report_every ticks, and never one for zero ticks."""
        if self._iterations and self._iterations % self.report_every_ticks == 0:
            emit(self.metrics_record())

    def serve_until_stopped(self):
        """Run iterations until the process is interrupted.

        This is the default mode. KeyboardInterrupt is the only stop condition
        this repository provides, and it is raised by the interpreter, not
        invented here. The helper holds no custody, so there is nothing to drain
        and the caller closes the handles straight away.
        """
        try:
            while True:
                self.run_once()
                self._report()
        except KeyboardInterrupt:
            return {"event": "helper_host_stopping", "reason": "interrupted",
                    "iterations": self._iterations}

    # --- shutdown ---------------------------------------------------------

    def close(self):
        """Release every Job handle. The registry row stays.

        Removing that row needs a verified death of this exact identity, which
        a live process cannot present about itself, and this repository has no
        live deregistration function. Inventing one here would put a removal
        rule where an authority record belongs.
        """
        cleanup = []
        for execution_id in self.jobs.enrolled:
            reason = self._release(execution_id)
            if reason is not None:
                cleanup.append(reason)
        self._started = False
        if cleanup:
            raise HelperHostRefused("helper_host_handle_cleanup_unverified",
                                    ",".join(sorted(set(cleanup))))
        return {"event": "helper_host_closed", "iterations": self._iterations,
                "enrolled": len(self.jobs.enrolled), "registry_row_retained": self.registered,
                "handles_retained_uncertain": self.jobs.retained_uncertain}


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel.adaptive.helper_host",
        description="Run one shadow helper process host. Observation only.")
    parser.add_argument("--data-dir", required=True, help="directory holding sentinel.db")
    parser.add_argument("--profile", default=None,
                        help="policy profile JSON file; mode shadow is the only mode that runs")
    parser.add_argument("--iterations", type=int, default=0,
                        help="0 runs until the process is interrupted; a positive "
                             "value is the bounded test and diagnostic mode")
    parser.add_argument("--enroll-every", type=int, default=DEFAULT_ENROLL_EVERY,
                        help="ticks between enrollment refreshes")
    parser.add_argument("--report-every", type=int, default=DEFAULT_REPORT_EVERY,
                        help="ticks between metrics records")
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if (options.iterations < 0 or not 1 <= options.enroll_every <= 3600
            or not 1 <= options.report_every <= 3600):
        emit({"event": "helper_host_refused", "reason": "helper_host_arguments_invalid"})
        return EXIT_REFUSED
    host = HelperHost(data_dir=options.data_dir, profile_path=options.profile,
                      enroll_every_ticks=options.enroll_every,
                      report_every_ticks=options.report_every)
    try:
        emit(host.start())
    except HelperHostRefused as error:
        emit({"event": "helper_host_refused", "reason": error.reason, "detail": error.detail})
        return EXIT_REFUSED
    code = EXIT_OK
    try:
        if options.iterations == 0:
            emit(host.serve_until_stopped())
        else:
            emit(host.run_bounded(options.iterations))
    except KeyboardInterrupt:
        emit({"event": "helper_host_stopping", "reason": "interrupted"})
    except HelperHostRefused as error:
        emit({"event": "helper_host_failed", "reason": error.reason, "detail": error.detail})
        code = EXIT_FAILED
    except Exception as error:
        emit({"event": "helper_host_failed", "reason": _reason(error)})
        code = EXIT_FAILED
    finally:
        # Handles are released on every path, including an unexpected failure.
        try:
            emit(host.close())
        except HelperHostRefused as error:
            emit({"event": "helper_host_refused", "reason": error.reason, "detail": error.detail})
            code = EXIT_FAILED
    return code


if __name__ == "__main__":
    raise SystemExit(main())
