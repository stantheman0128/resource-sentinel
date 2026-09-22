"""Native P4 measurement engine; only an owned daily cohort may supply subjects.

The prerequisite is the same authenticated aggregate fixture owner needed by
S2/S3. It must return retained original custody, not PIDs/receipts loaded from
JSON. No such aggregate provider is activated by this module. Missing coverage
refuses before native initialization or process creation. See P4-OVERHEAD-RUNNER.

The local process executes the real ShadowHelper/FrameSampler and is charged as
the helper, including its probe/orchestration cost. Guardian and waiting wrappers
must be real hosts supplied by the provider. Fifty Jobs are read-only stress in
five <=10 sampler shards, never fifty managed enrollments. Raw failed results
are preserved and are not promoted into passing capability evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.decision import Mode, PolicyProfile
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.native_job import JobAccess, NativeJob
from sentinel.adaptive.sampler import profile_revision
from tests.windows.adaptive_capability_runner import (
    NativeRunBlocked, NativeRunUnsettled, _directory, _write_new,
)


TICKS = 10_000_000
SCALES = (1, 10, 50)
SCALE_SECONDS = 600
LEAK_SECONDS = 3600
IDLE_SETTLE_SECONDS = 30
WRAPPER_TRIALS = 10
CASE_KEYS = ("membership_added", "membership_removed", "inaccessible_identity",
             "member_scan_timeout", "subtraction_zero_samples", "unsafe_subtractions")
MAX_RAW_BYTES = 4 * 1024 * 1024
MAX_LOG_FILES = 1024


@dataclass(frozen=True)
class NativeSetObservation:
    """Actual guardian instrumentation read through the authenticated bridge.

    Counter installation precedes the first measured/native scope operation.
    The bridge binds its reply to the retained guardian peer and scope nonce.
    This value alone, including one loaded from a file, grants no authority.
    """
    identity: ProcessIdentity
    scope_nonce: str
    sequence: int
    observed_tick: int
    installed_tick: int
    calls: int
    restrictive_calls: int


class OverheadUnsettled(NativeRunUnsettled):
    """Keep original cohort, local query owners and primary error reachable."""
    def __init__(self, coverage, session, error, *, local_owners=()):
        super().__init__(coverage)
        self.session, self.primary_error = session, error
        self.local_owners = tuple(local_owners)


def _uint(value, reason):
    if type(value) is not int or value < 0:
        raise NativeRunBlocked(reason)
    return value


def add_cases(total, delta):
    """Only aggregate observed counts; missing cases remain zero, never one."""
    if type(delta) is not dict or set(delta) != set(CASE_KEYS):
        raise NativeRunBlocked("p4_sampling_case_schema_invalid")
    for key in CASE_KEYS:
        total[key] += _uint(delta[key], "p4_sampling_case_invalid")


def process_endpoints(roles, first, last):
    """Exact identity joins; a restart cannot splice unrelated CPU endpoints."""
    initial = {item.identity: item for item in first}
    final = {item.identity: item for item in last}
    if (len(initial) != len(first) or len(final) != len(last)
            or set(initial) != set(final) or set(initial) != set(roles)):
        raise NativeRunBlocked("p4_monitor_identity_changed")
    rows = []
    for identity, role in roles.items():
        before = _uint(initial[identity].cpu_100ns, "p4_cpu_counter_invalid")
        after = _uint(final[identity].cpu_100ns, "p4_cpu_counter_invalid")
        if after < before:
            raise NativeRunBlocked("p4_cpu_counter_reversed")
        rows.append(dict(identity=identity.to_dict(), role=role,
                         cpu_start_100ns=before, cpu_end_100ns=after))
    return rows


def memory_totals(roles, readings):
    if len(readings) != len(roles) or {row.identity for row in readings} != set(roles):
        raise NativeRunBlocked("p4_monitor_coverage_incomplete")
    infrastructure, wrappers = 0, []
    for row in readings:
        value = _uint(row.peak_private_bytes, "p4_private_counter_invalid")
        if value < _uint(row.private_bytes, "p4_private_counter_invalid"):
            raise NativeRunBlocked("p4_private_peak_inconsistent")
        if roles[row.identity] == "waiting_wrapper":
            # Conservatively charge the WHOLE actual wrapper host. This is an
            # upper bound on additional Private Commit; no arbitrary idle-host
            # subtraction can hide wrapper cost or produce negative overhead.
            wrappers.append(value)
        else:
            infrastructure += value
    if not wrappers:
        raise NativeRunBlocked("p4_waiting_wrappers_missing")
    return infrastructure, max(wrappers)


def validate_audit(value, previous, *, guardian, nonce, now, maximum_age):
    if (type(value) is not NativeSetObservation or value.identity != guardian
            or value.scope_nonce != nonce):
        raise NativeRunBlocked("p4_native_set_audit_binding_invalid")
    for name in ("sequence", "observed_tick", "installed_tick", "calls", "restrictive_calls"):
        _uint(getattr(value, name), "p4_native_set_audit_invalid")
    if not value.installed_tick <= value.observed_tick <= now:
        raise NativeRunBlocked("p4_native_set_audit_clock_invalid")
    if now - value.observed_tick > maximum_age:
        raise NativeRunBlocked("p4_native_set_audit_stale")
    if value.restrictive_calls > value.calls:
        raise NativeRunBlocked("p4_native_set_audit_invalid")
    if previous is not None and (value.sequence <= previous.sequence
            or value.installed_tick != previous.installed_tick
            or value.calls < previous.calls or value.restrictive_calls < previous.restrictive_calls
            or value.observed_tick < previous.observed_tick):
        raise NativeRunBlocked("p4_native_set_audit_replayed")
    return value


def read_runtime_footprint(database, log_directory):
    """Read actual isolated runtime row/log counts, excluding producer output."""
    database, log_directory = Path(database), Path(log_directory)
    for path in (database, log_directory):
        resolved = path.resolve(strict=True)
        daily = (Path.home() / ".resource-sentinel").resolve()
        if resolved == daily or daily in resolved.parents or path.is_symlink():
            raise NativeRunBlocked("p4_footprint_must_be_isolated")
    if not database.is_file() or not log_directory.is_dir():
        raise NativeRunBlocked("p4_footprint_paths_invalid")
    conn = sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True,
                           timeout=.1)
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("BEGIN")
        # An interrupted/oversized query is unknown, not an observed zero.
        deadline = time.monotonic() + .1
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
        names = conn.execute("SELECT name FROM sqlite_master WHERE type='table' "
                             "AND name NOT LIKE 'sqlite_%' LIMIT 129").fetchall()
        if len(names) > 128:
            raise NativeRunBlocked("p4_footprint_table_bound")
        rows = sum(conn.execute('SELECT COUNT(*) FROM "' + name[0].replace('"', '""')
                                + '"').fetchone()[0] for name in names)
    finally:
        conn.close()
    count = size = visited = 0
    # Do not follow reparse/symlink directories or inspect arbitrary trees.
    def inaccessible(error):
        raise NativeRunBlocked("p4_log_scan_unavailable") from error

    for root, dirs, files in os.walk(log_directory, followlinks=False, onerror=inaccessible):
        visited += 1
        if visited > MAX_LOG_FILES or time.monotonic() > deadline + .4:
            raise NativeRunBlocked("p4_log_scan_bound")
        for name in dirs:
            path = Path(root) / name
            if path.is_symlink() or getattr(path.stat(), "st_file_attributes", 0) & 0x400:
                raise NativeRunBlocked("p4_log_reparse_refused")
        for name in files:
            path = Path(root) / name
            count += 1
            if count > MAX_LOG_FILES or time.monotonic() > deadline + .4:
                raise NativeRunBlocked("p4_log_scan_bound")
            stat = path.stat()
            if path.is_symlink() or getattr(stat, "st_file_attributes", 0) & 0x400:
                raise NativeRunBlocked("p4_log_reparse_refused")
            size += stat.st_size
    return int(rows), int(size)


class _RawTrace:
    """Buffered bounded evidence; no per-second fsync or active-file rotation."""
    def __init__(self, path):
        self.stream = Path(path).open("x", encoding="utf-8", newline="\n", buffering=65536)
        self.bytes = 0
        self.closed = False

    def append(self, row):
        text = json.dumps(row, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        self.bytes += len(text.encode("utf-8"))
        if self.bytes > MAX_RAW_BYTES:
            raise NativeRunBlocked("p4_raw_trace_bound")
        self.stream.write(text)

    def close(self):
        if self.closed:
            return
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        self.closed = True


def close_trace_preserving_primary(trace):
    """A failed evidence flush cannot erase original native/interrupt custody."""
    primary = sys.exc_info()[1]
    try:
        trace.close()
    except BaseException as cleanup:
        cleanup.overhead_trace = trace
        if primary is None:
            raise
        primary.overhead_trace = trace
        primary.overhead_trace_cleanup = cleanup
        if not isinstance(cleanup, Exception) and isinstance(primary, Exception):
            cleanup.overhead_primary = primary
            raise
        # Continue propagating the original primary (including its native
        # cleanup owners). The cleanup exception remains reachable above.


class P4Producer:
    """Execute fixed-duration native measurements inside retained daily coverage.

    ``coverage.open_overhead_session`` is an in-process aggregate bridge, not a
    configurable plugin. It owns all creation, original handles, admission,
    guardian instrumentation, cooperative fixture transitions and retirement.
    See the exact required session operations in the accompanying contract.
    No `cleanup succeeded` boolean can release its daily allocation here.
    """
    def __init__(self, coverage, directory, context, profile):
        if not callable(getattr(coverage, "open_overhead_session", None)):
            raise NativeRunBlocked("p4_authenticated_daily_cohort_unavailable")
        if type(context) is not evidence.LiveCapabilityContext:
            raise NativeRunBlocked("p4_native_context_required")
        if not isinstance(profile, PolicyProfile) or profile.mode is not Mode.SHADOW:
            raise NativeRunBlocked("p4_shadow_profile_required")
        if os.name != "nt":
            raise NativeRunBlocked("native_windows_required")
        if profile.sample_interval_ms != 1000:
            raise NativeRunBlocked("p4_one_second_profile_required")
        self.coverage, self.context, self.profile = coverage, context, profile
        self.directory = _directory(directory)
        self.active = None
        self.pending_open = False
        self.local_owners = []

    def _covered(self, session):
        # A successful check is None, never a bool/receipt permission shortcut.
        result = session.assert_daily_coverage()
        if result is not None:
            raise NativeRunBlocked("p4_continuous_coverage_contract_invalid")

    def _open(self, jobs, label):
        directory = self.directory / label
        directory.mkdir()
        # The bridge must retain its pending original attempt BEFORE creation;
        # if creation raises, the coverage object still owns that pending scope.
        self.pending_open = True
        session = self.coverage.open_overhead_session(jobs=jobs, directory=directory,
            profile=self.profile, query_only_stress=(jobs == 50))
        self.active = session
        self.pending_open = False
        self._covered(session)
        required = ("assert_daily_coverage", "read_guardian_set_audit", "enter_idle",
                    "enter_stress", "prepare_wrapper_trial", "retire")
        if any(not callable(getattr(session, method, None)) for method in required):
            raise NativeRunBlocked("p4_cohort_interface_incomplete")
        if (session.profile_revision != profile_revision(self.profile)
                or session.context != self.context or session.helper.identity.pid != os.getpid()
                or type(session.scope_nonce) is not str or len(session.scope_nonce) != 32):
            raise NativeRunBlocked("p4_cohort_binding_invalid")
        logs = Path(session.log_directory).resolve(strict=True)
        if logs == directory.resolve() or logs in directory.resolve().parents:
            raise NativeRunBlocked("p4_raw_trace_in_runtime_logs")
        witnesses = (session.helper, session.guardian, *session.wrappers)
        if len(session.wrappers) != jobs or len(session.jobs) != jobs:
            raise NativeRunBlocked("p4_cohort_cardinality_invalid")
        identities = []
        for owner in witnesses:
            if not isinstance(owner, VerifiedProcess):
                raise NativeRunBlocked("p4_original_monitor_custody_required")
            observation = owner.observe()
            if (observation.identity != owner.identity or observation.status is not IdentityStatus.ALIVE
                    or owner.identity.logon_id != self.context.logon_id):
                raise NativeRunBlocked("p4_monitor_identity_unverified")
            identities.append(owner.identity)
        if len(set(identities)) != len(identities):
            raise NativeRunBlocked("p4_monitor_identity_duplicate")
        for _, job in session.jobs:
            if (not isinstance(job, NativeJob) or job.access is not JobAccess.QUERY
                    or job.logon_sid != self.context.logon_id):
                raise NativeRunBlocked("p4_query_job_custody_required")
            cpu = job.query_cpu()
            if cpu.flags != 0:
                raise NativeRunBlocked("p4_job_not_uncapped")
        from tests.windows.adaptive_overhead_native import NativeCostProbe, ReadOnlyShadowSampler
        probe = NativeCostProbe(witnesses)
        sampler = ReadOnlyShadowSampler(self.profile, session.jobs)
        self.local_owners.extend((probe, sampler))
        if sampler.logical_processors != self.context.logical_processors:
            raise NativeRunBlocked("p4_native_denominator_changed")
        roles = {identities[0]: "helper", identities[1]: "guardian"}
        roles.update((identity, "waiting_wrapper") for identity in identities[2:])
        return session, probe, sampler, roles, directory

    def _audit(self, session, previous, clock):
        value = session.read_guardian_set_audit()
        return validate_audit(value, previous, guardian=session.guardian.identity,
            nonce=session.scope_nonce, now=clock(),
            maximum_age=self.profile.sample_max_age_ms * 10_000)

    def _pace(self, session, deadline, clock):
        self._covered(session)
        deadline += TICKS
        now = clock()
        if now < deadline:
            time.sleep(min((deadline - now) / TICKS, 1.0))
        # One iteration only. If late, drop missed ticks; no catch-up loop.
        return max(deadline, clock())

    def _retire(self, session, probe, sampler):
        self._covered(session)
        sampler.close()
        probe.close()
        # Provider must itself prove native empty/disabled, ledger settlement,
        # and close all original owners before retiring its daily reservation.
        session.retire()
        if session.custody_pending is not False:
            raise NativeRunBlocked("p4_cohort_retirement_unverified")
        self.active = None
        self.local_owners.clear()

    def _scale(self, jobs):
        from sentinel.adaptive.machine_sampler import _WindowsBackend
        clock = _WindowsBackend().tick
        session, probe, sampler, roles, directory = self._open(jobs, f"scale-{jobs}")
        trace = _RawTrace(directory / "measurements.jsonl")
        self.local_owners.append(trace)
        try:
            self._covered(session)
            audit = self._audit(session, None, clock)
            if audit.calls or audit.restrictive_calls:
                raise NativeRunBlocked("p4_shadow_set_observed")
            # Prime actual machine/Job delta baselines outside steady-state
            # timing, then wait one covered second. Never count a cheap failed
            # or bootstrap sample as a complete measured helper tick.
            prime = clock()
            sampler.tick()
            self._pace(session, prime, clock)
            first = probe.read()
            # All starting counters precede the elapsed bracket, and every
            # ending counter follows it. Serial reads can overcharge CPU
            # conservatively; they can never dilute cost with unmeasured time.
            start = clock()
            if audit.installed_tick > start:
                raise NativeRunBlocked("p4_native_set_audit_late")
            samples, cases = [], dict.fromkeys(CASE_KEYS, 0)
            deadline = start
            while clock() - start < SCALE_SECONDS * TICKS:
                self._covered(session)
                begin, end, delta = sampler.tick()
                if sampler.last_tick_warmup:
                    raise NativeRunBlocked("p4_sampling_warmup_restarted")
                readings = probe.read()
                private, wrappers = memory_totals(roles, readings)
                add_cases(cases, delta)
                samples.append([begin, end, private, wrappers])
                audit = self._audit(session, audit, clock)
                trace.append(dict(sample=samples[-1], cases=delta,
                    guardian_audit_sequence=audit.sequence, guardian_set_calls=audit.calls,
                    helper_set_calls=sampler.native_set_calls,
                    handles=[row.handles for row in readings]))
                if audit.calls or sampler.native_set_calls:
                    raise NativeRunBlocked("p4_shadow_set_observed")
                deadline = self._pace(session, deadline, clock)
            self._covered(session)
            end = clock()
            last = probe.read()
            audit = self._audit(session, audit, clock)
            if audit.calls or sampler.native_set_calls:
                raise NativeRunBlocked("p4_shadow_set_observed")
            result = dict(jobs=jobs, started_tick=start, ended_tick=end,
                processes=process_endpoints(roles, first, last), samples=samples,
                native_set_calls=audit.calls + sampler.native_set_calls, sampling_cases=cases)
            _write_new(directory / "scale.json", result)
            trace.close()
            self._retire(session, probe, sampler)
            return result
        finally:
            close_trace_preserving_primary(trace)

    def _idle(self, session, sampler, clock):
        session.enter_idle()
        started = deadline = clock()
        seconds = max(IDLE_SETTLE_SECONDS, self.profile.sample_ring_frames + 1)
        while clock() - started < seconds * TICKS:
            self._covered(session)
            sampler.tick()
            deadline = self._pace(session, deadline, clock)

    @staticmethod
    def _footprint(session, probe):
        readings = probe.read()
        rows, logs = read_runtime_footprint(session.database, session.log_directory)
        return dict(private_bytes=sum(row.private_bytes for row in readings),
                    handles=sum(row.handles for row in readings), rows=rows, log_bytes=logs)

    def _leak(self):
        from sentinel.adaptive.machine_sampler import _WindowsBackend
        clock = _WindowsBackend().tick
        session, probe, sampler, roles, directory = self._open(10, "leak")
        trace = _RawTrace(directory / "measurements.jsonl")
        self.local_owners.append(trace)
        try:
            audit = self._audit(session, None, clock)
            self._idle(session, sampler, clock)
            before = self._footprint(session, probe)
            session.enter_stress()
            first_stress = self._footprint(session, probe)
            start = deadline = clock()
            observations = [[start, *first_stress.values()]]
            while clock() - start < LEAK_SECONDS * TICKS:
                self._covered(session)
                begin, end, cases = sampler.tick()
                audit = self._audit(session, audit, clock)
                if audit.calls or sampler.native_set_calls:
                    raise NativeRunBlocked("p4_shadow_set_observed")
                if clock() - observations[-1][0] >= 60 * TICKS:
                    reading = self._footprint(session, probe)
                    observations.append([clock(), *reading.values()])
                trace.append(dict(begin=begin, end=end, cases=cases,
                    guardian_audit_sequence=audit.sequence, guardian_set_calls=audit.calls,
                    helper_set_calls=sampler.native_set_calls))
                deadline = self._pace(session, deadline, clock)
            end_reading = self._footprint(session, probe)
            end = clock()
            observations.append([end, *end_reading.values()])
            self._idle(session, sampler, clock)
            after = self._footprint(session, probe)
            audit = self._audit(session, audit, clock)
            if audit.calls or sampler.native_set_calls:
                raise NativeRunBlocked("p4_shadow_set_observed")
            result = dict(started_tick=start, ended_tick=end, idle_before=before,
                          idle_after=after, observations=observations)
            _write_new(directory / "leak.json", result)
            trace.close()
            self._retire(session, probe, sampler)
            return result
        finally:
            close_trace_preserving_primary(trace)

    def _wrappers(self):
        from sentinel.adaptive.machine_sampler import _WindowsBackend
        clock = _WindowsBackend().tick
        session, probe, sampler, roles, directory = self._open(1, "wrappers")
        result = {"wrapper_cold_ns": [], "wrapper_warm_ns": []}
        audit = self._audit(session, None, clock)
        if audit.calls or sampler.native_set_calls:
            raise NativeRunBlocked("p4_shadow_set_observed")
        for kind in ("cold", "warm"):
            for index in range(WRAPPER_TRIALS):
                self._covered(session)
                # Admission occurs in prepare, before the measured bracket.
                # Its retained owner represents one actual wrapper attempt.
                trial = session.prepare_wrapper_trial(kind=kind, iteration=index)
                self._covered(session)
                start = clock()
                trial.launch_once()
                # Cooperative bridge services retained custody/admission while
                # awaiting actual ready IPC; never process-running == ready.
                trial.wait_ready(assert_covered=lambda: self._covered(session))
                end = clock()
                if not start < end:
                    raise NativeRunBlocked("p4_wrapper_clock_invalid")
                result[f"wrapper_{kind}_ns"].append((end - start) * 100)
                trial.retire()
                if trial.custody_pending is not False:
                    raise NativeRunBlocked("p4_wrapper_retirement_unverified")
                audit = self._audit(session, audit, clock)
                if audit.calls or sampler.native_set_calls:
                    raise NativeRunBlocked("p4_shadow_set_observed")
        _write_new(directory / "wrappers.json", result)
        self._retire(session, probe, sampler)
        return result

    def run(self):
        data = {"scales": []}
        try:
            for jobs in SCALES:
                data["scales"].append(self._scale(jobs))
            data.update(self._wrappers())
            data["leak"] = self._leak()
            # Preserve actual failed measurements before applying the gate.
            _write_new(self.directory / "P4-data.json", data)
            evidence._p4(data, self.context, self.profile)
            return data
        except BaseException as error:
            if (self.active is not None or self.pending_open
                    or getattr(self.coverage, "pending_admissions", ())):
                retained = OverheadUnsettled(self.coverage, self.active, error,
                                              local_owners=self.local_owners)
                if not isinstance(error, Exception):
                    error.overhead_owner = retained
                    raise
                raise retained from error
            raise


def produce_p4(coverage, evidence_directory, context, profile):
    """Return raw artifact-v1 data only after native measurement and validation."""
    return P4Producer(coverage, evidence_directory, context, profile).run()
