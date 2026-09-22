"""Bounded S3 experiment authority, never a production capability purpose.

S3 cannot require a prior S3/P4 pass to measure its own recovery. This test-only
owner verifies the real pinned v1 S1/S2 artifacts using the shipped verifier,
then restricts one original isolated fixture scope for at most 120 seconds.
It neither changes NativeEvidenceAuthority nor emits substitute S3/P4 evidence.

The daily continuous-admission provider is mandatory and remains fail-closed
until it supplies an actual retained scope bridge. A status file, ordinary
reservation, fixture database, boolean, callback or serialized receipt cannot
construct that bridge. Expiry/refusal stops new control eligibility only; it
never releases allocation, restores a Job, closes custody or kills a process.

assess() performs bounded file/native/ledger reads OUTSIDE POLICY/Job locks.
assert_control_eligible() consumes fresh prepared state under those locks and
performs no file, database or native queries. Helper authority only permits
proposals: its distinct identity cannot satisfy the guardian actuator check.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import threading
from typing import Mapping

from sentinel.adaptive import capability_evidence as evidence
from sentinel.adaptive.contracts import IdentityStatus, ProcessIdentity
from sentinel.adaptive.guardian import GuardianLaunchOwner
from sentinel.adaptive.helper_control_host import HelperControlHost, OperationalHelperControlHost
from sentinel.adaptive.identity import VerifiedProcess
from sentinel.adaptive.launch_scope import MeasuredLaunchTopologies, RetainedLaunchScopeSource
from sentinel.adaptive.native_job import JobAccess, NativeJob


_DURATION_TICKS = 120 * 10_000_000
_COMMON_BINDING = ("execution_id", "job_name", "job_nonce", "guardian_epoch", "logon_id",
                   "principal_id", "role", "priority", "coverage")
_FULL_BINDING = (*_COMMON_BINDING, "spec_hash", "allocation_kind", "reservation_id",
                 "wrapper_pid", "wrapper_created_filetime_100ns", "root_pid",
                 "root_created_filetime_100ns")


def _deny(reason):
    raise evidence.CapabilityEvidenceError(reason)


def _live(process):
    if type(process) is not VerifiedProcess:
        _deny("recovery_spike_native_identity_required")
    observed = process.observe()
    if observed.identity != process.identity or observed.status is not IdentityStatus.ALIVE:
        _deny("recovery_spike_identity_unavailable")


def _identity(row, prefix):
    return ProcessIdentity(row[prefix + "_pid"],
        int(row[prefix + "_created_filetime_100ns"]), row["logon_id"])


@dataclass(frozen=True)
class _Scope:
    kind: str
    owner: object
    entry: object
    job: NativeJob
    process: VerifiedProcess
    wrapper: VerifiedProcess
    root: VerifiedProcess
    guardian_identity: ProcessIdentity
    binding: dict
    store: object
    counter_epoch: str | None = None


class SpikeRecoveryAuthority:
    """One in-process S3 fixture binding and one non-renewable deadline.

    bind_existing(owner, execution_id) borrows the original GuardianLaunchOwner
    custody. bind_helper(host, execution_id) borrows the helper's enrolled QUERY
    Job and retains native exact wrapper/root witnesses for proposal filtering.
    Neither accepts an execution row, native-proof flag or supplied scope hash.
    The optional clock is an explicit unit-test seam, not a CLI/env setting.
    """

    purpose = "recovery_spike"

    def __init__(self, *, profile, bundle_directory, expected_bundle_sha256,
                 data_directory, continuous_admission=None, clock=None,
                 observation_deadline_tick=None):
        self._evidence = evidence.NativeEvidenceAuthority(profile=profile,
            bundle_directory=bundle_directory, expected_bundle_sha256=expected_bundle_sha256,
            clock=clock)
        self.profile = profile
        self.config_revision = self._evidence.config_revision
        self.clock = self._evidence.clock
        self._start = evidence._integer(self.clock())
        self._deadline = (self._start + _DURATION_TICKS if observation_deadline_tick is None
                          else evidence._integer(observation_deadline_tick))
        if not self._start < self._deadline <= self._start + _DURATION_TICKS:
            _deny("recovery_spike_deadline_invalid")
        self._last_tick = self._start
        self.directory = Path(data_directory)
        self._ledger_identity = None
        self._scope = None
        self._binding_attempt = None
        self._binding_failure = None
        self._retained_processes = []
        self._prepared = self._prepared_tick = self._prepared_topologies = None
        self._gates_checked = False
        self._qualified_topologies = None
        self._failure = None
        self._context = None
        self._check_directory()
        # Import at use time: no alternate owner can be passed around the real
        # default-deny provider. Passing the original owner only checks identity.
        from tests.windows.adaptive_admission import require_continuous_admission
        self._coverage = require_continuous_admission()
        if (self._coverage is None or
                (continuous_admission is not None and continuous_admission is not self._coverage)):
            _deny("recovery_spike_daily_owner_mismatch")

    def _now(self):
        now = evidence._integer(self.clock())
        if now < self._last_tick or not self._start <= now < self._deadline:
            _deny("recovery_spike_deadline_expired")
        self._last_tick = now
        return now

    def _check_directory(self):
        if not self.directory.is_absolute():
            _deny("recovery_spike_isolated_directory_required")
        evidence._safe_directory(self.directory)
        daily = (Path.home() / ".resource-sentinel").resolve()
        actual = self.directory.resolve(strict=True)
        if actual == daily or daily in actual.parents or actual in daily.parents:
            _deny("recovery_spike_daily_directory_forbidden")
        ledger = self.directory / "sentinel.db"
        identity = evidence._fingerprint(ledger)[:2]
        daily_ledger = daily / "sentinel.db"
        if daily_ledger.exists() and evidence._fingerprint(daily_ledger)[:2] == identity:
            _deny("recovery_spike_daily_ledger_alias")
        if self._ledger_identity is not None and identity != self._ledger_identity:
            _deny("recovery_spike_ledger_replaced")
        self._ledger_identity = identity

    def _daily(self, row=None):
        # No duck-typed caller grants: this object came only from the trusted
        # default-deny provider above. Its live bridge must include scope demand
        # through restore + verified empty, including after wrapper/root exit.
        check = getattr(self._coverage, "assert_spike_covered", None)
        if not callable(check):
            _deny("recovery_spike_daily_scope_unverified")
        if check(data_directory=self.directory, execution_row=row) is not None:
            _deny("recovery_spike_daily_scope_unverified")

    def _store(self, owner):
        store = owner.store
        if (getattr(store, "existing_path", False) is not True or
                Path(store.db_path).resolve(strict=True) !=
                (self.directory / "sentinel.db").resolve(strict=True)):
            _deny("recovery_spike_foreign_ledger")
        return store

    def _begin_binding(self, kind, owner, execution_id):
        self._now()
        evidence._uuid(execution_id)
        if self._binding_attempt is not None:
            _deny("recovery_spike_scope_already_bound")
        # Pin before any open/query can become uncertain. Failed binding cannot
        # be replaced with a different fixture to obtain another 120 seconds.
        self._binding_attempt = (kind, owner, execution_id)
        self._prepared = self._prepared_tick = None

    def bind_existing(self, owner, execution_id):
        self._begin_binding("guardian", owner, execution_id)
        try:
            if type(owner) is not GuardianLaunchOwner:
                _deny("recovery_spike_original_guardian_required")
            store = self._store(owner)
            with owner.lifecycle._lock:
                entry = owner.lifecycle._entries.get(execution_id)
                if entry is None:
                    _deny("recovery_spike_original_custody_missing")
                row = dict(store.query(execution_id, existing_path=True))
                self._scope = _Scope("guardian", owner, entry, entry.job,
                    owner.guardian, entry.wrapper, entry.root, owner.guardian.identity,
                    {name: row[name] for name in _FULL_BINDING}, store)
                self._refresh_scope(row, initial=True)
        except BaseException as error:
            self._binding_failure = error
            raise

    def bind_helper(self, host, execution_id):
        self._begin_binding("helper", host, execution_id)
        try:
            if type(host) not in (HelperControlHost, OperationalHelperControlHost) or not host._started:
                _deny("recovery_spike_original_helper_required")
            store = self._store(host)
            entry = host.jobs._entries.get(execution_id)
            if entry is None:
                _deny("recovery_spike_helper_custody_missing")
            row = dict(store.query(execution_id, existing_path=True))
            wrapper = VerifiedProcess.open(_identity(row, "wrapper"))
            self._retained_processes.append(wrapper)
            root = VerifiedProcess.open(_identity(row, "root"))
            self._retained_processes.append(root)
            self._scope = _Scope("helper", host, entry, entry.job, host.process,
                wrapper, root, host.control_endpoint.server_identity,
                {name: row[name] for name in _FULL_BINDING}, store, entry.counter_epoch)
            self._refresh_scope(row, initial=True)
        except BaseException as error:
            # Any constructor cleanup owner stays reachable on the original
            # error. Do not silently close/reopen a PID on this failure path.
            self._binding_failure = error
            raise

    def _same_custody(self):
        scope = self._scope
        if scope is None or self._binding_failure is not None:
            _deny("recovery_spike_scope_unbound")
        owner, entry = scope.owner, scope.entry
        if owner.store is not scope.store:
            _deny("recovery_spike_store_owner_changed")
        if type(scope.job) is not NativeJob:
            _deny("recovery_spike_native_job_required")
        if (not scope.job._ready or scope.job._job.state != "owned" or
                any(type(process) is not VerifiedProcess or process._handle is None or
                    process._close_outcome_unknown for process in
                    (scope.process, scope.wrapper, scope.root))):
            _deny("recovery_spike_native_custody_unavailable")
        if scope.kind == "guardian":
            if (owner.lifecycle._entries.get(scope.binding["execution_id"]) is not entry or
                    owner.guardian is not scope.process or owner.lifecycle.guardian is not scope.process or
                    owner.guardian_epoch != scope.binding["guardian_epoch"] or
                    entry.job is not scope.job or entry.wrapper is not scope.wrapper or entry.root is not scope.root or
                    not entry.validated or entry.closed or entry.terminal or
                    entry.terminal_cleanup is not None or entry.journal_cleanup_error is not None or
                    entry.restore_integrity_error is not None or entry.mutex_error is not None or
                    scope.job.access is not JobAccess.OWNER):
                _deny("recovery_spike_guardian_custody_changed")
        elif (owner.jobs._entries.get(scope.binding["execution_id"]) is not entry or
                owner.process is not scope.process or entry.job is not scope.job or
                owner.control_endpoint.server_identity != scope.guardian_identity or
                owner.control_guardian_epoch != scope.binding["guardian_epoch"] or
                entry.counter_epoch != scope.counter_epoch or entry.unreadable or
                entry.cleanup_unverified or not entry.membership_provable or
                scope.job.access is not JobAccess.QUERY):
            _deny("recovery_spike_helper_custody_changed")
        if (scope.job.name != scope.binding["job_name"] or scope.job.nonce != scope.binding["job_nonce"] or
                scope.job.logon_sid != scope.binding["logon_id"] or
                scope.wrapper.identity != _identity(scope.binding, "wrapper") or
                scope.root.identity != _identity(scope.binding, "root")):
            _deny("recovery_spike_native_binding_changed")
        return scope

    @staticmethod
    def _row_eligible(row):
        if (row.get("role") != "background" or row.get("priority") not in {"P2", "P3"} or
                row.get("coverage") != "job_contained" or row.get("state") not in {"RUNNING", "DRAINING"} or
                type(row.get("launch_sealed")) is not int or row["launch_sealed"] != 1 or
                type(row.get("launch_in_flight")) is not int or row["launch_in_flight"] != 0):
            _deny("recovery_spike_execution_ineligible")

    def _refresh_scope(self, row, *, initial=False):
        scope = self._same_custody()
        self._row_eligible(row)
        if any(row.get(name) != value for name, value in scope.binding.items()):
            _deny("recovery_spike_execution_changed")
        _live(scope.process)
        _live(scope.wrapper)
        root_observation = scope.root.observe()
        if (root_observation.identity != scope.root.identity or
                root_observation.status is IdentityStatus.UNKNOWN or
                (initial and root_observation.status is not IdentityStatus.ALIVE)):
            _deny("recovery_spike_root_unavailable")
        if (scope.process.identity.pid != os.getpid() or
                len({scope.process.identity, scope.wrapper.identity, scope.root.identity}) != 3 or
                scope.process.identity.logon_id != scope.guardian_identity.logon_id or
                scope.guardian_identity.logon_id != scope.binding["logon_id"] or
                scope.process.is_in_job(scope.job.handle) is not False or
                scope.wrapper.is_in_job(scope.job.handle) is not False or
                (root_observation.status is IdentityStatus.ALIVE and
                    scope.root.is_in_job(scope.job.handle) is not True)):
            _deny("recovery_spike_native_scope_unverified")
        limits = scope.job.query_limits()
        if limits.limit_flags != 0 or limits.ui_restrictions != 0 or scope.job.accounting().active_processes < 1:
            _deny("recovery_spike_job_scope_unverified")
        if scope.kind == "helper" and scope.guardian_identity == scope.process.identity:
            _deny("recovery_spike_helper_is_not_actuator")
        self._daily(row)

    def assess(self):
        self._prepared = self._prepared_tick = self._prepared_topologies = None
        try:
            start = self._now()
            self._check_directory()
            self._daily()
            source = self._evidence
            source._load()  # production bounded strict JSON, pins and file identity
            context, build = source.context_source(), source.build_source()
            if type(context) is not evidence.LiveCapabilityContext or type(build) is not evidence.BuildIdentity:
                _deny("capability_live_source_invalid")
            bundle = source._bundle
            if evidence._object(bundle["build"], asdict(build)) != asdict(build):
                _deny("capability_build_mismatch")
            if evidence.LiveCapabilityContext(**evidence._object(bundle["context"], asdict(context))) != context:
                _deny("capability_host_context_mismatch")
            if bundle["profile_revision"] != self.config_revision:
                _deny("capability_profile_mismatch")
            missing = tuple(gate for gate in ("S1", "S2") if gate not in source._artifacts)
            if missing:
                return evidence.CapabilityAssessment(False, "capability_required_gates_unverified", missing)
            if not self._gates_checked:
                evidence._s1(source._artifacts["S1"], context)
                self._qualified_topologies = evidence._s2(source._artifacts["S2"], context)
                self._gates_checked = True
            measured = MeasuredLaunchTopologies(self.config_revision, context.fingerprint,
                source.expected_bundle_sha256, self._qualified_topologies)
            self._context = context
            if self._scope is not None:
                self._refresh_scope(dict(self._store(self._scope.owner).query(
                    self._scope.binding["execution_id"], existing_path=True)))
            if self._binding_failure is not None:
                _deny("recovery_spike_binding_unresolved")
            if self._now() - start > self.profile.sample_max_age_ms * 10_000:
                _deny("capability_refresh_stale")
            receipt = evidence.VerifiedCapability(context.logical_processors, self.config_revision,
                source.expected_bundle_sha256, self.purpose, context.fingerprint)
            self._prepared_topologies = measured
            self._prepared_tick = start
            self._prepared = evidence.CapabilityAssessment(True, "recovery_spike_prerequisites_verified",
                verified=receipt, scope_notes=("S3 fixture only; no S3/P4 or production promotion",))
            return self._prepared
        except Exception as error:
            self._failure = error
            reason = error.reason if isinstance(error, evidence.CapabilityEvidenceError) else "recovery_spike_unavailable"
            return evidence.CapabilityAssessment(False, reason)

    refresh = assess

    def _receipt(self):
        now = self._now()
        if self._prepared is None or self._prepared_tick is None:
            _deny("capability_receipt_unprepared")
        if now - self._prepared_tick > self.profile.sample_max_age_ms * 10_000:
            self._prepared = self._prepared_tick = self._prepared_topologies = None
            _deny("capability_receipt_stale")
        return self._prepared.verified

    def prepared_launch_topologies(self):
        self._receipt()
        return self._prepared_topologies

    def assert_control_eligible(self, *, profile_revision, logical_processors,
                                execution_row, guardian_identity):
        receipt = self._receipt()
        scope = self._same_custody()
        if (profile_revision != receipt.config_revision or type(logical_processors) is not int or
                logical_processors != receipt.logical_processors):
            _deny("capability_frame_binding_mismatch")
        if not isinstance(execution_row, Mapping) or type(guardian_identity) is not ProcessIdentity:
            _deny("capability_execution_binding_invalid")
        self._row_eligible(execution_row)
        fields = _FULL_BINDING if scope.kind == "guardian" else _COMMON_BINDING
        if (guardian_identity != scope.guardian_identity or
                any(execution_row.get(name) != scope.binding[name] for name in fields)):
            _deny("recovery_spike_execution_changed")
        if scope.kind == "guardian":
            lifecycle = scope.owner.lifecycle
            if (guardian_identity != scope.process.identity or guardian_identity.pid != os.getpid() or
                    lifecycle._scope_entry is not scope.entry or lifecycle._scope_thread != threading.get_ident()):
                _deny("recovery_spike_guardian_scope_required")
            scope.owner.store._policy.assert_held()
            RetainedLaunchScopeSource(owner=scope.owner, authority=self)(
                execution_id=execution_row["execution_id"], config_revision=receipt.config_revision,
                host_fingerprint=receipt.host_fingerprint, bundle_sha256=receipt.bundle_sha256)
        elif guardian_identity == scope.process.identity:
            _deny("recovery_spike_helper_is_not_actuator")
        elif execution_row.get("counter_epoch") != scope.counter_epoch:
            _deny("recovery_spike_helper_custody_changed")
        return receipt

    def close_helper_witnesses(self):
        """Close only our query witnesses after the fixture has settled control.

        This invalidates authority first and grants no restore/release evidence.
        Guardian custody is borrowed and is never closed here. Native ambiguous
        close owners retain their own quarantine; unresolved errors stay held.
        """
        self._prepared = self._prepared_tick = self._prepared_topologies = None
        self._binding_failure = evidence.CapabilityEvidenceError("recovery_spike_witnesses_closed")
        for process in tuple(self._retained_processes):
            process.close()
            self._retained_processes.remove(process)
