"""Test-only S3 bootstrap around the actual production hosts.

No role supplies admission, samples, acknowledgements, Query results or a
production capability receipt. Before starting any host it asks the trusted
daily provider for the original scope. JSON is a bounded rendezvous only.
Faults act only on this fixture process after native exact-owner validation.
The scheduler's restore/accounting/retirement code is used unchanged.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager, ExitStack
from dataclasses import asdict
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, strict_json_loads
from tests.windows.adaptive_recovery_runner import (
    CaseSpec, RawEvents, RecoveryRunUnavailable, _require, _tick, write_new,
)


ROLES = ("supervisor", "guardian", "helper", "wrapper")
CONTROL_FAULTS = {
    "intent_before", "intent_after_set_before", "set_after_query_before",
    "query_after_audit_before", "lease_renewal", "guardian_hang", "root_exit_after",
    "audit_unavailable",
}
_CLEANUP_HOLDS = []


class CleanupHold:
    """Resident custody after ambiguous cleanup, with no blind native retry."""
    def __init__(self, owners, error):
        self.owners, self.error = tuple(owners), error

    def wait_forever(self):
        while True:
            try:
                time.sleep(.25)
            except KeyboardInterrupt:
                # The external observer's deadline remains failed. A console
                # signal cannot turn unknown native cleanup into a normal exit.
                continue


def retain_cleanup(owners, error):
    hold = CleanupHold(owners, error)
    _CLEANUP_HOLDS.append(hold)
    hold.wait_forever()


@contextmanager
def _replace(owner, name, value):
    original = getattr(owner, name)
    setattr(owner, name, value)
    try:
        yield original
    finally:
        setattr(owner, name, original)


def load_case(directory):
    from sentinel.adaptive.capability_evidence import _safe_directory, _read
    directory = Path(directory)
    _require(directory.is_absolute(), "s3_case_absolute_directory_required")
    _safe_directory(directory)
    directory = directory.resolve(strict=True)
    daily = (Path.home() / ".resource-sentinel").resolve()
    _require(directory != daily and daily not in directory.parents and directory not in daily.parents,
             "s3_daily_runtime_forbidden")
    payload, _ = _read(directory / "case.json", 64 * 1024)
    value = strict_json_loads(payload)
    required = {"schema_version", "purpose", "run_id", "case", "iteration", "scope_nonce", "started_tick",
                "data_directory", "journal_directory", "profile", "prior_bundle_directory", "prior_bundle_sha256"}
    _require(type(value) is dict and set(value) == required and value["schema_version"] == 1 and
             value["purpose"] == "recovery_spike", "s3_case_schema_invalid")
    spec = CaseSpec(**{key: value[key] for key in ("run_id", "case", "iteration", "scope_nonce", "started_tick")})
    spec.check_time(_tick())
    for name in ("data_directory", "journal_directory"):
        path = Path(value[name])
        _require(path.is_absolute(), "s3_case_scope_directory_invalid")
        _safe_directory(path)
        path = path.resolve(strict=True)
        _require(directory in path.parents and path != daily and daily not in path.parents,
                 "s3_case_scope_directory_invalid")
    return directory, spec, value


class AuditOutage:
    """One thread owns a real isolated SQLite write lock through withdrawal."""
    def __init__(self, hooks, entry):
        self.hooks, self.entry = hooks, entry
        self.ready, self.done = threading.Event(), threading.Event()
        self.error, self.locked, self.thread = None, False, None
        self.path = Path(hooks.control.store.db_path).resolve(strict=True)
        daily = (Path.home() / ".resource-sentinel").resolve()
        _require(hooks.directory in self.path.parents and daily not in self.path.parents,
                 "s3_audit_daily_directory_forbidden")
        daily_ledger = daily / "sentinel.db"
        _require(not daily_ledger.exists() or not self.path.samefile(daily_ledger),
                 "s3_audit_daily_ledger_alias")

    def start(self):
        _require(self.thread is None, "s3_audit_owner_already_started")
        self.thread = threading.Thread(target=self._run, name="s3-isolated-audit-lock", daemon=False)
        self.thread.start()
        remaining = (self.hooks.spec.deadline_tick - _tick()) / 10_000_000
        if not self.ready.wait(max(0, min(1., remaining))) or self.error is not None or not self.locked:
            raise RecoveryRunUnavailable("s3_audit_lock_unavailable")

    def _run(self):
        connection = None
        details = dict(point="audit_unavailable", execution_id=self.entry.execution_id,
            job_nonce=self.entry.job.nonce, role="guardian", source="sqlite_transaction")
        try:
            self.hooks.spec.check_time(_tick())
            connection = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                                         timeout=.25, isolation_level=None)
            connection.execute("BEGIN IMMEDIATE")
            self.locked = True
            self.hooks.raw.append("audit_lock_acquired", tick=_tick(), **details)
            self.ready.set()
            while (_tick() < self.hooks.spec.deadline_tick and
                   not (self.hooks.directory / "release-audit").exists()):
                time.sleep(.02)
        except BaseException as error:
            self.error = error
            self.ready.set()
        finally:
            # Only this thread ever touches its connection. No external raw
            # handle close or retry substitutes for a positive rollback/close.
            if connection is not None:
                try:
                    connection.rollback()
                    connection.close()
                    was_locked = self.locked
                    self.locked = False
                except BaseException as error:
                    self.error = error
                    retain_cleanup((self, connection), error)
                else:
                    if was_locked:
                        try:
                            self.hooks.raw.append("audit_lock_released", tick=_tick(), **details)
                        except BaseException as error:
                            # The connection already closed positively. A log
                            # failure invalidates evidence, not that close ACK.
                            self.error = error
            self.done.set()


class FaultHooks:
    """Real method boundary instrumentation, restricted to one native owner.

    `arm-fault` is a synchronization signal, never scope authorization. The
    authority comes from this current fixture process and its original adopted
    GuardianLaunchOwner. A malformed scope refuses before any intentional exit.
    """
    def __init__(self, directory, spec, role, raw):
        self.directory, self.spec, self.role, self.raw = directory, spec, role, raw
        self.control = self.host = None
        self.fired = False
        self.observed = False
        self.audit_outage = None
        self._proposal_context = None
        self._published_intent = None
        self._latest_native_write = None

    def armed(self, point):
        return self.spec.case == point and (self.directory / "arm-fault").exists()

    def scope(self, job=None):
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.native_job import NativeJob
        _require(self.control is not None and self.role == "guardian", "s3_fault_owner_unbound")
        owner = self.control.owner
        ids = owner.lifecycle.retained_execution_ids
        _require(len(ids) == 1, "s3_fault_scope_not_single")
        entry = owner.lifecycle._entry(ids[0])
        _require(entry.validated and not entry.closed and type(entry.job) is NativeJob and
                 (job is None or job is entry.job), "s3_fault_job_not_owned")
        current = owner.guardian
        _require(type(current) is VerifiedProcess and current.identity.pid == os.getpid(),
                 "s3_fault_process_not_original")
        observed = current.observe()
        _require(observed.identity == current.identity and observed.status is IdentityStatus.ALIVE and
                 current.is_in_job(entry.job.handle) is False and entry.wrapper.is_in_job(entry.job.handle) is False,
                 "s3_fault_infrastructure_scope_invalid")
        _require(entry.job.accounting().active_processes > 0, "s3_fault_no_live_workload")
        return entry

    @contextmanager
    def proposal_context(self, proposal, entry, *, previous_lease=None):
        previous = self._proposal_context, self._published_intent
        self._proposal_context = (proposal, entry, previous_lease)
        self._published_intent = None
        try:
            yield
        finally:
            self._proposal_context, self._published_intent = previous

    def cutpoint(self, point, entry, manifest, action_id, desired, *, action=None, native_set=None):
        if self.fired or not self.armed(point):
            return None
        from sentinel.adaptive.contracts import ControlProposal, RecoveryManifest
        _require(self._proposal_context is not None, "s3_original_control_context_missing")
        proposal, original_entry, previous_lease = self._proposal_context
        _require(original_entry is entry and type(proposal) is ControlProposal and
                 type(manifest) is RecoveryManifest and proposal.execution_id == entry.execution_id and
                 manifest.execution_id == entry.execution_id and manifest.creation_nonce == entry.job.nonce,
                 "s3_original_control_context_mismatch")
        return self.raw.append("control_cutpoint", tick=_tick(), point=point,
            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
            actor_identity=self.control.owner.guardian.identity.to_dict(),
            boundary="set_after_query_before" if point == "guardian_hang" else point,
            manifest=manifest.to_dict(), proposal=proposal.to_dict(), action_id=action_id,
            desired=desired.to_dict(), action=None if action is None else asdict(action),
            native_set_attempt_id=None if native_set is None else native_set["attempt_id"],
            previous_lease_deadline_tick_100ns=previous_lease)

    def hit(self, point, *, job=None, cutpoint=None):
        if self.fired or not self.armed(point):
            return
        self.spec.check_time(_tick())
        entry = self.scope(job)
        if point in {"intent_before", "intent_after_set_before", "set_after_query_before",
                     "query_after_audit_before", "lease_renewal", "guardian_hang"}:
            _require(cutpoint is not None and any(item is cutpoint for item in self.raw.records) and
                     cutpoint.get("point") == point and cutpoint.get("execution_id") == entry.execution_id and
                     cutpoint.get("job_nonce") == entry.job.nonce,
                     "s3_control_cutpoint_missing")
        extra = {}
        if point == "root_exit_after":
            root = entry.root.observe()
            if root.status is IdentityStatus.ALIVE:
                return
            _require(root.identity == entry.root.identity and root.status is IdentityStatus.DEAD,
                     "s3_original_root_exit_unverified")
            if entry.job.query_cpu().flags != 5:
                return
            extra["root_identity"] = root.identity.to_dict()
            self.raw.append("root_exit_observed", tick=_tick(), point=point,
                execution_id=entry.execution_id, job_nonce=entry.job.nonce,
                observed_identity=root.identity.to_dict(), source="retained_root_witness",
                active_processes=entry.job.accounting().active_processes, exit_code=entry.root.exit_code())
        self.fired = True
        self.raw.append("fault_injected", tick=_tick(), point=point, role=self.role,
            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
            actor_identity=self.control.owner.guardian.identity.to_dict(),
            mechanism="original_fixture_self_exit" if point != "guardian_hang" else "original_fixture_wait", **extra)
        if point == "guardian_hang":
            # Keep the actual held POLICY/Job fences; no Suspend/Resume. This
            # measures a real hung owner. Releasing the wait is fixture cleanup,
            # never a claim that an unverified recovery owner can steal a lock.
            while not (self.directory / "release-hang").exists() and _tick() < self.spec.deadline_tick:
                time.sleep(.02)
            return
        self.raw.append("process_fault_termination", tick=_tick(), role=self.role, point=point,
            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
            actor_identity=self.control.owner.guardian.identity.to_dict(),
            original_creation_handle_verified=True, mechanism="original_fixture_self_exit")
        # Only this exact process is faulted. No PID/name lookup or taskkill.
        os._exit(197)

    def audit_failure(self):
        """Hold an actual writer lock; invoke the real audit unchanged."""
        if (not self.armed("audit_unavailable") or
                (self.directory / "release-audit").exists() or _tick() >= self.spec.deadline_tick):
            return
        if self.audit_outage is None:
            entry = self.scope()
            # Only test recovery of a restriction that really exists now.
            if entry.job.query_cpu().flags != 5:
                return
            self.audit_outage = AuditOutage(self, entry)
            self.audit_outage.start()
            self.fired = True
            self.raw.append("fault_injected", tick=_tick(), point=self.spec.case, role="guardian",
                execution_id=entry.execution_id, job_nonce=entry.job.nonce,
                actor_identity=self.control.owner.guardian.identity.to_dict(),
                mechanism="isolated_audit_write_failure")

    def audit_error(self, error):
        if (self.audit_outage is not None and self.audit_outage.locked and not self.observed and
                isinstance(error, sqlite3.OperationalError) and
                type(getattr(error, "sqlite_errorcode", None)) is int and
                error.sqlite_errorcode & 0xff in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}):
            entry = self.audit_outage.entry
            self.raw.append("fault_observed", tick=_tick(), point=self.spec.case, role="guardian",
                execution_id=entry.execution_id, job_nonce=entry.job.nonce,
                observed_identity=self.control.owner.guardian.identity.to_dict(),
                source="audit_write_exception", effect="audit_write_failed",
                sqlite_errorcode=error.sqlite_errorcode)
            self.observed = True

    def wrapper_loss(self, launcher):
        """Fault only this original, successfully bound fixture wrapper."""
        if self.fired or not self.armed("wrapper_loss"):
            return
        from sentinel.adaptive.identity import VerifiedProcess
        from sentinel.adaptive.launcher import ManagedLauncher
        from sentinel.adaptive.native_launcher import CreatedProcess
        from sentinel.adaptive.native_job import NativeJob
        self.spec.check_time(_tick())
        _require(self.role == "wrapper" and type(launcher) is ManagedLauncher and launcher._bound and
                 type(launcher.job) is NativeJob and type(launcher.process) is CreatedProcess,
                 "s3_original_bound_wrapper_required")
        current = launcher.admission._process
        _require(type(current) is VerifiedProcess and current.identity.pid == os.getpid(),
                 "s3_fault_process_not_original")
        observed = current.observe()
        _require(observed.identity == current.identity and observed.status is IdentityStatus.ALIVE and
                 current.is_in_job(launcher.job.handle) is False and
                 launcher.process.full_identity(expected_logon_id=current.identity.logon_id) == launcher._root and
                 launcher.process.is_in_job(launcher.job) is True and
                 launcher.job.accounting().active_processes > 0,
                 "s3_fault_infrastructure_scope_invalid")
        if launcher.job.query_cpu().flags != 5:
            return
        self.fired = True
        values = dict(point="wrapper_loss", role="wrapper", execution_id=launcher.execution_id,
            job_nonce=launcher.job.nonce, actor_identity=current.identity.to_dict(),
            mechanism="original_fixture_self_exit")
        self.raw.append("fault_injected", tick=_tick(), **values)
        self.raw.append("process_fault_termination", tick=_tick(),
            original_creation_handle_verified=True, **values)
        os._exit(197)

    def install_guardian(self, stack, authority_factory):
        from sentinel.adaptive import guardian_control as module
        from sentinel.adaptive.native_job import NativeJob
        original_constructor = module.GuardianControl
        hooks = self
        def construct(owner, **kwargs):
            kwargs["capability_authority"] = authority_factory(kwargs["profile"])
            control = original_constructor(owner, **kwargs)
            hooks.control = control
            return control
        stack.enter_context(_replace(module, "GuardianControl", construct))
        original_apply = original_constructor.apply
        def apply(control, proposal, **kwargs):
            authority = control.capability_authority
            if authority._scope is None:
                authority.bind_existing(control.owner, proposal.execution_id)
            return original_apply(control, proposal, **kwargs)
        stack.enter_context(_replace(original_constructor, "apply", apply))
        original_begin = original_constructor._begin_locked
        def begin(control, proposal, entry, *args, **kwargs):
            with hooks.proposal_context(proposal, entry):
                return original_begin(control, proposal, entry, *args, **kwargs)
        stack.enter_context(_replace(original_constructor, "_begin_locked", begin))
        original_intent = original_constructor._publish_intent
        def intent(control, entry, row, action_id, desired, **kwargs):
            if hooks.armed("intent_before") and not hooks.fired:
                manifest = control.lifecycle._manifest(entry, row)
                cut = hooks.cutpoint("intent_before", entry, manifest, action_id, desired)
                hooks.hit("intent_before", cutpoint=cut)
            value = original_intent(control, entry, row, action_id, desired, **kwargs)
            hooks._published_intent = (entry, value, action_id, desired)
            cut = hooks.cutpoint("intent_after_set_before", entry, value, action_id, desired)
            hooks.hit("intent_after_set_before", cutpoint=cut)
            return value
        stack.enter_context(_replace(original_constructor, "_publish_intent", intent))
        original_flush = original_constructor._flush
        def flush(control, execution_id, row):
            if hooks._proposal_context is not None:
                proposal, entry, _ = hooks._proposal_context
                actions = [item for item in control._actions.get(execution_id, ())
                           if item.execution_id == proposal.execution_id and
                              item.decision_seq == proposal.decision_seq]
                if len(actions) == 1 and actions[0].action_state in {"APPLIED", "RENEWED"}:
                    action = actions[0]
                    point = "query_after_audit_before" if action.action_state == "APPLIED" else "lease_renewal"
                    if hooks.armed(point) and not hooks.fired:
                        manifest = control.lifecycle._manifest(entry, row)
                        from sentinel.adaptive.contracts import CpuControl, CpuControlMode
                        desired = CpuControl(CpuControlMode.HARD_CAP, action.desired_rate_bp)
                        cut = hooks.cutpoint(point, entry, manifest, action.action_id, desired, action=action)
                        hooks.hit(point, cutpoint=cut)
            hooks.audit_failure()
            try:
                return original_flush(control, execution_id, row)
            except BaseException as error:
                hooks.audit_error(error)
                raise
        stack.enter_context(_replace(original_constructor, "_flush", flush))
        original_renew = original_constructor._renew_locked
        def renew(control, proposal, entry, episode, *args, **kwargs):
            with hooks.proposal_context(proposal, entry, previous_lease=episode.lease_deadline_tick_100ns):
                return original_renew(control, proposal, entry, episode, *args, **kwargs)
        stack.enter_context(_replace(original_constructor, "_renew_locked", renew))
        original_tick = original_constructor.tick
        def tick(control, *args, **kwargs):
            # Query the original root before the real production safety sweep.
            # A live child keeps the allocation regardless of that root's death.
            if hooks.armed("root_exit_after") and not hooks.fired:
                with control.owner._lock:
                    ids = control.owner.lifecycle.retained_execution_ids
                    if len(ids) == 1:
                        with control.owner.lifecycle._scope(control.owner.lifecycle._entry(ids[0])):
                            hooks.hit("root_exit_after")
            if hooks.armed("wrapper_loss") and not hooks.observed:
                for entry in tuple(control.owner.lifecycle._entries.values()):
                    observed = entry.wrapper.observe()
                    if observed.identity == entry.wrapper.identity and observed.status is IdentityStatus.DEAD:
                        hooks.raw.append("fault_observed", tick=_tick(), point="wrapper_loss", role="wrapper",
                            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
                            observed_identity=observed.identity.to_dict(), source="retained_wrapper_witness")
                        hooks.observed = True
            return original_tick(control, *args, **kwargs)
        stack.enter_context(_replace(original_constructor, "tick", tick))
        original_set = NativeJob.set_cpu_rate_unverified
        def set_rate(job, value):
            result = original_set(job, value)
            captured = hooks._published_intent
            native = hooks._latest_native_write
            if (captured is not None and captured[0].job is job and native is not None and
                    native[0] is job and native[1]["desired_flags"] == 5 and
                    native[1]["desired_rate_bp"] == value):
                entry, manifest, action_id, desired = captured
                for point in ("set_after_query_before", "guardian_hang"):
                    cut = hooks.cutpoint(point, entry, manifest, action_id, desired, native_set=native[1])
                    hooks.hit(point, job=job, cutpoint=cut)
            return result
        stack.enter_context(_replace(NativeJob, "set_cpu_rate_unverified", set_rate))

    def install_writes(self, stack):
        """Observe the real native Set boundary for both allowed writer roles."""
        from sentinel.adaptive.native_job import NativeJob
        original = NativeJob._set
        hooks = self
        def write(job, flags, rate_bp):
            entries = ()
            if hooks.role == "guardian":
                if hooks.control is not None:
                    entries = hooks.control.owner.lifecycle._entries.values()
            elif hooks.role == "supervisor" and hooks.host is not None and hooks.host.supervisor is not None:
                entries = hooks.host.supervisor.recovery._entries.values()
            matches = [entry for entry in entries if entry.job is job]
            started = _tick()
            attempt_id = str(uuid4())
            details = dict(attempt_id=attempt_id, before_tick=started,
                role="guardian" if hooks.role == "guardian" else "retained_supervisor",
                execution_id=matches[0].execution_id if len(matches) == 1 else None, job_nonce=job.nonce,
                desired_flags=flags, desired_rate_bp=rate_bp)
            record_error = None
            try:
                hooks.raw.append("cpu_write_attempt", tick=started, **details)
            except BaseException as error:
                record_error = error
                if flags != 0:
                    raise  # no new restriction without a complete attempt log.
            # Instrumentation does not block native withdrawal when a scope
            # becomes empty or observer attribution fails. Production fencing
            # remains authoritative. An unattributed write fails reduction.
            try:
                result = original(job, flags, rate_bp)
            except BaseException as primary:
                try:
                    hooks.raw.append("cpu_write_unknown", tick=_tick(), error_type=type(primary).__name__, **details)
                except BaseException as error:
                    hooks._instrumentation_error = error
                raise
            receipt = hooks.raw.append("cpu_write", tick=_tick(), **details)
            hooks._latest_native_write = (job, receipt)
            if record_error is not None:
                hooks._instrumentation_error = record_error
                raise record_error
            return result
        stack.enter_context(_replace(NativeJob, "_set", write))
        self.raw.append("writer_instrumentation_ready", tick=_tick(), role=self.role,
                        boundary="NativeJob._set")


def _authority_factory(value, coverage):
    from tests.windows.adaptive_recovery_authority import SpikeRecoveryAuthority
    def create(profile):
        return SpikeRecoveryAuthority(profile=profile, bundle_directory=value["prior_bundle_directory"],
            expected_bundle_sha256=value["prior_bundle_sha256"], data_directory=value["data_directory"],
            continuous_admission=coverage,
            observation_deadline_tick=value["started_tick"] + 120 * 10_000_000)
    return create


def _assert_arguments_scope(arguments, value, role="guardian"):
    # Validate the SAME grammar the host consumes, including --name=value,
    # abbreviation and argparse's last-value-wins duplicate semantics. A token
    # scan can otherwise validate a safe first value and run on a daily last.
    from sentinel.adaptive import guardian_host, supervisor_host, helper_host, wrapper_host
    modules = dict(guardian=guardian_host, supervisor=supervisor_host,
                   helper=helper_host, wrapper=wrapper_host)
    _require(role in modules, "s3_host_role_invalid")
    options = modules[role].build_parser().parse_args(arguments)
    for attribute, name in (("data_dir", "data_directory"), ("journal_dir", "journal_directory")):
        path = getattr(options, attribute, None)
        if path is None and attribute == "journal_dir":
            continue
        _require(path is not None and Path(path).resolve(strict=True) == Path(value[name]).resolve(strict=True),
                 "s3_host_scope_argument_mismatch")
    return options


def run_role(directory, role, arguments):
    directory, spec, value = load_case(directory)
    _assert_arguments_scope(arguments, value, role)
    from tests.windows.adaptive_admission import require_continuous_admission
    coverage = require_continuous_admission()
    verifier = getattr(coverage, "assert_spike_covered", None)
    _require(callable(verifier), "s3_daily_scope_bridge_unavailable")
    _require(verifier(data_directory=Path(value["data_directory"]), execution_row=None) is None,
             "s3_daily_scope_unverified")
    from tests.windows.adaptive_win32 import require_supported_host
    require_supported_host()
    raw = RawEvents(spec, directory / ("actor-" + role + "-" + str(os.getpid()) + ".jsonl"))
    hooks = FaultHooks(directory, spec, role, raw)
    factory = _authority_factory(value, coverage)
    with ExitStack() as stack:
        if role == "guardian":
            from sentinel.adaptive import guardian_host
            hooks.install_guardian(stack, factory)
            hooks.install_writes(stack)
            return guardian_host.main(arguments)
        if role == "supervisor":
            from sentinel.adaptive import supervisor_host
            original_child = supervisor_host.SupervisorHost._child_arguments
            original_helper = supervisor_host.SupervisorHost._helper_arguments
            def child(host, epoch):
                args = original_child(host, epoch)
                _require(args[:2] == ["-m", "sentinel.adaptive.guardian_host"], "s3_guardian_entrypoint_changed")
                return ["-m", "tests.fixtures.adaptive_recovery_host", "--case-directory", str(directory),
                        "--role", "guardian", "--", *args[2:]]
            def helper(host):
                args = original_helper(host)
                _require(args[:2] == ["-m", "sentinel.adaptive.helper_host"], "s3_helper_entrypoint_changed")
                return ["-m", "tests.fixtures.adaptive_recovery_host", "--case-directory", str(directory),
                        "--role", "helper", "--", *args[2:]]
            stack.enter_context(_replace(supervisor_host.SupervisorHost, "_child_arguments", child))
            stack.enter_context(_replace(supervisor_host.SupervisorHost, "_helper_arguments", helper))
            original_host = supervisor_host.SupervisorHost
            class ObservedSupervisor(original_host):
                def __init__(self, **kwargs):
                    super().__init__(**kwargs)
                    hooks.host = self
                    self._s3_death_observed = False

                def run_once(self):
                    # Observe the same creation witness BEFORE recovery tick;
                    # recovery latency is measured from an actual native wait.
                    if self.guardian is not None and not self._s3_death_observed:
                        observed = self.guardian.process.observe()
                        if observed.identity == self.guardian.process.identity and observed.status is IdentityStatus.DEAD:
                            known = () if self.supervisor is None else tuple(self.supervisor._known.items())
                            if len(known) == 1:
                                raw.append("fault_observed", tick=_tick(), role="guardian", point=spec.case,
                                    execution_id=known[0][0], job_nonce=known[0][1],
                                    observed_identity=observed.identity.to_dict(), source="retained_creation_witness")
                            self._s3_death_observed = True
                    if (directory / "stop-hosts").exists():
                        self.begin_drain()
                    return super().run_once()
            stack.enter_context(_replace(supervisor_host, "SupervisorHost", ObservedSupervisor))
            hooks.install_writes(stack)
            return supervisor_host.main(arguments)
        if role == "helper":
            # Active helper integration must retain its real operator endpoint.
            # This path uses actual sampling and does not force a HIGH frame.
            from sentinel.adaptive import helper_host
            from sentinel.adaptive.helper_control_host import (
                OperationalHelperControlHost, operational_options, run_operational,
            )
            from sentinel.adaptive.decision import parse_policy_profile
            options = helper_host.build_parser().parse_args(arguments)
            binding = operational_options(options)
            _require(binding is not None, "s3_helper_original_parent_required")
            profile = parse_policy_profile(Path(options.profile).read_bytes())
            authority = factory(profile)
            host = OperationalHelperControlHost(data_dir=options.data_dir, profile_path=options.profile,
                endpoint=binding["guardian_endpoint"], evidence_authority=authority,
                enroll_every_ticks=options.enroll_every, report_every_ticks=options.report_every, **binding)
            original_run_once = host.run_once
            def helper_tick():
                if authority._scope is None and len(host.jobs.enrolled) == 1:
                    authority.bind_helper(host, host.jobs.enrolled[0])
                return original_run_once()
            host.run_once = helper_tick
            # The guardian is the only actuator. Helper proposal filtering uses
            # its actual enrolled QUERY scopes; production receipt semantics
            # prevent this artifact-only prerequisite from enabling an OS Set.
            result = run_operational(host, iterations=options.iterations)
            try:
                authority.close_helper_witnesses()
            except BaseException as error:
                retain_cleanup((authority, host), error)
            return result
        from sentinel.adaptive import wrapper_host
        from sentinel.adaptive import native_launcher
        from sentinel.adaptive.launcher import ManagedLauncher
        original_host = wrapper_host.WrapperHost
        class ObservedWrapper(original_host):
            def _check_interrupt(self):
                super()._check_interrupt()
                if self.launcher is not None:
                    hooks.wrapper_loss(self.launcher)

            def _build_launcher(self, launch_spec):
                holder = {}
                def create(job, application, command_line, **kwargs):
                    launcher = holder["launcher"]
                    write_new(directory / "job-locator.json", dict(execution_id=launcher.execution_id,
                        job_name=job.name, job_nonce=job.nonce, logon_id=job.logon_sid))
                    return native_launcher.launch_in_job(job, application, command_line, **kwargs)
                def launcher_factory(*args, **kwargs):
                    launcher = ManagedLauncher(*args, **kwargs, launch=create)
                    holder["launcher"] = launcher
                    return launcher
                self.launcher_factory = launcher_factory
                return super()._build_launcher(launch_spec)

            def _launch(self, handles):
                result = super()._launch(handles)
                raw.append("wrapper_bound", tick=_tick(), execution_id=self.launcher.execution_id,
                           wrapper_identity=self.launcher.admission.snapshot().wrapper_identity.to_dict())
                return result

            def _wait(self):
                result = super()._wait()
                raw.append("wrapper_root_wait_completed", tick=_tick(), execution_id=self.launcher.execution_id,
                           active_processes=self.launcher.job.accounting().active_processes)
                return result
        stack.enter_context(_replace(wrapper_host, "WrapperHost", ObservedWrapper))
        # WrapperHost owns unknown submission/Create/bind outcomes and its
        # unbounded safe settlement loop. The fixture never maps these into a
        # normal prelaunch failure or invokes the raw command as fallback.
        return wrapper_host.main(arguments)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-directory", required=True)
    parser.add_argument("--role", choices=ROLES, required=True)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    options = parser.parse_args(argv)
    args = options.arguments[1:] if options.arguments[:1] == ["--"] else options.arguments
    _require(os.name == "nt", "s3_windows_required")
    return run_role(options.case_directory, options.role, args)


if __name__ == "__main__":
    raise SystemExit(main())
