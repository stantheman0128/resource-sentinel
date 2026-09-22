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
import os
from pathlib import Path
import sys
import time
from uuid import uuid4

from sentinel.adaptive.contracts import IdentityStatus, strict_json_loads
from tests.windows.adaptive_recovery_runner import (
    CaseSpec, RawEvents, RecoveryRunUnavailable, _require, _tick, write_new,
)


ROLES = ("supervisor", "guardian", "helper", "wrapper")
CONTROL_FAULTS = {
    "intent_before", "intent_after_set_before", "set_after_query_before",
    "query_after_audit_before", "lease_renewal", "guardian_hang",
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

    def hit(self, point, *, job=None):
        if self.fired or self.spec.case != point or not (self.directory / "arm-fault").exists():
            return
        self.spec.check_time(_tick())
        entry = self.scope(job)
        self.fired = True
        self.raw.append("fault_injected", tick=_tick(), point=point, role=self.role,
            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
            mechanism="original_fixture_self_exit" if point != "guardian_hang" else "original_fixture_wait")
        if point == "guardian_hang":
            # Keep the actual held POLICY/Job fences; no Suspend/Resume. This
            # measures a real hung owner. Releasing the wait is fixture cleanup,
            # never a claim that an unverified recovery owner can steal a lock.
            while not (self.directory / "release-hang").exists() and _tick() < self.spec.deadline_tick:
                time.sleep(.02)
            return
        self.raw.append("process_fault_termination", tick=_tick(), role=self.role,
            execution_id=entry.execution_id, job_nonce=entry.job.nonce,
            original_creation_handle_verified=True, mechanism="original_fixture_self_exit")
        # Only this exact process is faulted. No PID/name lookup or taskkill.
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
        original_intent = original_constructor._publish_intent
        def intent(control, *args, **kwargs):
            hooks.hit("intent_before")
            value = original_intent(control, *args, **kwargs)
            hooks.hit("intent_after_set_before")
            return value
        stack.enter_context(_replace(original_constructor, "_publish_intent", intent))
        original_flush = original_constructor._flush
        def flush(control, *args, **kwargs):
            hooks.hit("query_after_audit_before")
            return original_flush(control, *args, **kwargs)
        stack.enter_context(_replace(original_constructor, "_flush", flush))
        original_renew = original_constructor._renew_locked
        def renew(control, *args, **kwargs):
            hooks.hit("lease_renewal")
            return original_renew(control, *args, **kwargs)
        stack.enter_context(_replace(original_constructor, "_renew_locked", renew))
        original_set = NativeJob.set_cpu_rate_unverified
        def set_rate(job, value):
            result = original_set(job, value)
            hooks.hit("set_after_query_before", job=job)
            hooks.hit("guardian_hang", job=job)
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
            hooks.raw.append("cpu_write", tick=_tick(), **details)
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
    raw = RawEvents(spec, directory / ("actor-" + role + ".jsonl"))
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
                            raw.append("fault_observed", tick=_tick(), role="guardian",
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
                raw.append("root_exit_observed", tick=_tick(), execution_id=self.launcher.execution_id,
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
