"""Wrapper-owned direct admission and one no-cap, guardian-bound native launch.

The command exists only in this wrapper's memory. Coordinator admission binds
its original semantics; the deterministic cmd.exe transport is constructed only
for CreateProcess. No command, cwd or environment is sent over the launch RPC.
This module is not a CLI, supervisor, host capability test or control actuator.
The default native readiness authority refuses enrollment. A trusted in-process
runtime authority must independently verify the real host, capability gates and
continuous writer cohort immediately before claim and native creation.

One call to admit_once is one admission attempt. A denied/uncertain attempt keeps
the same ManagedAdmission for a caller's later retry, without cancelling its
queue. LaunchSpec.admission_timeout_sec belongs to that driver's admission wait;
it is never a workload timer. Once launch preparation starts, launch_once is
permanently sealed even if an RPC ACK or native creation result is lost.

The caller must keep this launcher (or an exception's launcher_owner) while any
outcome/cleanup is unresolved. Root exit never releases shared accounting. After
a verified BindRoot ACK and positive root exit, close_local releases only this
wrapper's handles; the guardian retains its independent Job/root custody and
observes descendants. There is no destructor, automatic retry, fallback or kill.
"""
from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import ntpath
import os
from pathlib import Path
import threading
from uuid import uuid4

from .admission import ManagedAdmission
from .contracts import ProcessIdentity, _identifier
from .launch_spec import LaunchSpec, build_cmd_command_line, utf16_units
from .native_job import JobAccess, JobLimits, NativeJob
from . import native_launcher


class ManagedLaunchError(RuntimeError):
    """Stable reason, never raw command/path text or a synthesized child exit."""
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class RootObservation:
    execution_id: str
    exited: bool
    exit_code: int | None
    bind_acknowledged: bool


class _UnavailableReadiness:
    def assert_launch_ready(self, admission, row, endpoint):
        raise ManagedLaunchError("native_launch_readiness_unavailable")


def resolve_system_cmd(cmd_path: str | None = None) -> str:
    """Resolve the OS system cmd.exe, never COMSPEC/PATH or a supplied program.

    This is executable-path validation, not a signature/host-readiness claim.
    The OS directory and its files are trusted; hostile replacement by a user
    able to modify system files is outside same-user scheduling governance.
    https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw
    """
    if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
        raise ManagedLaunchError("system_cmd_platform_unsupported")
    try:
        api = C.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
        api.argtypes, api.restype = (C.c_wchar_p, C.c_uint32), C.c_uint32
        buffer = C.create_unicode_buffer(32768)
        count = api(buffer, len(buffer))
        if not 0 < count < len(buffer) or utf16_units(buffer.value) != count:
            raise ManagedLaunchError("system_cmd_unavailable")
        expected = Path(ntpath.join(buffer.value, "cmd.exe")).resolve(strict=True)
        supplied = expected if cmd_path is None else Path(cmd_path).resolve(strict=True)
        if (not expected.is_file() or not supplied.is_file() or
                ntpath.normcase(str(supplied)) != ntpath.normcase(str(expected))):
            raise ManagedLaunchError("system_cmd_mismatch")
        return str(expected)
    except ManagedLaunchError:
        raise
    except (OSError, TypeError, ValueError, RuntimeError):
        raise ManagedLaunchError("system_cmd_unavailable") from None


def _remember(error, owner):
    error.launcher_owner = owner


class ManagedLauncher:
    """One wrapper execution; explicit collaborators are in-process seams only.

    Native defaults use ManagedAdmission, authenticated Named Pipes, NativeJob
    and the single-create native launcher. No serialized config or status field
    can replace ``readiness.assert_launch_ready(admission, row, endpoint)``.
    That method must raise on uncertainty and return None only after its real
    checks. A boolean or cached fixture readiness receipt is not authority.
    """
    def __init__(self, spec: LaunchSpec, *, coordinator, endpoint, guardian_epoch: str,
                 cmd_path=None, readiness=None, client_factory=None,
                 admission_factory=None, job_factory=None, launch=None, cmd_resolver=None):
        if type(spec) is not LaunchSpec:
            raise ManagedLaunchError("launch_spec_required")
        spec.__post_init__()
        _identifier(guardian_epoch, "guardian_epoch")
        self._lock = threading.RLock()
        self._spec, self.coordinator, self.endpoint = spec, coordinator, endpoint
        self.guardian_epoch = guardian_epoch
        self._resolve_cmd = resolve_system_cmd if cmd_resolver is None else cmd_resolver
        self._cmd_path = self._resolve_cmd(cmd_path)
        build_cmd_command_line(spec.command, cmd_path=self._cmd_path)
        self._readiness = _UnavailableReadiness() if readiness is None else readiness
        self._open_job = NativeJob.open if job_factory is None else job_factory
        self._launch = native_launcher.launch_in_job if launch is None else launch
        factory = ManagedAdmission.current if admission_factory is None else admission_factory
        self.admission = factory(command=spec.command, cwd=spec.cwd,
            repo_identifier=spec.repo_identifier, requested=spec.requested,
            role=spec.role, priority=spec.priority)
        self.job = self.process = None
        self._submitted = self._sealed = self._create_attempted = self._bound = False
        self._closed = self._closing = self._admission_closed = False
        self._admission_close_unknown = False
        self._admitted = self._prepared = self._claim = self._bound_result = None
        self._root = self._root_locator = self._exit_code = self._native_failure = None
        self.phase = "NEW"
        self._request_ids = {name: str(uuid4()) for name in ("prepare", "claim", "bind")}
        try:
            self._snapshot = self.admission.snapshot()
            if (self._snapshot.requested != spec.requested or self._snapshot.role is not spec.role or
                    self._snapshot.priority is not spec.priority or
                    self._snapshot.logon_id != endpoint.logon_id or
                    self._snapshot.wrapper_identity == endpoint.server_identity):
                raise ManagedLaunchError("launcher_admission_binding_mismatch")
            self.admission.verify_launch_payload(command=spec.command, cwd=spec.cwd)
            if client_factory is None:
                from .launch_transport import ManagedLaunchClient
                client_factory = ManagedLaunchClient
            self.client = client_factory(self.admission, endpoint, guardian_epoch=guardian_epoch)
        except BaseException as primary:
            try:
                self.admission.close()
            except BaseException as cleanup:
                self._admission_close_unknown = True
                primary.add_note("launcher_admission_cleanup_unverified")
                primary.launcher_cleanup_error = cleanup
                _remember(primary, self)
            raise

    @property
    def execution_id(self):
        return self._snapshot.execution_id

    @property
    def admission_timeout_sec(self):
        return self._spec.admission_timeout_sec

    def _assert_context(self, *, submitted=True):
        if self._closed or self._closing:
            raise ManagedLaunchError("launcher_closed_or_closing")
        snapshot = (self.admission.snapshot_for_ledger(self.coordinator.db_path)
                    if submitted else self.admission.snapshot())
        if snapshot != self._snapshot:
            raise ManagedLaunchError("launcher_admission_changed")
        return snapshot

    def admit_once(self, status, *, config=None):
        """Retry only this exact capacity request; no wait loop or queue removal."""
        with self._lock:
            # Coordinator owns first-submission/pinned-ledger reconciliation.
            # A prior call may have failed before it could pin the context.
            self._assert_context(submitted=False)
            if self._sealed:
                raise ManagedLaunchError("launcher_attempt_sealed")
            if self._admitted is not None:
                return dict(self._admitted)
            self._submitted = True
            self.phase = "ADMITTING"
            try:
                result = self.coordinator.admit_managed(self.admission, status, config=config)
                if (type(result) is not dict or type(result.get("allowed")) is not bool or
                        result.get("request_key") != self._snapshot.request.request_key):
                    raise ManagedLaunchError("launcher_admission_response_invalid")
                if result["allowed"]:
                    if (result.get("execution_id") != self.execution_id or result.get("state") != "RESERVED" or
                            type(result.get("state_revision")) is not int or result["state_revision"] < 0 or
                            type(result.get("reservation_id")) is not str or not result["reservation_id"] or
                            result.get("launch_authorized") is not False):
                        raise ManagedLaunchError("launcher_admission_response_invalid")
                    self._admitted = dict(result)
                    self.phase = "RESERVED"
                else:
                    # Some refusals occur before queue insertion (for example
                    # an incompatible policy); denial alone is not queue proof.
                    position = result.get("position")
                    self.phase = "QUEUED" if type(position) is int and position > 0 else "ADMISSION_DENIED"
                return dict(result)
            except BaseException as error:
                self.phase = "ADMISSION_UNKNOWN"
                _remember(error, self)
                raise

    def _ready(self, row):
        self._assert_context()
        if self._readiness.assert_launch_ready(self.admission, dict(row), self.endpoint) is not None:
            raise ManagedLaunchError("native_launch_readiness_unverified")

    def _result(self, result, *, states, minimum_revision, scope=None):
        from .launch_transport import LaunchResult
        if type(result) is not LaunchResult:
            raise ManagedLaunchError("launcher_response_invalid")
        # Revalidate even an in-memory object; frozen Python objects are not a
        # boundary against trusted code accidentally constructing invalid data.
        result.__post_init__()
        if (result.execution_id != self.execution_id or result.spec_hash != self._snapshot.spec_hash or
                result.guardian_epoch != self.guardian_epoch or result.state not in states or
                result.state_revision < minimum_revision or
                result.job_name != f"Local\\ResourceSentinel.Job.{self.execution_id}.{result.job_nonce}"):
            raise ManagedLaunchError("launcher_response_binding_mismatch")
        if scope is not None and (result.job_name, result.job_nonce) != (scope.job_name, scope.job_nonce):
            raise ManagedLaunchError("launcher_response_scope_changed")
        return result

    def launch_once(self, *, stdin_handle, stdout_handle, stderr_handle, timeout_ms=1000):
        """Prepare, consume one claim, Create once and bind the retained root.

        A lost Prepare/Claim/Bind ACK seals this attempt. Reconciliation belongs
        to the guardian; callers must not substitute a fresh launcher/request.
        """
        with self._lock:
            self._assert_context()
            if self._admitted is None:
                raise ManagedLaunchError("launcher_not_admitted")
            if self._sealed:
                raise ManagedLaunchError("launcher_attempt_sealed")
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
                raise ManagedLaunchError("launcher_deadline_invalid")
            if any(type(handle) is not int or not 0 < handle < 1 << (C.sizeof(C.c_void_p) * 8 - 1)
                   for handle in (stdin_handle, stdout_handle, stderr_handle)):
                raise ManagedLaunchError("launcher_stdio_handle_invalid")
            self.admission.verify_launch_payload(command=self._spec.command, cwd=self._spec.cwd)
            self._ready(self._admitted)
            # No mutation has happened on a failed initial readiness check.
            # Seal before the first RPC, not after receiving its acknowledgement.
            self._sealed = True
            self.phase = "PREPARING"
            try:
                prepared = self.client.prepare_execution(expected_revision=self._admitted["state_revision"],
                    request_id=self._request_ids["prepare"], timeout_ms=timeout_ms)
                self._prepared = self._result(prepared, states={"PREPARED"},
                    minimum_revision=self._admitted["state_revision"] + 1)
                if prepared.launch_authorized:
                    raise ManagedLaunchError("launcher_prepare_authorized_launch")
                self.phase = "PREPARED"
                self.job = self._open_job(prepared.job_name, prepared.job_nonce,
                    self._snapshot.logon_id, access=JobAccess.LAUNCH)
                if (self.job.name != prepared.job_name or self.job.nonce != prepared.job_nonce or
                        self.job.logon_sid != self._snapshot.logon_id or self.job.access is not JobAccess.LAUNCH or
                        self.job.query_cpu().flags != 0 or self.job.query_limits() != JobLimits(0, 0)):
                    raise ManagedLaunchError("launcher_job_binding_unverified")
                self._ready(prepared.to_dict())
                self.phase = "CLAIMING"
                claimed = self.client.claim_launch(expected_revision=prepared.state_revision,
                    job_nonce=prepared.job_nonce, request_id=self._request_ids["claim"], timeout_ms=timeout_ms)
                self._claim = self._result(claimed, states={"LAUNCHING"},
                    minimum_revision=prepared.state_revision + 1, scope=prepared)
                if claimed.launch_authorized is not True or claimed.duplicate is not False:
                    raise ManagedLaunchError("launcher_claim_not_authorized")
                self.phase = "CLAIMED"
                # Re-resolve trusted cmd immediately before use; never trust
                # COMSPEC, PATH, a prepared reply or a workload-provided binary.
                if self._resolve_cmd(self._cmd_path) != self._cmd_path:
                    raise ManagedLaunchError("system_cmd_changed")
                self.admission.verify_launch_payload(command=self._spec.command, cwd=self._spec.cwd)
                command_line = build_cmd_command_line(self._spec.command, cmd_path=self._cmd_path)
                self._ready(claimed.to_dict())
                self._create_attempted = True
                self.phase = "CREATING"
                try:
                    self.process = self._launch(self.job, self._cmd_path, command_line,
                        cwd=self._spec.cwd, stdin_handle=stdin_handle,
                        stdout_handle=stdout_handle, stderr_handle=stderr_handle)
                except native_launcher.LaunchOutcomeUnknown as error:
                    self.process = error.process
                    raise
                root = self.process.full_identity(expected_logon_id=self._snapshot.logon_id)
                if (type(root) is not ProcessIdentity or root.pid != self.process.pid or
                        root.logon_id != self._snapshot.logon_id or
                        root in (self._snapshot.wrapper_identity, self.endpoint.server_identity) or
                        self.process.is_in_job(self.job) is not True):
                    raise ManagedLaunchError("launcher_root_binding_unverified")
                self._root = root
                self._root_locator = self.process.handle
                self.phase = "BINDING"
                self._bind_verified_root(timeout_ms)
                return self.process
            except BaseException as error:
                self.phase = "UNCERTAIN"
                self._native_failure = error
                _remember(error, self)
                raise

    def _bind_verified_root(self, timeout_ms):
        bound = self.client.bind_root(expected_revision=self._claim.state_revision,
            job_nonce=self._prepared.job_nonce, root_identity=self._root,
            root_handle_locator=self._root_locator,
            request_id=self._request_ids["bind"], timeout_ms=timeout_ms)
        self._bound_result = self._result(bound, states={"RUNNING", "DRAINING", "FINISHED"},
            minimum_revision=self._claim.state_revision + 1, scope=self._prepared)
        if bound.launch_authorized:
            raise ManagedLaunchError("launcher_bind_authorized_launch")
        self._bound = True
        self.phase = "BOUND"
        return self._bound_result

    def reconcile_bind(self, *, timeout_ms=1000):
        """Explicit exact Bind replay only; never another preparation or launch.

        A native unknown result or missing verified root cannot use this path.
        The original native handle, identity, claim revision and request ID must
        all survive. No dead PID is reopened and no new authority is created.
        """
        with self._lock:
            self._assert_context()
            if (not self._sealed or not self._create_attempted or self._root is None or
                    self._root_locator is None or self.process is None or self.job is None or
                    self._prepared is None or self._claim is None):
                raise ManagedLaunchError("launcher_bind_reconciliation_unavailable")
            if self._bound:
                return self._bound_result
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
                raise ManagedLaunchError("launcher_deadline_invalid")
            try:
                if (self.process.handle != self._root_locator or
                        self.process.full_identity(expected_logon_id=self._snapshot.logon_id) != self._root or
                        self.job.name != self._prepared.job_name or self.job.nonce != self._prepared.job_nonce or
                        self.job.logon_sid != self._snapshot.logon_id or
                        self.process.is_in_job(self.job) is not True):
                    raise ManagedLaunchError("launcher_retained_root_changed")
                self.phase = "BINDING"
                return self._bind_verified_root(timeout_ms)
            except BaseException as error:
                self.phase = "UNCERTAIN"
                self._native_failure = error
                _remember(error, self)
                raise

    def poll_root(self) -> RootObservation:
        """Read the exact retained process only; no heartbeat/release or PID reopen."""
        with self._lock:
            if self._closed or self._closing or self.process is None:
                raise ManagedLaunchError("launcher_root_unavailable")
            try:
                exited = self.process.wait(0)
                if type(exited) is not bool:
                    raise ManagedLaunchError("launcher_root_exit_unverified")
                code = self.process.exit_code() if exited else None
                if exited and (type(code) is not int or not 0 <= code <= 0xFFFFFFFF):
                    raise ManagedLaunchError("launcher_root_exit_unverified")
                if self._exit_code is not None and (not exited or code != self._exit_code):
                    raise ManagedLaunchError("launcher_root_exit_changed")
                if exited:
                    self._exit_code = code
                return RootObservation(self.execution_id, exited, code, self._bound)
            except BaseException as error:
                _remember(error, self)
                raise

    def close_local(self) -> None:
        """Close wrapper handles only after acknowledged transfer and root exit.

        Never cancel/release an allocation. An unsubmitted launcher may close
        without starting anything. Submitted/unbound or still-running work stays
        retained for explicit guardian reconciliation. Admission.close's existing
        partial-failure contract is non-retryable, so such failure is quarantined.
        """
        with self._lock:
            if self._closed:
                return
            if not self._closing:
                if self._submitted:
                    if not self._bound or not self.poll_root().exited:
                        raise ManagedLaunchError("launcher_custody_unsettled")
                self._closing = True
            primary = None
            for owner in (self.process, self.job):
                if owner is not None:
                    try:
                        owner.close()
                    except BaseException as error:
                        if primary is None:
                            primary = error
                        else:
                            primary.add_note("launcher_additional_cleanup_unverified")
            if not self._admission_closed:
                try:
                    if self._admission_close_unknown:
                        raise ManagedLaunchError("launcher_admission_cleanup_unknown")
                    self._admission_close_unknown = True
                    self.admission.close()
                    self._admission_closed = True
                    self._admission_close_unknown = False
                except BaseException as error:
                    if primary is None:
                        primary = error
                    else:
                        primary.add_note("launcher_admission_cleanup_unverified")
            if primary is not None:
                _remember(primary, self)
                raise primary
            self._closed = True
            self.phase = "CLOSED"
