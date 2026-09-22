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
from .guardian_lifecycle import job_mutex_instance
from .store import LifecycleStore
from .windows import NativePolicyMutex, NativePolicyMutexError, retained_owners, unresolved_construction
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
    # Keep prior failures too: a later ACK/retry must not drop the sole owner
    # attached to an earlier native/transport cleanup failure.
    if hasattr(owner, "_operation_errors"):
        transport = getattr(error, "_transport_cleanup_error", None)
        has_cleanup = bool(getattr(error, "__notes__", ()) or retained_owners(error) or
            getattr(error, "_native_job_cleanup", ()) or getattr(error, "cleanup_owner", None) or
            (transport is not None and (getattr(transport, "__notes__", ()) or retained_owners(transport) or
                                       getattr(transport, "io_pending", False))) or
            isinstance(error, native_launcher.LaunchOutcomeUnknown))
        duplicate_reason = any(type(item) is type(error) and getattr(item, "reason", None) ==
                               getattr(error, "reason", None) for item in owner._operation_errors)
        if (not any(item is error for item in owner._operation_errors) and
                (has_cleanup or (not duplicate_reason and len(owner._operation_errors) < 32))):
            owner._operation_errors.append(error)


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
                 admission_factory=None, job_factory=None, launch=None, cmd_resolver=None,
                 mutex_factory=None):
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
        self._make_mutex = NativePolicyMutex if mutex_factory is None else mutex_factory
        factory = ManagedAdmission.current if admission_factory is None else admission_factory
        self.admission = factory(command=spec.command, cwd=spec.cwd,
            repo_identifier=spec.repo_identifier, requested=spec.requested,
            role=spec.role, priority=spec.priority)
        self.job = self.process = None
        self._launch_mutex = self._store = None
        self._extra_cleanup_owners = []
        # Keep the object alongside its state, so identity cannot be recycled.
        self._cleanup_records = {}
        self._mutex_construction_unknown = False
        self._submitted = self._sealed = self._create_attempted = self._bound = False
        self._prepare_attempted = self._claim_attempted = False
        self._abandoning = False
        self._abandon_result = self._abandon_cancel_target = None
        self._operation_errors = []
        self._transport_cleanup_unknown = False
        self._closed = self._closing = self._admission_closed = False
        self._admission_close_unknown = False
        self._admitted = self._prepared = self._claim = self._bound_result = None
        self._root = self._root_locator = self._exit_code = self._native_failure = None
        self._failed_native_owner = None
        self._retirement_requests = {}
        self._retired_result = None
        self.phase = "NEW"
        self._request_ids = {name: str(uuid4()) for name in ("prepare", "claim", "bind", "cancel", "start_failed")}
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

    def _ledger(self):
        # Opening/migrating the existing ledger happens outside the Job mutex.
        # All work inside that mutex is read-only until the single native create.
        if self._store is None:
            self._store = LifecycleStore(self.coordinator.db_path, existing_path=True)
        return self._store

    def _scope_row(self, store):
        row = store.query(self.execution_id, existing_path=True)
        expected = {
            "execution_id": self.execution_id, "spec_hash": self._snapshot.spec_hash,
            "logon_id": self._snapshot.logon_id,
            "wrapper_pid": self._snapshot.wrapper_identity.pid,
            "wrapper_created_filetime_100ns": str(self._snapshot.wrapper_identity.created_filetime_100ns),
            "guardian_epoch": self.guardian_epoch,
            "reservation_id": self._admitted["reservation_id"],
            "allocation_kind": "direct", "parent_execution_id": None,
        }
        if any(row.get(key) != value for key, value in expected.items()):
            raise ManagedLaunchError("launcher_ledger_binding_mismatch")
        if self._prepared is not None and (row.get("job_name"), row.get("job_nonce")) != (
                self._prepared.job_name, self._prepared.job_nonce):
            raise ManagedLaunchError("launcher_ledger_scope_changed")
        return row

    def _create_fenced(self, command_line, *, timeout_ms, stdin_handle, stdout_handle, stderr_handle):
        store = self._ledger()
        try:
            self._launch_mutex = self._make_mutex(self._snapshot.logon_id,
                job_mutex_instance(self.execution_id, self._prepared.job_nonce))
        except BaseException as error:
            owners = retained_owners(error)
            self._extra_cleanup_owners.extend(owners)
            for owner in owners:
                # These owners were already involved in failed construction
                # cleanup. A retained locator alone cannot authorize another
                # CloseHandle: its previous close might have taken effect.
                self._track_cleanup(owner, guarded=True,
                    unknown=not self._known_mutex_close_failure(error))
            self._mutex_construction_unknown = unresolved_construction(error) and not owners
            raise
        with self._launch_mutex.acquire(timeout_ms=timeout_ms) as lease:
            if lease.abandoned is not False:
                raise ManagedLaunchError("launcher_launch_fence_abandoned")
            row = self._scope_row(store)
            expected = {"state": "LAUNCHING", "state_revision": self._claim.state_revision,
                        "claim_consumed": 1, "launch_in_flight": 1, "launch_sealed": 0,
                        "cancel_requested_at": None, "root_pid": None,
                        "root_created_filetime_100ns": None, "root_outcome": None,
                        "hold_reason": None, "finished_at": None}
            if any(key not in row or row[key] != value for key, value in expected.items()):
                raise ManagedLaunchError("launcher_launch_fence_state_changed")
            store.assert_admission_covered(self.admission, row)
            store.assert_launch_fence(row, version=1)
            self._create_attempted = True
            self.phase = "CREATING"
            try:
                self.process = self._launch(self.job, self._cmd_path, command_line,
                    cwd=self._spec.cwd, stdin_handle=stdin_handle,
                    stdout_handle=stdout_handle, stderr_handle=stderr_handle)
            except native_launcher.LaunchOutcomeUnknown as error:
                self.process = error.process
                raise
            except BaseException as error:
                # Known failed creation can still own stdio/attribute cleanup.
                # Positive guardian retirement does not close those resources.
                native_owner = getattr(error, "native_launch_owner", None)
                if isinstance(native_owner, native_launcher.CreatedProcess):
                    self._failed_native_owner = native_owner
                    self._extra_cleanup_owners.append(native_owner)
                    self._track_cleanup(native_owner, guarded=False)
                owner = getattr(error, "cleanup_owner", None)
                if owner is not None:
                    self._extra_cleanup_owners.append(owner)
                    protected = isinstance(owner, native_launcher.CreatedProcess)
                    self._track_cleanup(owner, guarded=not protected, unknown=not protected)
                raise

    @staticmethod
    def _known_mutex_close_failure(error):
        return (isinstance(error, NativePolicyMutexError) and
                error.reason == "policy_mutex_handle_close_failed" and
                not getattr(error, "__notes__", ()) and
                not getattr(error, "_native_close_outcome_unknown", False))

    def _track_cleanup(self, owner, *, guarded, unknown=False):
        key = id(owner)
        record = self._cleanup_records.get(key)
        if record is None:
            record = self._cleanup_records[key] = dict(owner=owner, guarded=guarded,
                state="unknown" if unknown else "pending")
        elif unknown and record["state"] != "closed":
            record["state"] = "unknown"
        return record

    def _close_owned(self, owner, *, guarded):
        record = self._track_cleanup(owner, guarded=guarded)
        if record["state"] == "closed":
            return
        if record["state"] == "unknown":
            raise ManagedLaunchError("launcher_native_cleanup_outcome_unknown")
        # NativeJob/CreatedProcess quarantine each of their raw resources
        # internally. NativePolicyMutex and opaque construction owners do not.
        # Guard those before entering close, including BaseException paths.
        if record["guarded"]:
            record["state"] = "unknown"
        try:
            owner.close()
        except BaseException as error:
            if record["guarded"] and self._known_mutex_close_failure(error):
                record["state"] = "pending"
            raise
        # Tombstone success before any subsequent operation can fail. Never
        # reacquire this object, and never close it twice after another error.
        record["state"] = "closed"

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
                prepared = self._prepare_original(timeout_ms)
                self.phase = "PREPARED"
                try:
                    self.job = self._open_job(prepared.job_name, prepared.job_nonce,
                        self._snapshot.logon_id, access=JobAccess.LAUNCH)
                except BaseException as error:
                    for owner in getattr(error, "_native_job_cleanup", ()):
                        self._extra_cleanup_owners.append(owner)
                        self._track_cleanup(owner, guarded=not isinstance(owner, NativeJob),
                                            unknown=not isinstance(owner, NativeJob))
                    raise
                if (self.job.name != prepared.job_name or self.job.nonce != prepared.job_nonce or
                        self.job.logon_sid != self._snapshot.logon_id or self.job.access is not JobAccess.LAUNCH or
                        self.job.query_cpu().flags != 0 or self.job.query_limits() != JobLimits(0, 0)):
                    raise ManagedLaunchError("launcher_job_binding_unverified")
                self._ready(prepared.to_dict())
                self.phase = "CLAIMING"
                claimed = self._claim_original(timeout_ms)
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
                self._create_fenced(command_line, timeout_ms=timeout_ms,
                    stdin_handle=stdin_handle, stdout_handle=stdout_handle, stderr_handle=stderr_handle)
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

    def _prepare_original(self, timeout_ms):
        # Publish both boundaries before RPC. A RESERVED row cannot disprove
        # an in-flight Prepare; only this original request may reconcile it.
        self._prepare_attempted = True
        self.admission.mark_prepare_attempted()
        prepared = self._rpc(self.client.prepare_execution,
            expected_revision=self._admitted["state_revision"],
            request_id=self._request_ids["prepare"], timeout_ms=timeout_ms)
        prepared = self._result(prepared, states={"PREPARED"},
            minimum_revision=self._admitted["state_revision"] + 1)
        if prepared.launch_authorized:
            raise ManagedLaunchError("launcher_prepare_authorized_launch")
        self._prepared = prepared
        return prepared

    def _claim_original(self, timeout_ms):
        self._claim_attempted = True
        prepared = self._prepared
        claimed = self._rpc(self.client.claim_launch, expected_revision=prepared.state_revision,
            job_nonce=prepared.job_nonce, request_id=self._request_ids["claim"],
            launch_fence_version=1, timeout_ms=timeout_ms)
        claimed = self._result(claimed, states={"LAUNCHING"},
            minimum_revision=prepared.state_revision + 1, scope=prepared)
        if not (claimed.launch_authorized or claimed.duplicate):
            raise ManagedLaunchError("launcher_claim_not_authorized")
        self._claim = claimed
        return claimed

    def _rpc(self, method, **arguments):
        try:
            return method(**arguments)
        except BaseException as error:
            _remember(error, self)
            original = getattr(error, "_transport_cleanup_error", error)
            if original is None:
                original = error
            # The pipe registry and the original exception retain native
            # resources, but no contract transfers that cleanup to a guardian.
            # Replaying an authenticated RPC cannot settle an uncertain close.
            if (getattr(original, "__notes__", ()) or retained_owners(original) or
                    getattr(original, "io_pending", False) or
                    getattr(original, "_native_close_outcome_unknown", False)):
                self._transport_cleanup_unknown = True
            raise

    def _abandon_admission(self):
        """Cancel through the original context, never recreate its authority."""
        if self._abandon_result is not None:
            return
        if self._admitted is None:
            observation = self.coordinator.reconcile_managed(self.admission)
            if (type(observation) is not dict or observation.get("execution_id") != self.execution_id or
                    observation.get("request_key") != self._snapshot.request.request_key or
                    observation.get("launch_authorized") is not False):
                raise ManagedLaunchError("launcher_admission_reconciliation_invalid")
            if observation.get("state") == "RESERVED":
                if (type(observation.get("reservation_id")) is not str or not observation["reservation_id"] or
                        type(observation.get("state_revision")) is not int or observation["state_revision"] < 0):
                    raise ManagedLaunchError("launcher_admission_reconciliation_invalid")
                self._admitted = dict(observation)
        if self._admitted is not None and self._abandon_cancel_target is None:
            self._abandon_cancel_target = dict(reservation_id=self._admitted["reservation_id"],
                                              expected_revision=self._admitted["state_revision"])
        reply = self.coordinator.cancel_managed(self.admission, **(self._abandon_cancel_target or {}))
        if (type(reply) is not dict or reply.get("cancelled") is not True or
                reply.get("execution_id") != self.execution_id or
                reply.get("request_key") != self._snapshot.request.request_key or
                reply.get("state") not in {"QUEUED_CANCELLED", "NOT_SUBMITTED", "SUBMISSION_REJECTED",
                                           "CANCELLED_BEFORE_START"}):
            raise ManagedLaunchError("launcher_admission_cancellation_invalid")
        if self._abandon_cancel_target is not None:
            if (reply["state"] != "CANCELLED_BEFORE_START" or
                    reply.get("reservation_id") != self._abandon_cancel_target["reservation_id"] or
                    type(reply.get("state_revision")) is not int or
                    reply["state_revision"] <= self._abandon_cancel_target["expected_revision"]):
                raise ManagedLaunchError("launcher_admission_cancellation_invalid")
        elif reply["state"] == "CANCELLED_BEFORE_START":
            # A surprise allocation must be pinned on a subsequent read, never
            # accepted merely because a collaborator returned a boolean.
            raise ManagedLaunchError("launcher_admission_cancellation_unbound")
        self._abandon_result = dict(reply)

    def abandon_once(self, *, timeout_ms=1000):
        """One bounded original-owner settlement step; never rerun a command.

        Pending is not permission for the owning process to exit. The host must
        retain this launcher and retry eligible reconciliation/cleanup until a
        positive terminal result, or an existing acknowledged custody handoff.
        """
        with self._lock:
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
                raise ManagedLaunchError("launcher_deadline_invalid")
            self._abandoning = self._sealed = True
            record = dict(execution_id=self.execution_id, settled=False, closed=False,
                          guardian_handoff=False, state=self.phase, reason="launcher_abandon_pending")
            try:
                if self._transport_cleanup_unknown:
                    raise ManagedLaunchError("launcher_transport_cleanup_unknown")
                if not self._closed and not self._closing:
                    if not self._submitted:
                        pass
                    elif self._retired_result is not None or self._abandon_result is not None:
                        pass
                    elif not self._prepare_attempted:
                        self._abandon_admission()
                    elif (self._create_attempted and self.process is None and self._root is None and
                          self._failed_native_owner is not None and
                          self._failed_native_owner.creation_definitely_absent):
                        # The original native owner positively observed no
                        # creation. The guardian still must prove lifetime
                        # zero and atomically retire the claimed Job scope.
                        self.retire_before_start(kind="start_failed", timeout_ms=timeout_ms)
                    elif self._create_attempted or self.process is not None or self._root is not None:
                        # An uncertain Create never turns into StartFailed from
                        # a timeout or an empty observation. Bind replay needs
                        # the original positively verified root/handle.
                        if not self._bound:
                            self.reconcile_bind(timeout_ms=timeout_ms)
                        if not self.poll_root().exited:
                            record.update(state="ROOT_RUNNING", reason="launcher_root_still_running")
                            return record
                    else:
                        if self._prepared is None:
                            self._prepare_original(timeout_ms)
                        if self._claim_attempted and self._claim is None:
                            self._claim_original(timeout_ms)
                        # Do not advance an unclaimed request just to cancel.
                        # After a claim, guardian native lifetime-zero proof
                        # (not this local flag) must authorize StartFailed.
                        kind = "start_failed" if self._claim_attempted else "cancel"
                        self.retire_before_start(kind=kind, timeout_ms=timeout_ms)
                self.close_local()
                record.update(settled=True, closed=True, state="CLOSED", reason="launcher_abandon_settled")
            except BaseException as error:
                _remember(error, self)
                reason = getattr(error, "reason", None)
                if type(reason) is not str or not reason.replace("_", "").isalnum():
                    reason = "launcher_abandon_interrupted" if isinstance(error, KeyboardInterrupt) else "launcher_abandon_unverified"
                record.update(state=self.phase, reason=reason)
            return record

    def retire_before_start(self, *, kind="cancel", timeout_ms=1000):
        """Explicit authenticated abandonment of this exact named scope only.

        A request never supplies native-failure facts. The original guardian
        must prove never-created/never-associated and commit its sealed receipt.
        Cancel after claim is only pending reconciliation. A lost ACK keeps the
        same revision and request ID for explicit replay; it never creates again.
        """
        with self._lock:
            self._assert_context()
            if kind not in {"cancel", "start_failed"}:
                raise ManagedLaunchError("launcher_retirement_kind_invalid")
            if type(timeout_ms) is not int or not 1 <= timeout_ms <= 1000:
                raise ManagedLaunchError("launcher_deadline_invalid")
            if self._admitted is None:
                raise ManagedLaunchError("launcher_not_admitted")
            if kind == "start_failed" and (self.process is not None or self._root is not None or
                    isinstance(self._native_failure, native_launcher.LaunchOutcomeUnknown)):
                raise ManagedLaunchError("launcher_retirement_native_outcome_retained")
            if self._retired_result is not None:
                return self._retired_result
            # Irrevocable local fence precedes even a failed query or RPC.
            self._sealed = True
            self.phase = "RETIRING"
            try:
                request = self._retirement_requests.get(kind)
                if request is None:
                    store = self._ledger()
                    row = self._scope_row(store)
                    from .launch_transport import LaunchResult
                    scope = LaunchResult(self.execution_id, self._snapshot.spec_hash,
                        self.guardian_epoch, row["state"], row["state_revision"],
                        row["job_name"], row["job_nonce"], False, False)
                    store.assert_admission_covered(self.admission, row)
                    request = (scope, dict(expected_revision=scope.state_revision,
                        job_nonce=scope.job_nonce, request_id=self._request_ids[kind]))
                    self._retirement_requests[kind] = request
                scope, arguments = request
                method = self.client.cancel_before_start if kind == "cancel" else self.client.start_failed
                reply = self._rpc(method, **arguments, timeout_ms=timeout_ms)
                states = ({"CANCELLED_BEFORE_START", "LAUNCHING", "RUNNING", "DRAINING",
                           "START_UNKNOWN", "UNCERTAIN_HOLD", "FINISHED"} if kind == "cancel" else {"START_FAILED"})
                reply = self._result(reply, states=states,
                    minimum_revision=scope.state_revision, scope=scope)
                if reply.launch_authorized:
                    raise ManagedLaunchError("launcher_retirement_authorized_launch")
                if reply.state in {"CANCELLED_BEFORE_START", "START_FAILED"}:
                    if self.process is not None or self._root is not None:
                        raise ManagedLaunchError("launcher_retirement_native_outcome_retained")
                    self._retired_result = reply
                    self.phase = "RETIRED"
                else:
                    self.phase = "CANCEL_PENDING"
                return reply
            except BaseException as error:
                self.phase = "UNCERTAIN"
                _remember(error, self)
                raise

    def _bind_verified_root(self, timeout_ms):
        bound = self._rpc(self.client.bind_root, expected_revision=self._claim.state_revision,
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
            if self._transport_cleanup_unknown:
                raise ManagedLaunchError("launcher_transport_cleanup_unknown")
            if not self._closing:
                if self._submitted and self._retired_result is None and self._abandon_result is None:
                    if not self._bound or not self.poll_root().exited:
                        raise ManagedLaunchError("launcher_custody_unsettled")
                self._closing = True
            primary = (ManagedLaunchError("launcher_mutex_construction_cleanup_unknown")
                       if self._mutex_construction_unknown else None)
            attempted = set()
            for owner in (self.process, self.job, self._launch_mutex, *self._extra_cleanup_owners):
                if owner is not None and id(owner) not in attempted:
                    attempted.add(id(owner))
                    try:
                        self._close_owned(owner, guarded=owner is self._launch_mutex or
                            (owner is not self.process and owner is not self.job))
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
