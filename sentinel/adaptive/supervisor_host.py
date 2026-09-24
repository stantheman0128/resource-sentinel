"""Supervisor host; launch with the actual Python base executable.

The supervisor mints one guardian epoch, starts one guardian child with plain
process creation, keeps the creation handle, and builds its witness from that
handle. It never reopens a PID, never spoofs a parent, never asks for Job
breakaway, and never starts a workload.

Ordinary creation semantics matter here. A process inside a Job passes that Job
to its children, so a supervisor inside a foreign Job cannot create a guardian
with an independent CPU denominator. The capability preflight refuses that case
before anything is created, which is also what happens on a development machine
whose shell already runs inside a Job.

Observation is restore only. GuardianSupervisor.tick performs restore and
orphan drain internally once it has a verified death. This host adds nothing to
that: it holds on UNKNOWN, and a missing PID, a failed open, an elapsed lease
or an abandoned mutex is never treated as death. A replacement guardian is
started only after supervisor.close() has succeeded, and only under a new
epoch, so the dead epoch's provenance is never reused.

A verified death also releases the dead guardian's row in the infrastructure
registry. A guardian registers itself at startup, that registry is capped, and
no other process holds a death witness for the guardian this host created. The
removal re-verifies death on the retained witness, so this host adds no second
and weaker liveness test of its own. Failed removal blocks replacement and is
retried each tick with the original guard, independently of replacement budget.
A refusal the writer decides before its own transaction releases POLICY again,
so a later guardian start can still register. Only a failure at or after that
transaction keeps the durable entry, because the ledger outcome is unknown
then.

An opt in helper profile adds one shadow helper child to the same design. The
helper child is created the same way as the guardian, and its creation handle is
kept as the only witness of it. A verified death on that witness releases the
helper's row in the infrastructure registry, and a replacement follows when the
removal succeeded and the helper budget allows. A row that could not be removed
refuses the next helper start as occupied, so no replacement is attempted then.
Without a helper profile no helper child is created and no helper key appears in
any record.

An authenticated operator or local interrupt starts irreversible deliberate
drain. Both replacement paths stop, while original-witness recovery, registry
retirement and cleanup continue. A bounded observation or interrupt cannot make
the main program discard the sole original child witnesses. There is no kill
path, cold adoption, or workload cancellation.
"""
from __future__ import annotations

import argparse
import ctypes as C
from dataclasses import replace
import json
from pathlib import Path
import re
import sys
import time
from uuid import uuid4

from .host_authority import HostCapabilityUnsupported, read_host_capability
from .store import LifecycleError


EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_UNSETTLED = 4
_HANDLE = C.c_void_p
_DWORD = C.c_uint32
_BOOL = C.c_int
_REPO_ROOT = Path(__file__).resolve().parents[2]
# A stable code is a lowercase identifier. Anything else is free text.
_STABLE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class SupervisorHostRefused(RuntimeError):
    """Startup, replacement or shutdown refused with a stable reason."""

    def __init__(self, reason, detail=None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


def emit(record, stream=None, *, sink=None):
    if stream is None and sink is not None:
        return sink.offer(record)
    try:
        print(json.dumps(record, sort_keys=True, default=str),
              file=sys.stderr if stream is None else stream, flush=True)
        return True
    except Exception:
        # Losing a diagnostics sink must not unwind the sole native custodian.
        return False


def _reason(error):
    """The stable code an error carries, never free text.

    Errors raised in this package either expose a reason attribute or, for
    LifecycleError, carry the stable code as the message itself. Anything
    else reports only its type, so no path or command text reaches a record.
    """
    value = getattr(error, "reason", None)
    if type(value) is str and value:
        return value
    if isinstance(error, LifecycleError) and _STABLE_CODE.fullmatch(str(error)):
        return str(error)
    return type(error).__name__


def mint_guardian_epoch():
    """One fresh epoch per guardian process, matching the identifier contract."""
    return "guardian-" + uuid4().hex


class _StartupInfoW(C.Structure):
    _fields_ = [("cb", _DWORD), ("lpReserved", C.c_wchar_p), ("lpDesktop", C.c_wchar_p),
                ("lpTitle", C.c_wchar_p), ("dwX", _DWORD), ("dwY", _DWORD),
                ("dwXSize", _DWORD), ("dwYSize", _DWORD), ("dwXCountChars", _DWORD),
                ("dwYCountChars", _DWORD), ("dwFillAttribute", _DWORD), ("dwFlags", _DWORD),
                ("wShowWindow", C.c_uint16), ("cbReserved2", C.c_uint16),
                ("lpReserved2", C.c_void_p), ("hStdInput", _HANDLE),
                ("hStdOutput", _HANDLE), ("hStdError", _HANDLE)]


class _ProcessInformation(C.Structure):
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE),
                ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


def quote_argument(value):
    """Quote one argument for the documented CommandLineToArgvW rules."""
    if value and not any(char in value for char in ' \t\n\v"'):
        return value
    result = ['"']
    backslashes = 0
    for char in value:
        if char == "\\":
            backslashes += 1
            continue
        if char == '"':
            result.append("\\" * (backslashes * 2 + 1))
            result.append('"')
        else:
            result.append("\\" * backslashes)
            result.append(char)
        backslashes = 0
    result.append("\\" * (backslashes * 2))
    result.append('"')
    return "".join(result)


class _Creation:
    """One plain CreateProcessW with no inherited handles and no Job flags."""

    def __init__(self):
        try:
            self.kernel = k = C.WinDLL("kernel32", use_last_error=True)
            k.CreateProcessW.restype = _BOOL
            k.CreateProcessW.argtypes = (C.c_wchar_p, C.c_wchar_p, C.c_void_p, C.c_void_p,
                                         _BOOL, _DWORD, C.c_void_p, C.c_wchar_p,
                                         C.POINTER(_StartupInfoW), C.POINTER(_ProcessInformation))
            k.CloseHandle.restype, k.CloseHandle.argtypes = _BOOL, (_HANDLE,)
        except (AttributeError, OSError):
            raise SupervisorHostRefused("supervisor_host_native_api_unavailable") from None

    def create(self, executable, arguments, cwd):
        command_line = " ".join(quote_argument(item) for item in (executable, *arguments))
        startup = _StartupInfoW()
        startup.cb = C.sizeof(startup)
        info = _ProcessInformation()
        # No creation flag is passed: no breakaway, no new console group, no
        # suspended start. Handle inheritance stays off.
        created = self.kernel.CreateProcessW(executable, C.create_unicode_buffer(command_line),
                                             None, None, False, 0, None, str(cwd),
                                             C.byref(startup), C.byref(info))
        if not created:
            raise SupervisorHostRefused("supervisor_host_create_failed", C.get_last_error())
        return info

    def close_handle(self, handle):
        if handle and not self.kernel.CloseHandle(_HANDLE(handle)):
            raise SupervisorHostRefused("supervisor_host_handle_cleanup_failed", C.get_last_error())


class _Guardian:
    """One started guardian: its creation handle, its witness and its epoch."""

    def __init__(self, *, epoch, pid, creation_handle, process, creation_witness=None, endpoints=None):
        self.epoch = epoch
        self.pid = pid
        self.creation_handle = creation_handle
        self.process = process
        self.creation_witness = creation_witness
        for name, value in (endpoints or {}).items():
            setattr(self, name, value)


class _Helper:
    """One started helper: its creation handle and its witness.

    A helper carries no epoch. Nothing in the helper host takes one, and
    inventing one here would put a provenance claim on a process that never
    received it.
    """

    def __init__(self, *, pid, creation_handle, process, endpoints=None):
        self.pid = pid
        self.creation_handle = creation_handle
        self.process = process
        for name, value in (endpoints or {}).items():
            setattr(self, name, value)


class SupervisorHost:
    """Start one guardian, attach to it, and observe it with bounded ticks."""

    def __init__(self, *, data_dir, journal_dir, child_cwd=None, python_executable=None,
                 profile_path=None, max_guardians=1, guardian_iterations=0,
                 helper_profile_path=None, max_helpers=1,
                 sleep=time.sleep, tick_interval_sec=1.0, telemetry_factory=None):
        self.data_dir = Path(data_dir)
        self.journal_dir = Path(journal_dir)
        self.child_cwd = Path(_REPO_ROOT if child_cwd is None else child_cwd)
        self.python_executable = getattr(sys, "_base_executable", sys.executable) if python_executable is None else python_executable
        self.profile_path = profile_path
        self.max_guardians = max_guardians
        self.guardian_iterations = guardian_iterations
        # Helper supervision is opt in. With no helper profile this host
        # creates no helper child and reports no helper key anywhere.
        self.helper_profile_path = helper_profile_path
        self.max_helpers = max_helpers
        # Loop pacing only. Neither value is a measured reaction time and
        # neither one gates anything.
        self._sleep = sleep
        self.tick_interval_sec = tick_interval_sec
        self.capability = None
        self.store = self.journal = None
        self.creation = None
        self.guardian = None
        self.supervisor = None
        self.started_guardians = 0
        self.retired = []
        self.helper = None
        self.started_helpers = 0
        self.retired_helpers = []
        # Children that were created but whose witness could not be built. The
        # raw creation handle is kept here so the process is never lost.
        self.unverified = []
        # Partial recovery owners from a failed attach that refused to close.
        self.unsettled_captures = []
        self.startup = self.janitor = None
        self.cold_reason = None
        self._registry_retirements = {}
        self._registry_results = {}
        self._guardian_settled = False
        self._rollover = self._replacement_epoch = None
        self._creation_unknown = False
        self._creation_records = []
        self._capture_errors = []
        self._operator_cleanup_errors = []
        self._initial_start_operation = self._initial_start_result = None
        self._empty_check = self._empty_result = None
        self._empty_proof = False
        self._closed_handles = set()
        self._unknown_handles = set()
        self._closed = False
        self.draining = False
        self.operations = self.operator_service = self.operator_listener = None
        self.discovery = self.descriptor = self.guardian_descriptor = None
        self._operational_current = self._operational_error = None
        self._initial_epoch = None
        self._instance_id, self._operator_instance_id = str(uuid4()), str(uuid4())
        self.telemetry = None
        self._telemetry_factory = telemetry_factory
        self._guardian_endpoints = {}
        self._helper_endpoints = None
        self._helper_epoch_drain = None
        self._helper_restart_pending = False
        self._local_drain_request = None
        self._drain_closed_children = set()
        self._last_barrier = None
        self._descriptor_removed = self._operator_closed = self._discovery_closed = False

    def emit(self, record, stream=None):
        if stream is not None:
            return emit(record, stream=stream)
        from .telemetry import emit_resident
        return emit_resident(self, record)

    def _start_telemetry(self):
        current = getattr(self.startup, "_current", None)
        if (current is None or getattr(self.startup, "_acquire_stage", None)
                not in {"binding", "mutex", "held"}):
            # Portable startup-order fixtures own no native self handle.
            return
        from .telemetry import start_resident_telemetry
        start_resident_telemetry(self, role="supervisor", identity=current.identity,
            instance_id=self._instance_id, data_dir=self.data_dir,
            excluded_paths=(self.journal_dir,))

    def _finish_telemetry(self, record):
        if self.telemetry is None:
            return record
        from .telemetry import stop_resident_telemetry
        return {**record, "telemetry": stop_resident_telemetry(self, record)}

    # --- startup ----------------------------------------------------------

    def start(self):
        from .recovery_journal import RecoveryJournal
        from .store import LifecycleStore
        from .supervisor_reconcile import FinishedBarrierJanitor
        from .supervisor_startup import SupervisorStartup

        daily_successor = getattr(self, "_daily_successor_operation", None)
        if daily_successor is not None:
            from .daily_successor import DailySuccessorOperation
            if type(daily_successor) is not DailySuccessorOperation:
                raise SupervisorHostRefused("daily_successor_original_operation_required")
            daily_successor.bind_supervisor(self)

        try:
            self.capability = read_host_capability()
        except HostCapabilityUnsupported as error:
            raise SupervisorHostRefused(error.reason, error.win32_error) from None
        try:
            self.store = (LifecycleStore(self.data_dir / "sentinel.db", existing_path=True)
                if daily_successor is None else daily_successor.store)
        except Exception as error:
            raise SupervisorHostRefused("supervisor_host_ledger_unavailable", _reason(error)) from None
        try:
            self.journal = RecoveryJournal(self.journal_dir) if daily_successor is None else daily_successor.retirement.journal
        except Exception as error:
            raise SupervisorHostRefused("supervisor_host_journal_unavailable", _reason(error)) from None
        # Keep the owner reachable even if acquiring its native lifetime fence
        # fails. A new process never substitutes PID absence for old custody.
        self.startup = SupervisorStartup(self.store, self.journal)
        if daily_successor is not None:
            self.startup._daily_successor_operation = daily_successor
            self.startup._daily_successor_supervisor = self
        try:
            self.startup.acquire()
        except Exception as error:
            if getattr(self.startup, "policy_pending", False) is True:
                self._start_telemetry()
                self.cold_reason = _reason(error)
                return {"event": "supervisor_host_started", "state": "COLD_RECOVERY_HOLD",
                        "reason": self.cold_reason, "attached": False,
                        "guardian_created": False, "barrier": None}
            raise SupervisorHostRefused("supervisor_host_startup_unverified", _reason(error)) from None
        self.janitor = FinishedBarrierJanitor(self.store, self.journal)
        barrier = self._reconcile_barrier()
        return self._finish_startup(barrier)

    def _finish_startup(self, barrier):
        try:
            if self._initial_start_operation is None:
                self.startup.assert_fresh()
            daily_successor = getattr(self, "_daily_successor_operation", None)
            if daily_successor is not None:
                from .daily_successor_epoch import SuccessorGuardianEpoch
                epoch = daily_successor._guardian_epoch_operation
                if self._initial_start_operation is None:
                    if epoch is None:
                        epoch = SuccessorGuardianEpoch(daily_successor, self)
                    result = epoch.tick()
                    if not result.complete:
                        raise SupervisorHostRefused(result.reason or "daily_successor_epoch_pending")
                    epoch.assert_complete()
                else:
                    if type(epoch) is not SuccessorGuardianEpoch:
                        raise SupervisorHostRefused("daily_successor_original_epoch_required")
                    # The original child may already have registered (+1
                    # revision). Resume its retained creation/cleanup owner;
                    # re-publication is neither necessary nor permitted.
                    epoch.assert_retained_publication()
                if self._initial_epoch is not None and self._initial_epoch != epoch.new_epoch:
                    raise SupervisorHostRefused("daily_successor_epoch_changed")
                self._initial_epoch = epoch.new_epoch
            if self.creation is None:
                self.creation = _Creation()
            if self.draining and self.guardian is None:
                raise SupervisorHostRefused("supervisor_host_draining")
            if self._initial_epoch is None:
                self._initial_epoch = mint_guardian_epoch()
            self._ensure_operations(self._initial_epoch)
            self.guardian = self._start_initial_guardian()
        except Exception as error:
            self.cold_reason = _reason(error)
            self._start_telemetry()
            return {"event": "supervisor_host_started", "state": "COLD_RECOVERY_HOLD",
                    "reason": self.cold_reason, "attached": False,
                    "guardian_created": self.guardian is not None or bool(self.unverified) or self._creation_unknown,
                    "barrier": barrier}
        self.cold_reason = None
        record = {"event": "supervisor_host_started", "guardian_epoch": self.guardian.epoch,
                  "guardian_pid": self.guardian.pid, "pid": self.capability.pid,
                  "capability": self.capability.to_dict(), "attached": True,
                  "attach_reason": None}
        if self.helper_profile_path is not None and self.operations is None:
            record["helper"] = self._start_helper_supervision()
        # Attach can race the child's atomic identity/epoch publication. The
        # child already exists, so retry with its original witness every tick;
        # no managed workload is required to establish the initial binding.
        try:
            self.supervisor = self._attach(self.guardian)
        except SupervisorHostRefused as error:
            record["attached"], record["attach_reason"] = False, error.detail
        self._start_telemetry()
        return record

    def _child_arguments(self, epoch):
        arguments = ["-m", "sentinel.adaptive.guardian_host",
                     "--data-dir", str(self.data_dir), "--journal-dir", str(self.journal_dir),
                     "--guardian-epoch", epoch, "--iterations", str(self.guardian_iterations)]
        if self.profile_path is not None:
            arguments += ["--profile", str(self.profile_path)]
        if self._operational_current is not None:
            names = self._guardian_endpoints.setdefault(epoch, {
                name: str(uuid4()) for name in ("instance_id", "operator_instance_id",
                    "launch_instance_id", "query_instance_id", "control_instance_id")})
            for name, value in names.items():
                arguments += ["--" + name.replace("_", "-"), value]
            arguments += self._parent_arguments()
        return arguments

    def _parent_arguments(self):
        identity = self._operational_current.identity
        return ["--policy-instance-id", self.binding.instance_id,
                "--parent-instance-id", self._instance_id,
                "--parent-pid", str(identity.pid),
                "--parent-created-filetime", str(identity.created_filetime_100ns),
                "--parent-logon-id", identity.logon_id]

    # --- operational discovery and conservative requests -------------------

    def _ensure_operations(self, epoch):
        """Use the original singleton's self handle, never reopen a PID."""
        if self.operations is not None:
            if self.operations.epoch != epoch:
                raise SupervisorHostRefused("supervisor_host_operator_epoch_changed")
            return
        current = getattr(self.startup, "_current", None)
        if current is None:
            # Explicit synthetic host-order fixtures do not construct native
            # startup custody. Production SupervisorStartup.assert_fresh checks
            # its retained current handle before this point.
            return
        from .host_discovery import HostDiscovery, HostDescriptor, EndpointLocator
        from .operator_transport import OperatorService
        from .pipe_windows import NativePipeEndpoint, NativePipeListener
        from .supervisor_operations import SupervisorHostOperations
        self._operational_current = current
        endpoint = NativePipeEndpoint(current.identity.logon_id, self._operator_instance_id, current.identity)
        self.operations = SupervisorHostOperations(self, instance_id=self._instance_id,
            policy_instance_id=self.binding.instance_id, guardian_epoch=epoch, current=current)
        self.operator_service = OperatorService(endpoint, instance_id=self._instance_id,
            policy_instance_id=self.binding.instance_id, guardian_epoch=epoch, handler=self.operations)
        try:
            self.operator_listener = NativePipeListener(endpoint)
            self.discovery = HostDiscovery(self.data_dir, logon_id=current.identity.logon_id)
            record = HostDescriptor(self._instance_id, self.binding.instance_id, current.identity.logon_id,
                epoch, "supervisor", current.identity, (EndpointLocator("operator", endpoint),), "starting", 1)
            self.discovery.publish_instance(record, expected=None, owner_process=current)
            self.descriptor = record
        except BaseException as error:
            self._operational_error = error
            raise

    def _refresh_descriptor(self):
        if self.discovery is None or self.descriptor is None or self.guardian is None:
            return
        child = None
        try:
            if not self._guardian_settled:
                names = self._guardian_endpoints[self.guardian.epoch]
                child = self.discovery.read_guardian(parent_identity=self._operational_current.identity,
                    parent_instance_id=self._instance_id, child_identity=self.guardian.process.identity,
                    instance_id=names["instance_id"], policy_instance_id=self.binding.instance_id,
                    guardian_epoch=self.guardian.epoch)
                expected = {role: names[role + "_instance_id"] for role in ("operator", "launch", "query", "control")}
                if any(expected.get(item.role) != item.endpoint.instance_id for item in child.endpoints):
                    raise SupervisorHostRefused("supervisor_host_child_endpoint_changed")
                observed = self.guardian.process.observe()
                from .contracts import IdentityStatus
                if observed.status is not IdentityStatus.ALIVE or observed.identity != child.host_identity:
                    child = None
            self.guardian_descriptor = child
            state = "draining" if self.draining else "ready" if child is not None and child.state == "ready" else "unavailable"
            if self.descriptor.guardian == child and self.descriptor.state == state:
                return
            record = replace(self.descriptor, guardian=child, state=state, revision=self.descriptor.revision + 1)
            self.discovery.publish_instance(record, expected=self.descriptor,
                owner_process=self._operational_current,
                child_process=None if child is None else self.guardian.process)
            self.descriptor = record
        except Exception as error:
            self.guardian_descriptor = None
            # An unpublished child is still starting; it is not readiness and
            # does not invalidate the retained death/recovery owner.
            if self.operations is not None:
                self.operations.last_error = error
            if (getattr(error, "publication_may_have_occurred", False) or
                    getattr(self.discovery, "_quarantined", False)):
                self._operational_error = error

    def _rotate_operations(self, epoch):
        if self.operations is None:
            return
        if self.draining or self.operations.operations:
            raise SupervisorHostRefused("supervisor_host_operator_operation_retained")
        if self._operational_error is not None:
            raise SupervisorHostRefused("supervisor_host_operator_cleanup_unverified")
        # Exact compare/removal comes before a fresh logical instance. An old
        # request/endpoint is never rebound to the successor's guardian epoch.
        try:
            if self.descriptor is not None:
                self.discovery.remove_instance(self.descriptor, owner_process=self._operational_current)
            self.operator_listener.close()
            self.discovery.close()
        except BaseException as error:
            self._operational_error = error
            raise
        self.operations = self.operator_service = self.operator_listener = None
        self.discovery = self.descriptor = self.guardian_descriptor = None
        self._instance_id, self._operator_instance_id = str(uuid4()), str(uuid4())
        self._ensure_operations(epoch)

    def begin_drain(self):
        """Irreversible in-process intent, published before every child RPC."""
        self.draining = True

    def _runtime_observation(self):
        from .store import _ipc_read_transaction
        with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
            row = conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone()
            if row is None:
                raise LifecycleError("operator_ledger_unavailable")
            runtime = dict(row)
            if (self.binding is None or runtime["policy_instance_id"] != self.binding.instance_id or
                    runtime["policy_logon_id"] != self.binding.logon_id or
                    self.guardian is not None and runtime["guardian_epoch"] not in {"", self.guardian.epoch}):
                raise LifecycleError("operator_ledger_binding_changed")
            slot = conn.execute("SELECT slot_state FROM adaptive_control_slot WHERE singleton=1").fetchone()
        return runtime, slot

    def request_local_drain(self):
        self.begin_drain()
        if self.operations is None:
            return
        from .operator_messages import OperatorOperation, OperatorRequest
        if self._local_drain_request is None:
            try:
                runtime, _ = self._runtime_observation()
                self._local_drain_request = OperatorRequest(str(uuid4()), OperatorOperation.DRAIN,
                    self._instance_id, self.binding.instance_id, self.operations.epoch,
                    expected_registry_revision=runtime["registry_revision"])
            except Exception as error:
                self.operations.last_error = error
                return
        self.operations(self._local_drain_request, caller_identity=self._operational_current.identity)

    def _operational_recovery_pending(self):
        if self.unverified or self.unsettled_captures or self._creation_unknown or self._unknown_handles:
            return True
        if self._operator_cleanup_errors:
            return True
        known = {id(item) for item in [self.guardian, self.helper, *self.retired, *self.retired_helpers] if item is not None}
        if any(item.get("child") is not None and id(item["child"]) not in known for item in self._creation_records):
            return True
        if self.operations is not None:
            from .pipe_windows import _GLOBAL_REGISTRY
            status = _GLOBAL_REGISTRY.status()
            expected = 0 if self._operator_closed else 1
            if status.pending or status.quarantined or status.resources > expected:
                return True
        if any(result is None or not result.complete for result in self._registry_results.values()):
            return True
        if any(operation is not None and getattr(operation, "pending", False) is True for operation in
                (self._initial_start_operation, self._empty_check, self.janitor,
                 getattr(self._rollover, "_policy_operation", None), *self._registry_retirements.values())):
            return True
        if self.supervisor is not None and (getattr(self.supervisor, "_integrity_error", None) is not None or
                getattr(self.supervisor, "errors", ()) or getattr(self.supervisor, "drain_errors", ())):
            return True
        return False

    def _retain_operator_error(self, error):
        """Retain native peer cleanup hidden behind a sanitized RPC failure."""
        seen = set()
        current = error
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if (getattr(current, "_identity_handle_cleanup", ()) or
                    getattr(current, "_native_close_outcome_unknown", False)):
                if all(item is not current for item in self._operator_cleanup_errors):
                    self._operator_cleanup_errors.append(current)
            current = getattr(current, "_operator_cause", None) or getattr(current, "__cause__", None)

    def _reap_operator_cleanup(self):
        from .identity import retry_identity_cleanup
        from .pipe_windows import _GLOBAL_REGISTRY, NativeDeadline
        _GLOBAL_REGISTRY.reap(NativeDeadline.after_ms(100), max_ops=4)
        if self._operator_cleanup_errors:
            error = self._operator_cleanup_errors[0]
            if getattr(error, "_native_close_outcome_unknown", False):
                return
            try:
                retry_identity_cleanup(error)
            except Exception:
                return
            self._operator_cleanup_errors.pop(0)

    def _drain_children_settled(self):
        if self._operational_recovery_pending() or self.supervisor is not None:
            return False
        if self.guardian is not None and not self._guardian_settled or self.helper is not None:
            return False
        return not self.cold_reason

    def _custody_snapshot(self):
        children = [*self.retired, *self.retired_helpers]
        if self.guardian is not None:
            children.append(self.guardian)
        remaining = len({id(item) for item in children if id(item) not in self._drain_closed_children})
        if self.helper is not None:
            remaining += 1
        remaining += len(self.unverified) + len(self.unsettled_captures) + int(self._creation_unknown)
        result = dict(settled=False, remaining_custody=remaining,
                      reason="operator_supervisor_custody_pending")
        try:
            runtime, slot = self._runtime_observation()
            result.update(mode_off=runtime["mode"] == "off", registry_revision=runtime["registry_revision"],
                          barrier_cleared=runtime["admission_barrier"] == "NONE")
            result["settled"] = (self._drain_children_settled() and remaining == 0 and
                result["mode_off"] and (slot is None or slot[0] == "RESTORED") and
                result["barrier_cleared"] and runtime["policy_entry_nonce"] is None and
                self._operational_error is None)
            if result["settled"]:
                result["reason"] = "operator_instance_drained"
        except Exception:
            result["reason"] = "operator_ledger_unavailable"
        return result

    def _operational_tick(self):
        self._refresh_descriptor()
        if self.operations is None:
            return
        self._reap_operator_cleanup()
        if (self.helper_profile_path is not None and self.helper is None and
                (self.started_helpers == 0 or self._helper_restart_pending) and not self.draining):
            if self.guardian_descriptor is not None and self.guardian_descriptor.state == "ready":
                result = self._start_helper_supervision()
                if result["started"]:
                    self._helper_restart_pending = False
        try:
            self.operations.tick()
        except BaseException as error:
            self.operations.last_error = error
            self._retain_operator_error(error)
            if not isinstance(error, Exception):
                self.begin_drain()
                raise
        try:
            self.operator_service.serve_once(self.operator_listener, timeout_ms=750)
        except Exception as error:
            self.operations.last_error = error
            self._retain_operator_error(error)
        # Observation/RPC follows a recovery tick, never replaces it. Recheck
        # the janitor afterwards so a request cannot postpone owned cleanup.
        self._last_barrier = self._reconcile_barrier()
        if self.draining:
            for child in [*self.retired, *self.retired_helpers,
                    *([self.guardian] if self.guardian is not None and self._guardian_settled else [])]:
                if id(child) in self._drain_closed_children:
                    continue
                key = ("guardian" if hasattr(child, "epoch") else "helper", id(child))
                result = self._registry_results.get(key)
                if result is None or not result.complete:
                    continue
                try:
                    self._close_retired_child(child)
                    self._drain_closed_children.add(id(child))
                except Exception as error:
                    self.operations.last_error = error

    def _start_initial_guardian(self):
        successor = getattr(self, "_daily_successor_operation", None)
        if successor is None:
            return self._start_initial_guardian_owned()
        with successor.startup_sql_scope(self):
            return self._start_initial_guardian_owned()

    def _start_initial_guardian_owned(self):
        # No SQLite transaction spans CreateProcess; POLICY still serializes
        # the final fresh-state check with cooperating infrastructure writers.
        from .supervisor_reconcile import RetainedPolicyOperation
        from .supervisor_startup import _ColdHold
        if self._initial_start_operation is None:
            self._initial_start_operation = RetainedPolicyOperation(self.store)
        refusal = None

        def create_once():
            nonlocal refusal
            # Custody is published before POLICY cleanup. A failed nonce clear
            # must never hide an already-created child or cause another Create.
            if self.guardian is not None:
                return False
            if self.draining:
                return False  # settle the original guard without a late Create
            try:
                self.startup.assert_fresh_locked()
            except _ColdHold as error:
                if getattr(error, "__notes__", ()):
                    raise
                refusal = error
            if refusal is None:
                self.guardian = self._start_guardian(epoch=self._initial_epoch)
            return False

        result = self._initial_start_operation._run(self.binding.logon_id,
            create_once, lambda: self.guardian is not None)
        self._initial_start_result = result
        if not result.complete:
            raise SupervisorHostRefused(result.reason or "supervisor_host_initial_start_pending")
        if refusal is not None:
            raise SupervisorHostRefused("supervisor_host_startup_changed", _reason(refusal))
        if self.guardian is None:
            raise SupervisorHostRefused("supervisor_host_startup_changed")
        return self.guardian

    def _capture_guardian_creation(self, handle, pid, epoch):
        from .recovery_owner import RetainedGuardianCreation
        return RetainedGuardianCreation.from_creation_handle(handle, expected_pid=pid,
            expected_logon_id=self.capability_logon(), guardian_epoch=epoch)

    def _start_guardian(self, *, previous_epoch=None, epoch=None):
        """Create the child, then build its witness from the creation handle."""
        if self.draining:
            raise SupervisorHostRefused("supervisor_host_draining")
        if self.started_guardians >= self.max_guardians:
            raise SupervisorHostRefused("supervisor_host_guardian_budget_exhausted")
        if self._creation_unknown or self.unverified or self.unsettled_captures:
            raise SupervisorHostRefused("supervisor_host_creation_unsettled")
        epoch = mint_guardian_epoch() if epoch is None else epoch
        # Checked before anything is created. A reused epoch must never reach a
        # child process, so this cannot be a check after the fact.
        if previous_epoch is not None and epoch == previous_epoch:
            raise SupervisorHostRefused("supervisor_host_epoch_reused")
        arguments = self._child_arguments(epoch)
        retained = {"role": "guardian", "epoch": epoch}
        self._creation_records.append(retained)
        self._creation_unknown = True
        try:
            retained["info"] = self.creation.create(self.python_executable, arguments, self.child_cwd)
            info = retained["info"]
        except BaseException as error:
            retained["error"] = error
            if isinstance(error, SupervisorHostRefused) and error.reason == "supervisor_host_create_failed":
                self._creation_unknown = False
            raise
        self._creation_unknown = False
        handle = int(info.hProcess)
        try:
            self.creation.close_handle(int(info.hThread))
            creation_witness = self._capture_guardian_creation(handle, int(info.dwProcessId), epoch)
            retained["witness"] = creation_witness
            process = creation_witness.process
            child = _Guardian(epoch=epoch, pid=int(info.dwProcessId), creation_handle=handle,
                process=process, creation_witness=creation_witness, endpoints=self._guardian_endpoints.get(epoch))
            retained["child"] = child
        except BaseException as error:
            retained["error"] = error
            self._capture_errors.append(error)
            # The child is running and this handle is the only witness of it.
            # It is retained and reported, never closed here and never replaced
            # by a PID lookup later.
            self.unverified.append({"pid": int(info.dwProcessId), "handle": handle,
                                    "epoch": epoch, "reason": _reason(error)})
            partial = getattr(error, "_guardian_creation_owner", None)
            if partial is not None:
                self.unsettled_captures.append({"owner": partial, "epoch": epoch,
                                               "reason": "guardian_creation_unverified"})
            if not isinstance(error, Exception):
                raise
            raise SupervisorHostRefused("supervisor_host_guardian_unverified",
                                        _reason(error)) from None
        self.started_guardians += 1
        return child

    def _helper_arguments(self):
        arguments = ["-m", "sentinel.adaptive.helper_host",
                "--data-dir", str(self.data_dir), "--profile", str(self.helper_profile_path)]
        if self._operational_current is not None:
            if self.guardian_descriptor is None or self.guardian_descriptor.state != "ready":
                raise SupervisorHostRefused("supervisor_host_guardian_endpoint_unavailable")
            self._helper_endpoints = {name: str(uuid4()) for name in ("instance_id", "operator_instance_id")}
            for name, value in self._helper_endpoints.items():
                arguments += ["--" + name.replace("_", "-"), value]
            identity = self.guardian.process.identity
            arguments += self._parent_arguments() + ["--guardian-epoch", self.guardian.epoch,
                "--guardian-pid", str(identity.pid), "--guardian-created-filetime", str(identity.created_filetime_100ns),
                "--guardian-logon-id", identity.logon_id,
                "--guardian-control-instance-id", self.guardian.control_instance_id]
        return arguments

    def _start_helper(self):
        """Create the helper child, then build its witness from that handle.

        This is the guardian start without the epoch. The helper host takes no
        epoch, and the reason the supervisor creates this child at all is the
        creation handle: it is the only death evidence for the helper that can
        exist on this host, and without it the helper's registry row can never
        be removed.
        """
        from .identity import VerifiedProcess

        if self.draining:
            raise SupervisorHostRefused("supervisor_host_draining")
        if self.started_helpers >= self.max_helpers:
            raise SupervisorHostRefused("supervisor_host_helper_budget_exhausted")
        if self._creation_unknown or self.unverified or self.unsettled_captures:
            raise SupervisorHostRefused("supervisor_host_creation_unsettled")
        arguments = self._helper_arguments()
        retained = {"role": "helper"}
        self._creation_records.append(retained)
        self._creation_unknown = True
        try:
            retained["info"] = self.creation.create(self.python_executable, arguments, self.child_cwd)
            info = retained["info"]
        except BaseException as error:
            retained["error"] = error
            if isinstance(error, SupervisorHostRefused) and error.reason == "supervisor_host_create_failed":
                self._creation_unknown = False
            raise
        self._creation_unknown = False
        handle = int(info.hProcess)
        try:
            self.creation.close_handle(int(info.hThread))
            process = VerifiedProcess.duplicate_from_handle(
                handle, expected_pid=int(info.dwProcessId),
                expected_logon_id=self.capability_logon())
            retained["witness"] = process
            child = _Helper(pid=int(info.dwProcessId), creation_handle=handle, process=process,
                            endpoints=self._helper_endpoints)
            retained["child"] = child
        except BaseException as error:
            retained["error"] = error
            self._capture_errors.append(error)
            # Same rule as the guardian. The child is running, this handle is
            # the only witness of it, so it is retained and reported here and
            # never replaced by a PID lookup later.
            self.unverified.append({"pid": int(info.dwProcessId), "handle": handle,
                                    "role": "helper", "reason": _reason(error)})
            if not isinstance(error, Exception):
                raise
            raise SupervisorHostRefused("supervisor_host_helper_unverified",
                                        _reason(error)) from None
        self.started_helpers += 1
        return child

    def _start_helper_supervision(self):
        """Start the one helper child at startup. A failure here stops nothing.

        Guardian supervision is the job of this host and helper supervision is
        an addition to it, so a helper that could not be created is reported
        and the host carries on with the guardian.
        """
        try:
            self.helper = self._start_helper()
        except SupervisorHostRefused as error:
            return {"started": False, "reason": error.reason, "detail": error.detail}
        return {"started": True, "pid": self.helper.pid}

    def capability_logon(self):
        from .identity import VerifiedProcess

        with VerifiedProcess.current() as current:
            return current.identity.logon_id

    def _attach(self, guardian):
        return self._capture_supervisor(guardian, created=False)

    def _attach_created(self, guardian):
        return self._capture_supervisor(guardian, created=True)

    def _capture_supervisor(self, guardian, *, created):
        from .supervisor import GuardianSupervisor

        try:
            if created:
                return GuardianSupervisor.attach_created(self.store, self.journal,
                    creation=guardian.creation_witness, guardian_epoch=guardian.epoch)
            return GuardianSupervisor.attach(self.store, self.journal, guardian=guardian.process,
                                             guardian_epoch=guardian.epoch)
        except BaseException as error:
            # Capture succeeded and only the first inventory read failed. The
            # attach contract is to keep that same supervisor, so it is adopted
            # here and its next tick reads the inventory again.
            captured = getattr(error, "supervisor_owner", None)
            if captured is not None:
                if not isinstance(error, Exception):
                    self.supervisor = captured  # custody before interrupt escape
                    raise
                return captured
            # A failed capture leaves its partial owner on the exception. It is
            # closed here, and one that cannot be closed is kept and reported.
            partial = getattr(error, "_recovery_owner", None)
            if partial is not None:
                retained = {"owner": partial, "epoch": guardian.epoch,
                            "reason": "supervisor_capture_cleanup_pending"}
                self.unsettled_captures.append(retained)
                if not isinstance(error, Exception):
                    retained["reason"] = "supervisor_capture_interrupted"
                    raise
                try:
                    partial.close()
                    self.unsettled_captures.remove(retained)
                except BaseException as cleanup:
                    retained["reason"] = _reason(cleanup)
                    self._capture_errors.append(cleanup)
                    if not isinstance(cleanup, Exception):
                        raise
            if not isinstance(error, Exception):
                raise
            raise SupervisorHostRefused("supervisor_host_attach_unavailable",
                                        _reason(error)) from None

    # --- one bounded iteration --------------------------------------------

    def run_once(self):
        record = self._run_recovery_once()
        self._operational_tick()
        if self.draining:
            record["draining"] = True
            record["custody"] = self._custody_snapshot()
        return record

    def _run_recovery_once(self):
        from .contracts import IdentityStatus

        barrier = self._reconcile_barrier()
        if self.cold_reason is not None:
            if self.draining:
                # Existing creation may have committed before POLICY cleanup
                # failed. Settle that same operation, never create a new child.
                if self._initial_start_operation is not None and self._initial_start_operation.pending:
                    try:
                        self._start_initial_guardian()
                    except Exception as error:
                        self.cold_reason = _reason(error)
                if self.guardian is not None and not self._operational_recovery_pending():
                    self.cold_reason = None
                else:
                    return {"event": "supervisor_host_iteration", "state": "COLD_RECOVERY_HOLD",
                            "reason": self.cold_reason, "draining": True, "barrier": barrier}
        if self.cold_reason is not None:
            if getattr(self.startup, "can_retry_acquire", False) is True:
                try:
                    self.startup.retry_acquire()
                except Exception as error:
                    self.cold_reason = _reason(error)
                    return {"event": "supervisor_host_iteration", "state": "COLD_RECOVERY_HOLD",
                            "reason": self.cold_reason, "guardian_created": False, "barrier": barrier}
                from .supervisor_reconcile import FinishedBarrierJanitor
                self.janitor = FinishedBarrierJanitor(self.store, self.journal)
                record = self._finish_startup(self._reconcile_barrier())
                record["event"] = "supervisor_host_iteration"
                return record
            initial = self._initial_start_result
            retry = (initial is not None and initial.pending and not initial.quarantined)
            retry = retry or (getattr(self.startup, "policy_pending", False) is True and
                              getattr(self.startup, "policy_quarantined", True) is False)
            if retry:
                record = self._finish_startup(barrier)
                record["event"] = "supervisor_host_iteration"
                return record
            return {"event": "supervisor_host_iteration", "state": "COLD_RECOVERY_HOLD",
                    "reason": self.cold_reason,
                    "guardian_created": self.guardian is not None or bool(self.unverified) or self._creation_unknown,
                    "barrier": barrier}
        if self.guardian is None:
            raise SupervisorHostRefused("supervisor_host_not_started")
        if self._guardian_settled:
            record = {"event": "supervisor_host_iteration", "guardian_epoch": self.guardian.epoch,
                      "guardian_status": "dead", "replacement": self._replace()}
        elif self.supervisor is None:
            # A guardian that could not be attached is never observed through a
            # closed supervisor. The iteration says so and retries the attach
            # against the same live guardian under the same epoch.
            record = self._retry_attach()
        else:
            result = self.supervisor.tick()
            record = {"event": "supervisor_host_iteration", "guardian_epoch": self.guardian.epoch,
                      "guardian_status": result.guardian_status.value,
                      "inventory_verified": result.inventory_verified,
                      "known_executions": list(result.known_executions),
                      "restored_executions": list(result.restored_executions),
                      "unresolved_executions": list(result.unresolved_executions),
                      "slot_released_executions": list(result.slot_released_executions),
                      "finalized_executions": list(result.finalized_executions),
                      "drain_unresolved_executions": list(result.drain_unresolved_executions),
                      "inventory_error": result.inventory_error, "replacement": None}
            # UNKNOWN holds. Only a verified death may lead to a replacement,
            # and only after this supervisor settles its own custody.
            if result.guardian_status is IdentityStatus.DEAD:
                record["replacement"] = self._replace()
        # The helper is observed on both paths. Its witness is independent of
        # the guardian supervisor, so an unattached guardian says nothing about
        # it either way.
        if self.helper_profile_path is not None:
            record["helper"] = self._supervise_helper()
        if barrier is not None:
            record["barrier"] = barrier
        return record

    def _reconcile_barrier(self):
        if self.janitor is None:
            return None
        from dataclasses import asdict
        try:
            if self.supervisor is not None:
                if (getattr(self.supervisor, "_integrity_error", None) is not None or
                        getattr(self.supervisor, "errors", ()) or getattr(self.supervisor, "drain_errors", ())):
                    return {"complete": False, "pending": True,
                            "reason": "supervisor_barrier_integrity_unverified"}
                recovery = getattr(self.supervisor, "recovery", None)
                retained = getattr(recovery, "retained_execution_ids", ())
                if retained:
                    from .control_slot import read_slot
                    with self.store._connection() as conn:
                        slot = read_slot(conn)
                    if slot is not None and slot["execution_id"] in retained:
                        # A live native owner must settle/close its own custody
                        # first; a ledger-only janitor cannot override contrary
                        # native observations or ambiguous handle cleanup.
                        return {"complete": False, "pending": True,
                                "reason": "supervisor_barrier_retained_custody"}
            return asdict(self.janitor.tick())
        except Exception as error:
            return {"complete": False, "pending": True, "reason": _reason(error)}

    def supervise_until_stopped(self):
        """Remain resident through requested drain and exact custody cleanup."""
        iterations = 0
        while True:
            try:
                if self.draining and self._local_drain_request is None and self.operations is not None and not self.operations.operations:
                    self.request_local_drain()
                self.emit(self.run_once())
                iterations += 1
                if self.draining and self._custody_snapshot()["settled"]:
                    return {"event": "supervisor_host_stopping", "reason": "drain_settled",
                            "iterations": iterations}
                self._sleep(self.tick_interval_sec)
            except KeyboardInterrupt:
                self.begin_drain()
                self.emit({"event": "supervisor_host_stopping", "reason": "drain_requested",
                      "iterations": iterations})
                try:
                    self.request_local_drain()
                except (Exception, KeyboardInterrupt) as error:
                    if self.operations is not None:
                        self.operations.last_error = error
            except Exception as error:
                # Failure is retained by its original owners. An uncaught
                # ordinary exception must not turn into silent witness loss.
                self.begin_drain()
                self.emit({"event": "supervisor_host_draining", "reason": _reason(error),
                      "iterations": iterations})
                try:
                    self._sleep(self.tick_interval_sec)
                except KeyboardInterrupt:
                    pass

    def _observed_status(self):
        """What the retained witness reports now. A failed observation is unknown."""
        try:
            return self.guardian.process.observe().status.value
        except Exception:
            return "unknown"

    def _retry_attach(self):
        # The witness is asked each time. An unattached guardian is not assumed
        # to be running, and nothing here acts on the answer.
        record = {"event": "supervisor_host_iteration", "guardian_epoch": self.guardian.epoch,
                  "guardian_status": "unattached", "attached": False,
                  "guardian_observed": self._observed_status(), "replacement": None}
        try:
            if record["guardian_observed"] == "dead":
                if self._empty_check is not None and self._empty_check.pending:
                    # This earlier operation still owns a durable nonce.
                    # Attaching first could strand that owner permanently.
                    empty = self._unstarted_guardian_empty()
                    if self._empty_check.pending:
                        record["reason"] = "supervisor_host_empty_inspection_pending"
                        return record
                    if empty:
                        self._guardian_settled = True
                        record["replacement"] = self._replace()
                        return record
                try:
                    self.supervisor = self._attach_created(self.guardian)
                except SupervisorHostRefused:
                    # A child can exit before registering a first scope/epoch.
                    # Only a POLICY-fenced complete absence proves this narrow
                    # no-Job case; a missing manifest for a named scope holds.
                    if not self._unstarted_guardian_empty():
                        raise
                    self._guardian_settled = True
                    record["replacement"] = self._replace()
                    return record
            elif record["guardian_observed"] == "alive":
                self.supervisor = self._attach(self.guardian)
            else:
                record["reason"] = "supervisor_host_guardian_unknown"
                return record
        except SupervisorHostRefused as error:
            record["reason"], record["detail"] = error.reason, error.detail
            return record
        record["attached"] = True
        return record

    def _unstarted_guardian_empty(self):
        from .contracts import IdentityStatus
        from .identity import VerifiedProcess
        if (not isinstance(self.guardian.process, VerifiedProcess) or
                self.guardian.creation_witness is None or self.unverified or self.unsettled_captures):
            return False
        try:
            self.assert_held()
            observed = self.guardian.process.observe()
            if observed.status is not IdentityStatus.DEAD or observed.identity != self.guardian.process.identity:
                return False
            from .supervisor_reconcile import RetainedPolicyOperation
            if self._empty_check is None:
                self._empty_check = RetainedPolicyOperation(self.store)
            elif self._empty_result is not None and self._empty_result.complete:
                self._empty_check.reset_completed()
            self._empty_proof = False
            policy = self.store._policy

            def inspect():
                self.assert_held()
                exact = self.guardian.process.observe()
                if exact.status is not IdentityStatus.DEAD or exact.identity != observed.identity:
                    return False
                guard = policy.assert_held()
                with self.store._connection() as conn:
                    runtime = policy.revalidate(conn, guard)
                    if guard.binding != self.binding or runtime["guardian_epoch"] not in {"", self.guardian.epoch}:
                        return False
                    # No named scope at all is stronger than guessing which
                    # missing scope an early failed guardian might have owned.
                    if conn.execute("SELECT 1 FROM managed_executions WHERE job_name IS NOT NULL OR launch_in_flight IS NOT 0 LIMIT 1").fetchone():
                        return False
                    if conn.execute("SELECT 1 FROM adaptive_control_slot LIMIT 1").fetchone():
                        return False
                    self._empty_proof = runtime["admission_barrier"] == "NONE"
                return False

            # A released nonce without an ACK is not a fresh empty snapshot.
            # Retry the bounded read; it never reconstructs a lost guard.
            self._empty_result = self._empty_check._run(observed.identity.logon_id, inspect, lambda: False)
            return self._empty_result.complete and self._empty_proof
        except Exception:
            return False

    def _replace(self):
        """Close first. A new guardian is a new epoch or it does not happen."""
        if not self._guardian_settled:
            try:
                self.supervisor.close()
            except Exception as error:
                return {"started": False, "reason": _reason(error)}
            self.supervisor = None
            self._guardian_settled = True
        previous = self.guardian
        cached = self._registry_results.get(("guardian", id(previous)))
        if self.draining and cached is not None and cached.complete:
            removed, registry_reason = cached.changed, None
        else:
            removed, registry_reason = self._unregister("guardian", previous)
        registry = {"registry_removed": removed, "registry_reason": registry_reason}
        if registry_reason is not None:
            return {"started": False, "reason": "supervisor_host_guardian_row_retained", **registry}
        if self.draining:
            return {"started": False, "reason": "supervisor_host_draining", **registry}
        if self.helper is not None and self.operations is not None:
            self._request_helper_epoch_drain()
            return {"started": False, "reason": "supervisor_host_helper_epoch_retained", **registry}
        if self.started_guardians >= self.max_guardians:
            return {"started": False, "reason": "supervisor_host_guardian_budget_exhausted",
                    **registry}
        try:
            epoch = self._rollover_epoch(previous)
            self._rotate_operations(epoch)
            replacement = self._start_guardian(previous_epoch=previous.epoch, epoch=epoch)
        except Exception as error:
            return {"started": False, "reason": _reason(error), **registry}
        # The settled predecessor stays reachable until this host shuts down,
        # so its creation handle is released in one place with a reported
        # outcome instead of silently during a tick.
        self.retired.append(previous)
        self.guardian = replacement
        self._guardian_settled = False
        self._rollover = self._replacement_epoch = None
        try:
            self.supervisor = self._attach(replacement)
        except SupervisorHostRefused as error:
            return {"started": True, "attached": False, "reason": error.reason,
                    "guardian_epoch": replacement.epoch, **registry}
        return {"started": True, "attached": True, "guardian_epoch": replacement.epoch,
                "previous_epoch": previous.epoch, **registry}

    def _unregister(self, role, child):
        """Remove the dead child's infrastructure row under POLICY.

        A guardian and a helper both register themselves at startup and neither
        can remove its own row afterwards, so the row would stay until the
        capped registry refuses the next registration. The retained witness
        this host created is the only death evidence that exists for that
        child, and unregister_dead_infrastructure_locked re-verifies death on
        it. Nothing here reopens a PID, deletes by epoch or writes the table
        itself.

        The return is the pair reported in the replacement record. False with no
        reason means the row was already absent.

        A refusal the writer decided before its transaction, which is what
        legacy_infrastructure_death_unverified and
        legacy_infrastructure_identity_required are, releases the POLICY entry
        on the way out, so the next child start can still register. Letting
        those propagate out of the hold is what releases them, so nothing in
        this method raises an exception of its own inside the hold. A failure
        at or after that transaction retains the original guard. Subsequent
        ticks revalidate and retry that same exact operation; they never prepare
        a substitute guard to clear a possibly unrelated nonce.
        """
        from .supervisor_reconcile import PendingInfrastructureRetirement
        try:
            key = (role, id(child))
            pending = self._registry_retirements.get(key)
            if pending is None:
                pending = PendingInfrastructureRetirement(self.store, role=role, witness=child.process)
                self._registry_retirements[key] = pending
            result = pending.tick()
            self._registry_results[key] = result
        except Exception as error:
            self._registry_results[(role, id(child))] = None
            # LegacyMutationError carries its stable code as the message, the
            # same convention LifecycleError uses. Anything else reports the
            # type name _reason gives it.
            code = str(error)
            if _STABLE_CODE.fullmatch(code):
                return False, code
            return False, _reason(error)
        return result.changed, None if result.complete else (result.reason or "registry_retirement_pending")

    @property
    def binding(self):
        return None if self.startup is None else self.startup.binding

    def assert_held(self):
        if self.startup is None:
            raise LifecycleError("supervisor_instance_custody_missing")
        return self.startup.assert_held()

    def assert_settled_for_rollover(self):
        self.assert_held()
        if (not self._guardian_settled or self.supervisor is not None or self.unverified or
                self.unsettled_captures or self._creation_unknown):
            raise LifecycleError("supervisor_rollover_custody_unsettled")
        if self.guardian is None:
            raise LifecycleError("supervisor_rollover_guardian_missing")
        result = self._registry_results.get(("guardian", id(self.guardian)))
        if result is None or not result.complete or any(
                item is None or not item.complete for item in self._registry_results.values()):
            raise LifecycleError("supervisor_rollover_registry_pending")

    def _rollover_epoch(self, previous):
        from .supervisor_epoch import SettledEpochRollover
        if self._replacement_epoch is None:
            self._replacement_epoch = mint_guardian_epoch()
        if self._replacement_epoch == previous.epoch:
            raise SupervisorHostRefused("supervisor_host_epoch_reused")
        if self._rollover is None:
            self._rollover = SettledEpochRollover(self.store, self.journal,
                old_epoch=previous.epoch, witness=previous.process, instance_owner=self)
        result = self._rollover.tick(self._replacement_epoch)
        if not result.complete:
            raise SupervisorHostRefused(result.reason or "supervisor_host_rollover_pending")
        return self._replacement_epoch

    # --- the helper child --------------------------------------------------

    def _request_helper_epoch_drain(self):
        """Retire the old helper before changing its immutable epoch binding."""
        if self.helper is None or self.operations is None:
            return
        from .operator_messages import OperatorOperation as Op, OperatorRequest
        try:
            if self._helper_epoch_drain is None:
                runtime, _ = self._runtime_observation()
                request = OperatorRequest(str(uuid4()), Op.DRAIN, self._instance_id,
                    self.binding.instance_id, self.guardian.epoch,
                    expected_registry_revision=runtime["registry_revision"])
                self._helper_epoch_drain = self.operations._target("helper", request)
            child, request, client = self._helper_epoch_drain
            if self.helper is child and self.operations._alive(child):
                client.request(request, timeout_ms=250)
        except Exception as error:
            self.operations.last_error = error

    def _supervise_helper(self):
        """Observe the helper witness once. Only DEAD leads to anything.

        An observation that fails is unknown, and unknown holds. A missing PID,
        a failed open, a closed handle and a non zero exit code are none of
        them death here, because the only thing this reads is what the retained
        witness reports.
        """
        from .contracts import IdentityStatus

        if self.helper is None:
            # Either the start failed or a replacement did. Nothing is observed
            # and nothing is started from here.
            return {"status": "absent", "started": False}
        try:
            observed = self.helper.process.observe().status
        except Exception as error:
            return {"status": "unknown", "started": False, "reason": _reason(error)}
        if observed is not IdentityStatus.DEAD:
            return {"status": observed.value, "started": False}
        return self._replace_helper()

    def _replace_helper(self):
        """Release the dead helper's row first, then start a replacement.

        The order matters. helper_host refuses to start while another helper
        row for this logon exists, so a replacement created before the row is
        gone would refuse with helper_host_registry_occupied. A removal that
        failed leaves that row in place, so no replacement is started in that
        case and the record says why. False with no reason is a row that was
        already absent, which is the expected state for a helper that never
        managed to register.

        A failed deletion retains the helper and its exact pending operation.
        The next tick retries even when the replacement budget is exhausted.
        """
        dead = self.helper
        removed, registry_reason = self._unregister("helper", dead)
        record = {"status": "dead", "registry_removed": removed,
                  "registry_reason": registry_reason, "started": False}
        if registry_reason is not None:
            record["reason"] = "supervisor_host_helper_row_retained"
            return record
        self.helper = None
        self.retired_helpers.append(dead)
        if self.draining:
            record["reason"] = "supervisor_host_draining"
            return record
        if self.operations is not None:
            # The next helper must be bound to the guardian currently proven
            # ready. Do not reuse an old control endpoint across epoch rollover.
            self._helper_restart_pending = True
            self._helper_epoch_drain = None
            record["reason"] = "supervisor_host_helper_ready_pending"
            return record
        try:
            replacement = self._start_helper()
        except SupervisorHostRefused as error:
            record["reason"] = error.reason
            return record
        self.helper = replacement
        record["started"], record["pid"] = True, replacement.pid
        return record

    # --- shutdown ---------------------------------------------------------

    def close(self):
        """Stop supervising. Nothing here stops the guardian.

        The guardian keeps running and is now unsupervised, and the result says
        so. This host has no kill path, and ending a guardian that still owns
        Jobs is exactly what the design forbids. A child with no witness is
        reported too, and the entry point turns that into a non clean exit.

        The helper is left running for the same reason, and its row stays in
        the registry with nothing left that could witness its death.
        """
        if self._closed:
            return dict(self._close_record)
        if self.draining and not self._drain_children_settled():
            raise SupervisorHostRefused("supervisor_host_custody_unsettled")
        if any(result is None or not result.complete for result in self._registry_results.values()):
            raise SupervisorHostRefused("supervisor_host_registry_retirement_pending")
        if self._creation_unknown:
            raise SupervisorHostRefused("supervisor_host_creation_unsettled")
        if any(result is not None and not result.complete for result in
               (self._initial_start_result, self._empty_result)):
            raise SupervisorHostRefused("supervisor_host_policy_operation_pending")
        if any(operation is not None and getattr(operation, "pending", False) is True for operation in
               (self._initial_start_operation, self._empty_check, self.janitor,
                getattr(self._rollover, "_policy_operation", None), *self._registry_retirements.values())):
            raise SupervisorHostRefused("supervisor_host_policy_operation_pending")
        if self.supervisor is not None:
            try:
                self.supervisor.close()
            except Exception as error:
                raise SupervisorHostRefused("supervisor_host_custody_unsettled",
                                            _reason(error)) from None
        cleanup = []
        closed_children = [*self.retired, *self.retired_helpers]
        if self._guardian_settled and self.guardian is not None:
            closed_children.append(self.guardian)
        for retired in closed_children:
            try:
                self._close_retired_child(retired)
                self._drain_closed_children.add(id(retired))
            except Exception as error:
                cleanup.append(_reason(error))
        if self.draining and self.operations is not None and not cleanup:
            try:
                self._close_operational()
            except Exception as error:
                cleanup.append(_reason(error))
        if self.startup is not None and not cleanup:
            try:
                self.startup.close()
            except Exception as error:
                cleanup.append(_reason(error))
        record = {"event": "supervisor_host_closed", "cleanup_errors": cleanup,
                  "guardian_epoch": None if self.guardian is None else self.guardian.epoch,
                  "guardian_left_running": self.guardian is not None and not self._guardian_settled,
                  "unverified": list(self.unverified),
                  "unsettled_captures": [{"epoch": item["epoch"], "reason": item["reason"]}
                                         for item in self.unsettled_captures]}
        if self.helper_profile_path is not None:
            record["helper_left_running"] = self.helper is not None
        if self.cold_reason is not None:
            record["cold_recovery_reason"] = self.cold_reason
        if not cleanup:
            record = self._finish_telemetry(record)
            self._closed = True
            self._close_record = dict(record)
        return record

    def _close_operational(self):
        if self._operational_error is not None:
            raise SupervisorHostRefused("supervisor_host_operator_cleanup_unverified")
        if not self._custody_snapshot()["settled"]:
            raise SupervisorHostRefused("supervisor_host_custody_unsettled")
        # The exact descriptor is removed while its original self handle and
        # lifetime fence are still held. No old owner removes a successor.
        if not self._descriptor_removed and self.descriptor is not None:
            self.discovery.remove_instance(self.descriptor, owner_process=self._operational_current)
            self._descriptor_removed = True
        if not self._operator_closed:
            self.operator_listener.close()
            self._operator_closed = True
        if not self._discovery_closed:
            self.discovery.close()
            self._discovery_closed = True

    def _close_retired_child(self, child):
        # The duplicate owns its own unknown-close quarantine. Retain an
        # explicit tombstone for the raw CreateProcess handle as well.
        witness = getattr(child, "creation_witness", None) or child.process
        key = (id(child), "witness")
        if key not in self._closed_handles:
            witness.close()
            self._closed_handles.add(key)
        key = (id(child), "creation")
        if key in self._unknown_handles:
            raise SupervisorHostRefused("supervisor_host_handle_cleanup_unknown")
        if key not in self._closed_handles:
            self._unknown_handles.add(key)
            try:
                self.creation.close_handle(child.creation_handle)
            except SupervisorHostRefused as error:
                if error.reason == "supervisor_host_handle_cleanup_failed" and not getattr(error, "__notes__", ()):
                    self._unknown_handles.discard(key)
                raise
            self._closed_handles.add(key)
            self._unknown_handles.discard(key)


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel.adaptive.supervisor_host",
        description="Own one guardian and retain custody through explicit drain.")
    parser.add_argument("--data-dir", required=True, help="directory holding sentinel.db")
    parser.add_argument("--journal-dir", required=True, help="recovery manifest directory")
    parser.add_argument("--iterations", type=int, default=0,
                        help="0 serves until drain; a positive value requests drain "
                             "after this many observation ticks (cleanup may continue)")
    parser.add_argument("--guardian-iterations", type=int, default=0,
                        help="iterations passed to the guardian child; 0 leaves the "
                             "child running until it is interrupted")
    parser.add_argument("--max-guardians", type=int, default=1,
                        help="how many guardian processes this host may start in total")
    parser.add_argument("--helper-profile", default=None,
                        help="policy profile JSON file for one shadow helper child; "
                             "without it no helper is started and none is supervised")
    parser.add_argument("--max-helpers", type=int, default=1,
                        help="how many helper processes this host may start in total")
    parser.add_argument("--child-cwd", default=None, help="working directory for the child")
    parser.add_argument("--python", default=None, help="interpreter used for the child")
    parser.add_argument("--profile", default=None, help="policy profile JSON file for the child")
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if (options.iterations < 0 or options.guardian_iterations < 0 or options.max_guardians < 1
            or options.max_helpers < 1):
        emit({"event": "supervisor_host_refused", "reason": "supervisor_host_arguments_invalid"})
        return EXIT_REFUSED
    host = SupervisorHost(data_dir=options.data_dir, journal_dir=options.journal_dir,
                          child_cwd=options.child_cwd, python_executable=options.python,
                          profile_path=options.profile, max_guardians=options.max_guardians,
                          guardian_iterations=options.guardian_iterations,
                          helper_profile_path=options.helper_profile,
                          max_helpers=options.max_helpers)
    try:
        host.emit(host.start())
    except (Exception, KeyboardInterrupt) as error:
        # A refusal after the child was created leaves a guardian behind. The
        # record names it, and that case is not a clean refusal.
        child = (host.guardian is not None or bool(host.unverified) or host._creation_unknown or
                 host.unsettled_captures or any(item.get("child") is not None for item in host._creation_records) or
                 getattr(host.startup, "policy_pending", False) is True)
        if child:
            # An interrupted pending binding can already retain native self
            # custody even though start() never returned its HOLD record.
            host._start_telemetry()
        host.emit({"event": "supervisor_host_refused", "reason": _reason(error), "detail": getattr(error, "detail", None),
              "guardian_created": child,
              "guardian_epoch": None if host.guardian is None else host.guardian.epoch,
              "guardian_pid": None if host.guardian is None else host.guardian.pid,
              "unverified": list(host.unverified)})
        if not child:
            return EXIT_REFUSED
        host.begin_drain()
    try:
        if options.iterations == 0:
            host.emit(host.supervise_until_stopped())
        else:
            for _ in range(options.iterations):
                host.emit(host.run_once())
                if host.draining:
                    break
            host.request_local_drain()
            host.emit(host.supervise_until_stopped())
    except KeyboardInterrupt:
        host.emit({"event": "supervisor_host_stopping", "reason": "interrupted"})
        host.begin_drain()
        host.emit(host.supervise_until_stopped())
    except Exception as error:
        host.emit({"event": "supervisor_host_stopping", "reason": _reason(error)})
        host.begin_drain()
        host.emit(host.supervise_until_stopped())
    # A failed final close still owns its exact native objects. Stay resident
    # through a known retry or quarantined outcome. Never tick a closed listener
    # merely because final singleton cleanup remains unfinished.
    while True:
        try:
            record = host.close()
            if not record["cleanup_errors"]:
                break
            host.emit(record)
        except (Exception, KeyboardInterrupt) as pending:
            host.emit({"event": "supervisor_host_draining", "reason": _reason(pending)})
        try:
            if not host._drain_children_settled():
                host.emit(host.run_once())
            host._sleep(host.tick_interval_sec)
        except (Exception, KeyboardInterrupt) as pending:
            host.emit({"event": "supervisor_host_draining", "reason": _reason(pending)})
    host.emit(record)
    # A child with no witness or a partial capture that would not close is not
    # a clean exit, even though the supervision itself settled.
    return EXIT_UNSETTLED if (record["unverified"] or record["unsettled_captures"] or
        record["cleanup_errors"] or record.get("cold_recovery_reason")) else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
