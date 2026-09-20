"""Runnable supervisor process host: py -m sentinel.adaptive.supervisor_host.

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
and weaker liveness test of its own. It is reported and never blocks a
replacement, and a supervisor that could not close attempts no removal at all.
A refusal the writer decides before its own transaction releases POLICY again,
so a later guardian start can still register. Only a failure at or after that
transaction keeps the durable entry, because the ledger outcome is unknown
then.

The default mode ticks until the process is interrupted, which is the only stop
condition this repository provides. Stopping does not stop the guardian. This
host has no kill path at all, so it closes its own supervision and leaves the
guardian running and unsupervised, and it says so. Nothing can re-adopt that
guardian afterwards, because the creation handle that witnesses it cannot
outlive this process.
"""
from __future__ import annotations

import argparse
import ctypes as C
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


def emit(record, stream=None):
    print(json.dumps(record, sort_keys=True, default=str),
          file=sys.stderr if stream is None else stream, flush=True)


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

    def __init__(self, *, epoch, pid, creation_handle, process):
        self.epoch = epoch
        self.pid = pid
        self.creation_handle = creation_handle
        self.process = process


class SupervisorHost:
    """Start one guardian, attach to it, and observe it with bounded ticks."""

    def __init__(self, *, data_dir, journal_dir, child_cwd=None, python_executable=None,
                 profile_path=None, max_guardians=1, guardian_iterations=0,
                 sleep=time.sleep, tick_interval_sec=1.0):
        self.data_dir = Path(data_dir)
        self.journal_dir = Path(journal_dir)
        self.child_cwd = Path(_REPO_ROOT if child_cwd is None else child_cwd)
        self.python_executable = sys.executable if python_executable is None else python_executable
        self.profile_path = profile_path
        self.max_guardians = max_guardians
        self.guardian_iterations = guardian_iterations
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
        # Children that were created but whose witness could not be built. The
        # raw creation handle is kept here so the process is never lost.
        self.unverified = []
        # Partial recovery owners from a failed attach that refused to close.
        self.unsettled_captures = []

    # --- startup ----------------------------------------------------------

    def start(self):
        from .recovery_journal import RecoveryJournal
        from .store import LifecycleStore

        try:
            self.capability = read_host_capability()
        except HostCapabilityUnsupported as error:
            raise SupervisorHostRefused(error.reason, error.win32_error) from None
        try:
            self.store = LifecycleStore(self.data_dir / "sentinel.db", existing_path=True)
        except Exception as error:
            raise SupervisorHostRefused("supervisor_host_ledger_unavailable", _reason(error)) from None
        try:
            self.journal = RecoveryJournal(self.journal_dir)
        except Exception as error:
            raise SupervisorHostRefused("supervisor_host_journal_unavailable", _reason(error)) from None
        self.creation = _Creation()
        self.guardian = self._start_guardian()
        record = {"event": "supervisor_host_started", "guardian_epoch": self.guardian.epoch,
                  "guardian_pid": self.guardian.pid, "pid": self.capability.pid,
                  "capability": self.capability.to_dict(), "attached": True,
                  "attach_reason": None}
        # Attach reads the guardian epoch from the ledger, and a guardian writes
        # it only when it prepares its first execution. On a fresh ledger the
        # first attach is therefore refused. The child already exists, so this
        # host stays up unattached and retries every iteration.
        try:
            self.supervisor = self._attach(self.guardian)
        except SupervisorHostRefused as error:
            record["attached"], record["attach_reason"] = False, error.detail
        return record

    def _child_arguments(self, epoch):
        arguments = ["-m", "sentinel.adaptive.guardian_host",
                     "--data-dir", str(self.data_dir), "--journal-dir", str(self.journal_dir),
                     "--guardian-epoch", epoch, "--iterations", str(self.guardian_iterations)]
        if self.profile_path is not None:
            arguments += ["--profile", str(self.profile_path)]
        return arguments

    def _start_guardian(self, *, previous_epoch=None):
        """Create the child, then build its witness from the creation handle."""
        from .identity import VerifiedProcess

        if self.started_guardians >= self.max_guardians:
            raise SupervisorHostRefused("supervisor_host_guardian_budget_exhausted")
        epoch = mint_guardian_epoch()
        # Checked before anything is created. A reused epoch must never reach a
        # child process, so this cannot be a check after the fact.
        if previous_epoch is not None and epoch == previous_epoch:
            raise SupervisorHostRefused("supervisor_host_epoch_reused")
        info = self.creation.create(self.python_executable, self._child_arguments(epoch),
                                    self.child_cwd)
        handle = int(info.hProcess)
        try:
            self.creation.close_handle(int(info.hThread))
            process = VerifiedProcess.duplicate_from_handle(
                handle, expected_pid=int(info.dwProcessId),
                expected_logon_id=self.capability_logon())
        except Exception as error:
            # The child is running and this handle is the only witness of it.
            # It is retained and reported, never closed here and never replaced
            # by a PID lookup later.
            self.unverified.append({"pid": int(info.dwProcessId), "handle": handle,
                                    "epoch": epoch, "reason": _reason(error)})
            raise SupervisorHostRefused("supervisor_host_guardian_unverified",
                                        _reason(error)) from None
        self.started_guardians += 1
        return _Guardian(epoch=epoch, pid=int(info.dwProcessId), creation_handle=handle,
                         process=process)

    def capability_logon(self):
        from .identity import VerifiedProcess

        with VerifiedProcess.current() as current:
            return current.identity.logon_id

    def _attach(self, guardian):
        from .supervisor import GuardianSupervisor

        try:
            return GuardianSupervisor.attach(self.store, self.journal, guardian=guardian.process,
                                             guardian_epoch=guardian.epoch)
        except Exception as error:
            # Capture succeeded and only the first inventory read failed. The
            # attach contract is to keep that same supervisor, so it is adopted
            # here and its next tick reads the inventory again.
            captured = getattr(error, "supervisor_owner", None)
            if captured is not None:
                return captured
            # A failed capture leaves its partial owner on the exception. It is
            # closed here, and one that cannot be closed is kept and reported.
            partial = getattr(error, "_recovery_owner", None)
            if partial is not None:
                try:
                    partial.close()
                except Exception as cleanup:
                    self.unsettled_captures.append({"owner": partial, "epoch": guardian.epoch,
                                                    "reason": _reason(cleanup)})
            raise SupervisorHostRefused("supervisor_host_attach_unavailable",
                                        _reason(error)) from None

    # --- one bounded iteration --------------------------------------------

    def run_once(self):
        from .contracts import IdentityStatus

        if self.guardian is None:
            raise SupervisorHostRefused("supervisor_host_not_started")
        if self.supervisor is None:
            # A guardian that could not be attached is never observed through a
            # closed supervisor. The iteration says so and retries the attach
            # against the same live guardian under the same epoch.
            return self._retry_attach()
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
        # UNKNOWN holds. Only a verified death may lead to a replacement, and
        # only after this supervisor settles its own custody.
        if result.guardian_status is IdentityStatus.DEAD:
            record["replacement"] = self._replace()
        return record

    def supervise_until_stopped(self):
        """Tick until the process is interrupted. The guardian is left alone."""
        iterations = 0
        try:
            while True:
                emit(self.run_once())
                iterations += 1
                self._sleep(self.tick_interval_sec)
        except KeyboardInterrupt:
            return {"event": "supervisor_host_stopping", "reason": "interrupted",
                    "iterations": iterations}

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
            self.supervisor = self._attach(self.guardian)
        except SupervisorHostRefused as error:
            record["reason"], record["detail"] = error.reason, error.detail
            return record
        record["attached"] = True
        return record

    def _replace(self):
        """Close first. A new guardian is a new epoch or it does not happen."""
        try:
            self.supervisor.close()
        except Exception as error:
            # Custody is unsettled, so nothing is removed and the row stays.
            return {"started": False, "reason": _reason(error)}
        # A closed supervisor is never ticked again. Dropping the reference here
        # is what makes the next iteration take the unattached path.
        self.supervisor = None
        previous = self.guardian
        removed, registry_reason = self._unregister(previous)
        registry = {"registry_removed": removed, "registry_reason": registry_reason}
        if self.started_guardians >= self.max_guardians:
            return {"started": False, "reason": "supervisor_host_guardian_budget_exhausted",
                    **registry}
        try:
            replacement = self._start_guardian(previous_epoch=previous.epoch)
        except SupervisorHostRefused as error:
            return {"started": False, "reason": error.reason, **registry}
        # The settled predecessor stays reachable until this host shuts down,
        # so its creation handle is released in one place with a reported
        # outcome instead of silently during a tick.
        self.retired.append(previous)
        self.guardian = replacement
        try:
            self.supervisor = self._attach(replacement)
        except SupervisorHostRefused as error:
            return {"started": True, "attached": False, "reason": error.reason,
                    "guardian_epoch": replacement.epoch, **registry}
        return {"started": True, "attached": True, "guardian_epoch": replacement.epoch,
                "previous_epoch": previous.epoch, **registry}

    def _unregister(self, guardian):
        """Remove the dead guardian's infrastructure row under POLICY.

        The guardian registered itself at startup and cannot remove its own row
        afterwards, so the row would stay until the capped registry refuses the
        next registration. The retained witness this host created is the only
        death evidence that exists for that guardian, and
        unregister_dead_infrastructure_locked re-verifies death on it. Nothing
        here reopens a PID, deletes by epoch or writes the table itself.

        The return is the pair reported in the replacement record. False with no
        reason means the row was already absent.

        A refusal the writer decided before its transaction, which is what
        legacy_infrastructure_death_unverified and
        legacy_infrastructure_identity_required are, releases the POLICY entry
        on the way out, so the next guardian start can still register. A failure
        at or after that transaction keeps the entry, because the ledger outcome
        is then unknown, and the next POLICY user of this data directory sees
        policy_scope_busy.
        """
        from .legacy_writer import LegacyMutationError, unregister_dead_infrastructure_locked

        policy = self.store._policy
        try:
            guard = policy.prepare(policy.current_logon())
            with policy.hold(guard):
                removed = unregister_dead_infrastructure_locked(self.store, "guardian",
                                                                guardian.process)
        except Exception as error:
            # LegacyMutationError carries its stable code as the message, the
            # same convention LifecycleError uses. Anything else reports the
            # type name _reason gives it.
            code = str(error)
            if isinstance(error, LegacyMutationError) and _STABLE_CODE.fullmatch(code):
                return False, code
            return False, _reason(error)
        return bool(removed), None

    # --- shutdown ---------------------------------------------------------

    def close(self):
        """Stop supervising. Nothing here stops the guardian.

        The guardian keeps running and is now unsupervised, and the result says
        so. This host has no kill path, and ending a guardian that still owns
        Jobs is exactly what the design forbids. A child with no witness is
        reported too, and the entry point turns that into a non clean exit.
        """
        if self.supervisor is not None:
            try:
                self.supervisor.close()
            except Exception as error:
                raise SupervisorHostRefused("supervisor_host_custody_unsettled",
                                            _reason(error)) from None
        cleanup = []
        for retired in self.retired:
            try:
                self.creation.close_handle(retired.creation_handle)
            except SupervisorHostRefused as error:
                cleanup.append(error.reason)
        return {"event": "supervisor_host_closed", "cleanup_errors": cleanup,
                "guardian_epoch": None if self.guardian is None else self.guardian.epoch,
                "guardian_left_running": self.guardian is not None,
                "unverified": list(self.unverified),
                "unsettled_captures": [{"epoch": item["epoch"], "reason": item["reason"]}
                                       for item in self.unsettled_captures]}


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel.adaptive.supervisor_host",
        description="Start one guardian and observe it for a bounded number of ticks.")
    parser.add_argument("--data-dir", required=True, help="directory holding sentinel.db")
    parser.add_argument("--journal-dir", required=True, help="recovery manifest directory")
    parser.add_argument("--iterations", type=int, default=0,
                        help="0 ticks until the process is interrupted; a positive "
                             "value is the bounded test and diagnostic mode")
    parser.add_argument("--guardian-iterations", type=int, default=0,
                        help="iterations passed to the guardian child; 0 leaves the "
                             "child running until it is interrupted")
    parser.add_argument("--max-guardians", type=int, default=1,
                        help="how many guardian processes this host may start in total")
    parser.add_argument("--child-cwd", default=None, help="working directory for the child")
    parser.add_argument("--python", default=None, help="interpreter used for the child")
    parser.add_argument("--profile", default=None, help="policy profile JSON file for the child")
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if options.iterations < 0 or options.guardian_iterations < 0 or options.max_guardians < 1:
        emit({"event": "supervisor_host_refused", "reason": "supervisor_host_arguments_invalid"})
        return EXIT_REFUSED
    host = SupervisorHost(data_dir=options.data_dir, journal_dir=options.journal_dir,
                          child_cwd=options.child_cwd, python_executable=options.python,
                          profile_path=options.profile, max_guardians=options.max_guardians,
                          guardian_iterations=options.guardian_iterations)
    try:
        emit(host.start())
    except SupervisorHostRefused as error:
        # A refusal after the child was created leaves a guardian behind. The
        # record names it, and that case is not a clean refusal.
        child = host.guardian is not None or bool(host.unverified)
        emit({"event": "supervisor_host_refused", "reason": error.reason, "detail": error.detail,
              "guardian_created": child,
              "guardian_epoch": None if host.guardian is None else host.guardian.epoch,
              "guardian_pid": None if host.guardian is None else host.guardian.pid,
              "unverified": list(host.unverified)})
        return EXIT_UNSETTLED if child else EXIT_REFUSED
    try:
        if options.iterations == 0:
            emit(host.supervise_until_stopped())
        else:
            for _ in range(options.iterations):
                emit(host.run_once())
    except KeyboardInterrupt:
        emit({"event": "supervisor_host_stopping", "reason": "interrupted"})
    try:
        record = host.close()
    except SupervisorHostRefused as error:
        emit({"event": "supervisor_host_refused", "reason": error.reason, "detail": error.detail})
        return EXIT_UNSETTLED
    emit(record)
    # A child with no witness or a partial capture that would not close is not
    # a clean exit, even though the supervision itself settled.
    return EXIT_UNSETTLED if record["unverified"] or record["unsettled_captures"] else EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
