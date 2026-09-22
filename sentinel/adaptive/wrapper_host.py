"""Runnable wrapper host: py -m sentinel.adaptive.wrapper_host run-managed ...

This is the workload side of the design. It asks the coordinator for capacity,
asks the guardian to prepare and authorize one launch, creates the root process
once inside the guardian's Job, waits for that exact retained process, and
returns its exit code.

The host owns no policy. Readiness comes from the live HostAuthority, capacity
comes from the existing Coordinator, and every lifecycle transition comes from
the guardian over the authenticated pipe. Nothing here sets a CPU rate, kills,
suspends or trims a process, writes a ledger mode, or touches a user exemption.

Refusal is the default. A refused managed launch never falls back to running the
command outside the managed path. With --require-managed the process exits with
EXIT_REFUSED and the typed reason. Without it the process reports unmanaged and
still does not run the command, because this host has no unmanaged launch path
to fall back to.

stdout belongs to the workload. Every record this host writes goes to stderr,
and the workload inherits the real stdin, stdout and stderr handles.

Exit codes: the root process exit code on a completed managed run, EXIT_REFUSED
for a refusal that happened before any process was created, EXIT_UNMANAGED for
the same case without --require-managed, and EXIT_POST_LAUNCH for a refusal
after a create was attempted. The last one is separate on purpose. A caller
must not read it as nothing ran, because the workload may be running and its
custody belongs to the guardian. A workload can return those same small
integers, so a caller that needs certainty reads the JSON event record on
stderr, which carries launch_state and command_started.

Failure cleanup stays with the original wrapper. Exact queued/unused RESERVED
attempts may be abandoned through the original admission context; prepared
scopes require the guardian's proof. Any unresolved launch or native cleanup
keeps this host alive in owned recovery. Refusal, timeout and Ctrl+C are never
evidence that workload descendants ended or that capacity was released.

On a machine whose processes run inside a parent Job the capability preflight
refuses with host_foreign_parent_job before anything is opened, and that is the
expected result there.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import math
from pathlib import Path
import re
import signal
import sys
import time

from .host_authority import HostAuthority, HostCapabilityUnsupported, read_host_capability
from .store import LifecycleError


# A stable code is a lowercase identifier. Anything else is free text.
_STABLE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
EXIT_REFUSED = 3
EXIT_UNMANAGED = 4
EXIT_POST_LAUNCH = 5
DEFAULT_RPC_TIMEOUT_MS = 1000
DEFAULT_POLL_INTERVAL_MS = 100
_GIB = 1 << 30
# What this host knows about the root process when it reports a refusal.
NOT_ATTEMPTED = "not_attempted"
ATTEMPTED_UNKNOWN = "attempted_unknown"
LAUNCHED = "launched"


class WrapperHostRefused(RuntimeError):
    """A managed launch was refused, with a stable reason."""

    def __init__(self, reason, detail=None):
        self.reason = reason
        self.detail = detail
        super().__init__(reason)


def emit(record, stream=None):
    """One JSON record per line on stderr, so stdout stays free for the workload."""
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


def _load_json(path, reason):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except Exception as error:
        raise WrapperHostRefused(reason, _reason(error)) from None
    if type(value) is not dict:
        raise WrapperHostRefused(reason, "not_an_object")
    return value


def stdio_handles():
    """The real OS handles for fd 0, 1 and 2.

    The workload inherits these, so its output reaches the caller's console
    directly. An unusable descriptor refuses rather than substituting a null
    device the caller did not ask for.
    """
    try:
        import msvcrt
    except ImportError:
        raise WrapperHostRefused("wrapper_host_stdio_unavailable", "msvcrt") from None
    handles = []
    for fd in (0, 1, 2):
        try:
            handle = msvcrt.get_osfhandle(fd)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_stdio_unavailable", f"fd{fd}:{_reason(error)}") from None
        if type(handle) is not int or handle <= 0:
            raise WrapperHostRefused("wrapper_host_stdio_unavailable", f"fd{fd}")
        handles.append(handle)
    return tuple(handles)


class WrapperHost:
    """One managed execution attempt. Construct, run, and read the exit code.

    ``launcher_factory`` is an in-process seam for tests, the same kind the
    launcher itself exposes for its Job and create calls. It receives the live
    readiness object built here; it is not a way to supply a readiness receipt.
    """

    def __init__(self, *, data_dir, command, cwd, repo_identifier, role, priority,
                 requested, guardian_epoch, guardian_pid, guardian_created_filetime_100ns,
                 endpoint_instance_id, status_path=None, config_path=None,
                 admission_timeout_sec=None, rpc_timeout_ms=DEFAULT_RPC_TIMEOUT_MS,
                 poll_interval_ms=DEFAULT_POLL_INTERVAL_MS, max_wait_sec=0,
                 launcher_factory=None):
        self.data_dir = Path(data_dir)
        self.command = command
        self.cwd = cwd
        self.repo_identifier = repo_identifier
        self.role = role
        self.priority = priority
        self.requested = requested
        self.guardian_epoch = guardian_epoch
        self.guardian_pid = guardian_pid
        self.guardian_created_filetime_100ns = guardian_created_filetime_100ns
        self.endpoint_instance_id = endpoint_instance_id
        self.status_path = Path(self.data_dir / "status.json" if status_path is None else status_path)
        self.config_path = Path(self.data_dir / "config.json" if config_path is None else config_path)
        self.admission_timeout_sec = admission_timeout_sec
        self.rpc_timeout_ms = rpc_timeout_ms
        self.poll_interval_ms = poll_interval_ms
        self.max_wait_sec = max_wait_sec
        self.launcher_factory = launcher_factory
        if (type(rpc_timeout_ms) is not int or not 1 <= rpc_timeout_ms <= 1000 or
                type(poll_interval_ms) is not int or poll_interval_ms < 1 or
                type(max_wait_sec) is not int or max_wait_sec < 0):
            # One place for both entry paths. The command line parser converts
            # types; the bounds live here so a direct construction gets them too.
            raise WrapperHostRefused("wrapper_host_arguments_invalid")
        # What is known about the root process, reported with every refusal.
        self.launch_state = NOT_ATTEMPTED
        self.capability = None
        self.logon_id = None
        self.coordinator = self.store = self.readiness = None
        self.endpoint = self.launcher = None
        self._construction_unknown = None
        self._recovery_errors = []
        self._interrupt_requested = self._recovering = False

    # --- preflight --------------------------------------------------------

    def _capability(self):
        try:
            return read_host_capability()
        except HostCapabilityUnsupported as error:
            raise WrapperHostRefused(error.reason, error.win32_error) from None

    def _spec(self):
        from .launch_spec import LaunchSpec

        fields = {"command": self.command, "cwd": self.cwd,
                  "repo_identifier": self.repo_identifier, "requested": self.requested,
                  "role": self.role, "priority": self.priority}
        if self.admission_timeout_sec is not None:
            fields["admission_timeout_sec"] = self.admission_timeout_sec
        try:
            return LaunchSpec(**fields)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_launch_spec_invalid", _reason(error)) from None

    def _logon(self):
        """The live logon SID of this process, read from its own token."""
        from .identity import VerifiedProcess

        try:
            with VerifiedProcess.current() as current:
                return current.identity.logon_id
        except BaseException as error:
            if (getattr(error, "_identity_handle_cleanup", ()) or
                    getattr(error, "_policy_mutex_cleanup", ()) or getattr(error, "__notes__", ())):
                self._construction_unknown = error
            if not isinstance(error, Exception):
                raise
            raise WrapperHostRefused("wrapper_host_identity_unavailable", _reason(error)) from None

    def _guardian_endpoint(self):
        """Bind to the guardian's pipe identity.

        The guardian's pid and creation FILETIME are supplied by the caller
        because no record publishes them. They are checked by the pipe layer
        against the server that answers, so a wrong pair fails the RPC instead
        of silently connecting to some other process.
        """
        from .contracts import ProcessIdentity
        from .pipe_windows import NativePipeEndpoint

        try:
            # The contract is constructed directly because from_dict is the
            # wire form and wants a canonical decimal string. These values
            # arrive as integers from the command line.
            identity = ProcessIdentity(self.guardian_pid,
                                       self.guardian_created_filetime_100ns, self.logon_id)
            return NativePipeEndpoint(self.logon_id, self.endpoint_instance_id, identity)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_endpoint_invalid", _reason(error)) from None

    def _readiness(self):
        from .store import LifecycleStore

        try:
            self.store = LifecycleStore(self.coordinator.db_path, existing_path=True)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_ledger_unavailable", _reason(error)) from None
        # The wrapper proves host capability, admission coverage and endpoint
        # binding. It deliberately does not claim legacy writer exclusion; that
        # proof needs POLICY, which the guardian holds. See host_authority.
        return HostAuthority(self.store)

    def _coordinator(self):
        from sentinel.coordinator import Coordinator

        try:
            return Coordinator(self.data_dir)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_coordinator_unavailable", _reason(error)) from None

    def _build_launcher(self, spec):
        from .launcher import ManagedLauncher

        factory = ManagedLauncher if self.launcher_factory is None else self.launcher_factory
        try:
            return factory(spec, coordinator=self.coordinator, endpoint=self.endpoint,
                           guardian_epoch=self.guardian_epoch, readiness=self.readiness)
        except BaseException as error:
            owner = getattr(error, "launcher_owner", None)
            if owner is not None:
                self.launcher = owner
            elif (getattr(error, "_identity_handle_cleanup", ()) or
                  getattr(error, "_policy_mutex_cleanup", ()) or
                  getattr(error, "__notes__", ())):
                # No fabricated launcher/context can inherit this authority.
                self._construction_unknown = error
            if not isinstance(error, Exception):
                raise
            raise WrapperHostRefused("wrapper_host_launcher_unavailable", _reason(error)) from None

    # --- the managed run --------------------------------------------------

    def run(self):
        """Admit, launch, wait, and return the root exit code.

        Every failure raises WrapperHostRefused. The command is never started
        outside this path.
        """
        self.capability = self._capability()
        self.logon_id = self._logon()
        handles = stdio_handles()
        status = _load_json(self.status_path, "wrapper_host_status_unavailable")
        config = _load_json(self.config_path, "wrapper_host_config_unavailable")
        spec = self._spec()
        self.coordinator = self._coordinator()
        self.readiness = self._readiness()
        self.endpoint = self._guardian_endpoint()
        self.launcher = self._build_launcher(spec)
        self._check_interrupt()
        emit({"event": "wrapper_host_attempt", "execution_id": self.launcher.execution_id,
              "guardian_epoch": self.guardian_epoch, "endpoint": self.endpoint.name,
              "capability": self.capability.to_dict()})
        self._admit(status, config)
        self._check_interrupt()
        self._launch(handles)
        self._check_interrupt()
        observation = self._wait()
        self._close()
        return observation.exit_code

    def _check_interrupt(self):
        if self._interrupt_requested and not self._recovering:
            self._recovering = True
            raise KeyboardInterrupt()

    def _admit(self, status, config):
        try:
            result = self.launcher.admit_once(status, config=config)
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_admission_unknown", _reason(error)) from None
        if not result.get("allowed"):
            # A denial is the coordinator's answer to this exact request. The
            # wrapper does not resubmit, requeue or wait here.
            raise WrapperHostRefused("wrapper_host_admission_denied",
                                     result.get("reason") or result.get("state"))
        emit({"event": "wrapper_host_admitted", "execution_id": self.launcher.execution_id,
              "reservation_id": result.get("reservation_id"),
              "state_revision": result.get("state_revision")})

    def _launch(self, handles):
        """One create, then at most one exact bind replay.

        Lost acknowledgements pass to owned recovery. The host cannot infer a
        guardian handoff or exit merely because the remote mutation may exist.
        """
        from . import native_launcher
        from .launcher import ManagedLaunchError

        stdin_handle, stdout_handle, stderr_handle = handles
        try:
            self.launcher.launch_once(stdin_handle=stdin_handle, stdout_handle=stdout_handle,
                                      stderr_handle=stderr_handle, timeout_ms=self.rpc_timeout_ms)
        except native_launcher.LaunchOutcomeUnknown as error:
            # A create was attempted and its outcome is unknown. That stays
            # true whether or not the bind replay succeeds.
            self.launch_state = ATTEMPTED_UNKNOWN
            emit({"event": "wrapper_host_launch_unknown", "reason": _reason(error)})
            try:
                self.launcher.reconcile_bind(timeout_ms=self.rpc_timeout_ms)
            except Exception as replay:
                raise WrapperHostRefused("wrapper_host_launch_outcome_unknown",
                                         _reason(replay)) from None
            self.launch_state = LAUNCHED
        except ManagedLaunchError as error:
            self.launch_state = self._state_after_failure()
            raise WrapperHostRefused("wrapper_host_launch_refused", _reason(error)) from None
        except Exception as error:
            self.launch_state = self._state_after_failure()
            raise WrapperHostRefused("wrapper_host_launch_unverified", _reason(error)) from None
        else:
            self.launch_state = LAUNCHED
        emit({"event": "wrapper_host_launched", "execution_id": self.launcher.execution_id,
              "phase": self.launcher.phase, "launch_state": self.launch_state})

    def _state_after_failure(self):
        """Read the launcher's own record of whether a create was attempted.

        The launcher sets _create_attempted immediately before the native call
        and keeps the retained process afterwards. A refusal before that point
        genuinely started nothing; one after it did.
        """
        launcher = self.launcher
        if getattr(launcher, "_create_attempted", False) is not True:
            return NOT_ATTEMPTED
        return LAUNCHED if getattr(launcher, "_root", None) is not None else ATTEMPTED_UNKNOWN

    def _wait(self):
        """Wait for the exact retained root process.

        An expired wait is not a death, not a release and not an empty Job. It
        refuses and leaves custody alone.
        """
        deadline = None if self.max_wait_sec <= 0 else time.monotonic() + self.max_wait_sec
        interval = self.poll_interval_ms / 1000
        while True:
            self._check_interrupt()
            try:
                observation = self.launcher.poll_root()
            except Exception as error:
                raise WrapperHostRefused("wrapper_host_root_unverified", _reason(error)) from None
            if observation.exited:
                emit({"event": "wrapper_host_root_exited",
                      "execution_id": observation.execution_id,
                      "exit_code": observation.exit_code})
                return observation
            if deadline is not None and time.monotonic() >= deadline:
                raise WrapperHostRefused("wrapper_host_root_wait_expired")
            time.sleep(interval)

    def _close(self):
        try:
            self.launcher.close_local()
        except Exception as error:
            raise WrapperHostRefused("wrapper_host_close_unverified", _reason(error)) from None

    def release(self):
        """One bounded original-owner abandonment attempt, never an exit permit."""
        if self._construction_unknown is not None:
            return {"settled": False, "closed": False, "guardian_handoff": False,
                    "state": "CONSTRUCTION_UNKNOWN", "reason": "wrapper_host_construction_cleanup_unknown"}
        if self.launcher is None:
            return None
        try:
            return self.launcher.abandon_once(timeout_ms=self.rpc_timeout_ms)
        except BaseException as error:
            self._note_recovery_error(error)
            return {"settled": False, "closed": False, "guardian_handoff": False,
                    "state": "RECOVERY_PENDING", "reason": _reason(error)}

    def _note_recovery_error(self, error):
        # Repeated observation failures/interrupts must not grow memory while
        # waiting. Native owners live on the launcher or construction hold.
        if len(self._recovery_errors) < 32 and not any(
                type(previous) is type(error) and _reason(previous) == _reason(error)
                for previous in self._recovery_errors):
            self._recovery_errors.append(error)

    def settle_release(self, *, initial=None, max_iterations=None):
        """Keep the original owner until positively settled.

        The optional iteration bound is an in-process test/embedding seam. The
        CLI has no bound and cannot use an observer timeout or a second Ctrl+C
        to discard its only uncertain native owner. No work is relaunched here.
        """
        if max_iterations is not None and (type(max_iterations) is not int or max_iterations < 1):
            raise ValueError("wrapper_host_settle_bound_invalid")
        current = initial
        previous = None
        iterations = 0
        while True:
            if current is None:
                current = self.release()
            if current is None or (current.get("settled") is True and
                                   (current.get("closed") is True or current.get("guardian_handoff") is True)):
                return current
            iterations += 1
            if current != previous:
                try:
                    emit({"event": "wrapper_host_recovery_pending", "release": current})
                except BaseException as error:
                    self._note_recovery_error(error)
                previous = dict(current)
            if max_iterations is not None and iterations >= max_iterations:
                return current
            try:
                time.sleep(self.poll_interval_ms / 1000)
            except BaseException as error:
                # Neither another console interrupt nor failed reporting is
                # positive custody/release evidence. Keep the same owner.
                self._note_recovery_error(error)
            current = self.release()


def parse_demand(options):
    """Build the typed demand from the estimate arguments."""
    from .contracts import ResourceDemand

    commit_gib = options.ram_gib if options.commit_gib is None else options.commit_gib
    try:
        # Round up. A fractional GiB estimate must never be recorded as less
        # than the caller asked for.
        physical_bytes = math.ceil(options.ram_gib * _GIB)
        commit_bytes = math.ceil(commit_gib * _GIB)
    except (ValueError, OverflowError):
        raise WrapperHostRefused("wrapper_host_demand_invalid", str(options.ram_gib)) from None
    if physical_bytes < 0 or commit_bytes < 0:
        raise WrapperHostRefused("wrapper_host_demand_invalid", str(options.ram_gib))
    if int(physical_bytes / _GIB * _GIB) != physical_bytes:
        # This mirrors admission.py:123-125 so an oversized estimate is named
        # here rather than at the admission boundary. Scaling by a power of two
        # is exact, so it can only trigger above 2**53 bytes.
        raise WrapperHostRefused("wrapper_host_demand_inexact", str(options.ram_gib))
    try:
        return ResourceDemand(cpu_units=float(options.cpu_units), physical_bytes=physical_bytes,
                              commit_bytes=commit_bytes, io_slots=int(options.io_slots))
    except Exception as error:
        raise WrapperHostRefused("wrapper_host_demand_invalid", _reason(error)) from None


def parse_role_priority(options):
    from .contracts import Priority, Role

    try:
        return Role(options.role), Priority(options.priority)
    except ValueError as error:
        raise WrapperHostRefused("wrapper_host_role_or_priority_invalid", str(error)) from None


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel.adaptive.wrapper_host",
        description="Run one command as a managed execution under the guardian.")
    verbs = parser.add_subparsers(dest="verb", required=True)
    run = verbs.add_parser("run-managed", help="admit, launch and wait for one managed command")
    run.add_argument("--data-dir", required=True, help="directory holding sentinel.db and status.json")
    run.add_argument("--command", required=True, help="the workload command line")
    run.add_argument("--cwd", required=True, help="working directory for the workload")
    run.add_argument("--repo", required=True, dest="repo_identifier", help="repository identifier")
    run.add_argument("--role", default="neutral", choices=["background", "protected", "neutral"])
    run.add_argument("--priority", default="P2", choices=["P0", "P1", "P2", "P3"])
    run.add_argument("--cpu-units", type=float, required=True, help="estimated CPU units")
    run.add_argument("--ram-gib", type=float, required=True, help="estimated physical RAM in GiB")
    run.add_argument("--commit-gib", type=float, default=None, help="estimated commit in GiB")
    run.add_argument("--io-slots", type=int, default=0, help="estimated I/O slots")
    run.add_argument("--guardian-epoch", required=True, help="epoch the guardian reported")
    run.add_argument("--guardian-pid", type=int, required=True, help="guardian process id")
    run.add_argument("--guardian-created-filetime", type=int, required=True,
                     dest="guardian_created_filetime_100ns",
                     help="guardian creation FILETIME in 100ns units")
    run.add_argument("--endpoint-instance-id", required=True, help="guardian launch pipe instance id")
    run.add_argument("--status-file", default=None, help="capacity status JSON, default data-dir/status.json")
    run.add_argument("--config-file", default=None, help="policy config JSON, default data-dir/config.json")
    run.add_argument("--admission-timeout-sec", type=int, default=None, help="launch spec admission timeout")
    run.add_argument("--rpc-timeout-ms", type=int, default=DEFAULT_RPC_TIMEOUT_MS,
                     help="per RPC deadline in milliseconds")
    run.add_argument("--poll-interval-ms", type=int, default=DEFAULT_POLL_INTERVAL_MS,
                     help="root poll interval in milliseconds")
    run.add_argument("--max-wait-sec", type=int, default=0,
                     help="bound on waiting for the root process, 0 waits until it exits")
    run.add_argument("--require-managed", action="store_true",
                     help="exit with the typed reason when the managed launch is refused")
    return parser


@contextmanager
def _owned_interrupts(host):
    """Convert console SIGINT into a request at an owned safe boundary.

    A Python signal exception can otherwise land between native ownership
    publication statements, or inside an except suite performing recovery.
    The handler only records intent; repeated signals cannot discard custody.
    Embedded calls on a non-main thread keep the caller's signal handling.
    """
    previous = None
    installed = False
    def request_interrupt(signum, frame):
        host._interrupt_requested = True
    try:
        try:
            previous = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, request_interrupt)
            installed = True
        except ValueError:
            pass
        yield
    finally:
        if installed:
            signal.signal(signal.SIGINT, previous)


def main(argv=None):
    options = build_parser().parse_args(argv)
    try:
        role, priority = parse_role_priority(options)
        requested = parse_demand(options)
        host = WrapperHost(data_dir=options.data_dir, command=options.command, cwd=options.cwd,
                           repo_identifier=options.repo_identifier, role=role, priority=priority,
                           requested=requested, guardian_epoch=options.guardian_epoch,
                           guardian_pid=options.guardian_pid,
                           guardian_created_filetime_100ns=options.guardian_created_filetime_100ns,
                           endpoint_instance_id=options.endpoint_instance_id,
                           status_path=options.status_file, config_path=options.config_file,
                           admission_timeout_sec=options.admission_timeout_sec,
                           rpc_timeout_ms=options.rpc_timeout_ms,
                           poll_interval_ms=options.poll_interval_ms,
                           max_wait_sec=options.max_wait_sec)
    except WrapperHostRefused as error:
        return _refused(error, options.require_managed, None)
    with _owned_interrupts(host):
        try:
            exit_code = host.run()
        except BaseException as error:
            host._recovering = True
            host._note_recovery_error(error)
            if isinstance(error, WrapperHostRefused):
                refusal = error
            else:
                host.launch_state = host._state_after_failure()
                reason = "wrapper_host_interrupted" if isinstance(error, KeyboardInterrupt) else "wrapper_host_unverified"
                refusal = WrapperHostRefused(reason, _reason(error))
            while True:
                try:
                    return _refused(refusal, options.require_managed, host)
                except BaseException as recovery_error:
                    # Also cover injected/non-signal interruptions at call or
                    # publication boundaries, not only at sleep/emit sites.
                    host._note_recovery_error(recovery_error)
    emit({"event": "wrapper_host_finished", "exit_code": exit_code})
    return exit_code


def _refused(error, require_managed, host):
    """Report the refusal with what is actually known about the root process.

    Before a create is attempted the command really did not start, and that is
    the only case that reports a clean pre launch refusal. After a create was
    attempted the report says so and the exit code changes, because a caller
    must not read it as nothing ran.
    """
    state = NOT_ATTEMPTED if host is None else host.launch_state
    post_launch = state != NOT_ATTEMPTED
    if post_launch:
        event = "wrapper_host_post_launch_refused"
    else:
        event = "wrapper_host_refused" if require_managed else "wrapper_host_unmanaged"
    record = {"event": event, "reason": error.reason, "detail": error.detail,
              "launch_state": state, "command_started": None if state == ATTEMPTED_UNKNOWN
              else state == LAUNCHED}
    if host is not None:
        initial = host.release()
        if initial is not None and not initial.get("settled"):
            # Report before entering recovery, so a pending wrapper is visible.
            try:
                emit(dict(record, release=initial))
            except BaseException as report_error:
                host._note_recovery_error(report_error)
        record["release"] = host.settle_release(initial=initial)
    emit(record)
    if post_launch:
        return EXIT_POST_LAUNCH
    return EXIT_REFUSED if require_managed else EXIT_UNMANAGED


if __name__ == "__main__":
    raise SystemExit(main())
