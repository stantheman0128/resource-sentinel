"""Runnable guardian process host: py -m sentinel.adaptive.guardian_host.

This wires the existing libraries into one process. It owns no policy of its
own. The launch owner, the lifecycle dispatcher, the control consumer, the
recovery journal and the two pipe services are the production modules, and the
host authority is the live one in host_authority.py.

One iteration serves at most one launch RPC and one query RPC with a bounded
deadline, reconciles every retained execution, and calls the control consumer's
expiry sweep. Nothing here starts a thread or keeps a request queue of its own.

The default mode runs iterations until the process is stopped. The only stop
condition that exists in this repository today is an interrupt delivered to the
process, which Python raises as KeyboardInterrupt. There is no service control
handler, no named stop event and no ledger flag that means stop, and this host
does not invent one. A positive --iterations is the explicit bounded mode for
tests and diagnostics.

A stop never abandons custody. Once stopping, the host stops serving new launch
requests and keeps reconciling and sweeping until no execution is retained. Only
then does it close. Exiting with a retained execution would drop the Job handles
and the only normal actuator, so it is never done voluntarily.

What this host never does: it never terminates, suspends or trims a process,
never sets a CPU rate, never writes a ledger mode, and never touches a user
exemption. The control consumer is the only actuator in the design, and it
already refuses every mode outside canary and limited, so no second mode switch
is added here that could disagree with it.

Startup refuses before it opens anything when the host capability preflight
refuses. On a machine whose processes run inside a parent Job the refusal is
host_foreign_parent_job, and that is the expected result there.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time
from uuid import uuid4

from .host_authority import HostAuthority, HostCapabilityUnsupported, read_host_capability
from .store import LifecycleError


EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_UNSETTLED = 4
DEFAULT_RPC_TIMEOUT_MS = 1000
DEFAULT_PROFILE = Path(__file__).resolve().parents[2] / "config" / "adaptive.example.json"
# A stable code is a lowercase identifier. Anything else is free text.
_STABLE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")


class GuardianHostRefused(RuntimeError):
    """Startup or shutdown refused with a stable reason."""

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
    LifecycleError, carry the stable code as the message itself. Anything
    else reports only its type, so no path or command text reaches a record.
    """
    value = getattr(error, "reason", None)
    if type(value) is str and value:
        return value
    if isinstance(error, LifecycleError) and _STABLE_CODE.fullmatch(str(error)):
        return str(error)
    return type(error).__name__


class GuardianHost:
    """One guardian process. Construct, start, run iterations, then close."""

    def __init__(self, *, data_dir, journal_dir, guardian_epoch, profile_path=None,
                 rpc_timeout_ms=DEFAULT_RPC_TIMEOUT_MS, launch_instance_id=None,
                 query_instance_id=None, sleep=time.sleep):
        self.data_dir = Path(data_dir)
        self.journal_dir = Path(journal_dir)
        self.guardian_epoch = guardian_epoch
        self.profile_path = Path(DEFAULT_PROFILE if profile_path is None else profile_path)
        self.rpc_timeout_ms = rpc_timeout_ms
        # Paces the drain loop only. It is a test seam, never a timing claim.
        self._sleep = sleep
        self.launch_instance_id = str(uuid4()) if launch_instance_id is None else launch_instance_id
        self.query_instance_id = str(uuid4()) if query_instance_id is None else query_instance_id
        self.capability = None
        self.store = self.journal = self.guardian = self.authority = None
        self.owner = self.control = None
        self.launch_endpoint = self.query_endpoint = None
        self.launch_service = self.query_service = None
        self.launch_listener = self.query_listener = None
        self.registered = False
        self._started = False

    # --- startup ----------------------------------------------------------

    def start(self):
        """Refuse before touching the ledger when the host cannot support this."""
        from .decision import parse_policy_profile
        from .guardian import GuardianLaunchOwner
        from .guardian_control import GuardianControl
        from .identity import VerifiedProcess
        from .recovery_journal import RecoveryJournal
        from .store import LifecycleStore

        self.capability = self._capability()
        profile = self._profile(parse_policy_profile)
        db_path = self.data_dir / "sentinel.db"
        try:
            self.store = LifecycleStore(db_path, existing_path=True)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_ledger_unavailable", _reason(error)) from None
        try:
            self.journal = RecoveryJournal(self.journal_dir)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_journal_unavailable", _reason(error)) from None
        try:
            self.guardian = VerifiedProcess.current()
        except Exception as error:
            raise GuardianHostRefused("guardian_host_identity_unavailable", _reason(error)) from None
        self.authority = HostAuthority(self.store, guardian=self.guardian)
        try:
            self.owner = GuardianLaunchOwner(self.store, self.journal,
                                             guardian_epoch=self.guardian_epoch,
                                             authority=self.authority, guardian=self.guardian)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_owner_unavailable", _reason(error)) from None
        self._register()
        self._endpoints()
        try:
            self.control = GuardianControl(self.owner, profile=profile,
                                           exemptions=self.data_dir / "exemptions.sqlite3")
        except Exception as error:
            raise GuardianHostRefused("guardian_host_control_unavailable", _reason(error)) from None
        self._started = True
        return {"event": "guardian_host_started", "guardian_epoch": self.guardian_epoch,
                "pid": self.capability.pid, "launch_endpoint": self.launch_endpoint.name,
                "query_endpoint": self.query_endpoint.name,
                "launch_instance_id": self.launch_instance_id,
                "query_instance_id": self.query_instance_id,
                "profile": str(self.profile_path), "capability": self.capability.to_dict()}

    @staticmethod
    def _capability():
        try:
            return read_host_capability()
        except HostCapabilityUnsupported as error:
            raise GuardianHostRefused(error.reason, error.win32_error) from None

    def _profile(self, parse):
        try:
            return parse(self.profile_path.read_bytes())
        except Exception as error:
            raise GuardianHostRefused("guardian_host_profile_unavailable", _reason(error)) from None

    def _register(self):
        """Publish this guardian in the infrastructure registry under POLICY.

        The guarded legacy writer reads that registry and skips every identity
        in it, which is the fact the host authority later asserts. Registration
        is a ledger write, never a mode change.

        It writes to whatever sentinel.db --data-dir names. Pointing this host
        at the daily data directory therefore writes the registry table into
        the daily ledger.
        """
        from .legacy_writer import initialize_registry_locked, register_infrastructure_locked

        policy = self.store._policy
        try:
            guard = policy.prepare(policy.current_logon())
            with policy.hold(guard):
                initialize_registry_locked(self.store)
                register_infrastructure_locked(self.store, "guardian", self.guardian)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_registry_unavailable", _reason(error)) from None
        self.registered = True

    def _endpoints(self):
        from .ipc import LifecycleQueryService
        from .launch_transport import LaunchService
        from .pipe_windows import NativePipeEndpoint, NativePipeListener

        identity = self.guardian.identity
        try:
            self.launch_endpoint = NativePipeEndpoint(identity.logon_id, self.launch_instance_id, identity)
            self.query_endpoint = NativePipeEndpoint(identity.logon_id, self.query_instance_id, identity)
            self.launch_service = LaunchService(self.store.db_path, self.launch_endpoint, self.owner)
            self.query_service = LifecycleQueryService(self.store.db_path, self.query_endpoint)
            self.launch_listener = NativePipeListener(self.launch_endpoint)
            self.query_listener = NativePipeListener(self.query_endpoint)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_endpoint_unavailable", _reason(error)) from None

    # --- one bounded iteration --------------------------------------------

    def run_once(self, *, serve_launch=True):
        """Serve at most one RPC of each kind, reconcile, then sweep leases.

        ``serve_launch`` is false while draining. A stopping guardian must not
        take on new custody, but it keeps answering the read only query service
        so callers can still observe what it is finishing.
        """
        if not self._started:
            raise GuardianHostRefused("guardian_host_not_started")
        record = {"event": "guardian_host_iteration", "launch_rpc": None, "query_rpc": None,
                  "reconciled": [], "reconcile_errors": [], "restored": []}
        if serve_launch:
            record["launch_rpc"] = self._serve(self.launch_service, self.launch_listener)
        record["query_rpc"] = self._serve(self.query_service, self.query_listener)
        for execution_id in self.owner.lifecycle.retained_execution_ids:
            try:
                result = self.owner.lifecycle.reconcile(execution_id)
                record["reconciled"].append({"execution_id": execution_id, "state": result.state,
                                             "active_processes": result.active_processes,
                                             "terminal": result.terminal})
            except Exception as error:
                record["reconcile_errors"].append({"execution_id": execution_id,
                                                   "reason": _reason(error)})
        record["restored"] = [{"execution_id": execution_id, "reason": reason}
                              for execution_id, reason, _ in self.control.tick(self.control.clock())]
        return record

    def retained_execution_ids(self):
        return () if self.owner is None else tuple(self.owner.retained_execution_ids)

    def serve_until_stopped(self):
        """Run iterations until the process is interrupted.

        This is the default mode. KeyboardInterrupt is the only stop condition
        this repository provides, and it is raised by the interpreter, not
        invented here. The caller drains afterwards.
        """
        iterations = 0
        try:
            while True:
                emit(self.run_once())
                iterations += 1
        except KeyboardInterrupt:
            return {"event": "guardian_host_stopping", "reason": "interrupted",
                    "iterations": iterations}

    def drain_until_settled(self, budget=None):
        """Reconcile until nothing is retained. Never exit with custody.

        ``budget`` bounds the loop for tests only. When a bounded drain runs
        out the result says the host is still retaining work and is not
        exiting, and the caller keeps it alive. With no budget the loop can
        only return once custody is settled.
        """
        if not self._started:
            raise GuardianHostRefused("guardian_host_not_started")
        iterations = 0
        while self.retained_execution_ids():
            if budget is not None and iterations >= budget:
                return {"event": "guardian_host_custody_retained", "settled": False,
                        "exiting": False, "iterations": iterations,
                        "retained": list(self.retained_execution_ids())}
            try:
                emit(self.run_once(serve_launch=False))
                self._sleep(min(.25, self.rpc_timeout_ms / 1000))
            except KeyboardInterrupt:
                # A second interrupt does not release custody. The drain goes
                # on, and ending this process by force is a guardian death that
                # the supervisor handles.
                emit({"event": "guardian_host_interrupt_deferred",
                      "retained": list(self.retained_execution_ids())})
            iterations += 1
        return {"event": "guardian_host_drained", "settled": True, "iterations": iterations}

    def _serve(self, service, listener):
        from .ipc import IpcError
        from .launch_transport import LaunchTransportError
        from .pipe_windows import NativePipeError
        from .store import LifecycleError

        try:
            return {"served": True, "result": service.serve_once(listener, timeout_ms=self.rpc_timeout_ms)}
        except (NativePipeError, IpcError, LaunchTransportError, LifecycleError) as error:
            # A deadline with no caller is the ordinary idle outcome. A refused
            # or malformed request is reported and never retried here.
            return {"served": False, "reason": _reason(error)}

    # --- shutdown ---------------------------------------------------------

    def close(self):
        """Exit cleanly only when no execution is still retained.

        Retained custody is an obligation of this process. A live obligation
        cannot be discarded by shutting the host down, so this refuses and the
        caller keeps the process alive. The command line entry point drains
        first, so reaching this refusal means the drain itself was skipped.
        """
        if self.owner is not None and self.owner.retained_execution_ids:
            raise GuardianHostRefused("guardian_host_custody_unsettled",
                                      ",".join(self.owner.retained_execution_ids))
        errors = []
        for listener in (self.launch_listener, self.query_listener):
            if listener is None:
                continue
            try:
                listener.close()
            except Exception as error:
                errors.append(_reason(error))
        if errors:
            raise GuardianHostRefused("guardian_host_endpoint_cleanup_unverified", ",".join(errors))
        self._started = False
        return {"event": "guardian_host_closed", "guardian_epoch": self.guardian_epoch}


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinel.adaptive.guardian_host",
        description="Run one guardian process host for a bounded number of iterations.")
    parser.add_argument("--data-dir", required=True, help="directory holding sentinel.db")
    parser.add_argument("--journal-dir", required=True, help="recovery manifest directory")
    parser.add_argument("--guardian-epoch", required=True, help="epoch minted by the supervisor")
    parser.add_argument("--profile", default=None, help="policy profile JSON file")
    parser.add_argument("--iterations", type=int, default=0,
                        help="0 runs until the process is interrupted; a positive "
                             "value is the bounded test and diagnostic mode")
    parser.add_argument("--rpc-timeout-ms", type=int, default=DEFAULT_RPC_TIMEOUT_MS,
                        help="per RPC accept deadline in milliseconds")
    parser.add_argument("--launch-instance-id", default=None, help="launch pipe instance id")
    parser.add_argument("--query-instance-id", default=None, help="query pipe instance id")
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if options.iterations < 0 or options.rpc_timeout_ms < 1 or options.rpc_timeout_ms > 1000:
        emit({"event": "guardian_host_refused", "reason": "guardian_host_arguments_invalid"})
        return EXIT_REFUSED
    host = GuardianHost(data_dir=options.data_dir, journal_dir=options.journal_dir,
                        guardian_epoch=options.guardian_epoch, profile_path=options.profile,
                        rpc_timeout_ms=options.rpc_timeout_ms,
                        launch_instance_id=options.launch_instance_id,
                        query_instance_id=options.query_instance_id)
    try:
        emit(host.start())
    except GuardianHostRefused as error:
        emit({"event": "guardian_host_refused", "reason": error.reason, "detail": error.detail})
        return EXIT_REFUSED
    try:
        if options.iterations == 0:
            emit(host.serve_until_stopped())
        else:
            for _ in range(options.iterations):
                emit(host.run_once())
    except KeyboardInterrupt:
        emit({"event": "guardian_host_stopping", "reason": "interrupted"})
    # The drain is unbounded on purpose. This host does not return to the shell
    # while it still owns an execution.
    emit(host.drain_until_settled())
    try:
        emit(host.close())
    except GuardianHostRefused as error:
        emit({"event": "guardian_host_refused", "reason": error.reason, "detail": error.detail})
        return EXIT_UNSETTLED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
