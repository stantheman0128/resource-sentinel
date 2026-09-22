"""Runnable guardian host; invoke the actual Python base executable directly.

This wires the existing libraries into one process. It owns no policy of its
own. The launch owner, the lifecycle dispatcher, the control consumer, the
recovery journal and the three pipe services are the production modules, and the
host authority is the live one in host_authority.py.

One iteration serves at most one launch RPC, one typed helper control operation
and one query RPC, each with a bounded deadline, and reconciles retained work.
Lease checks precede RPC waits and follow reconciliation. The default accept
deadline is 100ms; this is a bound, not a measured reaction-time claim. Nothing
here starts a thread or keeps a request queue of its own.

The default mode runs until an authenticated operator drain or an interrupt.
A positive --iterations is the explicit bounded mode for tests and diagnostics.

A stop never abandons custody. Once stopping, the host stops serving new launch
requests, refuses restrictive proposals, and continues restore/frame RPCs while
reconciling and sweeping until no execution is retained. Only
then does it close. Exiting with a retained execution would drop the Job handles
and the only normal actuator, so it is never done voluntarily.

The control consumer is the only normal actuator. The operator adapter owns
the guarded mode-off transaction and retained recovery; it cannot enable a mode
or change user exemptions. No host operation terminates, suspends or trims work.

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
DEFAULT_RPC_TIMEOUT_MS = 100
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
    try:
        print(json.dumps(record, sort_keys=True, default=str),
              file=sys.stderr if stream is None else stream, flush=True)
    except (OSError, ValueError):
        # A closed diagnostic sink cannot unwind the native custodian.
        return


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
                 query_instance_id=None, control_instance_id=None, sleep=time.sleep,
                 evidence_directory=None, evidence_sha256=None, control_purpose="isolated_canary",
                 instance_id=None, operator_instance_id=None, policy_instance_id=None,
                 parent_identity=None, parent_instance_id=None):
        self.data_dir = Path(data_dir)
        self.journal_dir = Path(journal_dir)
        self.guardian_epoch = guardian_epoch
        self.profile_path = Path(DEFAULT_PROFILE if profile_path is None else profile_path)
        self.rpc_timeout_ms = rpc_timeout_ms
        self.evidence_directory, self.evidence_sha256 = evidence_directory, evidence_sha256
        self.control_purpose = control_purpose
        # Paces the drain loop only. It is a test seam, never a timing claim.
        self._sleep = sleep
        self.launch_instance_id = str(uuid4()) if launch_instance_id is None else launch_instance_id
        self.query_instance_id = str(uuid4()) if query_instance_id is None else query_instance_id
        self.control_instance_id = str(uuid4()) if control_instance_id is None else control_instance_id
        self.instance_id = str(uuid4()) if instance_id is None else instance_id
        self.operator_instance_id = str(uuid4()) if operator_instance_id is None else operator_instance_id
        self.policy_instance_id = policy_instance_id
        self.parent_identity, self.parent_instance_id = parent_identity, parent_instance_id
        self.parent = self.discovery = self.descriptor = None
        self._descriptor_attempt = None
        self.operator_endpoint = self.operator_service = self.operator_listener = None
        self.operations = None
        self._draining = False
        self._operation_result = None
        self._discovery_error = None
        self._closed_owners = set()
        self._cleanup_unknown = {}
        self._rpc_cleanup_errors = []
        self._runtime_error = None
        self.capability = None
        self.store = self.journal = self.guardian = self.authority = None
        self.owner = self.control = None
        self.launch_endpoint = self.query_endpoint = self.control_endpoint = None
        self.launch_service = self.query_service = self.control_service = None
        self.launch_listener = self.query_listener = self.control_listener = None
        self.registered = False
        self._registration = None
        self._startup_profile = None
        self._started = False

    # --- startup ----------------------------------------------------------

    def start(self):
        """Refuse before touching the ledger when the host cannot support this."""
        from .decision import parse_policy_profile
        from .guardian import GuardianLaunchOwner
        from .guardian_control import GuardianControl
        from .guardian_floor import FloorPublisher
        from .capability_evidence import NativeEvidenceAuthority
        from .identity import VerifiedProcess
        from .recovery_journal import RecoveryJournal
        from .store import LifecycleStore

        if self.capability is None:
            self.capability = self._capability()
        if self._startup_profile is None:
            self._startup_profile = self._profile(parse_policy_profile)
        profile = self._startup_profile
        db_path = self.data_dir / "sentinel.db"
        try:
            if self.store is None:
                self.store = LifecycleStore(db_path, existing_path=True)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_ledger_unavailable", _reason(error)) from None
        try:
            if self.journal is None:
                self.journal = RecoveryJournal(self.journal_dir)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_journal_unavailable", _reason(error)) from None
        try:
            if self.guardian is None:
                self.guardian = VerifiedProcess.current()
        except Exception as error:
            raise GuardianHostRefused("guardian_host_identity_unavailable", _reason(error)) from None
        if self.authority is None:
            self.authority = HostAuthority(self.store, guardian=self.guardian)
        try:
            if self.owner is None:
                self.owner = GuardianLaunchOwner(self.store, self.journal,
                                                 guardian_epoch=self.guardian_epoch,
                                                 authority=self.authority, guardian=self.guardian)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_owner_unavailable", _reason(error)) from None
        self._register()
        self._endpoints()
        try:
            capability_authority = NativeEvidenceAuthority(profile=profile,
                bundle_directory=self.evidence_directory,
                expected_bundle_sha256=self.evidence_sha256, purpose=self.control_purpose)
            floor_publisher = FloorPublisher(self.owner)
            self.control = GuardianControl(self.owner, profile=profile,
                exemptions=self.data_dir / "exemptions.sqlite3",
                capability_authority=capability_authority, floor_publisher=floor_publisher)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_control_unavailable", _reason(error)) from None
        self._control_endpoint()
        self._operator_endpoint()
        self._publish_descriptor("ready")
        self._started = True
        return {"event": "guardian_host_started", "guardian_epoch": self.guardian_epoch,
                "pid": self.capability.pid, "launch_endpoint": self.launch_endpoint.name,
                "query_endpoint": self.query_endpoint.name,
                "control_endpoint": self.control_endpoint.name,
                "launch_instance_id": self.launch_instance_id,
                "query_instance_id": self.query_instance_id,
                "control_instance_id": self.control_instance_id,
                "instance_id": self.instance_id, "operator_instance_id": self.operator_instance_id,
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
        """Retain one atomic registry/epoch/logon publication under POLICY.

        This writes only the explicit ledger and never changes mode. Keeping
        the same object across retry/interrupt preserves its original guard,
        exact pre/postimage and any uncertain commit or cleanup outcome.
        """
        from .guardian_registration import GuardianRegistration
        try:
            if self._registration is None:
                self._registration = GuardianRegistration(self.store, self.journal,
                    guardian=self.guardian, guardian_epoch=self.guardian_epoch)
            result = self._registration.tick()
        except Exception as error:
            raise GuardianHostRefused("guardian_host_registry_unavailable", _reason(error)) from None
        if result.refused:
            raise GuardianHostRefused(result.reason)
        if not result.complete:
            raise GuardianHostRefused("guardian_host_registry_unavailable", result.reason)
        self.registered = True

    @property
    def registration_pending(self):
        return self._registration is not None and self._registration.pending

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

    def _control_endpoint(self):
        """The helper's proposal pipe. It needs the control consumer, so it comes last.

        The service authenticates the registered helper and hands the typed
        proposal to GuardianControl. It adds no authority, and the consumer
        still refuses every mode outside canary and limited.
        """
        from .control_transport import ControlProposalService
        from .pipe_windows import NativePipeEndpoint, NativePipeListener

        identity = self.guardian.identity
        try:
            self.control_endpoint = NativePipeEndpoint(identity.logon_id, self.control_instance_id,
                                                       identity)
            self.control_service = ControlProposalService(self.store.db_path, self.control_endpoint,
                                                          self.control)
            self.control_listener = NativePipeListener(self.control_endpoint)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_endpoint_unavailable", _reason(error)) from None

    # --- one bounded iteration --------------------------------------------

    def _operator_endpoint(self):
        from .host_operations import GuardianHostOperations
        from .operator_transport import OperatorService
        from .pipe_windows import NativePipeEndpoint, NativePipeListener
        from .store import _ipc_read_transaction
        try:
            with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
                runtime = dict(conn.execute("SELECT * FROM adaptive_runtime WHERE singleton=1").fetchone())
            if self.policy_instance_id is not None and self.policy_instance_id != runtime["policy_instance_id"]:
                raise LifecycleError("guardian_host_policy_changed")
            self.policy_instance_id = runtime["policy_instance_id"]
            self.operations = GuardianHostOperations(self.owner, self.control,
                instance_id=self.instance_id, policy_instance_id=self.policy_instance_id,
                begin_drain=self.begin_drain)
            self.operator_endpoint = NativePipeEndpoint(self.guardian.identity.logon_id,
                self.operator_instance_id, self.guardian.identity)
            self.operator_service = OperatorService(self.operator_endpoint,
                instance_id=self.instance_id, policy_instance_id=self.policy_instance_id,
                guardian_epoch=self.guardian_epoch, handler=self.operations, scope="guardian")
            self.operator_listener = NativePipeListener(self.operator_endpoint)
        except Exception as error:
            raise GuardianHostRefused("guardian_host_operator_unavailable", _reason(error)) from None

    def _publish_descriptor(self, state):
        # A direct guardian has explicit endpoints only. It never impersonates
        # the canonical supervisor. The parent's opened exact handle is solely
        # a publication witness, not adoption or recovery authority.
        if self.parent_identity is None and self.parent_instance_id is None:
            return
        from .host_discovery import HostDiscovery, HostDescriptor, EndpointLocator
        from .identity import VerifiedProcess
        if self.parent_identity is None or self.parent_instance_id is None:
            raise GuardianHostRefused("guardian_host_parent_binding_incomplete")
        if self.parent is None:
            self.parent = VerifiedProcess.open(self.parent_identity)
        if self.discovery is None:
            self.discovery = HostDiscovery(self.data_dir, logon_id=self.guardian.identity.logon_id)
        if self.descriptor is not None and self.descriptor.state == state:
            return
        candidate = HostDescriptor(self.instance_id, self.policy_instance_id,
            self.guardian.identity.logon_id, self.guardian_epoch, "guardian", self.guardian.identity,
            tuple(EndpointLocator(role, endpoint) for role, endpoint in (
                ("operator", self.operator_endpoint), ("launch", self.launch_endpoint),
                ("query", self.query_endpoint), ("control", self.control_endpoint))),
            state, 1 if self.descriptor is None else self.descriptor.revision + 1,
            self.parent_identity, self.parent_instance_id)
        if self._descriptor_attempt is not None:
            raise GuardianHostRefused("guardian_host_discovery_publication_unknown")
        self._descriptor_attempt = candidate
        try:
            self.discovery.publish_guardian(candidate, expected=self.descriptor,
                owner_process=self.guardian, parent_process=self.parent)
        except BaseException as error:
            self._discovery_error = error
            # The exact attempted candidate remains retained after uncertain
            # publication. A locator read is not a durable publication ACK.
            if getattr(error, "publication_may_have_occurred", None) is False:
                self._descriptor_attempt = None
            raise
        self.descriptor = candidate
        self._descriptor_attempt = None

    def begin_drain(self):
        self._draining = True
        self.owner.begin_drain()
        self.control.begin_drain()

    def _operations_settled(self):
        if self._rpc_cleanup_errors:
            return False
        if self.operations is None:
            return True
        return self.operations.settled is True

    def _retain_rpc_cleanup(self, error):
        seen, current = set(), error
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            if (getattr(current, "_identity_handle_cleanup", ()) or
                    getattr(current, "_policy_mutex_cleanup", ()) or
                    getattr(current, "_native_close_outcome_unknown", False)):
                if all(item is not current for item in self._rpc_cleanup_errors):
                    self._rpc_cleanup_errors.append(current)
            current = (getattr(current, "_operator_cause", None) or
                getattr(current, "_control_cause", None) or getattr(current, "__cause__", None))

    def _reap_rpc_cleanup(self):
        from .windows import settle_retained
        from .pipe_windows import _GLOBAL_REGISTRY, NativeDeadline
        _GLOBAL_REGISTRY.reap(NativeDeadline.after_ms(100), max_ops=4)
        if self._rpc_cleanup_errors:
            error = self._rpc_cleanup_errors[0]
            if getattr(error, "_native_close_outcome_unknown", False):
                return
            try:
                if not settle_retained(error):
                    return
            except Exception:
                return
            self._rpc_cleanup_errors.pop(0)

    def run_once(self, *, serve_launch=True):
        """Serve at most one RPC of each kind, reconcile, then sweep leases.

        ``serve_launch`` is false while draining. The control consumer rejects
        restrictions and renewals but still handles restore/frame requests.
        Safety sweeps run before any bounded RPC wait and after reconciliation.

        The three pipes are served one after another, each with its own bounded
        deadline, so an idle iteration can take up to three of them. That is a
        property of this loop and not a measured reaction time.
        """
        if not self._started:
            raise GuardianHostRefused("guardian_host_not_started")
        record = {"event": "guardian_host_iteration", "launch_rpc": None, "query_rpc": None,
                  "control_rpc": None, "reconciled": [], "reconcile_errors": [], "restored": [],
                  "barrier_clears": [], "barrier_clear_errors": []}
        if not serve_launch and not self._draining:
            self.begin_drain()
        record["restored"] = [{"execution_id": execution_id, "reason": reason}
                              for execution_id, reason, _ in self.control.tick(self.control.clock())]
        self._reap_rpc_cleanup()
        # Accept an irreversible drain before considering another launch.
        if self.operator_service is not None:
            served = self._serve(self.operator_service, self.operator_listener)
            if served["served"]:
                served["result"] = served["result"].to_dict()
            record["operator_rpc"] = served
        # The same authenticated pipe carries retirement, lost-ACK replay and
        # BindRoot. The owner refuses new authorization after begin_drain().
        record["launch_rpc"] = self._serve(self.launch_service, self.launch_listener)
        record["control_rpc"] = self._control_rpc()
        record["query_rpc"] = self._serve(self.query_service, self.query_listener)
        for execution_id in self.owner.lifecycle.retained_execution_ids:
            try:
                if self.owner.lifecycle.terminal_cleanup_started(execution_id):
                    continue
                result = self.owner.lifecycle.reconcile(execution_id)
                record["reconciled"].append({"execution_id": execution_id, "state": result.state,
                                             "active_processes": result.active_processes,
                                             "terminal": result.terminal})
            except Exception as error:
                record["reconcile_errors"].append({"execution_id": execution_id,
                                                   "reason": _reason(error)})
        record["restored"].extend({"execution_id": execution_id, "reason": reason}
                                  for execution_id, reason, _ in self.control.tick(self.control.clock()))
        if self.operations is not None:
            self._operation_result = self.operations.tick()
        terminal = {item["execution_id"] for item in record["reconciled"] if item["terminal"]}
        record["terminal_retirements"] = []
        for execution_id in self.owner.lifecycle.retained_execution_ids:
            if execution_id in terminal or self.owner.lifecycle.terminal_cleanup_started(execution_id):
                try:
                    result = self.owner.lifecycle.retire_terminal(execution_id)
                    record["terminal_retirements"].append({"execution_id": execution_id,
                        "complete": result.complete, "pending": result.pending, "reason": result.reason})
                except Exception as error:
                    record["barrier_clear_errors"].append({"execution_id": execution_id, "reason": _reason(error)})
        record["prelaunch_retirements"] = self.owner.retire_completed_pending()
        if self._draining:
            try:
                self._publish_descriptor("draining")
            except Exception as error:
                self._discovery_error = error
                record["discovery_reason"] = _reason(error)
        return record

    def retained_execution_ids(self):
        return () if self.owner is None else tuple(self.owner.retained_execution_ids)

    def serve_until_stopped(self):
        """Run until a verified drain or interrupt; the caller retains custody."""
        iterations = 0
        try:
            while not self._draining:
                emit(self.run_once())
                iterations += 1
            return {"event": "guardian_host_stopping", "reason": "operator_drain",
                    "iterations": iterations}
        except KeyboardInterrupt:
            return {"event": "guardian_host_stopping", "reason": "interrupted",
                    "iterations": iterations}
        except Exception as error:
            self._runtime_error = error
            self._retain_rpc_cleanup(error)
            self.begin_drain()
            return {"event": "guardian_host_stopping", "reason": "runtime_failure",
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
        while self.retained_execution_ids() or not self._operations_settled():
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
            except Exception as error:
                self._runtime_error = error
                self._retain_rpc_cleanup(error)
                emit({"event": "guardian_host_recovery_pending", "reason": _reason(error)})
                try:
                    self._sleep(.25)
                except KeyboardInterrupt:
                    pass
            iterations += 1
        return {"event": "guardian_host_drained", "settled": True, "iterations": iterations}

    def _control_rpc(self):
        """Serve one authenticated operation, retaining only bounded outcomes."""
        from .control_messages import ControlFrameAck, RestoreAck
        served = self._serve(self.control_service, self.control_listener)
        if served["served"]:
            ack = served["result"]
            if isinstance(ack, ControlFrameAck):
                served["result"] = {"sample_seq": ack.sample_seq, "results": [
                    {"execution_id": item.execution_id, "observation": item.observation.value,
                     "barrier_cleared": item.barrier_cleared, "reason": item.reason}
                    for item in ack.results]}
            else:
                served["result"] = {"execution_id": ack.execution_id, "result": ack.result.value,
                                    "reason": ack.reason}
                if isinstance(ack, RestoreAck):
                    served["result"].update(native_disabled=ack.native_disabled,
                        bookkeeping_settled=ack.bookkeeping_settled,
                        slot_released=ack.slot_released, barrier_cleared=ack.barrier_cleared)
        return served

    def _serve(self, service, listener):
        from .ipc import IpcError
        from .launch_transport import LaunchTransportError
        from .pipe_windows import NativePipeError
        from .store import LifecycleError
        from .operator_transport import OperatorTransportError

        try:
            if len(self._rpc_cleanup_errors) >= 128:
                return {"served": False, "reason": "guardian_host_rpc_custody_full"}
            return {"served": True, "result": service.serve_once(listener, timeout_ms=self.rpc_timeout_ms)}
        except (NativePipeError, IpcError, LaunchTransportError, OperatorTransportError, LifecycleError) as error:
            # A deadline with no caller is the ordinary idle outcome. A refused
            # or malformed request is reported and never retried here.
            self._retain_rpc_cleanup(error)
            return {"served": False, "reason": _reason(error)}
        except BaseException as error:
            self._retain_rpc_cleanup(error)
            raise

    # --- shutdown ---------------------------------------------------------

    def close(self):
        """Exit cleanly only when no execution is still retained.

        Retained custody is an obligation of this process. A live obligation
        cannot be discarded by shutting the host down, so this refuses and the
        caller keeps the process alive. The command line entry point drains
        first, so reaching this refusal means the drain itself was skipped.
        """
        if self.registration_pending:
            # An empty execution inventory says nothing about the original
            # startup transaction or its POLICY/native cleanup obligation.
            raise GuardianHostRefused("guardian_host_registration_unsettled")
        self._reap_rpc_cleanup()
        if self.owner is not None and self.owner.retained_execution_ids:
            raise GuardianHostRefused("guardian_host_custody_unsettled",
                                      ",".join(self.owner.retained_execution_ids))
        if not self._operations_settled():
            raise GuardianHostRefused("guardian_host_operation_unsettled")
        if self._cleanup_unknown:
            raise GuardianHostRefused("guardian_host_cleanup_quarantined")
        if self._descriptor_attempt is not None:
            raise GuardianHostRefused("guardian_host_discovery_publication_unknown")
        if self.descriptor is not None:
            try:
                self.discovery.remove_guardian(self.descriptor, owner_process=self.guardian)
            except BaseException as error:
                self._cleanup_unknown["descriptor"] = error
                if not isinstance(error, Exception):
                    raise
                raise GuardianHostRefused("guardian_host_discovery_cleanup_unverified") from None
            self.descriptor = None
        if self.owner is not None:
            try:
                self.owner.lifecycle.close_retained_fences()
            except BaseException as error:
                self._cleanup_unknown["recovery_fence"] = error
                if not isinstance(error, Exception):
                    raise
                raise GuardianHostRefused("guardian_host_recovery_fence_cleanup_unverified") from None
        errors = []
        for name, listener in (("launch", self.launch_listener), ("query", self.query_listener),
                ("control", self.control_listener), ("operator", self.operator_listener),
                ("discovery", self.discovery)):
            if listener is None or name in self._closed_owners:
                continue
            try:
                listener.close()
                self._closed_owners.add(name)
            except BaseException as error:
                self._cleanup_unknown[name] = error
                errors.append(_reason(error))
                if not isinstance(error, Exception):
                    raise
        if errors:
            raise GuardianHostRefused("guardian_host_endpoint_cleanup_unverified", ",".join(errors))
        from .pipe_windows import _GLOBAL_REGISTRY, NativeDeadline
        status = _GLOBAL_REGISTRY.reap(NativeDeadline.after_ms(100), max_ops=128)
        if status.resources or status.pending or status.quarantined:
            raise GuardianHostRefused("guardian_host_pipe_custody_unsettled")
        for name, process in (("parent", self.parent), ("self", self.guardian)):
            if process is None or name in self._closed_owners:
                continue
            try:
                process.close()
                self._closed_owners.add(name)
            except BaseException as error:
                self._cleanup_unknown[name] = error
                if not isinstance(error, Exception):
                    raise
                raise GuardianHostRefused("guardian_host_identity_cleanup_unverified") from None
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
    parser.add_argument("--control-instance-id", default=None)
    parser.add_argument("--instance-id", default=None)
    parser.add_argument("--operator-instance-id", default=None)
    parser.add_argument("--policy-instance-id", default=None)
    parser.add_argument("--parent-pid", type=int, default=None)
    parser.add_argument("--parent-created-filetime", type=int, default=None)
    parser.add_argument("--parent-logon-id", default=None)
    parser.add_argument("--parent-instance-id", default=None)
    parser.add_argument("--evidence-dir", default=None, help="isolated measured capability evidence bundle")
    parser.add_argument("--evidence-sha256", default=None, help="pinned bundle manifest SHA-256")
    parser.add_argument("--control-purpose", choices=("isolated_canary", "p6_trial", "limited"),
                        default="isolated_canary", help="required evidence scope; never changes mode")
    return parser


def main(argv=None):
    options = build_parser().parse_args(argv)
    if options.iterations < 0 or options.rpc_timeout_ms < 1 or options.rpc_timeout_ms > 1000:
        emit({"event": "guardian_host_refused", "reason": "guardian_host_arguments_invalid"})
        return EXIT_REFUSED
    parent_identity = None
    parent = (options.parent_pid, options.parent_created_filetime,
              options.parent_logon_id, options.parent_instance_id)
    if any(item is not None for item in parent):
        if not all(item is not None for item in parent):
            emit({"event": "guardian_host_refused", "reason": "guardian_host_parent_binding_incomplete"})
            return EXIT_REFUSED
        from .contracts import ProcessIdentity, ContractViolation
        try:
            parent_identity = ProcessIdentity(*parent[:3])
        except ContractViolation:
            emit({"event": "guardian_host_refused", "reason": "guardian_host_parent_binding_invalid"})
            return EXIT_REFUSED
    host = GuardianHost(data_dir=options.data_dir, journal_dir=options.journal_dir,
                        guardian_epoch=options.guardian_epoch, profile_path=options.profile,
                        rpc_timeout_ms=options.rpc_timeout_ms,
                        launch_instance_id=options.launch_instance_id,
                        query_instance_id=options.query_instance_id,
                        control_instance_id=options.control_instance_id,
                        instance_id=options.instance_id, operator_instance_id=options.operator_instance_id,
                        policy_instance_id=options.policy_instance_id, parent_identity=parent_identity,
                        parent_instance_id=options.parent_instance_id,
                        evidence_directory=options.evidence_dir, evidence_sha256=options.evidence_sha256,
                        control_purpose=options.control_purpose)
    stopping = False
    while True:
        try:
            emit(host.start())
            break
        except (Exception, KeyboardInterrupt) as error:
            host._runtime_error = error
            host._retain_rpc_cleanup(error)
            stopping = stopping or isinstance(error, KeyboardInterrupt)
            if host.registration_pending:
                # Retry through the same registration object. Its original
                # guard decides whether progress is safe; quarantine stays
                # resident and never turns into a new transaction/identity.
                emit({"event": "guardian_host_registration_retained", "reason": _reason(error)})
                try:
                    host._sleep(1)
                except KeyboardInterrupt:
                    stopping = True
                continue
            emit({"event": "guardian_host_refused", "reason": _reason(error),
                  "detail": getattr(error, "detail", None)})
            # A later startup refusal may already own native identity or
            # listener handles. Finish the original cleanup before returning.
            if host.guardian is not None or host.owner is not None:
                _close_until_settled(host)
            return EXIT_REFUSED
    try:
        if stopping:
            host.begin_drain()
        elif options.iterations == 0:
            emit(host.serve_until_stopped())
        else:
            for _ in range(options.iterations):
                emit(host.run_once())
    except KeyboardInterrupt:
        emit({"event": "guardian_host_stopping", "reason": "interrupted"})
    except Exception as error:
        host._runtime_error = error
        host._retain_rpc_cleanup(error)
        host.begin_drain()
        emit({"event": "guardian_host_stopping", "reason": "runtime_failure"})
    # The drain is unbounded on purpose. This host does not return to the shell
    # while it still owns an execution.
    emit(host.drain_until_settled())
    # Unknown CloseHandle does not authorize dropping its only cleanup witness.
    # Keep the original owner alive; a second interrupt cannot turn uncertainty
    # into successful retirement or cause a blind repeated native close.
    _close_until_settled(host)
    return EXIT_OK


def _close_until_settled(host):
    while True:
        try:
            emit(host.close())
            return
        except (Exception, KeyboardInterrupt) as error:
            emit({"event": "guardian_host_cleanup_retained", "reason": _reason(error)})
            try:
                host._sleep(1)
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
