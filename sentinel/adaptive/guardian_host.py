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
import hashlib
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


def emit(record, stream=None, *, sink=None):
    """One JSON record per line on stderr, so stdout stays free for a workload."""
    if stream is None and sink is not None:
        return sink.offer(record)
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

    @classmethod
    def for_experiment(cls, spec, *, child_binding, isolated_store, daily_store):
        """Consume one released guardian role and the original child custody.

        The bootstrap owns the binding and its current-process handle. This
        host borrows both until it has drained and closed its own resources;
        host closure alone is not aggregate retirement or daily release.
        """
        from .experiment_host_roles import GuardianRoleSpec
        from .experiment_host_transport import ExperimentChildBinding
        from .experiment_host_authority import ExperimentBackedHostAuthority
        from .identity import VerifiedProcess
        from .store import LifecycleStore
        if (cls is not GuardianHost or type(spec) is not GuardianRoleSpec or
                type(child_binding) is not ExperimentChildBinding or
                not isinstance(isolated_store, LifecycleStore) or not isinstance(daily_store, LifecycleStore)):
            raise GuardianHostRefused("experiment_guardian_original_inputs_required")
        manifest = child_binding.manifest
        guardian = child_binding._process
        if (manifest.role != "guardian" or manifest.actor_member_id != spec.member_id or
                type(guardian) is not VerifiedProcess or guardian.identity != manifest.child_identity):
            raise GuardianHostRefused("experiment_guardian_original_child_required")
        wire = spec.to_json()
        original = getattr(child_binding, "_experiment_guardian_host", None)
        if original is not None:
            if (type(original) is not cls or any(left is not right for left, right in zip(
                    original._experiment_original[:5], (spec, child_binding, isolated_store, daily_store, guardian)))):
                raise GuardianHostRefused("experiment_guardian_original_host_changed")
            original._assert_experiment_host()
            return original
        owner = cls.__new__(cls)
        # Retain before initialization/authority construction or native checks.
        child_binding._experiment_guardian_host = owner
        owner._experiment_original = (spec, child_binding, isolated_store, daily_store, guardian,
                                      wire)
        owner._experiment_construction_error = None
        try:
            cls.__init__(owner, data_dir=spec.data_dir, journal_dir=spec.journal_dir,
                guardian_epoch=spec.guardian_epoch, profile_path=spec.profile_path,
                rpc_timeout_ms=spec.rpc_timeout_ms, launch_instance_id=spec.launch_instance_id,
                query_instance_id=spec.query_instance_id, control_instance_id=spec.control_instance_id,
                instance_id=spec.instance_id, operator_instance_id=spec.operator_instance_id,
                policy_instance_id=spec.policy_instance_id)
            owner._experiment_binding = child_binding
            owner.store, owner.guardian = isolated_store, guardian
            owner.authority = ExperimentBackedHostAuthority.for_guardian(child_binding,
                isolated_store=isolated_store, daily_store=daily_store, guardian=guardian)
            owner._experiment_authority = owner.authority
            owner._validate_experiment_start()
        except BaseException as error:
            owner._experiment_construction_error = error
            error.experiment_guardian_host = owner
            error.experiment_child_binding = child_binding
            raise
        return owner

    def __init__(self, *, data_dir, journal_dir, guardian_epoch, profile_path=None,
                 rpc_timeout_ms=DEFAULT_RPC_TIMEOUT_MS, launch_instance_id=None,
                 query_instance_id=None, control_instance_id=None, sleep=time.sleep,
                 evidence_directory=None, evidence_sha256=None, control_purpose="isolated_canary",
                 instance_id=None, operator_instance_id=None, policy_instance_id=None,
                 parent_identity=None, parent_instance_id=None, telemetry_factory=None):
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
        self.telemetry = None
        self._telemetry_factory = telemetry_factory
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
        self._experiment_binding = None
        self._experiment_closed = False
        self._experiment_closed_custody = None

    def _assert_experiment_host(self):
        """Original object checks only, so recovery never needs fresh admission."""
        from .experiment_host_authority import ExperimentBackedHostAuthority
        if self._experiment_construction_error is not None:
            raise GuardianHostRefused("experiment_guardian_construction_unsettled")
        spec, binding, store, daily, guardian, wire = self._experiment_original
        if (self._experiment_binding is not binding or binding._experiment_guardian_host is not self or
                self._experiment_construction_error is not None or spec.to_json() != wire or
                self.store is not store or self.guardian is not guardian or binding._process is not guardian or
                self.authority is not self._experiment_authority or
                type(self.authority) is not ExperimentBackedHostAuthority or
                self.authority.store is not store or self.authority.daily_store is not daily or
                self.authority.guardian is not guardian or self.authority.child_binding is not binding or
                (self.data_dir, self.journal_dir, self.profile_path) !=
                    (Path(spec.data_dir), Path(spec.journal_dir), Path(spec.profile_path)) or
                (self.guardian_epoch, self.rpc_timeout_ms, self.launch_instance_id, self.query_instance_id,
                 self.control_instance_id, self.instance_id, self.operator_instance_id, self.policy_instance_id) !=
                    (spec.guardian_epoch, spec.rpc_timeout_ms, spec.launch_instance_id, spec.query_instance_id,
                     spec.control_instance_id, spec.instance_id, spec.operator_instance_id, spec.policy_instance_id) or
                self.parent_identity is not None or self.parent_instance_id is not None or
                self.evidence_directory is not None or self.evidence_sha256 is not None or
                self._telemetry_factory is not None or self.control_purpose != "isolated_canary"):
            raise GuardianHostRefused("experiment_guardian_original_host_changed")
        if self.owner is not None and (self.owner.authority is not self.authority or
                self.owner.store is not store or self.owner.guardian is not guardian):
            raise GuardianHostRefused("experiment_guardian_original_owner_changed")
        self.authority._original()

    def _experiment_profile_bytes(self):
        raw = self.profile_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != self._experiment_original[0].profile_sha256:
            raise GuardianHostRefused("experiment_guardian_profile_changed")
        return raw

    def _validate_experiment_start(self):
        self._assert_experiment_host()
        if self._experiment_closed:
            raise GuardianHostRefused("experiment_guardian_host_closed")
        spec, binding, store, daily, guardian, wire = self._experiment_original
        # The fixed bootstrap supplies the authenticated parent Release witness.
        # A role/spec dict or successful child handshake alone is insufficient.
        release = getattr(type(binding), "require_role_release", None)
        if not callable(release) or release(binding, spec) is not None:
            raise GuardianHostRefused("experiment_guardian_role_release_required")
        manifest = binding.manifest
        if (self.data_dir.resolve() != Path(store.db_path).resolve(strict=True).parent or
                self.data_dir.resolve() == Path(daily.db_path).resolve(strict=True).parent or
                not self.journal_dir.resolve().is_relative_to(self.data_dir.resolve()) or
                spec.policy_instance_id != manifest.isolated_policy_instance_id):
            raise GuardianHostRefused("experiment_guardian_paths_or_policy_changed")
        self.authority._cleanup_observed()
        self.authority._native(restrictive=True)
        self._experiment_profile_bytes()

    def emit(self, record, stream=None):
        if stream is not None:
            return emit(record, stream=stream)
        from .telemetry import emit_resident
        return emit_resident(self, record)

    def _start_telemetry(self):
        from .telemetry import start_resident_telemetry
        start_resident_telemetry(self, role="guardian", identity=self.guardian.identity,
            instance_id=self.instance_id, data_dir=self.data_dir,
            excluded_paths=(self.journal_dir,))

    def _finish_telemetry(self, record):
        if self.telemetry is None:
            return record
        from .telemetry import stop_resident_telemetry
        return {**record, "telemetry": stop_resident_telemetry(self, record)}

    # --- startup ----------------------------------------------------------

    def start(self):
        try:
            return self._start()
        except BaseException as error:
            if self._experiment_binding is not None:
                error.experiment_guardian_host = self
                error.experiment_child_binding = self._experiment_binding
            raise

    def _start(self):
        """Refuse before touching the ledger when the host cannot support this."""
        from .decision import parse_policy_profile
        from .guardian import GuardianLaunchOwner
        from .guardian_control import GuardianControl
        from .guardian_floor import FloorPublisher
        from .capability_evidence import NativeEvidenceAuthority
        from .launch_scope import RetainedLaunchScopeSource
        from .identity import VerifiedProcess
        from .recovery_journal import RecoveryJournal
        from .store import LifecycleStore

        if self._experiment_binding is not None:
            self._assert_experiment_host()
            # An existing uncertain registration must retain its original retry
            # and cleanup path even if the parent/readiness has since failed.
            if not self.registration_pending:
                self._validate_experiment_start()
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
        if self._experiment_binding is not None:
            self._validate_experiment_start()
        self._endpoints()
        try:
            capability_authority = NativeEvidenceAuthority(profile=profile,
                bundle_directory=self.evidence_directory,
                expected_bundle_sha256=self.evidence_sha256, purpose=self.control_purpose)
            capability_authority.launch_scope_source = RetainedLaunchScopeSource(
                owner=self.owner, authority=capability_authority)
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
        self._start_telemetry()
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
            raw = (self.profile_path.read_bytes() if self._experiment_binding is None else
                   self._experiment_profile_bytes())
            return parse(raw)
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
            if self._experiment_binding is None:
                result = self._registration.tick()
            elif (self._registration is self.authority._actor_registration and
                    (self._registration.result.complete or self._registration.result.refused or
                     self._registration.pending and self._registration._publication_pins is not None)):
                # Replay/cleanup of the original captured registry postimage is
                # conservative bookkeeping, not fresh host admission. A busy
                # first attempt without that postimage must reacquire the actor
                # scope; pending by itself never bypasses the daily gate.
                result = self._registration.tick()
            else:
                with self.authority.actor_registration_scope(self._registration, self._experiment_original[0]):
                    self.authority.assert_actor_registration_ready(self._registration)
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
        if self._experiment_binding is not None:
            self._assert_experiment_host()
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
                self.emit(self.run_once())
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
                self.emit(self.run_once(serve_launch=False))
                self._sleep(min(.25, self.rpc_timeout_ms / 1000))
            except KeyboardInterrupt:
                # A second interrupt does not release custody. The drain goes
                # on, and ending this process by force is a guardian death that
                # the supervisor handles.
                self.emit({"event": "guardian_host_interrupt_deferred",
                      "retained": list(self.retained_execution_ids())})
            except Exception as error:
                self._runtime_error = error
                self._retain_rpc_cleanup(error)
                self.emit({"event": "guardian_host_recovery_pending", "reason": _reason(error)})
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
        if self._experiment_binding is not None:
            self._assert_experiment_host()
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
            if name == "self" and self._experiment_binding is not None:
                # The original bootstrap must still observe/report this actor
                # and close its child binding. Never consume its borrowed handle.
                continue
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
        result = self._finish_telemetry(
            {"event": "guardian_host_closed", "guardian_epoch": self.guardian_epoch})
        if self._experiment_binding is not None:
            self._experiment_closed = True
        return result

    def closed_experiment_custody(self):
        """Return exact retired owners after positive host-resource closure.

        This is historical custody only. The bootstrap still owns this actor's
        process handle, and the parent must prove actor exit and its aggregate
        separately. No closed native handle is queried or recreated here.
        """
        from .guardian import GuardianLaunchOwner
        from .prelaunch_receipt import PrelaunchReceiptOperation
        from .terminal_custody import TerminalCustody
        from .terminal_receipt import TerminalReceiptOperation
        self._assert_experiment_host()
        if (self._experiment_binding is None or not self._experiment_closed or self._started or
                not self._draining or type(self.owner) is not GuardianLaunchOwner or
                self.registration_pending or self._cleanup_unknown or not self._operations_settled() or
                self._descriptor_attempt is not None or self.descriptor is not None):
            raise GuardianHostRefused("experiment_guardian_host_not_closed")
        for name, resource in (("launch", self.launch_listener), ("query", self.query_listener),
                ("control", self.control_listener), ("operator", self.operator_listener),
                ("discovery", self.discovery)):
            if resource is not None and name not in self._closed_owners:
                raise GuardianHostRefused("experiment_guardian_host_not_closed")
        values = GuardianLaunchOwner.closed_experiment_custody(self.owner)
        for kind, entry, custody in values:
            if kind == "prelaunch":
                if (type(custody) is not PrelaunchReceiptOperation or custody.owner is not self.owner or
                        custody._entry is not entry or entry.retirement_receipt_operation is not custody or
                        entry.root is not None or not entry.retirement_sealed or
                        not entry.retirement_cleanup_started or entry.retirement_mutex_close_unknown or
                        entry.closed_handles != {key for key, value in custody.owners.items() if value is not None}):
                    raise GuardianHostRefused("experiment_guardian_prelaunch_custody_changed")
                receipt = custody
            elif kind == "terminal":
                if (type(custody) is not TerminalCustody or entry.terminal_cleanup is not custody or
                        entry.closed is not True or custody.proof_published is not True or
                        custody.native_complete is not True or custody.quarantined or
                        custody.closed_owners != ("root", "wrapper", "job", "mutex") or
                        type(custody.receipt_operation) is not TerminalReceiptOperation):
                    raise GuardianHostRefused("experiment_guardian_terminal_custody_changed")
                receipt = custody.receipt_operation
            else:
                raise GuardianHostRefused("experiment_guardian_custody_kind_invalid")
            if (receipt.lifecycle is not self.owner.lifecycle or receipt.store is not self.store or
                    receipt.custody is not custody or receipt._entry is not entry or
                    receipt._operation._complete is not True or receipt._operation.pending or
                    receipt._operation._quarantine or receipt._candidate is None or
                    custody.manifest.guardian_identity != self.guardian.identity or
                    custody.manifest.guardian_epoch != self.guardian_epoch or
                    custody.execution_id != entry.execution_id or entry.journal_cleanup_error is not None or
                    any(getattr(entry, name) is not original for name, original in custody.owners.items())):
                raise GuardianHostRefused("experiment_guardian_closed_receipt_changed")
        if self._experiment_closed_custody is None:
            self._experiment_closed_custody = values
        if values is not self._experiment_closed_custody:
            raise GuardianHostRefused("experiment_guardian_closed_custody_changed")
        return self._experiment_closed_custody


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
            host.emit(host.start())
            break
        except (Exception, KeyboardInterrupt) as error:
            host._runtime_error = error
            host._retain_rpc_cleanup(error)
            stopping = stopping or isinstance(error, KeyboardInterrupt)
            if host.registration_pending:
                host._start_telemetry()
                # Retry through the same registration object. Its original
                # guard decides whether progress is safe; quarantine stays
                # resident and never turns into a new transaction/identity.
                host.emit({"event": "guardian_host_registration_retained", "reason": _reason(error)})
                try:
                    host._sleep(1)
                except KeyboardInterrupt:
                    stopping = True
                continue
            refusal = {"event": "guardian_host_refused", "reason": _reason(error),
                       "detail": getattr(error, "detail", None)}
            # A later startup refusal may already own native identity or
            # listener handles. Finish the original cleanup before returning.
            if host.guardian is not None or host.owner is not None:
                _close_until_settled(host, initial_record=refusal)
            else:
                host.emit(refusal)
            return EXIT_REFUSED
    try:
        if stopping:
            host.begin_drain()
        elif options.iterations == 0:
            host.emit(host.serve_until_stopped())
        else:
            for _ in range(options.iterations):
                host.emit(host.run_once())
    except KeyboardInterrupt:
        host.emit({"event": "guardian_host_stopping", "reason": "interrupted"})
    except Exception as error:
        host._runtime_error = error
        host._retain_rpc_cleanup(error)
        host.begin_drain()
        host.emit({"event": "guardian_host_stopping", "reason": "runtime_failure"})
    # The drain is unbounded on purpose. This host does not return to the shell
    # while it still owns an execution.
    host.emit(host.drain_until_settled())
    # Unknown CloseHandle does not authorize dropping its only cleanup witness.
    # Keep the original owner alive; a second interrupt cannot turn uncertainty
    # into successful retirement or cause a blind repeated native close.
    _close_until_settled(host)
    return EXIT_OK


def _close_until_settled(host, *, initial_record=None):
    if initial_record is not None and getattr(host, "telemetry", None) is not None:
        host.emit(initial_record)
        initial_record = None
    while True:
        try:
            closed = host.close()
            if initial_record is not None:
                host.emit(initial_record)
            host.emit(closed)
            return
        except (Exception, KeyboardInterrupt) as error:
            from .contracts import ProcessIdentity

            guardian = getattr(host, "guardian", None)
            if type(getattr(guardian, "identity", None)) is ProcessIdentity:
                host._start_telemetry()
            if initial_record is not None:
                host.emit(initial_record)
                initial_record = None
            host.emit({"event": "guardian_host_cleanup_retained", "reason": _reason(error)})
            try:
                host._sleep(1)
            except KeyboardInterrupt:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
