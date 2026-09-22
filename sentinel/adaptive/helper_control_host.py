"""Explicit active helper wiring; no default CLI or discovery/mode mutation.

The existing HelperHost remains shadow-only. This separately constructed host
reuses its query-only handles, registration and paced enrollment, but never runs
its shadow policy loop. The endpoint and evidence authority are explicit inputs.
"""
from .helper_host import HelperHost, HelperHostRefused, TickOutcome, _reason, emit
from .helper_control import ControlBindingSource, HelperControl
from .store import _ipc_read_transaction


class HelperControlHost(HelperHost):
    def __init__(self, *, endpoint, guardian_epoch, evidence_authority, **kwargs):
        super().__init__(**kwargs)
        self.control_endpoint = endpoint
        self.control_guardian_epoch = guardian_epoch
        self.evidence_authority = evidence_authority
        self.control = None
        self._control_last = None

    def start(self):
        # Evidence files are not permission to mutate mode, nor does a writable
        # profile enable control. The exact live ledger mode is checked below.
        if self.evidence_authority is None:
            raise HelperHostRefused('capability_evidence_unavailable')
        # The explicit host may be pointed at an inactive ledger. Refuse before
        # capability artifact/context reads, registry writes or client creation.
        with _ipc_read_transaction(self.data_dir / 'sentinel.db', timeout_ms=250) as conn:
            runtime = conn.execute('SELECT substr(mode,1,9) FROM adaptive_runtime WHERE singleton=1').fetchone()
            if runtime is None or runtime[0] not in {'canary','limited'}:
                raise HelperHostRefused('helper_control_mode_inactive')
        assessment = self.evidence_authority.assess()
        if not assessment.eligible:
            raise HelperHostRefused(assessment.reason)
        record = super().start()
        source = ControlBindingSource(self.store.db_path, endpoint=self.control_endpoint,
            helper_identity=self.process.identity, guardian_epoch=self.control_guardian_epoch,
            profile=self.profile, retained_binding=self._retained_binding)
        initial = source.read(self.sampler.enrolled)
        if initial.mode not in {'canary','limited'}:
            raise HelperHostRefused('helper_control_mode_inactive')

        def client_factory(endpoint, identity):
            # Kept out of helper_host.py and called lazily only after the live
            # binding plus evidence-authorized frame is eligible.
            from .control_transport import ControlProposalClient
            if identity != self.process.identity:
                raise HelperHostRefused('helper_control_identity_changed')
            return ControlProposalClient(endpoint, caller_process_or_identity=self.process)

        from .capability_evidence import HelperProposalEvidence
        self.control = HelperControl(profile=self.profile, sampler=self.sampler,
            binding_source=source, evidence_authority=HelperProposalEvidence(self.evidence_authority),
            client_factory=client_factory, clock=self._clock)
        return {**record, 'event':'helper_control_host_started', 'mode':initial.mode,
                'capability_verified':True}

    def _retained_binding(self, execution_id):
        entry = self.jobs._entries.get(execution_id)
        if entry is None or entry.unreadable or entry.cleanup_unverified or entry.job.closed:
            raise HelperHostRefused('helper_retained_job_unavailable')
        return (entry.job.name, entry.job.nonce, entry.job.logon_sid, entry.counter_epoch)

    def run_once(self):
        if not self._started or self.control is None:
            raise HelperHostRefused('helper_control_host_not_started')
        self._iterations += 1
        refreshed = False
        if self._iterations > 1 and (self._iterations-1) % self.enroll_every_ticks == 0:
            self.refresh_enrollment()
            refreshed = True
        if self.control.pending is not None:
            result = self.control.reconcile()
        else:
            result = self._refresh_and_tick()
        self._control_last = result
        self._last_reason = result.reason
        # Closing query handles is not a lifecycle release or restoration ACK.
        released = 0
        for execution_id in self.jobs.unreadable():
            self._release(execution_id)
            released += 1
        self._dropped += released
        return TickOutcome(result.reason, False, refreshed, released, self._pace())

    def _refresh_and_tick(self):
        if self.control.restoration_only:
            return self.control.tick()
        try:
            # Read scope/mode, close the transaction, then refresh the prepared
            # capability receipt. No lock or sampling bracket spans this work.
            binding = self.control.source.read(self.sampler.enrolled)
            if binding.mode not in {'canary','limited'}:
                return self.control.tick()
            assessment = self.evidence_authority.assess()  # assess/refresh share the prepared-receipt API
            if not assessment.eligible:
                return self.control.evidence_unavailable()
        except Exception:
            return self.control.evidence_unavailable()
        return self.control.tick()

    def metrics_record(self):
        result = self._control_last
        return {'event':'helper_control_host_metrics', 'iterations':self._iterations,
                'enrolled':len(self.jobs.enrolled), 'reason':self._last_reason,
                'outcome_uncertain':None if result is None else result.uncertain,
                'operation':None if result is None else result.operation,
                'acknowledged_episode':bool(self.control and self.control.acknowledged),
                'pending_operation':bool(self.control and self.control.pending),
                'handles_retained_uncertain':self.jobs.retained_uncertain}

    def request_stop(self, reason='mode_off'):
        if self.control is None:
            return None
        self._control_last = self.control.request_stop(reason)
        return self._control_last

    def close(self):
        result = self.request_stop('helper_shutdown')
        if self.control is not None and self.control.drain_pending:
            # Caller keeps ticking bounded reconciliation/observations. Query
            # custody remains available; no false clean shutdown is returned.
            raise HelperHostRefused('helper_control_drain_pending')
        closed = super().close()
        return {**closed, 'event':'helper_control_host_closed',
                'control_restore_verified':None if result is None else result.acknowledged,
                'control_outcome_uncertain':None if result is None else result.uncertain}


class _HelperOperatorHost:
    """Explicit parent-bound operational surface, with no discovery file.

    Operator transport authenticates its actual peer before this callback. The
    extra exact-parent check narrows a helper's stop authority to its original
    supervisor; it does not create a same-SID general control endpoint. Drain
    never invokes active policy: any existing sender reconciles restoration,
    then the separate observer sends only authenticated recovery frames.
    """

    def __init__(self, *, instance_id, operator_instance_id, parent_instance_id,
                 policy_instance_id, guardian_epoch, parent_identity, guardian_endpoint,
                 listener_factory=None, observer_factory=None, parent_opener=None, **kwargs):
        from .contracts import ProcessIdentity, _identifier
        from .ipc import _uuid
        from .pipe_windows import NativePipeEndpoint

        for value in (instance_id, operator_instance_id, parent_instance_id, policy_instance_id):
            _uuid(value)
        _identifier(guardian_epoch, "guardian_epoch")
        if (type(parent_identity) is not ProcessIdentity or type(guardian_endpoint) is not NativePipeEndpoint
                or parent_identity.logon_id != guardian_endpoint.logon_id
                or parent_identity == guardian_endpoint.server_identity):
            raise HelperHostRefused("helper_operator_parent_binding_invalid")
        if isinstance(self, HelperControlHost):
            super().__init__(guardian_epoch=guardian_epoch, **kwargs)
        else:
            super().__init__(**kwargs)
        if (hasattr(self, "control_endpoint") and (self.control_endpoint != guardian_endpoint or
                self.control_guardian_epoch != guardian_epoch)):
            raise HelperHostRefused("helper_operator_control_binding_mismatch")
        self.instance_id, self.operator_instance_id = instance_id, operator_instance_id
        self.parent_instance_id, self.policy_instance_id = parent_instance_id, policy_instance_id
        self.guardian_epoch, self.parent_identity = guardian_epoch, parent_identity
        self.guardian_endpoint = guardian_endpoint
        self._listener_factory, self._observer_factory = listener_factory, observer_factory
        self._parent_opener = parent_opener
        self.parent_process = self.operator_endpoint = self.operator_service = self.operator_listener = None
        self._pipe_registry = self._drain_observer = self._drain_last = None
        self._operator_ready = self._drain_requested = self._cleanup_started = self._closed = False
        self._drain_request = self._startup_error = self._cleanup_error = self._operator_error = None
        self._operator_requests = {}
        self._last_enrollment_complete = False
        self._registry_revision = None
        self._runtime_off_clear = False
        self._drain_reason = None

    def start(self):
        from .identity import VerifiedProcess
        from .operator_transport import OperatorService
        from .pipe_windows import NativePipeEndpoint, NativePipeListener, NativePipeRegistry

        try:
            opener = VerifiedProcess.open if self._parent_opener is None else self._parent_opener
            self.parent_process = opener(self.parent_identity)
            self._parent_alive()
            record = super().start()
            if (self.process.identity.logon_id != self.parent_identity.logon_id
                    or self.process.identity in (self.parent_identity, self.guardian_endpoint.server_identity)):
                raise HelperHostRefused("helper_operator_identity_conflict")
            self._check_runtime_binding()
            self._make_observer()
            self.operator_endpoint = NativePipeEndpoint(self.process.identity.logon_id,
                self.operator_instance_id, self.process.identity)
            self._pipe_registry = NativePipeRegistry(max_resources=4)
            factory = NativePipeListener if self._listener_factory is None else self._listener_factory
            self.operator_listener = factory(self.operator_endpoint, registry=self._pipe_registry)
            self.operator_service = OperatorService(self.operator_endpoint,
                instance_id=self.instance_id, policy_instance_id=self.policy_instance_id,
                guardian_epoch=self.guardian_epoch, handler=self.handle_operator, scope="helper")
            self._operator_ready = True
            return {**record, "operator_instance_id": self.operator_instance_id,
                "instance_id": self.instance_id, "parent_instance_id": self.parent_instance_id,
                "operator_scope": "helper"}
        except BaseException as error:
            self._startup_error = error
            raise

    def _parent_alive(self):
        from .contracts import IdentityStatus
        from .identity import VerifiedProcess

        if not isinstance(self.parent_process, VerifiedProcess):
            raise HelperHostRefused("helper_operator_parent_unverified")
        observed = self.parent_process.observe()
        if observed.identity != self.parent_identity or observed.status is not IdentityStatus.ALIVE:
            raise HelperHostRefused("helper_operator_parent_unverified")

    def _check_runtime_binding(self):
        with _ipc_read_transaction(self.store.db_path, timeout_ms=250) as conn:
            row = conn.execute("""SELECT substr(policy_instance_id,1,37), substr(policy_logon_id,1,129),
                substr(guardian_epoch,1,129), registry_revision, policy_binding_initialized,
                substr(mode,1,9), substr(admission_barrier,1,20)
                FROM adaptive_runtime WHERE singleton=1""").fetchone()
        if (row is None or tuple(row[:3]) != (self.policy_instance_id, self.parent_identity.logon_id,
                self.guardian_epoch) or row[4] != 1 or type(row[3]) is not int or row[3] < 0):
            raise HelperHostRefused("helper_operator_runtime_binding_changed")
        self._registry_revision = row[3]
        self._runtime_off_clear = tuple(row[5:]) == ("off", "NONE")

    def _retained_binding(self, execution_id):
        entry = self.jobs._entries.get(execution_id)
        if entry is None or entry.unreadable or entry.cleanup_unverified or entry.job.closed:
            raise HelperHostRefused("helper_retained_job_unavailable")
        return (entry.job.name, entry.job.nonce, entry.job.logon_sid, entry.counter_epoch)

    def _restore_pending(self):
        control = getattr(self, "control", None)
        if control is None:
            return False
        # A general off barrier belongs to the frame-only observer. The active
        # sender retains only its pending RPC, acknowledged cap and uncertainty;
        # its legacy per-execution barrier marker must not block observation.
        return (control.pending is not None or control.acknowledged is not None
                or getattr(control, "_uncertain", False))

    def _make_observer(self):
        from .helper_observation import HelperDrainObserver

        source = ControlBindingSource(self.store.db_path, endpoint=self.guardian_endpoint,
            helper_identity=self.process.identity, guardian_epoch=self.guardian_epoch,
            profile=self.profile, retained_binding=self._retained_binding)

        def client_factory(endpoint, identity):
            from .control_transport import ObservationClient
            if identity != self.process.identity:
                raise HelperHostRefused("helper_control_identity_changed")
            return ObservationClient(endpoint, caller_process_or_identity=self.process)

        factory = HelperDrainObserver if self._observer_factory is None else self._observer_factory
        self._drain_observer = factory(profile=self.profile, sampler=self.sampler,
            binding_source=source, client_factory=client_factory, clock=self._clock,
            restore_pending=self._restore_pending)

    def refresh_enrollment(self):
        record = super().refresh_enrollment()
        self._last_enrollment_complete = (record["ledger"] is None
            and record["ledger_truncated"] is False and record["ledger_rows_rejected"] == 0
            and record["left_out"] == 0 and record["open_failed"] == 0
            and not record["cleanup_unverified"] and self.jobs.retained_uncertain == 0)
        return record

    def request_drain(self, reason="mode_off", request=None):
        # Retain monotonic stop intent before any RPC or fallible bookkeeping.
        self._drain_requested = True
        if self._drain_reason is None:
            self._drain_reason, self._drain_request = reason, request
        if self._drain_observer is not None:
            self._drain_observer.request_drain()

    def handle_operator(self, request, *, caller_identity):
        from .operator_messages import (MAX_OPERATOR_REQUESTS, OperatorOperation, OperatorOutcome,
                                        OperatorReply, OperatorRequest)
        from .operator_transport import OperatorTransportError

        if (type(request) is not OperatorRequest or caller_identity != self.parent_identity
                or request.instance_id != self.instance_id
                or request.policy_instance_id != self.policy_instance_id
                or request.guardian_epoch != self.guardian_epoch):
            raise OperatorTransportError("helper_operator_parent_binding_mismatch")
        self._parent_alive()
        if request.operation not in (OperatorOperation.DESCRIBE, OperatorOperation.DRAIN):
            raise OperatorTransportError("operator_scope_unsupported")
        if request.operation is OperatorOperation.DRAIN:
            payload = request.to_json()
            prior = self._operator_requests.get(request.request_id)
            if prior is not None and prior != payload:
                raise OperatorTransportError("operator_request_payload_changed")
            if prior is None and len(self._operator_requests) >= MAX_OPERATOR_REQUESTS:
                raise OperatorTransportError("operator_request_capacity")
            self._operator_requests[request.request_id] = payload
            self.request_drain(request=request)
        if request.observe_request_id is not None and request.observe_request_id not in self._operator_requests:
            raise OperatorTransportError("operator_request_unknown")
        try:
            self._check_runtime_binding()
            runtime_known = True
        except Exception:
            runtime_known = False
            self._runtime_off_clear = False
        settled = self._drain_ready()
        pending = self._drain_requested and not self._closed
        return OperatorReply(request.request_id, request.operation, self.instance_id,
            self.policy_instance_id, self.guardian_epoch,
            OperatorOutcome.PENDING if pending else OperatorOutcome.COMPLETE,
            "helper", "helper_drain_ready" if settled else "helper_draining" if pending else "helper_observing",
            accepted=True, desired_mode="off" if self._drain_requested else None,
            host_state="cleanup_pending" if self._cleanup_started and not self._closed else
                "draining" if self._drain_requested else "observing",
            inventory_complete=self._last_enrollment_complete if runtime_known else None,
            native_disabled=None, bookkeeping_settled=None, slot_released=None,
            barrier_cleared=True if settled else None, cleanup_settled=self._closed,
            remaining_executions=len(self.jobs.enrolled),
            remaining_custody=len(self.jobs.enrolled) + self.jobs.retained_uncertain,
            registry_revision=self._registry_revision if runtime_known else None)

    def _drain_ready(self):
        return (self._drain_requested and self._drain_observer is not None
            and self._drain_observer.complete is True and self._restore_pending() is False
            and getattr(self._drain_observer, "cleanup_pending", False) is False
            and self._runtime_off_clear
            and self._last_enrollment_complete and self.jobs.retained_uncertain == 0
            and self._cleanup_error is None and self._operator_error is None)

    def _operator_poll(self):
        from .ipc import IpcError
        from .pipe_windows import NativePipeError

        if self.operator_listener is None or self._operator_error is not None:
            return
        try:
            self.operator_service.serve_once(self.operator_listener, timeout_ms=50)
        except (IpcError, NativePipeError) as error:
            # NativePipeRegistry retains partial I/O/cleanup. Unknown ownership
            # is sticky; a normal idle timeout carries no such obligation.
            status = self._pipe_registry.status()
            if status.pending or status.quarantined or getattr(error, "__notes__", ()):
                self._operator_error = error
                self.request_drain("operator_cleanup_unverified")
        except BaseException as error:
            self._operator_error = error
            self.request_drain("operator_failure")
            raise

    def _drain_tick(self):
        self._iterations += 1
        if self._cleanup_started:
            return TickOutcome("helper_cleanup_unverified", False, False, 0, self._pace())
        refreshed = False
        if self._restore_pending() is False:
            if self._drain_observer.pending is None:
                self.refresh_enrollment()
            else:
                self._retire_observation_handles()
            refreshed = True
        control = getattr(self, "control", None)
        if control is not None and self._restore_pending():
            # Stop latches before the active sender reconciles any pending RPC.
            # It cannot run ordinary policy or send another restriction here.
            control._stopping = True
            result = control.reconcile() if control.pending is not None else control.request_stop(self._drain_reason)
            self._control_last = result
            reason = result.reason
        elif self._last_enrollment_complete or self._drain_observer.pending is not None:
            self._drain_last = self._drain_observer.tick()
            reason = self._drain_last.reason
        else:
            reason = "helper_drain_inventory_unverified"
        try:
            self._check_runtime_binding()
        except Exception:
            self._runtime_off_clear = False
        self._last_reason = reason
        return TickOutcome(reason, False, refreshed, 0, self._pace())

    def _retire_observation_handles(self):
        """Retire departed query scopes without replacing a pending frame.

        An immutable pending frame may outlive natural Job finalization. Let
        its observer ask for the old receipt using the CURRENT enrolled set;
        never reopen/replace an overlapping query handle or relabel that frame.
        New scope enrollment waits until the pending receipt is reconciled.
        """
        try:
            candidates, truncated, invalid = self._ledger_candidates()
        except Exception:
            self._last_enrollment_complete = False
            return
        if truncated or invalid:
            self._last_enrollment_complete = False
            return
        live = {item.execution_id for item in candidates}
        for execution_id in self.jobs.enrolled:
            if execution_id not in live:
                self._release(execution_id)
        self._last_enrollment_complete = (live == set(self.jobs.enrolled)
            and not self.jobs.unreadable() and self.jobs.retained_uncertain == 0)

    def run_once(self):
        result = self._drain_tick() if self._drain_requested else super().run_once()
        self._operator_poll()
        return result

    def serve_until_stopped(self):
        while True:
            try:
                self.run_once()
                self._report()
                if self._drain_ready():
                    return self.close()
            except KeyboardInterrupt as error:
                self.request_drain("interrupted")
                self._run_interrupt = error
            except Exception as error:
                self._run_failure = error
                self.request_drain("helper_host_failure")
                emit({"event": "helper_host_pending", "reason": _reason(error)})
                self._sleep(1)

    def close(self):
        if self._closed:
            return {"event": "helper_operator_host_closed", "registry_row_retained": self.registered}
        if self._cleanup_error is not None:
            raise HelperHostRefused("helper_host_cleanup_quarantined")
        if self._startup_error is not None and (getattr(self._startup_error, "__notes__", ()) or
                getattr(self._startup_error, "_identity_handle_cleanup", ()) or
                getattr(self._startup_error, "_native_close_outcome_unknown", False)):
            raise HelperHostRefused("helper_host_startup_cleanup_unverified")
        if self._operator_ready and self._drain_requested and self._drain_observer is not None:
            # A cached successful observation is not permission to leave after
            # the binding, mode or recovery obligations subsequently changed.
            self._drain_last = self._drain_observer.tick()
            self._check_runtime_binding()
        if self._operator_ready and not self._drain_ready():
            raise HelperHostRefused("helper_operator_drain_pending")
        self._cleanup_started = True
        try:
            # Bypass active-host's per-execution barrier marker: the dedicated
            # observer has positively checked the complete general off barrier.
            record = HelperHost.close(self)
            if self.operator_listener is not None:
                self.operator_listener.close()
                self.operator_listener = None
            if self._pipe_registry is not None:
                status = self._pipe_registry.status()
                if status.resources:
                    raise HelperHostRefused("helper_operator_pipe_cleanup_pending")
            for name in ("parent_process", "process"):
                process = getattr(self, name)
                if process is not None:
                    process.close()
                    setattr(self, name, None)
        except BaseException as error:
            self._cleanup_error = error
            raise
        self._closed = True
        return {**record, "event": "helper_operator_host_closed", "operator_scope": "helper"}


class OperationalHelperHost(_HelperOperatorHost, HelperHost):
    """Default shadow helper plus an explicit original-parent drain endpoint."""


class OperationalHelperControlHost(_HelperOperatorHost, HelperControlHost):
    """Explicit active host whose operator drain never returns to active policy."""


def run_operational(host, *, iterations=0):
    """Keep process-local obligations resident after interrupts or close faults."""
    from .helper_host import EXIT_OK, EXIT_REFUSED

    try:
        emit(host.start())
    except BaseException as error:
        host._startup_error = error
        emit({"event": "helper_host_refused", "reason": _reason(error)})
        try:
            emit(host.close())
        except BaseException as cleanup:
            host._exit_failure = cleanup
            return retain_cleanup(host)
        return EXIT_REFUSED
    if iterations:
        try:
            emit(host.run_bounded(iterations))
        except BaseException as error:
            host._run_failure = error
        host.request_drain("bounded_run_complete")
    emit(host.serve_until_stopped())
    return EXIT_OK


def retain_cleanup(host):
    """Unknown close keeps the original objects alive; it never proves exit.

    Only existing owners may eventually prove cleanup. This deliberately has
    no fresh process open, retry-close loop or force flag. External process
    termination is outside the clean-shutdown contract.
    """
    reported = False
    while True:
        try:
            if not reported:
                emit({"event": "helper_host_pending", "reason": "helper_cleanup_unverified"})
                reported = True
            operation = getattr(host, "_registration_operation", None)
            if operation is not None and operation.pending and not operation._quarantine:
                try:
                    # Retry the same original operation/guard; _run itself
                    # verifies nonce and native cleanup before another attempt.
                    host._register()
                    emit(host.close())
                    from .helper_host import EXIT_REFUSED
                    return EXIT_REFUSED
                except Exception as error:
                    host._retained_registration_error = error
            host._sleep(1)
        except KeyboardInterrupt as error:
            host._cleanup_interrupt = error


def operational_options(options):
    """Parse the complete explicit child binding; a partial tuple is refused."""
    from .contracts import ProcessIdentity
    from .pipe_windows import NativePipeEndpoint

    names = ("instance_id", "operator_instance_id", "parent_instance_id", "policy_instance_id",
        "guardian_epoch", "parent_pid", "parent_created_filetime", "parent_logon_id",
        "guardian_pid", "guardian_created_filetime", "guardian_logon_id", "guardian_control_instance_id")
    supplied = [getattr(options, name, None) for name in names]
    if all(value is None for value in supplied):
        return None
    if any(value is None for value in supplied):
        raise HelperHostRefused("helper_operator_arguments_incomplete")
    try:
        parent = ProcessIdentity(options.parent_pid, int(options.parent_created_filetime), options.parent_logon_id)
        guardian = ProcessIdentity(options.guardian_pid, int(options.guardian_created_filetime), options.guardian_logon_id)
        endpoint = NativePipeEndpoint(guardian.logon_id, options.guardian_control_instance_id, guardian)
        return dict(instance_id=options.instance_id, operator_instance_id=options.operator_instance_id,
            parent_instance_id=options.parent_instance_id, policy_instance_id=options.policy_instance_id,
            guardian_epoch=options.guardian_epoch, parent_identity=parent, guardian_endpoint=endpoint)
    except (TypeError, ValueError) as error:
        raise HelperHostRefused("helper_operator_arguments_invalid") from error
