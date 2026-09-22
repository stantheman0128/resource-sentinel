"""Explicit active helper wiring; no default CLI or discovery/mode mutation.

The existing HelperHost remains shadow-only. This separately constructed host
reuses its query-only handles, registration and paced enrollment, but never runs
its shadow policy loop. The endpoint and evidence authority are explicit inputs.
"""
from .helper_host import HelperHost, HelperHostRefused, TickOutcome
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

        self.control = HelperControl(profile=self.profile, sampler=self.sampler,
            binding_source=source, evidence_authority=self.evidence_authority,
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
