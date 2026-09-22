"""Authenticated, no-cap launch ownership and post-launch guardian custody.

This service component consumes the shared admitted row, not a remote
ManagedAdmission or command. A provisioned host authority must establish actual
continuous capacity coverage and loaded legacy-writer exclusion. Its default
denies preparation. Construction never installs a task, migrates a daily DB,
enables a mode, or promises that the current host supports managed launch.

The fixed Prepare/Claim/Bind chain records durable operation identities and
scope before native Create. Unknown outcomes retain the exact owners; neither
an RPC receipt nor replay grants a second Create/launch. Native peer handles
are borrowed by IPC and duplicated before they enter retained custody.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields
from uuid import uuid4

from .contracts import (AllocationKind, CpuControl, CpuControlMode, IdentityStatus,
                        ProcessIdentity, RecoveryManifest, ReservationRef, ResourceDemand)
from .guardian_lifecycle import GuardianLifecycle
from .identity import VerifiedProcess
from .native_job import JobAccess, NativeJob
from .recovery_journal import RecoveryJournalError
from .store import LifecycleError, LifecycleEvidence


_DISABLED = CpuControl(CpuControlMode.DISABLED, None)


class _UnavailableAuthority:
    def assert_ready(self):
        raise LifecycleError("native_launch_authority_unavailable")


class _PendingExecution:
    def __init__(self, owner, row, wrapper, auth):
        self.owner, self.wrapper, self.auth = owner, wrapper, auth
        self.execution_id, self.spec_hash = row["execution_id"], row["spec_hash"]
        self.reservation = ReservationRef(AllocationKind(row["allocation_kind"]), row["reservation_id"])
        self.creation_nonce = uuid4().hex
        self.job_name = f"Local\\ResourceSentinel.Job.{self.execution_id}.{self.creation_nonce}"
        self.job = self.root = self.mutex = self.record = None
        self.create_attempted = self.membership_verified = False
        self.manifest_created = False
        self.initial_retryable = False
        self.pending_record = None
        self.transfer_error = self.journal_cleanup_error = None
        self.retirement_sealed = False
        self.retirement_operation = None
        self.closed_handles = set()
        self.retirement_cleanup_started = False
        self.retirement_mutex_close_unknown = False

    def assert_held(self):
        self.owner.lifecycle.store._policy.assert_held()
        lifecycle = self.owner.lifecycle
        import threading
        if (lifecycle._scope_entry is not self or lifecycle._scope_thread != threading.get_ident()
                or self.mutex is None):
            raise LifecycleError("guardian_launch_scope_required")

    def query_cpu_control(self):
        self.assert_held()
        if self.job is None:
            raise LifecycleError("guardian_job_unavailable")
        return GuardianLifecycle._control(self)

    def assert_job_creation_unattempted(self):
        self.assert_held()
        if self.create_attempted or self.job is not None:
            raise LifecycleError("guardian_job_creation_already_attempted")


class GuardianLaunchOwner:
    """One fixed dispatcher for prepared and started scopes, at most ten Jobs.

    authority is a trusted runtime collaborator with assert_ready(),
    assert_covered(row), assert_excluded(row). These are continuous operational
    obligations, not wire booleans or persisted readiness flags. Test factories
    below are explicit in-process seams and cannot certify native acceptance.
    The owner retains partial objects until explicit reconciliation; there is no
    destructor or blanket cleanup that could discard an uncertain allocation.
    """

    def __init__(self, store, journal, *, guardian_epoch, authority=None,
                 guardian=None, job_factory=None, mutex_factory=None):
        from .contracts import _identifier
        _identifier(guardian_epoch, "guardian_epoch")
        self.guardian_epoch = guardian_epoch
        self.store, self.journal = store, journal
        self.authority = _UnavailableAuthority() if authority is None else authority
        self.lifecycle = GuardianLifecycle(store, journal, guardian=guardian,
            mutex_factory=mutex_factory, install_evidence_provider=False)
        self.guardian = self.lifecycle.guardian
        self._job_factory = NativeJob.create if job_factory is None else job_factory
        self._pending = {}
        self._failed_peers = {}
        self._uncertain = []
        self._lock = self.lifecycle._lock
        self._draining = False
        self.store.evidence_provider = self.evidence_scope

    def begin_drain(self):
        """Permanently stop new Job creation and launch grants, retaining cleanup."""
        with self._lock:
            self._draining = True

    @property
    def retained_execution_ids(self):
        with self._lock:
            return tuple(self._pending) + self.lifecycle.retained_execution_ids + tuple(self._failed_peers)

    def restore_owned_caps(self):
        """Restore the bounded adopted inventory without new admission/readiness.

        Pending launch scopes have never received cap authority. Every adopted
        entry gets one bounded attempt, so one bookkeeping failure cannot strand
        a later cap. An aggregate error retains all unresolved outcomes.
        """
        with self._lock:
            from .guardian_restore import RestoreBatchError
            results, errors = [], []
            for execution_id in self.lifecycle.retained_execution_ids:
                try:
                    results.append(self.lifecycle.restore_owned_cap(execution_id))
                except BaseException as error:
                    errors.append((execution_id, error))
            if errors:
                failure = RestoreBatchError(results, errors)
                failure.guardian_restore_owner = self
                raise failure
            return tuple(results)

    @staticmethod
    def _deadline(deadline):
        if deadline.remaining_ms() <= 0:
            raise LifecycleError("guardian_launch_deadline_exceeded")

    def _authenticate(self, request, peer, auth, deadline, *, terminal_bind=False, terminal_retirement=False):
        self._deadline(deadline)
        self.lifecycle._validate_guardian()
        if not isinstance(peer, VerifiedProcess):
            raise LifecycleError("guardian_peer_required")
        observed = peer.observe()
        if (observed.status is not IdentityStatus.ALIVE or observed.identity != peer.identity or
                peer.identity != auth.wrapper_identity or peer.identity == self.guardian.identity or
                peer.identity.logon_id != self.guardian.identity.logon_id or
                request.guardian_epoch != self.guardian_epoch):
            raise LifecycleError("guardian_peer_mismatch")
        row = self.store.query(request.execution_id, existing_path=True)
        if (request.spec_hash != row["spec_hash"] or request.execution_id != auth.execution_id or
                row["role"] != "background" or row["priority"] not in {"P2", "P3"}):
            raise LifecycleError("guardian_launch_binding_mismatch")
        if not ((terminal_bind and row["state"] == "FINISHED" and
                 request.execution_id in self.lifecycle.retained_execution_ids) or
                (terminal_retirement and (row["state"] in {"CANCELLED_BEFORE_START", "START_FAILED"} or
                    (request.operation == "CancelBeforeStart" and row["state"] == "FINISHED")))):
            self.store.assert_authenticated_allocation(row, caller=peer.identity, expected_auth=auth)
        # The sole terminal exception proceeds only to the existing request's
        # same-transaction auth replay and retained terminal/native proof.
        return row

    def _authority(self, operation, *args):
        if getattr(self.authority, operation)(*args) is not None:
            raise LifecycleError("guardian_authority_unverified")

    def _check_entry(self, entry, row):
        if (row["execution_id"] != entry.execution_id or row["spec_hash"] != entry.spec_hash or
                row["allocation_kind"] != entry.reservation.kind.value or
                row["reservation_id"] != entry.reservation.id or
                row["wrapper_pid"] != entry.wrapper.identity.pid or
                row["wrapper_created_filetime_100ns"] != str(entry.wrapper.identity.created_filetime_100ns) or
                row["logon_id"] != entry.wrapper.identity.logon_id):
            raise LifecycleError("guardian_launch_binding_mismatch")
        if row["job_name"] is not None and (row["job_name"] != entry.job_name or
                row["job_nonce"] != entry.creation_nonce or row["guardian_epoch"] != self.guardian_epoch):
            raise LifecycleError("guardian_launch_scope_mismatch")

    def _covered(self, entry, row, *, recovery=False):
        self._check_entry(entry, row)
        self.store.assert_authenticated_allocation(row, caller=entry.wrapper.identity, expected_auth=entry.auth)
        if not recovery:
            self._authority("assert_ready")
            self._authority("assert_covered", row)

    def _record_request(self, request, peer, auth, *, replay_only=False):
        if replay_only:
            # POLICY remains held through the exact request check and the
            # store's authenticated replay. A refused request never seeds a slot.
            guard = self.store._policy.assert_held()
            with self.store._connection() as conn:
                self.store._policy.revalidate(conn, guard)
                recorded = conn.execute("""SELECT execution_id,operation,request_id,payload_hash,spec_hash,guardian_epoch
                    FROM adaptive_launch_requests WHERE (execution_id=? AND operation=?) OR request_id=? LIMIT 2""",
                    (request.execution_id, request.operation, request.request_id)).fetchall()
            if not recorded:
                raise LifecycleError("guardian_launch_draining")
            if len(recorded) != 1 or tuple(recorded[0]) != (request.execution_id, request.operation,
                    request.request_id, request.payload_hash(), request.spec_hash, request.guardian_epoch):
                raise LifecycleError("launch_request_mismatch")
        return self.store.record_launch_request_locked(request.execution_id, request.operation,
            request.request_id, request.payload_hash(), caller=peer.identity, expected_auth=auth,
            guardian_epoch=request.guardian_epoch)

    def _read_manifest(self, entry):
        entry.assert_held()
        record = self._read_record(entry)
        if (record.execution_id != entry.execution_id or record.spec_hash != entry.spec_hash or
                record.reservation != entry.reservation or record.job_name != entry.job_name or
                record.guardian_identity != self.guardian.identity or
                record.guardian_epoch != self.guardian_epoch or
                record.wrapper_identity != entry.wrapper.identity or
                record.root_identity != (None if entry.root is None else entry.root.identity) or
                record.original != _DISABLED or record.last_applied is not None or record.pending_intent is not None):
            raise LifecycleError("guardian_launch_manifest_mismatch")
        if entry.record is not None and record != entry.record:
            raise LifecycleError("guardian_launch_manifest_changed")
        entry.record = record
        return record

    def _read_record(self, entry):
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("guardian_journal_cleanup_unverified")
        try:
            return self.journal.read(entry.execution_id, creation_nonce=entry.creation_nonce)
        except BaseException as error:
            if hasattr(error, "_journal_cleanup_owner"):
                entry.journal_cleanup_error = error
            raise

    def _result(self, request, row, *, authorized=False, duplicate=False):
        from .launch_transport import LaunchResult
        return LaunchResult(execution_id=row["execution_id"], spec_hash=row["spec_hash"],
            guardian_epoch=row["guardian_epoch"], state=row["state"], state_revision=row["state_revision"],
            job_name=row["job_name"], job_nonce=row["job_nonce"],
            launch_authorized=authorized, duplicate=duplicate)

    def prepare_execution(self, request, peer, auth_record, deadline):
        with self._lock:
            row = self._authenticate(request, peer, auth_record, deadline)
            if not self._draining:
                self._authority("assert_ready")
            if request.execution_id in self._failed_peers:
                raise LifecycleError("guardian_peer_transfer_reconciliation_required")
            entry = self._pending.get(request.execution_id)
            if entry is None:
                if (row["state"] != "RESERVED" or row["job_name"] is not None or row["claim_consumed"] or
                        request.execution_id in self.lifecycle.retained_execution_ids):
                    raise LifecycleError("guardian_launch_recovery_required")
                if len(self.retained_execution_ids) >= 10:
                    raise LifecycleError("managed_job_limit_reached")
                self.store._require_revision(row, request.expected_revision)
                # Independently duplicate before the IPC borrowed peer closes.
                try:
                    wrapper = peer.duplicate()
                except BaseException as error:
                    if getattr(error, "_identity_handle_cleanup", ()):
                        self._failed_peers[request.execution_id] = error
                    raise
                try:
                    entry = _PendingExecution(self, row, wrapper, auth_record)
                    self._pending[request.execution_id] = entry
                except BaseException as primary:
                    self._failed_peers[request.execution_id] = wrapper
                    primary.add_note("guardian_wrapper_custody_retained")
                    raise
            with self.lifecycle._scope(entry):
                if self._draining:
                    return self._prepare_retirement_scope(request, peer, auth_record, entry, deadline)
                if entry.retirement_sealed:
                    raise LifecycleError("guardian_launch_retirement_sealed")
                row = self.store.query(request.execution_id, existing_path=True)
                self._covered(entry, row)
                duplicate = self._record_request(request, peer, auth_record)
                if row["state"] == "PREPARED" and entry.job is not None:
                    self._verify_prepared(entry, row)
                    return self._result(request, row, duplicate=True)
                if row["state"] != "RESERVED":
                    raise LifecycleError("guardian_launch_recovery_required")
                if row["job_name"] is None:
                    row = self.store.register_job_scope(request.execution_id, caller=peer.identity,
                        expected_revision=row["state_revision"], guardian_epoch=self.guardian_epoch,
                        job_name=entry.job_name, job_nonce=entry.creation_nonce, expected_auth=auth_record)
                if entry.record is None:
                    entry.record = self._initial_record(entry, row)
                if not entry.manifest_created:
                    self._publish_initial(entry)
                self._read_manifest(entry)
                self._authority("assert_excluded", row)
                self._deadline(deadline)
                if entry.job is None:
                    if entry.create_attempted:
                        raise LifecycleError("guardian_job_create_outcome_unknown")
                    entry.create_attempted = True
                    try:
                        entry.job = self._job_factory(entry.job_name, entry.creation_nonce,
                            entry.wrapper.identity.logon_id, access=JobAccess.OWNER)
                    except BaseException as error:
                        self._uncertain.append(error)
                        raise
                self._verify_prepared(entry, row)
                row = self.store.mark_prepared(request.execution_id, caller=peer.identity,
                    expected_revision=row["state_revision"], expected_auth=auth_record)
                self._deadline(deadline)
                return self._result(request, row, duplicate=duplicate)

    def _prepare_retirement_scope(self, request, peer, auth_record, entry, deadline):
        """Keep the original wrapper's cleanup route without ever creating a Job.

        A Prepare first delivered after drain may retain a bounded, sealed,
        never-created owner. Only its exact request can recover this scope;
        normal launch rejects RESERVED and Claim cannot grant new authority.
        """
        row = self.store.query(request.execution_id, existing_path=True)
        self._covered(entry, row, recovery=True)
        duplicate = self._record_request(request, peer, auth_record)
        if row["state"] not in {"RESERVED", "PREPARED"}:
            raise LifecycleError("guardian_launch_recovery_required")
        entry.retirement_sealed = True
        if row["job_name"] is None:
            row = self.store.register_job_scope(request.execution_id, caller=peer.identity,
                expected_revision=row["state_revision"], guardian_epoch=self.guardian_epoch,
                job_name=entry.job_name, job_nonce=entry.creation_nonce, expected_auth=auth_record)
        if entry.job is None and not entry.create_attempted:
            if entry.record is None:
                entry.record = self._initial_record(entry, row)
            if not entry.manifest_created:
                self._publish_initial(entry)
        # Named-scope registration must advance a first RESERVED admission.
        # The informational response never stands in for completed preparation.
        if row["state_revision"] <= request.expected_revision:
            raise LifecycleError("guardian_launch_recovery_required")
        self._deadline(deadline)
        return self._result(request, row, duplicate=duplicate)

    def _initial_record(self, entry, row):
        entry.assert_job_creation_unattempted()
        self._check_entry(entry, row)
        return RecoveryManifest.create(execution_id=entry.execution_id,
            reservation=entry.reservation, spec_hash=entry.spec_hash,
            job_name=entry.job_name, creation_nonce=entry.creation_nonce,
            wrapper_identity=entry.wrapper.identity, root_identity=None,
            guardian_identity=self.guardian.identity, guardian_epoch=self.guardian_epoch,
            original=_DISABLED, last_applied=None, pending_intent=None,
            allocated_floor=ResourceDemand.from_dict({key: row["floor_" + key] for key in
                ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")}), manifest_seq=0)

    def _publish_initial(self, entry):
        entry.assert_job_creation_unattempted()
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("guardian_journal_cleanup_unverified")
        if not hasattr(entry, "initial_attempted") or entry.initial_retryable:
            entry.initial_attempted = True
            entry.initial_retryable = False
            try:
                self.journal.create(entry.record, writer_scope=entry)
            except BaseException as error:
                entry.initial_retryable = (type(error) is RecoveryJournalError and
                    error.publication_may_have_occurred is False and
                    error.reason not in {"manifest_already_exists", "manifest_path_unsafe"} and
                    not getattr(error, "__notes__", ()))
                if hasattr(error, "_journal_cleanup_owner"):
                    entry.journal_cleanup_error = error
                raise
        else:
            # Exact readback alone does not repair a lost durable publication
            # ACK. Reaffirm the initial record before the first native Create.
            try:
                self.journal.reaffirm_initial(entry.record, writer_scope=entry)
            except BaseException as error:
                if hasattr(error, "_journal_cleanup_owner"):
                    entry.journal_cleanup_error = error
                raise
        entry.manifest_created = True

    def _verify_prepared(self, entry, row):
        self._covered(entry, row)
        if (entry.job.name != entry.job_name or entry.job.nonce != entry.creation_nonce or
                entry.job.logon_sid != entry.wrapper.identity.logon_id or
                self.guardian.is_in_job(entry.job.handle) is not False or
                entry.wrapper.is_in_job(None) is not False):
            raise LifecycleError("guardian_launch_host_unverified")
        limits = entry.job.query_limits()
        if limits.limit_flags != 0 or limits.ui_restrictions != 0:
            raise LifecycleError("guardian_job_limits_unverified")
        if GuardianLifecycle._members(entry) != (0, ()) or entry.query_cpu_control() != _DISABLED:
            raise LifecycleError("guardian_job_not_pristine")
        self._read_manifest(entry)
        self._authority("assert_excluded", row)

    def claim_launch(self, request, peer, auth_record, deadline):
        with self._lock:
            row = self._authenticate(request, peer, auth_record, deadline)
            entry = self._pending.get(request.execution_id)
            if entry is None or request.job_nonce != entry.creation_nonce:
                raise LifecycleError("guardian_launch_scope_missing")
            with self.lifecycle._scope(entry):
                if self._draining:
                    return self._claim_replay_during_drain(request, peer, auth_record, entry, deadline)
                if entry.retirement_sealed:
                    raise LifecycleError("guardian_launch_retirement_sealed")
                self._covered(entry, row)
                self._record_request(request, peer, auth_record)
                if row["state"] == "PREPARED":
                    self.store.bind_launch_fence_locked(request.execution_id, caller=peer.identity,
                        expected_auth=auth_record, guardian_epoch=self.guardian_epoch,
                        version=request.launch_fence_version)
                else:
                    self.store.assert_launch_fence(row, version=request.launch_fence_version)
                self._deadline(deadline)
                result = self.store.claim_launch_locked(request.execution_id, caller=peer.identity,
                    claim_token=request.claim_token, spec_hash=request.spec_hash,
                    guardian_epoch=request.guardian_epoch, expected_revision=request.expected_revision,
                    expected_auth=auth_record)
                return self._result(request, result, authorized=result["launch_authorized"],
                    duplicate=result["duplicate"])

    def _claim_replay_during_drain(self, request, peer, auth_record, entry, deadline):
        from .store import _revalidate_launch_auth

        self._record_request(request, peer, auth_record, replay_only=True)
        guard = self.store._policy.assert_held()
        with self.store._connection() as conn:
            conn.execute("BEGIN")
            self.store._policy.revalidate(conn, guard)
            _revalidate_launch_auth(conn, request.execution_id, peer.identity, auth_record)
            row = self.store._get(conn, request.execution_id)
            self._check_entry(entry, row)
            self.store._authenticate_claim(row, peer.identity, self.store._claim_digest(request.claim_token),
                request.spec_hash, request.guardian_epoch)
            self.store._require_authenticated_allocation(conn, row)
            if not row["claim_consumed"]:
                self.store._require_revision(row, request.expected_revision)
                if row["state"] != "PREPARED" or row["launch_sealed"]:
                    raise LifecycleError("guardian_launch_recovery_required")
            else:
                self.store._assert_launch_fence(conn, row, version=request.launch_fence_version)
            self._deadline(deadline)
            return self._result(request, row, duplicate=True)

    def _retirement_evidence(self, entry, row, operation):
        """Observe before SQL; the caller retains POLICY and the launch fence."""
        entry.assert_held()
        self._check_entry(entry, row)
        self.store.assert_authenticated_allocation(row, caller=entry.wrapper.identity, expected_auth=entry.auth)
        preclaim = row["state"] in {"RESERVED", "PREPARED"} and not row["claim_consumed"] and not row["launch_in_flight"]
        if operation == "cancel" and not preclaim:
            return LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex,
                entry.wrapper.identity, guardian_epoch=self.guardian_epoch,
                job_name=entry.job_name, job_nonce=entry.creation_nonce)
        if (entry.root is not None or row["root_pid"] is not None or row["root_outcome"] is not None or
                entry.transfer_error is not None or entry.journal_cleanup_error is not None):
            raise LifecycleError("guardian_never_started_unverified")
        version = 0
        if not preclaim:
            self.store.assert_launch_fence(row, version=1)
            version = 1
        entry.retirement_sealed = True
        count = members = total = None
        if entry.job is None:
            entry.assert_job_creation_unattempted()
            if not preclaim:
                raise LifecycleError("guardian_never_started_unverified")
            if entry.record is None:
                entry.record = self._initial_record(entry, row)
            if not entry.manifest_created:
                self._publish_initial(entry)
        else:
            if (entry.job.name != entry.job_name or entry.job.nonce != entry.creation_nonce or
                    entry.job.logon_sid != entry.wrapper.identity.logon_id):
                raise LifecycleError("guardian_launch_scope_mismatch")
            accounting = entry.job.accounting()
            for name in ("total_processes", "active_processes", "user_100ns", "kernel_100ns", "total_terminated_processes"):
                value = getattr(accounting, name, None)
                if type(value) is not int or value != 0:
                    raise LifecycleError("guardian_never_started_unverified")
            total = accounting.total_processes
            count, members = GuardianLifecycle._members(entry)
            limits = entry.job.query_limits()
            if (count != 0 or members != () or entry.query_cpu_control() != _DISABLED or
                    limits.limit_flags != 0 or limits.ui_restrictions != 0):
                raise LifecycleError("guardian_never_started_unverified")
        record = self._read_manifest(entry)
        return LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex,
            entry.wrapper.identity, guardian_epoch=self.guardian_epoch, job_name=entry.job_name,
            job_nonce=entry.creation_nonce, launch_sealed=True, user_code_started=False,
            launch_failed=(True if operation == "start_failed" else None), active_process_count=count,
            process_ids=members, current_cpu_disabled=True, original_cpu_disabled=True,
            durable_manifest=True, recovery_manifest_settled=True,
            job_creation_never_attempted=not entry.create_attempted,
            retirement_manifest=record, total_process_count=total, launch_fence_version=version)

    def retire_before_start(self, request, peer, auth_record, deadline):
        """Authenticated retirement trigger; no caller-provided failure evidence."""
        from .launch_transport import CancelBeforeStartRequest, StartFailedRequest
        if type(request) not in {CancelBeforeStartRequest, StartFailedRequest}:
            raise LifecycleError("guardian_retirement_operation_invalid")
        operation = "cancel" if type(request) is CancelBeforeStartRequest else "start_failed"
        terminal = "CANCELLED_BEFORE_START" if operation == "cancel" else "START_FAILED"
        with self._lock:
            row = self._authenticate(request, peer, auth_record, deadline, terminal_retirement=True)
            if (row["job_nonce"] != request.job_nonce or row["guardian_epoch"] != self.guardian_epoch):
                raise LifecycleError("guardian_launch_scope_mismatch")
            entry = self._pending.get(request.execution_id)
            if row["state"] in {"CANCELLED_BEFORE_START", "START_FAILED", "FINISHED"}:
                if row["state"] != terminal and not (operation == "cancel" and row["state"] == "FINISHED"):
                    raise LifecycleError("guardian_retirement_state_mismatch")
                # Retired handles may already be closed. The exact durable
                # proof/manifest/archive, not a missing native name, allows ACK replay.
                if entry is None or entry.retirement_cleanup_started:
                    scope = self.store._policy.hold(self.store._policy.prepare(peer.identity.logon_id))
                else:
                    scope = self.lifecycle._scope(entry)
                with scope:
                    manifest = self.journal.read(request.execution_id, creation_nonce=request.job_nonce)
                    if manifest.guardian_identity != self.guardian.identity:
                        raise LifecycleError("guardian_retirement_owner_mismatch")
                    if (manifest.original != _DISABLED or manifest.pending_intent is not None or
                            manifest.last_applied not in (None, _DISABLED)):
                        raise LifecycleError("guardian_retirement_manifest_unsettled")
                    self.store.assert_retained_terminal(row, manifest)
                    duplicate = self.store.record_retirement_request_locked(request.execution_id,
                        request.operation, request.request_id, request.payload_hash(), caller=peer.identity,
                        expected_auth=auth_record, guardian_epoch=self.guardian_epoch)
                    if not duplicate:
                        raise LifecycleError("guardian_retirement_replay_required")
                return self._result(request, row, duplicate=True)
            if entry is None:
                if operation != "cancel":
                    raise LifecycleError("guardian_launch_scope_missing")
                entry = self.lifecycle._entry(request.execution_id)
                with self.lifecycle._scope(entry):
                    self._check_retirement_revision(request, row, peer, auth_record)
                    duplicate = self.store.record_retirement_request_locked(request.execution_id,
                        request.operation, request.request_id, request.payload_hash(), caller=peer.identity,
                        expected_auth=auth_record, guardian_epoch=self.guardian_epoch)
                    result = self.store.cancel_before_start(request.execution_id, caller=peer.identity,
                        expected_revision=row["state_revision"])
                return self._result(request, result, duplicate=duplicate)
            with self.lifecycle._scope(entry):
                row = self.store.query(request.execution_id, existing_path=True)
                # For a pending cancel replay, the immutable request journal is
                # authoritative; a changed request cannot silently take its place.
                self._check_retirement_revision(request, row, peer, auth_record)
                entry.retirement_operation = operation
                self._retirement_evidence(entry, row, operation)
                self._deadline(deadline)
                duplicate = self.store.record_retirement_request_locked(request.execution_id,
                    request.operation, request.request_id, request.payload_hash(), caller=peer.identity,
                    expected_auth=auth_record, guardian_epoch=self.guardian_epoch)
                method = self.store.cancel_before_start if operation == "cancel" else self.store.mark_start_failed
                result = method(request.execution_id, caller=peer.identity, expected_revision=row["state_revision"])
                if result["state"] == terminal:
                    self.store.assert_retained_terminal(result, self._read_manifest(entry))
                return self._result(request, result, duplicate=duplicate)

    def _check_retirement_revision(self, request, row, peer, auth_record):
        duplicate = self.store.check_retirement_request_locked(request.execution_id, request.operation,
            request.request_id, request.payload_hash(), caller=peer.identity, expected_auth=auth_record,
            guardian_epoch=self.guardian_epoch)
        if not duplicate:
            self.store._require_revision(row, request.expected_revision)

    def retire_completed_pending(self):
        """Each tick retries only positively committed prelaunch cleanup."""
        results = []
        with self._lock:
            for execution_id, entry in tuple(self._pending.items()):
                try:
                    row = self.store.query(execution_id, existing_path=True)
                    if row["state"] not in {"CANCELLED_BEFORE_START", "START_FAILED"}:
                        continue
                    if not entry.retirement_cleanup_started:
                        with self.lifecycle._scope(entry):
                            record = self._read_manifest(entry)
                            self.store.assert_retained_terminal(row, record)
                            if entry.job is not None:
                                if (GuardianLifecycle._members(entry) != (0, ()) or
                                        entry.query_cpu_control() != _DISABLED or
                                        entry.job.accounting().total_processes != 0):
                                    raise LifecycleError("guardian_retirement_changed")
                        # Publish after successful fence exit, before any close.
                        entry.retirement_cleanup_started = True
                    else:
                        # NativeJob becomes non-queryable as soon as close starts;
                        # a possibly closed mutex must never be acquired again.
                        # The immutable terminal receipt is now the authority to
                        # retry only the exact native owners' cleanup contracts.
                        self.lifecycle._validate_guardian()
                        record = self._read_record(entry)
                        if record != entry.record:
                            raise LifecycleError("guardian_retirement_manifest_changed")
                        self.store.assert_retained_terminal(row, record)
                    for name in ("job", "wrapper", "mutex"):
                        owner = getattr(entry, name)
                        if owner is not None and name not in entry.closed_handles:
                            if name == "mutex":
                                from .windows import NativePolicyMutexError
                                if entry.retirement_mutex_close_unknown:
                                    raise LifecycleError("guardian_retirement_mutex_close_unknown")
                                entry.retirement_mutex_close_unknown = True
                                try:
                                    owner.close()
                                except NativePolicyMutexError as error:
                                    if (error.reason == "policy_mutex_handle_close_failed" and
                                            not getattr(error, "__notes__", ())):
                                        entry.retirement_mutex_close_unknown = False
                                    raise
                                entry.retirement_mutex_close_unknown = False
                            else:
                                # Job and process owners quarantine ambiguous
                                # CloseHandle outcomes internally before the call.
                                owner.close()
                            entry.closed_handles.add(name)
                    del self._pending[execution_id]
                    results.append({"execution_id": execution_id, "state": row["state"], "terminal": True})
                except Exception as error:
                    results.append({"execution_id": execution_id, "terminal": False,
                                    "reason": getattr(error, "reason", "guardian_retirement_cleanup_unverified")})
        return results

    def bind_root(self, request, peer, auth_record, deadline):
        with self._lock:
            row = self._authenticate(request, peer, auth_record, deadline, terminal_bind=True)
            entry = self._pending.get(request.execution_id)
            if entry is None:
                # A lost ACK after custody transfer can only observe the same
                # committed root. It never redelivers handles or launch rights.
                owned = self.lifecycle._entry(request.execution_id)
                self.lifecycle.retry_adoption(request.execution_id)
                with self.lifecycle._scope(owned):
                    self._record_request(request, peer, auth_record)
                    if request.job_nonce != owned.job.nonce or request.root_identity != owned.root.identity:
                        raise LifecycleError("guardian_root_binding_mismatch")
                    manifest = self.lifecycle._manifest(owned, row, terminal=row["state"] == "FINISHED")
                    if row["state"] == "FINISHED":
                        if (GuardianLifecycle._members(owned) != (0, ()) or
                                GuardianLifecycle._control(owned) != _DISABLED or
                                manifest.pending_intent is not None or manifest.last_applied not in (None, _DISABLED) or
                                str(owned.root.exit_code()) != row["root_outcome"]):
                            raise LifecycleError("guardian_terminal_unverified")
                    return self._result(request, row, duplicate=True)
            if request.job_nonce != entry.creation_nonce:
                raise LifecycleError("guardian_launch_scope_missing")
            with self.lifecycle._scope(entry):
                if entry.journal_cleanup_error is not None:
                    raise LifecycleError("guardian_journal_cleanup_unverified")
                self._covered(entry, row, recovery=self._draining)
                duplicate = self._record_request(request, peer, auth_record)
                if row["state"] not in {"LAUNCHING", "START_UNKNOWN", "RUNNING"} or not row["claim_consumed"]:
                    raise LifecycleError("guardian_launch_not_claimed")
                if request.root_identity in {peer.identity, self.guardian.identity}:
                    raise LifecycleError("guardian_root_binding_mismatch")
                if entry.root is None:
                    if entry.transfer_error is not None:
                        raise LifecycleError("guardian_root_transfer_reconciliation_required")
                    try:
                        entry.root = peer.duplicate_remote_handle(request.root_handle_locator,
                            expected=request.root_identity)
                    except BaseException as error:
                        if getattr(error, "_identity_handle_cleanup", ()):
                            entry.transfer_error = error
                        raise
                elif entry.root.identity != request.root_identity:
                    raise LifecycleError("guardian_root_binding_mismatch")
                self._verify_root(entry)
                self._deadline(deadline)
                # Read the old record without requiring its not-yet-bound root.
                previous = self._read_record(entry)
                if previous != entry.record and previous != entry.pending_record:
                    raise LifecycleError("guardian_launch_manifest_changed")
                if previous.root_identity is None or entry.pending_record is not None:
                    values = {field.name: getattr(previous, field.name) for field in fields(previous)
                              if field.name != "manifest_hash"}
                    values.update(root_identity=entry.root.identity, manifest_seq=previous.manifest_seq + 1)
                    following = RecoveryManifest.create(**values)
                    entry.record, entry.pending_record = previous, following
                    try:
                        self.journal.publish(following, expected_seq=previous.manifest_seq,
                            expected_hash=previous.manifest_hash, writer_scope=entry)
                    except BaseException as error:
                        if hasattr(error, "_journal_cleanup_owner"):
                            entry.journal_cleanup_error = error
                        raise
                    entry.record = following
                    entry.pending_record = None
                self._read_manifest(entry)
                row = self.store.bind_root(request.execution_id, caller=peer.identity,
                    expected_revision=request.expected_revision, expected_auth=auth_record)
            # Transfer outside the old scope; retain exactly the same mutex.
            try:
                self.lifecycle.adopt_started(entry.execution_id, job=entry.job,
                    wrapper=entry.wrapper, root=entry.root, mutex=entry.mutex)
            finally:
                if entry.execution_id in self.lifecycle.retained_execution_ids:
                    del self._pending[entry.execution_id]
            self._deadline(deadline)
            return self._result(request, row, duplicate=duplicate)

    def _verify_root(self, entry):
        observed = entry.root.observe()
        if observed.identity != entry.root.identity or observed.status is IdentityStatus.UNKNOWN:
            raise LifecycleError("guardian_root_unverified")
        # This query is independent of liveness. A dead process is accepted
        # only when native membership is positive or was already witnessed on
        # this exact retained handle. Unknown is never historical membership.
        if not entry.membership_verified:
            if entry.root.query_owned_job_membership(entry.job.handle) is not True:
                raise LifecycleError("guardian_root_membership_unverified")
            entry.membership_verified = True
        if observed.status is IdentityStatus.ALIVE and entry.root.is_in_job(entry.job.handle) is not True:
            raise LifecycleError("guardian_root_membership_unverified")

    @contextmanager
    def evidence_scope(self, operation, row, caller):
        entry = self._pending.get(row["execution_id"])
        if entry is None:
            with self.lifecycle.evidence_scope(operation, row, caller) as evidence:
                yield evidence
            return
        if operation not in {"register_scope", "prepare", "claim", "bind_root", "cancel", "start_failed"}:
            raise LifecycleError("guardian_launch_evidence_unsupported")
        with self.lifecycle._scope(entry):
            if caller != entry.wrapper.identity:
                raise LifecycleError("guardian_peer_mismatch")
            if operation in {"cancel", "start_failed"}:
                if entry.retirement_operation != operation:
                    raise LifecycleError("guardian_retirement_request_required")
                yield self._retirement_evidence(entry, row, operation)
                return
            self._covered(entry, row, recovery=self._draining and operation in {"register_scope", "bind_root"})
            count = members = None
            durable = disabled = excluded = False
            if entry.job is not None:
                count, members = GuardianLifecycle._members(entry)
                disabled = entry.query_cpu_control() == _DISABLED
                self._read_manifest(entry)
                durable = True
                self._authority("assert_excluded", row)
                excluded = True
            if operation in {"prepare", "claim"}:
                self._verify_prepared(entry, row)
            if operation == "bind_root":
                if entry.root is None:
                    raise LifecycleError("guardian_root_unverified")
                self._verify_root(entry)
            yield LifecycleEvidence(operation, entry.execution_id, row["state_revision"], uuid4().hex,
                caller, guardian_epoch=self.guardian_epoch, job_name=entry.job_name,
                job_nonce=entry.creation_nonce, root=None if entry.root is None else entry.root.identity,
                active_process_count=count, process_ids=members, launch_sealed=entry.root is not None,
                original_cpu_disabled=disabled, durable_manifest=durable, legacy_exclusion=excluded,
                current_cpu_disabled=disabled, recovery_manifest_settled=durable,
                job_creation_never_attempted=not entry.create_attempted)
