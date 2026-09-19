"""P1 per-case custody used by the S1 runner; not a production launcher.

The caller must already own a real admitted ManagedAdmission and a trusted
same-host authority. This module does not discover a ledger or turn fixture
evidence, a status file, or an environment switch into that authority.
"""
from contextlib import contextmanager
import threading
import time
import uuid

from sentinel.adaptive.contracts import CpuControl, CpuControlMode, PendingIntent
from sentinel.adaptive.store import LifecycleEvidence, LifecycleError
from tests.windows.adaptive_recovery_journal import TestRecoveryJournal, TestRecoveryRecord


DISABLED = CpuControl(CpuControlMode.DISABLED, None)
_RETAINED_OWNERS = {}


def cpu_control(raw):
    # Unused union bits are not meaningful when ENABLE is clear. Unknown
    # enabled flags must not be normalized into a policy we are allowed to undo.
    if type(raw) is not dict or type(raw.get("flags")) is not int:
        raise LifecycleError("cpu_control_unverified")
    if not raw["flags"] & 1:
        return DISABLED
    if raw["flags"] != 5:
        raise LifecycleError("external_control_conflict")
    return CpuControl(CpuControlMode.HARD_CAP, raw.get("rate_bp"))


class S1Runtime:
    """Serial S1 admission and ownership on an already verified runtime cohort.

    Construction is not a readiness result. ``authority.assert_ready`` must
    verify the real running cohort; capacity() returns that host's current
    status/config. No CLI/config decoder constructs an authority here. The
    default native preflight still rejects because this host has no such owner.
    """
    def __init__(self, *, coordinator, authority, native, store_factory=None):
        from sentinel.adaptive.store import LifecycleStore
        self.coordinator, self.authority, self.native = coordinator, authority, native
        self.store_factory = store_factory or LifecycleStore
        self.owners = []
        self.pending_admissions = []
        self._lock = threading.Lock()

    def open_case(self, *, command, cwd, directory, requested, creation_nonce):
        from sentinel.adaptive.admission import ManagedAdmission
        from sentinel.adaptive.contracts import Priority, Role
        with self._lock:
            self.native.require_supported_host()
            self.authority.assert_ready()
            if any(not owner._closed for owner in self.owners) or self.pending_admissions:
                raise LifecycleError("previous_case_unsettled")
            admission = ManagedAdmission.current(command=command, cwd=cwd,
                repo_identifier="sentinel-p1-s1", requested=requested,
                role=Role.BACKGROUND, priority=Priority.P2)
            # Keep ownership before any submission/ACK can become uncertain.
            self.pending_admissions.append(admission)
            status, config = self.authority.capacity()
            result = self.coordinator.admit_managed(admission, status, config=config)
            while not result["allowed"]:
                # Retry this same context/key, never mint a second request or
                # cancel needed work to get past temporary resource pressure.
                time.sleep(1)
                self.authority.assert_ready()
                status, config = self.authority.capacity()
                result = self.coordinator.admit_managed(admission, status, config=config)
            store = self.store_factory(self.coordinator.db_path)
            owner = S1ExecutionOwner(admission=admission, store=store,
                authority=self.authority, directory=directory, native=self.native,
                creation_nonce=creation_nonce)
            self.owners.append(owner)
            self.pending_admissions.remove(admission)
            return owner


class S1ExecutionOwner:
    """Keep allocation, creation capability, native handles and journal together.

    ``authority`` is an in-process runtime owner, never deserialized input.
    The owner always verifies its actual retained ledger allocation before
    calling authority.assert_covered(admission, row) for host cohort coverage.
    The authority also provides assert_excluded(row), and
    authorize_control(owner, target) must enforce fresh exemption state, the
    single-victim slot and the host admission barrier under the borrowed POLICY
    fence before any intent/Set. control_restored(owner) reports verified local
    restoration; it must not clear host barriers before accounting is fresh.
    retains ownership on failures via retain(owner). The real native entry
    remains unavailable until those same-host contracts can actually be met.
    ``native`` is the existing P1 adaptive_win32 module, replaceable only by
    explicitly synthetic collaborators in L1 tests.
    """

    def __init__(self, *, admission, store, authority, directory, native,
                 creation_nonce=None):
        self.admission, self.store, self.authority = admission, store, authority
        self.native = native
        self.snapshot = admission.snapshot()
        self.execution_id = self.snapshot.execution_id
        self.caller = self.snapshot.wrapper_identity
        self.creation_nonce = creation_nonce or uuid.uuid4().hex
        self.job_name = native.JOB_PREFIX + self.creation_nonce
        self.guardian_epoch = authority.guardian_epoch
        self.journal = TestRecoveryJournal(directory)
        self.job = self.process = self.mutex = None
        self.record = None
        self._lock = threading.RLock()
        self._scope_thread = None
        self._release_uncertain_thread = None
        self._create_attempted = self._launch_attempted = self._sealed = False
        self._terminal = self._closed = False
        self._prepared = False
        self.observation_started_at = time.monotonic()
        self.observation_deadline = self.observation_started_at + 120
        self._root = None
        self._retained = False
        self._recovery_guard = None
        self._last_borrowed_guard = None
        self._probe_handles = []
        self.store.evidence_provider = self.evidence_scope
        # A new owner can only adopt its own exact admitted, unused execution.
        row = self.store.query(self.execution_id)
        self._assert_row(row)
        if row["state"] != "RESERVED" or row["job_name"] is not None or row["claim_consumed"]:
            raise LifecycleError("case_owner_already_started")
        self._assert_covered(row)

    def _assert_covered(self, row):
        # An injected host collaborator cannot replace actual ledger custody.
        # This read grants neither launch nor permission to apply a CPU cap.
        self.store.assert_admission_covered(self.admission, row)
        self.authority.assert_covered(self.admission, row)

    def _assert_row(self, row):
        current = self.admission.snapshot()
        if (current != self.snapshot or row["execution_id"] != self.execution_id or
                row["spec_hash"] != self.snapshot.spec_hash or
                row["wrapper_pid"] != self.caller.pid or
                str(row["wrapper_created_filetime_100ns"]) != str(self.caller.created_filetime_100ns) or
                row["logon_id"] != self.caller.logon_id):
            raise LifecycleError("case_identity_mismatch")
        if row["job_name"] is not None and (row["job_name"] != self.job_name or
                row.get("job_nonce") != self.creation_nonce or row["guardian_epoch"] != self.guardian_epoch):
            raise LifecycleError("case_scope_mismatch")

    def _retain(self):
        if not self._retained:
            _RETAINED_OWNERS[self.execution_id] = self
            self._retained = True
            # The in-process fallback remains even if the external custodian's
            # acknowledgement fails. Preserve the operation's primary error.
            try:
                self.authority.retain(self)
            except Exception:
                pass

    @contextmanager
    def mutation_scope(self):
        """Borrow a real current POLICY guard or acquire it, then the Job mutex."""
        with self._lock:
            if self._closed:
                raise LifecycleError("case_owner_closed")
            current = self.store._policy.current_guard()
            if current is None:
                guard = self._refresh_recovery_guard()
                if guard is None:
                    guard = self.store._policy.prepare(self.caller.logon_id)
                try:
                    with self.store._policy.hold(guard):
                        # A previous operation can retain its own durable entry
                        # nonce after a failure. Reacquire the native mutex and
                        # verify the exact entry before restore; no takeover or
                        # clearing another owner's uncertainty is authorized.
                        with self.store._connection() as conn:
                            self.store._policy.revalidate(conn, guard)
                        with self._job_scope():
                            yield self
                    self._recovery_guard = None
                except BaseException:
                    self._recovery_guard = guard
                    self._retain()
                    raise
            else:
                self.store._policy.assert_held(current)
                self._last_borrowed_guard = current
                try:
                    with self._job_scope():
                        yield self
                except BaseException:
                    self._recovery_guard = current
                    raise

    def _refresh_recovery_guard(self):
        """Retain an exact pending entry; discard only positively cleared ones.

        A claim can reject cleanly after borrowing our evidence scope. In that
        case its outer POLICY scope already released and cleared the nonce.
        Reusing that entry would permanently prevent restore. A different or
        unreadable binding/entry is not permission to mint a replacement.
        """
        guard = self._recovery_guard
        if guard is None:
            return None
        policy = self.store._policy
        with self.store._connection() as conn:
            runtime = policy._runtime(conn)
            binding = policy._binding(runtime, guard.binding.logon_id)
        if (binding != guard.binding or
                runtime["active_logon_id"] not in {"", guard.binding.logon_id}):
            raise LifecycleError("case_recovery_policy_changed")
        if runtime["policy_entry_nonce"] == guard.nonce:
            return guard
        if runtime["policy_entry_nonce"] is None:
            self._recovery_guard = None
            return None
        raise LifecycleError("case_recovery_policy_changed")

    @contextmanager
    def _job_scope(self):
        if self._scope_thread is not None:
            self.assert_held()
            yield self
            return
        if self.mutex is None:
            self.mutex = self.native.NamedMutex(
                self.native.MUTEX_PREFIX + self.creation_nonce + ".Job", self.creation_nonce)
        if self._release_uncertain_thread is not None:
            if self._release_uncertain_thread != threading.get_ident():
                raise LifecycleError("case_mutex_release_unverified")
            # Positive release of the exact retained handle must precede any
            # new acquisition or mutation after a failed ReleaseMutex result.
            self.mutex.release()
            self._release_uncertain_thread = None
        abandoned = self.mutex.acquire(.25)
        primary = None
        try:
            if abandoned:
                self._retain()
                raise LifecycleError("case_mutex_abandoned")
            self._scope_thread = threading.get_ident()
            yield self
        except BaseException as error:
            primary = error
            raise
        finally:
            self._scope_thread = None
            try:
                self.mutex.release()
            except BaseException:
                self._release_uncertain_thread = threading.get_ident()
                self._retain()
                if primary is None:
                    raise
                primary.add_note("case_mutex_release_unverified")

    def assert_held(self):
        self.store._policy.assert_held()
        if (self._scope_thread != threading.get_ident() or self.mutex is None or
                not self.mutex.acquired):
            raise LifecycleError("case_mutation_scope_required")

    def query_cpu_control(self):
        self.assert_held()
        if self.job is None:
            raise LifecycleError("case_job_unavailable")
        return cpu_control(self.job.query_cpu())

    def _read_manifest(self):
        self.assert_held()
        value = self.journal.read(self.execution_id, creation_nonce=self.creation_nonce)
        if (value.job_name != self.job_name or value.wrapper_identity != self.caller or
                value.guardian_identity != self.caller or value.guardian_epoch != self.guardian_epoch or
                value.allocated_floor != self.snapshot.requested):
            raise LifecycleError("case_manifest_mismatch")
        self.record = value
        return value

    def _publish(self, **changes):
        previous = self._read_manifest()
        # create accepts typed fields, not the serialized identity dictionaries.
        from dataclasses import fields
        values = {field.name: getattr(previous, field.name) for field in fields(previous)}
        values.update(changes, manifest_seq=previous.manifest_seq + 1)
        values.pop("manifest_hash")
        following = TestRecoveryRecord.create(**values)
        self.journal.publish(following, expected_seq=previous.manifest_seq,
                             expected_hash=previous.manifest_hash, writer_scope=self)
        self.record = following
        return following

    def prepare(self):
        with self._lock:
            if self._create_attempted or self._prepared or self._sealed:
                raise LifecycleError("case_create_already_attempted")
            try:
                with self.mutation_scope():
                    row = self.store.query(self.execution_id)
                    self._assert_row(row)
                    self._assert_covered(row)
                    row = self.store.register_job_scope(self.execution_id, caller=self.caller,
                        expected_revision=row["state_revision"], guardian_epoch=self.guardian_epoch,
                        job_name=self.job_name, job_nonce=self.creation_nonce)
                    self.record = TestRecoveryRecord.create(execution_id=self.execution_id,
                        job_name=self.job_name, creation_nonce=self.creation_nonce,
                        wrapper_identity=self.caller, root_identity=None,
                        guardian_identity=self.caller, guardian_epoch=self.guardian_epoch,
                        original=DISABLED, last_applied=None, pending_intent=None,
                        allocated_floor=self.snapshot.requested, manifest_seq=0)
                    self.journal.create(self.record, writer_scope=self)
                    self.authority.assert_excluded(row)
                    if time.monotonic() >= self.observation_deadline:
                        raise LifecycleError("case_observation_deadline_expired")
                    # Irreversible before calling the native constructor. A
                    # failed/uncertain result cannot authorize another Create.
                    self._create_attempted = True
                    self.job = self.native.OwnedJob.create(nonce=self.creation_nonce)
                    if self.job.name != self.job_name or self.job.logon_sid != self.caller.logon_id:
                        raise LifecycleError("case_created_job_mismatch")
                    prepared = self.store.mark_prepared(self.execution_id, caller=self.caller,
                                                       expected_revision=row["state_revision"])
                    self._prepared = True
                    return self.reopen_probe()
            except BaseException:
                self._retain()
                raise

    @contextmanager
    def evidence_scope(self, operation, row, caller):
        if caller != self.caller:
            raise LifecycleError("case_identity_mismatch")
        with self.mutation_scope():
            self._assert_row(row)
            self._assert_covered(row)
            named = row["job_name"] is not None or operation == "register_scope"
            count, members = None, None
            current, settled, durable, initial = False, False, False, False
            excluded = False
            if self.job is not None:
                count = self.job.accounting()["active_processes"]
                members = tuple(self.job.active_pids())
                control = self.query_cpu_control()
                manifest = self._read_manifest()
                current = control.mode is CpuControlMode.DISABLED
                settled = manifest.pending_intent is None and (
                    manifest.last_applied is None or manifest.last_applied.mode is CpuControlMode.DISABLED)
                durable = True
                initial = manifest.original == DISABLED and control == DISABLED
                self.authority.assert_excluded(row)
                excluded = True
            elif self.record is not None:
                manifest = self._read_manifest()
                durable = True
                settled = manifest.pending_intent is None and manifest.last_applied is None
            root_exited = self.process is not None and self.process.wait(0)
            yield LifecycleEvidence(operation, self.execution_id, row["state_revision"],
                uuid.uuid4().hex, caller, guardian_epoch=self.guardian_epoch if named else row["guardian_epoch"],
                job_name=self.job_name if named else None, job_nonce=self.creation_nonce if named else None,
                root=self._root, active_process_count=count, process_ids=members,
                launch_sealed=self._sealed, original_cpu_disabled=initial,
                durable_manifest=durable, legacy_exclusion=excluded, root_exited=root_exited,
                user_code_started=False if not self._launch_attempted else None,
                current_cpu_disabled=current, recovery_manifest_settled=settled,
                job_creation_never_attempted=named and not self._create_attempted)

    def reopen_probe(self):
        """An S1 observation handle can close without dropping owner custody."""
        if self.job is None:
            raise LifecycleError("case_job_unavailable")
        handle = self.native.OwnedJob.open(self.job_name, self.creation_nonce)
        self._probe_handles.append(handle)
        return handle

    def launch_once(self, application, command_line, *, cwd, stdin_handle,
                    stdout_handle, stderr_handle):
        with self._lock:
            if not self._prepared or self._launch_attempted or self._sealed:
                raise LifecycleError("case_launch_not_available")
            self.admission.verify_launch_payload(command=command_line, cwd=cwd)
            claim_returned = False
            self._last_borrowed_guard = None
            try:
                row = self.store.query(self.execution_id)
                token = self.admission.launch_claim_token()
                claim = self.store.claim_launch(self.execution_id, caller=self.caller,
                    expected_revision=row["state_revision"], claim_token=token,
                    spec_hash=self.snapshot.spec_hash, guardian_epoch=self.guardian_epoch)
                claim_returned = True
                if not claim["launch_authorized"]:
                    raise LifecycleError("case_launch_claim_not_authorized")
                if time.monotonic() >= self.observation_deadline:
                    raise LifecycleError("case_observation_deadline_expired")
                self._launch_attempted = True
                self._sealed = True
                try:
                    self.process = self.native.launch_in_job(self.job, application, command_line,
                        cwd=cwd, stdin_handle=stdin_handle, stdout_handle=stdout_handle,
                        stderr_handle=stderr_handle)
                except self.native.LaunchOutcomeUnknown as error:
                    self.process = error.process
                    raise
                self._root = self.process.full_identity(expected_logon_id=self.caller.logon_id)
                with self.mutation_scope():
                    self._publish(root_identity=self._root)
                    self.store.bind_root(self.execution_id, caller=self.caller,
                                         expected_revision=claim["state_revision"])
                return self.process
            except BaseException as primary:
                # Never release or retry a possibly executed command merely
                # because its CreateProcess, bind or ACK failed.
                self._sealed = True
                if not claim_returned and self._recovery_guard is None:
                    self._recovery_guard = self._last_borrowed_guard
                try:
                    self._refresh_recovery_guard()
                except BaseException:
                    primary.add_note("case_recovery_policy_unverified")
                try:
                    failed = self.store.query(self.execution_id)
                    self._assert_row(failed)
                    clean_prelaunch = (not self._launch_attempted and
                        not failed["claim_consumed"] and not failed["launch_in_flight"] and
                        failed["state"] in {"RESERVED", "PREPARED"})
                    # A positively unused claim stays cancellable under the
                    # sealed owner. It still retains the full reservation until
                    # cancel verifies restoration and empty membership.
                    if (not clean_prelaunch and failed["state"] not in
                            {"FINISHED", "CANCELLED_BEFORE_START", "START_FAILED"}):
                        self.store.hold(self.execution_id, expected_revision=failed["state_revision"],
                                        reason="launch_ack_lost")
                except BaseException:
                    primary.add_note("case_launch_hold_unverified")
                self._retain()
                raise

    def set_cpu_rate(self, rate_bp):
        target = CpuControl(CpuControlMode.HARD_CAP, rate_bp)
        try:
            with self.mutation_scope():
                row = self.store.query(self.execution_id)
                self._assert_row(row)
                self._assert_covered(row)
                self.authority.assert_excluded(row)
                self.authority.authorize_control(self, target)
                previous = self._read_manifest()
                observed = self.query_cpu_control()
                if previous.pending_intent is not None or observed != (previous.last_applied or previous.original):
                    raise LifecycleError("external_control_conflict")
                self._publish(pending_intent=PendingIntent(str(uuid.uuid4()), observed, target))
                result = self.job.set_cpu_rate(rate_bp)
                if self.query_cpu_control() != target:
                    raise LifecycleError("api_readback_mismatch")
                self._publish(last_applied=target, pending_intent=None)
                return result
        except BaseException:
            self._retain()
            raise

    def restore(self, *, through=None):
        # Restoration must remain possible even if fresh admission is denied.
        try:
            with self.mutation_scope():
                target = self.job if through is None else through
                if target is not self.job and not any(target is probe for probe in self._probe_handles):
                    raise LifecycleError("case_restore_handle_unowned")
                if (target is None or target.name != self.job_name or
                        target.logon_sid != self.caller.logon_id):
                    raise LifecycleError("case_restore_handle_unowned")
                manifest = self._read_manifest()
                observed = self.query_cpu_control()
                if cpu_control(target.query_cpu()) != observed:
                    raise LifecycleError("external_control_conflict")
                candidates = {manifest.original, manifest.last_applied or manifest.original}
                if manifest.pending_intent is not None:
                    candidates.update((manifest.pending_intent.old, manifest.pending_intent.new))
                if observed not in candidates:
                    raise LifecycleError("external_control_conflict")
                if observed != DISABLED:
                    result = target.disable()
                else:
                    result = target.query_cpu()
                if cpu_control(target.query_cpu()) != DISABLED or self.query_cpu_control() != DISABLED:
                    raise LifecycleError("restore_unverified")
                if manifest.pending_intent is not None or manifest.last_applied not in (None, DISABLED):
                    self._publish(last_applied=DISABLED, pending_intent=None)
                self.authority.control_restored(self)
                return result
        except BaseException:
            self._retain()
            raise

    def finalize(self):
        with self._lock:
            self._sealed = True
            try:
                row = self.store.query(self.execution_id)
                self._assert_row(row)
                # A committed claim can lose its ACK before the native call.
                # In-memory Create state cannot turn that durable claim back
                # into an unused reservation. Reconcile it as sealed/empty.
                if row["state"] == "LAUNCHING":
                    row = self.store.hold(self.execution_id,
                        expected_revision=row["state_revision"], reason="launch_ack_lost")
                claimed = (row["claim_consumed"] or row["launch_in_flight"] or
                           row["state"] in {"RUNNING", "DRAINING", "START_UNKNOWN", "FINISHED"})
                if not self._launch_attempted and not claimed:
                    result = self.store.cancel_before_start(self.execution_id, caller=self.caller,
                                                          expected_revision=row["state_revision"])
                    if not result["cancelled"]:
                        raise LifecycleError("case_cancel_unverified")
                else:
                    result = self.store.finalize_if_empty(self.execution_id, caller=self.caller,
                                                         expected_revision=row["state_revision"])
                self._terminal = True
                return result
            except BaseException:
                self._retain()
                raise

    def close(self):
        with self._lock:
            if self._closed:
                return
            if not self._terminal:
                self._retain()
                raise LifecycleError("case_custody_not_settled")
            # Retain each reference on a failed close, allowing exact cleanup
            # retry. A handle close is never the proof used by finalization.
            if self.process is not None:
                self.process.close()
            for probe in self._probe_handles:
                probe.close()
            self._probe_handles.clear()
            if self.job is not None:
                self.job.close()
            if self.mutex is not None:
                self.mutex.close()
            self.admission.close()
            self._closed = True
            _RETAINED_OWNERS.pop(self.execution_id, None)
