"""Monotone lifetime floors under retained guardian POLICY and Job custody.

The ledger is raised first, so every interrupted publication keeps conservative
accounting. Only a matching durable manifest permits the caller to proceed to
its separate control intent. A later held read may raise the journal to the
already committed ledger floor; it never lowers either record or grants new
capacity. This module has no native Set, process launch, or cold adoption path.
"""
from __future__ import annotations

from dataclasses import fields
import threading

from sentinel.accounting import update_demand_floor
from .contracts import (CpuControl, CpuControlMode, FastFrame, RecoveryManifest,
                        ResourceDemand, Validity)
from .store import LifecycleError


_KEYS = ("cpu_units", "physical_bytes", "commit_bytes", "io_slots")
_DISABLED = CpuControl(CpuControlMode.DISABLED, None)


class _Publication:
    def __init__(self):
        self.previous = self.candidate = self.error = None
        # Only actual measurements paired with this guardian's own disabled
        # readback enter this bounded lifetime max. Sampler-reported CPU high
        # water has no proof that its historical windows were uncapped.
        self.uncapped_observed = {}


def _state(entry):
    value = getattr(entry, "_floor_publication", None)
    if value is None:
        value = _Publication()
        entry._floor_publication = value
    if type(value) is not _Publication:
        raise LifecycleError("guardian_floor_custody_unverified")
    return value


def _floor(row):
    return ResourceDemand.from_dict({key: row["floor_" + key] for key in _KEYS})


class _FloorScope:
    """Journal capability bound to this one retained, already held scope."""

    def __init__(self, record, assert_held, query):
        self.execution_id, self.creation_nonce = record.execution_id, record.creation_nonce
        self.job_name, self.reservation, self.spec_hash = record.job_name, record.reservation, record.spec_hash
        self._assert_held, self._query = assert_held, query

    def assert_held(self):
        self._assert_held()

    def query_cpu_control(self):
        self.assert_held()
        return self._query()


def _publish_to_ledger_floor(store, journal, entry, row, record, scope):
    """Raise only the manifest; exact normal validation remains mandatory after."""
    scope.assert_held()
    store.assert_retained_floor_growth(row, record)
    target = _floor(row)
    state = _state(entry)
    if target == record.allocated_floor and state.candidate is None:
        store.assert_retained_allocation(row, record)
        return record
    # Even when a lost publication ACK landed, a fresh sequence is published
    # positively. Merely reading the candidate does not settle uncertain I/O.
    values = {field.name: getattr(record, field.name) for field in fields(record)
              if field.name != "manifest_hash"}
    values.update(allocated_floor=target, manifest_seq=record.manifest_seq + 1)
    following = RecoveryManifest.create(**values)
    state.previous, state.candidate = record, following
    try:
        journal.publish(following, expected_seq=record.manifest_seq,
                        expected_hash=record.manifest_hash, writer_scope=scope)
        store.assert_retained_allocation(row, following)
    except BaseException as error:
        state.error = error
        # Existing lifecycle cleanup custody has priority over another open.
        if hasattr(error, "_journal_cleanup_owner"):
            entry.journal_cleanup_error = error
        raise
    state.previous = state.candidate = state.error = None
    return following


class FloorPublisher:
    """Production collaborator of one GuardianLaunchOwner's retained lifecycle.

    The caller has already authenticated and validated the exact frame's
    freshness, topology, sampler/config/registry provenance and execution set.
    This publisher additionally checks typed measurements, native uncapped CPU,
    exact custody, and the same ledger allocation inside the actual transaction.
    It never trusts a proposal target as measured resource demand.
    """

    def __init__(self, owner):
        from .guardian_lifecycle import GuardianLifecycle

        lifecycle = getattr(owner, "lifecycle", None)
        if not isinstance(lifecycle, GuardianLifecycle):
            raise LifecycleError("guardian_floor_owner_required")
        prior = getattr(lifecycle, "_floor_publisher", None)
        if prior is not None and prior is not self:
            raise LifecycleError("guardian_floor_publisher_exists")
        self.owner, self.lifecycle = owner, lifecycle
        self.store, self.journal = lifecycle.store, lifecycle.journal
        lifecycle._floor_publisher = self

    def _held(self, entry, *, validated=True):
        self.lifecycle._validate_guardian()
        guard = self.store._policy.assert_held()
        if (self.lifecycle._scope_entry is not entry or
                self.lifecycle._scope_thread != threading.get_ident() or
                self.lifecycle._entry(entry.execution_id) is not entry or
                (validated and not entry.validated) or
                guard.binding.logon_id != self.lifecycle.guardian.identity.logon_id):
            raise LifecycleError("guardian_floor_scope_required")
        return guard

    def _failed(self, entry, error):
        state = _state(entry)
        state.error = error
        entry.restore_pending = True
        entry.restore_error = error
        if hasattr(error, "_journal_cleanup_owner"):
            entry.journal_cleanup_error = error
        error.guardian_floor_publisher = self
        try:
            self.store._policy.record_recovery_hold(self.store._policy.assert_held())
        except BaseException as hold_error:
            error.guardian_floor_hold_error = hold_error
            error.add_note("guardian_floor_hold_unverified")

    def reconcile_locked(self, entry, row, record):
        """Lifecycle hook: finish DB-ahead publication without changing the row.

        Lifecycle calls this only after its normal retained identity, monotone
        manifest and native-custody checks. The store's special growth assertion
        validates everything except exact floor equality, accepting DB >= journal
        only. The normal exact assertion must pass before this method returns.
        """
        # Adoption calls the lifecycle hook before setting entry.validated.
        # Its preceding native custody checks are still mandatory; this path
        # publishes no control and cannot grant normal actuator eligibility.
        self._held(entry, validated=False)
        if entry.journal_cleanup_error is not None:
            raise LifecycleError("guardian_journal_cleanup_unverified")
        scope = _FloorScope(record, lambda: self._held(entry, validated=False),
                            lambda: self.lifecycle._control(entry))
        try:
            following = _publish_to_ledger_floor(self.store, self.journal, entry, row, record, scope)
        except BaseException as error:
            if getattr(error, "guardian_floor_publisher", None) is not self:
                self._failed(entry, error)
            raise
        entry.manifest = following
        return following

    @staticmethod
    def _measurement(entry, frame):
        if type(frame) is not FastFrame or frame.validity is not Validity.VALID:
            raise LifecycleError("guardian_floor_frame_unverified")
        jobs = [job for job in frame.jobs if job.execution_id == entry.execution_id]
        if len(jobs) != 1:
            raise LifecycleError("guardian_floor_frame_unverified")
        return jobs[0]

    def remember_uncapped_locked(self, entry, frame):
        """Retain a guardian-paired high-water without changing frame revision.

        The caller has authenticated the frame and checked its freshness,
        provenance and replay status before entering here. This method repeats
        actual disabled Query under retained custody and remembers at most
        three maxima. It never consumes the wire CPU high-water field, writes
        the ledger/journal, or permits a cap. prepare_locked must durably retain
        these observations before the first restrictive intent.
        """
        self._held(entry)
        job = self._measurement(entry, frame)
        if self.lifecycle._control(entry) != _DISABLED:
            raise LifecycleError("guardian_floor_uncapped_unverified")
        observed = {}
        if job.membership_complete and job.cpu_units is not None:
            if job.cpu_units > frame.machine.logical_processors:
                raise LifecycleError("guardian_floor_cpu_invalid")
            observed["cpu_units"] = job.cpu_units
        if job.membership_complete and job.memory_validity is Validity.VALID:
            observed["physical_bytes"] = job.private_working_set_bytes
            observed["commit_bytes"] = job.private_commit_bytes
        retained = _state(entry).uncapped_observed
        for key, value in observed.items():
            retained[key] = max(retained.get(key, 0), value)

    def prepare_locked(self, entry, row, frame, *, uncapped):
        """Persist an actual high-water floor before a caller's restrictive Set.

        Same-target frames with no increased demand write no manifest. Capped
        frames ignore both CPU fields; complete valid private-memory readings
        can still raise their respective floors. Unknown memory contributes no
        measurement and preserves requested and previously observed demand.
        """
        guard = self._held(entry)
        if type(uncapped) is not bool:
            raise LifecycleError("guardian_floor_frame_unverified")
        job = self._measurement(entry, frame)
        if uncapped and self.lifecycle._control(entry) != _DISABLED:
            raise LifecycleError("guardian_floor_uncapped_unverified")
        # This is the existing lifecycle provenance check plus the growth hook.
        # No proposal-supplied floor or native-failure boolean is accepted.
        fresh = self.store.query(entry.execution_id, existing_path=True)
        if fresh != row:
            raise LifecycleError("guardian_floor_row_changed")
        record = self.lifecycle._manifest(entry, fresh)
        if entry.restore_candidate is not None or record.pending_intent is not None:
            raise LifecycleError("guardian_floor_control_unsettled")
        observed = dict(_state(entry).uncapped_observed)
        if uncapped and job.membership_complete:
            if job.cpu_units is not None:
                if job.cpu_units > frame.machine.logical_processors:
                    raise LifecycleError("guardian_floor_cpu_invalid")
                observed["cpu_units"] = max(observed.get("cpu_units", 0), job.cpu_units)
        if job.membership_complete and job.memory_validity is Validity.VALID:
            observed["physical_bytes"] = max(observed.get("physical_bytes", 0), job.private_working_set_bytes)
            observed["commit_bytes"] = max(observed.get("commit_bytes", 0), job.private_commit_bytes)
        try:
            with self.store._transaction() as conn:
                self.store._policy.revalidate(conn, guard)
                expected, exact = self.store._retained_inputs(fresh, record)
                self.store._validate_retained_allocation(conn, expected, exact)
                update_demand_floor(conn, entry.execution_id, observed,
                    expected_revision=fresh["state_revision"], valid=True, uncapped=uncapped)
            fresh = self.store.query(entry.execution_id, existing_path=True)
            record = self.reconcile_locked(entry, fresh, record)
            self.store.assert_retained_allocation(fresh, record)
            return fresh
        except BaseException as error:
            if getattr(error, "guardian_floor_publisher", None) is not self:
                self._failed(entry, error)
            raise


def reconcile_orphan_floor_locked(store, recovery, entry, row, record):
    """Finish floor publication only after the existing orphan native restore.

    The caller holds RecoveryOwner's instance/POLICY/Job fences and borrows the
    store's actual POLICY guard. Native death and disable are positively re-read.
    This does not make a cold witness, clear a barrier, or release allocation.
    """
    from .recovery_owner import RecoveryOwner

    if not isinstance(recovery, RecoveryOwner):
        raise LifecycleError("guardian_floor_recovery_owner_required")

    def held():
        recovery._assert_held(entry)
        guard = store._policy.assert_held()
        if guard.binding != recovery.binding:
            raise LifecycleError("guardian_floor_recovery_binding_changed")

    held()
    if (recovery._entries.get(row["execution_id"]) is not entry or
            not entry.native_disabled or not entry.settled or
            record.guardian_identity != recovery.guardian_identity or
            record.guardian_epoch != recovery.guardian_epoch or
            record.pending_intent is not None or record.last_applied not in (None, _DISABLED) or
            recovery._control(entry) != _DISABLED):
        raise LifecycleError("guardian_floor_restore_unverified")
    if entry.journal_error is not None:
        raise LifecycleError("recovery_journal_cleanup_unverified")
    # A floor publication may have landed before its ACK was lost. The existing
    # retained reader checks immutable custody, sequence and monotone demand
    # against entry.record; exact equality with that cached prior would strand
    # this legitimate retry. Re-read the supplied durable record under the same
    # fences before positively reaffirming it at a new sequence.
    if recovery._read(entry) != record:
        raise LifecycleError("guardian_floor_recovery_record_changed")
    scope = _FloorScope(record, held, lambda: recovery._control(entry))
    try:
        following = _publish_to_ledger_floor(store, recovery.journal, entry, row, record, scope)
    except BaseException as error:
        _state(entry).error = error
        if hasattr(error, "_journal_cleanup_owner"):
            entry.journal_error = error
        error._recovery_owner = recovery
        try:
            store._policy.record_recovery_hold(store._policy.assert_held())
        except BaseException as hold_error:
            error.guardian_floor_hold_error = hold_error
            error.add_note("guardian_floor_hold_unverified")
        raise
    entry.record = following
    return following
