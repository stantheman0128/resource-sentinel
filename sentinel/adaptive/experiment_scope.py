"""Original S1 native custody spanning actual daily demand and isolated control.

The isolated store contains no capacity allocation. Daily capacity belongs to
the original DailyExperimentDemand for the complete experiment. This module is
a test-only guardian: only its original Job may receive the explicit S1 2500bp
Set. It is not production enrollment or a capability-gate receipt.

Native creation and control use daily POLICY -> isolated POLICY -> Job. Native
restore uses isolated POLICY -> Job, independently of daily readiness. No SQL
transaction spans a native call, another ledger, or transport operation.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
import time
from uuid import uuid4

from . import daily_generation, experiment_demand, experiment_exclusion
from .contracts import IdentityStatus
from .exemption_sync import snapshot_locked
from .guardian_lifecycle import job_mutex_instance
from .identity import VerifiedProcess
from .native_job import CpuState, JobAccess, NativeJob
from .policy import PolicyCoordinator
from .policy import PolicyBusy
from .store import LifecycleStore
from .windows import NativePolicyMutex, NativePolicyMutexError


_NEW = object()
_COMPLETION = object()
_OWNERS = {}
_DISABLED = CpuState(0, 0)
_CAPPED = CpuState(5, 2500)


class ExperimentScopeError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = "experiment_scope_" + reason, owner
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise ExperimentScopeError(reason, owner)


def _cpu(observed):
    if (type(observed) is not CpuState or type(observed.flags) is not int or
            type(observed.rate_bp) is not int or not 0 <= observed.flags <= 0xffffffff or
            not 0 <= observed.rate_bp <= 0xffffffff):
        _fail("cpu_query_invalid")
    if observed.flags & 1 == 0:
        return _DISABLED
    if observed != _CAPPED:
        _fail("external_control_conflict")
    return observed


def _identity(path):
    value = Path(path).stat()
    return int(value.st_dev), int(value.st_ino)


class _IsolatedStore(LifecycleStore):
    """Own every original SQL connection, including unknown cleanup failures."""
    def __init__(self, path):
        self.connections, self.sql_errors = {}, []
        self._scope_path = Path(path).resolve()
        super().__init__(self._scope_path)

    @contextmanager
    def _connection(self, *, existing_path=None):
        if self.sql_errors:
            _fail("isolated_sql_cleanup_unverified")
        if existing_path is not None and Path(existing_path) != self._scope_path:
            _fail("isolated_ledger_changed")
        conn = None
        primary = None
        attempt = object()
        self.connections[attempt] = None
        try:
            conn = sqlite3.connect(self._scope_path, timeout=.25, isolation_level=None)
            self.connections[attempt] = conn
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            yield conn
        except BaseException as error:
            primary = error
            if conn is None:
                self.sql_errors.append(error)
            raise
        finally:
            if conn is not None:
                try:
                    conn.close()
                except BaseException as error:
                    self.sql_errors.append(error)
                    error.experiment_scope_sql_owner = self
                    if primary is None:
                        raise
                    primary.experiment_scope_sql_owner = self
                    primary.add_note("experiment_scope_sql_cleanup_unverified")
                else:
                    self.connections.pop(attempt, None)


@dataclass(frozen=True, init=False)
class NativeScopeCompletion:
    """Original completion capability; an observation dictionary cannot mint it."""
    owner: object
    digest: str

    def __init__(self, owner, digest, *, _token=None):
        if _token is not _COMPLETION or _OWNERS.get(owner.scope_id) is not owner:
            _fail("original_completion_required")
        object.__setattr__(self, "owner", owner)
        object.__setattr__(self, "digest", digest)

    def assert_original(self):
        owner = self.owner
        if (type(owner) is not ExperimentNativeScope or owner.completion is not self or
                _OWNERS.get(owner.scope_id) is not owner or not owner._native_closed or
                owner._completion_digest != self.digest or owner._closure_digest() != self.digest):
            _fail("original_completion_changed", owner)
        owner._validate_closed_custody()


class ExperimentNativeScope:
    """One actual guardian, independent wrapper, Job and immutable demand owner.

    The current same-process generation owner is required until the readiness
    layer offers retained remote connection ownership outside POLICY. Reopening
    a readiness pipe while holding POLICY is deliberately not an alternative.
    """
    def __init__(self, *, _token=None):
        if _token is not _NEW:
            _fail("original_factory_required")
        self._lock = threading.RLock()
        self.errors = []
        self.job = self.launch = self.mutex = self.store = self.journal = None
        self._original_job = self._original_launch = self._original_mutex = self._original_store = None
        self._guards = {"daily": None, "isolated": None}
        self._policy_poison = set()
        self._mutex_poison = None
        self._registered = self._create_attempted = self._launch_authorized = False
        self._close_started = self._native_closed = False
        self._job_closed = self._mutex_closed = False
        self._actors_closed = False
        self._actors_close_started = self._job_close_started = False
        self._mutex_close_attempted = False
        self.completion = self._completion_digest = None
        self.last_grant_revision = None

    @classmethod
    def prepare(cls, demand, command, *, scope_id=None, creation_nonce=None):
        """Keep custody before every acquisition; errors retain this same owner."""
        from tests.windows.adaptive_scope_launch import ScopeCommand, ScopeLaunch
        from .experiment_scope_journal import ScopeJournal

        if type(demand) is not experiment_demand.DailyExperimentDemand or type(command) is not ScopeCommand:
            _fail("original_demand_and_command_required")
        demand._original()
        if demand.declaration.suite != "S1" or demand.declaration.scope_sha256 != command.sha256:
            _fail("declared_command_mismatch", demand)
        inner = demand._admission
        with inner._lock:
            inner._require_settled_submission()
            if (not inner._submitted or inner._claim_exported or inner._prepare_attempted or
                    inner._cancel_sealed or inner._submission_policy is None):
                _fail("unused_daily_claim_required", demand)
        scope_id, creation_nonce = scope_id or str(uuid4()), creation_nonce or uuid4().hex
        if scope_id in _OWNERS or any(not item._native_closed for item in _OWNERS.values()):
            _fail("original_scope_occupied", demand)
        owner = cls(_token=_NEW)
        owner.demand, owner.scope_id, owner.creation_nonce = demand, scope_id, creation_nonce
        owner.command, owner.guardian = command, inner._process
        owner.daily_store = inner._submission_policy.store
        owner._daily_policy = inner._submission_policy
        owner.deadline = time.monotonic() + 120
        owner.job_name = "Local\\ResourceSentinel.Test.Job." + creation_nonce
        owner.directory = demand.directory
        owner.ledger_path = owner.directory / "s1-scope.sqlite3"
        owner._immutable = (demand, command, scope_id, creation_nonce, owner.guardian,
            owner.daily_store, owner._daily_policy, owner.deadline, owner.job_name,
            owner.directory, owner.ledger_path)
        _OWNERS[scope_id] = owner
        try:
            owner._assert_original()
            owner._ready()
            # A submitted-but-still-queued context owns no capacity. Prove the
            # actual row before even the test listener or isolated store exists.
            with owner._policy_scope("daily", owner.daily_store):
                with owner.daily_store._transaction() as conn:
                    owner._coverage_locked(conn, restrictive=True)
            if owner.ledger_path.exists():
                _fail("isolated_ledger_already_exists", owner)
            owner.store = _IsolatedStore(owner.ledger_path)
            owner._original_store = owner.store
            owner.isolated_identity = _identity(owner.ledger_path)
            owner.journal = ScopeJournal(owner.store, owner.scope_id)
            owner.launch = ScopeLaunch.prepare(demand, command, scope_id, creation_nonce, owner.deadline)
            owner._original_launch = owner.launch
            owner.mutex = NativePolicyMutex(owner.guardian.identity.logon_id,
                job_mutex_instance(scope_id, creation_nonce))
            owner._original_mutex = owner.mutex
            with owner._scope(daily=True):
                with owner.daily_store._transaction() as conn:
                    owner._coverage_locked(conn, restrictive=True)
                    experiment_exclusion.assert_available_locked(conn,
                        policy=owner._daily_policy, guard=owner._guards["daily"])
                # No SQLite transaction spans native creation. Daily POLICY
                # remains held until original actors and Job are published.
                owner._create_attempted = True
                owner.job = NativeJob.create(owner.job_name, creation_nonce,
                    owner.guardian.identity.logon_id, access=JobAccess.OWNER)
                owner._original_job = owner.job
                owner._verify_job(empty=True)
                wrapper = owner.launch.create_inert()
                if wrapper.identity == owner.guardian.identity:
                    _fail("distinct_wrapper_required", owner)
                with owner.store._transaction() as conn:
                    owner.journal.initialize_locked(conn, owner._journal_binding(wrapper.identity))
                owner.exclusion_binding = experiment_exclusion.ExperimentExclusionBinding(
                    experiment_id=demand.declaration.experiment_id,
                    daily_execution_id=demand._snapshot.execution_id,
                    reservation_id=owner.reservation_id,
                    source_generation=demand._prepared[0]["generation"],
                    scope_execution_id=scope_id, isolated_ledger_path=str(owner.ledger_path),
                    isolated_ledger_identity=owner.isolated_identity,
                    isolated_policy_instance_id=owner._guards["isolated"].binding.instance_id,
                    job_name=owner.job_name, creation_nonce=creation_nonce,
                    logon_id=owner.guardian.identity.logon_id,
                    guardian_identity=owner.guardian.identity, wrapper_identity=wrapper.identity)
                with owner.daily_store._transaction() as conn:
                    owner._coverage_locked(conn, restrictive=True)
                    experiment_exclusion.register_locked(conn, owner.exclusion_binding,
                        policy=owner._daily_policy, guard=owner._guards["daily"])
                owner._registered = True
            return owner
        except BaseException as error:
            owner._retain(error)
            raise

    def _retain(self, error):
        partial = getattr(error, "scope_launch_owner", None)
        if self.launch is None and partial is not None:
            from tests.windows.adaptive_scope_launch import ScopeLaunch
            if (type(partial) is ScopeLaunch and partial.demand is self.demand and
                    partial.command is self.command and partial.scope_id == self.scope_id and
                    partial.job_nonce == self.creation_nonce):
                self.launch = partial
                self._original_launch = partial
        self.errors.append(error)
        error.experiment_scope_owner = self
        return error

    def _assert_original(self, *, daily=True):
        self._assert_original_native_owners()
        if (type(self.demand) is not experiment_demand.DailyExperimentDemand or
                _OWNERS.get(self.scope_id) is not self or self._native_closed or
                (self.demand, self.command, self.scope_id, self.creation_nonce, self.guardian,
                 self.daily_store, self._daily_policy, self.deadline, self.job_name,
                 self.directory, self.ledger_path) != self._immutable or
                self.guardian is not self.demand._admission._process or
                type(self.guardian) is not VerifiedProcess or
                self._daily_policy is not self.demand._admission._submission_policy or
                self.daily_store is not self._daily_policy.store or
                Path(self.daily_store.db_path).absolute() != self.demand.ledger_path):
            _fail("original_binding_changed", self)
        if daily:
            self.demand._original()
        elif (experiment_demand._RETAINED.get(self.demand.declaration.experiment_id) is not self.demand or
                getattr(self.demand._admission, "_experiment_demand", None) is not self.demand):
            # Restore does not need the daily ledger, readiness or an unexpired
            # lease; it does still need these exact original native owners.
            _fail("original_demand_custody_changed", self)
        observed = self.guardian.observe()
        if (self.guardian.identity.pid != os.getpid() or observed.identity != self.guardian.identity or
                observed.status is not IdentityStatus.ALIVE):
            _fail("guardian_identity_unverified", self)
        if daily and self.guardian.is_in_job(None) is not False:
            _fail("guardian_foreign_job", self)

    def _assert_original_native_owners(self):
        for name in ("job", "launch", "mutex", "store"):
            if getattr(self, name) is not getattr(self, "_original_" + name):
                _fail("native_owner_replaced", self)

    def _ready(self):
        """Genuine original source owner, outside every SQL/native lock."""
        self._assert_original()
        if self.demand._prepared is None:
            _fail("daily_admission_unverified", self)
        generation = self.demand._prepared[0]["generation"]
        owner = daily_generation._LOCAL_GENERATIONS.get(generation)
        if (type(owner) is not daily_generation.DailyGenerationOwner or
                owner.ledger_path != self.demand.ledger_path or
                owner.ledger_identity != self.demand.ledger_identity or
                owner.manifest.digest != self.demand._prepared[0]["source_digest"]):
            _fail("original_local_generation_required", self)
        owner.assert_ready()
        self.generation_owner = owner

    @contextmanager
    def _policy_scope(self, key, store):
        policy = store._policy
        if key in self._policy_poison or policy.current_guard() is not None:
            _fail("policy_custody_unverified", self)
        guard = self._guards[key]
        if guard is not None:
            with store._connection() as conn:
                row = policy._runtime(conn)
                if policy._binding(row, guard.binding.logon_id) != guard.binding:
                    _fail("policy_binding_changed", self)
                if row["policy_entry_nonce"] is None:
                    guard = self._guards[key] = None
                elif row["policy_entry_nonce"] != guard.nonce:
                    _fail("policy_entry_changed", self)
        entered = False
        try:
            if guard is None:
                try:
                    guard = policy.prepare(self.guardian.identity.logon_id)
                except PolicyBusy as error:
                    if getattr(error, "__notes__", ()):
                        self._policy_poison.add(key)
                    raise
                except BaseException:
                    # A prepare interrupted after COMMIT returned no guard.
                    self._policy_poison.add(key)
                    raise
                self._guards[key] = guard
            with policy.hold(guard):
                entered = True
                yield guard
            self._guards[key] = None
        except BaseException as error:
            notes = set(getattr(error, "__notes__", ()))
            clean_timeout = (type(error) is NativePolicyMutexError and
                error.reason == "policy_mutex_timeout" and not notes)
            pending_native = any(getattr(error, name, None) is not None for name in (
                "_policy_mutex_cleanup", "_identity_handle_cleanup", "_daily_readiness_connection",
                "daily_readiness_current_process", "_sentinel_connection_cleanup"))
            if (not entered and not clean_timeout and not isinstance(error, PolicyBusy)) or pending_native or notes & {
                    "policy_scope_cleanup_failed", "policy_scope_cleanup_unverified"}:
                self._policy_poison.add(key)
            self._retain(error)
            raise

    @contextmanager
    def _job_scope(self):
        if self._mutex_poison is not None or self.mutex is None or self._mutex_closed:
            _fail("job_mutex_unverified", self)
        entered, primary, original_notes = False, None, ()
        try:
            with self.mutex.acquire(timeout_ms=250) as lease:
                entered = True
                if lease.abandoned:
                    _fail("job_mutex_abandoned", self)
                try:
                    yield
                except BaseException as error:
                    primary, original_notes = error, tuple(getattr(error, "__notes__", ()))
                    raise
        except BaseException as error:
            if (entered and (primary is not error or original_notes != tuple(getattr(error, "__notes__", ())))) or (
                    not entered and getattr(error, "reason", None) != "policy_mutex_timeout"):
                self._mutex_poison = error
            self._retain(error)
            raise

    @contextmanager
    def _scope(self, *, daily):
        with self._lock:
            self._assert_original(daily=daily)
            if self.store is None or _identity(self.ledger_path) != self.isolated_identity:
                _fail("isolated_ledger_changed", self)
            if daily:
                with self._policy_scope("daily", self.daily_store):
                    with self._policy_scope("isolated", self.store):
                        with self._job_scope():
                            yield
            else:
                with self._policy_scope("isolated", self.store):
                    with self._job_scope():
                        yield

    def _coverage_locked(self, conn, *, restrictive):
        from sentinel.accounting import validate_active_allocation
        from .daily_retirement_fence import assert_new_capacity_allowed

        self._daily_policy.assert_held(self._guards["daily"])
        runtime = self._daily_policy.revalidate(conn, self._guards["daily"])
        if not conn.in_transaction or runtime["mode"] != "off":
            _fail("daily_off_required", self)
        generation = daily_generation.read_generation(conn)
        if generation is None or any(generation[key] != value for key, value in self.demand._prepared[0].items()):
            _fail("generation_changed", self)
        experiment_demand._schema(conn)
        metadata = conn.execute("SELECT * FROM adaptive_experiment_demands WHERE experiment_id=?",
            (self.demand.declaration.experiment_id,)).fetchone()
        if metadata is None:
            _fail("demand_missing", self)
        self.reservation_id = metadata["reservation_id"]
        if dict(metadata) != self.demand._binding(self.reservation_id):
            _fail("demand_binding_changed", self)
        self._daily_binding_sha256 = metadata["binding_sha256"]
        source = validate_active_allocation(conn, self.demand._snapshot.execution_id,
            local_context=self.daily_store._local_context)
        row, allocation = source["execution"], source["allocation"]
        self.demand._admission._validate_cancel_allocation(allocation, self.demand._snapshot, self.reservation_id)
        # Expiry/owner loss may put the unused claim into HOLD. It retains the
        # entire floor but cannot authorize further creation or restriction.
        if (row["state"] not in {"RESERVED", "UNCERTAIN_HOLD"} or
                row["job_name"] is not None or row["root_pid"] is not None or
                row["claim_consumed"] != 0 or row["launch_sealed"] != 0 or row["launch_in_flight"] != 0 or
                row["claim_token_hash"] != self.demand._snapshot.claim_token_hash or
                any(source["floor"][key] < amount for key, amount in self.demand.declaration.requested.to_dict().items())):
            _fail("unused_daily_claim_changed", self)
        if restrictive:
            assert_new_capacity_allowed(conn)
            if (generation["state"] != "ACTIVE" or runtime["admission_barrier"] != "NONE" or
                    row["state"] != "RESERVED" or time.monotonic() >= self.deadline or
                    float(allocation["expires_at"]) <= time.time()):
                _fail("daily_coverage_no_new_work", self)
            self._restriction_lease_deadline = float(allocation["expires_at"])
        if self._registered:
            inventory = experiment_exclusion.read_locked(conn,
                policy=self._daily_policy, guard=self._guards["daily"])
            if inventory.bindings != (self.exclusion_binding,):
                _fail("legacy_exclusion_changed", self)
        return row

    def _journal_binding(self, wrapper):
        pin = self.demand._prepared[0]
        return dict(schema_version=1, experiment_id=self.demand.declaration.experiment_id,
            scope_id=self.scope_id, daily_execution_id=self.demand._snapshot.execution_id,
            reservation_id=self.reservation_id, isolated_ledger_identity=list(self.isolated_identity),
            job_name=self.job_name, creation_nonce=self.creation_nonce,
            guardian_identity=self.guardian.identity.to_dict(), wrapper_identity=wrapper.to_dict(),
            command_sha256=self.command.sha256, source_generation=pin["generation"],
            source_digest=pin["source_digest"], config_digest=pin["config_digest"],
            deadline_monotonic_ns=int(self.deadline * 1_000_000_000))

    def reconcile_registration(self):
        """Read/publish only this original created scope after an uncertain ACK.

        This method cannot create a Job or wrapper, replay launch, extend a
        deadline, or acquire another allocation. It exists for cleanup of a
        publication that may have committed before its acknowledgement failed.
        """
        with self._lock:
            self._ready()
            if (not self._create_attempted or self.job is None or self.launch is None or
                    self.launch.wrapper_witness is None or self._job_closed):
                _fail("partial_creation_custody_required", self)
            with self._scope(daily=True):
                with self.daily_store._transaction() as conn:
                    self._coverage_locked(conn, restrictive=False)
                self._verify_job(empty=not self._launch_authorized)
                wrapper = self.launch.wrapper_witness
                if (wrapper.identity == self.guardian.identity or
                        wrapper.observe().status is not IdentityStatus.ALIVE):
                    _fail("original_wrapper_unavailable", self)
                with self.store._transaction() as conn:
                    self.journal.initialize_locked(conn, self._journal_binding(wrapper.identity))
                binding = experiment_exclusion.ExperimentExclusionBinding(
                    experiment_id=self.demand.declaration.experiment_id,
                    daily_execution_id=self.demand._snapshot.execution_id,
                    reservation_id=self.reservation_id,
                    source_generation=self.demand._prepared[0]["generation"],
                    scope_execution_id=self.scope_id, isolated_ledger_path=str(self.ledger_path),
                    isolated_ledger_identity=self.isolated_identity,
                    isolated_policy_instance_id=self._guards["isolated"].binding.instance_id,
                    job_name=self.job_name, creation_nonce=self.creation_nonce,
                    logon_id=self.guardian.identity.logon_id,
                    guardian_identity=self.guardian.identity, wrapper_identity=wrapper.identity)
                if hasattr(self, "exclusion_binding") and self.exclusion_binding != binding:
                    _fail("registration_binding_changed", self)
                self.exclusion_binding = binding
                with self.daily_store._transaction() as conn:
                    experiment_exclusion.register_locked(conn, binding,
                        policy=self._daily_policy, guard=self._guards["daily"])
                self._registered = True
            return self

    def _verify_job(self, *, empty=False):
        if (type(self.job) is not NativeJob or self.job.name != self.job_name or
                self.job.nonce != self.creation_nonce or self.job.logon_sid != self.guardian.identity.logon_id or
                self.job.access is not JobAccess.OWNER):
            _fail("original_job_required", self)
        limits = self.job.query_limits()
        if limits.limit_flags != 0 or limits.ui_restrictions != 0:
            _fail("external_job_limits", self)
        if self.guardian.query_owned_job_membership(self.job.handle) is not False:
            _fail("guardian_inside_workload", self)
        if self.launch is not None and self.launch.wrapper_witness is not None and not self.launch._closed:
            if self.launch.wrapper_witness.query_owned_job_membership(self.job.handle) is not False:
                _fail("wrapper_inside_workload", self)
        if empty and (self.job.accounting().active_processes != 0 or self.job.active_pids()):
            _fail("job_not_empty", self)

    def _grants_locked(self):
        from sentinel.exemptions import Exemptions
        snapshot = snapshot_locked(Exemptions(self.demand.ledger_path.parent),
            lifecycle_store=self.daily_store, now=time.time(), deadline=time.monotonic() + .25)
        self.last_grant_revision = snapshot.revision
        # Legacy float birth times do not prove precise unrelated ancestry.
        # Any active grant therefore denies/restores this one isolated Job.
        return snapshot

    def assert_covered(self):
        self._ready()
        with self._scope(daily=True):
            with self.daily_store._transaction() as conn:
                self._coverage_locked(conn, restrictive=True)

    def _authorize_launch(self, launcher, job):
        if (launcher is not self.launch or job is not self.job or not self._registered or
                self._launch_authorized or self._close_started):
            _fail("launch_binding_changed", self)
        self._ready()
        with self._scope(daily=True):
            with self.daily_store._transaction() as conn:
                self._coverage_locked(conn, restrictive=True)
            self._verify_job(empty=True)
            with self.store._transaction() as conn:
                self.journal.begin_launch_locked(conn)
            self._launch_authorized = True
        # The actual launcher performs authenticated IPC only after every lock
        # above has positively settled. This return is not a serialized permit.

    def launch_once(self):
        try:
            root = self.launch.launch_once(self.job, self)
            with self._scope(daily=False):
                if (root is not self.launch.root_witness or root.identity in
                        {self.guardian.identity, self.launch.wrapper_witness.identity} or
                        root.query_owned_job_membership(self.job.handle) is not True):
                    _fail("root_custody_unverified", self)
                with self.store._transaction() as conn:
                    self.journal.acknowledge_launch_locked(conn, root.identity)
            return root
        except BaseException as error:
            self._retain(error)
            raise

    def set_cpu_rate(self, rate_bp=2500):
        if (rate_bp != 2500 or type(rate_bp) is not int or self._close_started or
                not self._registered):
            _fail("only_explicit_s1_rate", self)
        self._ready()
        with self._scope(daily=True):
            with self.daily_store._transaction() as conn:
                self._coverage_locked(conn, restrictive=True)
            self._verify_job()
            if self._grants_locked().leases:
                _fail("user_exemption_active_or_unknown", self)
            current = _cpu(self.job.query_cpu())
            with self.store._transaction() as conn:
                row = self.journal.read_locked(conn)
                expected = row["last_applied_cpu"] or row["original_cpu"]
                if current != CpuState(**expected) or row["pending_target_cpu"] is not None:
                    _fail("control_state_changed", self)
                self.journal.begin_control_locked(conn, _CAPPED)
            # No grant can commit while daily POLICY remains held. Check the
            # original lease/experiment clocks adjacent to the native boundary;
            # an expired pending intent remains owned for restore reconciliation.
            if (time.monotonic() >= self.deadline or time.time() >= self._restriction_lease_deadline):
                _fail("control_deadline_expired", self)
            self.job.set_cpu_rate_unverified(2500)
            observed = _cpu(self.job.query_cpu())
            if observed != _CAPPED:
                _fail("control_readback_mismatch", self)
            with self.store._transaction() as conn:
                self.journal.acknowledge_control_locked(conn, observed)
            return observed

    def restore(self):
        """Withdraw only this original scope's exact cap; no daily prerequisite."""
        with self._scope(daily=False):
            self._verify_job()
            observed = _cpu(self.job.query_cpu())
            with self.store._transaction() as conn:
                self.journal.begin_restore_locked(conn, observed)
            if observed != _DISABLED:
                self.job.disable()
            observed = _cpu(self.job.query_cpu())
            if observed != _DISABLED:
                _fail("restore_readback_mismatch", self)
            with self.store._transaction() as conn:
                self.journal.acknowledge_control_locked(conn, observed)
            return observed

    def observe_control(self):
        """Owning guardian sweep; grant-after-cap restores the entire Job."""
        restore = False
        try:
            self._ready()
            with self._scope(daily=True):
                with self.daily_store._transaction() as conn:
                    self._coverage_locked(conn, restrictive=True)
                restore = bool(self._grants_locked().leases)
        except BaseException as error:
            self._retain(error)
            restore = True
        if restore:
            self.restore()
        return self.job.query_cpu()

    def close_native(self):
        """One cleanup tick; returns original capability only after native close."""
        with self._lock:
            if self.completion is not None:
                self.completion.assert_original()
                return self.completion
            self._assert_original(daily=False)
            if not self._registered:
                if (self.job is not None and self.launch is not None and
                        self.launch.wrapper_witness is None and self.launch.root_witness is None and
                        not self.launch._command_dispatched and
                        (not self.launch._wrapper_create_entered or self.launch.process is not None and
                         self.launch.process.creation_definitely_absent)):
                    return self._close_uncreated_wrapper()
                self.reconcile_registration()
            self._close_started = True
            try:
                if not self._job_closed:
                    if not self._actors_close_started:
                        self.restore()
                        self.launch.seal()  # authenticated IPC, outside POLICY
                        with self._scope(daily=False):
                            with self.store._transaction() as conn:
                                state = self.journal.read_locked(conn)
                            root = self.launch.root_witness
                            if root is not None:
                                if not self.launch.root_job_bound:
                                    _fail("root_custody_unverified", self)
                                with self.store._transaction() as conn:
                                    if state["state"] in {"LAUNCH_INTENT", "LAUNCH_UNKNOWN"}:
                                        self.journal.acknowledge_launch_locked(conn, root.identity)
                                    self.journal.seal_launch_locked(conn, outcome="started")
                            else:
                                result = self.launch._last_result
                                if (self.launch._transport_unknown or result is None or
                                        result["sealed"] is not True or result["root"] is not None or
                                        result["creation_outcome"] not in {"not_attempted", "not_created"} or
                                        self.job.accounting().total_processes != 0):
                                    _fail("uncreated_scope_unverified", self)
                                with self.store._transaction() as conn:
                                    self.journal.seal_uncreated_locked(conn)
                        drain = self.launch.drain_once(self.job)  # native/IPC, outside POLICY
                        if not drain.complete:
                            return None
                        with self._scope(daily=False):
                            self._verify_job(empty=True)
                            accounting = self.job.accounting()
                            if _cpu(self.job.query_cpu()) != _DISABLED:
                                _fail("close_cpu_not_disabled", self)
                            root = self.launch.root_witness
                            root_exit = None if root is None else root.exit_code()
                            if root is not None and root.observe().status is not IdentityStatus.DEAD:
                                _fail("root_not_dead", self)
                            with self.store._transaction() as conn:
                                self._terminal_record = self.journal.finish_locked(conn,
                                    root_exit_code=root_exit, total_processes=accounting.total_processes)
                        self._actors_close_started = True
                    if not self._actors_closed:
                        # Once close begins, the launcher itself resumes only
                        # its retained remaining owners, never actor queries.
                        self.launch.close()
                        self._actors_closed = True
                    # A later clean lock timeout resumes here. Never query or
                    # close the already positively settled process witnesses.
                    with self._scope(daily=False):
                        if not self._job_close_started:
                            self._verify_job(empty=True)
                            if _cpu(self.job.query_cpu()) != _DISABLED:
                                _fail("close_cpu_not_disabled", self)
                            self._job_close_started = True
                        self.job.close()
                        self._job_closed = True
                for key, store in (("isolated", self.store), ("daily", self.daily_store)):
                    if self._guards[key] is not None:
                        # Only the same original guard may settle a lost final
                        # SQL-clear ACK. Unknown native release remains poisoned.
                        with self._policy_scope(key, store):
                            pass
                if not self._mutex_closed:
                    if self._mutex_close_attempted:
                        _fail("mutex_close_outcome_unknown", self)
                    self._mutex_close_attempted = True
                    self.mutex.close()
                    self._mutex_closed = True
                self._validate_closed_custody()
                self._completion_digest = self._closure_digest()
                self._native_closed = True
                self.completion = NativeScopeCompletion(self, self._completion_digest, _token=_COMPLETION)
                return self.completion
            except BaseException as error:
                self._retain(error)
                raise

    def _closure_digest(self):
        binding = (self.exclusion_binding._values() if hasattr(self, "exclusion_binding") else
            dict(experiment_id=self.demand.declaration.experiment_id, scope_id=self.scope_id,
                job_name=self.job_name, creation_nonce=self.creation_nonce,
                guardian_identity=self.guardian.identity.to_dict(), command_sha256=self.command.sha256,
                isolated_ledger_identity=self.isolated_identity, wrapper_creation="never_created"))
        payload = dict(binding=binding, terminal=self._terminal_record,
            daily_binding_sha256=self._daily_binding_sha256)
        return hashlib.sha256(json.dumps(payload, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest()

    def _close_uncreated_wrapper(self):
        """Only original positive Create FALSE/pre-Create custody, never PID absence.

        No wrapper identity, journal row, exclusion row or production C2 receipt
        is invented for this branch. An uncertain Job constructor remains owned
        on its original exception and cannot enter this positive path.
        """
        from tests.windows.adaptive_scope_launch import ScopeLaunch
        if (type(self.launch) is not ScopeLaunch or self.launch.demand is not self.demand or
                self.launch.scope_id != self.scope_id or self.launch.command is not self.command or
                self._registered or self._launch_authorized or self.job is None):
            _fail("uncreated_wrapper_custody_invalid", self)
        self._close_started = True
        try:
            if not self._actors_close_started:
                with self._scope(daily=False):
                    self._verify_job(empty=True)
                    accounting = self.job.accounting()
                    if accounting.total_processes != 0 or _cpu(self.job.query_cpu()) != _DISABLED:
                        _fail("uncreated_wrapper_job_used", self)
                    self._terminal_record = dict(state="WRAPPER_NOT_CREATED", scope_id=self.scope_id,
                        launch_sealed=True, root=None, total_processes=0, root_exit_code=None,
                        cpu_flags=0, pending_intents=0)
                self._actors_close_started = True
            if not self._actors_closed:
                # ScopeLaunch independently checks its original Create outcome,
                # unknown transport/SQL owners and close state before returning.
                self.launch.close()
                self._actors_closed = True
            if not self._job_closed:
                with self._scope(daily=False):
                    if not self._job_close_started:
                        self._verify_job(empty=True)
                        if self.job.accounting().total_processes != 0 or _cpu(self.job.query_cpu()) != _DISABLED:
                            _fail("uncreated_wrapper_job_used", self)
                        self._job_close_started = True
                    self.job.close()
                    self._job_closed = True
            for key, store in (("isolated", self.store), ("daily", self.daily_store)):
                if self._guards[key] is not None:
                    with self._policy_scope(key, store):
                        pass
            if not self._mutex_closed:
                if self._mutex_close_attempted:
                    _fail("mutex_close_outcome_unknown", self)
                self._mutex_close_attempted = True
                self.mutex.close()
                self._mutex_closed = True
            self._validate_closed_custody()
            self._completion_digest = self._closure_digest()
            self._native_closed = True
            self.completion = NativeScopeCompletion(self, self._completion_digest, _token=_COMPLETION)
            return self.completion
        except BaseException as error:
            self._retain(error)
            raise

    def _validate_closed_custody(self):
        self._assert_original_native_owners()
        if (not self._job_closed or not self._mutex_closed or not self.job.closed or
                not self.launch._closed or self.store.connections or self.store.sql_errors or
                any(self._guards.values()) or self._policy_poison or self._mutex_poison is not None or
                not getattr(self, "_terminal_record", None)):
            _fail("native_cleanup_unverified", self)
