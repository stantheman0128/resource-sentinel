"""Consume an authenticated child partition using real isolated admission.

The daily intent is not authority by itself. A retained ExperimentChildBinding,
fresh daily readiness, exact ledger files and both native POLICY fences are
required. The original daily floor is never modified here. This adapter borrows
its coordinator, store and child binding; their owners retain cleanup duties.
"""
from contextlib import contextmanager
from pathlib import Path
import threading
import time

from sentinel.coordinator import Coordinator, PRIORITY_RANK
from . import daily_generation, experiment_host_ledger as ledger
from . import experiment_host_backing as backing
from . import experiment_local_backing as local_backing
from .admission import ManagedAdmission
from .daily_readiness_transport import LedgerFileIdentity
from .experiment_host_transport import ExperimentChildBinding
from .operation_waits import bounded_waits
from .policy import PolicyBusy
from .store import LifecycleStore, commit_managed_admission, retry_managed_admission


class PartitionAdmissionError(RuntimeError):
    def __init__(self, reason):
        self.reason = "experiment_partition_" + reason
        super().__init__(self.reason)


class ExperimentPartitionCoordinator:
    def __init__(self, coordinator, child_binding, *, member_id, reservation_id, daily_store):
        if type(coordinator) is not Coordinator or type(child_binding) is not ExperimentChildBinding:
            raise PartitionAdmissionError("original_collaborators_required")
        if not isinstance(daily_store, LifecycleStore):
            raise PartitionAdmissionError("daily_store_required")
        ledger._uuid(member_id)
        ledger._text(reservation_id)
        manifest = child_binding.manifest
        if manifest.role != "wrapper" or member_id not in manifest.permitted_member_ids:
            raise PartitionAdmissionError("wrapper_member_required")
        self.coordinator, self.child_binding = coordinator, child_binding
        self.daily_store, self.member_id, self.reservation_id = daily_store, member_id, reservation_id
        self.manifest = manifest
        self.db_path = Path(coordinator.db_path).resolve(strict=True)
        self.daily_path = Path(daily_store.db_path).resolve(strict=True)
        self._fixed = (coordinator, child_binding, daily_store, manifest, member_id, reservation_id,
                       self.db_path, self.daily_path)
        self._context = self._snapshot = self._backing = None
        self._local_backing_publication = self._local_backing_observation = None
        self._lock = threading.RLock()
        self._daily_guard = None
        self._daily_prepare_unknown = False
        self._daily_reads = []
        self._errors = []
        self._isolated_store = coordinator._managed_lifecycle_store()
        self._original_isolated_policy = self._isolated_store._policy
        self._original_daily_policy = daily_store._policy
        self._files()

    def __reduce__(self):
        raise TypeError("experiment_partition_not_serializable")

    def _retain(self, error):
        if len(self._errors) < 32 and not any(item is error for item in self._errors):
            self._errors.append(error)
        error.experiment_partition_owner = self
        return error

    def _original(self):
        if ((self.coordinator, self.child_binding, self.daily_store, self.manifest, self.member_id,
             self.reservation_id, self.db_path, self.daily_path) != self._fixed or
                self.child_binding.manifest is not self.manifest or
                self.coordinator._managed_lifecycle_store() is not self._isolated_store or
                self._isolated_store._policy is not self._original_isolated_policy or
                self.daily_store._policy is not self._original_daily_policy or
                Path(self.coordinator.db_path).resolve() != self.db_path or
                Path(self.daily_store.db_path).resolve() != self.daily_path):
            raise PartitionAdmissionError("original_binding_changed")

    def _files(self):
        if (self.db_path != Path(self.manifest.isolated_ledger_path) or
                self.daily_path != Path(self.manifest.daily_ledger_path) or
                LedgerFileIdentity.capture(self.db_path) != self.manifest.isolated_ledger_identity or
                LedgerFileIdentity.capture(self.daily_path) != self.manifest.daily_ledger_identity):
            raise PartitionAdmissionError("ledger_identity_changed")

    def _bind_context(self, context):
        self._original()
        if type(context) is not ManagedAdmission or getattr(context, "_experiment_demand", None) is not None:
            raise PartitionAdmissionError("original_child_context_required")
        snapshot = context.snapshot()
        candidate = backing._snapshot_binding(snapshot, self.reservation_id)
        if snapshot.wrapper_identity != self.manifest.child_identity:
            raise PartitionAdmissionError("current_wrapper_changed")
        if self._context is None:
            self._context, self._snapshot, self._backing = context, snapshot, candidate
        if self._context is not context or self._snapshot is not snapshot or self._backing != candidate:
            raise PartitionAdmissionError("original_context_changed")
        return snapshot

    def _native_binding(self):
        self.child_binding.revalidate(self.manifest, role="wrapper", member_id=self.member_id)
        self._files()

    @contextmanager
    def _daily_read(self):
        attempt = {"closed": False, "rollback_unknown": False, "error": None}
        self._daily_reads.append(attempt)
        primary = None
        try:
            with self.daily_store._connection(existing_path=self.daily_path) as conn:
                attempt["connection"] = conn
                conn.execute("BEGIN")
                try:
                    daily_generation.revalidate_transaction(conn, db_path=self.daily_path)
                    yield conn
                except BaseException as error:
                    primary = error
                finally:
                    attempt["rollback_unknown"] = True
                    conn.rollback()
                    attempt["rollback_unknown"] = False
            attempt["closed"] = True
            if primary is not None:
                raise primary
        except BaseException as error:
            attempt["error"] = error
            if primary is not None and error is not primary:
                error._partition_read_error = primary
            raise
        finally:
            if attempt["closed"] and not attempt["rollback_unknown"]:
                self._daily_reads.remove(attempt)

    def _assert_daily_cleanup_observed(self):
        """Refuse unresolved originals before acquiring any new readiness."""
        if self._daily_prepare_unknown or self._daily_reads:
            raise PartitionAdmissionError("daily_cleanup_unverified")
        guard = self._daily_guard
        if guard is None:
            return
        # Only the original guard's positive native release/nonentry authorizes
        # bookkeeping cleanup. Never re-wait an uncertain native mutex here.
        if not (guard._native_exit_confirmed or guard._native_no_entry_confirmed):
            raise PartitionAdmissionError("daily_native_cleanup_unverified")

    def _settle_daily(self):
        self._assert_daily_cleanup_observed()
        guard = self._daily_guard
        if guard is None:
            return
        policy = self._original_daily_policy
        with self._daily_read() as conn:
            runtime = policy._runtime(conn)
            if policy._binding(runtime, guard.binding.logon_id) != guard.binding:
                raise PartitionAdmissionError("daily_policy_changed")
            nonce = runtime["policy_entry_nonce"]
        if nonce is not None:
            if nonce != guard.nonce:
                raise PartitionAdmissionError("daily_nonce_changed")
            policy._clear(guard)
        self._daily_guard = None

    @contextmanager
    def _daily_operation(self):
        self._assert_daily_cleanup_observed()
        paths = (self.daily_path, self.db_path)
        # Readiness RPC acquisition has its own deadline and completes before
        # any POLICY lock. The shared 250 ms bounds subsequent lock/SQL waits;
        # it is not an end-to-end RPC or filesystem duration guarantee.
        with daily_generation.readiness_scopes(paths, absent_paths=(self.db_path,)):
            with bounded_waits() as budget:
                self._settle_daily()
                self._native_binding()
                policy = self._original_daily_policy
                budget.require()
                self._daily_prepare_unknown = True
                try:
                    guard = policy.prepare(self.manifest.child_identity.logon_id)
                except PolicyBusy as error:
                    if not getattr(error, "__notes__", ()):
                        self._daily_prepare_unknown = False
                    raise
                self._daily_guard = guard
                self._daily_prepare_unknown = False
                with policy.hold(guard):
                    try:
                        if (guard.binding.instance_id != self.manifest.daily_policy_instance_id or
                                guard.binding.logon_id != self.manifest.child_identity.logon_id):
                            raise PartitionAdmissionError("daily_policy_changed")
                        budget.require()
                        yield guard, budget
                    except BaseException:
                        # This component performs ONLY daily read transactions.
                        # Their positive rollback/close plus this guard's own
                        # release can settle its nonce even if isolated custody
                        # remains pending. This does not settle the partition.
                        if not self._daily_reads:
                            guard.clean_rejection = True
                        raise
                self._daily_guard = None

    def _observe_backing(self, guard):
        with self._daily_read() as conn:
            observation = backing.validate_admission_locked(conn,
                scope_id=self.manifest.scope_id, member_id=self.member_id,
                wrapper_member_id=self.manifest.actor_member_id, binding=self._backing,
                policy=self._original_daily_policy, guard=guard)
            scope = conn.execute("SELECT * FROM " + ledger.SCOPES_TABLE + " WHERE scope_id=?",
                                 (self.manifest.scope_id,)).fetchone()
            generation = daily_generation.read_generation(conn)
            if (scope is None or generation is None or
                    scope["source_generation"] != self.manifest.source_generation or
                    scope["source_digest"] != self.manifest.source_digest or
                    scope["config_digest"] != self.manifest.config_digest or
                    scope["isolated_policy_instance_id"] != self.manifest.isolated_policy_instance_id or
                    scope["daily_policy_instance_id"] != self.manifest.daily_policy_instance_id or
                    scope["isolated_ledger_path"] != str(self.db_path) or
                    ledger._decode(scope["isolated_ledger_identity_json"]) !=
                        [self.manifest.isolated_ledger_identity.st_dev, self.manifest.isolated_ledger_identity.st_ino]):
                raise PartitionAdmissionError("daily_scope_changed")
        return observation, generation

    def _readiness_deadline(self, budget, generation):
        # Full source/file/native validation finishes before isolated BEGIN.
        # Capture the timing endpoint before querying the original deadline so
        # time spent in that query cannot extend its remaining lifetime.
        deadline = daily_generation.revalidate_scoped_readiness(
            self.daily_path, expected_generation=generation)
        before = time.monotonic()
        bound = budget.deadline
        if deadline is not None:
            bound = min(bound, before + deadline.require() / 1000)
        budget.require()
        return bound

    def _before_commit(self, budget, expires_at, readiness_deadline):
        # In-transaction checks are pure clocks; no native, RPC or filesystem
        # observations are repeated while the isolated writer lock is held.
        budget.require()
        if time.monotonic() >= readiness_deadline:
            raise PartitionAdmissionError("readiness_expired")
        if time.time() >= expires_at:
            raise PartitionAdmissionError("daily_allocation_expired")

    def admit_managed(self, context, status=None, *, config=None, now=None):
        # Signature fits ManagedLauncher, but copied status/config/clock are
        # deliberately refused instead of interpreted as capacity evidence.
        if status is not None or config is not None or now is not None:
            raise PartitionAdmissionError("caller_capacity_input_forbidden")
        with self._lock:
            try:
                if len(self._errors) >= 32:
                    raise PartitionAdmissionError("failure_inventory_full")
                snapshot = self._bind_context(context)
                with context.submission_scope(), self._daily_operation() as (daily_guard, budget):
                    observation, generation = self._observe_backing(daily_guard)
                    self._local_backing_observation = observation
                    publication = local_backing.LocalBackingPublication.prepare(
                        adapter=self, context=context, observation=observation)
                    expires_at = observation.daily_expires_at
                    self._native_binding()
                    readiness_deadline = self._readiness_deadline(budget, generation)
                    self._before_commit(budget, expires_at, readiness_deadline)
                    local = {"local_host_id": self.coordinator.local_host_id}
                    with self.coordinator._admission_db(snapshot, context) as (conn, policy, first, tx):
                        if (policy is not self._original_isolated_policy or
                                policy.assert_held().binding.instance_id != self.manifest.isolated_policy_instance_id):
                            raise PartitionAdmissionError("isolated_policy_changed")
                        runtime = policy.revalidate(conn, policy.assert_held())
                        if runtime["mode"] not in {"off", "shadow"} or runtime["admission_barrier"] != "NONE":
                            raise PartitionAdmissionError("isolated_new_work_blocked")
                        local_backing.begin_locked(conn, operation=publication, policy=policy,
                                                   guard=policy.assert_held())
                        replay = retry_managed_admission(conn, snapshot, local_context=local)
                        if replay is not None:
                            if replay["reservation_id"] != self.reservation_id:
                                raise PartitionAdmissionError("isolated_reservation_changed")
                            result = replay
                        else:
                            if not first:
                                raise PartitionAdmissionError("original_submission_missing")
                            req = snapshot.request
                            conflicts = conn.execute("SELECT 1 FROM reservations WHERE id=? OR request_key=? OR execution_id=? LIMIT 1",
                                (self.reservation_id, req.request_key, snapshot.execution_id)).fetchone()
                            queued = conn.execute("SELECT 1 FROM queue WHERE request_key=? OR managed_execution_id=? LIMIT 1",
                                (req.request_key, snapshot.execution_id)).fetchone()
                            if conflicts or queued:
                                raise PartitionAdmissionError("isolated_admission_conflict")
                            admitted_at = time.time()
                            self._before_commit(budget, expires_at, readiness_deadline)
                            # This exact ID/deadline is backed by the original
                            # daily intent. It never extends the parent's lease.
                            conn.execute("""INSERT INTO reservations
                                (id,request_key,owner_pid,owner_started,tool_use_id,repo,command_signature,command_text,
                                 resource_class,priority,priority_rank,cpu_units,ram_gib,io_slots,created_at,
                                 heartbeat_at,expires_at,spec_hash,commit_bytes,execution_id,lifecycle_managed,
                                 managed_spec_hash,lease_duration_sec,writer_protocol,writer_revision)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,0)""",
                                (self.reservation_id,req.request_key,req.owner_pid,req.owner_started,req.tool_use_id,
                                 req.repo,req.command_signature,"",req.resource_class,req.priority,PRIORITY_RANK[req.priority],
                                 req.cpu_units,req.ram_gib,req.io_slots,admitted_at,admitted_at,expires_at,req.spec_hash,
                                 req.commit_bytes,snapshot.execution_id,1,snapshot.spec_hash,None))
                            result = commit_managed_admission(conn, snapshot, self.reservation_id, now=admitted_at,
                                local_context=local, policy_coordinator=policy)
                        local_backing.publish_locked(conn, operation=publication, policy=policy,
                            guard=policy.assert_held(), admission_result=result)
                        self._before_commit(budget, expires_at, readiness_deadline)
                        self.coordinator._commit_admission(conn, tx)
                    # No launch/admission ACK until both native scopes and their
                    # exact nonce cleanup have positively returned.
                return result
            except BaseException as error:
                raise self._retain(error)

    def reconcile_managed(self, context):
        with self._lock:
            try:
                self._bind_context(context)
                self._files()
                return self.coordinator.reconcile_managed(context)
            except BaseException as error:
                raise self._retain(error)

    def cancel_managed(self, context, **kwargs):
        with self._lock:
            try:
                self._bind_context(context)
                self._files()
                # Exclusive local unused-claim cleanup needs neither a live
                # parent nor fresh daily admission. The daily backing remains.
                return self.coordinator.cancel_managed(context, **kwargs)
            except BaseException as error:
                raise self._retain(error)
