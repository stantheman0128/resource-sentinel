"""Original experiment host authority, separate from ordinary host admission.

Each operation borrows its own fresh two-ledger readiness group and holds daily
POLICY before callers enter isolated POLICY/Job. No lock may span a client RPC.
The local link is immutable provenance, never a replacement child credential.
Existing-work reconciliation omits parent liveness and new-admission predicates;
it is not a native emergency restore API or authority to release daily capacity.
This S2/P4 slice preserves the partition adapter's off/shadow and NONE barrier
requirement. Its restrict/renew observations confer no CPU Set permission and do
not enable future canary/limited control or replace its native evidence gates.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
import threading
import time

from . import daily_generation, experiment_host_backing as backing
from . import experiment_host_ledger as ledger, experiment_local_backing as local
from .admission import ManagedAdmission
from .contracts import IdentityStatus, ProcessIdentity, ResourceDemand
from .daily_readiness_transport import LedgerFileIdentity
from .experiment_host_transport import ExperimentChildBinding
from .experiment_partition_admission import ExperimentPartitionCoordinator
from .host_authority import (HostAuthority, HostAuthorityError, HostReadinessError,
    HostCapabilityUnsupported, read_host_capability)
from .identity import VerifiedProcess
from .operation_waits import bounded_waits
from .policy import PolicyBusy
from .store import LifecycleStore, TERMINAL_STATES
from .windows import current_thread_holds_mutex


_CREATE = object()
_OPERATIONS = {"wrapper": frozenset({"prepare", "claim", "create"}),
               "guardian": frozenset({"prepare", "claim", "restrict", "renew"})}
_MAX_FAILURES = 32


class ExperimentHostAuthorityError(HostAuthorityError):
    def __init__(self, reason):
        super().__init__("experiment_host_" + reason)


def _fail(reason):
    raise ExperimentHostAuthorityError(reason)


@dataclass(frozen=True)
class _Operation:
    execution_id: str
    operation: str
    restrictive: bool
    link_payload: str
    generation_payload: str
    deadline: object
    bound: float
    expires_at: float
    guard: object
    thread: int


@dataclass(frozen=True)
class _ActorOperation:
    member_id: str
    generation_payload: str
    deadline: object
    bound: float
    expires_at: float
    guard: object
    thread: int


class ExperimentBackedHostAuthority:
    """Exact in-process factories only; never a wire/config bypass switch."""
    def __init__(self, *, _key=None):
        if _key is not _CREATE or type(self) is not ExperimentBackedHostAuthority:
            _fail("original_factory_required")

    def __reduce__(self):
        raise TypeError("experiment_host_authority_not_serializable")

    @classmethod
    def for_wrapper(cls, adapter):
        if cls is not ExperimentBackedHostAuthority or type(adapter) is not ExperimentPartitionCoordinator:
            _fail("original_partition_required")
        adapter._original()
        original = getattr(adapter.child_binding, "_experiment_host_authority", None)
        if original is not None:
            if type(original) is not cls or original.adapter is not adapter:
                _fail("original_factory_changed")
            original._original()
            return original
        value = cls(_key=_CREATE)
        value._initialize(adapter.child_binding, adapter._isolated_store, adapter.daily_store,
                          guardian=None, adapter=adapter)
        return value

    @classmethod
    def for_guardian(cls, child_binding, *, isolated_store, daily_store, guardian):
        if (cls is not ExperimentBackedHostAuthority or type(child_binding) is not ExperimentChildBinding or
                type(guardian) is not VerifiedProcess or child_binding.manifest.role != "guardian" or
                guardian.identity != child_binding.manifest.child_identity):
            _fail("original_guardian_required")
        original = getattr(child_binding, "_experiment_host_authority", None)
        if original is not None:
            if (type(original) is not cls or original.store is not isolated_store or
                    original.daily_store is not daily_store or original.guardian is not guardian):
                _fail("original_factory_changed")
            original._original()
            return original
        value = cls(_key=_CREATE)
        value._initialize(child_binding, isolated_store, daily_store, guardian=guardian, adapter=None)
        return value

    def _initialize(self, child, store, daily_store, *, guardian, adapter):
        if (type(child) is not ExperimentChildBinding or not isinstance(store, LifecycleStore) or
                not isinstance(daily_store, LifecycleStore)):
            _fail("original_collaborators_required")
        manifest = child.manifest
        if manifest.role != ("wrapper" if adapter is not None else "guardian"):
            _fail("role_invalid")
        self.child_binding, self.manifest = child, manifest
        self.store, self.daily_store, self.guardian, self.adapter = store, daily_store, guardian, adapter
        self._daily_policy, self._isolated_policy = daily_store._policy, store._policy
        self.daily_path, self.isolated_path = Path(daily_store.db_path).resolve(strict=True), Path(store.db_path).resolve(strict=True)
        self._manifest_payload = ledger._canonical(manifest.to_dict())
        self._factory_owner = self
        self._thread = threading.get_ident()
        self._fixed = (child, manifest, store, daily_store, guardian, adapter, self._daily_policy,
                       self._isolated_policy, self.daily_path, self.isolated_path, self._manifest_payload, self._thread)
        self._guardian_native = None if guardian is None else (guardian._backend, guardian._handle, guardian.identity)
        self._ordinary = HostAuthority(store, guardian=guardian)
        self._guard = self._active = self._body_attempt = None
        self._actor_active = self._actor_registration = self._actor_registration_pins = None
        self._prepare_unknown = False
        self._reads, self._external_reads, self._errors = [], [], []
        # Register with the original authenticated child before first file or
        # native validation. Recalling a factory cannot replace failed custody.
        self._initialized = False
        child._experiment_host_authority = self
        self._files()
        self._initialized = True

    def _original(self):
        current = (self.child_binding, self.manifest, self.store, self.daily_store, self.guardian, self.adapter,
                   self._daily_policy, self._isolated_policy, self.daily_path, self.isolated_path,
                   self._manifest_payload, self._thread)
        if (type(self) is not ExperimentBackedHostAuthority or self._factory_owner is not self or
                self._initialized is not True or self.child_binding._experiment_host_authority is not self or
                any(a is not b for a, b in zip(current[:8], self._fixed[:8])) or
                current[8:] != self._fixed[8:] or threading.get_ident() != self._thread or
                self.child_binding.manifest is not self.manifest or
                ledger._canonical(self.manifest.to_dict()) != self._manifest_payload or
                self.store._policy is not self._isolated_policy or self.daily_store._policy is not self._daily_policy or
                self._ordinary.store is not self.store or self._ordinary.guardian is not self.guardian):
            _fail("original_binding_changed")
        if self.guardian is not None and (self.guardian._backend, self.guardian._handle, self.guardian.identity) != self._guardian_native:
            _fail("original_guardian_changed")
        if self.adapter is not None:
            self.adapter._original()
            if (self.adapter.child_binding is not self.child_binding or self.adapter._isolated_store is not self.store or
                    self.adapter.daily_store is not self.daily_store):
                _fail("original_partition_changed")

    def _files(self):
        if (Path(self.store.db_path).resolve(strict=True) != self.isolated_path or
                Path(self.daily_store.db_path).resolve(strict=True) != self.daily_path or
                str(self.daily_path) != self.manifest.daily_ledger_path or
                str(self.isolated_path) != self.manifest.isolated_ledger_path or
                LedgerFileIdentity.capture(self.daily_path) != self.manifest.daily_ledger_identity or
                LedgerFileIdentity.capture(self.isolated_path) != self.manifest.isolated_ledger_identity):
            _fail("ledger_identity_changed")

    def _native(self, *, restrictive):
        self._original()
        if self._reads:
            _fail("native_during_sql")
        if restrictive:
            self.child_binding.revalidate(self.manifest, role=self.manifest.role)
        else:
            # Pure original-custody checks deliberately do not observe parent
            # liveness. The actual guardian remains the same retained process.
            self.child_binding._check_original()
            if (self.child_binding._issued is not True or self.child_binding._closed is not False or
                    self.child_binding._close_attempted is not False or self.child_binding._peer_pin is None or
                    self.child_binding._attempt.exchange_complete is not True or
                    self.child_binding._attempt.peer_settled is not True or
                    self.child_binding._attempt.channel_settled is not True):
                _fail("child_binding_unavailable")
            # A dead original parent is permitted; a replaced/closed/unknown
            # handle is not. This checks custody without observing liveness.
            self.child_binding._peer_pin.check()
            current = self.child_binding._process.observe()
            if current.status is not IdentityStatus.ALIVE or current.identity != self.manifest.child_identity:
                _fail("current_child_unavailable")
        if self.guardian is not None:
            observed = self.guardian.observe()
            if observed.status is not IdentityStatus.ALIVE or observed.identity != self.manifest.child_identity:
                _fail("guardian_unavailable")
        self._files()

    def _retain(self, error):
        if len(self._errors) < _MAX_FAILURES and not any(value is error for value in self._errors):
            self._errors.append(error)
        error.experiment_host_authority = self
        return error

    def _cleanup_observed(self, *, registration=None):
        if self._prepare_unknown or self._reads or self._external_reads or self._body_attempt is not None:
            _fail("cleanup_unverified")
        if self._guard is not None and not (
                self._guard._native_exit_confirmed or self._guard._native_no_entry_confirmed):
            _fail("native_cleanup_unverified")
        if self.adapter is not None:
            self.adapter._assert_daily_cleanup_observed()
        if self._actor_registration is not None:
            original, spec, wire = self._actor_registration_pins
            if (self._actor_registration is not original or original.store is not self.store or
                    original.guardian is not self.guardian or spec.to_json() != wire):
                _fail("original_registration_changed")
            original._original()
            if original.pending and registration is not original:
                _fail("registration_cleanup_unverified")

    @contextmanager
    def _sql(self, store):
        if self._reads:
            _fail("nested_sql")
        if store not in (self.store, self.daily_store):
            _fail("foreign_ledger")
        attempt = {"closed": False, "rollback_unknown": False}
        self._reads.append(attempt)
        primary = None
        try:
            with store._connection(existing_path=store.db_path) as conn:
                attempt["connection"] = conn
                # LifecycleStore prepares this exact connection outside BEGIN
                # against the already-acquired original readiness group. Keep
                # its generation and file observation for SQL-only comparison;
                # the generic generation UDF also probes native identity/files
                # and therefore must not be invoked inside this read snapshot.
                self._files()
                generation = daily_generation.read_generation(conn)
                generation_payload = ledger._canonical(generation)
                databases = tuple(tuple(value) for value in conn.execute("PRAGMA database_list"))
                if (len(databases) != 1 or databases[0][1] != "main" or
                        Path(databases[0][2]).resolve(strict=True) != Path(store.db_path).resolve(strict=True)):
                    _fail("connection_ledger_changed")
                conn.execute("BEGIN")
                try:
                    if (ledger._canonical(daily_generation.read_generation(conn)) != generation_payload or
                            tuple(tuple(value) for value in conn.execute("PRAGMA database_list")) != databases):
                        _fail("transaction_source_changed")
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
            if primary is not None and primary is not error:
                error.experiment_host_sql_body_error = primary
            raise self._retain(error)
        finally:
            if attempt["closed"] and not attempt["rollback_unknown"]:
                self._reads.remove(attempt)

    @contextmanager
    def _external_read(self):
        """Retain exact helper failures whose inner close cannot be observed.

        These fixed existing proof helpers own their SQL connections. Only
        their successful return proves their cleanup; exceptions conservatively
        retain the original traceback/owner and prevent another acquisition.
        """
        if self._reads or self._external_reads:
            _fail("read_cleanup_unverified")
        attempt = {}
        self._external_reads.append(attempt)
        try:
            yield
        except BaseException as error:
            attempt["error"] = error
            raise self._retain(error)
        else:
            self._external_reads.remove(attempt)

    def _settle_guard(self, *, registration=None):
        self._cleanup_observed(registration=registration)
        if self._guard is None:
            return
        guard = self._guard
        with self._sql(self.daily_store) as conn:
            runtime = self._daily_policy._runtime(conn)
            if self._daily_policy._binding(runtime, guard.binding.logon_id) != guard.binding:
                _fail("daily_policy_changed")
            nonce = runtime["policy_entry_nonce"]
        if nonce is not None:
            if nonce != guard.nonce:
                _fail("daily_nonce_changed")
            self._daily_policy._clear(guard)
        self._guard = None

    def _actor_view(self):
        """Existing published actor and its real daily floor; no execution ID."""
        manifest = self.manifest
        with self._sql(self.store) as conn:
            runtime = self._isolated_policy._runtime(conn)
            if (runtime["policy_instance_id"] != manifest.isolated_policy_instance_id or
                    runtime["policy_logon_id"] != manifest.child_identity.logon_id or
                    runtime["policy_binding_initialized"] != 1 or runtime["mode"] not in {"off", "shadow"} or
                    runtime["admission_barrier"] != "NONE"):
                _fail("isolated_actor_registration_blocked")
        with self._sql(self.daily_store) as conn:
            _, history, tables = ledger._inventory(conn, self._daily_policy, self._guard)
            scopes = [row for row in tables.get(ledger.SCOPES_TABLE, ()) if row["scope_id"] == manifest.scope_id]
            if len(scopes) != 1 or history is None:
                _fail("actor_scope_missing")
            scope = scopes[0]
            if (any(scope[key] != getattr(manifest, key) for key in (
                    "source_generation", "source_digest", "config_digest", "daily_policy_instance_id",
                    "isolated_ledger_path", "isolated_policy_instance_id")) or
                    ledger._decode(scope["isolated_ledger_identity_json"]) !=
                        [manifest.isolated_ledger_identity.st_dev, manifest.isolated_ledger_identity.st_ino]):
                _fail("actor_scope_changed")
            ledger._daily_binding(conn, scope, history, self._guard, restrictive=True)
            members = [row for row in tables[ledger.MEMBERS_TABLE] if row["member_id"] == manifest.actor_member_id]
            actors = [row for row in tables[ledger.ACTORS_TABLE] if row["member_id"] == manifest.actor_member_id]
            if (len(members) != 1 or members[0]["role"] != "guardian" or len(actors) != 1 or
                    ProcessIdentity.from_dict(ledger._decode(actors[0]["identity_json"])) != manifest.child_identity):
                _fail("actor_publication_required")
            rows = conn.execute("SELECT expires_at FROM reservations WHERE id=? AND execution_id=? LIMIT 2",
                (scope["reservation_id"], scope["daily_execution_id"])).fetchall()
            if len(rows) != 1:
                _fail("actor_daily_allocation_missing")
            generation = daily_generation.read_generation(conn)
            return generation, rows[0][0]

    @contextmanager
    def actor_registration_scope(self, registration, role_spec):
        """Fence only the original guardian's isolated registration operation.

        The actor was already published by its parent. This reads that exact
        allocation and holds daily POLICY before GuardianRegistration acquires
        isolated POLICY. It grants neither a workload claim nor native control.
        """
        from .guardian_registration import GuardianRegistration
        from .experiment_host_roles import GuardianRoleSpec
        self._original()
        if (self.manifest.role != "guardian" or type(registration) is not GuardianRegistration or
                type(role_spec) is not GuardianRoleSpec or registration.store is not self.store or
                registration.guardian is not self.guardian or role_spec.member_id != self.manifest.actor_member_id or
                registration.epoch != role_spec.guardian_epoch):
            _fail("original_registration_required")
        if self._actor_registration is None:
            self._actor_registration = registration
            self._actor_registration_pins = (registration, role_spec, role_spec.to_json())
        elif self._actor_registration is not registration or self._actor_registration_pins[1] is not role_spec:
            _fail("original_registration_changed")
        self._cleanup_observed(registration=registration)
        if self._active is not None or self._actor_active is not None or len(self._errors) >= _MAX_FAILURES:
            _fail("operation_unavailable")
        if (self._isolated_policy.current_guard() is not None or self._daily_policy.current_guard() is not None or
                current_thread_holds_mutex()):
            _fail("outer_daily_scope_required")
        release = getattr(type(self.child_binding), "require_role_release", None)
        if not callable(release) or release(self.child_binding, role_spec) is not None:
            _fail("actor_role_release_required")
        try:
            with daily_generation.readiness_scopes((self.daily_path, self.isolated_path), absent_paths=(self.isolated_path,)):
                with bounded_waits() as budget:
                    self._settle_guard(registration=registration)
                    self._native(restrictive=True)
                    self._prepare_unknown = True
                    try:
                        self._guard = self._daily_policy.prepare(self.manifest.child_identity.logon_id)
                    except PolicyBusy as error:
                        if not getattr(error, "__notes__", ()):
                            self._prepare_unknown = False
                        raise
                    self._prepare_unknown = False
                    guard = self._guard
                    with self._daily_policy.hold(guard):
                        try:
                            if (guard.binding.instance_id != self.manifest.daily_policy_instance_id or
                                    guard.binding.logon_id != self.manifest.child_identity.logon_id):
                                _fail("daily_policy_changed")
                            generation, expiry = self._actor_view()
                            self._native(restrictive=True)
                            deadline = daily_generation.revalidate_scoped_readiness(self.daily_path,
                                expected_generation=generation)
                            before = time.monotonic()
                            bound = min(budget.deadline, before + max(0, expiry - time.time()))
                            if deadline is not None:
                                bound = min(bound, before + deadline.require() / 1000)
                            active = _ActorOperation(self.manifest.actor_member_id, ledger._canonical(generation),
                                deadline, bound, expiry, guard, self._thread)
                            self._actor_active = active
                            self.assert_actor_registration_ready(registration)
                            attempt = {"returned": False, "error": None}
                            self._body_attempt = attempt
                            try:
                                yield
                            except BaseException as error:
                                attempt["error"] = error
                                # tick retains its original SQL/native failures.
                                # Transfer only to that exact existing owner;
                                # an unrelated body failure remains quarantined.
                                if registration._error is error:
                                    self._body_attempt = None
                                raise
                            else:
                                attempt["returned"] = True
                                self._body_attempt = None
                        except BaseException:
                            if not self._reads and not self._external_reads and self._body_attempt is None:
                                guard.clean_rejection = True
                            raise
                        finally:
                            self._actor_active = None
                    self._guard = None
        except BaseException as error:
            raise self._retain(error)

    def assert_actor_registration_ready(self, registration):
        """Original actor scope immediately before its isolated operation."""
        self._original()
        active = self._actor_active
        if (registration is not self._actor_registration or type(active) is not _ActorOperation or
                active.member_id != self.manifest.actor_member_id or active.guard is not self._guard or
                active.thread != threading.get_ident() or self._reads or self._external_reads):
            _fail("original_actor_operation_required")
        self._daily_policy.assert_held(active.guard)
        if time.monotonic() >= active.bound or time.time() >= active.expires_at:
            _fail("operation_expired")
        if active.deadline is not None:
            active.deadline.require()

    def _local_view(self, execution_id, *, restrictive=True):
        with self._sql(self.store) as conn:
            runtime = self._isolated_policy._runtime(conn)
            if (runtime["policy_instance_id"] != self.manifest.isolated_policy_instance_id or
                    runtime["policy_logon_id"] != self.manifest.child_identity.logon_id or
                    type(runtime["policy_binding_initialized"]) is not int or runtime["policy_binding_initialized"] != 1):
                _fail("isolated_policy_changed")
            if restrictive and (runtime["mode"] not in {"off", "shadow"} or runtime["admission_barrier"] != "NONE"):
                _fail("isolated_new_work_blocked")
            observed = local.read_link_locked(conn, execution_id, max_rows=1, max_bytes=local.MAX_BYTES)
            if observed is None:
                _fail("local_backing_required")
            row = HostAuthority._live_row(conn, execution_id, HostAuthorityError, "experiment_host_execution_missing")
            allocation = (None if not restrictive and row["state"] in TERMINAL_STATES else
                          self._ordinary._allocation(conn, execution_id)["allocation"])
        link = observed.to_dict()
        manifest = self.manifest
        if (link["scope_id"] != manifest.scope_id or link["member_id"] not in manifest.permitted_member_ids or
                any(link[key] != getattr(manifest, key) for key in (
                    "scope_nonce", "plan_sha256", "source_generation", "source_digest", "config_digest",
                    "daily_ledger_path", "daily_policy_instance_id", "isolated_ledger_path", "isolated_policy_instance_id")) or
                (link["daily_ledger_dev"], link["daily_ledger_ino"]) !=
                    (str(manifest.daily_ledger_identity.st_dev), str(manifest.daily_ledger_identity.st_ino)) or
                (link["isolated_ledger_dev"], link["isolated_ledger_ino"]) !=
                    (str(manifest.isolated_ledger_identity.st_dev), str(manifest.isolated_ledger_identity.st_ino))):
            _fail("local_backing_changed")
        if self.adapter is not None:
            operation = self.adapter._local_backing_publication
            if (type(operation) is not local.LocalBackingPublication or self.adapter._context is None or
                    operation._row != link or self.adapter._snapshot.execution_id != execution_id or
                    link["wrapper_member_id"] != manifest.actor_member_id):
                _fail("original_publication_required")
            operation._original()
        return link, row, allocation

    @staticmethod
    def _binding(link):
        return backing.IsolatedAdmissionBinding(link["execution_id"], link["reservation_id"], link["request_key"],
            link["request_spec_hash"], link["spec_hash"], link["admission_binding_hash"],
            ProcessIdentity(link["wrapper_pid"], int(link["wrapper_created_filetime_100ns"]), link["logon_id"]),
            ResourceDemand(link["cpu_units"], link["physical_bytes"], link["commit_bytes"], link["io_slots"]))

    def _daily_view(self, link, row, *, restrictive, require_job):
        guard = self._daily_policy.assert_held(self._guard)
        with self._sql(self.daily_store) as conn:
            observed, history, tables = backing._validated(conn, scope_id=link["scope_id"],
                member_id=link["member_id"], wrapper_member_id=link["wrapper_member_id"],
                binding=self._binding(link), policy=self._daily_policy, guard=guard)
            scopes = [value for value in tables[ledger.SCOPES_TABLE] if value["scope_id"] == link["scope_id"]]
            if len(scopes) != 1:
                _fail("scope_missing")
            ledger._daily_binding(conn, scopes[0], history, guard, restrictive=restrictive)
            scope = scopes[0]
            if (any(scope[key] != link[key] for key in ("source_generation", "source_digest", "config_digest",
                    "daily_policy_instance_id", "isolated_policy_instance_id", "isolated_ledger_path")) or
                    ledger._decode(scope["isolated_ledger_identity_json"]) !=
                        [int(link["isolated_ledger_dev"]), int(link["isolated_ledger_ino"])] or
                    observed.registered_revision != link["daily_registered_revision"] or
                    observed.binding_sha256 != link["daily_binding_sha256"] or observed.daily_expires_at != link["daily_expires_at"]):
                _fail("daily_backing_changed")
            actors = {value["member_id"]: ProcessIdentity.from_dict(ledger._decode(value["identity_json"]))
                      for value in tables[ledger.ACTORS_TABLE]}
            if (actors.get(self.manifest.actor_member_id) != self.manifest.child_identity or
                    actors.get(link["wrapper_member_id"]) != self._binding(link).wrapper_identity):
                _fail("actor_binding_changed")
            jobs = [value for value in tables[ledger.JOBS_TABLE] if value["member_id"] == link["member_id"]]
            if require_job or row["job_name"] is not None:
                if len(jobs) != 1:
                    _fail("daily_job_required")
                job = ledger.JobBinding(**{key: jobs[0][key] for key in ledger.JobBinding.__dataclass_fields__})
                if (job.kind != "managed" or job.wrapper_member_id != link["wrapper_member_id"] or
                        job.isolated_execution_id != link["execution_id"] or
                        job.isolated_reservation_id != link["reservation_id"] or
                        job.job_name != row["job_name"] or job.creation_nonce != row["job_nonce"] or
                        self.guardian is not None and job.guardian_member_id != self.manifest.actor_member_id):
                    _fail("daily_job_changed")
            generation = daily_generation.read_generation(conn)
        if generation is None or any(generation.get(source) != link[target] for source, target in (
                ("generation", "source_generation"), ("source_digest", "source_digest"), ("config_digest", "config_digest"))):
            _fail("source_generation_changed")
        return observed, generation

    @contextmanager
    def new_work_scope(self, execution_id, *, operation):
        if type(operation) is not str or operation not in _OPERATIONS[self.manifest.role]:
            _fail("operation_forbidden")
        with self._operation(execution_id, operation=operation, restrictive=True):
            yield

    @contextmanager
    def existing_work_scope(self, execution_id):
        """Existing Bind/custody bookkeeping only, never launch or CPU Set.

        Fresh source/readiness is still needed to read live ledgers. Emergency
        withdrawal uses the guardian's retained native restore fences directly,
        without this context, and cannot infer bookkeeping/capacity completion.
        """
        if self.manifest.role != "guardian":
            _fail("guardian_required")
        with self._operation(execution_id, operation="bind", restrictive=False):
            yield

    @contextmanager
    def _operation(self, execution_id, *, operation, restrictive):
        ledger._uuid(execution_id)
        self._original()
        self._cleanup_observed()
        if self._active is not None or self._actor_active is not None or len(self._errors) >= _MAX_FAILURES:
            _fail("operation_unavailable")
        # Refuse an inverted acquisition before any readiness RPC is possible.
        if (self._isolated_policy.current_guard() is not None or self._daily_policy.current_guard() is not None or
                current_thread_holds_mutex()):
            _fail("outer_daily_scope_required")
        try:
            with daily_generation.readiness_scopes((self.daily_path, self.isolated_path), absent_paths=(self.isolated_path,)):
                with bounded_waits() as budget:
                    self._settle_guard()
                    self._native(restrictive=restrictive)
                    self._prepare_unknown = True
                    try:
                        self._guard = self._daily_policy.prepare(self.manifest.child_identity.logon_id)
                    except PolicyBusy as error:
                        if not getattr(error, "__notes__", ()):
                            self._prepare_unknown = False
                        raise
                    self._prepare_unknown = False
                    guard = self._guard
                    with self._daily_policy.hold(guard):
                        try:
                            if (guard.binding.instance_id != self.manifest.daily_policy_instance_id or
                                    guard.binding.logon_id != self.manifest.child_identity.logon_id):
                                _fail("daily_policy_changed")
                            link, row, allocation = self._local_view(execution_id, restrictive=restrictive)
                            require_job = operation != "prepare"
                            observed, generation = self._daily_view(link, row, restrictive=restrictive, require_job=require_job)
                            if restrictive:
                                HostAuthority._active(row, HostAuthorityError)
                                HostAuthority._lease(allocation, time.time())
                            self._native(restrictive=restrictive)
                            deadline = daily_generation.revalidate_scoped_readiness(self.daily_path, expected_generation=generation)
                            before = time.monotonic()
                            bound = budget.deadline
                            if deadline is not None:
                                bound = min(bound, before + deadline.require() / 1000)
                            if restrictive:
                                bound = min(bound, before + max(0, observed.daily_expires_at - time.time()))
                            active = _Operation(execution_id, operation, restrictive, ledger._canonical(link),
                                ledger._canonical(generation), deadline, bound, observed.daily_expires_at, guard, self._thread)
                            self._active = active
                            self._check_active(execution_id)
                            body_attempt = {"returned": False, "error": None}
                            self._body_attempt = body_attempt
                            try:
                                yield
                            except BaseException as error:
                                # The caller may own isolated SQL/native work
                                # that this authority cannot observe closing.
                                # Retain its exact failure rather than infer
                                # safety from our own empty read inventory.
                                body_attempt["error"] = error
                                raise
                            else:
                                body_attempt["returned"] = True
                                self._body_attempt = None
                        except BaseException:
                            if not self._reads and not self._external_reads and self._body_attempt is None:
                                guard.clean_rejection = True
                            raise
                        finally:
                            self._active = None
                    self._guard = None
        except BaseException as error:
            self._retain(error)
            if not isinstance(error, Exception) or isinstance(error, ExperimentHostAuthorityError):
                raise
            failure = ExperimentHostAuthorityError("operation_unverified")
            failure.original_error = error
            for note in getattr(error, "__notes__", ()):
                failure.add_note(note)
            raise self._retain(failure) from error

    def _check_active(self, execution_id, *, restrictive=None):
        self._original()
        active = self._active
        if (type(active) is not _Operation or active.execution_id != execution_id or active.guard is not self._guard or
                active.thread != threading.get_ident() or self._reads or self._external_reads or
                restrictive is not None and active.restrictive is not restrictive):
            _fail("original_operation_required")
        self._daily_policy.assert_held(active.guard)
        if time.monotonic() >= active.bound or active.restrictive and time.time() >= active.expires_at:
            _fail("operation_expired")
        if active.deadline is not None:
            active.deadline.require()
        return active

    def assert_ready(self):
        try:
            read_host_capability()
        except HostCapabilityUnsupported as error:
            raise HostAuthorityError(error.reason, error.win32_error) from None
        if self._active is None:
            _fail("original_operation_required")
        self._check_active(self._active.execution_id)

    def _coverage(self, supplied, *, restrictive):
        execution_id = HostAuthority._execution_id(supplied, HostAuthorityError, "experiment_host_row_invalid")
        active = self._check_active(execution_id, restrictive=restrictive)
        link, row, allocation = self._local_view(execution_id, restrictive=restrictive)
        if ledger._canonical(link) != active.link_payload:
            _fail("original_link_changed")
        HostAuthority._match(supplied, row, HostAuthorityError, "experiment_host_row_changed")
        observed, generation = self._daily_view(link, row, restrictive=restrictive, require_job=active.operation != "prepare")
        if ledger._canonical(generation) != active.generation_payload or observed.daily_expires_at != active.expires_at:
            _fail("original_source_changed")
        if restrictive:
            HostAuthority._active(row, HostAuthorityError)
            HostAuthority._lease(allocation, time.time())
        self._check_active(execution_id, restrictive=restrictive)
        return row

    def assert_covered(self, row):
        self._coverage(row, restrictive=True)

    def assert_existing_covered(self, row):
        self._coverage(row, restrictive=False)

    def assert_excluded(self, row):
        """Exact daily and local exclusion under already-held ordered guards."""
        from .legacy_writer import _registry_locked
        from .writers import writer_obligations_present
        if self.guardian is None:
            _fail("guardian_required")
        execution_id = HostAuthority._execution_id(row, HostAuthorityError, "experiment_host_row_invalid")
        active = self._check_active(execution_id)
        live = self._coverage(row, restrictive=active.restrictive)
        guard = self._isolated_policy.assert_held()
        if (guard.binding.instance_id != self.manifest.isolated_policy_instance_id or
                guard.binding.logon_id != self.manifest.child_identity.logon_id):
            _fail("isolated_policy_changed")
        guardian = self._ordinary._live_guardian()
        with self._external_read():
            self._ordinary._writer_fence(writer_obligations_present)
        with self._external_read():
            revision, protected, jobs = _registry_locked(self.store, guard, time.monotonic() + .25, time.monotonic)
        if (type(revision) is not int or revision < 0 or guardian not in protected or
                HostAuthority._wrapper_identity(live) not in protected or live["job_name"] not in jobs):
            _fail("local_exclusion_unverified")
        link = ledger._decode(active.link_payload)
        self._daily_view(link, live, restrictive=active.restrictive, require_job=True)
        with self._sql(self.daily_store) as conn:
            inventory = ledger.read_locked(conn, policy=self._daily_policy, guard=active.guard)
            if (guardian not in inventory.identities or HostAuthority._wrapper_identity(live) not in inventory.identities or
                    live["job_name"] not in inventory.managed_job_names or writer_obligations_present(conn) is not True):
                _fail("daily_exclusion_unverified")
        self._check_active(execution_id)

    def _wrapper_ready(self, admission, row, endpoint):
        if self.adapter is None or type(admission) is not ManagedAdmission or admission is not self.adapter._context:
            _fail("original_admission_required")
        snapshot = admission.snapshot()
        if snapshot is not self.adapter._snapshot:
            _fail("original_snapshot_changed")
        HostAuthority._endpoint(endpoint, snapshot)
        self.assert_ready()
        live = self._coverage(row, restrictive=True)
        if live["execution_id"] != snapshot.execution_id:
            _fail("admission_execution_changed")
        # The endpoint/epoch are bootstrap selectors, not launch authority.
        # Resolve its actual server against the already published daily actor;
        # after Job publication that exact Job selects the guardian member.
        active = self._check_active(snapshot.execution_id, restrictive=True)
        link = ledger._decode(active.link_payload)
        with self._sql(self.daily_store) as conn:
            _, _, tables = ledger._inventory(conn, self._daily_policy, active.guard)
            members = {value["member_id"]: value for value in tables[ledger.MEMBERS_TABLE]}
            actors = {value["member_id"]: ProcessIdentity.from_dict(ledger._decode(value["identity_json"]))
                      for value in tables[ledger.ACTORS_TABLE]}
            matched = [member for member, identity in actors.items()
                       if identity == endpoint.server_identity and members[member]["role"] == "guardian"]
            if len(matched) != 1:
                _fail("guardian_endpoint_unpublished")
            jobs = [value for value in tables[ledger.JOBS_TABLE] if value["member_id"] == link["member_id"]]
            if live["job_name"] is not None and (len(jobs) != 1 or jobs[0]["guardian_member_id"] != matched[0]):
                _fail("guardian_endpoint_changed")
        with self._external_read():
            self.store.assert_admission_covered(admission, live)
        self._native(restrictive=True)
        active = self._check_active(snapshot.execution_id, restrictive=True)
        deadline = daily_generation.revalidate_scoped_readiness(self.daily_path,
            expected_generation=ledger._decode(active.generation_payload))
        if deadline is not active.deadline:
            _fail("original_readiness_changed")
        self._check_active(snapshot.execution_id, restrictive=True)

    def assert_launch_ready(self, admission, row, endpoint):
        """One standalone pre-RPC check, or a check inside the original scope."""
        try:
            execution_id = HostAuthority._execution_id(row, HostReadinessError, "experiment_host_row_invalid")
            if self._active is None:
                with self.new_work_scope(execution_id, operation="prepare"):
                    self._wrapper_ready(admission, row, endpoint)
            else:
                self._wrapper_ready(admission, row, endpoint)
        except HostReadinessError:
            raise
        except (RuntimeError, ValueError, TypeError, sqlite3.Error, OSError) as error:
            failure = HostReadinessError(getattr(error, "reason", "experiment_host_readiness_unavailable"))
            failure.experiment_host_authority = self
            failure.original_error = error
            raise failure from error

    def assert_create_ready(self, admission, row, endpoint):
        if self._active is None or self._active.operation != "create":
            raise HostReadinessError("experiment_host_original_create_scope_required")
        self.assert_launch_ready(admission, row, endpoint)

    def _native_create_limits(self, execution_id):
        """Restrictions for the native API's existing final-boundary checks.

        These deadlines narrow the original lexical authority. They are neither
        a permit nor a receipt, and cannot survive leaving this Create scope.
        """
        active = self._check_active(execution_id, restrictive=True)
        if active.operation != "create":
            _fail("original_create_scope_required")
        return dict(readiness_deadline=active.deadline, scope_deadline_monotonic=active.bound,
                    lease_deadline_monotonic_ns=int(active.bound * 1_000_000_000), lease_expires_at=active.expires_at)
