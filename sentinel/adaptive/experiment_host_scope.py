"""Original parent custody for one production S2/P4 host cohort.

This owner partitions an already admitted daily demand. It never captures a new
machine budget or interprets serialized records as native custody. All SQL is
local and ends before native work/IPC. Child bootstrap, launch and completion
retain their own originals; registering this scope alone authorizes none of them.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3
import secrets
import sys
import threading
import time
from uuid import uuid4

from . import daily_generation, experiment_demand, experiment_host_ledger as ledger
from .contracts import IdentityStatus
from .daily_readiness_transport import LedgerFileIdentity
from .identity import VerifiedProcess
from .policy import PolicyCoordinator


_CREATE = object()
_OWNERS = {}
_OWNERS_LOCK = threading.RLock()


class ProductionScopeError(RuntimeError):
    def __init__(self, reason, owner=None):
        self.reason, self.owner = "production_scope_" + reason, owner
        super().__init__(self.reason)


def _fail(reason, owner=None):
    raise ProductionScopeError(reason, owner)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False)


@dataclass(frozen=True)
class ProductionExperimentPlan:
    """Fixed metadata covered by the original daily declaration's scope hash."""
    spec: ledger.HostScopeSpec
    members: tuple[ledger.MemberClaim, ...]
    commands: tuple = ()

    def __post_init__(self):
        if (type(self.spec) is not ledger.HostScopeSpec or type(self.members) is not tuple or
                not 1 <= len(self.members) <= ledger.MAX_MEMBERS or
                any(type(item) is not ledger.MemberClaim for item in self.members) or
                len({item.member_id for item in self.members}) != len(self.members) or
                sum(item.kind == "infrastructure" for item in self.members) > ledger.MAX_ACTORS):
            _fail("plan_invalid")
        if type(self.commands) is not tuple:
            _fail("plan_commands_invalid")
        if self.commands:
            from .experiment_host_creation import ChildCommand
            if (any(type(pair) is not tuple or len(pair) != 2 or type(pair[1]) is not ChildCommand
                    for pair in self.commands) or
                    len({pair[0] for pair in self.commands}) != len(self.commands) or
                    not {pair[0] for pair in self.commands} <=
                    {item.member_id for item in self.members if item.kind == "infrastructure"}):
                _fail("plan_commands_invalid")

    def to_dict(self):
        spec = self.spec
        return dict(domain="sentinel-production-experiment-plan-v1",
            scope=dict(scope_id=spec.scope_id, suite=spec.suite,
                isolated_ledger_path=spec.isolated_ledger_path,
                isolated_ledger_identity=list(spec.isolated_ledger_identity),
                isolated_policy_instance_id=spec.isolated_policy_instance_id),
            members=[dict(member_id=item.member_id, kind=item.kind, role=item.role,
                          requested=item.requested.to_dict()) for item in self.members],
            commands=[dict(member_id=member, executable=command.executable,
                           arguments=list(command.arguments), cwd=command.cwd)
                      for member, command in self.commands])

    @property
    def sha256(self):
        return hashlib.sha256(_canonical(self.to_dict()).encode("ascii")).hexdigest()


def is_original_preparation(scope, demand):
    """Pure memory whitelist used by the daily owner, including partial setup."""
    if type(scope) is not ProductionExperimentScope:
        return False
    return (scope.demand is demand and _OWNERS.get(scope.scope_id) is scope and
            type(scope.plan) is ProductionExperimentPlan and scope.plan is scope._plan_original and
            scope.spec is scope.plan.spec and scope.scope_id == scope.spec.scope_id and
            scope._pid == os.getpid() and scope._thread is threading.current_thread() and
            scope.plan.sha256 == scope._plan_hash and
            demand.declaration.suite == scope.spec.suite and
            demand.declaration.scope_sha256 == scope._plan_hash)


class _SqlAttempt:
    def __init__(self, path, write):
        self.path, self.write = path, write
        self.connection = self.error = None
        self.commit_entered = self.committed = False
        self.rollback_unknown = self.close_unknown = self.closed = False


class ProductionExperimentScope:
    """One retained parent; even failed preparation remains the daily owner's."""
    def __init__(self, *, _token=None):
        if _token is not _CREATE:
            _fail("original_factory_required")
        self._lock = threading.RLock()
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self.registered_scope = self._registered_original = None
        self._guard = None
        self._guard_unknown = False
        self._sql_attempts = []
        self._active_sql = None
        self._errors = []
        self._scope_cleanup_error = None
        self._prepared = self._sealed = False
        self._attempts = {}
        self._creation_gate = None
        self._creation_deadline = None
        self._creation_ready_set = False
        self._creation_bounds = {}
        self._pending_members = {}
        self._published_actors = {}
        self._child_registrations = {}
        self._accepted_children = {}
        self._transport_service = None
        self._transport_endpoint = None
        self._scope_nonce = secrets.token_hex(32)

    def __reduce__(self):
        raise TypeError("production_scope_not_serializable")

    @classmethod
    def prepare(cls, demand, plan):
        if (cls is not ProductionExperimentScope or
                type(demand) is not experiment_demand.DailyExperimentDemand or
                type(plan) is not ProductionExperimentPlan):
            _fail("original_demand_and_plan_required")
        demand._static_original()
        if (demand.declaration.suite != plan.spec.suite or
                demand.declaration.scope_sha256 != plan.sha256):
            _fail("declared_plan_mismatch", demand)
        policy = demand._admission._submission_policy
        process = demand._admission._process
        if type(policy) is not PolicyCoordinator or type(process) is not VerifiedProcess:
            _fail("original_daily_admission_required", demand)
        # Validate cumulative partition demand before registering/acquiring. This
        # metadata check grants no capacity; the real daily rows are checked below.
        for key, capacity in demand.declaration.requested.to_dict().items():
            if sum(item.requested.to_dict()[key] for item in plan.members) > capacity:
                _fail("plan_exceeds_daily_demand", demand)
        owner = cls(_token=_CREATE)
        owner.demand, owner.plan, owner.spec = demand, plan, plan.spec
        owner.scope_id = plan.spec.scope_id
        owner._plan_original, owner._plan_hash = plan, plan.sha256
        owner.process, owner._daily_policy, owner.daily_store = process, policy, policy.store
        owner.ledger_path = Path(plan.spec.isolated_ledger_path)
        owner._pin = (demand, process, policy, policy.store, owner.ledger_path)
        owner._process_pin = (process._backend, process._handle, process._lock, process.identity)
        # These memory publications precede source/readiness, file/SQL opens and
        # all native queries. A failed acquisition must not enable a fresh owner.
        with _OWNERS_LOCK, demand._lock:
            if (owner.scope_id in _OWNERS or demand._native_preparation is not None or
                    demand._native_preparation_sealed):
                _fail("original_scope_occupied", demand)
            _OWNERS[owner.scope_id] = owner
            demand._register_native_preparation(owner)
        try:
            demand._assert_unused_claim()
            owner.reconcile_preparation()
            return owner
        except BaseException as error:
            owner._retain(error)
            raise

    def _retain(self, error):
        if not any(value is error for value in self._errors):
            self._errors.append(error)
        error.production_scope_owner = self
        error.experiment_demand_owner = self.demand
        return error

    def _assert_ledger_original(self, demand, spec, registered=None):
        """Pure original-object checks; safe inside a SQL guard callback."""
        if (not is_original_preparation(self, demand) or self.spec is not spec or
                (self.demand, self.process, self._daily_policy, self.daily_store, self.ledger_path) != self._pin or
                self._daily_policy is not demand._admission._submission_policy or
                self.process is not demand._admission._process or
                self.registered_scope is not self._registered_original or
                (registered is not None and self.registered_scope is not registered)):
            _fail("original_binding_changed", self)
        demand._static_original()
        demand._assert_native_preparation(self)

    def _retain_ledger_scope(self, registered):
        self._assert_ledger_original(self.demand, self.spec)
        if type(registered) is not ledger.RegisteredHostScope or registered.demand is not self.demand or registered.spec is not self.spec:
            _fail("original_registration_required", self)
        if self._registered_original is not None and registered is not self._registered_original:
            _fail("original_registration_changed", self)
        self.registered_scope = self._registered_original = registered

    def _native_parent(self):
        self._assert_ledger_original(self.demand, self.spec)
        process = self.process
        if ((process._backend, process._handle, process._lock, process.identity) != self._process_pin or
                process._close_outcome_unknown):
            _fail("original_parent_changed", self)
        observed = process.observe()
        if (process.identity.pid != self._pid or observed.identity != process.identity or
                observed.status is not IdentityStatus.ALIVE):
            _fail("original_parent_unavailable", self)
        self.demand._original()
        identity = LedgerFileIdentity.capture(self.ledger_path)
        if (identity.st_dev, identity.st_ino) != self.spec.isolated_ledger_identity:
            _fail("isolated_ledger_changed", self)

    @contextmanager
    def _operation(self):
        """Original daily fence; never entered by an existing SQL transaction."""
        with self._lock:
            if (self._active_sql is not None or self._guard is not None or self._guard_unknown or
                    self._scope_cleanup_error is not None):
                _fail("operation_custody_unsettled", self)
            if any(not item.closed or item.rollback_unknown for item in self._sql_attempts):
                _fail("sql_custody_unsettled", self)
            self._native_parent()
            body_error = None
            context_complete = False
            try:
                with daily_generation.readiness_scopes((self.demand.ledger_path, self.ledger_path),
                                                       absent_paths=(self.ledger_path,)):
                    daily_generation.revalidate_scoped_readiness(self.demand.ledger_path,
                        expected_generation=self.demand._original_generation_binding())
                    # Retain prepare/hold uncertainty; no replacement POLICY
                    # owner can infer that an interrupted entry was released.
                    self._guard_unknown = True
                    self._guard = self._daily_policy.prepare(self.process.identity.logon_id)
                    with self._daily_policy.hold(self._guard):
                        self._guard_unknown = False
                        try:
                            yield self._guard
                        except BaseException as error:
                            body_error = error
                        finally:
                            self._guard_unknown = True
                    self._guard = None
                    self._guard_unknown = False
                context_complete = True
                if body_error is not None:
                    raise body_error
            except BaseException as error:
                # Keep the original body error if native/context cleanup itself
                # failed. A missing current_guard is never a release ACK.
                if not context_complete:
                    self._scope_cleanup_error = error
                    if body_error is not None and body_error is not error:
                        error.production_scope_body_error = body_error
                self._retain(error)
                raise

    @contextmanager
    def _sql(self, path, *, write=False):
        """Borrow the exact pre-acquired ledger before opening its consumer."""
        if self._active_sql is not None or len(self._sql_attempts) >= 128:
            _fail("nested_sql", self)
        target = Path(path)
        if target not in (self.demand.ledger_path, self.ledger_path):
            _fail("foreign_ledger", self)
        expected = (self.demand.ledger_identity if target == self.demand.ledger_path
                    else self.spec.isolated_ledger_identity)
        with daily_generation.readiness_scope(target) as original:
            if original.path != target or original.ledger_identity != expected:
                _fail("original_ledger_changed", self)
            with self._sql_owned(target, write=write, expected_identity=expected) as conn:
                yield conn

    @contextmanager
    def _sql_owned(self, target, *, write, expected_identity):
        """Retain each acquisition and compare original identity before BEGIN."""
        before = LedgerFileIdentity.capture(target)
        if (before.st_dev, before.st_ino) != expected_identity:
            _fail("original_ledger_changed", self)
        attempt = _SqlAttempt(target, write)
        self._sql_attempts.append(attempt)
        self._active_sql = attempt
        conn, primary = None, None
        try:
            conn = sqlite3.connect(target.as_uri() + "?mode=rw", uri=True,
                                   timeout=.25, isolation_level=None)
            attempt.connection = conn
            conn.row_factory = sqlite3.Row
            databases = conn.execute("PRAGMA database_list").fetchall()
            after = LedgerFileIdentity.capture(target)
            if (len(databases) != 1 or databases[0][1] != "main" or
                    Path(databases[0][2]).resolve(strict=True) != target or
                    (after.st_dev, after.st_ino) != expected_identity):
                _fail("original_ledger_changed", self)
            daily_generation.prepare_connection(conn, role="lifecycle", db_path=target)
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            daily_generation.revalidate_transaction(conn, db_path=target)
            yield conn
            attempt.commit_entered = True
            conn.commit()
            attempt.committed = True
        except BaseException as error:
            primary = attempt.error = error
            if conn is not None and conn.in_transaction:
                attempt.rollback_unknown = True
                try:
                    conn.rollback()
                except BaseException as cleanup:
                    error.production_scope_rollback_error = cleanup
                else:
                    attempt.rollback_unknown = False
            self._retain(error)
            raise
        finally:
            self._active_sql = None
            if conn is not None:
                attempt.close_unknown = True
                try:
                    conn.close()
                except BaseException as cleanup:
                    self._retain(cleanup)
                    if primary is None:
                        raise
                    primary.production_scope_close_error = cleanup
                else:
                    attempt.close_unknown = False
                    attempt.closed = True
            # Retain failed publication originals and their outcome evidence,
            # but ordinary positive reads/writes need no permanent live owner.
            if attempt.closed and attempt.error is None:
                self._sql_attempts.remove(attempt)

    def _verify_isolated(self):
        with self._sql(self.ledger_path) as conn:
            runtime = PolicyCoordinator._runtime(conn)
            binding = PolicyCoordinator._binding(runtime, self.process.identity.logon_id)
            if (binding.instance_id != self.spec.isolated_policy_instance_id or
                    binding == self.demand._policy_original or runtime["mode"] not in {"off", "shadow"} or
                    runtime["admission_barrier"] != "NONE"):
                _fail("isolated_policy_changed", self)

    def reconcile_preparation(self):
        """Retry only this original SQL publication; never recreate a child."""
        self._assert_ledger_original(self.demand, self.spec)
        with self._operation() as guard:
            self._verify_isolated()
            with self._sql(self.demand.ledger_path, write=True) as conn:
                registered = ledger.declare_scope_locked(conn, demand=self.demand, spec=self.spec,
                    policy=self._daily_policy, guard=guard, preparation=self)
                if registered is not self.registered_scope:
                    _fail("original_registration_changed", self)
        self._prepared = True
        return self

    def reserve_member(self, claim):
        """Publish one fixed partition; this does not create or launch an actor."""
        self._assert_ledger_original(self.demand, self.spec)
        if not self._prepared or self._sealed or not any(item is claim for item in self.plan.members):
            _fail("declared_original_member_required", self)
        with self._operation() as guard:
            with self._sql(self.demand.ledger_path, write=True) as conn:
                return ledger.reserve_member_locked(conn, scope=self.registered_scope, claim=claim,
                    policy=self._daily_policy, guard=guard)

    def seal_new_work(self):
        """Local seal only: never a completion or capacity-release result."""
        with self._lock:
            self._assert_ledger_original(self.demand, self.spec)
            self.demand._seal_native_preparation(self)
            self._sealed = True

    def _assert_creation_gate(self, attempt):
        """Original lexical readiness at each native boundary; no RPC or SQL."""
        self._assert_ledger_original(self.demand, self.spec)
        if (self._creation_gate is not attempt or self._active_sql is not None or self._sealed or
                self._attempts.get(attempt.member.member_id) is not attempt or
                self._pending_members.get(attempt.member.member_id) is not attempt.member or
                self._guard is None or self._guard_unknown or not self._creation_ready_set):
            _fail("creation_scope_required", self)
        self._daily_policy.assert_held(self._guard)
        deadline = daily_generation.revalidate_scoped_readiness(self.demand.ledger_path,
            expected_generation=self.demand._original_generation_binding())
        if deadline is not self._creation_deadline:
            _fail("original_creation_readiness_changed", self)
        isolated = LedgerFileIdentity.capture(self.ledger_path)
        if (isolated.st_dev, isolated.st_ino) != self.spec.isolated_ledger_identity:
            _fail("isolated_ledger_changed", self)
        if deadline is not None:
            deadline.require()
        bounds = self._creation_bounds.get(attempt.member.member_id)
        if bounds is None:
            _fail("original_creation_bounds_required", self)
        observation, fixed, monotonic_deadline = bounds
        if (type(observation) is not ledger.MemberCreationObservation or
                (observation.member_id, observation.registered_revision, observation.daily_expires_at) != fixed or
                observation.member_id != attempt.member.member_id or
                time.monotonic_ns() >= monotonic_deadline or time.time() >= observation.daily_expires_at):
            _fail("original_creation_expired", self)

    def _inert_command(self, member):
        matches = [command for key, command in self.plan.commands if key == member.member_id]
        if len(matches) != 1:
            _fail("declared_inert_command_required", self)
        command = matches[0]
        entry = self.demand._source_root / "scripts" / "adaptive-experiment-child.py"
        registration = self.demand.directory / (".experiment-child-" + member.member_id + ".json")
        if (command.executable != str(Path(sys._base_executable).resolve(strict=True)) or
                command.arguments != ("-I", str(entry), "--registration", str(registration)) or
                Path(command.cwd) != self.demand._source_root):
            _fail("fixed_inert_bootstrap_required", self)
        generation = self.demand._original_generation_binding()
        manifest = daily_generation.SourceManifest.from_dict(json.loads(generation["source_manifest_json"]))
        daily_generation._manifest_bound_sources(manifest, self.demand._source_root,
                                                 ("scripts/adaptive-experiment-child.py",))
        return command

    def create_actor(self, member):
        """Only the declared inert entry; publish identity before releasing it."""
        from .experiment_host_creation import CreationAttempt
        self._assert_ledger_original(self.demand, self.spec)
        if (not self._prepared or self._sealed or not any(value is member for value in self.plan.members) or
                member.kind != "infrastructure" or member.member_id in self._attempts):
            _fail("new_declared_actor_required", self)
        command = self._inert_command(member)
        try:
            with self._operation() as guard:
                with self._sql(self.demand.ledger_path, write=True) as conn:
                    ledger.reserve_member_locked(conn, scope=self.registered_scope, claim=member,
                                                 policy=self._daily_policy, guard=guard)
                    observation = ledger.validate_member_creation_locked(conn, scope=self.registered_scope,
                        claim=member, policy=self._daily_policy, guard=guard)
                    monotonic_start = time.monotonic_ns()
                    wall = time.time()
                    if (type(observation) is not ledger.MemberCreationObservation or
                            observation.member_id != member.member_id or
                            type(observation.daily_expires_at) not in (int, float) or
                            not math.isfinite(observation.daily_expires_at) or
                            type(wall) not in (int, float) or not math.isfinite(wall) or
                            observation.daily_expires_at <= wall):
                        _fail("original_creation_expired", self)
                    remaining_ns = math.floor((observation.daily_expires_at - wall) * 1_000_000_000)
                    if remaining_ns <= 0 or member.member_id in self._creation_bounds:
                        _fail("original_creation_bounds_required", self)
                    # This same observation survives a lost commit ACK. It is
                    # timing/data only and never authorizes a second Create.
                    self._creation_bounds[member.member_id] = (observation,
                        (observation.member_id, observation.registered_revision, observation.daily_expires_at),
                        monotonic_start + remaining_ns)
                self._pending_members[member.member_id] = member
                attempt = CreationAttempt._prepare(self, member, command)
                self._creation_gate = attempt
                try:
                    self._creation_deadline = daily_generation.revalidate_scoped_readiness(self.demand.ledger_path,
                        expected_generation=self.demand._original_generation_binding())
                    self._creation_ready_set = True
                    attempt.create(self)
                    attempt.capture_identity(self)
                    process = attempt.process
                    if type(process) is not VerifiedProcess:
                        _fail("created_actor_identity_required", self)
                    identity = process.identity
                    with self._sql(self.demand.ledger_path, write=True) as conn:
                        ledger.publish_actor_locked(conn, scope=self.registered_scope,
                            member_id=member.member_id, actor=identity, policy=self._daily_policy, guard=guard)
                    self._published_actors[member.member_id] = (attempt, identity)
                finally:
                    self._creation_gate = None
                    self._creation_ready_set = False
                    self._creation_deadline = None
            return attempt
        except BaseException as error:
            self._retain(error)
            raise

    def child_registration(self, attempt, *, permitted_member_ids=()):
        """Mint fixed bootstrap DATA only from retained, published creation."""
        from .experiment_host_creation import CreationAttempt
        from .experiment_host_transport import ExperimentChildManifest, ExperimentChildRegistration
        from .pipe_windows import NativePipeEndpoint
        self._assert_ledger_original(self.demand, self.spec)
        if self._active_sql is not None or self._guard is not None or self._sealed:
            _fail("transport_outside_policy_required", self)
        if type(attempt) is not CreationAttempt:
            _fail("original_creation_required", self)
        attempt.assert_original(self)
        actor = self._published_actors.get(attempt.member.member_id)
        if actor is None or actor[0] is not attempt or actor[1] != attempt.process.identity:
            _fail("published_original_actor_required", self)
        allowed = tuple(sorted(permitted_member_ids))
        if (type(permitted_member_ids) is not tuple or len(set(allowed)) != len(allowed) or
                not set(allowed) <= {item.member_id for item in self.plan.members}):
            _fail("declared_permissions_required", self)
        prior = self._child_registrations.get(attempt.member.member_id)
        if prior is not None:
            if prior[0] is not attempt or prior[1].manifest.permitted_member_ids != allowed:
                _fail("original_registration_changed", self)
            return prior[1]
        if self._transport_endpoint is None:
            self._transport_endpoint = NativePipeEndpoint(self.process.identity.logon_id,
                                                         str(uuid4()), self.process.identity)
        generation = self.demand._original_generation_binding()
        manifest = ExperimentChildManifest(endpoint=self._transport_endpoint, child_identity=actor[1],
            scope_id=self.scope_id, scope_nonce=self._scope_nonce, plan_sha256=self._plan_hash,
            source_generation=generation["generation"], source_digest=generation["source_digest"],
            config_digest=generation["config_digest"], daily_ledger_path=str(self.demand.ledger_path),
            daily_ledger_identity=LedgerFileIdentity(*self.demand.ledger_identity),
            daily_policy_instance_id=self.demand._policy_original.instance_id,
            isolated_ledger_path=str(self.ledger_path),
            isolated_ledger_identity=LedgerFileIdentity(*self.spec.isolated_ledger_identity),
            isolated_policy_instance_id=self.spec.isolated_policy_instance_id,
            actor_member_id=attempt.member.member_id, role=attempt.member.role,
            permitted_member_ids=allowed, request_id=str(uuid4()))
        registration = ExperimentChildRegistration(manifest, secrets.token_bytes(32))
        self._child_registrations[attempt.member.member_id] = (attempt, registration)
        return registration

    def reconcile_actor_publication(self, attempt):
        """Reconcile only the retained creation identity; never repeat Create."""
        from .experiment_host_creation import CreationAttempt
        self._assert_ledger_original(self.demand, self.spec)
        if type(attempt) is not CreationAttempt:
            _fail("original_creation_required", self)
        attempt.assert_original(self)
        process = attempt.process
        if type(process) is not VerifiedProcess:
            _fail("created_actor_identity_required", self)
        identity = process.identity
        if self._attempts.get(attempt.member.member_id) is not attempt:
            _fail("original_creation_changed", self)
        with self._operation() as guard:
            with self._sql(self.demand.ledger_path, write=True) as conn:
                ledger.publish_actor_locked(conn, scope=self.registered_scope,
                    member_id=attempt.member.member_id, actor=identity, policy=self._daily_policy, guard=guard)
        self._published_actors[attempt.member.member_id] = (attempt, identity)
        return attempt

    def _assert_transport_original(self, endpoint):
        from .windows import current_thread_holds_mutex
        self._assert_ledger_original(self.demand, self.spec)
        if (self._active_sql is not None or self._guard is not None or current_thread_holds_mutex() or
                self._transport_endpoint is None or endpoint != self._transport_endpoint):
            _fail("original_transport_scope_required", self)
        self._native_parent()
        return self.process

    def _retain_child_transport(self, service):
        from .experiment_host_transport import ExperimentChildService
        if type(service) is not ExperimentChildService:
            _fail("original_transport_required", self)
        self._assert_transport_original(service.endpoint)
        if self._transport_service is not None and self._transport_service is not service:
            _fail("original_transport_changed", self)
        self._transport_service = service

    def _transport_child_registration(self, request, peer):
        from .experiment_host_transport import BindExperimentChildRequest
        if type(request) is not BindExperimentChildRequest or type(peer) is not VerifiedProcess:
            _fail("original_transport_peer_required", self)
        self._assert_transport_original(request.manifest.endpoint)
        original = self._child_registrations.get(request.manifest.actor_member_id)
        if original is None or original[1].manifest != request.manifest:
            _fail("original_child_registration_required", self)
        attempt, registration = original
        attempt.assert_original(self)
        created = attempt.process.observe()
        observed = peer.observe()
        if (created.status is not IdentityStatus.ALIVE or observed.status is not IdentityStatus.ALIVE or
                created.identity != registration.manifest.child_identity or observed.identity != created.identity or
                self._published_actors.get(attempt.member.member_id) != (attempt, created.identity)):
            _fail("original_child_unavailable", self)
        return registration

    def _accept_transport_child(self, request, peer, registration):
        if self._transport_child_registration(request, peer) is not registration:
            _fail("original_child_registration_changed", self)
        previous = self._accepted_children.get(request.request_id)
        if previous is not None and previous is not registration:
            _fail("child_request_reused", self)
        if self._sealed and previous is None:
            _fail("new_work_sealed", self)
        self._accepted_children[request.request_id] = registration
