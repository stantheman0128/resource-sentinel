"""Actual supervisor custody for a fixed, admitted S2/P4 host cohort.

Only creation is redirected: the ordinary SupervisorHost still owns its startup
fence, discovery, original guardian recovery, registry retirement and drain.
CreationAttempt owns both CreateProcess handles and its captured process. The
guardian recovery witness is a separate, explicitly retained duplicate, closed
before that attempt. No process is reopened by PID and no child is killed here.
"""
from __future__ import annotations

from contextlib import contextmanager
import os
import threading
from uuid import uuid4

from .contracts import IdentityStatus
from .experiment_host_creation import CreationAttempt
from .experiment_host_roles import GuardianRoleSpec, HelperRoleSpec, WrapperRoleSpec
from .experiment_host_scope import ProductionExperimentScope
from .policy import PolicyBusy, _cleanup_outcome_unverified
from .recovery_owner import RetainedGuardianCreation
from .supervisor_host import SupervisorHost, SupervisorHostRefused, _Guardian, _Helper


_TOKEN = object()
_ORIGINALS = {}


def _fail(reason, owner=None):
    error = SupervisorHostRefused("experiment_supervisor_" + reason)
    error.experiment_supervisor = owner
    raise error


class ExperimentSupervisor:
    """One actual host and its two optional, predeclared creation operations."""

    def __init__(self, *, _token=None):
        if _token is not _TOKEN:
            _fail("original_factory_required")
        self._pid, self._thread = os.getpid(), threading.current_thread()
        self._records = {}
        self._guards = []
        self._errors = []
        self._current_creation = None
        self._operations_pin = None
        self._close_record = self._closure_pin = None
        self._closed = False

    def __reduce__(self):
        raise TypeError("experiment_supervisor_not_serializable")

    @classmethod
    def prepare(cls, scope):
        if cls is not ExperimentSupervisor or type(scope) is not ProductionExperimentScope:
            _fail("original_scope_required")
        ProductionExperimentScope._assert_ledger_original(scope, scope.demand, scope.spec)
        if (not scope._prepared or scope._sealed or scope._guard is not None or
                scope._active_sql is not None or scope.spec.suite not in {"S2", "P4"} or
                getattr(scope, "_supervisor_integration", None) is not None or
                scope._supervisor_host is not None):
            _fail("unused_scope_required")
        guardians = [role for role in scope.plan.roles if type(role) is GuardianRoleSpec]
        helpers = [role for role in scope.plan.roles if type(role) is HelperRoleSpec]
        if len(guardians) != 1 or len(helpers) > 1:
            _fail("declared_roles_required")
        guardian = guardians[0]
        helper = helpers[0] if helpers else None
        if guardian.policy_instance_id != scope.spec.isolated_policy_instance_id:
            _fail("declared_policy_changed")
        members = {member.member_id: member for member in scope.plan.members}
        guardian_member = members[guardian.member_id]
        helper_member = None if helper is None else members[helper.member_id]
        if any(member.member_id in scope._attempts for member in
               (guardian_member, helper_member) if member is not None):
            _fail("unused_members_required")
        owner = cls(_token=_TOKEN)
        owner.scope, owner.guardian_role, owner.helper_role = scope, guardian, helper
        owner.guardian_member, owner.helper_member = guardian_member, helper_member
        host = owner.host = SupervisorHost(data_dir=guardian.data_dir,
            journal_dir=guardian.journal_dir, profile_path=guardian.profile_path,
            helper_profile_path=None if helper is None else helper.profile_path,
            child_cwd=scope.demand._source_root, max_guardians=1, max_helpers=1)
        host._initial_epoch = guardian.guardian_epoch
        names = {name: getattr(guardian, name) for name in
                 ("instance_id", "operator_instance_id", "launch_instance_id",
                  "query_instance_id", "control_instance_id")}
        host._guardian_endpoints[guardian.guardian_epoch] = names
        helper_names = None
        owner._helper_selectors = None
        if helper is not None:
            if helper.member_id in scope._role_release_data:
                _fail("helper_selectors_occupied")
            selectors = (str(uuid4()), str(uuid4()))
            owner._helper_selectors = selectors
            scope._role_release_data[helper.member_id] = selectors
            helper_names = dict(zip(("instance_id", "operator_instance_id"), selectors))
            host._helper_endpoints = helper_names
        owner._base_pin = (scope, scope.plan, scope.demand, scope.demand._source_root,
            host, guardian, helper, guardian_member, helper_member,
            owner._records, owner._guards, owner._errors)
        owner._host_values = (host.data_dir, host.journal_dir, host.profile_path,
            host.helper_profile_path, host._initial_epoch, host._instance_id,
            host._operator_instance_id, tuple(names.items()),
            None if helper_names is None else tuple(helper_names.items()))
        # Publish the original owner before any startup, SQL, native or IPC work.
        _ORIGINALS[id(owner)] = owner
        scope._supervisor_integration = host._experiment_supervisor = owner
        owner.assert_original()
        return owner

    def assert_original(self):
        """Pure memory identity checks, including the exact source-bound scope."""
        if type(self) is not ExperimentSupervisor or _ORIGINALS.get(id(self)) is not self:
            _fail("original_integration_required", self)
        (scope, plan, demand, source, host, guardian, helper, guardian_member,
         helper_member, records, guards, errors) = self._base_pin
        if (self._pid != os.getpid() or self._thread is not threading.current_thread() or
                self.scope is not scope or scope.plan is not plan or scope.demand is not demand or
                demand._source_root != source or self.host is not host or type(host) is not SupervisorHost or
                scope._supervisor_integration is not self or host._experiment_supervisor is not self or
                self.guardian_role is not guardian or self.helper_role is not helper or
                self.guardian_member is not guardian_member or self.helper_member is not helper_member or
                self._records is not records or self._guards is not guards or self._errors is not errors or
                getattr(host, "_daily_successor_operation", None) is not None or
                host.max_guardians != 1 or host.max_helpers != 1 or host.creation is not None):
            _fail("original_changed", self)
        ProductionExperimentScope._assert_ledger_original(scope, demand, scope.spec)
        values = (host.data_dir, host.journal_dir, host.profile_path, host.helper_profile_path,
            host._initial_epoch, host._instance_id, host._operator_instance_id,
            tuple(host._guardian_endpoints.get(guardian.guardian_epoch, {}).items()),
            None if host._helper_endpoints is None else tuple(host._helper_endpoints.items()))
        if values != self._host_values:
            _fail("host_binding_changed", self)
        if helper is not None and scope._role_release_data.get(helper.member_id) is not self._helper_selectors:
            _fail("helper_selectors_changed", self)
        if self._operations_pin is not None:
            current, startup, store, operations, instance = self._operations_pin
            if (host._operational_current is not current or host.startup is not startup or
                    host.store is not store or host.operations is not operations or
                    host._instance_id != instance or scope._supervisor_host is not host or
                    scope._supervisor_pin != (host, current, startup, store, operations, instance)):
                _fail("operations_changed", self)
        for member_id, record in records.items():
            if record["member"].member_id != member_id:
                _fail("creation_record_changed", self)
            attempt = record.get("attempt")
            if attempt is not None:
                if type(attempt) is not CreationAttempt or scope._attempts.get(member_id) is not attempt:
                    _fail("creation_owner_changed", self)
                CreationAttempt.assert_original(attempt, scope)
            child_pin = record.get("child_pin")
            if child_pin is not None:
                child, process, witness, handle, pid = child_pin
                if (record.get("child") is not child or child.process is not process or
                        getattr(child, "creation_witness", None) is not witness or
                        child.creation_handle != handle or child.pid != pid or
                        getattr(child, "epoch", None) != record["epoch_pin"] or
                        any(getattr(child, name, None) != value for name, value in record["endpoint_pin"])):
                    _fail("child_custody_changed", self)
            witness_pin = record.get("witness_pin")
            if witness_pin is not None:
                witness, process, backend, handle, lock, identity, owner_lock, pid, epoch = witness_pin
                if (record.get("witness") is not witness or witness._process is not process or
                        record["child"].process is not process or process._backend is not backend or
                        process._lock is not lock or process.identity != identity or witness._lock is not owner_lock or
                        witness._creator_pid != pid or witness._guardian_epoch != epoch or
                        witness._construction_error is not None or process._close_outcome_unknown or
                        getattr(process, "_duplicate_outcome_unknown", False) or
                        (record.get("recovery_witness_closed", False) and
                            (not witness._closed or process._handle is not None)) or
                        (not record.get("recovery_witness_closed", False) and
                            (witness._closed or process._handle != handle))):
                    _fail("recovery_witness_changed", self)

    def bind_operations(self):
        self.assert_original()
        host, scope = self.host, self.scope
        if host._closed or host._operational_current is None or host.operations is None:
            _fail("actual_operations_required", self)
        scope.open_dispatcher()
        scope.bind_supervisor(host)
        pin = (host._operational_current, host.startup, host.store, host.operations, host._instance_id)
        if self._operations_pin is not None and any(a is not b for a, b in
                zip(pin[:4], self._operations_pin[:4])):
            _fail("operations_changed", self)
        self._operations_pin = pin

    @contextmanager
    def creation_scope(self, member):
        """Entered by original create_actor AFTER its daily POLICY acquisition."""
        self.assert_original()
        scope, host = self.scope, self.host
        record = self._current_creation
        if (self._closed or self._operations_pin is None or record is None or
                record["member"] is not member or
                not (member is self.guardian_member or member is self.helper_member) or
                scope._guard is None or scope._daily_policy.current_guard() is not scope._guard or
                scope._active_sql is not None or host.store._policy.current_guard() is not None):
            _fail("ordered_creation_scope_required", self)
        retained = {"member": member, "guard": None, "settled": False}
        self._guards.append(retained)
        body_error = None
        try:
            guard = retained["guard"] = host.store._policy.prepare(scope.process.identity.logon_id)
            with host.store._policy.hold(guard):
                try:
                    if guard.binding != host.binding:
                        _fail("isolated_policy_changed", self)
                    if member is self.guardian_member:
                        host.startup.assert_fresh_locked()
                    else:
                        host.startup.assert_held()
                        guardian = host.guardian
                        observed = None if guardian is None else guardian.process.observe()
                        if (observed is None or observed.status is not IdentityStatus.ALIVE or
                                observed.identity != guardian.process.identity or host.guardian_descriptor is None or
                                host.guardian_descriptor.state != "ready" or host.draining):
                            _fail("ready_guardian_required", self)
                    yield
                except BaseException as error:
                    # Keep the original child/SQL error while the exact native
                    # POLICY owner completes release and nonce cleanup. As in
                    # ProductionExperimentScope._operation, this is cleanup,
                    # never permission to repeat the failed Create operation.
                    body_error = error
            retained["settled"] = True
            if body_error is not None:
                raise body_error
        except BaseException as error:
            guard = retained["guard"]
            if (guard is not None and guard._nonce_clear_confirmed and
                    (guard._native_exit_confirmed or guard._native_no_entry_confirmed)):
                retained["settled"] = True
            elif (guard is None and type(error) is PolicyBusy and
                    not _cleanup_outcome_unverified(error)):
                retained["settled"] = True
            retained["error"] = error
            self._errors.append(error)
            error.experiment_supervisor = self
            raise

    @property
    def pending(self):
        self.assert_original()
        return (self._current_creation is not None or any(not item["settled"] for item in self._guards) or
            any(not record.get("no_creation", False) and
                (record.get("error") is not None or record.get("close_error") is not None or
                 not record.get("registration_complete", False))
                for record in self._records.values()))

    def _settle_no_creation(self, record):
        """A positive no-Create outcome is distinct from an unknown native call."""
        scope = self.scope
        attempt = record.get("attempt")
        if (record.get("child") is not None or record.get("witness") is not None or
                scope._guard is not None or scope._guard_unknown or scope._active_sql is not None or
                any(not item["settled"] for item in self._guards)):
            return False
        if attempt is None:
            # The fixed scope retains CreationAttempt before entering native.
            # No attempt plus positive scope cleanup proves it never entered.
            if record["member"].member_id in scope._attempts:
                return False
        elif attempt.never_created:
            CreationAttempt.settle_native(attempt, scope)
        else:
            return False
        record["no_creation"] = record["closed"] = True
        record["recovery_witness_closed"] = True
        self.host._creation_unknown = False
        return True

    def _create(self, member, *, guardian):
        self.assert_original()
        host, scope = self.host, self.scope
        if (host.draining or self._closed or self._operations_pin is None or
                member.member_id in self._records or self.pending):
            _fail("new_creation_refused", self)
        retained = {"member": member, "role": member.role, "registration_complete": False,
                    "phase": "creating"}
        self._records[member.member_id] = retained
        host._creation_records.append(retained)
        self._current_creation = retained
        host._creation_unknown = True
        try:
            attempt = retained["attempt"] = scope.create_actor(member)
            host._creation_unknown = False
            if guardian:
                witness = RetainedGuardianCreation.from_creation_handle(attempt._raw_pin[0],
                    expected_pid=attempt.process.identity.pid,
                    expected_logon_id=scope.process.identity.logon_id,
                    guardian_epoch=self.guardian_role.guardian_epoch)
                retained["witness"] = witness
                child = _Guardian(epoch=self.guardian_role.guardian_epoch,
                    pid=attempt.process.identity.pid, creation_handle=attempt._raw_pin[0],
                    process=witness.process, creation_witness=witness,
                    endpoints=host._guardian_endpoints[self.guardian_role.guardian_epoch])
            else:
                child = _Helper(pid=attempt.process.identity.pid, creation_handle=attempt._raw_pin[0],
                    process=attempt.process, endpoints=host._helper_endpoints)
            retained["child"] = child
            retained["child_pin"] = (child, child.process,
                getattr(child, "creation_witness", None), child.creation_handle, child.pid)
            retained["epoch_pin"] = getattr(child, "epoch", None)
            retained["endpoint_pin"] = tuple((host._guardian_endpoints[self.guardian_role.guardian_epoch]
                if guardian else host._helper_endpoints).items())
            if guardian:
                process = witness.process
                retained["witness_pin"] = (witness, process, process._backend, process._handle,
                    process._lock, process.identity, witness._lock, witness._creator_pid,
                    witness._guardian_epoch)
            # Host custody precedes registration publication and any child RPC.
            if guardian:
                host.guardian = child
                host.started_guardians += 1
            else:
                host.helper = child
                host.started_helpers += 1
            retained["phase"] = "owned"
        except BaseException as error:
            retained["attempt"] = scope._attempts.get(member.member_id)
            retained["error"] = error
            self._errors.append(error)
            partial = getattr(error, "_guardian_creation_owner", None)
            if partial is not None:
                retained["witness"] = partial
                host.unsettled_captures.append({"owner": partial,
                    "epoch": self.guardian_role.guardian_epoch,
                    "reason": "experiment_guardian_creation_unverified"})
            self._settle_no_creation(retained)
            error.experiment_supervisor = self
            raise
        finally:
            self._current_creation = None
        # Never publish authorization under either POLICY or a SQL transaction.
        self._publish_registration(retained)
        return child

    def _publish_registration(self, record):
        self.assert_original()
        guardian = record["member"] is self.guardian_member
        expected = self.host.guardian if guardian else self.host.helper
        if (record.get("phase") not in {"owned", "publishing", "published"} or
                record.get("child") is None or record["child"] is not expected or
                record.get("child_pin") is None or (guardian and record.get("witness_pin") is None)):
            _fail("adopted_child_required", self)
        if record.get("registration_complete", False) and record.get("error") is None:
            return
        try:
            permitted = tuple(sorted(role.workload_member_id for role in self.scope.plan.roles
                if record["member"] is self.guardian_member and type(role) is WrapperRoleSpec and
                role.guardian_member_id == self.guardian_member.member_id))
            record["phase"] = "publishing"
            self.scope.publish_child_registration(record["attempt"], permitted_member_ids=permitted)
            record["registration_complete"] = True
            record["phase"] = "published"
            record.pop("error", None)
        except BaseException as error:
            record["error"] = error
            self._errors.append(error)
            error.experiment_supervisor = self
            raise

    def start_guardian(self, *, epoch=None, previous_epoch=None):
        self.assert_original()
        if previous_epoch is not None or epoch != self.guardian_role.guardian_epoch:
            _fail("declared_epoch_required", self)
        record = self._records.get(self.guardian_member.member_id)
        if record is not None:
            if (record.get("child") is not None and record["child"] is self.host.guardian and
                    not self.pending):
                return self.host.guardian
            _fail("original_creation_unsettled", self)
        return self._create(self.guardian_member, guardian=True)

    def start_helper(self):
        self.assert_original()
        if self.helper_member is None or self.host.started_helpers:
            _fail("declared_helper_budget_exhausted", self)
        return self._create(self.helper_member, guardian=False)

    def poll_once(self):
        self.assert_original()
        if self._closed:
            _fail("closed", self)
        dispatcher = self.scope._host_dispatcher
        if dispatcher is None:
            return False
        if not self.scope._sealed:
            for record in self._records.values():
                if (record.get("phase") in {"owned", "publishing", "published"} and
                        (not record.get("registration_complete", False) or record.get("error") is not None)):
                    self._publish_registration(record)
                    if record["child"] is self.host.guardian and not self.pending:
                        # Resume the same already-published child after its
                        # original auth publication recovered; never Create again.
                        self.host.cold_reason = None
        # The dispatcher checks original thread, no POLICY/SQL and native peers.
        return dispatcher.poll_once(timeout_ms=1000)

    def close_child(self, child):
        self.assert_original()
        records = [record for record in self._records.values() if record.get("child") is child]
        if len(records) != 1:
            _fail("original_child_required", self)
        record = records[0]
        attempt = record["attempt"]
        if CreationAttempt.observe_exit(attempt, self.scope) is not IdentityStatus.DEAD:
            _fail("child_death_unverified", self)
        try:
            if not record.get("recovery_witness_closed", False):
                witness = getattr(child, "creation_witness", None)
                if witness is not None:
                    if type(witness) is not RetainedGuardianCreation or record.get("witness") is not witness:
                        _fail("original_recovery_witness_required", self)
                    RetainedGuardianCreation.close(witness)
                record["recovery_witness_closed"] = True
            # This is the sole closer of the raw process/thread and captured duplicate.
            CreationAttempt.settle_native(attempt, self.scope)
            record["closed"] = True
            record.pop("close_error", None)
        except BaseException as error:
            record["close_error"] = error
            self._errors.append(error)
            error.experiment_supervisor = self
            raise

    def assert_close_ready(self):
        self.assert_original()
        if not self.host.draining or self.pending:
            _fail("deliberate_drain_required", self)

    def prepare_close(self):
        """No waiting or cancellation: finish only already drained host custody."""
        self.assert_original()
        if self._closed:
            return self.assert_closed()
        self.assert_close_ready()
        if (self.host.guardian is None and self._records and
                all(record.get("no_creation", False) for record in self._records.values())):
            # The cold start refusal is retained in this owner's errors. A
            # positive no-Create result permits lifetime-fence cleanup only.
            self.host.cold_reason = None
        # Ordinary host close performs recovery checks before closing children,
        # operator discovery and the original startup lifetime fence.
        result = SupervisorHost.close(self.host)
        if (not self.host._closed or result.get("cleanup_errors") or
                result.get("guardian_left_running") or result.get("helper_left_running") or
                result.get("unverified") or result.get("unsettled_captures") or
                any(not record.get("closed", False) for record in self._records.values())):
            _fail("actual_host_close_unsettled", self)
        self._close_record = self.host._close_record
        self._closure_pin = (self.host.startup, self.host.operations, self.host.operator_listener,
                             self.host.discovery, self._close_record)
        self._closed = True
        self.assert_closed()

    def close(self):
        self.prepare_close()
        self.assert_closed()

    def assert_closed(self):
        """Positive original closure only; pure memory, safe for final SQL checks."""
        self.assert_original()
        host = self.host
        if (not self._closed or self._closure_pin is None or self._close_record is not host._close_record or
                not host._closed or self.pending or not host.draining or
                host.startup is None or not host.startup._closed or
                not host._operator_closed or not host._discovery_closed or not host._descriptor_removed or
                any(a is not b for a, b in zip(self._closure_pin,
                    (host.startup, host.operations, host.operator_listener, host.discovery, host._close_record))) or
                any(not record.get("closed", False) or
                    (record.get("attempt") is not None and not record["attempt"].native_settled) or
                    not record.get("recovery_witness_closed", False) or
                    (record.get("witness") is not None and not record["witness"]._closed)
                    for record in self._records.values())):
            _fail("positive_close_required", self)
