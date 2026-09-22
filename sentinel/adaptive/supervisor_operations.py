"""Conservative instance operations routed through retained child owners.

The supervisor publishes drain before any child RPC. The original guardian
owns the single FencedOffOperation; the supervisor retains its exact routed
request and creation witness. It never races that transaction with another off
writer after delivery/ACK uncertainty. Child replies describe child scope only:
full drain additionally needs the supervisor's original death, recovery,
registry retirement and native cleanup proofs.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from uuid import uuid4

from .contracts import IdentityStatus, ProcessIdentity
from .operator_messages import (MAX_OPERATOR_REQUESTS, OperatorOperation as Op,
    OperatorOutcome as Outcome, OperatorReply, OperatorRequest)
from .operator_transport import OperatorClient
from .pipe_windows import NativePipeEndpoint
from .store import LifecycleError


@dataclass
class _Operation:
    request: OperatorRequest
    caller: ProcessIdentity
    children: dict = field(default_factory=dict)
    replies: dict = field(default_factory=dict)
    errors: dict = field(default_factory=dict)
    fresh_guardian: bool = False


class SupervisorHostOperations:
    def __init__(self, host, *, instance_id, policy_instance_id, guardian_epoch,
                 current, client_factory=OperatorClient):
        self.host, self.current = host, current
        self.instance_id, self.policy_instance_id = instance_id, policy_instance_id
        self.epoch, self.logon_id = guardian_epoch, current.identity.logon_id
        self.client_factory = client_factory
        self.operations = {}
        self._tick_index = 0
        self.last_error = None

    def _assert_owner(self, request):
        self.host.assert_held()
        observation = self.current.observe()
        if (observation.status is not IdentityStatus.ALIVE or observation.identity != self.current.identity or
                request.instance_id != self.instance_id or request.policy_instance_id != self.policy_instance_id or
                request.guardian_epoch != self.epoch or self.host.guardian is None or
                self.host.guardian.epoch != self.epoch):
            raise LifecycleError("operator_target_changed")

    def _reply(self, request, **values):
        return OperatorReply(request.request_id, request.operation, self.instance_id,
            self.policy_instance_id, self.epoch, scope="instance",
            host_state="draining" if self.host.draining else "running", **values)

    def _target(self, role, request):
        child = getattr(self.host, role)
        if child is None:
            return None
        instance = getattr(child, "instance_id", None)
        endpoint_id = getattr(child, "operator_instance_id", None)
        if instance is None or endpoint_id is None:
            raise LifecycleError("operator_child_endpoint_unavailable")
        identity = child.process.identity
        endpoint = NativePipeEndpoint(identity.logon_id, endpoint_id, identity)
        child_request = replace(request, request_id=str(uuid4()), instance_id=instance,
                                observe_request_id=None, cursor=None)
        client = self.client_factory(endpoint, caller_process_or_identity=self.current,
            instance_id=instance, policy_instance_id=self.policy_instance_id,
            guardian_epoch=self.epoch, scope=role)
        return child, child_request, client

    @staticmethod
    def _alive(child):
        observed = child.process.observe()
        return observed.status is IdentityStatus.ALIVE and observed.identity == child.process.identity

    def _retain_error(self, error):
        self.last_error = error
        retain = getattr(self.host, "_retain_operator_error", None)
        if callable(retain):
            retain(error)

    def _advance(self, record):
        # One attempt per applicable child. The original child/request survives
        # transport failure, descriptor changes and a disconnected operator.
        record.fresh_guardian = False
        for role in ("guardian", "helper"):
            if role == "helper" and record.request.operation is not Op.DRAIN:
                continue
            try:
                target = record.children.get(role)
                if target is None:
                    target = self._target(role, record.request)
                    if target is None:
                        continue
                    record.children[role] = target  # before possible delivery
                child, request, client = target
                if getattr(self.host, role) is not child or not self._alive(child):
                    continue  # original host recovery owns the dead witness
                record.replies[role] = client.request(request, timeout_ms=250)
                if role == "guardian":
                    record.fresh_guardian = True
                record.errors.pop(role, None)
            except BaseException as error:
                record.errors[role] = error  # retain private native cleanup owner
                self._retain_error(error)
                if not isinstance(error, Exception):
                    raise
        return self._observe(record, refreshed=True)

    def _observe(self, record, *, refreshed=False):
        snapshot = self.host._custody_snapshot()
        child = record.replies.get("guardian") if refreshed and record.fresh_guardian else None
        if not refreshed:
            target = record.children.get("guardian")
            if target is not None:
                retained, original, client = target
                try:
                    if self.host.guardian is retained and self._alive(retained):
                        observation = replace(original, request_id=str(uuid4()), operation=Op.DESCRIBE,
                            observe_request_id=original.request_id, expected_registry_revision=None)
                        child = client.request(observation, timeout_ms=250)
                        if not self._alive(retained):
                            child = None
                except Exception as error:
                    record.errors["guardian_observation"] = error
                    self._retain_error(error)
        if child is not None and child.registry_revision != snapshot.get("registry_revision"):
            child = None  # never relabel another revision's native inventory
        values = dict(accepted=True, desired_mode="off" if record.request.operation is Op.DRAIN else None,
            outcome=Outcome.PENDING, reason="operator_instance_draining",
            remaining_custody=snapshot["remaining_custody"],
            registry_revision=snapshot.get("registry_revision"),
            barrier_cleared=snapshot.get("barrier_cleared"),
            cleanup_settled=snapshot["settled"])
        if child is not None:
            for key in ("inventory_complete", "native_disabled", "bookkeeping_settled",
                        "slot_released", "remaining_executions"):
                values[key] = getattr(child, key)
        if record.request.operation is Op.DRAIN:
            # A guardian COMPLETE ACK, empty DB or requested shutdown cannot
            # release the supervisor's sole creation/recovery witnesses.
            if snapshot["settled"] and snapshot.get("mode_off") is True:
                values.update(outcome=Outcome.COMPLETE, reason="operator_instance_drained",
                    inventory_complete=True, native_disabled=True, bookkeeping_settled=True,
                    slot_released=True, barrier_cleared=True, cleanup_settled=True,
                    remaining_executions=0, remaining_custody=0)
            elif snapshot.get("reason"):
                values["reason"] = snapshot["reason"]
        elif child is not None:
            # Restore-only is an observation of owned restrictions, not all
            # workload exit. Preserve unverified host recovery as an additional
            # refusal; the live child response cannot override it.
            if child.outcome is Outcome.COMPLETE and not self.host._operational_recovery_pending():
                values.update(outcome=Outcome.COMPLETE, reason="operator_restore_observed")
            else:
                values.update(outcome=Outcome.UNVERIFIED, reason="operator_recovery_unverified")
        return values

    def tick(self):
        if not self.operations:
            return None
        records = tuple(self.operations.values())
        chosen = records[self._tick_index % len(records)]
        self._tick_index += 1
        return self._advance(chosen)

    def __call__(self, request, *, caller_identity):
        if type(request) is not OperatorRequest or type(caller_identity) is not ProcessIdentity:
            raise LifecycleError("operator_request_invalid")
        self._assert_owner(request)
        if caller_identity.logon_id != self.logon_id:
            raise LifecycleError("operator_logon_mismatch")
        if request.mutating:
            record = self.operations.get(request.request_id)
            if record is not None and (record.request != request or record.caller != caller_identity):
                raise LifecycleError("operator_request_payload_changed")
            if record is None:
                if len(self.operations) >= MAX_OPERATOR_REQUESTS:
                    raise LifecycleError("operator_request_capacity")
                record = _Operation(request, caller_identity)
                self.operations[request.request_id] = record
                # Guardian restore-only also freezes its own normal policy.
                # Suppress replacement on the parent first in both cases.
                self.host.begin_drain()
            return self._reply(request, **self._advance(record))
        if request.observe_request_id is not None:
            record = self.operations.get(request.observe_request_id)
            if record is None:
                return self._reply(request, outcome=Outcome.UNAVAILABLE, reason="operator_request_unknown")
            return self._reply(request, **self._observe(record))
        try:
            target = self._target("guardian", request)
            if target is None:
                raise LifecycleError("operator_original_owner_unavailable")
            child, child_request, client = target
            # Read paging is passed only to the original guardian, never to a
            # replacement or another logical instance.
            child_request = replace(child_request, cursor=request.cursor)
            if not self._alive(child):
                raise LifecycleError("operator_original_owner_unavailable")
            reply = client.request(child_request, timeout_ms=250)
            if not self._alive(child):
                raise LifecycleError("operator_original_owner_unavailable")
            values = {name: getattr(reply, name) for name in (
                "outcome", "reason", "accepted", "desired_mode", "inventory_complete",
                "native_disabled", "bookkeeping_settled", "slot_released", "barrier_cleared",
                "cleanup_settled", "remaining_executions", "remaining_custody",
                "registry_revision", "items", "next_cursor")}
            if self.host._operational_recovery_pending():
                values.update(outcome=Outcome.UNVERIFIED, reason="operator_supervisor_recovery_pending",
                              cleanup_settled=False)
            return self._reply(request, **values)
        except Exception as error:
            self._retain_error(error)
            return self._reply(request, outcome=Outcome.UNAVAILABLE,
                               reason="operator_original_owner_unavailable")
