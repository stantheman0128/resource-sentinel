"""Explicit-target operational clients; no migrations or reconstructed owners.

The operator protocol carries conservative requests to the existing instance.
Its descriptor is a locator only. Managed commands execute through the original
wrapper host, preserving its native context, stdio and child exit contract.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import re
import time
from uuid import UUID, uuid4


COMMANDS = frozenset({"run-managed", "adaptive-status", "adaptive-mode",
                      "adaptive-recover", "adaptive-audit"})
EXIT_CODES = {"complete": 0, "refused": 2, "pending": 3, "unavailable": 4,
              "unverified": 5}
_CODE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_MAX_WAIT_SECONDS = 3600


class OperationalRefused(ValueError):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


class OperationalUnverified(OperationalRefused):
    pass


def register_commands(sub):
    """Extend sentinelctl's parser without touching its existing subcommands."""
    run = sub.add_parser("run-managed", help="Run one exact managed attempt through the wrapper")
    run.add_argument("--command", required=True, dest="managed_command")
    run.add_argument("--cwd", required=True)
    run.add_argument("--repo", required=True)
    run.add_argument("--role", choices=("background", "protected", "neutral"), default="neutral")
    run.add_argument("--priority", choices=("P0", "P1", "P2", "P3"), default="P2")
    run.add_argument("--cpu-units", required=True, type=float)
    run.add_argument("--ram-gib", required=True, type=float)
    run.add_argument("--commit-gib", type=float)
    run.add_argument("--io-slots", type=int, default=0)
    run.add_argument("--guardian-epoch")
    run.add_argument("--guardian-pid", type=int)
    run.add_argument("--guardian-created-filetime", type=int)
    run.add_argument("--endpoint-instance-id")
    run.add_argument("--status-file")
    run.add_argument("--config-file")
    run.add_argument("--admission-timeout-sec", type=int)
    run.add_argument("--rpc-timeout-ms", type=int, default=1000)
    run.add_argument("--poll-interval-ms", type=int, default=100)
    run.add_argument("--max-wait-sec", type=int, default=0)
    run.add_argument("--require-managed", action="store_true")

    status = sub.add_parser("adaptive-status", help="Observe existing ledger and authenticated host status")
    status.add_argument("--observe-request-id", help="Observe a saved operation without replaying it")
    status.add_argument("--instance-id", help="Exact instance from the saved operation receipt")
    status.add_argument("--policy-instance-id", help="Exact policy instance from the saved receipt")
    status.add_argument("--guardian-epoch", help="Exact guardian epoch from the saved receipt")
    mode = sub.add_parser("adaptive-mode", help="Request off and drain from the original instance")
    mode.add_argument("--mode", choices=("off",), required=True)
    mode.add_argument("--drain", action="store_true", required=True)
    recover = sub.add_parser("adaptive-recover", help="Request retained-owner restoration; never cold-adopt")
    recover.add_argument("--restore-only", action="store_true", required=True)
    recover.add_argument("--verify", action="store_true", required=True)
    audit = sub.add_parser("adaptive-audit", help="Require a complete verified owned-cap inventory")
    audit.add_argument("--require-no-active-caps", action="store_true", required=True)
    for parser in (status, mode, recover, audit):
        parser.add_argument("--rpc-timeout-ms", type=int, default=1000)
        parser.add_argument("--wait", action="store_true", help="Observe the same operation until a bounded timeout")
        parser.add_argument("--timeout-sec", type=float, help="Required with --wait; greater than zero, at most 3600")


def build_parser():
    parser = argparse.ArgumentParser(prog="sentinelctl")
    parser.add_argument("--data-dir", help="Explicit existing target; no daily-runtime default")
    register_commands(parser.add_subparsers(dest="command", required=True))
    return parser


def _reason(error):
    value = getattr(error, "reason", "")
    return value if type(value) is str and _CODE.fullmatch(value) else type(error).__name__


def _validate(args):
    if not isinstance(args.data_dir, str) or not args.data_dir.strip():
        raise OperationalRefused("operational_explicit_data_dir_required")
    if type(args.rpc_timeout_ms) is not int or not 1 <= args.rpc_timeout_ms <= 1000:
        raise OperationalRefused("operational_rpc_timeout_invalid")
    if args.command != "run-managed":
        timeout = args.timeout_sec
        if args.wait:
            if (type(timeout) not in (int, float) or not math.isfinite(timeout) or
                    not 0 < timeout <= _MAX_WAIT_SECONDS):
                raise OperationalRefused("operational_wait_timeout_required")
        elif timeout is not None:
            raise OperationalRefused("operational_timeout_requires_wait")
    if args.command == "adaptive-status":
        names = ("observe_request_id", "instance_id", "policy_instance_id", "guardian_epoch")
        values = [getattr(args, name) for name in names]
        if any(value is not None for value in values):
            if not all(type(value) is str and value for value in values):
                raise OperationalRefused("operational_observer_binding_required")
            try:
                for value in values[:3]:
                    parsed = UUID(value)
                    if parsed.int == 0 or str(parsed) != value:
                        raise ValueError
                from .contracts import _identifier
                _identifier(args.guardian_epoch, "guardian_epoch")
            except (ValueError, TypeError):
                raise OperationalRefused("operational_observer_binding_invalid") from None


def _current_process():
    from .identity import VerifiedProcess
    return VerifiedProcess.current()


def _discovery(data_dir, caller):
    from .host_discovery import HostDiscovery
    descriptor = HostDiscovery(data_dir, logon_id=caller.identity.logon_id).read_instance()
    if descriptor.host_role != "supervisor" or descriptor.logon_id != caller.identity.logon_id:
        raise OperationalRefused("operational_instance_binding_invalid")
    return descriptor


def _endpoint(descriptor, role):
    matches = [item.endpoint for item in descriptor.endpoints if item.role == role]
    if len(matches) != 1 or matches[0].server_identity != descriptor.host_identity:
        raise OperationalRefused("operational_endpoint_binding_invalid")
    return matches[0]


def _ledger(data_dir):
    from .query import query_adaptive
    return query_adaptive(Path(data_dir) / "sentinel.db", timeout_ms=250)


def _client(descriptor, caller):
    from .operator_transport import OperatorClient
    return OperatorClient(_endpoint(descriptor, "operator"), caller_process_or_identity=caller,
        instance_id=descriptor.instance_id, policy_instance_id=descriptor.policy_instance_id,
        guardian_epoch=descriptor.guardian_epoch)


def _request(descriptor, operation, *, revision=None, observe=None, cursor=None):
    from .operator_messages import OperatorOperation, OperatorRequest
    return OperatorRequest(request_id=str(uuid4()), operation=OperatorOperation(operation),
        instance_id=descriptor.instance_id, policy_instance_id=descriptor.policy_instance_id,
        guardian_epoch=descriptor.guardian_epoch, expected_registry_revision=revision,
        observe_request_id=observe, cursor=cursor)


def _check_reply(reply, request):
    from .operator_messages import OperatorReply
    if type(reply) is not OperatorReply:
        raise OperationalUnverified("operational_reply_unverified")
    try:
        reply.__post_init__()
    except Exception:
        raise OperationalUnverified("operational_reply_unverified") from None
    if any(getattr(reply, field) != getattr(request, field) for field in
           ("request_id", "operation", "instance_id", "policy_instance_id", "guardian_epoch")):
        raise OperationalUnverified("operational_reply_binding_invalid")


def _completion(command, reply):
    outcome = reply.outcome.value
    if outcome != "complete":
        return outcome, reply.reason
    if reply.scope != "instance":
        return "unverified", "operational_instance_scope_unverified"
    if command == "adaptive-status":
        return "complete", reply.reason
    required = (reply.inventory_complete, reply.native_disabled, reply.bookkeeping_settled,
                reply.slot_released, reply.cleanup_settled)
    if any(value is not True for value in required):
        return "unverified", "operational_completion_unverified"
    if command == "adaptive-mode":
        if reply.desired_mode != "off" or reply.accepted is not True or reply.barrier_cleared is not True:
            return "unverified", "operational_drain_unverified"
        remaining = (reply.remaining_executions, reply.remaining_custody)
        if any(type(value) is not int or value < 0 for value in remaining):
            return "unverified", "operational_drain_inventory_unverified"
        if any(remaining):
            return "pending", "rollback_draining"
    return "complete", reply.reason


def _operate(args, record):
    # These diagnostics never construct Coordinator/LifecycleStore. Recovery
    # still reaches a retained owner when the ledger is temporarily unreadable.
    try:
        record["ledger"] = _ledger(args.data_dir)
    except Exception as error:
        record["ledger"] = {"available": False, "reason": _reason(error)}
    if args.command in {"adaptive-status", "adaptive-audit"} and record["ledger"].get("available") is not True:
        record.update(outcome="unavailable", reason="operational_ledger_unavailable")
        return 4
    revision = record["ledger"].get("registry_revision")
    if args.command == "adaptive-mode" and (record["ledger"].get("available") is not True or
            type(revision) is not int or revision < 0):
        record.update(outcome="unavailable", reason="operational_registry_revision_unavailable")
        return 4
    operation = {"adaptive-status": "describe", "adaptive-mode": "drain",
                 "adaptive-recover": "restore_only", "adaptive-audit": "audit"}[args.command]
    deadline = time.monotonic() + args.timeout_sec if args.wait else None
    with _current_process() as caller:
        descriptor = _discovery(args.data_dir, caller)
        observe = getattr(args, "observe_request_id", None)
        if observe is not None and any(getattr(args, name) != getattr(descriptor, name)
                for name in ("instance_id", "policy_instance_id", "guardian_epoch")):
            raise OperationalRefused("operational_observer_target_changed")
        client = _client(descriptor, caller)
        request = _request(descriptor, operation, revision=revision if operation == "drain" else None,
                           observe=observe)
        original_id = observe or request.request_id
        record["operation_request_id"] = original_id
        record["instance_id"] = descriptor.instance_id
        record["policy_instance_id"] = descriptor.policy_instance_id
        record["guardian_epoch"] = descriptor.guardian_epoch
        attempted = False
        audit_revision = None
        while True:
            timeout = args.rpc_timeout_ms
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    record.update(outcome="pending" if attempted else "unavailable",
                                  reason="operational_wait_timeout" if attempted else
                                  "operational_deadline_before_request")
                    return 3 if attempted else 4
                timeout = min(timeout, max(1, math.floor(remaining * 1000)))
            attempted = True
            try:
                reply = client.request(request, timeout_ms=timeout)
            except Exception as error:
                # Only the transport may positively classify an operation as
                # not delivered, including reads. Unexpected errors may occur
                # after request write and cannot imply clean unavailability.
                if not hasattr(error, "outcome_unknown"):
                    error.outcome_unknown = True
                raise
            _check_reply(reply, request)
            if operation == "audit":
                if audit_revision is not None and reply.registry_revision != audit_revision:
                    raise OperationalUnverified("operational_audit_revision_changed")
                if reply.next_cursor is not None:
                    audit_revision = reply.registry_revision
            outcome, reason = _completion(args.command, reply)
            if operation == "audit" and outcome == "pending" and reply.next_cursor is None:
                # Audits are bounded read snapshots, not retained mutations.
                # Without a next page there is no operation to observe later.
                outcome, reason = "unverified", "operational_audit_incomplete"
            record.update(outcome=outcome, reason=reason, result=reply.to_dict())
            if outcome != "pending" or not args.wait:
                return EXIT_CODES[outcome]
            if operation == "audit" and reply.next_cursor is not None:
                if type(reply.registry_revision) is not int or reply.registry_revision < 0:
                    record.update(outcome="unverified", reason="operational_audit_revision_unverified")
                    return 5
                request = _request(descriptor, "audit", revision=reply.registry_revision,
                                   cursor=reply.next_cursor)
            else:
                request = _request(descriptor, "describe",
                                   observe=observe if operation == "describe" else original_id)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(.25, remaining))


def _managed_argv(args):
    names = ("guardian_epoch", "guardian_pid", "guardian_created_filetime", "endpoint_instance_id")
    supplied = [getattr(args, name) is not None for name in names]
    if any(supplied) and not all(supplied):
        raise OperationalRefused("operational_partial_guardian_endpoint")
    if not any(supplied):
        with _current_process() as caller:
            descriptor = _discovery(args.data_dir, caller)
            child = descriptor.guardian
            if child is None or child.state != "ready":
                raise OperationalRefused("operational_guardian_not_ready")
            endpoint = _endpoint(child, "launch")
            args.guardian_epoch = child.guardian_epoch
            args.guardian_pid = child.host_identity.pid
            args.guardian_created_filetime = child.host_identity.created_filetime_100ns
            args.endpoint_instance_id = endpoint.instance_id
    argv = ["run-managed", "--data-dir", args.data_dir, "--command", args.managed_command]
    fields = ("cwd", "repo", "role", "priority", "cpu_units", "ram_gib", "commit_gib", "io_slots",
              *names, "status_file", "config_file", "admission_timeout_sec", "rpc_timeout_ms",
              "poll_interval_ms", "max_wait_sec")
    for name in fields:
        value = getattr(args, name)
        if value is not None:
            argv.extend(("--" + name.replace("_", "-"), str(value)))
    if args.require_managed:
        argv.append("--require-managed")
    return argv


def dispatch(args):
    record = {"event": "adaptive_operational_result", "command": args.command}
    if args.command == "run-managed":
        from . import wrapper_host
        try:
            _validate(args)
            argv = _managed_argv(args)
        except KeyboardInterrupt:
            return wrapper_host._refused(wrapper_host.WrapperHostRefused(
                "wrapper_host_operational_interrupted"), args.require_managed, None)
        except Exception as error:
            return wrapper_host._refused(wrapper_host.WrapperHostRefused(
                "wrapper_host_operational_refused", _reason(error)), args.require_managed, None)
        # Execution-stage failures and interrupts remain exclusively owned by
        # the wrapper. Never remap one to a prelaunch refusal with host=None.
        return wrapper_host.main(argv)
    try:
        _validate(args)
        code = _operate(args, record)
    except KeyboardInterrupt as error:
        record.update(outcome="unverified", reason="operational_observer_interrupted",
                      outcome_unknown=bool(getattr(error, "operator_outcome_unknown", False)))
        code = 130
    except OperationalUnverified as error:
        record.update(outcome="unverified", reason=error.reason)
        code = 5
    except OperationalRefused as error:
        record.update(outcome="refused", reason=error.reason)
        code = 2
    except Exception as error:
        unknown = bool(getattr(error, "outcome_unknown", False) or
                       getattr(error, "_native_close_outcome_unknown", False) or
                       getattr(error, "__notes__", ()) or "result" in record)
        record.update(outcome="unverified" if unknown else "unavailable", reason=_reason(error))
        code = 5 if unknown else 4
    print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
    return code


def main(argv=None):
    return dispatch(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
