#!/usr/bin/env python3
"""CLI for the Resource Sentinel coordinator."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.coordinator import Coordinator, ResourceRequest
from sentinel.exemptions import Exemptions, process_chain


def load_json(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except Exception:
        return {}


def load_request(args) -> dict:
    if getattr(args, "request_b64", ""):
        raw = base64.b64decode(args.request_b64).decode("utf-8")
        return json.loads(raw)
    return json.loads(args.request_json)


def cancel_exact_queue_request(
    coord: Coordinator,
    request_key: str,
    *,
    owner_pid: int | None = None,
) -> int:
    """Cancel one known queue row; an absent/ambiguous key is always a no-op."""
    if not request_key:
        return 0
    if owner_pid is None:
        matches = [
            row for row in coord.snapshot().get("queue", [])
            if row.get("request_key") == request_key
        ]
        if len(matches) != 1:
            return 0
        owner_pid = int(matches[0]["owner_pid"])
    return coord.cancel_queued(owner_pid=owner_pid, request_key=request_key)


def remaining_sleep(deadline: float) -> float:
    return min(5.0, max(0.0, deadline - time.time()))


def main() -> int:
    default_data = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".resource-sentinel"
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir")
    sub = parser.add_subparsers(dest="command", required=True)

    admit = sub.add_parser("admit")
    admit_request = admit.add_mutually_exclusive_group(required=True)
    admit_request.add_argument("--request-json")
    admit_request.add_argument("--request-b64")
    admit.add_argument("--status-file")
    admit.add_argument("--config-file")

    release = sub.add_parser("release")
    release.add_argument("--owner-pid", type=int, required=True)
    release.add_argument("--tool-use-id", default="")
    release.add_argument("--command-text", default="")
    release.add_argument("--outcome", default="success")

    wait = sub.add_parser("wait")
    wait_request = wait.add_mutually_exclusive_group(required=True)
    wait_request.add_argument("--request-json")
    wait_request.add_argument("--request-b64")
    wait.add_argument("--status-file", required=True)
    wait.add_argument("--config-file")
    wait.add_argument("--timeout-sec", type=float, default=480)

    wait_existing = sub.add_parser("wait-existing")
    wait_existing.add_argument("--request-key", default="")
    wait_existing.add_argument("--owner-pid", type=int)
    wait_existing.add_argument("--status-file", required=True)
    wait_existing.add_argument("--config-file")
    wait_existing.add_argument("--timeout-sec", type=float, default=480)

    cleanup = sub.add_parser("cleanup")
    cleanup.add_argument("--config-file")

    cancel = sub.add_parser("cancel", help="Abandon one queued request owned by this caller or its verified ancestor")
    cancel.add_argument("--request-key", required=True)
    cancel.add_argument("--owner-pid", type=int, required=True)

    sample = sub.add_parser("sample")
    sample.add_argument("--status-file", required=True)

    grant = sub.add_parser("exemption-grant", help="Record explicit user authorization for one process tree")
    grant.add_argument("--pid", type=int, required=True)
    grant.add_argument("--minutes", type=float, default=60)
    grant.add_argument("--reason", required=True)
    grant.add_argument("--user-authorized", action="store_true", required=True)
    revoke = sub.add_parser("exemption-revoke")
    revoke.add_argument("--id", required=True)
    sub.add_parser("exemption-list")
    sub.add_parser("exemption-resolve")
    check = sub.add_parser("exemption-check")
    check.add_argument("--pid", type=int, required=True)
    sub.add_parser("snapshot")
    adaptive_query = sub.add_parser("adaptive-query", help="Read bounded lifecycle diagnostics without migrations or control writes")
    adaptive_query.add_argument("--execution-id")
    adaptive_query.add_argument("--reservation-id")
    adaptive_query.add_argument("--limit", type=int, default=20)
    from sentinel.adaptive.operational_cli import COMMANDS, dispatch, register_commands
    register_commands(sub)
    args = parser.parse_args()
    if args.command in COMMANDS:
        return dispatch(args)
    if args.data_dir is None:
        args.data_dir = str(default_data)
    if args.command == "cancel":
        from sentinel.queue_cancellation import cancel_for_caller
        result = cancel_for_caller(args.data_dir, request_key=args.request_key, owner_pid=args.owner_pid)
        print(json.dumps(result, separators=(",", ":")))
        return 0 if result["ok"] else 2
    if args.command == "adaptive-query":
        from sentinel.adaptive.query import query_adaptive
        try:
            result = query_adaptive(Path(args.data_dir) / "sentinel.db", execution_id=args.execution_id,
                                    reservation_id=args.reservation_id, limit=args.limit)
        except ValueError as exc:
            parser.error(str(exc))
        print(json.dumps(result, separators=(",", ":")))
        return 0 if result["available"] else 2
    if args.command.startswith("exemption-"):
        exemptions = Exemptions(args.data_dir)
        if args.command == "exemption-grant":
            try:
                result = exemptions.grant(args.pid, minutes=args.minutes, reason=args.reason, user_authorized=args.user_authorized)
            except ValueError as exc:
                parser.error(str(exc))
        elif args.command == "exemption-revoke":
            result = {"revoked": exemptions.revoke(args.id)}
        elif args.command == "exemption-resolve":
            result = exemptions.resolve()
        elif args.command == "exemption-check":
            chain = process_chain(args.pid)
            result = exemptions.match(*chain[0]) if chain else None
        else:
            result = exemptions.rows(include_inactive=True)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    coord = Coordinator(args.data_dir)

    if args.command == "admit":
        raw = load_request(args)
        status_path = args.status_file or str(Path(args.data_dir) / "status.json")
        config_path = args.config_file or str(Path(args.data_dir) / "config.json")
        result = coord.admit(ResourceRequest(**raw), load_json(status_path), config=load_json(config_path))
        print(json.dumps(result, separators=(",", ":")))
        return 0 if result["allowed"] else 2
    if args.command == "release":
        count = coord.release(
            owner_pid=args.owner_pid, tool_use_id=args.tool_use_id,
            command=args.command_text, outcome=args.outcome,
        )
        print(json.dumps({"released": count}))
        return 0
    if args.command == "wait":
        request = ResourceRequest(**load_request(args))
        deadline = time.time() + args.timeout_sec
        acquired = False
        cancelled = 0
        try:
            while time.time() < deadline:
                result = coord.admit(request, load_json(args.status_file), config=load_json(args.config_file) if args.config_file else {})
                if result["allowed"]:
                    acquired = True
                    print(json.dumps(result, separators=(",", ":")))
                    return 0
                time.sleep(remaining_sleep(deadline))
        finally:
            if not acquired:
                cancelled = cancel_exact_queue_request(
                    coord, request.request_key, owner_pid=request.owner_pid,
                )
        print(json.dumps({
            "allowed": False, "reason": "timeout", "request_key": request.request_key,
            "cancelled": cancelled,
        }, separators=(",", ":")))
        return 1
    if args.command == "wait-existing":
        request_key = args.request_key
        if not request_key and args.owner_pid:
            queued = coord.queued_for_owner(args.owner_pid)
            if queued:
                request_key = queued[0]["request_key"]
        if not request_key:
            print(json.dumps({"allowed": False, "reason": "request_missing"}))
            return 1
        deadline = time.time() + args.timeout_sec
        acquired = False
        cancelled = 0
        missing_result = None
        try:
            while time.time() < deadline:
                result = coord.retry_queued(
                    request_key, load_json(args.status_file),
                    config=load_json(args.config_file) if args.config_file else {},
                )
                if result["allowed"]:
                    acquired = True
                    print(json.dumps(result, separators=(",", ":")))
                    return 0
                if result.get("reason") == "request_missing":
                    missing_result = result
                    break
                time.sleep(remaining_sleep(deadline))
        finally:
            if not acquired:
                cancelled = cancel_exact_queue_request(
                    coord, request_key, owner_pid=args.owner_pid,
                )
        if missing_result is not None:
            print(json.dumps(missing_result, separators=(",", ":")))
            return 1
        print(json.dumps({
            "allowed": False, "reason": "timeout", "request_key": request_key,
            "cancelled": cancelled,
        }, separators=(",", ":")))
        return 1
    if args.command == "cleanup":
        removed = coord.cleanup(config=load_json(args.config_file) if args.config_file else {})
        print(json.dumps({"removed": removed}))
        return 0
    if args.command == "sample":
        coord.record_sample(load_json(args.status_file))
        print(json.dumps({"sampled": True}))
        return 0
    if args.command == "snapshot":
        print(json.dumps(coord.snapshot(), ensure_ascii=False, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
