#!/usr/bin/env python3
"""CLI for the Resource Sentinel multi-agent/cloud orchestrator."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.orchestrator import Orchestrator, TaskSpec


def read_json(value: str) -> Any:
    try:
        candidate = Path(value)
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8-sig"))
    except OSError:
        pass
    return json.loads(value)


def emit(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def main() -> int:
    default_data = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".resource-sentinel"
    parser = argparse.ArgumentParser(description="Resource Sentinel task orchestrator")
    parser.add_argument("--data-dir", default=str(default_data))
    sub = parser.add_subparsers(dest="command", required=True)

    submit = sub.add_parser("submit")
    submit.add_argument("--task", required=True, help="Task JSON object or file")
    ls = sub.add_parser("list")
    ls.add_argument("--state", action="append", default=[])
    ls.add_argument("--limit", type=int, default=100)
    show = sub.add_parser("show")
    show.add_argument("--task-id", required=True)
    tick = sub.add_parser("tick")
    tick.add_argument("--limit", type=int, default=4)
    sub.add_parser("reconcile")
    cancel = sub.add_parser("cancel")
    cancel.add_argument("--task-id", required=True)
    retry = sub.add_parser("retry")
    retry.add_argument("--task-id", required=True)
    resolve_dispatch = sub.add_parser("resolve-dispatch")
    resolve_dispatch.add_argument("--task-id", required=True)
    resolution = resolve_dispatch.add_mutually_exclusive_group(required=True)
    resolution.add_argument("--external-job-id", default="")
    resolution.add_argument("--confirmed-not-submitted", action="store_true")
    manual = sub.add_parser("complete-manual")
    manual.add_argument("--task-id", required=True)
    manual.add_argument("--success", action="store_true")
    manual.add_argument("--result", default="{}")
    manual.add_argument("--error", default="")
    session = sub.add_parser("session-heartbeat")
    session.add_argument("--session-id", required=True)
    session.add_argument("--agent-kind", required=True)
    session.add_argument("--owner-pid", type=int, required=True)
    session.add_argument("--owner-started", type=float, default=0)
    session.add_argument("--repo", default="")
    session.add_argument("--state", default="IDLE")
    session.add_argument("--current-task-id", default="")
    session.add_argument("--control-adapter", default="pull")
    session.add_argument("--bound-worker-id", default="local-windows")
    session.add_argument("--max-inflight", type=int, default=1)
    session.add_argument("--ttl-sec", type=int, default=600)
    pulse = sub.add_parser("session-pulse")
    pulse.add_argument("--session-id", required=True)
    pulse.add_argument("--state")
    pulse.add_argument("--current-task-id")
    pulse.add_argument("--ttl-sec", type=int, default=600)
    pull = sub.add_parser("session-pull")
    pull.add_argument("--session-id", required=True)
    session_done = sub.add_parser("session-complete")
    session_done.add_argument("--session-id", required=True)
    session_done.add_argument("--task-id", required=True)
    session_done.add_argument("--success", action="store_true")
    session_done.add_argument("--result", default="{}")
    session_done.add_argument("--error", default="")
    close = sub.add_parser("session-close")
    close.add_argument("--session-id", required=True)
    sync_sessions = sub.add_parser("sessions-sync")
    sync_sessions.add_argument("--sessions", required=True, help="Session JSON array or file")
    sub.add_parser("sessions")
    sub.add_parser("profiles")
    sub.add_parser("snapshot")
    args = parser.parse_args()

    orchestrator = Orchestrator(args.data_dir)
    if args.command == "submit":
        raw = read_json(args.task)
        for key in (
            "path_scopes", "allowed_trust_domains", "allowed_worker_ids",
            "allowed_agent_kinds", "depends_on",
        ):
            if isinstance(raw.get(key), list):
                raw[key] = tuple(raw[key])
        result = orchestrator.submit_task(TaskSpec(**raw))
    elif args.command == "list":
        result = orchestrator.list_tasks(states=tuple(s.upper() for s in args.state), limit=args.limit)
    elif args.command == "show":
        result = orchestrator.get_task(args.task_id) or {"error": "task_missing"}
    elif args.command == "tick":
        result = orchestrator.tick(limit=args.limit)
    elif args.command == "reconcile":
        result = orchestrator.reconcile()
    elif args.command == "cancel":
        result = orchestrator.cancel(args.task_id)
    elif args.command == "retry":
        result = orchestrator.retry(args.task_id)
    elif args.command == "resolve-dispatch":
        result = orchestrator.resolve_dispatch(
            args.task_id, external_job_id=args.external_job_id,
            confirmed_not_submitted=args.confirmed_not_submitted,
        )
    elif args.command == "complete-manual":
        result = orchestrator.complete_manual(
            args.task_id, success=args.success, result=read_json(args.result), error=args.error
        )
    elif args.command == "session-heartbeat":
        result = orchestrator.register_session(
            args.session_id, agent_kind=args.agent_kind, owner_pid=args.owner_pid,
            owner_started=args.owner_started, repo=args.repo, state=args.state,
            current_task_id=args.current_task_id, control_adapter=args.control_adapter,
            bound_worker_id=args.bound_worker_id, max_inflight=args.max_inflight,
            ttl_sec=args.ttl_sec,
        )
    elif args.command == "session-pulse":
        result = orchestrator.heartbeat_session(
            args.session_id, state=args.state, current_task_id=args.current_task_id,
            ttl_sec=args.ttl_sec,
        )
    elif args.command == "session-pull":
        result = orchestrator.session_pull(args.session_id)
    elif args.command == "session-complete":
        result = orchestrator.session_complete(
            args.session_id, args.task_id, success=args.success,
            result=read_json(args.result), error=args.error,
        )
    elif args.command == "session-close":
        result = orchestrator.close_session(args.session_id)
    elif args.command == "sessions-sync":
        raw_sessions = read_json(args.sessions)
        if not isinstance(raw_sessions, list):
            raise ValueError("sessions must be a JSON array")
        result = orchestrator.discover_sessions(raw_sessions)
    elif args.command == "sessions":
        result = orchestrator.sessions()
    elif args.command == "profiles":
        result = orchestrator.resource_profiles()
    else:
        result = orchestrator.snapshot()
    emit(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
