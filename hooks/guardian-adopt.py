#!/usr/bin/env python3
"""Hook for any agent CLI: put the CLI that runs this hook into its Guardian session job.

  python -I <repo>/hooks/guardian-adopt.py <provider> [--instance main] [--cls normal] [--context] [--stdout TEXT]

Wire it to the CLI's session-start hook (docs/guardian.md lists the place for each CLI). It walks up from its own
process to the CLI (claude.exe, codex.exe, grok.exe, agy.exe, or the node.exe running gemini or cursor-agent) and asks
the daemon to adopt it. Children the CLI starts afterwards inherit the job.

It never blocks the CLI or changes its decisions: stdout stays empty unless --stdout gives the exact text a CLI
expects, the exit code is always 0, and the outcome goes to ~/.resource-sentinel/guardian/<instance>/adopt.log.
GUARDIAN_ADOPT=0 in the environment turns it off.

--context also tells the model what the session may use (CPU cap, priority, free RAM, how to queue a long command),
in the output shape the CLI reads: Claude Code and Codex take SessionStart additionalContext, Cursor takes
sessionStart additional_context. For the other CLIs it prints nothing more. A CLI that a desktop app runs is refused
adoption, but when the daemon already holds it in a desktop job the hook still gives the context.
"""
import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SESSION_KEYS = ("session_id", "sessionId", "conversation_id", "conversationId", "thread_id", "threadId")


def read_payload(limit=1 << 20, wait=2.0):
    """The hook's JSON from stdin, or {}. A CLI that leaves stdin open must not hang the hook."""
    if sys.stdin is None or sys.stdin.isatty():
        return {}
    box = []
    t = threading.Thread(target=lambda: box.append(sys.stdin.buffer.read(limit)), daemon=True)
    t.start()
    t.join(wait)
    try:
        payload = json.loads(box[0]) if box and box[0].strip() else {}
    except ValueError:
        return {}
    return payload if isinstance(payload, dict) else {}


def session_name(provider, payload, cli_pid):
    """The launcher's session when the CLI was started through gagent/srun, else the CLI's own session id."""
    if os.environ.get("GUARDIAN_PROVIDER") == provider and os.environ.get("GUARDIAN_SESSION"):
        return os.environ["GUARDIAN_SESSION"]
    for k in SESSION_KEYS:
        v = payload.get(k)
        if isinstance(v, str) and v.strip():
            # the tail: Codex and Grok ids are UUIDv7, whose head is a timestamp shared by sessions a minute apart
            return "".join(ch for ch in v if ch.isalnum())[-8:] or f"pid{cli_pid}"
    return f"pid{cli_pid}"


def log(instance, row):
    from sentinel.guardian.client import home_dir
    path = home_dir(instance) / "adopt.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(row, default=str) + "\n")
    except OSError:
        pass


def context(provider, row, instance):
    """--context: the budget of the session holding the CLI, or the hook itself when no CLI was adopted, in the
    shape the CLI's hook output takes; "" when there is none."""
    try:
        from sentinel.guardian.client import budget_text, hook_output, whereis
        where = whereis(row.get("cli_pid") or os.getpid(), instance, timeout=3.0)
        row["context"] = budget_text(where, long=True)
        return hook_output(provider, row.get("event") or "SessionStart", row["context"])
    except Exception as e:  # never break the CLI over the context
        row["context_error"] = f"{e.__class__.__name__}: {e}"
        return ""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("provider")
    ap.add_argument("--instance", default="main")
    ap.add_argument("--cls", default="normal")
    ap.add_argument("--stdout", default="", help="exact text to print for CLIs that parse hook output")
    ap.add_argument("--context", action="store_true", help="give the model the session's Guardian budget")
    a, _ = ap.parse_known_args(argv)
    instance = os.environ.get("GUARDIAN_INSTANCE") or a.instance
    row = {"t": time.strftime("%Y-%m-%d %H:%M:%S"), "provider": a.provider, "hook_pid": os.getpid()}
    try:
        if os.environ.get("GUARDIAN_ADOPT") == "0":
            row["state"] = "off"
            return
        payload = read_payload()
        row["event"] = payload.get("hook_event_name") or payload.get("hookEventName") or payload.get("event")
        from sentinel.guardian import providers as PV
        from sentinel.guardian import winjob as wj
        from sentinel.guardian.client import adopt
        table = wj.process_table()
        cli, why = PV.find_cli(a.provider, os.getpid(), table, wj.image_path)
        if cli is None:
            row.update(state="no_cli", reason=why)
            return
        chain = [os.getpid()]
        for p in wj.ancestors(os.getpid(), table):
            if p == cli:
                break
            chain.append(p)
        session = session_name(a.provider, payload, cli)
        row.update(cli_pid=cli, image=table[cli][1], session=session)
        row.update(adopt(cli, a.provider, session, a.cls, instance, "hook", skip=chain))
    except Exception as e:  # a hook must never break the CLI that runs it
        row.update(state="error", reason=f"{e.__class__.__name__}: {e}")
    finally:
        out = a.stdout
        if a.context and row.get("state") != "off":
            out = context(a.provider, row, instance) or out
        log(instance, row)
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:  # a bad argument list: exit 2 would read as "block" to Claude Code
        pass
    sys.exit(0)
