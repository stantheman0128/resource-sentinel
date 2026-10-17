#!/usr/bin/env python3
"""Prompt hook for Claude Code and Codex: one line on the session's Guardian budget before each prompt.

  python -I <repo>/hooks/guardian-status.py <provider> [--instance main]

Wire it to UserPromptSubmit (scripts/guardian-install-hooks.py --status does). The line names the session, its CPU
cap, the free RAM, and whether new srun commands wait, and goes to the model as additionalContext. The hook asks the
daemon about its own process, which sits in the CLI's session job once the CLI joined Guardian.

It never holds up the prompt: outside Guardian, with the daemon down or slow to answer, stdout stays empty, and the
exit code is always 0. GUARDIAN_STATUS=0 in the environment turns it off.
"""
import argparse
import importlib.util
import os
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def read_payload():
    """guardian-adopt.py's stdin reader: a CLI that leaves stdin open must not hang the hook."""
    spec = importlib.util.spec_from_file_location("guardian_adopt", Path(__file__).with_name("guardian-adopt.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.read_payload(wait=1.0)


def status(provider, instance, payload, wait=2.0):
    from sentinel.guardian.client import budget_text, hook_output, whereis
    box = []
    # whereis has its own timeouts, but the stdlib waits up to 20 s for a busy pipe before the handshake starts
    t = threading.Thread(target=lambda: box.append(whereis(os.getpid(), instance, timeout=wait)), daemon=True)
    t.start()
    t.join(wait + 0.5)
    event = payload.get("hook_event_name") or "UserPromptSubmit"
    return hook_output(provider, event, budget_text(box[0] if box else None))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("provider")
    ap.add_argument("--instance", default="main")
    a, _ = ap.parse_known_args(argv)
    if os.environ.get("GUARDIAN_STATUS") == "0":
        return
    try:
        out = status(a.provider, os.environ.get("GUARDIAN_INSTANCE") or a.instance, read_payload())
    except Exception:  # a hook must never break the prompt it runs for
        return
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:  # a bad argument list: exit 2 would block the prompt in Claude Code
        pass
    os._exit(0)  # do not wait on a whereis thread still stuck on a busy pipe
