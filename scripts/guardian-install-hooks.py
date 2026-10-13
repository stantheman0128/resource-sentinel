#!/usr/bin/env python3
"""Install the Guardian adopt hook into an agent CLI's user-level hook config, so every new session of that CLI joins
Guardian on start. Opt-in and for Stan to run himself: without --apply it only prints what it would change.

  python -I scripts/guardian-install-hooks.py [codex grok antigravity] [--instance main] [--remove] [--apply]

Only CLIs Guardian can adopt after they start get a hook. Claude Code and Cursor Agent put themselves in a job of
their own at start, so for them the hook could only log a refusal; use guardian-install-shims.py or gagent. gemini-cli
0.1.3 has no hooks. --apply copies a changed file to <file>.bak-guardian-<time> before writing it. --remove takes
out only entries that run guardian-adopt.py.
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "guardian-adopt.py"
HOME = Path.home()
MARK = "guardian-adopt.py"

NOT_SUPPORTED = {
    "claude": "Claude Code puts itself in its own job at start, so adopting it is refused; use the PATH wrapper (guardian-install-shims.py) or gagent claude",
    "cursor": "Cursor Agent's node puts itself in its own job at start, so adopting it is refused; use the PATH wrapper (guardian-install-shims.py) or gagent cursor",
    "gemini": "gemini-cli 0.1.3 has no hooks (0.24 and later have them on by default); use the PATH wrapper or gagent gemini",
}


def command(provider, instance, backslash):
    py, hook = Path(sys.executable), HOOK
    if not backslash:
        py, hook = py.as_posix(), hook.as_posix()
    return f"{py} -I {hook} {provider} --instance {instance}"


def read_json(path):
    """A missing file is an empty config. utf-8-sig: the hooks.json found on this machine starts with a BOM."""
    return json.loads(path.read_bytes().decode("utf-8-sig") or "{}") if path.exists() else {}


def without_ours(entries):
    """SessionStart entries with every guardian-adopt.py command removed (and entries left empty dropped)."""
    out = []
    for e in entries:
        hooks = [h for h in e.get("hooks", []) if MARK not in str(h.get("command", ""))]
        if hooks:
            out.append(dict(e, hooks=hooks))
        elif not e.get("hooks"):
            out.append(e)
    return out


def plan_codex(instance, remove):
    # Codex runs hook commands with cmd /C, hence backslashes. Codex asks for trust once: open /hooks in codex.
    path = HOME / ".codex" / "hooks.json"
    data = read_json(path)
    hooks = data.setdefault("hooks", {})
    starts = without_ours(hooks.get("SessionStart", []))
    if not remove:
        starts.append({"hooks": [{"type": "command", "command": command("codex", instance, True), "timeout": 30}]})
    if starts:
        hooks["SessionStart"] = starts
    else:
        hooks.pop("SessionStart", None)
    note = ("then open /hooks in codex once and trust the Guardian hook (Codex will not run it before that). "
            "The Codex app reads this file too; the hook refuses its sessions, it never assigns the app.")
    return path, data, note


def plan_grok(instance, remove):
    # Global hooks in ~/.grok/hooks/ are trusted without a prompt. Grok runs them through pwsh or Git Bash.
    path = HOME / ".grok" / "hooks" / "guardian.json"
    if remove:
        return path, None, ""
    data = {"hooks": {"SessionStart": [{"hooks": [
        {"type": "command", "command": command("grok", instance, False), "timeout": 30}]}]}}
    note = "every new grok session joins Guardian, including ones a bot or another tool starts."
    return path, data, note


def without_ours_named(data):
    """agy's named hooks with every guardian-adopt.py command removed. Other commands stay, also in the same named
    hook; an event left empty is dropped, and so is a named hook left without events."""
    out = {}
    for name, hook in data.items():
        if not isinstance(hook, dict) or MARK not in json.dumps(hook):
            out[name] = hook
            continue
        left = {}
        for key, entries in hook.items():
            if not isinstance(entries, list):  # "enabled"
                left[key] = entries
                continue
            # SessionStart lists commands; PreToolUse and PostToolUse list {"matcher", "hooks": [commands]}
            entries = [e for e in without_ours(entries) if MARK not in str(e.get("command", ""))]
            if entries:
                left[key] = entries
        if any(isinstance(v, list) for v in left.values()):
            out[name] = left
    return out


def plan_antigravity(instance, remove):
    # agy loads named hooks from ~/.gemini/config/hooks.json and runs each command through cmd.exe. Antigravity 2.0
    # lists the same file; a hook run under the app finds the app among its parents and only logs a refusal.
    path = HOME / ".gemini" / "config" / "hooks.json"
    data = without_ours_named(read_json(path))
    if remove:
        return path, data or None, ""
    name, n = "guardian-adopt", 2
    while name in data:  # the user's own hook by that name stays
        name, n = f"guardian-adopt-{n}", n + 1
    data[name] = {"SessionStart": [
        {"type": "command", "command": command("antigravity", instance, False), "timeout": 30}]}
    note = "every new agy session joins Guardian; agy reads hooks when a session starts, so open a new one."
    return path, data, note


PLANS = {"codex": plan_codex, "grok": plan_grok, "antigravity": plan_antigravity}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*", default=sorted(PLANS))
    ap.add_argument("--instance", default="main")
    ap.add_argument("--remove", action="store_true", help="take the Guardian hook out instead")
    ap.add_argument("--apply", action="store_true", help="write the change (default: print it only)")
    a = ap.parse_args(argv)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    for name in a.providers:
        if name not in PLANS:
            print(f"{name}: not installed. {NOT_SUPPORTED.get(name, 'unknown CLI')}")
            continue
        path, data, note = PLANS[name](a.instance, a.remove)
        old = path.read_bytes().decode("utf-8-sig") if path.exists() else None
        new = None if data is None else json.dumps(data, indent=2) + "\n"
        if old is not None and new is not None and json.loads(old or "{}") == data:
            print(f"{name}: {path} already as wanted")
            continue
        if old is None and new is None:
            print(f"{name}: {path} not present, nothing to remove")
            continue
        if new is None and MARK not in old:
            print(f"{name}: {path} has no Guardian hook, left alone")
            continue
        verb = "remove" if new is None else ("write" if old is None else "update")
        print(f"{name}: would {verb} {path}" if not a.apply else f"{name}: {verb} {path}")
        if new is not None:
            print("  " + new.rstrip().replace("\n", "\n  "))
        if not a.apply:
            continue
        if old is not None:
            backup = path.with_name(f"{path.name}.bak-guardian-{stamp}")
            backup.write_bytes(path.read_bytes())
            print(f"  backup: {backup}")
        if new is None:
            path.unlink()
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(new, encoding="utf-8")  # no BOM: codex 0.156 cannot parse a hooks.json that has one
        if note and not a.remove:
            print(f"  {note}")
    if not a.apply:
        print("\nNothing written. Add --apply to write it. The hook adopts sessions only while the Guardian daemon "
              f"for instance {a.instance} runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
