#!/usr/bin/env python3
"""Install the Guardian adopt hook into an agent CLI's user-level hook config, so every new session of that CLI joins
Guardian on start. Opt-in and for Stan to run himself: without --apply it only prints what it would change.

  python -I scripts/guardian-install-hooks.py [claude codex cursor grok antigravity] [--instance main] [--remove]
                                              [--apply]

Claude Code and Cursor Agent put themselves in a job of their own at start; the daemon adopts them into a job nested
under it. Gemini CLI is left out, see NOT_SUPPORTED. The output names only the hook event that changes, never the rest
of the file (~/.claude/settings.json can hold secrets in env), and shows other tools' hooks in that event masked.
--apply copies a changed file to <file>.bak-guardian-<time> before writing it. --remove takes out only entries that
run guardian-adopt.py.
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
    "gemini": "Gemini CLI 0.63 has hooks, but this installer leaves ~/.gemini/settings.json alone (it holds other "
              "tools' hooks), and Google refuses this machine's sign-in; use the PATH wrapper "
              "(guardian-install-shims.py) or gagent gemini",
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


def set_hook(data, event, keep, entry):
    """Replace our entries in data["hooks"][event] with entry (None: only take ours out). keep filters ours out of
    the event's list. Every other key and entry stays where it was; an event left empty is dropped, and so is a hooks
    object left empty, unless it was empty before."""
    was_empty = data.get("hooks") == {}
    hooks = data.setdefault("hooks", {})
    entries = keep(hooks.get(event, []))
    if entry is not None:
        entries.append(entry)
    if entries:
        hooks[event] = entries
    else:
        hooks.pop(event, None)
    if not hooks and not was_empty:
        data.pop("hooks")
    return data


def plan_claude(instance, remove):
    # Claude Code runs hook commands through a POSIX shell (Git Bash) here, hence forward slashes.
    path = HOME / ".claude" / "settings.json"
    if remove and not path.exists():
        return path, None, ""
    entry = None if remove else {"matcher": "startup|resume", "hooks": [
        {"type": "command", "command": command("claude", instance, False), "timeout": 30}]}
    data = set_hook(read_json(path), "SessionStart", without_ours, entry)
    note = ("every new or resumed claude session joins Guardian. The Claude app's Code tab reads this file too: "
            "there the hook finds the Claude app among its parents and only logs a refusal, and the daemon puts "
            "those sessions in desktop jobs instead. VS Code is not on the desktop-app list, so a session of VS "
            "Code's Claude extension is adopted like a terminal one when its CLI is claude.exe. A claude under "
            "Cursor's editor (its terminal or an extension) is refused, since Cursor is on the list.")
    return path, data, note


def without_ours_flat(entries):
    """Cursor's flat entries ({"command", "timeout"}) without the ones that run guardian-adopt.py."""
    return [e for e in entries if MARK not in str(e.get("command", ""))]


def plan_cursor(instance, remove):
    path = HOME / ".cursor" / "hooks.json"
    if remove and not path.exists():
        return path, None, ""
    data = read_json(path)
    if not remove:
        data.setdefault("version", 1)
    entry = None if remove else {"command": command("cursor", instance, False), "timeout": 30}
    data = set_hook(data, "sessionStart", without_ours_flat, entry)
    note = ("every new cursor-agent session joins Guardian. Cursor's editor reads this file too: there the hook "
            "finds Cursor among its parents and only logs a refusal. The daemon has no desktop job for Cursor, so "
            "the editor's agent sessions stay outside Guardian, and so does a cursor-agent started in its terminal.")
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


PLANS = {"claude": plan_claude, "codex": plan_codex, "cursor": plan_cursor, "grok": plan_grok,
         "antigravity": plan_antigravity}


GONE = object()  # a key one side of changes() does not have
OTHER = "(other hook, not shown)"


def shown(entry):
    """A list entry as changes() prints it: a hook whose command runs guardian-adopt.py as it is, an entry holding a
    "hooks" list with that list shown the same way, and anything else as OTHER, never with its values. Another
    tool's hook can carry a secret in its command, url or headers."""
    if isinstance(entry, dict) and MARK in str(entry.get("command", "")):
        return entry
    if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
        return dict(entry, hooks=[shown(h) for h in entry["hooks"]])
    return OTHER


def changes(old, new, where=""):
    """Lines that show how new differs from old, naming only what changed: dicts are walked key by key and lists
    show the entries that go (-) and come (+), masked by shown(). A value that stays the same is never printed, so
    a dry run of ~/.claude/settings.json shows the SessionStart hooks and nothing of its env block."""
    if isinstance(old, dict) or isinstance(new, dict):
        old = old if isinstance(old, dict) else {}
        new = new if isinstance(new, dict) else {}
        out = []
        for k in list(old) + [k for k in new if k not in old]:
            if k not in new or k not in old or old[k] != new[k]:
                out += changes(old.get(k, GONE), new.get(k, GONE), f"{where}.{k}" if where else k)
        return out
    if isinstance(old, list) or isinstance(new, list):
        old = old if isinstance(old, list) else []
        new = new if isinstance(new, list) else []
        lines = [f"  - {json.dumps(shown(e))}" for e in old if e not in new] + \
                [f"  + {json.dumps(shown(e))}" for e in new if e not in old]
        return [f"{where}:"] + (lines or ["  (same entries, new order)"])
    if old is GONE:
        return [f"{where}: + {json.dumps(new)}"]
    if new is GONE:
        return [f"{where}: - {json.dumps(old)}"]
    return [f"{where}: {json.dumps(old)} -> {json.dumps(new)}"]


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
        new = None if data is None else json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        if new is not None and old is not None and "\r\n" in old:
            new = new.replace("\n", "\r\n")  # keep the file's own line endings; a new file gets LF
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
        for line in changes(json.loads(old or "{}") if old is not None else {}, {} if data is None else data):
            print("  " + line)
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
            path.write_bytes(new.encode("utf-8"))  # no BOM: codex 0.156 cannot parse a hooks.json that has one
        if note and not a.remove:
            print(f"  {note}")
    if not a.apply:
        print("\nNothing written. Add --apply to write it. The hook adopts sessions only while the Guardian daemon "
              f"for instance {a.instance} runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
