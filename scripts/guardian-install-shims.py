#!/usr/bin/env python3
"""Put Guardian wrappers for the agent CLIs ahead of the real ones on the user Path, so typing claude, codex, gemini,
cursor-agent or grok in a new terminal starts that CLI inside a Guardian session job (scripts/guardian-shim.py).
Opt-in and for Stan to run himself: without --apply it only prints what it would change.

  python -I scripts/guardian-install-shims.py [--remove] [--apply]

--apply writes, for each installed CLI, a .ps1 (PowerShell, when its execution policy runs local scripts), a .cmd
(cmd, and PowerShell otherwise) and an extensionless sh script (Git Bash) into ~/.resource-sentinel/guardian/shims,
puts that folder first on the user Path (HKCU\\Environment), saves the old Path value to path-backup-<time>.txt
beside the folder, and tells running programs the environment changed. Terminals that were already open keep their
old PATH. --remove takes the folder off the user Path and deletes only wrapper files that carry the guardian-shim
note. Run it from the main checkout: the wrappers call the guardian-shim.py that sits next to this script, with the
Python that runs this script.
"""
import argparse
import ctypes
import os
import subprocess
import sys
import time
import winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import providers as PV
from sentinel.guardian.client import shim_dir

SHIM = ROOT / "scripts" / "guardian-shim.py"
MARK = PV.SHIM_MARK.decode()
USER_ENV = (winreg.HKEY_CURRENT_USER, "Environment")
SYSTEM_ENV = (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")


def norm(d):
    d = os.path.expandvars(d.strip().strip('"'))
    return os.path.normcase(os.path.normpath(d)) if d else ""


def with_dir(value, d):
    """The Path value with d first; every other entry stays as it was, in order."""
    return ";".join([str(d)] + [x for x in (value.split(";") if value else []) if norm(x) != norm(str(d))])


def without_dir(value, d):
    return ";".join(x for x in (value.split(";") if value else []) if norm(x) != norm(str(d)))


def wrappers(provider, python, shim, ps1=True):
    """{file name: text} for one CLI. The .cmd keeps CRLF for cmd.exe, the sh script LF for Git Bash. PowerShell
    prefers the .ps1 to the .cmd in the same folder, and it passes arguments as they are, where a .cmd hands them
    to cmd.exe to read again (& | % ^) and asks "Terminate batch job (Y/N)?" after Ctrl+C."""
    command = PV.PROVIDERS[provider].command
    note = f"{MARK}: starts {command} inside a Guardian session (scripts/guardian-install-shims.py --remove)"
    cmd = f'@echo off\r\nrem {note}\r\n"{python}" -I "{shim}" {provider} %*\r\nexit /b %ERRORLEVEL%\r\n'
    sh = f'#!/bin/sh\n# {note}\nexec "{python.as_posix()}" -I "{shim.as_posix()}" {provider} "$@"\n'
    run = "& '{}' -I '{}' {} $args".format(str(python).replace("'", "''"), str(shim).replace("'", "''"), provider)
    # UTF-8 with a byte order mark, which Windows PowerShell 5.1 needs to read a non-ASCII path right
    ps = (f"﻿# {note}\r\nif ($MyInvocation.ExpectingInput) {{\r\n  $input | {run}\r\n}} else {{\r\n  {run}\r\n}}"
          "\r\nexit $LASTEXITCODE\r\n")
    return {f"{command}.cmd": cmd, command: sh, **({f"{command}.ps1": ps} if ps1 else {})}


def file_names():
    return {f"{p.command}{x}" for p in PV.PROVIDERS.values() for x in ("", ".cmd", ".ps1")}


def scripts_allowed():
    """Whether PowerShell runs a local .ps1 (policy RemoteSigned, Unrestricted or Bypass). Without that the .ps1
    wrapper would only fail, and PowerShell uses the .cmd."""
    try:
        r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.stdout.strip() in ("RemoteSigned", "Unrestricted", "Bypass")


def read_path(where):
    try:
        with winreg.OpenKey(*where) as k:
            return winreg.QueryValueEx(k, "Path")
    except FileNotFoundError:
        return "", winreg.REG_EXPAND_SZ


def broadcast():
    """WM_SETTINGCHANGE "Environment", so Explorer (and what it starts next) reads the new Path."""
    result = ctypes.c_size_t()
    ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x001A, 0, ctypes.c_wchar_p("Environment"), 0x0002, 5000,
                                             ctypes.byref(result))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--remove", action="store_true", help="take the wrappers and the Path entry out instead")
    ap.add_argument("--apply", action="store_true", help="write the change (default: print it only)")
    a = ap.parse_args(argv)
    d, python = shim_dir(), Path(sys.executable).resolve()
    old_path, kind = read_path(USER_ENV)
    new_path = without_dir(old_path, d) if a.remove else with_dir(old_path, d)
    files = []  # (file, text); text None means delete
    if a.remove:
        for f in sorted(d.iterdir()) if d.is_dir() else []:
            if f.is_file() and f.name.lower() in file_names() and PV.is_shim(f):
                files.append((f, None))
            elif f.is_file():
                print(f"{f.name}: not a {MARK} wrapper, left alone")
    else:
        if "\\.claude\\worktrees\\" in str(ROOT).lower() or "\\windowsapps\\" in str(python).lower():
            print(f"warning: the wrappers would call {python} and {SHIM}; run this from the main checkout with a "
                  "regular python.exe so they keep working")
        ps1 = scripts_allowed()
        if not ps1:
            print("PowerShell does not run local scripts here (Get-ExecutionPolicy), so no .ps1 wrappers; PowerShell "
                  "uses the .cmd ones")
        system_path = os.path.expandvars(read_path(SYSTEM_ENV)[0])
        for name, p in PV.PROVIDERS.items():
            real = PV.real_cli(p.command)
            if not real:
                print(f"{p.command}: not installed, no wrapper")
                continue
            first = PV.real_cli(p.command, system_path)
            if first:
                print(f"{p.command}: the system Path, which Windows puts before the user Path, has {first}; "
                      "the wrapper would never be found first")
            for fname, text in wrappers(name, python, SHIM, ps1).items():
                f = d / fname
                if f.exists() and not PV.is_shim(f):
                    print(f"{f}: exists without the {MARK} mark, left alone")
                elif not (f.exists() and f.read_bytes() == text.encode()):
                    files.append((f, text))
            print(f"{p.command}: {real} will start through {d / p.command}{'.ps1 / .cmd' if ps1 else '.cmd'}")
    for f, text in files:
        verb = "delete" if text is None else ("update" if f.exists() else "write")
        print(f"{'would ' if not a.apply else ''}{verb} {f}")
    path_change = new_path != old_path
    if path_change:
        print(f"{'would ' if not a.apply else ''}{'take' if a.remove else 'put'} {d} "
              f"{'off' if a.remove else 'first on'} the user Path")
    if not files and not path_change:
        print("nothing to change")
        return 0
    if not a.apply:
        print("\nNothing written. Add --apply to write it. Wrapped CLIs join Guardian only while the daemon runs "
              "(instance main, or GUARDIAN_SHIM_INSTANCE); otherwise they start as before with a one-line notice.")
        return 0
    if path_change:
        backup = d.parent / f"path-backup-{time.strftime('%Y%m%d-%H%M%S')}.txt"
        backup.parent.mkdir(parents=True, exist_ok=True)
        backup.write_text(f"HKCU\\Environment Path, registry type {kind}\n{old_path}\n", encoding="utf-8")
        print(f"old user Path saved to {backup}")
    if a.remove and path_change:  # off the Path first, so nothing points at a half-removed folder
        with winreg.OpenKey(USER_ENV[0], USER_ENV[1], 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Path", 0, kind, new_path)
    for f, text in files:
        if text is None:
            f.unlink()
        else:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(text.encode())
    if not a.remove and path_change:  # wrappers first, then the Path entry that finds them
        with winreg.OpenKey(USER_ENV[0], USER_ENV[1], 0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "Path", 0, kind, new_path)
    if path_change:
        broadcast()
        print("Done. Open a new terminal; if a new tab still runs the real CLI, close Windows Terminal completely and "
              "open it again. Check with: where claude")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
