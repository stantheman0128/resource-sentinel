#!/usr/bin/env python3
"""Run an agent CLI in this console, inside a Guardian session job from its first instruction.

  python -I scripts/guardian-shim.py [--instance main] [--session NAME] [--cls normal] [--verbose] <provider> [args]

scripts/guardian-install-shims.py puts small claude / codex / gemini / cursor-agent / grok wrappers ahead of the
real CLIs on PATH that call this, so typing `claude` starts Claude Code under Guardian. The CLI is created
suspended, the daemon assigns it to root > provider > session, and only then does it run. That also covers the
CLIs that put themselves in a job of their own at start (Claude Code, Cursor Agent), which a hook cannot adopt.
Every child the CLI starts inherits the job, since Guardian's jobs never allow breakaway.

Everything after the provider goes to the CLI untouched, a leading "--" included. The CLI runs unchanged, without a
word, when this process is already inside Guardian (the CLI inherits that job), when a desktop app started it
(Guardian leaves the apps alone), or when GUARDIAN_SHIM=off. When Guardian is not running, will not take the CLI
or does not answer within 15 s, the CLI runs anyway and one [guardian] line on stderr says why.
GUARDIAN_SHIM_INSTANCE picks the instance (default main); GUARDIAN_SHIM_VERBOSE=1 also says where the CLI runs.
"""
import argparse
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import providers as PV
from sentinel.guardian import winjob as wj
from sentinel.guardian.client import CLASSES, adopt, notice, shim_dir

ADOPT_LIMIT = 15.0  # adopt() waits up to 10 s for the answer; connecting has no limit of its own
TAKES_VALUE = ("--instance", "--session", "--cls")
CMD = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "cmd.exe")
PLAIN = set("#$*+-./:?@\\_")  # the ASCII symbols cmd.exe leaves alone outside quotes


def split_argv(argv):
    """(shim options, provider, CLI args): the first word that names a provider ends the shim's own options."""
    i = 0
    while i < len(argv):
        if argv[i] in PV.PROVIDERS:
            return argv[:i], argv[i], argv[i + 1:]
        i += 2 if argv[i] in TAKES_VALUE else 1
    return argv, None, []


def bat_arg(x):
    """One argument for a batch file, written the way Rust's standard library does it (make_bat_command_line):
    quoted unless plain, a double quote doubled, and every % turned into %%cd:~,% so cmd.exe expands no %NAME%."""
    if "\r" in x or "\n" in x:
        raise ValueError("cmd.exe cannot pass an argument that holds a line break")
    quote = not x or x.endswith("\\") or any((c.isascii() and not c.isalnum() and c not in PLAIN) or not c.isprintable()
                                             for c in x)
    out, slashes = [], 0
    for c in x:
        if c == "\\":
            slashes += 1
        else:
            if c == '"':
                out.append("\\" * slashes + '"')
            elif c == "%":
                out.append("%%cd:~,")
            slashes = 0
        out.append(c)
    if quote:
        out.append("\\" * slashes)
    return f'"{"".join(out)}"' if quote else "".join(out)


def command_line(argv):
    """(executable, args) for Popen. A .cmd or .bat CLI (an npm install) runs through cmd.exe, which reads the
    command line again, so each argument is written for cmd.exe; anything else gets argv as it is."""
    script = argv[0]
    if Path(script).suffix.lower() not in (".cmd", ".bat"):
        return None, argv
    if '"' in script or script.endswith("\\"):
        raise ValueError(f"cmd.exe cannot run {script}")
    line = " ".join([f'"{script}"'] + [bat_arg(x) for x in argv[1:]])
    return CMD, f'"{CMD}" /e:ON /v:OFF /d /c "{line}"'


def why_direct(instance, table):
    """Why the CLI should run as it is, outside a new session; None means take it in."""
    if os.environ.get("GUARDIAN_SHIM", "").lower() == "off":
        return "GUARDIAN_SHIM=off"
    if wj.in_named_job(os.getpid(), f"{instance}.AllAgents"):
        return "already in a Guardian session, whose job it inherits"
    # the parent chain breaks where a process in between has exited (Git Bash's fork and exec emulation leaves
    # one above sh); the variable is still there
    if PV.app_among(os.getpid(), table, wj.image_path) or os.environ.get("CLAUDE_CODE_ENTRYPOINT") == "claude-desktop":
        return "started by a desktop app, which Guardian leaves alone"
    return None


def adopt_within(pid, provider, session, cls, instance, limit=ADOPT_LIMIT):
    """adopt() on a helper thread, so a daemon that takes the pipe but never answers cannot keep the CLI suspended."""
    box = {}

    def ask():
        try:
            box["r"] = adopt(pid, provider, session, cls, instance, via="shim")
        except Exception as e:  # the CLI must run whatever goes wrong here
            box["r"] = {"ok": False, "state": "error", "reason": f"{e.__class__.__name__}: {e}"}

    t = threading.Thread(target=ask, daemon=True)
    t.start()
    t.join(limit)
    if "r" not in box:
        return {"ok": False, "state": "timeout", "reason": f"no answer within {limit:.0f} s"}
    if not isinstance(box["r"], dict):
        return {"ok": False, "state": "error", "reason": "Guardian's answer is not one the shim can read"}
    return box["r"]


def wait(p):
    # the CLI shares this console and handles Ctrl+C itself; this process only waits for it
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    return p.wait()


def main(argv=None):
    ap = argparse.ArgumentParser(usage=__doc__.splitlines()[2].strip())
    ap.add_argument("--instance", default=os.environ.get("GUARDIAN_SHIM_INSTANCE") or "main")
    ap.add_argument("--session", help="session name (default: <provider>-<time>-<pid>)")
    ap.add_argument("--cls", choices=CLASSES, default="normal")
    ap.add_argument("--verbose", action="store_true", help="also say where the CLI runs")
    ap.add_argument("provider", choices=sorted(PV.PROVIDERS))
    opts, provider, cli_args = split_argv(sys.argv[1:] if argv is None else argv)
    a = ap.parse_args(opts + ([provider] if provider else []))
    verbose = a.verbose or os.environ.get("GUARDIAN_SHIM_VERBOSE", "").lower() not in ("", "0", "off", "no", "false")
    command = PV.PROVIDERS[a.provider].command
    exe = PV.real_cli(command)
    if not exe:
        notice(f"{command} is not on PATH, apart from Guardian wrappers (installed ones are in {shim_dir()})")
        return 127
    try:
        executable, argv = command_line([exe] + cli_args)
    except ValueError as e:
        notice(f"{command} not started: {e}")
        return 2
    why = why_direct(a.instance, wj.process_table())
    session = a.session or f"{a.provider}-{time.strftime('%H%M%S')}-{os.getpid()}"
    # the CLI's own hooks read these, so the adopt hook reports the session it already runs in
    env = dict(os.environ, GUARDIAN_PROVIDER=a.provider, GUARDIAN_SESSION=session, GUARDIAN_INSTANCE=a.instance)
    p = None
    try:
        if why is not None:
            if verbose:
                notice(f"{command} runs without a new session: {why}")
            return wait(subprocess.Popen(argv, executable=executable))
        if wj.in_job(os.getpid()):
            # another job (a terminal's, a CI runner's) holds this process; leave it if that job allows it, since
            # Windows only lets a process join a job inside its current job tree
            try:
                p = subprocess.Popen(argv, executable=executable, env=env,
                                     creationflags=wj.CREATE_SUSPENDED | wj.CREATE_BREAKAWAY_FROM_JOB)
            except OSError:
                p = None
        if p is None:
            p = subprocess.Popen(argv, executable=executable, env=env, creationflags=wj.CREATE_SUSPENDED)
    except OSError as e:
        notice(f"cannot start {exe}: {e}")
        return 127
    # from here on Ctrl+C belongs to the CLI, also while Guardian answers: this process must live to wait for it
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        r = adopt_within(p.pid, a.provider, session, a.cls, a.instance)
    finally:
        wj.resume_process_threads(p.pid)
    if not r.get("ok"):
        notice(f"{command} runs without Guardian control: {r.get('reason')}")
    elif verbose:
        notice(f"{command} runs in session {r.get('session')} ({r.get('coverage')})")
    return wait(p)


if __name__ == "__main__":
    raise SystemExit(main())
