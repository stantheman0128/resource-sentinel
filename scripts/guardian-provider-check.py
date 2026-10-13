#!/usr/bin/env python3
"""Check that each agent CLI runs under Guardian and that its sessions are really controlled.

  python -I scripts/guardian-provider-check.py [claude codex gemini cursor grok antigravity] [--levels version,...]

Runs against its own daemon instance (default `check`, dashboard port 8768), started here if needed, so it never
touches the instance Stan works in. Levels, per provider:
  version  `<cli> --version` started through srun: the CLI starts inside the session job (coverage enforced)
  srun     a one-shot prompt started through srun that makes the agent run guardian-whereami as a shell command;
           passes when that command reports itself inside the srun session job
  hook     the same prompt, but the CLI starts outside Guardian with this run's own hook config (no global config
           is edited); passes when guardian-adopt.py adopted the CLI and the shell command then reports a session
  shimver  `<cli> --version` started through the PATH wrapper guardian-install-shims.py would install (written to
           this run's own folder, so nothing global changes), from a launcher that exits at once, like typing the
           CLI's name in a terminal; passes when guardian-shim.py says the CLI joined a session. For gemini, its
           node.exe also runs whereami as its own child (NODE_OPTIONS --require), with no model call.
  shim     the whereami prompt started through that wrapper; passes when the shell command reports the session
           the shim opened. This is the route for claude and cursor, which a hook cannot adopt. For grok, its
           session-start hook also runs whereami, before the model call.
Antigravity CLI (agy) runs shell commands headless only with permission rules in its global settings or with
--dangerously-skip-permissions, so by default its srun, hook and shim levels ask for a plain reply and judge by a
PreInvocation hook in the run folder's .agents/hooks.json: that hook is a child of agy.exe started after the session
began (and after the SessionStart adopt hook finished), and runs whereami. --allow-yolo adds the flag and the shell
command instead.
The srun, hook and shim levels make one real model call each and use the CLI's own login; a CLI that is not logged
in fails with the CLI's own message. LIMIT means the hook ran but Windows would not let Guardian adopt a CLI that sits
in a job of its own (claude, cursor); SKIP means the level cannot run for that CLI as installed. The report goes to
~/.resource-sentinel/guardian/<instance>/check/report-*.json.
"""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sentinel.guardian import winjob as wj
from sentinel.guardian.client import home_dir, start_daemon
from sentinel.guardian.providers import PROVIDERS

PY = Path(sys.executable).as_posix()
WHEREAMI = (ROOT / "scripts" / "guardian-whereami.py").as_posix()
HOOK = (ROOT / "hooks" / "guardian-adopt.py").as_posix()
SRUN = ROOT / "scripts" / "srun.py"
SHIM = ROOT / "scripts" / "guardian-shim.py"
_spec = importlib.util.spec_from_file_location("guardian_install_shims", ROOT / "scripts" / "guardian-install-shims.py")
INSTALL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(INSTALL)
# Variables a desktop agent app sets for its own children. A CLI that inherits them may think it is nested in that
# app; Stan's own terminal does not have them.
DROP_ENV = ("CLAUDECODE", "CLAUDE_", "ANTHROPIC_", "GUARDIAN_", "CODEX_", "OPENAI_CODEX")
# Git Bash markers. With them cursor-agent 2026.10.01 runs hooks through bash but writes the hook line in PowerShell,
# so every hook fails and every shell command is rejected. A CLI started from a plain Windows terminal has none.
GIT_BASH_ENV = {"MSYSTEM", "SHELL", "EXEPATH", "TERM", "SHLVL", "PWD", "_", "PLINK_PROTOCOL"}


def clean_env():
    return {k: v for k, v in os.environ.items()
            if not k.upper().startswith(DROP_ENV) and k.upper() not in GIT_BASH_ENV}


def tool_prompt(cmd):
    # one line: cursor-agent and gemini start through .cmd shims, and cmd.exe cuts an argument at a newline
    return ("This is an automated check. Run exactly this one shell command with your shell tool, without changing "
            "it, then reply with the single word DONE. Do not run anything else. The command: " + cmd)


PLAIN_PROMPT = "This is an automated check. Do not use any tools. Reply with the single word DONE."


def hook_command(provider, instance, backslash=False):
    py, hook = (str(Path(PY)), str(Path(HOOK))) if backslash else (PY, HOOK)
    return f"{py} -I {hook} {provider} --instance {instance}"


# ---- per-provider knowledge -----------------------------------------------------------------------------------
# python      how the tool command starts, chosen so the narrow allow rule below matches it
# headless    (prompt, prefix, work, extra) -> argv for a one-shot run that may run prefix... as a shell command
# hook        (work, provider, instance) -> (extra argv, extra env) wiring the adopt hook to session start for this
#             run only; None when the CLI has no hooks (hook_none says why)
# own_job     the CLI puts itself in a job of its own at start (measured), so adopting it after start is refused
# yolo        the only headless way to run a shell command approves every command; needs --allow-yolo
# yolo_flag   the shell command needs this approve-everything flag: without --allow-yolo the levels ask for a plain
#             reply and judge by `child` instead
# child       (work, command) -> extra env; makes the CLI run command as its own child once the session has begun
# level_dirs  each level runs in its own folder, so hook files one level writes do not run in the next
def claude_headless(prompt, prefix, work, extra):
    return ["claude", "-p", prompt, "--model", "sonnet", "--max-turns", "4", "--allowedTools", f"Bash({prefix}:*)",
            *extra]


def claude_hook(work, provider, instance):
    f = work / "claude-settings.json"
    f.write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [
        {"type": "command", "command": hook_command(provider, instance)}]}]}}), encoding="utf-8")
    return ["--settings", str(f)], {}


def codex_headless(prompt, prefix, work, extra):
    # exec never asks; workspace-write lets the command write its --out file in the work dir
    return ["codex", "exec", "--skip-git-repo-check", "-s", "workspace-write", "-C", str(work),
            "-c", 'approval_policy="never"', *extra, prompt]


def codex_hook(work, provider, instance):
    # Codex runs hooks with cmd /C, hence backslashes. Hook trust is bypassed for this one invocation only, so no
    # trust record is written to ~/.codex.
    cmd = hook_command(provider, instance, backslash=True)
    return ["--dangerously-bypass-hook-trust",
            "-c", f"hooks.SessionStart=[{{hooks=[{{type='command',command='{cmd}',timeout=30}}]}}]"], {}


def gemini_headless(prompt, prefix, work, extra):
    # gemini 0.1.3 drops its shell tool in non-interactive mode unless --yolo, and has no per-command allow rule
    return ["gemini", "-p", prompt, "--yolo", *extra]


def node_probe(work, command):
    # NODE_OPTIONS --require runs this file inside the CLI's own node.exe before the CLI's code, so the command runs
    # as a child of the CLI process, where its tool commands would run, without a model call or a login
    js = work / "guardian-probe.js"
    js.write_text(f"require('child_process').execSync({json.dumps(command)}, {{stdio: 'ignore'}});", encoding="utf-8")
    return {"NODE_OPTIONS": f"--require {js.as_posix()}"}


def cursor_headless(prompt, prefix, work, extra):
    (work / ".cursor").mkdir(exist_ok=True)
    (work / ".cursor" / "cli.json").write_text(json.dumps({"permissions": {"allow": ["Shell(python)"], "deny": []}}),
                                                encoding="utf-8")
    return ["cursor-agent", "-p", "--trust", "--output-format", "text", *extra, prompt]


def cursor_hook(work, provider, instance):
    (work / ".cursor").mkdir(exist_ok=True)
    (work / ".cursor" / "hooks.json").write_text(json.dumps({"version": 1, "hooks": {"sessionStart": [
        {"command": hook_command(provider, instance)}]}}), encoding="utf-8")
    return [], {}


def grok_headless(prompt, prefix, work, extra):
    return ["grok", "-p", prompt, "--permission-mode", "dontAsk", "--allow", "Bash(python -I *guardian-whereami.py*)",
            "--max-turns", "4", "--no-subagents", *extra]


def grok_project_hook(work, command):
    # Grok reads .grok/hooks only inside a project root, which a bare folder is not, hence git init. Project hooks are
    # skipped without a word in an untrusted folder; GROK_FOLDER_TRUST=0 lifts that for this process only, where
    # --trust would write the folder into ~/.grok/trusted_folders.toml.
    if not (work / ".git").exists():
        subprocess.run(["git", "init", "-q", str(work)], capture_output=True, timeout=30)
    d = work / ".grok" / "hooks"
    d.mkdir(parents=True, exist_ok=True)
    (d / "guardian.json").write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [
        {"type": "command", "command": command, "timeout": 30}]}]}}), encoding="utf-8")
    return {"GROK_FOLDER_TRUST": "0"}


def grok_probe(work, command):
    # the hook is grok's own child and runs before the model call, so it shows where grok's children land even when
    # the model call fails (an expired login, say)
    return grok_project_hook(work, command)


def grok_hook(work, provider, instance):
    return [], grok_project_hook(work, hook_command(provider, instance))


def agy_headless(prompt, prefix, work, extra):
    return ["agy", "-p", prompt, *extra]


def agy_workspace_hook(work, name, event, command):
    # .agents/hooks.json in the folder agy starts in, which needs no git repo and no trust (measured, agy 1.3.4). agy
    # runs each command through cmd.exe, as a child of agy.exe, and finishes SessionStart before PreInvocation.
    f = work / ".agents" / "hooks.json"
    f.parent.mkdir(exist_ok=True)
    data = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    data[name] = {event: [{"type": "command", "command": command, "timeout": 30}]}
    f.write_text(json.dumps(data, indent=1), encoding="utf-8")


def agy_hook(work, provider, instance):
    agy_workspace_hook(work, "guardian-adopt", "SessionStart", hook_command(provider, instance))
    return [], {}


def agy_child(work, command):
    agy_workspace_hook(work, "guardian-probe", "PreInvocation", command)
    return {}


SPECS = {
    "claude": {"python": PY, "headless": claude_headless, "hook": claude_hook, "own_job": True},
    "codex": {"python": PY, "headless": codex_headless, "hook": codex_hook},
    "gemini": {"python": PY, "headless": gemini_headless, "hook": None, "yolo": True, "version_probe": node_probe,
               "hook_none": "gemini-cli 0.1.3 has no hooks (they arrive in 0.15 and are on by default from 0.24)"},
    "cursor": {"python": "python", "headless": cursor_headless, "hook": cursor_hook, "own_job": True},
    "grok": {"python": "python", "headless": grok_headless, "hook": grok_hook, "probe": grok_probe},
    "antigravity": {"python": PY, "headless": agy_headless, "hook": agy_hook, "child": agy_child,
                    "yolo_flag": "--dangerously-skip-permissions", "level_dirs": True},
}


def tool_route(spec, a):
    """(may the model be asked for the shell command, extra argv). False means: judge by the CLI's child instead."""
    flag = spec.get("yolo_flag")
    if flag is None:
        return True, []
    return (True, [flag]) if a.allow_yolo else (False, [])


# ---- running things -------------------------------------------------------------------------------------------
def srun(provider, session, argv, instance, timeout, cwd, extra_env=None):
    cmd = [sys.executable, "-I", str(SRUN), "--provider", provider, "--session", session, "--instance", instance,
           "--verbose", "--", *argv]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           cwd=cwd, env=dict(clean_env(), **(extra_env or {})), stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired as e:
        return None, e.stdout or "", f"timed out after {timeout} s"


def launch_detached(argv, cwd, env, out_path):
    """Start argv through a launcher that exits at once. The CLI's parent chain then ends at the launcher instead of
    leading into whatever started this check (the Claude app, say), which is what a CLI started from Stan's own
    terminal looks like to adopt."""
    exe = shutil.which(argv[0]) or argv[0]
    code = ("import json,subprocess,sys;a=json.load(sys.stdin);f=open(a['out'],'wb');"
            "p=subprocess.Popen(a['argv'],cwd=a['cwd'],env=a['env'],stdin=subprocess.DEVNULL,stdout=f,"
            "stderr=subprocess.STDOUT,creationflags=0x08000000|0x00000200);print(p.pid)")
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=30,
                       input=json.dumps({"argv": [exe] + argv[1:], "cwd": str(cwd), "env": env, "out": str(out_path)}))
    return int(r.stdout.strip())


def wait_exit(pid, timeout):
    h = wj.open_waitable(pid)
    if not h:
        return True
    try:
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout:
            if wj.has_exited(h):
                return True
            time.sleep(0.5)
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)  # our own test CLI
        return False
    finally:
        wj.CloseHandle(h)


def read_jsonl(path):
    try:
        return [json.loads(x) for x in Path(path).read_text(encoding="utf-8").splitlines() if x.strip()]
    except (OSError, ValueError):
        return []


def tail(text, n=300):
    text = (text or "").strip().replace("\r", "")
    return text[-n:]


def wire_child(fn, work, prefix, a, tag):
    """Have fn make the CLI run whereami as its own child. Returns (rows file, extra env)."""
    f = work / f"{tag}-child.jsonl"
    return f, (fn(work, f"{prefix} --instance {a.instance} --out {f.as_posix()}") if fn else {})


def evidence_of(tool, rows, child):
    said = f"a hook child of the CLI says: {child[-1]['answer']}" if child else ""
    if tool:
        return (rows[-1]["answer"] if rows else "the shell command never ran") + (f"; {said}" if said else "")
    return (said or "the hook child never ran") + " (no shell command asked for: that needs --allow-yolo)"


# ---- levels ---------------------------------------------------------------------------------------------------
def level_version(p, a, work):
    session = f"chk-version-{time.strftime('%H%M%S')}"
    rc, out, err = srun(p.name, session, [p.command, "--version"], a.instance, 120, work)
    started = [x for x in err.splitlines() if "started run" in x]
    ok = rc == 0 and any("enforced" in x for x in started)
    return {"pass": ok, "exit": rc, "version": tail(out, 120), "evidence": started[-1] if started else tail(err)}


def level_srun(p, spec, a, work):
    """The hook is wired here too, to show it does no harm when the CLI already runs in its srun session."""
    session = f"chk-srun-{time.strftime('%H%M%S')}"
    out_file = work / f"{p.name}-srun.jsonl"
    log = home_dir(a.instance) / "adopt.log"
    seen = len(read_jsonl(log))
    tool, allow = tool_route(spec, a)
    extra_argv, extra_env = spec["hook"](work, p.name, a.instance) if spec.get("hook") else ([], {})
    prefix = f"{spec['python']} -I {WHEREAMI}"
    cmd = f"{prefix} --instance {a.instance} --out {out_file.as_posix()}"
    child_file, child_env = wire_child(spec.get("child"), work, prefix, a, f"{p.name}-srun")
    argv = spec["headless"](tool_prompt(cmd) if tool else PLAIN_PROMPT, prefix, work, extra_argv + allow)
    rc, out, err = srun(p.name, session, argv, a.instance, a.timeout, work, {**extra_env, **child_env})
    rows, child = read_jsonl(out_file), read_jsonl(child_file)
    want = f"session {p.name}/{session} "
    ok = any(want in r.get("answer", "") for r in (rows if tool else child))
    hooks = [r for r in read_jsonl(log)[seen:] if r.get("provider") == p.name]
    return {"pass": ok, "exit": rc, "session": f"{p.name}/{session}", "evidence": evidence_of(tool, rows, child),
            "hook": (hooks[-1].get("state"), hooks[-1].get("reason")) if hooks else None,
            "cli_output": tail(out), "stderr": tail(err)}


def level_hook(p, spec, a, work):
    out_file = work / f"{p.name}-hook.jsonl"
    log = home_dir(a.instance) / "adopt.log"
    seen = len(read_jsonl(log))
    tool, allow = tool_route(spec, a)
    extra_argv, extra_env = spec["hook"](work, p.name, a.instance)
    prefix = f"{spec['python']} -I {WHEREAMI}"
    cmd = f"{prefix} --instance {a.instance} --out {out_file.as_posix()}"
    child_file, child_env = wire_child(spec.get("child"), work, prefix, a, f"{p.name}-hook")
    argv = spec["headless"](tool_prompt(cmd) if tool else PLAIN_PROMPT, prefix, work, extra_argv + allow)
    console = work / f"{p.name}-hook.out"
    pid = launch_detached(argv, work, {**clean_env(), **extra_env, **child_env}, console)
    finished = wait_exit(pid, a.timeout)
    rows, child = read_jsonl(out_file), read_jsonl(child_file)
    adopts = [r for r in read_jsonl(log)[seen:] if r.get("provider") == p.name]
    adopted = [r for r in adopts if r.get("state") in ("adopted", "partial", "already")]
    ok = bool(adopted) and any("CONTROLLED: session" in r.get("answer", "") for r in (rows if tool else child))
    limit = False
    if not adopts:
        evidence = "the hook never ran (no adopt.log row)"
    elif not adopted:
        evidence = f"hook ran, adopt {adopts[-1].get('state')}: {adopts[-1].get('reason')}"
        if spec.get("own_job") and "job outside Guardian" in str(adopts[-1].get("reason")):
            ok, limit = None, True  # the known limit, measured: start this CLI with gagent/srun
    else:
        evidence = evidence_of(tool, rows, child)
    return {"pass": ok, "limit": limit, "launcher_pid": pid, "finished": finished,
            "adopt": adopts[-1] if adopts else None, "evidence": evidence,
            "cli_output": tail(console.read_text(encoding="utf-8", errors="replace") if console.exists() else "")}


def shim_launch(p, a, work, args, tag, extra_env=None):
    """Start the CLI through its wrapper, written to this run's own folder, from a launcher that exits at once."""
    shims = work / "shims"
    shims.mkdir(exist_ok=True)
    for fname, text in INSTALL.wrappers(p.name, Path(sys.executable).resolve(), SHIM).items():
        (shims / fname).write_bytes(text.encode())
    env = dict(clean_env(), PATH=f"{shims}{os.pathsep}{os.environ.get('PATH', '')}", GUARDIAN_SHIM_INSTANCE=a.instance,
               GUARDIAN_SHIM_VERBOSE="1", **(extra_env or {}))
    console = work / f"{p.name}-{tag}.out"
    pid = launch_detached([str(shims / f"{p.command}.cmd"), *args], work, env, console)
    finished = wait_exit(pid, a.timeout)
    text = console.read_text(encoding="utf-8", errors="replace") if console.exists() else ""
    said = next((x for x in text.splitlines() if x.startswith("[guardian]")), None)
    return pid, finished, text, said


def level_shimver(p, spec, a, work):
    child_file, extra_env = work / f"{p.name}-shimver-child.jsonl", {}
    if spec and spec.get("version_probe"):
        extra_env = spec["version_probe"](work, f"{spec['python']} -I {WHEREAMI} --instance {a.instance} "
                                                f"--out {child_file.as_posix()}")
    pid, finished, text, said = shim_launch(p, a, work, ["--version"], "shimver", extra_env)
    ok = finished and f"runs in session {p.name}/{p.name}-" in (said or "")
    rest = " ".join(x for x in text.splitlines() if not x.startswith("[guardian]"))
    child = read_jsonl(child_file)
    evidence = said or tail(text)
    if child:
        evidence += f"; a child of the CLI process says: {child[-1]['answer']}"
    return {"pass": ok, "launcher_pid": pid, "finished": finished, "version": tail(rest, 120),
            "child": child[-1]["answer"] if child else None, "evidence": evidence}


def level_shim(p, spec, a, work):
    out_file = work / f"{p.name}-shim.jsonl"
    tool, allow = tool_route(spec, a)
    prefix = f"{spec['python']} -I {WHEREAMI}"
    cmd = f"{prefix} --instance {a.instance} --out {out_file.as_posix()}"
    argv = spec["headless"](tool_prompt(cmd) if tool else PLAIN_PROMPT, prefix, work, allow)
    # grok's probe is its session-start hook; agy's child is a PreInvocation hook
    child_file, extra_env = wire_child(spec.get("probe") or spec.get("child"), work, prefix, a, f"{p.name}-shim")
    pid, finished, text, said = shim_launch(p, a, work, argv[1:], "shim", extra_env)
    rows, child = read_jsonl(out_file), read_jsonl(child_file)
    ok = any(f"CONTROLLED: session {p.name}/{p.name}-" in r.get("answer", "") for r in (rows if tool else child))
    return {"pass": ok, "launcher_pid": pid, "finished": finished, "shim": said,
            "evidence": evidence_of(tool, rows, child),
            "child": child[-1]["answer"] if child else None, "cli_output": tail(text)}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("providers", nargs="*", default=sorted(PROVIDERS))
    ap.add_argument("--levels", default="version,srun,hook,shimver,shim")
    ap.add_argument("--instance", default="check")
    ap.add_argument("--port", type=int, default=8768)
    ap.add_argument("--timeout", type=int, default=240, help="seconds per model run")
    ap.add_argument("--allow-yolo", action="store_true",
                    help="let a CLI whose only headless shell route approves everything (gemini 0.1.3, agy without "
                         "global permission rules) run its shell command")
    a = ap.parse_args(argv)
    levels = a.levels.split(",")
    if not start_daemon(a.instance, a.port, ["--no-probe", "--no-apps"]):
        print(f"Guardian {a.instance} did not start", file=sys.stderr)
        return 2
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = home_dir(a.instance) / "check" / stamp
    report = {"instance": a.instance, "started": stamp, "results": {}}
    for name in a.providers:
        p = PROVIDERS[name]
        res = report["results"][name] = {}
        if not shutil.which(p.command):
            res["installed"] = False
            print(f"{name:11} not on PATH", flush=True)
            continue
        work = base / name
        work.mkdir(parents=True, exist_ok=True)
        spec = SPECS.get(name)
        for lv in levels:
            wd = work / lv if spec and spec.get("level_dirs") else work
            wd.mkdir(exist_ok=True)
            if lv == "version":
                r = level_version(p, a, wd)
            elif lv == "shimver":
                r = level_shimver(p, spec, a, wd)
            elif spec is None:
                r = {"pass": None, "evidence": "no headless/hook recipe for this CLI yet"}
            elif lv == "hook" and not spec.get("hook"):
                r = {"pass": None, "evidence": spec.get("hook_none", "no session-start hook") +
                     "; use gagent/srun, or guardctl adopt <pid>"}
            elif spec.get("yolo") and not a.allow_yolo:
                r = {"pass": None, "evidence": "its only headless shell route is --yolo, which approves every "
                     "command; rerun with --allow-yolo to test it"}
            elif lv == "srun":
                r = level_srun(p, spec, a, wd)
            elif lv == "hook":
                r = level_hook(p, spec, a, wd)
            elif lv == "shim":
                r = level_shim(p, spec, a, wd)
            else:
                continue
            res[lv] = r
            mark = "LIMIT" if r.get("limit") else {True: "PASS", False: "FAIL", None: "SKIP"}[r["pass"]]
            print(f"{name:11} {lv:8} {mark}  {r.get('evidence')}", flush=True)
    path = home_dir(a.instance) / "check" / f"report-{stamp}.json"
    path.write_text(json.dumps(report, indent=1, default=str), encoding="utf-8")
    print(f"report: {path}")
    return 0 if all(r.get("pass") is not False for res in report["results"].values()
                    for r in res.values() if isinstance(r, dict)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
