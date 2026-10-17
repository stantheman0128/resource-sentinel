"""Client side of the Guardian pipe, used by scripts/srun.py, scripts/gagent.py and hooks/guardian-adopt.py.

Messages are length-framed by multiprocessing.connection and tagged by their first byte:
J = JSON control message, O = stdout bytes, E = stderr bytes. The daemon never unpickles anything.
When the daemon is not reachable, run() starts the command locally and says so on stderr
(coverage=unavailable), so routing never blocks work.
"""
import json
import os
import shutil
import subprocess
import sys
import time
from multiprocessing.connection import Client, answer_challenge, deliver_challenge
from pathlib import Path

CLASSES = ("focus", "normal", "batch")
HANDSHAKE_SECONDS = 5.0


def home_dir(instance="main"):
    return Path.home() / ".resource-sentinel" / "guardian" / instance


def shim_dir():
    """Where scripts/guardian-install-shims.py puts the claude/codex/gemini/cursor-agent/grok/agy wrappers."""
    return Path.home() / ".resource-sentinel" / "guardian" / "shims"


def pipe_name(instance="main"):
    return r"\\.\pipe\resource-sentinel-guardian-%s-%s" % (instance, os.environ.get("USERNAME", "user"))


def send_json(conn, obj, lock=None):
    data = b"J" + json.dumps(obj, default=str).encode()
    if lock is None:
        conn.send_bytes(data)
    else:
        with lock:
            conn.send_bytes(data)


class _Deadline:
    """The connection as the stdlib handshake sees it, with one deadline for the whole exchange: a peer that stops
    answering raises TimeoutError instead of holding the thread."""

    def __init__(self, conn, seconds):
        self.conn, self.end = conn, time.monotonic() + seconds

    def send_bytes(self, data):
        self.conn.send_bytes(data)

    def recv_bytes(self, maxlength=None):
        if not self.conn.poll(max(0.0, self.end - time.monotonic())):
            raise TimeoutError("no handshake answer before the deadline")
        return self.conn.recv_bytes(maxlength)


def handshake(conn, authkey, server, seconds=HANDSHAKE_SECONDS):
    """The HMAC challenge both ways, the same bytes that Listener.accept() and Client() exchange when given an
    authkey. Raises AuthenticationError (wrong or no key), TimeoutError, EOFError or OSError."""
    d = _Deadline(conn, seconds)
    if server:
        deliver_challenge(d, authkey)
        answer_challenge(d, authkey)
    else:
        answer_challenge(d, authkey)
        deliver_challenge(d, authkey)


def connect(instance="main", timeout=HANDSHAKE_SECONDS, end=None):
    """end: a time.monotonic() deadline the caller set for its whole exchange, which the handshake keeps too."""
    conn = None
    try:
        key = (home_dir(instance) / "pipe-authkey").read_text(encoding="ascii").strip().encode()
        conn = Client(pipe_name(instance), family="AF_PIPE")  # the stdlib retries a busy pipe for up to 20 s
        if end is not None:
            timeout = min(timeout, end - time.monotonic())
        handshake(conn, key, server=False, seconds=timeout)
        return conn
    except Exception:  # no key file, no pipe, busy pipe, failed or stalled handshake: all mean "not reachable"
        if conn is not None:
            conn.close()
        return None


def ping(instance="main"):
    conn = connect(instance)
    if conn is None:
        return None
    try:
        send_json(conn, {"op": "ping"})
        return json.loads(conn.recv_bytes()[1:])
    except (EOFError, OSError):
        return None
    finally:
        conn.close()


def notice(text):
    sys.stderr.write(f"[guardian] {text}\n")
    sys.stderr.flush()


def run_local(argv, why):
    notice(f"coverage=unavailable: {why}; running locally without Guardian control")
    try:
        return subprocess.call(argv)
    except OSError as e:
        notice(f"cannot start {argv[0]}: {e}")
        return 127


def run(argv, provider, session, cls="normal", est_gib=None, console=False, instance="main", verbose=False):
    """Run argv inside the Guardian session job and relay its output. Returns the exit code."""
    exe = shutil.which(argv[0]) or argv[0]  # the daemon's own PATH may differ, so resolve here
    argv = [exe] + list(argv[1:])
    conn = connect(instance)
    if conn is None:
        return run_local(argv, "Guardian daemon not reachable")
    # the CLI's own hooks read these, so a CLI started here reports the session it already runs in
    env = dict(os.environ, GUARDIAN_PROVIDER=provider, GUARDIAN_SESSION=session, GUARDIAN_INSTANCE=instance)
    req = {"op": "run", "argv": argv, "cwd": os.getcwd(), "env": env, "provider": provider,
           "session": session, "cls": cls, "est_gib": est_gib, "console": console}
    try:
        send_json(conn, req)
        last = None
        while True:
            msg = conn.recv_bytes()
            tag, body = msg[:1], msg[1:]
            if tag == b"O":
                sys.stdout.buffer.write(body)
                sys.stdout.flush()
                continue
            if tag == b"E":
                sys.stderr.buffer.write(body)
                sys.stderr.flush()
                continue
            ev = json.loads(body)
            kind = ev.get("event")
            if kind == "queued" and ev.get("reason") != last and (verbose or not
                                                                 ev.get("reason", "").startswith("LAUNCH_")):
                last = ev.get("reason")
                notice(f"queued: {last}")
            elif kind == "started" and (verbose or last):
                notice(f"started run {ev.get('run_id')} pid {ev.get('pid')} ({ev.get('coverage')})")
            elif kind == "exit":
                if ev.get("cancelled"):
                    notice(f"cancelled: {ev.get('cancelled')}")
                return int(ev.get("code") or 0)
            elif kind == "error":
                if ev.get("kind") == "assign":
                    return run_local(argv, ev.get("message", "job assignment failed"))
                notice(ev.get("message", "error"))
                return 127
    except KeyboardInterrupt:
        try:
            send_json(conn, {"op": "cancel"})
        except OSError:
            pass
        return 130
    except (EOFError, OSError) as e:
        notice(f"lost the Guardian connection ({e.__class__.__name__})")
        return 255
    finally:
        conn.close()


def adopt(pid, provider, session, cls="normal", instance="main", via="hook", skip=(), timeout=10.0):
    """Ask the daemon to take a running CLI (and what it has started) into a session job. Never raises; the
    answer is a dict whose "state" is adopted, already, partial, refused, unreachable or timeout."""
    conn = connect(instance)
    if conn is None:
        return {"ok": False, "state": "unreachable", "reason": f"Guardian {instance} is not running"}
    try:
        send_json(conn, {"op": "adopt", "pid": int(pid), "provider": provider, "session": session, "cls": cls,
                         "via": via, "skip": [int(x) for x in skip]})
        if not conn.poll(timeout):
            return {"ok": False, "state": "timeout", "reason": f"no answer within {timeout:.0f} s"}
        return json.loads(conn.recv_bytes()[1:])
    except (EOFError, OSError, ValueError) as e:
        return {"ok": False, "state": "unreachable", "reason": f"lost the Guardian connection ({e.__class__.__name__})"}
    finally:
        conn.close()


def whereis(pid, instance="main", timeout=10.0):
    """The daemon's view of pid: {"in_guardian", "session", "priority", "budget", ...}, or None when it is not
    running or does not answer within timeout, one deadline for the handshake and the answer together. The stdlib's
    wait for a busy pipe, up to 20 s, can still run past it, so the hooks call this on a thread of their own."""
    end = time.monotonic() + timeout
    conn = connect(instance, end=end)
    if conn is None:
        return None
    try:
        send_json(conn, {"op": "whereis", "pid": int(pid)})
        return json.loads(conn.recv_bytes()[1:]) if conn.poll(max(0.0, end - time.monotonic())) else None
    except (EOFError, OSError, ValueError):
        return None
    finally:
        conn.close()


def budget_text(where, long=False):
    """What a hook tells an agent about its own Guardian session, from a whereis() answer; "" outside a session.
    long is the session-start context, otherwise the one line given before each prompt."""
    b = (where or {}).get("budget")
    if not b:
        return ""
    pool, world = b["pool_cap_cores"], b["world_cpus"]
    if not b["control"]:
        cpu = "control off, nothing capped"
    elif b["cls"] == "exempt":
        cpu = f"exempt from caps for {(b['exempt_left_s'] or 0) // 60} more minutes"
    else:
        cap = pool if b["cap_cores"] is None else min(b["cap_cores"], pool)
        cpu = f"CPU cap {cap:g} of {world} cores"
    state = []
    if b["paused"]:
        state.append("paused")
    if not b["admission_open"]:
        state.append(f"new srun commands wait ({b['admission_reason']})")
    if b.get("memory_pressure", b["memory_rung"]):  # pressure can last at rung 0 while trim is off
        state.append("memory pressure")
    if b["queued"]:
        state.append(f"{b['queued']} queued")
    ram = f"{b['available_gib']:g} GiB RAM available" if b["available_gib"] is not None else ""
    short = ", ".join(x for x in [f"Guardian: {b['key']} {b['cls']}", cpu, ram] + state if x)
    if not long:
        return short
    provider, _, session = b["key"].partition("/")
    srun = Path(__file__).resolve().parents[2] / "scripts" / "srun.py"
    workers = "" if not b["control"] or b["cls"] == "exempt" else (
        f" About {max(1, int(cap))} parallel workers fit in that cap.")
    instance = where.get("instance") or "main"
    return (f"This session runs under Guardian, the resource controller on Stan's machine. {short}."
            f" The agents together may use {pool:g} cores. Their processes run at {where.get('priority') or '?'}"
            f" CPU priority and {b['io']} I/O priority" + (", so Stan's own apps go first." if b["control"] else ".") +
            f"{workers} A long build or test can wait for room instead of slowing the machine:"
            f" python -I {srun.as_posix()} --provider {provider} --session {session}"
            + ("" if instance == "main" else f" --instance {instance}") + " -- <command>.")


def hook_output(provider, event, text):
    """The stdout a CLI's hook needs to hand text to the model, or "" where the hook has no such channel.
    Claude Code and Codex: SessionStart and UserPromptSubmit take additionalContext. Cursor: sessionStart takes
    additional_context. Grok ignores the stdout of these events."""
    if not text:
        return ""
    event = (event or "")[:1].upper() + (event or "")[1:]  # Cursor names it sessionStart
    if provider in ("claude", "codex") and event in ("SessionStart", "UserPromptSubmit"):
        return json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}})
    if provider == "cursor" and event == "SessionStart":
        return json.dumps({"additional_context": text})
    return ""


def start_daemon(instance="main", port=8765, extra=(), wait=20.0):
    """Start the daemon in the background unless it is already running; its output goes to
    ~/.resource-sentinel/guardian/<instance>-daemon.log. Returns its ping answer, or None if it did not come up."""
    up = ping(instance)
    if up:
        return up
    log = home_dir(instance).parent / f"{instance}-daemon.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve().parents[2] / "scripts" / "guardian.py"
    with open(log, "a", encoding="utf-8") as f:
        subprocess.Popen([sys.executable, "-I", str(script), "--instance", instance, "--port", str(port), *extra],
                         stdin=subprocess.DEVNULL, stdout=f, stderr=f,
                         creationflags=0x08000000 | 0x00000200)  # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
    t0 = time.monotonic()
    while time.monotonic() - t0 < wait:
        up = ping(instance)
        if up:
            return up
        time.sleep(0.3)
    return None
