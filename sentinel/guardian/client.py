"""Client side of the Guardian pipe, used by scripts/srun.py and hooks/guardian-route.py.

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
from multiprocessing.connection import Client
from pathlib import Path

CLASSES = ("focus", "normal", "batch")


def home_dir(instance="main"):
    return Path.home() / ".resource-sentinel" / "guardian" / instance


def pipe_name(instance="main"):
    return r"\\.\pipe\resource-sentinel-guardian-%s-%s" % (instance, os.environ.get("USERNAME", "user"))


def send_json(conn, obj, lock=None):
    data = b"J" + json.dumps(obj, default=str).encode()
    if lock is None:
        conn.send_bytes(data)
    else:
        with lock:
            conn.send_bytes(data)


def connect(instance="main"):
    key = home_dir(instance) / "pipe-authkey"
    try:
        return Client(pipe_name(instance), family="AF_PIPE", authkey=key.read_text(encoding="ascii").strip().encode())
    except Exception:  # no key file, no pipe, busy pipe or failed handshake: all mean "not reachable"
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
    req = {"op": "run", "argv": argv, "cwd": os.getcwd(), "env": dict(os.environ), "provider": provider,
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
