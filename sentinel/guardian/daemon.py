"""Guardian daemon: owns the one big agent job, launches agent commands into it, runs the 1 Hz control loop and
serves the local dashboard API.

Job tree (named in the session namespace, so a restarted daemon or `guardctl rollback` can reopen it):
  Local\\Guardian.<instance>.AllAgents          below_normal priority + dynamic hard cap: the one big job
    Local\\Guardian.<instance>.p.<provider>     pause or resume a whole provider (rate 1 = paused)
      Local\\Guardian.<instance>.s.<p>.<s>      per-session hard cap from weighted max-min, relative to the pool
        unnamed run job per command             cancel = TerminateJobObject; CPU, peak commit
Running app UIs (Claude desktop, the Codex app, Cursor) stay where they are: a process cannot leave its job, and
a cap on their own app job would also slow their UI. apps.py only measures them.
Nothing here kills or suspends work on its own. Cancel happens only when the requesting client goes away or
Stan presses cancel; pause is a CPU rate of 1/10000 that resume lifts.
"""
import argparse
import collections
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import traceback
import uuid
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from multiprocessing.connection import Listener
from pathlib import Path

from . import policy as P
from . import winjob as wj
from .client import CLASSES, home_dir, pipe_name, ping, send_json
from .ledger import Ledger

REPO = Path(__file__).resolve().parents[2]
DASHBOARD = REPO / "dashboard" / "guardian.html"
PROBE = Path(__file__).with_name("probe.py")
PROVIDERS = ("claude", "codex", "cursor", "grok", "gemini", "other")
CLASS_RANK = {"focus": 0, "normal": 1, "batch": 2}
CREATE_NO_WINDOW, CREATE_NEW_CONSOLE = 0x08000000, 0x00000010
GiB = 2**30


def secret(path, nbytes):
    """Per-user secret in the profile directory; other accounts cannot read it there."""
    path = Path(path)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(secrets.token_hex(nbytes), encoding="ascii")
    return path.read_text(encoding="ascii").strip()


def safe(name, default="default"):
    s = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(name or ""))[:48]
    return s or default


def describe(argv):
    """Dashboard label and profile fingerprint from the first words only, so whole command lines (which can
    hold tokens) are never stored."""
    raw = argv[2].split() if len(argv) >= 3 and argv[1] == "-c" else argv
    words = [os.path.basename(w.rstrip("/\\")) or w for w in raw]
    label = " ".join(words[:3])[:60]
    plain = [w for w in words[1:] if not w.startswith("-")]
    head = " ".join(words[:1] + plain[:1]).lower()  # program + first non-option word, e.g. "python.exe burn.py"
    return label, head


class Cancelled(Exception):
    pass


class SpawnError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class Session:
    def __init__(self, provider, name, cls, job):
        self.provider, self.name, self.cls, self.job = provider, name, cls, job
        self.key = f"{provider}/{name}"
        self.paused = False
        self.applied = None        # None = no CPU control, "paused", or ("rel", fraction of the pool)
        self.usage = 0.0
        self.prev = None
        self.live_runs = 0
        self.t_last = time.time()


class Run:
    def __init__(self, run_id, session, argv, cwd, env, console, est, src, unprofiled, label, fingerprint):
        self.run_id, self.session, self.argv, self.cwd, self.env = run_id, session, argv, cwd, env
        self.console, self.est_gib, self.est_source, self.unprofiled = console, est, src, unprofiled
        self.label, self.fingerprint = label, fingerprint
        self.state, self.reason, self.numbers = "queued", "", {}
        self.t_request = time.monotonic()
        self.t_start = None
        self.admitted = threading.Event()
        self.cancelled = None
        self.job = self.proc = None
        self.commit_gib = 0.0
        self.coverage = None
        self.send_lock = threading.Lock()


class Guardian:
    def __init__(self, instance="main", world_cpus=None, initial_cap=None, cfg_over=None, port=8765, probe=True,
                 apps=True):
        self.instance, self.port = safe(instance, "main"), port
        self.home = home_dir(self.instance)
        self.home.mkdir(parents=True, exist_ok=True)
        self.cfg = P.merged(P.DEFAULTS, cfg_over)
        c = self.cfg["cpu"]
        self.world = max(1, min(wj.NCPU, int(world_cpus or wj.NCPU)))
        self.mask = sum(1 << i for i in range(wj.NCPU - self.world, wj.NCPU)) if self.world < wj.NCPU else None
        self.cap = P.CapState(cap=float(initial_cap or c["initial_cap_percent"]))
        self.alloc = P.AllocState()
        self.allocator_on = True
        self.control = True
        self.lock = threading.RLock()
        self.ledger = Ledger(self.home / "guardian.sqlite3")
        self.sessions, self.providers, self.queue, self.live, self.lingering = {}, {}, [], {}, []
        self.hold = False
        self.inject = None
        self.media = None
        self.probe_levels = collections.deque(maxlen=5)
        self.probe_last, self.probe_t, self.probe_proc, self.probe_job = None, 0.0, None, None
        self.probe_enabled, self.apps_enabled = probe, apps
        self.sample = None
        self.history = collections.deque(maxlen=300)
        self.events = collections.deque(maxlen=200)
        self.apps_rows = []
        self.last_launch, self.launch_starts = -1e9, []
        self.pool_priority = c["pool_priority"]
        self.pool_priority_readback = None
        self.token = secret(self.home / "http-token", 24)
        self.authkey = secret(self.home / "pipe-authkey", 32).encode()
        self.stop = threading.Event()
        self.busy_fn = wj.system_busy()
        self.busy_fn()
        self.last_core_ok = time.monotonic()
        self.pool_cores = 0.0

    # ---- logging and decisions -----------------------------------------------------------------------------
    def log(self, text):
        line = time.strftime("%H:%M:%S ") + text
        self.events.appendleft(line)
        print(line, flush=True)

    def decide(self, kind, target, before=None, requested=None, readback=None, error=None, reason=""):
        self.ledger.decision(kind, target, before, requested, readback, error, reason, P.POLICY_VERSION)
        self.log(f"{kind} {target}: {reason}" + (f" [error {error}]" if error else ""))

    def jobname(self, *parts):
        return ".".join((self.instance,) + parts)

    # ---- job tree --------------------------------------------------------------------------------------------
    def open_tree(self):
        self.root = wj.Job.create(self.jobname("AllAgents"))
        if self.root.existed:
            self.log("reopened the AllAgents job a previous daemon left behind")
        self.set_pool_priority(self.pool_priority, "startup: agent work yields to the foreground (E9)")
        before = self.root.limits()["flags"] & wj.LIMIT_AFFINITY
        wj.set_job_affinity(self.root, self.mask)
        if self.mask or before:
            self.decide("affinity", "AllAgents", requested=hex(self.mask) if self.mask else None,
                        readback=hex(self.root.extended().Basic.Affinity) if self.mask else None,
                        reason=f"world = {self.world} of {wj.NCPU} logical CPUs")
        self.apply_cap("startup", f"initial cap {self.cap.cap:.0f}% of {self.world} CPUs")
        stale = self.ledger.reconcile_on_start()
        if stale:
            self.log(f"{len(stale)} runs from an earlier daemon marked NEEDS_RECONCILIATION")

    def set_pool_priority(self, name, reason):
        before = self.root.limits()["priority"]
        err = None
        try:
            self.root.set_limits(priority=name)  # the limit also re-sets current members; never cleared (see E9)
        except OSError as e:
            err = str(e)
        self.pool_priority_readback = self.root.limits()["priority"]
        self.pool_priority = name
        self.decide("pool_priority", "AllAgents", before, name, self.pool_priority_readback, err, reason)

    def apply_cap(self, kind, reason):
        cores = self.cap.cap / 100 * self.world
        before = self.root.cpu()
        err = None
        try:
            self.root.set_cpu(max_cores=cores)
        except OSError as e:
            err = str(e)
        rb = self.root.cpu()
        self.decide(kind, "AllAgents", before.get("cores"), {"cap_percent": self.cap.cap, "cores": round(cores, 2)},
                    round(rb.get("cores", 0), 2), err, reason)

    def set_world(self, n, reason):
        """Let the agents use only the top n logical CPUs, so the rest stay free for the foreground (for example a
        remote desktop). The cap stays a percent of the world, so the cores it allows move with n. Like the world
        given at startup, it holds while control is off; the probe follows it to keep seeing the pool's CPUs."""
        self.world = max(1, min(wj.NCPU, int(n)))
        self.mask = sum(1 << i for i in range(wj.NCPU - self.world, wj.NCPU)) if self.world < wj.NCPU else None
        # widening sets every CPU explicitly: clearing the limit would leave running members on the old, smaller mask
        mask = self.mask or (1 << wj.NCPU) - 1
        wj.set_job_affinity(self.root, mask)
        if self.probe_proc and self.probe_proc.poll() is None:
            if not self.probe_job:
                self.probe_job = wj.Job.create()
                self.probe_job.assign(self.probe_proc.pid)
            wj.set_job_affinity(self.probe_job, mask)
        self.decide("affinity", "AllAgents", requested=hex(mask), readback=hex(self.root.extended().Basic.Affinity),
                    reason=f"world = {self.world} of {wj.NCPU} logical CPUs, {reason}")
        if self.control:
            self.apply_cap("world", f"cap {self.cap.cap:.0f}% of {self.world} CPUs")
            self.allocate()

    def provider(self, name):
        p = self.providers.get(name)
        if p is None:
            job = wj.Job.create(self.jobname("p", name))
            job.set_cpu()  # a job reopened from an earlier daemon may still carry its pause
            p = self.providers[name] = {"name": name, "job": job, "paused": False}
        return p

    def session(self, provider, name, cls):
        key = f"{provider}/{name}"
        s = self.sessions.get(key)
        if s is None:
            self.provider(provider)
            job = wj.Job.create(self.jobname("s", provider, name))
            job.set_cpu()
            s = self.sessions[key] = Session(provider, name, cls, job)
            self.log(f"new session {key} class {cls}")
        return s

    def set_provider_paused(self, name, paused):
        p = self.provider(name)
        before = p["job"].cpu()
        err = None
        try:
            if paused:
                p["job"].set_cpu_rate(1)
            else:
                p["job"].set_cpu()
            p["paused"] = paused
        except OSError as e:
            err = str(e)
        self.decide("provider_pause" if paused else "provider_resume", name, before.get("mode"),
                    "rate 1" if paused else "none", p["job"].cpu().get("mode"), err,
                    "Stan paused the provider: CPU rate 1/10000, processes stay alive" if paused else "resumed")

    def apply_session(self, s, want, budget):
        err = None
        try:
            if want == "paused":
                s.job.set_cpu_rate(1)
            elif want is None:
                s.job.set_cpu()
            else:
                s.job.set_cpu(max_cores=want[1] * wj.NCPU)  # nested caps are a fraction of the parent (E8b)
        except OSError as e:
            err = str(e)
        rb = s.job.cpu()
        before, s.applied = s.applied, (s.applied if err else want)
        shown = lambda v: v if not isinstance(v, tuple) else f"{v[1] * budget:.2f} cores"
        self.ledger.decision("session_cap", s.key, shown(before), shown(want), rb.get("mode"), err,
                             f"weighted max-min, class {s.cls}", P.POLICY_VERSION)

    # ---- 1 Hz control loop -----------------------------------------------------------------------------------
    def experience(self, now):
        o = self.cfg["observation"]
        if self.inject and now < self.inject[0]:
            return self.inject[1], "injected"
        if self.media and now - self.media["t"] <= o["sensor_valid_seconds"] and self.media["level"]:
            return ("ok" if self.media["level"] == "ok" else "degraded"), "media"
        if self.probe_last and now - self.probe_t <= o["sensor_valid_seconds"]:
            level = P.sustained(list(self.probe_levels))
            if level:
                return level, "probe"
        return None, None

    def tick(self, prev):
        now = time.monotonic()
        avail = head = busy = None
        try:
            perf = wj.performance_info()
            busy = self.busy_fn()
            avail = perf["available"] / GiB
            head = (perf["commit_limit"] - perf["commit_total"]) / GiB
            self.last_core_ok = now
        except OSError as e:
            self.log(f"core telemetry failed: {e}")
        cpu_s = self.root.accounting()["cpu_s"]
        dt = max(1e-3, now - prev[0])
        self.pool_cores = max(0.0, (cpu_s - prev[1]) / dt)
        with self.lock:
            for s in self.sessions.values():
                a = s.job.accounting()["cpu_s"]
                s.usage = max(0.0, (a - s.prev[1]) / max(1e-3, now - s.prev[0])) if s.prev else 0.0
                s.prev = (now, a)
            for r in list(self.live.values()):
                if r.state == "running" and r.job:
                    try:
                        r.commit_gib = r.job.memory_usage()[0] / GiB
                    except OSError:
                        pass
            for r in list(self.lingering):
                if r.job.accounting()["active"] == 0:
                    r.job.close()
                    self.lingering.remove(r)
            if self.probe_enabled and self.probe_proc and self.probe_proc.poll() is not None:
                self.log("probe exited; restarting it")
                self.start_probe()
            level, kind = self.experience(now)
            s = P.Sample(t=now, age_s=now - self.last_core_ok, cpu_busy=busy, pool_cores=self.pool_cores,
                         available_gib=avail, commit_headroom_gib=head, experience=level, experience_kind=kind,
                         pool_priority=self.pool_priority_readback, ncpu=self.world)
            if self.control:
                self.cap, d = P.cap_step(self.cap, s, self.cfg)
                if d:
                    self.apply_cap(d["kind"], d["reason"])
                self.allocate()
            self.sample = s
            row = {"t": time.time(), "mode": self.cap.mode if self.control else "ROLLED_BACK", "cap": self.cap.cap,
                   "cpu_busy": busy, "pool_cores": round(self.pool_cores, 2), "available_gib": avail,
                   "commit_headroom_gib": head, "experience": f"{level or '-'}/{kind or '-'}", "probe": self.probe_last,
                   "sessions": {k: [round(x.usage, 2), self.alloc.caps.get(k)] for k, x in self.sessions.items()},
                   "apps": self.apps_rows}
            self.history.append({"t": row["t"], "cap": self.cap.cap if self.control else None, "pool": row["pool_cores"],
                                 "p95": (self.probe_last or {}).get("lag_p95_ms"), "level": level,
                                 "sessions": {k: round(x.usage, 2) for k, x in self.sessions.items()}})
        self.ledger.sample(row)
        return now, cpu_s

    def allocate(self):
        budget = self.cap.cap / 100 * self.world
        weights = self.cfg["cpu"]["allocation_weights"]
        active = {k: {"allocation_weight": weights.get(s.cls, 5), "usage": s.usage,
                      "paused": s.paused or self.providers[s.provider]["paused"]}
                  for k, s in self.sessions.items() if s.live_runs or s.usage > 0.05}
        if self.allocator_on:
            self.alloc, _ = P.allocate(self.alloc, budget, active, self.cfg)
        else:
            self.alloc = P.AllocState()
        for k, s in self.sessions.items():
            if s.paused:
                want = "paused"
            else:
                cap = self.alloc.caps.get(k) if k in active else None
                want = None if cap is None or cap >= 0.98 * budget else ("rel", round(cap / budget, 3))
            same = want == s.applied or (isinstance(want, tuple) and isinstance(s.applied, tuple)
                                         and abs(want[1] - s.applied[1]) < 0.02)
            if not same:
                self.apply_session(s, want, budget)

    def tick_loop(self):
        prev = (time.monotonic(), self.root.accounting()["cpu_s"])
        while not self.stop.is_set():
            t0 = time.monotonic()
            try:
                prev = self.tick(prev)
            except Exception:
                self.log("tick failed: " + traceback.format_exc(limit=3).replace("\n", " | "))
            self.stop.wait(max(0.05, 1.0 - (time.monotonic() - t0)))

    # ---- probe and app observer ------------------------------------------------------------------------------
    def start_probe(self):
        self.probe_proc = subprocess.Popen([sys.executable, "-I", str(PROBE)], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                           creationflags=CREATE_NO_WINDOW)
        if self.mask:  # pin the probe to the same CPUs as the pool, as in E9, so it sees the pool's contention
            self.probe_job = wj.Job.create()
            self.probe_job.assign(self.probe_proc.pid)
            wj.set_job_affinity(self.probe_job, self.mask)
        threading.Thread(target=self.probe_reader, args=(self.probe_proc,), daemon=True).start()

    def probe_reader(self, proc):
        obs = self.cfg["observation"]
        for line in proc.stdout:
            try:
                w = json.loads(line)
            except ValueError:
                continue
            with self.lock:
                self.probe_levels.append(P.probe_window_level(w, obs))
                self.probe_last, self.probe_t = w, time.monotonic()

    def apps_loop(self):
        from .apps import AppObserver
        obs = AppObserver()
        while not self.stop.wait(2.0):
            try:
                rows = obs.sample()
                for r in rows:
                    if r.get("hosts_guardian") and r.get("cores") is not None:
                        # the daemon was started from inside this app, so its job also holds the agent pool
                        r["cores"] = round(max(0.0, r["cores"] - self.pool_cores), 2)
                        r["coverage"] += "; Guardian pool subtracted (daemon runs inside this app)"
                self.apps_rows = rows
            except Exception as e:
                self.apps_rows = [{"name": "?", "error": str(e)}]

    # ---- admission -------------------------------------------------------------------------------------------
    def admit_loop(self):
        while not self.stop.wait(0.25):
            with self.lock:
                self.admit_once(time.monotonic())

    def admit_once(self, now):
        if not self.queue or self.sample is None:
            return
        unused = sum(max(0.0, r.est_gib - r.commit_gib) for r in self.live.values()
                     if r.state in ("admitted", "running"))
        for run in sorted(self.queue, key=lambda r: (CLASS_RANK.get(r.session.cls, 1), r.t_request)):
            ok, reason = self.can_admit(run, now, unused)
            if ok:
                self.queue.remove(run)
                run.state, run.reason = "admitted", ""
                unused += run.est_gib
                if run.unprofiled:
                    self.last_launch = now
                    self.launch_starts.append(now)
                run.admitted.set()
            elif reason != run.reason:
                run.reason = reason
                self.ledger.run_update(run.run_id, reason=reason)

    def can_admit(self, run, now, unused):
        s = run.session
        if self.providers[s.provider]["paused"]:
            return False, "PROVIDER_PAUSED"
        if s.paused:
            return False, "SESSION_PAUSED"
        ok, reason, run.numbers = P.admission(run.est_gib, self.sample, unused, unused, self.cap, self.cfg, self.hold)
        if not ok:
            return False, reason
        if run.unprofiled:
            window = self.cfg["unknown_work"]["initial_observation_seconds"]
            self.launch_starts = [t for t in self.launch_starts if now - t < window]
            ok, reason = P.launch_slot(now, self.launch_starts, self.last_launch, self.cfg)
            if not ok:
                return False, "LAUNCH_OBSERVATION: " + reason
        return True, ""

    # ---- pipe server -----------------------------------------------------------------------------------------
    def accept_loop(self):
        listener = Listener(pipe_name(self.instance), family="AF_PIPE", authkey=self.authkey)
        while not self.stop.is_set():
            try:
                conn = listener.accept()
            except Exception as e:  # failed handshake from a client without the key, or a dropped connect
                self.log(f"pipe accept failed: {e.__class__.__name__}")
                continue
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            req = json.loads(conn.recv_bytes(1 << 22)[1:])
            if req.get("op") == "ping":
                send_json(conn, {"ok": True, "instance": self.instance, "pid": os.getpid(), "world": self.world})
            elif req.get("op") == "run":
                self.serve_run(conn, req)
        except (EOFError, OSError):
            pass
        except Exception:
            self.log("serve failed: " + traceback.format_exc(limit=3).replace("\n", " | "))
        finally:
            conn.close()

    def client_message(self, conn):
        """Raises Cancelled when the client asks to cancel or goes away (Ctrl+C, closed tool call, killed shell)."""
        try:
            msg = conn.recv_bytes()
        except (EOFError, OSError):
            raise Cancelled("client disconnected")
        if msg[:1] == b"J" and json.loads(msg[1:]).get("op") == "cancel":
            raise Cancelled("client cancelled")

    def serve_run(self, conn, req):
        provider = safe(req.get("provider"), "other").lower()
        provider = provider if provider in PROVIDERS else "other"
        name = safe(req.get("session"))
        cls = req.get("cls") if req.get("cls") in CLASSES else "normal"
        argv = [str(a) for a in req["argv"]]
        label, head = describe(argv)
        fingerprint = hashlib.sha1(f"{provider}|{head}".encode()).hexdigest()[:16]
        with self.lock:
            s = self.session(provider, name, cls)
            est, src, _ = P.estimate(self.ledger.profile(fingerprint), req.get("est_gib"), self.cfg)
            run = Run(uuid.uuid4().hex[:12], s, argv, req.get("cwd"), req.get("env"), bool(req.get("console")),
                      est, src, src == "exploration", label, fingerprint)
            self.ledger.run_requested({"run_id": run.run_id, "provider": provider, "session": name, "cls": s.cls,
                                       "fingerprint": fingerprint, "cwd": run.cwd, "label": label, "est_gib": est,
                                       "est_source": src, "unprofiled": run.unprofiled, "t_request": time.time()})
            self.live[run.run_id] = run
            s.live_runs += 1
            s.t_last = time.time()
            self.queue.append(run)
            self.admit_once(time.monotonic())
        send = lambda obj: send_json(conn, obj, run.send_lock)
        send({"event": "accepted", "run_id": run.run_id, "est_gib": round(est, 2), "est_source": src})
        rc, state = None, "done"
        try:
            told = None
            while not run.admitted.wait(0.25):
                if run.cancelled:
                    raise Cancelled(run.cancelled)
                if run.reason and run.reason != told:
                    told = run.reason
                    send({"event": "queued", "reason": run.reason, "numbers": run.numbers})
                if conn.poll(0):
                    self.client_message(conn)
            self.launch(run)
            send({"event": "started", "run_id": run.run_id, "pid": run.proc.pid, "coverage": run.coverage})
            pumps = []
            if not run.console:
                for stream, tag in ((run.proc.stdout, b"O"), (run.proc.stderr, b"E")):
                    t = threading.Thread(target=self.pump, args=(conn, run, stream, tag), daemon=True)
                    t.start()
                    pumps.append(t)
            while (rc := run.proc.poll()) is None:
                if run.cancelled:
                    raise Cancelled(run.cancelled)
                if conn.poll(0.2):
                    self.client_message(conn)
            for t in pumps:
                t.join(2.0)  # a background grandchild may keep the pipe open; do not wait for it
            if run.cancelled:
                raise Cancelled(run.cancelled)
            send({"event": "exit", "code": rc})
        except Cancelled as e:
            state = "cancelled"
            run.cancelled = run.cancelled or str(e)
            self.cancel(run, str(e))
            try:
                send({"event": "exit", "code": 1, "cancelled": run.cancelled})
            except OSError:
                pass
        except SpawnError as e:
            state = "failed"
            run.reason = str(e)
            try:
                send({"event": "error", "kind": e.kind, "message": str(e)})
            except OSError:
                pass
        except (EOFError, OSError):
            state = "cancelled"
            self.cancel(run, "client disconnected")
        finally:
            self.finish(run, state, rc)

    def pump(self, conn, run, stream, tag):
        try:
            while True:
                b = stream.read1(65536)
                if not b:
                    return
                with run.send_lock:
                    conn.send_bytes(tag + b)
        except (OSError, ValueError):
            return

    def launch(self, run):
        s = run.session
        run.job = wj.Job.create()
        chain = [self.root, self.providers[s.provider]["job"], s.job, run.job]
        kw = {"cwd": run.cwd or None, "env": run.env or None}
        if run.console:
            kw["creationflags"] = CREATE_NEW_CONSOLE
        else:
            kw.update(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      creationflags=CREATE_NO_WINDOW)
        self.ledger.run_update(run.run_id, state="starting")
        try:
            run.proc = wj.spawn_in_jobs(run.argv, chain, **kw)
        except wj.WinError as e:
            raise SpawnError("assign", f"job assignment failed: {e}")
        except OSError as e:
            raise SpawnError("spawn", f"cannot start {os.path.basename(run.argv[0])}: {e}")
        pid = run.proc.pid
        run.t_start, run.state = time.monotonic(), "running"
        in_root, in_session = wj.in_job(pid, self.root.h), wj.in_job(pid, s.job.h)
        prio = wj.priority_class(pid)
        run.coverage = ("enforced" if in_root and in_session else "partial") + f", priority {prio}"
        self.ledger.run_update(run.run_id, state="running", t_start=time.time(), pid=pid, coverage=run.coverage)

    def cancel(self, run, why):
        with self.lock:
            if run in self.queue:
                self.queue.remove(run)
        if run.job and run.state == "running":
            try:
                run.job.terminate(1)
            except OSError as e:
                self.log(f"terminate {run.run_id} failed: {e}")
        self.log(f"cancelled run {run.run_id} ({run.session.key}): {why}")

    def finish(self, run, state, rc):
        cpu_s = peak = None
        if run.job:
            try:
                acc, lim = run.job.accounting(), run.job.limits()
                cpu_s, peak = acc["cpu_s"], lim["peak_job_mem_bytes"]
                lingering = acc["active"] > 0
            except OSError:
                lingering = False
        with self.lock:
            self.live.pop(run.run_id, None)
            run.session.live_runs -= 1
            run.state = state
            if run.job:
                if lingering and state != "cancelled":
                    self.lingering.append(run)
                else:
                    run.job.close()
        self.ledger.run_update(run.run_id, state=state, t_end=time.time(), exit_code=rc, cpu_s=cpu_s,
                               peak_commit_bytes=peak, reason=run.cancelled or run.reason or "")

    # ---- dashboard API ---------------------------------------------------------------------------------------
    def state(self):
        with self.lock:
            s = self.sample
            c = self.cfg["cpu"]
            budget = self.cap.cap / 100 * self.world
            level, kind = self.experience(time.monotonic())
            prov_cores = collections.Counter()
            for x in self.sessions.values():
                prov_cores[x.provider] += x.usage
            return {
                "t": time.time(), "instance": self.instance, "world_cpus": self.world, "ncpu": wj.NCPU,
                "mode": self.cap.mode if self.control else "ROLLED_BACK", "control": self.control,
                "cap": self.cap.cap, "cap_cores": round(budget, 2), "cap_min": c["minimum_cap_percent"],
                "cap_max": c["maximum_cap_percent"], "pool_cores": round(self.pool_cores, 2),
                "cpu_busy": s.cpu_busy if s else None,
                "available_gib": round(s.available_gib, 1) if s and s.available_gib else None,
                "commit_headroom_gib": round(s.commit_headroom_gib, 1) if s and s.commit_headroom_gib else None,
                "admission": {"open": self.cap.admission_open, "reason": self.cap.admission_reason, "hold": self.hold},
                "pool_priority": self.pool_priority_readback, "allocator": self.allocator_on,
                "experience": {"level": level, "kind": kind, "probe": self.probe_last,
                               "inject_left_s": round(self.inject[0] - time.monotonic())
                               if self.inject and self.inject[0] > time.monotonic() else 0},
                "notes": self.cap.notes,
                "providers": [{"name": n, "paused": p["paused"], "cores": round(prov_cores[n], 2)}
                              for n, p in self.providers.items()],
                "sessions": [{"key": k, "provider": x.provider, "name": x.name, "cls": x.cls,
                              "allocation_weight": c["allocation_weights"].get(x.cls, 5), "paused": x.paused,
                              "provider_paused": self.providers[x.provider]["paused"], "usage": round(x.usage, 2),
                              "cap_cores": self.alloc.caps.get(k), "runs": x.live_runs}
                             for k, x in self.sessions.items()],
                "queue": [{"run_id": r.run_id, "session": r.session.key, "label": r.label, "reason": r.reason,
                           "est_gib": round(r.est_gib, 2), "numbers": r.numbers,
                           "waiting_s": round(time.monotonic() - r.t_request)} for r in self.queue],
                "runs": [{"run_id": r.run_id, "session": r.session.key, "label": r.label, "state": r.state,
                          "pid": r.proc.pid if r.proc else None, "coverage": r.coverage,
                          "est_gib": round(r.est_gib, 2), "est_source": r.est_source,
                          "commit_gib": round(r.commit_gib, 2)} for r in self.live.values() if r.state != "queued"],
                "recent_runs": self.ledger.recent_runs(12),
                "apps": self.apps_rows, "decisions": self.ledger.recent_decisions(25),
                "events": list(self.events)[:30], "history": list(self.history)[-180:],
            }

    def action(self, path, b):
        with self.lock:
            now = time.monotonic()
            if path == "/api/session":
                s = self.sessions[b["key"]]
                if b.get("cls") in CLASSES and b["cls"] != s.cls:
                    self.decide("session_class", s.key, s.cls, b["cls"], b["cls"], None, "set by Stan")
                    s.cls = b["cls"]
                if "paused" in b and bool(b["paused"]) != s.paused:
                    s.paused = bool(b["paused"])
                    self.decide("session_pause" if s.paused else "session_resume", s.key, reason=
                                "Stan paused the session: CPU rate 1/10000, processes stay alive" if s.paused
                                else "resumed")
                self.allocate()
            elif path == "/api/provider":
                self.set_provider_paused(safe(b["name"]), bool(b["paused"]))
            elif path == "/api/cap":
                c = self.cfg["cpu"]
                v = max(c["minimum_cap_percent"], min(c["maximum_cap_percent"], float(b["cap"])))
                self.cap = replace(self.cap, cap=v, healthy_since=None)
                self.apply_cap("manual_cap", f"set by Stan to {v:.0f}%")
            elif path == "/api/world":
                self.set_world(b["cpus"], "set by Stan")
            elif path == "/api/hold":
                self.hold = bool(b["on"])
                self.decide("admission_hold", "queue", requested=self.hold, reason="set by Stan")
            elif path == "/api/inject":
                secs = max(0, min(300, int(b.get("seconds", 30))))
                level = b.get("level", "degraded") if b.get("level") in ("ok", "degraded", "severe") else "degraded"
                self.inject = (now + secs, level) if secs else None
                self.decide("inject", "experience", requested={"level": level, "seconds": secs},
                            reason="test sample injected by Stan (acceptance: fast back-off, slow recovery)")
            elif path == "/api/pool_priority":
                if b.get("priority") not in ("below_normal", "normal"):
                    raise ValueError("priority must be below_normal or normal")
                self.set_pool_priority(b["priority"], "set by Stan")
            elif path == "/api/allocator":
                self.allocator_on = bool(b["on"])
                self.decide("allocator", "sessions", requested=self.allocator_on,
                            reason="per-session caps on" if self.allocator_on else "off: kernel per-thread sharing")
                self.allocate()
            elif path == "/api/cancel":
                run = self.live[b["run_id"]]
                run.cancelled = "cancelled by Stan from the dashboard"
            elif path == "/api/media":
                level = P.media_window_level(b, self.cfg["observation"])
                self.media = {"t": now, "level": level, "raw": b}
            elif path == "/api/rollback":
                self.rollback("requested by Stan")
            elif path == "/api/resume_control":
                self.control = True
                self.set_pool_priority(self.pool_priority, "control resumed")
                self.apply_cap("resume_control", "control resumed")
            elif path == "/api/shutdown":
                threading.Thread(target=self.shutdown, daemon=True).start()
            else:
                raise KeyError(path)
        return {"ok": True}

    def rollback(self, why):
        """Remove every CPU control the Guardian set. Member priority goes back to normal explicitly, because
        clearing a priority limit does not restore the processes it already changed (E9)."""
        self.control = False
        for s in self.sessions.values():
            self.apply_session(s, None, 1)
            s.paused = False
        for name, p in self.providers.items():
            p["job"].set_cpu()
            p["paused"] = False
        self.root.set_cpu()
        self.root.set_limits(priority="normal")
        self.pool_priority_readback = self.root.limits()["priority"]
        # a miniature world (--world-cpus) is the demo's safety boundary, not a control: keep it
        wj.set_job_affinity(self.root, self.mask)
        self.decide("rollback", "AllAgents", requested="no caps, normal priority, " +
                    (f"affinity kept to the {self.world}-CPU demo world" if self.mask else "no affinity"),
                    readback=self.root.cpu().get("mode"), reason=why)

    def shutdown(self):
        """Leave no throttle behind: work still running after the daemon exits must not stay capped or paused."""
        with self.lock:
            try:
                for s in self.sessions.values():
                    self.apply_session(s, None, 1)
                for p in self.providers.values():
                    p["job"].set_cpu()
                self.root.set_cpu()
                self.decide("shutdown", "AllAgents", reason="daemon stopping: caps and pauses removed, "
                            "below_normal kept so leftover work still yields to the foreground")
            except OSError as e:
                self.log(f"shutdown cleanup failed: {e}")
        if self.probe_proc:
            self.probe_proc.kill()
        self.stop.set()
        time.sleep(0.3)
        os._exit(0)

    def run_forever(self):
        # the controller has to keep answering while the agents it governs fill every CPU (control off). The probe
        # still starts at NORMAL: only IDLE and BELOW_NORMAL parents pass their priority class to children.
        wj.set_own_priority("above_normal")
        self.open_tree()
        if self.probe_enabled:
            self.start_probe()
            t0 = time.monotonic()
            while self.probe_last is None and time.monotonic() - t0 < 3:  # first decision waits for the sensor
                time.sleep(0.1)
        server = ExclusiveHTTPServer(("127.0.0.1", self.port), make_handler(self))
        loops = [self.tick_loop, self.admit_loop, self.accept_loop, server.serve_forever]
        if self.apps_enabled:
            loops.append(self.apps_loop)
        for f in loops:
            threading.Thread(target=f, daemon=True).start()
        (self.home / "daemon.json").write_text(json.dumps({
            "pid": os.getpid(), "instance": self.instance, "pipe": pipe_name(self.instance), "port": self.port,
            "world_cpus": self.world, "started": time.time()}), encoding="utf-8")
        self.log(f"Guardian {self.instance} up: pipe {pipe_name(self.instance)}, dashboard http://127.0.0.1:{self.port}/")
        try:
            while not self.stop.wait(0.5):
                pass
        except KeyboardInterrupt:
            self.shutdown()


class ExclusiveHTTPServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR lets a second process bind a port that is already listening, and connections then go
    # to whichever socket Windows picks (seen 2026-10-13: another local server answered on 8766). Fail instead.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def make_handler(g):
    class Api(BaseHTTPRequestHandler):
        server_version = "Guardian/1"

        def log_message(self, *args):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self):
            # Host check stops DNS rebinding; the token header stops cross-site requests from other tabs
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0]
            return host in ("127.0.0.1", "localhost")

        def _authed(self):
            return secrets.compare_digest(self.headers.get("X-Guardian-Token", ""), g.token)

        def do_GET(self):
            path = self.path.split("?")[0]
            if not self._allowed():
                return self._send(403, {"error": "host"})
            if path == "/":
                html = DASHBOARD.read_text(encoding="utf-8").replace("__GUARDIAN_TOKEN__", g.token)
                return self._send(200, html.encode(), "text/html; charset=utf-8")
            if not self._authed():
                return self._send(401, {"error": "token"})
            if path == "/api/state":
                return self._send(200, g.state())
            return self._send(404, {"error": "not found"})

        def do_POST(self):
            if not self._allowed() or not self._authed():
                return self._send(403, {"error": "forbidden"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > 65536:
                return self._send(413, {"error": "too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                return self._send(200, g.action(self.path.split("?")[0], body))
            except KeyError as e:
                return self._send(404, {"error": f"unknown {e}"})
            except (ValueError, TypeError) as e:
                return self._send(400, {"error": str(e)})
            except OSError as e:
                return self._send(500, {"error": str(e)})
    return Api


def main(argv=None):
    ap = argparse.ArgumentParser(description="Guardian daemon: one big job for agent work, foreground first.")
    ap.add_argument("--instance", default="main")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--world-cpus", type=int, help="miniature world: pool and probe use only the top N CPUs")
    ap.add_argument("--initial-cap", type=float)
    ap.add_argument("--max-cap", type=float, help="upper cap in percent of the world (default 95)")
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--no-apps", action="store_true")
    a = ap.parse_args(argv)
    if ping(a.instance):
        print(f"Guardian {a.instance} is already running", file=sys.stderr)
        return 1
    over = {"cpu": {"maximum_cap_percent": a.max_cap}} if a.max_cap else {}
    Guardian(a.instance, a.world_cpus, a.initial_cap, over, a.port, not a.no_probe, not a.no_apps).run_forever()
    return 0
