"""Guardian daemon: owns the one big agent job, launches agent commands into it, runs the 1 Hz control loop and
serves the local dashboard API.

Job tree (named in the session namespace so whereami can find it; other processes of the user may only query it,
and a daemon refuses to start while another process holds its AllAgents job open, see winjob.named_job_sddl):
  Local\\Guardian.<instance>.AllAgents          below_normal priority + dynamic hard cap: the one big job
    Local\\Guardian.<instance>.p.<provider>     pause or resume a whole provider (rate 1 = paused)
      Local\\Guardian.<instance>.s.<p>.<s>      per-session hard cap from weighted max-min, relative to the pool
        unnamed run job per command             cancel = TerminateJobObject; CPU, peak commit
A CLI that was started outside Guardian joins the tree when its hook asks (op "adopt"): the daemon assigns the
running CLI and its children to the session job, and what the CLI starts later inherits it.
Running app UIs (Claude desktop, the Codex app, Cursor) stay where they are: a process cannot leave its job, and
a cap on their own app job would also slow their UI. apps.py only measures them, and adopt refuses them.
The CLIs the Claude app and the Codex app run for their agent sessions are the exception: each goes into a desktop
job of its own, Local\\Guardian.<instance>.d.<p>.desk-<pid>, which nests under the app's job and so sits outside
AllAgents. allocate() caps those jobs in absolute cores.
A session Stan marks exempt (dashboard or guardctl, never srun or a hook) gets no session cap for a set time, its
queued runs skip the admission gates, and the runs it starts meanwhile go into run jobs outside the tree, so the pool
cap does not reach them either; what already runs inside the tree stays under the pool cap.
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
from . import providers as PV
from . import winjob as wj
from .client import CLASSES, handshake, home_dir, pipe_name, ping, send_json
from .ledger import Ledger

REPO = Path(__file__).resolve().parents[2]
DASHBOARD = REPO / "dashboard" / "guardian.html"
PROBE = Path(__file__).with_name("probe.py")
PROVIDERS = ("claude", "codex", "cursor", "grok", "gemini", "antigravity", "other")
CREATE_NO_WINDOW, CREATE_NEW_CONSOLE = 0x08000000, 0x00000010
GiB = 2**30
CONHOST = r"C:\Windows\System32\conhost.exe"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
# Win32_Process.Create starts the command under the WMI provider host, in no job and in the caller's session
# (measured 2026-10-15). Command line and directory arrive through the environment, so nothing is quoted into the
# script. conhost --headless expands %NAME% in the command line it runs when NAME is a defined variable; Create keeps
# both the command line and the directory as given (measured 2026-10-15).
WMI_CREATE = ("$ErrorActionPreference = 'Stop'; $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
              "-Arguments @{CommandLine = $env:GUARDIAN_RELAUNCH_COMMAND; "
              "CurrentDirectory = $env:GUARDIAN_RELAUNCH_CWD}; \"$($r.ReturnValue) $($r.ProcessId)\"")


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


def sweep_targets(pids, table, path, own=(), skip=()):
    """The children that join an adopted CLI's job: not Guardian's own, not skipped, and neither a desktop app nor
    a helper with an app above it, since Guardian never puts the apps in a job."""
    return [p for p in pids if p not in own and p not in skip and not PV.app_among(p, table, path)]


def desktop_sweep(pid, table, path, own=()):
    """The children that join a desktop CLI's job. The app above the CLI does not count against them: the table is
    cut at the CLI, so only an app between the CLI and a child keeps that child out."""
    if pid not in table:
        return []
    cut = dict(table)
    cut[pid] = (None, table[pid][1])
    return sweep_targets(wj.descendants(pid, cut)[1:], cut, path, own)


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


class StartRefused(Exception):
    pass


def taken_reason(e):
    """Why Guardian will not use a named job that was already there (wj.JobTaken), for logs and refusals. A job's
    name lasts only while some process holds a handle to it (measured 2026-10-13: member processes alone do not
    keep it), so an existing name means a handle is still open somewhere."""
    who = (f"processes {', '.join(map(str, e.pids))} are in it" if e.pids else
           "no process is in it" if e.pids == [] else "its processes cannot be read")
    if isinstance(e, wj.NameRedirected) and e.real and e.expected:
        return (f"the name of job {e.name} leads to {e.real} instead of {e.expected}, so a symbolic link at the name "
                f"redirects it, and Guardian refuses the name")
    if isinstance(e, wj.NameRedirected):
        return (f"Guardian could not read where the name of job {e.name} leads, so it cannot rule out a symbolic link "
                f"there and refuses the name")
    if isinstance(e, wj.NameNotJob):
        return (f"the name of job {e.name} is held by an object that is not a job, so some process still holds that "
                f"object open")
    if isinstance(e, wj.NameUnusable):
        return (f"Guardian could not create job {e.name}: {e.detail} (winerror {e.winerror}), and no job opens under "
                f"that name. Another process may hold a symbolic link or another object there, or this was a resource "
                f"error")
    if isinstance(e, wj.JobLocked):
        return (f"job {e.name} already exists, this process may not open it with full access, and some process holds "
                f"it open, for example a running daemon of this instance, a script reading it, or another process "
                f"that created it with a restrictive DACL; {who}")
    try:
        elevated = wj.is_elevated()
    except OSError:
        elevated = False
    if elevated:
        return (f"job {e.name} already exists; this daemon runs elevated, and an elevated open cannot tell Guardian's "
                f"DACL from a permissive one; {who}. Guardian still does not take over a job it did not create")
    return (f"job {e.name} already exists and its DACL lets other processes change it; {who}. Guardian never takes "
            f"over a job it did not create")


class Session:
    def __init__(self, provider, name, cls, job):
        self.provider, self.name, self.cls, self.job = provider, name, cls, job
        self.key = f"{provider}/{name}"
        self.paused = False
        self.applied = None        # None = no CPU control, "paused", ("rel", fraction of the pool) or ("abs", cores)
        self.usage = 0.0
        self.prev = None
        self.live_runs = 0
        self.t_last = time.time()
        self.desktop = False       # a job outside AllAgents, capped in absolute cores: a desktop job, or a nested one
        self.nested = False        # a hook-adopted CLI's job, nested under the job the CLI put itself in
        self.app_pids = set()      # the desktop CLI's parents when it was placed, the app's root among them
        self.exempt_until = None   # wall time an exemption ends; cls is "exempt" until then
        self.cls_before = None     # the class to go back to when it ends
        self.cpu_s = 0.0           # CPU seconds so far, runs outside the tree included (fair queue order)
        self.outside_done_s = 0.0  # CPU seconds of runs outside the tree that have ended


class Run:
    def __init__(self, run_id, session, argv, cwd, env, console, est, src, unprofiled, label, fingerprint):
        self.run_id, self.session, self.argv, self.cwd, self.env = run_id, session, argv, cwd, env
        self.console, self.est_gib, self.est_source, self.unprofiled = console, est, src, unprofiled
        self.label, self.fingerprint = label, fingerprint
        self.state, self.reason, self.numbers = "queued", "", {}
        self.est_s, self.est_s_source = None, None
        self.outside = False       # started while its session was exempt: a run job outside the tree
        self.t_request = time.monotonic()
        self.t_start = None
        self.admitted = threading.Event()
        self.cancelled = None
        self.job = self.proc = None
        self.commit_gib = 0.0
        self.coverage = None
        self.send_lock = threading.Lock()


class Adopted:
    """A CLI that was already running when it asked to join. Guardian did not start it, so it is never cancelled
    from here; the row ends when the process exits."""

    def __init__(self, run_id, session, pid, handle, label, coverage):
        self.run_id, self.session, self.pid, self.handle = run_id, session, pid, handle
        self.label, self.coverage = label, coverage
        self.state, self.est_gib, self.est_source, self.commit_gib = "adopted", 0.0, "adopted", 0.0
        self.proc = self.job = self.cancelled = None


class Guardian:
    def __init__(self, instance="main", world_cpus=None, initial_cap=None, cfg_over=None, port=8765, probe=True,
                 apps=True, desktop=None):
        self.instance, self.port = safe(instance, "main"), port
        # desktop jobs: on by default for the main instance only, so a test instance never reaches into the apps
        self.desktop_on = self.instance == "main" if desktop is None else bool(desktop)
        self.desktop_skip = set()  # desktop CLI pids refused or failed once; not tried again while they run
        self.marked_apps = set()   # app pids that keep their agent commands out (see agent_commands), logged once
        self.home = home_dir(self.instance)
        self.home.mkdir(parents=True, exist_ok=True)
        self.cfg = P.merged(P.DEFAULTS, cfg_over)
        if self.cfg["queue"]["order"] not in P.QUEUE_ORDERS:
            raise SystemExit(f"queue order must be one of {', '.join(P.QUEUE_ORDERS)}")
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
        self.adopted = {}  # CLI pid -> Adopted
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
        self.outside = None  # CPU of the processes outside Guardian's jobs, top image names first
        self.last_launch, self.launch_starts = -1e9, []
        self.pool_priority = c["pool_priority"]
        self.pool_priority_readback = None
        self.agent_io = self.cfg["io"]["agent_io_priority"]
        self.agent_memory = self.cfg["memory"]["agent_memory_priority"]
        self.niced = {}  # pid in a Guardian job -> whether Windows took its I/O and memory priority
        self.token = secret(self.home / "http-token", 24)
        self.authkey = secret(self.home / "pipe-authkey", 32).encode()
        self.stop = threading.Event()
        self.busy_fn = wj.system_busy()
        self.busy_fn()
        self.last_core_ok = time.monotonic()
        self.pool_cores = 0.0
        self.mem = P.MemState()    # the memory pressure ladder
        self.agents_gib = 0.0      # private commit of every process in Guardian's jobs
        self.trimmed = {}          # pid -> when its working set was last trimmed
        self.trimmed_gib = 0.0     # working set the trims took out of RAM since start
        self.mem_paused = set()    # sessions the ladder paused (Stan's own pauses are Session.paused)

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
        try:
            self.root = wj.Job.create(self.jobname("AllAgents"))
        except wj.JobTaken as e:
            why = taken_reason(e)
            self.decide("startup_refused", "AllAgents", readback={"pids": e.pids}, error=str(e), reason=why)
            if isinstance(e, wj.NameUnusable):
                raise StartRefused(f"{why}. End the process that created that object or link, or start with another "
                                   f"--instance")
            fix = (f"{why}. End the process that holds the job open (the old daemon or the script), or start with "
                   f"another --instance")
            dacl = getattr(e, "guardian_dacl", None)
            if isinstance(e, wj.JobLocked) and dacl:
                fix += (". The job carries Guardian's DACL, so an elevated prompt can still open it with full access "
                        "to end its processes")
            elif isinstance(e, wj.JobLocked) and dacl is False:
                fix += ". The job does not carry Guardian's DACL"
            elif isinstance(e, wj.JobLocked):
                fix += (". If the job carries Guardian's DACL, an elevated prompt can still open it with full access "
                        "to end its processes; its DACL could not be read here")
            raise StartRefused(fix)
        self.set_pool_priority(self.pool_priority, "startup: agent work yields to the foreground (E9)")
        before = self.root.limits()["flags"] & wj.LIMIT_AFFINITY
        wj.set_job_affinity(self.root, self.mask)
        if self.mask or before:
            self.decide("affinity", "AllAgents", requested=hex(self.mask) if self.mask else None,
                        readback=hex(self.root.extended().Basic.Affinity) if self.mask else None,
                        reason=f"world = {self.world} of {wj.NCPU} logical CPUs")
        self.apply_cap("startup", f"initial cap {self.cap.cap:.0f}% of {self.world} CPUs")
        if self.cfg["memory"]["job_commit_hard_limit_gib"]:
            self.set_hard_limit(self.cfg["memory"]["job_commit_hard_limit_gib"], "startup: job_commit_hard_limit_gib")
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
        for s in self.sessions.values():
            if s.desktop:  # outside AllAgents, so the root's limit does not reach them
                self.desktop_priority(s, name)

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

    def set_hard_limit(self, gib, reason):
        """AllAgents' job memory limit, or none: past it the agents' allocations fail, so it is off unless Stan sets
        it. It counts every process in the tree, and leaves desktop and nested jobs out."""
        before = self.root.limits()["mem_max_bytes"]
        err = None
        try:
            if gib:
                self.root.set_limits(mem_max_bytes=gib * GiB)
            else:
                self.root.set_limits(clear_mem=True)
        except OSError as e:
            err = str(e)
        rb = self.root.limits()["mem_max_bytes"]
        self.decide("memory_limit", "AllAgents", round(before / GiB, 2) if before else None, gib,
                    round(rb / GiB, 2) if rb else None, err, reason)

    def set_world(self, n, reason):
        """Let the agents use only the top n logical CPUs, so the rest stay free for the foreground (for example a
        remote desktop). The cap stays a percent of the world, so the cores it allows move with n. Like the world
        given at startup, it holds while control is off; the probe follows it to keep seeing the pool's CPUs."""
        self.world = max(1, min(wj.NCPU, int(n)))
        self.mask = sum(1 << i for i in range(wj.NCPU - self.world, wj.NCPU)) if self.world < wj.NCPU else None
        # widening sets every CPU explicitly: clearing the limit would leave running members on the old, smaller mask
        mask = self.mask or (1 << wj.NCPU) - 1
        wj.set_job_affinity(self.root, mask)
        for s in self.sessions.values():
            if s.desktop:
                wj.set_job_affinity(s.job, mask)
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
            try:
                job = wj.Job.create(self.jobname("p", name))
            except wj.JobTaken as e:
                self.decide("provider_refused", name, readback={"pids": e.pids}, error=str(e), reason=taken_reason(e))
                raise
            job.set_cpu()
            p = self.providers[name] = {"name": name, "job": job, "paused": False}
        return p

    def session(self, provider, name, cls):
        key = f"{provider}/{name}"
        s = self.sessions.get(key)
        if s is None:
            self.provider(provider)
            try:  # a name another process still holds open (a dropped session's job) or took first
                job = wj.Job.create(self.jobname("s", provider, name))
            except wj.JobTaken as e:
                self.decide("session_refused", key, readback={"pids": e.pids}, error=str(e), reason=taken_reason(e))
                raise
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
        budget = self.cap.cap / 100 * self.world
        for s in [x for x in self.sessions.values() if x.provider == name]:
            if s.desktop:  # the provider job does not hold desktop jobs
                self.apply_session(s, self.desktop_want(s, self.alloc.caps.get(s.key), budget), budget)
            else:  # nor the runs a session started outside the tree while exempt; this holds with control off too
                # the flag as set, not the request: when the provider's own pause failed, nothing would release them
                self.hold_outside(s, p["paused"] or s.paused or (s.cls != "exempt" and s.key in self.mem_paused))

    def hold_outside(self, s, held):
        """Pause or release the runs session s started while it was exempt, or those of every session when s is None
        (rollback and shutdown, which also reach the runs of a session that has left). Each sits in a run job of its
        own outside the tree, where neither the session's job nor its provider's job reaches. A run whose main process
        has ended while its children go on is in self.lingering, and its job stays open until they end too, so it is
        held and released here as well. Returns the first error."""
        err = None
        for r in [r for r in self.live.values() if r.state == "running"] + self.lingering:
            if (s is None or r.session is s) and getattr(r, "outside", False) and r.job:
                try:
                    r.job.set_cpu_rate(1) if held else r.job.set_cpu()
                except OSError as e:
                    err = err or str(e)
        return err

    def apply_session(self, s, want, budget):
        err = None
        try:
            if want == "paused":
                s.job.set_cpu_rate(1)
            elif want is None:
                s.job.set_cpu()
            elif want[0] == "abs":
                s.job.set_cpu(max_cores=want[1])  # a desktop job's parent, the app's job, has no CPU rate
            else:
                s.job.set_cpu(max_cores=want[1] * wj.NCPU)  # nested caps are a fraction of the parent (E8b)
        except OSError as e:
            err = str(e)
        # the runs it started while exempt follow the pause of the session and of its provider, whatever its class now
        err = self.hold_outside(s, want == "paused" or self.providers[s.provider]["paused"]) or err
        rb = s.job.cpu()
        before, s.applied = s.applied, (s.applied if err else want)
        shown = lambda v: v if not isinstance(v, tuple) else f"{v[1] * (1 if v[0] == 'abs' else budget):.2f} cores"
        self.ledger.decision("session_cap", s.key, shown(before), shown(want), rb.get("mode"), err,
                             ("exempt: no session cap" if s.cls == "exempt" else f"weighted max-min, class {s.cls}") +
                             (", nested job" if s.nested else ", desktop job" if s.desktop else ""),
                             P.POLICY_VERSION)

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
        tree = max(0.0, (cpu_s - prev[1]) / dt)
        with self.lock:
            outside = collections.Counter()
            for r in self.live.values():
                if getattr(r, "outside", False) and r.job and r.state == "running":
                    outside[r.session.key] += r.job.accounting()["cpu_s"]
            for s in self.sessions.values():
                a = s.cpu_s = s.job.accounting()["cpu_s"] + s.outside_done_s + outside[s.key]
                s.usage = max(0.0, (a - s.prev[1]) / max(1e-3, now - s.prev[0])) if s.prev else 0.0
                s.prev = (now, a)
            # desktop jobs sit outside AllAgents, so the pool adds their use to what the tree's root job counts
            self.pool_cores = tree + sum(x.usage for x in self.sessions.values() if x.desktop and x.cls != "exempt")
            for r in list(self.live.values()):
                if r.state == "running" and r.job:
                    try:
                        r.commit_gib = r.job.memory_usage()[0] / GiB
                    except OSError:
                        pass
                elif r.state == "adopted":
                    if wj.has_exited(r.handle):
                        self.end_adopted(r)
                    else:
                        m = wj.process_memory(r.pid)
                        r.commit_gib = m[0] / GiB if m else 0.0
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
                         pool_priority=self.pool_priority_readback, ncpu=self.world, machine_cpus=wj.NCPU)
            members = self.members()
            mem = {pid: wj.process_memory(pid) for pid in members}
            self.agents_gib = sum(m[0] for m in mem.values() if m) / GiB
            self.end_exemptions()
            if self.control:
                self.cap, d = P.cap_step(self.cap, s, self.cfg)
                if d:
                    self.apply_cap(d["kind"], d["reason"])
                self.mem, d = P.memory_step(self.mem, s, self.agents_gib, self.cfg)
                if d:
                    self.decide(d["kind"], "agent memory", requested={"rung": d["rung"]}, reason=d["reason"])
                self.memory_ladder(mem, now)
                self.allocate()
                self.nice_sweep(members)
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
        # a desktop session counts as active by its use alone: its CLI runs as long as the app's tab is open, and
        # every idle tab would otherwise ask for a share of the budget and squeeze the busy ones
        active = {k: {"allocation_weight": weights.get(s.cls, 5), "usage": s.usage,
                      "paused": s.paused or k in self.mem_paused or self.providers[s.provider]["paused"]}
                  for k, s in self.sessions.items()
                  if s.cls != "exempt" and (s.usage > 0.05 or (s.live_runs and not s.desktop))}
        if self.allocator_on:
            self.alloc, _ = P.allocate(self.alloc, budget, active, self.cfg)
        else:
            self.alloc = P.AllocState()
        for k, s in self.sessions.items():
            cap = self.alloc.caps.get(k) if k in active else None
            if s.cls == "exempt":
                want = "paused" if s.paused or self.providers[s.provider]["paused"] else None
            elif s.desktop:
                want = self.desktop_want(s, cap, budget)
            elif s.paused or k in self.mem_paused:
                want = "paused"
            else:
                want = None if cap is None or cap >= 0.98 * budget else ("rel", round(cap / budget, 3))
            same = want == s.applied or (isinstance(want, tuple) and isinstance(s.applied, tuple)
                                         and abs(want[1] - s.applied[1]) < (0.02 * budget if s.desktop else 0.02))
            if not same:
                self.apply_session(s, want, budget)

    def set_exempt(self, s, minutes, reason):
        if s.cls != "exempt":
            s.cls_before = s.cls
        s.exempt_until = time.time() + minutes * 60
        until = time.strftime("%H:%M", time.localtime(s.exempt_until))
        self.decide("session_class", s.key, s.cls_before, "exempt", f"until {until}", None,
                    f"{reason} for {minutes:g} minutes: no session cap, queue gates skipped, new runs outside the pool")
        s.cls = "exempt"
        self.end_memory_pause(s.key, "Stan exempted the session")

    def end_exemptions(self):
        for s in self.sessions.values():
            if s.cls == "exempt" and time.time() >= s.exempt_until:
                s.cls, s.exempt_until = s.cls_before or "normal", None
                self.decide("session_class", s.key, "exempt", s.cls, s.cls, None,
                            "exemption ended; runs already started outside the pool stay there until they end")

    def memory_ladder(self, mem, now):
        """Act on memory_step's rung. Rung 1 trims working sets while pressure_trim is on, largest first, each process
        at most once per spacing. Rung 2 also pauses the session holding the most private commit, one session, until
        the pressure is over, the rung drops, or the paused session holds nothing any more (its run ended, or its CLI
        exited while a run of it outside the tree goes on). A pause is a CPU rate of 0.01%, not a suspend: it slows
        growth and frees nothing. An exempt session, one Stan paused or one holding no private commit is never picked."""
        m = self.cfg["memory"]
        for pid in self.trimmed.keys() - mem.keys():
            del self.trimmed[pid]
        if self.mem.rung >= 1 and m["pressure_trim"]:
            freed = n = 0
            for pid, x in sorted(mem.items(), key=lambda kv: -(kv[1][1] if kv[1] else 0)):
                if x and now - self.trimmed.get(pid, -1e9) >= m["pressure_trim_spacing_seconds"]:
                    self.trimmed[pid] = now
                    got = wj.trim_working_set(pid)
                    if got is not None:
                        freed, n = freed + got, n + 1
            if n:
                self.trimmed_gib += freed / GiB
                self.decide("memory_trim", "agent processes", requested=n, readback=round(freed / GiB, 2),
                            reason=f"{n} working sets trimmed, {freed / GiB:.2f} GiB out of RAM; their commit stays")
        if self.mem.rung >= 2:
            # drop_ended ends the pause of a desktop session it drops, but a session in the tree outlives its runs, and
            # a desktop one stays while a run of it outside the tree goes on. One that holds no private commit any
            # more (the pick's measure) would block every other pause, so its pause ends and the pick below goes on
            for k in sorted(self.mem_paused):
                x = self.sessions.get(k)
                try:
                    pids = x.job.pids() if x is not None else []
                except OSError:
                    continue  # its processes cannot be listed, so the pause stays
                if any(mem.get(p) is None for p in pids):
                    continue  # one could not be read this pass (or joined after it): unknown is not empty
                if not sum(mem[p][0] for p in pids):
                    self.end_memory_pause(k, "the paused session holds no private commit any more"
                                          if x is not None else "the session ended")
        if self.mem.rung >= 2 and not self.mem_paused:
            held = {}
            for k, x in self.sessions.items():
                if x.cls == "exempt" or x.paused:
                    continue
                try:
                    pids = x.job.pids()
                except OSError:
                    continue
                got = sum(mem[p][0] for p in pids if mem.get(p))
                if got:  # pausing a session that holds nothing frees nothing and would block every other pause
                    held[k] = got
            if held:
                k = max(held, key=held.get)
                self.mem_paused.add(k)
                self.decide("memory_pause", k, requested="rate 1", readback=round(held[k] / GiB, 2),
                            reason="memory pressure lasted: the session holding the most private commit is paused, "
                                   "and its processes keep their memory")
        elif self.mem.rung < 2 and self.mem_paused:
            why = "memory pressure over" if self.mem.since is None else "pressure_pause turned off"
            for k in sorted(self.mem_paused):
                self.end_memory_pause(k, why)

    def end_memory_pause(self, key, why):
        """Take key off the ladder's pause. The ladder pauses one session at a time, so while pressure lasts its next
        pass may pick the next largest session."""
        if key in self.mem_paused:
            self.mem_paused.discard(key)
            self.decide("memory_resume", key, reason=why)

    def desktop_want(self, s, cap, budget):
        """A desktop job's cap in absolute cores, since the app's job above it has no CPU rate: the allocator's cap,
        or the whole budget when it sets none. While control is on, a desktop session never runs uncapped."""
        if s.paused or s.key in self.mem_paused or self.providers[s.provider]["paused"]:
            return "paused"
        if not self.control or s.cls == "exempt":
            return None
        return "abs", round(budget if cap is None else min(cap, budget), 2)

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
        from .apps import AppObserver, LoadObserver
        obs, load = AppObserver(), LoadObserver()
        while not self.stop.wait(2.0):
            try:
                with self.lock:
                    members = self.members() | self.own_pids()  # the daemon and its probe
                    for r in list(self.live.values()) + self.lingering:  # runs outside the tree: run jobs of their own
                        if getattr(r, "outside", False) and r.job:
                            try:
                                members.update(r.job.pids())
                            except OSError:
                                pass
                self.outside = load.sample(members)
            except Exception as e:
                self.outside = {"error": str(e)}
            try:
                rows = obs.sample()
                with self.lock:
                    desk = [(x.app_pids, x.usage) for x in self.sessions.values() if x.desktop]
                    tree = self.pool_cores - sum(u for _, u in desk)
                for r in rows:
                    if r.get("hosts_guardian") and r.get("cores") is not None:
                        # the daemon was started from inside this app, so its job also holds the agent pool
                        r["cores"] = round(max(0.0, r["cores"] - tree), 2)
                        r["coverage"] += "; Guardian pool subtracted (daemon runs inside this app)"
                    mine = [u for pids, u in desk if r.get("root_pid") in pids]
                    if mine and r.get("cores") is not None:
                        # a desktop job nests under the app's job, so the app's figure also holds what the pool counts
                        r["cores"] = round(max(0.0, r["cores"] - sum(mine)), 2)
                        r["coverage"] += "; desktop jobs subtracted (Guardian counts them in its pool)"
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
        weights = self.cfg["cpu"]["allocation_weights"]
        waiting = [{"run": r, "cls": r.session.cls, "t_request": r.t_request, "est_s": r.est_s,
                    "share": r.session.cpu_s / weights.get(r.session.cls, 5)} for r in self.queue]
        for run in [x["run"] for x in P.queue_order(waiting, self.cfg["queue"]["order"], now)]:
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
        if s.cls == "exempt":
            return True, ""
        ok, reason, run.numbers = P.admission(run.est_gib, self.sample, unused, unused, self.cap, self.cfg, self.hold,
                                              agents_gib=self.agents_gib)
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
        # No authkey on the Listener: with one, accept() runs the HMAC handshake on this thread, and a client that
        # connects and then stalls holds every other client. greet() runs it per connection, with a deadline.
        listener = Listener(pipe_name(self.instance), family="AF_PIPE")
        while not self.stop.is_set():
            try:
                conn = listener.accept()
            except Exception as e:  # a dropped connect
                self.log(f"pipe accept failed: {e.__class__.__name__}")
                continue
            threading.Thread(target=self.greet, args=(conn,), daemon=True).start()

    def greet(self, conn):
        try:
            handshake(conn, self.authkey, server=True)
        except Exception as e:  # wrong or no key, no answer before the deadline, or gone
            self.log(f"pipe handshake failed: {e.__class__.__name__}")
            conn.close()
            return
        self.serve(conn)

    def serve(self, conn):
        try:
            req = json.loads(conn.recv_bytes(1 << 22)[1:])
            if req.get("op") == "ping":
                send_json(conn, {"ok": True, "instance": self.instance, "pid": os.getpid(), "world": self.world})
            elif req.get("op") == "run":
                self.serve_run(conn, req)
            elif req.get("op") == "adopt":
                self.serve_adopt(conn, req)
            elif req.get("op") == "whereis":
                send_json(conn, self.whereis(int(req.get("pid") or 0)))
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
            try:
                s = self.session(provider, name, cls)
            except wj.JobTaken as e:  # session() logged it; the client prints the reason and runs nothing
                return send_json(conn, {"event": "error", "kind": "session",
                                        "message": f"Guardian refused session {provider}/{name}: {taken_reason(e)}"})
            est, src, _ = P.estimate(self.ledger.profile(fingerprint), req.get("est_gib"), self.cfg)
            run = Run(uuid.uuid4().hex[:12], s, argv, req.get("cwd"), req.get("env"), bool(req.get("console")),
                      est, src, src == "exploration", label, fingerprint)
            run.est_s, run.est_s_source = P.estimate_seconds(self.ledger.durations(fingerprint), self.cfg)
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
        # a desktop or nested session too: its job sits under another job, so the tree's chain could not reach it
        run.outside = s.cls == "exempt"
        chain = [run.job] if run.outside else [self.root, self.providers[s.provider]["job"], s.job, run.job]
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
        with self.lock:  # a pause after the admission either finds the run running or is found here
            run.t_start, run.state = time.monotonic(), "running"
            if run.outside and (s.paused or self.providers[s.provider]["paused"]):
                err = self.hold_outside(s, True)
                self.log(f"run {run.run_id} ({s.key}) starts paused, outside the pool"
                         + (f" [error {err}]" if err else ""))
        in_root, in_session = wj.in_job(pid, self.root.h), wj.in_job(pid, s.job.h)
        prio = wj.priority_class(pid)
        if run.outside:
            run.coverage = ("exempt, outside the pool" if not in_root else "partial") + f", priority {prio}"
        else:
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
            if run.outside and cpu_s:
                run.session.outside_done_s += cpu_s
            run.state = state
            if run.job:
                if lingering and state != "cancelled":
                    self.lingering.append(run)
                else:
                    run.job.close()
        self.ledger.run_update(run.run_id, state=state, t_end=time.time(), exit_code=rc, cpu_s=cpu_s,
                               peak_commit_bytes=peak, reason=run.cancelled or run.reason or "")

    # ---- adopting a CLI that is already running --------------------------------------------------------------
    def serve_adopt(self, conn, req):
        provider = safe(req.get("provider"), "other").lower()
        provider = provider if provider in PROVIDERS else "other"
        cls = req.get("cls") if req.get("cls") in CLASSES else "normal"
        try:
            pid = int(req["pid"])
        except (KeyError, TypeError, ValueError):
            return send_json(conn, {"ok": False, "state": "refused", "reason": "no pid given"})
        skip = {int(x) for x in (req.get("skip") or [])[:64] if str(x).isdigit()}
        send_json(conn, self.adopt(pid, provider, safe(req.get("session")), cls, safe(req.get("via"), "hook"), skip))

    def own_pids(self):
        own = {os.getpid()}
        if self.probe_proc:
            own.add(self.probe_proc.pid)
        return own

    def own_or_parent(self, pid, table):
        return pid in self.own_pids() or pid in wj.ancestors(os.getpid(), table)

    def adopt_refusal(self, pid, table):
        if self.own_or_parent(pid, table):
            return "that process is the Guardian daemon or one of its parents"
        app = PV.app_among(pid, table, wj.image_path)
        if app:
            return f"the {app} is the process or one of its parents, and Guardian never puts the apps in a job"
        return None

    def assign_chain(self, pid, chain):
        """Outer job first, skipping jobs the process is already in, so the nesting matches spawn_in_jobs."""
        try:
            for j in chain:
                if not wj.in_job(pid, j.h):
                    j.assign(pid)
        except OSError as e:
            return str(e)
        return None

    def adopt(self, pid, provider, name, cls="normal", via="hook", skip=()):
        """Put a running CLI and everything it has started into a session job; what it starts later inherits the
        job. A CLI in a job of its own gets a nested job instead (nest()). state: adopted (new), already (it was in
        a Guardian job before), partial (some children stayed out), refused. skip: the hook process and the shells
        between it and the CLI, which exit in a moment anyway and may sit in a job of their own (the py launcher puts
        python in one)."""
        table = wj.process_table()
        if pid not in table:
            return {"ok": False, "state": "refused", "reason": f"process {pid} is not running"}
        image = table[pid][1]
        why = self.adopt_refusal(pid, table)
        if why:
            self.decide("adopt_refused", f"{provider}/{name}", requested={"pid": pid, "image": image, "via": via},
                        reason=why)
            return {"ok": False, "state": "refused", "reason": why}
        with self.lock:
            # started through srun, adopted before, or a tool command of another CLI Guardian already holds. A desktop
            # or nested job holds its CLI outside the root, so every session job is asked first
            holder = next((x for x in self.sessions.values() if wj.in_job(pid, x.job.h)), None)
            if holder or wj.in_job(pid, self.root.h):
                key = holder.key if holder else "?"
                chain = [holder.job] if holder and holder.desktop else \
                    [self.root, self.providers[holder.provider]["job"], holder.job] if holder else [self.root]
                late = [p for p in sweep_targets(wj.descendants(pid, table)[1:], table, wj.image_path,
                                                 self.own_pids(), skip)
                        if not wj.in_job(p, chain[-1].h) and not self.assign_chain(p, chain)]
                return {"ok": True, "state": "already", "session": key, "pid": pid, "swept": len(late),
                        "nested": bool(holder and holder.nested), "coverage": self.coverage_of(pid, holder),
                        "reason": f"already in Guardian session {key}"}
            fresh = f"{provider}/{name}" not in self.sessions
            try:
                s = self.session(provider, name, cls)
            except wj.JobTaken as e:  # session() logged it
                return {"ok": False, "state": "refused", "pid": pid, "reason": taken_reason(e)}
            if s.desktop:  # its job sits under another CLI's job or an app's, where this process cannot follow
                why = (f"session {s.key} already holds another CLI in a {'nested' if s.nested else 'desktop'} job "
                       f"outside AllAgents, and this one cannot join it; start it with gagent/srun instead")
                self.decide("adopt_refused", s.key, requested={"pid": pid, "image": image, "via": via}, reason=why)
                return {"ok": False, "state": "refused", "pid": pid, "reason": why}
            chain = [self.root, self.providers[provider]["job"], s.job]
            # the first process in AllAgents fixes where that job sits for good: a CLI in a job of its own would put
            # AllAgents, and every run after it, under its job (kill on close for Node), so it gets a nested job
            first = wj.in_job(pid) and not self.root.accounting()["total"]
            err = "AllAgents has never held a process" if first else self.assign_chain(pid, chain)
            if err and fresh:  # do not leave an empty session row behind
                self.sessions.pop(s.key).job.close()
            if err and fresh and "OpenProcess" not in err and not name.startswith("desk-") \
                    and not wj.in_job(pid, self.root.h):
                # the CLI sits in a job of its own, so it may only join an empty job, which then nests under that job
                try:
                    s = self.nest(pid, provider, name, cls)
                    err, chain = None, [s.job]
                except wj.JobTaken as e:  # nest() logged it
                    return {"ok": False, "state": "refused", "pid": pid, "reason": taken_reason(e)}
                except OSError as e:
                    err += f"; a nested job refused it too: {e}"
            if err:
                why = ("Guardian cannot open the process (another user's, or protected)" if "OpenProcess" in err
                       else "the CLI is in a job outside Guardian's tree; start it with gagent/srun instead")
                self.decide("adopt_failed", s.key, requested={"pid": pid, "image": image, "via": via}, error=err,
                            reason=why)
                return {"ok": False, "state": "refused", "pid": pid, "reason": f"{why} ({err})"}
            failed, moved = [], 1
            for p in sweep_targets(wj.descendants(pid, table)[1:], table, wj.image_path, self.own_pids(), skip):
                e = self.assign_chain(p, chain)
                if e:
                    failed.append({"pid": p, "image": table[p][1], "error": e})
                else:
                    moved += 1
            coverage = self.coverage_of(pid, s)
            run = Adopted(uuid.uuid4().hex[:12], s, pid, wj.open_waitable(pid), f"{image} (adopted)", coverage)
            if run.handle:
                self.live[run.run_id] = run
                self.adopted[pid] = run
                s.live_runs += 1
                s.t_last = time.time()
            self.ledger.run_requested({"run_id": run.run_id, "provider": provider, "session": name, "cls": s.cls,
                                       "fingerprint": hashlib.sha1(f"{provider}|adopt".encode()).hexdigest()[:16],
                                       "label": run.label, "est_gib": 0.0, "est_source": "adopted",
                                       "unprofiled": False, "t_request": time.time(), "coverage": coverage})
            self.ledger.run_update(run.run_id, state="running" if run.handle else "done", t_start=time.time(),
                                   pid=pid)
            state = "partial" if failed else "adopted"
            reason = f"{image} and {moved - 1} child processes joined " + \
                ("a nested job under the CLI's own job, capped outside AllAgents" if s.nested else "the session job")
            self.decide("adopt", s.key, requested={"pid": pid, "image": image, "via": via},
                        readback={"processes": moved, "failed": failed[:5], "coverage": coverage}, reason=reason)
            return {"ok": True, "state": state, "session": s.key, "pid": pid, "run_id": run.run_id,
                    "processes": moved, "failed": failed[:5], "coverage": coverage, "nested": s.nested,
                    "reason": reason}

    def nest(self, pid, provider, name, cls):
        """A session for a hook-adopted CLI that sits in a job of its own: claude.exe, and the node.exe of Cursor
        Agent and Gemini CLI. Such a process cannot join the tree once its jobs have held work (and must not be the
        first, see adopt()), but it can join an empty job, which Windows then nests under the CLI's own job (measured
        2026-10-15). That job sits outside AllAgents, so allocate() caps it in absolute cores as it does a desktop
        job. Raises wj.JobTaken (logged) when the name already exists, OSError when the process will not join."""
        key = f"{provider}/{name}"
        try:  # a name that already exists is refused as for a session: never take over a job Guardian did not create
            job = wj.Job.create(self.jobname("d", provider, name))
        except wj.JobTaken as e:
            self.decide("session_refused", key, readback={"pids": e.pids}, error=str(e), reason=taken_reason(e))
            raise
        try:
            job.assign(pid)
        except OSError:
            job.close()
            raise
        s = self.sessions[key] = Session(provider, name, cls, job)
        s.desktop = s.nested = True
        budget = self.cap.cap / 100 * self.world
        try:
            if self.control:
                job.set_limits(priority=self.pool_priority)
            if self.mask:
                wj.set_job_affinity(job, self.mask)
        except OSError as e:
            self.log(f"nested job limits for {key} failed: {e}")
        self.apply_session(s, self.desktop_want(s, None, budget), budget)
        self.log(f"session {key} class {cls} nested under the CLI's own job")
        return s

    def whereis(self, pid):
        """Which Guardian session job holds pid; what scripts/guardian-whereami.py and the provider check ask."""
        with self.lock:
            holder = next((x for x in self.sessions.values() if wj.in_job(pid, x.job.h)), None)
            outside = bool(holder and holder.desktop)  # a desktop or nested job, outside the root
            nested = bool(holder and holder.nested)
            return {"pid": pid, "in_guardian": bool(wj.in_job(pid, self.root.h)) or outside,
                    "in_any_job": wj.in_job(pid), "session": holder.key if holder else None,
                    "desktop": outside and not nested, "nested": nested, "priority": wj.priority_class(pid),
                    "adopted": pid in self.adopted, "instance": self.instance,
                    "budget": self.budget_of(holder) if holder else None}

    def budget_of(self, s):
        """What session s may use right now, told to the agent itself by the adopt hook's --context and by
        hooks/guardian-status.py. cap_cores None: no session cap, so the pool's cap is the limit."""
        smp = getattr(self, "sample", None)
        return {"key": s.key, "cls": s.cls, "cap_cores": self.alloc.caps.get(s.key),
                "pool_cap_cores": round(self.cap.cap / 100 * self.world, 2), "world_cpus": self.world,
                "control": self.control, "priority": self.pool_priority,
                "io": self.agent_io if self.control else "normal", "io_configured": self.agent_io,
                "admission_open": self.cap.admission_open, "admission_reason": self.cap.admission_reason,
                "queued": sum(1 for r in self.queue if r.session is s),
                "paused": s.paused or s.key in self.mem_paused, "memory_rung": self.mem.rung,
                "memory_pressure": self.mem.since is not None,
                "available_gib": round(smp.available_gib, 1) if smp and smp.available_gib else None,
                "exempt_left_s": max(0, round(s.exempt_until - time.time())) if s.cls == "exempt" else None}

    def coverage_of(self, pid, s):
        if s and s.desktop:
            return (f"enforced ({'nested' if s.nested else 'desktop'} job)" if wj.in_job(pid, s.job.h) else
                    "partial") + f", priority {wj.priority_class(pid)}"
        in_root, in_session = wj.in_job(pid, self.root.h), bool(s) and wj.in_job(pid, s.job.h)
        return ("enforced" if in_root and in_session else "partial") + f", priority {wj.priority_class(pid)}"

    def end_adopted(self, r, why=None):
        self.live.pop(r.run_id, None)
        self.adopted.pop(r.pid, None)
        r.session.live_runs -= 1
        wj.CloseHandle(r.handle)
        r.state = "done"
        self.ledger.run_update(r.run_id, state="done", t_end=time.time(), reason=why or "the adopted CLI exited")
        self.log(f"{r.label} pid {r.pid} ({r.session.key}): {why}" if why else
                 f"adopted {r.label} pid {r.pid} ({r.session.key}) exited")

    # ---- desktop jobs ----------------------------------------------------------------------------------------
    # A desktop app's agent CLI already sits in the app's job, so it can only join a fresh job, which then nests
    # under the app's job (measured 2026-10-14). These desktop jobs are outside AllAgents: the pool total holds
    # only through allocate(), which caps each of them in absolute cores once a second.
    def desktop_loop(self):
        while not self.stop.wait(2.0):
            try:
                if not self.desktop_on:
                    with self.lock:
                        self.drop_ended()  # a nested job does not depend on the switch, so it still ends here
                    continue
                table = wj.process_table()
                targets = PV.desktop_targets(table, wj.image_path)
                with self.lock:
                    inside = set(self.desktop_skip)
                    for s in [x for x in self.sessions.values() if x.desktop]:
                        try:
                            inside.update(s.job.pids())
                        except OSError:
                            pass
                # environments are read outside the lock: a few processes under the apps, about 1 ms each
                marked = {}
                commands = PV.agent_commands(table, wj.image_path, wj.environment, inside | {p for p, _ in targets},
                                             marked_apps=marked)
                with self.lock:
                    if self.desktop_on:
                        self.desktop_once(table, targets, commands)
                    for pid in sorted(marked.keys() - self.marked_apps):  # once for each app process, not every pass
                        self.log(f"{table[pid][1]} pid {pid} " + (
                            "carries the agent mark itself, so every process under it has it" if marked[pid] else
                            "has an environment Guardian cannot read, so its mark is unknown") +
                            ": its agent commands stay out of desktop jobs")
                    self.marked_apps = (self.marked_apps & set(table)) | marked.keys()
            except Exception:
                self.log("desktop poll failed: " + traceback.format_exc(limit=3).replace("\n", " | "))

    def desktop_once(self, table, targets, commands=()):
        self.desktop_skip &= set(table)
        for pid, provider in targets:
            if f"{provider}/desk-{pid}" not in self.sessions and pid not in self.desktop_skip:
                self.place_desktop(pid, provider, table)
        clis = {p for p, _ in targets}
        # ancestors first, since a Windows pid says nothing about which process is older: a marked command under
        # another one may have the lower pid, and placed first it would get a job of its own instead of going with the
        # sweep of the command above it. The sort is stable, so pid order holds within one depth
        for pid, provider, chat in sorted(commands, key=lambda c: len(wj.ancestors(c[0], table))):
            # a command under a desktop CLI is left to that CLI's job, as desktop_targets leaves a target under another
            # target, and one that a sweep of this pass already put in a desktop job stays there: a job placed for it
            # would nest inside that one, and the pool figure would count its CPU twice
            if clis & set(wj.ancestors(pid, table)) or \
                    any(wj.in_job(pid, s.job.h) for s in self.sessions.values() if s.desktop):
                continue
            if pid not in self.desktop_skip and pid not in self.adopted:
                self.place_command(pid, provider, chat, table)
        self.drop_ended()

    def place_command(self, pid, provider, chat, table):
        """An agent command an app started outside its agent CLI (Cursor's extension host runs some itself): it goes
        into the desktop job of its chat, so one chat is one session. When that job exists, the command tries to join
        it first and gets a job of its own only when joining fails, for example under another host than the chat's
        first command, since a job nests under one parent job only. A command without a chat id gets a job of its
        own."""
        var, value = PV.AGENT_ENV[provider][:2]
        still = lambda: (wj.environment(pid) or {}).get(var) == value
        if not chat:
            return self.place_desktop(pid, provider, table, f"cmd-{pid}", still, "agent command")
        name = PV.chat_session(chat)
        s = self.sessions.get(f"{provider}/{name}")
        if s is not None and s.desktop and not s.nested and self.join_desktop(s, pid, table, still):
            return s
        return self.place_desktop(pid, provider, table, name if s is None else f"{name}-{pid}", still,
                                  "agent command")

    def drop_ended(self):
        for s in [x for x in self.sessions.values() if x.desktop and not x.live_runs]:
            if s.job.accounting()["active"] == 0:  # the CLI has exited, and so has everything it started
                self.hold_outside(s, False)  # a run of it outside the tree may linger: no pause would reach it again
                self.sessions.pop(s.key, None)
                s.job.close()
                self.log(f"{'nested' if s.nested else 'desktop'} session {s.key} ended")
                self.end_memory_pause(s.key, "the session ended")

    def place_desktop(self, pid, provider, table, name=None, still=None, what="desktop CLI"):
        """Put one desktop CLI (or one agent command, see place_command) and what it has started into a desktop job of
        its own; what it starts later inherits the job. still() tells whether pid is still the process the scan
        found. A refusal or failure is logged once, and that pid is not tried again while it runs."""
        name, image = name or f"desk-{pid}", table[pid][1]
        key = f"{provider}/{name}"
        still = still or (lambda: PV.DESKTOP_CLIS[provider][1] in (wj.image_path(pid) or "").lower())

        def refuse(why, err=None):
            self.desktop_skip.add(pid)
            self.decide("desktop_refused", key, requested={"pid": pid, "image": image}, error=err, reason=why)

        if self.own_or_parent(pid, table):
            return refuse("that process is the Guardian daemon or one of its parents")
        if wj.in_job(pid, self.root.h):
            return refuse("the process is already in Guardian's tree")
        handle = wj.open_waitable(pid)  # holds the pid, so it cannot be reused while it is placed
        if not handle:
            return None  # it exited after the process table was read
        if not still():
            wj.CloseHandle(handle)
            return refuse(f"the process is no longer the {what} the scan found")
        try:
            self.provider(provider)  # the pause switch lives there, although its job does not hold desktop jobs
            # a name that already exists is refused as for a session: never take over a job Guardian did not create
            job = wj.Job.create(self.jobname("d", provider, name))
        except (wj.JobTaken, OSError) as e:
            wj.CloseHandle(handle)
            return refuse(taken_reason(e) if isinstance(e, wj.JobTaken) else "Guardian could not create or open the "
                          "desktop job", str(e))
        err = self.assign_chain(pid, [job])
        if err:
            job.close()
            wj.CloseHandle(handle)
            return refuse("the process cannot join a fresh job (protected, or in a job that allows no nesting)", err)
        s = self.sessions[key] = Session(provider, name, "normal", job)
        s.desktop, s.app_pids = True, set(wj.ancestors(pid, table))
        budget = self.cap.cap / 100 * self.world
        try:
            if self.control:
                job.set_limits(priority=self.pool_priority)
            if self.mask:
                wj.set_job_affinity(job, self.mask)
        except OSError as e:
            self.log(f"desktop limits for {key} failed: {e}")
        self.apply_session(s, self.desktop_want(s, None, budget), budget)
        self.track_desktop(s, pid, handle, image, what)
        return s

    def join_desktop(self, s, pid, table, still):
        """Add one more agent command to an existing desktop session. False when it cannot join that job (another
        host's job, or it is not the command the scan found), so the caller gives it a job of its own."""
        if self.own_or_parent(pid, table) or wj.in_job(pid, self.root.h):
            return False
        handle = wj.open_waitable(pid)
        if not handle:
            return True  # it exited after the scan: nothing left to place
        if not still() or self.assign_chain(pid, [s.job]):
            wj.CloseHandle(handle)
            return False
        self.track_desktop(s, pid, handle, table[pid][1], "agent command")
        return True

    def track_desktop(self, s, pid, handle, image, what):
        """Sweep pid's children into the session's job, then keep a run row for pid until it exits."""
        fresh = wj.process_table()
        own = self.own_pids() | set(wj.ancestors(os.getpid(), fresh))
        failed, moved = [], 1
        for p in desktop_sweep(pid, fresh, wj.image_path, own):
            e = self.assign_chain(p, [s.job])
            if e:
                failed.append({"pid": p, "image": fresh[p][1], "error": e})
            else:
                moved += 1
        coverage = self.coverage_of(pid, s)
        app = (PV.DESKTOP_CLIS.get(s.provider) or PV.AGENT_ENV.get(s.provider) or ("app",))[-1]
        run = Adopted(uuid.uuid4().hex[:12], s, pid, handle,
                      f"{image} ({'desktop' if what == 'desktop CLI' else what})", coverage)
        run.est_source = "desktop"
        self.live[run.run_id] = run
        s.live_runs += 1
        self.ledger.run_requested({"run_id": run.run_id, "provider": s.provider, "session": s.name, "cls": s.cls,
                                   "fingerprint": hashlib.sha1(f"{s.provider}|desktop".encode()).hexdigest()[:16],
                                   "label": run.label, "est_gib": 0.0, "est_source": "desktop",
                                   "unprofiled": False, "t_request": time.time(), "coverage": coverage})
        self.ledger.run_update(run.run_id, state="running", t_start=time.time(), pid=pid)
        self.decide("desktop", s.key, requested={"pid": pid, "image": image},
                    readback={"processes": moved, "failed": failed[:5], "coverage": coverage},
                    reason=f"{what} {image} and {moved - 1} child processes joined a desktop job under the {app}'s "
                           f"job")

    def set_desktop(self, on, reason):
        """Off lets every desktop job go: no CPU cap, normal priority, every CPU, and no new placements. A nested
        job stays capped until its CLI exits: that CLI asked to join through its adopt hook, while the switch is
        about Guardian reaching into the apps. Rollback and shutdown still release it."""
        self.desktop_on = on
        released = [s for s in self.sessions.values() if s.desktop and not s.nested] if not on else []
        for s in released:
            try:
                s.job.set_cpu()
                if s.job.limits()["priority"]:
                    s.job.set_limits(priority="normal")  # clearing the limit would not restore the members (E9)
                if s.job.limits()["flags"] & wj.LIMIT_AFFINITY:
                    wj.set_job_affinity(s.job, (1 << wj.NCPU) - 1)  # the same holds for a narrowed CPU set
                self.restore_priority(s.job.pids())
            except OSError as e:
                self.log(f"releasing {s.key} failed: {e}")
            err = self.hold_outside(s, False)  # its runs started while exempt: no pause reaches them once it is gone
            if err:
                self.log(f"releasing the runs of {s.key} outside the pool failed: {err}")
            for r in [r for r in self.live.values() if r.session is s and isinstance(r, Adopted)]:
                self.end_adopted(r, "desktop jobs switched off; the CLI keeps running outside Guardian")
            self.sessions.pop(s.key, None)
            s.job.close()
            self.end_memory_pause(s.key, "desktop jobs switched off, so the session left Guardian")
        self.desktop_skip.clear()
        self.decide("desktop", "desktop jobs", requested=on,
                    readback={"released": len(released),
                              "nested_kept": sum(1 for s in self.sessions.values() if s.nested)},
                    reason=f"{reason}: " + ("the desktop apps' agent CLIs and agent commands go into desktop jobs" if on
                                            else "desktop jobs released, none placed"))

    def desktop_priority(self, s, name):
        try:
            s.job.set_limits(priority=name)
        except OSError as e:
            self.log(f"priority {name} for {s.key} failed: {e}")

    # ---- I/O and memory priority -------------------------------------------------------------------------------
    def members(self):
        """Every process in Guardian's jobs: the root lists the processes of the jobs nested in it too, and the
        desktop and nested jobs sit outside it."""
        pids = set()
        for job in [self.root] + [s.job for s in self.sessions.values() if s.desktop]:
            try:
                pids.update(job.pids())
            except OSError:
                pass
        return pids

    def nice_sweep(self, members=None):
        """Give each process that has joined a Guardian job the agents' I/O and memory priority. A job has no limit
        for either, but a process passes both on to the children it starts afterwards (measured 2026-10-17), so a
        pid is set once, when it first shows up in a job, and is read again only after it leaves."""
        members = self.members() if members is None else members
        for pid in members - self.niced.keys():
            self.niced[pid] = wj.set_io_priority(pid, self.agent_io) & wj.set_memory_priority(pid, self.agent_memory)
        for pid in self.niced.keys() - members:
            del self.niced[pid]

    def restore_priority(self, pids):
        """Normal I/O and memory priority again (rollback, desktop jobs off); it does not follow by itself, as with
        the CPU priority class (E9)."""
        for pid in pids:
            wj.set_io_priority(pid, "normal")
            wj.set_memory_priority(pid, "normal")
            self.niced.pop(pid, None)

    def set_agent_priority(self, io=None, memory=None, reason="set by Stan"):
        if io is not None and io not in wj.IO_PRIORITY:
            raise ValueError(f"io must be one of {', '.join(wj.IO_PRIORITY)}")
        if memory is not None and memory not in wj.MEMORY_PRIORITY:
            raise ValueError(f"memory must be one of {', '.join(wj.MEMORY_PRIORITY)}")
        before = {"io": self.agent_io, "memory": self.agent_memory}
        self.agent_io, self.agent_memory = io or self.agent_io, memory or self.agent_memory
        self.niced.clear()  # the next tick sets every member again
        self.decide("agent_priority", "agent processes", before, {"io": self.agent_io, "memory": self.agent_memory},
                    reason=reason)

    # ---- dashboard API ---------------------------------------------------------------------------------------
    def state(self):
        with self.lock:
            s = self.sample
            c, m = self.cfg["cpu"], self.cfg["memory"]
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
                # in effect: rollback puts the members back at normal, and nothing lowers them while control is off
                "agent_priority": {"io": self.agent_io if self.control else "normal",
                                   "memory": self.agent_memory if self.control else "normal",
                                   "io_configured": self.agent_io, "memory_configured": self.agent_memory,
                                   "set": sum(1 for v in self.niced.values() if v),
                                   "refused": sum(1 for v in self.niced.values() if not v)},
                "desktop": self.desktop_on,
                "memory": {"agents_gib": round(self.agents_gib, 2), "budget_gib": m["agent_memory_budget_gib"],
                           "rung": self.mem.rung, "pressure": self.mem.since is not None, "trim": m["pressure_trim"],
                           "pause": m["pressure_pause"],
                           "hard_limit_gib": m["job_commit_hard_limit_gib"] if self.control else None,
                           "hard_limit_configured_gib": m["job_commit_hard_limit_gib"],
                           "paused": sorted(self.mem_paused),
                           "trimmed_gib": round(self.trimmed_gib, 2)},
                "experience": {"level": level, "kind": kind, "probe": self.probe_last,
                               "inject_left_s": round(self.inject[0] - time.monotonic())
                               if self.inject and self.inject[0] > time.monotonic() else 0},
                "notes": self.cap.notes,
                "providers": [{"name": n, "paused": p["paused"], "cores": round(prov_cores[n], 2)}
                              for n, p in self.providers.items()],
                "sessions": [{"key": k, "provider": x.provider, "name": x.name, "cls": x.cls,
                              "allocation_weight": c["allocation_weights"].get(x.cls, 5), "paused": x.paused,
                              "provider_paused": self.providers[x.provider]["paused"], "usage": round(x.usage, 2),
                              "cap_cores": self.alloc.caps.get(k), "runs": x.live_runs,
                              "desktop": x.desktop and not x.nested, "nested": x.nested,
                              "memory_paused": k in self.mem_paused,
                              "exempt_left_s": max(0, round(x.exempt_until - time.time()))
                              if x.cls == "exempt" else None}
                             for k, x in self.sessions.items()],
                "queue_order": self.cfg["queue"]["order"],
                "queue": [{"run_id": r.run_id, "session": r.session.key, "label": r.label, "reason": r.reason,
                           "est_gib": round(r.est_gib, 2), "numbers": r.numbers,
                           "est_s": round(r.est_s) if r.est_s is not None else None, "est_s_source": r.est_s_source,
                           "waiting_s": round(time.monotonic() - r.t_request)}
                          for r in [x["run"] for x in P.queue_order(
                              [{"run": r, "cls": r.session.cls, "t_request": r.t_request, "est_s": r.est_s,
                                "share": r.session.cpu_s / c["allocation_weights"].get(r.session.cls, 5)}
                               for r in self.queue], self.cfg["queue"]["order"], time.monotonic())]],
                "runs": [{"run_id": r.run_id, "session": r.session.key, "label": r.label, "state": r.state,
                          "pid": r.proc.pid if r.proc else getattr(r, "pid", None), "coverage": r.coverage,
                          "est_gib": round(r.est_gib, 2), "est_source": r.est_source,
                          "commit_gib": round(r.commit_gib, 2)} for r in self.live.values() if r.state != "queued"],
                "recent_runs": self.ledger.recent_runs(12),
                "apps": self.apps_rows, "outside": self.outside, "decisions": self.ledger.recent_decisions(25),
                "events": list(self.events)[:30], "history": list(self.history)[-180:],
            }

    def action(self, path, b):
        with self.lock:
            now = time.monotonic()
            if path == "/api/session":
                s = self.sessions[b["key"]]
                if b.get("cls") == "exempt":
                    minutes = float(self.cfg["queue"]["exempt_minutes"] if b.get("minutes") is None else b["minutes"])
                    if not 0 < minutes <= 24 * 60:
                        raise ValueError("an exemption lasts more than 0 and at most 1440 minutes")
                    self.set_exempt(s, minutes, "set by Stan")
                elif b.get("cls") in CLASSES and b["cls"] != s.cls:
                    self.decide("session_class", s.key, s.cls, b["cls"], b["cls"], None, "set by Stan" +
                                ("; exemption ended early" if s.cls == "exempt" else ""))
                    s.cls, s.exempt_until = b["cls"], None
                if "paused" in b and bool(b["paused"]) != s.paused:
                    s.paused = bool(b["paused"])
                    self.decide("session_pause" if s.paused else "session_resume", s.key, reason=
                                "Stan paused the session: CPU rate 1/10000, processes stay alive" if s.paused
                                else "resumed")
                    if s.paused:  # Stan's resume leaves a ladder pause alone
                        self.end_memory_pause(s.key, "Stan paused the session, and that pause holds it now")
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
            elif path == "/api/queue_order":
                if b.get("order") not in P.QUEUE_ORDERS:
                    raise ValueError(f"order must be one of {', '.join(P.QUEUE_ORDERS)}")
                self.decide("queue_order", "queue", self.cfg["queue"]["order"], b["order"], b["order"],
                            reason="set by Stan")
                self.cfg["queue"]["order"] = b["order"]
            elif path == "/api/memory":
                self.set_memory(b)
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
            elif path == "/api/desktop":
                self.set_desktop(bool(b["on"]), "set by Stan")
            elif path == "/api/agent_priority":
                self.set_agent_priority(b.get("io"), b.get("memory"))
            elif path == "/api/cancel":
                run = self.live[b["run_id"]]
                if isinstance(run, Adopted):
                    raise ValueError("an adopted CLI is not cancelled from here; close it where it runs")
                run.cancelled = "cancelled by Stan from the dashboard"
            elif path == "/api/adopt":
                pid, provider = int(b["pid"]), safe(b.get("provider"), "other").lower()
                provider = provider if provider in PROVIDERS else "other"
                return self.adopt(pid, provider, safe(b.get("session"), f"{provider}-{pid}"),
                                  b.get("cls") if b.get("cls") in CLASSES else "normal", "guardctl")
            elif path == "/api/media":
                level = P.media_window_level(b, self.cfg["observation"])
                self.media = {"t": now, "level": level, "raw": b}
            elif path == "/api/rollback":
                self.rollback("requested by Stan")
            elif path == "/api/resume_control":
                self.control = True
                self.set_pool_priority(self.pool_priority, "control resumed")
                self.apply_cap("resume_control", "control resumed")
                if self.cfg["memory"]["job_commit_hard_limit_gib"]:
                    self.set_hard_limit(self.cfg["memory"]["job_commit_hard_limit_gib"], "control resumed")
            elif path == "/api/shutdown":
                threading.Thread(target=self.shutdown, daemon=True).start()
            else:
                raise KeyError(path)
        return {"ok": True}

    def set_memory(self, b):
        m = self.cfg["memory"]
        keys = {"budget_gib": "agent_memory_budget_gib", "trim": "pressure_trim", "pause": "pressure_pause",
                "hard_limit_gib": "job_commit_hard_limit_gib"}
        before = {k: m[v] for k, v in keys.items()}
        for k in ("budget_gib", "hard_limit_gib"):
            if k in b and b[k] is not None and not 0 < float(b[k]) <= 1024:
                raise ValueError(f"{k} must be more than 0 and at most 1024 GiB, or null for none")
        for k, v in keys.items():
            if k in b:
                m[v] = (bool(b[k]) if k in ("trim", "pause") else None if b[k] is None else float(b[k]))
        self.decide("memory_settings", "agent memory", before, {k: m[v] for k, v in keys.items()}, reason="set by Stan")
        if "hard_limit_gib" in b and self.control:
            self.set_hard_limit(m["job_commit_hard_limit_gib"], "set by Stan")

    def rollback(self, why):
        """Remove every CPU control the Guardian set. Member priority goes back to normal explicitly, because
        clearing a priority limit does not restore the processes it already changed (E9)."""
        self.control = False
        self.mem, self.mem_paused = P.MemState(), set()
        for p in self.providers.values():  # first, so that apply_session also releases the runs outside the tree
            p["paused"] = False
        # every run outside the tree, those of sessions that have left too, before a session's readback can raise
        err = self.hold_outside(None, False)
        if err:
            self.log(f"releasing the runs outside the pool failed: {err}")
        for s in self.sessions.values():
            self.apply_session(s, None, 1)
            s.paused = False
            if s.desktop:  # outside AllAgents, so the root's priority below does not reach it
                self.desktop_priority(s, "normal")
        for name, p in self.providers.items():
            p["job"].set_cpu()
        self.root.set_cpu()
        self.root.set_limits(priority="normal", clear_mem=True)
        self.pool_priority_readback = self.root.limits()["priority"]
        self.restore_priority(self.members())
        # a miniature world (--world-cpus) is the demo's safety boundary, not a control: keep it
        wj.set_job_affinity(self.root, self.mask)
        self.decide("rollback", "AllAgents", requested="no caps or memory limit, normal CPU, I/O and memory priority, " +
                    (f"affinity kept to the {self.world}-CPU demo world" if self.mask else "no affinity"),
                    readback=self.root.cpu().get("mode"), reason=why)

    def shutdown(self):
        """Leave no throttle behind: work still running after the daemon exits must not stay capped or paused."""
        with self.lock:
            self.desktop_on = False  # no desktop job placed, and capped, after the cleanup below
            # nor capped, trimmed or paused by a tick that was waiting for the lock: tick acts only under control
            self.control = False
            self.mem, self.mem_paused = P.MemState(), set()
            try:
                for p in self.providers.values():  # first, so apply_session also releases the runs outside the tree
                    p["paused"] = False
                # every run outside the tree, those of sessions that have left too, before a readback can raise
                err = self.hold_outside(None, False)
                if err:
                    self.log(f"releasing the runs outside the pool failed: {err}")
                for s in self.sessions.values():
                    self.apply_session(s, None, 1)
                for p in self.providers.values():
                    p["job"].set_cpu()
                self.root.set_cpu()
                self.root.set_limits(clear_mem=True)
                self.decide("shutdown", "AllAgents", reason="daemon stopping: caps, pauses and the memory limit removed, "
                            "below_normal and the low I/O and memory priority kept so leftover work still yields "
                            "to the foreground")
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
        loops = [self.tick_loop, self.admit_loop, self.accept_loop, server.serve_forever, self.desktop_loop]
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


def stdout_path():
    """The disk file stdout writes to, or None for a console, a pipe or no stdout at all."""
    try:
        return wj.disk_file_path(sys.stdout.fileno())
    except (AttributeError, OSError, ValueError):  # no stdout, or a stream without a descriptor
        return None


def relaunch_command(log):
    """This process's command line under a headless conhost, with --stay-in-job and its output appended to log. The
    new copy gets the default user environment, not this one, so UTF-8 mode is passed on as -X utf8."""
    utf8 = ["-X", "utf8"] if sys.flags.utf8_mode else []
    return subprocess.list2cmdline([CONHOST, "--headless", sys.executable, *utf8, *sys.orig_argv[1:],
                                    "--stay-in-job", "--log", log])


def relaunch_outside_job(cmd):
    """Start cmd through WMI. Returns the pid of the new conhost; raises OSError or ValueError when that fails."""
    env = dict(os.environ, GUARDIAN_RELAUNCH_COMMAND=cmd, GUARDIAN_RELAUNCH_CWD=os.getcwd())
    try:
        r = subprocess.run([POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", WMI_CREATE], env=env,
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace", timeout=30,
                           creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise OSError("powershell did not answer within 30 s") from None
    if r.returncode:
        raise OSError(f"powershell exited with {r.returncode}: {' '.join(r.stderr.split())[:300]}")
    code, _, pid = r.stdout.strip().partition(" ")
    if code != "0":
        raise OSError(f"Win32_Process.Create returned {code or 'nothing'}")
    return int(pid)


def leave_job(stay):
    """True when this process started itself again outside its job and should exit now. Runs the daemon spawns
    inherit its job, and once AllAgents holds a process from outside that job, such as an adopted CLI, they cannot
    join AllAgents (Access is denied) and srun runs them without control."""
    if not wj.in_job(os.getpid()):
        return False
    log = None if stay else stdout_path()
    cmd = relaunch_command(log) if log else ""
    why = ("--stay-in-job keeps it there" if stay else
           "with stdout going to a file it would start again outside" if not log else
           "it stays there because conhost would expand %NAME% in its command line" if "%" in cmd else "")
    if why:
        print("[guardian] warning: the daemon runs inside a job, so runs started through srun or gagent cannot enter "
              "Guardian's jobs once it adopts a process from outside that job; " + why, file=sys.stderr, flush=True)
        return False
    # before Create, while nothing else writes to the log: once the new copy runs, this copy only writes if it died
    print("[guardian] leaving the job: starting again outside it through WMI", flush=True)
    try:
        pid = relaunch_outside_job(cmd)
    except (OSError, ValueError) as e:
        print(f"[guardian] warning: could not leave the job, so runs started through srun or gagent may not enter "
              f"Guardian's jobs ({e})", file=sys.stderr, flush=True)
        return False
    # conhost, not ping: in a scheduled task the new copy waits in open_log until this copy's cmd lets go of the log
    if not exited_within(pid, 3.0):
        return True
    sys.stdout.flush()
    os.lseek(sys.stdout.fileno(), 0, os.SEEK_END)  # the new copy may have appended to the file before it died
    print(f"[guardian] warning: the copy started outside the job (conhost pid {pid}) exited at once, so this one runs "
          f"in place and runs started through srun or gagent may not enter Guardian's jobs", file=sys.stderr,
          flush=True)
    return False


def exited_within(pid, seconds):
    """True when process pid ends within seconds or is gone already."""
    h = wj.open_waitable(pid)
    if not h:
        return True
    try:
        return wj.WaitForSingleObject(h, int(seconds * 1000)) == 0  # WAIT_OBJECT_0: it has exited
    finally:
        wj.CloseHandle(h)


def open_log(path, wait=30.0):
    """path opened for appending, line-buffered, in the encoding a redirect gives stdout: the locale's, or UTF-8 in
    UTF-8 mode, which the old copy passes on with -X utf8. The copy that left a job retries while the old copy's cmd
    still holds the file, which it shares for reading only (measured 2026-10-15)."""
    t0 = time.monotonic()
    while True:
        try:
            return open(path, "a", buffering=1, errors="backslashreplace")
        except PermissionError:
            if time.monotonic() - t0 > wait:
                raise
            time.sleep(0.1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Guardian daemon: one big job for agent work, foreground first.")
    ap.add_argument("--instance", default="main")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--world-cpus", type=int, help="miniature world: pool and probe use only the top N CPUs")
    ap.add_argument("--initial-cap", type=float)
    ap.add_argument("--max-cap", type=float, help="upper cap in percent of the world (default 95)")
    ap.add_argument("--policy", metavar="FILE", help='JSON merged over the policy defaults, e.g. '
                    '{"cpu": {"decrease_factor": 0.5}}; for experiments on a test instance')
    ap.add_argument("--no-probe", action="store_true")
    ap.add_argument("--no-apps", action="store_true")
    ap.add_argument("--desktop", choices=("on", "off"),
                    help="put the Claude, Codex and Cursor apps' agent CLIs and Cursor's agent commands in desktop "
                         "jobs (default: on for main only)")
    ap.add_argument("--stay-in-job", action="store_true", help="never start again outside the job this runs in")
    ap.add_argument("--log", metavar="PATH", help="append stdout and stderr to PATH")
    a = ap.parse_args(argv)
    if a.log:  # the copy that left a job: its console is headless
        sys.stdout = sys.stderr = open_log(a.log)
    if ping(a.instance):
        print(f"Guardian {a.instance} is already running", file=sys.stderr)
        return 1
    # before leave_job, so the message reaches the console Stan typed into; utf-8-sig takes what PowerShell 5.1 writes
    try:
        over = P.check_over(json.loads(Path(a.policy).read_text(encoding="utf-8-sig"))) if a.policy else {}
    except (OSError, ValueError) as e:
        print(f"Guardian {a.instance}: bad --policy {a.policy}: {e}", file=sys.stderr)
        return 2
    # only with argv from the command line: the new copy gets this process's own command line
    if argv is None and leave_job(a.stay_in_job):
        return 0
    if a.max_cap:
        over = P.merged(over, {"cpu": {"maximum_cap_percent": a.max_cap}})
    if over:
        print(f"policy over the defaults: {json.dumps(over)}", flush=True)
    try:
        Guardian(a.instance, a.world_cpus, a.initial_cap, over, a.port, not a.no_probe, not a.no_apps,
                 None if a.desktop is None else a.desktop == "on").run_forever()
    except StartRefused as e:
        print(f"Guardian {a.instance} refused to start: {e}", file=sys.stderr)
        return 2
    return 0
