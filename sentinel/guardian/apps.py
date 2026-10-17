"""Read-only view of the agent apps that are already running (coverage = observed).

Measured 2026-10-13 (audits/20261013-session-control, E8a): Claude desktop and the Codex app (ChatGPT.exe)
each keep almost their whole process tree in one job they hold themselves; Cursor has no app-level job,
only per-renderer sandbox jobs. A running app cannot be moved under the Guardian's job, so this module
only measures them. Job handles are duplicated with JOB_OBJECT_QUERY and closed right after each read,
because some of these jobs are kill-on-close and a handle we kept open would delay that cleanup.
"""
import ctypes
import ctypes.wintypes as w
import os
import time

from . import winjob as wj

APP_ROOTS = {"claude.exe": "Claude", "chatgpt.exe": "Codex", "cursor.exe": "Cursor", "grok.exe": "Grok",
             "gemini.exe": "Gemini", "antigravity.exe": "Antigravity"}

_ntdll = ctypes.WinDLL("ntdll")
_ntdll.NtQuerySystemInformation.restype = ctypes.c_long
_ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                            ctypes.POINTER(ctypes.c_ulong)]
DuplicateHandle = wj._bind("DuplicateHandle", w.BOOL, wj.HANDLE, wj.HANDLE, wj.HANDLE,
                           ctypes.POINTER(wj.HANDLE), w.DWORD, w.BOOL, w.DWORD)
GetProcessTimes = wj.GetProcessTimes


class _HandleEntry(ctypes.Structure):
    _fields_ = [("Object", ctypes.c_void_p), ("Pid", ctypes.c_size_t), ("Value", ctypes.c_size_t),
                ("Access", w.ULONG), ("Backtrace", w.USHORT), ("TypeIndex", w.USHORT), ("Attrs", w.ULONG),
                ("Reserved", w.ULONG)]


def _handles():
    size = 1 << 22
    while True:
        buf = ctypes.create_string_buffer(size)
        need = ctypes.c_ulong()
        st = _ntdll.NtQuerySystemInformation(64, buf, size, ctypes.byref(need)) & 0xFFFFFFFF
        if st == 0:
            break
        if st != 0xC0000004 or size > 1 << 30:
            raise OSError(f"NtQuerySystemInformation status {st:#x}")
        size = max(size * 2, need.value + (1 << 20))
    n = ctypes.c_size_t.from_buffer(buf).value
    return [(e.Pid, e.Value, e.TypeIndex) for e in (_HandleEntry * n).from_buffer(buf, 16)]


def _job_type_index():
    probe = wj.Job.create()
    try:
        for pid, val, t in _handles():
            if pid == os.getpid() and val == probe.h:
                return t
    finally:
        probe.close()
    return None


def _dup(owner_pid, value):
    src = wj.OpenProcess(wj.PROCESS_DUP_HANDLE, False, owner_pid)
    if not src:
        return None
    try:
        out = wj.HANDLE()
        ok = DuplicateHandle(src, wj.HANDLE(value), wj.GetCurrentProcess(), ctypes.byref(out), wj.JOB_OBJECT_QUERY,
                             False, 0)
        return out.value if ok else None
    finally:
        wj.CloseHandle(src)


def _process_cpu_s(pid):
    h = wj.OpenProcess(wj.PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return 0.0
    try:
        c, e, k, u = w.FILETIME(), w.FILETIME(), w.FILETIME(), w.FILETIME()
        if not GetProcessTimes(h, ctypes.byref(c), ctypes.byref(e), ctypes.byref(k), ctypes.byref(u)):
            return 0.0
        ft = lambda f: (f.dwHighDateTime << 32) | f.dwLowDateTime
        return (ft(k) + ft(u)) / 1e7
    finally:
        wj.CloseHandle(h)


def _process_times():
    """{pid: (image name, kernel+user CPU seconds, start time)} for every process from one SystemProcessInformation
    call, so elevated and protected processes (Defender, services) are counted too. The start time (CreateTime, as
    winjob.created) tells a reused pid apart. x64 SYSTEM_PROCESS_INFORMATION offsets, so a 32-bit Python gets
    OSError; measured 2026-10-17: 612 processes in about 7 ms, CPU seconds equal to GetProcessTimes on all 422
    readable."""
    if not wj.X64:
        raise OSError("the SystemProcessInformation offsets here are x64 ones; this Python is 32-bit")
    size = 1 << 22
    while True:
        buf = ctypes.create_string_buffer(size)
        need = ctypes.c_ulong()
        st = _ntdll.NtQuerySystemInformation(5, buf, size, ctypes.byref(need)) & 0xFFFFFFFF
        if st == 0:
            break
        if st != 0xC0000004 or size > 1 << 28:
            raise OSError(f"NtQuerySystemInformation status {st:#x}")
        size = max(size * 2, need.value + (1 << 20))
    out, off = {}, 0
    while True:
        at = lambda t, o: t.from_buffer(buf, off + o).value
        cpu = at(ctypes.c_longlong, 0x28) + at(ctypes.c_longlong, 0x30)  # UserTime + KernelTime, 100 ns
        name_len, name_ptr = at(ctypes.c_ushort, 0x38), at(ctypes.c_void_p, 0x40)  # ImageName
        out[at(ctypes.c_size_t, 0x50)] = (ctypes.wstring_at(name_ptr, name_len // 2) if name_ptr else "", cpu / 1e7,
                                          at(ctypes.c_longlong, 0x20))  # CreateTime
        nxt = ctypes.c_ulong.from_buffer(buf, off).value
        if not nxt:
            return out
        off += nxt


class AppObserver:
    """Finds each app's root process and its widest self-held job, then reports CPU cores and coverage."""

    def __init__(self, refresh_s=30.0):
        self.refresh_s = refresh_s
        self._jt = None
        self._found = {}      # root pid -> dict(name, exe, holder, value, members, tree)
        self._last_scan = 0.0
        self._prev = {}       # root pid -> (t, cpu_s)

    def _scan(self):
        table = wj.process_table()
        roots = [p for p, (pp, exe) in table.items() if exe.lower() in APP_ROOTS
                 and not (pp in table and table[pp][1].lower() == exe.lower())]
        if self._jt is None:
            self._jt = _job_type_index()
        trees = {r: wj.descendants(r, table) for r in roots}
        owner = {p: r for r, ps in trees.items() for p in ps}
        best = {}
        for pid, val, t in _handles():
            r = owner.get(pid)
            if t != self._jt or r is None or pid == os.getpid():
                continue
            h = _dup(pid, val)
            if not h:
                continue
            try:
                if not wj.in_job(r, h):
                    continue
                j = wj.Job(h, "app")
                n = len(j.pids())
                if n > best.get(r, {}).get("members", 0):
                    best[r] = {"holder": pid, "value": val, "members": n}
            except OSError:
                pass
            finally:
                wj.CloseHandle(h)
        self._found = {}
        for r in roots:
            exe = table[r][1]
            info = {"name": APP_ROOTS[exe.lower()], "exe": exe, "tree": trees[r]}
            b = best.get(r, {})
            if b.get("members", 0) * 2 >= len(trees[r]):  # a 1-process sandbox job is not an app-level job
                info.update(b)
            self._found[r] = info
        self._last_scan = time.time()

    def sample(self):
        if time.time() - self._last_scan > self.refresh_s or not self._found:
            try:
                self._scan()
            except OSError as e:
                return [{"name": "?", "error": str(e)}]
        out, now = [], time.perf_counter()
        for r, info in list(self._found.items()):
            row = {"name": info["name"], "root_pid": r, "procs": len(info["tree"]),
                   "hosts_guardian": os.getpid() in info["tree"]}
            cpu_s = None
            if "holder" in info:
                h = _dup(info["holder"], info["value"])
                if h:
                    try:
                        j = wj.Job(h, "app")
                        cpu_s = j.accounting()["cpu_s"]
                        row["job_members"] = info["members"]
                        row["coverage"] = f"observed: app job, {info['members']} of {len(info['tree'])} processes"
                    except OSError:
                        cpu_s = None
                    finally:
                        wj.CloseHandle(h)
            if cpu_s is None:
                # no app-level job (Cursor) or it went away: sum the process tree; exited children drop out
                cpu_s = sum(_process_cpu_s(p) for p in info["tree"])
                row["coverage"] = f"observed: process tree sum, {len(info['tree'])} processes"
            prev = self._prev.get(r)
            self._prev[r] = (now, cpu_s)
            row["cores"] = round(max(0.0, (cpu_s - prev[1]) / (now - prev[0])), 2) if prev and now > prev[0] else None
            out.append(row)
        return out


class LoadObserver:
    """CPU of every process outside Guardian's jobs, grouped by image name, so the dashboard shows what else is
    loading the machine (a browser, Raycast, Defender) next to what the agents use."""

    def __init__(self, times=None, busy=None, cpus=None):
        self._times = times or _process_times
        self._busy = busy or wj.system_busy()  # whole-machine busy fraction since the previous call
        self._cpus = cpus or os.cpu_count()
        self._prev = None  # (t, {pid: (name, cpu_s)})

    def sample(self, members, now=None, top=5):
        now = time.monotonic() if now is None else now
        cur, busy = self._times(), self._busy()
        prev, self._prev = self._prev, (now, cur)
        if not prev or now <= prev[0]:
            return None
        groups, in_jobs = {}, 0.0
        for pid, (name, cpu_s, born) in cur.items():
            old = prev[1].get(pid)
            # pid 0 is the idle process; a pid seen for the first time, or reused by a later process (another start
            # time, even with the same image), waits a sample
            if pid == 0 or not old or old[0] != name or old[2] != born:
                continue
            cores = max(0.0, cpu_s - old[1]) / (now - prev[0])
            if pid in members:
                in_jobs += cores
                continue
            g = groups.setdefault(name.lower(), [name, 0.0, 0])
            g[1] += cores
            g[2] += 1
        rows = sorted(groups.values(), key=lambda g: -g[1])
        outside = sum(g[1] for g in rows)
        machine = None if busy is None else busy * self._cpus
        return {"cores": round(outside, 2), "processes": sum(g[2] for g in rows),
                "top": [{"name": n, "cores": round(c, 2), "processes": k} for n, c, k in rows[:top] if c >= 0.01],
                "machine_cores": None if machine is None else round(machine, 2),
                # interrupts and DPCs, and processes that started and ended between two samples, belong to no row
                "unattributed_cores": None if machine is None else round(max(0.0, machine - outside - in_jobs), 2),
                "coverage": "observed: every process outside Guardian's jobs, protected ones too; "
                            "a new process counts from its second sample"}
