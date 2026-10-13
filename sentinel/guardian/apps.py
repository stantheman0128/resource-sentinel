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
GetProcessTimes = wj._bind("GetProcessTimes", w.BOOL, wj.HANDLE, ctypes.POINTER(w.FILETIME),
                           ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME))


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
