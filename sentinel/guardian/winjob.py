"""Thin ctypes layer over Windows Job Objects for the Guardian. Standard library only.

Constants come from Windows SDK 10.0.26100.0 (winnt.h, WinBase.h, winerror.h).
This module never sets JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: a process can never leave
a job, so a job attached to a live app must not be able to kill it.
"""
import ctypes
import ctypes.wintypes as w
import os
import subprocess

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
HANDLE = ctypes.c_void_p

# JOBOBJECTINFOCLASS
BASIC_ACCOUNTING, BASIC_LIMIT, PROCESS_ID_LIST = 1, 2, 3
ASSOC_COMPLETION_PORT, BASIC_AND_IO_ACCOUNTING, EXTENDED_LIMIT = 7, 8, 9
NOTIFICATION_LIMIT, LIMIT_VIOLATION, CPU_RATE_CONTROL = 12, 13, 15

# JOB_OBJECT_LIMIT_*
LIMIT_ACTIVE_PROCESS = 0x8
LIMIT_PRIORITY_CLASS = 0x20
LIMIT_PROCESS_MEMORY = 0x100
LIMIT_JOB_MEMORY = 0x200
LIMIT_BREAKAWAY_OK = 0x800
LIMIT_SILENT_BREAKAWAY_OK = 0x1000
LIMIT_KILL_ON_JOB_CLOSE = 0x2000

# JOB_OBJECT_CPU_RATE_CONTROL_*
CPU_ENABLE, CPU_WEIGHT_BASED, CPU_HARD_CAP, CPU_NOTIFY, CPU_MIN_MAX = 0x1, 0x2, 0x4, 0x8, 0x10

PRIORITY = {"high": 0x80, "above_normal": 0x8000, "normal": 0x20, "below_normal": 0x4000, "idle": 0x40}
PRIORITY_NAME = {v: k for k, v in PRIORITY.items()}

PROCESS_TERMINATE, PROCESS_SET_QUOTA = 0x0001, 0x0100
PROCESS_VM_READ, PROCESS_SUSPEND_RESUME, PROCESS_QUERY_LIMITED = 0x0010, 0x0800, 0x1000
JOB_OBJECT_ALL_ACCESS = 0x1F001F
CREATE_SUSPENDED, CREATE_BREAKAWAY_FROM_JOB = 0x4, 0x01000000
ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_MORE_DATA = 5, 183, 234
NCPU = os.cpu_count() or 1


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in ("ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                                               "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class BASIC_ACCOUNTING_INFO(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
                ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD)]


class BASIC_AND_IO_ACCOUNTING_INFO(ctypes.Structure):
    _fields_ = [("Basic", BASIC_ACCOUNTING_INFO), ("Io", IO_COUNTERS)]


class BASIC_LIMIT_INFO(ctypes.Structure):
    _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", w.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", w.DWORD),
                ("Affinity", ctypes.c_size_t), ("PriorityClass", w.DWORD), ("SchedulingClass", w.DWORD)]


class EXTENDED_LIMIT_INFO(ctypes.Structure):
    _fields_ = [("Basic", BASIC_LIMIT_INFO), ("Io", IO_COUNTERS), ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t)]


class CPU_RATE_INFO(ctypes.Structure):
    # Value is the union: CpuRate | Weight | (MinRate | MaxRate << 16)
    _fields_ = [("ControlFlags", w.DWORD), ("Value", w.DWORD)]


class NOTIFICATION_LIMIT_INFO(ctypes.Structure):
    _fields_ = [("IoReadBytesLimit", ctypes.c_uint64), ("IoWriteBytesLimit", ctypes.c_uint64),
                ("PerJobUserTimeLimit", ctypes.c_int64), ("JobMemoryLimit", ctypes.c_uint64),
                ("RateControlTolerance", ctypes.c_int), ("RateControlToleranceInterval", ctypes.c_int),
                ("LimitFlags", w.DWORD)]


class ASSOC_PORT_INFO(ctypes.Structure):
    _fields_ = [("CompletionKey", ctypes.c_void_p), ("CompletionPort", HANDLE)]


class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
    _fields_ = [("cb", w.DWORD), ("PageFaultCount", w.DWORD)] + [(n, ctypes.c_size_t) for n in (
        "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage",
        "QuotaPeakNonPagedPoolUsage", "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ThreadID", w.DWORD),
                ("th32OwnerProcessID", w.DWORD), ("tpBasePri", w.LONG), ("tpDeltaPri", w.LONG), ("dwFlags", w.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", w.LONG), ("dwFlags", w.DWORD),
                ("szExeFile", w.WCHAR * 260)]


def _bind(name, res, *args):
    f = getattr(k32, name)
    f.restype, f.argtypes = res, list(args)
    return f


CreateJobObjectW = _bind("CreateJobObjectW", HANDLE, ctypes.c_void_p, w.LPCWSTR)
OpenJobObjectW = _bind("OpenJobObjectW", HANDLE, w.DWORD, w.BOOL, w.LPCWSTR)
TerminateJobObject = _bind("TerminateJobObject", w.BOOL, HANDLE, w.UINT)
SetInformationJobObject = _bind("SetInformationJobObject", w.BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD)
QueryInformationJobObject = _bind("QueryInformationJobObject", w.BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p,
                                  w.DWORD, ctypes.POINTER(w.DWORD))
AssignProcessToJobObject = _bind("AssignProcessToJobObject", w.BOOL, HANDLE, HANDLE)
IsProcessInJob = _bind("IsProcessInJob", w.BOOL, HANDLE, HANDLE, ctypes.POINTER(w.BOOL))
OpenProcess = _bind("OpenProcess", HANDLE, w.DWORD, w.BOOL, w.DWORD)
CloseHandle = _bind("CloseHandle", w.BOOL, HANDLE)
GetPriorityClass = _bind("GetPriorityClass", w.DWORD, HANDLE)
SetPriorityClass = _bind("SetPriorityClass", w.BOOL, HANDLE, w.DWORD)
GetCurrentProcess = _bind("GetCurrentProcess", HANDLE)
GetProcessMemoryInfo = _bind("K32GetProcessMemoryInfo", w.BOOL, HANDLE, ctypes.c_void_p, w.DWORD)
CreateToolhelp32Snapshot = _bind("CreateToolhelp32Snapshot", HANDLE, w.DWORD, w.DWORD)
Thread32First = _bind("Thread32First", w.BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
Thread32Next = _bind("Thread32Next", w.BOOL, HANDLE, ctypes.POINTER(THREADENTRY32))
Process32FirstW = _bind("Process32FirstW", w.BOOL, HANDLE, ctypes.POINTER(PROCESSENTRY32W))
Process32NextW = _bind("Process32NextW", w.BOOL, HANDLE, ctypes.POINTER(PROCESSENTRY32W))
OpenThread = _bind("OpenThread", HANDLE, w.DWORD, w.BOOL, w.DWORD)
ResumeThread = _bind("ResumeThread", w.DWORD, HANDLE)
CreateIoCompletionPort = _bind("CreateIoCompletionPort", HANDLE, HANDLE, HANDLE, ctypes.c_size_t, w.DWORD)
GetQueuedCompletionStatus = _bind("GetQueuedCompletionStatus", w.BOOL, HANDLE, ctypes.POINTER(w.DWORD),
                                  ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_void_p), w.DWORD)
GetSystemTimes = _bind("GetSystemTimes", w.BOOL, ctypes.POINTER(w.FILETIME), ctypes.POINTER(w.FILETIME),
                       ctypes.POINTER(w.FILETIME))


class WinError(OSError):
    def __init__(self, what):
        code = ctypes.get_last_error()
        super().__init__(code, f"{what} failed: {ctypes.FormatError(code).strip()} (winerror {code})")
        self.winerror = code


def _check(ok, what):
    if not ok:
        raise WinError(what)
    return ok


def job_name(name):
    return name if "\\" in name else "Local\\Guardian." + name


class Job:
    """One Windows Job Object. Named jobs live in the session namespace (Local\\)."""

    def __init__(self, handle, name):
        self.h, self.name = handle, name

    @classmethod
    def create(cls, name=None):
        ctypes.set_last_error(0)
        h = CreateJobObjectW(None, job_name(name) if name else None)
        existed = ctypes.get_last_error() == ERROR_ALREADY_EXISTS
        j = cls(_check(h, f"CreateJobObject({name})"), name)
        j.existed = bool(h) and existed
        return j

    @classmethod
    def open(cls, name):
        return cls(_check(OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, False, job_name(name)), f"OpenJobObject({name})"), name)

    def close(self):
        if self.h:
            CloseHandle(self.h)
            self.h = None

    def _query(self, cls_id, obj):
        _check(QueryInformationJobObject(self.h, cls_id, ctypes.byref(obj), ctypes.sizeof(obj), None),
               f"QueryInformationJobObject({cls_id})")
        return obj

    def _set(self, cls_id, obj):
        _check(SetInformationJobObject(self.h, cls_id, ctypes.byref(obj), ctypes.sizeof(obj)),
               f"SetInformationJobObject({cls_id})")

    # ---- CPU -------------------------------------------------------------
    def terminate(self, exit_code=1):
        """Kill every process in the job, including orphans whose parent already exited."""
        _check(TerminateJobObject(self.h, exit_code), f"TerminateJobObject({self.name})")

    def set_cpu(self, max_cores=None, min_cores=None, weight=None):
        """max only -> HARD_CAP; min and/or max -> MIN_MAX_RATE; weight -> WEIGHT_BASED; nothing -> off.
        Cores convert to the 1/10000-of-machine units the kernel uses."""
        rate = lambda cores: max(1, min(10000, round(cores / NCPU * 10000)))
        c = CPU_RATE_INFO()
        if weight is not None:
            c.ControlFlags, c.Value = CPU_ENABLE | CPU_WEIGHT_BASED, max(1, min(9, int(weight)))
        elif min_cores:
            lo = rate(min_cores)
            hi = rate(max_cores) if max_cores else 10000
            c.ControlFlags, c.Value = CPU_ENABLE | CPU_MIN_MAX, lo | (max(hi, lo) << 16)
        elif max_cores is not None:
            c.ControlFlags, c.Value = CPU_ENABLE | CPU_HARD_CAP, rate(max_cores)
        elif not self.cpu()["flags"] & CPU_ENABLE:
            return  # turning off control that was never on fails with winerror 87
        self._set(CPU_RATE_CONTROL, c)

    def set_cpu_rate(self, rate):
        """Raw hard cap in 1/10000 of the machine; rate=1 is the throttle-pause (0.01%)."""
        c = CPU_RATE_INFO(CPU_ENABLE | CPU_HARD_CAP, max(1, min(10000, int(rate))))
        self._set(CPU_RATE_CONTROL, c)

    def cpu(self):
        c = self._query(CPU_RATE_CONTROL, CPU_RATE_INFO())
        f, v = c.ControlFlags, c.Value
        if not f & CPU_ENABLE:
            return {"mode": "none", "flags": f}
        if f & CPU_WEIGHT_BASED:
            return {"mode": "weight", "weight": v, "flags": f}
        if f & CPU_MIN_MAX:
            lo, hi = v & 0xFFFF, v >> 16
            return {"mode": "min_max", "min_rate": lo, "max_rate": hi, "min_cores": lo * NCPU / 1e4,
                    "max_cores": hi * NCPU / 1e4, "flags": f}
        return {"mode": "hard_cap" if f & CPU_HARD_CAP else "soft_cap", "rate": v, "cores": v * NCPU / 1e4, "flags": f}

    # ---- memory and priority ---------------------------------------------
    def extended(self):
        return self._query(EXTENDED_LIMIT, EXTENDED_LIMIT_INFO())

    def set_limits(self, mem_max_bytes=None, priority=None, clear_mem=False, clear_priority=False, pids=None,
                   clear_pids=False):
        """Read-modify-write the extended limits so unrelated flags survive. Never adds KILL_ON_JOB_CLOSE."""
        e = self.extended()
        flags = e.Basic.LimitFlags
        if mem_max_bytes:
            flags |= LIMIT_JOB_MEMORY
            e.JobMemoryLimit = int(mem_max_bytes)
        elif clear_mem:
            flags &= ~LIMIT_JOB_MEMORY
        if pids:  # process-count cap: CreateProcess in the job fails once it holds this many live processes
            flags |= LIMIT_ACTIVE_PROCESS
            e.Basic.ActiveProcessLimit = int(pids)
        elif clear_pids:
            flags &= ~LIMIT_ACTIVE_PROCESS
        if priority:
            flags |= LIMIT_PRIORITY_CLASS
            e.Basic.PriorityClass = PRIORITY[priority]
        elif clear_priority:
            flags &= ~LIMIT_PRIORITY_CLASS
        assert not (flags & LIMIT_KILL_ON_JOB_CLOSE) or (e.Basic.LimitFlags & LIMIT_KILL_ON_JOB_CLOSE)
        e.Basic.LimitFlags = flags
        self._set(EXTENDED_LIMIT, e)

    def limits(self):
        e = self.extended()
        f = e.Basic.LimitFlags
        return {"flags": f, "mem_max_bytes": e.JobMemoryLimit if f & LIMIT_JOB_MEMORY else None,
                "peak_job_mem_bytes": e.PeakJobMemoryUsed,
                "pids_max": e.Basic.ActiveProcessLimit if f & LIMIT_ACTIVE_PROCESS else None,
                "priority": PRIORITY_NAME.get(e.Basic.PriorityClass) if f & LIMIT_PRIORITY_CLASS else None,
                "kill_on_close": bool(f & LIMIT_KILL_ON_JOB_CLOSE), "breakaway_ok": bool(f & LIMIT_BREAKAWAY_OK)}

    def set_soft_memory(self, high_bytes, port=None, key=0):
        """Notification limit: the kernel posts JOB_OBJECT_MSG_NOTIFICATION_LIMIT (11) and nothing fails."""
        if port:
            self._set(ASSOC_COMPLETION_PORT, ASSOC_PORT_INFO(key, port))
        n = NOTIFICATION_LIMIT_INFO()
        n.JobMemoryLimit, n.LimitFlags = int(high_bytes), LIMIT_JOB_MEMORY
        self._set(NOTIFICATION_LIMIT, n)

    def soft_memory(self):
        n = self._query(NOTIFICATION_LIMIT, NOTIFICATION_LIMIT_INFO())
        return n.JobMemoryLimit if n.LimitFlags & LIMIT_JOB_MEMORY else None

    # ---- membership and accounting ---------------------------------------
    def pids(self):
        n = 64
        while True:
            class L(ctypes.Structure):
                _fields_ = [("Assigned", w.DWORD), ("InList", w.DWORD), ("Ids", ctypes.c_size_t * n)]
            lst = L()
            if QueryInformationJobObject(self.h, PROCESS_ID_LIST, ctypes.byref(lst), ctypes.sizeof(lst), None):
                return [int(p) for p in lst.Ids[:lst.InList]]
            if ctypes.get_last_error() != ERROR_MORE_DATA or n > 65536:
                raise WinError("QueryInformationJobObject(ProcessIdList)")
            n *= 4

    def accounting(self):
        a = self._query(BASIC_AND_IO_ACCOUNTING, BASIC_AND_IO_ACCOUNTING_INFO())
        b = a.Basic
        return {"cpu_s": (b.TotalUserTime + b.TotalKernelTime) / 1e7, "active": b.ActiveProcesses,
                "total": b.TotalProcesses, "terminated": b.TotalTerminatedProcesses,
                "io_read_bytes": a.Io.ReadTransferCount, "io_write_bytes": a.Io.WriteTransferCount}

    def memory_usage(self):
        """Current private commit and working set summed over member processes."""
        priv = ws = 0
        for pid in self.pids():
            m = process_memory(pid)
            if m:
                priv += m[0]
                ws += m[1]
        return priv, ws

    def assign(self, pid):
        h = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED, False, pid)
        _check(h, f"OpenProcess({pid})")
        try:
            _check(AssignProcessToJobObject(self.h, h), f"AssignProcessToJobObject(pid {pid})")
        finally:
            CloseHandle(h)

    def contains(self, pid):
        return in_job(pid, self.h)


def in_job(pid, job_handle=None):
    """True/False, or None when the process cannot be opened."""
    h = OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        b = w.BOOL()
        return bool(b.value) if IsProcessInJob(h, job_handle, ctypes.byref(b)) else None
    finally:
        CloseHandle(h)


def process_memory(pid):
    h = OpenProcess(PROCESS_QUERY_LIMITED | PROCESS_VM_READ, False, pid)
    if not h:
        return None
    try:
        m = PROCESS_MEMORY_COUNTERS_EX()
        m.cb = ctypes.sizeof(m)
        return (m.PrivateUsage, m.WorkingSetSize) if GetProcessMemoryInfo(h, ctypes.byref(m), m.cb) else None
    finally:
        CloseHandle(h)


def priority_class(pid):
    h = OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        return PRIORITY_NAME.get(GetPriorityClass(h), "?")
    finally:
        CloseHandle(h)


def process_table():
    """{pid: (ppid, exe)} from one Toolhelp snapshot (cheap, a few ms)."""
    snap = CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    out = {}
    if not snap or snap == HANDLE(-1).value:
        return out
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out[e.th32ProcessID] = (e.th32ParentProcessID, e.szExeFile)
            ok = Process32NextW(snap, ctypes.byref(e))
    finally:
        CloseHandle(snap)
    return out


def descendants(root_pid, table=None):
    """root_pid plus every live descendant. Guards against PID reuse by requiring parents to be in the set first."""
    table = table or process_table()
    kids = {}
    for pid, (ppid, _) in table.items():
        kids.setdefault(ppid, []).append(pid)
    out, stack = [], [root_pid] if root_pid in table else []
    while stack:
        p = stack.pop()
        out.append(p)
        stack.extend(c for c in kids.get(p, []) if c != p and c not in out)
    return out


def resume_process_threads(pid):
    """Documented resume of a CREATE_SUSPENDED process: ResumeThread on each of its threads."""
    snap = CreateToolhelp32Snapshot(0x4, 0)  # TH32CS_SNAPTHREAD
    n = 0
    try:
        t = THREADENTRY32()
        t.dwSize = ctypes.sizeof(t)
        ok = Thread32First(snap, ctypes.byref(t))
        while ok:
            if t.th32OwnerProcessID == pid:
                th = OpenThread(0x0002, False, t.th32ThreadID)  # THREAD_SUSPEND_RESUME
                if th:
                    ResumeThread(th)
                    CloseHandle(th)
                    n += 1
            ok = Thread32Next(snap, ctypes.byref(t))
    finally:
        CloseHandle(snap)
    return n


def spawn_in_jobs(argv, jobs, **popen_kw):
    """Start argv suspended, assign it to each job in order (outer first), then resume.
    Children it creates later inherit the innermost job automatically."""
    flags = popen_kw.pop("creationflags", 0) | CREATE_SUSPENDED
    p = subprocess.Popen(argv, creationflags=flags, **popen_kw)
    try:
        for j in jobs:
            j.assign(p.pid)
    except OSError:
        p.kill()
        raise
    finally:
        resume_process_threads(p.pid)
    return p


def set_own_priority(name):
    return bool(SetPriorityClass(GetCurrentProcess(), PRIORITY[name]))


def make_port():
    return _check(CreateIoCompletionPort(HANDLE(-1).value, None, 0, 1), "CreateIoCompletionPort")


def port_get(port, timeout_ms):
    """Next job message as (msg_id, key, pid) or None on timeout. 11 = NOTIFICATION_LIMIT, 6/7 = new/exit process."""
    msg, key, ov = w.DWORD(), ctypes.c_size_t(), ctypes.c_void_p()
    if GetQueuedCompletionStatus(port, ctypes.byref(msg), ctypes.byref(key), ctypes.byref(ov), timeout_ms):
        return msg.value, key.value, ov.value
    return None


def system_busy():
    """Returns a function that yields whole-machine busy fraction since the previous call."""
    def ft(f):
        return (f.dwHighDateTime << 32) | f.dwLowDateTime
    prev = [None]

    def sample():
        i, k, u = w.FILETIME(), w.FILETIME(), w.FILETIME()
        GetSystemTimes(ctypes.byref(i), ctypes.byref(k), ctypes.byref(u))
        cur = (ft(i), ft(k) + ft(u))
        if prev[0] is None:
            prev[0] = cur
            return None
        di, dt = cur[0] - prev[0][0], cur[1] - prev[0][1]
        prev[0] = cur
        return 1 - di / dt if dt else None
    return sample


# ---- additions for the Guardian ---------------------------------------------------------------
LIMIT_AFFINITY = 0x10
PROCESS_SET_INFORMATION, PROCESS_DUP_HANDLE = 0x0200, 0x0040
JOB_OBJECT_QUERY = 0x0004


def set_job_affinity(job, mask):
    """mask=None clears the affinity limit (read-modify-write keeps the other flags)."""
    e = job.extended()
    if mask:
        e.Basic.LimitFlags |= LIMIT_AFFINITY
        e.Basic.Affinity = int(mask)
    else:
        e.Basic.LimitFlags &= ~LIMIT_AFFINITY
    job._set(EXTENDED_LIMIT, e)


def set_process_priority(pid, name):
    """Clearing a job's priority limit does not restore member processes, so rollback sets them back explicitly."""
    h = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return False
    try:
        return bool(SetPriorityClass(h, PRIORITY[name]))
    finally:
        CloseHandle(h)


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [("cb", w.DWORD)] + [(n, ctypes.c_size_t) for n in (
        "CommitTotal", "CommitLimit", "CommitPeak", "PhysicalTotal", "PhysicalAvailable", "SystemCache",
        "KernelTotal", "KernelPaged", "KernelNonpaged", "PageSize")] + [
        (n, w.DWORD) for n in ("HandleCount", "ProcessCount", "ThreadCount")]


_psapi = ctypes.WinDLL("psapi", use_last_error=True)
GetPerformanceInfo = _psapi.GetPerformanceInfo
GetPerformanceInfo.restype, GetPerformanceInfo.argtypes = w.BOOL, [ctypes.c_void_p, w.DWORD]


def performance_info():
    """Bytes, not pages: GetPerformanceInfo reports pages, multiplied by PageSize here."""
    p = PERFORMANCE_INFORMATION()
    p.cb = ctypes.sizeof(p)
    if not GetPerformanceInfo(ctypes.byref(p), p.cb):
        raise WinError("GetPerformanceInfo")
    ps = p.PageSize
    return {"available": p.PhysicalAvailable * ps, "physical_total": p.PhysicalTotal * ps,
            "commit_total": p.CommitTotal * ps, "commit_limit": p.CommitLimit * ps}


# ---- adopting a process that is already running -----------------------------------------------
SYNCHRONIZE = 0x00100000
QueryFullProcessImageNameW = _bind("QueryFullProcessImageNameW", w.BOOL, HANDLE, w.DWORD, w.LPWSTR,
                                   ctypes.POINTER(w.DWORD))
WaitForSingleObject = _bind("WaitForSingleObject", w.DWORD, HANDLE, w.DWORD)


def image_path(pid):
    """Full path of the process image, or None when the process cannot be opened."""
    h = OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
    if not h:
        return None
    try:
        buf, n = ctypes.create_unicode_buffer(1024), w.DWORD(1024)
        return buf.value if QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)) else None
    finally:
        CloseHandle(h)


def ancestors(pid, table=None):
    """pid's parent, grandparent and so on, nearest first. Stops at the first parent that has exited or repeats.
    A parent PID can be reused after its process exits, so callers check what they find by image name."""
    table = table or process_table()
    out, seen = [], {pid}
    p = table.get(pid, (None,))[0]
    while p in table and p not in seen:
        out.append(p)
        seen.add(p)
        p = table[p][0]
    return out


def open_waitable(pid):
    """A handle that keeps the PID from being reused while it is open; None if the process is gone."""
    return OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED, False, pid) or None


def has_exited(handle):
    return WaitForSingleObject(handle, 0) == 0  # WAIT_OBJECT_0: the process has exited


def in_named_job(pid, name):
    """True/False when the named job exists and pid can be checked against it, else None. Query access only, so
    it also works where a sandbox keeps a process from reaching the daemon's pipe."""
    h = OpenJobObjectW(JOB_OBJECT_QUERY, False, job_name(name))
    if not h:
        return None
    try:
        return in_job(pid, h)
    finally:
        CloseHandle(h)
