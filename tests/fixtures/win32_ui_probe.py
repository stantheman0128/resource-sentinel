"""Bounded, standalone, own-window responsiveness measurements for P6.

Launch directly with the base Python interpreter, outside every Job. This fixture
does not launch workloads, change priority, capture input, or inspect any other
window. Its hidden window measures posted-message dispatch and *internal* paint
scheduling, not visible rendering, compositor latency, or a user's foreground
application. RedrawWindow(RDW_INTERNALPAINT) asks Windows to generate WM_PAINT;
we never post WM_PAINT or call UpdateWindow to manufacture a synchronous result.

Only native observations with verified Normal priority, no Job membership, and
successful cleanup receive status="measured". Portable tests exercise validation
and bookkeeping only. Native completion remains a separately admitted gate.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import stat
import sys
import threading
import time
import uuid


NORMAL_PRIORITY_CLASS = 0x20
SCHEMA_VERSION = 1
MAX_DURATION_SECONDS = 3600.0
MAX_SAMPLES = 100_000
COMPLETION_GRACE_NS = 2_000_000_000


class ProbeError(ValueError):
    """A fixed, non-private reason safe to put in a result."""


@dataclass(frozen=True)
class ProbeConfig:
    duration_seconds: float = 60.0
    interval_ms: int = 100
    max_samples: int = 10_000

    def __post_init__(self):
        if (type(self.duration_seconds) not in (int, float)
                or not math.isfinite(self.duration_seconds)
                or not 1 <= self.duration_seconds <= MAX_DURATION_SECONDS):
            raise ProbeError("duration_out_of_range")
        if type(self.interval_ms) is not int or not 20 <= self.interval_ms <= 1000:
            raise ProbeError("interval_out_of_range")
        if type(self.max_samples) is not int or not 1 <= self.max_samples <= MAX_SAMPLES:
            raise ProbeError("sample_limit_out_of_range")


def percentile(values, quantile):
    """Linear interpolation, retaining raw samples so another statistic is possible."""
    if not values:
        return None
    if not 0 <= quantile <= 1:
        raise ProbeError("quantile_invalid")
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    low, high = math.floor(position), math.ceil(position)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def distribution(values):
    return {"count": len(values), "p50": percentile(values, .50),
            "p95": percentile(values, .95), "p99": percentile(values, .99)}


def require_native_context(job_membership, priority_class):
    if type(job_membership) is not bool or type(priority_class) is not int:
        raise ProbeError("native_context_unverified")
    if job_membership:
        raise ProbeError("process_is_in_job")
    if priority_class != NORMAL_PRIORITY_CLASS:
        raise ProbeError("process_priority_not_normal")


class ProbeRecorder:
    """One outstanding sample prevents paint-message coalescing from faking pairs.

    The caller owns the lock. Timestamps are supplied only by the native producer
    and WndProc in production; this class contains no clock or native API.
    """

    def __init__(self, maximum):
        if type(maximum) is not int or not 1 <= maximum <= MAX_SAMPLES:
            raise ProbeError("sample_limit_out_of_range")
        self.maximum = maximum
        self.samples = []
        self.pending = None

    @staticmethod
    def _tick(tick):
        if type(tick) is not int or tick < 0:
            raise ProbeError("clock_invalid")

    def enqueue(self, now):
        self._tick(now)
        if self.pending is not None or len(self.samples) >= self.maximum:
            return None
        self.pending = {"sequence": len(self.samples) + 1, "enqueued_ns": now}
        return self.pending["sequence"]

    def dispatch(self, sequence, now):
        self._tick(now)
        if (self.pending is None or self.pending["sequence"] != sequence
                or "dispatch_ns" in self.pending):
            return False
        if now < self.pending["enqueued_ns"]:
            raise ProbeError("clock_regressed")
        self.pending["dispatch_ns"] = now
        return True

    def request_paint(self, now):
        self._tick(now)
        if self.pending is None or "dispatch_ns" not in self.pending:
            raise ProbeError("paint_without_dispatch")
        if "paint_requested_ns" in self.pending:
            raise ProbeError("duplicate_paint_request")
        if now < self.pending["dispatch_ns"]:
            raise ProbeError("clock_regressed")
        self.pending["paint_requested_ns"] = now

    def paint(self, started, finished):
        self._tick(started)
        self._tick(finished)
        if self.pending is None or "paint_requested_ns" not in self.pending:
            return False
        if not self.pending["paint_requested_ns"] <= started <= finished:
            raise ProbeError("clock_regressed")
        self.pending["paint_ns"] = started
        self.pending["paint_finished_ns"] = finished
        self.samples.append(self.pending)
        self.pending = None
        return True


def _produce_samples(config, recorder, lock, stopped, post_sample, clock=time.monotonic_ns):
    """The stop decision and new-sample admission share the recorder lock."""
    while not stopped.is_set():
        with lock:
            # A stop may occur between the outer loop check and lock acquisition.
            if stopped.is_set():
                return
            sequence = recorder.enqueue(clock())
            if sequence is not None and not post_sample(sequence):
                raise ProbeError("post_message_failed")
        stopped.wait(config.interval_ms / 1000.0)


def validate_path(value, *, absent=False):
    """Only explicit local, regular, non-redirected fixture paths are accepted."""
    path = Path(value)
    spelling = os.fspath(value).replace("\\", "/")
    if spelling.startswith("//") or not path.is_absolute() or ".." in path.parts:
        raise ProbeError("path_must_be_absolute_local")
    if any(part.casefold() == ".resource-sentinel" for part in path.parts):
        raise ProbeError("production_directory_forbidden")
    for ancestor in (path.parent, *path.parent.parents):
        info = ancestor.lstat()
        if (not stat.S_ISDIR(info.st_mode) or ancestor.is_symlink()
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ProbeError("path_parent_redirected")
    if os.path.lexists(path):
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ProbeError("path_not_regular")
        if absent:
            raise ProbeError("path_already_exists")
    return path


def publish_json(path, payload):
    """Publish once, atomically, without overwriting an earlier run's evidence."""
    path = validate_path(path, absent=True)
    encoded = json.dumps(payload, allow_nan=False, ensure_ascii=True,
                         separators=(",", ":")).encode("utf-8")
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    with temporary.open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    validate_path(path, absent=True)
    if os.name == "nt":
        os.rename(temporary, path)  # Windows rename refuses an existing target.
    else:
        os.link(temporary, path)  # Same no-overwrite guarantee in portable tests.
        temporary.unlink()


def _result(config):
    return {
        "schema_version": SCHEMA_VERSION, "probe": "win32_own_hidden_window",
        "scope": "posted_message_and_internal_paint_scheduling",
        "status": "blocked", "reason": "not_started", "process_id": os.getpid(),
        "outside_job": None, "priority_class": None, "clock": "monotonic_ns",
        "started_ns": None, "ended_ns": None, "stop_reason": None,
        "duration_limit_seconds": config.duration_seconds,
        "interval_ms": config.interval_ms, "sample_limit": config.max_samples,
        "samples": [], "incomplete_sample": None,
        "dispatch_ms": distribution([]), "paint_ms": distribution([]),
        "cleanup_complete": False, "errors": [],
    }


def run_probe(config, *, stop_file=None, ready_file=None):
    """Run native work only on Windows; return structured denial everywhere else."""
    result = _result(config)
    if os.name != "nt":
        result["reason"] = "windows_required"
        result["cleanup_complete"] = True
        return result
    return _run_windows(config, result, stop_file=stop_file, ready_file=ready_file)


def _run_windows(config, result, *, stop_file, ready_file):
    # Importing this fixture is portable. Native types/API loading occur only here.
    import ctypes
    from ctypes import wintypes as w

    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    LRESULT = ctypes.c_ssize_t
    WPARAM = ctypes.c_size_t
    LPARAM = ctypes.c_ssize_t
    WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, WPARAM, LPARAM)

    class WNDCLASS(ctypes.Structure):
        _fields_ = [("style", w.UINT), ("lpfnWndProc", WNDPROC),
                    ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int),
                    ("hInstance", w.HINSTANCE), ("hIcon", w.HANDLE),
                    ("hCursor", w.HANDLE), ("hbrBackground", w.HANDLE),
                    ("lpszMenuName", w.LPCWSTR), ("lpszClassName", w.LPCWSTR)]

    class PAINTSTRUCT(ctypes.Structure):
        _fields_ = [("hdc", w.HDC), ("fErase", w.BOOL), ("rcPaint", w.RECT),
                    ("fRestore", w.BOOL), ("fIncUpdate", w.BOOL),
                    ("rgbReserved", w.BYTE * 32)]

    class MSG(ctypes.Structure):
        _fields_ = [("hwnd", w.HWND), ("message", w.UINT), ("wParam", WPARAM),
                    ("lParam", LPARAM), ("time", w.DWORD), ("pt", w.POINT),
                    ("lPrivate", w.DWORD)]

    def api(library, name, arguments, returns):
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, returns
        return function

    current = api(kernel, "GetCurrentProcess", [], w.HANDLE)
    in_job = api(kernel, "IsProcessInJob", [w.HANDLE, w.HANDLE, ctypes.POINTER(w.BOOL)], w.BOOL)
    priority = api(kernel, "GetPriorityClass", [w.HANDLE], w.DWORD)
    module = api(kernel, "GetModuleHandleW", [w.LPCWSTR], w.HMODULE)
    register = api(user, "RegisterClassW", [ctypes.POINTER(WNDCLASS)], w.ATOM)
    unregister = api(user, "UnregisterClassW", [w.LPCWSTR, w.HINSTANCE], w.BOOL)
    create = api(user, "CreateWindowExW", [w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                 ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                 w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID], w.HWND)
    destroy = api(user, "DestroyWindow", [w.HWND], w.BOOL)
    default = api(user, "DefWindowProcW", [w.HWND, w.UINT, WPARAM, LPARAM], LRESULT)
    post = api(user, "PostMessageW", [w.HWND, w.UINT, WPARAM, LPARAM], w.BOOL)
    redraw = api(user, "RedrawWindow", [w.HWND, ctypes.POINTER(w.RECT), w.HANDLE, w.UINT], w.BOOL)
    begin = api(user, "BeginPaint", [w.HWND, ctypes.POINTER(PAINTSTRUCT)], w.HDC)
    end = api(user, "EndPaint", [w.HWND, ctypes.POINTER(PAINTSTRUCT)], w.BOOL)
    peek = api(user, "PeekMessageW", [ctypes.POINTER(MSG), w.HWND, w.UINT, w.UINT, w.UINT], w.BOOL)
    translate = api(user, "TranslateMessage", [ctypes.POINTER(MSG)], w.BOOL)
    dispatch = api(user, "DispatchMessageW", [ctypes.POINTER(MSG)], LRESULT)
    wait = api(user, "MsgWaitForMultipleObjectsEx", [w.DWORD, ctypes.POINTER(w.HANDLE),
               w.DWORD, w.DWORD, w.DWORD], w.DWORD)

    WM_PROBE, WM_PAINT = 0x8001, 0x000F
    lock, stopped = threading.RLock(), threading.Event()
    recorder = ProbeRecorder(config.max_samples)
    hwnd, atom, producer = None, None, None
    errors = []
    class_name = "ResourceSentinel.UIProbe." + uuid.uuid4().hex
    instance = None
    accepting = True

    def error(reason):
        if reason not in errors:
            errors.append(reason)
        stopped.set()

    def verify_own_context():
        membership = w.BOOL()
        if not in_job(current(), None, ctypes.byref(membership)):
            raise ProbeError("job_membership_query_failed")
        observed_priority = priority(current())
        if not observed_priority:
            raise ProbeError("priority_query_failed")
        result["outside_job"] = not bool(membership.value)
        result["priority_class"] = observed_priority
        require_native_context(bool(membership.value), observed_priority)

    @WNDPROC
    def window_proc(window, message, wparam, lparam):
        try:
            if message == WM_PROBE:
                with lock:
                    if not recorder.dispatch(int(wparam), time.monotonic_ns()):
                        return 0
                    verify_own_context()
                    recorder.request_paint(time.monotonic_ns())
                    # INTERNALPAINT generates a real queued WM_PAINT even if the
                    # hidden window has no visible invalid region. No UPDATENOW.
                    if not redraw(window, None, None, 0x0001 | 0x0002):
                        error("redraw_request_failed")
                return 0
            if message == WM_PAINT:
                paint = PAINTSTRUCT()
                started = time.monotonic_ns()
                hdc = begin(window, ctypes.byref(paint))
                if not hdc:
                    error("begin_paint_failed")
                    return 0
                if not end(window, ctypes.byref(paint)):
                    error("end_paint_failed")
                    return 0
                finished = time.monotonic_ns()
                with lock:
                    recorder.paint(started, finished)
                return 0
            return default(window, message, wparam, lparam)
        except BaseException as exc:
            error(str(exc) if isinstance(exc, ProbeError) else "window_callback_failed")
            return 0

    def produce():
        try:
            _produce_samples(config, recorder, lock, stopped,
                             lambda sequence: accepting and hwnd and post(hwnd, WM_PROBE, sequence, 0))
        except BaseException as exc:
            error(str(exc) if isinstance(exc, ProbeError) else "producer_failed")

    try:
        verify_own_context()
        instance = module(None)
        if not instance:
            raise ProbeError("module_query_failed")
        cls = WNDCLASS()
        cls.lpfnWndProc, cls.hInstance, cls.lpszClassName = window_proc, instance, class_name
        atom = register(ctypes.byref(cls))
        if not atom:
            raise ProbeError("window_class_registration_failed")
        # No WS_VISIBLE or ShowWindow: never activates, captures input or appears.
        hwnd = create(0x08000080, class_name, "", 0x80000000,
                      0, 0, 1, 1, None, None, instance, None)
        if not hwnd:
            raise ProbeError("window_creation_failed")
        result["started_ns"] = time.monotonic_ns()
        if ready_file is not None:
            publish_json(ready_file, {
                "schema_version": SCHEMA_VERSION, "status": "ready",
                "process_id": os.getpid(), "outside_job": True,
                "priority_class": NORMAL_PRIORITY_CLASS,
                "started_ns": result["started_ns"], "clock": "monotonic_ns",
                "scope": result["scope"],
            })
        deadline = result["started_ns"] + int(config.duration_seconds * 1_000_000_000)
        stop_at = None
        producer = threading.Thread(target=produce, name="sentinel-ui-probe-producer")
        producer.start()
        message = MSG()
        while True:
            now = time.monotonic_ns()
            if stop_at is None:
                reason = None
                if stop_file is not None and os.path.lexists(stop_file):
                    validate_path(stop_file)
                    reason = "stop_file"
                elif now >= deadline:
                    reason = "duration"
                elif len(recorder.samples) >= config.max_samples:
                    reason = "sample_limit"
                if reason is not None:
                    result["stop_reason"] = reason
                    stop_at = now
                    stopped.set()
            if errors:
                break
            with lock:
                pending = recorder.pending is not None
            if stop_at is not None and not pending:
                break
            if stop_at is not None and now - stop_at > COMPLETION_GRACE_NS:
                raise ProbeError("outstanding_sample_timed_out")
            # Bound each batch so shutdown still progresses under unexpected input.
            for _ in range(64):
                if not peek(ctypes.byref(message), None, 0, 0, 0x0001):
                    break
                if message.message == 0x0012:  # WM_QUIT is not a measurement.
                    raise ProbeError("unexpected_quit")
                translate(ctypes.byref(message))
                dispatch(ctypes.byref(message))
            if wait(0, None, 50, 0x04FF, 0x0004) == 0xFFFFFFFF:
                raise ProbeError("message_wait_failed")
        verify_own_context()
        if not errors and not recorder.samples:
            raise ProbeError("no_complete_samples")
    except BaseException as exc:
        error(str(exc) if isinstance(exc, ProbeError) else
              "interrupted" if isinstance(exc, KeyboardInterrupt) else "native_probe_failed")
    finally:
        stopped.set()
        if producer is not None and producer.ident is not None:
            producer.join(timeout=2.0)
            if producer.is_alive():
                error("producer_cleanup_pending")
        # Do not allow a late producer to post to a subsequently reused HWND.
        with lock:
            accepting = False
            owned_window, hwnd = hwnd, None
            if owned_window and not destroy(owned_window):
                error("window_cleanup_failed")
        if atom and not unregister(class_name, instance):
            error("class_cleanup_failed")
        if recorder.pending is not None:
            error("incomplete_sample")
        result["ended_ns"] = time.monotonic_ns()
        result["samples"] = recorder.samples
        result["incomplete_sample"] = recorder.pending
        result["errors"] = errors
        result["cleanup_complete"] = not any("cleanup" in item for item in errors)
        result["dispatch_ms"] = distribution([
            (sample["dispatch_ns"] - sample["enqueued_ns"]) / 1_000_000
            for sample in recorder.samples])
        result["paint_ms"] = distribution([
            (sample["paint_ns"] - sample["paint_requested_ns"]) / 1_000_000
            for sample in recorder.samples])
        if errors:
            result["status"] = "blocked" if result["started_ns"] is None else "failed"
            result["reason"] = errors[0]
        else:
            result["status"], result["reason"] = "measured", "native_observations_complete"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--duration-seconds", type=float, default=60.0)
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--max-samples", type=int, default=10_000)
    parser.add_argument("--stop-file")
    parser.add_argument("--ready-file")
    args = parser.parse_args(argv)
    try:
        config = ProbeConfig(args.duration_seconds, args.interval_ms, args.max_samples)
        output = validate_path(args.output, absent=True)
        stop = validate_path(args.stop_file, absent=True) if args.stop_file else None
        ready = validate_path(args.ready_file, absent=True) if args.ready_file else None
        paths = [os.path.normcase(str(path)) for path in (output, stop, ready) if path is not None]
        if len(set(paths)) != len(paths):
            raise ProbeError("fixture_paths_must_differ")
        result = run_probe(config, stop_file=stop, ready_file=ready)
        publish_json(output, result)
    except (OSError, ProbeError) as exc:
        reason = str(exc) if isinstance(exc, ProbeError) else "fixture_io_failed"
        print(json.dumps({"schema_version": SCHEMA_VERSION, "status": "blocked", "reason": reason}),
              file=sys.stderr)
        return 2
    return 0 if result["status"] == "measured" else 2


if __name__ == "__main__":
    raise SystemExit(main())
